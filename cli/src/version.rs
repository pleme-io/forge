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

    /// The bounded-lattice bottom (⊥) on the magnitude ladder — the
    /// variant at the floor of the derived [`Ord`] chain
    /// (`Patch < Minor < Major`). Named typed-primitive peer of
    /// [`BumpLevel::Patch`] at the bounded-lattice surface, distinct from
    /// the variant-name surface: where `BumpLevel::Patch` reads the
    /// semver-component semantic role ("increment the patch component"),
    /// [`BumpLevel::BOTTOM`] reads the bounded-lattice semantic role
    /// ("the floor of the magnitude ladder — the join-identity, the
    /// meet-absorbing element, the lower bound every variant sits at-or-
    /// above"). Mirror const of [`BumpLevel::TOP`] at the ceiling of the
    /// same ladder, closing the bounded-lattice anchor pair at the
    /// typed-primitive surface.
    ///
    /// # The bounded-lattice axiom set
    ///
    /// The recent lattice trajectory closed the distributive-lattice
    /// axiom set on the meet/join pair on this ladder (idempotence +
    /// commutativity + associativity + identity + absorbing-element +
    /// lattice-bracket + absorption + distributivity, commits f7436eb /
    /// ba37d27 / 46d2754). A BOUNDED lattice is a distributive lattice
    /// equipped with explicit ⊥ and ⊤ constants and the bounded-lattice
    /// laws relating them to the meet/join pair:
    ///
    /// - `BOTTOM.join(a) == a` (BOTTOM is the join-identity);
    /// - `BOTTOM.meet(a) == BOTTOM` (BOTTOM is the meet-absorbing element);
    /// - `BOTTOM <= a` at every variant (BOTTOM is the global lower bound).
    ///
    /// These three laws — pinned by
    /// [`tests::test_bump_level_bottom_is_join_identity_at_every_variant`],
    /// [`tests::test_bump_level_bottom_is_meet_absorbing_at_every_variant`],
    /// and [`tests::test_bump_level_bottom_le_every_variant`] — name the
    /// ⊥ anchor at the typed-primitive surface, where prior commits pinned
    /// the same facts against the variant name (`BumpLevel::Patch`). The
    /// named [`BOTTOM`](Self::BOTTOM) surface carries the bounded-lattice
    /// semantic role distinct from the variant-name surface: a downstream
    /// consumer reading "seed a per-commit-magnitude join-fold at the
    /// lattice bottom" reads
    /// `levels.fold(BumpLevel::BOTTOM, |acc, l| acc.join(l))` once at one
    /// named oracle, where the same consumer reading
    /// `levels.fold(BumpLevel::Patch, ...)` reads the variant-name
    /// surface (the patch semver-component, which happens to coincide
    /// with the bottom at the present ladder).
    ///
    /// # Why a named const, not the variant
    ///
    /// The const reads `Self::Patch` and at the present three-variant
    /// ladder the two coincide (pinned by
    /// [`tests::test_bump_level_bottom_named_at_lattice_floor`] and
    /// [`tests::test_bump_level_bottom_equals_ladder_floor`]). The named
    /// [`BOTTOM`](Self::BOTTOM) const carries TWO load-bearing pieces of
    /// content the bare variant name does not:
    ///
    /// 1. The bounded-lattice semantic role. A downstream consumer that
    ///    reads `BumpLevel::BOTTOM` reads "the magnitude-ladder floor —
    ///    the value any per-commit-magnitude join-fold seeds at and any
    ///    per-commit-floor meet-fold early-exits on" at the call site,
    ///    where the same consumer reading `BumpLevel::Patch` reads the
    ///    semver-component semantic role (the canonical patch bump). The
    ///    two surfaces overlap at the present ladder but diverge under
    ///    refinement: a future `Prerelease` variant inserted strictly
    ///    below `Patch` (release-candidate / staging-channel bump shapes)
    ///    shifts the bounded-lattice floor — [`BOTTOM`](Self::BOTTOM)
    ///    would update at this one site to `Self::Prerelease` and every
    ///    consumer of "the join-fold seed" / "the meet-fold absorber"
    ///    would automatically pick up the new floor, while consumers of
    ///    `BumpLevel::Patch` (semver-component readers) would
    ///    structurally NOT pick up the new variant. Same one-oracle
    ///    discipline [`as_str`](Self::as_str) established for the
    ///    canonical-string surface and [`ALL`](Self::ALL) established
    ///    for the variant-enumeration surface — here applied to the
    ///    bounded-lattice anchor surface.
    /// 2. A const-pattern surface for the bounded-lattice readback. A
    ///    `match level { BumpLevel::BOTTOM => ..., _ => ... }` consumer
    ///    is structurally a "branch on whether this is the magnitude
    ///    floor" reader; the variant-name surface
    ///    `match level { BumpLevel::Patch => ... }` is a "branch on the
    ///    patch semver-component" reader. Same intent vs. shape
    ///    distinction the [`is_fix_only`](Self::is_fix_only) /
    ///    [`is_minor_only`](Self::is_minor_only) /
    ///    [`is_major_only`](Self::is_major_only) typed-method trio
    ///    surfaces at the variant-identity reading, here applied to the
    ///    bounded-lattice anchor surface.
    ///
    /// THEORY.md §V.4 typed primitives: the bounded-lattice floor is a
    /// typed-primitive surface on [`BumpLevel`] itself (one named const),
    /// not the variant name re-aliased at every join-fold seed site.
    /// THEORY.md §V.5 total-order discipline: [`BOTTOM`](Self::BOTTOM)
    /// is the global lower bound of the derived [`Ord`] chain, the
    /// structural anchor a downstream `<= BOTTOM` / `>= BOTTOM` reader
    /// consumes through one named oracle rather than the variant name.
    /// THEORY.md §VI.1 one-oracle / generation-over-composition: the
    /// bounded-lattice floor semantic role is named at one site (this
    /// const), so a future ladder refinement that shifts the floor
    /// updates one site, not every join-fold seed / meet-fold absorber
    /// consumer.
    #[allow(dead_code)]
    pub const BOTTOM: Self = Self::Patch;

    /// The bounded-lattice top (⊤) on the magnitude ladder — the variant
    /// at the ceiling of the derived [`Ord`] chain (`Patch < Minor <
    /// Major`). Named typed-primitive peer of [`BumpLevel::Major`] at
    /// the bounded-lattice surface, distinct from the variant-name
    /// surface: where `BumpLevel::Major` reads the semver-component
    /// semantic role ("increment the major component"),
    /// [`BumpLevel::TOP`] reads the bounded-lattice semantic role
    /// ("the ceiling of the magnitude ladder — the meet-identity, the
    /// join-absorbing element, the upper bound every variant sits at-or-
    /// below"). Mirror const of [`BumpLevel::BOTTOM`] at the floor of the
    /// same ladder, closing the bounded-lattice anchor pair at the
    /// typed-primitive surface.
    ///
    /// # The bounded-lattice axiom set (top dual)
    ///
    /// The dual of the [`BOTTOM`](Self::BOTTOM) axioms at the same
    /// ladder:
    ///
    /// - `TOP.meet(a) == a` (TOP is the meet-identity);
    /// - `TOP.join(a) == TOP` (TOP is the join-absorbing element);
    /// - `a <= TOP` at every variant (TOP is the global upper bound).
    ///
    /// Pinned by
    /// [`tests::test_bump_level_top_is_meet_identity_at_every_variant`],
    /// [`tests::test_bump_level_top_is_join_absorbing_at_every_variant`],
    /// and [`tests::test_bump_level_top_ge_every_variant`]. Together
    /// with the [`BOTTOM`](Self::BOTTOM) axioms, these close the
    /// bounded-lattice axiom set on the [`BumpLevel`] ladder at the
    /// typed-primitive surface, naming the meet/join pair as a BOUNDED
    /// DISTRIBUTIVE LATTICE rather than the unbounded distributive
    /// lattice the prior trajectory closed.
    ///
    /// # Why a named const, not the variant
    ///
    /// At the present three-variant ladder [`TOP`](Self::TOP) coincides
    /// with [`BumpLevel::Major`] (pinned by
    /// [`tests::test_bump_level_top_named_at_lattice_ceiling`] and
    /// [`tests::test_bump_level_top_equals_ladder_ceiling`]). The named
    /// [`TOP`](Self::TOP) surface carries the bounded-lattice ceiling
    /// semantic role distinct from the variant-name surface — the dual
    /// of the [`BOTTOM`](Self::BOTTOM) / [`Patch`](Self::Patch) split at
    /// the floor. A future ladder refinement that inserts an `Epoch`
    /// variant strictly above `Major` (semver4 / `0ver`-style
    /// incompatible-by-design rewrites) shifts the bounded-lattice
    /// ceiling — [`TOP`](Self::TOP) would update at this one site to
    /// `Self::Epoch`, and every consumer of "the join-fold absorber" /
    /// "the meet-fold seed" would automatically pick up the new
    /// ceiling. Same one-oracle discipline [`BOTTOM`](Self::BOTTOM)
    /// established at the floor, here applied to the ceiling.
    ///
    /// # Together with [`BOTTOM`](Self::BOTTOM)
    ///
    /// The pair [`BOTTOM`](Self::BOTTOM) / [`TOP`](Self::TOP) names the
    /// closed magnitude-ladder interval `[BOTTOM, TOP]` that contains
    /// every variant — pinned by
    /// [`tests::test_bump_level_bottom_le_top_at_lattice`] and the
    /// per-variant pins above. A downstream consumer that needs the
    /// global bounds of the magnitude ladder reads
    /// `BumpLevel::BOTTOM..=BumpLevel::TOP` once at one named oracle
    /// pair, rather than restating the variant names at every consumer
    /// site. Mirror of [`AdmissionTier`] at the admission-gate surface
    /// — the dual ladder-anchor lift the next routine can land —
    /// closing the bounded-lattice anchor pair symmetry across the two
    /// repo-internal tier ladders.
    ///
    /// THEORY.md §V.4 typed primitives: the bounded-lattice ceiling is
    /// a typed-primitive surface on [`BumpLevel`] itself (one named
    /// const). THEORY.md §V.5 total-order discipline: [`TOP`](Self::TOP)
    /// is the global upper bound of the derived [`Ord`] chain.
    /// THEORY.md §VI.1 one-oracle: the bounded-lattice ceiling semantic
    /// role is named at one site, so a future ladder refinement that
    /// shifts the ceiling updates one site.
    #[allow(dead_code)]
    pub const TOP: Self = Self::Major;

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

/// [`serde::Serialize`] impl routes through [`BumpLevel::as_str`] so a
/// downstream release-manifest YAML emit, SLSA-provenance JSON stamp,
/// or telemetry breadcrumb serialises the variant as its canonical
/// lowercase label (`"patch"`, `"minor"`, `"major"`) rather than the
/// UpperCamel variant identifier the derived [`serde::Serialize`] (via
/// `#[derive(Serialize)]`) would emit (`"Patch"`, `"Minor"`, `"Major"`)
/// — the same label axis [`std::fmt::Display`] and [`std::str::FromStr`]
/// already inhabit, now extended to the serde read/write surface at one
/// typed-primitive site.
///
/// Sibling of `serde::Serialize for AdmissionTier` (commit 22e1ae0) and
/// `serde::Serialize for PerAttemptRegion` (commit 8fd06fe) — the same
/// lift at the admission-tier and per-attempt-region ladders, routing
/// through each sum's [`as_str`] canonical-label oracle. After this
/// commit the three repo-internal ordered typed sums that carry
/// `as_str` + [`Display`](std::fmt::Display) + [`FromStr`](std::str::FromStr)
/// ([`BumpLevel`], [`crate::probe_outcome::AdmissionTier`],
/// [`crate::retry::PerAttemptRegion`]) all also carry `Serialize` +
/// `Deserialize` routing through the same canonical-label oracle,
/// closing the serde read/write surface at every ordered typed sum
/// against its shared label-axis grammar.
///
/// A future variant insertion (a `Prerelease` band strictly below
/// [`BumpLevel::Patch`], an `Epoch` ceiling strictly above
/// [`BumpLevel::Major`] for semver4 / `0ver`-style incompatible-by-
/// design rewrites) updates the [`as_str`] match body alone and every
/// serde emitter — release-manifest YAML, SLSA-provenance JSON, TOML
/// changelog stamp — automatically inherits the new canonical label
/// with no manifest schema churn per consumer.
///
/// The round-trip `level -> serialize -> deserialize` identity at every
/// [`BumpLevel::ALL`] variant is pinned by
/// [`tests::test_bump_level_serde_round_trips_through_json_at_every_variant`],
/// closing the two-oracle discipline (canonical-label emission through
/// [`as_str`], canonical-label parsing through [`std::str::FromStr`])
/// across the full serde read/write surface — the structural mirror of
/// the [`crate::probe_outcome::AdmissionTier`] serde round-trip pin at
/// the admission-tier ladder.
///
/// THEORY.md §V.4 typed primitives: the serialisation surface is a
/// typed-primitive site on [`BumpLevel`] itself (one `Serialize` impl
/// routing through the [`as_str`] canonical-label oracle), not a
/// per-consumer `#[derive(Serialize)]` + `#[serde(rename_all = "lowercase")]`
/// retyping that would fragment the label-axis definition across every
/// downstream consumer's release-manifest struct. THEORY.md §VI.1
/// one-oracle: the canonical label is named at one site
/// ([`BumpLevel::as_str`]) and every surface — `as_str`, `Display`,
/// this `Serialize`, `Deserialize`, `FromStr` — reads through it.
impl serde::Serialize for BumpLevel {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

/// [`serde::Deserialize`] impl routes through [`std::str::FromStr`] so
/// a downstream release-manifest YAML load, changelog TOML replay, or
/// SLSA-provenance JSON rehydration recovers the [`BumpLevel`] variant
/// from the same canonical lowercase grammar [`BumpLevel::as_str`]
/// emits — no per-consumer `#[serde(rename)]` matrix, no drift between
/// the serialised value a release-pipeline stage stamped and the
/// deserialised variant a downstream release-notes generator reads
/// back.
///
/// Sibling of `serde::Deserialize for AdmissionTier` (commit 22e1ae0)
/// and `serde::Deserialize for PerAttemptRegion` (commit 8fd06fe) —
/// the same lift at the admission-tier and per-attempt-region ladders,
/// routing through each sum's [`std::str::FromStr`] impl. Together
/// with the paired `serde::Serialize` impl above, this closes the
/// `Serialize`↔`Deserialize` round-trip at the version-bump-magnitude
/// ladder against the shared [`as_str`] / [`std::str::FromStr`]
/// canonical-label oracle.
///
/// The parser is strict for the same reason [`std::str::FromStr`] is:
/// only the canonical labels emitted by [`BumpLevel::as_str`] parse.
/// Empty input, UpperCamel rendering (as the derived [`Debug`] impl
/// would emit — `"Patch"`, `"Minor"`, `"Major"`), whitespace padding,
/// uppercase (`"MAJOR"`), and abbreviations (`"maj"`, `"p"`) all
/// reject with the byte-identical error wording the prior in-line
/// [`bump_semver`] match-arm trap emitted. Non-string JSON/YAML
/// scalars (numbers, booleans, nulls, objects, arrays) reject at the
/// [`serde::Deserialize`] visitor layer with the standard "invalid
/// type" diagnostic — a downstream surface that wants alias matrix,
/// whitespace tolerance, or numeric-tag support normalises the input
/// before routing it through this canonical parser.
///
/// The round-trip `level -> serialize -> deserialize` identity at
/// every [`BumpLevel::ALL`] variant is pinned by
/// [`tests::test_bump_level_serde_round_trips_through_json_at_every_variant`].
/// The strict-parse behaviour on unknown labels is pinned by
/// [`tests::test_bump_level_deserialize_rejects_unknown_string`].
///
/// THEORY.md §V.4 typed primitives: the deserialisation surface is a
/// typed-primitive site on [`BumpLevel`] itself (one `Deserialize`
/// impl routing through the [`std::str::FromStr`] canonical-label
/// parser), not a per-consumer `#[derive(Deserialize)]` +
/// `#[serde(rename_all)]` retyping. THEORY.md §VI.1 one-oracle:
/// canonical-label parsing lives at one site ([`std::str::FromStr`]
/// for [`BumpLevel`]) and every read surface — `FromStr`, this
/// `Deserialize`, a future TOML changelog loader, a future MessagePack
/// telemetry replay — reads through it.
impl<'de> serde::Deserialize<'de> for BumpLevel {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = <&str as serde::Deserialize>::deserialize(deserializer)?;
        s.parse::<Self>().map_err(serde::de::Error::custom)
    }
}

/// [`AsRef<str>`] impl routes through [`BumpLevel::as_str`] so a
/// downstream consumer that accepts `impl AsRef<str>` (a path-segment
/// builder assembling a release-manifest key, a version-tag env-var
/// setter, a [`std::collections::HashMap<&str, _>`] keyed by bump
/// magnitude, a generic log-fields sink, an OpenTelemetry / tracing
/// attribute setter that keys by `Into<Cow<'static, str>>`) reads the
/// canonical lowercase label (`"patch"`, `"minor"`, `"major"`)
/// directly from a [`BumpLevel`] value without going through the
/// [`std::fmt::Display`] formatter buffer or an intermediate [`String`]
/// allocation. The zero-cost byte-slice-coercion peer of the
/// format-machinery [`std::fmt::Display`] surface, both routing
/// through the same [`BumpLevel::as_str`] canonical-label oracle.
///
/// Sibling of the [`std::fmt::Display`], [`std::str::FromStr`],
/// [`serde::Serialize`], and [`serde::Deserialize`] impls above — the
/// same lift at the byte-slice-access layer instead of the format /
/// parse / serde layers. Together with the impls above this closes
/// the `as_str` ⇢ {`Display`, `AsRef<str>`, `Serialize`} emission
/// triangle and the {`FromStr`, `Deserialize`} parse pair at the
/// version-bump-magnitude ladder against the shared canonical-label
/// oracle. Structural mirror of `impl AsRef<str> for AdmissionTier`
/// (commit 7acca19 — the same lift at the admission-tier ladder,
/// routing through [`crate::probe_outcome::AdmissionTier::as_str`])
/// and `impl AsRef<str> for PerAttemptRegion` (commit 8c8cffe — the
/// same lift at the per-attempt-region ladder, routing through
/// [`crate::retry::PerAttemptRegion::as_str`]). After this commit
/// all three repo-internal ordered typed sums that carry
/// `as_str` + [`Display`](std::fmt::Display) +
/// [`FromStr`](std::str::FromStr) + [`serde::Serialize`] +
/// [`serde::Deserialize`] ([`BumpLevel`],
/// [`crate::probe_outcome::AdmissionTier`],
/// [`crate::retry::PerAttemptRegion`]) also carry [`AsRef<str>`]
/// routing through the shared canonical-label oracle — the label-axis
/// grammar at every ordered typed sum is now a one-oracle surface at
/// every Rust-idiomatic reading (direct call `as_str`, format
/// machinery [`std::fmt::Display`], byte slice [`AsRef<str>`], string
/// parse [`std::str::FromStr`], serde [`serde::Serialize`] /
/// [`serde::Deserialize`]).
///
/// Zero-cost by construction: the returned `&str` is `'static`
/// (delegated from [`BumpLevel::as_str`]'s `&'static str` return
/// type), so a consumer that borrows the slice reads directly into
/// the static-string constant table without a copy, matching the
/// zero-allocation discipline [`std::fmt::Display`] doesn't offer
/// (which writes through a [`std::fmt::Formatter`] into a
/// caller-provided buffer).
///
/// A future variant insertion (a `Prerelease` band strictly below
/// [`BumpLevel::Patch`], an `Epoch` ceiling strictly above
/// [`BumpLevel::Major`] for semver4 / `0ver`-style incompatible-by-
/// design rewrites) updates the [`as_str`] match body alone and every
/// consumer — release-manifest path-segment builder, changelog-tag
/// env-var setter, SLSA-provenance attribute-key stamper — that
/// accepts `impl AsRef<str>` inherits the new canonical label
/// automatically with no downstream retyping.
///
/// The identity `level.as_ref() == level.as_str()` at every
/// [`BumpLevel::ALL`] variant is pinned by
/// [`tests::test_bump_level_as_ref_str_agrees_with_as_str`]; the
/// identity carrying through a generic `impl AsRef<str>` consumer at
/// every variant is pinned by
/// [`tests::test_bump_level_as_ref_str_carries_through_generic_consumer`].
///
/// THEORY.md §V.4 typed primitives: the byte-slice-coercion surface
/// is a typed-primitive site on [`BumpLevel`] itself (one `AsRef<str>`
/// impl routing through [`BumpLevel::as_str`]), not a per-consumer
/// `.as_str()` restatement at every downstream site that accepts
/// `impl AsRef<str>`. THEORY.md §VI.1 one-oracle: the canonical label
/// is named at one site ([`BumpLevel::as_str`]) and every surface —
/// `as_str`, `Display`, `Serialize`, `FromStr`, `Deserialize`, this
/// `AsRef<str>` — reads through it.
impl AsRef<str> for BumpLevel {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

/// [`AsRef<[u8]>`] routes through
/// `<BumpLevel as AsRef<str>>::as_ref` composed with
/// [`str::as_bytes`] at the canonical-label oracle so a downstream
/// consumer that takes a borrowed byte-slice view via
/// [`AsRef<[u8]>`] (a `blake3` / `sha2` streaming hasher `update`
/// slot, a byte-oriented [`std::io::Write`] sink, a
/// [`std::collections::HashMap<Box<[u8]>, _>`] key lookup that
/// hashes canonical labels as UTF-8 byte sequences, an
/// [`std::os::unix::ffi::OsStrExt`] label bridge, a memchr-driven
/// classifier over canonical labels) reads the canonical
/// lowercase label (`"patch"`, `"minor"`, `"major"`) as a
/// borrowed `&[u8]` view of the static-lifetime label constant
/// without a [`String`] allocation, a [`Vec<u8>`] copy, or an
/// intermediate [`std::fmt::Display`] format-buffer step.
///
/// Sibling of [`AsRef<str>`] directly above — the same borrowed-
/// view surface at the same canonical-label oracle, projected onto
/// the byte-slice frontier instead of the UTF-8 string frontier.
/// Extends the borrowed-view axis at the bump-level ladder
/// parallel to the [`AsRef<str>`] surface: the [`AsRef<str>`] impl
/// yields `&str`, this [`AsRef<[u8]>`] impl yields `&[u8]` — the
/// same routing discipline (`self.as_str().as_bytes()` == one
/// composition through [`BumpLevel::as_str`] and
/// [`str::as_bytes`], both zero-copy views of the static-lifetime
/// label constant) so a future consumer that requires the byte-
/// slice frontier reads the canonical label through one typed-
/// primitive surface at the same oracle instead of restating the
/// two-step `level.as_str().as_bytes()` composition at every call
/// site. The natural bridge to consumers that work over the byte-
/// slice frontier at the borrowed-view axis: streaming hashers
/// (`blake3::Hasher::update`, `sha2::Sha256::update`,
/// `blake2::Blake2b::update`, etc.) take [`impl AsRef<[u8]>`] as
/// their standard input surface, so a consumer that hashes a
/// canonical [`BumpLevel`] label reads it directly from a
/// [`BumpLevel`] value without an [`str::as_bytes`] restatement
/// at the hash boundary.
///
/// Closing peer of the byte-slice borrowed-view trio: the
/// opening peer at the per-attempt-region ladder is
/// `impl AsRef<[u8]> for` [`crate::retry::PerAttemptRegion`]
/// (commit af44439); the mid-trio peer at the admission-tier
/// ladder is `impl AsRef<[u8]> for`
/// [`crate::probe_outcome::AdmissionTier`] (commit 13abcc4). This
/// commit matches the [`AsRef<str>`] closure order
/// (8c8cffe → 7acca19 → f1ca293), closing the byte-slice
/// borrowed-view surface across all three canonical-label typed
/// primitives on the ladder set against ONE canonical-label
/// oracle each.
///
/// Zero-cost by construction: the returned `&[u8]` is a
/// zero-length-check-free view of the static-lifetime label
/// constant table's UTF-8 bytes — [`str::as_bytes`] is a zero-cost
/// transmute at the borrow-view boundary, no allocation, no copy,
/// no branching over the variant discriminant beyond what
/// [`BumpLevel::as_str`] itself does at its match body.
///
/// The identity `<BumpLevel as AsRef<[u8]>>::as_ref(&level)
/// == level.as_str().as_bytes()` at every [`BumpLevel::ALL`]
/// variant is pinned by
/// [`tests::test_bump_level_as_ref_bytes_agrees_with_as_str_as_bytes`];
/// the identity carried through a generic `impl AsRef<[u8]>`
/// consumer at every variant is pinned by
/// [`tests::test_bump_level_as_ref_bytes_carries_through_generic_consumer`];
/// the round-trip through [`std::str::from_utf8`] recovering the
/// canonical label at every variant is pinned by
/// [`tests::test_bump_level_as_ref_bytes_round_trips_through_from_utf8`].
///
/// THEORY.md §V.4 typed primitives: the byte-slice borrowed-view
/// surface is a typed-primitive site on [`BumpLevel`] itself
/// (one `AsRef<[u8]>` impl routing through [`AsRef<str>`] and
/// [`str::as_bytes`]), not a per-consumer `level.as_str().as_bytes()`
/// restatement at every downstream site that accepts
/// `impl AsRef<[u8]>`. THEORY.md §VI.1 one-oracle: the canonical
/// label is named at one site ([`BumpLevel::as_str`]) and every
/// borrowed-view surface — [`AsRef<str>`] (yields `&str`), this
/// [`AsRef<[u8]>`] (yields `&[u8]`) — reads through it.
impl AsRef<[u8]> for BumpLevel {
    fn as_ref(&self) -> &[u8] {
        <Self as AsRef<str>>::as_ref(self).as_bytes()
    }
}

/// [`AsRef<std::ffi::OsStr>`] routes through
/// `<BumpLevel as AsRef<str>>::as_ref` composed with
/// [`std::ffi::OsStr::new`] at the canonical-label oracle so a
/// downstream consumer that takes a borrowed OS-string view via
/// [`AsRef<std::ffi::OsStr>`] (a [`std::process::Command::env`] /
/// [`std::process::Command::arg`] / [`std::process::Command::current_dir`]
/// slot that keys by [`AsRef<std::ffi::OsStr>`], a
/// [`std::env::set_var`] / [`std::env::var_os`] telemetry-key bridge,
/// a [`std::path::PathBuf::push`] / [`std::fs::create_dir`] path-
/// segment component built from a canonical bump-level label, a
/// [`std::ffi::OsString::push`] sink over a caller-owned buffer)
/// reads the canonical lowercase label (`"patch"`, `"minor"`,
/// `"major"`) as a borrowed `&OsStr` view of the static-lifetime
/// label constant without a [`String`] allocation, an
/// [`std::ffi::OsString`] copy, or an intermediate
/// [`std::fmt::Display`] format-buffer step.
///
/// Sibling of [`AsRef<str>`] and [`AsRef<[u8]>`] directly above —
/// the same borrowed-view surface at the same canonical-label
/// oracle, projected onto the OS-string frontier instead of the
/// UTF-8 string frontier or the byte-slice frontier. Extends the
/// borrowed-view axis at the bump-level ladder parallel to the
/// [`AsRef<str>`] and [`AsRef<[u8]>`] surfaces: the [`AsRef<str>`]
/// impl yields `&str`, the [`AsRef<[u8]>`] impl yields `&[u8]`,
/// this [`AsRef<std::ffi::OsStr>`] impl yields `&OsStr` — the same
/// routing discipline (`OsStr::new(self.as_str())` == one
/// composition through [`BumpLevel::as_str`] and
/// [`std::ffi::OsStr::new`], both zero-copy views of the static-
/// lifetime label constant on Unix and a valid WTF-8 view of the
/// same UTF-8 bytes on Windows since the labels are pure ASCII) so
/// a future consumer that requires the OS-string frontier reads the
/// canonical label through one typed-primitive surface at the same
/// oracle instead of restating the two-step
/// `OsStr::new(level.as_str())` composition at every call site.
///
/// The natural bridge to consumers that work over the OS-string
/// frontier at the borrowed-view axis: process-spawn machinery
/// ([`std::process::Command::env`], [`std::process::Command::arg`],
/// [`std::process::Command::current_dir`]), environment machinery
/// ([`std::env::set_var`], [`std::env::var_os`]), and filesystem
/// path components (a canonical [`BumpLevel`] label used as a
/// release-manifest directory or file segment via
/// [`std::path::PathBuf::push`]) all take
/// [`impl AsRef<std::ffi::OsStr>`] as their standard input surface,
/// so a consumer that hands a canonical [`BumpLevel`] label to any
/// of these boundaries reads it directly from a [`BumpLevel`] value
/// without an [`std::ffi::OsStr::new`] restatement at the boundary.
///
/// Closing peer of the OS-string borrowed-view trio: the opening
/// peer at the per-attempt-region ladder is
/// `impl AsRef<std::ffi::OsStr> for` [`crate::retry::PerAttemptRegion`]
/// (commit 70e1ab5); the mid-trio peer at the admission-tier ladder
/// is `impl AsRef<std::ffi::OsStr> for`
/// [`crate::probe_outcome::AdmissionTier`] (commit 1d708f4). This
/// commit matches the [`AsRef<[u8]>`] closure order
/// (af44439 → 13abcc4 → 833d706) and the [`AsRef<str>`] closure
/// order (8c8cffe → 7acca19 → f1ca293), closing the OS-string
/// borrowed-view surface across all three canonical-label typed
/// primitives on the ladder set against ONE canonical-label oracle
/// each.
///
/// Zero-cost by construction: the returned `&OsStr` is a
/// zero-length-check-free view of the static-lifetime label
/// constant table's UTF-8 bytes — [`std::ffi::OsStr::new`] on a
/// `&str` is a zero-cost transmute at the borrow-view boundary
/// (on Unix, `OsStr` is a `[u8]` newtype; on Windows, `OsStr` is a
/// WTF-8 slice which is a strict superset of UTF-8, so a valid
/// `&str` is always a valid `&OsStr`), no allocation, no copy, no
/// branching over the variant discriminant beyond what
/// [`BumpLevel::as_str`] itself does at its match body.
///
/// The identity `<BumpLevel as AsRef<std::ffi::OsStr>>::as_ref(&level)
/// == std::ffi::OsStr::new(level.as_str())` at every
/// [`BumpLevel::ALL`] variant is pinned by
/// [`tests::test_bump_level_as_ref_osstr_agrees_with_as_str`]; the
/// identity carried through a generic
/// `impl AsRef<std::ffi::OsStr>` consumer at every variant is
/// pinned by
/// [`tests::test_bump_level_as_ref_osstr_carries_through_generic_consumer`];
/// the round-trip through [`std::ffi::OsStr::to_str`] recovering
/// the canonical label at every variant is pinned by
/// [`tests::test_bump_level_as_ref_osstr_round_trips_through_to_str`].
///
/// THEORY.md §V.4 typed primitives: the OS-string borrowed-view
/// surface is a typed-primitive site on [`BumpLevel`] itself
/// (one `AsRef<std::ffi::OsStr>` impl routing through
/// [`AsRef<str>`] and [`std::ffi::OsStr::new`]), not a per-consumer
/// `OsStr::new(level.as_str())` restatement at every downstream
/// site that accepts `impl AsRef<std::ffi::OsStr>`. THEORY.md
/// §VI.1 one-oracle: the canonical label is named at one site
/// ([`BumpLevel::as_str`]) and every borrowed-view surface —
/// [`AsRef<str>`] (yields `&str`), [`AsRef<[u8]>`] (yields
/// `&[u8]`), this [`AsRef<std::ffi::OsStr>`] (yields `&OsStr`) —
/// reads through it.
impl AsRef<std::ffi::OsStr> for BumpLevel {
    fn as_ref(&self) -> &std::ffi::OsStr {
        std::ffi::OsStr::new(<Self as AsRef<str>>::as_ref(self))
    }
}

/// Zero-copy borrowed filesystem-path view of the canonical
/// lowercase label (`"patch"`, `"minor"`, `"major"`) at the
/// [`std::path::Path`] frontier — a downstream consumer bound
/// by `impl AsRef<std::path::Path>` (a [`std::fs::create_dir`] /
/// [`std::fs::create_dir_all`] name component, a
/// [`std::fs::read_dir`] entry key, a
/// [`std::path::PathBuf::push`] / [`std::path::PathBuf::join`]
/// path segment, a [`std::fs::File::open`] /
/// [`std::fs::File::create`] path argument, a
/// [`std::fs::metadata`] / [`std::fs::remove_dir_all`] input, a
/// [`std::path::PathBuf::from`] sink over a caller-owned buffer)
/// reads the canonical lowercase label as a borrowed
/// `&std::path::Path` view of the static-lifetime label constant
/// without a [`String`] allocation, a [`std::path::PathBuf`]
/// copy, or an intermediate [`std::fmt::Display`] format-buffer
/// step.
///
/// Sibling of [`AsRef<str>`] (commit f1ca293), [`AsRef<[u8]>`]
/// (commit 833d706), and [`AsRef<std::ffi::OsStr>`] (commit
/// 242ed89) above — the same borrowed-view surface at the same
/// canonical-label oracle, projected onto the filesystem-path
/// frontier instead of the UTF-8 string frontier, the byte-slice
/// frontier, or the OS-string frontier. Closing peer at the
/// third ordered typed sum of the filesystem-path borrowed-view
/// trio: `AsRef<Path>` for [`crate::retry::PerAttemptRegion`]
/// (commit 17718d2) opened the trio at the first typed sum;
/// `AsRef<Path>` for [`crate::probe_outcome::AdmissionTier`]
/// (commit f6c4c75) is the mid-trio peer at the second typed
/// sum; this commit closes it at the third, matching the
/// [`AsRef<std::ffi::OsStr>`] closing order
/// (70e1ab5 → 1d708f4 → 242ed89), the [`AsRef<[u8]>`] closing
/// order (af44439 → 13abcc4 → 833d706), and the [`AsRef<str>`]
/// closing order (8c8cffe → 7acca19 → f1ca293). The
/// [`AsRef<str>`] impl yields `&str`, the [`AsRef<[u8]>`] impl
/// yields `&[u8]`, the [`AsRef<std::ffi::OsStr>`] impl yields
/// `&OsStr`, this [`AsRef<std::path::Path>`] impl yields
/// `&Path` — the same routing discipline
/// (`Path::new(self.as_str())` == one composition through
/// [`BumpLevel::as_str`] and [`std::path::Path::new`], both
/// zero-copy views of the static-lifetime label constant since
/// [`std::path::Path`] is an [`std::ffi::OsStr`] newtype on
/// every supported platform) so a future consumer that requires
/// the filesystem-path frontier reads the canonical label
/// through one typed-primitive surface at the same oracle
/// instead of restating the two-step `Path::new(level.as_str())`
/// composition at every call site.
///
/// The natural bridge to consumers that work over the filesystem-
/// path frontier at the borrowed-view axis: directory-creation
/// machinery ([`std::fs::create_dir`],
/// [`std::fs::create_dir_all`]), directory-enumeration machinery
/// ([`std::fs::read_dir`]), path-composition machinery
/// ([`std::path::PathBuf::push`], [`std::path::PathBuf::join`]),
/// file-open machinery ([`std::fs::File::open`],
/// [`std::fs::File::create`]), and metadata machinery
/// ([`std::fs::metadata`], [`std::fs::symlink_metadata`],
/// [`std::fs::remove_dir_all`]) all take
/// [`impl AsRef<std::path::Path>`] as their standard input
/// surface, so a consumer that hands a canonical [`BumpLevel`]
/// label to any of these boundaries reads it directly from a
/// [`BumpLevel`] value without a [`std::path::Path::new`]
/// restatement at the boundary — a per-bump-magnitude-scoped
/// release-manifest directory (`release_root.join(level)`), a
/// per-bump-magnitude-scoped changelog artifact
/// (`std::fs::File::create(changelog_root.join(level))`), or a
/// per-bump-magnitude-scoped metadata probe reads directly from
/// a [`BumpLevel`] value at these boundaries.
///
/// Closing peer of the filesystem-path borrowed-view trio: the
/// opening peer at the per-attempt-region ladder is
/// `impl AsRef<std::path::Path> for`
/// [`crate::retry::PerAttemptRegion`] (commit 17718d2); the
/// mid-trio peer at the admission-tier ladder is
/// `impl AsRef<std::path::Path> for`
/// [`crate::probe_outcome::AdmissionTier`] (commit f6c4c75).
/// After this commit the filesystem-path borrowed-view surface
/// is closed across all three canonical-label typed primitives
/// on the ladder set against ONE canonical-label oracle each,
/// alongside the closed [`AsRef<str>`], [`AsRef<[u8]>`], and
/// [`AsRef<std::ffi::OsStr>`] borrowed-view surfaces — the
/// borrowed-view axis is now a four-frontier closure at every
/// ordered typed sum in the ladder set.
///
/// Zero-cost by construction: the returned `&Path` is a view of
/// the static-lifetime label constant table's UTF-8 bytes —
/// [`std::path::Path::new`] on an [`AsRef<std::ffi::OsStr>`]
/// input is a zero-cost transmute at the borrow-view boundary
/// ([`std::path::Path`] is an [`std::ffi::OsStr`] newtype on
/// every supported platform), no allocation, no copy, no
/// branching over the variant discriminant beyond what
/// [`BumpLevel::as_str`] itself does at its match body.
///
/// The identity `<BumpLevel as AsRef<std::path::Path>>::as_ref(&level)
/// == std::path::Path::new(level.as_str())` at every
/// [`BumpLevel::ALL`] variant is pinned by
/// [`tests::test_bump_level_as_ref_path_agrees_with_as_str`];
/// the identity carried through a generic
/// `impl AsRef<std::path::Path>` consumer at every variant is
/// pinned by
/// [`tests::test_bump_level_as_ref_path_carries_through_generic_consumer`];
/// the round-trip through [`std::path::Path::to_str`] recovering
/// the canonical label at every variant is pinned by
/// [`tests::test_bump_level_as_ref_path_round_trips_through_to_str`].
///
/// THEORY.md §V.4 typed primitives: the filesystem-path borrowed-
/// view surface is a typed-primitive site on [`BumpLevel`]
/// itself (one `AsRef<std::path::Path>` impl routing through
/// [`AsRef<str>`] and [`std::path::Path::new`]), not a
/// per-consumer `Path::new(level.as_str())` restatement at every
/// downstream site that accepts `impl AsRef<std::path::Path>`.
/// THEORY.md §VI.1 one-oracle: the canonical label is named at
/// one site ([`BumpLevel::as_str`]) and every borrowed-view
/// surface — [`AsRef<str>`] (yields `&str`), [`AsRef<[u8]>`]
/// (yields `&[u8]`), [`AsRef<std::ffi::OsStr>`] (yields
/// `&OsStr`), this [`AsRef<std::path::Path>`] (yields `&Path`) —
/// reads through it.
impl AsRef<std::path::Path> for BumpLevel {
    fn as_ref(&self) -> &std::path::Path {
        std::path::Path::new(<Self as AsRef<str>>::as_ref(self))
    }
}

/// [`From<BumpLevel> for std::ffi::OsString`] routes through
/// [`BumpLevel::as_str`] composed with [`std::ffi::OsString::from`]
/// so a downstream consumer bound by `impl Into<std::ffi::OsString>`
/// (a [`std::process::Command::env`] owned key/value slot, a
/// [`std::env::set_var`] owned key, a
/// [`std::path::PathBuf::push`] segment consumer, a
/// [`std::collections::HashMap<std::ffi::OsString, _>::insert`]
/// key builder, a serde container that opts into
/// `#[serde(into = "OsString")]` on a wrapper field) recovers the
/// canonical lowercase label (`"patch"`, `"minor"`, `"major"`) as
/// an owned [`std::ffi::OsString`] directly from a [`BumpLevel`]
/// value without a per-consumer `OsString::from(level.as_str())`
/// two-step restatement at every by-value boundary.
///
/// Closing peer at the third ordered typed sum of the owned-buffer
/// OS-string emit trio: `From<PerAttemptRegion> for
/// std::ffi::OsString` (commit 976f5af) opened the trio at the
/// first typed sum; `From<AdmissionTier> for std::ffi::OsString`
/// (commit 0791fc7) carried the mid-trio slot at the second typed
/// sum; this commit closes the trio at the third, matching the
/// [`AsRef<std::ffi::OsStr>`] closing order (70e1ab5 → 1d708f4 →
/// 242ed89), the [`AsRef<std::path::Path>`] closing order
/// (17718d2 → f6c4c75 → dfd887a), the [`From<T> for Vec<u8>`]
/// closing order (2ad52bc → 491db4d → 6701191), and the
/// [`From<T> for String`] closing order at the UTF-8 owned-buffer
/// frontier. The by-value owned peer of [`AsRef<std::ffi::OsStr>`]
/// above — both are OS-string surfaces at the same canonical-
/// label oracle, differing only on the receiver's ownership:
/// [`AsRef<std::ffi::OsStr>`] yields `&OsStr` for consumers that
/// already hold a borrow, this [`From<BumpLevel> for
/// std::ffi::OsString`] yields [`std::ffi::OsString`] for
/// consumers that own the input buffer. The str-frontier parallel
/// is [`AsRef<str>`] → [`From<BumpLevel> for String`]; the byte-
/// slice-frontier parallel is [`AsRef<[u8]>`] →
/// [`From<BumpLevel> for Vec<u8>`]; this [`AsRef<OsStr>`] →
/// [`From<BumpLevel> for OsString`] closes the same borrowed-view
/// → owned-buffer emit peer at the OS-string frontier at the
/// version-bump-magnitude ladder.
///
/// After this commit the owned-buffer emit axis spans BOTH the
/// UTF-8 string frontier ([`From<T> for String`]), the byte-slice
/// frontier ([`From<T> for Vec<u8>`]), and the OS-string frontier
/// ([`From<T> for std::ffi::OsString`]) across all three ordered
/// typed sums on the ladder set against ONE canonical-label
/// oracle each — a three-frontier × three-typed-sum closure at
/// the by-value owned-buffer emit axis.
///
/// The natural bridge to consumers that work over the OS-string
/// frontier at the owned-buffer axis: process-environment
/// machinery ([`std::process::Command::env`],
/// [`std::env::set_var`]), owned-key hash-map machinery
/// ([`std::collections::HashMap<std::ffi::OsString, _>::insert`]),
/// path-composition machinery over an owned buffer
/// ([`std::path::PathBuf::push`]), and serde
/// `#[serde(into = "OsString")]` wrappers all take
/// [`impl Into<std::ffi::OsString>`] as their standard input
/// surface, so a consumer that hands a canonical [`BumpLevel`]
/// label to any of these boundaries reads it directly from a
/// [`BumpLevel`] value without a
/// [`std::ffi::OsString::from`]-plus-[`BumpLevel::as_str`]
/// two-step restatement at the boundary — a per-bump-magnitude-
/// scoped release-manifest environment variable
/// (`Command::env("BUMP_LEVEL", level)`), a per-bump-magnitude
/// process-scope side effect (`env::set_var("BUMP_LEVEL", level)`),
/// or a per-bump-magnitude telemetry index
/// (`HashMap::<OsString, T>::insert(level.into(), ...)`) reads
/// directly from a [`BumpLevel`] value at these boundaries.
///
/// The identity `std::ffi::OsString::from(level) ==
/// std::ffi::OsString::from(level.as_str())` at every
/// [`BumpLevel::ALL`] variant is pinned by
/// [`tests::test_bump_level_from_into_osstring_agrees_with_as_str`];
/// the identity carried through a generic
/// `impl Into<std::ffi::OsString>` consumer at every variant is
/// pinned by
/// [`tests::test_bump_level_into_osstring_carries_through_generic_consumer`];
/// the round-trip through [`std::ffi::OsString::into_string`]
/// recovering the canonical label at every variant is pinned by
/// [`tests::test_bump_level_from_into_osstring_round_trips_through_into_string`].
///
/// THEORY.md §V.4 typed primitives: the by-value owned OS-string
/// emit surface is a typed-primitive site on [`BumpLevel`]
/// itself (one `From<BumpLevel> for std::ffi::OsString` impl
/// routing through [`BumpLevel::as_str`] and
/// [`std::ffi::OsString::from`]), not a per-consumer
/// `OsString::from(level.as_str())` restatement at every
/// downstream site that accepts `impl Into<std::ffi::OsString>`.
/// THEORY.md §VI.1 one-oracle: the canonical label is named at
/// one site ([`BumpLevel::as_str`]) and every owned-buffer
/// emit surface — [`From<T> for String`] (yields [`String`]),
/// [`From<T> for Vec<u8>`] (yields [`Vec<u8>`]), this
/// [`From<T> for std::ffi::OsString`] (yields
/// [`std::ffi::OsString`]) — reads through it.
impl From<BumpLevel> for std::ffi::OsString {
    fn from(level: BumpLevel) -> std::ffi::OsString {
        std::ffi::OsString::from(level.as_str())
    }
}

/// [`From<BumpLevel> for std::path::PathBuf`] routes through
/// [`BumpLevel::as_str`] composed with
/// [`std::path::PathBuf::from`] so a downstream consumer bound by
/// `impl Into<std::path::PathBuf>` (a
/// [`std::path::PathBuf::push`] segment consumer that owns its
/// receiver, a [`std::path::PathBuf::join`] argument that owns
/// its input, a [`std::fs::create_dir_all`] argument via
/// [`std::path::PathBuf`], a
/// [`std::collections::HashMap<std::path::PathBuf, _>::insert`]
/// key builder, a serde container that opts into
/// `#[serde(into = "PathBuf")]` on a wrapper field) recovers the
/// canonical lowercase label (`"patch"`, `"minor"`, `"major"`)
/// as an owned [`std::path::PathBuf`] directly from a
/// [`BumpLevel`] value without a per-consumer
/// `PathBuf::from(level.as_str())` two-step restatement at every
/// by-value boundary.
///
/// Closing peer at the third ordered typed sum of the owned-
/// buffer filesystem-path emit trio: `From<PerAttemptRegion> for
/// std::path::PathBuf` (commit 6333c31) opened the trio at the
/// first typed sum; `From<AdmissionTier> for std::path::PathBuf`
/// (commit 75a37d4) carried the mid-trio slot at the second
/// typed sum; this commit closes the trio at the third, matching
/// the [`AsRef<std::path::Path>`] closing order (17718d2 →
/// f6c4c75 → dfd887a), the [`From<T> for std::ffi::OsString`]
/// closing order (976f5af → 0791fc7 → b069eec), the
/// [`From<T> for Vec<u8>`] closing order (2ad52bc → 491db4d →
/// 6701191), and the [`From<T> for String`] closing order at the
/// UTF-8 owned-buffer frontier. The by-value owned peer of
/// [`AsRef<std::path::Path>`] above — both are filesystem-path
/// surfaces at the same canonical-label oracle, differing only
/// on the receiver's ownership: [`AsRef<std::path::Path>`]
/// yields `&Path` for consumers that already hold a borrow, this
/// [`From<BumpLevel> for std::path::PathBuf`] yields
/// [`std::path::PathBuf`] for consumers that own the input
/// buffer. The str-frontier parallel is
/// [`AsRef<str>`] → [`From<BumpLevel> for String`]; the byte-
/// slice-frontier parallel is [`AsRef<[u8]>`] →
/// [`From<BumpLevel> for Vec<u8>`]; the OS-string-frontier
/// parallel is [`AsRef<std::ffi::OsStr>`] →
/// [`From<BumpLevel> for std::ffi::OsString`]; this
/// [`AsRef<std::path::Path>`] →
/// [`From<BumpLevel> for std::path::PathBuf`] closes the same
/// borrowed-view → owned-buffer emit peer at the filesystem-
/// path frontier at the version-bump-magnitude ladder.
///
/// After this commit the owned-buffer emit axis spans the UTF-8
/// string frontier ([`From<T> for String`]), the byte-slice
/// frontier ([`From<T> for Vec<u8>`]), the OS-string frontier
/// ([`From<T> for std::ffi::OsString`]), and the filesystem-path
/// frontier ([`From<T> for std::path::PathBuf`]) across all
/// three ordered typed sums on the ladder set against ONE
/// canonical-label oracle each — a four-frontier × three-typed-
/// sum closure at the by-value owned-buffer emit axis, matching
/// the four-frontier × three-typed-sum closure at the borrowed-
/// view axis (dfd887a).
///
/// The natural bridge to consumers that work over the filesystem-
/// path frontier at the owned-buffer emit axis: directory-
/// composition machinery ([`std::path::PathBuf::push`],
/// [`std::path::PathBuf::join`]) that owns its receiver,
/// directory-creation machinery ([`std::fs::create_dir_all`])
/// that owns its argument, keyed-index machinery
/// ([`std::collections::HashMap<std::path::PathBuf, _>::insert`],
/// [`std::collections::BTreeMap<std::path::PathBuf, _>::insert`])
/// that owns its key, and serde container round-trip machinery
/// (`#[serde(into = "PathBuf")]`) that owns its serialized
/// shape, so a consumer that hands a canonical [`BumpLevel`]
/// label to any of these boundaries reads it directly from a
/// [`BumpLevel`] value without a `PathBuf::from(level.as_str())`
/// restatement at the boundary — a per-bump-magnitude-scoped
/// release-manifest directory keyed by owned
/// [`std::path::PathBuf`]
/// (`manifest_dir_map.insert(level.into(), events)`), a per-
/// bump-magnitude-scoped artifact directory that owns the
/// segment (`let mut p = release_root.clone(); p.push(level);`
/// against an owned [`std::path::PathBuf`] slot), or a per-bump-
/// magnitude-scoped serde container that opts into
/// `#[serde(into = "PathBuf")]` on a filesystem-path field reads
/// directly from a [`BumpLevel`] value at these boundaries.
///
/// The identity `std::path::PathBuf::from(level) ==
/// std::path::PathBuf::from(level.as_str())` at every
/// [`BumpLevel::ALL`] variant is pinned by
/// [`tests::test_bump_level_from_into_pathbuf_agrees_with_as_str`];
/// the identity carried through a generic
/// `impl Into<std::path::PathBuf>` consumer at every variant is
/// pinned by
/// [`tests::test_bump_level_into_pathbuf_carries_through_generic_consumer`];
/// the round-trip through [`std::path::PathBuf::into_os_string`]
/// then [`std::ffi::OsString::into_string`] recovering the
/// canonical label at every variant is pinned by
/// [`tests::test_bump_level_from_into_pathbuf_round_trips_through_into_os_string`].
///
/// THEORY.md §V.4 typed primitives: the by-value owned filesystem-
/// path emit surface is a typed-primitive site on [`BumpLevel`]
/// itself (one `From<BumpLevel> for std::path::PathBuf` impl
/// routing through [`BumpLevel::as_str`] and
/// [`std::path::PathBuf::from`]), not a per-consumer
/// `PathBuf::from(level.as_str())` restatement at every
/// downstream site that accepts `impl Into<std::path::PathBuf>`.
/// THEORY.md §VI.1 one-oracle: the canonical label is named at
/// one site ([`BumpLevel::as_str`]) and every owned-buffer
/// emit surface — [`From<T> for String`] (yields [`String`]),
/// [`From<T> for Vec<u8>`] (yields [`Vec<u8>`]),
/// [`From<T> for std::ffi::OsString`] (yields
/// [`std::ffi::OsString`]), this
/// [`From<T> for std::path::PathBuf`] (yields
/// [`std::path::PathBuf`]) — reads through it.
impl From<BumpLevel> for std::path::PathBuf {
    fn from(level: BumpLevel) -> std::path::PathBuf {
        std::path::PathBuf::from(level.as_str())
    }
}

/// [`From<BumpLevel> for &'static std::ffi::OsStr`] routes through
/// [`BumpLevel::as_str`] composed with the lifetime-preserving
/// [`std::ffi::OsStr::new`] constructor so a downstream consumer
/// bound by `impl Into<&'static std::ffi::OsStr>` (a `const`-adjacent
/// OS-string sink that stashes the bump label in a
/// `&'static std::ffi::OsStr` field, a
/// [`std::borrow::Cow<'static, std::ffi::OsStr>`] sink taking
/// `Into<Cow<'static, OsStr>>`, a `phf`-style static lookup table
/// keyed by canonical label OS-strings) reads the canonical
/// lowercase label (`"patch"`, `"minor"`, `"major"`) as an owned
/// `&'static std::ffi::OsStr` view of the static-lifetime label
/// constant with `'static` lifetime preserved.
///
/// The by-value static-lifetime peer of the [`AsRef<std::ffi::OsStr>`]
/// borrow surface — both are OS-string surfaces at the same
/// canonical-label oracle, differing only on ownership and lifetime:
/// [`AsRef<std::ffi::OsStr>`] borrows through the receiver's
/// lifetime (a caller with a short-lived [`BumpLevel`] gets a
/// short-lived `&std::ffi::OsStr` back), whereas this [`From`] impl
/// consumes the receiver by value and returns
/// `&'static std::ffi::OsStr` (a caller that no longer needs the
/// [`BumpLevel`] value gets a `'static`-lived
/// [`std::ffi::OsStr`] label back). Structural mirror of
/// [`From<BumpLevel> for &'static str`] and
/// [`From<BumpLevel> for &'static [u8]`] at the UTF-8 and
/// byte-slice frontiers respectively — the same by-value static-
/// lifetime emit surface at the same one-oracle discipline,
/// projected onto the OS-string frontier this time.
///
/// Trio-closing peer at the third ordered typed sum of the by-value
/// static-lifetime OS-string emit trio:
/// `From<PerAttemptRegion> for &'static std::ffi::OsStr` (commit
/// be57ac3) opened the trio at the first typed sum;
/// `From<AdmissionTier> for &'static std::ffi::OsStr` (commit
/// b69f733) carried the mid-trio slot at the second typed sum;
/// this impl closes the trio at the version-bump-magnitude ladder,
/// matching the [`From<T> for &'static [u8]`] closure order
/// (70e813b → 694dff9 → 762437f), the [`AsRef<std::ffi::OsStr>`]
/// closure order (70e1ab5 → 1d708f4 → 242ed89), and the
/// [`From<T> for std::ffi::OsString`] closure order
/// (976f5af → 0791fc7 → b069eec). After this commit the by-value
/// static-lifetime emit axis spans THREE frontiers — UTF-8 string,
/// byte-slice, OS-string — across all three ordered typed sums
/// against ONE canonical-label oracle each: a three-frontier x
/// three-typed-sum closure at the by-value static-lifetime emit
/// axis, matching the four-frontier x three-typed-sum closure at
/// the borrowed-view axis ([`AsRef<str>`], [`AsRef<[u8]>`],
/// [`AsRef<std::ffi::OsStr>`], [`AsRef<std::path::Path>`]) and the
/// four-frontier x three-typed-sum closure at the by-value owned-
/// buffer emit axis ([`From<T> for String`], [`From<T> for Vec<u8>`],
/// [`From<T> for std::ffi::OsString`],
/// [`From<T> for std::path::PathBuf`]).
///
/// Zero-cost by construction: [`std::ffi::OsStr::new`] on an
/// [`AsRef<std::ffi::OsStr>`] input is a zero-cost transmute at the
/// borrow-view boundary — [`std::ffi::OsStr`] is a `[u8]` newtype on
/// Unix and a `[u16]`-wide newtype on Windows, both accepting a
/// `&str` view without allocation — no copy, no branching over the
/// variant discriminant beyond what [`BumpLevel::as_str`] itself
/// does at its match body. The `'static` lifetime is preserved
/// through the composition because [`BumpLevel::as_str`] returns
/// `&'static str` and [`std::ffi::OsStr::new`] preserves the
/// receiver's lifetime.
///
/// The identity `<&'static std::ffi::OsStr>::from(level) ==
/// std::ffi::OsStr::new(level.as_str())` at every
/// [`BumpLevel::ALL`] variant is pinned by
/// [`tests::test_bump_level_from_into_static_os_str_agrees_with_os_str_new_as_str`];
/// the identity carried through a generic
/// `impl Into<&'static std::ffi::OsStr>` consumer at every variant
/// is pinned by
/// [`tests::test_bump_level_into_static_os_str_carries_through_generic_consumer`];
/// the round-trip through [`std::ffi::OsStr::to_str`] recovering
/// the canonical label at every variant is pinned by
/// [`tests::test_bump_level_from_into_static_os_str_round_trips_through_to_str`].
///
/// THEORY.md §V.4 typed primitives: the by-value static-lifetime
/// OS-string emit surface is a typed-primitive site on
/// [`BumpLevel`] itself (one
/// `From<BumpLevel> for &'static std::ffi::OsStr` impl routing
/// through [`BumpLevel::as_str`] and [`std::ffi::OsStr::new`]),
/// not a per-consumer `OsStr::new(level.as_str())` restatement at
/// every downstream site that accepts
/// `impl Into<&'static std::ffi::OsStr>`.
/// THEORY.md §VI.1 one-oracle: the canonical label is named at
/// one site ([`BumpLevel::as_str`]) and every by-value
/// static-lifetime emit surface — [`From<T> for &'static str`]
/// (yields `&'static str`), [`From<T> for &'static [u8]`] (yields
/// `&'static [u8]`), this [`From<T> for &'static std::ffi::OsStr`]
/// (yields `&'static std::ffi::OsStr`) — reads through it.
impl From<BumpLevel> for &'static std::ffi::OsStr {
    fn from(level: BumpLevel) -> &'static std::ffi::OsStr {
        std::ffi::OsStr::new(level.as_str())
    }
}

/// The by-value static-lifetime filesystem-path emit surface at the
/// version-bump-magnitude ladder — a downstream consumer bound by
/// `impl Into<&'static std::path::Path>` (a `const`-adjacent
/// filesystem-path sink stashing the bump label in a
/// `&'static std::path::Path` field, a
/// [`std::borrow::Cow<'static, std::path::Path>`] sink taking
/// `Into<Cow<'static, Path>>`, a `phf`-style static lookup table
/// keyed by canonical label paths) recovers the canonical lowercase
/// label (`"patch"`, `"minor"`, `"major"`) as an owned
/// `&'static std::path::Path` view of the static-lifetime label
/// constant with `'static` lifetime preserved end-to-end, no
/// per-consumer `Path::new(level.as_str())` restatement at every
/// boundary.
///
/// The by-value static-lifetime peer of the [`AsRef<std::path::Path>`]
/// borrow surface — both are filesystem-path surfaces at the same
/// canonical-label oracle, differing only on ownership and lifetime:
/// [`AsRef<std::path::Path>`] borrows through the receiver's
/// lifetime (a caller with a short-lived [`BumpLevel`] gets a
/// short-lived `&std::path::Path` back), whereas this [`From`] impl
/// consumes the receiver by value and returns
/// `&'static std::path::Path` (a caller that no longer needs the
/// [`BumpLevel`] value gets a `'static`-lived
/// [`std::path::Path`] label back). Structural mirror of
/// [`From<BumpLevel> for &'static str`],
/// [`From<BumpLevel> for &'static [u8]`], and
/// [`From<BumpLevel> for &'static std::ffi::OsStr`] at the
/// UTF-8, byte-slice, and OS-string frontiers respectively — the
/// same by-value static-lifetime emit surface at the same one-oracle
/// discipline, projected onto the filesystem-path frontier this
/// time.
///
/// Trio-closing peer at the third ordered typed sum of the by-value
/// static-lifetime filesystem-path emit trio:
/// `From<PerAttemptRegion> for &'static std::path::Path` (commit
/// 671119d) opened the trio at the first typed sum;
/// `From<AdmissionTier> for &'static std::path::Path` (commit
/// 758321a) carried the mid-trio slot at the second typed sum;
/// this impl closes the trio at the version-bump-magnitude ladder,
/// matching the [`From<T> for &'static std::ffi::OsStr`] closure
/// order (be57ac3 → b69f733 → 3cbc7bc), the
/// [`AsRef<std::path::Path>`] closure order (17718d2 → f6c4c75 →
/// dfd887a), and the [`From<T> for std::path::PathBuf`] closure
/// order (6333c31 → 75a37d4 → 9e544b8). After this commit the
/// by-value static-lifetime emit axis spans FOUR frontiers — UTF-8
/// string, byte-slice, OS-string, filesystem-path — across all
/// three ordered typed sums against ONE canonical-label oracle
/// each: a four-frontier x three-typed-sum closure at the by-value
/// static-lifetime emit axis, matching the four-frontier x
/// three-typed-sum closure at the borrowed-view axis
/// ([`AsRef<str>`], [`AsRef<[u8]>`], [`AsRef<std::ffi::OsStr>`],
/// [`AsRef<std::path::Path>`]) and the four-frontier x
/// three-typed-sum closure at the by-value owned-buffer emit axis
/// ([`From<T> for String`], [`From<T> for Vec<u8>`],
/// [`From<T> for std::ffi::OsString`],
/// [`From<T> for std::path::PathBuf`]).
///
/// Zero-cost by construction: [`std::path::Path::new`] on an
/// [`AsRef<std::ffi::OsStr>`] input is a zero-cost transmute at the
/// borrow-view boundary — [`std::path::Path`] is an
/// [`std::ffi::OsStr`] newtype on all platforms, accepting a `&str`
/// view without allocation — no copy, no branching over the variant
/// discriminant beyond what [`BumpLevel::as_str`] itself does at
/// its match body. The `'static` lifetime is preserved through the
/// composition because [`BumpLevel::as_str`] returns `&'static str`
/// and [`std::path::Path::new`] preserves the receiver's lifetime.
///
/// The identity `<&'static std::path::Path>::from(level) ==
/// std::path::Path::new(level.as_str())` at every
/// [`BumpLevel::ALL`] variant is pinned by
/// [`tests::test_bump_level_from_into_static_path_agrees_with_path_new_as_str`];
/// the identity carried through a generic
/// `impl Into<&'static std::path::Path>` consumer at every variant
/// is pinned by
/// [`tests::test_bump_level_into_static_path_carries_through_generic_consumer`];
/// the round-trip through [`std::path::Path::to_str`] recovering
/// the canonical label at every variant is pinned by
/// [`tests::test_bump_level_from_into_static_path_round_trips_through_to_str`].
///
/// THEORY.md §V.4 typed primitives: the by-value static-lifetime
/// filesystem-path emit surface is a typed-primitive site on
/// [`BumpLevel`] itself (one
/// `From<BumpLevel> for &'static std::path::Path` impl routing
/// through [`BumpLevel::as_str`] and [`std::path::Path::new`]),
/// not a per-consumer `Path::new(level.as_str())` restatement at
/// every downstream site that accepts
/// `impl Into<&'static std::path::Path>`. THEORY.md §VI.1
/// one-oracle: the canonical label is named at one site
/// ([`BumpLevel::as_str`]) and every by-value static-lifetime emit
/// surface — [`From<T> for &'static str`] (yields `&'static str`),
/// [`From<T> for &'static [u8]`] (yields `&'static [u8]`),
/// [`From<T> for &'static std::ffi::OsStr`] (yields
/// `&'static std::ffi::OsStr`), this
/// [`From<T> for &'static std::path::Path`] (yields
/// `&'static std::path::Path`) — reads through it.
impl From<BumpLevel> for &'static std::path::Path {
    fn from(level: BumpLevel) -> &'static std::path::Path {
        std::path::Path::new(level.as_str())
    }
}

/// [`From<BumpLevel> for std::borrow::Cow<'static,
/// std::ffi::OsStr>`] routes through [`BumpLevel::as_str`] composed
/// with the lifetime-preserving [`std::ffi::OsStr::new`] constructor
/// and wrapped in [`std::borrow::Cow::Borrowed`] so a downstream
/// consumer bound by `impl Into<Cow<'static, std::ffi::OsStr>>` (a
/// config-schema builder that accepts either a static OS-string label
/// or a caller-supplied [`std::ffi::OsString`] uniformly, a
/// subprocess-argv sink taking [`Cow<'static, std::ffi::OsStr>`] slots
/// at a [`std::process::Command`] boundary — the release-plumbing
/// `cargo release`-adjacent bump-magnitude argv sink is the natural
/// consumer, `phf`-style static lookup table keyed by canonical label
/// OS-strings) reads the canonical lowercase label (`"patch"`,
/// `"minor"`, `"major"`) as a borrowed
/// [`Cow<'static, std::ffi::OsStr>`] view of the static-lifetime label
/// constant with `'static` lifetime preserved end-to-end and zero
/// allocation at the emit boundary.
///
/// The by-value borrowed/owned-frontier peer of the by-value static-
/// lifetime [`From<BumpLevel> for &'static std::ffi::OsStr`] and
/// by-value owned [`From<BumpLevel> for std::ffi::OsString`] surfaces
/// above — all three are OS-string emit surfaces at the same
/// canonical-label oracle, differing only on receiver-side shape:
/// [`From<T> for &'static std::ffi::OsStr`] returns a borrowed
/// `'static`-lived view for consumers that want the borrow,
/// [`From<T> for std::ffi::OsString`] returns an owned buffer for
/// consumers that own the label, this
/// [`From<T> for Cow<'static, std::ffi::OsStr>`] returns either
/// uniformly at the borrowed/owned-frontier receiver shape. All three
/// route through the same canonical-label oracle at
/// [`BumpLevel::as_str`]: the `&'static std::ffi::OsStr` peer through
/// [`std::ffi::OsStr::new`] directly, the [`std::ffi::OsString`] peer
/// through [`std::ffi::OsString::from`], this
/// [`Cow<'static, std::ffi::OsStr>`] peer through
/// [`std::ffi::OsStr::new`] composed with
/// [`std::borrow::Cow::Borrowed`] — the same one-oracle discipline
/// lifted to the borrowed/owned-frontier emit layer, with the
/// [`std::borrow::Cow::Borrowed`] branch taken uniformly because the
/// canonical label already has `'static` lifetime.
///
/// Structural mirror of
/// [`From<BumpLevel> for std::borrow::Cow<'static, str>`] and
/// [`From<BumpLevel> for std::borrow::Cow<'static, [u8]>`] at the
/// UTF-8 and byte-slice frontiers respectively — the same by-value
/// borrowed/owned-frontier emit surface at the same one-oracle
/// discipline, projected onto the OS-string frontier this time; both
/// siblings similarly wrap [`std::borrow::Cow::Borrowed`] around the
/// `'static`-lived borrowed view produced by their frontier
/// constructor (`&'static str` directly for the UTF-8 sibling,
/// `str::as_bytes` for the byte-slice sibling, [`std::ffi::OsStr::new`]
/// here for the OS-string frontier).
///
/// Trio-closing peer at the third ordered typed sum of the by-value
/// borrowed/owned-frontier OS-string emit trio:
/// `From<PerAttemptRegion> for Cow<'static, std::ffi::OsStr>` (commit
/// 24f6110) opened the trio at the per-attempt-region ladder;
/// `From<AdmissionTier> for Cow<'static, std::ffi::OsStr>` (commit
/// 4e94fc5) carried the mid-trio slot at the admission-tier ladder;
/// this impl closes the trio at the version-bump-magnitude ladder,
/// matching the [`From<T> for &'static std::ffi::OsStr`] closure order
/// (be57ac3 → b69f733 → 3cbc7bc), the
/// [`From<T> for std::ffi::OsString`] closure order
/// (976f5af → 0791fc7 → b069eec), the [`AsRef<std::ffi::OsStr>`]
/// closure order (70e1ab5 → 1d708f4 → 242ed89), and the
/// [`From<T> for std::borrow::Cow<'static, [u8]>`] closure order at
/// the byte-slice sibling frontier (912a5ff → 89af285 → 7c465d1).
/// After this commit the by-value borrowed/owned-frontier emit axis
/// spans THREE frontiers — UTF-8 string, byte-slice, OS-string —
/// across all three ordered typed sums
/// ([`crate::retry::PerAttemptRegion`],
/// [`crate::probe_outcome::AdmissionTier`], [`BumpLevel`]) against
/// ONE canonical-label oracle each, matching the three-frontier x
/// three-typed-sum closure patterns already carried at the by-value
/// owned-buffer emit axis (`From<T> for String`, `From<T> for
/// Vec<u8>`, `From<T> for std::ffi::OsString`), the by-value
/// static-lifetime emit axis (`From<T> for &'static str`,
/// `From<T> for &'static [u8]`, `From<T> for &'static std::ffi::OsStr`),
/// and the borrowed-view axis (`AsRef<str>`, `AsRef<[u8]>`,
/// `AsRef<std::ffi::OsStr>`).
///
/// Zero-cost by construction: [`std::ffi::OsStr::new`] on an
/// [`AsRef<std::ffi::OsStr>`] input is a zero-cost transmute at the
/// borrow-view boundary — [`std::ffi::OsStr`] is a `[u8]` newtype on
/// Unix and a `[u16]`-wide newtype on Windows, both accepting a `&str`
/// view without allocation — and [`std::borrow::Cow::Borrowed`] is a
/// plain enum-variant construction carrying the reference verbatim; no
/// copy, no branching over the variant discriminant beyond what
/// [`BumpLevel::as_str`] itself does at its match body. The `'static`
/// lifetime is preserved through the composition because
/// [`BumpLevel::as_str`] returns `&'static str`,
/// [`std::ffi::OsStr::new`] preserves the receiver's lifetime, and
/// [`std::borrow::Cow::Borrowed`] preserves the inner reference's
/// lifetime.
///
/// The identity `<Cow<'static, std::ffi::OsStr>>::from(level) ==
/// Cow::Borrowed(std::ffi::OsStr::new(level.as_str()))` at every
/// [`BumpLevel::ALL`] variant is pinned by
/// [`tests::test_bump_level_from_into_cow_static_os_str_agrees_with_cow_borrowed_os_str_new_as_str`];
/// the identity carried through a generic
/// `impl Into<Cow<'static, std::ffi::OsStr>>` consumer at every variant
/// is pinned by
/// [`tests::test_bump_level_into_cow_static_os_str_carries_through_generic_consumer`];
/// the zero-allocation contract (impl returns the
/// [`std::borrow::Cow::Borrowed`] branch rather than
/// [`std::borrow::Cow::Owned`]) at every variant is pinned by
/// [`tests::test_bump_level_into_cow_static_os_str_is_borrowed`].
///
/// THEORY.md §V.4 typed primitives: the by-value borrowed/owned-
/// frontier OS-string emit surface is a typed-primitive site on
/// [`BumpLevel`] itself (one
/// `From<BumpLevel> for Cow<'static, std::ffi::OsStr>` impl routing
/// through [`BumpLevel::as_str`], [`std::ffi::OsStr::new`], and
/// [`std::borrow::Cow::Borrowed`]), not a per-consumer
/// `Cow::Borrowed(std::ffi::OsStr::new(level.as_str()))` restatement
/// at every downstream site that accepts
/// `impl Into<Cow<'static, std::ffi::OsStr>>`.
/// THEORY.md §VI.1 one-oracle: the canonical label is named at one
/// site ([`BumpLevel::as_str`]) and every by-value borrowed/owned-
/// frontier emit surface —
/// [`From<T> for std::borrow::Cow<'static, str>`] (yields
/// `Cow<'static, str>`),
/// [`From<T> for std::borrow::Cow<'static, [u8]>`] (yields
/// `Cow<'static, [u8]>`), this
/// [`From<T> for std::borrow::Cow<'static, std::ffi::OsStr>`] (yields
/// `Cow<'static, std::ffi::OsStr>`) — reads through it.
impl From<BumpLevel> for std::borrow::Cow<'static, std::ffi::OsStr> {
    fn from(level: BumpLevel) -> std::borrow::Cow<'static, std::ffi::OsStr> {
        std::borrow::Cow::Borrowed(std::ffi::OsStr::new(level.as_str()))
    }
}

/// [`From<BumpLevel> for std::borrow::Cow<'static, std::path::Path>`]
/// routes through [`BumpLevel::as_str`] composed with the
/// lifetime-preserving [`std::path::Path::new`] constructor and
/// wrapped in [`std::borrow::Cow::Borrowed`] so a downstream consumer
/// bound by `impl Into<Cow<'static, std::path::Path>>` (a
/// [`std::path::PathBuf`]-adjacent config-schema builder that accepts
/// either a static path label or a caller-supplied
/// [`std::path::PathBuf`] uniformly at the borrowed/owned frontier, a
/// `phf`-style static lookup table keyed by canonical label
/// filesystem-paths, a Nix-store-path segment router at the
/// filesystem-path frontier, an OCI / GHCR layer-path sink typed as
/// [`std::borrow::Cow<'static, std::path::Path>`]) reads the
/// canonical lowercase label (`"patch"`, `"minor"`, `"major"`) as a
/// borrowed [`Cow<'static, std::path::Path>`] view of the
/// static-lifetime label constant with `'static` lifetime preserved
/// end-to-end and zero allocation at the emit boundary.
///
/// The by-value borrowed/owned-frontier peer of the by-value
/// static-lifetime [`From<BumpLevel> for &'static std::path::Path`]
/// and by-value owned [`From<BumpLevel> for std::path::PathBuf`]
/// surfaces above — all three are filesystem-path emit surfaces at
/// the same canonical-label oracle, differing only on receiver-side
/// shape: [`From<T> for &'static std::path::Path`] returns a borrowed
/// `'static`-lived view for consumers that want the borrow,
/// [`From<T> for std::path::PathBuf`] returns an owned buffer for
/// consumers that own the label, this
/// [`From<T> for Cow<'static, std::path::Path>`] returns either
/// uniformly at the borrowed/owned-frontier receiver shape. All three
/// route through the same canonical-label oracle at
/// [`BumpLevel::as_str`]: the `&'static std::path::Path` peer through
/// [`std::path::Path::new`] directly, the [`std::path::PathBuf`] peer
/// through [`std::path::PathBuf::from`], this
/// [`Cow<'static, std::path::Path>`] peer through
/// [`std::path::Path::new`] composed with
/// [`std::borrow::Cow::Borrowed`] — the same one-oracle discipline
/// lifted to the borrowed/owned-frontier emit layer, with the
/// [`std::borrow::Cow::Borrowed`] branch taken uniformly because the
/// canonical label already has `'static` lifetime.
///
/// Structural mirror of
/// [`From<BumpLevel> for std::borrow::Cow<'static, str>`],
/// [`From<BumpLevel> for std::borrow::Cow<'static, [u8]>`], and
/// [`From<BumpLevel> for std::borrow::Cow<'static, std::ffi::OsStr>`]
/// at the UTF-8, byte-slice, and OS-string frontiers respectively —
/// the same by-value borrowed/owned-frontier emit surface at the
/// same one-oracle discipline, projected onto the filesystem-path
/// frontier this time; all siblings wrap
/// [`std::borrow::Cow::Borrowed`] around the `'static`-lived borrowed
/// view produced by their frontier constructor (`&'static str`
/// directly for the UTF-8 sibling, [`str::as_bytes`] for the
/// byte-slice sibling, [`std::ffi::OsStr::new`] for the OS-string
/// sibling, [`std::path::Path::new`] here for the filesystem-path
/// frontier).
///
/// Trio-closing peer at the third ordered typed sum of the by-value
/// borrowed/owned-frontier filesystem-path emit trio:
/// `From<PerAttemptRegion> for Cow<'static, std::path::Path>` (commit
/// cfb6125) opened the trio at the per-attempt-region ladder;
/// `From<AdmissionTier> for Cow<'static, std::path::Path>` (commit
/// f11faad) carried the mid-trio slot at the admission-tier ladder;
/// this impl closes the trio at the version-bump-magnitude ladder,
/// matching the [`From<T> for &'static std::path::Path`] closure
/// order (671119d → 758321a → 4431027), the
/// [`From<T> for std::path::PathBuf`] closure order
/// (6333c31 → 75a37d4 → 9e544b8), the
/// [`AsRef<std::path::Path>`] closure order
/// (17718d2 → f6c4c75 → dfd887a), and the
/// [`From<T> for std::borrow::Cow<'static, std::ffi::OsStr>`] closure
/// order at the OS-string sibling frontier
/// (24f6110 → 4e94fc5 → f305c9b). After this commit the by-value
/// borrowed/owned-frontier emit axis spans ALL FOUR widely-used
/// string frontiers the standard library exposes — UTF-8 string,
/// byte-slice, OS-string, filesystem-path — across all three ordered
/// typed sums ([`crate::retry::PerAttemptRegion`],
/// [`crate::probe_outcome::AdmissionTier`], [`BumpLevel`]) against
/// ONE canonical-label oracle each, matching the four-frontier x
/// three-typed-sum closure patterns already carried at the by-value
/// owned-buffer emit axis (`From<T> for String`,
/// `From<T> for Vec<u8>`, `From<T> for std::ffi::OsString`,
/// `From<T> for std::path::PathBuf`), the by-value static-lifetime
/// emit axis (`From<T> for &'static str`,
/// `From<T> for &'static [u8]`,
/// `From<T> for &'static std::ffi::OsStr`,
/// `From<T> for &'static std::path::Path`), and the borrowed-view
/// axis (`AsRef<str>`, `AsRef<[u8]>`, `AsRef<std::ffi::OsStr>`,
/// `AsRef<std::path::Path>`).
///
/// Zero-cost by construction: [`std::path::Path::new`] on an
/// [`AsRef<std::path::Path>`] input is a zero-cost transmute at the
/// borrow-view boundary — [`std::path::Path`] is a
/// [`std::ffi::OsStr`] newtype at every platform, accepting a `&str`
/// view without allocation — and [`std::borrow::Cow::Borrowed`] is a
/// plain enum-variant construction carrying the reference verbatim;
/// no copy, no branching over the variant discriminant beyond what
/// [`BumpLevel::as_str`] itself does at its match body. The `'static`
/// lifetime is preserved through the composition because
/// [`BumpLevel::as_str`] returns `&'static str`,
/// [`std::path::Path::new`] preserves the receiver's lifetime, and
/// [`std::borrow::Cow::Borrowed`] preserves the inner reference's
/// lifetime.
///
/// The identity `<Cow<'static, std::path::Path>>::from(level) ==
/// Cow::Borrowed(std::path::Path::new(level.as_str()))` at every
/// [`BumpLevel::ALL`] variant is pinned by
/// [`tests::test_bump_level_from_into_cow_static_path_agrees_with_cow_borrowed_path_new_as_str`];
/// the identity carried through a generic
/// `impl Into<Cow<'static, std::path::Path>>` consumer at every
/// variant is pinned by
/// [`tests::test_bump_level_into_cow_static_path_carries_through_generic_consumer`];
/// the zero-allocation contract (impl returns the
/// [`std::borrow::Cow::Borrowed`] branch rather than
/// [`std::borrow::Cow::Owned`]) at every variant is pinned by
/// [`tests::test_bump_level_into_cow_static_path_is_borrowed`].
///
/// THEORY.md §V.4 typed primitives: the by-value
/// borrowed/owned-frontier filesystem-path emit surface is a
/// typed-primitive site on [`BumpLevel`] itself (one
/// `From<BumpLevel> for Cow<'static, std::path::Path>` impl routing
/// through [`BumpLevel::as_str`], [`std::path::Path::new`], and
/// [`std::borrow::Cow::Borrowed`]), not a per-consumer
/// `Cow::Borrowed(std::path::Path::new(level.as_str()))` restatement
/// at every downstream site that accepts
/// `impl Into<Cow<'static, std::path::Path>>`.
/// THEORY.md §VI.1 one-oracle: the canonical label is named at one
/// site ([`BumpLevel::as_str`]) and every by-value
/// borrowed/owned-frontier emit surface —
/// [`From<T> for std::borrow::Cow<'static, str>`] (yields
/// `Cow<'static, str>`),
/// [`From<T> for std::borrow::Cow<'static, [u8]>`] (yields
/// `Cow<'static, [u8]>`),
/// [`From<T> for std::borrow::Cow<'static, std::ffi::OsStr>`]
/// (yields `Cow<'static, std::ffi::OsStr>`), this
/// [`From<T> for std::borrow::Cow<'static, std::path::Path>`]
/// (yields `Cow<'static, std::path::Path>`) — reads through it.
impl From<BumpLevel> for std::borrow::Cow<'static, std::path::Path> {
    fn from(level: BumpLevel) -> std::borrow::Cow<'static, std::path::Path> {
        std::borrow::Cow::Borrowed(std::path::Path::new(level.as_str()))
    }
}

/// [`TryFrom<&std::ffi::OsStr> for BumpLevel`] routes through
/// [`std::ffi::OsStr::to_str`] and the by-reference UTF-8 parse peer
/// [`TryFrom<&str> for BumpLevel`] so a downstream consumer bound by
/// `impl for<'a> TryFrom<&'a std::ffi::OsStr>` (a [`std::env::var_os`]
/// reader that surfaces a canonical [`BumpLevel`] label as a `&OsStr`
/// view of the process-environment slot without a
/// [`std::ffi::OsString`] intermediate, a [`std::process::Command::get_args`]
/// iterator inspector reading a canonical label CLI argument, a
/// [`std::path::Path::file_name`] receiver that returns an
/// [`Option<&OsStr>`] over a bump-magnitude-labeled path segment, an
/// [`std::os::unix::ffi::OsStrExt`]-styled byte-boundary parser at a
/// POSIX interop frontier, a generic try-conversion helper
/// `fn parse<T: for<'a> TryFrom<&'a OsStr>>` that composes with borrowed
/// OS-string inputs uniformly) recovers a [`BumpLevel`] value from a
/// borrowed OS-string label view (`OsStr::new("patch")`,
/// `OsStr::new("minor")`, `OsStr::new("major")`) through the same
/// one-oracle grammar the direct `.parse::<BumpLevel>()` call sites,
/// the sibling [`TryFrom<&str>`], [`TryFrom<String>`],
/// [`TryFrom<Cow<'_, str>>`], [`TryFrom<Box<str>>`],
/// [`TryFrom<Arc<str>>`], [`TryFrom<Rc<str>>`], [`TryFrom<&[u8]>`],
/// [`TryFrom<Vec<u8>>`], [`TryFrom<Cow<'_, [u8]>>`],
/// [`TryFrom<Box<[u8]>>`], [`TryFrom<Arc<[u8]>>`], and
/// [`TryFrom<Rc<[u8]>>`] parse peers already read.
///
/// The by-reference OS-string parse peer of the by-reference UTF-8
/// [`TryFrom<&str> for BumpLevel`] parse peer below at the
/// borrowed-view axis, and the parse-side dual of the emit-only
/// borrowed-view [`AsRef<std::ffi::OsStr>`] surface (commit 242ed89)
/// above at the OS-string frontier. The [`AsRef<std::ffi::OsStr>`]
/// surface yields a canonical `&OsStr` view out of a [`BumpLevel`]
/// value, this [`TryFrom<&std::ffi::OsStr>`] surface reads a canonical
/// `&OsStr` view IN to a [`BumpLevel`] value at the same OS-string
/// frontier — closing the emit/parse pair at the borrowed-view axis at
/// the OS-string frontier that the UTF-8 frontier already closes
/// through [`AsRef<str>`] paired with [`TryFrom<&str>`] and the
/// byte-slice frontier closes through [`AsRef<[u8]>`] paired with
/// [`TryFrom<&[u8]>`].
///
/// Closing peer of the OS-string borrowed-view parse trio at the
/// version-bump-magnitude ladder: `TryFrom<&OsStr>` for
/// [`crate::retry::PerAttemptRegion`] (commit d37e6fe) opened the trio
/// at the first ordered typed sum; `TryFrom<&OsStr>` for
/// [`crate::probe_outcome::AdmissionTier`] (commit 9fca3bb) carried
/// the mid-trio slot at the second ordered typed sum; this impl closes
/// the trio at the third ordered typed sum, matching the
/// [`TryFrom<&[u8]>`] byte-slice frontier's borrowed-view parse
/// closing order (5c0c827 → cdb192c → 629b242) at the byte-slice
/// sibling, and the emit-side [`AsRef<std::ffi::OsStr>`] borrowed-view
/// emit closing order (70e1ab5 → 1d708f4 → 242ed89) at this OS-string
/// frontier's emit-side dual. After this commit the OS-string
/// borrowed-view parse axis spans all three ordered typed sums on the
/// ladder set through ONE [`std::ffi::OsStr::to_str`] +
/// [`TryFrom<&str>`] composition each.
///
/// # Two-stage strictness
///
/// The parser is strict at the same TWO frontiers a direct
/// [`std::ffi::OsStr::to_str`] + [`str::parse`] composition would be
/// strict at, lifted to ONE typed-primitive site:
///
/// - Non-Unicode OS-string sequences (on Unix, a `&OsStr` may hold any
///   byte sequence — an invalid-UTF-8 filesystem path segment from a
///   foreign locale or a malformed shell-quoted CLI argument) reject
///   at the [`std::ffi::OsStr::to_str`] Unicode-decode frontier with a
///   diagnostic naming the offending OS-string.
/// - Valid-Unicode OS-string sequences that decode to a non-canonical
///   label (`OsStr::new("Patch")`, `OsStr::new("Minor")`,
///   `OsStr::new("Major")`, `OsStr::new("PATCH")`,
///   `OsStr::new(" patch")`, `OsStr::new("patch ")`,
///   `OsStr::new("pat")`, `OsStr::new("")`) reject at the underlying
///   [`std::str::FromStr`] impl — the same canonical-only strictness
///   the UTF-8 frontier already carries at the by-reference parse
///   peer, now lifted to the OS-string input layer at ONE composition
///   through the borrowed [`TryFrom<&str>`] peer.
///
/// The identity `BumpLevel::try_from(std::ffi::OsStr::new(
/// level.as_str())).unwrap() == level` at every [`BumpLevel::ALL`]
/// variant is pinned by
/// [`tests::test_bump_level_try_from_os_str_agrees_with_from_str`];
/// the identity carried through a generic
/// `impl for<'a> TryFrom<&'a std::ffi::OsStr>` consumer at every
/// variant is pinned by
/// [`tests::test_bump_level_try_from_os_str_carries_through_generic_consumer`];
/// the strict-rejection contract on non-Unicode OS-string input is
/// pinned by
/// [`tests::test_bump_level_try_from_os_str_rejects_non_unicode_input`];
/// the strict-rejection contract on valid-Unicode non-canonical
/// OS-string input is pinned by
/// [`tests::test_bump_level_try_from_os_str_rejects_non_canonical_input`].
///
/// THEORY.md §V.4 typed primitives: the by-reference OS-string parse
/// surface is a typed-primitive site on [`BumpLevel`] itself (one
/// `TryFrom<&std::ffi::OsStr>` impl routing through
/// [`std::ffi::OsStr::to_str`] and the by-reference [`TryFrom<&str>`]
/// parse peer), not a per-consumer
/// `BumpLevel::try_from(os_str.to_str().ok_or(...)?)` restatement at
/// every downstream site that types its parse contract as
/// `impl for<'a> TryFrom<&'a std::ffi::OsStr>`.
/// THEORY.md §VI.1 one-oracle: the canonical label grammar is named
/// at one site ([`BumpLevel::as_str`]), inverted at one site
/// ([`<BumpLevel as std::str::FromStr>::from_str`]), and every parse
/// surface — [`std::str::FromStr`], [`serde::Deserialize`],
/// [`TryFrom<&str>`], [`TryFrom<String>`], [`TryFrom<Cow<'_, str>>`],
/// [`TryFrom<Box<str>>`], [`TryFrom<Arc<str>>`], [`TryFrom<Rc<str>>`],
/// [`TryFrom<&[u8]>`], [`TryFrom<Vec<u8>>`],
/// [`TryFrom<Cow<'_, [u8]>>`], [`TryFrom<Box<[u8]>>`],
/// [`TryFrom<Arc<[u8]>>`], [`TryFrom<Rc<[u8]>>`], this
/// [`TryFrom<&std::ffi::OsStr>`] — reads through it.
impl TryFrom<&std::ffi::OsStr> for BumpLevel {
    type Error = anyhow::Error;

    fn try_from(os: &std::ffi::OsStr) -> Result<Self, Self::Error> {
        let decoded = os
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("invalid Unicode in bump level OsStr input {os:?}"))?;
        <Self as std::convert::TryFrom<&str>>::try_from(decoded)
    }
}

/// [`TryFrom<std::ffi::OsString> for BumpLevel`] routes through the
/// by-reference [`TryFrom<&std::ffi::OsStr>`] parse peer directly above on
/// [`std::ffi::OsString::as_os_str`] of the caller-owned OS-string buffer,
/// so a downstream consumer bound by `impl TryFrom<std::ffi::OsString>` (a
/// `serde` container that opts into `#[serde(try_from = "OsString")]` on a
/// wrapper field, a generic try-conversion helper `fn parse_os_field<T:
/// TryFrom<OsString>>` that owns the input OS-string, a validated-input
/// newtype builder that consumes an owned [`std::ffi::OsString`] and
/// returns a validated [`BumpLevel`], a [`std::env::var_os`] reader that
/// owns the [`std::ffi::OsString`] returned by the process-environment
/// slot, a [`std::env::args_os`] iterator consumer that owns each
/// CLI-argument [`std::ffi::OsString`], a
/// [`std::path::PathBuf::into_os_string`] terminus at the
/// filesystem-frontier layer, a [`std::process::Command::get_program`] +
/// [`std::ffi::OsStr::to_owned`] compose at the child-process-frontier
/// layer) recovers a [`BumpLevel`] value from a canonical lowercase-label
/// OS-string through the same one-oracle grammar the direct
/// `.parse::<BumpLevel>()` call sites, the sibling [`TryFrom<&str>`],
/// [`TryFrom<String>`], [`TryFrom<Cow<'_, str>>`], [`TryFrom<Box<str>>`],
/// [`TryFrom<Arc<str>>`], [`TryFrom<Rc<str>>`], [`TryFrom<&[u8]>`],
/// [`TryFrom<Vec<u8>>`], [`TryFrom<Cow<'_, [u8]>>`],
/// [`TryFrom<Box<[u8]>>`], [`TryFrom<Arc<[u8]>>`], [`TryFrom<Rc<[u8]>>`],
/// and [`TryFrom<&std::ffi::OsStr>`] parse peers already read.
///
/// The by-value owned-buffer parse peer of [`TryFrom<&std::ffi::OsStr>
/// for BumpLevel`] directly above — both are parse surfaces of the
/// OS-string frontier, differing only on the input OS-string ownership:
/// [`TryFrom<&std::ffi::OsStr>`] takes a borrowed [`&std::ffi::OsStr`]
/// view for consumers that already hold a borrow, this
/// [`TryFrom<std::ffi::OsString>`] takes an owned [`std::ffi::OsString`]
/// for consumers that own the input OS-string buffer (a `serde`
/// `try_from = "OsString"` container, an OS-string-consuming builder, a
/// [`std::env::var_os`] receiver, a [`std::env::args_os`] iterator
/// consumer). Both delegate through the shared [`std::str::FromStr`]
/// parse oracle: the borrowed peer through [`std::ffi::OsStr::to_str`] +
/// [`TryFrom<&str>`] (which itself composes through
/// [`std::str::FromStr`]), this owned peer through the borrowed peer via
/// [`std::ffi::OsString::as_os_str`] at the boundary — the same
/// canonical grammar lifted to the owned-buffer input layer.
///
/// Closing peer of the by-value owned-buffer OS-string-parse trio at
/// the version-bump-magnitude ladder: [`TryFrom<std::ffi::OsString>`]
/// for [`crate::retry::PerAttemptRegion`] (commit e629465) opened the
/// trio at the first ordered typed sum; [`TryFrom<std::ffi::OsString>`]
/// for [`crate::probe_outcome::AdmissionTier`] (commit 810794b) carried
/// the mid-trio slot at the second ordered typed sum; this impl closes
/// the trio at the third ordered typed sum, matching the
/// [`TryFrom<&std::ffi::OsStr>`] OS-string by-reference parse closing
/// order (d37e6fe → 9fca3bb → 1ea7110) at this OS-string frontier's
/// borrowed-view sibling, the [`TryFrom<String>`] UTF-8 owned-buffer
/// parse closing order (9f6feb3 → affb017 → 760e7d9) at the UTF-8
/// frontier's owned-buffer counterpart, the [`TryFrom<Vec<u8>>`]
/// byte-slice owned-buffer parse closing order
/// (91ba4bf → f4a2052 → 5b6f488) at the byte-slice frontier's
/// owned-buffer counterpart, and the [`From<BumpLevel> for
/// std::ffi::OsString`] OS-string owned-buffer emit closing order
/// (976f5af → 0791fc7 → b069eec) at this OS-string frontier's emit-side
/// owned-buffer dual. After this commit the OS-string owned-buffer
/// parse axis spans all three ordered typed sums on the ladder set
/// through ONE [`std::ffi::OsString::as_os_str`] +
/// [`TryFrom<&std::ffi::OsStr>`] composition each.
///
/// # Two-stage strictness
///
/// The parser is strict at the same TWO frontiers the
/// [`TryFrom<&std::ffi::OsStr>`] peer directly above is strict at,
/// inherited through the delegation: non-Unicode OS-string byte
/// sequences reject at [`std::ffi::OsStr::to_str`] with the standard
/// "invalid Unicode in bump level OsStr input" diagnostic surfaced
/// through [`anyhow::Error`], and valid-Unicode OS-string sequences
/// that decode to a non-canonical label (`""`, `"Patch"`, `"Minor"`,
/// `"Major"`, `"PATCH"`, `" patch"`, `"patch "`, `"pat"`) reject at
/// the underlying [`std::str::FromStr`] impl — the same canonical-only
/// strictness the OS-string frontier already carries at the
/// by-reference peer, now lifted to the owned-buffer input layer at
/// ONE composition through the borrowed [`TryFrom<&std::ffi::OsStr>`]
/// peer.
///
/// The impl body picks [`std::ffi::OsString::as_os_str`] rather than
/// [`std::ffi::OsString::into_string`] or an intermediate `to_str` +
/// [`str::parse`] restatement: [`std::ffi::OsString::as_os_str`] yields
/// a borrowed [`&std::ffi::OsStr`] view of the caller-owned buffer
/// without allocation, so the parse-side receiver pays the by-reference
/// [`TryFrom<&std::ffi::OsStr>`] cost, not the [`String`]-allocation
/// cost of an [`std::ffi::OsString::into_string`] round trip. The owned
/// [`std::ffi::OsString`] input is dropped at return, freeing its
/// buffer exactly once — the same discipline the sibling
/// [`TryFrom<Vec<u8>>`] and [`TryFrom<String>`] owned-buffer parse
/// peers apply at the [`Vec::as_slice`] and [`String::as_str`]
/// boundaries at the byte-slice and UTF-8 frontiers.
///
/// The identity `BumpLevel::try_from(std::ffi::OsString::from(
/// level.as_str())).unwrap() == level` at every [`BumpLevel::ALL`]
/// variant is pinned by
/// [`tests::test_bump_level_try_from_os_string_agrees_with_from_str`];
/// the identity carried through a generic
/// `impl TryFrom<std::ffi::OsString>` consumer at every variant is
/// pinned by
/// [`tests::test_bump_level_try_from_os_string_carries_through_generic_consumer`];
/// the strict-rejection contract on non-Unicode owned-buffer input is
/// pinned by
/// [`tests::test_bump_level_try_from_os_string_rejects_non_unicode_input`];
/// the strict-rejection contract on valid-Unicode non-canonical
/// owned-buffer input is pinned by
/// [`tests::test_bump_level_try_from_os_string_rejects_non_canonical_input`].
///
/// THEORY.md §V.1 typed primitives: the by-value owned-buffer OS-string
/// try-conversion surface is a typed-primitive site on [`BumpLevel`]
/// itself (one `TryFrom<std::ffi::OsString>` impl routing through the
/// borrowed [`TryFrom<&std::ffi::OsStr>`] parse peer on
/// [`std::ffi::OsString::as_os_str`]), not a per-consumer
/// `BumpLevel::try_from(buf.as_os_str())` bridge at every downstream
/// site that types its parse contract as
/// `impl TryFrom<std::ffi::OsString>` rather than
/// [`TryFrom<&std::ffi::OsStr>`] or [`std::str::FromStr`]. THEORY.md
/// §VI.1 one-oracle discipline: the canonical label grammar is named
/// at one site ([`BumpLevel::as_str`]), inverted at one site
/// ([`<BumpLevel as std::str::FromStr>::from_str`]), and every parse
/// surface — [`std::str::FromStr`], [`serde::Deserialize`],
/// [`TryFrom<&str>`], [`TryFrom<String>`], [`TryFrom<Cow<'_, str>>`],
/// [`TryFrom<Box<str>>`], [`TryFrom<Arc<str>>`], [`TryFrom<Rc<str>>`],
/// [`TryFrom<&[u8]>`], [`TryFrom<Vec<u8>>`],
/// [`TryFrom<Cow<'_, [u8]>>`], [`TryFrom<Box<[u8]>>`],
/// [`TryFrom<Arc<[u8]>>`], [`TryFrom<Rc<[u8]>>`],
/// [`TryFrom<&std::ffi::OsStr>`], this
/// [`TryFrom<std::ffi::OsString>`] — reads through it.
impl TryFrom<std::ffi::OsString> for BumpLevel {
    type Error = anyhow::Error;

    fn try_from(os: std::ffi::OsString) -> Result<Self, Self::Error> {
        <Self as std::convert::TryFrom<&std::ffi::OsStr>>::try_from(os.as_os_str())
    }
}

/// [`TryFrom<&std::path::Path> for BumpLevel`] routes through the
/// by-reference [`TryFrom<&std::ffi::OsStr>`] parse peer directly above
/// on [`std::path::Path::as_os_str`] of the caller-borrowed
/// filesystem-path view, so a downstream consumer bound by
/// `impl for<'a> TryFrom<&'a std::path::Path>` (a
/// [`std::path::Path::file_name`] receiver decoding a canonical
/// [`BumpLevel`] label from a release-manifest filesystem-path
/// segment, a [`std::fs::read_dir`] iterator inspector reading each
/// entry's borrowed [`&std::path::Path`] view over a release-directory
/// tree, a `walkdir` traversal borrowing each visited
/// [`&std::path::Path`] without a [`std::path::PathBuf`] allocation,
/// a generic try-conversion helper, a `serde` container whose
/// deserializer routes through a [`&std::path::Path`] intermediate at
/// a release-config-file-path parse frontier) recovers a [`BumpLevel`]
/// value from a canonical lowercase-label filesystem path through the
/// same one-oracle grammar the direct `.parse::<BumpLevel>()` call
/// sites, the sibling [`TryFrom<&str>`], [`TryFrom<String>`],
/// [`TryFrom<Cow<'_, str>>`], [`TryFrom<Box<str>>`],
/// [`TryFrom<Arc<str>>`], [`TryFrom<Rc<str>>`], [`TryFrom<&[u8]>`],
/// [`TryFrom<Vec<u8>>`], [`TryFrom<Cow<'_, [u8]>>`],
/// [`TryFrom<Box<[u8]>>`], [`TryFrom<Arc<[u8]>>`],
/// [`TryFrom<Rc<[u8]>>`], [`TryFrom<&std::ffi::OsStr>`], and
/// [`TryFrom<std::ffi::OsString>`] parse peers already read.
///
/// The by-reference filesystem-path parse peer of the by-reference
/// [`TryFrom<&std::ffi::OsStr>`] OS-string surface directly above —
/// both are parse surfaces reading the same one-oracle canonical
/// grammar, differing only on the input frontier:
/// [`TryFrom<&std::ffi::OsStr>`] takes a borrowed OS-string view for
/// consumers that already hold a [`&std::ffi::OsStr`], this
/// [`TryFrom<&std::path::Path>`] takes a borrowed filesystem-path view
/// for consumers whose input arrives at the filesystem-path layer
/// (a [`std::path::Path::file_name`] receiver, a [`std::fs::read_dir`]
/// entry inspector, a `walkdir` traversal element, a `serde`
/// deserializer routed through a [`&std::path::Path`] intermediate).
/// Both delegate through the shared [`std::str::FromStr`] parse
/// oracle: the OS-string peer through [`std::ffi::OsStr::to_str`] +
/// [`TryFrom<&str>`], this filesystem-path peer through the OS-string
/// peer via [`std::path::Path::as_os_str`] at the boundary — no
/// intermediate [`std::path::Path::to_str`] + [`str::parse`]
/// restatement: [`std::path::Path::as_os_str`] yields a borrowed
/// [`&std::ffi::OsStr`] view of the caller's [`&std::path::Path`]
/// view without allocation, so the parse-side receiver pays the
/// by-reference [`TryFrom<&std::ffi::OsStr>`] cost, not the
/// [`String`]-allocation cost of an intermediate UTF-8 decode
/// restatement. The delegation preserves the two-stage strictness
/// end-to-end: the Unicode-decode gate lives at
/// [`std::ffi::OsStr::to_str`] inside the
/// [`TryFrom<&std::ffi::OsStr>`] peer, and the canonical-label gate
/// lives at the underlying [`std::str::FromStr`] impl — the same
/// one-oracle discipline the sibling [`TryFrom<&std::ffi::OsStr>`]
/// peer applies at the OS-string input layer.
///
/// Closing peer of the by-reference filesystem-path parse trio at the
/// version-bump-magnitude ladder: [`TryFrom<&std::path::Path>`] for
/// [`crate::retry::PerAttemptRegion`] (commit dba4c6b) opened the
/// trio at the first ordered typed sum;
/// [`TryFrom<&std::path::Path>`] for
/// [`crate::probe_outcome::AdmissionTier`] (commit 321b2d8) carried
/// the mid-trio at the second ordered typed sum; this impl closes it
/// at the third ordered typed sum — matching the
/// [`TryFrom<&std::ffi::OsStr>`] OS-string by-reference parse closing
/// order (d37e6fe → 9fca3bb → 1ea7110) at this ladder's OS-string
/// borrowed-view sibling, the [`TryFrom<&[u8]>`] byte-slice
/// by-reference parse closing order (5c0c827 → cdb192c → 629b242) at
/// the byte-slice borrowed-view counterpart, and the emit-side
/// [`AsRef<std::path::Path>`] borrowed-view emit closing order
/// (17718d2 → f6c4c75 → dfd887a) at this filesystem-path frontier's
/// emit-side dual.
///
/// The identity `BumpLevel::try_from(std::path::Path::new(
/// level.as_str())).unwrap() == level` at every [`BumpLevel::ALL`]
/// variant is pinned by
/// [`tests::test_bump_level_try_from_path_agrees_with_from_str`];
/// the identity carried through a generic
/// `impl for<'a> TryFrom<&'a std::path::Path>` consumer at every
/// variant is pinned by
/// [`tests::test_bump_level_try_from_path_carries_through_generic_consumer`];
/// the strict-rejection contract on non-Unicode filesystem-path input
/// is pinned by
/// [`tests::test_bump_level_try_from_path_rejects_non_unicode_input`];
/// the strict-rejection contract on valid-Unicode non-canonical
/// filesystem-path input is pinned by
/// [`tests::test_bump_level_try_from_path_rejects_non_canonical_input`].
///
/// THEORY.md §V.4 typed primitives: the by-reference filesystem-path
/// try-conversion surface is a typed-primitive site on [`BumpLevel`]
/// itself (one `TryFrom<&std::path::Path>` impl routing through
/// [`std::path::Path::as_os_str`] and the by-reference
/// [`TryFrom<&std::ffi::OsStr>`] parse peer), not a per-consumer
/// `BumpLevel::try_from(path.as_os_str())` bridge at every downstream
/// site that types its parse contract as
/// `impl for<'a> TryFrom<&'a std::path::Path>` rather than
/// [`TryFrom<&std::ffi::OsStr>`] or [`std::str::FromStr`].
/// THEORY.md §VI.1 one-oracle: the canonical label grammar is named
/// at one site ([`BumpLevel::as_str`]), inverted at one site
/// ([`<BumpLevel as std::str::FromStr>::from_str`]), and every parse
/// surface — [`std::str::FromStr`], [`serde::Deserialize`],
/// [`TryFrom<&str>`], [`TryFrom<String>`], [`TryFrom<Cow<'_, str>>`],
/// [`TryFrom<Box<str>>`], [`TryFrom<Arc<str>>`], [`TryFrom<Rc<str>>`],
/// [`TryFrom<&[u8]>`], [`TryFrom<Vec<u8>>`],
/// [`TryFrom<Cow<'_, [u8]>>`], [`TryFrom<Box<[u8]>>`],
/// [`TryFrom<Arc<[u8]>>`], [`TryFrom<Rc<[u8]>>`],
/// [`TryFrom<&std::ffi::OsStr>`], [`TryFrom<std::ffi::OsString>`],
/// this [`TryFrom<&std::path::Path>`] — reads through it.
impl TryFrom<&std::path::Path> for BumpLevel {
    type Error = anyhow::Error;

    fn try_from(path: &std::path::Path) -> Result<Self, Self::Error> {
        <Self as std::convert::TryFrom<&std::ffi::OsStr>>::try_from(path.as_os_str())
    }
}

/// [`TryFrom<std::path::PathBuf> for BumpLevel`] routes through
/// [`std::path::PathBuf::as_path`] and the by-reference filesystem-path
/// parse peer [`TryFrom<&std::path::Path> for BumpLevel`] directly above,
/// so a downstream consumer bound by `impl TryFrom<std::path::PathBuf>`
/// (a [`std::fs::read_dir`] iterator element whose
/// [`std::fs::DirEntry::path`] returns an owned [`std::path::PathBuf`]
/// naming a bump-level-labeled release-manifest subdirectory, a
/// `walkdir::DirEntry::into_path` sink surrendering an owned
/// [`std::path::PathBuf`] at the end of a release-directory-tree walk, a
/// [`std::env::current_dir`] receiver decoding a canonical [`BumpLevel`]
/// label from the working-directory name, a `clap` argument-parse
/// frontier materializing a [`std::path::PathBuf`] value from a CLI flag
/// before try-conversion, a generic try-conversion helper
/// `fn parse<T: TryFrom<PathBuf>>` composing with owned filesystem-path
/// inputs uniformly) recovers a [`BumpLevel`] value from an owned
/// filesystem-path label buffer (`PathBuf::from("patch")`,
/// `PathBuf::from("minor")`, `PathBuf::from("major")`) through the same
/// one-oracle grammar the direct `.parse::<BumpLevel>()` call sites, the
/// sibling [`TryFrom<&str>`], [`TryFrom<String>`],
/// [`TryFrom<Cow<'_, str>>`], [`TryFrom<Box<str>>`],
/// [`TryFrom<Arc<str>>`], [`TryFrom<Rc<str>>`], [`TryFrom<&[u8]>`],
/// [`TryFrom<Vec<u8>>`], [`TryFrom<Cow<'_, [u8]>>`],
/// [`TryFrom<Box<[u8]>>`], [`TryFrom<Arc<[u8]>>`], [`TryFrom<Rc<[u8]>>`],
/// [`TryFrom<&std::ffi::OsStr>`], [`TryFrom<std::ffi::OsString>`], and
/// [`TryFrom<&std::path::Path>`] parse peers already read.
///
/// The by-value owned-buffer filesystem-path parse peer of the
/// by-reference [`TryFrom<&std::path::Path>`] surface directly above at
/// the borrowed/owned-buffer axis, and the owned-buffer sibling of the
/// [`TryFrom<std::ffi::OsString>`] owned OS-string parse peer at the
/// owned-buffer axis one frontier below via
/// [`std::path::PathBuf::as_path`] → [`std::path::Path::as_os_str`].
///
/// Closing peer of the by-value owned-buffer filesystem-path parse trio
/// at the version-bump-magnitude ladder:
/// [`TryFrom<std::path::PathBuf>`] for [`crate::retry::PerAttemptRegion`]
/// (commit 33e4e48) opened the trio at the first ordered typed sum;
/// [`TryFrom<std::path::PathBuf>`] for
/// [`crate::probe_outcome::AdmissionTier`] (commit 2855792) carried the
/// mid-trio at the second ordered typed sum; this impl closes it at the
/// third ordered typed sum — matching the [`TryFrom<&std::path::Path>`]
/// borrowed-view filesystem-path parse closing order
/// (dba4c6b → 321b2d8 → 7863a1d) at this filesystem-path frontier's
/// borrowed-view sibling, the [`TryFrom<std::ffi::OsString>`] OS-string
/// owned-buffer parse closing order (e629465 → 810794b → 6544330) at
/// the OS-string owned-buffer sibling one frontier below, the
/// [`TryFrom<String>`] UTF-8 owned-buffer parse closing order at the
/// UTF-8 frontier's owned-buffer counterpart, and the [`TryFrom<Vec<u8>>`]
/// byte-slice owned-buffer parse closing order at the byte-slice
/// frontier's owned-buffer counterpart. After this commit the
/// owned-buffer filesystem-path parse axis spans all three ordered typed
/// sums on the ladder set through ONE [`std::path::PathBuf::as_path`] +
/// [`TryFrom<&std::path::Path>`] composition each.
///
/// # Two-stage strictness
///
/// The parser is strict at the same TWO frontiers the
/// [`TryFrom<&std::path::Path>`] peer directly above is strict at,
/// inherited through the [`std::path::PathBuf::as_path`] +
/// [`TryFrom<&std::path::Path>`] delegation:
///
/// - Non-Unicode filesystem-path sequences (on Unix, a
///   [`std::path::PathBuf`] wraps a [`std::ffi::OsString`] that may hold
///   any byte sequence — an owned [`std::fs::DirEntry::path`] return
///   that is not valid Unicode, a `walkdir::DirEntry::into_path` sink
///   whose owned [`std::path::PathBuf`] carries a foreign-locale byte
///   segment, a [`std::env::current_dir`] receiver whose owned
///   working-directory name is non-Unicode) reject at the
///   [`std::ffi::OsStr::to_str`] Unicode-decode frontier reached through
///   [`std::path::PathBuf::as_path`] → [`std::path::Path::as_os_str`]
///   with a diagnostic naming the offending OS-string.
/// - Valid-Unicode filesystem-path sequences that decode to a
///   non-canonical label (`PathBuf::from("Patch")`,
///   `PathBuf::from("Minor")`, `PathBuf::from("Major")`,
///   `PathBuf::from("PATCH")`, `PathBuf::from(" patch")`,
///   `PathBuf::from("patch ")`, `PathBuf::from("pat")`,
///   `PathBuf::from("")`) reject at the underlying [`std::str::FromStr`]
///   impl — the same canonical-only strictness the borrowed-view
///   filesystem-path peer already carries, now lifted to the owned-buffer
///   filesystem-path input layer at ONE composition through the
///   by-reference [`TryFrom<&std::path::Path>`] peer via
///   [`std::path::PathBuf::as_path`].
///
/// The impl body picks [`std::path::PathBuf::as_path`] rather than an
/// intermediate [`std::path::PathBuf::into_os_string`] +
/// `TryFrom<OsString>` restatement: [`std::path::PathBuf::as_path`]
/// yields a borrowed [`&std::path::Path`] view of the caller's owned
/// [`std::path::PathBuf`] buffer without moving the underlying
/// [`std::ffi::OsString`] out of the [`std::path::PathBuf`], so the
/// parse-side receiver pays the by-reference
/// [`TryFrom<&std::path::Path>`] cost — the same borrow-then-drop
/// discipline the sibling [`TryFrom<std::ffi::OsString>`] peer applies
/// at the OS-string owned-buffer axis via
/// [`std::ffi::OsString::as_os_str`].
///
/// The identity `BumpLevel::try_from(std::path::PathBuf::from(
/// level.as_str())).unwrap() == level` at every [`BumpLevel::ALL`]
/// variant is pinned by
/// [`tests::test_bump_level_try_from_path_buf_agrees_with_from_str`];
/// the identity carried through a generic
/// `impl TryFrom<std::path::PathBuf>` consumer at every variant is
/// pinned by
/// [`tests::test_bump_level_try_from_path_buf_carries_through_generic_consumer`];
/// the strict-rejection contract on non-Unicode owned filesystem-path
/// input is pinned by
/// [`tests::test_bump_level_try_from_path_buf_rejects_non_unicode_input`];
/// the strict-rejection contract on valid-Unicode non-canonical
/// owned filesystem-path input is pinned by
/// [`tests::test_bump_level_try_from_path_buf_rejects_non_canonical_input`].
///
/// THEORY.md §V.4 typed primitives: the by-value owned-buffer
/// filesystem-path try-conversion surface is a typed-primitive site on
/// [`BumpLevel`] itself (one `TryFrom<std::path::PathBuf>` impl routing
/// through [`std::path::PathBuf::as_path`] and the by-reference
/// [`TryFrom<&std::path::Path>`] parse peer), not a per-consumer
/// `BumpLevel::try_from(path_buf.as_path())` bridge at every downstream
/// site that types its parse contract as
/// `impl TryFrom<std::path::PathBuf>`.
/// THEORY.md §VI.1 one-oracle: the canonical label grammar is named at
/// one site ([`BumpLevel::as_str`]), inverted at one site
/// ([`<BumpLevel as std::str::FromStr>::from_str`]), and every parse
/// surface — including this by-value owned-buffer filesystem-path peer
/// — reads through it.
impl TryFrom<std::path::PathBuf> for BumpLevel {
    type Error = anyhow::Error;

    fn try_from(path: std::path::PathBuf) -> Result<Self, Self::Error> {
        <Self as std::convert::TryFrom<&std::path::Path>>::try_from(path.as_path())
    }
}

/// [`TryFrom<Cow<'_, std::ffi::OsStr>> for BumpLevel`] routes through
/// [`std::borrow::Cow::as_ref`] on the caller-supplied borrowed/owned-
/// frontier OS-string and the by-reference OS-string parse peer
/// [`TryFrom<&std::ffi::OsStr>`] (which itself composes
/// [`std::ffi::OsStr::to_str`] with [`TryFrom<&str>`] whose body
/// delegates through [`<BumpLevel as std::str::FromStr>::from_str`]), so
/// a downstream consumer bound by `impl for<'a> TryFrom<Cow<'a,
/// std::ffi::OsStr>>` (a serde container that opts into
/// `#[serde(try_from = "Cow<'_, OsStr>")]` on a wrapper field, a
/// caller-owned-or-borrowed OS-string sink whose parse frontier receives
/// a [`Cow`]-typed value from a
/// [`std::path::Path::components`]/[`std::path::Component::as_os_str`]
/// walk where some segments are borrowed static labels and others own
/// their bytes, a generic try-conversion helper
/// `fn parse<T: for<'a> TryFrom<Cow<'a, std::ffi::OsStr>>>` that
/// composes with borrowed/owned-frontier OS-string inputs uniformly)
/// recovers a [`BumpLevel`] value from a borrowed-or-owned canonical
/// OS-string label (`Cow::Borrowed(OsStr::new("patch"))`,
/// `Cow::Owned(OsString::from("patch"))`, and analogously for `"minor"`
/// / `"major"`) through the same one-oracle grammar the direct
/// `.parse::<BumpLevel>()` call sites and the sibling
/// [`TryFrom<&str>`], [`TryFrom<String>`], [`TryFrom<Cow<'_, str>>`],
/// [`TryFrom<Box<str>>`], [`TryFrom<Arc<str>>`], [`TryFrom<Rc<str>>`],
/// [`TryFrom<&[u8]>`], [`TryFrom<Vec<u8>>`], [`TryFrom<Cow<'_, [u8]>>`],
/// [`TryFrom<Box<[u8]>>`], [`TryFrom<Arc<[u8]>>`], [`TryFrom<Rc<[u8]>>`],
/// [`TryFrom<&std::ffi::OsStr>`], [`TryFrom<std::ffi::OsString>`],
/// [`TryFrom<&std::path::Path>`], and [`TryFrom<std::path::PathBuf>`]
/// parse peers already read.
///
/// The borrowed/owned-frontier OS-string parse peer of the
/// [`From<BumpLevel> for Cow<'static, std::ffi::OsStr>`] emit surface at
/// the OS-string borrowed/owned-frontier axis: the emit side yields a
/// `Cow::Borrowed` view of the `'static`-lived OS-string label
/// constant, this parse side accepts a `Cow<'_, std::ffi::OsStr>`
/// whose contents may be borrowed (`Cow::Borrowed(&OsStr)`) or owned
/// (`Cow::Owned(OsString)`) — the two-stage strictness discipline
/// (Unicode validity at the OS-string decode frontier gated by
/// [`std::ffi::OsStr::to_str`], canonical-label grammar at the parse
/// frontier gated by [`std::str::FromStr`]) is inherited unchanged from
/// the by-reference [`TryFrom<&std::ffi::OsStr>`] peer via
/// [`std::borrow::Cow::as_ref`] which yields a `&std::ffi::OsStr` view
/// of either the borrowed or owned inner variant.
///
/// Closing peer of the borrowed/owned-frontier OS-string parse trio at
/// the version-bump-magnitude ladder:
/// [`TryFrom<std::borrow::Cow<'_, std::ffi::OsStr>>`] for
/// [`crate::retry::PerAttemptRegion`] (commit 16f6b8e) opened the trio
/// at the first ordered typed sum;
/// [`TryFrom<std::borrow::Cow<'_, std::ffi::OsStr>>`] for
/// [`crate::probe_outcome::AdmissionTier`] (commit d68695f) carried the
/// mid-trio at the second ordered typed sum; this impl closes it at the
/// third ordered typed sum — matching the [`TryFrom<Cow<'_, str>>`]
/// borrowed/owned-frontier UTF-8-string parse closing order (0b85b4f →
/// 03d977b → 6301ac4) at the UTF-8 string sibling one frontier below,
/// the [`TryFrom<&std::ffi::OsStr>`] borrowed-view OS-string parse
/// closing order (d37e6fe → 9fca3bb → 1ea7110) at this OS-string
/// frontier's borrowed-view sibling above, the
/// [`TryFrom<std::ffi::OsString>`] owned-buffer OS-string parse closing
/// order (e629465 → 810794b → 6544330) at this frontier's owned-buffer
/// sibling above, and the [`From<BumpLevel> for Cow<'static,
/// std::ffi::OsStr>`] borrowed/owned-frontier OS-string emit closing
/// order (24f6110 → 4e94fc5 → f305c9b) at this frontier's borrowed/
/// owned-frontier emit sibling above. After this commit the borrowed/
/// owned-frontier OS-string parse axis spans all three ordered typed
/// sums on the ladder set through ONE [`std::borrow::Cow::as_ref`] +
/// [`TryFrom<&std::ffi::OsStr>`] composition each. Opens the next
/// OsStr/Path parse layer — a filesystem-path borrowed/owned-frontier
/// peer at `TryFrom<Cow<'_, std::path::Path>>`, or the shrunk-owned
/// OsStr/Path peer at `TryFrom<Box<std::ffi::OsStr>>` /
/// `TryFrom<Box<std::path::Path>>` — routing through this typed-
/// primitive rather than restating the two-stage decode-then-parse
/// discipline at every Cow-typed OS-string sum.
///
/// # Two-stage strictness
///
/// The parser is strict at the same TWO frontiers the by-reference
/// [`TryFrom<&std::ffi::OsStr>`] peer above is strict at, inherited
/// through the [`std::borrow::Cow::as_ref`] +
/// [`TryFrom<&std::ffi::OsStr>`] delegation:
///
/// - Non-Unicode OS-string sequences (on Unix, a
///   [`std::ffi::OsString`] may hold any byte sequence via
///   [`std::os::unix::ffi::OsStringExt::from_vec`] — a foreign-locale
///   byte segment materialized into an owned [`std::ffi::OsString`]
///   wrapped in [`std::borrow::Cow::Owned`], a [`std::ffi::OsStr::new`]
///   borrow over a non-Unicode byte slice wrapped in
///   [`std::borrow::Cow::Borrowed`]) reject at the
///   [`std::ffi::OsStr::to_str`] Unicode-decode frontier reached
///   through [`std::borrow::Cow::as_ref`] with a diagnostic naming the
///   offending OS-string.
/// - Valid-Unicode OS-string sequences that decode to a non-canonical
///   label (`Cow::Owned(OsString::from("Patch"))`,
///   `Cow::Borrowed(OsStr::new("Minor"))`,
///   `Cow::Borrowed(OsStr::new("Major"))`,
///   `Cow::Borrowed(OsStr::new("PATCH"))`,
///   `Cow::Owned(OsString::from(" patch"))`,
///   `Cow::Owned(OsString::from("patch "))`,
///   `Cow::Borrowed(OsStr::new("pat"))`,
///   `Cow::Borrowed(OsStr::new(""))`) reject at the underlying
///   [`std::str::FromStr`] impl — the same canonical-only strictness
///   the borrowed-view OS-string peer already carries, now lifted to
///   the borrowed/owned-frontier OS-string input layer at ONE
///   composition through the by-reference
///   [`TryFrom<&std::ffi::OsStr>`] peer via
///   [`std::borrow::Cow::as_ref`].
///
/// The impl body picks [`std::borrow::Cow::as_ref`] rather than an
/// intermediate [`std::borrow::Cow::into_owned`] + `TryFrom<OsString>`
/// restatement: [`std::borrow::Cow::as_ref`] yields a borrowed
/// [`&std::ffi::OsStr`] view of either variant without cloning the
/// borrowed side or moving the owned side, so a
/// [`std::borrow::Cow::Borrowed`] input pays zero allocation and a
/// [`std::borrow::Cow::Owned`] input pays zero clone — the
/// borrow-then-drop discipline the sibling
/// [`TryFrom<std::ffi::OsString>`] peer applies at the OS-string owned-
/// buffer axis via [`std::ffi::OsString::as_os_str`] lifted to the
/// borrowed/owned-frontier axis via [`std::borrow::Cow::as_ref`].
///
/// The identity `BumpLevel::try_from(std::borrow::Cow::Owned(
/// std::ffi::OsString::from(level.as_str()))).unwrap() == level` and
/// `BumpLevel::try_from(std::borrow::Cow::Borrowed(
/// std::ffi::OsStr::new(level.as_str()))).unwrap() == level` at every
/// [`BumpLevel::ALL`] variant is pinned by
/// [`tests::test_bump_level_try_from_cow_os_str_agrees_with_from_str`];
/// the identity carried through a generic
/// `impl for<'a> TryFrom<Cow<'a, std::ffi::OsStr>>` consumer at every
/// variant is pinned by
/// [`tests::test_bump_level_try_from_cow_os_str_carries_through_generic_consumer`];
/// the strict-rejection contract on non-Unicode borrowed/owned OS-
/// string input is pinned by
/// [`tests::test_bump_level_try_from_cow_os_str_rejects_non_unicode_input`];
/// the strict-rejection contract on valid-Unicode non-canonical
/// borrowed/owned OS-string input is pinned by
/// [`tests::test_bump_level_try_from_cow_os_str_rejects_non_canonical_input`].
///
/// THEORY.md §V.4 typed primitives: the borrowed/owned-frontier OS-
/// string try-conversion parse surface is a typed-primitive site on
/// [`BumpLevel`] itself (one `TryFrom<Cow<'_, std::ffi::OsStr>>` impl
/// routing through [`std::borrow::Cow::as_ref`] and the by-reference
/// [`TryFrom<&std::ffi::OsStr>`] peer), not a per-consumer
/// `BumpLevel::try_from(cow.as_ref())` bridge at every downstream site
/// that types its parse contract as
/// `impl for<'a> TryFrom<Cow<'a, std::ffi::OsStr>>`.
/// THEORY.md §VI.1 one-oracle: the canonical label grammar is named at
/// one site ([`BumpLevel::as_str`]), inverted at one site
/// ([`<BumpLevel as std::str::FromStr>::from_str`]), and every parse
/// surface — including this borrowed/owned-frontier OS-string peer —
/// reads through it.
impl<'a> TryFrom<std::borrow::Cow<'a, std::ffi::OsStr>> for BumpLevel {
    type Error = anyhow::Error;

    fn try_from(os_str: std::borrow::Cow<'a, std::ffi::OsStr>) -> Result<Self, Self::Error> {
        <Self as std::convert::TryFrom<&std::ffi::OsStr>>::try_from(os_str.as_ref())
    }
}

/// [`TryFrom<Cow<'_, std::path::Path>> for BumpLevel`] routes through
/// [`std::borrow::Cow::as_ref`] on the caller-supplied borrowed/owned-
/// frontier filesystem-path and the by-reference filesystem-path parse
/// peer [`TryFrom<&std::path::Path>`] (which itself composes
/// [`std::path::Path::as_os_str`] with the by-reference OS-string parse
/// peer [`TryFrom<&std::ffi::OsStr>`] which composes
/// [`std::ffi::OsStr::to_str`] with [`TryFrom<&str>`] which itself
/// delegates through [`<BumpLevel as std::str::FromStr>::from_str`]), so
/// a downstream consumer bound by `impl for<'a> TryFrom<Cow<'a,
/// std::path::Path>>` (a serde container that opts into
/// `#[serde(try_from = "Cow<'_, Path>")]` on a wrapper field, a
/// [`std::path::Path::components`]/[`std::path::Component::as_os_str`]
/// walk that materializes some segments as a borrowed static
/// [`std::path::Path`] and others as an owned [`std::path::PathBuf`]
/// before wrapping in a [`std::borrow::Cow`], a generic try-conversion
/// helper `fn parse<T: for<'a> TryFrom<Cow<'a, std::path::Path>>>` that
/// composes with borrowed/owned-frontier filesystem-path inputs
/// uniformly) recovers a [`BumpLevel`] value from a borrowed-or-owned
/// canonical filesystem-path label
/// (`Cow::Borrowed(Path::new("patch"))`,
/// `Cow::Owned(PathBuf::from("patch"))`, and analogously for `"minor"`
/// / `"major"`) through the same one-oracle grammar the direct
/// `.parse::<BumpLevel>()` call sites and the sibling
/// [`TryFrom<&str>`], [`TryFrom<String>`], [`TryFrom<Cow<'_, str>>`],
/// [`TryFrom<Box<str>>`], [`TryFrom<Arc<str>>`], [`TryFrom<Rc<str>>`],
/// [`TryFrom<&[u8]>`], [`TryFrom<Vec<u8>>`], [`TryFrom<Cow<'_, [u8]>>`],
/// [`TryFrom<Box<[u8]>>`], [`TryFrom<Arc<[u8]>>`], [`TryFrom<Rc<[u8]>>`],
/// [`TryFrom<&std::ffi::OsStr>`], [`TryFrom<std::ffi::OsString>`],
/// [`TryFrom<Cow<'_, std::ffi::OsStr>>`], [`TryFrom<&std::path::Path>`],
/// and [`TryFrom<std::path::PathBuf>`] parse peers already read.
///
/// The borrowed/owned-frontier filesystem-path parse peer of the
/// [`From<BumpLevel> for Cow<'static, std::path::Path>`] emit surface at
/// the filesystem-path borrowed/owned-frontier axis: the emit side yields
/// a `Cow::Borrowed` view of the `'static`-lived filesystem-path label
/// constant, this parse side accepts a `Cow<'_, std::path::Path>` whose
/// contents may be borrowed (`Cow::Borrowed(&Path)`) or owned
/// (`Cow::Owned(PathBuf)`) — the two-stage strictness discipline
/// (Unicode validity at the OS-string decode frontier gated by
/// [`std::ffi::OsStr::to_str`] reached through
/// [`std::path::Path::as_os_str`], canonical-label grammar at the parse
/// frontier gated by [`std::str::FromStr`]) is inherited unchanged from
/// the by-reference [`TryFrom<&std::path::Path>`] peer via
/// [`std::borrow::Cow::as_ref`] which yields a `&std::path::Path` view of
/// either the borrowed or owned inner variant.
///
/// Closing peer of the borrowed/owned-frontier filesystem-path parse trio
/// at the version-bump-magnitude ladder:
/// [`TryFrom<std::borrow::Cow<'_, std::path::Path>>`] for
/// [`crate::retry::PerAttemptRegion`] (commit 47c471f) opened the trio at
/// the first ordered typed sum;
/// [`TryFrom<std::borrow::Cow<'_, std::path::Path>>`] for
/// [`crate::probe_outcome::AdmissionTier`] (commit b52ed1e) carried the
/// mid-trio at the second ordered typed sum; this impl closes it at the
/// third ordered typed sum — matching the [`TryFrom<Cow<'_,
/// std::ffi::OsStr>>`] borrowed/owned-frontier OS-string parse closing
/// order (16f6b8e → d68695f → 7e37e95) at the OS-string sibling one
/// frontier below, the [`TryFrom<Cow<'_, str>>`] borrowed/owned-frontier
/// UTF-8-string parse closing order (0b85b4f → 03d977b → 6301ac4) at the
/// UTF-8 string sibling two frontiers below, the
/// [`TryFrom<&std::path::Path>`] borrowed-view filesystem-path parse
/// closing order (dba4c6b → 321b2d8 → 7863a1d) at this filesystem-path
/// frontier's borrowed-view sibling above, the
/// [`TryFrom<std::path::PathBuf>`] owned-buffer filesystem-path parse
/// closing order (33e4e48 → 2855792 → b1945f4) at this frontier's
/// owned-buffer sibling above, and the [`From<BumpLevel> for Cow<'static,
/// std::path::Path>`] borrowed/owned-frontier filesystem-path emit
/// closing order (cfb6125 → f11faad → 9e12c75) at this frontier's
/// borrowed/owned-frontier emit sibling above. After this commit the
/// borrowed/owned-frontier filesystem-path parse axis spans all three
/// ordered typed sums on the ladder set through ONE
/// [`std::borrow::Cow::as_ref`] + [`TryFrom<&std::path::Path>`]
/// composition each. Opens the next OsStr/Path parse layer — a
/// shrunk-owned filesystem-path peer at `TryFrom<Box<std::path::Path>>`,
/// or the shared-owned filesystem-path peer at
/// `TryFrom<Arc<std::path::Path>>` / `TryFrom<Rc<std::path::Path>>` —
/// routing through this typed-primitive rather than restating the
/// three-stage decode-then-parse discipline at every Cow-typed
/// filesystem-path sum.
///
/// # Two-stage strictness
///
/// The parser is strict at the same TWO frontiers the by-reference
/// [`TryFrom<&std::path::Path>`] peer above is strict at, inherited
/// through the [`std::borrow::Cow::as_ref`] +
/// [`TryFrom<&std::path::Path>`] delegation:
///
/// - Non-Unicode filesystem-path sequences (on Unix, a
///   [`std::path::PathBuf`] wraps a [`std::ffi::OsString`] that may hold
///   any byte sequence via
///   [`std::os::unix::ffi::OsStringExt::from_vec`], and a
///   [`&std::path::Path`] wraps a [`&std::ffi::OsStr`] whose bytes may be
///   non-Unicode via [`std::os::unix::ffi::OsStrExt::from_bytes`] — a
///   foreign-locale filesystem path segment materialized as an owned
///   [`std::path::PathBuf`] wrapped in [`std::borrow::Cow::Owned`], a
///   `walkdir`-yielded borrowed [`&std::path::Path`] with a non-Unicode
///   filename wrapped in [`std::borrow::Cow::Borrowed`]) reject at the
///   [`std::ffi::OsStr::to_str`] Unicode-decode frontier reached through
///   [`std::path::Path::as_os_str`] via [`std::borrow::Cow::as_ref`] with
///   a diagnostic naming the offending filesystem path.
/// - Valid-Unicode filesystem-path sequences that decode to a
///   non-canonical label (`Cow::Owned(PathBuf::from("Patch"))`,
///   `Cow::Borrowed(Path::new("Minor"))`,
///   `Cow::Borrowed(Path::new("Major"))`,
///   `Cow::Borrowed(Path::new("PATCH"))`,
///   `Cow::Owned(PathBuf::from(" patch"))`,
///   `Cow::Owned(PathBuf::from("patch "))`,
///   `Cow::Borrowed(Path::new("pat"))`,
///   `Cow::Borrowed(Path::new(""))`) reject at the underlying
///   [`std::str::FromStr`] impl — the same canonical-only strictness the
///   borrowed-view filesystem-path peer already carries, now lifted to
///   the borrowed/owned-frontier filesystem-path input layer at ONE
///   composition through the by-reference [`TryFrom<&std::path::Path>`]
///   peer via [`std::borrow::Cow::as_ref`].
///
/// The impl body picks [`std::borrow::Cow::as_ref`] rather than an
/// intermediate [`std::borrow::Cow::into_owned`] + `TryFrom<PathBuf>`
/// restatement: [`std::borrow::Cow::as_ref`] yields a borrowed
/// [`&std::path::Path`] view of either variant without cloning the
/// borrowed side or moving the owned side, so a
/// [`std::borrow::Cow::Borrowed`] input pays zero allocation and a
/// [`std::borrow::Cow::Owned`] input pays zero clone — the
/// borrow-then-drop discipline the sibling [`TryFrom<std::path::PathBuf>`]
/// peer applies at the filesystem-path owned-buffer axis via
/// [`std::path::PathBuf::as_path`] lifted to the borrowed/owned-frontier
/// axis via [`std::borrow::Cow::as_ref`].
///
/// The identity `BumpLevel::try_from(std::borrow::Cow::Owned(
/// std::path::PathBuf::from(level.as_str()))).unwrap() == level` and
/// `BumpLevel::try_from(std::borrow::Cow::Borrowed(
/// std::path::Path::new(level.as_str()))).unwrap() == level` at every
/// [`BumpLevel::ALL`] variant is pinned by
/// [`tests::test_bump_level_try_from_cow_path_agrees_with_from_str`];
/// the identity carried through a generic
/// `impl for<'a> TryFrom<Cow<'a, std::path::Path>>` consumer at every
/// variant is pinned by
/// [`tests::test_bump_level_try_from_cow_path_carries_through_generic_consumer`];
/// the strict-rejection contract on non-Unicode borrowed/owned
/// filesystem-path input is pinned by
/// [`tests::test_bump_level_try_from_cow_path_rejects_non_unicode_input`];
/// the strict-rejection contract on valid-Unicode non-canonical
/// borrowed/owned filesystem-path input is pinned by
/// [`tests::test_bump_level_try_from_cow_path_rejects_non_canonical_input`].
///
/// THEORY.md §V.4 typed primitives: the borrowed/owned-frontier
/// filesystem-path try-conversion parse surface is a typed-primitive site
/// on [`BumpLevel`] itself (one `TryFrom<Cow<'_, std::path::Path>>` impl
/// routing through [`std::borrow::Cow::as_ref`] and the by-reference
/// [`TryFrom<&std::path::Path>`] peer), not a per-consumer
/// `BumpLevel::try_from(cow.as_ref())` bridge at every downstream site
/// that types its parse contract as
/// `impl for<'a> TryFrom<Cow<'a, std::path::Path>>`.
/// THEORY.md §VI.1 one-oracle: the canonical label grammar is named at
/// one site ([`BumpLevel::as_str`]), inverted at one site
/// ([`<BumpLevel as std::str::FromStr>::from_str`]), and every parse
/// surface — including this borrowed/owned-frontier filesystem-path peer
/// — reads through it.
impl<'a> TryFrom<std::borrow::Cow<'a, std::path::Path>> for BumpLevel {
    type Error = anyhow::Error;

    fn try_from(path: std::borrow::Cow<'a, std::path::Path>) -> Result<Self, Self::Error> {
        <Self as std::convert::TryFrom<&std::path::Path>>::try_from(path.as_ref())
    }
}

/// Structural mirror of `impl TryFrom<Box<std::ffi::OsStr>> for
/// PerAttemptRegion` (commit b6c015b) and `impl TryFrom<Box<
/// std::ffi::OsStr>> for AdmissionTier` (commit 84c6966) — the
/// shrunk-owned OS-string parse peer at the third ordered typed sum
/// (trio-closing slot). Routes through
/// [`std::boxed::Box::<std::ffi::OsStr>::as_ref`] on the caller-
/// supplied shrunk-owned OS-string and the by-reference OS-string
/// parse peer [`TryFrom<&std::ffi::OsStr>`] (which itself composes
/// [`std::ffi::OsStr::to_str`] with [`TryFrom<&str>`] which itself
/// delegates through [`<BumpLevel as std::str::FromStr>::from_str`]),
/// so a downstream consumer bound by `impl TryFrom<Box<
/// std::ffi::OsStr>>` (a serde container that opts into
/// `#[serde(try_from = "Box<OsStr>")]` on a wrapper field, a
/// [`std::ffi::OsString::into_boxed_os_str`]-shrunk release-manifest
/// path-segment input at a slot arena that trades the resizable-buffer
/// [`std::ffi::OsString`] receiver footprint for a single-allocation
/// immutable [`Box<std::ffi::OsStr>`], a generic try-conversion helper
/// `fn parse<T: TryFrom<Box<std::ffi::OsStr>>>` that composes with
/// shrunk-owned OS-string inputs) recovers a [`BumpLevel`] value from
/// a shrunk-owned canonical OS-string label through the same one-
/// oracle grammar the sibling [`TryFrom<&std::ffi::OsStr>`],
/// [`TryFrom<std::ffi::OsString>`],
/// [`TryFrom<Cow<'_, std::ffi::OsStr>>`], and (one frontier below)
/// [`TryFrom<Box<str>>`], [`TryFrom<Box<[u8]>>`] shrunk-owned parse
/// peers already read at neighboring UTF-8/byte-slice frontiers.
///
/// The two-stage strictness discipline (Unicode validity at the OS-
/// string decode frontier gated by [`std::ffi::OsStr::to_str`],
/// canonical-label grammar at the parse frontier gated by
/// [`FromStr`]) is inherited unchanged from the by-reference
/// [`TryFrom<&std::ffi::OsStr>`] peer via
/// [`std::boxed::Box::<std::ffi::OsStr>::as_ref`] which yields a
/// `&std::ffi::OsStr` view of the boxed inner payload without moving
/// out or reallocating.
///
/// The impl body picks [`std::boxed::Box::<std::ffi::OsStr>::as_ref`]
/// rather than an intermediate `Box::<std::ffi::OsStr>::into` +
/// `TryFrom<OsString>` restatement: the [`AsRef`] view yields a
/// borrowed `&std::ffi::OsStr` window over the boxed heap allocation
/// without converting the shrunk-owned receiver into a resizable
/// [`std::ffi::OsString`] first, so the receiver pays no reallocation
/// and no capacity-vs-length metadata rebuild on the fast path — the
/// same borrow-then-drop discipline the sibling
/// [`TryFrom<std::ffi::OsString>`] and
/// [`TryFrom<Cow<'_, std::ffi::OsStr>>`] peers apply at the
/// resizable-buffer and borrowed/owned-frontier axes, lifted to the
/// shrunk-owned axis via
/// [`std::boxed::Box::<std::ffi::OsStr>::as_ref`].
///
/// Trio-closing slot in the shrunk-owned OS-string parse trio at the
/// bump-level ladder — the opening peer at
/// [`crate::retry::PerAttemptRegion`] was carried at b6c015b
/// (`TryFrom<Box<std::ffi::OsStr>> for PerAttemptRegion` — opens
/// shrunk-owned OS-string parse trio), the mid-trio peer at
/// [`crate::probe_outcome::AdmissionTier`] followed at 84c6966, and
/// this impl carries the closing slot at the third ordered typed sum.
/// After this commit the shrunk-owned OS-string parse axis spans all
/// three ordered typed sums on the ladder set through ONE
/// [`std::boxed::Box::<std::ffi::OsStr>::as_ref`] +
/// [`TryFrom<&std::ffi::OsStr>`] composition each — matching the
/// [`TryFrom<Cow<'_, std::ffi::OsStr>>`] borrowed/owned-frontier
/// OS-string parse closing order (16f6b8e → d68695f → 7e37e95), the
/// [`TryFrom<&std::ffi::OsStr>`] borrowed-view OS-string parse
/// closing order (d37e6fe → 9fca3bb → 1ea7110), the
/// [`TryFrom<std::ffi::OsString>`] owned-buffer OS-string parse
/// closing order (e629465 → 810794b → 6544330), and (one frontier
/// above) the shrunk-owned filesystem-path parse closing order
/// (315c145 → 657434c → 336e453).
///
/// THEORY.md §V.4 typed primitives: the shrunk-owned OS-string
/// try-conversion parse surface is a typed-primitive site on
/// [`BumpLevel`] itself (one `TryFrom<Box<std::ffi::OsStr>>` impl
/// routing through [`std::boxed::Box::<std::ffi::OsStr>::as_ref`]
/// and the by-reference [`TryFrom<&std::ffi::OsStr>`] peer), not a
/// per-consumer `BumpLevel::try_from(boxed.as_ref())` bridge at
/// every downstream site that types its parse contract as
/// `impl TryFrom<Box<std::ffi::OsStr>>`.
/// THEORY.md §VI.1 one-oracle: the canonical label grammar is named
/// at one site ([`BumpLevel::as_str`]), inverted at one site
/// ([`<BumpLevel as std::str::FromStr>::from_str`]), and every parse
/// surface — including this shrunk-owned OS-string peer — reads
/// through it.
impl TryFrom<Box<std::ffi::OsStr>> for BumpLevel {
    type Error = anyhow::Error;

    fn try_from(os_str: Box<std::ffi::OsStr>) -> Result<Self, Self::Error> {
        <Self as std::convert::TryFrom<&std::ffi::OsStr>>::try_from(os_str.as_ref())
    }
}

/// Structural mirror of `impl TryFrom<Box<std::path::Path>> for
/// PerAttemptRegion` (commit 315c145) and `impl TryFrom<Box<
/// std::path::Path>> for AdmissionTier` (commit 657434c) — the
/// shrunk-owned filesystem-path parse peer at the third ordered typed
/// sum (trio-closing slot). Routes through
/// [`std::boxed::Box::<std::path::Path>::as_ref`] on the caller-
/// supplied shrunk-owned filesystem-path and the by-reference
/// filesystem-path parse peer [`TryFrom<&std::path::Path>`] (which
/// itself composes [`std::path::Path::as_os_str`] with the by-
/// reference OS-string parse peer [`TryFrom<&std::ffi::OsStr>`] which
/// composes [`std::ffi::OsStr::to_str`] with [`TryFrom<&str>`] which
/// itself delegates through
/// [`<BumpLevel as std::str::FromStr>::from_str`]), so a downstream
/// consumer bound by `impl TryFrom<Box<std::path::Path>>` (a serde
/// container that opts into `#[serde(try_from = "Box<Path>")]` on a
/// wrapper field, a [`std::path::PathBuf::into_boxed_path`]-shrunk
/// release-manifest path-segment input at a slot arena that trades
/// the resizable-buffer [`std::path::PathBuf`] receiver footprint for
/// a single-allocation immutable [`Box<std::path::Path>`], a generic
/// try-conversion helper `fn parse<T: TryFrom<Box<std::path::Path>>>`
/// that composes with shrunk-owned filesystem-path inputs) recovers a
/// [`BumpLevel`] value from a shrunk-owned canonical filesystem-path
/// label through the same one-oracle grammar the sibling
/// [`TryFrom<&std::path::Path>`], [`TryFrom<std::path::PathBuf>`],
/// [`TryFrom<Cow<'_, std::path::Path>>`], and (one frontier below)
/// [`TryFrom<Box<str>>`], [`TryFrom<Box<[u8]>>`] shrunk-owned parse
/// peers already read at neighboring OsStr/UTF-8/byte-slice
/// frontiers.
///
/// The two-stage strictness discipline (Unicode validity at the OS-
/// string decode frontier gated by [`std::ffi::OsStr::to_str`]
/// reached through [`std::path::Path::as_os_str`], canonical-label
/// grammar at the parse frontier gated by [`FromStr`]) is inherited
/// unchanged from the by-reference [`TryFrom<&std::path::Path>`]
/// peer via [`std::boxed::Box::<std::path::Path>::as_ref`] which
/// yields a `&std::path::Path` view of the boxed inner payload
/// without moving out or reallocating.
///
/// The impl body picks [`std::boxed::Box::<std::path::Path>::as_ref`]
/// rather than an intermediate `Box::<std::path::Path>::into` +
/// `TryFrom<PathBuf>` restatement: the [`AsRef`] view yields a
/// borrowed `&std::path::Path` window over the boxed heap allocation
/// without converting the shrunk-owned receiver into a resizable
/// [`std::path::PathBuf`] first, so the receiver pays no
/// reallocation and no capacity-vs-length metadata rebuild on the
/// fast path — the same borrow-then-drop discipline the sibling
/// [`TryFrom<std::path::PathBuf>`] and
/// [`TryFrom<Cow<'_, std::path::Path>>`] peers apply at the
/// resizable-buffer and borrowed/owned-frontier axes, lifted to the
/// shrunk-owned axis via
/// [`std::boxed::Box::<std::path::Path>::as_ref`].
///
/// Trio-closing slot in the shrunk-owned filesystem-path parse trio
/// at the bump-level ladder — the opening peer at
/// [`crate::retry::PerAttemptRegion`] was carried at 315c145
/// (`TryFrom<Box<std::path::Path>> for PerAttemptRegion` — opens
/// shrunk-owned filesystem-path parse trio), the mid-trio peer at
/// [`crate::probe_outcome::AdmissionTier`] followed at 657434c, and
/// this impl carries the closing slot at the third ordered typed
/// sum. After this commit the shrunk-owned filesystem-path parse
/// axis spans all three ordered typed sums on the ladder set through
/// ONE [`std::boxed::Box::<std::path::Path>::as_ref`] +
/// [`TryFrom<&std::path::Path>`] composition each — matching the
/// [`TryFrom<Cow<'_, std::path::Path>>`] borrowed/owned-frontier
/// filesystem-path parse closing order
/// (47c471f → b52ed1e → 87eda90), the [`TryFrom<&std::path::Path>`]
/// borrowed-view filesystem-path parse closing order
/// (dba4c6b → 321b2d8 → 7863a1d), and the
/// [`TryFrom<std::path::PathBuf>`] owned-buffer filesystem-path parse
/// closing order (33e4e48 → 2855792 → b1945f4) at neighboring
/// OsStr/Path frontiers.
///
/// THEORY.md §V.4 typed primitives: the shrunk-owned filesystem-path
/// try-conversion parse surface is a typed-primitive site on
/// [`BumpLevel`] itself (one `TryFrom<Box<std::path::Path>>` impl
/// routing through [`std::boxed::Box::<std::path::Path>::as_ref`]
/// and the by-reference [`TryFrom<&std::path::Path>`] peer), not a
/// per-consumer `BumpLevel::try_from(boxed.as_ref())` bridge at
/// every downstream site that types its parse contract as
/// `impl TryFrom<Box<std::path::Path>>`.
/// THEORY.md §VI.1 one-oracle: the canonical label grammar is named
/// at one site ([`BumpLevel::as_str`]), inverted at one site
/// ([`<BumpLevel as std::str::FromStr>::from_str`]), and every parse
/// surface — including this shrunk-owned filesystem-path peer —
/// reads through it.
impl TryFrom<Box<std::path::Path>> for BumpLevel {
    type Error = anyhow::Error;

    fn try_from(path: Box<std::path::Path>) -> Result<Self, Self::Error> {
        <Self as std::convert::TryFrom<&std::path::Path>>::try_from(path.as_ref())
    }
}

/// Structural mirror of `impl TryFrom<Arc<std::ffi::OsStr>> for
/// PerAttemptRegion` (commit 478313f) and `impl TryFrom<Arc<
/// std::ffi::OsStr>> for AdmissionTier` (commit 7f411bc) — the
/// shared-owned OS-string parse peer at the third ordered typed sum
/// (trio-closing slot). Routes through
/// [`std::sync::Arc::<std::ffi::OsStr>::as_ref`] on the caller-supplied
/// shared-owned OS-string and the by-reference OS-string parse peer
/// [`TryFrom<&std::ffi::OsStr>`] (which itself composes
/// [`std::ffi::OsStr::to_str`] with [`TryFrom<&str>`] which itself
/// delegates through [`<BumpLevel as std::str::FromStr>::from_str`]),
/// so a downstream consumer bound by `impl TryFrom<Arc<
/// std::ffi::OsStr>>` (a shared-owned OS-string release-manifest
/// path-segment input handed to sibling threads through an atomic-
/// refcount header, a [`Box<std::ffi::OsStr>::into`] shared-buffer
/// input that trades exclusive shrunk-owned single-owner semantics
/// for a shared reader-count of the same immutable OS-string, a
/// generic try-conversion helper `fn parse<T: TryFrom<Arc<
/// std::ffi::OsStr>>>` that composes with shared-owned OS-string
/// inputs) recovers a [`BumpLevel`] value from a shared-owned
/// canonical OS-string label (`"patch"`, `"minor"`, `"major"`)
/// through the same one-oracle grammar the sibling
/// [`TryFrom<&std::ffi::OsStr>`], [`TryFrom<std::ffi::OsString>`],
/// [`TryFrom<Cow<'_, std::ffi::OsStr>>`],
/// [`TryFrom<Box<std::ffi::OsStr>>`], and (one frontier below)
/// [`TryFrom<std::sync::Arc<str>>`] shared-owned parse peers read.
///
/// The by-value shared-owned OS-string parse peer of
/// [`TryFrom<Box<std::ffi::OsStr>>`] above — both are shrunk/shared
/// immutable-heap OS-string parse surfaces of the label-axis
/// conversion set, differing on ownership discipline:
/// [`TryFrom<Box<std::ffi::OsStr>>`] consumes a single-owner shrunk
/// buffer with exclusive ownership semantics, this
/// [`TryFrom<Arc<std::ffi::OsStr>>`] consumes a shared-owner atomic-
/// refcount buffer that may have surviving clones outside the
/// receiver. Both route through the shared
/// [`<BumpLevel as std::str::FromStr>::from_str`] canonical-label
/// parse oracle: the shrunk-owned peer through
/// [`std::boxed::Box::<std::ffi::OsStr>::as_ref`] composed with
/// [`TryFrom<&std::ffi::OsStr>`], this shared-owned peer through
/// [`std::sync::Arc::<std::ffi::OsStr>::as_ref`] composed with
/// [`TryFrom<&std::ffi::OsStr>`] — the same canonical grammar lifted
/// to the shared-owned OS-string layer.
///
/// The two-stage strictness discipline (Unicode validity at the OS-
/// string decode frontier gated by [`std::ffi::OsStr::to_str`],
/// canonical-label grammar at the parse frontier gated by
/// [`FromStr`]) is inherited unchanged from the by-reference
/// [`TryFrom<&std::ffi::OsStr>`] peer via
/// [`std::sync::Arc::<std::ffi::OsStr>::as_ref`] which yields a
/// `&std::ffi::OsStr` view of the shared inner payload without
/// mutating the refcount or reallocating.
///
/// The impl body picks [`std::sync::Arc::<std::ffi::OsStr>::as_ref`]
/// rather than [`std::sync::Arc::<std::ffi::OsStr>::to_string`] or an
/// intermediate [`std::sync::Arc::<std::ffi::OsStr>::to_owned`] +
/// [`TryFrom<OsString>`] restatement: the [`AsRef`] view yields a
/// borrowed `&std::ffi::OsStr` window over the shared heap allocation
/// without cloning the atomic-refcount header, converting the shared-
/// owned receiver into a resizable [`std::ffi::OsString`], or forking
/// the underlying immutable buffer — the receiver pays no atomic
/// increment on the fast path, only the eventual drop-decrement when
/// the [`std::sync::Arc<std::ffi::OsStr>`] receiver falls out of
/// scope. The same borrow-then-drop discipline the sibling
/// [`TryFrom<Box<std::ffi::OsStr>>`],
/// [`TryFrom<std::ffi::OsString>`], and
/// [`TryFrom<Cow<'_, std::ffi::OsStr>>`] peers apply at the shrunk-
/// owned, resizable-buffer, and borrowed/owned-frontier axes, lifted
/// to the shared-owned axis via
/// [`std::sync::Arc::<std::ffi::OsStr>::as_ref`].
///
/// Trio-closing slot in the shared-owned OS-string parse trio at
/// the bump-level ladder — the opening peer at
/// [`crate::retry::PerAttemptRegion`] was carried at 478313f
/// (`TryFrom<Arc<std::ffi::OsStr>> for PerAttemptRegion` — opens
/// shared-owned OS-string parse trio), the mid-trio peer at
/// [`crate::probe_outcome::AdmissionTier`] followed at 7f411bc, and
/// this impl carries the closing slot at the third ordered typed
/// sum. After this commit the shared-owned OS-string parse axis
/// spans all three ordered typed sums on the ladder set through
/// ONE [`std::sync::Arc::<std::ffi::OsStr>::as_ref`] +
/// [`TryFrom<&std::ffi::OsStr>`] composition each — matching the
/// shrunk-owned OS-string parse closing order
/// (b6c015b → 84c6966 → 2772a34), the borrowed/owned-frontier
/// OS-string parse closing order (16f6b8e → d68695f → 7e37e95), the
/// borrowed-view OS-string parse closing order
/// (d37e6fe → 9fca3bb → 1ea7110), the owned-buffer OS-string parse
/// closing order (e629465 → 810794b → 6544330), and (one frontier
/// below) the shared-owned string parse closing order
/// (a9c007a → 64ec99e → bc8b5be).
///
/// The parser inherits the two-stage strict-rejection discipline of
/// the underlying [`TryFrom<&std::ffi::OsStr>`] impl: non-Unicode
/// [`std::ffi::OsStr`] input reaches the [`std::ffi::OsStr::to_str`]
/// Unicode-decode boundary and returns an [`anyhow::Error`] before
/// the [`FromStr`] canonical-grammar gate; valid-Unicode but non-
/// canonical input (empty, UpperCamel `"Patch"`/`"Minor"`/`"Major"`,
/// whitespace padding, uppercase `"PATCH"`, truncated `"pat"`) all
/// reach the [`FromStr`] canonical-grammar gate and return an
/// [`anyhow::Error`] there.
///
/// The identity
/// `BumpLevel::try_from(std::sync::Arc::<std::ffi::OsStr>::from(
/// std::ffi::OsString::from(level.as_str()).into_boxed_os_str()))
/// .unwrap() == level` at every [`BumpLevel::ALL`] variant is
/// pinned by
/// [`tests::test_bump_level_try_from_arc_os_str_agrees_with_from_str`];
/// the identity carried through a generic
/// `impl TryFrom<Arc<std::ffi::OsStr>>` consumer at every variant is
/// pinned by
/// [`tests::test_bump_level_try_from_arc_os_str_carries_through_generic_consumer`];
/// the Unicode-decode strict-rejection contract at the shared-owned
/// OS-string boundary is pinned (Unix-only, per the same platform
/// constraint the sibling [`TryFrom<Box<std::ffi::OsStr>>`] non-
/// Unicode pin reads) by
/// [`tests::test_bump_level_try_from_arc_os_str_rejects_non_unicode_input`];
/// the FromStr-gate strict-rejection contract on valid-Unicode non-
/// canonical shared-owned OS-string input is pinned by
/// [`tests::test_bump_level_try_from_arc_os_str_rejects_non_canonical_input`].
///
/// THEORY.md §V.4 typed primitives: the shared-owned OS-string
/// try-conversion parse surface is a typed-primitive site on
/// [`BumpLevel`] itself (one `TryFrom<Arc<std::ffi::OsStr>>` impl
/// routing through [`std::sync::Arc::<std::ffi::OsStr>::as_ref`]
/// and the by-reference [`TryFrom<&std::ffi::OsStr>`] peer), not a
/// per-consumer `BumpLevel::try_from(arc.as_ref())` bridge at every
/// downstream site that types its parse contract as
/// `impl TryFrom<Arc<std::ffi::OsStr>>`. THEORY.md §VI.1 one-oracle:
/// the canonical label grammar is named at one site
/// ([`BumpLevel::as_str`]), inverted at one site
/// ([`<BumpLevel as std::str::FromStr>::from_str`]), and every parse
/// surface — including this shared-owned OS-string peer — reads
/// through it.
impl TryFrom<std::sync::Arc<std::ffi::OsStr>> for BumpLevel {
    type Error = anyhow::Error;

    fn try_from(os_str: std::sync::Arc<std::ffi::OsStr>) -> Result<Self, Self::Error> {
        <Self as std::convert::TryFrom<&std::ffi::OsStr>>::try_from(os_str.as_ref())
    }
}

/// [`TryFrom<Arc<std::path::Path>> for BumpLevel`] routes through
/// [`std::sync::Arc::<std::path::Path>::as_ref`] on the caller-supplied
/// shared-owned filesystem-path and the by-reference filesystem-path
/// parse peer [`TryFrom<&std::path::Path>`] (which itself composes
/// [`std::path::Path::as_os_str`] with the by-reference OS-string parse
/// peer [`TryFrom<&std::ffi::OsStr>`] which composes
/// [`std::ffi::OsStr::to_str`] with [`TryFrom<&str>`] which itself
/// delegates through
/// [`<BumpLevel as std::str::FromStr>::from_str`]), so a downstream
/// consumer bound by `impl TryFrom<Arc<std::path::Path>>` (a shared-
/// owned filesystem-path wrapper handed to sibling threads through an
/// atomic-refcount header, a [`Box<std::path::Path>::into`] shared-
/// buffer input that trades exclusive shrunk-owned single-owner
/// semantics for a shared reader-count of the same immutable
/// filesystem-path, a generic try-conversion helper
/// `fn parse<T: TryFrom<Arc<std::path::Path>>>` that composes with
/// shared-owned filesystem-path inputs) recovers a [`BumpLevel`]
/// value from a shared-owned canonical filesystem-path label through
/// the same one-oracle grammar the sibling
/// [`TryFrom<&std::path::Path>`], [`TryFrom<std::path::PathBuf>`],
/// [`TryFrom<std::borrow::Cow<'_, std::path::Path>>`],
/// [`TryFrom<Box<std::path::Path>>`], and (one frontier below)
/// [`TryFrom<std::sync::Arc<std::ffi::OsStr>>`] shared-owned parse peers
/// read.
///
/// The by-value shared-owned filesystem-path parse peer of
/// [`TryFrom<Box<std::path::Path>>`] above — both are shrunk/shared
/// immutable-heap filesystem-path parse surfaces of the label-axis
/// conversion set, differing on ownership discipline:
/// [`TryFrom<Box<std::path::Path>>`] consumes a single-owner shrunk
/// buffer with exclusive ownership semantics,
/// this [`TryFrom<Arc<std::path::Path>>`] consumes a shared-owner
/// atomic-refcount buffer that may have surviving clones outside the
/// receiver. Both route through the shared
/// [`<BumpLevel as std::str::FromStr>::from_str`] canonical-label
/// parse oracle: the shrunk-owned peer through
/// [`std::boxed::Box::<std::path::Path>::as_ref`] composed with
/// [`TryFrom<&std::path::Path>`], this shared-owned peer through
/// [`std::sync::Arc::<std::path::Path>::as_ref`] composed with
/// [`TryFrom<&std::path::Path>`] — the same canonical grammar lifted
/// to the shared-owned filesystem-path layer.
///
/// Closes the shared-owned filesystem-path parse trio at the
/// version-bump-magnitude ladder — the opening peer at
/// [`crate::retry::PerAttemptRegion`] was carried at b9f5ef1
/// (`TryFrom<Arc<std::path::Path>> for PerAttemptRegion` — opens
/// shared-owned filesystem-path parse trio) and the mid-trio peer at
/// [`crate::probe_outcome::AdmissionTier`] at aec69b1
/// (`TryFrom<Arc<std::path::Path>> for AdmissionTier` — mid-trio
/// shared-owned filesystem-path parse peer), matching the shared-owned
/// OS-string trio closing order at one frontier below
/// (478313f → 7f411bc → 140d9c2 for
/// [`TryFrom<std::sync::Arc<std::ffi::OsStr>>`]) and the shrunk-owned
/// filesystem-path trio closing order at one ownership discipline over
/// (315c145 → 657434c → 336e453 for
/// [`TryFrom<Box<std::path::Path>>`]). After this commit the shared-
/// owned filesystem-path parse axis spans all three ordered typed
/// sums on the ladder set through ONE
/// [`std::sync::Arc::<std::path::Path>::as_ref`] +
/// [`TryFrom<&std::path::Path>`] composition each.
///
/// The parser inherits the two-stage strict-rejection discipline of
/// the underlying [`TryFrom<&std::path::Path>`] impl: non-Unicode
/// [`std::path::Path`] input reaches the [`std::ffi::OsStr::to_str`]
/// Unicode-decode boundary via [`std::path::Path::as_os_str`] and
/// returns an [`anyhow::Error`] before the [`FromStr`] canonical-
/// grammar gate; valid-Unicode but non-canonical input (empty,
/// UpperCamel, whitespace-padded, uppercase, truncated stem) reaches
/// the [`FromStr`] canonical-grammar gate and returns an
/// [`anyhow::Error`] there.
///
/// The identity
/// `BumpLevel::try_from(std::sync::Arc::<std::path::Path>::from(
/// std::path::PathBuf::from(level.as_str()).into_boxed_path()))
/// .unwrap() == level` at every [`BumpLevel::ALL`] variant is pinned
/// by
/// [`tests::test_bump_level_try_from_arc_path_agrees_with_from_str`];
/// the identity carried through a generic
/// `impl TryFrom<Arc<std::path::Path>>` consumer at every variant is
/// pinned by
/// [`tests::test_bump_level_try_from_arc_path_carries_through_generic_consumer`];
/// the Unicode-decode strict-rejection contract at the shared-owned
/// filesystem-path boundary is pinned (Unix-only, per the same
/// platform constraint the sibling [`TryFrom<Box<std::path::Path>>`]
/// non-Unicode pin reads) by
/// [`tests::test_bump_level_try_from_arc_path_rejects_non_unicode_input`];
/// the FromStr-gate strict-rejection contract on valid-Unicode non-
/// canonical shared-owned filesystem-path input is pinned by
/// [`tests::test_bump_level_try_from_arc_path_rejects_non_canonical_input`].
///
/// THEORY.md §V.4 typed primitives: the shared-owned filesystem-path
/// parse surface is a typed-primitive site on [`BumpLevel`] itself
/// (one [`TryFrom<Arc<std::path::Path>>`] impl routing through
/// [`std::sync::Arc::<std::path::Path>::as_ref`] and
/// [`TryFrom<&std::path::Path>`]), not a per-consumer
/// `.as_ref().as_os_str().to_str().parse()` composition at every
/// downstream site that types its parse contract as
/// `impl TryFrom<Arc<std::path::Path>>`. THEORY.md §VI.1 one-oracle:
/// the canonical label grammar is named at one site
/// ([`BumpLevel::as_str`]), inverted at one site
/// ([`<BumpLevel as std::str::FromStr>::from_str`]), and every parse
/// surface — including this shared-owned filesystem-path peer —
/// reads through it.
impl TryFrom<std::sync::Arc<std::path::Path>> for BumpLevel {
    type Error = anyhow::Error;

    fn try_from(path: std::sync::Arc<std::path::Path>) -> Result<Self, Self::Error> {
        <Self as std::convert::TryFrom<&std::path::Path>>::try_from(path.as_ref())
    }
}

/// Structural mirror of `impl TryFrom<Rc<std::ffi::OsStr>> for
/// PerAttemptRegion` (commit 63f6f55) and `impl TryFrom<Rc<
/// std::ffi::OsStr>> for AdmissionTier` (commit 2adee36) — the
/// thread-local shared-owned OS-string parse peer at the third ordered
/// typed sum (trio-closing slot). Routes through
/// [`std::rc::Rc::<std::ffi::OsStr>::as_ref`] on the caller-supplied
/// thread-local shared-owned OS-string and the by-reference OS-string
/// parse peer [`TryFrom<&std::ffi::OsStr>`] (which itself composes
/// [`std::ffi::OsStr::to_str`] with [`TryFrom<&str>`] which itself
/// delegates through [`<BumpLevel as std::str::FromStr>::from_str`]),
/// so a downstream consumer bound by `impl TryFrom<Rc<
/// std::ffi::OsStr>>` (a thread-local shared-owned OS-string release-
/// manifest path-segment input handed to sibling non-`Send` receivers
/// through a single-threaded refcount header — a non-`Sync` renderer
/// that stashes canonical bump labels in an [`Rc`] cell for cheap in-
/// thread clone, a [`Box<std::ffi::OsStr>::into`] shared-buffer input
/// that trades exclusive shrunk-owned single-owner semantics for a
/// shared reader-count of the same immutable OS-string within a single
/// thread, a generic try-conversion helper
/// `fn parse<T: TryFrom<Rc<std::ffi::OsStr>>>` that composes with
/// thread-local shared-owned OS-string inputs) recovers a
/// [`BumpLevel`] value from a thread-local shared-owned canonical
/// OS-string label (`"patch"`, `"minor"`, `"major"`) through the same
/// one-oracle grammar the sibling [`TryFrom<&std::ffi::OsStr>`],
/// [`TryFrom<std::ffi::OsString>`],
/// [`TryFrom<std::borrow::Cow<'_, std::ffi::OsStr>>`],
/// [`TryFrom<Box<std::ffi::OsStr>>`],
/// [`TryFrom<std::sync::Arc<std::ffi::OsStr>>`], and (one frontier
/// below) [`TryFrom<std::rc::Rc<str>>`] shared-owned parse peers read.
///
/// The thread-local shared-owned OS-string parse peer of
/// [`TryFrom<std::sync::Arc<std::ffi::OsStr>>`] above — both are
/// shared-owned immutable-heap OS-string parse surfaces of the label-
/// axis conversion set, differing on refcount discipline:
/// [`TryFrom<std::sync::Arc<std::ffi::OsStr>>`] consumes an atomic-
/// refcount buffer that may have surviving clones across sibling
/// threads, this [`TryFrom<std::rc::Rc<std::ffi::OsStr>>`] consumes a
/// single-threaded refcount buffer that may have surviving clones only
/// within the receiver's thread. Both route through the shared
/// [`<BumpLevel as std::str::FromStr>::from_str`] canonical-label
/// parse oracle: the atomic-refcount peer through
/// [`std::sync::Arc::<std::ffi::OsStr>::as_ref`] composed with
/// [`TryFrom<&std::ffi::OsStr>`], this single-threaded-refcount peer
/// through [`std::rc::Rc::<std::ffi::OsStr>::as_ref`] composed with
/// [`TryFrom<&std::ffi::OsStr>`] — the same canonical grammar lifted
/// to the thread-local shared-owned OS-string layer, trading the
/// atomic-refcount header cost for the single-threaded restriction.
///
/// The impl body picks [`std::rc::Rc::<std::ffi::OsStr>::as_ref`]
/// rather than [`std::rc::Rc::<std::ffi::OsStr>::to_string`] or an
/// intermediate [`std::rc::Rc::<std::ffi::OsStr>::to_owned`] +
/// [`TryFrom<OsString>`] restatement: the [`AsRef`] view yields a
/// borrowed `&std::ffi::OsStr` window over the shared heap allocation
/// without cloning the single-threaded refcount header, converting the
/// shared-owned receiver into a resizable [`std::ffi::OsString`], or
/// forking the underlying immutable buffer — the receiver pays no
/// refcount increment on the fast path, only the eventual drop-
/// decrement when the [`std::rc::Rc<std::ffi::OsStr>`] receiver falls
/// out of scope. The same borrow-then-drop discipline the sibling
/// [`TryFrom<Box<std::ffi::OsStr>>`], [`TryFrom<std::ffi::OsString>`],
/// [`TryFrom<Cow<'_, std::ffi::OsStr>>`], and
/// [`TryFrom<std::sync::Arc<std::ffi::OsStr>>`] peers apply at the
/// shrunk-owned, resizable-buffer, borrowed/owned-frontier, and
/// atomic-shared-owned axes, lifted to the thread-local shared-owned
/// axis via [`std::rc::Rc::<std::ffi::OsStr>::as_ref`].
///
/// Trio-closing slot in the thread-local shared-owned OS-string parse
/// trio at the bump-level ladder — the opening peer at
/// [`crate::retry::PerAttemptRegion`] was carried at 63f6f55
/// (`TryFrom<Rc<std::ffi::OsStr>> for PerAttemptRegion` — opens
/// thread-local shared-owned OS-string parse trio), the mid-trio peer
/// at [`crate::probe_outcome::AdmissionTier`] followed at 2adee36, and
/// this impl carries the closing slot at the third ordered typed sum.
/// After this commit the thread-local shared-owned OS-string parse
/// axis spans all three ordered typed sums on the ladder set through
/// ONE [`std::rc::Rc::<std::ffi::OsStr>::as_ref`] +
/// [`TryFrom<&std::ffi::OsStr>`] composition each — matching the
/// atomic-shared-owned OS-string parse closing order
/// (478313f → 7f411bc → 140d9c2), the shrunk-owned OS-string parse
/// closing order (b6c015b → 84c6966 → 2772a34), the borrowed/owned-
/// frontier OS-string parse closing order
/// (16f6b8e → d68695f → 7e37e95), the borrowed-view OS-string parse
/// closing order (d37e6fe → 9fca3bb → 1ea7110), the owned-buffer
/// OS-string parse closing order (e629465 → 810794b → 6544330), and
/// (one frontier below) the thread-local shared-owned string parse
/// closing order at the bump-level ladder already read.
///
/// The parser inherits the two-stage strict-rejection discipline of
/// the underlying [`TryFrom<&std::ffi::OsStr>`] impl: non-Unicode
/// [`std::ffi::OsStr`] input reaches the [`std::ffi::OsStr::to_str`]
/// Unicode-decode boundary and returns an [`anyhow::Error`] before
/// the [`FromStr`] canonical-grammar gate; valid-Unicode but non-
/// canonical input (empty, UpperCamel `"Patch"`/`"Minor"`/`"Major"`,
/// whitespace padding, uppercase `"PATCH"`, truncated `"pat"`) all
/// reach the [`FromStr`] canonical-grammar gate and return an
/// [`anyhow::Error`] there.
///
/// The identity
/// `BumpLevel::try_from(std::rc::Rc::<std::ffi::OsStr>::from(
/// std::ffi::OsString::from(level.as_str()).into_boxed_os_str()))
/// .unwrap() == level` at every [`BumpLevel::ALL`] variant is pinned
/// by [`tests::test_bump_level_try_from_rc_os_str_agrees_with_from_str`];
/// the identity carried through a generic
/// `impl TryFrom<Rc<std::ffi::OsStr>>` consumer at every variant is
/// pinned by
/// [`tests::test_bump_level_try_from_rc_os_str_carries_through_generic_consumer`];
/// the Unicode-decode strict-rejection contract at the thread-local
/// shared-owned OS-string boundary is pinned (Unix-only, per the same
/// platform constraint the sibling
/// [`TryFrom<std::sync::Arc<std::ffi::OsStr>>`] non-Unicode pin
/// reads) by
/// [`tests::test_bump_level_try_from_rc_os_str_rejects_non_unicode_input`];
/// the FromStr-gate strict-rejection contract on valid-Unicode non-
/// canonical thread-local shared-owned OS-string input is pinned by
/// [`tests::test_bump_level_try_from_rc_os_str_rejects_non_canonical_input`].
///
/// THEORY.md §V.4 typed primitives: the thread-local shared-owned
/// OS-string try-conversion parse surface is a typed-primitive site
/// on [`BumpLevel`] itself (one `TryFrom<Rc<std::ffi::OsStr>>` impl
/// routing through [`std::rc::Rc::<std::ffi::OsStr>::as_ref`] and the
/// by-reference [`TryFrom<&std::ffi::OsStr>`] peer), not a per-
/// consumer `BumpLevel::try_from(rc.as_ref())` bridge at every
/// downstream site that types its parse contract as
/// `impl TryFrom<Rc<std::ffi::OsStr>>`. THEORY.md §VI.1 one-oracle:
/// the canonical label grammar is named at one site
/// ([`BumpLevel::as_str`]), inverted at one site
/// ([`<BumpLevel as std::str::FromStr>::from_str`]), and every parse
/// surface — including this thread-local shared-owned OS-string peer
/// — reads through it.
impl TryFrom<std::rc::Rc<std::ffi::OsStr>> for BumpLevel {
    type Error = anyhow::Error;

    fn try_from(os_str: std::rc::Rc<std::ffi::OsStr>) -> Result<Self, Self::Error> {
        <Self as std::convert::TryFrom<&std::ffi::OsStr>>::try_from(os_str.as_ref())
    }
}

/// [`From<BumpLevel> for &'static str`] routes through
/// [`BumpLevel::as_str`] so a downstream consumer that takes an owned
/// [`&'static str`] via [`Into<&'static str>`] (a `const`-adjacent
/// release-manifest path-segment builder that stashes the bump label
/// in a `&'static str` slot, a `phf`-style static lookup table keyed
/// by canonical bump label, an OpenTelemetry / tracing attribute slot
/// that keys by `&'static str` for the zero-copy fast path, a
/// [`std::borrow::Cow<'static, str>`] sink taking `Into<Cow<'static,
/// str>>`) reads the canonical lowercase label (`"patch"`, `"minor"`,
/// `"major"`) directly from a [`BumpLevel`] value with `'static`
/// lifetime preserved. The zero-cost by-value conversion peer of the
/// [`AsRef<str>`] borrow surface, both routing through the same
/// [`BumpLevel::as_str`] canonical-label oracle — the difference is
/// that [`AsRef<str>`] borrows through the receiver's lifetime (a
/// caller with a short-lived [`BumpLevel`] gets a short-lived `&str`
/// back), whereas this [`From`] impl consumes the receiver by value
/// and returns `&'static str` (a caller that no longer needs the
/// [`BumpLevel`] value gets a `'static`-lived label back).
///
/// Sibling of the [`std::fmt::Display`], [`std::str::FromStr`],
/// [`serde::Serialize`], [`serde::Deserialize`], and [`AsRef<str>`]
/// impls above — the same lift at the by-value static-lifetime
/// conversion layer instead of the format / parse / serde / borrow
/// layers. Together with the impls above this closes the
/// `as_str` ⇢ {`Display`, `AsRef<str>`, `Serialize`, `From<T> for
/// &'static str`} emission set and the {`FromStr`, `Deserialize`}
/// parse pair at the version-bump-magnitude ladder against the shared
/// canonical-label oracle. Structural mirror of
/// `impl From<PerAttemptRegion> for &'static str` (commit c8614e9 —
/// the by-value static-lifetime peer at the per-attempt-region
/// ladder, routing through [`crate::retry::PerAttemptRegion::as_str`])
/// and `impl From<AdmissionTier> for &'static str` (commit c041b0b —
/// the by-value static-lifetime peer at the admission-tier ladder,
/// routing through [`crate::probe_outcome::AdmissionTier::as_str`]).
/// After this commit all three repo-internal ordered typed sums that
/// carry `as_str` + [`std::fmt::Display`] + [`std::str::FromStr`] +
/// [`serde::Serialize`] + [`serde::Deserialize`] + [`AsRef<str>`]
/// ([`BumpLevel`], [`crate::probe_outcome::AdmissionTier`],
/// [`crate::retry::PerAttemptRegion`]) also carry `From<T> for
/// &'static str` routing through the shared canonical-label oracle —
/// the label-axis grammar at every ordered typed sum is now a
/// one-oracle surface at every Rust-idiomatic reading (direct call
/// `as_str`, format machinery [`std::fmt::Display`], byte slice
/// [`AsRef<str>`], string parse [`std::str::FromStr`], serde
/// [`serde::Serialize`] / [`serde::Deserialize`], by-value
/// static-lifetime conversion [`From<T> for &'static str`]). The
/// natural bridge to the [`strum::IntoStaticStr`] /
/// [`strum_macros::IntoStaticStr`] frontier idiom (`strum` derives
/// exactly this pattern via `#[derive(IntoStaticStr)]`) — here
/// hand-written at ONE typed-primitive site so the routing through
/// the shared [`BumpLevel::as_str`] oracle is explicit and
/// inspectable rather than macro-generated.
///
/// Zero-cost by construction: the returned `&'static str` is
/// delegated from [`BumpLevel::as_str`]'s `&'static str` return type,
/// so a consumer that receives the slice reads directly into the
/// static-string constant table without a copy, matching the
/// zero-allocation discipline the [`std::fmt::Display`] format
/// surface doesn't offer (which writes through a
/// [`std::fmt::Formatter`] into a caller-provided buffer).
///
/// A future variant insertion (a `Prerelease` band strictly below
/// [`BumpLevel::Patch`], an `Epoch` ceiling strictly above
/// [`BumpLevel::Major`] for semver4 / `0ver`-style incompatible-by-
/// design rewrites) updates the [`BumpLevel::as_str`] match body
/// alone and every consumer — release-manifest path-segment builder
/// holding `&'static str` slots, `phf`-style static lookup table
/// keyed by canonical bump label, OpenTelemetry / tracing attribute
/// slot, [`std::borrow::Cow<'static, str>`] sink — that accepts
/// `impl Into<&'static str>` inherits the new canonical label
/// automatically with no downstream retyping.
///
/// The identity `<&'static str>::from(level) == level.as_str()` at
/// every [`BumpLevel::ALL`] variant is pinned by
/// [`tests::test_bump_level_from_into_static_str_agrees_with_as_str`];
/// the identity carried through a generic
/// `impl Into<&'static str>` consumer at every variant is pinned by
/// [`tests::test_bump_level_into_static_str_carries_through_generic_consumer`].
///
/// THEORY.md §V.4 typed primitives: the by-value static-lifetime
/// conversion surface is a typed-primitive site on [`BumpLevel`]
/// itself (one `From<BumpLevel> for &'static str` impl routing
/// through [`BumpLevel::as_str`]), not a per-consumer `.as_str()`
/// restatement at every downstream site that accepts
/// `impl Into<&'static str>`. THEORY.md §VI.1 one-oracle: the
/// canonical label is named at one site ([`BumpLevel::as_str`]) and
/// every surface — `as_str`, `Display`, `Serialize`, `AsRef<str>`,
/// this `From<T> for &'static str` — reads through it.
impl From<BumpLevel> for &'static str {
    fn from(level: BumpLevel) -> &'static str {
        level.as_str()
    }
}

/// [`From<BumpLevel> for &'static [u8]`] routes through
/// [`BumpLevel::as_str`] composed with [`str::as_bytes`] at the
/// canonical-label oracle so a downstream consumer that takes an
/// owned `&'static [u8]` via [`Into<&'static [u8]>`] (a
/// `const`-adjacent hasher input slot that stashes the bump label in
/// a `&'static [u8]` field, a `phf`-style static lookup table keyed
/// by canonical bump label bytes, a `blake3` / `sha2` hasher factory
/// that pre-materializes update inputs as `&'static [u8]`, a
/// [`std::borrow::Cow<'static, [u8]>`] sink taking
/// `Into<Cow<'static, [u8]>>`) reads the canonical lowercase label
/// (`"patch"`, `"minor"`, `"major"`) as an owned `&'static [u8]`
/// view of the static-lifetime label constant table's UTF-8 bytes
/// with `'static` lifetime preserved. The zero-cost by-value
/// conversion peer of the [`AsRef<[u8]>`] borrow surface directly
/// above, both routing through the same [`BumpLevel::as_str`]
/// canonical-label oracle composed with [`str::as_bytes`] — the
/// difference is that [`AsRef<[u8]>`] borrows through the receiver's
/// lifetime (a caller with a short-lived [`BumpLevel`] gets a
/// short-lived `&[u8]` back), whereas this [`From`] impl consumes
/// the receiver by value and returns `&'static [u8]` (a caller that
/// no longer needs the [`BumpLevel`] value gets a `'static`-lived
/// byte-slice label back).
///
/// Structural mirror of [`From<BumpLevel> for &'static str`]
/// (commit 819a4c3) directly above — the same by-value static-
/// lifetime emit surface at the same one-oracle discipline,
/// projected onto the byte-slice frontier instead of the UTF-8
/// string frontier. Trio-closing peer of the by-value static-
/// lifetime byte-slice-emit trio: `From<PerAttemptRegion> for
/// &'static [u8]` (commit 70e813b) opened the trio at the per-
/// attempt-region ladder; `From<AdmissionTier> for &'static [u8]`
/// (commit 694dff9) carried the mid-trio slot at the admission-tier
/// ladder; this impl closes the trio at the version-bump-magnitude
/// ladder, matching the `From<T> for &'static str` closure order
/// (c8614e9 → c041b0b → 819a4c3) and the `AsRef<[u8]>` closure
/// order (af44439 → 13abcc4 → 833d706). After this commit the by-
/// value static-lifetime emit axis spans BOTH the UTF-8 string
/// frontier (`From<T> for &'static str`) and the byte-slice
/// frontier (`From<T> for &'static [u8]`) across all three ordered
/// typed sums on the ladder set against ONE canonical-label oracle
/// each.
///
/// Zero-cost by construction: the returned `&'static [u8]` is a
/// zero-length-check-free view of the static-lifetime label
/// constant table's UTF-8 bytes — [`str::as_bytes`] is a zero-cost
/// transmute at the borrow-view boundary, no allocation, no copy,
/// no branching over the variant discriminant beyond what
/// [`BumpLevel::as_str`] itself does at its match body. The
/// `'static` lifetime is preserved through the composition because
/// [`BumpLevel::as_str`] returns `&'static str` and [`str::as_bytes`]
/// preserves the receiver's lifetime.
///
/// The identity `<&'static [u8]>::from(level) ==
/// level.as_str().as_bytes()` at every [`BumpLevel::ALL`] variant is
/// pinned by
/// [`tests::test_bump_level_from_into_static_bytes_agrees_with_as_str_as_bytes`];
/// the identity carried through a generic `impl Into<&'static [u8]>`
/// consumer at every variant is pinned by
/// [`tests::test_bump_level_into_static_bytes_carries_through_generic_consumer`];
/// the round-trip through [`std::str::from_utf8`] recovering the
/// canonical label at every variant is pinned by
/// [`tests::test_bump_level_from_into_static_bytes_round_trips_through_from_utf8`].
///
/// THEORY.md §V.4 typed primitives: the by-value static-lifetime
/// byte-slice-emit surface is a typed-primitive site on [`BumpLevel`]
/// itself (one `From<BumpLevel> for &'static [u8]` impl routing
/// through [`BumpLevel::as_str`] and [`str::as_bytes`]), not a
/// per-consumer `.as_str().as_bytes()` restatement at every
/// downstream site that accepts `impl Into<&'static [u8]>`.
/// THEORY.md §VI.1 one-oracle: the canonical label is named at one
/// site ([`BumpLevel::as_str`]) and every surface — `as_str`,
/// `Display`, `Serialize`, `AsRef<str>`, `AsRef<[u8]>`,
/// `From<T> for &'static str`, this `From<T> for &'static [u8]` —
/// reads through it.
impl From<BumpLevel> for &'static [u8] {
    fn from(level: BumpLevel) -> &'static [u8] {
        level.as_str().as_bytes()
    }
}

/// [`From<BumpLevel> for Vec<u8>`] routes through [`BumpLevel::as_str`]
/// composed with [`str::as_bytes`] and [`slice::to_vec`] at the emit
/// boundary so a downstream consumer that types its byte-slice emit
/// contract as [`Into<Vec<u8>>`] (an OCI / GHCR blob-upload sink whose
/// input is an owned [`Vec<u8>`] payload, a `bytes::Bytes::from` bridge
/// that takes an owned [`Vec<u8>`] before it hands the buffer to a
/// shared-owned reader, a `reqwest::Body::from` request-body builder
/// over an owned buffer, a SLSA / sigstore attestation-subject bytes
/// builder that owns its payload for signing, a
/// [`tokio::io::AsyncWriteExt::write_all`] sink typed as [`Vec<u8>`], a
/// `blake3::Hasher::update` sink that consumes an owned buffer) reads
/// the canonical lowercase label bytes (`b"patch"`, `b"minor"`,
/// `b"major"`) as an owned [`Vec<u8>`] with EXACT-CAPACITY allocation
/// at the emit boundary — the [`slice::to_vec`] route allocates a
/// fresh [`Vec<u8>`] of exactly the canonical label's byte length, no
/// [`String`]-realloc-plus-shrink round trip through a
/// [`String::into_bytes`] composition, no [`Vec::with_capacity`] +
/// [`Vec::extend_from_slice`] restatement per consumer.
///
/// The by-value owned-buffer byte-slice emit peer of the
/// [`AsRef<[u8]>`] (borrowed-view byte-slice emit, commit 833d706) and
/// [`From<BumpLevel> for &'static [u8]`] (by-value static-lifetime
/// byte-slice emit, commit 762437f) impls above and the
/// [`From<BumpLevel> for Cow<'static, [u8]>`] (by-value borrowed/
/// owned-frontier byte-slice emit, commit 7c465d1) impl below — the
/// four impls together close the borrowed-view / by-value static-
/// lifetime / by-value owned-buffer / by-value borrowed/owned-frontier
/// emit quadrilateral at the byte-slice frontier against the shared
/// [`BumpLevel::as_str`] + [`str::as_bytes`] canonical-label-bytes
/// oracle. The [`AsRef<[u8]>`] impl is the borrowed-view surface (zero
/// allocation, caller pays receiver lifetime), the
/// [`From<BumpLevel> for &'static [u8]`] impl is the by-value
/// `'static`-lifetime surface (zero allocation, receiver pays
/// `'static`-borrow cost), this [`From<BumpLevel> for Vec<u8>`] impl
/// is the by-value owned-buffer surface (single exact-capacity
/// allocation, receiver pays owned-[`Vec<u8>`] cost), the
/// [`From<BumpLevel> for Cow<'static, [u8]>`] impl is the by-value
/// borrowed/owned-frontier surface (zero allocation at the
/// [`std::borrow::Cow::Borrowed`] branch, receiver pays [`Cow`] tag
/// dispatch) — the same one-oracle discipline projected onto the four
/// distinct byte-slice ownership shapes.
///
/// Structural mirror of [`From<BumpLevel> for String`] (commit
/// 37d172c) at the UTF-8 frontier — the same by-value owned-buffer
/// emit surface at the same one-oracle discipline, projected onto the
/// byte-slice frontier instead of the UTF-8 string frontier. Trio-
/// closing peer of the by-value owned-buffer byte-slice-emit trio at
/// the third ordered typed sum: [`From<crate::retry::PerAttemptRegion>
/// for Vec<u8>`] (commit 2ad52bc) opened the trio at the per-attempt-
/// region ladder; [`From<crate::probe_outcome::AdmissionTier> for
/// Vec<u8>`] (commit 491db4d) carried the mid-trio slot at the
/// admission-tier ladder; this impl closes the trio at the version-
/// bump-magnitude ladder, matching the [`From<T> for &'static [u8]`]
/// closure order (70e813b → 694dff9 → 762437f), the
/// [`From<T> for Cow<'static, [u8]>`] closure order (912a5ff → 89af285
/// → 7c465d1), the [`AsRef<[u8]>`] closure order (af44439 → 13abcc4 →
/// 833d706), and the [`From<T> for String`] closure order at the
/// UTF-8 owned-buffer frontier (a5a379f → 463b31b → 37d172c). After
/// this commit the by-value owned-buffer emit axis spans BOTH the
/// UTF-8 string frontier ([`From<T> for String`]) and the byte-slice
/// frontier ([`From<T> for Vec<u8>`]) across all three ordered typed
/// sums on the ladder set against ONE canonical-label oracle each.
///
/// The natural bridge from the borrowed-view [`AsRef<[u8]>`] and
/// by-value static-lifetime [`From<T> for &'static [u8]`] emit peers
/// above to any downstream site that types its byte-slice sink as
/// [`Into<Vec<u8>>`] — the emit peer that answers the receiver-side
/// question "does this byte-oriented API want a borrow, a `'static`-
/// lifetime view, or a caller-owned buffer?" with "the owned buffer,
/// allocated exactly once at the canonical label length." A receiver
/// typed as [`Vec<u8>`] (rather than `&'static [u8]`) permits the
/// caller to hand the byte-buffer through a shared-owned reader
/// (`bytes::Bytes::from`, [`std::sync::Arc<[u8]>`]) or a mutable
/// buffer sink ([`Vec::extend_from_slice`], [`Vec::push`]) that
/// requires an owned allocation; a receiver typed as [`Vec<u8>`]
/// (rather than [`std::borrow::Cow<'static, [u8]>`]) commits to the
/// owned branch up-front (avoiding the [`std::borrow::Cow`] enum tag
/// and the borrowed-branch dispatch) when the downstream contract
/// requires an owned buffer regardless of provenance.
///
/// The impl body picks [`slice::to_vec`] rather than
/// [`String::from`]-then-[`String::into_bytes`] or
/// [`Vec::with_capacity`]-then-[`Vec::extend_from_slice`]:
/// [`slice::to_vec`] issues ONE allocation at exactly the byte-
/// slice's length (no [`String`] growth-header, no
/// [`Vec::with_capacity`] over-allocation slack), and the composed
/// call [`BumpLevel::as_str`] + [`str::as_bytes`] + [`slice::to_vec`]
/// yields the same discipline the sibling [`From<BumpLevel> for
/// String`] peer applies at the UTF-8 frontier through
/// [`str::to_owned`] — a single exact-capacity allocation per emit.
///
/// The identity `Vec::<u8>::from(level) == level.as_str().as_bytes()`
/// at every [`BumpLevel::ALL`] variant is pinned by
/// [`tests::test_bump_level_from_into_owned_bytes_agrees_with_as_str_as_bytes`];
/// the identity carried through a generic `impl Into<Vec<u8>>`
/// consumer at every variant is pinned by
/// [`tests::test_bump_level_into_owned_bytes_carries_through_generic_consumer`];
/// the round-trip identity `Vec::<u8>::from(level)` fed back through
/// [`TryFrom<Vec<u8>>`] at every variant is pinned by
/// [`tests::test_bump_level_from_into_owned_bytes_round_trips_through_try_from`].
///
/// THEORY.md §V.4 typed primitives: the by-value owned-buffer byte-
/// slice emit surface is a typed-primitive site on [`BumpLevel`]
/// itself (one `From<BumpLevel> for Vec<u8>` impl routing through
/// [`BumpLevel::as_str`] + [`str::as_bytes`] + [`slice::to_vec`]), not
/// a per-consumer `level.as_str().as_bytes().to_vec()` restatement at
/// every downstream site that accepts `impl Into<Vec<u8>>`. THEORY.md
/// §VI.1 one-oracle: the canonical label is named at one site
/// ([`BumpLevel::as_str`]) and every emit surface — `as_str`,
/// [`std::fmt::Display`], [`serde::Serialize`], [`AsRef<str>`],
/// [`AsRef<[u8]>`], `From<T> for &'static str`, `From<T> for &'static
/// [u8]`, `From<T> for String`, this `From<T> for Vec<u8>` — reads
/// through it.
impl From<BumpLevel> for Vec<u8> {
    fn from(level: BumpLevel) -> Vec<u8> {
        level.as_str().as_bytes().to_vec()
    }
}

/// [`From<BumpLevel> for Cow<'static, [u8]>`] routes through
/// [`BumpLevel::as_str`] composed with [`str::as_bytes`] and wraps
/// the resulting `'static`-lived byte view at the
/// [`std::borrow::Cow::Borrowed`] branch so a downstream consumer
/// that takes an [`Into<Cow<'static, [u8]>>`] (a hasher factory
/// keyed on either a static label or a caller-owned owned
/// [`Vec<u8>`] uniformly, a SLSA / sigstore attestation-subject
/// bytes sink typed as [`std::borrow::Cow<'static, [u8]>`], a
/// `phf`-style static byte-key lookup table over canonical labels,
/// an OCI / GHCR manifest annotation-value sink at the byte-slice
/// frontier) reads the canonical lowercase label bytes (`"patch"`,
/// `"minor"`, `"major"` as UTF-8 byte-slices) directly from a
/// [`BumpLevel`] value with **zero allocation** at the emit
/// boundary — the [`std::borrow::Cow::Borrowed`] branch preserves
/// the `'static` lifetime end-to-end through the composition
/// [`BumpLevel::as_str`] → [`str::as_bytes`], not the
/// [`std::borrow::Cow::Owned`] branch that would allocate a fresh
/// [`Vec<u8>`] per call.
///
/// Structural mirror of [`From<BumpLevel> for Cow<'static, str>`]
/// (commit 133769a) at the UTF-8 frontier — the same by-value
/// borrowed/owned-frontier emit surface at the same one-oracle
/// discipline, projected onto the byte-slice frontier. Trio-closing
/// peer of the by-value borrowed/owned-frontier byte-slice-emit
/// trio: `From<PerAttemptRegion> for Cow<'static, [u8]>` (commit
/// 912a5ff) opened the trio at the per-attempt-region ladder;
/// `From<AdmissionTier> for Cow<'static, [u8]>` (commit 89af285)
/// carried the mid-trio slot at the admission-tier ladder; this
/// impl closes the trio at the version-bump-magnitude ladder,
/// matching the `From<T> for Cow<'static, str>` closure order
/// (79113dd → 65b1e77 → 133769a) and the `From<T> for &'static [u8]`
/// closure order (70e813b → 694dff9 → 762437f). After this commit
/// the by-value borrowed/owned-frontier emit axis spans BOTH the
/// UTF-8 string frontier (`From<T> for Cow<'static, str>`) and the
/// byte-slice frontier (`From<T> for Cow<'static, [u8]>`) across
/// all three ordered typed sums on the ladder set against ONE
/// canonical-label oracle each at the same
/// [`std::borrow::Cow::Borrowed`] branch discipline.
///
/// Zero-cost by construction: the returned
/// [`std::borrow::Cow<'static, [u8]>`] wraps a zero-length-check-
/// free view of the static-lifetime label constant table's UTF-8
/// bytes — [`str::as_bytes`] is a zero-cost transmute at the borrow-
/// view boundary, and the [`std::borrow::Cow::Borrowed`] wrapping
/// is a discriminant tag with no runtime work at the emit site. No
/// allocation, no copy, no branching over the variant discriminant
/// beyond what [`BumpLevel::as_str`] itself does at its match body.
/// The `'static` lifetime is preserved through the composition
/// because [`BumpLevel::as_str`] returns `&'static str`,
/// [`str::as_bytes`] preserves the receiver's lifetime, and
/// [`std::borrow::Cow::Borrowed`] carries the byte-slice's lifetime
/// through the [`Cow`] wrapper.
///
/// The identity `Cow::<'static, [u8]>::from(level).as_ref() ==
/// level.as_str().as_bytes()` at every [`BumpLevel::ALL`] variant is
/// pinned by
/// [`tests::test_bump_level_from_into_cow_static_bytes_agrees_with_as_str_as_bytes`];
/// the identity carried through a generic `impl Into<Cow<'static,
/// [u8]>>` consumer at every variant is pinned by
/// [`tests::test_bump_level_into_cow_static_bytes_carries_through_generic_consumer`];
/// the [`std::borrow::Cow::Borrowed`]-not-[`std::borrow::Cow::Owned`]
/// zero-allocation branch choice at every variant is pinned by
/// [`tests::test_bump_level_into_cow_static_bytes_is_borrowed`].
///
/// THEORY.md §V.4 typed primitives: the by-value borrowed/owned-
/// frontier byte-slice-emit surface is a typed-primitive site on
/// [`BumpLevel`] itself (one `From<BumpLevel> for Cow<'static, [u8]>`
/// impl routing through [`BumpLevel::as_str`] composed with
/// [`str::as_bytes`] at the [`std::borrow::Cow::Borrowed`] branch),
/// not a per-consumer `Cow::Borrowed(level.as_str().as_bytes())`
/// restatement at every downstream site that accepts
/// `impl Into<Cow<'static, [u8]>>`. THEORY.md §VI.1 one-oracle: the
/// canonical label is named at one site ([`BumpLevel::as_str`]) and
/// every emit surface — `as_str`, [`std::fmt::Display`],
/// [`serde::Serialize`], [`AsRef<str>`], [`AsRef<[u8]>`],
/// `From<T> for &'static str`, `From<T> for &'static [u8]`,
/// `From<T> for String`, `From<T> for Cow<'static, str>`, this
/// `From<T> for Cow<'static, [u8]>` — reads through it. Closing
/// the trio at the version-bump-magnitude ladder extends the one-
/// oracle surface across the byte-slice frontier at the borrowed/
/// owned-frontier receiver shape at the third ordered typed sum
/// without introducing a second canonical-label site or a second
/// grammar path.
impl From<BumpLevel> for std::borrow::Cow<'static, [u8]> {
    fn from(level: BumpLevel) -> std::borrow::Cow<'static, [u8]> {
        std::borrow::Cow::Borrowed(level.as_str().as_bytes())
    }
}

/// [`From<BumpLevel> for Box<[u8]>`] routes through [`BumpLevel::as_str`]
/// composed with [`str::as_bytes`] and
/// [`<Box<[u8]> as From<&[u8]>>::from`] so a downstream consumer bound by
/// [`Into<Box<[u8]>>`] (a validated-input newtype whose byte-slice
/// payload field is typed [`Box<[u8]>`] to carry the canonical label
/// bytes at a single exact-capacity allocation with no [`Vec<u8>`]
/// growth-header slack, a `phf`-style keyed-table byte-key value slot
/// at the shrunk-owned frontier, a SLSA / sigstore attestation-subject
/// bytes builder whose payload sink is typed as an immutable heap-
/// owned byte slice, an OCI / GHCR annotation-value sink that owns the
/// label bytes without the [`Vec<u8>`] growth-header cost for the
/// network round-trip) receives the canonical lowercase label bytes
/// (`b"patch"`, `b"minor"`, `b"major"`) as an immutable heap-owned
/// [`Box<[u8]>`] with a single exact-capacity allocation — no
/// [`Vec<u8>`] growth-header, no [`Vec::with_capacity`] over-
/// allocation slack, no [`Vec::into_boxed_slice`] realloc-plus-shrink
/// round trip — through ONE composition rather than a per-consumer
/// `Box::<[u8]>::from(level.as_str().as_bytes())` restatement.
///
/// Structural mirror of [`From<BumpLevel> for Box<str>`] (commit
/// 5308841) at the UTF-8 frontier — the same by-value shrunk-owned
/// emit surface at the same one-oracle discipline, projected onto the
/// byte-slice frontier instead of the UTF-8 string frontier. Trio-
/// closing peer of the by-value [`Box<[u8]>`]-emit trio at the third
/// ordered typed sum: [`From<crate::retry::PerAttemptRegion> for
/// Box<[u8]>`] (commit 7045474) opened the trio at the per-attempt-
/// region ladder;
/// [`From<crate::probe_outcome::AdmissionTier> for Box<[u8]>`] (commit
/// e78e47a) carried the mid-trio slot at the admission-tier ladder;
/// this impl closes the trio at the version-bump-magnitude ladder,
/// matching the [`From<T> for Box<str>`] closure order
/// (c54e10a → f8e0e02 → 5308841), the [`From<T> for &'static [u8]`]
/// closure order (70e813b → 694dff9 → 762437f), the
/// [`From<T> for Vec<u8>`] closure order (2ad52bc → 491db4d → 6701191),
/// and the [`From<T> for Cow<'static, [u8]>`] closure order
/// (912a5ff → 89af285 → 7c465d1). After this commit the by-value
/// shrunk-owned byte-slice emit surface spans all three ordered typed
/// sums on the ladder set through the same composition — the same
/// lock-step uniformity every prior byte-slice emit peer already
/// carries.
///
/// The natural bridge from the [`Vec<u8>`] peer above to any
/// downstream site that types its byte-slice sink as
/// `impl Into<Box<[u8]>>` — the emit peer that answers the receiver-
/// side question "does this byte-oriented API want a growable
/// [`Vec<u8>`] with resize headroom or a shrunk-owned immutable
/// heap-owned buffer?" with "the immutable shrunk-owned
/// [`Box<[u8]>`]." A receiver typed as [`Box<[u8]>`] (rather than
/// [`Vec<u8>`]) pays the exact-capacity single-allocation cost
/// without the growth-header slack, and cannot silently grow past its
/// allocated end — the load-bearing discipline for a keyed-table
/// byte-key slot, a validated-input newtype byte-payload field, or an
/// SLSA subject-bytes sink that must not reallocate after signing.
/// The routing discipline picks [`<Box<[u8]> as From<&[u8]>>::from`]
/// rather than
/// `level.as_str().as_bytes().to_vec().into_boxed_slice()`:
/// [`<Box<[u8]> as From<&[u8]>>::from`] allocates the boxed slice at
/// exactly the canonical label bytes' length in one call, so the
/// emit-side receiver pays exactly one exact-capacity heap allocation,
/// not the [`Vec<u8>`]-with-growth-header allocation plus
/// [`Vec::into_boxed_slice`] realloc-and-shrink round trip that a
/// `.to_vec().into_boxed_slice()` composition would pay.
///
/// The identity `Box::<[u8]>::from(level).as_ref() ==
/// level.as_str().as_bytes()` at every [`BumpLevel::ALL`] variant is
/// pinned by
/// [`tests::test_bump_level_from_into_boxed_bytes_agrees_with_as_str_as_bytes`];
/// the identity carried through a generic
/// `impl Into<Box<[u8]>>` consumer at every variant is pinned by
/// [`tests::test_bump_level_into_boxed_bytes_carries_through_generic_consumer`];
/// the UTF-8 validity of the emitted boxed bytes decoding back to
/// [`BumpLevel::as_str`] at every variant is pinned by
/// [`tests::test_bump_level_from_into_boxed_bytes_round_trips_through_from_utf8`].
///
/// THEORY.md §V.4 typed primitives: the by-value shrunk-owned
/// [`Box<[u8]>`] emit surface is a typed-primitive site on
/// [`BumpLevel`] itself (one `From<BumpLevel> for Box<[u8]>` impl
/// routing through [`as_str`] + [`str::as_bytes`] composed with
/// [`<Box<[u8]> as From<&[u8]>>::from`]), not a per-consumer
/// `Box::<[u8]>::from(level.as_str().as_bytes())` restatement at
/// every downstream site that accepts `impl Into<Box<[u8]>>`.
/// THEORY.md §VI.1 one-oracle: the canonical label is named at one
/// site ([`BumpLevel::as_str`]) and every byte-slice emit surface —
/// [`AsRef<[u8]>`], [`From<T> for &'static [u8]`],
/// [`From<T> for Vec<u8>`], [`From<T> for Cow<'static, [u8]>`], this
/// [`From<T> for Box<[u8]>`] — reads through it composed with
/// [`str::as_bytes`], so the shrunk-owned allocation shape sits ON
/// TOP of the same canonical-label oracle every borrowed-view,
/// static-lifetime, owned-buffer, and borrowed/owned-frontier emit
/// peer already reads. Closing the trio at the version-bump-magnitude
/// ladder extends the one-oracle surface across the byte-slice
/// frontier at the shrunk-owned receiver shape at the third ordered
/// typed sum without introducing a second canonical-label site or a
/// second grammar path.
impl From<BumpLevel> for Box<[u8]> {
    fn from(level: BumpLevel) -> Box<[u8]> {
        Box::<[u8]>::from(level.as_str().as_bytes())
    }
}

/// [`From<BumpLevel> for Arc<[u8]>`] routes through [`BumpLevel::as_str`]
/// composed with [`str::as_bytes`] and then
/// [`std::sync::Arc::<[u8]>::from`] so a downstream consumer bound by
/// `impl Into<Arc<[u8]>>` (a cross-thread cached-payload slot that wants
/// a single canonical allocation of the label bytes shared across worker
/// threads via atomic refcount, a validated-input newtype wrapper whose
/// byte-slice payload field is stored as [`Arc<[u8]>`] to hand cheap
/// [`Arc::clone`]s to sibling structures on other threads, a serde
/// container that opts into `#[serde(from = "Arc<[u8]>")]` on a byte-
/// payload field, a dashmap-style keyed-table byte-value slot whose
/// readers want an [`Arc`] clone rather than a per-lookup allocation, an
/// SLSA / sigstore attestation-subject bytes builder whose signed
/// payload is shared read-only across a signing-and-verification worker
/// pool, an OCI / GHCR annotation-value sink that hands the same label-
/// bytes allocation to multiple upload workers without re-allocating per
/// worker) receives the canonical lowercase label bytes (`b"patch"`,
/// `b"minor"`, `b"major"`) as a shared-owned immutable heap-owned
/// [`Arc<[u8]>`] with a single allocation for the atomic-refcount header
/// plus the exact-length label bytes, enabling `O(1)` [`Arc::clone`] on
/// the emit result across threads without a per-clone allocation —
/// through ONE composition rather than a per-consumer
/// `Arc::<[u8]>::from(level.as_str().as_bytes())` restatement.
///
/// Structural mirror of [`From<BumpLevel> for Arc<str>`] below at the
/// byte-slice frontier — the same by-value shared-owned emit surface at
/// the same one-oracle discipline, projected onto the byte-slice
/// frontier instead of the UTF-8 string frontier. Trio-closing peer of
/// the by-value [`Arc<[u8]>`]-emit trio at the third ordered typed sum:
/// [`From<crate::retry::PerAttemptRegion> for Arc<[u8]>`] (commit
/// c922ae1) opened the trio at the per-attempt-region ladder;
/// [`From<crate::probe_outcome::AdmissionTier> for Arc<[u8]>`] (commit
/// 5e869fc) carried the mid-trio slot at the admission-tier ladder;
/// this impl closes the trio at the version-bump-magnitude ladder,
/// matching the [`From<T> for Arc<str>`] closure order
/// (c3a722d → 6bab1ab → fc894ef), the [`From<T> for Box<[u8]>`] closure
/// order (7045474 → e78e47a → 23f8696), the [`From<T> for Vec<u8>`]
/// closure order (2ad52bc → 491db4d → 6701191), and the
/// [`From<T> for Cow<'static, [u8]>`] closure order
/// (912a5ff → 89af285 → 7c465d1). After this commit the by-value emit
/// cross-product at the byte-slice frontier spans all six ownership
/// shapes — borrowed-view [`AsRef<[u8]>`], by-value static-lifetime
/// [`&'static [u8]`], by-value owned-buffer [`Vec<u8>`], by-value
/// borrowed/owned-frontier [`Cow<'static, [u8]>`], by-value shrunk-owned
/// [`Box<[u8]>`], by-value shared-owned [`Arc<[u8]>`] — across all
/// three ordered typed sums against ONE canonical-label oracle each,
/// matching the discipline already achieved at the UTF-8 frontier's
/// by-value emit peers [`&'static str`], [`String`],
/// [`Cow<'static, str>`], [`Box<str>`], [`Arc<str>`], [`Rc<str>`].
///
/// The natural bridge from the [`Box<[u8]>`] peer above to any
/// downstream site that types its byte-slice sink as
/// `impl Into<Arc<[u8]>>` — the emit peer that answers the receiver-
/// side question "does this byte-oriented API want an exclusively-owned
/// [`Box<[u8]>`] immutable buffer or a shared-owned [`Arc<[u8]>`]
/// immutable buffer clonable in `O(1)` across threads?" with "the
/// shared-owned [`Arc<[u8]>`]." A receiver typed as [`Arc<[u8]>`]
/// (rather than [`Box<[u8]>`]) pays one extra atomic-refcount-header
/// slot preceding the label bytes in exchange for `O(1)` [`Arc::clone`]
/// across every fan-out worker on any thread, so a `rayon` / `tokio`
/// fan-out that wants the same canonical label bytes at every worker
/// receives one clone-cheap [`Arc<[u8]>`] handle at each fan-out edge
/// rather than a per-worker [`Box<[u8]>`] allocation. The routing
/// discipline picks [`std::sync::Arc::<[u8]>::from`] rather than
/// `Arc::from(Box::<[u8]>::from(level.as_str().as_bytes()))` (two
/// allocations: box the slice, then rewrap into an [`Arc<[u8]>`]) or
/// `Arc::from(level.as_str().as_bytes().to_vec().into_boxed_slice())`
/// (three allocations plus a realloc-and-shrink round trip): the direct
/// [`std::sync::Arc::<[u8]>::from`] path allocates once from the
/// `'static` label byte-slice, including the atomic-refcount header, so
/// the emit-side receiver pays exactly one allocation for the header
/// plus the label's byte-length.
///
/// The identity `Arc::<[u8]>::from(level).as_ref() ==
/// level.as_str().as_bytes()` at every [`BumpLevel::ALL`] variant is
/// pinned by
/// [`tests::test_bump_level_into_arc_bytes_agrees_with_as_str_as_bytes`];
/// the identity carried through a generic
/// `impl Into<Arc<[u8]>>` consumer at every variant is pinned by
/// [`tests::test_bump_level_into_arc_bytes_carries_through_generic_consumer`];
/// the shared-owned receiver contract — [`Arc::clone`] reads the same
/// canonical label bytes, [`Arc::ptr_eq`] holds after [`Arc::clone`],
/// and [`Arc::strong_count`] lifts to at least two after the clone —
/// at every variant is pinned by
/// [`tests::test_bump_level_into_arc_bytes_shares_label_across_clones`],
/// mirroring the `Arc::clone`-preserves-value pin at the [`Arc<str>`]
/// surface
/// ([`tests::test_bump_level_into_arc_str_shares_label_across_clones`]).
///
/// THEORY.md §V.4 typed primitives: the by-value shared-owned
/// [`Arc<[u8]>`] emit surface is a typed-primitive site on
/// [`BumpLevel`] itself (one `From<BumpLevel> for Arc<[u8]>` impl
/// routing through [`as_str`] + [`str::as_bytes`] composed with
/// [`std::sync::Arc::<[u8]>::from`]), not a per-consumer
/// `Arc::<[u8]>::from(level.as_str().as_bytes())` restatement at every
/// downstream site that accepts `impl Into<Arc<[u8]>>`.
/// THEORY.md §VI.1 one-oracle: the canonical label is named at one site
/// ([`BumpLevel::as_str`]) and every byte-slice emit surface —
/// [`AsRef<[u8]>`], [`From<T> for &'static [u8]`],
/// [`From<T> for Vec<u8>`], [`From<T> for Cow<'static, [u8]>`],
/// [`From<T> for Box<[u8]>`], this [`From<T> for Arc<[u8]>`] — reads
/// through it composed with [`str::as_bytes`], so the shared-owned
/// allocation shape sits ON TOP of the same canonical-label oracle
/// every borrowed-view, static-lifetime, owned-buffer, borrowed/owned-
/// frontier, and shrunk-owned emit peer already reads. Closing the trio
/// at the version-bump-magnitude ladder extends the one-oracle surface
/// across the byte-slice frontier at the shared-owned receiver shape at
/// the third ordered typed sum without introducing a second canonical-
/// label site or a second grammar path.
impl From<BumpLevel> for std::sync::Arc<[u8]> {
    fn from(level: BumpLevel) -> std::sync::Arc<[u8]> {
        std::sync::Arc::<[u8]>::from(level.as_str().as_bytes())
    }
}

/// [`From<BumpLevel> for Rc<[u8]>`] routes through
/// [`BumpLevel::as_str`] composed with [`str::as_bytes`] and then
/// [`std::rc::Rc::<[u8]>::from`] so a downstream consumer bound by
/// `impl Into<Rc<[u8]>>` (a thread-local cached-payload slot that
/// wants a single canonical allocation of the label bytes shared
/// within one worker thread via non-atomic refcount, a validated-
/// input newtype wrapper whose byte-slice payload field is stored
/// as [`Rc<[u8]>`] to hand cheap [`Rc::clone`]s to sibling
/// structures on the same thread, a serde container that opts into
/// `#[serde(from = "Rc<[u8]>")]` on a byte-payload field, a per-
/// request-arena byte-value slot whose readers want an [`Rc`] clone
/// rather than a per-lookup allocation on a single-threaded pipeline
/// stage, a graph-walk visitor that clones canonical byte-payloads
/// across nodes without needing [`Send`] / [`Sync`], a same-thread
/// SLSA / sigstore attestation-subject bytes builder whose signed
/// payload is shared read-only across a single-threaded signing
/// pipeline, an OCI / GHCR annotation-value sink that hands the same
/// label-bytes allocation to multiple within-thread emit stages
/// without re-allocating per stage) receives the canonical lowercase
/// label bytes (`b"patch"`, `b"minor"`, `b"major"`) as a thread-
/// local shared-owned immutable heap-owned [`Rc<[u8]>`] with a
/// single allocation for the non-atomic-refcount header plus the
/// exact-length label bytes, enabling `O(1)` [`Rc::clone`] on the
/// emit result within the emitting thread at a strictly lower per-
/// clone cost than the atomic [`Arc::clone`] — through ONE
/// composition rather than a per-consumer
/// `Rc::<[u8]>::from(level.as_str().as_bytes())` restatement.
///
/// Structural mirror of [`From<BumpLevel> for Rc<str>`] below at the
/// byte-slice frontier — the same by-value thread-local shared-
/// owned emit surface at the same one-oracle discipline, projected
/// onto the byte-slice frontier instead of the UTF-8 string
/// frontier. Trio-closing peer of the by-value [`Rc<[u8]>`]-emit
/// trio at the third ordered typed sum:
/// [`From<crate::retry::PerAttemptRegion> for Rc<[u8]>`] (commit
/// b27865d) opened the trio at the per-attempt-region ladder;
/// [`From<crate::probe_outcome::AdmissionTier> for Rc<[u8]>`]
/// (commit e621a28) carried the mid-trio slot at the admission-tier
/// ladder; this impl closes the trio at the version-bump-magnitude
/// ladder, matching the [`From<T> for Rc<str>`] closure order
/// (8950199 → 62c49a0 → ae286b7), the [`From<T> for Arc<[u8]>`]
/// closure order (c922ae1 → 5e869fc → c6b636b), the
/// [`From<T> for Box<[u8]>`] closure order
/// (7045474 → e78e47a → 23f8696), the [`From<T> for Vec<u8>`]
/// closure order (2ad52bc → 491db4d → 6701191), and the
/// [`From<T> for Cow<'static, [u8]>`] closure order
/// (912a5ff → 89af285 → 7c465d1). After this commit the by-value
/// emit cross-product at the byte-slice frontier spans all seven
/// ownership shapes — borrowed-view [`AsRef<[u8]>`], by-value
/// static-lifetime [`&'static [u8]`], by-value owned-buffer
/// [`Vec<u8>`], by-value borrowed/owned-frontier
/// [`Cow<'static, [u8]>`], by-value shrunk-owned [`Box<[u8]>`],
/// by-value atomic-shared-owned [`Arc<[u8]>`], by-value thread-
/// local shared-owned [`Rc<[u8]>`] — across all three ordered typed
/// sums against ONE canonical-label oracle each, matching the
/// discipline already achieved at the UTF-8 frontier's by-value
/// emit peers [`&'static str`], [`String`], [`Cow<'static, str>`],
/// [`Box<str>`], [`Arc<str>`], [`Rc<str>`].
///
/// The natural bridge from the [`Arc<[u8]>`] peer above to any
/// downstream site that types its byte-slice sink as
/// `impl Into<Rc<[u8]>>` — the emit peer that answers the receiver-
/// side question "does this byte-oriented API want an atomic-
/// refcounted [`Arc<[u8]>`] shared-owned buffer clonable across
/// threads or a non-atomic-refcounted [`Rc<[u8]>`] shared-owned
/// buffer clonable only within one thread at a strictly lower per-
/// clone cost?" with "the non-atomic [`Rc<[u8]>`]." A receiver typed
/// as [`Rc<[u8]>`] (rather than [`Arc<[u8]>`]) trades the
/// [`Send`] / [`Sync`] cross-thread guarantee for a strictly lower
/// per-clone cost — the correct choice at every emit site where the
/// consumer is known to never cross a thread boundary. The routing
/// discipline picks [`std::rc::Rc::<[u8]>::from`] rather than
/// `Rc::from(Box::<[u8]>::from(level.as_str().as_bytes()))` (two
/// allocations: box the slice, then rewrap into an [`Rc<[u8]>`]) or
/// `Rc::from(level.as_str().as_bytes().to_vec().into_boxed_slice())`
/// (three allocations plus a realloc-and-shrink round trip): the
/// direct [`std::rc::Rc::<[u8]>::from`] path allocates once from the
/// `'static` label byte-slice, including the non-atomic-refcount
/// header, so the emit-side receiver pays exactly one allocation
/// for the header plus the label's byte-length.
///
/// The identity `Rc::<[u8]>::from(level).as_ref() ==
/// level.as_str().as_bytes()` at every [`BumpLevel::ALL`] variant is
/// pinned by
/// [`tests::test_bump_level_into_rc_bytes_agrees_with_as_str_as_bytes`];
/// the identity carried through a generic `impl Into<Rc<[u8]>>`
/// consumer at every variant is pinned by
/// [`tests::test_bump_level_into_rc_bytes_carries_through_generic_consumer`];
/// the thread-local shared-owned receiver contract — [`Rc::clone`]
/// reads the same canonical label bytes, [`Rc::ptr_eq`] holds after
/// [`Rc::clone`], and [`Rc::strong_count`] lifts to at least two
/// after the clone — at every variant is pinned by
/// [`tests::test_bump_level_into_rc_bytes_shares_label_across_clones`],
/// mirroring the `Rc::clone`-preserves-value pin at the [`Rc<str>`]
/// surface
/// ([`tests::test_bump_level_into_rc_str_shares_label_across_clones`]).
///
/// THEORY.md §V.4 typed primitives: the by-value thread-local
/// shared-owned [`Rc<[u8]>`] emit surface is a typed-primitive site
/// on [`BumpLevel`] itself (one `From<BumpLevel> for Rc<[u8]>` impl
/// routing through [`as_str`] + [`str::as_bytes`] composed with
/// [`std::rc::Rc::<[u8]>::from`]), not a per-consumer
/// `Rc::<[u8]>::from(level.as_str().as_bytes())` restatement at
/// every downstream site that accepts `impl Into<Rc<[u8]>>`.
/// THEORY.md §VI.1 one-oracle: the canonical label is named at one
/// site ([`BumpLevel::as_str`]) and every byte-slice emit surface —
/// [`AsRef<[u8]>`], [`From<T> for &'static [u8]`],
/// [`From<T> for Vec<u8>`], [`From<T> for Cow<'static, [u8]>`],
/// [`From<T> for Box<[u8]>`], [`From<T> for Arc<[u8]>`], this
/// [`From<T> for Rc<[u8]>`] — reads through it composed with
/// [`str::as_bytes`], so the thread-local shared-owned allocation
/// shape sits ON TOP of the same canonical-label oracle every
/// borrowed-view, static-lifetime, owned-buffer, borrowed/owned-
/// frontier, shrunk-owned, and atomic-shared-owned emit peer
/// already reads. Closing the trio at the version-bump-magnitude
/// ladder extends the one-oracle surface across the byte-slice
/// frontier at the thread-local shared-owned receiver shape at the
/// third ordered typed sum without introducing a second canonical-
/// label site or a second grammar path.
impl From<BumpLevel> for std::rc::Rc<[u8]> {
    fn from(level: BumpLevel) -> std::rc::Rc<[u8]> {
        std::rc::Rc::<[u8]>::from(level.as_str().as_bytes())
    }
}

/// [`TryFrom<&[u8]> for BumpLevel`] routes through
/// [`std::str::from_utf8`] at the byte-slice / UTF-8 frontier composed
/// with [`<Self as std::str::FromStr>::from_str`] at the canonical-
/// label parse oracle so a downstream consumer bound by
/// `impl for<'a> TryFrom<&'a [u8]>` (a `memchr`-driven line-splitter
/// that hands slice tokens straight to a typed parser, an OCI / GHCR
/// manifest annotation-value reader that surfaces raw `&[u8]`
/// payloads, a SLSA / sigstore attestation-subject bytes reader that
/// rehydrates variant labels from the byte-slice frontier, a
/// `blake3` / `sha2` digest-input replay verifier that re-parses the
/// pre-hashed canonical label bytes, an
/// [`std::os::unix::ffi::OsStrExt`] label bridge that carries the
/// canonical label as `&[u8]` across the OS-string boundary, a
/// `nom` / `winnow` byte-parser combinator that hands a token slice
/// to a typed-sum parser) recovers a [`BumpLevel`] value from a
/// canonical lowercase label byte-sequence (`b"patch"`, `b"minor"`,
/// `b"major"`) through the same one-oracle grammar the direct
/// `.parse::<BumpLevel>()` call sites, the sibling [`TryFrom<&str>`],
/// [`TryFrom<String>`], [`TryFrom<Cow<'_, str>>`],
/// [`TryFrom<Box<str>>`], [`TryFrom<Arc<str>>`], and
/// [`TryFrom<Rc<str>>`] parse peers already read.
///
/// The by-reference byte-slice parse peer of [`AsRef<[u8]>`]
/// (commit 833d706, the borrowed-view byte-slice emit surface),
/// [`From<BumpLevel> for &'static [u8]`] (commit 762437f, the
/// by-value static-lifetime byte-slice emit surface), and
/// [`From<BumpLevel> for Cow<'static, [u8]>`] (commit 7c465d1, the
/// by-value borrowed/owned-frontier byte-slice emit surface) directly
/// above — the four impls together close the borrowed-view /
/// by-value-emit / by-reference-parse quartet at the byte-slice
/// frontier against the shared [`BumpLevel::as_str`] +
/// [`str::as_bytes`] canonical-label-bytes oracle. The
/// [`AsRef<[u8]>`], [`From<BumpLevel> for &'static [u8]`], and
/// [`From<BumpLevel> for Cow<'static, [u8]>`] impls are the emit
/// side (canonical label bytes out); this [`TryFrom<&[u8]>`] impl is
/// the parse side (canonical label bytes in) — the byte-slice
/// frontier's parse peer of the emit trio, symmetric with
/// [`TryFrom<&str>`] (the parse peer of the UTF-8 frontier emit set
/// [`AsRef<str>`] + [`From<BumpLevel> for &'static str`] +
/// [`From<BumpLevel> for Cow<'static, str>`]) at the UTF-8 frontier.
///
/// Trio-closing peer of the by-reference byte-slice-parse trio at the
/// third ordered typed sum: [`TryFrom<&[u8]>`] for
/// [`crate::retry::PerAttemptRegion`] (commit 5c0c827) opened the
/// trio at the per-attempt-region ladder; [`TryFrom<&[u8]>`] for
/// [`crate::probe_outcome::AdmissionTier`] (commit cdb192c) carried
/// the mid-trio slot at the admission-tier ladder; this impl closes
/// the trio at the version-bump-magnitude ladder, matching the
/// [`AsRef<[u8]>`] closure order (af44439 → 13abcc4 → 833d706), the
/// [`From<T> for &'static [u8]`] closure order
/// (70e813b → 694dff9 → 762437f), the [`From<T> for Cow<'static, [u8]>`]
/// closure order (912a5ff → 89af285 → 7c465d1), and the
/// [`TryFrom<&str>`] closure order (1be3c49 → a17cd83 → 1fb1f1d) at
/// the UTF-8 frontier's parse-side counterpart. After this commit
/// the by-reference byte-slice-parse axis spans all three ordered
/// typed sums on the ladder set against ONE
/// [`std::str::from_utf8`] + [`FromStr`] composition each.
///
/// The natural bridge to any downstream site that types its
/// byte-slice parse contract as `impl for<'a> TryFrom<&'a [u8]>`
/// rather than [`std::str::FromStr`] or [`TryFrom<&str>`] — the
/// byte-slice frontier's `serde` `try_from` container attribute
/// (`#[serde(try_from = "&[u8]")]` — which keys off
/// [`TryFrom<&[u8]>`], not [`std::str::FromStr`]), a validated-
/// input newtype builder whose canonical parse contract is stated
/// as `TryFrom<&[u8]>`, a byte-slice classifier that composes over
/// the `TryFrom<&[u8]>` contract. The [`FromStr`] impl carries the
/// load-bearing match body against the canonical grammar; this
/// [`TryFrom<&[u8]>`] impl delegates through [`std::str::from_utf8`]
/// composed with [`FromStr`], so the parse-oracle discipline is
/// preserved end-to-end and a future variant insertion (a
/// `Prerelease` band strictly below [`BumpLevel::Patch`], an
/// `Epoch` ceiling strictly above [`BumpLevel::Major`]) remains a
/// one-site edit at [`BumpLevel::as_str`] plus the matching
/// [`std::str::FromStr`] arm addition.
///
/// # Two-stage strictness
///
/// The parser is strict at TWO frontiers. First, non-UTF-8 byte
/// sequences reject at [`std::str::from_utf8`] with the standard
/// [`std::str::Utf8Error`] diagnostic surfaced through
/// [`anyhow::Error`] — an invalid UTF-8 payload never reaches the
/// canonical-label match body, so a downstream consumer bound by
/// [`TryFrom<&[u8]>`] inherits the same encoding-strictness a
/// direct [`std::str::from_utf8`] + [`str::parse`] composition
/// would offer, at one typed-primitive site rather than a per-
/// consumer two-step restatement. Second, valid-UTF-8 byte
/// sequences that decode to a non-canonical label (`b"Patch"`,
/// `b"Minor"`, `b"Major"`, `b"PATCH"`, `b" patch"`, `b"patch "`,
/// the empty byte sequence `b""`) reject at the underlying
/// [`FromStr`] impl — the same canonical-only strictness the
/// by-reference UTF-8 parse peer [`TryFrom<&str>`] and the direct
/// `.parse::<BumpLevel>()` call sites already carry, now lifted to
/// the byte-slice frontier at ONE composition through
/// [`std::str::from_utf8`] and [`FromStr`].
///
/// The identity `BumpLevel::try_from(level.as_str().as_bytes())
/// .unwrap() == level` at every [`BumpLevel::ALL`] variant is pinned
/// by
/// [`tests::test_bump_level_try_from_bytes_agrees_with_from_str`];
/// the identity carried through a generic
/// `impl for<'a> TryFrom<&'a [u8]>` consumer at every variant is
/// pinned by
/// [`tests::test_bump_level_try_from_bytes_carries_through_generic_consumer`];
/// the strict-rejection contract on non-UTF-8 input is pinned by
/// [`tests::test_bump_level_try_from_bytes_rejects_non_utf8_input`];
/// the strict-rejection contract on valid-UTF-8 non-canonical input
/// is pinned by
/// [`tests::test_bump_level_try_from_bytes_rejects_non_canonical_input`].
///
/// THEORY.md §V.4 typed primitives: the by-reference byte-slice
/// try-conversion surface is a typed-primitive site on [`BumpLevel`]
/// itself (one `TryFrom<&[u8]>` impl routing through
/// [`std::str::from_utf8`] + [`FromStr`]), not a per-consumer
/// `std::str::from_utf8(bytes).and_then(|s| s.parse::<BumpLevel>())`
/// restatement at every downstream site that receives canonical-
/// label byte sequences. THEORY.md §VI.1 one-oracle: the canonical-
/// label grammar is named at one site ([`BumpLevel::as_str`]),
/// inverted at one site
/// ([`<BumpLevel as std::str::FromStr>::from_str`]), and every
/// parse surface — [`std::str::FromStr`], [`serde::Deserialize`],
/// [`TryFrom<&str>`], [`TryFrom<String>`], [`TryFrom<Cow<'_, str>>`],
/// [`TryFrom<Box<str>>`], [`TryFrom<Arc<str>>`],
/// [`TryFrom<Rc<str>>`], this [`TryFrom<&[u8]>`] — reads through it.
/// Closing the trio at the version-bump-magnitude ladder extends
/// the one-oracle parse-side surface across the byte-slice frontier
/// at the third ordered typed sum without introducing a second
/// canonical-label site or a second grammar path.
impl TryFrom<&[u8]> for BumpLevel {
    type Error = anyhow::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let s = std::str::from_utf8(bytes)
            .map_err(|e| anyhow::anyhow!("Invalid UTF-8 in bump level bytes: {e}"))?;
        <Self as std::str::FromStr>::from_str(s)
    }
}

/// [`TryFrom<Vec<u8>> for BumpLevel`] routes through the by-reference
/// [`TryFrom<&[u8]>`] parse peer directly above on the `.as_slice()` borrow
/// of the caller-owned byte buffer, so a downstream consumer bound by
/// `impl TryFrom<Vec<u8>>` (a `serde` container that opts into
/// `#[serde(try_from = "Vec<u8>")]` on a wrapper field, a generic
/// try-conversion helper `fn parse_bytes_field<T: TryFrom<Vec<u8>>>` that
/// owns the input buffer, a validated-input newtype builder that consumes an
/// owned [`Vec<u8>`] and returns a validated [`BumpLevel`], an OCI / GHCR
/// manifest annotation-value reader that materializes payload bytes as
/// owned [`Vec<u8>`] rather than borrowed `&[u8]`, a SLSA / sigstore
/// attestation-subject bytes reader that reads through a
/// [`std::io::Read::read_to_end`] surface into an owned buffer, a
/// `bytes::Bytes::to_vec` round-trip point at the async HTTP-body /
/// registry-response frontier, a `blake3` / `sha2` pre-hashed input replay
/// verifier that owns the input buffer to feed both the hasher and the
/// canonical parse) recovers a [`BumpLevel`] value from a canonical
/// lowercase label byte-sequence (`b"patch"`, `b"minor"`, `b"major"`)
/// through the same one-oracle grammar the direct `.parse::<BumpLevel>()`
/// call sites, the sibling [`TryFrom<&str>`], [`TryFrom<String>`],
/// [`TryFrom<Cow<'_, str>>`], [`TryFrom<Box<str>>`], [`TryFrom<Arc<str>>`],
/// [`TryFrom<Rc<str>>`], and [`TryFrom<&[u8]>`] parse peers already read.
///
/// The by-value owned-buffer parse peer of [`TryFrom<&[u8]> for BumpLevel`]
/// directly above — both are parse surfaces of the byte-slice frontier,
/// differing only on the input byte-buffer ownership: [`TryFrom<&[u8]>`]
/// takes a borrowed `&[u8]` view for consumers that already hold a borrow,
/// this [`TryFrom<Vec<u8>>`] takes an owned [`Vec<u8>`] for consumers that
/// own the input buffer (a serde `try_from = "Vec<u8>"` container, a
/// byte-buffer-consuming builder). Both delegate through the shared
/// [`FromStr`] parse oracle: the borrowed peer through
/// [`std::str::from_utf8`] + [`FromStr`] directly, this owned peer through
/// the borrowed peer via `.as_slice()` at the boundary — the same canonical
/// grammar lifted to the owned-buffer input layer.
///
/// Structural mirror of [`TryFrom<String> for BumpLevel`] (commit 760e7d9)
/// at the UTF-8 frontier — the same by-value owned-input parse surface at
/// the same one-oracle discipline, projected onto the byte-slice frontier
/// instead of the UTF-8 string frontier.
///
/// Trio-closing peer of the by-value owned-buffer byte-slice-parse trio at
/// the third ordered typed sum: [`TryFrom<Vec<u8>>`] for
/// [`crate::retry::PerAttemptRegion`] (commit 91ba4bf) opened the trio at
/// the per-attempt-region ladder; [`TryFrom<Vec<u8>>`] for
/// [`crate::probe_outcome::AdmissionTier`] (commit f4a2052) carried the
/// mid-trio slot at the admission-tier ladder; this impl closes the trio at
/// the version-bump-magnitude ladder, matching the [`TryFrom<&[u8]>`]
/// closure order (5c0c827 → cdb192c → 629b242), the [`TryFrom<String>`]
/// closure order (9f6feb3 → affb017 → 760e7d9) at the UTF-8 frontier's
/// owned-input counterpart, the [`From<T> for &'static [u8]`] closure order
/// (70e813b → 694dff9 → 762437f), the [`From<T> for Cow<'static, [u8]>`]
/// closure order (912a5ff → 89af285 → 7c465d1), and the [`AsRef<[u8]>`]
/// closure order (af44439 → 13abcc4 → 833d706). After this commit the
/// by-value owned-buffer byte-slice-parse axis spans all three ordered
/// typed sums on the ladder set through ONE `.as_slice()` delegation into
/// the by-reference [`TryFrom<&[u8]>`] peer each.
///
/// The natural bridge to any downstream site that types its byte-slice
/// parse contract as `impl TryFrom<Vec<u8>>` rather than
/// [`TryFrom<&[u8]>`] — the byte-slice frontier's `serde` `try_from`
/// container attribute at the owned-buffer layer
/// (`#[serde(try_from = "Vec<u8>")]` — which keys off
/// [`TryFrom<Vec<u8>>`], not [`TryFrom<&[u8]>`]), a validated-input newtype
/// builder whose canonical parse contract is stated as `TryFrom<Vec<u8>>`
/// (consumes the caller's input buffer end-to-end), a `bytes::Bytes::to_vec`
/// / [`std::io::Read::read_to_end`] pipeline terminus that hands the
/// accumulated buffer to a typed parser. The [`FromStr`] impl carries the
/// load-bearing match body against the canonical grammar; this
/// [`TryFrom<Vec<u8>>`] impl delegates through the [`TryFrom<&[u8]>`] parse
/// peer (which itself delegates through [`std::str::from_utf8`] +
/// [`FromStr`]), so the parse-oracle discipline is preserved end-to-end and
/// a future variant insertion (a `Prerelease` band strictly below
/// [`BumpLevel::Patch`], an `Epoch` ceiling strictly above
/// [`BumpLevel::Major`]) remains a one-site edit at [`BumpLevel::as_str`]
/// plus the matching [`std::str::FromStr`] arm addition.
///
/// # Two-stage strictness
///
/// The parser is strict at the same TWO frontiers the [`TryFrom<&[u8]>`]
/// peer directly above is strict at, inherited through the delegation:
/// non-UTF-8 byte sequences reject at [`std::str::from_utf8`] with the
/// standard [`std::str::Utf8Error`] diagnostic surfaced through
/// [`anyhow::Error`], and valid-UTF-8 byte sequences that decode to a
/// non-canonical label (`b"Patch"`, `b"Minor"`, `b"Major"`, `b"PATCH"`,
/// `b" patch"`, `b"patch "`, the empty byte sequence `b""`) reject at the
/// underlying [`FromStr`] impl — the same canonical-only strictness the
/// byte-slice frontier already carries at the by-reference peer, now lifted
/// to the owned-buffer input layer at ONE composition through the borrowed
/// [`TryFrom<&[u8]>`] peer.
///
/// The identity `BumpLevel::try_from(level.as_str().as_bytes().to_vec())
/// .unwrap() == level` at every [`BumpLevel::ALL`] variant is pinned by
/// [`tests::test_bump_level_try_from_vec_bytes_agrees_with_from_str`];
/// the identity carried through a generic `impl TryFrom<Vec<u8>>`
/// consumer at every variant is pinned by
/// [`tests::test_bump_level_try_from_vec_bytes_carries_through_generic_consumer`];
/// the strict-rejection contract on non-UTF-8 owned-buffer input is pinned
/// by
/// [`tests::test_bump_level_try_from_vec_bytes_rejects_non_utf8_input`];
/// the strict-rejection contract on valid-UTF-8 non-canonical owned-buffer
/// input is pinned by
/// [`tests::test_bump_level_try_from_vec_bytes_rejects_non_canonical_input`].
///
/// THEORY.md §V.4 typed primitives: the by-value owned-buffer byte-slice
/// try-conversion surface is a typed-primitive site on [`BumpLevel`]
/// itself (one `TryFrom<Vec<u8>>` impl routing through the borrowed
/// [`TryFrom<&[u8]>`] parse peer), not a per-consumer
/// `BumpLevel::try_from(buf.as_slice())` bridge at every downstream site
/// that types its parse contract as `impl TryFrom<Vec<u8>>` rather than
/// [`TryFrom<&[u8]>`] or [`std::str::FromStr`]. THEORY.md §VI.1 one-oracle:
/// the canonical-label grammar is named at one site
/// ([`BumpLevel::as_str`]), inverted at one site
/// ([`<BumpLevel as std::str::FromStr>::from_str`]), and every parse
/// surface — [`std::str::FromStr`], [`serde::Deserialize`],
/// [`TryFrom<&str>`], [`TryFrom<String>`], [`TryFrom<Cow<'_, str>>`],
/// [`TryFrom<Box<str>>`], [`TryFrom<Arc<str>>`], [`TryFrom<Rc<str>>`],
/// [`TryFrom<&[u8]>`], this [`TryFrom<Vec<u8>>`] — reads through it.
/// Closing the trio at the version-bump-magnitude ladder extends the
/// one-oracle owned-buffer parse-side surface across the byte-slice
/// frontier at the third ordered typed sum without introducing a second
/// canonical-label site or a second grammar path.
impl TryFrom<Vec<u8>> for BumpLevel {
    type Error = anyhow::Error;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        <Self as std::convert::TryFrom<&[u8]>>::try_from(bytes.as_slice())
    }
}

/// [`TryFrom<Cow<'_, [u8]>> for BumpLevel`] routes through
/// `<Self as TryFrom<&[u8]>>::try_from(bytes.as_ref())` at the boundary so
/// a downstream consumer bound by `impl TryFrom<Cow<'_, [u8]>>` (a serde
/// container that opts into `#[serde(try_from = "Cow<'a, [u8]>")]` on a
/// wrapper field, a generic try-conversion helper
/// `fn parse<'a, T: TryFrom<Cow<'a, [u8]>>>` that composes with either a
/// `'static`-lived label byte-slice or an owned [`Vec<u8>`] payload
/// uniformly, a validated-input newtype builder that accepts either a
/// borrowed or an owned canonical label byte-buffer at the borrowed/owned
/// frontier, an OCI / GHCR manifest annotation-value reader that borrows a
/// `'static`-lived label constant against uncached entries and owns a
/// decoded payload against cached entries, a SLSA / sigstore attestation-
/// subject bytes reader that materializes payloads as [`Vec<u8>`] on the
/// fetch path and as `'static`-lived label slices on the constant path)
/// recovers a [`BumpLevel`] value from its canonical lowercase label
/// byte-sequence (`b"patch"`, `b"minor"`, `b"major"`) through the same
/// two-stage strictness composition — [`std::str::from_utf8`] decode gate
/// then the canonical-label [`FromStr`] parse gate — at ONE typed-
/// primitive site rather than a per-consumer branch-`match` on the
/// [`Cow`] variant / `str::from_utf8` + `.parse` restatement (or the
/// `BumpLevel::try_from(buf.as_ref())` bridge that leaks the underlying
/// [`TryFrom<&[u8]>`] contract at every downstream site).
///
/// Trio-closing peer of the by-value borrowed/owned-frontier byte-slice-
/// parse trio at the third ordered typed sum: [`TryFrom<Cow<'_, [u8]>>`]
/// for [`crate::retry::PerAttemptRegion`] (commit 506c183) opened the trio
/// at the per-attempt-region ladder; [`TryFrom<Cow<'_, [u8]>>`] for
/// [`crate::probe_outcome::AdmissionTier`] (commit ac5b862) carried the
/// mid-trio slot at the admission-tier ladder; this impl closes the trio
/// at the version-bump-magnitude ladder, matching the [`TryFrom<&[u8]>`]
/// closure order (5c0c827 → cdb192c → 629b242), the [`TryFrom<Vec<u8>>`]
/// closure order (91ba4bf → f4a2052 → 5b6f488), the sibling UTF-8-frontier
/// [`TryFrom<Cow<'_, str>>`] closure order (0b85b4f → 03d977b → 6301ac4),
/// the [`From<T> for Cow<'static, [u8]>`] closure order (912a5ff →
/// 89af285 → 7c465d1), the [`From<T> for &'static [u8]`] closure order
/// (70e813b → 694dff9 → 762437f), and the [`AsRef<[u8]>`] closure order
/// (af44439 → 13abcc4 → 833d706). After this commit the by-value
/// borrowed/owned-frontier byte-slice-parse axis spans all three ordered
/// typed sums on the ladder set through ONE `Cow::as_ref` delegation into
/// the by-reference [`TryFrom<&[u8]>`] peer each.
///
/// The `Cow::as_ref` delegation body picks the zero-allocation reading
/// that dispatches uniformly against both [`Cow::Borrowed`] (yields the
/// underlying `&[u8]` borrow directly) and [`Cow::Owned`] (yields the
/// [`Vec::as_slice`] view of the caller-owned buffer without a redundant
/// clone) — the same discipline the sibling [`TryFrom<Cow<'_, str>>`]
/// parse peer applies at the UTF-8 frontier and the emit-side
/// [`From<BumpLevel> for Cow<'static, [u8]>`] peer applies at the
/// [`Cow::Borrowed`] branch. The parse-side receiver pays the by-reference
/// [`TryFrom<&[u8]>`] cost, not the [`Vec<u8>`]-allocation cost of a
/// `Cow::into_owned` round trip.
///
/// # Two-stage strictness
///
/// The parser is strict at the same TWO frontiers the [`TryFrom<&[u8]>`]
/// and [`TryFrom<Vec<u8>>`] peers above are strict at, inherited through
/// the delegation: non-UTF-8 byte sequences reject at
/// [`std::str::from_utf8`] with the standard [`std::str::Utf8Error`]
/// diagnostic surfaced through [`anyhow::Error`], and valid-UTF-8 byte
/// sequences that decode to a non-canonical label (`b"Patch"`,
/// `b"Minor"`, `b"Major"`, `b"PATCH"`, `b" patch"`, `b"patch "`, the
/// empty byte sequence `b""`) reject at the underlying [`FromStr`] impl
/// — the same canonical-only strictness the byte-slice frontier already
/// carries at the by-reference and by-value owned-buffer peers, now
/// lifted to the borrowed/owned-frontier input layer at ONE composition
/// through the borrowed [`TryFrom<&[u8]>`] peer.
///
/// The identity
/// `BumpLevel::try_from(Cow::Borrowed(level.as_str().as_bytes())).unwrap()
/// == level` (and its [`Cow::Owned`] sibling) at every
/// [`BumpLevel::ALL`] variant is pinned by
/// [`tests::test_bump_level_try_from_cow_bytes_agrees_with_from_str`];
/// the identity carried through a generic
/// `impl TryFrom<Cow<'_, [u8]>>` consumer at every variant across both
/// [`Cow`] branches is pinned by
/// [`tests::test_bump_level_try_from_cow_bytes_carries_through_generic_consumer`];
/// the strict-rejection contract on non-UTF-8 borrowed/owned-frontier
/// input is pinned by
/// [`tests::test_bump_level_try_from_cow_bytes_rejects_non_utf8_input`];
/// the strict-rejection contract on valid-UTF-8 non-canonical borrowed/
/// owned-frontier input is pinned by
/// [`tests::test_bump_level_try_from_cow_bytes_rejects_non_canonical_input`].
///
/// THEORY.md §V.4 typed primitives: the by-value borrowed/owned-frontier
/// byte-slice try-conversion surface is a typed-primitive site on
/// [`BumpLevel`] itself (one `TryFrom<Cow<'_, [u8]>>` impl routing through
/// the borrowed [`TryFrom<&[u8]>`] parse peer), not a per-consumer
/// `BumpLevel::try_from(buf.as_ref())` bridge at every downstream site
/// that types its parse contract as `impl TryFrom<Cow<'_, [u8]>>` rather
/// than [`TryFrom<&[u8]>`] or [`TryFrom<Vec<u8>>`]. THEORY.md §VI.1
/// one-oracle: the canonical-label grammar is named at one site
/// ([`BumpLevel::as_str`]), inverted at one site
/// ([`<BumpLevel as std::str::FromStr>::from_str`]), and every parse
/// surface — [`std::str::FromStr`], [`serde::Deserialize`],
/// [`TryFrom<&str>`], [`TryFrom<String>`], [`TryFrom<Cow<'_, str>>`],
/// [`TryFrom<Box<str>>`], [`TryFrom<Arc<str>>`], [`TryFrom<Rc<str>>`],
/// [`TryFrom<&[u8]>`], [`TryFrom<Vec<u8>>`], this
/// [`TryFrom<Cow<'_, [u8]>>`] — reads through it. Closing the trio at
/// the version-bump-magnitude ladder extends the one-oracle borrowed/
/// owned-frontier parse-side surface across the byte-slice frontier at
/// the third ordered typed sum without introducing a second canonical-
/// label site or a second grammar path.
impl<'a> TryFrom<std::borrow::Cow<'a, [u8]>> for BumpLevel {
    type Error = anyhow::Error;

    fn try_from(bytes: std::borrow::Cow<'a, [u8]>) -> Result<Self, Self::Error> {
        <Self as std::convert::TryFrom<&[u8]>>::try_from(bytes.as_ref())
    }
}

/// [`TryFrom<Box<[u8]>> for BumpLevel`] routes through the by-reference
/// [`TryFrom<&[u8]>`] parse peer on the caller-supplied [`Box<[u8]>`]'s
/// [`AsRef<[u8]>`] view, so a downstream consumer bound by
/// `impl TryFrom<Box<[u8]>>` (a serde container that opts into
/// `#[serde(try_from = "Box<[u8]>")]` on a wrapper field, a generic
/// try-conversion helper `fn parse<T: TryFrom<Box<[u8]>>>` that composes
/// with a caller-owned shrunk byte-buffer uniformly, a validated-input
/// newtype builder whose canonical parse contract is stated as
/// `TryFrom<Box<[u8]>>` rather than [`std::str::FromStr`]) recovers a
/// [`BumpLevel`] value from its canonical lowercase label bytes
/// (`b"patch"`, `b"minor"`, `b"major"`) through the same one-oracle
/// byte-slice grammar the by-reference [`TryFrom<&[u8]>`], by-value
/// owned-buffer [`TryFrom<Vec<u8>>`], and by-value borrowed/owned-frontier
/// [`TryFrom<Cow<'_, [u8]>>`] parse peers above already read — the caller-
/// owned shrunk buffer is consumed end-to-end, matching the discipline
/// [`TryFrom<Box<str>>`] reads at the UTF-8 frontier.
///
/// Trio-closing peer of the by-value shrunk-owned byte-slice-parse trio at
/// the third ordered typed sum:
/// [`TryFrom<Box<[u8]>>`] for [`crate::retry::PerAttemptRegion`] (commit
/// 51dcd67) opened the trio at the per-attempt-region ladder;
/// [`TryFrom<Box<[u8]>>`] for [`crate::probe_outcome::AdmissionTier`]
/// (commit c03b846) carried the mid-trio slot at the admission-tier
/// ladder; this impl closes the trio at the version-bump-magnitude
/// ladder, matching the [`TryFrom<&[u8]>`] closing order (5c0c827 →
/// cdb192c → 629b242), the [`TryFrom<Vec<u8>>`] closing order (91ba4bf →
/// f4a2052 → 5b6f488), the [`TryFrom<Cow<'_, [u8]>>`] closing order
/// (506c183 → ac5b862 → 51c42d7), and the sibling UTF-8-frontier
/// [`TryFrom<Box<str>>`] closing order (3b8c512 → 1a34d2a → 3b8a8e7).
///
/// The by-value shrunk-owned parse peer of the by-value
/// borrowed/owned-frontier byte-slice parse peer
/// [`TryFrom<Cow<'_, [u8]>> for BumpLevel`] directly above: both route
/// through the same by-reference [`TryFrom<&[u8]>`] parse oracle, but this
/// impl consumes a caller-owned [`Box<[u8]>`] (dropped after the parse)
/// whereas the [`Cow`] impl carries either borrowed or owned bytes.
/// Structural mirror of [`TryFrom<Box<str>> for BumpLevel`] at the UTF-8
/// frontier — the same shrunk-owned parse discipline, projected onto the
/// byte-slice frontier.
///
/// The parser is strict for the same reason [`std::str::FromStr`] is:
/// only the canonical lowercase labels parse. Empty input, UpperCamel
/// rendering, whitespace padding, uppercase, and non-UTF-8 byte sequences
/// all reject — the strictness is delegated from the underlying
/// [`TryFrom<&[u8]>`] impl through [`std::str::from_utf8`] and then
/// [`std::str::FromStr`].
///
/// The identity `BumpLevel::try_from(Box::<[u8]>::from(
/// level.as_str().as_bytes())).unwrap() == level` at every
/// [`BumpLevel::ALL`] variant is pinned by
/// [`tests::test_bump_level_try_from_box_bytes_agrees_with_from_str`];
/// the identity carried through a generic `impl TryFrom<Box<[u8]>>`
/// consumer at every variant is pinned by
/// [`tests::test_bump_level_try_from_box_bytes_carries_through_generic_consumer`];
/// the strict-rejection contract on non-canonical input is pinned by
/// [`tests::test_bump_level_try_from_box_bytes_rejects_non_canonical_input`].
///
/// THEORY.md §V.4 typed primitives: the by-value shrunk-owned
/// byte-slice-parse surface is a typed-primitive site on [`BumpLevel`]
/// itself (one `TryFrom<Box<[u8]>>` impl routing through the
/// by-reference [`TryFrom<&[u8]>`] parse oracle), not a per-consumer
/// `BumpLevel::try_from(std::str::from_utf8(&bytes)?.trim())` restatement
/// at every downstream site.
/// THEORY.md §VI.1 one-oracle: the canonical label grammar is named at one
/// site ([`BumpLevel::as_str`]), inverted at one site
/// ([`<BumpLevel as std::str::FromStr>::from_str`]), and every parse
/// surface — [`std::str::FromStr`], [`serde::Deserialize`],
/// [`TryFrom<&str>`], [`TryFrom<String>`], [`TryFrom<Cow<'_, str>>`],
/// [`TryFrom<Box<str>>`], [`TryFrom<Arc<str>>`], [`TryFrom<Rc<str>>`],
/// [`TryFrom<&[u8]>`], [`TryFrom<Vec<u8>>`], [`TryFrom<Cow<'_, [u8]>>`],
/// this [`TryFrom<Box<[u8]>>`] — reads through it. Closing the trio at
/// the version-bump-magnitude ladder extends the one-oracle shrunk-owned
/// byte-slice parse-side surface across every repo-internal ordered typed
/// sum at the byte-slice frontier without introducing a second
/// canonical-label site or a second grammar path.
impl TryFrom<Box<[u8]>> for BumpLevel {
    type Error = anyhow::Error;

    fn try_from(bytes: Box<[u8]>) -> Result<Self, Self::Error> {
        <Self as std::convert::TryFrom<&[u8]>>::try_from(bytes.as_ref())
    }
}

/// [`TryFrom<Arc<[u8]>> for BumpLevel`] routes through the by-reference
/// [`TryFrom<&[u8]>`] parse peer above on the caller-supplied
/// [`std::sync::Arc<[u8]>`]'s [`AsRef<[u8]>`] view, so a downstream
/// consumer bound by `impl TryFrom<Arc<[u8]>>` (a serde container that
/// opts into `#[serde(try_from = "Arc<[u8]>")]` on a wrapper field, a
/// generic try-conversion helper `fn parse<T: TryFrom<Arc<[u8]>>>`
/// that composes with a caller-shared refcounted byte-buffer uniformly,
/// a validated-input newtype builder whose canonical parse contract is
/// stated as `TryFrom<Arc<[u8]>>` rather than [`std::str::FromStr`])
/// recovers a [`BumpLevel`] value from its canonical lowercase label
/// bytes (`b"patch"`, `b"minor"`, `b"major"`) through the same
/// one-oracle byte-slice grammar the by-reference [`TryFrom<&[u8]>`],
/// by-value owned-buffer [`TryFrom<Vec<u8>>`], by-value
/// borrowed/owned-frontier [`TryFrom<Cow<'_, [u8]>>`], and by-value
/// shrunk-owned [`TryFrom<Box<[u8]>>`] parse peers above already read —
/// the caller's atomic-refcounted shared byte-buffer is inspected
/// end-to-end without unsharing the refcount, matching the discipline
/// [`TryFrom<Arc<str>>`] reads at the UTF-8 frontier.
///
/// Trio-closing peer of the by-value shared-owned byte-slice-parse trio
/// at the third ordered typed sum:
/// [`TryFrom<Arc<[u8]>>`] for [`crate::retry::PerAttemptRegion`] (commit
/// eca99cc) opened the trio at the per-attempt-region ladder;
/// [`TryFrom<Arc<[u8]>>`] for [`crate::probe_outcome::AdmissionTier`]
/// (commit 9874d09) carried the mid-trio slot at the admission-tier
/// ladder; this impl closes the trio at the version-bump-magnitude
/// ladder, matching the [`TryFrom<&[u8]>`] closing order (5c0c827 →
/// cdb192c → 629b242), the [`TryFrom<Vec<u8>>`] closing order (91ba4bf
/// → f4a2052 → 5b6f488), the [`TryFrom<Cow<'_, [u8]>>`] closing order
/// (506c183 → ac5b862 → 51c42d7), the [`TryFrom<Box<[u8]>>`] closing
/// order (51dcd67 → c03b846 → 78229cd), and the sibling UTF-8-frontier
/// [`TryFrom<Arc<str>>`] closing order (a9c007a → 64ec99e → bc8b5be).
///
/// The by-value shared-owned parse peer of the by-value shrunk-owned
/// byte-slice parse peer [`TryFrom<Box<[u8]>> for BumpLevel`] directly
/// above: both route through the same by-reference [`TryFrom<&[u8]>`]
/// parse oracle, but this impl consumes a caller-supplied
/// [`std::sync::Arc<[u8]>`] (the atomic-refcount-header shared buffer,
/// whose refcount drops by one when the parse returns) whereas the
/// [`Box<[u8]>`] impl consumes a caller-owned shrunk buffer (dropped
/// after the parse). Structural mirror of [`TryFrom<Arc<str>> for
/// BumpLevel`] at the UTF-8 frontier — the same shared-owned parse
/// discipline, projected onto the byte-slice frontier.
///
/// The parser is strict for the same reason [`std::str::FromStr`] is:
/// only the canonical lowercase labels parse. Empty input, UpperCamel
/// rendering, whitespace padding, uppercase, and non-UTF-8 byte
/// sequences all reject — the strictness is delegated from the
/// underlying [`TryFrom<&[u8]>`] impl through [`std::str::from_utf8`]
/// and then [`std::str::FromStr`].
///
/// The identity `BumpLevel::try_from(Arc::<[u8]>::from(
/// level.as_str().as_bytes())).unwrap() == level` at every
/// [`BumpLevel::ALL`] variant is pinned by
/// [`tests::test_bump_level_try_from_arc_bytes_agrees_with_from_str`];
/// the identity carried through a generic `impl TryFrom<Arc<[u8]>>`
/// consumer at every variant is pinned by
/// [`tests::test_bump_level_try_from_arc_bytes_carries_through_generic_consumer`];
/// the strict-rejection contract on non-canonical input is pinned by
/// [`tests::test_bump_level_try_from_arc_bytes_rejects_non_canonical_input`].
///
/// THEORY.md §V.4 typed primitives: the by-value shared-owned
/// byte-slice-parse surface is a typed-primitive site on [`BumpLevel`]
/// itself (one `TryFrom<Arc<[u8]>>` impl routing through the
/// by-reference [`TryFrom<&[u8]>`] parse oracle), not a per-consumer
/// `BumpLevel::try_from(std::str::from_utf8(&bytes)?.trim())`
/// restatement at every downstream site that types its parse contract
/// as `impl TryFrom<Arc<[u8]>>`.
/// THEORY.md §VI.1 one-oracle: the canonical label grammar is named at
/// one site ([`BumpLevel::as_str`]), inverted at one site
/// ([`<BumpLevel as std::str::FromStr>::from_str`]), and every parse
/// surface — [`std::str::FromStr`], [`serde::Deserialize`],
/// [`TryFrom<&str>`], [`TryFrom<String>`], [`TryFrom<Cow<'_, str>>`],
/// [`TryFrom<Box<str>>`], [`TryFrom<Arc<str>>`], [`TryFrom<Rc<str>>`],
/// [`TryFrom<&[u8]>`], [`TryFrom<Vec<u8>>`], [`TryFrom<Cow<'_, [u8]>>`],
/// [`TryFrom<Box<[u8]>>`], this [`TryFrom<Arc<[u8]>>`] — reads through
/// it. Closing the trio at the version-bump-magnitude ladder extends
/// the one-oracle shared-owned byte-slice parse-side surface across
/// every repo-internal ordered typed sum at the byte-slice frontier
/// without introducing a second canonical-label site or a second
/// grammar path.
impl TryFrom<std::sync::Arc<[u8]>> for BumpLevel {
    type Error = anyhow::Error;

    fn try_from(bytes: std::sync::Arc<[u8]>) -> Result<Self, Self::Error> {
        <Self as std::convert::TryFrom<&[u8]>>::try_from(bytes.as_ref())
    }
}

/// [`TryFrom<Rc<[u8]>> for BumpLevel`] routes through the by-reference
/// [`TryFrom<&[u8]>`] parse peer above on the caller-supplied
/// [`std::rc::Rc<[u8]>`]'s [`AsRef<[u8]>`] view, so a downstream
/// consumer bound by `impl TryFrom<Rc<[u8]>>` (a single-threaded
/// validated-input newtype builder whose canonical parse contract is
/// stated as `TryFrom<Rc<[u8]>>` rather than [`std::str::FromStr`], a
/// generic try-conversion helper `fn parse<T: TryFrom<Rc<[u8]>>>` that
/// composes with a caller-shared refcounted byte-buffer uniformly on
/// the current thread, an [`std::rc::Rc<[u8]>`]-carrying event log
/// replay that hands the canonical label bytes to a typed-sum parser
/// without unsharing the non-atomic refcount) recovers a [`BumpLevel`]
/// value from its canonical lowercase label bytes (`b"patch"`,
/// `b"minor"`, `b"major"`) through the same one-oracle byte-slice
/// grammar the by-reference [`TryFrom<&[u8]>`], by-value owned-buffer
/// [`TryFrom<Vec<u8>>`], by-value borrowed/owned-frontier
/// [`TryFrom<Cow<'_, [u8]>>`], by-value shrunk-owned
/// [`TryFrom<Box<[u8]>>`], and by-value shared-owned
/// [`TryFrom<Arc<[u8]>>`] parse peers above already read — the caller's
/// non-atomic-refcounted thread-local shared byte-buffer is inspected
/// end-to-end without unsharing the refcount, matching the discipline
/// [`TryFrom<Rc<str>>`] reads at the UTF-8 frontier.
///
/// Trio-closing peer of the by-value thread-local shared-owned
/// byte-slice-parse trio at the third ordered typed sum:
/// [`TryFrom<Rc<[u8]>>`] for [`crate::retry::PerAttemptRegion`] (commit
/// 19f862a) opened the trio at the per-attempt-region ladder;
/// [`TryFrom<Rc<[u8]>>`] for [`crate::probe_outcome::AdmissionTier`]
/// (commit 399e69f) carried the mid-trio slot at the admission-tier
/// ladder; this impl closes the trio at the version-bump-magnitude
/// ladder, matching the [`TryFrom<&[u8]>`] closing order (5c0c827 →
/// cdb192c → 629b242), the [`TryFrom<Vec<u8>>`] closing order (91ba4bf
/// → f4a2052 → 5b6f488), the [`TryFrom<Cow<'_, [u8]>>`] closing order
/// (506c183 → ac5b862 → 51c42d7), the [`TryFrom<Box<[u8]>>`] closing
/// order (51dcd67 → c03b846 → 78229cd), the [`TryFrom<Arc<[u8]>>`]
/// closing order (eca99cc → 9874d09 → 376ed4b), and the sibling
/// UTF-8-frontier [`TryFrom<Rc<str>>`] closing order (0e9bc9f →
/// 9545b4d → d8276b3).
///
/// The by-value thread-local shared-owned parse peer of the by-value
/// shared-owned byte-slice parse peer [`TryFrom<Arc<[u8]>> for
/// BumpLevel`] directly above: both route through the same
/// by-reference [`TryFrom<&[u8]>`] parse oracle, but this impl consumes
/// a caller-supplied [`std::rc::Rc<[u8]>`] (the non-atomic-refcount-
/// header thread-local shared buffer, whose refcount drops by one when
/// the parse returns) whereas the [`Arc<[u8]>`] impl consumes an
/// atomic-refcount-header cross-thread shared buffer. Structural
/// mirror of [`TryFrom<Rc<str>> for BumpLevel`] at the UTF-8 frontier
/// — the same thread-local shared-owned parse discipline, projected
/// onto the byte-slice frontier. Closes the byte-slice parse matrix
/// on [`BumpLevel`] at every owned/borrowed pointer flavor the UTF-8
/// parse matrix already covers.
///
/// The parser is strict for the same reason [`std::str::FromStr`] is:
/// only the canonical lowercase labels parse. Empty input, UpperCamel
/// rendering, whitespace padding, uppercase, and non-UTF-8 byte
/// sequences all reject — the strictness is delegated from the
/// underlying [`TryFrom<&[u8]>`] impl through [`std::str::from_utf8`]
/// and then [`std::str::FromStr`].
///
/// The identity `BumpLevel::try_from(Rc::<[u8]>::from(
/// level.as_str().as_bytes())).unwrap() == level` at every
/// [`BumpLevel::ALL`] variant is pinned by
/// [`tests::test_bump_level_try_from_rc_bytes_agrees_with_from_str`];
/// the identity carried through a generic `impl TryFrom<Rc<[u8]>>`
/// consumer at every variant is pinned by
/// [`tests::test_bump_level_try_from_rc_bytes_carries_through_generic_consumer`];
/// the strict-rejection contract on non-canonical input is pinned by
/// [`tests::test_bump_level_try_from_rc_bytes_rejects_non_canonical_input`].
///
/// THEORY.md §V.4 typed primitives: the by-value thread-local
/// shared-owned byte-slice-parse surface is a typed-primitive site on
/// [`BumpLevel`] itself (one `TryFrom<Rc<[u8]>>` impl routing through
/// the by-reference [`TryFrom<&[u8]>`] parse oracle), not a per-
/// consumer `BumpLevel::try_from(std::str::from_utf8(&bytes)?.trim())`
/// restatement at every downstream site that types its parse contract
/// as `impl TryFrom<Rc<[u8]>>`.
/// THEORY.md §VI.1 one-oracle: the canonical label grammar is named at
/// one site ([`BumpLevel::as_str`]), inverted at one site
/// ([`<BumpLevel as std::str::FromStr>::from_str`]), and every parse
/// surface — [`std::str::FromStr`], [`serde::Deserialize`],
/// [`TryFrom<&str>`], [`TryFrom<String>`], [`TryFrom<Cow<'_, str>>`],
/// [`TryFrom<Box<str>>`], [`TryFrom<Arc<str>>`], [`TryFrom<Rc<str>>`],
/// [`TryFrom<&[u8]>`], [`TryFrom<Vec<u8>>`], [`TryFrom<Cow<'_, [u8]>>`],
/// [`TryFrom<Box<[u8]>>`], [`TryFrom<Arc<[u8]>>`], this
/// [`TryFrom<Rc<[u8]>>`] — reads through it. Closing the trio at the
/// version-bump-magnitude ladder completes the byte-slice parse
/// cross-product at every repo-internal ordered typed sum against the
/// one-oracle canonical-label grammar at every owned/borrowed pointer
/// flavor the UTF-8 parse cross-product already spans.
impl TryFrom<std::rc::Rc<[u8]>> for BumpLevel {
    type Error = anyhow::Error;

    fn try_from(bytes: std::rc::Rc<[u8]>) -> Result<Self, Self::Error> {
        <Self as std::convert::TryFrom<&[u8]>>::try_from(bytes.as_ref())
    }
}

/// [`TryFrom<&str> for BumpLevel`] routes through
/// [`<BumpLevel as std::str::FromStr>::from_str`] so a downstream
/// consumer bound by `impl TryFrom<&str>` (a serde container that opts
/// into `#[serde(try_from = "&str")]` on a wrapper field, a generic
/// try-conversion helper `fn parse_field<T: for<'a> TryFrom<&'a str>>`,
/// a validated-input newtype builder whose canonical parse contract is
/// stated as `TryFrom<&str>` rather than [`std::str::FromStr`]) recovers
/// a [`BumpLevel`] value from its canonical lowercase label
/// (`"patch"`, `"minor"`, `"major"`) through the same one-oracle
/// grammar the direct `.parse::<BumpLevel>()` call sites already read.
///
/// The by-reference parse peer of [`From<BumpLevel> for &'static str`]
/// (the by-value emit peer of the canonical-label axis) —
/// [`From<BumpLevel> for &'static str`] is the by-value output
/// direction of the label-axis conversion surface, this
/// [`TryFrom<&str>`] is the by-reference input direction of the same
/// label-axis conversion surface. Both route through the shared
/// [`BumpLevel::as_str`] canonical-label oracle: the emit side through
/// [`BumpLevel::as_str`] directly, this parse side through the
/// [`std::str::FromStr`] impl whose match body inverts the
/// [`BumpLevel::as_str`] grammar.
///
/// Sibling of the [`std::fmt::Display`], [`std::str::FromStr`],
/// [`serde::Serialize`], [`serde::Deserialize`], [`AsRef<str>`], and
/// [`From<BumpLevel> for &'static str`] impls above — the same lift at
/// the by-reference try-conversion layer instead of the format / parse
/// / serde / borrow / by-value-emit layers. Together with the impls
/// above this closes the `as_str` ⇢ {`Display`, `AsRef<str>`,
/// `Serialize`, `From<T> for &'static str`} emission set and the
/// {`FromStr`, `Deserialize`, `TryFrom<&str>`} parse set at the
/// version-bump-magnitude ladder against the shared canonical-label
/// oracle. Structural mirror of `impl TryFrom<&str> for
/// PerAttemptRegion` (commit 1be3c49 — the by-reference try-conversion
/// peer at the per-attempt-region ladder) and `impl TryFrom<&str> for
/// AdmissionTier` (commit a17cd83 — the by-reference try-conversion
/// peer at the admission-tier ladder) at the version-bump-magnitude
/// ladder: the same lift by construction, at the third ordered typed
/// sum. After this commit all three repo-internal ordered typed sums
/// that carry `as_str` + [`std::fmt::Display`] + [`std::str::FromStr`]
/// + [`serde::Serialize`] + [`serde::Deserialize`] + [`AsRef<str>`] +
/// [`From<T> for &'static str`] ([`BumpLevel`],
/// [`crate::probe_outcome::AdmissionTier`],
/// [`crate::retry::PerAttemptRegion`]) also carry [`TryFrom<&str>`]
/// routing through the shared canonical-label oracle — the label-axis
/// grammar at every ordered typed sum is now a one-oracle surface at
/// every Rust-idiomatic reading (direct call `as_str`, format
/// machinery [`std::fmt::Display`], byte slice [`AsRef<str>`], string
/// parse [`std::str::FromStr`], serde [`serde::Serialize`] /
/// [`serde::Deserialize`], by-value static-lifetime conversion
/// [`From<T> for &'static str`], by-reference try-conversion
/// [`TryFrom<&str>`]).
///
/// The natural bridge to the `serde` `try_from` container attribute
/// (`#[serde(try_from = "&str")]` — which keys off [`TryFrom<&str>`],
/// not [`std::str::FromStr`]) so a downstream config-schema field that
/// wraps a [`BumpLevel`] and wants serde's `try_from` grammar (as
/// opposed to the direct [`serde::Deserialize`] impl above) composes
/// with one blanket impl at the typed-primitive site, not a
/// per-consumer inline `#[serde(deserialize_with)]` cascade. The
/// [`std::str::FromStr`] impl carries the load-bearing match body
/// against the canonical grammar; this [`TryFrom<&str>`] impl
/// delegates through it, so the parse-oracle discipline is preserved
/// end-to-end and a future variant insertion (a `Prerelease` band
/// strictly below [`BumpLevel::Patch`], an `Epoch` ceiling strictly
/// above [`BumpLevel::Major`]) remains a one-site edit at
/// [`BumpLevel::as_str`] plus the matching [`std::str::FromStr`] arm
/// addition.
///
/// The parser is strict for the same reason [`std::str::FromStr`] is:
/// only the canonical lowercase labels emitted by [`BumpLevel::as_str`]
/// parse. Empty input, UpperCamel rendering (`"Patch"`, `"Minor"`,
/// `"Major"`), whitespace padding, and uppercase (`"PATCH"`) all
/// reject — the strictness is delegated from the underlying
/// [`std::str::FromStr`] impl.
///
/// The identity `BumpLevel::try_from(level.as_str()).unwrap() == level`
/// at every [`BumpLevel::ALL`] variant is pinned by
/// [`tests::test_bump_level_try_from_str_agrees_with_from_str`]; the
/// identity carried through a generic `impl for<'a> TryFrom<&'a str>`
/// consumer at every variant is pinned by
/// [`tests::test_bump_level_try_from_str_carries_through_generic_consumer`];
/// the strict-rejection contract on non-canonical input is pinned by
/// [`tests::test_bump_level_try_from_str_rejects_non_canonical_input`].
///
/// THEORY.md §V.4 typed primitives: the by-reference try-conversion
/// surface is a typed-primitive site on [`BumpLevel`] itself (one
/// `TryFrom<&str>` impl routing through the [`std::str::FromStr`]
/// parse oracle), not a per-consumer `.parse::<BumpLevel>()` bridge at
/// every downstream site that types its parse contract as
/// `impl TryFrom<&str>` rather than [`std::str::FromStr`]. THEORY.md
/// §VI.1 one-oracle: the canonical-label grammar is named at one site
/// ([`BumpLevel::as_str`]), inverted at one site
/// ([`<BumpLevel as std::str::FromStr>::from_str`]), and every parse
/// surface — [`std::str::FromStr`], [`serde::Deserialize`], this
/// `TryFrom<&str>` — reads through it.
impl TryFrom<&str> for BumpLevel {
    type Error = anyhow::Error;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        <Self as std::str::FromStr>::from_str(s)
    }
}

/// [`From<BumpLevel> for String`] routes through [`BumpLevel::as_str`] so
/// a downstream consumer bound by [`Into<String>`] (a
/// `std::collections::HashMap::<String, _>::insert` key builder keyed by
/// canonical bump label, a
/// [`std::process::Command::env(String, String)`]-shaped receiver that
/// owns its key/value pair, a [`String::push_str`] sink over a
/// caller-owned buffer, a release-manifest field builder that owns its
/// bump-label emission, a [`std::borrow::Cow<'static, str>`] sink through
/// the [`Cow::Owned`] branch) reads the canonical lowercase label
/// (`"patch"`, `"minor"`, `"major"`) directly from a [`BumpLevel`] value
/// with the [`String`] allocation named at this typed-primitive site
/// rather than at every downstream `.as_str().to_owned()` /
/// `.to_string()` call site.
///
/// The by-value owned-string emit peer of
/// [`From<BumpLevel> for &'static str`] above — both are by-value emit
/// surfaces of the label-axis conversion set, differing only on the
/// returned string ownership: [`From<BumpLevel> for &'static str`]
/// returns a zero-copy `'static`-lived borrow into the static-string
/// constant table for [`Into<&'static str>`] consumers, this
/// [`From<BumpLevel> for String`] returns the single-allocation owned
/// [`String`] for [`Into<String>`] consumers. Both route through the
/// shared [`BumpLevel::as_str`] canonical-label oracle: the borrowed peer
/// through [`BumpLevel::as_str`] directly, this owned peer through
/// `as_str().to_owned()` — the same canonical grammar lifted to the
/// owned-string layer.
///
/// Structural mirror of
/// `impl From<AdmissionTier> for String` (commit 463b31b — the by-value
/// owned-string emit peer at the admission-tier ladder, routing through
/// [`crate::probe_outcome::AdmissionTier::as_str`]) and
/// `impl From<PerAttemptRegion> for String` (commit a5a379f — the
/// by-value owned-string emit peer at the per-attempt-region ladder,
/// routing through [`crate::retry::PerAttemptRegion::as_str`]) at the
/// version-bump-magnitude ladder: the same lift by construction, at the
/// remaining ordered typed sum in the label-axis idiom. After this
/// commit all three repo-internal ordered typed sums that carry
/// `as_str` + [`std::fmt::Display`] + [`std::str::FromStr`] +
/// [`serde::Serialize`] + [`serde::Deserialize`] + [`AsRef<str>`] +
/// [`From<T> for &'static str`] + [`TryFrom<&str>`] ([`BumpLevel`],
/// [`crate::probe_outcome::AdmissionTier`],
/// [`crate::retry::PerAttemptRegion`]) also carry
/// `From<T> for String` routing through the shared canonical-label
/// oracle — the by-value emit surface at every ordered typed sum is now
/// a one-oracle surface at both string-ownership readings
/// (`'static`-lived borrow via [`From<T> for &'static str`], owned
/// allocation via [`From<T> for String`]).
///
/// Sibling of the [`std::fmt::Display`], [`std::str::FromStr`],
/// [`serde::Serialize`], [`serde::Deserialize`], [`AsRef<str>`],
/// [`From<BumpLevel> for &'static str`], and [`TryFrom<&str>`] impls
/// above — the same lift at the by-value owned-string emit layer instead
/// of the format / parse / serde / borrow / static-lifetime /
/// try-conversion layers. Together with the impls above this closes the
/// `as_str` ⇢ {`Display`, `AsRef<str>`, `Serialize`, `From<T> for
/// &'static str`, `From<T> for String`} emission set at the
/// version-bump-magnitude ladder against the shared canonical-label
/// oracle.
///
/// The natural bridge to any downstream site that types its label sink
/// as [`Into<String>`] — the owned-string sibling of the
/// [`Into<&'static str>`] bridge [`From<BumpLevel> for &'static str`]
/// opened for the borrowed static-lifetime peer.
///
/// The identity `String::from(level) == level.as_str()` at every
/// [`BumpLevel::ALL`] variant is pinned by
/// [`tests::test_bump_level_from_into_string_agrees_with_as_str`]; the
/// identity carried through a generic `impl Into<String>` consumer at
/// every variant is pinned by
/// [`tests::test_bump_level_into_string_carries_through_generic_consumer`].
///
/// THEORY.md §VI.1 one-oracle: the canonical label is named at one site
/// ([`BumpLevel::as_str`]) and every emit surface —
/// [`BumpLevel::as_str`], [`std::fmt::Display`], [`serde::Serialize`],
/// [`AsRef<str>`], [`From<BumpLevel> for &'static str`], this
/// [`From<BumpLevel> for String`] — reads through it.
impl From<BumpLevel> for String {
    fn from(level: BumpLevel) -> String {
        level.as_str().to_owned()
    }
}

/// [`TryFrom<String> for BumpLevel`] routes through
/// [`<BumpLevel as std::str::FromStr>::from_str`] on the borrowed `&str`
/// view of the caller-owned input, so a downstream consumer bound by
/// `impl TryFrom<String>` (a serde container that opts into
/// `#[serde(try_from = "String")]` on a wrapper field, a generic
/// try-conversion helper `fn parse_field<T: TryFrom<String>>` that owns
/// the input buffer, a validated-input newtype builder that consumes an
/// owned [`String`] and returns a validated [`BumpLevel`]) recovers a
/// [`BumpLevel`] value from its canonical lowercase label (`"patch"`,
/// `"minor"`, `"major"`) through the same one-oracle
/// [`std::str::FromStr`]/[`BumpLevel::as_str`] grammar the direct
/// `.parse::<BumpLevel>()` call sites and the sibling [`TryFrom<&str>`]
/// impl already read.
///
/// The by-value owned-string parse peer of [`TryFrom<&str> for
/// BumpLevel`] above — both are parse surfaces of the label-axis
/// conversion set, differing only on the input string ownership:
/// [`TryFrom<&str>`] takes a borrowed `&str` view for consumers that
/// already hold a borrow, this [`TryFrom<String>`] takes an owned
/// [`String`] for consumers that own the input buffer (a serde
/// `try_from = "String"` container, a builder that consumes its input).
/// Both delegate through the shared [`std::str::FromStr`] parse oracle:
/// the borrowed peer directly, this owned peer through `s.as_str()` at
/// the boundary — the same canonical grammar lifted to the owned-string
/// input layer.
///
/// The symmetric parse-side sibling of [`From<BumpLevel> for String`]
/// above: the two together close the by-value owned-string input+output
/// symmetry at the version-bump-magnitude ladder —
/// [`From<BumpLevel> for String`] emits the canonical label as an owned
/// [`String`] for [`Into<String>`] consumers, this
/// [`TryFrom<String>`] parses the canonical label from an owned
/// [`String`] for [`TryFrom<String>`] consumers, both routing through
/// the shared [`BumpLevel::as_str`] / [`std::str::FromStr`] oracle pair.
/// After this impl the version-bump-magnitude ladder carries the closed
/// by-reference + by-value pair at both emission
/// ([`From<BumpLevel> for &'static str`] +
/// [`From<BumpLevel> for String`]) and try-conversion
/// ([`TryFrom<&str>`] + this [`TryFrom<String>`]) surfaces of the label
/// axis — the four-way corner set of the string-ownership × conversion-
/// direction grid at the version-bump-magnitude ladder, all routing
/// through the shared canonical-label oracle.
///
/// Structural mirror of `impl TryFrom<String> for PerAttemptRegion`
/// (commit 9f6feb3 — the by-value owned-string parse peer at the
/// per-attempt-region ladder) and `impl TryFrom<String> for
/// AdmissionTier` (commit affb017 — the by-value owned-string parse
/// peer at the admission-tier ladder) at the version-bump-magnitude
/// ladder: the same lift by construction, at the remaining ordered
/// typed sum in the label-axis idiom. After this commit all three
/// repo-internal ordered typed sums that carry `as_str` +
/// [`std::fmt::Display`] + [`std::str::FromStr`] + [`serde::Serialize`]
/// + [`serde::Deserialize`] + [`AsRef<str>`] + [`From<T> for &'static
/// str`] + [`TryFrom<&str>`] + [`From<T> for String`] ([`BumpLevel`],
/// [`crate::probe_outcome::AdmissionTier`],
/// [`crate::retry::PerAttemptRegion`]) also carry [`TryFrom<String>`]
/// routing through the shared [`std::str::FromStr`] parse oracle — the
/// try-conversion surface at every ordered typed sum is now a
/// one-oracle surface at both string-ownership readings (borrowed
/// [`&str`] via [`TryFrom<&str>`], owned [`String`] via
/// [`TryFrom<String>`]).
///
/// Sibling of the [`std::fmt::Display`], [`std::str::FromStr`],
/// [`serde::Serialize`], [`serde::Deserialize`], [`AsRef<str>`],
/// [`From<BumpLevel> for &'static str`], [`TryFrom<&str>`], and
/// [`From<BumpLevel> for String`] impls above — the same lift at the
/// by-value owned-string try-conversion layer instead of the format /
/// parse / serde / borrow / static-lifetime / borrowed-try-conversion /
/// owned-emit layers. Together with the impls above this closes the
/// `as_str` ⇢ {`TryFrom<&str>`, `TryFrom<String>`} try-conversion set
/// at the version-bump-magnitude ladder against the shared
/// canonical-label oracle.
///
/// The natural bridge to the `serde` `try_from` container attribute at
/// the owned-string layer (`#[serde(try_from = "String")]` — which keys
/// off [`TryFrom<String>`], not [`TryFrom<&str>`]) so a downstream
/// release-manifest field that wraps a [`BumpLevel`] and wants serde's
/// owned-string `try_from` grammar (as opposed to the borrowed
/// [`TryFrom<&str>`] variant or the direct [`serde::Deserialize`] impl)
/// composes with one blanket impl at the typed-primitive site, not a
/// per-consumer inline `#[serde(deserialize_with)]` cascade. The
/// [`std::str::FromStr`] impl carries the load-bearing match body
/// against the canonical grammar; this [`TryFrom<String>`] impl
/// delegates through it, so the parse-oracle discipline is preserved
/// end-to-end and a future variant insertion / grammar refinement
/// remains a one-site edit at [`BumpLevel::as_str`] plus the matching
/// [`std::str::FromStr`] arm addition.
///
/// The parser is strict for the same reason [`std::str::FromStr`] is:
/// only the canonical lowercase labels emitted by [`BumpLevel::as_str`]
/// parse. Empty input, UpperCamel rendering (`"Patch"`, `"Minor"`,
/// `"Major"`), whitespace padding, and uppercase (`"PATCH"`) all reject
/// — the strictness is delegated from the underlying
/// [`std::str::FromStr`] impl.
///
/// The identity `BumpLevel::try_from(String::from(level.as_str())).unwrap() ==
/// level` at every [`BumpLevel::ALL`] variant is pinned by
/// [`tests::test_bump_level_try_from_string_agrees_with_from_str`]; the
/// identity carried through a generic `impl TryFrom<String>` consumer
/// at every variant is pinned by
/// [`tests::test_bump_level_try_from_string_carries_through_generic_consumer`];
/// the strict-rejection contract on non-canonical owned input is pinned
/// by
/// [`tests::test_bump_level_try_from_string_rejects_non_canonical_input`].
///
/// THEORY.md §V.1 knowable platform: the by-value owned-string
/// try-conversion surface is a typed-primitive site on [`BumpLevel`]
/// itself (one `TryFrom<String>` impl routing through the
/// [`std::str::FromStr`] parse oracle), not a per-consumer
/// `.parse::<BumpLevel>()` bridge at every downstream site that types
/// its parse contract as `impl TryFrom<String>` rather than
/// [`std::str::FromStr`] or [`TryFrom<&str>`] — invalid states remain
/// unrepresentable at the owned-string parse layer by construction.
/// THEORY.md §VI.1 generation over composition: the canonical-label
/// grammar is named at one site ([`BumpLevel::as_str`]), inverted at
/// one site ([`<BumpLevel as std::str::FromStr>::from_str`]), and every
/// parse surface — [`std::str::FromStr`], [`serde::Deserialize`],
/// [`TryFrom<&str>`], this [`TryFrom<String>`] — reads through it, so
/// a future variant insertion propagates by construction to every
/// parse surface without a per-surface rewrite.
impl TryFrom<String> for BumpLevel {
    type Error = anyhow::Error;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        <Self as std::str::FromStr>::from_str(s.as_str())
    }
}

/// [`From<BumpLevel> for Cow<'static, str>`] routes through
/// [`BumpLevel::as_str`] and wraps the `'static`-lived label borrow at
/// the [`std::borrow::Cow::Borrowed`] branch so a downstream consumer
/// that takes an [`Into<Cow<'static, str>>`] (a release-manifest
/// serializer that keys its emission on either a static label or a
/// caller-supplied [`String`] uniformly, a tracing / OpenTelemetry
/// attribute slot typed as `Cow<'static, str>`, a `phf`-style static
/// lookup table keyed by canonical label, a `clap` [`clap::builder::Str`]
/// / [`clap::builder::StyledStr`] sink that accepts `Cow<'static, str>`,
/// a serde helper that composes with `#[serde(borrow)]`-shaped grammars
/// at the owned/borrowed frontier) reads the canonical lowercase label
/// (`"patch"`, `"minor"`, `"major"`) directly from a [`BumpLevel`] value
/// with **zero allocation** at the emit boundary — the [`Cow::Borrowed`]
/// branch preserves the `'static` lifetime end-to-end, so a receiver
/// bound by [`Into<Cow<'static, str>>`] pays the `'static`-borrow cost
/// of [`From<BumpLevel> for &'static str`], not the [`String`]-
/// allocation cost of [`From<BumpLevel> for String`].
///
/// The by-value `Cow<'static, str>` emit peer that closes the emit-side
/// lifetime-choice ladder [`From<BumpLevel> for &'static str`] (zero-copy
/// `'static` borrow) → [`From<BumpLevel> for String`] (single-allocation
/// owned [`String`]) → this [`From<BumpLevel> for Cow<'static, str>`]
/// (uniform emit at the borrowed/owned frontier, delegated through the
/// [`Cow::Borrowed`] branch so zero-allocation is preserved at every
/// [`BumpLevel`]-typed emit site regardless of receiver shape). The
/// three by-value emit peers together consume the three canonical
/// string-owner shapes at the label axis — `&'static str`, [`String`],
/// [`std::borrow::Cow<'static, str>`] — through the shared
/// [`BumpLevel::as_str`] canonical-label oracle: the `&'static str` peer
/// through [`as_str`] directly, the [`String`] peer through
/// `as_str().to_owned()`, this [`Cow<'static, str>`] peer through
/// [`Cow::Borrowed`] wrapping [`as_str`] — the same canonical grammar
/// lifted to the borrowed/owned-frontier emit layer.
///
/// Structural mirror of `impl From<PerAttemptRegion> for
/// std::borrow::Cow<'static, str>` (commit 79113dd — the by-value
/// `Cow<'static, str>` emit peer at the per-attempt-region ladder) and
/// `impl From<AdmissionTier> for std::borrow::Cow<'static, str>` (commit
/// 65b1e77 — the by-value `Cow<'static, str>` emit peer at the
/// admission-tier ladder) at the version-bump-magnitude ladder: the
/// same [`Cow::Borrowed`] lift, through the same one-oracle discipline,
/// at the remaining ordered typed sum in the label-axis idiom. After
/// this commit all three repo-internal ordered typed sums that carry
/// `as_str` + [`std::fmt::Display`] + [`std::str::FromStr`] +
/// [`serde::Serialize`] + [`serde::Deserialize`] + [`AsRef<str>`] +
/// [`From<T> for &'static str`] + [`TryFrom<&str>`] +
/// [`From<T> for String`] + [`TryFrom<String>`] ([`BumpLevel`],
/// [`crate::probe_outcome::AdmissionTier`],
/// [`crate::retry::PerAttemptRegion`]) also carry
/// [`From<T> for Cow<'static, str>`] routing through the shared
/// [`Cow::Borrowed`] wrapping of the [`as_str`] canonical-label oracle
/// — the borrowed/owned-frontier emit surface at every ordered typed
/// sum is now a one-oracle surface at the [`Cow<'static, str>`] layer.
///
/// Sibling of the [`std::fmt::Display`], [`std::str::FromStr`],
/// [`serde::Serialize`], [`serde::Deserialize`], [`AsRef<str>`],
/// [`From<BumpLevel> for &'static str`], [`TryFrom<&str>`],
/// [`From<BumpLevel> for String`], and [`TryFrom<String>`] impls above
/// — the same lift at the by-value [`Cow<'static, str>`] emit layer
/// instead of the format / parse / serde / borrow / static-lifetime /
/// borrowed-try-conversion / owned-emit / owned-try-conversion layers.
/// Together with the impls above this closes the `as_str` ⇢
/// {`Display`, `AsRef<str>`, `Serialize`, `From<T> for &'static str`,
/// `From<T> for String`, `From<T> for Cow<'static, str>`} emission set
/// at the version-bump-magnitude ladder against the shared
/// canonical-label oracle.
///
/// The natural bridge to any downstream site that types its label sink
/// as [`Into<Cow<'static, str>>`] — the emit peer that answers the
/// receiver-side question "does this API want a borrow or an owned
/// [`String`]?" with "either, and in the [`BumpLevel`] case, always the
/// zero-allocation [`Cow::Borrowed`] branch." A receiver typed as
/// [`Cow<'static, str>`] (rather than `&'static str`) permits the caller
/// to interleave [`BumpLevel`] labels with computed [`String`]s in the
/// same sink; a receiver typed as [`Cow<'static, str>`] rather than
/// [`String`] permits the caller to elide the allocation when the label
/// is already `'static` — which every [`BumpLevel`] label is. The
/// [`Cow::Borrowed`] branch is the load-bearing choice at this impl
/// body: [`Cow::Owned`] would drift the impl toward the [`String`]-emit
/// peer's allocation cost, defeating the borrowed/owned-frontier
/// discipline this impl closes.
///
/// The identity `Cow::<'static, str>::from(level) == level.as_str()` at
/// every [`BumpLevel::ALL`] variant is pinned by
/// [`tests::test_bump_level_from_into_cow_static_str_agrees_with_as_str`];
/// the identity carried through a generic
/// `impl Into<Cow<'static, str>>` consumer at every variant is pinned
/// by
/// [`tests::test_bump_level_into_cow_static_str_carries_through_generic_consumer`];
/// the [`Cow::Borrowed`]-not-[`Cow::Owned`] zero-allocation contract at
/// the emit boundary is pinned by
/// [`tests::test_bump_level_into_cow_static_str_is_borrowed`].
///
/// THEORY.md §V.4 typed primitives: the by-value `Cow<'static, str>`
/// emit surface is a typed-primitive site on [`BumpLevel`] itself (one
/// `From<BumpLevel> for Cow<'static, str>` impl routing through
/// [`as_str`] at the [`Cow::Borrowed`] branch), not a per-consumer
/// `Cow::Borrowed(level.as_str())` restatement at every downstream
/// site that accepts `impl Into<Cow<'static, str>>`. THEORY.md §VI.1
/// one-oracle: the canonical label is named at one site
/// ([`BumpLevel::as_str`]) and every emit surface — [`BumpLevel::as_str`],
/// [`std::fmt::Display`], [`serde::Serialize`], [`AsRef<str>`],
/// [`From<BumpLevel> for &'static str`], [`From<BumpLevel> for String`],
/// this [`From<BumpLevel> for Cow<'static, str>`] — reads through it.
impl From<BumpLevel> for std::borrow::Cow<'static, str> {
    fn from(level: BumpLevel) -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed(level.as_str())
    }
}

/// [`TryFrom<Cow<'_, str>> for BumpLevel`] routes through
/// [`<BumpLevel as std::str::FromStr>::from_str`] on the borrowed
/// `&str` view of the caller-supplied [`std::borrow::Cow`], so a
/// downstream consumer bound by `impl TryFrom<Cow<'a, str>>` (a serde
/// container that opts into `#[serde(try_from = "Cow<'a, str>")]` on a
/// wrapper field, a generic try-conversion helper
/// `fn parse<T: TryFrom<Cow<'a, str>>>` that composes with either a
/// `'static`-lived label or an owned [`String`] uniformly, a validated-
/// input newtype builder that accepts either a borrowed or an owned
/// canonical label at the borrowed/owned frontier) recovers a
/// [`BumpLevel`] value from its canonical lowercase label (`"patch"`,
/// `"minor"`, `"major"`) through the same one-oracle grammar the direct
/// `.parse::<BumpLevel>()` call sites and the sibling [`TryFrom<&str>`]
/// / [`TryFrom<String>`] impls already read.
///
/// The by-value [`Cow<'_, str>`] parse peer of [`TryFrom<&str> for
/// BumpLevel`] and [`TryFrom<String> for BumpLevel`] above — all three
/// are parse surfaces of the label-axis conversion set, differing only
/// on the input string-owner shape: [`TryFrom<&str>`] takes a borrowed
/// `&str` view for consumers that already hold a borrow,
/// [`TryFrom<String>`] takes an owned [`String`] for consumers that own
/// the input buffer, this [`TryFrom<Cow<'_, str>>`] takes either
/// uniformly at the borrowed/owned-frontier receiver shape. All three
/// route through the shared [`<Self as std::str::FromStr>::from_str`]
/// canonical-grammar oracle: the [`&str`] peer through `from_str`
/// directly, the [`String`] peer through `from_str(s.as_str())`, this
/// [`Cow<'_, str>`] peer through `from_str(s.as_ref())` — the same
/// canonical grammar lifted to the borrowed/owned-frontier parse layer,
/// with the receiver-side [`std::borrow::Cow::as_ref`] call dispatching
/// uniformly against both branches ([`Cow::Borrowed`] yields the
/// borrowed `&str` view directly, [`Cow::Owned`] yields the borrowed
/// `&str` view of the owned [`String`] via [`String::as_str`]) so the
/// impl body reads the same one-oracle grammar regardless of receiver-
/// supplied `Cow` branch.
///
/// The parse-side mirror of [`From<BumpLevel> for Cow<'static, str>`]
/// above — the emit peer closes the borrowed/owned-frontier emit
/// surface (uniform emit at the [`Cow::Borrowed`] branch, zero
/// allocation regardless of receiver typing), this parse peer closes
/// the borrowed/owned-frontier parse surface (uniform parse regardless
/// of caller-supplied `Cow` branch). Together the two impls close both
/// directions of the borrowed/owned-frontier conversion at the
/// version-bump-magnitude ladder, giving a downstream site that types
/// its label sink or source as [`Cow<'a, str>`] (rather than one of the
/// four owned/borrowed cross products [`&str`] / [`String`] on the emit
/// or parse side) a first-class typed-primitive surface at both ends,
/// not a per-consumer `Cow::Borrowed(...)` / `Cow::Owned(...)`
/// restatement.
///
/// Structural mirror of [`TryFrom<Cow<'_, str>> for PerAttemptRegion`]
/// (commit 0b85b4f) and [`TryFrom<Cow<'_, str>> for AdmissionTier`]
/// (commit 03d977b) at the version-bump-magnitude ladder — the same
/// `from_str(s.as_ref())` lift, through the same one-oracle discipline,
/// at the remaining ordered typed sum in the label-axis idiom. After
/// this impl all three repo-internal ordered typed sums that carry
/// `as_str` + [`std::fmt::Display`] + [`std::str::FromStr`] +
/// [`serde::Serialize`] + [`serde::Deserialize`] + [`AsRef<str>`] +
/// [`From<T> for &'static str`] + [`TryFrom<&str>`] +
/// [`From<T> for String`] + [`TryFrom<String>`] +
/// [`From<T> for Cow<'static, str>`] ([`BumpLevel`],
/// [`crate::probe_outcome::AdmissionTier`],
/// [`crate::retry::PerAttemptRegion`]) also carry
/// [`TryFrom<Cow<'_, str>>`] routing through the shared
/// [`std::str::FromStr`] parse oracle on [`Cow::as_ref`] — the parse-
/// side arm of the borrowed/owned-frontier peer set is closed at every
/// ordered typed sum, mirroring the emit-side arm the
/// [`From<T> for Cow<'static, str>`] trio (79113dd / 65b1e77 / 133769a)
/// already closed.
///
/// Sibling of the [`std::fmt::Display`], [`std::str::FromStr`],
/// [`serde::Serialize`], [`serde::Deserialize`], [`AsRef<str>`],
/// [`From<BumpLevel> for &'static str`], [`TryFrom<&str>`],
/// [`From<BumpLevel> for String`], [`TryFrom<String>`], and
/// [`From<BumpLevel> for Cow<'static, str>`] impls above — the same
/// lift at the by-value `Cow<'_, str>` parse layer instead of the
/// format / parse / serde / borrow / static-lifetime / by-reference-
/// try / owned-string-emit / owned-string-try / borrowed-frontier-emit
/// layers. Together with the impls above this closes the parse-side arm
/// of the borrowed/owned-frontier peer set at the version-bump-
/// magnitude ladder against the shared
/// [`<Self as std::str::FromStr>::from_str`] canonical-grammar oracle.
///
/// The impl body picks [`std::borrow::Cow::as_ref`] rather than
/// [`Cow::into_owned`] or a per-branch [`match`]: [`Cow::as_ref`]
/// yields a borrowed `&str` view against both branches without
/// allocation ([`Cow::Borrowed`] yields the underlying borrow directly,
/// [`Cow::Owned`] yields the [`String::as_str`] view of the caller-
/// owned buffer without a redundant clone), so the parse-side receiver
/// pays the by-reference `from_str` cost, not the [`String`]-
/// allocation cost of a [`Cow::into_owned`] round trip — the same
/// discipline the emit-side [`From<BumpLevel> for Cow<'static, str>`]
/// peer applies at the [`Cow::Borrowed`] branch.
///
/// The identity `BumpLevel::try_from(Cow::Borrowed(level.as_str())).unwrap()
/// == level` and its [`Cow::Owned`] sibling at every [`BumpLevel::ALL`]
/// variant is pinned by
/// [`tests::test_bump_level_try_from_cow_str_agrees_with_from_str`];
/// the identity carried through a generic
/// `impl TryFrom<Cow<'_, str>>` consumer at every variant is pinned by
/// [`tests::test_bump_level_try_from_cow_str_carries_through_generic_consumer`];
/// the strict-rejection contract at non-canonical input across both
/// [`Cow`] branches is pinned by
/// [`tests::test_bump_level_try_from_cow_str_rejects_non_canonical_input`].
///
/// THEORY.md §V.4 typed primitives: the by-value [`Cow<'_, str>`] parse
/// surface is a typed-primitive site on [`BumpLevel`] itself (one
/// `TryFrom<Cow<'_, str>>` impl routing through
/// [`<Self as std::str::FromStr>::from_str`] on
/// [`Cow::as_ref`]), not a per-consumer
/// `level_str.parse::<BumpLevel>()` restatement at every downstream
/// site that receives a `Cow<'_, str>` label.
/// THEORY.md §VI.1 one-oracle: the canonical grammar is named at one
/// site ([`<BumpLevel as std::str::FromStr>::from_str`]) and every
/// parse surface — [`FromStr`], [`serde::Deserialize`],
/// [`TryFrom<&str>`], [`TryFrom<String>`], this [`TryFrom<Cow<'_,
/// str>>`] — reads through it.
impl<'a> TryFrom<std::borrow::Cow<'a, str>> for BumpLevel {
    type Error = anyhow::Error;

    fn try_from(s: std::borrow::Cow<'a, str>) -> Result<Self, Self::Error> {
        <Self as std::str::FromStr>::from_str(s.as_ref())
    }
}

/// [`From<BumpLevel> for Box<str>`] routes through [`BumpLevel::as_str`]
/// and hands the canonical lowercase label (`"patch"`, `"minor"`,
/// `"major"`) to [`Box::<str>::from`] so a downstream consumer bound by
/// `impl Into<Box<str>>` (a config-struct field typed as [`Box<str>`] to
/// shrink an owned label off a resizable [`String`]'s spare-capacity
/// tail, a validated-input newtype wrapper that stores a canonical label
/// as a fixed-size heap allocation without the [`String`] growth header,
/// a serde container that opts into `#[serde(from = "Box<str>")]` at the
/// immutable-owned-string frontier, a `phf`-style keyed table whose
/// value slot wants a heap-owned label but not the excess-capacity
/// overhead of a [`String`]) reads the canonical label directly from a
/// [`BumpLevel`] value at a single heap allocation — the shrunk-owned
/// emit peer of [`From<BumpLevel> for String`] (single allocation with
/// resize headroom) that trades resizability for a smaller receiver
/// footprint (two machine words: pointer + length, no capacity slot).
///
/// The by-value emit peer of [`From<BumpLevel> for &'static str`]
/// (zero-copy `'static` borrow of the label constant, no allocation),
/// [`From<BumpLevel> for String`] (single allocation, resizable
/// receiver), [`From<BumpLevel> for Cow<'static, str>`] (uniform emit at
/// the borrowed/owned frontier through [`Cow::Borrowed`], zero
/// allocation regardless of receiver typing), and this
/// [`From<BumpLevel> for Box<str>`] (single allocation, immutable
/// heap-owned receiver at the shrunk-owned frontier). All four route
/// through the shared [`BumpLevel::as_str`] canonical-label oracle: the
/// [`&'static str`] peer through [`as_str`] directly, the [`String`]
/// peer through [`str::to_owned`] on [`as_str`], the
/// [`Cow<'static, str>`] peer through [`Cow::Borrowed`] wrapping
/// [`as_str`], this [`Box<str>`] peer through [`Box::<str>::from`] on
/// [`as_str`] — the same canonical grammar lifted to the shrunk-owned-
/// frontier emit layer.
///
/// The impl body picks [`Box::<str>::from`] rather than
/// [`String::into_boxed_str`] on the [`String`]-emit peer: the direct
/// [`Box::<str>::from`] path allocates once from the `'static` label
/// slice through [`Box::<[u8]>::from`] on the label bytes and rewraps as
/// [`Box<str>`] internally, so the receiver pays a single allocation for
/// exactly the label's length — never the [`String`]-realloc-plus-shrink
/// round trip a `Self::from(level).into_boxed_str()` composition would
/// pay when the intermediate [`String`] allocates with resize headroom
/// and [`String::into_boxed_str`] then shrinks it back to the label
/// length. The single-allocation contract is pinned by
/// [`tests::test_bump_level_into_box_str_agrees_with_as_str`] at the
/// label-oracle surface (value agreement across every variant) and by
/// [`tests::test_bump_level_into_box_str_carries_through_generic_consumer`]
/// (identity carried through a tiny generic
/// `fn read<T: Into<Box<str>>>(t: T) -> Box<str>` consumer at every
/// variant — the structural witness that a [`BumpLevel`] is genuinely
/// usable at `impl Into<Box<str>>` call sites, so a regression that
/// drifted the impl signature (a returned [`String`] instead of
/// [`Box<str>`], a required `&BumpLevel` receiver losing the by-value
/// semantics) fails at compile time or at the assertion instead of at
/// every downstream generic call site).
///
/// Structural mirror of
/// [`From<PerAttemptRegion> for Box<str>`](crate::retry::PerAttemptRegion)
/// (commit c54e10a) at the per-attempt-region ladder and
/// [`From<AdmissionTier> for Box<str>`](crate::probe_outcome::AdmissionTier)
/// (commit f8e0e02) at the admission-tier ladder — the same
/// [`Box::<str>::from`] lift, through the same one-oracle discipline, at
/// the third ordered typed sum. Together with those two impls this
/// closes the shrunk-owned-frontier emit peer at all three canonical-
/// label typed primitives on the same ladder — the third arm of the
/// trio whose first two arms landed at c54e10a and f8e0e02.
///
/// Sibling of the [`std::fmt::Display`], [`std::str::FromStr`],
/// [`serde::Serialize`], [`serde::Deserialize`], [`AsRef<str>`],
/// [`From<BumpLevel> for &'static str`], [`TryFrom<&str>`],
/// [`From<BumpLevel> for String`], [`TryFrom<String>`],
/// [`From<BumpLevel> for Cow<'static, str>`], and
/// [`TryFrom<Cow<'_, str>>`] impls above — the same lift at the by-value
/// [`Box<str>`] emit layer instead of the format / parse / serde /
/// borrow / static-lifetime / by-reference-try / owned-string-emit /
/// owned-string-try / borrowed-frontier-emit / borrowed-frontier-try
/// layers. Closes the shrunk-owned-frontier arm of the emit peer set at
/// the version-bump-magnitude ladder against the shared
/// [`BumpLevel::as_str`] canonical-label oracle.
///
/// THEORY.md §V.4 typed primitives: the by-value [`Box<str>`] emit
/// surface is a typed-primitive site on [`BumpLevel`] itself (one
/// `From<BumpLevel> for Box<str>` impl routing through [`as_str`] at
/// the [`Box::<str>::from`] boundary), not a per-consumer
/// `Box::<str>::from(level.as_str())` restatement at every downstream
/// site that receives an [`Into<Box<str>>`] label sink.
/// THEORY.md §VI.1 one-oracle: the canonical label is named at one site
/// ([`BumpLevel::as_str`]) and every emit surface — [`as_str`],
/// [`Display`], [`serde::Serialize`], [`AsRef<str>`],
/// [`From<BumpLevel> for &'static str`],
/// [`From<BumpLevel> for String`],
/// [`From<BumpLevel> for Cow<'static, str>`], this
/// `From<BumpLevel> for Box<str>` — reads through it.
impl From<BumpLevel> for Box<str> {
    fn from(level: BumpLevel) -> Box<str> {
        Box::<str>::from(level.as_str())
    }
}

/// [`TryFrom<Box<str>> for BumpLevel`] routes through
/// [`<BumpLevel as std::str::FromStr>::from_str`] on the borrowed `&str`
/// view of the caller-supplied [`Box<str>`], so a downstream consumer
/// bound by `impl TryFrom<Box<str>>` (a serde container that opts into
/// `#[serde(try_from = "Box<str>")]` on a wrapper field to consume an
/// immutable heap-owned label without the [`String`] growth-header cost,
/// a validated-input newtype builder whose parse contract accepts a
/// caller-supplied [`Box<str>`] label slot at the shrunk-owned frontier,
/// a `phf`-style keyed-table consumer whose key slot arrives as an
/// immutable-owned label from an upstream table build) recovers a
/// [`BumpLevel`] value from its canonical lowercase label (`"patch"`,
/// `"minor"`, `"major"`) through the same one-oracle grammar the direct
/// `.parse::<BumpLevel>()` call sites and the sibling [`TryFrom<&str>`]
/// / [`TryFrom<String>`] / [`TryFrom<Cow<'_, str>>`] impls already read.
///
/// The by-value [`Box<str>`] parse peer of the [`TryFrom<&str>`]
/// (borrowed-view input), [`TryFrom<String>`] (owned-string input with
/// [`String`] resize headroom), and [`TryFrom<Cow<'_, str>>`]
/// (borrowed/owned-frontier input) impls above — all four are parse
/// surfaces of the label-axis conversion set, differing only on the
/// input string-owner shape: [`TryFrom<&str>`] takes a borrowed `&str`
/// view for consumers that already hold a borrow, [`TryFrom<String>`]
/// takes an owned resizable [`String`] for consumers that own the input
/// buffer with growth headroom, [`TryFrom<Cow<'_, str>>`] takes either
/// uniformly at the borrowed/owned-frontier receiver shape, this
/// [`TryFrom<Box<str>>`] takes an immutable heap-owned [`Box<str>`] for
/// consumers whose upstream produced a shrunk-owned label without the
/// [`String`] growth-header (a boxed slice held through a `phf`-style
/// value slot, a `Box<str>` field on a validated-input newtype, a serde
/// container that owns the label as a boxed slice). All four route
/// through the shared [`<Self as std::str::FromStr>::from_str`]
/// canonical-grammar oracle: the [`&str`] peer through `from_str`
/// directly, the [`String`] peer through `from_str(s.as_str())`, the
/// [`Cow<'_, str>`] peer through `from_str(s.as_ref())`, this
/// [`Box<str>`] peer through `from_str(s.as_ref())` — the same
/// canonical grammar lifted to the shrunk-owned-frontier parse layer,
/// with the receiver-side [`<Box<str> as AsRef<str>>::as_ref`] call
/// yielding a borrowed `&str` view of the boxed slice without a
/// redundant clone.
///
/// The parse-side mirror of [`From<BumpLevel> for Box<str>`] above — the
/// emit peer closes the shrunk-owned-frontier emit surface (single heap
/// allocation for exactly the label's length, no
/// [`String`]-realloc-plus-shrink round trip), this parse peer closes
/// the shrunk-owned-frontier parse surface (single [`FromStr`] read
/// through the boxed slice's borrowed view, no [`String`]-allocation
/// round trip). Together the two impls close both directions of the
/// shrunk-owned-frontier conversion at the version-bump-magnitude
/// ladder, giving a downstream site that types its label sink or source
/// as [`Box<str>`] (rather than one of the four owned/borrowed cross
/// products [`&str`] / [`String`] / [`Cow<'_, str>`] on the emit or
/// parse side) a first-class typed-primitive surface at both ends, not
/// a per-consumer `boxed.parse::<BumpLevel>()` restatement.
///
/// Structural mirror of
/// [`TryFrom<Box<str>> for PerAttemptRegion`](crate::retry::PerAttemptRegion)
/// (commit 3b8c512) at the per-attempt-region ladder and
/// [`TryFrom<Box<str>> for AdmissionTier`](crate::probe_outcome::AdmissionTier)
/// (commit 1a34d2a) at the admission-tier ladder — the same
/// `<Self as FromStr>::from_str` lift on the `<Box<str> as
/// AsRef<str>>::as_ref` borrowed view, through the same one-oracle
/// discipline, at the third ordered typed sum. This closes the third
/// arm of the parse-side [`Box<str>`] trio the prior two commits opened
/// at the per-attempt-region and admission-tier ladders; together with
/// the sibling [`From<BumpLevel> for Box<str>`] this closes both
/// directions of the shrunk-owned-frontier conversion at ALL THREE
/// canonical-label typed sums on the same ladder — the same closure
/// discipline already achieved at the `&str` / `String` / `Cow<'_, str>`
/// frontiers in prior runs.
///
/// Sibling of the [`std::fmt::Display`], [`std::str::FromStr`],
/// [`serde::Serialize`], [`serde::Deserialize`], [`AsRef<str>`],
/// [`From<BumpLevel> for &'static str`], [`TryFrom<&str>`],
/// [`From<BumpLevel> for String`], [`TryFrom<String>`],
/// [`From<BumpLevel> for Cow<'static, str>`], [`TryFrom<Cow<'_, str>>`],
/// and [`From<BumpLevel> for Box<str>`] impls above — the same lift at
/// the by-value [`Box<str>`] parse layer instead of the format / parse
/// / serde / borrow / static-lifetime / by-reference-try /
/// owned-string-emit / owned-string-try / borrowed-frontier-emit /
/// borrowed-frontier-try / shrunk-owned-frontier-emit layers.
///
/// The impl body picks [`<Box<str> as AsRef<str>>::as_ref`] rather than
/// [`Box::<str>::into_string`] or a per-branch consumption:
/// [`AsRef::as_ref`] yields a borrowed `&str` view of the boxed slice
/// without allocation, so the parse-side receiver pays the
/// by-reference `from_str` cost, not the [`String`]-allocation cost of
/// a `Box::<str>::into_string`-then-`from_str` composition — the same
/// discipline the sibling [`TryFrom<Cow<'_, str>>`] peer applies at the
/// [`Cow::as_ref`] boundary.
///
/// The identity
/// `BumpLevel::try_from(Box::<str>::from(level.as_str())).unwrap() ==
/// level` at every [`BumpLevel::ALL`] variant is pinned by
/// [`tests::test_bump_level_try_from_box_str_agrees_with_from_str`];
/// the identity carried through a generic
/// `impl TryFrom<Box<str>>` consumer at every variant is pinned by
/// [`tests::test_bump_level_try_from_box_str_carries_through_generic_consumer`];
/// the strict-rejection contract at non-canonical input is pinned by
/// [`tests::test_bump_level_try_from_box_str_rejects_non_canonical_input`].
///
/// THEORY.md §V.4 typed primitives: the by-value [`Box<str>`] parse
/// surface is a typed-primitive site on [`BumpLevel`] itself (one
/// `TryFrom<Box<str>>` impl routing through
/// [`<Self as std::str::FromStr>::from_str`] on
/// [`<Box<str> as AsRef<str>>::as_ref`]), not a per-consumer
/// `boxed.parse::<BumpLevel>()` restatement at every downstream site
/// that receives a [`Box<str>`] label.
/// THEORY.md §VI.1 one-oracle: the canonical grammar is named at one
/// site ([`<BumpLevel as std::str::FromStr>::from_str`]) and every
/// parse surface — [`FromStr`], [`serde::Deserialize`],
/// [`TryFrom<&str>`], [`TryFrom<String>`], [`TryFrom<Cow<'_, str>>`],
/// this [`TryFrom<Box<str>>`] — reads through it.
impl TryFrom<Box<str>> for BumpLevel {
    type Error = anyhow::Error;

    fn try_from(s: Box<str>) -> Result<Self, Self::Error> {
        <Self as std::str::FromStr>::from_str(s.as_ref())
    }
}

/// [`From<BumpLevel> for Arc<str>`] routes through [`BumpLevel::as_str`]
/// and hands the canonical lowercase label (`"patch"`, `"minor"`,
/// `"major"`) to [`std::sync::Arc::<str>::from`] so a downstream consumer
/// bound by `impl Into<Arc<str>>` (a cross-thread cached-label slot that
/// wants a single canonical allocation shared across worker threads via
/// atomic refcount, a validated-input newtype wrapper whose level field
/// is stored as [`Arc<str>`] to hand cheap clones to sibling structures
/// on other threads, a serde container that opts into
/// `#[serde(from = "Arc<str>")]` at the shared-owned frontier, a
/// dashmap-style keyed-table value slot whose readers want an [`Arc`]
/// clone rather than a per-lookup allocation) reads the canonical label
/// directly from a [`BumpLevel`] value at a single atomic-refcount heap
/// allocation — the shared-owned emit peer of
/// [`From<BumpLevel> for Box<str>`] (single allocation, immutable
/// heap-owned receiver at the shrunk-owned frontier, no refcount header)
/// that trades the two-machine-word [`Box<str>`] receiver footprint for
/// an [`Arc<str>`] receiver with an atomic-refcount slot preceding the
/// label bytes, enabling `O(1)` [`Arc::clone`] on the emit result across
/// threads without a per-clone allocation.
///
/// The by-value emit peer of [`From<BumpLevel> for &'static str`]
/// (zero-copy `'static` borrow of the label constant, no allocation),
/// [`From<BumpLevel> for String`] (single allocation, resizable
/// receiver), [`From<BumpLevel> for Cow<'static, str>`] (uniform emit at
/// the borrowed/owned frontier through [`Cow::Borrowed`], zero
/// allocation regardless of receiver typing),
/// [`From<BumpLevel> for Box<str>`] (single allocation, immutable
/// heap-owned receiver at the shrunk-owned frontier), and this
/// [`From<BumpLevel> for Arc<str>`] (single allocation with
/// atomic-refcount header, immutable heap-owned receiver at the
/// shared-owned frontier). All five route through the shared
/// [`BumpLevel::as_str`] canonical-label oracle: the [`&'static str`]
/// peer through [`as_str`] directly, the [`String`] peer through
/// [`str::to_owned`] on [`as_str`], the [`Cow<'static, str>`] peer
/// through [`Cow::Borrowed`] wrapping [`as_str`], the [`Box<str>`] peer
/// through [`Box::<str>::from`] on [`as_str`], this [`Arc<str>`] peer
/// through [`std::sync::Arc::<str>::from`] on [`as_str`] — the same
/// canonical grammar lifted to the shared-owned-frontier emit layer.
///
/// The impl body picks [`std::sync::Arc::<str>::from`] rather than
/// [`std::sync::Arc::from`] on a [`Box<str>`] intermediate or an
/// [`std::sync::Arc::from`] on a [`String`]: the direct
/// [`std::sync::Arc::<str>::from`] path allocates once from the
/// `'static` label slice, including the atomic-refcount header, so the
/// receiver pays a single allocation for exactly the label's length
/// plus the header — never the [`Box<str>`]-then-[`Arc::from`] round
/// trip (two allocations: box the slice, then rewrap into an
/// [`Arc<str>`]) nor the [`String`]-then-[`Arc::from`] round trip
/// (resizable allocation, then rewrap). The single-allocation contract
/// is pinned by
/// [`tests::test_bump_level_into_arc_str_agrees_with_as_str`] at the
/// label-oracle surface (value agreement across every variant) and by
/// [`tests::test_bump_level_into_arc_str_carries_through_generic_consumer`]
/// (identity carried through a tiny generic
/// `fn read<T: Into<Arc<str>>>(t: T) -> Arc<str>` consumer at every
/// variant — the structural witness that a [`BumpLevel`] is genuinely
/// usable at `impl Into<Arc<str>>` call sites, so a regression that
/// drifted the impl signature (a returned [`Box<str>`] instead of
/// [`Arc<str>`], a required `&BumpLevel` receiver losing the by-value
/// semantics) fails at compile time or at the assertion instead of at
/// every downstream generic call site). The
/// `Arc::clone`-preserves-value contract is pinned by
/// [`tests::test_bump_level_into_arc_str_shares_label_across_clones`]
/// at every variant — the structural witness that the shared-owned
/// receiver semantics hold: an [`Arc::clone`] of the emit result reads
/// the same canonical label bytes as the original, and the atomic
/// refcount lifts to at least two after the clone.
///
/// Structural mirror of
/// [`From<PerAttemptRegion> for Arc<str>`](crate::retry::PerAttemptRegion)
/// (commit c3a722d) at the per-attempt-region ladder and
/// [`From<AdmissionTier> for Arc<str>`](crate::probe_outcome::AdmissionTier)
/// (commit 6bab1ab) at the admission-tier ladder — the same
/// [`std::sync::Arc::<str>::from`] lift, through the same one-oracle
/// discipline, at the third ordered typed sum. Together with those two
/// impls this closes the shared-owned-frontier emit peer at ALL THREE
/// canonical-label typed primitives on the same ladder — the third arm
/// of the trio whose first two arms landed at c3a722d and 6bab1ab. The
/// closure discipline mirrors the same trio-closing rhythm already
/// achieved at the `&'static str` / `String` / `Cow<'static, str>` /
/// `Box<str>` emit frontiers in prior runs.
///
/// Sibling of the [`std::fmt::Display`], [`std::str::FromStr`],
/// [`serde::Serialize`], [`serde::Deserialize`], [`AsRef<str>`],
/// [`From<BumpLevel> for &'static str`], [`TryFrom<&str>`],
/// [`From<BumpLevel> for String`], [`TryFrom<String>`],
/// [`From<BumpLevel> for Cow<'static, str>`], [`TryFrom<Cow<'_, str>>`],
/// [`From<BumpLevel> for Box<str>`], and [`TryFrom<Box<str>>`] impls
/// above — the same lift at the by-value [`Arc<str>`] emit layer instead
/// of the format / parse / serde / borrow / static-lifetime /
/// by-reference-try / owned-string-emit / owned-string-try /
/// borrowed-frontier-emit / borrowed-frontier-try /
/// shrunk-owned-frontier-emit / shrunk-owned-frontier-try layers.
/// Closes the shared-owned-frontier arm of the emit peer set at the
/// version-bump-magnitude ladder against the shared
/// [`BumpLevel::as_str`] canonical-label oracle.
///
/// THEORY.md §V.4 typed primitives: the by-value [`Arc<str>`] emit
/// surface is a typed-primitive site on [`BumpLevel`] itself (one
/// `From<BumpLevel> for Arc<str>` impl routing through [`as_str`] at
/// the [`std::sync::Arc::<str>::from`] boundary), not a per-consumer
/// `Arc::<str>::from(level.as_str())` restatement at every downstream
/// site that receives an [`Into<Arc<str>>`] label sink.
/// THEORY.md §VI.1 one-oracle: the canonical label is named at one site
/// ([`BumpLevel::as_str`]) and every emit surface — [`as_str`],
/// [`Display`], [`serde::Serialize`], [`AsRef<str>`],
/// [`From<BumpLevel> for &'static str`],
/// [`From<BumpLevel> for String`],
/// [`From<BumpLevel> for Cow<'static, str>`],
/// [`From<BumpLevel> for Box<str>`], this
/// `From<BumpLevel> for Arc<str>` — reads through it.
impl From<BumpLevel> for std::sync::Arc<str> {
    fn from(level: BumpLevel) -> std::sync::Arc<str> {
        std::sync::Arc::<str>::from(level.as_str())
    }
}

/// [`TryFrom<Arc<str>> for BumpLevel`] routes through
/// [`<BumpLevel as std::str::FromStr>::from_str`] on the borrowed `&str`
/// view of the caller-supplied [`std::sync::Arc<str>`], so a downstream
/// consumer bound by `impl TryFrom<Arc<str>>` (a serde container that
/// opts into `#[serde(try_from = "Arc<str>")]` on a wrapper field to
/// consume a shared-owned label without a per-consumer allocation, a
/// validated-input newtype builder whose parse contract accepts a
/// caller-supplied [`Arc<str>`] label slot at the shared-owned frontier
/// for cross-thread cheap-clone semantics on the input, a dashmap-style
/// keyed-table consumer whose key slot arrives as a shared-owned label
/// from an upstream table build) recovers a [`BumpLevel`] value from its
/// canonical lowercase label (`"patch"`, `"minor"`, `"major"`) through
/// the same one-oracle grammar the direct `.parse::<BumpLevel>()` call
/// sites and the sibling [`TryFrom<&str>`] / [`TryFrom<String>`] /
/// [`TryFrom<Cow<'_, str>>`] / [`TryFrom<Box<str>>`] impls already read.
///
/// The by-value [`Arc<str>`] parse peer of the [`TryFrom<&str>`]
/// (borrowed-view input), [`TryFrom<String>`] (owned-string input with
/// [`String`] resize headroom), [`TryFrom<Cow<'_, str>>`]
/// (borrowed/owned-frontier input), and [`TryFrom<Box<str>>`]
/// (shrunk-owned-frontier input, no refcount header) impls above — all
/// five are parse surfaces of the label-axis conversion set, differing
/// only on the input string-owner shape: [`TryFrom<&str>`] takes a
/// borrowed `&str` view for consumers that already hold a borrow,
/// [`TryFrom<String>`] takes an owned resizable [`String`] for consumers
/// that own the input buffer with growth headroom, [`TryFrom<Cow<'_, str>>`]
/// takes either uniformly at the borrowed/owned-frontier receiver shape,
/// [`TryFrom<Box<str>>`] takes an immutable heap-owned [`Box<str>`] with
/// no refcount header, this [`TryFrom<Arc<str>>`] takes an immutable
/// shared-owned [`std::sync::Arc<str>`] with an atomic-refcount header
/// preceding the label bytes for consumers whose upstream produced a
/// shared-owned label already refcounted across worker threads (a
/// cross-thread cached-label slot handed cheaply via [`Arc::clone`], a
/// dashmap-style value slot, a validated-input newtype whose label field
/// is stored as [`Arc<str>`]). All five route through the shared
/// [`<Self as std::str::FromStr>::from_str`] canonical-grammar oracle:
/// the [`&str`] peer through `from_str` directly, the [`String`] peer
/// through `from_str(s.as_str())`, the [`Cow<'_, str>`] peer through
/// `from_str(s.as_ref())`, the [`Box<str>`] peer through
/// `from_str(s.as_ref())`, this [`Arc<str>`] peer through
/// `from_str(s.as_ref())` — the same canonical grammar lifted to the
/// shared-owned-frontier parse layer, with the receiver-side
/// [`<std::sync::Arc<str> as AsRef<str>>::as_ref`] call yielding a
/// borrowed `&str` view of the shared allocation without touching the
/// atomic refcount and without a redundant clone.
///
/// The parse-side mirror of [`From<BumpLevel> for Arc<str>`] above — the
/// emit peer closes the shared-owned-frontier emit surface (single
/// atomic-refcount allocation for exactly the label's length plus
/// refcount header, `O(1)` [`Arc::clone`] across worker threads without
/// a per-clone allocation), this parse peer closes the
/// shared-owned-frontier parse surface (single [`FromStr`] read through
/// the shared allocation's borrowed view, no [`String`]-allocation round
/// trip, no refcount touch during the parse). Together the two impls
/// close both directions of the shared-owned-frontier conversion at the
/// version-bump-magnitude ladder, giving a downstream site that types
/// its label sink or source as [`Arc<str>`] (rather than one of the five
/// owned/borrowed cross products [`&str`] / [`String`] / [`Cow<'_, str>`]
/// / [`Box<str>`] / [`Arc<str>`] on the emit or parse side) a first-class
/// typed-primitive surface at both ends, not a per-consumer
/// `shared.parse::<BumpLevel>()` restatement.
///
/// Structural mirror of
/// [`TryFrom<Arc<str>> for PerAttemptRegion`](crate::retry::PerAttemptRegion)
/// (commit a9c007a) at the per-attempt-region ladder and
/// [`TryFrom<Arc<str>> for AdmissionTier`](crate::probe_outcome::AdmissionTier)
/// (commit 64ec99e) at the admission-tier ladder — the same
/// `<Self as FromStr>::from_str` lift on the `<std::sync::Arc<str> as
/// AsRef<str>>::as_ref` borrowed view, through the same one-oracle
/// discipline, at the third ordered typed sum. This closes the third
/// arm of the parse-side [`Arc<str>`] trio the prior two commits opened
/// at the per-attempt-region and admission-tier ladders; together with
/// the sibling [`From<BumpLevel> for Arc<str>`] this closes both
/// directions of the shared-owned-frontier conversion at ALL THREE
/// canonical-label typed sums on the same ladder — the same closure
/// discipline already achieved at the `&str` / `String` / `Cow<'_, str>`
/// / `Box<str>` frontiers in prior runs.
///
/// Sibling of the [`std::fmt::Display`], [`std::str::FromStr`],
/// [`serde::Serialize`], [`serde::Deserialize`], [`AsRef<str>`],
/// [`From<BumpLevel> for &'static str`], [`TryFrom<&str>`],
/// [`From<BumpLevel> for String`], [`TryFrom<String>`],
/// [`From<BumpLevel> for Cow<'static, str>`], [`TryFrom<Cow<'_, str>>`],
/// [`From<BumpLevel> for Box<str>`], [`TryFrom<Box<str>>`], and
/// [`From<BumpLevel> for Arc<str>`] impls above — the same lift at the
/// by-value [`Arc<str>`] parse layer instead of the format / parse /
/// serde / borrow / static-lifetime / by-reference-try / owned-string-
/// emit / owned-string-try / borrowed-frontier-emit / borrowed-frontier-
/// try / shrunk-owned-frontier-emit / shrunk-owned-frontier-try /
/// shared-owned-frontier-emit layers.
///
/// The impl body picks [`<std::sync::Arc<str> as AsRef<str>>::as_ref`]
/// rather than an [`std::sync::Arc::try_unwrap`]-then-conversion cascade
/// or a per-branch consumption: [`AsRef::as_ref`] yields a borrowed
/// `&str` view of the shared allocation without allocation and without
/// touching the atomic refcount, so the parse-side receiver pays the
/// by-reference `from_str` cost only, not the [`String`]-allocation cost
/// of an [`Arc::try_unwrap`]-fallback-clone-then-`from_str` composition
/// nor the [`String`]-copy cost of an `Arc::to_string`-then-`from_str`
/// round trip — the same discipline the sibling [`TryFrom<Box<str>>`]
/// peer applies at the [`Box::as_ref`] boundary and the sibling
/// [`TryFrom<Cow<'_, str>>`] peer applies at the [`Cow::as_ref`] boundary.
///
/// The identity
/// `BumpLevel::try_from(std::sync::Arc::<str>::from(level.as_str())).unwrap()
/// == level` at every [`BumpLevel::ALL`] variant is pinned by
/// [`tests::test_bump_level_try_from_arc_str_agrees_with_from_str`];
/// the identity carried through a generic
/// `impl TryFrom<Arc<str>>` consumer at every variant is pinned by
/// [`tests::test_bump_level_try_from_arc_str_carries_through_generic_consumer`];
/// the strict-rejection contract at non-canonical input is pinned by
/// [`tests::test_bump_level_try_from_arc_str_rejects_non_canonical_input`].
///
/// THEORY.md §V.4 typed primitives: the by-value [`Arc<str>`] parse
/// surface is a typed-primitive site on [`BumpLevel`] itself (one
/// `TryFrom<Arc<str>>` impl routing through
/// [`<Self as std::str::FromStr>::from_str`] on
/// [`<std::sync::Arc<str> as AsRef<str>>::as_ref`]), not a per-consumer
/// `shared.parse::<BumpLevel>()` restatement at every downstream site
/// that receives an [`Arc<str>`] label.
/// THEORY.md §VI.1 one-oracle: the canonical grammar is named at one
/// site ([`<BumpLevel as std::str::FromStr>::from_str`]) and every parse
/// surface — [`FromStr`], [`serde::Deserialize`], [`TryFrom<&str>`],
/// [`TryFrom<String>`], [`TryFrom<Cow<'_, str>>`], [`TryFrom<Box<str>>`],
/// this [`TryFrom<Arc<str>>`] — reads through it.
impl TryFrom<std::sync::Arc<str>> for BumpLevel {
    type Error = anyhow::Error;

    fn try_from(s: std::sync::Arc<str>) -> Result<Self, Self::Error> {
        <Self as std::str::FromStr>::from_str(s.as_ref())
    }
}

/// [`From<BumpLevel> for Rc<str>`] routes through [`BumpLevel::as_str`]
/// and hands the canonical lowercase label (`"patch"`, `"minor"`,
/// `"major"`) to [`std::rc::Rc::<str>::from`] so a downstream consumer
/// bound by `impl Into<Rc<str>>` (a thread-local cached-label slot that
/// wants a single canonical allocation shared within one worker via
/// non-atomic refcount, a validated-input newtype wrapper whose label
/// field is stored as [`Rc<str>`] to hand cheap clones to sibling
/// structures on the same thread, a per-request-arena label slot that
/// never crosses a thread boundary, a graph-walk visitor that clones
/// labels across nodes without needing [`Send`] / [`Sync`]) reads the
/// canonical label directly from a [`BumpLevel`] value at a single
/// non-atomic-refcount heap allocation — the thread-local shared-owned
/// emit peer of [`From<BumpLevel> for Arc<str>`] (single allocation with
/// atomic-refcount header, immutable heap-owned receiver at the
/// shared-owned frontier, [`Send`] + [`Sync`]) that trades the atomic
/// refcount for the non-atomic [`std::rc::Rc`] refcount, enabling
/// `O(1)` [`Rc::clone`] within a single thread at a strictly lower
/// per-clone cost than the atomic [`Arc::clone`] — the correct choice
/// at every emit site where the consumer is known to never cross a
/// thread boundary.
///
/// The by-value emit peer of [`From<BumpLevel> for &'static str`]
/// (zero-copy `'static` borrow of the label constant, no allocation),
/// [`From<BumpLevel> for String`] (single allocation, resizable
/// receiver), [`From<BumpLevel> for Cow<'static, str>`] (uniform emit at
/// the borrowed/owned frontier through [`Cow::Borrowed`], zero
/// allocation regardless of receiver typing),
/// [`From<BumpLevel> for Box<str>`] (single allocation, immutable
/// heap-owned receiver at the shrunk-owned frontier, no refcount header),
/// [`From<BumpLevel> for Arc<str>`] (single allocation with atomic-
/// refcount header, immutable heap-owned receiver at the shared-owned
/// frontier, [`Send`] + [`Sync`]), and this [`From<BumpLevel> for Rc<str>`]
/// (single allocation with non-atomic-refcount header, immutable
/// heap-owned receiver at the thread-local shared-owned frontier,
/// `!Send` / `!Sync`). All six route through the shared
/// [`BumpLevel::as_str`] canonical-label oracle: the [`&'static str`]
/// peer through [`as_str`] directly, the [`String`] peer through
/// [`str::to_owned`] on [`as_str`], the [`Cow<'static, str>`] peer
/// through [`Cow::Borrowed`] wrapping [`as_str`], the [`Box<str>`] peer
/// through [`Box::<str>::from`] on [`as_str`], the [`Arc<str>`] peer
/// through [`std::sync::Arc::<str>::from`] on [`as_str`], this
/// [`Rc<str>`] peer through [`std::rc::Rc::<str>::from`] on [`as_str`] —
/// the same canonical grammar lifted to the thread-local shared-owned-
/// frontier emit layer.
///
/// The impl body picks [`std::rc::Rc::<str>::from`] rather than
/// [`std::rc::Rc::from`] on a [`Box<str>`] intermediate or an
/// [`std::rc::Rc::from`] on a [`String`]: the direct
/// [`std::rc::Rc::<str>::from`] path allocates once from the `'static`
/// label slice, including the non-atomic-refcount header, so the
/// receiver pays a single allocation for exactly the label's length
/// plus the header — never the [`Box<str>`]-then-[`Rc::from`] round
/// trip (two allocations: box the slice, then rewrap into an [`Rc<str>`])
/// nor the [`String`]-then-[`Rc::from`] round trip (resizable
/// allocation, then rewrap). The single-allocation contract is pinned
/// by [`tests::test_bump_level_into_rc_str_agrees_with_as_str`] at the
/// label-oracle surface (value agreement across every variant) and by
/// [`tests::test_bump_level_into_rc_str_carries_through_generic_consumer`]
/// (identity carried through a tiny generic
/// `fn read<T: Into<Rc<str>>>(t: T) -> Rc<str>` consumer at every
/// variant — the structural witness that a [`BumpLevel`] is genuinely
/// usable at `impl Into<Rc<str>>` call sites, so a regression that
/// drifted the impl signature (a returned [`Box<str>`] instead of
/// [`Rc<str>`], a required `&BumpLevel` receiver losing the by-value
/// semantics) fails at compile time or at the assertion instead of at
/// every downstream generic call site). The `Rc::clone`-preserves-value
/// contract is pinned by
/// [`tests::test_bump_level_into_rc_str_shares_label_across_clones`] at
/// every variant — the structural witness that the thread-local
/// shared-owned receiver semantics hold: an [`Rc::clone`] of the emit
/// result reads the same canonical label bytes as the original, points
/// at the same allocation ([`std::rc::Rc::ptr_eq`]), and the non-atomic
/// refcount lifts to at least two after the clone.
///
/// Structural mirror of
/// [`From<PerAttemptRegion> for Rc<str>`](crate::retry::PerAttemptRegion)
/// (commit 8950199) at the per-attempt-region ladder and
/// [`From<AdmissionTier> for Rc<str>`](crate::probe_outcome::AdmissionTier)
/// (commit 62c49a0) at the admission-tier ladder — the same
/// [`std::rc::Rc::<str>::from`] lift, through the same one-oracle
/// discipline, at the third ordered typed sum. This closes the
/// thread-local shared-owned emit peer at ALL THREE canonical-label
/// typed primitives on the same ladder, matching the closure discipline
/// already achieved at the `&str` / `String` / `Cow<'_, str>` /
/// `Box<str>` / `Arc<str>` frontiers in prior runs.
///
/// Sibling of the [`std::fmt::Display`], [`std::str::FromStr`],
/// [`serde::Serialize`], [`serde::Deserialize`], [`AsRef<str>`],
/// [`From<BumpLevel> for &'static str`], [`TryFrom<&str>`],
/// [`From<BumpLevel> for String`], [`TryFrom<String>`],
/// [`From<BumpLevel> for Cow<'static, str>`], [`TryFrom<Cow<'_, str>>`],
/// [`From<BumpLevel> for Box<str>`], [`TryFrom<Box<str>>`],
/// [`From<BumpLevel> for Arc<str>`], and [`TryFrom<Arc<str>>`] impls
/// above — the same lift at the by-value [`Rc<str>`] emit layer instead
/// of the format / parse / serde / borrow / static-lifetime /
/// by-reference-try / owned-string-emit / owned-string-try / borrowed-
/// frontier-emit / borrowed-frontier-try / shrunk-owned-frontier-emit /
/// shrunk-owned-frontier-try / atomic-shared-owned-frontier-emit /
/// atomic-shared-owned-frontier-try layers. Opens the emit-side arm of
/// the thread-local shared-owned-frontier peer set at the version-bump
/// ladder against the shared [`BumpLevel::as_str`] canonical-label
/// oracle — the [`Rc<str>`] parse peer ([`TryFrom<Rc<str>>`]) closes the
/// trio in a follow-up commit, sibling of the closed [`Arc<str>`] emit +
/// parse trio directly above.
///
/// THEORY.md §V.4 typed primitives: the by-value [`Rc<str>`] emit
/// surface is a typed-primitive site on [`BumpLevel`] itself (one
/// `From<BumpLevel> for Rc<str>` impl routing through [`as_str`] at the
/// [`std::rc::Rc::<str>::from`] boundary), not a per-consumer
/// `Rc::<str>::from(level.as_str())` restatement at every downstream
/// site that receives an [`Into<Rc<str>>`] label sink.
/// THEORY.md §VI.1 one-oracle: the canonical label is named at one site
/// ([`BumpLevel::as_str`]) and every emit surface — [`as_str`],
/// [`Display`], [`serde::Serialize`], [`AsRef<str>`],
/// [`From<BumpLevel> for &'static str`],
/// [`From<BumpLevel> for String`],
/// [`From<BumpLevel> for Cow<'static, str>`],
/// [`From<BumpLevel> for Box<str>`],
/// [`From<BumpLevel> for Arc<str>`], this
/// `From<BumpLevel> for Rc<str>` — reads through it.
impl From<BumpLevel> for std::rc::Rc<str> {
    fn from(level: BumpLevel) -> std::rc::Rc<str> {
        std::rc::Rc::<str>::from(level.as_str())
    }
}

/// [`TryFrom<Rc<str>> for BumpLevel`] routes the by-value thread-local
/// shared-owned canonical label through
/// [`<Self as std::str::FromStr>::from_str`] on
/// [`<std::rc::Rc<str> as AsRef<str>>::as_ref`] so a downstream consumer
/// bound by `impl TryFrom<Rc<str>>` (a serde container that opts into
/// `#[serde(try_from = "Rc<str>")]` on a wrapper field to consume a
/// thread-local shared-owned canonical label without a per-consumer
/// allocation, a validated-input newtype builder whose parse contract
/// accepts a caller-supplied [`Rc<str>`] label slot at the thread-local
/// shared-owned frontier for cheap same-thread [`Rc::clone`] semantics on
/// the input, a single-threaded arena-keyed table consumer whose key slot
/// arrives as an [`Rc<str>`] label from an upstream table build that
/// never crosses a thread boundary) reads the canonical variant directly
/// from a caller-supplied [`Rc<str>`] with a single receiver-side
/// [`<std::rc::Rc<str> as AsRef<str>>::as_ref`] call yielding a borrowed
/// `&str` view of the shared allocation without allocation and without
/// touching the non-atomic refcount, so the parse-side receiver pays the
/// by-reference `from_str` cost only, not the [`String`]-allocation cost
/// of an [`Rc::try_unwrap`]-fallback-clone-then-`from_str` composition
/// nor the [`String`]-copy cost of an `Rc::to_string`-then-`from_str`
/// round trip — the same discipline the sibling [`TryFrom<Arc<str>>`]
/// peer applies at the [`Arc::as_ref`] boundary, the sibling
/// [`TryFrom<Box<str>>`] peer applies at the [`Box::as_ref`] boundary,
/// and the sibling [`TryFrom<Cow<'_, str>>`] peer applies at the
/// [`Cow::as_ref`] boundary.
///
/// The parse-side mirror of [`From<BumpLevel> for Rc<str>`] directly
/// above — the emit peer closes the thread-local shared-owned-frontier
/// emit surface (single non-atomic-refcount allocation for exactly the
/// label's length plus refcount header, `O(1)` [`Rc::clone`] within a
/// single thread at strictly lower per-clone cost than atomic
/// [`Arc::clone`]), this parse peer closes the thread-local shared-owned-
/// frontier parse surface (single [`FromStr`] read through the shared
/// allocation's borrowed view, no [`String`]-allocation round trip, no
/// refcount touch during the parse). Together the two impls close both
/// directions of the thread-local shared-owned-frontier conversion at
/// the version-bump ladder, giving a downstream site that types its
/// label sink or source as [`Rc<str>`] (rather than one of the five
/// owned/borrowed cross products [`&str`] / [`String`] / [`Cow<'_, str>`]
/// / [`Box<str>`] / [`Arc<str>`] on the emit or parse side) a first-class
/// typed-primitive surface at both ends, not a per-consumer
/// `shared.parse::<BumpLevel>()` restatement.
///
/// Structural mirror of
/// [`TryFrom<Rc<str>> for PerAttemptRegion`](crate::retry::PerAttemptRegion)
/// (commit 0e9bc9f) at the per-attempt-region ladder and
/// [`TryFrom<Rc<str>> for AdmissionTier`](crate::probe_outcome::AdmissionTier)
/// (commit 9545b4d) at the admission-tier ladder — the same
/// [`<Self as std::str::FromStr>::from_str`] route on the same
/// [`<std::rc::Rc<str> as AsRef<str>>::as_ref`] borrow, through the same
/// one-oracle discipline, at the third and final ordered typed sum. This
/// closes the parse-side arm of the thread-local shared-owned-frontier
/// peer set at ALL THREE canonical-label typed primitives on the same
/// ladder — the closure discipline already achieved at the `&str` /
/// `String` / `Cow<'_, str>` / `Box<str>` / `Arc<str>` frontiers in prior
/// runs, now extended to the `Rc<str>` frontier. Sibling of
/// [`TryFrom<Arc<str>> for BumpLevel`] at the atomic-shared-owned-
/// frontier one string-owner shape above — same route, same oracle,
/// same by-value receiver shape; only the refcount discipline (non-atomic
/// vs atomic) differs.
///
/// Sibling of the [`std::fmt::Display`], [`std::str::FromStr`],
/// [`serde::Serialize`], [`serde::Deserialize`], [`AsRef<str>`],
/// [`From<BumpLevel> for &'static str`], [`TryFrom<&str>`],
/// [`From<BumpLevel> for String`], [`TryFrom<String>`],
/// [`From<BumpLevel> for Cow<'static, str>`],
/// [`TryFrom<Cow<'_, str>>`], [`From<BumpLevel> for Box<str>`],
/// [`TryFrom<Box<str>>`], [`From<BumpLevel> for Arc<str>`],
/// [`TryFrom<Arc<str>>`], and [`From<BumpLevel> for Rc<str>`] impls
/// above — the same lift at the by-value [`Rc<str>`] parse layer instead
/// of the format / parse / serde / borrow / static-lifetime /
/// by-reference-try / owned-string-emit / owned-string-try /
/// borrowed-frontier-emit / borrowed-frontier-try /
/// shrunk-owned-frontier-emit / shrunk-owned-frontier-try /
/// atomic-shared-owned-frontier-emit / atomic-shared-owned-frontier-try /
/// thread-local-shared-owned-frontier-emit layers.
///
/// The identity
/// `BumpLevel::try_from(std::rc::Rc::<str>::from(level.as_str())).unwrap()
/// == level` at every [`BumpLevel::ALL`] variant is pinned by
/// [`tests::test_bump_level_try_from_rc_str_agrees_with_from_str`]; the
/// identity carried through a generic `impl TryFrom<Rc<str>>` consumer
/// at every variant is pinned by
/// [`tests::test_bump_level_try_from_rc_str_carries_through_generic_consumer`];
/// the strict-rejection contract at non-canonical input is pinned by
/// [`tests::test_bump_level_try_from_rc_str_rejects_non_canonical_input`].
///
/// THEORY.md §V.4 typed primitives: the by-value [`Rc<str>`] parse
/// surface is a typed-primitive site on [`BumpLevel`] itself (one
/// `TryFrom<Rc<str>>` impl routing through
/// [`<Self as std::str::FromStr>::from_str`] on
/// [`<std::rc::Rc<str> as AsRef<str>>::as_ref`]), not a per-consumer
/// `shared.parse::<BumpLevel>()` restatement at every downstream site
/// that receives an [`Rc<str>`] label.
/// THEORY.md §VI.1 one-oracle: the canonical grammar is named at one
/// site ([`<BumpLevel as std::str::FromStr>::from_str`]) and every parse
/// surface — [`FromStr`], [`serde::Deserialize`], [`TryFrom<&str>`],
/// [`TryFrom<String>`], [`TryFrom<Cow<'_, str>>`], [`TryFrom<Box<str>>`],
/// [`TryFrom<Arc<str>>`], this [`TryFrom<Rc<str>>`] — reads through it.
impl TryFrom<std::rc::Rc<str>> for BumpLevel {
    type Error = anyhow::Error;

    fn try_from(s: std::rc::Rc<str>) -> Result<Self, Self::Error> {
        <Self as std::str::FromStr>::from_str(s.as_ref())
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

    /// At every `(level_a, level_b)` pair over [`BumpLevel::ALL`] × [`BumpLevel::ALL`]
    /// (the 3×3 grid, 9 pairs), the [`BumpLevel`] total order is reflected
    /// in the bump-output total order: `level_a.cmp(&level_b)` equals
    /// `parse_semver(bump_semver_typed(v, level_a)).cmp(
    /// &parse_semver(bump_semver_typed(v, level_b)))` in semver lex order
    /// (the natural [`Ord`] on `(u64, u64, u64)`) at every well-formed input
    /// version `v`. The structural anchor that the [`BumpLevel`] ladder
    /// `Patch < Minor < Major` is an ORDER ISOMORPHISM onto the bump-output
    /// ladder, not merely a typed sum carrying a derived order: bumping by
    /// a strictly higher level yields a strictly higher output (strict
    /// monotonicity at `level_a < level_b`), bumping by an equal level
    /// yields an equal output (reflexivity at `level_a == level_b`), and
    /// the inverse pair holds at the dual end (`level_a > level_b` ⇒
    /// `out_a > out_b`).
    ///
    /// The pin sits next to the totality pin
    /// ([`test_bump_semver_typed_total_over_bump_level_domain`]) at the
    /// [`bump_semver_typed`] surface: totality says every level yields an
    /// `Ok` output; this isomorphism pin says the level→output map respects
    /// the ladder structure on both ends. Together they pin the structural
    /// signature `bump_semver_typed : (version, BumpLevel) → semver-triple`
    /// as a total order-isomorphism on the level axis at every well-formed
    /// version input — the load-bearing fact a downstream release-pipeline
    /// gate reading `level >= BumpLevel::Major` depends on for "produces a
    /// major-version output", and the dual fact a `level <= BumpLevel::Patch`
    /// reading depends on for "produces a patch-only output". The named
    /// typed-method peer [`BumpLevel::is_breaking`] (`>= Major`) and its De
    /// Morgan complement [`BumpLevel::is_non_breaking`] (`< Major`) ride
    /// this same isomorphism: a release-notes gate that reads
    /// `level.is_breaking()` to decide whether to surface the major-bump
    /// upgrade-guide section trusts that the rendered `bump_semver_typed`
    /// output also reflects that `>= Major` reading on the semver-triple
    /// axis. Across the present three-variant ladder the strict cases
    /// resolve to:
    ///
    /// - `Patch < Minor` ⇒ `(M, m, p+1) < (M, m+1, 0)` (the patch lex
    ///   advances the lowest component; the minor lex advances the middle
    ///   and zeroes the lowest — middle-advance dominates by lex
    ///   precedence);
    /// - `Minor < Major` ⇒ `(M, m+1, 0) < (M+1, 0, 0)` (the major lex
    ///   advances the highest component and zeroes the lower two —
    ///   highest-advance dominates by lex precedence);
    /// - `Patch < Major` ⇒ `(M, m, p+1) < (M+1, 0, 0)` (composition by
    ///   transitivity).
    ///
    /// Versions exercised: `"1.2.3"` (interior input with non-zero
    /// components on every axis — the standard release-cadence input,
    /// where every bump-output triple is distinguishable on every
    /// component), `"0.0.0"` (boundary input at the floor — the zeroed-
    /// component case the typed-bump primitive must distinguish without
    /// underflow or off-by-one), and `"9.9.9"` (saturation input with
    /// high-decade components — the case the bump arithmetic must
    /// distinguish without confusion between `9.9.10` and `9.10.0` lex
    /// order on the patch axis). The full 3-version × 9-pair = 27-case
    /// sweep exhausts the present level-axis combinatorics across three
    /// structurally-distinct input shapes; a future ladder refinement
    /// that broke the order isomorphism (e.g., a hypothetical
    /// `Prerelease` variant inserted strictly below `Patch` whose
    /// bump-output overlapped the `Patch` semver-triple) would light up
    /// here at exactly the offending pair.
    ///
    /// THEORY.md §III.3 lattice algebra: the level axis carries a
    /// chain-derived bounded distributive lattice (pinned by
    /// `test_bump_level_meet_distributes_over_join_at_every_triple` and
    /// `test_bump_level_join_distributes_over_meet_at_every_triple`), and
    /// the bump-output axis carries a sublattice of the semver-triple
    /// total order via the order-preserving embedding pinned here — the
    /// structural witness that the [`BumpLevel`] lattice operations
    /// (`meet` / `join`) propagate downstream onto the rendered version
    /// string without retyping the order discipline at every consumer.
    /// THEORY.md §V.1 construction guarantees: the property test sweeps
    /// the full 27-case cross product so the order-isomorphism axiom is
    /// proven by construction at every reachable (version, level_a,
    /// level_b) triple at the typed-primitive site, not approximated by
    /// spot checks.
    #[test]
    fn test_bump_semver_typed_reflects_bump_level_order_across_cross_product() {
        let versions = ["1.2.3", "0.0.0", "9.9.9"];
        for version in versions {
            for level_a in BumpLevel::ALL {
                for level_b in BumpLevel::ALL {
                    let out_a = parse_semver(
                        &bump_semver_typed(version, level_a).expect("typed bump must succeed"),
                    )
                    .expect("typed bump must produce a parseable semver triple");
                    let out_b = parse_semver(
                        &bump_semver_typed(version, level_b).expect("typed bump must succeed"),
                    )
                    .expect("typed bump must produce a parseable semver triple");
                    assert_eq!(
                        level_a.cmp(&level_b),
                        out_a.cmp(&out_b),
                        "BumpLevel total order must be reflected in bump-output \
                         total order at version {version:?}: \
                         level_a={level_a:?}, level_b={level_b:?}, \
                         out_a={out_a:?}, out_b={out_b:?}",
                    );
                }
            }
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

    /// [`BumpLevel::BOTTOM`] is exactly [`BumpLevel::Patch`] at the
    /// present three-variant ladder. The structural exact-shape pin
    /// that names the bounded-lattice floor at the typed-primitive
    /// surface: a future variant insertion strictly below `Patch`
    /// (e.g., a `Prerelease` release-candidate variant) forces the
    /// author to update this one pin alongside the const body so that
    /// every consumer reading "the magnitude-ladder floor" picks up
    /// the new bottom automatically. Floor-sibling of
    /// [`test_bump_level_top_named_at_lattice_ceiling`] at the
    /// bounded-lattice anchor surface.
    #[test]
    fn test_bump_level_bottom_named_at_lattice_floor() {
        assert_eq!(
            BumpLevel::BOTTOM,
            BumpLevel::Patch,
            "BOTTOM must read as Patch at the present three-variant magnitude ladder",
        );
    }

    /// [`BumpLevel::TOP`] is exactly [`BumpLevel::Major`] at the
    /// present three-variant ladder. The dual of
    /// [`test_bump_level_bottom_named_at_lattice_floor`] at the
    /// bounded-lattice ceiling — a future variant insertion strictly
    /// above `Major` (e.g., an `Epoch` semver4-style variant) forces
    /// the author to update this one pin so every consumer reading
    /// "the magnitude-ladder ceiling" picks up the new top.
    #[test]
    fn test_bump_level_top_named_at_lattice_ceiling() {
        assert_eq!(
            BumpLevel::TOP,
            BumpLevel::Major,
            "TOP must read as Major at the present three-variant magnitude ladder",
        );
    }

    /// [`BumpLevel::BOTTOM`] coincides with the first element of
    /// [`BumpLevel::ALL`] — the structural routing pin that ties the
    /// bounded-lattice floor to the canonical ladder-order
    /// enumeration. The pin that holds against a refactor that
    /// silently desynced the bounded-lattice anchor from the
    /// canonical-ladder-order surface (e.g., a future variant
    /// insertion that updated [`ALL`](BumpLevel::ALL) but forgot to
    /// shift [`BOTTOM`](BumpLevel::BOTTOM) accordingly, leaving the
    /// bounded-lattice surface stale relative to the enumeration
    /// surface). Together with
    /// [`test_bump_level_all_is_canonical_ladder_order`] (the
    /// pre-existing pin that ties `ALL`'s order to the derived [`Ord`]
    /// chain), this seals the two-step routing
    /// `BOTTOM == ALL[0] == min(every-variant)` at the typed-primitive
    /// site.
    #[test]
    fn test_bump_level_bottom_equals_ladder_floor() {
        let first = *BumpLevel::ALL.first().expect("ALL must be non-empty");
        assert_eq!(
            BumpLevel::BOTTOM,
            first,
            "BOTTOM must equal ALL.first() — the canonical ladder floor",
        );
    }

    /// [`BumpLevel::TOP`] coincides with the last element of
    /// [`BumpLevel::ALL`] — the dual of
    /// [`test_bump_level_bottom_equals_ladder_floor`] at the
    /// bounded-lattice ceiling, sealing the
    /// `TOP == ALL[ALL.len() - 1] == max(every-variant)` routing at
    /// the typed-primitive site.
    #[test]
    fn test_bump_level_top_equals_ladder_ceiling() {
        let last = *BumpLevel::ALL.last().expect("ALL must be non-empty");
        assert_eq!(
            BumpLevel::TOP,
            last,
            "TOP must equal ALL.last() — the canonical ladder ceiling",
        );
    }

    /// Bounded-lattice lower-bound law: [`BumpLevel::BOTTOM`] sits
    /// at-or-below every variant under the derived [`Ord`] chain. The
    /// structural anchor of "BOTTOM is the global lower bound" at
    /// the typed-primitive surface — pinned at every variant rather
    /// than only at the present floor, so a future variant insertion
    /// either side of the ladder forces the property to hold against
    /// the new variant before the test passes. Floor pin of
    /// [`test_bump_level_top_ge_every_variant`].
    #[test]
    fn test_bump_level_bottom_le_every_variant() {
        for level in BumpLevel::ALL {
            assert!(
                BumpLevel::BOTTOM <= level,
                "BOTTOM must be <= every variant — failed at {level:?}",
            );
        }
    }

    /// Bounded-lattice upper-bound law: [`BumpLevel::TOP`] sits
    /// at-or-above every variant under the derived [`Ord`] chain. The
    /// dual of [`test_bump_level_bottom_le_every_variant`] — together
    /// the two pins seal the closed magnitude-ladder interval
    /// `[BOTTOM, TOP]` as the global containment range every variant
    /// sits inside.
    #[test]
    fn test_bump_level_top_ge_every_variant() {
        for level in BumpLevel::ALL {
            assert!(
                BumpLevel::TOP >= level,
                "TOP must be >= every variant — failed at {level:?}",
            );
        }
    }

    /// Bounded-lattice non-degeneracy pin: `BOTTOM <= TOP` at the
    /// magnitude ladder. The structural witness that the bounded-
    /// lattice interval is non-empty — a refactor that collapsed the
    /// two anchors to the same variant (or inverted them) would light
    /// up here. At the present three-variant ladder the inequality is
    /// strict (`Patch < Major`); a degenerate one-variant ladder
    /// would coincide and still pass under `<=` — the pin holds the
    /// containment direction, not the cardinality.
    #[test]
    fn test_bump_level_bottom_le_top_at_lattice() {
        assert!(
            BumpLevel::BOTTOM <= BumpLevel::TOP,
            "BOTTOM must be <= TOP — the bounded-lattice interval must not invert",
        );
    }

    /// Bounded-lattice join-identity law: `BOTTOM.join(a) ==
    /// a.join(BOTTOM) == a` at every variant. The load-bearing
    /// structural fact a downstream join-fold seeded at the lattice
    /// bottom relies on — `levels.fold(BumpLevel::BOTTOM, |acc, l|
    /// acc.join(l))` returns the join of `levels`, or `BOTTOM` on an
    /// empty sequence. Pins the bounded-lattice anchor against the
    /// join surface, where the pre-existing
    /// [`test_bump_level_join_has_patch_as_identity`] pinned the same
    /// fact against the variant name. Same property — the bounded-
    /// lattice surface adds the named-anchor route so a consumer
    /// reading "seed the join-fold at the lattice floor" reads through
    /// one named oracle rather than the variant name.
    #[test]
    fn test_bump_level_bottom_is_join_identity_at_every_variant() {
        for level in BumpLevel::ALL {
            assert_eq!(
                BumpLevel::BOTTOM.join(level),
                level,
                "BOTTOM must be left-identity for join at {level:?}",
            );
            assert_eq!(
                level.join(BumpLevel::BOTTOM),
                level,
                "BOTTOM must be right-identity for join at {level:?}",
            );
        }
    }

    /// Bounded-lattice meet-identity law: `TOP.meet(a) == a.meet(TOP)
    /// == a` at every variant. Dual of
    /// [`test_bump_level_bottom_is_join_identity_at_every_variant`] —
    /// a downstream meet-fold seeded at the lattice top relies on the
    /// fact that `levels.fold(BumpLevel::TOP, |acc, l| acc.meet(l))`
    /// returns the meet of `levels`, or `TOP` on an empty sequence.
    /// Bounded-lattice anchor route over the same property pre-pinned
    /// at the variant-name surface by
    /// [`test_bump_level_meet_has_major_as_identity`].
    #[test]
    fn test_bump_level_top_is_meet_identity_at_every_variant() {
        for level in BumpLevel::ALL {
            assert_eq!(
                BumpLevel::TOP.meet(level),
                level,
                "TOP must be left-identity for meet at {level:?}",
            );
            assert_eq!(
                level.meet(BumpLevel::TOP),
                level,
                "TOP must be right-identity for meet at {level:?}",
            );
        }
    }

    /// Bounded-lattice meet-absorbing law: `BOTTOM.meet(a) ==
    /// a.meet(BOTTOM) == BOTTOM` at every variant. The load-bearing
    /// structural fact a downstream per-commit-floor meet-fold can
    /// early-exit on — once any per-commit magnitude reads BOTTOM, the
    /// per-commit-floor collapses to BOTTOM regardless of the
    /// remaining commits. Bounded-lattice anchor route over the same
    /// property pre-pinned at the variant-name surface by
    /// [`test_bump_level_meet_has_patch_as_absorbing_element`].
    #[test]
    fn test_bump_level_bottom_is_meet_absorbing_at_every_variant() {
        for level in BumpLevel::ALL {
            assert_eq!(
                BumpLevel::BOTTOM.meet(level),
                BumpLevel::BOTTOM,
                "BOTTOM must be left-absorbing for meet at {level:?}",
            );
            assert_eq!(
                level.meet(BumpLevel::BOTTOM),
                BumpLevel::BOTTOM,
                "BOTTOM must be right-absorbing for meet at {level:?}",
            );
        }
    }

    /// Bounded-lattice join-absorbing law: `TOP.join(a) == a.join(TOP)
    /// == TOP` at every variant. Dual of
    /// [`test_bump_level_bottom_is_meet_absorbing_at_every_variant`]
    /// — a downstream release-aggregation join-fold can early-exit on
    /// the fact that once any per-commit magnitude reads TOP, the
    /// release-aggregation join collapses to TOP regardless of the
    /// remaining commits. Bounded-lattice anchor route over the same
    /// property pre-pinned at the variant-name surface by
    /// [`test_bump_level_join_has_major_as_absorbing_element`].
    #[test]
    fn test_bump_level_top_is_join_absorbing_at_every_variant() {
        for level in BumpLevel::ALL {
            assert_eq!(
                BumpLevel::TOP.join(level),
                BumpLevel::TOP,
                "TOP must be left-absorbing for join at {level:?}",
            );
            assert_eq!(
                level.join(BumpLevel::TOP),
                BumpLevel::TOP,
                "TOP must be right-absorbing for join at {level:?}",
            );
        }
    }

    /// At every [`BumpLevel`] variant enumerated by [`BumpLevel::ALL`],
    /// the round-trip `level -> Serialize -> Deserialize` through JSON
    /// is the identity —
    /// `serde_json::from_str(&serde_json::to_string(&level).unwrap()).unwrap()
    /// == level`. The load-bearing structural pin that ties the
    /// canonical-label oracle ([`BumpLevel::as_str`]) to its serde-
    /// round-trip inverse via the `Serialize` impl that routes through
    /// [`as_str`] and the `Deserialize` impl that routes through
    /// [`std::str::FromStr`]: a regression that drifted either side (a
    /// `Serialize` change bypassing [`as_str`], a `Deserialize` change
    /// bypassing [`std::str::FromStr`], or a variant insertion without
    /// matching arms in both) desynchronises this pin at one site
    /// instead of leaking to every downstream release-manifest YAML /
    /// SLSA-provenance JSON / changelog TOML consumer that reads a
    /// rehydrated [`BumpLevel`] back from its serialised form. Sibling
    /// of [`test_bump_level_display_round_trips_through_from_str`] at
    /// the string-scalar round-trip surface, and structural mirror of
    /// `test_admission_tier_serde_round_trips_through_json_at_every_variant`
    /// at the admission-tier ladder — the three pins together close
    /// the label-axis identity across both the `Display`/`FromStr` and
    /// `Serialize`/`Deserialize` surfaces on all three ordered typed
    /// sums.
    #[test]
    fn test_bump_level_serde_round_trips_through_json_at_every_variant() {
        for level in BumpLevel::ALL {
            let json = serde_json::to_string(&level).unwrap();
            let round: BumpLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(
                round, level,
                "serde JSON round-trip must be identity at {level:?} (json={json:?})",
            );
        }
    }

    /// At every [`BumpLevel::ALL`] variant, the emitted JSON scalar is
    /// exactly the canonical lowercase string [`BumpLevel::as_str`]
    /// emits, quoted as a JSON string (`"patch"` / `"minor"` /
    /// `"major"`), not the UpperCamel variant identifier a
    /// `#[derive(Serialize)]` would emit (`"Patch"`, `"Minor"`,
    /// `"Major"`). The structural pin that the `Serialize` impl routes
    /// through [`as_str`] rather than the derived variant name — a
    /// regression that dropped the routing (e.g., a future
    /// `#[derive(Serialize)]` covering [`BumpLevel`] that shadowed the
    /// hand-rolled impl) lights up here at the exact variant whose
    /// serialised form drifted from the canonical label.
    #[test]
    fn test_bump_level_serialize_emits_canonical_label_at_every_variant() {
        for level in BumpLevel::ALL {
            let json = serde_json::to_string(&level).unwrap();
            let expected = format!("\"{}\"", level.as_str());
            assert_eq!(
                json, expected,
                "serde JSON emit must be as_str-quoted at {level:?}",
            );
        }
    }

    /// The [`serde::Deserialize`] parser is strict: only the canonical
    /// lowercase labels [`BumpLevel::as_str`] emits (`"patch"` /
    /// `"minor"` / `"major"`) parse. Empty input, UpperCamel rendering
    /// (as the derived [`Debug`] impl would emit — `"Patch"`,
    /// `"Minor"`, `"Major"`), whitespace padding, uppercase
    /// (`"MAJOR"`), and abbreviations (`"maj"`, `"p"`) all reject. The
    /// structural pin that the `Deserialize` impl inverts through
    /// [`std::str::FromStr`] rather than a lenient alias matrix — the
    /// same strict-parse discipline
    /// [`test_admission_tier_deserialize_rejects_unknown_string`]
    /// pins at the admission-tier ladder, here mirrored at the
    /// version-bump-magnitude ladder.
    #[test]
    fn test_bump_level_deserialize_rejects_unknown_string() {
        for bad in [
            "\"\"",
            "\"Patch\"",
            "\"Minor\"",
            "\"Major\"",
            "\"MAJOR\"",
            "\"  patch \"",
            "\"maj\"",
            "\"p\"",
            "\"prerelease\"",
        ] {
            assert!(
                serde_json::from_str::<BumpLevel>(bad).is_err(),
                "Deserialize must reject non-canonical string {bad}",
            );
        }
    }

    /// Non-string JSON scalars (numbers, booleans, nulls, objects,
    /// arrays) reject at the [`serde::Deserialize`] visitor layer,
    /// mirroring the strict-parse discipline the string surface
    /// enforces at
    /// [`test_bump_level_deserialize_rejects_unknown_string`]. A
    /// downstream consumer that wants numeric-tag or boolean-flag
    /// support normalises the input before routing it through this
    /// canonical parser.
    #[test]
    fn test_bump_level_deserialize_rejects_non_string_scalar() {
        for bad in ["0", "1", "true", "false", "null", "{}", "[]"] {
            assert!(
                serde_json::from_str::<BumpLevel>(bad).is_err(),
                "Deserialize must reject non-string scalar {bad}",
            );
        }
    }

    /// At every [`BumpLevel`] variant enumerated by
    /// [`BumpLevel::ALL`], `level.as_ref()` (the [`AsRef<str>`] impl
    /// body) equals `level.as_str()` (the canonical-label oracle)
    /// exactly. The load-bearing structural pin that ties the
    /// byte-slice-coercion surface to the shared
    /// [`BumpLevel::as_str`] oracle: a regression that swapped
    /// [`AsRef<str>`] to route through the [`std::fmt::Display`]
    /// formatter buffer (paying a [`String`] allocation), or drifted
    /// the [`AsRef<str>`] grammar from [`BumpLevel::as_str`]'s
    /// lowercase labels, fails here at ONE named site instead of
    /// leaking to every downstream consumer that accepts
    /// `impl AsRef<str>` (path-segment builder assembling a release-
    /// manifest key, version-tag env-var setter,
    /// [`std::collections::HashMap<&str, _>`] key lookup, generic
    /// log-fields sink, OpenTelemetry / tracing attribute setter).
    /// Sibling of [`test_bump_level_display_round_trips_through_from_str`]
    /// at the format-machinery surface, and structural mirror of
    /// `test_admission_tier_as_ref_str_agrees_with_as_str` (commit
    /// 7acca19) at the admission-tier ladder and
    /// `test_per_attempt_region_as_ref_str_agrees_with_as_str`
    /// (commit 8c8cffe) at the per-attempt-region ladder — the three
    /// agreement pins together close the read-side agreement across
    /// both the format-buffer surface ([`std::fmt::Display`]) and the
    /// byte-slice surface ([`AsRef<str>`]) against the shared
    /// canonical-label oracle at every ordered typed sum.
    #[test]
    fn test_bump_level_as_ref_str_agrees_with_as_str() {
        for level in BumpLevel::ALL {
            let borrowed: &str = level.as_ref();
            assert_eq!(
                borrowed,
                level.as_str(),
                "AsRef<str> and as_str must agree at {level:?}",
            );
        }
    }

    /// The [`AsRef<str>`] identity carries through a generic
    /// `impl AsRef<str>` consumer at every [`BumpLevel::ALL`] variant.
    /// A tiny generic function `fn read<T: AsRef<str>>(t: &T) -> &str
    /// { t.as_ref() }` — the shape of an actual downstream consumer
    /// (release-manifest path-segment builder, version-tag env-var
    /// setter, [`std::collections::HashMap`] key lookup, tracing
    /// attribute setter) — reads the canonical lowercase label
    /// directly from a [`BumpLevel`] value without going through the
    /// [`std::fmt::Display`] formatter buffer or an intermediate
    /// [`String`] allocation. The structural witness that a
    /// [`BumpLevel`] is genuinely usable at `impl AsRef<str>` call
    /// sites — a regression that drifted the [`AsRef<str>`] impl
    /// signature (e.g., returning an owned [`String`] instead of a
    /// `&str`, or requiring a `&mut self`) fails here at compile time
    /// instead of at every downstream generic call site. Structural
    /// mirror of
    /// `test_admission_tier_as_ref_str_carries_through_generic_consumer`
    /// (commit 7acca19) at the admission-tier ladder and
    /// `test_per_attempt_region_as_ref_str_carries_through_generic_consumer`
    /// (commit 8c8cffe) at the per-attempt-region ladder.
    #[test]
    fn test_bump_level_as_ref_str_carries_through_generic_consumer() {
        fn read<T: AsRef<str>>(t: &T) -> &str {
            t.as_ref()
        }

        for level in BumpLevel::ALL {
            assert_eq!(
                read(&level),
                level.as_str(),
                "generic AsRef<str> consumer must read canonical label at {level:?}",
            );
        }
    }

    /// At every [`BumpLevel`] variant enumerated by
    /// [`BumpLevel::ALL`], `<BumpLevel as AsRef<[u8]>>::as_ref(&level)`
    /// (the [`AsRef<[u8]>`] impl body) equals
    /// `level.as_str().as_bytes()` (the composition of the
    /// canonical-label oracle and [`str::as_bytes`]) exactly. The
    /// load-bearing structural pin that ties the byte-slice
    /// borrowed-view surface to the shared [`BumpLevel::as_str`]
    /// oracle at the byte frontier: a regression that swapped
    /// [`AsRef<[u8]>`] to route through an intermediate
    /// [`String::into_bytes`] path (a per-call [`Vec<u8>`]
    /// allocation from an owned label, discarding the zero-copy
    /// static-lifetime borrow) or drifted the byte grammar from
    /// [`BumpLevel::as_str`]'s lowercase labels (yielding
    /// UpperCamel bytes via the derived [`std::fmt::Debug`] surface,
    /// or a numeric-discriminant byte cast) fails here at ONE named
    /// site instead of leaking to every downstream
    /// `impl AsRef<[u8]>` consumer (streaming hasher `update`,
    /// byte-write sink, [`std::collections::HashMap<Box<[u8]>, _>`]
    /// key builder). Sibling of
    /// [`test_bump_level_as_ref_str_agrees_with_as_str`] at the
    /// UTF-8 borrowed-view surface — the two agreement pins together
    /// close the borrowed-view axis across both the string (`&str`)
    /// and byte-slice (`&[u8]`) frontiers against the same
    /// canonical-label oracle. Structural mirror of
    /// `test_per_attempt_region_as_ref_bytes_agrees_with_as_str_as_bytes`
    /// (commit af44439) at the per-attempt-region ladder and
    /// `test_admission_tier_as_ref_bytes_agrees_with_as_str_as_bytes`
    /// (commit 13abcc4) at the admission-tier ladder.
    #[test]
    fn test_bump_level_as_ref_bytes_agrees_with_as_str_as_bytes() {
        for level in BumpLevel::ALL {
            let borrowed: &[u8] = level.as_ref();
            assert_eq!(
                borrowed,
                level.as_str().as_bytes(),
                "AsRef<[u8]> and as_str().as_bytes() must agree at {level:?}",
            );
        }
    }

    /// The [`AsRef<[u8]>`] identity carries through a generic
    /// `impl AsRef<[u8]>` consumer at every [`BumpLevel::ALL`]
    /// variant. A tiny generic function `fn read<T: AsRef<[u8]>>(t:
    /// &T) -> &[u8] { t.as_ref() }` — the shape of an actual
    /// downstream consumer (a `blake3::Hasher::update` call, a
    /// [`std::io::Write::write_all`] sink, a
    /// `HashMap<Box<[u8]>, _>::get` key lookup, a memchr-driven
    /// classifier over canonical labels) — reads the canonical
    /// lowercase label directly from a [`BumpLevel`] value
    /// without going through the [`std::fmt::Display`] formatter
    /// buffer or an intermediate [`String::into_bytes`] [`Vec<u8>`]
    /// allocation. The structural witness that a
    /// [`BumpLevel`] is genuinely usable at `impl AsRef<[u8]>`
    /// call sites — a regression that drifted the [`AsRef<[u8]>`]
    /// impl signature (e.g., returning an owned [`Vec<u8>`] instead
    /// of a `&[u8]`, or requiring a `&mut self`) fails here at
    /// compile time instead of at every downstream generic call
    /// site. Structural mirror of
    /// `test_per_attempt_region_as_ref_bytes_carries_through_generic_consumer`
    /// (commit af44439) at the per-attempt-region ladder and
    /// `test_admission_tier_as_ref_bytes_carries_through_generic_consumer`
    /// (commit 13abcc4) at the admission-tier ladder.
    #[test]
    fn test_bump_level_as_ref_bytes_carries_through_generic_consumer() {
        fn read<T: AsRef<[u8]>>(t: &T) -> &[u8] {
            t.as_ref()
        }

        for level in BumpLevel::ALL {
            assert_eq!(
                read(&level),
                level.as_str().as_bytes(),
                "generic AsRef<[u8]> consumer must read canonical label bytes at {level:?}",
            );
        }
    }

    /// At every [`BumpLevel`] variant enumerated by
    /// [`BumpLevel::ALL`], the borrowed byte-slice view from
    /// the [`AsRef<[u8]>`] impl round-trips through
    /// [`std::str::from_utf8`] back to the canonical lowercase
    /// label exactly. The load-bearing structural pin that ties
    /// the byte frontier to the UTF-8 frontier through the
    /// standard library's UTF-8 validator, without a per-consumer
    /// restatement of "the canonical labels are ASCII and UTF-8-
    /// valid" at every downstream site: a regression that drifted
    /// [`AsRef<[u8]>`] to yield non-UTF-8 bytes (a numeric-
    /// discriminant byte cast, a byte-swapped label, a mangled
    /// encoding) fails here at ONE named site with a
    /// [`std::str::Utf8Error`] at the [`std::str::from_utf8`]
    /// boundary or a label mismatch at the round-trip assertion.
    /// Together with
    /// [`test_bump_level_as_ref_bytes_agrees_with_as_str_as_bytes`]
    /// this closes the byte-slice borrowed-view surface against
    /// both the composition oracle (`.as_str().as_bytes()`) and
    /// the UTF-8 validity oracle ([`std::str::from_utf8`]) at
    /// every [`BumpLevel::ALL`] variant. Structural mirror of
    /// `test_per_attempt_region_as_ref_bytes_round_trips_through_from_utf8`
    /// (commit af44439) at the per-attempt-region ladder and
    /// `test_admission_tier_as_ref_bytes_round_trips_through_from_utf8`
    /// (commit 13abcc4) at the admission-tier ladder.
    #[test]
    fn test_bump_level_as_ref_bytes_round_trips_through_from_utf8() {
        for level in BumpLevel::ALL {
            let borrowed: &[u8] = level.as_ref();
            let decoded = std::str::from_utf8(borrowed).unwrap_or_else(|err| {
                panic!("AsRef<[u8]> bytes for {level:?} must be valid UTF-8 (got {err})")
            });
            assert_eq!(
                decoded,
                level.as_str(),
                "from_utf8 round-trip must recover canonical label at {level:?}",
            );
        }
    }

    /// At every [`BumpLevel`] variant enumerated by
    /// [`BumpLevel::ALL`],
    /// `<Self as AsRef<std::ffi::OsStr>>::as_ref(&level)` equals
    /// `std::ffi::OsStr::new(level.as_str())`. Pins the agreement
    /// identity that the OS-string borrowed-view surface reads the
    /// same canonical label the [`AsRef<str>`] surface reads,
    /// projected through [`std::ffi::OsStr::new`]. A regression that
    /// swapped the [`AsRef<std::ffi::OsStr>`] impl to route through
    /// an intermediate [`std::fmt::Display`] format buffer or a
    /// fresh [`std::ffi::OsString`] allocation would break this
    /// composition equality at at least one variant and fail here
    /// at the canonical-label pin, not at every downstream
    /// `impl AsRef<std::ffi::OsStr>` call site. Structural mirror of
    /// `test_per_attempt_region_as_ref_osstr_agrees_with_as_str`
    /// (commit 70e1ab5) at the per-attempt-region ladder and
    /// `test_admission_tier_as_ref_osstr_agrees_with_as_str`
    /// (commit 1d708f4) at the admission-tier ladder.
    #[test]
    fn test_bump_level_as_ref_osstr_agrees_with_as_str() {
        for level in BumpLevel::ALL {
            let borrowed: &std::ffi::OsStr = <BumpLevel as AsRef<std::ffi::OsStr>>::as_ref(&level);
            assert_eq!(
                borrowed,
                std::ffi::OsStr::new(level.as_str()),
                "AsRef<OsStr> and OsStr::new(as_str()) must agree at {level:?}",
            );
        }
    }

    /// The [`AsRef<std::ffi::OsStr>`] identity carries through a
    /// generic `impl AsRef<std::ffi::OsStr>` consumer at every
    /// [`BumpLevel::ALL`] variant. A tiny generic function
    /// `fn read<T: AsRef<OsStr>>(t: &T) -> &OsStr { t.as_ref() }` —
    /// the shape of an actual downstream consumer (a
    /// [`std::process::Command::env`] call, a
    /// [`std::env::set_var`] key, a [`std::path::PathBuf::push`]
    /// segment, a [`std::fs::create_dir`] name) — reads the
    /// canonical lowercase label directly from a [`BumpLevel`]
    /// value without going through the [`std::fmt::Display`]
    /// formatter buffer or an intermediate [`std::ffi::OsString`]
    /// allocation. The structural witness that a [`BumpLevel`] is
    /// genuinely usable at `impl AsRef<std::ffi::OsStr>` call sites
    /// — a regression that drifted the [`AsRef<std::ffi::OsStr>`]
    /// impl signature (e.g., returning an owned
    /// [`std::ffi::OsString`] instead of a `&OsStr`, or requiring a
    /// `&mut self`) fails here at compile time instead of at every
    /// downstream generic call site. Structural mirror of
    /// `test_per_attempt_region_as_ref_osstr_carries_through_generic_consumer`
    /// (commit 70e1ab5) at the per-attempt-region ladder and
    /// `test_admission_tier_as_ref_osstr_carries_through_generic_consumer`
    /// (commit 1d708f4) at the admission-tier ladder.
    #[test]
    fn test_bump_level_as_ref_osstr_carries_through_generic_consumer() {
        fn read<T: AsRef<std::ffi::OsStr>>(t: &T) -> &std::ffi::OsStr {
            t.as_ref()
        }
        for level in BumpLevel::ALL {
            assert_eq!(
                read(&level),
                std::ffi::OsStr::new(level.as_str()),
                "generic AsRef<OsStr> consumer must recover canonical label at {level:?}",
            );
        }
    }

    /// The [`AsRef<std::ffi::OsStr>`] output round-trips through
    /// [`std::ffi::OsStr::to_str`] recovering the canonical
    /// lowercase label at every [`BumpLevel::ALL`] variant. Pins
    /// the UTF-8 validity contract on the OS-string borrowed-view
    /// surface: the returned `&OsStr` is always a valid UTF-8
    /// sequence because the canonical labels are pure ASCII, and
    /// [`std::ffi::OsStr::to_str`] recovers exactly the
    /// [`BumpLevel::as_str`] emission. Together with
    /// [`test_bump_level_as_ref_osstr_agrees_with_as_str`] this
    /// closes the OS-string borrowed-view surface against both the
    /// composition oracle (`OsStr::new(as_str())`) and the UTF-8
    /// validity oracle ([`std::ffi::OsStr::to_str`]) at every
    /// [`BumpLevel::ALL`] variant. Structural mirror of
    /// `test_per_attempt_region_as_ref_osstr_round_trips_through_to_str`
    /// (commit 70e1ab5) at the per-attempt-region ladder and
    /// `test_admission_tier_as_ref_osstr_round_trips_through_to_str`
    /// (commit 1d708f4) at the admission-tier ladder.
    #[test]
    fn test_bump_level_as_ref_osstr_round_trips_through_to_str() {
        for level in BumpLevel::ALL {
            let borrowed: &std::ffi::OsStr = <BumpLevel as AsRef<std::ffi::OsStr>>::as_ref(&level);
            let decoded = borrowed
                .to_str()
                .unwrap_or_else(|| panic!("AsRef<OsStr> bytes for {level:?} must be valid UTF-8"));
            assert_eq!(
                decoded,
                level.as_str(),
                "OsStr::to_str round-trip must recover canonical label at {level:?}",
            );
        }
    }

    /// At every [`BumpLevel`] variant enumerated by
    /// [`BumpLevel::ALL`],
    /// `<Self as AsRef<std::path::Path>>::as_ref(&level)` equals
    /// `std::path::Path::new(level.as_str())`. Pins the agreement
    /// identity that the filesystem-path borrowed-view surface
    /// reads the same canonical label the [`AsRef<str>`] surface
    /// reads, projected through [`std::path::Path::new`]. A
    /// regression that swapped the [`AsRef<std::path::Path>`] impl
    /// to route through an intermediate [`std::fmt::Display`]
    /// format buffer or a fresh [`std::path::PathBuf`] allocation
    /// would break this composition equality at at least one
    /// variant and fail here at the canonical-label pin, not at
    /// every downstream `impl AsRef<std::path::Path>` call site.
    /// Structural mirror of
    /// `test_per_attempt_region_as_ref_path_agrees_with_as_str`
    /// (commit 17718d2) at the per-attempt-region ladder and
    /// `test_admission_tier_as_ref_path_agrees_with_as_str`
    /// (commit f6c4c75) at the admission-tier ladder.
    #[test]
    fn test_bump_level_as_ref_path_agrees_with_as_str() {
        for level in BumpLevel::ALL {
            let borrowed: &std::path::Path = <BumpLevel as AsRef<std::path::Path>>::as_ref(&level);
            assert_eq!(
                borrowed,
                std::path::Path::new(level.as_str()),
                "AsRef<Path> and Path::new(as_str()) must agree at {level:?}",
            );
        }
    }

    /// The [`AsRef<std::path::Path>`] identity carries through a
    /// generic `impl AsRef<std::path::Path>` consumer at every
    /// [`BumpLevel::ALL`] variant. A tiny generic function
    /// `fn read<T: AsRef<Path>>(t: &T) -> &Path { t.as_ref() }` —
    /// the shape of an actual downstream consumer (a
    /// [`std::fs::create_dir`] call, a
    /// [`std::path::PathBuf::push`] segment, a
    /// [`std::fs::File::open`] argument, a [`std::fs::metadata`]
    /// input) — reads the canonical lowercase label directly
    /// from a [`BumpLevel`] value without going through the
    /// [`std::fmt::Display`] formatter buffer or an intermediate
    /// [`std::path::PathBuf`] allocation. The structural witness
    /// that a [`BumpLevel`] is genuinely usable at
    /// `impl AsRef<std::path::Path>` call sites — a regression
    /// that drifted the [`AsRef<std::path::Path>`] impl signature
    /// (e.g., returning an owned [`std::path::PathBuf`] instead of
    /// a `&Path`, or requiring a `&mut self`) fails here at
    /// compile time instead of at every downstream generic call
    /// site. Structural mirror of
    /// `test_per_attempt_region_as_ref_path_carries_through_generic_consumer`
    /// (commit 17718d2) at the per-attempt-region ladder and
    /// `test_admission_tier_as_ref_path_carries_through_generic_consumer`
    /// (commit f6c4c75) at the admission-tier ladder.
    #[test]
    fn test_bump_level_as_ref_path_carries_through_generic_consumer() {
        fn read<T: AsRef<std::path::Path>>(t: &T) -> &std::path::Path {
            t.as_ref()
        }
        for level in BumpLevel::ALL {
            assert_eq!(
                read(&level),
                std::path::Path::new(level.as_str()),
                "generic AsRef<Path> consumer must recover canonical label at {level:?}",
            );
        }
    }

    /// The [`AsRef<std::path::Path>`] output round-trips through
    /// [`std::path::Path::to_str`] recovering the canonical
    /// lowercase label at every [`BumpLevel::ALL`] variant. Pins
    /// the UTF-8 validity contract on the filesystem-path
    /// borrowed-view surface: the returned `&Path` is always a
    /// valid UTF-8 sequence because the canonical labels are pure
    /// ASCII, and [`std::path::Path::to_str`] recovers exactly the
    /// [`BumpLevel::as_str`] emission. Together with
    /// [`test_bump_level_as_ref_path_agrees_with_as_str`] this
    /// closes the filesystem-path borrowed-view surface against
    /// both the composition oracle (`Path::new(as_str())`) and
    /// the UTF-8 validity oracle ([`std::path::Path::to_str`]) at
    /// every [`BumpLevel::ALL`] variant. Structural mirror of
    /// `test_per_attempt_region_as_ref_path_round_trips_through_to_str`
    /// (commit 17718d2) at the per-attempt-region ladder and
    /// `test_admission_tier_as_ref_path_round_trips_through_to_str`
    /// (commit f6c4c75) at the admission-tier ladder.
    #[test]
    fn test_bump_level_as_ref_path_round_trips_through_to_str() {
        for level in BumpLevel::ALL {
            let borrowed: &std::path::Path = <BumpLevel as AsRef<std::path::Path>>::as_ref(&level);
            let decoded = borrowed
                .to_str()
                .unwrap_or_else(|| panic!("AsRef<Path> bytes for {level:?} must be valid UTF-8"));
            assert_eq!(
                decoded,
                level.as_str(),
                "Path::to_str round-trip must recover canonical label at {level:?}",
            );
        }
    }

    /// At every [`BumpLevel`] variant enumerated by
    /// [`BumpLevel::ALL`], `std::ffi::OsString::from(level)`
    /// equals `std::ffi::OsString::from(level.as_str())`. Pins the
    /// agreement identity that the by-value owned OS-string emit
    /// surface reads the same canonical label the [`AsRef<str>`]
    /// surface reads, projected through [`std::ffi::OsString::from`].
    /// A regression that swapped the [`From`] impl to route through
    /// an intermediate [`std::fmt::Display`] format buffer or a
    /// [`std::path::PathBuf`] round-trip would break this
    /// composition equality at at least one variant and fail here
    /// at the canonical-label pin, not at every downstream
    /// `impl Into<std::ffi::OsString>` call site. Structural mirror
    /// of `test_per_attempt_region_from_into_osstring_agrees_with_as_str`
    /// (commit 976f5af) at the per-attempt-region ladder and
    /// `test_admission_tier_from_into_osstring_agrees_with_as_str`
    /// (commit 0791fc7) at the admission-tier ladder.
    #[test]
    fn test_bump_level_from_into_osstring_agrees_with_as_str() {
        for level in BumpLevel::ALL {
            let owned: std::ffi::OsString = std::ffi::OsString::from(level);
            assert_eq!(
                owned,
                std::ffi::OsString::from(level.as_str()),
                "From<BumpLevel> for OsString and OsString::from(as_str()) must agree at {level:?}",
            );
        }
    }

    /// The [`From<BumpLevel> for std::ffi::OsString`] identity
    /// carries through a generic `impl Into<std::ffi::OsString>`
    /// consumer at every [`BumpLevel::ALL`] variant. A tiny
    /// generic function `fn read<T: Into<OsString>>(t: T) -> OsString
    /// { t.into() }` — the shape of an actual downstream consumer
    /// (a [`std::process::Command::env`] key/value that owns its
    /// slot, a [`std::env::set_var`] owned key, a
    /// [`std::path::PathBuf::push`] segment consumer) — reads the
    /// canonical lowercase label directly from a [`BumpLevel`]
    /// value as an owned [`std::ffi::OsString`]. The structural
    /// witness that a [`BumpLevel`] is genuinely usable at
    /// `impl Into<std::ffi::OsString>` call sites — a regression
    /// that drifted the [`From`] impl signature (e.g., returning
    /// `&std::ffi::OsStr` instead of [`std::ffi::OsString`],
    /// requiring `&BumpLevel` and losing the by-value semantics)
    /// fails here at compile time instead of at every downstream
    /// generic call site.
    #[test]
    fn test_bump_level_into_osstring_carries_through_generic_consumer() {
        fn read<T: Into<std::ffi::OsString>>(t: T) -> std::ffi::OsString {
            t.into()
        }
        for level in BumpLevel::ALL {
            assert_eq!(
                read(level),
                std::ffi::OsString::from(level.as_str()),
                "generic Into<OsString> consumer must recover canonical label at {level:?}",
            );
        }
    }

    /// The [`From<BumpLevel> for std::ffi::OsString`] output
    /// round-trips through [`std::ffi::OsString::into_string`]
    /// recovering the canonical lowercase label byte-for-byte at
    /// every [`BumpLevel::ALL`] variant. Pins the UTF-8 validity
    /// contract on the by-value owned OS-string emit surface: the
    /// produced [`std::ffi::OsString`] is always a valid UTF-8
    /// sequence because the canonical labels are pure ASCII, and
    /// [`std::ffi::OsString::into_string`] recovers exactly the
    /// [`BumpLevel::as_str`] emission. Together with
    /// [`test_bump_level_from_into_osstring_agrees_with_as_str`]
    /// this closes the owned OS-string emit surface against both
    /// the composition oracle (`OsString::from(as_str())`) and
    /// the UTF-8 validity oracle
    /// ([`std::ffi::OsString::into_string`]) at every
    /// [`BumpLevel::ALL`] variant. Structural mirror of
    /// `test_per_attempt_region_from_into_osstring_round_trips_through_into_string`
    /// (commit 976f5af) at the per-attempt-region ladder and
    /// `test_admission_tier_from_into_osstring_round_trips_through_into_string`
    /// (commit 0791fc7) at the admission-tier ladder.
    #[test]
    fn test_bump_level_from_into_osstring_round_trips_through_into_string() {
        for level in BumpLevel::ALL {
            let owned: std::ffi::OsString = std::ffi::OsString::from(level);
            let decoded = owned.into_string().unwrap_or_else(|s| {
                panic!("OsString for {level:?} must be valid UTF-8 (got {s:?})")
            });
            assert_eq!(
                decoded,
                level.as_str(),
                "OsString::into_string round-trip must recover canonical label at {level:?}",
            );
        }
    }

    /// At every [`BumpLevel`] variant enumerated by
    /// [`BumpLevel::ALL`], `std::path::PathBuf::from(level)`
    /// equals `std::path::PathBuf::from(level.as_str())`. Pins
    /// the agreement identity that the by-value owned
    /// filesystem-path emit surface reads the same canonical
    /// label the [`AsRef<str>`] surface reads, projected through
    /// [`std::path::PathBuf::from`]. A regression that swapped
    /// the [`From`] impl to route through an intermediate
    /// [`std::fmt::Display`] format buffer or a
    /// [`std::ffi::OsString`] round-trip would break this
    /// composition equality at at least one variant and fail
    /// here at the canonical-label pin, not at every downstream
    /// `impl Into<std::path::PathBuf>` call site. Structural
    /// mirror of `test_per_attempt_region_from_into_pathbuf_agrees_with_as_str`
    /// (commit 6333c31) at the per-attempt-region ladder and
    /// `test_admission_tier_from_into_pathbuf_agrees_with_as_str`
    /// (commit 75a37d4) at the admission-tier ladder.
    #[test]
    fn test_bump_level_from_into_pathbuf_agrees_with_as_str() {
        for level in BumpLevel::ALL {
            let owned: std::path::PathBuf = std::path::PathBuf::from(level);
            assert_eq!(
                owned,
                std::path::PathBuf::from(level.as_str()),
                "From<BumpLevel> for PathBuf and PathBuf::from(as_str()) must agree at {level:?}",
            );
        }
    }

    /// The [`From<BumpLevel> for std::path::PathBuf`] identity
    /// carries through a generic `impl Into<std::path::PathBuf>`
    /// consumer at every [`BumpLevel::ALL`] variant. A tiny
    /// generic function `fn read<T: Into<PathBuf>>(t: T) ->
    /// PathBuf { t.into() }` — the shape of an actual
    /// downstream consumer (a [`std::path::PathBuf::push`]
    /// segment consumer that owns its receiver, a
    /// [`std::fs::create_dir_all`] argument, a
    /// [`std::collections::HashMap<std::path::PathBuf, _>::insert`]
    /// key builder) — reads the canonical lowercase label
    /// directly from a [`BumpLevel`] value as an owned
    /// [`std::path::PathBuf`]. The structural witness that a
    /// [`BumpLevel`] is genuinely usable at
    /// `impl Into<std::path::PathBuf>` call sites — a regression
    /// that drifted the [`From`] impl signature (e.g., returning
    /// `&std::path::Path` instead of [`std::path::PathBuf`],
    /// requiring `&BumpLevel` and losing the by-value
    /// semantics) fails here at compile time instead of at every
    /// downstream generic call site.
    #[test]
    fn test_bump_level_into_pathbuf_carries_through_generic_consumer() {
        fn read<T: Into<std::path::PathBuf>>(t: T) -> std::path::PathBuf {
            t.into()
        }
        for level in BumpLevel::ALL {
            assert_eq!(
                read(level),
                std::path::PathBuf::from(level.as_str()),
                "generic Into<PathBuf> consumer must recover canonical label at {level:?}",
            );
        }
    }

    /// The [`From<BumpLevel> for std::path::PathBuf`] output
    /// round-trips through [`std::path::PathBuf::into_os_string`]
    /// composed with [`std::ffi::OsString::into_string`]
    /// recovering the canonical lowercase label byte-for-byte at
    /// every [`BumpLevel::ALL`] variant. Pins the UTF-8 validity
    /// contract on the by-value owned filesystem-path emit
    /// surface: the produced [`std::path::PathBuf`] is always a
    /// valid UTF-8 sequence because the canonical labels are
    /// pure ASCII, and [`std::path::PathBuf::into_os_string`] +
    /// [`std::ffi::OsString::into_string`] recovers exactly the
    /// [`BumpLevel::as_str`] emission. Together with
    /// [`test_bump_level_from_into_pathbuf_agrees_with_as_str`]
    /// this closes the owned filesystem-path emit surface
    /// against both the composition oracle
    /// (`PathBuf::from(as_str())`) and the UTF-8 validity oracle
    /// (`PathBuf::into_os_string ∘ OsString::into_string`) at
    /// every [`BumpLevel::ALL`] variant. Structural mirror of
    /// `test_per_attempt_region_from_into_pathbuf_round_trips_through_into_os_string`
    /// (commit 6333c31) at the per-attempt-region ladder and
    /// `test_admission_tier_from_into_pathbuf_round_trips_through_into_os_string`
    /// (commit 75a37d4) at the admission-tier ladder.
    #[test]
    fn test_bump_level_from_into_pathbuf_round_trips_through_into_os_string() {
        for level in BumpLevel::ALL {
            let owned: std::path::PathBuf = std::path::PathBuf::from(level);
            let decoded = owned.into_os_string().into_string().unwrap_or_else(|s| {
                panic!("PathBuf for {level:?} must be valid UTF-8 (got {s:?})")
            });
            assert_eq!(
                decoded,
                level.as_str(),
                "PathBuf::into_os_string ∘ OsString::into_string round-trip must recover canonical label at {level:?}",
            );
        }
    }

    /// At every [`BumpLevel`] variant enumerated by
    /// [`BumpLevel::ALL`],
    /// `<&'static std::ffi::OsStr>::from(level)` (the
    /// [`From<BumpLevel> for &'static std::ffi::OsStr`] impl body)
    /// equals `std::ffi::OsStr::new(level.as_str())` (the
    /// composition through the canonical-label oracle and
    /// [`std::ffi::OsStr::new`]). Pins the agreement identity that
    /// the by-value static-lifetime OS-string emit surface reads the
    /// same canonical label the borrowed-view
    /// [`AsRef<std::ffi::OsStr>`] surface and the by-value owned
    /// [`From<BumpLevel> for std::ffi::OsString`] surface already
    /// read at the OS-string frontier: a regression that swapped the
    /// [`From`] impl body to route through
    /// [`std::ffi::OsString::from`]-then-[`std::ffi::OsString::as_os_str`]
    /// (dropping the `'static` lifetime through an owned buffer), or
    /// through an intermediate [`std::fmt::Display`] format buffer,
    /// or through a [`std::path::Path::as_os_str`] round-trip, would
    /// break this composition equality at at least one variant and
    /// fail here at the canonical-label pin, not at every downstream
    /// `impl Into<&'static std::ffi::OsStr>` call site. Structural
    /// mirror of
    /// `test_per_attempt_region_from_into_static_os_str_agrees_with_os_str_new_as_str`
    /// (commit be57ac3) at the per-attempt-region ladder and
    /// `test_admission_tier_from_into_static_os_str_agrees_with_os_str_new_as_str`
    /// (commit b69f733) at the admission-tier ladder.
    #[test]
    fn test_bump_level_from_into_static_os_str_agrees_with_os_str_new_as_str() {
        for level in BumpLevel::ALL {
            let borrowed: &'static std::ffi::OsStr = <&'static std::ffi::OsStr>::from(level);
            assert_eq!(
                borrowed,
                std::ffi::OsStr::new(level.as_str()),
                "From<BumpLevel> for &'static OsStr and OsStr::new(as_str()) must agree at {level:?}",
            );
        }
    }

    /// The [`From<BumpLevel> for &'static std::ffi::OsStr`]
    /// identity carries through a generic
    /// `impl Into<&'static std::ffi::OsStr>` consumer at every
    /// [`BumpLevel::ALL`] variant. A tiny generic function
    /// `fn read<T: Into<&'static OsStr>>(t: T) -> &'static OsStr
    /// { t.into() }` — the shape of an actual downstream consumer
    /// (a `const`-adjacent OS-string sink holding
    /// `&'static std::ffi::OsStr` slots, a
    /// [`std::borrow::Cow<'static, std::ffi::OsStr>`] sink taking
    /// `Into<Cow<'static, OsStr>>`, a `phf`-style static lookup
    /// table keyed by canonical label OS-strings) — reads the
    /// canonical lowercase label directly from a [`BumpLevel`]
    /// value as a borrowed `&'static std::ffi::OsStr` with
    /// `'static` lifetime preserved end-to-end. The structural
    /// witness that a [`BumpLevel`] is genuinely usable at
    /// `impl Into<&'static std::ffi::OsStr>` call sites — a
    /// regression that drifted the [`From`] impl signature (e.g.,
    /// returning an owned [`std::ffi::OsString`] instead of
    /// `&'static std::ffi::OsStr`, or requiring `&BumpLevel` and
    /// losing the `'static` lifetime through a receiver borrow)
    /// fails here at compile time instead of at every downstream
    /// generic call site.
    #[test]
    fn test_bump_level_into_static_os_str_carries_through_generic_consumer() {
        fn read<T: Into<&'static std::ffi::OsStr>>(t: T) -> &'static std::ffi::OsStr {
            t.into()
        }
        for level in BumpLevel::ALL {
            assert_eq!(
                read(level),
                std::ffi::OsStr::new(level.as_str()),
                "generic Into<&'static OsStr> consumer must recover canonical label at {level:?}",
            );
        }
    }

    /// The [`From<BumpLevel> for &'static std::ffi::OsStr`] output
    /// round-trips through [`std::ffi::OsStr::to_str`] recovering
    /// the canonical lowercase label byte-for-byte at every
    /// [`BumpLevel::ALL`] variant. Pins the UTF-8 validity contract
    /// on the by-value static-lifetime OS-string emit surface: the
    /// produced `&'static std::ffi::OsStr` is always a valid UTF-8
    /// sequence because the canonical labels are pure ASCII, and
    /// [`std::ffi::OsStr::to_str`] recovers exactly the
    /// [`BumpLevel::as_str`] emission. Together with
    /// [`test_bump_level_from_into_static_os_str_agrees_with_os_str_new_as_str`]
    /// this closes the by-value static-lifetime OS-string emit
    /// surface against both the composition oracle
    /// (`OsStr::new(as_str())`) and the UTF-8 validity oracle
    /// (`OsStr::to_str`) at every [`BumpLevel::ALL`] variant.
    /// Structural mirror of
    /// `test_per_attempt_region_from_into_static_os_str_round_trips_through_to_str`
    /// (commit be57ac3) at the per-attempt-region ladder and
    /// `test_admission_tier_from_into_static_os_str_round_trips_through_to_str`
    /// (commit b69f733) at the admission-tier ladder.
    #[test]
    fn test_bump_level_from_into_static_os_str_round_trips_through_to_str() {
        for level in BumpLevel::ALL {
            let borrowed: &'static std::ffi::OsStr = <&'static std::ffi::OsStr>::from(level);
            let decoded = borrowed.to_str().unwrap_or_else(|| {
                panic!("&'static OsStr bytes for {level:?} must be valid UTF-8")
            });
            assert_eq!(
                decoded,
                level.as_str(),
                "OsStr::to_str round-trip must recover canonical label at {level:?}",
            );
        }
    }

    /// At every [`BumpLevel`] variant enumerated by
    /// [`BumpLevel::ALL`],
    /// `<&'static std::path::Path>::from(level)` (the
    /// [`From<BumpLevel> for &'static std::path::Path`] impl body)
    /// equals `std::path::Path::new(level.as_str())` (the
    /// composition through the canonical-label oracle and
    /// [`std::path::Path::new`]). Pins the agreement identity that
    /// the by-value static-lifetime filesystem-path emit surface
    /// reads the same canonical label the borrowed-view
    /// [`AsRef<std::path::Path>`] surface and the by-value owned
    /// [`From<BumpLevel> for std::path::PathBuf`] surface already
    /// read at the filesystem-path frontier: a regression that
    /// swapped the [`From`] impl body to route through
    /// [`std::path::PathBuf::from`]-then-[`std::path::PathBuf::as_path`]
    /// (dropping the `'static` lifetime through an owned buffer), or
    /// through an intermediate [`std::fmt::Display`] format buffer,
    /// or through a [`std::ffi::OsStr`] round-trip that leaks a
    /// non-`'static` lifetime, would break this composition equality
    /// at at least one variant and fail here at the canonical-label
    /// pin, not at every downstream
    /// `impl Into<&'static std::path::Path>` call site. Structural
    /// mirror of
    /// `test_per_attempt_region_from_into_static_path_agrees_with_path_new_as_str`
    /// (commit 671119d) at the per-attempt-region ladder and
    /// `test_admission_tier_from_into_static_path_agrees_with_path_new_as_str`
    /// (commit 758321a) at the admission-tier ladder.
    #[test]
    fn test_bump_level_from_into_static_path_agrees_with_path_new_as_str() {
        for level in BumpLevel::ALL {
            let borrowed: &'static std::path::Path = <&'static std::path::Path>::from(level);
            assert_eq!(
                borrowed,
                std::path::Path::new(level.as_str()),
                "From<BumpLevel> for &'static Path and Path::new(as_str()) must agree at {level:?}",
            );
        }
    }

    /// The [`From<BumpLevel> for &'static std::path::Path`] identity
    /// carries through a generic `impl Into<&'static std::path::Path>`
    /// consumer at every [`BumpLevel::ALL`] variant. A tiny generic
    /// function
    /// `fn read<T: Into<&'static Path>>(t: T) -> &'static Path
    /// { t.into() }` — the shape of an actual downstream consumer
    /// (a `const`-adjacent filesystem-path sink holding
    /// `&'static std::path::Path` slots, a
    /// [`std::borrow::Cow<'static, std::path::Path>`] sink taking
    /// `Into<Cow<'static, Path>>`, a `phf`-style static lookup table
    /// keyed by canonical label paths) — reads the canonical
    /// lowercase label directly from a [`BumpLevel`] value as a
    /// borrowed `&'static std::path::Path` with `'static` lifetime
    /// preserved end-to-end. The structural witness that a
    /// [`BumpLevel`] is genuinely usable at
    /// `impl Into<&'static std::path::Path>` call sites — a
    /// regression that drifted the [`From`] impl signature (e.g.,
    /// returning an owned [`std::path::PathBuf`] instead of
    /// `&'static std::path::Path`, or requiring `&BumpLevel` and
    /// losing the `'static` lifetime through a receiver borrow)
    /// fails here at compile time instead of at every downstream
    /// generic call site.
    #[test]
    fn test_bump_level_into_static_path_carries_through_generic_consumer() {
        fn read<T: Into<&'static std::path::Path>>(t: T) -> &'static std::path::Path {
            t.into()
        }
        for level in BumpLevel::ALL {
            assert_eq!(
                read(level),
                std::path::Path::new(level.as_str()),
                "generic Into<&'static Path> consumer must recover canonical label at {level:?}",
            );
        }
    }

    /// The [`From<BumpLevel> for &'static std::path::Path`] output
    /// round-trips through [`std::path::Path::to_str`] recovering
    /// the canonical lowercase label byte-for-byte at every
    /// [`BumpLevel::ALL`] variant. Pins the UTF-8 validity contract
    /// on the by-value static-lifetime filesystem-path emit surface:
    /// the produced `&'static std::path::Path` is always a valid
    /// UTF-8 sequence because the canonical labels are pure ASCII,
    /// and [`std::path::Path::to_str`] recovers exactly the
    /// [`BumpLevel::as_str`] emission. Together with
    /// [`test_bump_level_from_into_static_path_agrees_with_path_new_as_str`]
    /// this closes the by-value static-lifetime filesystem-path emit
    /// surface against both the composition oracle
    /// (`Path::new(as_str())`) and the UTF-8 validity oracle
    /// (`Path::to_str`) at every [`BumpLevel::ALL`] variant.
    /// Structural mirror of
    /// `test_per_attempt_region_from_into_static_path_round_trips_through_to_str`
    /// (commit 671119d) at the per-attempt-region ladder and
    /// `test_admission_tier_from_into_static_path_round_trips_through_to_str`
    /// (commit 758321a) at the admission-tier ladder.
    #[test]
    fn test_bump_level_from_into_static_path_round_trips_through_to_str() {
        for level in BumpLevel::ALL {
            let borrowed: &'static std::path::Path = <&'static std::path::Path>::from(level);
            let decoded = borrowed
                .to_str()
                .unwrap_or_else(|| panic!("&'static Path bytes for {level:?} must be valid UTF-8"));
            assert_eq!(
                decoded,
                level.as_str(),
                "Path::to_str round-trip must recover canonical label at {level:?}",
            );
        }
    }

    /// At every [`BumpLevel`] variant enumerated by
    /// [`BumpLevel::ALL`],
    /// `<std::borrow::Cow<'static, std::ffi::OsStr>>::from(level)` (the
    /// [`From<BumpLevel> for Cow<'static, std::ffi::OsStr>`] impl body)
    /// equals `Cow::Borrowed(std::ffi::OsStr::new(level.as_str()))`
    /// (the composition through the canonical-label oracle,
    /// [`std::ffi::OsStr::new`], and [`std::borrow::Cow::Borrowed`]).
    /// Pins the agreement identity that the by-value borrowed/owned-
    /// frontier OS-string emit surface reads the same canonical label
    /// the borrowed-view [`AsRef<std::ffi::OsStr>`] surface, the by-
    /// value owned [`From<BumpLevel> for std::ffi::OsString`] surface,
    /// and the by-value static-lifetime
    /// [`From<BumpLevel> for &'static std::ffi::OsStr`] surface
    /// already read at the OS-string frontier: a regression that
    /// swapped the [`From`] impl body to route through
    /// [`std::ffi::OsString::from`]-then-into-[`std::borrow::Cow::Owned`]
    /// (dropping the zero-allocation branch), or through an intermediate
    /// [`String`] buffer, or through a bare [`std::borrow::Cow::Borrowed`]
    /// wrap of a [`&'static str`] cast that leaks the wrong frontier,
    /// would break this composition equality at at least one variant
    /// and fail here at the canonical-label pin, not at every
    /// downstream `impl Into<Cow<'static, std::ffi::OsStr>>` call site.
    /// Structural mirror of
    /// `test_per_attempt_region_from_into_cow_static_os_str_agrees_with_cow_borrowed_os_str_new_as_str`
    /// (commit 24f6110) at the per-attempt-region ladder and
    /// `test_admission_tier_from_into_cow_static_os_str_agrees_with_cow_borrowed_os_str_new_as_str`
    /// (commit 4e94fc5) at the admission-tier ladder — the same lift
    /// at the by-value borrowed/owned-frontier OS-string emit layer at
    /// this third and last ordered typed sum, closing the trio.
    #[test]
    fn test_bump_level_from_into_cow_static_os_str_agrees_with_cow_borrowed_os_str_new_as_str() {
        for level in BumpLevel::ALL {
            let cow: std::borrow::Cow<'static, std::ffi::OsStr> = std::borrow::Cow::from(level);
            let borrowed: &std::ffi::OsStr = &cow;
            assert_eq!(
                borrowed,
                std::ffi::OsStr::new(level.as_str()),
                "From<BumpLevel> for Cow<'static, OsStr> and Cow::Borrowed(OsStr::new(as_str())) must agree at {level:?}",
            );
        }
    }

    /// The
    /// [`From<BumpLevel> for std::borrow::Cow<'static, std::ffi::OsStr>`]
    /// identity carries through a generic
    /// `impl Into<Cow<'static, std::ffi::OsStr>>` consumer at every
    /// [`BumpLevel::ALL`] variant. A tiny generic function
    /// `fn read<T: Into<Cow<'static, OsStr>>>(t: T) -> Cow<'static, OsStr>
    /// { t.into() }` — the shape of an actual downstream consumer
    /// (config-schema builder that accepts either a static OS-string
    /// label or a caller-supplied [`std::ffi::OsString`] uniformly,
    /// subprocess-argv sink taking [`std::borrow::Cow<'static, std::ffi::OsStr>`]
    /// slots at a [`std::process::Command`] boundary, a `phf`-style
    /// static lookup table keyed by canonical label OS-strings) —
    /// reads the canonical lowercase label directly from a
    /// [`BumpLevel`] value with the `'static` lifetime preserved
    /// through the [`std::borrow::Cow<'static, std::ffi::OsStr>`]
    /// wrapper. The structural witness that a [`BumpLevel`] is
    /// genuinely usable at `impl Into<Cow<'static, std::ffi::OsStr>>`
    /// call sites — a regression that drifted the [`From`] impl
    /// signature (e.g., returning
    /// [`std::borrow::Cow<'_, std::ffi::OsStr>`] with a non-`'static`
    /// lifetime, requiring [`&BumpLevel`] and losing the by-value
    /// semantics, or dropping the [`std::borrow::Cow`] wrapper
    /// entirely) fails here at compile time instead of at every
    /// downstream generic call site. Structural mirror of
    /// `test_per_attempt_region_into_cow_static_os_str_carries_through_generic_consumer`
    /// (commit 24f6110) at the per-attempt-region ladder and
    /// `test_admission_tier_into_cow_static_os_str_carries_through_generic_consumer`
    /// (commit 4e94fc5) at the admission-tier ladder.
    #[test]
    fn test_bump_level_into_cow_static_os_str_carries_through_generic_consumer() {
        fn read<T: Into<std::borrow::Cow<'static, std::ffi::OsStr>>>(
            t: T,
        ) -> std::borrow::Cow<'static, std::ffi::OsStr> {
            t.into()
        }

        for level in BumpLevel::ALL {
            let cow = read(level);
            let borrowed: &std::ffi::OsStr = &cow;
            assert_eq!(
                borrowed,
                std::ffi::OsStr::new(level.as_str()),
                "generic Into<Cow<'static, OsStr>> consumer must read canonical label at {level:?}",
            );
        }
    }

    /// [`From<BumpLevel> for std::borrow::Cow<'static, std::ffi::OsStr>`]
    /// returns the [`std::borrow::Cow::Borrowed`] branch, not
    /// [`std::borrow::Cow::Owned`], at every [`BumpLevel::ALL`]
    /// variant. Pins the zero-allocation contract at the emit
    /// boundary: because [`BumpLevel::as_str`] returns a
    /// `'static`-lived borrow into the static-string constant table
    /// and [`std::ffi::OsStr::new`] preserves the borrow's lifetime,
    /// this impl composes with an
    /// [`Into<std::borrow::Cow<'static, std::ffi::OsStr>>`] receiver
    /// at the [`std::borrow::Cow::Borrowed`] branch — the receiver
    /// pays the `'static`-borrow cost of
    /// [`From<BumpLevel> for &'static std::ffi::OsStr`], not the
    /// [`std::ffi::OsString`]-allocation cost of
    /// [`From<BumpLevel> for std::ffi::OsString`]. The structural
    /// witness that the impl body picks the load-bearing
    /// [`std::borrow::Cow::Borrowed`] branch — a regression that
    /// drifted the impl body toward
    /// `Cow::Owned(std::ffi::OsString::from(level.as_str()))` would
    /// silently allocate at every emit site and defeat the
    /// borrowed/owned-frontier discipline this impl trio-closes; the
    /// [`matches!`] pin lights up here at ONE named site instead of
    /// leaking to every downstream
    /// `impl Into<Cow<'static, std::ffi::OsStr>>` consumer as a
    /// hidden per-call allocation. Sibling of the agreement pin
    /// [`test_bump_level_from_into_cow_static_os_str_agrees_with_cow_borrowed_os_str_new_as_str`]
    /// at the label-oracle surface — the two pins together close both
    /// the value-agreement contract and the branch-choice / zero-
    /// allocation contract at the by-value
    /// [`std::borrow::Cow<'static, std::ffi::OsStr>`] emit surface.
    /// Structural mirror of
    /// `test_per_attempt_region_into_cow_static_os_str_is_borrowed`
    /// (commit 24f6110) at the per-attempt-region ladder and
    /// `test_admission_tier_into_cow_static_os_str_is_borrowed`
    /// (commit 4e94fc5) at the admission-tier ladder — closing the
    /// zero-allocation-branch contract at the third and last ordered
    /// typed sum.
    #[test]
    fn test_bump_level_into_cow_static_os_str_is_borrowed() {
        for level in BumpLevel::ALL {
            let cow: std::borrow::Cow<'static, std::ffi::OsStr> = std::borrow::Cow::from(level);
            assert!(
                matches!(cow, std::borrow::Cow::Borrowed(_)),
                "From<BumpLevel> for Cow<'static, OsStr> must return Cow::Borrowed \
                 (zero-allocation branch) at {level:?}, not Cow::Owned",
            );
        }
    }

    /// At every [`BumpLevel`] variant enumerated by
    /// [`BumpLevel::ALL`],
    /// `<std::borrow::Cow<'static, std::path::Path>>::from(level)` (the
    /// [`From<BumpLevel> for Cow<'static, std::path::Path>`] impl body)
    /// equals `Cow::Borrowed(std::path::Path::new(level.as_str()))` (the
    /// composition through the canonical-label oracle,
    /// [`std::path::Path::new`], and [`std::borrow::Cow::Borrowed`]).
    /// Pins the agreement identity that the by-value
    /// borrowed/owned-frontier filesystem-path emit surface reads the
    /// same canonical label the borrowed-view
    /// [`AsRef<std::path::Path>`] surface, the by-value owned
    /// [`From<BumpLevel> for std::path::PathBuf`] surface, and the
    /// by-value static-lifetime
    /// [`From<BumpLevel> for &'static std::path::Path`] surface already
    /// read at the filesystem-path frontier: a regression that swapped
    /// the [`From`] impl body to route through
    /// [`std::path::PathBuf::from`]-then-into-[`std::borrow::Cow::Owned`]
    /// (dropping the zero-allocation branch), or through an
    /// intermediate [`String`] buffer, or through a bare
    /// [`std::borrow::Cow::Borrowed`] wrap of a [`&'static str`] cast
    /// that leaks the wrong frontier, would break this composition
    /// equality at at least one variant and fail here at the
    /// canonical-label pin, not at every downstream
    /// `impl Into<Cow<'static, std::path::Path>>` call site. Structural
    /// mirror of
    /// `test_per_attempt_region_from_into_cow_static_path_agrees_with_cow_borrowed_path_new_as_str`
    /// (commit cfb6125) at the per-attempt-region ladder and
    /// `test_admission_tier_from_into_cow_static_path_agrees_with_cow_borrowed_path_new_as_str`
    /// (commit f11faad) at the admission-tier ladder — closing the
    /// canonical-label agreement contract at the third and last
    /// ordered typed sum.
    #[test]
    fn test_bump_level_from_into_cow_static_path_agrees_with_cow_borrowed_path_new_as_str() {
        for level in BumpLevel::ALL {
            let cow: std::borrow::Cow<'static, std::path::Path> = std::borrow::Cow::from(level);
            let borrowed: &std::path::Path = &cow;
            assert_eq!(
                borrowed,
                std::path::Path::new(level.as_str()),
                "From<BumpLevel> for Cow<'static, Path> and \
                 Cow::Borrowed(Path::new(as_str())) must agree at {level:?}",
            );
        }
    }

    /// The
    /// [`From<BumpLevel> for std::borrow::Cow<'static, std::path::Path>`]
    /// identity carries through a generic
    /// `impl Into<Cow<'static, std::path::Path>>` consumer at every
    /// [`BumpLevel::ALL`] variant. A tiny generic function
    /// `fn read<T: Into<Cow<'static, Path>>>(t: T) -> Cow<'static, Path>
    /// { t.into() }` — the shape of an actual downstream consumer (a
    /// [`std::path::PathBuf`]-adjacent config-schema builder that
    /// accepts either a static path label or a caller-supplied
    /// [`std::path::PathBuf`] uniformly, a `phf`-style static lookup
    /// table keyed by canonical label filesystem-paths, a
    /// Nix-store-path segment router at the filesystem-path frontier,
    /// an OCI / GHCR layer-path sink typed as
    /// [`std::borrow::Cow<'static, std::path::Path>`]) — reads the
    /// canonical lowercase label directly from a [`BumpLevel`] value
    /// with the `'static` lifetime preserved through the
    /// [`std::borrow::Cow<'static, std::path::Path>`] wrapper. The
    /// structural witness that a [`BumpLevel`] is genuinely usable at
    /// `impl Into<Cow<'static, std::path::Path>>` call sites — a
    /// regression that drifted the [`From`] impl signature (e.g.,
    /// returning [`std::borrow::Cow<'_, std::path::Path>`] with a
    /// non-`'static` lifetime, requiring [`&BumpLevel`] and losing the
    /// by-value semantics, or dropping the [`std::borrow::Cow`]
    /// wrapper entirely) fails here at compile time instead of at
    /// every downstream generic call site. Structural mirror of
    /// `test_per_attempt_region_into_cow_static_path_carries_through_generic_consumer`
    /// (commit cfb6125) at the per-attempt-region ladder and
    /// `test_admission_tier_into_cow_static_path_carries_through_generic_consumer`
    /// (commit f11faad) at the admission-tier ladder.
    #[test]
    fn test_bump_level_into_cow_static_path_carries_through_generic_consumer() {
        fn read<T: Into<std::borrow::Cow<'static, std::path::Path>>>(
            t: T,
        ) -> std::borrow::Cow<'static, std::path::Path> {
            t.into()
        }

        for level in BumpLevel::ALL {
            let cow = read(level);
            let borrowed: &std::path::Path = &cow;
            assert_eq!(
                borrowed,
                std::path::Path::new(level.as_str()),
                "generic Into<Cow<'static, Path>> consumer must read \
                 canonical label at {level:?}",
            );
        }
    }

    /// [`From<BumpLevel> for std::borrow::Cow<'static, std::path::Path>`]
    /// returns the [`std::borrow::Cow::Borrowed`] branch, not
    /// [`std::borrow::Cow::Owned`], at every [`BumpLevel::ALL`]
    /// variant. Pins the zero-allocation contract at the emit
    /// boundary: because [`BumpLevel::as_str`] returns a
    /// `'static`-lived borrow into the static-string constant table
    /// and [`std::path::Path::new`] preserves the borrow's lifetime,
    /// this impl composes with an
    /// [`Into<std::borrow::Cow<'static, std::path::Path>>`] receiver
    /// at the [`std::borrow::Cow::Borrowed`] branch — the receiver
    /// pays the `'static`-borrow cost of
    /// [`From<BumpLevel> for &'static std::path::Path`], not the
    /// [`std::path::PathBuf`]-allocation cost of
    /// [`From<BumpLevel> for std::path::PathBuf`]. The structural
    /// witness that the impl body picks the load-bearing
    /// [`std::borrow::Cow::Borrowed`] branch — a regression that
    /// drifted the impl body toward
    /// `Cow::Owned(std::path::PathBuf::from(level.as_str()))` would
    /// silently allocate at every emit site and defeat the
    /// borrowed/owned-frontier discipline this impl trio-closes; the
    /// [`matches!`] pin lights up here at ONE named site instead of
    /// leaking to every downstream
    /// `impl Into<Cow<'static, std::path::Path>>` consumer as a
    /// hidden per-call allocation. Sibling of the agreement pin
    /// [`test_bump_level_from_into_cow_static_path_agrees_with_cow_borrowed_path_new_as_str`]
    /// at the label-oracle surface — the two pins together close both
    /// the value-agreement contract and the branch-choice /
    /// zero-allocation contract at the by-value
    /// [`std::borrow::Cow<'static, std::path::Path>`] emit surface,
    /// mirroring the discipline
    /// [`test_bump_level_into_cow_static_os_str_is_borrowed`] carries
    /// at the OS-string frontier. Structural mirror of
    /// `test_per_attempt_region_into_cow_static_path_is_borrowed`
    /// (commit cfb6125) at the per-attempt-region ladder and
    /// `test_admission_tier_into_cow_static_path_is_borrowed`
    /// (commit f11faad) at the admission-tier ladder — closing the
    /// zero-allocation-branch contract at the third and last ordered
    /// typed sum.
    #[test]
    fn test_bump_level_into_cow_static_path_is_borrowed() {
        for level in BumpLevel::ALL {
            let cow: std::borrow::Cow<'static, std::path::Path> = std::borrow::Cow::from(level);
            assert!(
                matches!(cow, std::borrow::Cow::Borrowed(_)),
                "From<BumpLevel> for Cow<'static, Path> must return Cow::Borrowed \
                 (zero-allocation branch) at {level:?}, not Cow::Owned",
            );
        }
    }

    /// At every [`BumpLevel`] variant enumerated by
    /// [`BumpLevel::ALL`],
    /// `<&'static str as From<BumpLevel>>::from(level)` (the
    /// [`From<BumpLevel> for &'static str`] impl body) equals
    /// `level.as_str()` (the canonical-label oracle) exactly. The
    /// load-bearing structural pin that ties the by-value static-
    /// lifetime conversion surface to the shared [`BumpLevel::as_str`]
    /// oracle: a regression that swapped [`From<BumpLevel> for
    /// &'static str`] to route through the [`std::fmt::Display`]
    /// formatter (which cannot return `&'static str` at all —
    /// [`Display`](std::fmt::Display) writes through a
    /// [`std::fmt::Formatter`] into a caller-provided buffer, forcing
    /// a [`String::leak`] or [`Box::leak`] fabrication that would
    /// drift from the canonical-label constant table), or drifted the
    /// [`From`] grammar from [`BumpLevel::as_str`]'s lowercase labels,
    /// fails here at ONE named site instead of leaking to every
    /// downstream consumer that accepts `impl Into<&'static str>`
    /// (release-manifest path-segment builder holding `&'static str`
    /// slots, `phf`-style static lookup table keyed by canonical bump
    /// label, OpenTelemetry / tracing attribute slot,
    /// [`std::borrow::Cow<'static, str>`] sink). Sibling of
    /// [`test_bump_level_as_ref_str_agrees_with_as_str`] at the
    /// byte-slice-coercion surface and
    /// [`test_bump_level_display_round_trips_through_from_str`] at
    /// the format-machinery surface — the three agreement pins
    /// together close the read-side agreement across the by-value
    /// static-lifetime surface ([`From<BumpLevel> for &'static str`]),
    /// the borrow surface ([`AsRef<str>`]), and the format-buffer
    /// surface ([`std::fmt::Display`]) against the shared canonical-
    /// label oracle. Structural mirror of
    /// `test_per_attempt_region_from_into_static_str_agrees_with_as_str`
    /// (commit c8614e9) at the per-attempt-region ladder and
    /// `test_admission_tier_from_into_static_str_agrees_with_as_str`
    /// (commit c041b0b) at the admission-tier ladder.
    #[test]
    fn test_bump_level_from_into_static_str_agrees_with_as_str() {
        for level in BumpLevel::ALL {
            let borrowed: &'static str = <&'static str>::from(level);
            assert_eq!(
                borrowed,
                level.as_str(),
                "From<BumpLevel> for &'static str and as_str must agree at {level:?}",
            );
        }
    }

    /// The [`From<BumpLevel> for &'static str`] identity carries
    /// through a generic `impl Into<&'static str>` consumer at every
    /// [`BumpLevel::ALL`] variant. A tiny generic function
    /// `fn read<T: Into<&'static str>>(t: T) -> &'static str
    /// { t.into() }` — the shape of an actual downstream consumer
    /// (release-manifest path-segment builder holding `&'static str`
    /// slots, `phf`-style static lookup table keyed by canonical bump
    /// label, OpenTelemetry / tracing attribute slot,
    /// [`std::borrow::Cow<'static, str>`] sink) — reads the canonical
    /// lowercase label directly from a [`BumpLevel`] value with
    /// `'static` lifetime preserved end-to-end. The structural
    /// witness that a [`BumpLevel`] is genuinely usable at
    /// `impl Into<&'static str>` call sites — a regression that
    /// drifted the [`From`] impl signature (e.g., returning [`String`]
    /// instead of `&'static str`, or requiring `&BumpLevel` and
    /// losing the `'static` lifetime through a receiver borrow) fails
    /// here at compile time instead of at every downstream generic
    /// call site. Structural mirror of
    /// `test_per_attempt_region_into_static_str_carries_through_generic_consumer`
    /// (commit c8614e9) at the per-attempt-region ladder and
    /// `test_admission_tier_into_static_str_carries_through_generic_consumer`
    /// (commit c041b0b) at the admission-tier ladder.
    #[test]
    fn test_bump_level_into_static_str_carries_through_generic_consumer() {
        fn read<T: Into<&'static str>>(t: T) -> &'static str {
            t.into()
        }

        for level in BumpLevel::ALL {
            assert_eq!(
                read(level),
                level.as_str(),
                "generic Into<&'static str> consumer must read canonical label at {level:?}",
            );
        }
    }

    /// At every [`BumpLevel`] variant enumerated by [`BumpLevel::ALL`],
    /// `<&'static [u8]>::from(level)` (the
    /// [`From<BumpLevel> for &'static [u8]`] impl body) equals
    /// `level.as_str().as_bytes()` (the composition through the
    /// canonical-label oracle and [`str::as_bytes`]). Pins the
    /// agreement identity that the by-value static-lifetime byte-
    /// slice emit surface reads the same canonical label the
    /// borrowed-view surface reads at the byte-slice frontier: a
    /// regression that swapped [`From<BumpLevel> for &'static [u8]`]
    /// to route through an intermediate [`std::fmt::Display`] format
    /// buffer or a fresh [`String`] allocation would fail here at
    /// ONE named site instead of leaking to every downstream
    /// `impl Into<&'static [u8]>` consumer (streaming hasher
    /// preloaded input slot, `phf`-style static byte-key lookup
    /// table, `Cow<'static, [u8]>` sink, etc.). Structural mirror of
    /// [`test_bump_level_from_into_static_str_agrees_with_as_str`]
    /// at the UTF-8 emit surface — the two agreement pins together
    /// close the by-value static-lifetime emit axis across both the
    /// string (`&'static str`) and byte-slice (`&'static [u8]`)
    /// frontiers against the same canonical-label oracle. Structural
    /// mirror of
    /// `test_per_attempt_region_from_into_static_bytes_agrees_with_as_str_as_bytes`
    /// (commit 70e813b) at the per-attempt-region ladder and
    /// `test_admission_tier_from_into_static_bytes_agrees_with_as_str_as_bytes`
    /// (commit 694dff9) at the admission-tier ladder.
    #[test]
    fn test_bump_level_from_into_static_bytes_agrees_with_as_str_as_bytes() {
        for level in BumpLevel::ALL {
            let borrowed: &'static [u8] = <&'static [u8]>::from(level);
            assert_eq!(
                borrowed,
                level.as_str().as_bytes(),
                "From<BumpLevel> for &'static [u8] and as_str().as_bytes() must agree at {level:?}",
            );
        }
    }

    /// The [`From<BumpLevel> for &'static [u8]`] identity carries
    /// through a generic `impl Into<&'static [u8]>` consumer at every
    /// [`BumpLevel::ALL`] variant. A tiny generic function
    /// `fn read<T: Into<&'static [u8]>>(t: T) -> &'static [u8]
    /// { t.into() }` — the shape of an actual downstream consumer
    /// (a hasher factory holding `&'static [u8]` update slots, a
    /// `phf`-style static lookup table keyed by canonical label
    /// bytes, a [`std::borrow::Cow<'static, [u8]>`] sink taking
    /// `Into<Cow<'static, [u8]>>`) — reads the canonical lowercase
    /// label bytes directly from a [`BumpLevel`] value with `'static`
    /// lifetime preserved end-to-end. The structural witness that a
    /// [`BumpLevel`] is genuinely usable at `impl Into<&'static [u8]>`
    /// call sites — a regression that drifted the [`From`] impl
    /// signature (e.g., returning an owned [`Vec<u8>`] instead of
    /// `&'static [u8]`, or requiring `&BumpLevel` and losing the
    /// `'static` lifetime through a receiver borrow) fails here at
    /// compile time instead of at every downstream generic call
    /// site. Structural mirror of
    /// `test_per_attempt_region_into_static_bytes_carries_through_generic_consumer`
    /// (commit 70e813b) at the per-attempt-region ladder and
    /// `test_admission_tier_into_static_bytes_carries_through_generic_consumer`
    /// (commit 694dff9) at the admission-tier ladder.
    #[test]
    fn test_bump_level_into_static_bytes_carries_through_generic_consumer() {
        fn read<T: Into<&'static [u8]>>(t: T) -> &'static [u8] {
            t.into()
        }

        for level in BumpLevel::ALL {
            assert_eq!(
                read(level),
                level.as_str().as_bytes(),
                "generic Into<&'static [u8]> consumer must read canonical label bytes at {level:?}",
            );
        }
    }

    /// At every [`BumpLevel`] variant enumerated by [`BumpLevel::ALL`],
    /// the owned `&'static [u8]` view from the
    /// [`From<BumpLevel> for &'static [u8]`] impl round-trips through
    /// [`std::str::from_utf8`] back to the canonical lowercase label
    /// exactly. Ties the by-value static-lifetime byte frontier to
    /// the UTF-8 frontier through the standard library's UTF-8
    /// validator at ONE named site: a regression that drifted
    /// [`From<BumpLevel> for &'static [u8]`] to yield non-UTF-8
    /// bytes (a numeric-discriminant byte cast, a byte-swapped
    /// label, a mangled encoding) fails here with a
    /// [`std::str::Utf8Error`] at the [`std::str::from_utf8`]
    /// boundary or a label mismatch at the round-trip assertion.
    /// Together with
    /// [`test_bump_level_from_into_static_bytes_agrees_with_as_str_as_bytes`]
    /// this closes the by-value static-lifetime byte-slice emit
    /// surface against both the composition oracle
    /// (`.as_str().as_bytes()`) and the UTF-8 validity oracle
    /// ([`std::str::from_utf8`]) at every [`BumpLevel::ALL`] variant,
    /// matching the discipline the borrowed-view pin
    /// [`test_bump_level_as_ref_bytes_round_trips_through_from_utf8`]
    /// already reads at the [`AsRef<[u8]>`] surface. Structural
    /// mirror of
    /// `test_per_attempt_region_from_into_static_bytes_round_trips_through_from_utf8`
    /// (commit 70e813b) at the per-attempt-region ladder and
    /// `test_admission_tier_from_into_static_bytes_round_trips_through_from_utf8`
    /// (commit 694dff9) at the admission-tier ladder.
    #[test]
    fn test_bump_level_from_into_static_bytes_round_trips_through_from_utf8() {
        for level in BumpLevel::ALL {
            let borrowed: &'static [u8] = <&'static [u8]>::from(level);
            let decoded = std::str::from_utf8(borrowed).unwrap_or_else(|err| {
                panic!(
                    "From<BumpLevel> for &'static [u8] bytes for {level:?} must be valid UTF-8 (got {err})"
                )
            });
            assert_eq!(
                decoded,
                level.as_str(),
                "from_utf8 round-trip must recover canonical label at {level:?}",
            );
        }
    }

    /// At every [`BumpLevel`] variant enumerated by [`BumpLevel::ALL`],
    /// `Vec::<u8>::from(level)` (the [`From<BumpLevel> for Vec<u8>`]
    /// impl body) equals `level.as_str().as_bytes()` (the composition
    /// through the canonical-label oracle and [`str::as_bytes`]). Pins
    /// the agreement identity that the by-value owned-buffer byte-
    /// slice emit surface reads the same canonical label the borrowed-
    /// view [`AsRef<[u8]>`] surface and the by-value static-lifetime
    /// [`From<BumpLevel> for &'static [u8]`] surface already read at
    /// the byte-slice frontier: a regression that swapped the [`From`]
    /// impl body to route through
    /// [`String::from`]-then-[`String::into_bytes`] (adding a
    /// [`String`] growth-header allocation slack), or through a
    /// [`Vec::with_capacity`] + [`Vec::extend_from_slice`] restatement
    /// (over-allocating capacity headroom), or through an intermediate
    /// [`std::fmt::Display`] format buffer, would fail here at ONE
    /// named site instead of leaking to every downstream
    /// `impl Into<Vec<u8>>` consumer (an owned-buffer blob-upload sink,
    /// a `bytes::Bytes::from` bridge, a mutable byte-buffer
    /// accumulator). Structural mirror of
    /// [`test_bump_level_from_into_string_agrees_with_as_str`] at the
    /// UTF-8 owned-buffer emit surface — the two agreement pins
    /// together close the by-value owned-buffer emit axis across both
    /// the string ([`String`]) and byte-slice ([`Vec<u8>`]) frontiers
    /// against the same canonical-label oracle. Structural mirror of
    /// `test_per_attempt_region_from_into_owned_bytes_agrees_with_as_str_as_bytes`
    /// (commit 2ad52bc) at the per-attempt-region ladder and
    /// `test_admission_tier_from_into_owned_bytes_agrees_with_as_str_as_bytes`
    /// (commit 491db4d) at the admission-tier ladder.
    #[test]
    fn test_bump_level_from_into_owned_bytes_agrees_with_as_str_as_bytes() {
        for level in BumpLevel::ALL {
            let owned: Vec<u8> = Vec::<u8>::from(level);
            assert_eq!(
                owned.as_slice(),
                level.as_str().as_bytes(),
                "From<BumpLevel> for Vec<u8> and as_str().as_bytes() must agree at {level:?}",
            );
        }
    }

    /// The [`From<BumpLevel> for Vec<u8>`] identity carries through a
    /// generic `impl Into<Vec<u8>>` consumer at every [`BumpLevel::ALL`]
    /// variant. A tiny generic function
    /// `fn read<T: Into<Vec<u8>>>(t: T) -> Vec<u8> { t.into() }` — the
    /// shape of an actual downstream consumer (an OCI / GHCR blob-
    /// upload sink whose input is an owned [`Vec<u8>`] payload, a
    /// `bytes::Bytes::from` bridge that takes an owned [`Vec<u8>`]
    /// before handing the buffer to a shared-owned reader, a
    /// `reqwest::Body::from` request-body builder over an owned buffer,
    /// a SLSA / sigstore attestation-subject bytes builder that owns
    /// its payload for signing) — reads the canonical lowercase label
    /// bytes directly from a [`BumpLevel`] value as an owned
    /// [`Vec<u8>`]. The structural witness that a [`BumpLevel`] is
    /// genuinely usable at `impl Into<Vec<u8>>` call sites — a
    /// regression that drifted the [`From`] impl signature (returning
    /// `&'static [u8]` instead of `Vec<u8>`, returning a
    /// [`std::borrow::Cow<'_, [u8]>`] wrapper instead of the bare
    /// owned buffer, requiring `&BumpLevel` and losing the by-value
    /// semantics) fails here at compile time instead of at every
    /// downstream generic call site. Structural mirror of
    /// `test_per_attempt_region_into_owned_bytes_carries_through_generic_consumer`
    /// (commit 2ad52bc) at the per-attempt-region ladder and
    /// `test_admission_tier_into_owned_bytes_carries_through_generic_consumer`
    /// (commit 491db4d) at the admission-tier ladder.
    #[test]
    fn test_bump_level_into_owned_bytes_carries_through_generic_consumer() {
        fn read<T: Into<Vec<u8>>>(t: T) -> Vec<u8> {
            t.into()
        }

        for level in BumpLevel::ALL {
            assert_eq!(
                read(level),
                level.as_str().as_bytes(),
                "generic Into<Vec<u8>> consumer must read canonical label bytes at {level:?}",
            );
        }
    }

    /// At every [`BumpLevel`] variant enumerated by [`BumpLevel::ALL`],
    /// the owned [`Vec<u8>`] emitted by
    /// [`From<BumpLevel> for Vec<u8>`] round-trips back through
    /// [`TryFrom<Vec<u8>>`] to the original variant. Ties the by-value
    /// owned-buffer byte-slice emit surface to its byte-slice parse-
    /// side sibling [`TryFrom<Vec<u8>> for BumpLevel`] (commit 5b6f488)
    /// at the same one-oracle discipline: a regression that drifted
    /// the emit impl body toward non-canonical bytes (a byte-swapped
    /// label, a mangled encoding, a numeric-discriminant byte cast) OR
    /// drifted the parse impl body away from the shared
    /// [`std::str::from_utf8`] + [`std::str::FromStr`] composition
    /// fails here at ONE named site instead of leaking to every
    /// downstream owned-byte-buffer round-trip consumer (an OCI / GHCR
    /// annotation-value writer that reads its own emitted label back,
    /// a SLSA / sigstore attestation-subject bytes replay verifier, a
    /// cache-index owned-key re-parse). Together with
    /// [`test_bump_level_from_into_owned_bytes_agrees_with_as_str_as_bytes`]
    /// this closes the by-value owned-buffer byte-slice emit surface
    /// against both the composition oracle (`.as_str().as_bytes()`)
    /// and the round-trip parse oracle ([`TryFrom<Vec<u8>>`]) at every
    /// [`BumpLevel::ALL`] variant, matching the discipline the by-
    /// value static-lifetime pin
    /// [`test_bump_level_from_into_static_bytes_round_trips_through_from_utf8`]
    /// already reads at the `'static`-lifetime byte-slice emit
    /// surface. Structural mirror of
    /// `test_per_attempt_region_from_into_owned_bytes_round_trips_through_try_from`
    /// (commit 2ad52bc) at the per-attempt-region ladder and
    /// `test_admission_tier_from_into_owned_bytes_round_trips_through_try_from`
    /// (commit 491db4d) at the admission-tier ladder.
    #[test]
    fn test_bump_level_from_into_owned_bytes_round_trips_through_try_from() {
        for level in BumpLevel::ALL {
            let owned: Vec<u8> = Vec::<u8>::from(level);
            let parsed = <BumpLevel as std::convert::TryFrom<Vec<u8>>>::try_from(owned)
                .expect("emitted owned bytes must parse through TryFrom<Vec<u8>>");
            assert_eq!(
                parsed, level,
                "From<BumpLevel> for Vec<u8> must round-trip through TryFrom<Vec<u8>> at {level:?}",
            );
        }
    }

    /// At every [`BumpLevel`] variant enumerated by
    /// [`BumpLevel::ALL`], `Cow::<'static, [u8]>::from(level)` (the
    /// [`From<BumpLevel> for Cow<'static, [u8]>`] impl body) yields
    /// the same byte-slice view as `level.as_str().as_bytes()` — the
    /// composition through the canonical-label oracle and
    /// [`str::as_bytes`]. Pins the agreement identity that the by-
    /// value borrowed/owned-frontier byte-slice emit surface reads
    /// the same canonical label the [`&'static [u8]`] emit surface
    /// and the borrowed-view [`AsRef<[u8]>`] surface already read at
    /// the byte-slice frontier. Structural mirror of the
    /// [`Cow<'static, str>`] agreement pin
    /// [`test_bump_level_from_into_cow_static_str_agrees_with_as_str`]
    /// at the UTF-8 frontier — the two agreement pins together close
    /// the by-value borrowed/owned-frontier emit axis across both
    /// string and byte frontiers against the same oracle. Structural
    /// mirror of
    /// `test_per_attempt_region_from_into_cow_static_bytes_agrees_with_as_str_as_bytes`
    /// (commit 912a5ff) at the per-attempt-region ladder and
    /// `test_admission_tier_from_into_cow_static_bytes_agrees_with_as_str_as_bytes`
    /// (commit 89af285) at the admission-tier ladder.
    #[test]
    fn test_bump_level_from_into_cow_static_bytes_agrees_with_as_str_as_bytes() {
        for level in BumpLevel::ALL {
            let cow: std::borrow::Cow<'static, [u8]> = std::borrow::Cow::from(level);
            assert_eq!(
                cow.as_ref(),
                level.as_str().as_bytes(),
                "From<BumpLevel> for Cow<'static, [u8]> and as_str().as_bytes() must agree at {level:?}",
            );
        }
    }

    /// The [`From<BumpLevel> for Cow<'static, [u8]>`] identity
    /// carries through a generic `impl Into<Cow<'static, [u8]>>`
    /// consumer at every [`BumpLevel::ALL`] variant. A tiny generic
    /// function `fn read<T: Into<Cow<'static, [u8]>>>(t: T) ->
    /// Cow<'static, [u8]> { t.into() }` — the shape of an actual
    /// downstream consumer (a SLSA / sigstore attestation-subject
    /// bytes sink, an OCI / GHCR manifest annotation-value sink, a
    /// `blake3` hasher factory keyed on either a static label or a
    /// caller-owned [`Vec<u8>`] uniformly) — reads the canonical
    /// lowercase label bytes directly from a [`BumpLevel`] value
    /// with the `'static` lifetime preserved through the
    /// [`Cow<'static, [u8]>`] wrapper. A regression that drifted
    /// the [`From`] impl signature (returning `Cow<'_, [u8]>` with
    /// a non-`'static` lifetime, returning an owned [`Vec<u8>`]
    /// instead of the [`Cow`] wrapper, requiring `&BumpLevel` and
    /// losing the by-value semantics) fails here at compile time
    /// instead of at every downstream generic call site. Structural
    /// mirror of
    /// `test_per_attempt_region_into_cow_static_bytes_carries_through_generic_consumer`
    /// (commit 912a5ff) at the per-attempt-region ladder and
    /// `test_admission_tier_into_cow_static_bytes_carries_through_generic_consumer`
    /// (commit 89af285) at the admission-tier ladder.
    #[test]
    fn test_bump_level_into_cow_static_bytes_carries_through_generic_consumer() {
        fn read<T: Into<std::borrow::Cow<'static, [u8]>>>(t: T) -> std::borrow::Cow<'static, [u8]> {
            t.into()
        }

        for level in BumpLevel::ALL {
            assert_eq!(
                read(level).as_ref(),
                level.as_str().as_bytes(),
                "generic Into<Cow<'static, [u8]>> consumer must read canonical label bytes at {level:?}",
            );
        }
    }

    /// [`From<BumpLevel> for Cow<'static, [u8]>`] returns the
    /// [`std::borrow::Cow::Borrowed`] branch, not
    /// [`std::borrow::Cow::Owned`], at every [`BumpLevel::ALL`]
    /// variant. Pins the zero-allocation contract at the emit
    /// boundary: because [`BumpLevel::as_str`] returns a
    /// `'static`-lived borrow into the static-string constant table
    /// and [`str::as_bytes`] preserves the receiver's lifetime, this
    /// impl composes with an [`Into<Cow<'static, [u8]>>`] receiver
    /// at the [`std::borrow::Cow::Borrowed`] branch — the receiver
    /// pays the `'static`-borrow cost of
    /// [`From<BumpLevel> for &'static [u8]`], not the [`Vec<u8>`]-
    /// allocation cost a [`std::borrow::Cow::Owned`] branch would
    /// silently pay. A regression that drifted the impl body toward
    /// `Cow::Owned(level.as_str().as_bytes().to_vec())` would
    /// silently allocate at every byte-oriented emit site and defeat
    /// the borrowed/owned-frontier discipline this impl closes.
    /// Structural mirror of the [`Cow<'static, str>`] pin
    /// [`test_bump_level_into_cow_static_str_is_borrowed`] at the
    /// UTF-8 frontier — the two pins together close the zero-
    /// allocation branch-choice contract across both string and
    /// byte-slice frontiers. Structural mirror of
    /// `test_per_attempt_region_into_cow_static_bytes_is_borrowed`
    /// (commit 912a5ff) at the per-attempt-region ladder and
    /// `test_admission_tier_into_cow_static_bytes_is_borrowed`
    /// (commit 89af285) at the admission-tier ladder.
    #[test]
    fn test_bump_level_into_cow_static_bytes_is_borrowed() {
        for level in BumpLevel::ALL {
            let cow: std::borrow::Cow<'static, [u8]> = std::borrow::Cow::from(level);
            assert!(
                matches!(cow, std::borrow::Cow::Borrowed(_)),
                "From<BumpLevel> for Cow<'static, [u8]> must return Cow::Borrowed \
                 (zero-allocation branch) at {level:?}, not Cow::Owned",
            );
        }
    }

    /// At every [`BumpLevel`] variant enumerated by [`BumpLevel::ALL`],
    /// `Box::<[u8]>::from(level)` (the
    /// [`From<BumpLevel> for Box<[u8]>`] impl body) yields the same
    /// byte-slice view as `level.as_str().as_bytes()` — the composition
    /// through the canonical-label oracle and [`str::as_bytes`]. Pins
    /// the agreement identity that the by-value shrunk-owned byte-slice
    /// emit surface reads the same canonical label the borrowed-view
    /// [`AsRef<[u8]>`], the by-value static-lifetime
    /// [`From<BumpLevel> for &'static [u8]`], the by-value owned-buffer
    /// [`From<BumpLevel> for Vec<u8>`], and the by-value borrowed/
    /// owned-frontier [`From<BumpLevel> for Cow<'static, [u8]>`]
    /// surfaces already read at the byte-slice frontier. Structural
    /// mirror of the [`Box<str>`] agreement pin
    /// [`test_bump_level_into_box_str_agrees_with_as_str`] at the UTF-8
    /// frontier — the two agreement pins together close the by-value
    /// shrunk-owned emit axis across both string and byte-slice
    /// frontiers against the same oracle. A regression that swapped the
    /// [`From`] impl body to route through
    /// `level.as_str().as_bytes().to_vec().into_boxed_slice()` (paying
    /// a [`Vec<u8>`] growth-header allocation plus a
    /// [`Vec::into_boxed_slice`] realloc-and-shrink round trip) or
    /// through [`String::from`]-then-[`String::into_bytes`]-then-
    /// [`Vec::into_boxed_slice`] (adding a [`String`] growth-header
    /// allocation on top) fails here at ONE named site instead of
    /// leaking to every downstream `impl Into<Box<[u8]>>` consumer.
    /// Structural mirror of
    /// `test_per_attempt_region_from_into_boxed_bytes_agrees_with_as_str_as_bytes`
    /// (commit 7045474) at the per-attempt-region ladder and
    /// `test_admission_tier_from_into_boxed_bytes_agrees_with_as_str_as_bytes`
    /// (commit e78e47a) at the admission-tier ladder.
    #[test]
    fn test_bump_level_from_into_boxed_bytes_agrees_with_as_str_as_bytes() {
        for level in BumpLevel::ALL {
            let boxed: Box<[u8]> = Box::<[u8]>::from(level);
            assert_eq!(
                boxed.as_ref(),
                level.as_str().as_bytes(),
                "From<BumpLevel> for Box<[u8]> and as_str().as_bytes() must agree at {level:?}",
            );
        }
    }

    /// The [`From<BumpLevel> for Box<[u8]>`] identity carries through a
    /// generic `impl Into<Box<[u8]>>` consumer at every
    /// [`BumpLevel::ALL`] variant. A tiny generic function
    /// `fn read<T: Into<Box<[u8]>>>(t: T) -> Box<[u8]> { t.into() }` —
    /// the shape of an actual downstream consumer (a validated-input
    /// newtype whose byte-slice payload field is typed [`Box<[u8]>`], a
    /// `phf`-style keyed-table byte-key value slot at the shrunk-owned
    /// frontier, an SLSA / sigstore attestation-subject bytes builder
    /// whose payload sink is typed as an immutable heap-owned byte
    /// slice, an OCI / GHCR annotation-value sink that owns the label
    /// bytes without the [`Vec<u8>`] growth-header cost) — reads the
    /// canonical lowercase label bytes directly from a [`BumpLevel`]
    /// value as an immutable heap-owned [`Box<[u8]>`]. The structural
    /// witness that a [`BumpLevel`] is genuinely usable at
    /// `impl Into<Box<[u8]>>` call sites — a regression that drifted
    /// the [`From`] impl signature (returning [`Vec<u8>`] instead of
    /// [`Box<[u8]>`], returning a [`std::borrow::Cow<'_, [u8]>`]
    /// wrapper instead of the bare boxed slice, requiring
    /// `&BumpLevel` and losing the by-value semantics) fails here at
    /// compile time instead of at every downstream generic call site.
    /// Structural mirror of
    /// `test_per_attempt_region_into_boxed_bytes_carries_through_generic_consumer`
    /// (commit 7045474) at the per-attempt-region ladder and
    /// `test_admission_tier_into_boxed_bytes_carries_through_generic_consumer`
    /// (commit e78e47a) at the admission-tier ladder.
    #[test]
    fn test_bump_level_into_boxed_bytes_carries_through_generic_consumer() {
        fn read<T: Into<Box<[u8]>>>(t: T) -> Box<[u8]> {
            t.into()
        }

        for level in BumpLevel::ALL {
            assert_eq!(
                read(level).as_ref(),
                level.as_str().as_bytes(),
                "generic Into<Box<[u8]>> consumer must read canonical label bytes at {level:?}",
            );
        }
    }

    /// At every [`BumpLevel`] variant enumerated by [`BumpLevel::ALL`],
    /// the shrunk-owned [`Box<[u8]>`] emitted by
    /// [`From<BumpLevel> for Box<[u8]>`] decodes back through
    /// [`std::str::from_utf8`] to [`BumpLevel::as_str`]. Pins that the
    /// emitted bytes are valid UTF-8 and equal the canonical label
    /// bytes at the standard library's UTF-8 validator at ONE named
    /// site: a regression that drifted [`From<BumpLevel> for Box<[u8]>`]
    /// to yield non-UTF-8 bytes (a numeric-discriminant byte cast, a
    /// byte-swapped label, a mangled encoding) fails here with a
    /// [`std::str::Utf8Error`] at the [`std::str::from_utf8`] boundary
    /// or a label mismatch at the round-trip assertion. Together with
    /// [`test_bump_level_from_into_boxed_bytes_agrees_with_as_str_as_bytes`]
    /// this closes the by-value shrunk-owned byte-slice emit surface
    /// against both the composition oracle (`.as_str().as_bytes()`)
    /// and the UTF-8 validity oracle ([`std::str::from_utf8`]) at
    /// every [`BumpLevel::ALL`] variant, matching the discipline the
    /// by-value static-lifetime pin
    /// [`test_bump_level_from_into_static_bytes_round_trips_through_from_utf8`]
    /// and the borrowed-view pin
    /// [`test_bump_level_as_ref_bytes_round_trips_through_from_utf8`]
    /// already read at the [`&'static [u8]`] and [`AsRef<[u8]>`]
    /// surfaces. Structural mirror of
    /// `test_per_attempt_region_from_into_boxed_bytes_round_trips_through_from_utf8`
    /// (commit 7045474) at the per-attempt-region ladder and
    /// `test_admission_tier_from_into_boxed_bytes_round_trips_through_from_utf8`
    /// (commit e78e47a) at the admission-tier ladder.
    #[test]
    fn test_bump_level_from_into_boxed_bytes_round_trips_through_from_utf8() {
        for level in BumpLevel::ALL {
            let boxed: Box<[u8]> = Box::<[u8]>::from(level);
            let decoded = std::str::from_utf8(&boxed).unwrap_or_else(|err| {
                panic!(
                    "From<BumpLevel> for Box<[u8]> bytes for {level:?} must be valid UTF-8 (got {err})"
                )
            });
            assert_eq!(
                decoded,
                level.as_str(),
                "from_utf8 round-trip must recover canonical label at {level:?}",
            );
        }
    }

    /// At every [`BumpLevel`] variant enumerated by [`BumpLevel::ALL`],
    /// `Arc::<[u8]>::from(level)` (the
    /// [`From<BumpLevel> for Arc<[u8]>`] impl body) yields the same
    /// byte-slice view as `level.as_str().as_bytes()` — the composition
    /// through the canonical-label oracle and [`str::as_bytes`]. Pins
    /// the agreement identity that the by-value shared-owned byte-
    /// slice emit surface reads the same canonical label the borrowed-
    /// view [`AsRef<[u8]>`], the by-value static-lifetime
    /// [`From<BumpLevel> for &'static [u8]`], the by-value owned-buffer
    /// [`From<BumpLevel> for Vec<u8>`], the by-value borrowed/owned-
    /// frontier [`From<BumpLevel> for Cow<'static, [u8]>`], and the
    /// by-value shrunk-owned [`From<BumpLevel> for Box<[u8]>`]
    /// surfaces already read at the byte-slice frontier. Structural
    /// mirror of the [`Arc<str>`] agreement pin
    /// [`test_bump_level_into_arc_str_agrees_with_as_str`] at the UTF-8
    /// frontier — the two agreement pins together close the by-value
    /// shared-owned emit axis across both string and byte-slice
    /// frontiers against the same oracle. A regression that swapped
    /// the [`From`] impl body to route through
    /// `Arc::from(Box::<[u8]>::from(level.as_str().as_bytes()))`
    /// (paying an extra [`Box<[u8]>`] allocation before the
    /// [`Arc<[u8]>`] rewrap) or through
    /// `Arc::from(level.as_str().as_bytes().to_vec().into_boxed_slice())`
    /// (paying a [`Vec<u8>`] growth-header allocation plus a
    /// [`Vec::into_boxed_slice`] realloc-and-shrink round trip before
    /// the [`Arc<[u8]>`] rewrap) fails here at ONE named site instead
    /// of leaking to every downstream `impl Into<Arc<[u8]>>` consumer.
    /// Structural mirror of
    /// `test_per_attempt_region_into_arc_bytes_agrees_with_as_str_as_bytes`
    /// (commit c922ae1) at the per-attempt-region ladder and
    /// `test_admission_tier_into_arc_bytes_agrees_with_as_str_as_bytes`
    /// (commit 5e869fc) at the admission-tier ladder.
    #[test]
    fn test_bump_level_into_arc_bytes_agrees_with_as_str_as_bytes() {
        for level in BumpLevel::ALL {
            let shared: std::sync::Arc<[u8]> = std::sync::Arc::<[u8]>::from(level);
            assert_eq!(
                shared.as_ref(),
                level.as_str().as_bytes(),
                "From<BumpLevel> for Arc<[u8]> and as_str().as_bytes() must agree at {level:?}",
            );
        }
    }

    /// The [`From<BumpLevel> for Arc<[u8]>`] identity carries through a
    /// generic `impl Into<Arc<[u8]>>` consumer at every
    /// [`BumpLevel::ALL`] variant. A tiny generic function
    /// `fn read<T: Into<Arc<[u8]>>>(t: T) -> Arc<[u8]> { t.into() }` —
    /// the shape of an actual downstream consumer (a cross-thread
    /// cached-payload slot typed as [`Arc<[u8]>`] to share a canonical
    /// byte-payload allocation across worker threads via atomic
    /// refcount, a validated-input newtype wrapper that stores
    /// canonical label bytes as [`Arc<[u8]>`] to hand cheap
    /// [`Arc::clone`]s to sibling structures, a serde container that
    /// opts into `#[serde(from = "Arc<[u8]>")]` at the shared-owned
    /// byte-frontier, a dashmap-style keyed-table byte-value slot
    /// whose readers want an [`Arc`] clone rather than a per-lookup
    /// allocation, an SLSA / sigstore attestation-subject bytes
    /// builder that shares the signed payload across a signing-and-
    /// verification worker pool) reads the canonical lowercase label
    /// bytes directly from a [`BumpLevel`] value as a shared-owned
    /// immutable heap-owned [`Arc<[u8]>`]. The structural witness that
    /// a [`BumpLevel`] is genuinely usable at `impl Into<Arc<[u8]>>`
    /// call sites — a regression that drifted the [`From`] impl
    /// signature (returning [`Box<[u8]>`] instead of [`Arc<[u8]>`],
    /// returning a [`Vec<u8>`] instead of the shared-owned handle,
    /// requiring `&BumpLevel` and losing the by-value semantics, or
    /// dropping to a [`Box<[u8]>`]-then-[`Arc::from`] composition that
    /// would allocate twice) fails here at compile time or at the
    /// assertion instead of at every downstream generic call site.
    /// Structural mirror of
    /// `test_per_attempt_region_into_arc_bytes_carries_through_generic_consumer`
    /// (commit c922ae1) at the per-attempt-region ladder and
    /// `test_admission_tier_into_arc_bytes_carries_through_generic_consumer`
    /// (commit 5e869fc) at the admission-tier ladder.
    #[test]
    fn test_bump_level_into_arc_bytes_carries_through_generic_consumer() {
        fn read<T: Into<std::sync::Arc<[u8]>>>(t: T) -> std::sync::Arc<[u8]> {
            t.into()
        }

        for level in BumpLevel::ALL {
            assert_eq!(
                read(level).as_ref(),
                level.as_str().as_bytes(),
                "generic Into<Arc<[u8]>> consumer must read canonical label bytes at {level:?}",
            );
        }
    }

    /// The [`From<BumpLevel> for Arc<[u8]>`] shared-owned semantics
    /// hold across [`std::sync::Arc::clone`] at every
    /// [`BumpLevel::ALL`] variant: the clone reads exactly the same
    /// canonical lowercase label bytes the original reads, points at
    /// the same allocation (identity of the underlying byte pointer
    /// via [`std::sync::Arc::ptr_eq`]), and the atomic refcount lifts
    /// to at least two after the clone (via
    /// [`std::sync::Arc::strong_count`]). Pins the shared-owned
    /// receiver contract at the byte-slice emit surface — a
    /// regression that drifted the impl body to a non-`Arc`
    /// composition ([`Box::<[u8]>::from`]-then-ad-hoc-rewrap, a
    /// [`Vec<u8>`] intermediate) would break the pointer-identity
    /// assertion (each clone would land at a distinct allocation) even
    /// if the canonical-label bytes still agreed. Structural mirror of
    /// the [`Arc<str>`] clone-identity pin
    /// [`test_bump_level_into_arc_str_shares_label_across_clones`] at
    /// the UTF-8 frontier — the two clone-identity pins together close
    /// the structural witness that the receiver actually holds a
    /// shared-owned [`Arc<[u8]>`] slot rather than an [`Arc<[u8]>`]-
    /// typed wrapper around a per-clone-allocated [`Box<[u8]>`],
    /// across both string and byte-slice frontiers. Structural mirror
    /// of
    /// `test_per_attempt_region_into_arc_bytes_shares_label_across_clones`
    /// (commit c922ae1) at the per-attempt-region ladder and
    /// `test_admission_tier_into_arc_bytes_shares_label_across_clones`
    /// (commit 5e869fc) at the admission-tier ladder.
    #[test]
    fn test_bump_level_into_arc_bytes_shares_label_across_clones() {
        for level in BumpLevel::ALL {
            let shared: std::sync::Arc<[u8]> = std::sync::Arc::<[u8]>::from(level);
            let cloned = std::sync::Arc::clone(&shared);
            assert_eq!(
                cloned.as_ref(),
                level.as_str().as_bytes(),
                "Arc<[u8]> clone must read canonical label bytes at {level:?}",
            );
            assert!(
                std::sync::Arc::ptr_eq(&shared, &cloned),
                "Arc<[u8]> clone must share the same underlying allocation at {level:?}",
            );
            assert!(
                std::sync::Arc::strong_count(&shared) >= 2,
                "Arc<[u8]> strong count must be at least 2 after clone at {level:?}",
            );
        }
    }

    /// At every [`BumpLevel`] variant enumerated by
    /// [`BumpLevel::ALL`], `Rc::<[u8]>::from(level)` (the
    /// [`From<BumpLevel> for Rc<[u8]>`] impl body) yields the same
    /// byte-slice view as `level.as_str().as_bytes()` — the
    /// composition through the canonical-label oracle and
    /// [`str::as_bytes`]. Pins the agreement identity that the by-
    /// value thread-local shared-owned byte-slice emit surface reads
    /// the same canonical label the borrowed-view [`AsRef<[u8]>`],
    /// the by-value static-lifetime
    /// [`From<BumpLevel> for &'static [u8]`], the by-value owned-
    /// buffer [`From<BumpLevel> for Vec<u8>`], the by-value
    /// borrowed/owned-frontier
    /// [`From<BumpLevel> for Cow<'static, [u8]>`], the by-value
    /// shrunk-owned [`From<BumpLevel> for Box<[u8]>`], and the by-
    /// value atomic-shared-owned
    /// [`From<BumpLevel> for Arc<[u8]>`] surfaces already read at
    /// the byte-slice frontier. Structural mirror of the [`Rc<str>`]
    /// agreement pin
    /// [`test_bump_level_into_rc_str_agrees_with_as_str`] at the
    /// UTF-8 frontier — the two agreement pins together close the
    /// by-value thread-local shared-owned emit axis across both
    /// string and byte-slice frontiers against the same oracle. A
    /// regression that swapped the [`From`] impl body to route
    /// through `Rc::from(Box::<[u8]>::from(level.as_str().as_bytes()))`
    /// (paying an extra [`Box<[u8]>`] allocation before the
    /// [`Rc<[u8]>`] rewrap) or through
    /// `Rc::from(level.as_str().as_bytes().to_vec().into_boxed_slice())`
    /// (paying a [`Vec<u8>`] growth-header allocation plus a
    /// [`Vec::into_boxed_slice`] realloc-and-shrink round trip before
    /// the [`Rc<[u8]>`] rewrap) fails here at ONE named site instead
    /// of leaking to every downstream `impl Into<Rc<[u8]>>` consumer.
    /// Structural mirror of
    /// `test_per_attempt_region_into_rc_bytes_agrees_with_as_str_as_bytes`
    /// (commit b27865d) at the per-attempt-region ladder and
    /// `test_admission_tier_into_rc_bytes_agrees_with_as_str_as_bytes`
    /// (commit e621a28) at the admission-tier ladder.
    #[test]
    fn test_bump_level_into_rc_bytes_agrees_with_as_str_as_bytes() {
        for level in BumpLevel::ALL {
            let shared: std::rc::Rc<[u8]> = std::rc::Rc::<[u8]>::from(level);
            assert_eq!(
                shared.as_ref(),
                level.as_str().as_bytes(),
                "From<BumpLevel> for Rc<[u8]> and as_str().as_bytes() must agree at {level:?}",
            );
        }
    }

    /// The [`From<BumpLevel> for Rc<[u8]>`] identity carries through
    /// a generic `impl Into<Rc<[u8]>>` consumer at every
    /// [`BumpLevel::ALL`] variant. A tiny generic function
    /// `fn read<T: Into<Rc<[u8]>>>(t: T) -> Rc<[u8]> { t.into() }` —
    /// the shape of an actual downstream consumer (a thread-local
    /// cached-payload slot typed as [`Rc<[u8]>`] to share a canonical
    /// byte-payload allocation within one worker thread via non-
    /// atomic refcount, a validated-input newtype wrapper that stores
    /// canonical label bytes as [`Rc<[u8]>`] to hand cheap
    /// [`Rc::clone`]s to sibling structures on the same thread, a
    /// serde container that opts into `#[serde(from = "Rc<[u8]>")]`
    /// at the thread-local shared-owned byte-frontier, a per-
    /// request-arena byte-value slot whose readers want an [`Rc`]
    /// clone rather than a per-lookup allocation on a single-threaded
    /// pipeline stage, a same-thread SLSA / sigstore attestation-
    /// subject bytes builder that shares the signed payload within a
    /// single-threaded signing pipeline) reads the canonical
    /// lowercase label bytes directly from a [`BumpLevel`] value as
    /// a thread-local shared-owned immutable heap-owned [`Rc<[u8]>`].
    /// The structural witness that a [`BumpLevel`] is genuinely
    /// usable at `impl Into<Rc<[u8]>>` call sites — a regression that
    /// drifted the [`From`] impl signature (returning [`Box<[u8]>`]
    /// instead of [`Rc<[u8]>`], returning [`Arc<[u8]>`] and paying
    /// the atomic-refcount cost at every clone, returning a
    /// [`Vec<u8>`] instead of the shared-owned handle, requiring
    /// `&BumpLevel` and losing the by-value semantics, or dropping to
    /// a [`Box<[u8]>`]-then-[`Rc::from`] composition that would
    /// allocate twice) fails here at compile time or at the assertion
    /// instead of at every downstream generic call site. Structural
    /// mirror of
    /// `test_per_attempt_region_into_rc_bytes_carries_through_generic_consumer`
    /// (commit b27865d) at the per-attempt-region ladder and
    /// `test_admission_tier_into_rc_bytes_carries_through_generic_consumer`
    /// (commit e621a28) at the admission-tier ladder.
    #[test]
    fn test_bump_level_into_rc_bytes_carries_through_generic_consumer() {
        fn read<T: Into<std::rc::Rc<[u8]>>>(t: T) -> std::rc::Rc<[u8]> {
            t.into()
        }

        for level in BumpLevel::ALL {
            assert_eq!(
                read(level).as_ref(),
                level.as_str().as_bytes(),
                "generic Into<Rc<[u8]>> consumer must read canonical label bytes at {level:?}",
            );
        }
    }

    /// The [`From<BumpLevel> for Rc<[u8]>`] thread-local shared-
    /// owned semantics hold across [`std::rc::Rc::clone`] at every
    /// [`BumpLevel::ALL`] variant: the clone reads exactly the same
    /// canonical lowercase label bytes the original reads, points at
    /// the same allocation (identity of the underlying byte pointer
    /// via [`std::rc::Rc::ptr_eq`]), and the non-atomic refcount
    /// lifts to at least two after the clone (via
    /// [`std::rc::Rc::strong_count`]). Pins the thread-local shared-
    /// owned receiver contract at the byte-slice emit surface — a
    /// regression that drifted the impl body to a non-`Rc`
    /// composition ([`Box::<[u8]>::from`]-then-ad-hoc-rewrap, a
    /// [`Vec<u8>`] intermediate) would break the pointer-identity
    /// assertion (each clone would land at a distinct allocation)
    /// even if the canonical-label bytes still agreed. Structural
    /// mirror of the [`Rc<str>`] clone-identity pin
    /// [`test_bump_level_into_rc_str_shares_label_across_clones`] at
    /// the UTF-8 frontier and of the [`Arc<[u8]>`] clone-identity
    /// pin
    /// [`test_bump_level_into_arc_bytes_shares_label_across_clones`]
    /// at the atomic-shared-owned byte-slice frontier — the three
    /// pins together close the structural witness that the receiver
    /// actually holds a thread-local shared-owned [`Rc<[u8]>`] slot
    /// rather than an [`Rc<[u8]>`]-typed wrapper around a per-clone-
    /// allocated [`Box<[u8]>`], across both refcount disciplines and
    /// both string and byte-slice frontiers. Structural mirror of
    /// `test_per_attempt_region_into_rc_bytes_shares_label_across_clones`
    /// (commit b27865d) at the per-attempt-region ladder and
    /// `test_admission_tier_into_rc_bytes_shares_label_across_clones`
    /// (commit e621a28) at the admission-tier ladder.
    #[test]
    fn test_bump_level_into_rc_bytes_shares_label_across_clones() {
        for level in BumpLevel::ALL {
            let shared: std::rc::Rc<[u8]> = std::rc::Rc::<[u8]>::from(level);
            let cloned = std::rc::Rc::clone(&shared);
            assert_eq!(
                cloned.as_ref(),
                level.as_str().as_bytes(),
                "Rc<[u8]> clone must read canonical label bytes at {level:?}",
            );
            assert!(
                std::rc::Rc::ptr_eq(&shared, &cloned),
                "Rc<[u8]> clone must share the same underlying allocation at {level:?}",
            );
            assert!(
                std::rc::Rc::strong_count(&shared) >= 2,
                "Rc<[u8]> strong count must be at least 2 after clone at {level:?}",
            );
        }
    }

    /// [`TryFrom<&[u8]> for BumpLevel`] recovers the original variant
    /// at every [`BumpLevel::ALL`] variant when the canonical label
    /// bytes emitted by `level.as_str().as_bytes()` are fed back
    /// through it. Pins the round-trip identity
    /// `BumpLevel::try_from(level.as_str().as_bytes()).unwrap()
    /// == level` at every variant against the shared
    /// [`BumpLevel::as_str`] + [`str::as_bytes`] canonical-label-
    /// bytes oracle. The structural witness that the by-reference
    /// byte-slice try-conversion parse surface (this
    /// [`TryFrom<&[u8]>`]) reads the same one-oracle grammar the
    /// by-value emit surface [`From<BumpLevel> for &'static [u8]`],
    /// the by-value borrowed/owned-frontier emit surface
    /// [`From<BumpLevel> for Cow<'static, [u8]>`], and the borrowed-
    /// view surface [`AsRef<[u8]>`] write — one round-trip pin per
    /// variant, refuses a future variant insertion that drops the
    /// `TryFrom<&[u8]>`/`as_str().as_bytes()` agreement. Structural
    /// mirror of
    /// `test_per_attempt_region_try_from_bytes_agrees_with_from_str`
    /// (commit 5c0c827) at the per-attempt-region ladder and
    /// `test_admission_tier_try_from_bytes_agrees_with_from_str`
    /// (commit cdb192c) at the admission-tier ladder.
    #[test]
    fn test_bump_level_try_from_bytes_agrees_with_from_str() {
        for level in BumpLevel::ALL {
            let parsed =
                <BumpLevel as std::convert::TryFrom<&[u8]>>::try_from(level.as_str().as_bytes())
                    .expect("canonical label bytes must parse through TryFrom<&[u8]>");
            assert_eq!(
                parsed, level,
                "TryFrom<&[u8]> must round-trip through as_str().as_bytes() at {level:?}",
            );
        }
    }

    /// The [`TryFrom<&[u8]> for BumpLevel`] identity carries through
    /// a generic `impl for<'a> TryFrom<&'a [u8]>` consumer at every
    /// [`BumpLevel::ALL`] variant. A tiny generic function
    /// `fn parse<T>(b: &[u8]) -> T where T: for<'a>
    /// TryFrom<&'a [u8]>, T::Error: std::fmt::Debug` — the shape of
    /// an actual downstream consumer (a `memchr`-driven line-
    /// splitter, an OCI / GHCR manifest annotation-value reader that
    /// surfaces `&[u8]` payloads, a SLSA / sigstore attestation-
    /// subject bytes reader, a `nom` / `winnow` byte-parser
    /// combinator) — recovers the canonical variant from the
    /// canonical lowercase label byte-sequence at every variant.
    /// The structural witness that a [`BumpLevel`] is genuinely
    /// usable at `impl for<'a> TryFrom<&'a [u8]>` call sites — a
    /// regression that drifted the [`TryFrom`] impl signature
    /// (requiring an owned [`Vec<u8>`] input, returning a different
    /// variant than [`FromStr`] would, dropping the UTF-8 decode
    /// step and misparsing non-UTF-8 input) fails here at compile
    /// time or at the assertion instead of at every downstream
    /// generic call site. Structural mirror of
    /// `test_per_attempt_region_try_from_bytes_carries_through_generic_consumer`
    /// (commit 5c0c827) at the per-attempt-region ladder and
    /// `test_admission_tier_try_from_bytes_carries_through_generic_consumer`
    /// (commit cdb192c) at the admission-tier ladder.
    #[test]
    fn test_bump_level_try_from_bytes_carries_through_generic_consumer() {
        fn parse<T>(b: &[u8]) -> T
        where
            T: for<'a> std::convert::TryFrom<&'a [u8]>,
            for<'a> <T as std::convert::TryFrom<&'a [u8]>>::Error: std::fmt::Debug,
        {
            <T as std::convert::TryFrom<&[u8]>>::try_from(b)
                .expect("canonical label bytes must parse through generic TryFrom<&[u8]>")
        }

        for level in BumpLevel::ALL {
            assert_eq!(
                parse::<BumpLevel>(level.as_str().as_bytes()),
                level,
                "generic TryFrom<&[u8]> consumer must recover canonical variant at {level:?}",
            );
        }
    }

    /// [`TryFrom<&[u8]> for BumpLevel`] rejects non-UTF-8 byte
    /// sequences at the [`std::str::from_utf8`] decode frontier.
    /// Pins the encoding-strictness contract at the byte-slice
    /// frontier's first strictness gate so a downstream consumer
    /// bound by [`TryFrom<&[u8]>`] (a `memchr`-driven line-splitter
    /// over an unknown-encoding input buffer, an OCI / GHCR
    /// manifest annotation-value reader that surfaces raw byte
    /// payloads, a byte-slice classifier that composes over the
    /// `TryFrom<&[u8]>` contract) inherits the same UTF-8-only
    /// encoding discipline a direct [`std::str::from_utf8`] +
    /// [`str::parse`] composition would offer, at ONE typed-
    /// primitive site rather than a per-consumer two-step
    /// restatement. A regression that dropped the UTF-8 decode
    /// step (e.g., a naive `unsafe { from_utf8_unchecked }`) would
    /// light up here rather than drifting silently to a mis-parsed
    /// variant. Structural mirror of
    /// `test_per_attempt_region_try_from_bytes_rejects_non_utf8_input`
    /// (commit 5c0c827) at the per-attempt-region ladder and
    /// `test_admission_tier_try_from_bytes_rejects_non_utf8_input`
    /// (commit cdb192c) at the admission-tier ladder.
    #[test]
    fn test_bump_level_try_from_bytes_rejects_non_utf8_input() {
        for bad in [
            &[0xffu8][..],
            &[0xffu8, 0xfe][..],
            &[0x80][..],
            &[b'p', b'a', 0xff, b'c', b'h'][..],
            &[b'm', b'a', b'j', b'o', b'r', 0xff][..],
        ] {
            assert!(
                <BumpLevel as std::convert::TryFrom<&[u8]>>::try_from(bad).is_err(),
                "TryFrom<&[u8]> must reject non-UTF-8 input {bad:?}",
            );
        }
    }

    /// [`TryFrom<&[u8]> for BumpLevel`] rejects valid-UTF-8 non-
    /// canonical byte sequences at the underlying [`FromStr`]
    /// strictness gate — empty byte sequence, UpperCamel rendering,
    /// uppercase, and whitespace-padded lowercase labels all reject.
    /// Pins the canonical-label strictness contract at the byte-
    /// slice frontier's second strictness gate so a downstream
    /// consumer bound by [`TryFrom<&[u8]>`] inherits the same
    /// canonical-only grammar the direct `.parse::<BumpLevel>()`
    /// call sites and the sibling [`TryFrom<&str>`] impl already
    /// read, and a future permissive-parse regression at the
    /// underlying [`FromStr`] impl lights up here rather than
    /// drifting silently through the byte-slice try-conversion
    /// surface. Sibling of the UTF-8-frontier pin
    /// [`test_bump_level_try_from_str_rejects_non_canonical_input`]
    /// at the by-reference UTF-8 parse peer — the two pins together
    /// close the canonical-only strictness contract across both
    /// UTF-8 and byte-slice frontiers. Structural mirror of
    /// `test_per_attempt_region_try_from_bytes_rejects_non_canonical_input`
    /// (commit 5c0c827) at the per-attempt-region ladder and
    /// `test_admission_tier_try_from_bytes_rejects_non_canonical_input`
    /// (commit cdb192c) at the admission-tier ladder.
    #[test]
    fn test_bump_level_try_from_bytes_rejects_non_canonical_input() {
        for bad in [
            &b""[..],
            &b"Patch"[..],
            &b"Minor"[..],
            &b"Major"[..],
            &b"PATCH"[..],
            &b" patch"[..],
            &b"patch "[..],
        ] {
            assert!(
                <BumpLevel as std::convert::TryFrom<&[u8]>>::try_from(bad).is_err(),
                "TryFrom<&[u8]> must reject valid-UTF-8 non-canonical input {bad:?}",
            );
        }
    }

    /// [`TryFrom<Vec<u8>> for BumpLevel`] recovers the original variant
    /// at every [`BumpLevel::ALL`] variant when the canonical label bytes
    /// emitted by `level.as_str().as_bytes().to_vec()` are fed back
    /// through it. Pins the round-trip identity
    /// `BumpLevel::try_from(level.as_str().as_bytes().to_vec()).unwrap()
    /// == level` at every variant against the shared
    /// [`BumpLevel::as_str`] + [`str::as_bytes`] canonical-label-bytes
    /// oracle. The structural witness that the by-value owned-buffer
    /// byte-slice try-conversion parse surface (this
    /// [`TryFrom<Vec<u8>>`]) reads the same one-oracle grammar the
    /// by-reference byte-slice parse peer [`TryFrom<&[u8]>`] reads —
    /// one round-trip pin per variant, refuses a future variant insertion
    /// that drops the `TryFrom<Vec<u8>>`/`as_str().as_bytes().to_vec()`
    /// agreement. Structural mirror of
    /// `test_per_attempt_region_try_from_vec_bytes_agrees_with_from_str`
    /// (commit 91ba4bf) at the per-attempt-region ladder and
    /// `test_admission_tier_try_from_vec_bytes_agrees_with_from_str`
    /// (commit f4a2052) at the admission-tier ladder.
    #[test]
    fn test_bump_level_try_from_vec_bytes_agrees_with_from_str() {
        for level in BumpLevel::ALL {
            let parsed = <BumpLevel as std::convert::TryFrom<Vec<u8>>>::try_from(
                level.as_str().as_bytes().to_vec(),
            )
            .expect("canonical label bytes must parse through TryFrom<Vec<u8>>");
            assert_eq!(
                parsed, level,
                "TryFrom<Vec<u8>> must round-trip through as_str().as_bytes().to_vec() at {level:?}",
            );
        }
    }

    /// The [`TryFrom<Vec<u8>> for BumpLevel`] identity carries through a
    /// generic `impl TryFrom<Vec<u8>>` consumer at every
    /// [`BumpLevel::ALL`] variant. A tiny generic function
    /// `fn parse<T>(b: Vec<u8>) -> T where T: TryFrom<Vec<u8>>, T::Error:
    /// std::fmt::Debug` — the shape of an actual downstream consumer (a
    /// serde container `#[serde(try_from = "Vec<u8>")]` deserializer, an
    /// [`std::io::Read::read_to_end`] pipeline terminus that hands an
    /// owned buffer to a typed parser, a `bytes::Bytes::to_vec`
    /// round-trip point at an async HTTP-body / registry-response
    /// frontier, an OCI / GHCR annotation-value reader that materializes
    /// payload bytes as owned [`Vec<u8>`], a SLSA / sigstore
    /// attestation-subject bytes reader that owns its buffer end-to-end)
    /// — recovers the canonical variant from the canonical lowercase
    /// label byte-sequence at every variant. The structural witness that
    /// a [`BumpLevel`] is genuinely usable at `impl TryFrom<Vec<u8>>`
    /// call sites — a regression that drifted the [`TryFrom`] impl
    /// signature (taking `&Vec<u8>` instead of by-value, returning a
    /// different variant than [`TryFrom<&[u8]>`] would, dropping the
    /// UTF-8 decode step and misparsing non-UTF-8 input) fails here at
    /// compile time or at the assertion instead of at every downstream
    /// generic call site. Structural mirror of
    /// `test_per_attempt_region_try_from_vec_bytes_carries_through_generic_consumer`
    /// (commit 91ba4bf) at the per-attempt-region ladder and
    /// `test_admission_tier_try_from_vec_bytes_carries_through_generic_consumer`
    /// (commit f4a2052) at the admission-tier ladder.
    #[test]
    fn test_bump_level_try_from_vec_bytes_carries_through_generic_consumer() {
        fn parse<T>(b: Vec<u8>) -> T
        where
            T: std::convert::TryFrom<Vec<u8>>,
            <T as std::convert::TryFrom<Vec<u8>>>::Error: std::fmt::Debug,
        {
            <T as std::convert::TryFrom<Vec<u8>>>::try_from(b)
                .expect("canonical label bytes must parse through generic TryFrom<Vec<u8>>")
        }

        for level in BumpLevel::ALL {
            assert_eq!(
                parse::<BumpLevel>(level.as_str().as_bytes().to_vec()),
                level,
                "generic TryFrom<Vec<u8>> consumer must recover canonical variant at {level:?}",
            );
        }
    }

    /// [`TryFrom<Vec<u8>> for BumpLevel`] rejects non-UTF-8 owned-buffer
    /// input at the [`std::str::from_utf8`] decode frontier inherited
    /// through delegation to the by-reference [`TryFrom<&[u8]>`] parse
    /// peer. Pins the encoding-strictness contract at the byte-slice
    /// frontier's owned-buffer parse layer so a downstream consumer bound
    /// by [`TryFrom<Vec<u8>>`] (a serde container that opts into
    /// `#[serde(try_from = "Vec<u8>")]`, an
    /// [`std::io::Read::read_to_end`] pipeline terminus, an OCI / GHCR
    /// annotation-value reader that surfaces raw byte payloads as owned
    /// [`Vec<u8>`], a byte-slice classifier that composes over the
    /// `TryFrom<Vec<u8>>` contract) inherits the same UTF-8-only encoding
    /// discipline the by-reference [`TryFrom<&[u8]>`] peer already
    /// carries, at ONE typed-primitive site rather than a per-consumer
    /// `String::from_utf8` + `.parse` restatement. A regression that
    /// dropped the delegation to [`TryFrom<&[u8]>`] (e.g., a naive
    /// `String::from_utf8_unchecked` bypass) would light up here rather
    /// than drifting silently to a mis-parsed variant. Structural mirror
    /// of
    /// `test_per_attempt_region_try_from_vec_bytes_rejects_non_utf8_input`
    /// (commit 91ba4bf) at the per-attempt-region ladder and
    /// `test_admission_tier_try_from_vec_bytes_rejects_non_utf8_input`
    /// (commit f4a2052) at the admission-tier ladder.
    #[test]
    fn test_bump_level_try_from_vec_bytes_rejects_non_utf8_input() {
        for bad in [
            vec![0xffu8],
            vec![0xffu8, 0xfe],
            vec![0x80u8],
            vec![b'p', b'a', 0xff, b'c', b'h'],
            vec![b'm', b'a', b'j', b'o', b'r', 0xff],
        ] {
            assert!(
                <BumpLevel as std::convert::TryFrom<Vec<u8>>>::try_from(bad.clone()).is_err(),
                "TryFrom<Vec<u8>> must reject non-UTF-8 input {bad:?}",
            );
        }
    }

    /// [`TryFrom<Vec<u8>> for BumpLevel`] rejects valid-UTF-8
    /// non-canonical owned-buffer input at the underlying [`FromStr`]
    /// strictness gate inherited through delegation to [`TryFrom<&[u8]>`]
    /// — empty byte sequence, UpperCamel rendering, uppercase, and
    /// whitespace-padded lowercase labels all reject. Pins the
    /// canonical-label strictness contract at the byte-slice frontier's
    /// owned-buffer parse layer so a downstream consumer bound by
    /// [`TryFrom<Vec<u8>>`] inherits the same canonical-only grammar the
    /// direct `.parse::<BumpLevel>()` call sites, the sibling
    /// [`TryFrom<&str>`], [`TryFrom<String>`], and [`TryFrom<&[u8]>`]
    /// impls already read, and a future permissive-parse regression at
    /// the underlying [`FromStr`] impl lights up here rather than
    /// drifting silently through the owned-buffer try-conversion surface.
    /// Sibling of the by-reference byte-slice pin
    /// [`test_bump_level_try_from_bytes_rejects_non_canonical_input`] at
    /// the by-reference [`TryFrom<&[u8]>`] peer — the two pins together
    /// close the canonical-only strictness contract across both borrowed
    /// and owned byte-slice input ownership at the byte-slice frontier.
    /// Structural mirror of
    /// `test_per_attempt_region_try_from_vec_bytes_rejects_non_canonical_input`
    /// (commit 91ba4bf) at the per-attempt-region ladder and
    /// `test_admission_tier_try_from_vec_bytes_rejects_non_canonical_input`
    /// (commit f4a2052) at the admission-tier ladder.
    #[test]
    fn test_bump_level_try_from_vec_bytes_rejects_non_canonical_input() {
        for bad in [
            b"".to_vec(),
            b"Patch".to_vec(),
            b"Minor".to_vec(),
            b"Major".to_vec(),
            b"PATCH".to_vec(),
            b" patch".to_vec(),
            b"patch ".to_vec(),
        ] {
            assert!(
                <BumpLevel as std::convert::TryFrom<Vec<u8>>>::try_from(bad.clone()).is_err(),
                "TryFrom<Vec<u8>> must reject valid-UTF-8 non-canonical input {bad:?}",
            );
        }
    }

    /// [`TryFrom<Cow<'_, [u8]>> for BumpLevel`] recovers the original
    /// variant at every [`BumpLevel::ALL`] variant across BOTH [`Cow`]
    /// branches when the canonical label emitted by
    /// [`BumpLevel::as_str`] is fed back through it as a byte slice
    /// wrapped in [`Cow::Borrowed`] and as an owned byte buffer wrapped
    /// in [`Cow::Owned`]. Pins the round-trip identity
    /// `BumpLevel::try_from(Cow::Borrowed(level.as_str().as_bytes()))
    /// .unwrap() == level` AND its [`Cow::Owned`] sibling at every
    /// variant against the shared canonical-label oracle. The structural
    /// witness that the by-value borrowed/owned-frontier byte-slice
    /// try-conversion parse surface (this [`TryFrom<Cow<'_, [u8]>>`])
    /// reads the same one-oracle grammar the by-reference byte-slice
    /// parse peer [`TryFrom<&[u8]>`], the by-value owned-buffer
    /// byte-slice parse peer [`TryFrom<Vec<u8>>`], the sibling UTF-8-
    /// frontier [`TryFrom<Cow<'_, str>>`] parse peer, and the by-value
    /// borrowed-frontier byte-slice emit surface
    /// ([`From<BumpLevel> for Cow<'static, [u8]>`]) all read — one
    /// round-trip pin per variant per [`Cow`] branch, refuses a future
    /// variant insertion that drops the `TryFrom<Cow<'_, [u8]>>`/
    /// `as_str().as_bytes()` agreement across either branch. Structural
    /// mirror of
    /// `test_per_attempt_region_try_from_cow_bytes_agrees_with_from_str`
    /// (commit 506c183) at the per-attempt-region ladder and
    /// `test_admission_tier_try_from_cow_bytes_agrees_with_from_str`
    /// (commit ac5b862) at the admission-tier ladder.
    #[test]
    fn test_bump_level_try_from_cow_bytes_agrees_with_from_str() {
        for level in BumpLevel::ALL {
            let borrowed: std::borrow::Cow<'_, [u8]> =
                std::borrow::Cow::Borrowed(level.as_str().as_bytes());
            let parsed_borrowed = <BumpLevel as std::convert::TryFrom<
                std::borrow::Cow<'_, [u8]>,
            >>::try_from(borrowed)
            .expect("canonical label bytes must parse through TryFrom<Cow::Borrowed>");
            assert_eq!(
                parsed_borrowed, level,
                "TryFrom<Cow<'_, [u8]>> must round-trip through Cow::Borrowed at {level:?}",
            );

            let owned: std::borrow::Cow<'_, [u8]> =
                std::borrow::Cow::Owned(level.as_str().as_bytes().to_vec());
            let parsed_owned =
                <BumpLevel as std::convert::TryFrom<std::borrow::Cow<'_, [u8]>>>::try_from(owned)
                    .expect("canonical label bytes must parse through TryFrom<Cow::Owned>");
            assert_eq!(
                parsed_owned, level,
                "TryFrom<Cow<'_, [u8]>> must round-trip through Cow::Owned at {level:?}",
            );
        }
    }

    /// The [`TryFrom<Cow<'_, [u8]>> for BumpLevel`] identity carries
    /// through a generic `impl TryFrom<Cow<'_, [u8]>>` consumer at every
    /// [`BumpLevel::ALL`] variant across both [`Cow`] branches. A tiny
    /// generic function `fn parse<'a, T: TryFrom<Cow<'a, [u8]>>>(b:
    /// Cow<'a, [u8]>) -> T` — the shape of an actual downstream consumer
    /// (a serde container `#[serde(try_from = "Cow<'a, [u8]>")]`
    /// deserializer, a validated-input newtype builder that accepts
    /// either a borrowed `'static`-lived label byte-slice or an owned
    /// caller-supplied [`Vec<u8>`] uniformly, a generic try-conversion
    /// helper that opts into the [`TryFrom<Cow<'_, [u8]>>`] contract
    /// rather than [`TryFrom<&[u8]>`] / [`TryFrom<Vec<u8>>`] to compose
    /// with the borrowed/owned-frontier byte-buffer receiver shape, an
    /// OCI / GHCR annotation-value reader that borrows a `'static`-
    /// lived label constant against uncached entries and owns a decoded
    /// payload against cached entries) — recovers the canonical variant
    /// from the canonical lowercase label byte-sequence at every variant
    /// against both [`Cow`] branches. The structural witness that a
    /// [`BumpLevel`] is genuinely usable at `impl TryFrom<Cow<'_, [u8]>>`
    /// call sites — a regression that drifted the [`TryFrom`] impl
    /// signature (e.g., requiring a specific `'static` lifetime rather
    /// than the parametric `'a`, dropping the [`Cow`] wrapper entirely,
    /// or returning a different variant than [`TryFrom<&[u8]>`] would)
    /// fails here at compile time or at the assertion instead of at
    /// every downstream generic call site. Structural mirror of
    /// `test_per_attempt_region_try_from_cow_bytes_carries_through_generic_consumer`
    /// (commit 506c183) at the per-attempt-region ladder and
    /// `test_admission_tier_try_from_cow_bytes_carries_through_generic_consumer`
    /// (commit ac5b862) at the admission-tier ladder.
    #[test]
    fn test_bump_level_try_from_cow_bytes_carries_through_generic_consumer() {
        fn parse<'a, T>(b: std::borrow::Cow<'a, [u8]>) -> T
        where
            T: std::convert::TryFrom<std::borrow::Cow<'a, [u8]>>,
            <T as std::convert::TryFrom<std::borrow::Cow<'a, [u8]>>>::Error: std::fmt::Debug,
        {
            <T as std::convert::TryFrom<std::borrow::Cow<'a, [u8]>>>::try_from(b)
                .expect("canonical label bytes must parse through generic TryFrom<Cow<'_, [u8]>>")
        }

        for level in BumpLevel::ALL {
            assert_eq!(
                parse::<BumpLevel>(std::borrow::Cow::Borrowed(level.as_str().as_bytes())),
                level,
                "generic TryFrom<Cow<'_, [u8]>> consumer must recover canonical variant \
                 through Cow::Borrowed at {level:?}",
            );
            assert_eq!(
                parse::<BumpLevel>(std::borrow::Cow::Owned(level.as_str().as_bytes().to_vec())),
                level,
                "generic TryFrom<Cow<'_, [u8]>> consumer must recover canonical variant \
                 through Cow::Owned at {level:?}",
            );
        }
    }

    /// [`TryFrom<Cow<'_, [u8]>> for BumpLevel`] rejects non-UTF-8 input
    /// at the [`std::str::from_utf8`] decode frontier inherited through
    /// delegation to the by-reference [`TryFrom<&[u8]>`] parse peer,
    /// across both [`Cow`] branches. Pins the encoding-strictness
    /// contract at the byte-slice frontier's borrowed/owned-frontier
    /// parse layer so a downstream consumer bound by
    /// [`TryFrom<Cow<'_, [u8]>>`] (a serde container that opts into
    /// `#[serde(try_from = "Cow<'_, [u8]>")]`, an OCI / GHCR
    /// annotation-value reader that surfaces raw byte payloads across
    /// either [`Cow`] branch, a byte-slice classifier that composes
    /// over the `TryFrom<Cow<'_, [u8]>>` contract) inherits the same
    /// UTF-8-only encoding discipline the by-reference
    /// [`TryFrom<&[u8]>`] and by-value owned-buffer [`TryFrom<Vec<u8>>`]
    /// peers already carry, at ONE typed-primitive site rather than a
    /// per-consumer `String::from_utf8` + `.parse` restatement. A
    /// regression that dropped the delegation to [`TryFrom<&[u8]>`]
    /// (e.g., a naive `String::from_utf8_unchecked` bypass) would light
    /// up here rather than drifting silently to a mis-parsed variant.
    /// Structural mirror of
    /// `test_per_attempt_region_try_from_cow_bytes_rejects_non_utf8_input`
    /// (commit 506c183) at the per-attempt-region ladder and
    /// `test_admission_tier_try_from_cow_bytes_rejects_non_utf8_input`
    /// (commit ac5b862) at the admission-tier ladder.
    #[test]
    fn test_bump_level_try_from_cow_bytes_rejects_non_utf8_input() {
        for bad in [
            vec![0xffu8],
            vec![0xffu8, 0xfe],
            vec![0x80u8],
            vec![b'p', b'a', 0xff, b'c', b'h'],
            vec![b'm', b'a', b'j', b'o', b'r', 0xff],
        ] {
            assert!(
                <BumpLevel as std::convert::TryFrom<std::borrow::Cow<'_, [u8]>>>::try_from(
                    std::borrow::Cow::Borrowed(bad.as_slice()),
                )
                .is_err(),
                "TryFrom<Cow<'_, [u8]>> must reject non-UTF-8 Cow::Borrowed input {bad:?}",
            );
            assert!(
                <BumpLevel as std::convert::TryFrom<std::borrow::Cow<'_, [u8]>>>::try_from(
                    std::borrow::Cow::Owned(bad.clone()),
                )
                .is_err(),
                "TryFrom<Cow<'_, [u8]>> must reject non-UTF-8 Cow::Owned input {bad:?}",
            );
        }
    }

    /// [`TryFrom<Cow<'_, [u8]>> for BumpLevel`] rejects valid-UTF-8
    /// non-canonical input at the underlying [`FromStr`] strictness gate
    /// inherited through delegation to [`TryFrom<&[u8]>`], across both
    /// [`Cow`] branches — empty byte sequence, UpperCamel rendering,
    /// uppercase, and whitespace-padded lowercase labels all reject,
    /// whether wrapped in [`Cow::Borrowed`] or [`Cow::Owned`]. Pins the
    /// canonical-label strictness contract at the byte-slice frontier's
    /// borrowed/owned-frontier parse layer so a downstream consumer
    /// bound by [`TryFrom<Cow<'_, [u8]>>`] inherits the same canonical-
    /// only grammar the direct `.parse::<BumpLevel>()` call sites, the
    /// sibling [`TryFrom<&str>`], [`TryFrom<String>`],
    /// [`TryFrom<Cow<'_, str>>`], [`TryFrom<&[u8]>`], and
    /// [`TryFrom<Vec<u8>>`] impls already read, and a future permissive-
    /// parse regression at the underlying [`FromStr`] impl lights up
    /// here rather than drifting silently through the borrowed/owned-
    /// frontier byte-slice try-conversion surface at either branch.
    /// Sibling of the by-reference byte-slice pin
    /// [`test_bump_level_try_from_bytes_rejects_non_canonical_input`]
    /// at the by-reference [`TryFrom<&[u8]>`] peer and the by-value
    /// owned-buffer pin
    /// [`test_bump_level_try_from_vec_bytes_rejects_non_canonical_input`]
    /// at the by-value [`TryFrom<Vec<u8>>`] peer — the three pins
    /// together close the canonical-only strictness contract across
    /// borrowed, owned, and borrowed/owned-frontier byte-slice input
    /// ownership at the byte-slice frontier. Structural mirror of
    /// `test_per_attempt_region_try_from_cow_bytes_rejects_non_canonical_input`
    /// (commit 506c183) at the per-attempt-region ladder and
    /// `test_admission_tier_try_from_cow_bytes_rejects_non_canonical_input`
    /// (commit ac5b862) at the admission-tier ladder.
    #[test]
    fn test_bump_level_try_from_cow_bytes_rejects_non_canonical_input() {
        for bad in [
            b"".to_vec(),
            b"Patch".to_vec(),
            b"Minor".to_vec(),
            b"Major".to_vec(),
            b"PATCH".to_vec(),
            b" patch".to_vec(),
            b"patch ".to_vec(),
        ] {
            assert!(
                <BumpLevel as std::convert::TryFrom<std::borrow::Cow<'_, [u8]>>>::try_from(
                    std::borrow::Cow::Borrowed(bad.as_slice()),
                )
                .is_err(),
                "TryFrom<Cow<'_, [u8]>> must reject non-canonical Cow::Borrowed input {bad:?}",
            );
            assert!(
                <BumpLevel as std::convert::TryFrom<std::borrow::Cow<'_, [u8]>>>::try_from(
                    std::borrow::Cow::Owned(bad.clone()),
                )
                .is_err(),
                "TryFrom<Cow<'_, [u8]>> must reject non-canonical Cow::Owned input {bad:?}",
            );
        }
    }

    /// [`TryFrom<Box<[u8]>> for BumpLevel`] recovers the original variant
    /// at every [`BumpLevel::ALL`] variant when the canonical label bytes
    /// emitted by [`BumpLevel::as_str`] are wrapped in a [`Box<[u8]>`] and
    /// fed back through it. Pins the round-trip identity
    /// `BumpLevel::try_from(Box::<[u8]>::from(level.as_str().as_bytes()))
    /// .unwrap() == level` at every variant against the shared canonical-
    /// label oracle, applied to the caller-owned shrunk buffer input
    /// shape. Pins the round-trip identity that the by-value shrunk-owned
    /// byte-slice parse surface reads the same canonical grammar the
    /// borrowed [`TryFrom<&[u8]>`], owned-buffer [`TryFrom<Vec<u8>>`], and
    /// borrowed/owned-frontier [`TryFrom<Cow<'_, [u8]>>`] peers read at
    /// the byte-slice frontier. Structural mirror of
    /// `test_per_attempt_region_try_from_box_bytes_agrees_with_from_str`
    /// (commit 51dcd67) at the per-attempt-region ladder and
    /// `test_admission_tier_try_from_box_bytes_agrees_with_from_str`
    /// (commit c03b846) at the admission-tier ladder.
    #[test]
    fn test_bump_level_try_from_box_bytes_agrees_with_from_str() {
        for level in BumpLevel::ALL {
            let boxed: Box<[u8]> = Box::from(level.as_str().as_bytes());
            let parsed: BumpLevel =
                <BumpLevel as std::convert::TryFrom<Box<[u8]>>>::try_from(boxed).unwrap();
            assert_eq!(
                parsed, level,
                "TryFrom<Box<[u8]>> must round-trip canonical label bytes at {level:?}",
            );
        }
    }

    /// The [`TryFrom<Box<[u8]>>`] identity carries through a generic
    /// `impl TryFrom<Box<[u8]>>` consumer at every [`BumpLevel::ALL`]
    /// variant. A tiny generic function
    /// `fn parse<T: TryFrom<Box<[u8]>, Error = anyhow::Error>>(bytes:
    /// Box<[u8]>) -> Result<T> { T::try_from(bytes) }` — the shape of an
    /// actual downstream consumer (a `serde` container with
    /// `#[serde(try_from = "Box<[u8]>")]` on a wrapper field, a
    /// validated-input newtype builder whose canonical parse contract is
    /// stated as `TryFrom<Box<[u8]>>`) — recovers a [`BumpLevel`] value
    /// from its canonical lowercase label bytes with the shrunk-owned
    /// buffer consumed end-to-end. Compile-time witness that a
    /// [`BumpLevel`] is genuinely usable at `impl TryFrom<Box<[u8]>>`
    /// call sites. Structural mirror of
    /// `test_per_attempt_region_try_from_box_bytes_carries_through_generic_consumer`
    /// (commit 51dcd67) at the per-attempt-region ladder and
    /// `test_admission_tier_try_from_box_bytes_carries_through_generic_consumer`
    /// (commit c03b846) at the admission-tier ladder.
    #[test]
    fn test_bump_level_try_from_box_bytes_carries_through_generic_consumer() {
        fn parse<T>(bytes: Box<[u8]>) -> anyhow::Result<T>
        where
            T: std::convert::TryFrom<Box<[u8]>, Error = anyhow::Error>,
        {
            T::try_from(bytes)
        }

        for level in BumpLevel::ALL {
            let boxed: Box<[u8]> = Box::from(level.as_str().as_bytes());
            let parsed: BumpLevel = parse(boxed).unwrap();
            assert_eq!(
                parsed, level,
                "generic TryFrom<Box<[u8]>> consumer must recover canonical variant at {level:?}",
            );
        }
    }

    /// [`TryFrom<Box<[u8]>> for BumpLevel`] strict-rejects non-canonical
    /// input at every non-canonical byte-buffer shape the underlying
    /// [`std::str::from_utf8`] + [`std::str::FromStr`] pipeline rejects:
    /// empty, UpperCamel rendering, whitespace padding, and uppercase.
    /// Pins the strict-rejection contract at ONE named site so a
    /// regression that loosened the underlying [`TryFrom<&[u8]>`] parser
    /// (e.g., trimming whitespace, case-folding, or accepting alternative
    /// spellings) would fail here instead of leaking to every downstream
    /// `impl TryFrom<Box<[u8]>>` consumer. Structural mirror of
    /// `test_per_attempt_region_try_from_box_bytes_rejects_non_canonical_input`
    /// (commit 51dcd67) at the per-attempt-region ladder and
    /// `test_admission_tier_try_from_box_bytes_rejects_non_canonical_input`
    /// (commit c03b846) at the admission-tier ladder.
    #[test]
    fn test_bump_level_try_from_box_bytes_rejects_non_canonical_input() {
        for bad in [
            b"".to_vec(),
            b"Patch".to_vec(),
            b"Minor".to_vec(),
            b"Major".to_vec(),
            b"PATCH".to_vec(),
            b" patch".to_vec(),
            b"patch ".to_vec(),
        ] {
            let boxed: Box<[u8]> = Box::from(bad.as_slice());
            assert!(
                <BumpLevel as std::convert::TryFrom<Box<[u8]>>>::try_from(boxed).is_err(),
                "TryFrom<Box<[u8]>> must reject non-canonical input {bad:?}",
            );
        }
    }

    /// Round-trip identity: every [`BumpLevel::ALL`] variant rendered as
    /// its canonical lowercase label bytes and wrapped in an
    /// [`std::sync::Arc<[u8]>`] parses back through
    /// [`TryFrom<Arc<[u8]>>`] to the same variant. Pins at ONE named
    /// site the round-trip identity that the by-value shared-owned
    /// byte-slice parse surface reads the same canonical grammar the
    /// borrowed [`TryFrom<&[u8]>`], owned-buffer [`TryFrom<Vec<u8>>`],
    /// borrowed/owned-frontier [`TryFrom<Cow<'_, [u8]>>`], and
    /// shrunk-owned [`TryFrom<Box<[u8]>>`] peers already read at the
    /// byte-slice frontier. Structural mirror of
    /// `test_per_attempt_region_try_from_arc_bytes_agrees_with_from_str`
    /// (commit eca99cc) at the per-attempt-region ladder and
    /// `test_admission_tier_try_from_arc_bytes_agrees_with_from_str`
    /// (commit 9874d09) at the admission-tier ladder.
    #[test]
    fn test_bump_level_try_from_arc_bytes_agrees_with_from_str() {
        for level in BumpLevel::ALL {
            let arced: std::sync::Arc<[u8]> = std::sync::Arc::from(level.as_str().as_bytes());
            let parsed: BumpLevel =
                <BumpLevel as std::convert::TryFrom<std::sync::Arc<[u8]>>>::try_from(arced)
                    .unwrap();
            assert_eq!(
                parsed, level,
                "TryFrom<Arc<[u8]>> must round-trip canonical label bytes at {level:?}",
            );
        }
    }

    /// The [`TryFrom<Arc<[u8]>>`] identity carries through a generic
    /// `impl TryFrom<Arc<[u8]>>` consumer at every [`BumpLevel::ALL`]
    /// variant. A tiny generic function
    /// `fn parse<T: TryFrom<Arc<[u8]>, Error = anyhow::Error>>(bytes:
    /// Arc<[u8]>) -> Result<T> { T::try_from(bytes) }` — the shape of
    /// an actual downstream consumer (a `serde` container with
    /// `#[serde(try_from = "Arc<[u8]>")]` on a wrapper field, a
    /// validated-input newtype builder whose canonical parse contract
    /// is stated as `TryFrom<Arc<[u8]>>`) — recovers a [`BumpLevel`]
    /// value from its canonical lowercase label bytes with the
    /// atomic-refcounted shared buffer consumed end-to-end.
    /// Compile-time witness that a [`BumpLevel`] is genuinely usable at
    /// `impl TryFrom<Arc<[u8]>>` call sites. Structural mirror of
    /// `test_per_attempt_region_try_from_arc_bytes_carries_through_generic_consumer`
    /// (commit eca99cc) at the per-attempt-region ladder and
    /// `test_admission_tier_try_from_arc_bytes_carries_through_generic_consumer`
    /// (commit 9874d09) at the admission-tier ladder.
    #[test]
    fn test_bump_level_try_from_arc_bytes_carries_through_generic_consumer() {
        fn parse<T>(bytes: std::sync::Arc<[u8]>) -> anyhow::Result<T>
        where
            T: std::convert::TryFrom<std::sync::Arc<[u8]>, Error = anyhow::Error>,
        {
            T::try_from(bytes)
        }

        for level in BumpLevel::ALL {
            let arced: std::sync::Arc<[u8]> = std::sync::Arc::from(level.as_str().as_bytes());
            let parsed: BumpLevel = parse(arced).unwrap();
            assert_eq!(
                parsed, level,
                "generic TryFrom<Arc<[u8]>> consumer must recover canonical variant at {level:?}",
            );
        }
    }

    /// [`TryFrom<Arc<[u8]>> for BumpLevel`] strict-rejects non-canonical
    /// input at every non-canonical byte-buffer shape the underlying
    /// [`std::str::from_utf8`] + [`std::str::FromStr`] pipeline rejects:
    /// empty, UpperCamel rendering, whitespace padding, and uppercase.
    /// Pins the strict-rejection contract at ONE named site so a
    /// regression that loosened the underlying [`TryFrom<&[u8]>`] parser
    /// (e.g., trimming whitespace, case-folding, or accepting
    /// alternative spellings) would fail here instead of leaking to
    /// every downstream `impl TryFrom<Arc<[u8]>>` consumer. Structural
    /// mirror of
    /// `test_per_attempt_region_try_from_arc_bytes_rejects_non_canonical_input`
    /// (commit eca99cc) at the per-attempt-region ladder and
    /// `test_admission_tier_try_from_arc_bytes_rejects_non_canonical_input`
    /// (commit 9874d09) at the admission-tier ladder.
    #[test]
    fn test_bump_level_try_from_arc_bytes_rejects_non_canonical_input() {
        for bad in [
            b"".to_vec(),
            b"Patch".to_vec(),
            b"Minor".to_vec(),
            b"Major".to_vec(),
            b"PATCH".to_vec(),
            b" patch".to_vec(),
            b"patch ".to_vec(),
        ] {
            let arced: std::sync::Arc<[u8]> = std::sync::Arc::from(bad.as_slice());
            assert!(
                <BumpLevel as std::convert::TryFrom<std::sync::Arc<[u8]>>>::try_from(arced)
                    .is_err(),
                "TryFrom<Arc<[u8]>> must reject non-canonical input {bad:?}",
            );
        }
    }

    /// Round-trip identity: every [`BumpLevel::ALL`] variant rendered as
    /// its canonical lowercase label bytes and wrapped in an
    /// [`std::rc::Rc<[u8]>`] parses back through [`TryFrom<Rc<[u8]>>`]
    /// to the same variant. Pins at ONE named site the round-trip
    /// identity that the by-value thread-local shared-owned byte-slice
    /// parse surface reads the same canonical grammar the borrowed
    /// [`TryFrom<&[u8]>`], owned-buffer [`TryFrom<Vec<u8>>`], borrowed/
    /// owned-frontier [`TryFrom<Cow<'_, [u8]>>`], shrunk-owned
    /// [`TryFrom<Box<[u8]>>`], and shared-owned [`TryFrom<Arc<[u8]>>`]
    /// peers already read at the byte-slice frontier. Structural mirror
    /// of `test_per_attempt_region_try_from_rc_bytes_agrees_with_from_str`
    /// (commit 19f862a) at the per-attempt-region ladder and
    /// `test_admission_tier_try_from_rc_bytes_agrees_with_from_str`
    /// (commit 399e69f) at the admission-tier ladder.
    #[test]
    fn test_bump_level_try_from_rc_bytes_agrees_with_from_str() {
        for level in BumpLevel::ALL {
            let rced: std::rc::Rc<[u8]> = std::rc::Rc::from(level.as_str().as_bytes());
            let parsed: BumpLevel =
                <BumpLevel as std::convert::TryFrom<std::rc::Rc<[u8]>>>::try_from(rced).unwrap();
            assert_eq!(
                parsed, level,
                "TryFrom<Rc<[u8]>> must round-trip canonical label bytes at {level:?}",
            );
        }
    }

    /// The [`TryFrom<Rc<[u8]>>`] identity carries through a generic
    /// `impl TryFrom<Rc<[u8]>>` consumer at every [`BumpLevel::ALL`]
    /// variant. A tiny generic function
    /// `fn parse<T: TryFrom<Rc<[u8]>, Error = anyhow::Error>>(bytes:
    /// Rc<[u8]>) -> Result<T> { T::try_from(bytes) }` — the shape of
    /// an actual downstream consumer (a single-threaded validated-input
    /// newtype builder whose canonical parse contract is stated as
    /// `TryFrom<Rc<[u8]>>`, a thread-local event log replay that hands
    /// the canonical label bytes to a typed-sum parser) — recovers a
    /// [`BumpLevel`] value from its canonical lowercase label bytes with
    /// the non-atomic-refcounted shared buffer consumed end-to-end.
    /// Compile-time witness that a [`BumpLevel`] is genuinely usable at
    /// `impl TryFrom<Rc<[u8]>>` call sites. Structural mirror of
    /// `test_per_attempt_region_try_from_rc_bytes_carries_through_generic_consumer`
    /// (commit 19f862a) at the per-attempt-region ladder and
    /// `test_admission_tier_try_from_rc_bytes_carries_through_generic_consumer`
    /// (commit 399e69f) at the admission-tier ladder.
    #[test]
    fn test_bump_level_try_from_rc_bytes_carries_through_generic_consumer() {
        fn parse<T>(bytes: std::rc::Rc<[u8]>) -> anyhow::Result<T>
        where
            T: std::convert::TryFrom<std::rc::Rc<[u8]>, Error = anyhow::Error>,
        {
            T::try_from(bytes)
        }

        for level in BumpLevel::ALL {
            let rced: std::rc::Rc<[u8]> = std::rc::Rc::from(level.as_str().as_bytes());
            let parsed: BumpLevel = parse(rced).unwrap();
            assert_eq!(
                parsed, level,
                "generic TryFrom<Rc<[u8]>> consumer must recover canonical variant at {level:?}",
            );
        }
    }

    /// [`TryFrom<Rc<[u8]>> for BumpLevel`] strict-rejects non-canonical
    /// input at every non-canonical byte-buffer shape the underlying
    /// [`std::str::from_utf8`] + [`std::str::FromStr`] pipeline rejects:
    /// empty, UpperCamel rendering, whitespace padding, and uppercase.
    /// Pins the strict-rejection contract at ONE named site so a
    /// regression that loosened the underlying [`TryFrom<&[u8]>`] parser
    /// (e.g., trimming whitespace, case-folding, or accepting
    /// alternative spellings) would fail here instead of leaking to
    /// every downstream `impl TryFrom<Rc<[u8]>>` consumer. Structural
    /// mirror of
    /// `test_per_attempt_region_try_from_rc_bytes_rejects_non_canonical_input`
    /// (commit 19f862a) at the per-attempt-region ladder and
    /// `test_admission_tier_try_from_rc_bytes_rejects_non_canonical_input`
    /// (commit 399e69f) at the admission-tier ladder.
    #[test]
    fn test_bump_level_try_from_rc_bytes_rejects_non_canonical_input() {
        for bad in [
            b"".to_vec(),
            b"Patch".to_vec(),
            b"Minor".to_vec(),
            b"Major".to_vec(),
            b"PATCH".to_vec(),
            b" patch".to_vec(),
            b"patch ".to_vec(),
        ] {
            let rced: std::rc::Rc<[u8]> = std::rc::Rc::from(bad.as_slice());
            assert!(
                <BumpLevel as std::convert::TryFrom<std::rc::Rc<[u8]>>>::try_from(rced).is_err(),
                "TryFrom<Rc<[u8]>> must reject non-canonical input {bad:?}",
            );
        }
    }

    /// [`TryFrom<&str> for BumpLevel`] recovers the original variant at
    /// every [`BumpLevel::ALL`] variant when the canonical label emitted
    /// by [`BumpLevel::as_str`] is fed back through it. Pins the
    /// round-trip identity
    /// `BumpLevel::try_from(level.as_str()).unwrap() == level` at every
    /// variant against the shared canonical-label oracle. The
    /// structural witness that the by-reference try-conversion parse
    /// surface (this [`TryFrom<&str>`]) reads the same one-oracle
    /// grammar the by-value emit surface
    /// ([`From<BumpLevel> for &'static str`], the sibling above) writes
    /// — one round-trip pin per variant, refuses a future variant
    /// insertion that drops the `TryFrom`/`as_str` agreement.
    /// Structural mirror of
    /// `test_per_attempt_region_try_from_str_agrees_with_from_str`
    /// (commit 1be3c49) at the per-attempt-region ladder and
    /// `test_admission_tier_try_from_str_agrees_with_from_str` (commit
    /// a17cd83) at the admission-tier ladder.
    #[test]
    fn test_bump_level_try_from_str_agrees_with_from_str() {
        for level in BumpLevel::ALL {
            let parsed = <BumpLevel as std::convert::TryFrom<&str>>::try_from(level.as_str())
                .expect("canonical label must parse through TryFrom<&str>");
            assert_eq!(
                parsed, level,
                "TryFrom<&str> must round-trip through as_str at {level:?}",
            );
        }
    }

    /// The [`TryFrom<&str> for BumpLevel`] identity carries through a
    /// generic `impl for<'a> TryFrom<&'a str>` consumer at every
    /// [`BumpLevel::ALL`] variant. A tiny generic function
    /// `fn parse<T>(s: &str) -> T where T: for<'a> TryFrom<&'a str>,
    /// T::Error: std::fmt::Debug` — the shape of an actual downstream
    /// consumer (validated-input newtype builder, serde `try_from`
    /// wrapper, generic try-conversion helper that opts into the
    /// [`TryFrom<&str>`] contract rather than [`std::str::FromStr`]) —
    /// recovers the canonical variant from the canonical lowercase
    /// label at every variant. The structural witness that a
    /// [`BumpLevel`] is genuinely usable at
    /// `impl for<'a> TryFrom<&'a str>` call sites — a regression that
    /// drifted the [`TryFrom`] impl signature (e.g., requiring an
    /// owned [`String`] input instead of `&str`, or returning a
    /// different variant than [`std::str::FromStr`] would) fails here
    /// at compile time or at the assertion instead of at every
    /// downstream generic call site. Structural mirror of
    /// `test_per_attempt_region_try_from_str_carries_through_generic_consumer`
    /// (commit 1be3c49) at the per-attempt-region ladder and
    /// `test_admission_tier_try_from_str_carries_through_generic_consumer`
    /// (commit a17cd83) at the admission-tier ladder.
    #[test]
    fn test_bump_level_try_from_str_carries_through_generic_consumer() {
        fn parse<T>(s: &str) -> T
        where
            T: for<'a> std::convert::TryFrom<&'a str>,
            for<'a> <T as std::convert::TryFrom<&'a str>>::Error: std::fmt::Debug,
        {
            <T as std::convert::TryFrom<&str>>::try_from(s)
                .expect("canonical label must parse through generic TryFrom<&str>")
        }

        for level in BumpLevel::ALL {
            assert_eq!(
                parse::<BumpLevel>(level.as_str()),
                level,
                "generic TryFrom<&str> consumer must recover canonical variant at {level:?}",
            );
        }
    }

    /// [`TryFrom<&str> for BumpLevel`] rejects non-canonical input with
    /// the same strictness [`std::str::FromStr`] enforces — empty
    /// string, UpperCamel rendering, uppercase, and whitespace padding
    /// all reject. Pins the strict-rejection contract at the
    /// by-reference try-conversion surface so a downstream consumer
    /// bound by [`TryFrom<&str>`] (a serde `try_from` container, a
    /// generic try-conversion helper) inherits the same canonical-only
    /// grammar the direct `.parse::<BumpLevel>()` call sites already
    /// read, and a future permissive-parse regression at the underlying
    /// [`std::str::FromStr`] impl lights up here rather than drifting
    /// silently through the by-reference try-conversion surface.
    /// Structural mirror of
    /// `test_per_attempt_region_try_from_str_rejects_non_canonical_input`
    /// (commit 1be3c49) at the per-attempt-region ladder and
    /// `test_admission_tier_try_from_str_rejects_non_canonical_input`
    /// (commit a17cd83) at the admission-tier ladder.
    #[test]
    fn test_bump_level_try_from_str_rejects_non_canonical_input() {
        for bad in [
            "", "Patch", "Minor", "Major", "PATCH", "MINOR", "MAJOR", " patch", "patch ",
            "  patch ", "invalid",
        ] {
            assert!(
                <BumpLevel as std::convert::TryFrom<&str>>::try_from(bad).is_err(),
                "TryFrom<&str> must reject non-canonical input {bad:?}",
            );
        }
    }

    /// [`From<BumpLevel> for String`] agrees with the canonical
    /// [`BumpLevel::as_str`] label at every [`BumpLevel::ALL`] variant.
    /// Pins the identity `String::from(level) == level.as_str()` at every
    /// variant so a future variant insertion / grammar refinement at the
    /// shared [`BumpLevel::as_str`] oracle propagates to the by-value
    /// owned-string emit surface without a per-variant retype at the
    /// [`From`] impl body. The structural agreement pin between the
    /// by-value owned-string emit surface
    /// ([`From<BumpLevel> for String`]) and the canonical-label oracle
    /// ([`BumpLevel::as_str`]) — the owned-[`String`] sibling of the
    /// borrowed `'static`-lifetime agreement pin
    /// [`test_bump_level_from_into_static_str_agrees_with_as_str`]
    /// already carries. Structural mirror of
    /// `test_admission_tier_from_into_string_agrees_with_as_str` (commit
    /// 463b31b) at the admission-tier ladder and
    /// `test_per_attempt_region_from_into_string_agrees_with_as_str`
    /// (commit a5a379f) at the per-attempt-region ladder.
    #[test]
    fn test_bump_level_from_into_string_agrees_with_as_str() {
        for level in BumpLevel::ALL {
            let owned: String = String::from(level);
            assert_eq!(
                owned,
                level.as_str(),
                "From<BumpLevel> for String and as_str must agree at {level:?}",
            );
        }
    }

    /// The [`From<BumpLevel> for String`] identity carries through a
    /// generic `impl Into<String>` consumer at every [`BumpLevel::ALL`]
    /// variant. A tiny generic function
    /// `fn read<T: Into<String>>(t: T) -> String { t.into() }` — the
    /// shape of an actual downstream consumer
    /// (`std::collections::HashMap::<String, _>::insert` key builder,
    /// environment-variable setter that owns its key, release-manifest
    /// field builder that owns its bump-label emission,
    /// [`String::push_str`] sink over a caller-owned buffer) — reads the
    /// canonical lowercase label directly from a [`BumpLevel`] value as
    /// an owned [`String`]. The structural witness that a [`BumpLevel`]
    /// is genuinely usable at `impl Into<String>` call sites — a
    /// regression that drifted the [`From`] impl signature (returning
    /// [`&'static str`] instead of [`String`], requiring
    /// [`&BumpLevel`] and losing the by-value semantics) fails here at
    /// compile time instead of at every downstream generic call site.
    /// Structural mirror of
    /// `test_admission_tier_into_string_carries_through_generic_consumer`
    /// (commit 463b31b) at the admission-tier ladder and
    /// `test_per_attempt_region_into_string_carries_through_generic_consumer`
    /// (commit a5a379f) at the per-attempt-region ladder.
    #[test]
    fn test_bump_level_into_string_carries_through_generic_consumer() {
        fn read<T: Into<String>>(t: T) -> String {
            t.into()
        }

        for level in BumpLevel::ALL {
            assert_eq!(
                read(level),
                level.as_str(),
                "generic Into<String> consumer must read canonical label at {level:?}",
            );
        }
    }

    /// [`TryFrom<String> for BumpLevel`] recovers the canonical variant
    /// from the owned canonical lowercase label at every
    /// [`BumpLevel::ALL`] variant. The by-value owned-string
    /// try-conversion peer of the by-reference round-trip pin
    /// [`test_bump_level_try_from_str_agrees_with_from_str`] above —
    /// same one-oracle grammar, the caller owns the input buffer and
    /// drives it through as an owned [`String`]. Pins the round-trip
    /// identity `BumpLevel::try_from(String::from(level.as_str())).unwrap()
    /// == level` at every variant against the shared canonical-label
    /// oracle. The structural witness that the by-value owned-string
    /// try-conversion parse surface (this [`TryFrom<String>`]) reads
    /// the same one-oracle grammar the by-reference try-conversion
    /// parse surface ([`TryFrom<&str>`], the sibling above) and the
    /// by-value owned-string emit surface
    /// ([`From<BumpLevel> for String`], the sibling above) both read —
    /// one round-trip pin per variant, refuses a future variant
    /// insertion that drops the `TryFrom<String>`/`as_str` agreement.
    /// Structural mirror of
    /// `test_per_attempt_region_try_from_string_agrees_with_from_str`
    /// (commit 9f6feb3) at the per-attempt-region ladder and
    /// `test_admission_tier_try_from_string_agrees_with_from_str`
    /// (commit affb017) at the admission-tier ladder.
    #[test]
    fn test_bump_level_try_from_string_agrees_with_from_str() {
        for level in BumpLevel::ALL {
            let owned: String = level.as_str().to_owned();
            let parsed = <BumpLevel as std::convert::TryFrom<String>>::try_from(owned)
                .expect("canonical label must parse through TryFrom<String>");
            assert_eq!(
                parsed, level,
                "TryFrom<String> must round-trip through as_str at {level:?}",
            );
        }
    }

    /// The [`TryFrom<String> for BumpLevel`] identity carries through
    /// a generic `impl TryFrom<String>` consumer at every
    /// [`BumpLevel::ALL`] variant. A tiny generic function
    /// `fn parse<T: TryFrom<String>>(s: String) -> T` — the shape of
    /// an actual downstream consumer (validated-input newtype builder
    /// that consumes an owned [`String`], serde `try_from = "String"`
    /// wrapper, generic try-conversion helper that opts into the
    /// [`TryFrom<String>`] contract rather than [`std::str::FromStr`]
    /// or [`TryFrom<&str>`]) — recovers the canonical variant from the
    /// canonical lowercase label at every variant. The structural
    /// witness that a [`BumpLevel`] is genuinely usable at
    /// `impl TryFrom<String>` call sites — a regression that drifted
    /// the [`TryFrom`] impl signature (e.g., requiring
    /// [`&BumpLevel`], or returning a different variant than
    /// [`std::str::FromStr`] would) fails here at compile time or at
    /// the assertion instead of at every downstream generic call site.
    /// Structural mirror of
    /// `test_per_attempt_region_try_from_string_carries_through_generic_consumer`
    /// (commit 9f6feb3) at the per-attempt-region ladder and
    /// `test_admission_tier_try_from_string_carries_through_generic_consumer`
    /// (commit affb017) at the admission-tier ladder.
    #[test]
    fn test_bump_level_try_from_string_carries_through_generic_consumer() {
        fn parse<T>(s: String) -> T
        where
            T: std::convert::TryFrom<String>,
            <T as std::convert::TryFrom<String>>::Error: std::fmt::Debug,
        {
            <T as std::convert::TryFrom<String>>::try_from(s)
                .expect("canonical label must parse through generic TryFrom<String>")
        }

        for level in BumpLevel::ALL {
            assert_eq!(
                parse::<BumpLevel>(level.as_str().to_owned()),
                level,
                "generic TryFrom<String> consumer must recover canonical variant at {level:?}",
            );
        }
    }

    /// [`TryFrom<String> for BumpLevel`] rejects non-canonical owned
    /// input with the same strictness [`std::str::FromStr`] enforces —
    /// empty string, UpperCamel rendering, uppercase, whitespace
    /// padding, and unrelated tokens all reject. Pins the
    /// strict-rejection contract at the by-value owned-string
    /// try-conversion surface so a downstream consumer bound by
    /// [`TryFrom<String>`] (a serde `try_from = "String"` container, a
    /// builder that consumes owned input) inherits the same
    /// canonical-only grammar the direct `.parse::<BumpLevel>()` call
    /// sites and the sibling [`TryFrom<&str>`] impl already read, and
    /// a future permissive-parse regression at the underlying
    /// [`std::str::FromStr`] impl lights up here rather than drifting
    /// silently through the owned-string try-conversion surface.
    /// Structural mirror of
    /// `test_per_attempt_region_try_from_string_rejects_non_canonical_input`
    /// (commit 9f6feb3) at the per-attempt-region ladder and
    /// `test_admission_tier_try_from_string_rejects_non_canonical_input`
    /// (commit affb017) at the admission-tier ladder.
    #[test]
    fn test_bump_level_try_from_string_rejects_non_canonical_input() {
        for bad in [
            "", "Patch", "Minor", "Major", "PATCH", "MINOR", "MAJOR", " patch", "patch ",
            "  patch ", "invalid",
        ] {
            assert!(
                <BumpLevel as std::convert::TryFrom<String>>::try_from(bad.to_owned()).is_err(),
                "TryFrom<String> must reject non-canonical input {bad:?}",
            );
        }
    }

    /// [`From<BumpLevel> for Cow<'static, str>`] agrees with the canonical
    /// [`BumpLevel::as_str`] label at every [`BumpLevel::ALL`] variant.
    /// Pins the identity `Cow::<'static, str>::from(level).as_ref() ==
    /// level.as_str()` at every variant so a future variant insertion /
    /// grammar refinement at the shared [`BumpLevel::as_str`] oracle
    /// propagates to the by-value `Cow<'static, str>` emit surface
    /// without a per-variant retype at the [`From`] impl body. The
    /// borrowed/owned-frontier sibling of the borrowed `'static`-lifetime
    /// agreement pin
    /// [`test_bump_level_from_into_static_str_agrees_with_as_str`] and
    /// the owned-[`String`] agreement pin
    /// [`test_bump_level_from_into_string_agrees_with_as_str`] already
    /// carry, closing the three-way emit agreement across the canonical
    /// string-owner shapes (`&'static str`, [`String`],
    /// [`std::borrow::Cow<'static, str>`]). Structural mirror of
    /// `test_admission_tier_from_into_cow_static_str_agrees_with_as_str`
    /// (commit 65b1e77) at the admission-tier ladder and
    /// `test_per_attempt_region_from_into_cow_static_str_agrees_with_as_str`
    /// (commit 79113dd) at the per-attempt-region ladder.
    #[test]
    fn test_bump_level_from_into_cow_static_str_agrees_with_as_str() {
        for level in BumpLevel::ALL {
            let cow: std::borrow::Cow<'static, str> = std::borrow::Cow::from(level);
            assert_eq!(
                cow.as_ref(),
                level.as_str(),
                "From<BumpLevel> for Cow<'static, str> and as_str must agree at {level:?}",
            );
        }
    }

    /// The [`From<BumpLevel> for Cow<'static, str>`] identity carries
    /// through a generic `impl Into<Cow<'static, str>>` consumer at every
    /// [`BumpLevel::ALL`] variant. A tiny generic function
    /// `fn read<T: Into<Cow<'static, str>>>(t: T) -> Cow<'static, str>
    /// { t.into() }` — the shape of an actual downstream consumer
    /// (release-manifest serializer that accepts either a static label
    /// or a caller-supplied [`String`] uniformly, tracing /
    /// OpenTelemetry attribute slot typed as
    /// [`std::borrow::Cow<'static, str>`], `clap`
    /// [`clap::builder::Str`] / [`clap::builder::StyledStr`] sink) —
    /// reads the canonical lowercase label directly from a [`BumpLevel`]
    /// value with the `'static` lifetime preserved through the
    /// [`std::borrow::Cow<'static, str>`] wrapper. The structural
    /// witness that a [`BumpLevel`] is genuinely usable at
    /// `impl Into<Cow<'static, str>>` call sites — a regression that
    /// drifted the [`From`] impl signature (e.g., returning
    /// [`std::borrow::Cow<'_, str>`] with a non-`'static` lifetime,
    /// requiring [`&BumpLevel`] and losing the by-value semantics, or
    /// dropping the [`std::borrow::Cow`] wrapper entirely) fails here at
    /// compile time instead of at every downstream generic call site.
    /// Structural mirror of
    /// `test_admission_tier_into_cow_static_str_carries_through_generic_consumer`
    /// (commit 65b1e77) at the admission-tier ladder and
    /// `test_per_attempt_region_into_cow_static_str_carries_through_generic_consumer`
    /// (commit 79113dd) at the per-attempt-region ladder.
    #[test]
    fn test_bump_level_into_cow_static_str_carries_through_generic_consumer() {
        fn read<T: Into<std::borrow::Cow<'static, str>>>(t: T) -> std::borrow::Cow<'static, str> {
            t.into()
        }

        for level in BumpLevel::ALL {
            assert_eq!(
                read(level).as_ref(),
                level.as_str(),
                "generic Into<Cow<'static, str>> consumer must read canonical label at {level:?}",
            );
        }
    }

    /// [`From<BumpLevel> for Cow<'static, str>`] returns the
    /// [`std::borrow::Cow::Borrowed`] branch, not
    /// [`std::borrow::Cow::Owned`], at every [`BumpLevel::ALL`] variant.
    /// Pins the zero-allocation contract at the emit boundary: because
    /// [`BumpLevel::as_str`] returns a `'static`-lived borrow into the
    /// static-string constant table, this impl composes with an
    /// [`Into<Cow<'static, str>>`] receiver at the
    /// [`std::borrow::Cow::Borrowed`] branch — the receiver pays the
    /// `'static`-borrow cost of [`From<BumpLevel> for &'static str`],
    /// not the [`String`]-allocation cost of
    /// [`From<BumpLevel> for String`]. The structural witness that the
    /// impl body picks the load-bearing [`std::borrow::Cow::Borrowed`]
    /// branch — a regression that drifted the impl body toward
    /// `Cow::Owned(level.as_str().to_owned())` would silently allocate
    /// at every emit site and defeat the borrowed/owned-frontier
    /// discipline this impl closes; the [`matches!`] pin lights up here
    /// at ONE named site instead of leaking to every downstream
    /// `impl Into<Cow<'static, str>>` consumer as a hidden per-call
    /// allocation. Sibling of the agreement pin
    /// [`test_bump_level_from_into_cow_static_str_agrees_with_as_str`]
    /// at the label-oracle surface — the two pins together close both
    /// the value-agreement contract and the branch-choice /
    /// zero-allocation contract at the by-value
    /// [`std::borrow::Cow<'static, str>`] emit surface. Structural
    /// mirror of `test_admission_tier_into_cow_static_str_is_borrowed`
    /// (commit 65b1e77) at the admission-tier ladder and
    /// `test_per_attempt_region_into_cow_static_str_is_borrowed`
    /// (commit 79113dd) at the per-attempt-region ladder.
    #[test]
    fn test_bump_level_into_cow_static_str_is_borrowed() {
        for level in BumpLevel::ALL {
            let cow: std::borrow::Cow<'static, str> = std::borrow::Cow::from(level);
            assert!(
                matches!(cow, std::borrow::Cow::Borrowed(_)),
                "From<BumpLevel> for Cow<'static, str> must return Cow::Borrowed \
                 (zero-allocation branch) at {level:?}, not Cow::Owned",
            );
        }
    }

    /// [`TryFrom<Cow<'_, str>> for BumpLevel`] agrees with the canonical
    /// [`std::str::FromStr`] grammar at every [`BumpLevel::ALL`] variant
    /// across both [`Cow`] branches. Pins the identity
    /// `BumpLevel::try_from(Cow::Borrowed(level.as_str())).unwrap() ==
    /// level` and its [`Cow::Owned`] sibling at every variant so a future
    /// variant insertion / grammar refinement at the shared
    /// [`std::str::FromStr`] oracle propagates to the by-value
    /// [`Cow<'_, str>`] try-conversion surface without a per-variant
    /// retype at the [`TryFrom`] impl body. The structural agreement pin
    /// between the by-value [`Cow<'_, str>`] parse surface
    /// ([`TryFrom<Cow<'_, str>> for BumpLevel`]) and the canonical-
    /// grammar oracle ([`<BumpLevel as std::str::FromStr>::from_str`]) —
    /// the borrowed/owned-frontier parse-side sibling of the borrowed-
    /// `&str` agreement pin
    /// [`test_bump_level_try_from_str_agrees_with_from_str`] and the
    /// owned-[`String`] agreement pin
    /// [`test_bump_level_try_from_string_agrees_with_from_str`] already
    /// carry, closing the three-way parse agreement across the canonical
    /// string-owner shapes (`&str`, [`String`], [`Cow<'_, str>`]).
    /// Structural mirror of
    /// `test_per_attempt_region_try_from_cow_str_agrees_with_from_str`
    /// (commit 0b85b4f) at the per-attempt-region ladder and
    /// `test_admission_tier_try_from_cow_str_agrees_with_from_str`
    /// (commit 03d977b) at the admission-tier ladder.
    #[test]
    fn test_bump_level_try_from_cow_str_agrees_with_from_str() {
        for level in BumpLevel::ALL {
            let borrowed: std::borrow::Cow<'_, str> = std::borrow::Cow::Borrowed(level.as_str());
            let parsed_borrowed =
                <BumpLevel as std::convert::TryFrom<std::borrow::Cow<'_, str>>>::try_from(borrowed)
                    .expect("canonical label must parse through TryFrom<Cow::Borrowed>");
            assert_eq!(
                parsed_borrowed, level,
                "TryFrom<Cow<'_, str>> must round-trip through Cow::Borrowed at {level:?}",
            );

            let owned: std::borrow::Cow<'_, str> =
                std::borrow::Cow::Owned(level.as_str().to_owned());
            let parsed_owned =
                <BumpLevel as std::convert::TryFrom<std::borrow::Cow<'_, str>>>::try_from(owned)
                    .expect("canonical label must parse through TryFrom<Cow::Owned>");
            assert_eq!(
                parsed_owned, level,
                "TryFrom<Cow<'_, str>> must round-trip through Cow::Owned at {level:?}",
            );
        }
    }

    /// The [`TryFrom<Cow<'_, str>> for BumpLevel`] identity carries
    /// through a generic `impl TryFrom<Cow<'_, str>>` consumer at every
    /// [`BumpLevel::ALL`] variant across both [`Cow`] branches. A tiny
    /// generic function
    /// `fn parse<'a, T: TryFrom<Cow<'a, str>>>(s: Cow<'a, str>) -> T` —
    /// the shape of an actual downstream consumer (validated-input
    /// newtype builder that accepts either a borrowed static label or an
    /// owned caller-supplied [`String`] uniformly, serde
    /// `try_from = "Cow<'a, str>"` wrapper, generic try-conversion
    /// helper that opts into the [`TryFrom<Cow<'_, str>>`] contract
    /// rather than [`std::str::FromStr`] / [`TryFrom<&str>`] /
    /// [`TryFrom<String>`] to compose with the borrowed/owned-frontier
    /// receiver shape) — recovers the canonical variant from the
    /// canonical lowercase label at every variant against both [`Cow`]
    /// branches. The structural witness that a [`BumpLevel`] is
    /// genuinely usable at `impl TryFrom<Cow<'_, str>>` call sites — a
    /// regression that drifted the [`TryFrom`] impl signature (e.g.,
    /// requiring a specific `'static` lifetime rather than the parametric
    /// `'a`, dropping the [`Cow`] wrapper entirely, or returning a
    /// different variant than [`FromStr`] would) fails here at compile
    /// time or at the assertion instead of at every downstream generic
    /// call site. Structural mirror of
    /// `test_per_attempt_region_try_from_cow_str_carries_through_generic_consumer`
    /// (commit 0b85b4f) at the per-attempt-region ladder and
    /// `test_admission_tier_try_from_cow_str_carries_through_generic_consumer`
    /// (commit 03d977b) at the admission-tier ladder.
    #[test]
    fn test_bump_level_try_from_cow_str_carries_through_generic_consumer() {
        fn parse<'a, T>(s: std::borrow::Cow<'a, str>) -> T
        where
            T: std::convert::TryFrom<std::borrow::Cow<'a, str>>,
            <T as std::convert::TryFrom<std::borrow::Cow<'a, str>>>::Error: std::fmt::Debug,
        {
            <T as std::convert::TryFrom<std::borrow::Cow<'a, str>>>::try_from(s)
                .expect("canonical label must parse through generic TryFrom<Cow<'_, str>>")
        }

        for level in BumpLevel::ALL {
            assert_eq!(
                parse::<BumpLevel>(std::borrow::Cow::Borrowed(level.as_str())),
                level,
                "generic TryFrom<Cow<'_, str>> consumer must recover canonical variant \
                 through Cow::Borrowed at {level:?}",
            );
            assert_eq!(
                parse::<BumpLevel>(std::borrow::Cow::Owned(level.as_str().to_owned())),
                level,
                "generic TryFrom<Cow<'_, str>> consumer must recover canonical variant \
                 through Cow::Owned at {level:?}",
            );
        }
    }

    /// [`TryFrom<Cow<'_, str>> for BumpLevel`] rejects non-canonical
    /// input with the same strictness [`std::str::FromStr`] enforces
    /// across both [`Cow`] branches — empty string, UpperCamel rendering,
    /// uppercase, and whitespace padding all reject, whether wrapped in
    /// [`Cow::Borrowed`] or [`Cow::Owned`]. Pins the strict-rejection
    /// contract at the by-value [`Cow<'_, str>`] try-conversion surface
    /// so a downstream consumer bound by [`TryFrom<Cow<'_, str>>`] (a
    /// serde `try_from = "Cow<'_, str>"` container, a builder that
    /// consumes either a borrowed or an owned canonical label) inherits
    /// the same canonical-only grammar the direct `.parse::<BumpLevel>()`
    /// call sites and the sibling [`TryFrom<&str>`] / [`TryFrom<String>`]
    /// impls already read, and a future permissive-parse regression at
    /// the underlying [`FromStr`] impl lights up here rather than
    /// drifting silently through the borrowed/owned-frontier
    /// try-conversion surface at either branch. Structural mirror of
    /// `test_per_attempt_region_try_from_cow_str_rejects_non_canonical_input`
    /// (commit 0b85b4f) at the per-attempt-region ladder and
    /// `test_admission_tier_try_from_cow_str_rejects_non_canonical_input`
    /// (commit 03d977b) at the admission-tier ladder.
    #[test]
    fn test_bump_level_try_from_cow_str_rejects_non_canonical_input() {
        for bad in [
            "", "Patch", "Minor", "Major", "PATCH", "MINOR", "MAJOR", " patch", "patch ",
            "  patch ", "invalid",
        ] {
            assert!(
                <BumpLevel as std::convert::TryFrom<std::borrow::Cow<'_, str>>>::try_from(
                    std::borrow::Cow::Borrowed(bad),
                )
                .is_err(),
                "TryFrom<Cow<'_, str>> must reject non-canonical Cow::Borrowed input {bad:?}",
            );
            assert!(
                <BumpLevel as std::convert::TryFrom<std::borrow::Cow<'_, str>>>::try_from(
                    std::borrow::Cow::Owned(bad.to_owned()),
                )
                .is_err(),
                "TryFrom<Cow<'_, str>> must reject non-canonical Cow::Owned input {bad:?}",
            );
        }
    }

    /// [`From<BumpLevel> for Box<str>`] agrees with [`BumpLevel::as_str`]
    /// at every [`BumpLevel::ALL`] variant — the shrunk-owned emit peer
    /// reads the same canonical lowercase label the shared oracle names.
    /// Pins the value-agreement contract at the by-value [`Box<str>`]
    /// emit surface across every variant:
    /// [`Box::<str>::from(level).as_ref()`] equals [`level.as_str()`] for
    /// [`Patch`](BumpLevel::Patch), [`Minor`](BumpLevel::Minor), and
    /// [`Major`](BumpLevel::Major). A regression that drifted the impl
    /// body (e.g., emitting the [`std::fmt::Display`] label from a stale
    /// variant name, boxing an unrelated string constant, or diverging
    /// from the [`as_str`] one-oracle grammar) lights up here at ONE
    /// named site instead of leaking through every downstream
    /// `impl Into<Box<str>>` consumer as a silent label-drift.
    /// Structural mirror of
    /// [`test_bump_level_from_into_static_str_agrees_with_as_str`] at
    /// the `'static`-borrow emit surface,
    /// [`test_bump_level_from_into_string_agrees_with_as_str`] at the
    /// owned [`String`] emit surface, and
    /// [`test_bump_level_from_into_cow_static_str_agrees_with_as_str`]
    /// at the borrowed/owned-frontier emit surface — the four agreement
    /// pins together close the read-side agreement across every by-value
    /// emit surface at the version-bump-magnitude ladder. Structural
    /// mirror of `test_per_attempt_region_into_box_str_agrees_with_as_str`
    /// (commit c54e10a) and
    /// `test_admission_tier_into_box_str_agrees_with_as_str` (commit
    /// f8e0e02) at the version-bump-magnitude ladder — the same
    /// agreement pin through the same one-oracle discipline at the third
    /// ordered typed sum.
    #[test]
    fn test_bump_level_into_box_str_agrees_with_as_str() {
        for level in BumpLevel::ALL {
            let boxed: Box<str> = Box::<str>::from(level);
            assert_eq!(
                boxed.as_ref(),
                level.as_str(),
                "From<BumpLevel> for Box<str> and as_str must agree at {level:?}",
            );
        }
    }

    /// The [`From<BumpLevel> for Box<str>`] identity carries through a
    /// generic `impl Into<Box<str>>` consumer at every
    /// [`BumpLevel::ALL`] variant. A tiny generic function
    /// `fn read<T: Into<Box<str>>>(t: T) -> Box<str> { t.into() }` — the
    /// shape of an actual downstream consumer (config-struct field typed
    /// as [`Box<str>`] to shrink an owned label off a resizable
    /// [`String`]'s spare-capacity tail, a validated-input newtype
    /// wrapper that stores a canonical label as a fixed-size heap
    /// allocation, a serde container that opts into
    /// `#[serde(from = "Box<str>")]` at the immutable-owned-string
    /// frontier) — reads the canonical lowercase label directly from a
    /// [`BumpLevel`] value at a single heap allocation. The structural
    /// witness that a [`BumpLevel`] is genuinely usable at
    /// `impl Into<Box<str>>` call sites — a regression that drifted the
    /// [`From`] impl signature (e.g., returning [`String`] instead of
    /// [`Box<str>`], requiring [`&BumpLevel`] and losing the by-value
    /// semantics, or dropping to a [`String::into_boxed_str`]
    /// composition on the [`String`]-emit peer that would allocate-then-
    /// shrink) fails here at compile time instead of at every downstream
    /// generic call site. Structural mirror of
    /// `test_per_attempt_region_into_box_str_carries_through_generic_consumer`
    /// (commit c54e10a) and
    /// `test_admission_tier_into_box_str_carries_through_generic_consumer`
    /// (commit f8e0e02) at the version-bump-magnitude ladder — the same
    /// generic consumer pin through the same one-oracle discipline at
    /// the third ordered typed sum.
    #[test]
    fn test_bump_level_into_box_str_carries_through_generic_consumer() {
        fn read<T: Into<Box<str>>>(t: T) -> Box<str> {
            t.into()
        }

        for level in BumpLevel::ALL {
            assert_eq!(
                read(level).as_ref(),
                level.as_str(),
                "generic Into<Box<str>> consumer must read canonical label at {level:?}",
            );
        }
    }

    /// [`TryFrom<Box<str>> for BumpLevel`] round-trips through the shared
    /// canonical-label oracle at every [`BumpLevel::ALL`] variant: the
    /// caller emits the canonical label through [`BumpLevel::as_str`],
    /// boxes it via [`Box::<str>::from`] at the shrunk-owned frontier,
    /// and this parse peer recovers the variant from the boxed slice
    /// through the shared [`<Self as std::str::FromStr>::from_str`]
    /// oracle. Pins the round-trip identity
    /// `BumpLevel::try_from(Box::<str>::from(level.as_str())).unwrap() ==
    /// level` at every variant against the shared canonical-label
    /// oracle. The structural witness that the by-value [`Box<str>`]
    /// try-conversion parse surface (this [`TryFrom<Box<str>>`]) reads
    /// the same one-oracle grammar the by-reference try-conversion parse
    /// surface ([`TryFrom<&str>`]), the by-value owned-string
    /// try-conversion parse surface ([`TryFrom<String>`]), the by-value
    /// borrowed/owned-frontier try-conversion parse surface
    /// ([`TryFrom<Cow<'_, str>>`]), and the by-value shrunk-owned-
    /// frontier emit surface ([`From<BumpLevel> for Box<str>`]) all read
    /// — one round-trip pin per variant, refuses a future variant
    /// insertion that drops the `TryFrom<Box<str>>`/`as_str` agreement.
    /// Structural mirror of
    /// `test_per_attempt_region_try_from_box_str_agrees_with_from_str`
    /// (commit 3b8c512) and
    /// `test_admission_tier_try_from_box_str_agrees_with_from_str`
    /// (commit 1a34d2a) at the version-bump-magnitude ladder.
    #[test]
    fn test_bump_level_try_from_box_str_agrees_with_from_str() {
        for level in BumpLevel::ALL {
            let boxed: Box<str> = Box::<str>::from(level.as_str());
            let parsed = <BumpLevel as std::convert::TryFrom<Box<str>>>::try_from(boxed)
                .expect("canonical label must parse through TryFrom<Box<str>>");
            assert_eq!(
                parsed, level,
                "TryFrom<Box<str>> must round-trip through Box::<str>::from(as_str) at {level:?}",
            );
        }
    }

    /// The [`TryFrom<Box<str>> for BumpLevel`] identity carries through a
    /// generic `impl TryFrom<Box<str>>` consumer at every
    /// [`BumpLevel::ALL`] variant. A tiny generic function
    /// `fn parse<T: TryFrom<Box<str>>>(s: Box<str>) -> T` — the shape of
    /// an actual downstream consumer (validated-input newtype builder
    /// that accepts a caller-supplied [`Box<str>`] label at the
    /// shrunk-owned frontier, serde `try_from = "Box<str>"` wrapper,
    /// generic try-conversion helper that opts into the
    /// [`TryFrom<Box<str>>`] contract rather than [`std::str::FromStr`]
    /// / [`TryFrom<&str>`] / [`TryFrom<String>`] /
    /// [`TryFrom<Cow<'_, str>>`] to compose with the shrunk-owned-
    /// frontier receiver shape) — recovers the canonical variant from
    /// the canonical lowercase label at every variant. The structural
    /// witness that a [`BumpLevel`] is genuinely usable at
    /// `impl TryFrom<Box<str>>` call sites — a regression that drifted
    /// the [`TryFrom`] impl signature (e.g., requiring a [`&Box<str>`]
    /// receiver and losing the by-value semantics, dropping the
    /// [`Box<str>`] wrapper entirely and demanding a [`String`], or
    /// returning a different variant than [`FromStr`] would) fails here
    /// at compile time or at the assertion instead of at every
    /// downstream generic call site. Structural mirror of
    /// `test_per_attempt_region_try_from_box_str_carries_through_generic_consumer`
    /// (commit 3b8c512) and
    /// `test_admission_tier_try_from_box_str_carries_through_generic_consumer`
    /// (commit 1a34d2a) at the version-bump-magnitude ladder.
    #[test]
    fn test_bump_level_try_from_box_str_carries_through_generic_consumer() {
        fn parse<T>(s: Box<str>) -> T
        where
            T: std::convert::TryFrom<Box<str>>,
            <T as std::convert::TryFrom<Box<str>>>::Error: std::fmt::Debug,
        {
            <T as std::convert::TryFrom<Box<str>>>::try_from(s)
                .expect("canonical label must parse through generic TryFrom<Box<str>>")
        }

        for level in BumpLevel::ALL {
            assert_eq!(
                parse::<BumpLevel>(Box::<str>::from(level.as_str())),
                level,
                "generic TryFrom<Box<str>> consumer must recover canonical variant at {level:?}",
            );
        }
    }

    /// [`TryFrom<Box<str>> for BumpLevel`] rejects non-canonical input
    /// with the same strictness [`std::str::FromStr`] enforces — empty
    /// string, UpperCamel rendering, uppercase, whitespace padding, and
    /// mangled labels all reject when wrapped in a [`Box<str>`]. Pins
    /// the strict-rejection contract at the by-value [`Box<str>`]
    /// try-conversion surface so a downstream consumer bound by
    /// [`TryFrom<Box<str>>`] (a serde `try_from = "Box<str>"` container,
    /// a builder that consumes an immutable-owned canonical label at
    /// the shrunk-owned frontier) inherits the same canonical-only
    /// grammar the direct `.parse::<BumpLevel>()` call sites and the
    /// sibling [`TryFrom<&str>`] / [`TryFrom<String>`] /
    /// [`TryFrom<Cow<'_, str>>`] impls already read, and a future
    /// permissive-parse regression at the underlying [`FromStr`] impl
    /// lights up here rather than drifting silently through the
    /// shrunk-owned-frontier try-conversion surface. Structural mirror
    /// of
    /// `test_per_attempt_region_try_from_box_str_rejects_non_canonical_input`
    /// (commit 3b8c512) and
    /// `test_admission_tier_try_from_box_str_rejects_non_canonical_input`
    /// (commit 1a34d2a) at the version-bump-magnitude ladder.
    #[test]
    fn test_bump_level_try_from_box_str_rejects_non_canonical_input() {
        for bad in [
            "", "Patch", "Minor", "Major", "PATCH", " patch", "patch ", "pat",
        ] {
            assert!(
                <BumpLevel as std::convert::TryFrom<Box<str>>>::try_from(Box::<str>::from(bad))
                    .is_err(),
                "TryFrom<Box<str>> must reject non-canonical input {bad:?}",
            );
        }
    }

    /// [`From<BumpLevel> for Arc<str>`] agrees with
    /// [`BumpLevel::as_str`] at every [`BumpLevel::ALL`] variant: the
    /// emitted [`std::sync::Arc<str>`] reads exactly the canonical
    /// lowercase label the [`as_str`] oracle returns. Pins the
    /// shared-owned emit surface against the same canonical-label oracle
    /// every sibling emit surface reads —
    /// [`test_bump_level_as_str_matches_display`] at the [`Display`]
    /// emit surface,
    /// [`test_bump_level_from_into_static_str_agrees_with_as_str`] at
    /// the `'static`-borrow emit surface,
    /// [`test_bump_level_from_into_string_agrees_with_as_str`] at the
    /// owned [`String`] emit surface,
    /// [`test_bump_level_from_into_cow_static_str_agrees_with_as_str`]
    /// at the borrowed/owned-frontier emit surface, and
    /// [`test_bump_level_into_box_str_agrees_with_as_str`] at the
    /// shrunk-owned-frontier emit surface — the five agreement pins
    /// together close the read-side agreement across every by-value
    /// emit surface at the version-bump-magnitude ladder. Structural
    /// mirror of `test_per_attempt_region_into_arc_str_agrees_with_as_str`
    /// (commit c3a722d) at the per-attempt-region ladder and
    /// `test_admission_tier_into_arc_str_agrees_with_as_str` (commit
    /// 6bab1ab) at the admission-tier ladder — the same agreement pin
    /// through the same one-oracle discipline at the third ordered
    /// typed sum.
    #[test]
    fn test_bump_level_into_arc_str_agrees_with_as_str() {
        for level in BumpLevel::ALL {
            let shared: std::sync::Arc<str> = std::sync::Arc::<str>::from(level);
            assert_eq!(
                shared.as_ref(),
                level.as_str(),
                "From<BumpLevel> for Arc<str> and as_str must agree at {level:?}",
            );
        }
    }

    /// The [`From<BumpLevel> for Arc<str>`] identity carries through a
    /// generic `impl Into<Arc<str>>` consumer at every
    /// [`BumpLevel::ALL`] variant. A tiny generic function
    /// `fn read<T: Into<Arc<str>>>(t: T) -> Arc<str> { t.into() }` — the
    /// shape of an actual downstream consumer (cross-thread cached-label
    /// slot typed as [`Arc<str>`] to share a canonical allocation across
    /// worker threads via atomic refcount, a validated-input newtype
    /// wrapper that stores a canonical label as [`Arc<str>`] to hand
    /// cheap clones to sibling structures, a serde container that opts
    /// into `#[serde(from = "Arc<str>")]` at the shared-owned frontier,
    /// a dashmap-style keyed-table value slot whose readers want an
    /// [`Arc`] clone rather than a per-lookup allocation) reads the
    /// canonical lowercase label directly from a [`BumpLevel`] value at
    /// a single atomic-refcount heap allocation. The structural witness
    /// that a [`BumpLevel`] is genuinely usable at
    /// `impl Into<Arc<str>>` call sites — a regression that drifted the
    /// [`From`] impl signature (e.g., returning [`Box<str>`] instead of
    /// [`Arc<str>`], requiring [`&BumpLevel`] and losing the by-value
    /// semantics, or dropping to a [`Box<str>`]-then-[`Arc::from`]
    /// composition that would allocate twice) fails here at compile time
    /// instead of at every downstream generic call site. Structural
    /// mirror of
    /// `test_per_attempt_region_into_arc_str_carries_through_generic_consumer`
    /// (commit c3a722d) and
    /// `test_admission_tier_into_arc_str_carries_through_generic_consumer`
    /// (commit 6bab1ab) at the version-bump-magnitude ladder.
    #[test]
    fn test_bump_level_into_arc_str_carries_through_generic_consumer() {
        fn read<T: Into<std::sync::Arc<str>>>(t: T) -> std::sync::Arc<str> {
            t.into()
        }

        for level in BumpLevel::ALL {
            assert_eq!(
                read(level).as_ref(),
                level.as_str(),
                "generic Into<Arc<str>> consumer must read canonical label at {level:?}",
            );
        }
    }

    /// The [`From<BumpLevel> for Arc<str>`] shared-owned semantics hold
    /// across [`std::sync::Arc::clone`] at every [`BumpLevel::ALL`]
    /// variant: the clone reads exactly the same canonical lowercase
    /// label the original reads, points at the same allocation (identity
    /// of the underlying byte pointer via [`std::sync::Arc::ptr_eq`]),
    /// and the atomic refcount lifts to at least two after the clone
    /// (via [`std::sync::Arc::strong_count`]). Pins the shared-owned
    /// receiver contract at the emit surface — a regression that drifted
    /// the impl body to a non-`Arc` composition
    /// ([`Box::<str>::from(as_str)`] then some ad-hoc rewrap, an
    /// [`String`] intermediate) would break the pointer-identity
    /// assertion (each clone would land at a distinct allocation) even
    /// if the canonical-label bytes still agreed. The three pins
    /// together (label agreement, pointer identity, refcount lift)
    /// close the structural witness that the receiver actually holds a
    /// shared-owned [`Arc<str>`] slot rather than an [`Arc<str>`]-typed
    /// wrapper around a per-clone-allocated [`Box<str>`]. Structural
    /// mirror of
    /// `test_per_attempt_region_into_arc_str_shares_label_across_clones`
    /// (commit c3a722d) and
    /// `test_admission_tier_into_arc_str_shares_label_across_clones`
    /// (commit 6bab1ab) at the version-bump-magnitude ladder.
    #[test]
    fn test_bump_level_into_arc_str_shares_label_across_clones() {
        for level in BumpLevel::ALL {
            let shared: std::sync::Arc<str> = std::sync::Arc::<str>::from(level);
            let cloned = std::sync::Arc::clone(&shared);
            assert_eq!(
                cloned.as_ref(),
                level.as_str(),
                "Arc<str> clone must read canonical label at {level:?}",
            );
            assert!(
                std::sync::Arc::ptr_eq(&shared, &cloned),
                "Arc<str> clone must share the same underlying allocation at {level:?}",
            );
            assert!(
                std::sync::Arc::strong_count(&shared) >= 2,
                "Arc<str> strong count must be at least 2 after clone at {level:?}",
            );
        }
    }

    /// [`TryFrom<Arc<str>> for BumpLevel`] round-trips through the shared
    /// canonical-label oracle at every [`BumpLevel::ALL`] variant: the
    /// caller emits the canonical label through [`BumpLevel::as_str`],
    /// wraps it via [`std::sync::Arc::<str>::from`] at the shared-owned
    /// frontier, and this parse peer recovers the variant from the
    /// shared allocation through the shared
    /// [`<Self as std::str::FromStr>::from_str`] oracle. Pins the
    /// round-trip identity
    /// `BumpLevel::try_from(std::sync::Arc::<str>::from(level.as_str())).unwrap()
    /// == level` at every variant against the shared canonical-label
    /// oracle. The structural witness that the by-value [`Arc<str>`]
    /// try-conversion parse surface (this [`TryFrom<Arc<str>>`]) reads
    /// the same one-oracle grammar the by-reference try-conversion parse
    /// surface ([`TryFrom<&str>`]), the by-value owned-string
    /// try-conversion parse surface ([`TryFrom<String>`]), the by-value
    /// borrowed/owned-frontier try-conversion parse surface
    /// ([`TryFrom<Cow<'_, str>>`]), the by-value shrunk-owned-frontier
    /// try-conversion parse surface ([`TryFrom<Box<str>>`]), and the
    /// by-value shared-owned-frontier emit surface
    /// ([`From<BumpLevel> for Arc<str>`]) all read — one round-trip pin
    /// per variant, refuses a future variant insertion that drops the
    /// `TryFrom<Arc<str>>`/`as_str` agreement. Structural mirror of
    /// `test_per_attempt_region_try_from_arc_str_agrees_with_from_str`
    /// (commit a9c007a) and
    /// `test_admission_tier_try_from_arc_str_agrees_with_from_str`
    /// (commit 64ec99e) at the version-bump-magnitude ladder.
    #[test]
    fn test_bump_level_try_from_arc_str_agrees_with_from_str() {
        for level in BumpLevel::ALL {
            let shared: std::sync::Arc<str> = std::sync::Arc::<str>::from(level.as_str());
            let parsed =
                <BumpLevel as std::convert::TryFrom<std::sync::Arc<str>>>::try_from(shared)
                    .expect("canonical label must parse through TryFrom<Arc<str>>");
            assert_eq!(
                parsed, level,
                "TryFrom<Arc<str>> must round-trip through Arc::<str>::from(as_str) at {level:?}",
            );
        }
    }

    /// The [`TryFrom<Arc<str>> for BumpLevel`] identity carries through a
    /// generic `impl TryFrom<Arc<str>>` consumer at every
    /// [`BumpLevel::ALL`] variant. A tiny generic function
    /// `fn parse<T: TryFrom<Arc<str>>>(s: Arc<str>) -> T` — the shape of
    /// an actual downstream consumer (validated-input newtype builder
    /// that accepts a caller-supplied [`Arc<str>`] label at the
    /// shared-owned frontier for cross-thread cheap-clone semantics on
    /// the input, serde `try_from = "Arc<str>"` wrapper, generic
    /// try-conversion helper that opts into the [`TryFrom<Arc<str>>`]
    /// contract rather than [`std::str::FromStr`] / [`TryFrom<&str>`] /
    /// [`TryFrom<String>`] / [`TryFrom<Cow<'_, str>>`] /
    /// [`TryFrom<Box<str>>`] to compose with the shared-owned-frontier
    /// receiver shape) — recovers the canonical variant from the
    /// canonical lowercase label at every variant. The structural
    /// witness that a [`BumpLevel`] is genuinely usable at
    /// `impl TryFrom<Arc<str>>` call sites — a regression that drifted
    /// the [`TryFrom`] impl signature (e.g., requiring a [`&Arc<str>`]
    /// receiver and losing the by-value semantics, dropping the
    /// [`Arc<str>`] wrapper entirely and demanding a [`String`], or
    /// returning a different variant than [`FromStr`] would) fails here
    /// at compile time or at the assertion instead of at every
    /// downstream generic call site. Structural mirror of
    /// `test_per_attempt_region_try_from_arc_str_carries_through_generic_consumer`
    /// (commit a9c007a) and
    /// `test_admission_tier_try_from_arc_str_carries_through_generic_consumer`
    /// (commit 64ec99e) at the version-bump-magnitude ladder.
    #[test]
    fn test_bump_level_try_from_arc_str_carries_through_generic_consumer() {
        fn parse<T>(s: std::sync::Arc<str>) -> T
        where
            T: std::convert::TryFrom<std::sync::Arc<str>>,
            <T as std::convert::TryFrom<std::sync::Arc<str>>>::Error: std::fmt::Debug,
        {
            <T as std::convert::TryFrom<std::sync::Arc<str>>>::try_from(s)
                .expect("canonical label must parse through generic TryFrom<Arc<str>>")
        }

        for level in BumpLevel::ALL {
            assert_eq!(
                parse::<BumpLevel>(std::sync::Arc::<str>::from(level.as_str())),
                level,
                "generic TryFrom<Arc<str>> consumer must recover canonical variant at {level:?}",
            );
        }
    }

    /// [`TryFrom<Arc<str>> for BumpLevel`] rejects non-canonical input
    /// with the same strictness [`std::str::FromStr`] enforces — empty
    /// string, UpperCamel rendering, uppercase, whitespace padding, and
    /// mangled labels all reject when wrapped in an [`Arc<str>`]. Pins
    /// the strict-rejection contract at the by-value [`Arc<str>`]
    /// try-conversion surface so a downstream consumer bound by
    /// [`TryFrom<Arc<str>>`] (a serde `try_from = "Arc<str>"` container,
    /// a builder that consumes a shared-owned canonical label at the
    /// shared-owned frontier for cross-thread cheap-clone semantics on
    /// the input) inherits the same canonical-only grammar the direct
    /// `.parse::<BumpLevel>()` call sites and the sibling
    /// [`TryFrom<&str>`] / [`TryFrom<String>`] / [`TryFrom<Cow<'_, str>>`]
    /// / [`TryFrom<Box<str>>`] impls already read, and a future
    /// permissive-parse regression at the underlying [`FromStr`] impl
    /// lights up here rather than drifting silently through the
    /// shared-owned-frontier try-conversion surface. Structural mirror
    /// of
    /// `test_per_attempt_region_try_from_arc_str_rejects_non_canonical_input`
    /// (commit a9c007a) and
    /// `test_admission_tier_try_from_arc_str_rejects_non_canonical_input`
    /// (commit 64ec99e) at the version-bump-magnitude ladder.
    #[test]
    fn test_bump_level_try_from_arc_str_rejects_non_canonical_input() {
        for bad in [
            "", "Patch", "Minor", "Major", "PATCH", " patch", "patch ", "pat",
        ] {
            assert!(
                <BumpLevel as std::convert::TryFrom<std::sync::Arc<str>>>::try_from(
                    std::sync::Arc::<str>::from(bad)
                )
                .is_err(),
                "TryFrom<Arc<str>> must reject non-canonical input {bad:?}",
            );
        }
    }

    /// [`From<BumpLevel> for Rc<str>`] agrees with the canonical
    /// [`BumpLevel::as_str`] label oracle at every [`BumpLevel::ALL`]
    /// variant: the emitted [`std::rc::Rc<str>`] reads exactly the
    /// canonical lowercase label the [`as_str`] oracle returns. Pins
    /// the thread-local shared-owned emit surface against the same
    /// canonical-label oracle every sibling emit surface reads —
    /// [`test_bump_level_as_str_matches_display`] at the [`Display`]
    /// emit surface,
    /// [`test_bump_level_from_into_static_str_agrees_with_as_str`] at
    /// the `'static`-borrow emit surface,
    /// [`test_bump_level_from_into_string_agrees_with_as_str`] at the
    /// owned [`String`] emit surface,
    /// [`test_bump_level_from_into_cow_static_str_agrees_with_as_str`]
    /// at the borrowed/owned-frontier emit surface,
    /// [`test_bump_level_into_box_str_agrees_with_as_str`] at the
    /// shrunk-owned-frontier emit surface, and
    /// [`test_bump_level_into_arc_str_agrees_with_as_str`] at the
    /// atomic-shared-owned-frontier emit surface — the six agreement
    /// pins together close the read-side agreement across every
    /// by-value emit surface at the version-bump-magnitude ladder.
    /// Structural mirror of
    /// `test_per_attempt_region_into_rc_str_agrees_with_as_str`
    /// (commit 8950199) and
    /// `test_admission_tier_into_rc_str_agrees_with_as_str`
    /// (commit 62c49a0) at the version-bump-magnitude ladder — the
    /// same agreement pin through the same one-oracle discipline at
    /// the third ordered typed sum.
    #[test]
    fn test_bump_level_into_rc_str_agrees_with_as_str() {
        for level in BumpLevel::ALL {
            let shared: std::rc::Rc<str> = std::rc::Rc::<str>::from(level);
            assert_eq!(
                shared.as_ref(),
                level.as_str(),
                "From<BumpLevel> for Rc<str> and as_str must agree at {level:?}",
            );
        }
    }

    /// The [`From<BumpLevel> for Rc<str>`] identity carries through a
    /// generic `impl Into<Rc<str>>` consumer at every
    /// [`BumpLevel::ALL`] variant. A tiny generic function
    /// `fn read<T: Into<Rc<str>>>(t: T) -> Rc<str> { t.into() }` — the
    /// shape of an actual downstream consumer (thread-local cached-
    /// label slot typed as [`Rc<str>`] to share a canonical allocation
    /// within one worker via non-atomic refcount, a validated-input
    /// newtype wrapper that stores a canonical label as [`Rc<str>`] to
    /// hand cheap clones to sibling structures on the same thread, a
    /// per-request-arena label slot that never crosses a thread
    /// boundary, a graph-walk visitor that clones labels across nodes
    /// without needing [`Send`] / [`Sync`]) reads the canonical
    /// lowercase label directly from a [`BumpLevel`] value at a single
    /// non-atomic-refcount heap allocation. The structural witness
    /// that a [`BumpLevel`] is genuinely usable at
    /// `impl Into<Rc<str>>` call sites — a regression that drifted the
    /// [`From`] impl signature (e.g., returning [`Box<str>`] instead
    /// of [`Rc<str>`], requiring [`&BumpLevel`] and losing the by-value
    /// semantics, or dropping to a [`Box<str>`]-then-[`Rc::from`]
    /// composition that would allocate twice) fails here at compile
    /// time instead of at every downstream generic call site.
    /// Structural mirror of
    /// `test_per_attempt_region_into_rc_str_carries_through_generic_consumer`
    /// (commit 8950199) and
    /// `test_admission_tier_into_rc_str_carries_through_generic_consumer`
    /// (commit 62c49a0) at the version-bump-magnitude ladder.
    #[test]
    fn test_bump_level_into_rc_str_carries_through_generic_consumer() {
        fn read<T: Into<std::rc::Rc<str>>>(t: T) -> std::rc::Rc<str> {
            t.into()
        }

        for level in BumpLevel::ALL {
            assert_eq!(
                read(level).as_ref(),
                level.as_str(),
                "generic Into<Rc<str>> consumer must read canonical label at {level:?}",
            );
        }
    }

    /// The [`From<BumpLevel> for Rc<str>`] thread-local shared-owned
    /// semantics hold across [`std::rc::Rc::clone`] at every
    /// [`BumpLevel::ALL`] variant: the clone reads exactly the same
    /// canonical lowercase label the original reads, points at the
    /// same allocation (identity of the underlying byte pointer via
    /// [`std::rc::Rc::ptr_eq`]), and the non-atomic refcount lifts to
    /// at least two after the clone (via
    /// [`std::rc::Rc::strong_count`]). Pins the thread-local shared-
    /// owned receiver contract at the emit surface — a regression that
    /// drifted the impl body to a non-`Rc` composition
    /// ([`Box::<str>::from(as_str)`] then some ad-hoc rewrap, a
    /// [`String`] intermediate) would break the pointer-identity
    /// assertion (each clone would land at a distinct allocation) even
    /// if the canonical-label bytes still agreed. The three pins
    /// together (label agreement, pointer identity, refcount lift)
    /// close the structural witness that the receiver actually holds a
    /// thread-local shared-owned [`Rc<str>`] slot rather than an
    /// [`Rc<str>`]-typed wrapper around a per-clone-allocated
    /// [`Box<str>`]. Structural mirror of
    /// [`test_bump_level_into_arc_str_shares_label_across_clones`] at
    /// the atomic-shared-owned-frontier ([`Arc<str>`]) — the two pins
    /// together close the shared-owned semantics across both refcount
    /// disciplines the version-bump ladder exposes, and of
    /// `test_per_attempt_region_into_rc_str_shares_label_across_clones`
    /// (commit 8950199) and
    /// `test_admission_tier_into_rc_str_shares_label_across_clones`
    /// (commit 62c49a0) at the two ordered typed sums above — the same
    /// clone-preserves-value pin through the same one-oracle
    /// discipline at the third ordered typed sum.
    #[test]
    fn test_bump_level_into_rc_str_shares_label_across_clones() {
        for level in BumpLevel::ALL {
            let shared: std::rc::Rc<str> = std::rc::Rc::<str>::from(level);
            let cloned = std::rc::Rc::clone(&shared);
            assert_eq!(
                cloned.as_ref(),
                level.as_str(),
                "Rc<str> clone must read canonical label at {level:?}",
            );
            assert!(
                std::rc::Rc::ptr_eq(&shared, &cloned),
                "Rc<str> clone must share the same underlying allocation at {level:?}",
            );
            assert!(
                std::rc::Rc::strong_count(&shared) >= 2,
                "Rc<str> strong count must be at least 2 after clone at {level:?}",
            );
        }
    }

    /// The [`TryFrom<Rc<str>> for BumpLevel`] impl round-trips through
    /// the canonical lowercase label at every [`BumpLevel::ALL`] variant:
    /// taking each variant's [`BumpLevel::as_str`] label, wrapping it as
    /// an [`std::rc::Rc<str>`] via [`std::rc::Rc::<str>::from`], then
    /// parsing it back through [`TryFrom<Rc<str>>`], recovers the
    /// original variant. Pins the parse-side agreement at the thread-
    /// local shared-owned-frontier receiver against the same canonical-
    /// label oracle the by-reference try-conversion parse surface
    /// ([`TryFrom<&str>`]), the by-value owned-string try-conversion
    /// parse surface ([`TryFrom<String>`]), the borrowed/owned-frontier
    /// try-conversion parse surface ([`TryFrom<Cow<'_, str>>`]), the
    /// shrunk-owned-frontier try-conversion parse surface
    /// ([`TryFrom<Box<str>>`]), the atomic-shared-owned-frontier try-
    /// conversion parse surface ([`TryFrom<Arc<str>>`]), and the by-value
    /// thread-local shared-owned emit surface
    /// ([`From<BumpLevel> for Rc<str>`]) all read — one round-trip pin
    /// per variant, refuses a future variant insertion that drops the
    /// `TryFrom<Rc<str>>`/`as_str` agreement. Structural mirror of
    /// `test_per_attempt_region_try_from_rc_str_agrees_with_from_str`
    /// (commit 0e9bc9f) and
    /// `test_admission_tier_try_from_rc_str_agrees_with_from_str`
    /// (commit 9545b4d) at the version-bump-magnitude ladder.
    #[test]
    fn test_bump_level_try_from_rc_str_agrees_with_from_str() {
        for level in BumpLevel::ALL {
            let shared: std::rc::Rc<str> = std::rc::Rc::<str>::from(level.as_str());
            let parsed = <BumpLevel as std::convert::TryFrom<std::rc::Rc<str>>>::try_from(shared)
                .expect("canonical label must parse through TryFrom<Rc<str>>");
            assert_eq!(
                parsed, level,
                "TryFrom<Rc<str>> must round-trip through Rc::<str>::from(as_str) at {level:?}",
            );
        }
    }

    /// The [`TryFrom<Rc<str>> for BumpLevel`] identity carries through a
    /// generic `impl TryFrom<Rc<str>>` consumer at every
    /// [`BumpLevel::ALL`] variant. A tiny generic function
    /// `fn parse<T: TryFrom<Rc<str>>>(s: Rc<str>) -> T` — the shape of
    /// an actual downstream consumer (validated-input newtype builder
    /// that accepts a caller-supplied [`Rc<str>`] label at the thread-
    /// local shared-owned frontier, serde `try_from = "Rc<str>"` wrapper,
    /// generic try-conversion helper that opts into the
    /// [`TryFrom<Rc<str>>`] contract rather than [`std::str::FromStr`] /
    /// [`TryFrom<&str>`] / [`TryFrom<String>`] / [`TryFrom<Cow<'_, str>>`]
    /// / [`TryFrom<Box<str>>`] / [`TryFrom<Arc<str>>`] to compose with
    /// the thread-local shared-owned-frontier receiver shape) — recovers
    /// the canonical variant from the canonical lowercase label at every
    /// variant. The structural witness that a [`BumpLevel`] is genuinely
    /// usable at `impl TryFrom<Rc<str>>` call sites — a regression that
    /// drifted the [`TryFrom`] impl signature (e.g., requiring a
    /// [`&Rc<str>`] receiver and losing the by-value semantics, dropping
    /// the [`Rc<str>`] wrapper entirely and demanding a [`String`], or
    /// returning a different variant than [`FromStr`] would) fails here
    /// at compile time or at the assertion instead of at every downstream
    /// generic call site. Structural mirror of
    /// `test_per_attempt_region_try_from_rc_str_carries_through_generic_consumer`
    /// (commit 0e9bc9f) and
    /// `test_admission_tier_try_from_rc_str_carries_through_generic_consumer`
    /// (commit 9545b4d) at the version-bump-magnitude ladder.
    #[test]
    fn test_bump_level_try_from_rc_str_carries_through_generic_consumer() {
        fn parse<T>(s: std::rc::Rc<str>) -> T
        where
            T: std::convert::TryFrom<std::rc::Rc<str>>,
            <T as std::convert::TryFrom<std::rc::Rc<str>>>::Error: std::fmt::Debug,
        {
            <T as std::convert::TryFrom<std::rc::Rc<str>>>::try_from(s)
                .expect("canonical label must parse through generic TryFrom<Rc<str>>")
        }

        for level in BumpLevel::ALL {
            assert_eq!(
                parse::<BumpLevel>(std::rc::Rc::<str>::from(level.as_str())),
                level,
                "generic TryFrom<Rc<str>> consumer must recover canonical variant at {level:?}",
            );
        }
    }

    /// [`TryFrom<Rc<str>> for BumpLevel`] rejects non-canonical input
    /// with the same strictness [`std::str::FromStr`] enforces — empty
    /// string, UpperCamel rendering, uppercase, whitespace padding, and
    /// mangled labels all reject when wrapped in an [`Rc<str>`]. Pins
    /// the strict-rejection contract at the by-value [`Rc<str>`] try-
    /// conversion surface so a downstream consumer bound by
    /// [`TryFrom<Rc<str>>`] (a serde `try_from = "Rc<str>"` container, a
    /// builder that consumes a thread-local shared-owned canonical label
    /// at the thread-local-shared-owned frontier for cheap same-thread
    /// [`Rc::clone`] semantics on the input) inherits the same
    /// canonical-only grammar the direct `.parse::<BumpLevel>()` call
    /// sites and the sibling [`TryFrom<&str>`] / [`TryFrom<String>`] /
    /// [`TryFrom<Cow<'_, str>>`] / [`TryFrom<Box<str>>`] /
    /// [`TryFrom<Arc<str>>`] impls already read, and a future permissive-
    /// parse regression at the underlying [`FromStr`] impl lights up here
    /// rather than drifting silently through the thread-local-shared-
    /// owned-frontier try-conversion surface. Structural mirror of
    /// `test_per_attempt_region_try_from_rc_str_rejects_non_canonical_input`
    /// (commit 0e9bc9f) and
    /// `test_admission_tier_try_from_rc_str_rejects_non_canonical_input`
    /// (commit 9545b4d) at the version-bump-magnitude ladder.
    #[test]
    fn test_bump_level_try_from_rc_str_rejects_non_canonical_input() {
        for bad in [
            "", "Patch", "Minor", "Major", "PATCH", " patch", "patch ", "pat",
        ] {
            assert!(
                <BumpLevel as std::convert::TryFrom<std::rc::Rc<str>>>::try_from(
                    std::rc::Rc::<str>::from(bad)
                )
                .is_err(),
                "TryFrom<Rc<str>> must reject non-canonical input {bad:?}",
            );
        }
    }

    /// [`TryFrom<&std::ffi::OsStr> for BumpLevel`] recovers the
    /// original variant at every [`BumpLevel::ALL`] variant when the
    /// canonical label emitted by
    /// [`std::ffi::OsStr::new`]`(level.as_str())` is fed back through
    /// it. Pins the round-trip identity `BumpLevel::try_from(
    /// std::ffi::OsStr::new(level.as_str())).unwrap() == level` at
    /// every variant against the shared [`BumpLevel::as_str`] +
    /// [`std::ffi::OsStr::new`] canonical-label OS-string oracle. The
    /// structural witness that the by-reference OS-string parse
    /// surface (this [`TryFrom<&std::ffi::OsStr>`]) reads the same
    /// one-oracle grammar the by-reference UTF-8 parse peer
    /// [`TryFrom<&str>`] and the by-reference byte-slice parse peer
    /// [`TryFrom<&[u8]>`] read — one round-trip pin per variant,
    /// refuses a future variant insertion that drops the
    /// `TryFrom<&OsStr>`/`OsStr::new(as_str())` agreement. Structural
    /// mirror of
    /// `test_per_attempt_region_try_from_os_str_agrees_with_from_str`
    /// (commit d37e6fe) at the per-attempt-region ladder and
    /// `test_admission_tier_try_from_os_str_agrees_with_from_str`
    /// (commit 9fca3bb) at the admission-tier ladder.
    #[test]
    fn test_bump_level_try_from_os_str_agrees_with_from_str() {
        for level in BumpLevel::ALL {
            let parsed = <BumpLevel as std::convert::TryFrom<&std::ffi::OsStr>>::try_from(
                std::ffi::OsStr::new(level.as_str()),
            )
            .expect("canonical label OsStr must parse through TryFrom<&OsStr>");
            assert_eq!(
                parsed, level,
                "TryFrom<&OsStr> must round-trip through OsStr::new(as_str()) at {level:?}",
            );
        }
    }

    /// The [`TryFrom<&std::ffi::OsStr> for BumpLevel`] identity
    /// carries through a generic `impl for<'a> TryFrom<&'a
    /// std::ffi::OsStr>` consumer at every [`BumpLevel::ALL`]
    /// variant. A tiny generic function `fn parse<T>(o: &OsStr) -> T
    /// where T: for<'a> TryFrom<&'a OsStr>, T::Error: std::fmt::Debug`
    /// — the shape of an actual downstream consumer (a
    /// [`std::env::var_os`] reader that decodes a canonical
    /// [`BumpLevel`] label from a process-environment slot without a
    /// [`std::ffi::OsString`] intermediate, a
    /// [`std::process::Command::get_args`] iterator inspector reading
    /// a canonical label CLI argument, a
    /// [`std::path::Path::file_name`] receiver over a
    /// bump-magnitude-labeled path segment, a generic try-conversion
    /// helper) — recovers the canonical variant from the canonical
    /// lowercase label OS-string at every variant. The structural
    /// witness that a [`BumpLevel`] is genuinely usable at
    /// `impl for<'a> TryFrom<&'a std::ffi::OsStr>` call sites — a
    /// regression that drifted the [`TryFrom`] impl signature
    /// (requiring an owned [`std::ffi::OsString`] input, dropping the
    /// [`std::ffi::OsStr::to_str`] decode step and misparsing
    /// non-Unicode input, returning a different variant than
    /// [`std::str::FromStr`] would) fails here at compile time or at
    /// the assertion instead of at every downstream generic call
    /// site.
    #[test]
    fn test_bump_level_try_from_os_str_carries_through_generic_consumer() {
        fn parse<T>(o: &std::ffi::OsStr) -> T
        where
            T: for<'a> std::convert::TryFrom<&'a std::ffi::OsStr>,
            for<'a> <T as std::convert::TryFrom<&'a std::ffi::OsStr>>::Error: std::fmt::Debug,
        {
            <T as std::convert::TryFrom<&std::ffi::OsStr>>::try_from(o)
                .expect("canonical label OsStr must parse through generic TryFrom<&OsStr>")
        }

        for level in BumpLevel::ALL {
            assert_eq!(
                parse::<BumpLevel>(std::ffi::OsStr::new(level.as_str())),
                level,
                "generic TryFrom<&OsStr> consumer must recover canonical variant at {level:?}",
            );
        }
    }

    /// [`TryFrom<&std::ffi::OsStr> for BumpLevel`] rejects non-Unicode
    /// OS-string sequences at the [`std::ffi::OsStr::to_str`] decode
    /// frontier. On Unix a `&OsStr` may hold any byte sequence — an
    /// invalid-UTF-8 filesystem path segment from a foreign locale or
    /// a malformed shell-quoted CLI argument. Pins the
    /// encoding-strictness contract at the OS-string frontier's first
    /// strictness gate so a downstream consumer bound by
    /// [`TryFrom<&std::ffi::OsStr>`] inherits the same Unicode-only
    /// encoding discipline a direct [`std::ffi::OsStr::to_str`] +
    /// [`str::parse`] composition would offer, at ONE typed-primitive
    /// site rather than a per-consumer two-step restatement. Sibling
    /// of the UTF-8-frontier pin
    /// [`test_bump_level_try_from_bytes_rejects_non_utf8_input`] at
    /// the byte-slice frontier — both pin the encoding-strictness
    /// contract at the parse peer's first strictness gate.
    #[cfg(unix)]
    #[test]
    fn test_bump_level_try_from_os_str_rejects_non_unicode_input() {
        use std::os::unix::ffi::OsStrExt;
        for bad in [
            &[0xffu8][..],
            &[0xffu8, 0xfe][..],
            &[0x80][..],
            &[b'p', b'a', 0xff, b't', b'c', b'h'][..],
            &[b'm', b'a', b'j', b'o', b'r', 0xff][..],
        ] {
            let bad_os = std::ffi::OsStr::from_bytes(bad);
            assert!(
                <BumpLevel as std::convert::TryFrom<&std::ffi::OsStr>>::try_from(bad_os).is_err(),
                "TryFrom<&OsStr> must reject non-Unicode input {bad:?}",
            );
        }
    }

    /// [`TryFrom<&std::ffi::OsStr> for BumpLevel`] rejects
    /// valid-Unicode non-canonical OS-string sequences at the
    /// underlying [`std::str::FromStr`] strictness gate — empty
    /// OS-string, UpperCamel rendering, uppercase, whitespace
    /// padding, and truncated labels all reject. Pins the
    /// canonical-label strictness contract at the OS-string
    /// frontier's second strictness gate so a downstream consumer
    /// bound by [`TryFrom<&std::ffi::OsStr>`] inherits the same
    /// canonical-only grammar the direct `.parse::<BumpLevel>()` call
    /// sites and the sibling [`TryFrom<&str>`], [`TryFrom<&[u8]>`]
    /// impls already read, and a future permissive-parse regression
    /// at the underlying [`std::str::FromStr`] impl lights up here
    /// rather than drifting silently through the OS-string
    /// try-conversion surface. Sibling of the UTF-8-frontier pin
    /// [`test_bump_level_try_from_str_rejects_non_canonical_input`]
    /// and the byte-slice-frontier pin
    /// [`test_bump_level_try_from_bytes_rejects_non_canonical_input`]
    /// at the by-reference parse peers — the three pins together
    /// close the canonical-only strictness contract across the UTF-8,
    /// byte-slice, and OS-string frontiers.
    #[test]
    fn test_bump_level_try_from_os_str_rejects_non_canonical_input() {
        for bad in [
            "", "Patch", "Minor", "Major", "PATCH", " patch", "patch ", "pat",
        ] {
            let bad_os = std::ffi::OsStr::new(bad);
            assert!(
                <BumpLevel as std::convert::TryFrom<&std::ffi::OsStr>>::try_from(bad_os).is_err(),
                "TryFrom<&OsStr> must reject valid-Unicode non-canonical input {bad:?}",
            );
        }
    }

    /// [`TryFrom<std::ffi::OsString> for BumpLevel`] agrees with
    /// [`std::str::FromStr`] at every [`BumpLevel::ALL`] variant.
    /// Owning the [`std::ffi::OsString`] input round-trips through
    /// [`std::ffi::OsString::from(level.as_str())`] and the by-value
    /// owned-buffer OS-string try-conversion recovers the canonical
    /// variant — the by-value owned-buffer OS-string parse peer of the
    /// by-reference [`TryFrom<&std::ffi::OsStr>`] surface reads the
    /// same one-oracle grammar the by-value owned-buffer UTF-8 parse
    /// peer [`TryFrom<String>`] and the by-value owned-buffer
    /// byte-slice parse peer [`TryFrom<Vec<u8>>`] read — one
    /// round-trip pin per variant, refuses a future variant insertion
    /// that drops the `TryFrom<OsString>`/`OsString::from(as_str())`
    /// agreement. Structural mirror of
    /// `test_per_attempt_region_try_from_os_string_agrees_with_from_str`
    /// (commit e629465) at the per-attempt-region ladder and
    /// `test_admission_tier_try_from_os_string_agrees_with_from_str`
    /// (commit 810794b) at the admission-tier ladder.
    #[test]
    fn test_bump_level_try_from_os_string_agrees_with_from_str() {
        for level in BumpLevel::ALL {
            let parsed = <BumpLevel as std::convert::TryFrom<std::ffi::OsString>>::try_from(
                std::ffi::OsString::from(level.as_str()),
            )
            .expect("canonical label OsString must parse through TryFrom<OsString>");
            assert_eq!(
                parsed, level,
                "TryFrom<OsString> must round-trip through OsString::from(as_str()) at {level:?}",
            );
        }
    }

    /// The [`TryFrom<std::ffi::OsString> for BumpLevel`] identity
    /// carries through a generic `impl TryFrom<std::ffi::OsString>`
    /// consumer at every [`BumpLevel::ALL`] variant. A tiny generic
    /// function `fn parse<T>(o: OsString) -> T where T:
    /// TryFrom<OsString>, T::Error: std::fmt::Debug` — the shape of an
    /// actual downstream consumer (a [`std::env::var_os`] receiver
    /// that owns the returned [`std::ffi::OsString`] and decodes a
    /// canonical [`BumpLevel`] label from a process-environment slot
    /// without a borrow-then-clone round trip, a
    /// [`std::env::args_os`] iterator consumer over owned CLI-argument
    /// [`std::ffi::OsString`] elements, a
    /// [`std::path::PathBuf::into_os_string`] terminus at the
    /// filesystem-frontier layer, a generic try-conversion helper) —
    /// recovers the canonical variant from the canonical lowercase
    /// label owned OS-string at every variant. The structural witness
    /// that a [`BumpLevel`] is genuinely usable at
    /// `impl TryFrom<std::ffi::OsString>` call sites — a regression
    /// that drifted the [`TryFrom`] impl signature (requiring a
    /// borrowed [`&std::ffi::OsStr`] input, dropping the
    /// [`std::ffi::OsString::as_os_str`] borrow step and misparsing
    /// non-Unicode input, returning a different variant than
    /// [`std::str::FromStr`] would) fails here at compile time or at
    /// the assertion instead of at every downstream generic call
    /// site.
    #[test]
    fn test_bump_level_try_from_os_string_carries_through_generic_consumer() {
        fn parse<T>(o: std::ffi::OsString) -> T
        where
            T: std::convert::TryFrom<std::ffi::OsString>,
            <T as std::convert::TryFrom<std::ffi::OsString>>::Error: std::fmt::Debug,
        {
            <T as std::convert::TryFrom<std::ffi::OsString>>::try_from(o)
                .expect("canonical label OsString must parse through generic TryFrom<OsString>")
        }

        for level in BumpLevel::ALL {
            assert_eq!(
                parse::<BumpLevel>(std::ffi::OsString::from(level.as_str())),
                level,
                "generic TryFrom<OsString> consumer must recover canonical variant at {level:?}",
            );
        }
    }

    /// [`TryFrom<std::ffi::OsString> for BumpLevel`] rejects
    /// non-Unicode owned OS-string sequences at the
    /// [`std::ffi::OsStr::to_str`] decode frontier inherited through
    /// the by-reference [`TryFrom<&std::ffi::OsStr>`] delegation. On
    /// Unix a [`std::ffi::OsString`] may hold any byte sequence — an
    /// owned invalid-UTF-8 filesystem path segment from a foreign
    /// locale, an owned malformed shell-quoted CLI argument yielded by
    /// [`std::env::args_os`], an owned [`std::env::var_os`] payload
    /// from a locale-tainted process-environment slot. Pins the
    /// encoding-strictness contract at the owned-buffer OS-string
    /// frontier's first strictness gate so a downstream consumer bound
    /// by [`TryFrom<std::ffi::OsString>`] inherits the same
    /// Unicode-only encoding discipline the by-reference peer offers,
    /// at ONE typed-primitive site rather than a per-consumer
    /// [`std::ffi::OsString::into_string`] + [`str::parse`]
    /// restatement. Sibling of the by-reference OS-string pin
    /// [`test_bump_level_try_from_os_str_rejects_non_unicode_input`]
    /// at the by-reference peer, the byte-slice frontier pin
    /// [`test_bump_level_try_from_bytes_rejects_non_utf8_input`]
    /// at the by-reference byte-slice peer, and the byte-slice
    /// owned-buffer pin
    /// [`test_bump_level_try_from_vec_bytes_rejects_non_utf8_input`]
    /// — all pin the encoding-strictness contract at the parse peer's
    /// first strictness gate.
    #[cfg(unix)]
    #[test]
    fn test_bump_level_try_from_os_string_rejects_non_unicode_input() {
        use std::os::unix::ffi::OsStringExt;
        for bad in [
            vec![0xffu8],
            vec![0xffu8, 0xfe],
            vec![0x80],
            vec![b'p', b'a', 0xff, b't', b'c', b'h'],
            vec![b'm', b'a', b'j', b'o', b'r', 0xff],
        ] {
            let bad_os = std::ffi::OsString::from_vec(bad.clone());
            assert!(
                <BumpLevel as std::convert::TryFrom<std::ffi::OsString>>::try_from(bad_os).is_err(),
                "TryFrom<OsString> must reject non-Unicode input {bad:?}",
            );
        }
    }

    /// [`TryFrom<std::ffi::OsString> for BumpLevel`] rejects
    /// valid-Unicode non-canonical owned OS-string sequences at the
    /// underlying [`std::str::FromStr`] strictness gate inherited
    /// through the by-reference [`TryFrom<&std::ffi::OsStr>`]
    /// delegation — empty OS-string, UpperCamel rendering, uppercase,
    /// whitespace padding, and truncated labels all reject. Pins the
    /// canonical-label strictness contract at the owned-buffer
    /// OS-string frontier's second strictness gate so a downstream
    /// consumer bound by [`TryFrom<std::ffi::OsString>`] inherits the
    /// same canonical-only grammar the direct `.parse::<BumpLevel>()`
    /// call sites and the sibling [`TryFrom<&str>`],
    /// [`TryFrom<String>`], [`TryFrom<&[u8]>`], [`TryFrom<Vec<u8>>`],
    /// and [`TryFrom<&std::ffi::OsStr>`] impls already read, and a
    /// future permissive-parse regression at the underlying
    /// [`std::str::FromStr`] impl lights up here rather than drifting
    /// silently through the owned-buffer OS-string try-conversion
    /// surface. Sibling of the by-reference OS-string pin
    /// [`test_bump_level_try_from_os_str_rejects_non_canonical_input`]
    /// at the by-reference peer, the UTF-8-owned-buffer pin
    /// [`test_bump_level_try_from_string_rejects_non_canonical_input`]
    /// at the UTF-8 frontier, and the byte-slice-owned-buffer pin
    /// [`test_bump_level_try_from_vec_bytes_rejects_non_canonical_input`]
    /// at the byte-slice frontier — the four pins together close the
    /// canonical-only strictness contract across the UTF-8,
    /// byte-slice, and OS-string frontiers' owned-buffer parse
    /// surfaces.
    #[test]
    fn test_bump_level_try_from_os_string_rejects_non_canonical_input() {
        for bad in [
            "", "Patch", "Minor", "Major", "PATCH", " patch", "patch ", "pat",
        ] {
            let bad_os = std::ffi::OsString::from(bad);
            assert!(
                <BumpLevel as std::convert::TryFrom<std::ffi::OsString>>::try_from(bad_os).is_err(),
                "TryFrom<OsString> must reject valid-Unicode non-canonical input {bad:?}",
            );
        }
    }

    /// [`TryFrom<&std::path::Path> for BumpLevel`] agrees with
    /// [`FromStr`] at every [`BumpLevel::ALL`] variant. The borrowed
    /// [`&std::path::Path`] input round-trips through
    /// [`std::path::Path::new(level.as_str())`] and the by-reference
    /// filesystem-path try-conversion recovers the canonical variant
    /// — the by-reference filesystem-path parse peer of the
    /// by-reference OS-string [`TryFrom<&std::ffi::OsStr>`] surface
    /// reads the same one-oracle grammar the sibling frontiers'
    /// by-reference parse peers already read. One round-trip pin per
    /// variant, refuses a future variant insertion that drops the
    /// `TryFrom<&Path>`/`Path::new(as_str())` agreement. Structural
    /// mirror of `test_per_attempt_region_try_from_path_agrees_with_from_str`
    /// (commit dba4c6b) at the per-attempt-region ladder and
    /// `test_admission_tier_try_from_path_agrees_with_from_str`
    /// (commit 321b2d8) at the admission-tier ladder.
    #[test]
    fn test_bump_level_try_from_path_agrees_with_from_str() {
        for level in BumpLevel::ALL {
            let parsed = <BumpLevel as std::convert::TryFrom<&std::path::Path>>::try_from(
                std::path::Path::new(level.as_str()),
            )
            .expect("canonical label &Path must parse through TryFrom<&Path>");
            assert_eq!(
                parsed, level,
                "TryFrom<&Path> must round-trip through Path::new(as_str()) at {level:?}",
            );
        }
    }

    /// The [`TryFrom<&std::path::Path> for BumpLevel`] identity carries
    /// through a generic `impl for<'a> TryFrom<&'a std::path::Path>`
    /// consumer at every [`BumpLevel::ALL`] variant. A tiny generic
    /// function `fn parse<T>(p: &Path) -> T where T: for<'a>
    /// TryFrom<&'a Path>, T::Error: std::fmt::Debug` — the shape of an
    /// actual downstream consumer (a [`std::path::Path::file_name`]
    /// receiver decoding a canonical [`BumpLevel`] label from a
    /// release-manifest filesystem-path segment, a
    /// [`std::fs::read_dir`] iterator inspector reading each entry's
    /// borrowed [`&std::path::Path`] view over a release-directory
    /// tree, a `walkdir` traversal borrowing each visited
    /// [`&std::path::Path`] without a [`std::path::PathBuf`]
    /// allocation, a generic try-conversion helper) — recovers the
    /// canonical variant from the canonical lowercase-label borrowed
    /// [`&std::path::Path`] at every variant. The structural witness
    /// that a [`BumpLevel`] is genuinely usable at
    /// `impl for<'a> TryFrom<&'a std::path::Path>` call sites — a
    /// regression that drifted the [`TryFrom`] impl signature
    /// (requiring an owned [`std::path::PathBuf`] input, dropping the
    /// [`std::path::Path::as_os_str`] borrow step and misparsing
    /// non-Unicode input, returning a different variant than
    /// [`FromStr`] would) fails here at compile time or at the
    /// assertion instead of at every downstream generic call site.
    #[test]
    fn test_bump_level_try_from_path_carries_through_generic_consumer() {
        fn parse<T>(p: &std::path::Path) -> T
        where
            for<'a> T: std::convert::TryFrom<&'a std::path::Path>,
            for<'a> <T as std::convert::TryFrom<&'a std::path::Path>>::Error: std::fmt::Debug,
        {
            <T as std::convert::TryFrom<&std::path::Path>>::try_from(p)
                .expect("canonical label &Path must parse through generic TryFrom<&Path>")
        }

        for level in BumpLevel::ALL {
            assert_eq!(
                parse::<BumpLevel>(std::path::Path::new(level.as_str())),
                level,
                "generic TryFrom<&Path> consumer must recover canonical variant at {level:?}",
            );
        }
    }

    /// [`TryFrom<&std::path::Path> for BumpLevel`] rejects non-Unicode
    /// borrowed filesystem-path sequences at the
    /// [`std::ffi::OsStr::to_str`] decode frontier reached through
    /// [`std::path::Path::as_os_str`] inherited through the
    /// by-reference [`TryFrom<&std::ffi::OsStr>`] delegation. On Unix a
    /// [`&std::path::Path`] wraps a [`&std::ffi::OsStr`] that may hold
    /// any byte sequence — an invalid-UTF-8 filesystem path segment
    /// from a foreign locale, a `walkdir` traversal element whose
    /// [`std::path::Path::file_name`] returns a non-Unicode
    /// [`&std::ffi::OsStr`], a [`std::fs::read_dir`] iterator entry
    /// whose [`std::fs::DirEntry::path`] returns a
    /// [`std::path::PathBuf`] whose borrowed
    /// [`std::path::Path::file_name`] view is not valid Unicode. Pins
    /// the encoding-strictness contract at the borrowed-view
    /// filesystem-path frontier's first strictness gate so a
    /// downstream consumer bound by [`TryFrom<&std::path::Path>`]
    /// inherits the same Unicode-only encoding discipline the
    /// by-reference OS-string peer offers, at ONE typed-primitive site
    /// rather than a per-consumer [`std::path::Path::to_str`] +
    /// [`str::parse`] restatement. Sibling of the by-reference
    /// OS-string pin
    /// [`test_bump_level_try_from_os_str_rejects_non_unicode_input`]
    /// at the by-reference OS-string peer, the owned-buffer OS-string
    /// pin
    /// [`test_bump_level_try_from_os_string_rejects_non_unicode_input`]
    /// at the by-value OS-string peer, and the UTF-8-frontier pin
    /// [`test_bump_level_try_from_bytes_rejects_non_utf8_input`] at
    /// the byte-slice frontier — all pin the encoding-strictness
    /// contract at the parse peer's first strictness gate.
    #[cfg(unix)]
    #[test]
    fn test_bump_level_try_from_path_rejects_non_unicode_input() {
        use std::os::unix::ffi::OsStrExt;
        for bad in [
            vec![0xffu8],
            vec![0xffu8, 0xfe],
            vec![0x80],
            vec![b'p', b'a', 0xff, b't', b'c', b'h'],
            vec![b'm', b'a', b'j', b'o', b'r', 0xff],
        ] {
            let bad_os = std::ffi::OsStr::from_bytes(&bad);
            let bad_path = std::path::Path::new(bad_os);
            assert!(
                <BumpLevel as std::convert::TryFrom<&std::path::Path>>::try_from(bad_path).is_err(),
                "TryFrom<&Path> must reject non-Unicode input {bad:?}",
            );
        }
    }

    /// [`TryFrom<&std::path::Path> for BumpLevel`] rejects valid-Unicode
    /// non-canonical borrowed filesystem-path sequences at the
    /// underlying [`FromStr`] strictness gate inherited through the
    /// by-reference [`TryFrom<&std::ffi::OsStr>`] delegation via
    /// [`std::path::Path::as_os_str`] — empty path, UpperCamel
    /// rendering, uppercase, whitespace padding, and truncated labels
    /// all reject. Pins the canonical-label strictness contract at the
    /// borrowed-view filesystem-path frontier's second strictness gate
    /// so a downstream consumer bound by [`TryFrom<&std::path::Path>`]
    /// inherits the same canonical-only grammar the direct
    /// `.parse::<BumpLevel>()` call sites and the sibling
    /// [`TryFrom<&str>`], [`TryFrom<String>`], [`TryFrom<&[u8]>`],
    /// [`TryFrom<Vec<u8>>`], [`TryFrom<&std::ffi::OsStr>`], and
    /// [`TryFrom<std::ffi::OsString>`] impls already read, and a future
    /// permissive-parse regression at the underlying [`FromStr`] impl
    /// lights up here rather than drifting silently through the
    /// borrowed-view filesystem-path try-conversion surface. Sibling
    /// of the by-reference OS-string pin
    /// [`test_bump_level_try_from_os_str_rejects_non_canonical_input`]
    /// at the by-reference OS-string peer, the owned-buffer OS-string
    /// pin
    /// [`test_bump_level_try_from_os_string_rejects_non_canonical_input`]
    /// at the by-value OS-string peer, the UTF-8-owned-buffer pin
    /// [`test_bump_level_try_from_string_rejects_non_canonical_input`]
    /// at the UTF-8 frontier, and the byte-slice-owned-buffer pin
    /// [`test_bump_level_try_from_vec_bytes_rejects_non_canonical_input`]
    /// at the byte-slice frontier — the pins together close the
    /// canonical-only strictness contract across the UTF-8,
    /// byte-slice, OS-string, and filesystem-path frontiers' parse
    /// surfaces.
    #[test]
    fn test_bump_level_try_from_path_rejects_non_canonical_input() {
        for bad in [
            "", "Patch", "Minor", "Major", "PATCH", " patch", "patch ", "pat",
        ] {
            let bad_path = std::path::Path::new(bad);
            assert!(
                <BumpLevel as std::convert::TryFrom<&std::path::Path>>::try_from(bad_path).is_err(),
                "TryFrom<&Path> must reject valid-Unicode non-canonical input {bad:?}",
            );
        }
    }

    /// [`TryFrom<std::path::PathBuf> for BumpLevel`] agrees with
    /// [`FromStr`] at every [`BumpLevel::ALL`] variant. The owned
    /// [`std::path::PathBuf`] input round-trips through
    /// [`std::path::PathBuf::from(level.as_str())`] and the by-value
    /// owned-buffer filesystem-path try-conversion recovers the
    /// canonical variant — the by-value owned-buffer filesystem-path
    /// parse peer of the by-reference [`TryFrom<&std::path::Path>`]
    /// surface reads the same one-oracle grammar the by-value
    /// owned-buffer OS-string parse peer [`TryFrom<std::ffi::OsString>`]
    /// and the by-value owned-buffer UTF-8 parse peer
    /// [`TryFrom<String>`] read — one round-trip pin per variant,
    /// refuses a future variant insertion that drops the
    /// `TryFrom<PathBuf>`/`PathBuf::from(as_str())` agreement.
    /// Structural mirror of
    /// `test_per_attempt_region_try_from_path_buf_agrees_with_from_str`
    /// (commit 33e4e48) at the per-attempt-region ladder and
    /// `test_admission_tier_try_from_path_buf_agrees_with_from_str`
    /// (commit 2855792) at the admission-tier ladder.
    #[test]
    fn test_bump_level_try_from_path_buf_agrees_with_from_str() {
        for level in BumpLevel::ALL {
            let parsed = <BumpLevel as std::convert::TryFrom<std::path::PathBuf>>::try_from(
                std::path::PathBuf::from(level.as_str()),
            )
            .expect("canonical label PathBuf must parse through TryFrom<PathBuf>");
            assert_eq!(
                parsed, level,
                "TryFrom<PathBuf> must round-trip through PathBuf::from(as_str()) at {level:?}",
            );
        }
    }

    /// The [`TryFrom<std::path::PathBuf> for BumpLevel`] identity
    /// carries through a generic `impl TryFrom<std::path::PathBuf>`
    /// consumer at every [`BumpLevel::ALL`] variant. A tiny generic
    /// function `fn parse<T>(p: PathBuf) -> T where T: TryFrom<PathBuf>,
    /// T::Error: std::fmt::Debug` — the shape of an actual downstream
    /// consumer (a [`std::fs::read_dir`] iterator element whose
    /// [`std::fs::DirEntry::path`] returns an owned
    /// [`std::path::PathBuf`] naming a bump-level-labeled release-
    /// manifest subdirectory, a `walkdir::DirEntry::into_path` sink
    /// surrendering an owned [`std::path::PathBuf`], a
    /// [`std::env::current_dir`] receiver decoding a canonical
    /// [`BumpLevel`] label from the working-directory name, a `clap`
    /// argument-parse frontier materializing an owned
    /// [`std::path::PathBuf`] from a CLI flag, a generic
    /// try-conversion helper) — recovers the canonical variant from
    /// the canonical lowercase-label owned filesystem-path buffer at
    /// every variant. The structural witness that a [`BumpLevel`] is
    /// genuinely usable at `impl TryFrom<std::path::PathBuf>` call
    /// sites — a regression that drifted the [`TryFrom`] impl
    /// signature (requiring a borrowed [`&std::path::Path`] input,
    /// dropping the [`std::path::PathBuf::as_path`] borrow step and
    /// misparsing non-Unicode input, returning a different variant
    /// than [`FromStr`] would) fails here at compile time or at the
    /// assertion instead of at every downstream generic call site.
    #[test]
    fn test_bump_level_try_from_path_buf_carries_through_generic_consumer() {
        fn parse<T>(p: std::path::PathBuf) -> T
        where
            T: std::convert::TryFrom<std::path::PathBuf>,
            <T as std::convert::TryFrom<std::path::PathBuf>>::Error: std::fmt::Debug,
        {
            <T as std::convert::TryFrom<std::path::PathBuf>>::try_from(p)
                .expect("canonical label PathBuf must parse through generic TryFrom<PathBuf>")
        }

        for level in BumpLevel::ALL {
            assert_eq!(
                parse::<BumpLevel>(std::path::PathBuf::from(level.as_str())),
                level,
                "generic TryFrom<PathBuf> consumer must recover canonical variant at {level:?}",
            );
        }
    }

    /// [`TryFrom<std::path::PathBuf> for BumpLevel`] rejects
    /// non-Unicode owned filesystem-path sequences at the
    /// [`std::ffi::OsStr::to_str`] decode frontier reached through
    /// [`std::path::PathBuf::as_path`] →
    /// [`std::path::Path::as_os_str`] inherited through the
    /// by-reference [`TryFrom<&std::path::Path>`] delegation. On Unix
    /// a [`std::path::PathBuf`] wraps a [`std::ffi::OsString`] that
    /// may hold any byte sequence — an owned
    /// [`std::fs::DirEntry::path`] return that is not valid Unicode,
    /// a `walkdir::DirEntry::into_path` sink whose owned
    /// [`std::path::PathBuf`] carries a foreign-locale byte segment,
    /// a [`std::env::current_dir`] receiver whose owned
    /// working-directory name is non-Unicode. Pins the
    /// encoding-strictness contract at the owned-buffer
    /// filesystem-path frontier's first strictness gate so a
    /// downstream consumer bound by [`TryFrom<std::path::PathBuf>`]
    /// inherits the same Unicode-only encoding discipline the
    /// by-reference filesystem-path peer offers, at ONE typed-
    /// primitive site rather than a per-consumer
    /// [`std::path::PathBuf::into_os_string`] + [`str::parse`]
    /// restatement.
    #[cfg(unix)]
    #[test]
    fn test_bump_level_try_from_path_buf_rejects_non_unicode_input() {
        use std::os::unix::ffi::OsStringExt;
        for bad in [
            vec![0xffu8],
            vec![0xffu8, 0xfe],
            vec![0x80],
            vec![b'p', b'a', 0xff, b't', b'c', b'h'],
            vec![b'm', b'a', b'j', b'o', b'r', 0xff],
        ] {
            let bad_os = std::ffi::OsString::from_vec(bad.clone());
            let bad_path_buf = std::path::PathBuf::from(bad_os);
            assert!(
                <BumpLevel as std::convert::TryFrom<std::path::PathBuf>>::try_from(bad_path_buf)
                    .is_err(),
                "TryFrom<PathBuf> must reject non-Unicode input {bad:?}",
            );
        }
    }

    /// [`TryFrom<std::path::PathBuf> for BumpLevel`] rejects
    /// valid-Unicode non-canonical owned filesystem-path sequences at
    /// the underlying [`FromStr`] strictness gate inherited through
    /// the by-reference [`TryFrom<&std::path::Path>`] delegation via
    /// [`std::path::PathBuf::as_path`] — empty path, UpperCamel
    /// rendering, uppercase, whitespace padding, and truncated labels
    /// all reject. Pins the canonical-label strictness contract at
    /// the owned-buffer filesystem-path frontier's second strictness
    /// gate so a downstream consumer bound by
    /// [`TryFrom<std::path::PathBuf>`] inherits the same
    /// canonical-only grammar the direct `.parse::<BumpLevel>()` call
    /// sites and the sibling [`TryFrom<&str>`], [`TryFrom<String>`],
    /// [`TryFrom<&[u8]>`], [`TryFrom<Vec<u8>>`],
    /// [`TryFrom<&std::ffi::OsStr>`], [`TryFrom<std::ffi::OsString>`],
    /// and [`TryFrom<&std::path::Path>`] impls already read, and a
    /// future permissive-parse regression at the underlying
    /// [`FromStr`] impl lights up here rather than drifting silently
    /// through the owned-buffer filesystem-path try-conversion
    /// surface.
    #[test]
    fn test_bump_level_try_from_path_buf_rejects_non_canonical_input() {
        for bad in [
            "", "Patch", "Minor", "Major", "PATCH", " patch", "patch ", "pat",
        ] {
            let bad_path_buf = std::path::PathBuf::from(bad);
            assert!(
                <BumpLevel as std::convert::TryFrom<std::path::PathBuf>>::try_from(bad_path_buf)
                    .is_err(),
                "TryFrom<PathBuf> must reject valid-Unicode non-canonical input {bad:?}",
            );
        }
    }

    /// [`TryFrom<Cow<'_, std::ffi::OsStr>> for BumpLevel`] recovers the
    /// original variant at every [`BumpLevel::ALL`] variant when the
    /// canonical label emitted by [`BumpLevel::as_str`] is fed back
    /// through it in BOTH [`std::borrow::Cow::Borrowed`] (a
    /// [`std::ffi::OsStr::new`] view over the canonical label wrapped
    /// in [`std::borrow::Cow::Borrowed`]) and
    /// [`std::borrow::Cow::Owned`] (a [`std::ffi::OsString::from`]
    /// materialization wrapped in [`std::borrow::Cow::Owned`]) forms.
    /// Pins the round-trip identity at both variants of the borrowed/
    /// owned frontier against the shared canonical-label oracle.
    /// Structural mirror of
    /// [`test_per_attempt_region_try_from_cow_os_str_agrees_with_from_str`]
    /// and
    /// [`test_admission_tier_try_from_cow_os_str_agrees_with_from_str`]
    /// at the version-bump-magnitude ladder.
    #[test]
    fn test_bump_level_try_from_cow_os_str_agrees_with_from_str() {
        for level in BumpLevel::ALL {
            let borrowed: std::borrow::Cow<'_, std::ffi::OsStr> =
                std::borrow::Cow::Borrowed(std::ffi::OsStr::new(level.as_str()));
            let parsed_borrowed = <BumpLevel as std::convert::TryFrom<
                std::borrow::Cow<'_, std::ffi::OsStr>,
            >>::try_from(borrowed)
            .expect("canonical Cow::Borrowed(OsStr) must parse through TryFrom<Cow<'_, OsStr>>");
            assert_eq!(
                parsed_borrowed, level,
                "TryFrom<Cow<'_, OsStr>> must round-trip Cow::Borrowed at {level:?}",
            );

            let owned: std::borrow::Cow<'_, std::ffi::OsStr> =
                std::borrow::Cow::Owned(std::ffi::OsString::from(level.as_str()));
            let parsed_owned = <BumpLevel as std::convert::TryFrom<
                std::borrow::Cow<'_, std::ffi::OsStr>,
            >>::try_from(owned)
            .expect("canonical Cow::Owned(OsString) must parse through TryFrom<Cow<'_, OsStr>>");
            assert_eq!(
                parsed_owned, level,
                "TryFrom<Cow<'_, OsStr>> must round-trip Cow::Owned at {level:?}",
            );
        }
    }

    /// The [`TryFrom<Cow<'_, std::ffi::OsStr>> for BumpLevel`] identity
    /// carries through a generic
    /// `impl for<'a> TryFrom<Cow<'a, std::ffi::OsStr>>` consumer at
    /// every [`BumpLevel::ALL`] variant on BOTH the borrowed and owned
    /// Cow branches. A tiny generic function
    /// `fn parse<T>(os: Cow<'_, OsStr>) -> T where T: for<'a>
    /// TryFrom<Cow<'a, OsStr>>, T::Error: Debug` — the shape of an
    /// actual downstream consumer (validated-input newtype builder,
    /// serde `try_from` wrapper, generic try-conversion helper that
    /// opts into the [`TryFrom<Cow<'_, std::ffi::OsStr>>`] contract) —
    /// recovers the canonical variant from BOTH borrowed and owned Cow
    /// variants at every variant. The structural witness that a
    /// [`BumpLevel`] is genuinely usable at `impl for<'a>
    /// TryFrom<Cow<'a, OsStr>>` call sites — a regression that drifted
    /// the [`TryFrom`] impl signature (e.g., requiring only owned
    /// [`std::borrow::Cow::Owned`]`(OsString)` instead of accepting
    /// both variants, or returning a different variant on the borrowed
    /// branch than on the owned branch) fails here at compile time or
    /// at the assertion instead of at every downstream generic call
    /// site.
    #[test]
    fn test_bump_level_try_from_cow_os_str_carries_through_generic_consumer() {
        fn parse<T>(os_str: std::borrow::Cow<'_, std::ffi::OsStr>) -> T
        where
            T: for<'a> std::convert::TryFrom<std::borrow::Cow<'a, std::ffi::OsStr>>,
            for<'a> <T as std::convert::TryFrom<std::borrow::Cow<'a, std::ffi::OsStr>>>::Error:
                std::fmt::Debug,
        {
            <T as std::convert::TryFrom<std::borrow::Cow<'_, std::ffi::OsStr>>>::try_from(os_str)
                .expect(
                    "canonical Cow<'_, OsStr> must parse through generic TryFrom<Cow<'_, OsStr>>",
                )
        }

        for level in BumpLevel::ALL {
            let borrowed: std::borrow::Cow<'_, std::ffi::OsStr> =
                std::borrow::Cow::Borrowed(std::ffi::OsStr::new(level.as_str()));
            assert_eq!(
                parse::<BumpLevel>(borrowed),
                level,
                "generic TryFrom<Cow<'_, OsStr>> consumer must recover canonical variant on Cow::Borrowed at {level:?}",
            );

            let owned: std::borrow::Cow<'_, std::ffi::OsStr> =
                std::borrow::Cow::Owned(std::ffi::OsString::from(level.as_str()));
            assert_eq!(
                parse::<BumpLevel>(owned),
                level,
                "generic TryFrom<Cow<'_, OsStr>> consumer must recover canonical variant on Cow::Owned at {level:?}",
            );
        }
    }

    /// [`TryFrom<Cow<'_, std::ffi::OsStr>> for BumpLevel`] rejects non-
    /// Unicode OS-string sequences at the [`std::ffi::OsStr::to_str`]
    /// Unicode-decode frontier reached through
    /// [`std::borrow::Cow::as_ref`] before the [`std::str::FromStr`]
    /// canonical-grammar gate is reached — on BOTH
    /// [`std::borrow::Cow::Borrowed`] (a
    /// [`std::ffi::OsStr::new`]-borrowed non-Unicode byte slice via
    /// [`std::os::unix::ffi::OsStrExt::from_bytes`]) and
    /// [`std::borrow::Cow::Owned`] (a
    /// [`std::ffi::OsString::from`]-owned non-Unicode byte sequence via
    /// [`std::os::unix::ffi::OsStringExt::from_vec`]) branches. Pins
    /// the Unicode-decode strict-rejection contract at the borrowed/
    /// owned-frontier OS-string try-conversion surface so a downstream
    /// consumer bound by [`TryFrom<Cow<'_, std::ffi::OsStr>>`] inherits
    /// the same Unicode-only grammar the sibling
    /// [`TryFrom<&std::ffi::OsStr>`] impl and the direct
    /// `.parse::<BumpLevel>()` call sites already read on both branches
    /// of the borrowed/owned frontier. Unix-only because the only
    /// stable public API for constructing a non-Unicode
    /// [`std::ffi::OsString`] / [`std::ffi::OsStr`] view is via
    /// [`std::os::unix::ffi::OsStringExt::from_vec`] /
    /// [`std::os::unix::ffi::OsStrExt::from_bytes`]; the equivalent
    /// Windows discipline goes through
    /// [`std::os::windows::ffi::OsStringExt::from_wide`] with a lone
    /// surrogate, which is not portable across all non-Unix platforms.
    #[cfg(unix)]
    #[test]
    fn test_bump_level_try_from_cow_os_str_rejects_non_unicode_input() {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::ffi::OsStringExt;

        let non_unicode_bytes: Vec<u8> = vec![0x80, 0xC3, 0xC0, 0x80, 0xFF];

        let owned = std::borrow::Cow::<'_, std::ffi::OsStr>::Owned(std::ffi::OsString::from_vec(
            non_unicode_bytes.clone(),
        ));
        assert!(
            <BumpLevel as std::convert::TryFrom<std::borrow::Cow<'_, std::ffi::OsStr>>>::try_from(
                owned
            )
            .is_err(),
            "TryFrom<Cow<'_, OsStr>> must reject non-Unicode Cow::Owned input",
        );

        let borrowed_os_str = std::ffi::OsStr::from_bytes(&non_unicode_bytes);
        let borrowed = std::borrow::Cow::<'_, std::ffi::OsStr>::Borrowed(borrowed_os_str);
        assert!(
            <BumpLevel as std::convert::TryFrom<std::borrow::Cow<'_, std::ffi::OsStr>>>::try_from(
                borrowed
            )
            .is_err(),
            "TryFrom<Cow<'_, OsStr>> must reject non-Unicode Cow::Borrowed input",
        );
    }

    /// [`TryFrom<Cow<'_, std::ffi::OsStr>> for BumpLevel`] rejects
    /// valid-Unicode non-canonical borrowed/owned OS-string sequences
    /// with the same strictness [`std::str::FromStr`] enforces — empty
    /// string, UpperCamel rendering, uppercase, whitespace padding, and
    /// truncated labels all reject after the Unicode-decode stage
    /// passes, on BOTH [`std::borrow::Cow::Borrowed`] and
    /// [`std::borrow::Cow::Owned`] branches. Pins the FromStr-gate
    /// strict-rejection contract at the borrowed/owned-frontier OS-
    /// string try-conversion surface so a downstream consumer bound by
    /// [`TryFrom<Cow<'_, std::ffi::OsStr>>`] inherits the same
    /// canonical-only grammar the direct `.parse::<BumpLevel>()` call
    /// sites and the sibling [`TryFrom<&std::ffi::OsStr>`] /
    /// [`TryFrom<std::ffi::OsString>`] impls already read, and a future
    /// permissive-parse regression at the underlying
    /// [`std::str::FromStr`] impl lights up here rather than drifting
    /// silently through the borrowed/owned-frontier OS-string try-
    /// conversion surface.
    #[test]
    fn test_bump_level_try_from_cow_os_str_rejects_non_canonical_input() {
        for bad in [
            "", "Patch", "Minor", "Major", "PATCH", " patch", "patch ", "pat",
        ] {
            let borrowed =
                std::borrow::Cow::<'_, std::ffi::OsStr>::Borrowed(std::ffi::OsStr::new(bad));
            assert!(
                <BumpLevel as std::convert::TryFrom<
                    std::borrow::Cow<'_, std::ffi::OsStr>,
                >>::try_from(borrowed)
                .is_err(),
                "TryFrom<Cow<'_, OsStr>> must reject valid-Unicode non-canonical Cow::Borrowed input {bad:?}",
            );

            let owned =
                std::borrow::Cow::<'_, std::ffi::OsStr>::Owned(std::ffi::OsString::from(bad));
            assert!(
                <BumpLevel as std::convert::TryFrom<
                    std::borrow::Cow<'_, std::ffi::OsStr>,
                >>::try_from(owned)
                .is_err(),
                "TryFrom<Cow<'_, OsStr>> must reject valid-Unicode non-canonical Cow::Owned input {bad:?}",
            );
        }
    }

    /// [`TryFrom<Cow<'_, std::path::Path>> for BumpLevel`] recovers the
    /// original variant at every [`BumpLevel::ALL`] variant when the
    /// canonical label emitted by [`BumpLevel::as_str`] is fed back
    /// through it in BOTH [`std::borrow::Cow::Borrowed`] (a
    /// [`std::path::Path::new`] view over the canonical label wrapped in
    /// [`std::borrow::Cow::Borrowed`]) and [`std::borrow::Cow::Owned`] (a
    /// [`std::path::PathBuf::from`] materialization wrapped in
    /// [`std::borrow::Cow::Owned`]) forms. Pins the round-trip identity
    /// at both variants of the borrowed/owned frontier against the shared
    /// canonical-label oracle. Structural mirror of
    /// [`crate::retry::tests::test_per_attempt_region_try_from_cow_path_agrees_with_from_str`]
    /// and
    /// [`crate::probe_outcome::tests::test_admission_tier_try_from_cow_path_agrees_with_from_str`]
    /// at the version-bump-magnitude ladder.
    #[test]
    fn test_bump_level_try_from_cow_path_agrees_with_from_str() {
        for level in BumpLevel::ALL {
            let borrowed: std::borrow::Cow<'_, std::path::Path> =
                std::borrow::Cow::Borrowed(std::path::Path::new(level.as_str()));
            let parsed_borrowed = <BumpLevel as std::convert::TryFrom<
                std::borrow::Cow<'_, std::path::Path>,
            >>::try_from(borrowed)
            .expect("canonical Cow::Borrowed(Path) must parse through TryFrom<Cow<'_, Path>>");
            assert_eq!(
                parsed_borrowed, level,
                "TryFrom<Cow<'_, Path>> must round-trip Cow::Borrowed at {level:?}",
            );

            let owned: std::borrow::Cow<'_, std::path::Path> =
                std::borrow::Cow::Owned(std::path::PathBuf::from(level.as_str()));
            let parsed_owned = <BumpLevel as std::convert::TryFrom<
                std::borrow::Cow<'_, std::path::Path>,
            >>::try_from(owned)
            .expect("canonical Cow::Owned(PathBuf) must parse through TryFrom<Cow<'_, Path>>");
            assert_eq!(
                parsed_owned, level,
                "TryFrom<Cow<'_, Path>> must round-trip Cow::Owned at {level:?}",
            );
        }
    }

    /// The [`TryFrom<Cow<'_, std::path::Path>> for BumpLevel`] identity
    /// carries through a generic
    /// `impl for<'a> TryFrom<Cow<'a, std::path::Path>>` consumer at every
    /// [`BumpLevel::ALL`] variant on BOTH the borrowed and owned Cow
    /// branches. A tiny generic function
    /// `fn parse<T>(p: Cow<'_, Path>) -> T where T: for<'a>
    /// TryFrom<Cow<'a, Path>>, T::Error: Debug` — the shape of an actual
    /// downstream consumer (validated-input newtype builder, serde
    /// `try_from` wrapper, generic try-conversion helper that opts into
    /// the [`TryFrom<Cow<'_, std::path::Path>>`] contract) — recovers the
    /// canonical variant from BOTH borrowed and owned Cow variants at
    /// every variant. The structural witness that a [`BumpLevel`] is
    /// genuinely usable at `impl for<'a> TryFrom<Cow<'a, Path>>` call
    /// sites — a regression that drifted the [`TryFrom`] impl signature
    /// (e.g., requiring only owned [`std::borrow::Cow::Owned`]`(PathBuf)`
    /// instead of accepting both variants, or returning a different
    /// variant on the borrowed branch than on the owned branch) fails
    /// here at compile time or at the assertion instead of at every
    /// downstream generic call site.
    #[test]
    fn test_bump_level_try_from_cow_path_carries_through_generic_consumer() {
        fn parse<T>(path: std::borrow::Cow<'_, std::path::Path>) -> T
        where
            T: for<'a> std::convert::TryFrom<std::borrow::Cow<'a, std::path::Path>>,
            for<'a> <T as std::convert::TryFrom<std::borrow::Cow<'a, std::path::Path>>>::Error:
                std::fmt::Debug,
        {
            <T as std::convert::TryFrom<std::borrow::Cow<'_, std::path::Path>>>::try_from(path)
                .expect("canonical Cow<'_, Path> must parse through generic TryFrom<Cow<'_, Path>>")
        }

        for level in BumpLevel::ALL {
            let borrowed: std::borrow::Cow<'_, std::path::Path> =
                std::borrow::Cow::Borrowed(std::path::Path::new(level.as_str()));
            assert_eq!(
                parse::<BumpLevel>(borrowed),
                level,
                "generic TryFrom<Cow<'_, Path>> consumer must recover canonical variant on Cow::Borrowed at {level:?}",
            );

            let owned: std::borrow::Cow<'_, std::path::Path> =
                std::borrow::Cow::Owned(std::path::PathBuf::from(level.as_str()));
            assert_eq!(
                parse::<BumpLevel>(owned),
                level,
                "generic TryFrom<Cow<'_, Path>> consumer must recover canonical variant on Cow::Owned at {level:?}",
            );
        }
    }

    /// [`TryFrom<Cow<'_, std::path::Path>> for BumpLevel`] rejects
    /// non-Unicode filesystem-path sequences at the
    /// [`std::ffi::OsStr::to_str`] Unicode-decode frontier reached
    /// through [`std::path::Path::as_os_str`] via
    /// [`std::borrow::Cow::as_ref`] before the [`std::str::FromStr`]
    /// canonical-grammar gate is reached — on BOTH
    /// [`std::borrow::Cow::Borrowed`] (a `std::path::Path::new`-borrowed
    /// non-Unicode [`std::ffi::OsStr`] via
    /// [`std::os::unix::ffi::OsStrExt::from_bytes`]) and
    /// [`std::borrow::Cow::Owned`] (a `std::path::PathBuf::from`-owned
    /// non-Unicode [`std::ffi::OsString`] via
    /// [`std::os::unix::ffi::OsStringExt::from_vec`]) branches. Pins the
    /// Unicode-decode strict-rejection contract at the borrowed/owned-
    /// frontier filesystem-path try-conversion surface so a downstream
    /// consumer bound by [`TryFrom<Cow<'_, std::path::Path>>`] inherits
    /// the same Unicode-only grammar the sibling
    /// [`TryFrom<&std::path::Path>`] impl and the direct
    /// `.parse::<BumpLevel>()` call sites already read on both branches
    /// of the borrowed/owned frontier. Unix-only because the only stable
    /// public API for constructing a non-Unicode [`std::ffi::OsString`] /
    /// [`std::ffi::OsStr`] view is via
    /// [`std::os::unix::ffi::OsStringExt::from_vec`] /
    /// [`std::os::unix::ffi::OsStrExt::from_bytes`]; the equivalent
    /// Windows discipline goes through
    /// [`std::os::windows::ffi::OsStringExt::from_wide`] with a lone
    /// surrogate, which is not portable across all non-Unix platforms.
    #[cfg(unix)]
    #[test]
    fn test_bump_level_try_from_cow_path_rejects_non_unicode_input() {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::ffi::OsStringExt;

        let non_unicode_bytes: Vec<u8> = vec![0x80, 0xC3, 0xC0, 0x80, 0xFF];

        let owned_os = std::ffi::OsString::from_vec(non_unicode_bytes.clone());
        let owned =
            std::borrow::Cow::<'_, std::path::Path>::Owned(std::path::PathBuf::from(owned_os));
        assert!(
            <BumpLevel as std::convert::TryFrom<std::borrow::Cow<'_, std::path::Path>>>::try_from(
                owned
            )
            .is_err(),
            "TryFrom<Cow<'_, Path>> must reject non-Unicode Cow::Owned input",
        );

        let borrowed_os_str = std::ffi::OsStr::from_bytes(&non_unicode_bytes);
        let borrowed_path = std::path::Path::new(borrowed_os_str);
        let borrowed = std::borrow::Cow::<'_, std::path::Path>::Borrowed(borrowed_path);
        assert!(
            <BumpLevel as std::convert::TryFrom<std::borrow::Cow<'_, std::path::Path>>>::try_from(
                borrowed
            )
            .is_err(),
            "TryFrom<Cow<'_, Path>> must reject non-Unicode Cow::Borrowed input",
        );
    }

    /// [`TryFrom<Cow<'_, std::path::Path>> for BumpLevel`] rejects
    /// valid-Unicode non-canonical borrowed/owned filesystem-path
    /// sequences with the same strictness [`std::str::FromStr`] enforces
    /// — empty string, UpperCamel rendering, uppercase, whitespace
    /// padding, and truncated labels all reject after the Unicode-decode
    /// stage passes, on BOTH [`std::borrow::Cow::Borrowed`] and
    /// [`std::borrow::Cow::Owned`] branches. Pins the FromStr-gate
    /// strict-rejection contract at the borrowed/owned-frontier
    /// filesystem-path try-conversion surface so a downstream consumer
    /// bound by [`TryFrom<Cow<'_, std::path::Path>>`] inherits the same
    /// canonical-only grammar the direct `.parse::<BumpLevel>()` call
    /// sites and the sibling [`TryFrom<&std::path::Path>`] /
    /// [`TryFrom<std::path::PathBuf>`] impls already read, and a future
    /// permissive-parse regression at the underlying
    /// [`std::str::FromStr`] impl lights up here rather than drifting
    /// silently through the borrowed/owned-frontier filesystem-path
    /// try-conversion surface.
    #[test]
    fn test_bump_level_try_from_cow_path_rejects_non_canonical_input() {
        for bad in [
            "", "Patch", "Minor", "Major", "PATCH", " patch", "patch ", "pat",
        ] {
            let borrowed =
                std::borrow::Cow::<'_, std::path::Path>::Borrowed(std::path::Path::new(bad));
            assert!(
                <BumpLevel as std::convert::TryFrom<
                    std::borrow::Cow<'_, std::path::Path>,
                >>::try_from(borrowed)
                .is_err(),
                "TryFrom<Cow<'_, Path>> must reject valid-Unicode non-canonical Cow::Borrowed input {bad:?}",
            );

            let owned =
                std::borrow::Cow::<'_, std::path::Path>::Owned(std::path::PathBuf::from(bad));
            assert!(
                <BumpLevel as std::convert::TryFrom<
                    std::borrow::Cow<'_, std::path::Path>,
                >>::try_from(owned)
                .is_err(),
                "TryFrom<Cow<'_, Path>> must reject valid-Unicode non-canonical Cow::Owned input {bad:?}",
            );
        }
    }

    /// [`TryFrom<Box<std::path::Path>> for BumpLevel`] recovers the
    /// original variant at every [`BumpLevel::ALL`] variant when the
    /// canonical label emitted by [`BumpLevel::as_str`] is materialized
    /// as a [`std::path::PathBuf`] and shrunk to a
    /// [`Box<std::path::Path>`] via
    /// [`std::path::PathBuf::into_boxed_path`] and fed back through it.
    /// Pins the round-trip identity at the shrunk-owned filesystem-path
    /// frontier against the shared canonical-label oracle at the
    /// trio-closing slot of the shrunk-owned filesystem-path parse trio,
    /// structural mirror of
    /// [`crate::retry::tests::test_per_attempt_region_try_from_box_path_agrees_with_from_str`]
    /// (opening slot) and
    /// [`crate::probe_outcome::tests::test_admission_tier_try_from_box_path_agrees_with_from_str`]
    /// (mid-trio slot).
    #[test]
    fn test_bump_level_try_from_box_path_agrees_with_from_str() {
        for level in BumpLevel::ALL {
            let boxed: Box<std::path::Path> =
                std::path::PathBuf::from(level.as_str()).into_boxed_path();
            let parsed =
                <BumpLevel as std::convert::TryFrom<Box<std::path::Path>>>::try_from(boxed)
                    .expect("canonical Box<Path> must parse through TryFrom<Box<Path>>");
            assert_eq!(
                parsed, level,
                "TryFrom<Box<Path>> must round-trip at {level:?}",
            );
        }
    }

    /// The [`TryFrom<Box<std::path::Path>> for BumpLevel`] identity
    /// carries through a generic `impl TryFrom<Box<std::path::Path>>`
    /// consumer at every [`BumpLevel::ALL`] variant. A tiny generic
    /// function `fn parse<T>(b: Box<Path>) -> T where T: TryFrom<Box<
    /// Path>>, T::Error: Debug` — the shape of an actual downstream
    /// consumer (validated-input newtype builder, serde `try_from`
    /// wrapper, generic try-conversion helper that opts into the
    /// [`TryFrom<Box<std::path::Path>>`] contract) — recovers the
    /// canonical variant at every variant. The structural witness that
    /// a [`BumpLevel`] is genuinely usable at
    /// `impl TryFrom<Box<std::path::Path>>` call sites — a regression
    /// that drifted the [`TryFrom`] impl signature fails here at
    /// compile time or at the assertion instead of at every downstream
    /// generic call site.
    #[test]
    fn test_bump_level_try_from_box_path_carries_through_generic_consumer() {
        fn parse<T>(path: Box<std::path::Path>) -> T
        where
            T: std::convert::TryFrom<Box<std::path::Path>>,
            <T as std::convert::TryFrom<Box<std::path::Path>>>::Error: std::fmt::Debug,
        {
            <T as std::convert::TryFrom<Box<std::path::Path>>>::try_from(path)
                .expect("canonical Box<Path> must parse through generic TryFrom<Box<Path>>")
        }

        for level in BumpLevel::ALL {
            let boxed: Box<std::path::Path> =
                std::path::PathBuf::from(level.as_str()).into_boxed_path();
            assert_eq!(
                parse::<BumpLevel>(boxed),
                level,
                "generic TryFrom<Box<Path>> consumer must recover canonical variant at {level:?}",
            );
        }
    }

    /// [`TryFrom<Box<std::path::Path>> for BumpLevel`] rejects
    /// non-Unicode filesystem-path sequences at the
    /// [`std::ffi::OsStr::to_str`] Unicode-decode frontier reached
    /// through [`std::path::Path::as_os_str`] via
    /// [`std::boxed::Box::<std::path::Path>::as_ref`] before the
    /// [`FromStr`] canonical-grammar gate is reached — the input is a
    /// [`std::os::unix::ffi::OsStringExt::from_vec`]-constructed
    /// [`std::ffi::OsString`] materialized as a [`std::path::PathBuf`]
    /// and shrunk to a [`Box<std::path::Path>`] via
    /// [`std::path::PathBuf::into_boxed_path`]. Pins the Unicode-decode
    /// strict-rejection contract at the shrunk-owned filesystem-path
    /// try-conversion surface so a downstream consumer bound by
    /// [`TryFrom<Box<std::path::Path>>`] inherits the same Unicode-only
    /// grammar the sibling [`TryFrom<&std::path::Path>`] impl and the
    /// direct `.parse::<BumpLevel>()` call sites already read. Unix-
    /// only because the only stable public API for constructing a
    /// non-Unicode [`std::ffi::OsString`] view is via
    /// [`std::os::unix::ffi::OsStringExt::from_vec`].
    #[cfg(unix)]
    #[test]
    fn test_bump_level_try_from_box_path_rejects_non_unicode_input() {
        use std::os::unix::ffi::OsStringExt;

        let non_unicode_bytes: Vec<u8> = vec![0x80, 0xC3, 0xC0, 0x80, 0xFF];
        let owned_os = std::ffi::OsString::from_vec(non_unicode_bytes);
        let boxed: Box<std::path::Path> = std::path::PathBuf::from(owned_os).into_boxed_path();
        assert!(
            <BumpLevel as std::convert::TryFrom<Box<std::path::Path>>>::try_from(boxed).is_err(),
            "TryFrom<Box<Path>> must reject non-Unicode input",
        );
    }

    /// [`TryFrom<Box<std::path::Path>> for BumpLevel`] rejects
    /// valid-Unicode non-canonical filesystem-path sequences with the
    /// same strictness [`std::str::FromStr`] enforces — empty string,
    /// UpperCamel rendering, uppercase, whitespace padding, and
    /// truncated labels all reject after the Unicode-decode stage
    /// passes. Pins the FromStr-gate strict-rejection contract at the
    /// shrunk-owned filesystem-path try-conversion surface so a
    /// downstream consumer bound by [`TryFrom<Box<std::path::Path>>`]
    /// inherits the same canonical-only grammar the direct
    /// `.parse::<BumpLevel>()` call sites and the sibling
    /// [`TryFrom<&std::path::Path>`] / [`TryFrom<std::path::PathBuf>`] /
    /// [`TryFrom<Cow<'_, std::path::Path>>`] impls already read.
    #[test]
    fn test_bump_level_try_from_box_path_rejects_non_canonical_input() {
        for bad in [
            "", "Patch", "Minor", "Major", "PATCH", " patch", "patch ", "pat",
        ] {
            let boxed: Box<std::path::Path> = std::path::PathBuf::from(bad).into_boxed_path();
            assert!(
                <BumpLevel as std::convert::TryFrom<Box<std::path::Path>>>::try_from(boxed)
                    .is_err(),
                "TryFrom<Box<Path>> must reject valid-Unicode non-canonical input {bad:?}",
            );
        }
    }

    /// [`TryFrom<Box<std::ffi::OsStr>> for BumpLevel`] recovers the
    /// original variant at every [`BumpLevel::ALL`] variant when the
    /// canonical label emitted by [`BumpLevel::as_str`] is materialized
    /// as a [`std::ffi::OsString`] and shrunk to a
    /// [`Box<std::ffi::OsStr>`] via
    /// [`std::ffi::OsString::into_boxed_os_str`] and fed back through it.
    /// Pins the round-trip identity at the shrunk-owned OS-string
    /// frontier against the shared canonical-label oracle at the trio-
    /// closing slot of the shrunk-owned OS-string parse trio, structural
    /// mirror of
    /// [`crate::retry::tests::test_per_attempt_region_try_from_box_os_str_agrees_with_from_str`]
    /// (opening slot) and
    /// [`crate::probe_outcome::tests::test_admission_tier_try_from_box_os_str_agrees_with_from_str`]
    /// (mid-trio slot).
    #[test]
    fn test_bump_level_try_from_box_os_str_agrees_with_from_str() {
        for level in BumpLevel::ALL {
            let boxed: Box<std::ffi::OsStr> =
                std::ffi::OsString::from(level.as_str()).into_boxed_os_str();
            let parsed =
                <BumpLevel as std::convert::TryFrom<Box<std::ffi::OsStr>>>::try_from(boxed)
                    .expect("canonical Box<OsStr> must parse through TryFrom<Box<OsStr>>");
            assert_eq!(
                parsed, level,
                "TryFrom<Box<OsStr>> must round-trip at {level:?}",
            );
        }
    }

    /// The [`TryFrom<Box<std::ffi::OsStr>> for BumpLevel`] identity
    /// carries through a generic `impl TryFrom<Box<std::ffi::OsStr>>`
    /// consumer at every [`BumpLevel::ALL`] variant. A tiny generic
    /// function `fn parse<T>(b: Box<OsStr>) -> T where T: TryFrom<Box<
    /// OsStr>>, T::Error: Debug` — the shape of an actual downstream
    /// consumer (validated-input newtype builder, serde `try_from`
    /// wrapper, generic try-conversion helper that opts into the
    /// [`TryFrom<Box<std::ffi::OsStr>>`] contract) — recovers the
    /// canonical variant at every variant. The structural witness that
    /// a [`BumpLevel`] is genuinely usable at
    /// `impl TryFrom<Box<std::ffi::OsStr>>` call sites — a regression
    /// that drifted the [`TryFrom`] impl signature fails here at
    /// compile time or at the assertion instead of at every downstream
    /// generic call site.
    #[test]
    fn test_bump_level_try_from_box_os_str_carries_through_generic_consumer() {
        fn parse<T>(os_str: Box<std::ffi::OsStr>) -> T
        where
            T: std::convert::TryFrom<Box<std::ffi::OsStr>>,
            <T as std::convert::TryFrom<Box<std::ffi::OsStr>>>::Error: std::fmt::Debug,
        {
            <T as std::convert::TryFrom<Box<std::ffi::OsStr>>>::try_from(os_str)
                .expect("canonical Box<OsStr> must parse through generic TryFrom<Box<OsStr>>")
        }

        for level in BumpLevel::ALL {
            let boxed: Box<std::ffi::OsStr> =
                std::ffi::OsString::from(level.as_str()).into_boxed_os_str();
            assert_eq!(
                parse::<BumpLevel>(boxed),
                level,
                "generic TryFrom<Box<OsStr>> consumer must recover canonical variant at {level:?}",
            );
        }
    }

    /// [`TryFrom<Box<std::ffi::OsStr>> for BumpLevel`] rejects non-
    /// Unicode OS-string sequences at the [`std::ffi::OsStr::to_str`]
    /// Unicode-decode frontier reached through
    /// [`std::boxed::Box::<std::ffi::OsStr>::as_ref`] before the
    /// [`FromStr`] canonical-grammar gate is reached — the input is a
    /// [`std::os::unix::ffi::OsStringExt::from_vec`]-constructed
    /// [`std::ffi::OsString`] shrunk to a [`Box<std::ffi::OsStr>`] via
    /// [`std::ffi::OsString::into_boxed_os_str`]. Pins the Unicode-
    /// decode strict-rejection contract at the shrunk-owned OS-string
    /// try-conversion surface so a downstream consumer bound by
    /// [`TryFrom<Box<std::ffi::OsStr>>`] inherits the same Unicode-only
    /// grammar the sibling [`TryFrom<&std::ffi::OsStr>`] impl and the
    /// direct `.parse::<BumpLevel>()` call sites already read. Unix-
    /// only because the only stable public API for constructing a
    /// non-Unicode [`std::ffi::OsString`] view is via
    /// [`std::os::unix::ffi::OsStringExt::from_vec`].
    #[cfg(unix)]
    #[test]
    fn test_bump_level_try_from_box_os_str_rejects_non_unicode_input() {
        use std::os::unix::ffi::OsStringExt;

        let non_unicode_bytes: Vec<u8> = vec![0x80, 0xC3, 0xC0, 0x80, 0xFF];
        let owned_os = std::ffi::OsString::from_vec(non_unicode_bytes);
        let boxed: Box<std::ffi::OsStr> = owned_os.into_boxed_os_str();
        assert!(
            <BumpLevel as std::convert::TryFrom<Box<std::ffi::OsStr>>>::try_from(boxed).is_err(),
            "TryFrom<Box<OsStr>> must reject non-Unicode input",
        );
    }

    /// [`TryFrom<Box<std::ffi::OsStr>> for BumpLevel`] rejects valid-
    /// Unicode non-canonical OS-string sequences with the same
    /// strictness [`std::str::FromStr`] enforces — empty string,
    /// UpperCamel rendering, uppercase, whitespace padding, and
    /// truncated labels all reject after the Unicode-decode stage
    /// passes. Pins the FromStr-gate strict-rejection contract at the
    /// shrunk-owned OS-string try-conversion surface so a downstream
    /// consumer bound by [`TryFrom<Box<std::ffi::OsStr>>`] inherits the
    /// same canonical-only grammar the direct `.parse::<BumpLevel>()`
    /// call sites and the sibling [`TryFrom<&std::ffi::OsStr>`] /
    /// [`TryFrom<std::ffi::OsString>`] /
    /// [`TryFrom<Cow<'_, std::ffi::OsStr>>`] impls already read.
    #[test]
    fn test_bump_level_try_from_box_os_str_rejects_non_canonical_input() {
        for bad in [
            "", "Patch", "Minor", "Major", "PATCH", " patch", "patch ", "pat",
        ] {
            let boxed: Box<std::ffi::OsStr> = std::ffi::OsString::from(bad).into_boxed_os_str();
            assert!(
                <BumpLevel as std::convert::TryFrom<Box<std::ffi::OsStr>>>::try_from(boxed)
                    .is_err(),
                "TryFrom<Box<OsStr>> must reject valid-Unicode non-canonical input {bad:?}",
            );
        }
    }

    /// [`TryFrom<std::sync::Arc<std::ffi::OsStr>> for BumpLevel`]
    /// recovers the original variant at every [`BumpLevel::ALL`]
    /// variant when the canonical label emitted by
    /// [`BumpLevel::as_str`] is materialized as a
    /// [`std::ffi::OsString`], shrunk to a [`Box<std::ffi::OsStr>`]
    /// via [`std::ffi::OsString::into_boxed_os_str`], and lifted to
    /// a [`std::sync::Arc<std::ffi::OsStr>`] via
    /// [`std::sync::Arc::<std::ffi::OsStr>::from`] before being fed
    /// back through it. Pins the round-trip identity at the shared-
    /// owned OS-string frontier against the shared canonical-label
    /// oracle at the trio-closing slot of the shared-owned OS-string
    /// parse trio, structural mirror of
    /// [`crate::retry::tests::test_per_attempt_region_try_from_arc_os_str_agrees_with_from_str`]
    /// carried at the first ordered typed sum (opening slot at
    /// 478313f) and
    /// [`crate::probe_outcome::tests::test_admission_tier_try_from_arc_os_str_agrees_with_from_str`]
    /// carried at the second ordered typed sum (mid-trio slot at
    /// 7f411bc).
    #[test]
    fn test_bump_level_try_from_arc_os_str_agrees_with_from_str() {
        for level in BumpLevel::ALL {
            let boxed: Box<std::ffi::OsStr> =
                std::ffi::OsString::from(level.as_str()).into_boxed_os_str();
            let arc: std::sync::Arc<std::ffi::OsStr> = std::sync::Arc::from(boxed);
            let parsed =
                <BumpLevel as std::convert::TryFrom<std::sync::Arc<std::ffi::OsStr>>>::try_from(
                    arc,
                )
                .expect("canonical Arc<OsStr> must parse through TryFrom<Arc<OsStr>>");
            assert_eq!(
                parsed, level,
                "TryFrom<Arc<OsStr>> must round-trip at {level:?}",
            );
        }
    }

    /// The [`TryFrom<std::sync::Arc<std::ffi::OsStr>> for BumpLevel`]
    /// identity carries through a generic
    /// `impl TryFrom<Arc<std::ffi::OsStr>>` consumer at every
    /// [`BumpLevel::ALL`] variant. A tiny generic function
    /// `fn parse<T>(a: Arc<OsStr>) -> T where T: TryFrom<Arc<OsStr>>,
    /// T::Error: Debug` — the shape of an actual downstream consumer
    /// (validated-input newtype builder handing shared OS-string
    /// clones to sibling threads, serde `try_from` wrapper, generic
    /// try-conversion helper that opts into the
    /// [`TryFrom<std::sync::Arc<std::ffi::OsStr>>`] contract) —
    /// recovers the canonical variant at every variant. Structural
    /// witness that a [`BumpLevel`] is genuinely usable at
    /// `impl TryFrom<Arc<std::ffi::OsStr>>` call sites — a regression
    /// that drifted the [`TryFrom`] impl signature fails here at
    /// compile time or at the assertion instead of at every
    /// downstream generic call site.
    #[test]
    fn test_bump_level_try_from_arc_os_str_carries_through_generic_consumer() {
        fn parse<T>(os_str: std::sync::Arc<std::ffi::OsStr>) -> T
        where
            T: std::convert::TryFrom<std::sync::Arc<std::ffi::OsStr>>,
            <T as std::convert::TryFrom<std::sync::Arc<std::ffi::OsStr>>>::Error: std::fmt::Debug,
        {
            <T as std::convert::TryFrom<std::sync::Arc<std::ffi::OsStr>>>::try_from(os_str)
                .expect("canonical Arc<OsStr> must parse through generic TryFrom<Arc<OsStr>>")
        }

        for level in BumpLevel::ALL {
            let boxed: Box<std::ffi::OsStr> =
                std::ffi::OsString::from(level.as_str()).into_boxed_os_str();
            let arc: std::sync::Arc<std::ffi::OsStr> = std::sync::Arc::from(boxed);
            assert_eq!(
                parse::<BumpLevel>(arc),
                level,
                "generic TryFrom<Arc<OsStr>> consumer must recover canonical variant at {level:?}",
            );
        }
    }

    /// [`TryFrom<std::sync::Arc<std::ffi::OsStr>> for BumpLevel`]
    /// rejects non-Unicode OS-string sequences at the
    /// [`std::ffi::OsStr::to_str`] Unicode-decode frontier reached
    /// through [`std::sync::Arc::<std::ffi::OsStr>::as_ref`] before
    /// the [`FromStr`] canonical-grammar gate is reached. Unix-only
    /// because the only stable public API for constructing a non-
    /// Unicode [`std::ffi::OsString`] view is via
    /// [`std::os::unix::ffi::OsStringExt::from_vec`]. Structural
    /// mirror of
    /// [`crate::probe_outcome::tests::test_admission_tier_try_from_arc_os_str_rejects_non_unicode_input`]
    /// at the mid-trio slot and
    /// [`crate::retry::tests::test_per_attempt_region_try_from_arc_os_str_rejects_non_unicode_input`]
    /// at the opening slot.
    #[cfg(unix)]
    #[test]
    fn test_bump_level_try_from_arc_os_str_rejects_non_unicode_input() {
        use std::os::unix::ffi::OsStringExt;

        let non_unicode_bytes: Vec<u8> = vec![0x80, 0xC3, 0xC0, 0x80, 0xFF];
        let owned_os = std::ffi::OsString::from_vec(non_unicode_bytes);
        let boxed: Box<std::ffi::OsStr> = owned_os.into_boxed_os_str();
        let arc: std::sync::Arc<std::ffi::OsStr> = std::sync::Arc::from(boxed);
        assert!(
            <BumpLevel as std::convert::TryFrom<std::sync::Arc<std::ffi::OsStr>>>::try_from(arc)
                .is_err(),
            "TryFrom<Arc<OsStr>> must reject non-Unicode input",
        );
    }

    /// [`TryFrom<std::sync::Arc<std::ffi::OsStr>> for BumpLevel`]
    /// rejects valid-Unicode non-canonical OS-string sequences with
    /// the same strictness [`std::str::FromStr`] enforces — empty
    /// string, UpperCamel rendering (`"Patch"`, `"Minor"`,
    /// `"Major"`), uppercase (`"PATCH"`), whitespace padding, and
    /// truncated stem (`"pat"`) all reject after the Unicode-decode
    /// stage passes. Pins the FromStr-gate strict-rejection contract
    /// at the shared-owned OS-string try-conversion surface so a
    /// downstream consumer bound by
    /// [`TryFrom<std::sync::Arc<std::ffi::OsStr>>`] inherits the same
    /// canonical-only grammar the direct `.parse::<BumpLevel>()`
    /// call sites and the sibling [`TryFrom<&std::ffi::OsStr>`],
    /// [`TryFrom<std::ffi::OsString>`],
    /// [`TryFrom<Cow<'_, std::ffi::OsStr>>`], and
    /// [`TryFrom<Box<std::ffi::OsStr>>`] impls already read.
    #[test]
    fn test_bump_level_try_from_arc_os_str_rejects_non_canonical_input() {
        for bad in [
            "", "Patch", "Minor", "Major", "PATCH", " patch", "patch ", "pat",
        ] {
            let boxed: Box<std::ffi::OsStr> = std::ffi::OsString::from(bad).into_boxed_os_str();
            let arc: std::sync::Arc<std::ffi::OsStr> = std::sync::Arc::from(boxed);
            assert!(
                <BumpLevel as std::convert::TryFrom<std::sync::Arc<std::ffi::OsStr>>>::try_from(
                    arc,
                )
                .is_err(),
                "TryFrom<Arc<OsStr>> must reject valid-Unicode non-canonical input {bad:?}",
            );
        }
    }

    /// [`TryFrom<std::sync::Arc<std::path::Path>> for BumpLevel`]
    /// recovers the original variant at every [`BumpLevel::ALL`]
    /// variant when the canonical label emitted by
    /// [`BumpLevel::as_str`] is materialized as a
    /// [`std::path::PathBuf`], shrunk to a [`Box<std::path::Path>`] via
    /// [`std::path::PathBuf::into_boxed_path`], and lifted to a
    /// [`std::sync::Arc<std::path::Path>`] via
    /// [`std::sync::Arc::<std::path::Path>::from`] before being fed
    /// back through it. Pins the round-trip identity at the shared-
    /// owned filesystem-path frontier against the shared canonical-
    /// label oracle at the trio-closing slot of the shared-owned
    /// filesystem-path parse trio, structural mirror of
    /// [`crate::retry::tests::test_per_attempt_region_try_from_arc_path_agrees_with_from_str`]
    /// carried at the first ordered typed sum (opening slot at
    /// b9f5ef1) and
    /// [`crate::probe_outcome::tests::test_admission_tier_try_from_arc_path_agrees_with_from_str`]
    /// carried at the second ordered typed sum (mid-trio slot at
    /// aec69b1).
    #[test]
    fn test_bump_level_try_from_arc_path_agrees_with_from_str() {
        for level in BumpLevel::ALL {
            let boxed: Box<std::path::Path> =
                std::path::PathBuf::from(level.as_str()).into_boxed_path();
            let arc: std::sync::Arc<std::path::Path> = std::sync::Arc::from(boxed);
            let parsed =
                <BumpLevel as std::convert::TryFrom<std::sync::Arc<std::path::Path>>>::try_from(
                    arc,
                )
                .expect("canonical Arc<Path> must parse through TryFrom<Arc<Path>>");
            assert_eq!(
                parsed, level,
                "TryFrom<Arc<Path>> must round-trip at {level:?}",
            );
        }
    }

    /// The [`TryFrom<std::sync::Arc<std::path::Path>> for BumpLevel`]
    /// identity carries through a generic
    /// `impl TryFrom<Arc<std::path::Path>>` consumer at every
    /// [`BumpLevel::ALL`] variant. A tiny generic function
    /// `fn parse<T>(a: Arc<Path>) -> T where T: TryFrom<Arc<Path>>,
    /// T::Error: Debug` — the shape of an actual downstream consumer
    /// (validated-input newtype builder handing shared filesystem-path
    /// clones to sibling threads, serde `try_from` wrapper, generic
    /// try-conversion helper that opts into the
    /// [`TryFrom<std::sync::Arc<std::path::Path>>`] contract) —
    /// recovers the canonical variant at every variant. Structural
    /// witness that a [`BumpLevel`] is genuinely usable at
    /// `impl TryFrom<Arc<std::path::Path>>` call sites — a regression
    /// that drifted the [`TryFrom`] impl signature fails here at
    /// compile time or at the assertion instead of at every downstream
    /// generic call site.
    #[test]
    fn test_bump_level_try_from_arc_path_carries_through_generic_consumer() {
        fn parse<T>(path: std::sync::Arc<std::path::Path>) -> T
        where
            T: std::convert::TryFrom<std::sync::Arc<std::path::Path>>,
            <T as std::convert::TryFrom<std::sync::Arc<std::path::Path>>>::Error: std::fmt::Debug,
        {
            <T as std::convert::TryFrom<std::sync::Arc<std::path::Path>>>::try_from(path)
                .expect("canonical Arc<Path> must parse through generic TryFrom<Arc<Path>>")
        }

        for level in BumpLevel::ALL {
            let boxed: Box<std::path::Path> =
                std::path::PathBuf::from(level.as_str()).into_boxed_path();
            let arc: std::sync::Arc<std::path::Path> = std::sync::Arc::from(boxed);
            assert_eq!(
                parse::<BumpLevel>(arc),
                level,
                "generic TryFrom<Arc<Path>> consumer must recover canonical variant at {level:?}",
            );
        }
    }

    /// [`TryFrom<std::sync::Arc<std::path::Path>> for BumpLevel`]
    /// rejects non-Unicode filesystem-path sequences at the
    /// [`std::ffi::OsStr::to_str`] Unicode-decode frontier reached
    /// through [`std::path::Path::as_os_str`] via
    /// [`std::sync::Arc::<std::path::Path>::as_ref`] before the
    /// [`FromStr`] canonical-grammar gate is reached — the input is a
    /// [`std::os::unix::ffi::OsStringExt::from_vec`]-constructed
    /// [`std::ffi::OsString`] materialized as a
    /// [`std::path::PathBuf`], shrunk to a [`Box<std::path::Path>`]
    /// via [`std::path::PathBuf::into_boxed_path`], and lifted to a
    /// [`std::sync::Arc<std::path::Path>`] via
    /// [`std::sync::Arc::<std::path::Path>::from`]. Unix-only because
    /// the only stable public API for constructing a non-Unicode
    /// [`std::ffi::OsString`] view is via
    /// [`std::os::unix::ffi::OsStringExt::from_vec`].
    #[cfg(unix)]
    #[test]
    fn test_bump_level_try_from_arc_path_rejects_non_unicode_input() {
        use std::os::unix::ffi::OsStringExt;

        let non_unicode_bytes: Vec<u8> = vec![0x80, 0xC3, 0xC0, 0x80, 0xFF];
        let owned_os = std::ffi::OsString::from_vec(non_unicode_bytes);
        let boxed: Box<std::path::Path> = std::path::PathBuf::from(owned_os).into_boxed_path();
        let arc: std::sync::Arc<std::path::Path> = std::sync::Arc::from(boxed);
        assert!(
            <BumpLevel as std::convert::TryFrom<std::sync::Arc<std::path::Path>>>::try_from(arc)
                .is_err(),
            "TryFrom<Arc<Path>> must reject non-Unicode input",
        );
    }

    /// [`TryFrom<std::sync::Arc<std::path::Path>> for BumpLevel`]
    /// rejects valid-Unicode non-canonical filesystem-path sequences
    /// with the same strictness [`std::str::FromStr`] enforces — empty
    /// string, UpperCamel rendering (`"Patch"`, `"Minor"`, `"Major"`),
    /// uppercase (`"PATCH"`), whitespace padding, and truncated stem
    /// (`"pat"`) all reject after the Unicode-decode stage passes.
    /// Pins the FromStr-gate strict-rejection contract at the shared-
    /// owned filesystem-path try-conversion surface so a downstream
    /// consumer bound by
    /// [`TryFrom<std::sync::Arc<std::path::Path>>`] inherits the same
    /// canonical-only grammar the direct `.parse::<BumpLevel>()` call
    /// sites and the sibling [`TryFrom<&std::path::Path>`],
    /// [`TryFrom<std::path::PathBuf>`],
    /// [`TryFrom<Cow<'_, std::path::Path>>`], and
    /// [`TryFrom<Box<std::path::Path>>`] impls already read.
    #[test]
    fn test_bump_level_try_from_arc_path_rejects_non_canonical_input() {
        for bad in [
            "", "Patch", "Minor", "Major", "PATCH", " patch", "patch ", "pat",
        ] {
            let boxed: Box<std::path::Path> = std::path::PathBuf::from(bad).into_boxed_path();
            let arc: std::sync::Arc<std::path::Path> = std::sync::Arc::from(boxed);
            assert!(
                <BumpLevel as std::convert::TryFrom<std::sync::Arc<std::path::Path>>>::try_from(
                    arc
                )
                .is_err(),
                "TryFrom<Arc<Path>> must reject valid-Unicode non-canonical input {bad:?}",
            );
        }
    }

    /// [`TryFrom<std::rc::Rc<std::ffi::OsStr>> for BumpLevel`]
    /// recovers the original variant at every [`BumpLevel::ALL`]
    /// variant when the canonical label emitted by
    /// [`BumpLevel::as_str`] is materialized as a
    /// [`std::ffi::OsString`], shrunk to a [`Box<std::ffi::OsStr>`]
    /// via [`std::ffi::OsString::into_boxed_os_str`], and lifted to
    /// a [`std::rc::Rc<std::ffi::OsStr>`] via
    /// [`std::rc::Rc::<std::ffi::OsStr>::from`] before being fed
    /// back through it. Pins the round-trip identity at the thread-
    /// local shared-owned OS-string frontier against the shared
    /// canonical-label oracle at the trio-closing slot of the
    /// thread-local shared-owned OS-string parse trio, structural
    /// mirror of
    /// [`crate::retry::tests::test_per_attempt_region_try_from_rc_os_str_agrees_with_from_str`]
    /// carried at the first ordered typed sum (opening slot at
    /// 63f6f55) and
    /// [`crate::probe_outcome::tests::test_admission_tier_try_from_rc_os_str_agrees_with_from_str`]
    /// carried at the second ordered typed sum (mid-trio slot at
    /// 2adee36).
    #[test]
    fn test_bump_level_try_from_rc_os_str_agrees_with_from_str() {
        for level in BumpLevel::ALL {
            let boxed: Box<std::ffi::OsStr> =
                std::ffi::OsString::from(level.as_str()).into_boxed_os_str();
            let rc: std::rc::Rc<std::ffi::OsStr> = std::rc::Rc::from(boxed);
            let parsed =
                <BumpLevel as std::convert::TryFrom<std::rc::Rc<std::ffi::OsStr>>>::try_from(rc)
                    .expect("canonical Rc<OsStr> must parse through TryFrom<Rc<OsStr>>");
            assert_eq!(
                parsed, level,
                "TryFrom<Rc<OsStr>> must round-trip at {level:?}",
            );
        }
    }

    /// The [`TryFrom<std::rc::Rc<std::ffi::OsStr>> for BumpLevel`]
    /// identity carries through a generic
    /// `impl TryFrom<Rc<std::ffi::OsStr>>` consumer at every
    /// [`BumpLevel::ALL`] variant. A tiny generic function
    /// `fn parse<T>(r: Rc<OsStr>) -> T where T: TryFrom<Rc<OsStr>>,
    /// T::Error: Debug` — the shape of an actual downstream consumer
    /// (validated-input newtype builder handing thread-local shared
    /// OS-string clones to non-`Send` receivers, per-thread memoized
    /// canonical-label cache, generic try-conversion helper that
    /// opts into the [`TryFrom<std::rc::Rc<std::ffi::OsStr>>`]
    /// contract) — recovers the canonical variant at every variant.
    /// Structural witness that a [`BumpLevel`] is genuinely usable
    /// at `impl TryFrom<Rc<std::ffi::OsStr>>` call sites — a
    /// regression that drifted the [`TryFrom`] impl signature fails
    /// here at compile time or at the assertion instead of at every
    /// downstream generic call site.
    #[test]
    fn test_bump_level_try_from_rc_os_str_carries_through_generic_consumer() {
        fn parse<T>(os_str: std::rc::Rc<std::ffi::OsStr>) -> T
        where
            T: std::convert::TryFrom<std::rc::Rc<std::ffi::OsStr>>,
            <T as std::convert::TryFrom<std::rc::Rc<std::ffi::OsStr>>>::Error: std::fmt::Debug,
        {
            <T as std::convert::TryFrom<std::rc::Rc<std::ffi::OsStr>>>::try_from(os_str)
                .expect("canonical Rc<OsStr> must parse through generic TryFrom<Rc<OsStr>>")
        }

        for level in BumpLevel::ALL {
            let boxed: Box<std::ffi::OsStr> =
                std::ffi::OsString::from(level.as_str()).into_boxed_os_str();
            let rc: std::rc::Rc<std::ffi::OsStr> = std::rc::Rc::from(boxed);
            assert_eq!(
                parse::<BumpLevel>(rc),
                level,
                "generic TryFrom<Rc<OsStr>> consumer must recover canonical variant at {level:?}",
            );
        }
    }

    /// [`TryFrom<std::rc::Rc<std::ffi::OsStr>> for BumpLevel`]
    /// rejects non-Unicode OS-string sequences at the
    /// [`std::ffi::OsStr::to_str`] Unicode-decode frontier reached
    /// through [`std::rc::Rc::<std::ffi::OsStr>::as_ref`] before
    /// the [`FromStr`] canonical-grammar gate is reached. Unix-only
    /// because the only stable public API for constructing a non-
    /// Unicode [`std::ffi::OsString`] view is via
    /// [`std::os::unix::ffi::OsStringExt::from_vec`]. Structural
    /// mirror of
    /// [`crate::probe_outcome::tests::test_admission_tier_try_from_rc_os_str_rejects_non_unicode_input`]
    /// at the mid-trio slot and
    /// [`crate::retry::tests::test_per_attempt_region_try_from_rc_os_str_rejects_non_unicode_input`]
    /// at the opening slot.
    #[cfg(unix)]
    #[test]
    fn test_bump_level_try_from_rc_os_str_rejects_non_unicode_input() {
        use std::os::unix::ffi::OsStringExt;

        let non_unicode_bytes: Vec<u8> = vec![0x80, 0xC3, 0xC0, 0x80, 0xFF];
        let owned_os = std::ffi::OsString::from_vec(non_unicode_bytes);
        let boxed: Box<std::ffi::OsStr> = owned_os.into_boxed_os_str();
        let rc: std::rc::Rc<std::ffi::OsStr> = std::rc::Rc::from(boxed);
        assert!(
            <BumpLevel as std::convert::TryFrom<std::rc::Rc<std::ffi::OsStr>>>::try_from(rc)
                .is_err(),
            "TryFrom<Rc<OsStr>> must reject non-Unicode input",
        );
    }

    /// [`TryFrom<std::rc::Rc<std::ffi::OsStr>> for BumpLevel`]
    /// rejects valid-Unicode non-canonical OS-string sequences with
    /// the same strictness [`std::str::FromStr`] enforces — empty
    /// string, UpperCamel rendering (`"Patch"`, `"Minor"`,
    /// `"Major"`), uppercase (`"PATCH"`), whitespace padding, and
    /// truncated stem (`"pat"`) all reject after the Unicode-decode
    /// stage passes. Pins the FromStr-gate strict-rejection contract
    /// at the thread-local shared-owned OS-string try-conversion
    /// surface so a downstream consumer bound by
    /// [`TryFrom<std::rc::Rc<std::ffi::OsStr>>`] inherits the same
    /// canonical-only grammar the direct `.parse::<BumpLevel>()`
    /// call sites and the sibling [`TryFrom<&std::ffi::OsStr>`],
    /// [`TryFrom<std::ffi::OsString>`],
    /// [`TryFrom<Cow<'_, std::ffi::OsStr>>`],
    /// [`TryFrom<Box<std::ffi::OsStr>>`], and
    /// [`TryFrom<std::sync::Arc<std::ffi::OsStr>>`] impls already
    /// read.
    #[test]
    fn test_bump_level_try_from_rc_os_str_rejects_non_canonical_input() {
        for bad in [
            "", "Patch", "Minor", "Major", "PATCH", " patch", "patch ", "pat",
        ] {
            let boxed: Box<std::ffi::OsStr> = std::ffi::OsString::from(bad).into_boxed_os_str();
            let rc: std::rc::Rc<std::ffi::OsStr> = std::rc::Rc::from(boxed);
            assert!(
                <BumpLevel as std::convert::TryFrom<std::rc::Rc<std::ffi::OsStr>>>::try_from(rc)
                    .is_err(),
                "TryFrom<Rc<OsStr>> must reject valid-Unicode non-canonical input {bad:?}",
            );
        }
    }
}
