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
        for level in [BumpLevel::Patch, BumpLevel::Minor, BumpLevel::Major] {
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
        for level in [BumpLevel::Patch, BumpLevel::Minor, BumpLevel::Major] {
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
        for level in [BumpLevel::Patch, BumpLevel::Minor, BumpLevel::Major] {
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
            vec![BumpLevel::Patch, BumpLevel::Minor, BumpLevel::Major],
            "sorted variants must yield the Patch < Minor < Major ladder",
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
        for level in [BumpLevel::Patch, BumpLevel::Minor, BumpLevel::Major] {
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
        let breaking_count = [BumpLevel::Patch, BumpLevel::Minor, BumpLevel::Major]
            .iter()
            .filter(|l| l.is_breaking())
            .count();
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
        for level in [BumpLevel::Patch, BumpLevel::Minor, BumpLevel::Major] {
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
        for level in [BumpLevel::Patch, BumpLevel::Minor, BumpLevel::Major] {
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
        for level in [BumpLevel::Patch, BumpLevel::Minor, BumpLevel::Major] {
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
        for level in [BumpLevel::Patch, BumpLevel::Minor, BumpLevel::Major] {
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
        for level in [BumpLevel::Patch, BumpLevel::Minor, BumpLevel::Major] {
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
        for level in [BumpLevel::Patch, BumpLevel::Minor, BumpLevel::Major] {
            assert!(
                !(level.is_fix_only() && level.is_breaking()),
                "is_fix_only() AND is_breaking() must be empty at {level:?}",
            );
        }
    }
}
