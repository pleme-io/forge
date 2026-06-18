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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
}
