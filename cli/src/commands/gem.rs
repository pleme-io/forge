//! Ruby gem lifecycle commands
//!
//! Provides build, push, and version bump operations for Ruby gems.

use anyhow::{bail, Context, Result};
use std::path::Path;
use std::process::Command;
use tracing::info;

use crate::version;

/// Resolve the `gem` binary path via `GEM_BIN`, falling back to `gem` on
/// `PATH`. Wired through [`crate::repo::get_tool_path`] with the derived-
/// `_BIN`-suffix override: RubyGems itself claims the unadorned `GEM_*`
/// env-var surface for its own runtime config (`GEM_HOME`, `GEM_PATH`,
/// `GEM_SPEC_CACHE`, …), so a bare `GEM` env-var export from substrate
/// would collide with the tool's own read of that same env-var
/// namespace. The sigil therefore honors the `_BIN` derivation convention
/// every substrate-exported tool with a name-collision-prone unadorned
/// env honors (`ATTIC_BIN`, `GH_BIN`, `DOCA_BIN`, `KUBECTL_BIN`,
/// `DOCKER_BIN`, `BUNDLE_BIN`, `INSPEC_BIN` — the last two per e26787c
/// on the sibling Ruby-toolchain surface). The one bridge between the
/// gem-lifecycle surface (`build`, `push`) and the substrate-
/// `mkRuntimeToolsEnv`-exported binary path.
///
/// Pre-lift the two consumer sites — `build` (`gem build <gemspec>`)
/// and `push` (`gem push <gem-path> [--otp <code>]`) — spelled the
/// bare-literal tool-name form (a `Command::new` call with the tool
/// name inline as a string) verbatim, ignoring `GEM_BIN` at exactly
/// the two gates where a wrong-binary verdict is load-bearing: `build`
/// packages a gem whose `Gem::Specification` marshal-format is written
/// by whichever `gem` the wrapper's PATH found first (the RubyGems
/// marshal-format is Ruby-version-sensitive and the spec author-
/// signature is baked in at package time), and `push` publishes the
/// built artifact to the RubyGems.org registry under an OTP-authenticated
/// session whose credential-file semantics vary across gem major
/// versions (2.x vs 3.x credentials-file schema differs). A pre-lift
/// ambient-PATH `gem` at either site silently attributed the packaging
/// or publishing verdict to whichever `gem` PATH resolved to, not to
/// the substrate-pinned RubyGems derivation the flake declared. Same
/// silent-PATH-fallback bug class the sibling `TERRAFORM` / `BUNDLE_BIN`
/// / `INSPEC_BIN` migrations closed on their respective spawn surfaces.
fn gem_bin() -> String {
    crate::repo::get_tool_path("GEM_BIN", "gem")
}

/// Resolve the `bundle` binary path via `BUNDLE_BIN`, falling back to
/// `bundle` on `PATH`. Wired through [`crate::repo::get_tool_path`] with
/// the derived-`_BIN`-suffix override — Bundler itself claims the bare
/// `BUNDLE_*` env-var surface for its own runtime config (`BUNDLE_PATH`,
/// `BUNDLE_GEMFILE`, `BUNDLE_JOBS`, …), so the sigil honors the `_BIN`
/// derivation convention matching the sibling `bundle_bin()` in
/// `commands/pangea_infra.rs` (e26787c) verbatim. The one bridge between
/// the gem-lifecycle test surface and the substrate-`mkRuntimeToolsEnv`-
/// exported binary path.
///
/// Pre-lift the single consumer site — `test`
/// (`bundle exec rake spec`) — spelled the bare-literal tool-name form
/// (a `Command::new` call with the tool name inline as a string)
/// verbatim, ignoring `BUNDLE_BIN` at the RSpec-gate every downstream
/// gem-publish decision depends on: a stale ambient-PATH `bundle`
/// resolves the Gemfile lockfile against the wrong Ruby version
/// (Bundler's version-selection algorithm's lockfile-vs-runtime-Ruby
/// mismatches are the load-bearing failure mode), so the wrong bundler
/// at this gate silently attributes the test verdict every gem-push
/// downstream trusts to the wrong Ruby toolchain. Same silent-PATH-
/// fallback bug class the sibling `BUNDLE_BIN` migration on
/// `commands/pangea_infra.rs` (e26787c) closed on its RSpec-synthesis
/// surface — this commit closes the parallel gate on the gem-lifecycle
/// surface.
fn bundle_bin() -> String {
    crate::repo::get_tool_path("BUNDLE_BIN", "bundle")
}

/// Detect the gem name from a directory by finding the single *.gemspec file.
fn detect_gem_name(dir: &Path) -> Result<String> {
    let gemspecs: Vec<_> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_name()
                .to_str()
                .map(|n| n.ends_with(".gemspec"))
                .unwrap_or(false)
        })
        .collect();

    match gemspecs.len() {
        0 => bail!("No .gemspec file found in {}", dir.display()),
        1 => {
            let name = gemspecs[0]
                .file_name()
                .to_str()
                .unwrap()
                .trim_end_matches(".gemspec")
                .to_string();
            Ok(name)
        }
        n => bail!(
            "Found {} .gemspec files in {} — use --name to specify which one",
            n,
            dir.display()
        ),
    }
}

/// Find the version.rb file for a gem.
///
/// Searches for the pattern `lib/<gem-name>/version.rb` where the gem name
/// may use hyphens in the directory name (e.g., `lib/abstract-synthesizer/version.rb`).
fn find_version_file(dir: &Path, gem_name: &str) -> Result<std::path::PathBuf> {
    // Try hyphenated name first (abstract-synthesizer → lib/abstract-synthesizer/version.rb)
    let path = dir.join("lib").join(gem_name).join("version.rb");
    if path.exists() {
        return Ok(path);
    }

    // Try underscored name (abstract-synthesizer → lib/abstract_synthesizer/version.rb)
    let underscored = gem_name.replace('-', "_");
    let path = dir.join("lib").join(&underscored).join("version.rb");
    if path.exists() {
        return Ok(path);
    }

    bail!(
        "Version file not found. Tried:\n  lib/{}/version.rb\n  lib/{}/version.rb",
        gem_name,
        underscored
    )
}

// Version parsing and bumping delegated to crate::version module.

/// Exact `X.Y.Z`. Deliberately not a loose semver: every fleet gem uses three
/// numeric components, and accepting a prerelease here would let a tag that
/// sorts unexpectedly reach a published gem.
static SEMVER_EXACT: std::sync::LazyLock<regex::Regex> =
    std::sync::LazyLock::new(|| regex::Regex::new(r"^\d+\.\d+\.\d+$").expect("static regex"));

/// Which literal form a gem's `version.rb` uses for its `VERSION` constant.
///
/// A CLOSED enum on purpose: these are the three forms present across the
/// fleet's 41 root-gemspec repos (26 percent-freeze, 9 quoted, measured
/// 2026-08-17), and a form absent from this enum has no write path — so an
/// unsupported convention is a loud error at detection rather than a silent
/// no-op at write time. Adding a fourth form is one variant plus one arm,
/// which is the parameterization that lets ONE expression serve every gem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VersionLiteralForm {
    /// `VERSION = %(1.2.3).freeze` — the substrate ruby-gem-flake convention.
    PercentFreeze,
    /// `VERSION = "1.2.3"`
    DoubleQuoted,
    /// `VERSION = '1.2.3'`
    SingleQuoted,
}

impl VersionLiteralForm {
    /// Render this form with a new version. The inverse of the pattern that
    /// detected it, so detect→render round-trips by construction.
    fn render(self, version: &str) -> String {
        match self {
            Self::PercentFreeze => format!("VERSION = %({}).freeze", version),
            Self::DoubleQuoted => format!("VERSION = \"{}\"", version),
            Self::SingleQuoted => format!("VERSION = '{}'", version),
        }
    }

    fn pattern(self) -> &'static str {
        match self {
            Self::PercentFreeze => r"VERSION\s*=\s*%\((\d+\.\d+\.\d+)\)\.freeze",
            Self::DoubleQuoted => r#"VERSION\s*=\s*"(\d+\.\d+\.\d+)""#,
            Self::SingleQuoted => r"VERSION\s*=\s*'(\d+\.\d+\.\d+)'",
        }
    }

    /// Every form, in match priority order. Percent-freeze first because it is
    /// the substrate convention and the majority of the fleet.
    const ALL: [Self; 3] = [Self::PercentFreeze, Self::DoubleQuoted, Self::SingleQuoted];
}

/// A located `VERSION` assignment: which form, what version, and the exact byte
/// span it occupies — the span is what makes the rewrite splice-safe.
struct VersionLiteral {
    form: VersionLiteralForm,
    version: String,
    start: usize,
    end: usize,
}

impl VersionLiteral {
    fn find(content: &str) -> Option<Self> {
        for form in VersionLiteralForm::ALL {
            let re = regex::Regex::new(form.pattern()).expect("static regex");
            if let Some(caps) = re.captures(content) {
                let whole = caps.get(0)?;
                return Some(Self {
                    form,
                    version: caps.get(1)?.as_str().to_string(),
                    start: whole.start(),
                    end: whole.end(),
                });
            }
        }
        None
    }
}

/// Locate the byte span of the first VERSION assignment in `content`.
///
/// The reverify callback shape the version-writer family's
/// [`crate::version::splice_and_verify`] seal expects. Ports the ergonomic
/// `Option<VersionLiteral>` shape of [`VersionLiteral::find`] into the
/// `Result<Range<usize>>` shape every sibling ecosystem locator
/// (`zig_top_version_span`, `chart_top_version_span`,
/// `package_json_top_version_span`) already honors, so the gem writer
/// rides the same seal contract as the rest of the family.
///
/// The returned span covers the WHOLE matched form (e.g., the entire
/// `VERSION = %(1.2.3).freeze` bytes, not just the `1.2.3` inside) —
/// gem's `render` re-emits the assignment as a canonical form-preserving
/// unit, so what gets spliced and what gets reverified is the whole
/// rendered assignment.
fn version_literal_span(content: &str) -> anyhow::Result<std::ops::Range<usize>> {
    let found = VersionLiteral::find(content).context(
        "No VERSION assignment found. Expected one of: \
         `VERSION = %(X.Y.Z).freeze`, `VERSION = \"X.Y.Z\"`, \
         `VERSION = 'X.Y.Z'`",
    )?;
    Ok(found.start..found.end)
}

/// Bump the version in a gem's `version.rb`. Returns `(old, new)`.
///
/// THE one expression for writing a gem's version. It is parameterized on the
/// two axes that actually vary, so no sibling implementation is needed:
///
///   * the LITERAL FORM (`VersionLiteralForm`) — percent-freeze, double- or
///     single-quoted — detected from the file and preserved on write;
///   * the TARGET — `set_version` for a caller that already computed a monotone
///     version from released tags, or `level` to compute one from the manifest.
///
/// `level` seeds from the manifest ALONE and cannot see git tags, so a manifest
/// lagging its tags bumps into published territory. Callers that care pass
/// `set_version`.
pub fn bump(
    working_dir: &str,
    level: &str,
    name: Option<String>,
    set_version: Option<String>,
    seed_from_tags: bool,
) -> Result<(String, String)> {
    let dir = Path::new(working_dir);
    if !dir.exists() {
        bail!("Working directory not found: {}", working_dir);
    }

    let gem_name = match name {
        Some(n) => n,
        None => detect_gem_name(dir)?,
    };

    let version_file = find_version_file(dir, &gem_name)?;
    let content = std::fs::read_to_string(&version_file)
        .with_context(|| format!("Failed to read {}", version_file.display()))?;

    let found = VersionLiteral::find(&content).with_context(|| {
        format!(
            "No VERSION assignment found in {}. Expected one of: \
             `VERSION = %(X.Y.Z).freeze`, `VERSION = \"X.Y.Z\"`, \
             `VERSION = 'X.Y.Z'`",
            version_file.display()
        )
    })?;

    let old_version = found.version.clone();
    let new_version = match set_version {
        // An explicit target: the CALLER did the arithmetic. This exists so the
        // seeding decision (which must consider released git tags, something
        // this function cannot see) lives in exactly one place instead of being
        // re-derived per ecosystem. `--level` remains for standalone use.
        Some(v) => {
            if !SEMVER_EXACT.is_match(&v) {
                bail!("--set-version must be an exact X.Y.Z semver, got: {}", v);
            }
            v
        }
        // Seed from released tags: forge reads the tags itself, so the caller
        // supplies no arithmetic. This is what makes a lagging manifest safe —
        // `--level` alone bumps from the manifest and can land behind a
        // published release.
        None if seed_from_tags => {
            let max_released = crate::git::max_released_version("v", Some(dir))?;
            let tag_exists =
                |v: &str| crate::git::tag_exists_in(&format!("v{}", v), Some(dir)).unwrap_or(false);
            let next = version::next_free_version(&old_version, level, &max_released, &tag_exists)?;
            if !max_released.is_empty() {
                info!(
                    "{}: seeding from max(manifest {}, released {}) -> {}",
                    gem_name, old_version, max_released, next
                );
            }
            next
        }
        None => version::bump_semver(&old_version, level)?,
    };

    // Splice over the MATCHED SPAN, and render in the form we found.
    //
    // Two bugs fixed at once, both of which reported success while doing
    // nothing:
    //
    // 1. FORM. This used to match only `%(X.Y.Z).freeze`, so 9 of the fleet's
    //    41 root-gemspec repos — boreal, pangea-{akeyless,dashboards,datadog,
    //    grafana,kubernetes,splunk,spot,tailscale} — could not be bumped at
    //    all. Measured 2026-08-17; verified by running this command against
    //    both forms. The author's convention is PRESERVED rather than
    //    normalized: a bump should change a version and nothing else.
    //
    // 2. SPAN. The replacement used to be rebuilt as a literal
    //    `format!("VERSION = %({}).freeze", old)` and passed to
    //    `content.replace`. The regex tolerates `\s*` around `=`, so a file
    //    written `VERSION= %(0.1.0).freeze` MATCHED but the reconstructed
    //    needle was absent — `replace` found nothing, wrote the file back
    //    byte-identical, and returned Ok with a log line claiming the bump.
    //    Splicing the captured range cannot drift from what matched.
    //
    // The splice-and-seal rides the version-writer family's shared
    // `splice_and_verify` primitive: the same three-step seal every
    // sibling form-preserving writer (Cargo, Zig, Chart top-level, Chart
    // dep-version, Chart dep-repository, package.json) shares — a raw
    // splice, a re-locate-and-reread equality check, and a byte-length-
    // delta arithmetic seal. What lands in the file is the rendered
    // assignment (e.g. `VERSION = %(0.1.1).freeze`) spliced over the
    // whole matched form's byte span; the reverify callback re-runs the
    // same locator on the updated content and the seal proves the new
    // form reads back at the same span byte-for-byte. A rewrite that
    // reports success without actually changing the file is refused by
    // the seal — the exact class the writer family exists to close.
    let new_form = found.form.render(&new_version);
    let new_content = crate::version::splice_and_verify(
        &content,
        found.start..found.end,
        &new_form,
        "VERSION",
        version_literal_span,
    )?;

    std::fs::write(&version_file, &new_content)
        .with_context(|| format!("Failed to write {}", version_file.display()))?;

    info!(
        "{}: {} → {} ({})",
        gem_name, old_version, new_version, level
    );

    Ok((old_version, new_version))
}

/// Build a .gem file from a gemspec.
pub fn build(working_dir: &str, name: Option<String>) -> Result<String> {
    let dir = Path::new(working_dir);
    if !dir.exists() {
        bail!("Working directory not found: {}", working_dir);
    }

    let gem_name = match name {
        Some(n) => n,
        None => detect_gem_name(dir)?,
    };

    let gemspec = format!("{}.gemspec", gem_name);
    let gemspec_path = dir.join(&gemspec);
    if !gemspec_path.exists() {
        bail!("Gemspec not found: {}", gemspec_path.display());
    }

    info!("Building gem: {}", gem_name);

    // Clean previous .gem files for this gem
    for entry in std::fs::read_dir(dir)? {
        if let Ok(e) = entry {
            if let Some(name) = e.file_name().to_str() {
                if name.starts_with(&gem_name) && name.ends_with(".gem") {
                    std::fs::remove_file(e.path())?;
                }
            }
        }
    }

    // gem build
    let gem = gem_bin();
    let status = Command::new(&gem)
        .args(["build", &gemspec])
        .current_dir(dir)
        .status()
        .context("Failed to run gem build")?;

    if !status.success() {
        bail!("gem build failed for {}", gemspec);
    }

    // Find the built .gem file
    let gem_file = find_gem_file(dir, &gem_name)?;
    info!("Built: {}", gem_file);
    Ok(gem_file)
}

/// Build and push a gem to RubyGems.org.
pub fn push(
    working_dir: &str,
    name: Option<String>,
    api_key: Option<String>,
    otp: Option<String>,
) -> Result<()> {
    // Resolve API key
    let key = match api_key {
        Some(k) => k,
        None => {
            // Try reading from file
            let home = std::env::var("HOME").context("HOME not set")?;
            let key_file = Path::new(&home).join(".config/rubygems/api-key");

            if key_file.exists() {
                std::fs::read_to_string(&key_file)
                    .context("Failed to read ~/.config/rubygems/api-key")?
                    .trim()
                    .to_string()
            } else {
                bail!(
                    "No API key provided. Set GEM_HOST_API_KEY env var, \
                     pass --api-key, or create ~/.config/rubygems/api-key"
                );
            }
        }
    };

    // Write credentials file (gem push reads from ~/.gem/credentials)
    let home = std::env::var("HOME").context("HOME not set")?;
    let gem_dir = Path::new(&home).join(".gem");
    std::fs::create_dir_all(&gem_dir)?;
    let creds_path = gem_dir.join("credentials");
    let creds_content = format!("---\n:rubygems_api_key: {}\n", key);
    std::fs::write(&creds_path, &creds_content)?;

    // Set permissions to 0600
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&creds_path, std::fs::Permissions::from_mode(0o600))?;
    }

    info!("=== Build ===");
    let gem_file = build(working_dir, name)?;

    info!("=== Push ===");
    let gem_path = Path::new(working_dir).join(&gem_file);

    let mut args = vec!["push".to_string(), gem_path.to_str().unwrap().to_string()];
    if let Some(otp_code) = &otp {
        args.push("--otp".to_string());
        args.push(otp_code.clone());
    }

    let gem = gem_bin();
    let status = Command::new(&gem)
        .args(&args)
        .status()
        .context("Failed to run gem push")?;

    if !status.success() {
        bail!("gem push failed for {}", gem_file);
    }

    info!("Published: {}", gem_file);
    Ok(())
}

/// Run tests for a Ruby gem using bundle exec rake spec.
pub fn test(working_dir: &str, name: Option<String>) -> Result<()> {
    let dir = Path::new(working_dir);
    if !dir.exists() {
        bail!("Working directory not found: {}", working_dir);
    }

    let gem_name = match name {
        Some(n) => n,
        None => detect_gem_name(dir)?,
    };

    info!("Running tests for gem: {}", gem_name);

    let bundle = bundle_bin();
    let status = Command::new(&bundle)
        .args(["exec", "rake", "spec"])
        .current_dir(dir)
        .status()
        .context("Failed to run bundle exec rake spec")?;

    if !status.success() {
        bail!("Tests failed for {}", gem_name);
    }

    info!("Tests passed: {}", gem_name);
    Ok(())
}

// --- Helpers ---

fn find_gem_file(dir: &Path, prefix: &str) -> Result<String> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_name()
                .to_str()
                .map(|n| n.starts_with(prefix) && n.ends_with(".gem") && !n.ends_with(".gemspec"))
                .unwrap_or(false)
        })
        .collect();

    entries.sort_by(|a, b| {
        b.metadata()
            .and_then(|m| m.modified())
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
            .cmp(
                &a.metadata()
                    .and_then(|m| m.modified())
                    .unwrap_or(std::time::SystemTime::UNIX_EPOCH),
            )
    });

    entries
        .first()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .context(format!(
            "No .gem file found for {} in {}",
            prefix,
            dir.display()
        ))
}

#[cfg(test)]
mod tests {
    /// Whole-module shield: no raw `gem`-literal spawn may live in
    /// `commands/gem.rs`. Every gem spawn must resolve `GEM_BIN` via
    /// [`super::gem_bin`] first — the derived-`_BIN` override the
    /// sibling `_BIN`-suffix tools (`ATTIC_BIN`, `GH_BIN`, `DOCA_BIN`,
    /// `KUBECTL_BIN`, `DOCKER_BIN`, `BUNDLE_BIN`, `INSPEC_BIN`) honor,
    /// chosen over the bare-name form because RubyGems itself claims the
    /// unadorned `GEM_*` env-var surface for its own runtime config
    /// (`GEM_HOME`, `GEM_PATH`, `GEM_SPEC_CACHE`, …). Mirrors the
    /// sibling `BUNDLE_BIN` / `INSPEC_BIN` shields in
    /// `commands/pangea_infra.rs` (e26787c) — the immediate structural
    /// precedent from the same Ruby-toolchain surface.
    ///
    /// Pre-lift the two consumer sites — `build` (`gem build
    /// <gemspec>`) and `push` (`gem push <gem-path> [--otp <code>]`) —
    /// spelled the bare-literal tool-name form (a `Command::new` call
    /// with the tool name inline as a string) verbatim, ignoring
    /// `GEM_BIN` at both gates. `build` writes a
    /// `Gem::Specification`-marshaled artifact whose format is
    /// Ruby-version-sensitive, and `push` publishes it through a
    /// credentials-file schema that varies across gem 2.x / 3.x major
    /// versions; a stale ambient-PATH `gem` at either site silently
    /// attributed the packaging or publishing verdict to the wrong
    /// RubyGems binary, not to the substrate-pinned derivation the
    /// flake declared. Same silent-PATH-fallback bug class the sibling
    /// `TERRAFORM` / `BUNDLE_BIN` / `INSPEC_BIN` migrations closed on
    /// their respective spawn surfaces.
    ///
    /// This shield scans the module's own source via [`include_str!`]
    /// and forbids the fused literal shape at every spawn form
    /// (`std::process::Command::new(...)`, the bare `Command::new(...)`,
    /// and the `tokio::process::Command::new(...)` long form). The
    /// forbidden shapes are reconstructed via [`format!`] so this
    /// shield's own source text does not false-match itself — the
    /// whole-module scan therefore covers both the top-of-file
    /// production body AND every sibling `#[cfg(test)]` block (any of
    /// which could otherwise silently re-introduce a raw literal — the
    /// most likely growth site as new gem-lifecycle stanzas land in the
    /// gem-toolchain surface). Also asserts the canonical
    /// `crate::repo::get_tool_path("GEM_BIN", "gem")` delegation form
    /// is present so the sigil-body itself cannot silently drift away
    /// from the substrate-exported env-var contract.
    ///
    /// The end-to-end `GEM_BIN`-routing invariant of the underlying
    /// primitive is pinned separately by
    /// [`crate::repo::tests::test_get_tool_path_with_env`] and
    /// [`crate::repo::tests::test_get_tool_path_fallback`]; this shield
    /// only certifies that every gem-spawning site in this module reads
    /// through `gem_bin()`.
    #[test]
    fn test_gem_spawn_routes_through_gem_bin_not_raw_literal() {
        const SOURCE: &str = include_str!("gem.rs");

        crate::test_support::assert_source_forbids_bare_spawn_shapes(
            SOURCE,
            "commands/gem.rs",
            "gem",
            "resolve `GEM_BIN` via `gem_bin()`",
        );

        crate::test_support::assert_source_defines_sigil_bin_fn_code_line(
            SOURCE,
            "commands/gem.rs",
            "gem_bin",
            "GEM_BIN",
            "gem",
        );
        // Assert the canonical two-arg sigil-delegation form appears at
        // a code line. Pre-lift the shield spelled
        // `SOURCE.contains("crate::repo::get_tool_path(\"GEM_BIN\", \"gem\")")`
        // against the substituted literal; the shield's own docstring
        // above quotes the same form inside a `///` block and the
        // shield's own panic message quoted it inline too, so the naive
        // `contains` predicate always passed regardless of whether the
        // production sigil body at `commands/gem.rs:44` was intact —
        // deleting it would silently leave the doc/message bytes and
        // the shield would report green. The helper rides
        // `code_line_hits` (which filters `///`/`//!`/`//` lines) and
        // moves the panic message into `test_support.rs` so neither
        // narration site can satisfy the shield.
        crate::test_support::assert_source_has_canonical_two_arg_sigil_code_line(
            SOURCE,
            "commands/gem.rs",
            "GEM_BIN",
            "gem",
        );
    }

    /// Whole-module shield: no raw `bundle`-literal spawn may live in
    /// `commands/gem.rs`. Every bundle spawn must resolve `BUNDLE_BIN`
    /// via [`super::bundle_bin`] first — matches the sibling
    /// `bundle_bin()` shield in `commands/pangea_infra.rs` (e26787c)
    /// verbatim, so both Ruby-toolchain surfaces converge on the same
    /// env-var-override contract.
    ///
    /// Pre-lift the one consumer site — `test` (`bundle exec rake
    /// spec`) — spelled the bare-literal tool-name form (a
    /// `Command::new` call with the tool name inline as a string)
    /// verbatim, ignoring `BUNDLE_BIN`. The RSpec-gate this spawn
    /// produces is the load-bearing verdict every gem-push downstream
    /// of it depends on for correctness: a pre-lift ambient-PATH
    /// `bundle` silently resolved the Gemfile lockfile against a
    /// wrong-Ruby-version bundler (Bundler's version-selection
    /// algorithm's lockfile-vs-runtime-Ruby mismatches are the
    /// load-bearing failure mode), so the wrong-binary verdict silently
    /// attributed the test-gate result every gem-publish downstream
    /// trusts to the wrong Ruby toolchain. Same silent-PATH-fallback
    /// bug class the sibling `TERRAFORM` / `BUNDLE_BIN` / `INSPEC_BIN`
    /// migrations closed on their respective spawn surfaces.
    ///
    /// This shield scans the module's own source via [`include_str!`]
    /// and forbids the fused literal shape at every spawn form
    /// (`std::process::Command::new(...)`, the bare `Command::new(...)`,
    /// and the `tokio::process::Command::new(...)` long form),
    /// reconstructed via [`format!`] so this shield's own source text
    /// does not false-match itself. Also asserts the canonical
    /// `crate::repo::get_tool_path("BUNDLE_BIN", "bundle")` delegation
    /// form is present so the sigil-body itself cannot silently drift
    /// away from the substrate-exported env-var contract.
    #[test]
    fn test_bundle_spawn_routes_through_bundle_bin_not_raw_literal() {
        const SOURCE: &str = include_str!("gem.rs");

        crate::test_support::assert_source_forbids_bare_spawn_shapes(
            SOURCE,
            "commands/gem.rs",
            "bundle",
            "resolve `BUNDLE_BIN` via `bundle_bin()`",
        );

        crate::test_support::assert_source_defines_sigil_bin_fn_code_line(
            SOURCE,
            "commands/gem.rs",
            "bundle_bin",
            "BUNDLE_BIN",
            "bundle",
        );
        // Same docstring-self-match defect the sibling `GEM_BIN`
        // shield above closes: pre-lift the shield's own docstring
        // (line 469) and panic message quoted
        // `crate::repo::get_tool_path("BUNDLE_BIN", "bundle")` verbatim,
        // so a regression at `commands/gem.rs:72` (the production
        // sigil body) silently passed the naive `contains` shield.
        // The helper's `code_line_hits` filter closes it.
        crate::test_support::assert_source_has_canonical_two_arg_sigil_code_line(
            SOURCE,
            "commands/gem.rs",
            "BUNDLE_BIN",
            "bundle",
        );
    }

    // ── VERSION literal form: detect, render, splice ────────────────────
    //
    // These cover the two bugs the form-parameterization fixed, both of which
    // previously reported SUCCESS while changing nothing.

    #[test]
    fn finds_every_literal_form_the_fleet_uses() {
        // 26 of 41 fleet gems use percent-freeze, 9 use quotes (2026-08-17).
        let cases = [
            (
                "  VERSION = %(1.2.3).freeze",
                super::VersionLiteralForm::PercentFreeze,
            ),
            (
                "  VERSION = \"1.2.3\"",
                super::VersionLiteralForm::DoubleQuoted,
            ),
            (
                "  VERSION = '1.2.3'",
                super::VersionLiteralForm::SingleQuoted,
            ),
        ];
        for (src, want) in cases {
            let found = super::VersionLiteral::find(src)
                .unwrap_or_else(|| panic!("no VERSION found in {src:?}"));
            assert_eq!(found.form, want, "form for {src:?}");
            assert_eq!(found.version, "1.2.3", "version for {src:?}");
        }
    }

    #[test]
    fn render_preserves_the_authors_form() {
        // A bump must change a version and NOTHING else. Normalizing quotes to
        // percent-freeze would rewrite 9 repos' convention behind their backs.
        assert_eq!(
            super::VersionLiteralForm::PercentFreeze.render("2.0.0"),
            "VERSION = %(2.0.0).freeze"
        );
        assert_eq!(
            super::VersionLiteralForm::DoubleQuoted.render("2.0.0"),
            "VERSION = \"2.0.0\""
        );
        assert_eq!(
            super::VersionLiteralForm::SingleQuoted.render("2.0.0"),
            "VERSION = '2.0.0'"
        );
    }

    #[test]
    fn detect_then_render_round_trips_for_every_form() {
        // The property that makes ONE expression safe for every gem: whatever
        // was detected can be re-rendered, so no form is write-only.
        for src in [
            "VERSION = %(0.4.1).freeze",
            "VERSION = \"0.4.1\"",
            "VERSION = '0.4.1'",
        ] {
            let f = super::VersionLiteral::find(src).expect("found");
            assert_eq!(f.form.render(&f.version), src, "round-trip for {src:?}");
        }
    }

    #[test]
    fn span_splice_survives_nonstandard_spacing() {
        // THE SILENT-SUCCESS BUG. The old code rebuilt the needle as
        // `format!("VERSION = %({}).freeze", old)` and called `content.replace`.
        // The regex tolerates `\s*` around `=`, so `VERSION=` matched, the
        // reconstructed needle was absent, replace did nothing, and the file was
        // written back byte-identical with a log line claiming the bump.
        let content = "module D\n  VERSION= %(0.1.0).freeze\nend\n";
        let f = super::VersionLiteral::find(content).expect("matches despite spacing");
        assert_eq!(f.version, "0.1.0");
        let spliced = {
            let mut out = String::new();
            out.push_str(&content[..f.start]);
            out.push_str(&f.form.render("0.1.1"));
            out.push_str(&content[f.end..]);
            out
        };
        assert!(
            spliced.contains("0.1.1"),
            "the new version is actually written"
        );
        assert!(!spliced.contains("0.1.0"), "the old version is gone");
        assert_ne!(spliced, content, "the file genuinely changed");
    }

    #[test]
    fn unsupported_shapes_are_not_found_rather_than_mis_parsed() {
        // Absence must be loud at DETECTION, never a silent no-op at write.
        for src in [
            "VERSION = 1.2.3",             // bare, unquoted
            "VERSION = %(1.2).freeze",     // two components
            "VERSION = \"1.2.3-pre\"",     // prerelease
            "# VERSION = %(1.2.3).freeze", // commented out is still a match candidate
            "module Demo\nend\n",
        ] {
            let found = super::VersionLiteral::find(src);
            if src.starts_with('#') {
                // A commented line DOES match -- documented, not asserted away:
                // version.rb files do not carry commented VERSION lines in the
                // fleet, and stripping comments would need a Ruby parser.
                assert!(
                    found.is_some(),
                    "known limitation: comments are not skipped"
                );
            } else {
                assert!(found.is_none(), "{src:?} must not be parsed as a version");
            }
        }
    }

    // ── Bump splice-and-seal: the family's shared seal, not a local one ─
    //
    // The `bump` body was the LAST hand-rolled splice site in the forge
    // writer surface — a three-line `push_str(&content[..found.start]) +
    // push_str(&found.form.render(...)) + push_str(&content[found.end..])`
    // shape sitting outside the version-writer family's shared
    // `crate::version::splice_and_verify` seal. Every sibling ecosystem
    // writer (Cargo, Zig, Chart top-level, Chart dep-version, Chart
    // dep-repository, package.json) already routes its splice-and-seal
    // through that primitive, so a future edit to any of the three seals
    // it carries (splice arithmetic, reread-equals-new-value, byte-length-
    // delta) lands in exactly one place — and used to skip gem, whose
    // local splice re-opened the class the family's shield refuses. The
    // port closes the outlier; the two shields below refuse its regrowth.

    /// `bump` MUST route its splice-and-seal through
    /// [`crate::version::splice_and_verify`] — the one seal every
    /// form-preserving splice writer in the forge writer surface now
    /// shares. A hand-rolled
    /// `push_str(&content[..found.start]) + push_str(&content[found.end..])`
    /// splice re-opens the local-seal outlier the port closed, so a
    /// future family-wide seal enhancement (say, a checksum on the
    /// pre-splice bytes or an idempotence assertion under a second
    /// splice) would silently skip gem while every sibling ecosystem
    /// inherited it.
    ///
    /// Fail-before-pass-after: with the pre-port `let mut new_content =
    /// String::with_capacity(...); new_content.push_str(&content[..found.start]);
    /// new_content.push_str(&found.form.render(&new_version));
    /// new_content.push_str(&content[found.end..]);` body restored, the
    /// `contains("crate::version::splice_and_verify(")` assertion below
    /// fires. Restoring the delegation returns the shield to green.
    #[test]
    fn bump_routes_through_splice_and_verify_not_a_local_splice() {
        const SOURCE: &str = include_str!("gem.rs");
        let signature = "pub fn bump(";
        let start = SOURCE
            .find(signature)
            .expect("must find the public signature of gem::bump");
        let after_brace = SOURCE[start..]
            .find(" {\n")
            .map(|o| start + o + 3)
            .expect("must find the opening brace for gem::bump");
        let body_end = SOURCE[after_brace..]
            .find("\n}\n")
            .map(|o| after_brace + o)
            .expect("must find the closing brace for gem::bump");
        let body = &SOURCE[after_brace..body_end];

        assert!(
            body.contains("crate::version::splice_and_verify("),
            "gem::bump must route its splice-and-seal through \
             crate::version::splice_and_verify — the one seal the whole \
             forge writer family shares. Got body: {body:?}"
        );

        // Guard against the pre-port local splice regrowing. The three
        // `push_str(...)` calls that hand-roll the splice — head, rendered
        // form, tail — are the exact shape splice_and_verify subsumes.
        // Presence of the head or tail push in the bump body re-opens the
        // outlier.
        assert!(
            !body.contains("push_str(&content[..found.start]"),
            "gem::bump must NOT hand-roll the splice head — \
             crate::version::splice_and_verify owns that. Got body: {body:?}"
        );
        assert!(
            !body.contains("push_str(&content[found.end..]"),
            "gem::bump must NOT hand-roll the splice tail — \
             crate::version::splice_and_verify owns that. Got body: {body:?}"
        );
    }

    /// End-to-end round-trip: [`super::bump`] with `set_version` (no git,
    /// no gemspec-detection) rewrites a version.rb from `0.1.0` to a
    /// caller-supplied `0.1.1`, and the file on disk reads back with the
    /// new version at the same form, every surrounding byte unchanged.
    ///
    /// Pins the port's behavioral contract on the IO side: the
    /// [`crate::version::splice_and_verify`] seal fires against a real
    /// on-disk file, the returned `(old, new)` pair reflects what
    /// happened, and the file's form (`VERSION = %(X.Y.Z).freeze`) is
    /// preserved through the round-trip. A regression that hand-rolls
    /// the splice would still pass this test (the behavior is
    /// unchanged), but a regression that misuses the seal (wrong
    /// reverify callback, wrong new_value shape) would surface here as
    /// a seal-failure error rather than a silent success.
    #[test]
    fn bump_rewrites_version_rb_end_to_end_through_the_shared_seal() {
        let dir = tempfile::tempdir().unwrap();
        let lib = dir.path().join("lib").join("gem_under_test");
        std::fs::create_dir_all(&lib).unwrap();
        let version_file = lib.join("version.rb");
        let before = "module GemUnderTest\n  VERSION = %(0.1.0).freeze\nend\n";
        std::fs::write(&version_file, before).unwrap();

        let (old, new) = super::bump(
            dir.path().to_str().unwrap(),
            "patch",
            Some("gem_under_test".to_string()),
            Some("0.1.1".to_string()),
            false,
        )
        .expect("bump must succeed against a well-formed version.rb");

        assert_eq!(
            old, "0.1.0",
            "returned old version must match the file's pre-bump value"
        );
        assert_eq!(new, "0.1.1", "returned new version must match set_version");

        let after = std::fs::read_to_string(&version_file).unwrap();
        assert_eq!(
            after, "module GemUnderTest\n  VERSION = %(0.1.1).freeze\nend\n",
            "the file's post-bump bytes must be the pre-bump bytes with the version \
             spliced — every surrounding byte unchanged"
        );
    }
}
