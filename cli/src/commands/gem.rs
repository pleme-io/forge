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

/// Bump the version in a gem's version.rb file.
///
/// Finds `VERSION = %(X.Y.Z).freeze` and updates it.
/// Returns (old_version, new_version).
pub fn bump(working_dir: &str, level: &str, name: Option<String>) -> Result<(String, String)> {
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

    // Match VERSION = %(X.Y.Z).freeze
    let re = regex::Regex::new(r#"VERSION\s*=\s*%\((\d+\.\d+\.\d+)\)\.freeze"#)
        .context("Failed to compile version regex")?;

    let caps = re.captures(&content).with_context(|| {
        format!(
            "No VERSION = %(X.Y.Z).freeze found in {}",
            version_file.display()
        )
    })?;

    let old_version = caps[1].to_string();
    let new_version = version::bump_semver(&old_version, level)?;

    // Replace in file
    let new_content = content.replace(
        &format!("VERSION = %({}).freeze", old_version),
        &format!("VERSION = %({}).freeze", new_version),
    );

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
        assert!(
            SOURCE.contains("crate::repo::get_tool_path(\"GEM_BIN\", \"gem\")"),
            "`gem_bin()` must delegate to \
             `crate::repo::get_tool_path(\"GEM_BIN\", \"gem\")` — the \
             canonical lookup was not found in the module."
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
        assert!(
            SOURCE.contains("crate::repo::get_tool_path(\"BUNDLE_BIN\", \"bundle\")"),
            "`bundle_bin()` must delegate to \
             `crate::repo::get_tool_path(\"BUNDLE_BIN\", \"bundle\")` \
             — the canonical lookup was not found in the module."
        );
    }
}
