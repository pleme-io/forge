//! Ruby gem lifecycle commands
//!
//! Provides build, push, and version bump operations for Ruby gems.

use anyhow::{bail, Context, Result};
use std::path::Path;
use std::process::Command;
use tracing::info;

use crate::repo::require_existing_working_dir;
use crate::retry::run_inherited_status_sync;
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
    let dir = require_existing_working_dir(working_dir)?;

    // Parse `--level` at ONE top-of-fn site (before the manifest read and
    // before the `match set_version` branch selection), then thread the
    // typed [`version::BumpLevel`] through the seed_from_tags arm and the
    // fallback bump arm below via [`version::bump_semver_typed`].
    // Pre-lift the fallback `None => version::bump_semver(&old_version, level)?`
    // arm called the stringly [`version::bump_semver`] wrapper, which
    // parses `level: &str` into [`version::BumpLevel`] INSIDE its own
    // body via [`version::BumpLevel::from_str`] ([`crate::version`]:1428)
    // — so the level grammar was re-parsed at one further consumer, and
    // an invalid `--level` on that arm fired AFTER the version-file
    // locate + read (`find_version_file` + `read_to_string` +
    // `VersionLiteral::find`), a wasted three-step I/O on a bogus input
    // the parse alone could have refused.
    //
    // Post-lift the grammar is parsed at ONE site (this `level.parse()?`
    // call) and the typed value dispatches directly to the const
    // arithmetic on [`version::SemverTriple::bumped`] through the typed
    // peer. This mirrors the sibling `commands/tool.rs::bump` discipline
    // (commit fa0c6d9) which established the same top-of-fn parse and
    // typed-peer dispatch across its own two per-language branches
    // (Rust arm + Zig arm), off the same forbidden stringly-wrapper
    // shape. The `Some(v)` set_version arm ignores `level` on purpose
    // (the caller did the arithmetic), and clap declares `set_version`
    // as `conflicts_with = "level"` at [`crate::cli::GemCommands::Bump`]
    // — a user cannot pass a real `--level` alongside `--set-version`,
    // and the clap default `"patch"` always parses cleanly through
    // [`version::BumpLevel::from_str`], so hoisting the parse above the
    // match does not refuse any prior-accepted invocation.
    //
    // THEORY.md §V.4 typed primitives: the `--level` argument surface
    // now carries a typed peer parsed at ONE site (this call), matching
    // the discipline the sibling seed_from_tags arm below already
    // carried at its own inner `let level_typed: version::BumpLevel = ...`
    // (now hoisted here), and matching commit fa0c6d9's
    // `commands/tool.rs::bump` top-of-fn boundary parse.
    // THEORY.md §VI.1 one-oracle discipline: the level grammar (which
    // strings map to which [`version::BumpLevel`] variant) lives at ONE
    // body ([`version::BumpLevel::from_str`]) that this fn — and every
    // sibling `bump` fn — parses through, rather than at N
    // stringly-wrapper call sites that each re-derive it via
    // [`version::bump_semver`].
    let level_typed: version::BumpLevel = level.parse()?;

    let gem_name = match name {
        Some(n) => n,
        None => detect_gem_name(dir)?,
    };

    let version_file = find_version_file(dir, &gem_name)?;
    let content = crate::repo::read_text_sync(&version_file)?;

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
            // The FULLY-TYPED bridge: `max_released_version_typed` returns
            // an `Option<SemverTriple>` at the boundary and
            // `next_free_version_all_typed` takes typed
            // (`SemverTriple`, `BumpLevel`, `Option<SemverTriple>`,
            // `&dyn Fn(SemverTriple) -> bool`) all the way through the
            // seeding-and-collision arithmetic, returning a typed
            // `SemverTriple` winner. Pre-lift this branch called the
            // stringly `max_released_version` (`Option<SemverTriple>`
            // rendered to a `String` via `to_string()`, "no tag"
            // projected to the `""` empty-string sentinel) and the
            // stringly `next_free_version` (re-parsed `manifest_version`
            // and `max_released` via `parse_semver_typed` at every call,
            // wrapped the string-surface `tag_exists` inside a
            // `|t: SemverTriple| tag_exists(&t.to_string())` bridge
            // that fired one `to_string()` per iteration on the
            // pathological path, and re-rendered the typed winner to a
            // `String` at the return) — three parse/render round-trips
            // across a boundary the typed peers below the surface had
            // already opened.
            //
            // Post-lift there is ONE typed parse per side (the
            // `parse_semver_typed` on `old_version` and the
            // `BumpLevel::from_str` on `level`), the collision-skip
            // loop runs against a `HashSet`-style typed predicate at
            // zero allocations per iteration, and the winner is
            // available as a typed `SemverTriple` that renders to
            // `String` exactly once at the `to_string()` boundary
            // projection at the end of this arm — the boundary the
            // splice-and-seal below needs. The "no released tag yet"
            // state is `Option::None` at the type level, not the `""`
            // empty-string sentinel the pre-lift `if
            // !max_released.is_empty()` gate had to redeem at every
            // consumer.
            //
            // THEORY.md §V.4 typed primitives: the seeding-decision
            // arm at the last remaining stringly boundary in the
            // release-arithmetic surface routes through the
            // fully-typed peers end-to-end. THEORY.md §VI.1 one-oracle
            // discipline: the seeding-and-collision loop still lives
            // at ONE body (`next_free_version_all_typed` in
            // `version.rs`) that both this typed caller and the
            // stringly `next_free_version` / `next_free_version_typed`
            // wrappers delegate through, so the migration is a
            // caller-side lift with no forked oracle. Sibling of the
            // six b68778b/b3527d3/c8bcdd5/eec7dbe/85f9b3d/c96c115
            // typed-peer lifts on `parse_semver`, `bump_semver`,
            // `bump_seed`, `next_free_version`, `SemverTriple::bumped`,
            // and `max_released_version` that opened this typed peer
            // path — this commit closes the last stringly caller
            // that redeemed a rendered/re-parsed round-trip across
            // the boundary.
            // Fold the two derived values the seeding-and-collision arithmetic
            // reads over `<prefix>X.Y.Z` git tags — the numeric MAX (for the
            // seed) and MEMBERSHIP (for the collision predicate) — onto ONE
            // `git tag --list v*` fetch via
            // [`crate::git::released_semver_tags_typed`]. Pre-lift this arm
            // fired TWO git spawns on the fast path and up to `1 + 1024` on
            // the pathological path: one at [`crate::git::max_released_version_typed`]
            // to pick the seed, then one at [`crate::git::tag_exists_in`] per
            // collision-loop iteration — with the per-iteration lookup
            // rebuilding the tag string via `format!("v{t}")` (a per-iter
            // allocation the fully-typed peer had already closed inside the
            // loop body) AND swallowing the git-capture error via
            // `.unwrap_or(false)` (so a git failure on any iteration silently
            // promoted a real published tag to "does not exist" and let the
            // loop bump straight into a collision, which would land a release
            // atop the tag the arm was ADDED to skip). The joint typed peer
            // reads the whole prefix listing once, into a
            // `BTreeSet<SemverTriple>` whose derived `Ord` is exactly
            // `SemverTriple`'s field-declared semver-lex, so:
            //   - the seed's max is `released.iter().next_back().copied()`
            //     — the highest set element, no separate fold;
            //   - the collision predicate is `|t| released.contains(&t)`
            //     — pure, allocation-free, O(log n) per iteration, and
            //     TOTAL (no fallible `Result<bool>` to swallow);
            //   - a git-capture failure propagates at the ONE
            //     `released_semver_tags_typed` fetch site rather than being
            //     silently redeemed at every loop iteration.
            //
            // THEORY.md §V.4 typed primitives: the tag-scan surface now
            // carries typed values end-to-end (typed prefix, typed set of
            // triples, typed predicate over the set, typed winner) — not a
            // stringly `tag_exists_in(&format!("v{t}"), ...).unwrap_or(false)`
            // bridge that fell back to `false` on error.
            // THEORY.md §VI.1 one-oracle discipline: the tag-scan lives at
            // ONE body (`released_semver_tags_typed`) that both the seed and
            // the collision predicate consume — no forked fetch, no
            // double-scan, no error-swallowing bridge.
            let manifest = version::parse_semver_typed(&old_version)?;
            let released = crate::git::released_semver_tags_typed("v", Some(dir))?;
            let max_released = released.iter().next_back().copied();
            let tag_exists = |t: version::SemverTriple| released.contains(&t);
            let next = version::next_free_version_all_typed(
                manifest,
                level_typed,
                max_released,
                &tag_exists,
            )?;
            if let Some(max_r) = max_released {
                info!(
                    "{}: seeding from max(manifest {}, released {}) -> {}",
                    gem_name, old_version, max_r, next
                );
            }
            next.to_string()
        }
        None => version::bump_semver_typed(&old_version, level_typed)?,
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

    crate::repo::write_text_sync(&version_file, &new_content)?;

    info!(
        "{}: {} → {} ({})",
        gem_name, old_version, new_version, level_typed
    );

    Ok((old_version, new_version))
}

/// Build a .gem file from a gemspec.
pub fn build(working_dir: &str, name: Option<String>) -> Result<String> {
    let dir = require_existing_working_dir(working_dir)?;

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
    let mut cmd = Command::new(&gem);
    cmd.args(["build", &gemspec]).current_dir(dir);
    run_inherited_status_sync(cmd, &format!("gem build for {}", gemspec))?;

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
            let key_file = crate::repo::path_from_env("HOME", "HOME not set")?
                .join(".config/rubygems/api-key");

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
    let gem_dir = crate::repo::path_from_env("HOME", "HOME not set")?.join(".gem");
    crate::repo::create_dir_all_sync(&gem_dir)?;
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
    let mut cmd = Command::new(&gem);
    cmd.args(&args);
    run_inherited_status_sync(cmd, &format!("gem push for {}", gem_file))?;

    info!("Published: {}", gem_file);
    Ok(())
}

/// Run tests for a Ruby gem using bundle exec rake spec.
pub fn test(working_dir: &str, name: Option<String>) -> Result<()> {
    let dir = require_existing_working_dir(working_dir)?;

    let gem_name = match name {
        Some(n) => n,
        None => detect_gem_name(dir)?,
    };

    info!("Running tests for gem: {}", gem_name);

    let bundle = bundle_bin();
    let mut cmd = Command::new(&bundle);
    cmd.args(["exec", "rake", "spec"]).current_dir(dir);
    run_inherited_status_sync(cmd, &format!("bundle exec rake spec for {}", gem_name))?;

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

    crate::repo::sort_dir_entries_by_mtime_desc(&mut entries);

    entries
        .first()
        .map(crate::repo::dir_entry_name_lossy)
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

        // One canonical composition (per `test_support.rs::
        // assert_source_routes_bare_spawn_through_two_arg_sigil`) fuses
        // the three per-tool invariants — no bare `gem` spawn at any
        // shape, `gem_bin()` defined at a code line, and the sigil
        // delegates via the canonical two-arg
        // `crate::repo::get_tool_path("GEM_BIN", "gem")` at a code
        // line. Same three-primitive stanza the sibling shield family
        // rides across `commands/pangea_infra.rs`, `commands/federation.rs`,
        // `commands/prerelease.rs`, `commands/dashboards.rs`,
        // `commands/infra.rs`, and `infrastructure/docker.rs`.
        crate::test_support::assert_source_routes_bare_spawn_through_two_arg_sigil(
            SOURCE,
            "commands/gem.rs",
            "gem",
            "GEM_BIN",
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

        // Sibling of the `GEM_BIN` shield above — same composed
        // three-primitive stanza (`test_support.rs::
        // assert_source_routes_bare_spawn_through_two_arg_sigil`)
        // routed on `bundle` / `BUNDLE_BIN`. Same shape every
        // migrated sibling shield rides.
        crate::test_support::assert_source_routes_bare_spawn_through_two_arg_sigil(
            SOURCE,
            "commands/gem.rs",
            "bundle",
            "BUNDLE_BIN",
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

    /// Whole-module shield: every status-only spawn in
    /// `commands/gem.rs` routes through
    /// [`crate::retry::run_inherited_status_sync`], never a hand-rolled
    /// `.status()` + `if !status.success() { bail!(…) }` stanza that
    /// drops the exit code from the operator log line. Pre-lift all
    /// three spawns — `build` (`gem build <gemspec>`), `push`
    /// (`gem push <gem-path> [--otp <code>]`), and `test`
    /// (`bundle exec rake spec`) — spelled the inline stanza with an
    /// ad-hoc `gem build failed for <gemspec>` / `gem push failed for
    /// <gem-file>` / `Tests failed for <gem-name>` message that
    /// carried the gemspec / gem-file / gem-name context but no exit
    /// code; post-lift each is a one-line delegation and the canonical
    /// `"{op} failed (exit {code})"` envelope is emitted by
    /// construction at the primitive's ONE body, with the gemspec /
    /// gem-file / gem-name folded into the `op` label so the operator
    /// log line reads e.g. `gem push for foo-1.0.0.gem failed (exit 1)`
    /// — pre-lift context PLUS the exit code the canonical envelope
    /// now carries by construction.
    ///
    /// Sibling of the `commands/crossplane.rs` shield
    /// `test_crossplane_status_spawns_route_through_run_inherited_status_sync`
    /// (6cb9442) and `commands/pangea_infra.rs`'s
    /// `test_pangea_infra_status_spawns_route_through_run_inherited_status_sync`
    /// (a6e9b96). Same three-primitive discipline: negative side
    /// forbids the inline `.status()` builder-terminator at any code
    /// line in the module body; positive side pins that
    /// `run_inherited_status_sync(` appears at ≥3 code lines (one per
    /// pre-lift spawn), so a regression that dropped every delegation
    /// cannot leave the negative scan trivially satisfied by absence.
    /// Both hits route through [`crate::test_support::code_line_hits`]
    /// for anti-docstring-self-match discipline. Scan bounds from file
    /// start to the FIRST `\n#[cfg(test)]\n` marker (this test
    /// module's own opener), so this shield's own body — the string
    /// literal `".status()"` passed to `code_line_hits`, and the
    /// assertion message that names the forbidden terminator — stays
    /// out of scope.
    #[test]
    fn test_gem_status_spawns_route_through_run_inherited_status_sync() {
        crate::test_support::assert_source_routes_status_only_spawns_through_run_inherited_status_sync(
            include_str!("gem.rs"),
            "commands/gem.rs",
            3,
            "all three status-only spawns (`gem build` / `gem push` / \
             `bundle exec rake spec`)",
        );
    }

    /// Whole-body shield: the `seed_from_tags` arm of [`super::bump`]
    /// MUST route the tag-scan and the seeding-and-collision arithmetic
    /// through the FULLY-TYPED peers
    /// ([`crate::git::max_released_version_typed`] and
    /// [`crate::version::next_free_version_all_typed`]), never the
    /// stringly wrappers ([`crate::git::max_released_version`] /
    /// [`crate::version::next_free_version`]) that render/re-parse a
    /// `SemverTriple` across the boundary — three parse/render round-
    /// trips per invocation on the pathological path — even though
    /// the loop body itself never needs a string layer.
    ///
    /// Sibling of the six typed-peer lifts on the version.rs surface
    /// (b68778b next_free_version_typed → next_free_version_all_typed,
    /// b3527d3 max_released_version → max_released_version_typed,
    /// c8bcdd5 bump_seed → bump_seed_typed, eec7dbe bump_semver_typed
    /// → SemverTriple::bumped, 85f9b3d parse_semver →
    /// parse_semver_typed, c96c115 next_free_version →
    /// next_free_version_typed): closes the last stringly caller in
    /// the release-arithmetic surface at the exact call site that
    /// used to redeem a `SemverTriple → String → SemverTriple`
    /// round-trip at every seeding decision.
    ///
    /// Fail-before-pass-after: with the pre-lift stringly bodies
    /// (`crate::git::max_released_version("v", Some(dir))` /
    /// `version::next_free_version(&old_version, level, &max_released,
    /// &tag_exists)`) restored, the four `contains` / `!contains`
    /// assertions below fire. Restoring the fully-typed routing
    /// returns the shield to green.
    ///
    /// The scan bounds cover only [`super::bump`]'s body (from its
    /// signature to the first `\n}\n` after its opening brace), so
    /// this shield's own docstring — which names the forbidden
    /// stringly forms verbatim — is out of scope. The stringly
    /// wrappers themselves remain callable for other callers (an
    /// FFI boundary that already speaks `&str`, a future consumer
    /// that reads from a `HashMap<String, ...>`); this shield only
    /// certifies that `bump`'s `seed_from_tags` arm — the ONE
    /// production caller in the crate — reaches the typed peers
    /// directly.
    ///
    /// THEORY.md §V.4 typed primitives: the seeding-decision arm at
    /// the last remaining stringly boundary in the release-
    /// arithmetic surface routes through the fully-typed peers
    /// end-to-end. THEORY.md §VI.1 one-oracle discipline: the
    /// seeding-and-collision loop still lives at ONE body
    /// (`next_free_version_all_typed`) that both this typed caller
    /// and the stringly wrappers delegate through, so the migration
    /// is a caller-side lift with no forked oracle.
    #[test]
    fn bump_seed_from_tags_routes_through_fully_typed_peers_not_stringly_boundary() {
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

        // Route every scan through [`crate::test_support::code_line_hits`]
        // so the shield's own inline `//` narration inside `bump`'s
        // body — which necessarily names the forbidden shapes verbatim
        // (`.unwrap_or(false)`, `tag_exists_in`, `max_released_version`,
        // `next_free_version`) as the traps this arm was lifted OFF —
        // does not false-match. Only executable code lines count.
        let hit = |needle: &str| crate::test_support::code_line_hits(body, needle);

        // The stringly wrappers must NOT appear in gem::bump's body.
        // `max_released_version(` matches only the stringly wrapper
        // because the typed peer spells `max_released_version_typed(`
        // — the `(` immediately after `_version` distinguishes them.
        // Same discipline on `next_free_version(` vs
        // `next_free_version_all_typed(`.
        assert!(
            hit("crate::git::max_released_version(").is_empty(),
            "gem::bump's seed_from_tags arm must NOT call the stringly \
             `crate::git::max_released_version` wrapper — the typed peer \
             `max_released_version_typed` returns `Option<SemverTriple>` \
             at the boundary and skips the render-to-string projection. \
             Got: {:?}",
            hit("crate::git::max_released_version(")
        );
        assert!(
            hit("version::next_free_version(").is_empty(),
            "gem::bump's seed_from_tags arm must NOT call the stringly \
             `version::next_free_version` wrapper — the typed peer \
             `next_free_version_all_typed` takes typed (`SemverTriple`, \
             `BumpLevel`, `Option<SemverTriple>`, typed predicate) all \
             the way through and skips the parse-render round-trips at \
             the boundary. Got: {:?}",
            hit("version::next_free_version(")
        );

        // The joint typed tag-scan primitive MUST appear in gem::bump's
        // body — the `git tag --list v*` fetch that yields BOTH derived
        // values (the numeric max for the seed, and the typed
        // `BTreeSet<SemverTriple>` for the collision predicate) from
        // ONE spawn. Pre-lift this arm fired TWO git spawns on the
        // fast path (max_released_version_typed + at least one
        // tag_exists_in), and up to `1 + 1024` on the pathological
        // path, plus swallowed each tag_exists_in error via
        // `.unwrap_or(false)` — the joint peer collapses the scan
        // AND removes the error-swallowing bridge in one lift.
        assert!(
            !hit("crate::git::released_semver_tags_typed(").is_empty(),
            "gem::bump's seed_from_tags arm must call \
             `crate::git::released_semver_tags_typed` — the joint typed \
             peer that reads the whole `<prefix>X.Y.Z` tag listing once \
             into a sorted `BTreeSet<SemverTriple>` and feeds both the \
             seed's `max` AND the collision predicate's `contains` off \
             that ONE fetch. Got body: {body:?}"
        );
        assert!(
            !hit("version::next_free_version_all_typed(").is_empty(),
            "gem::bump's seed_from_tags arm must call \
             `version::next_free_version_all_typed` — the fully-typed \
             peer that takes typed values end-to-end. Got body: {body:?}"
        );

        // The pre-lift per-iteration git spawn (tag_exists_in) MUST
        // NOT appear as executable code in the arm — the joint scan
        // renders the collision predicate as a pure `BTreeSet::contains`,
        // so a reintroduced tag_exists_in closure would re-open the
        // error-swallowing boundary that used to let a git failure
        // silently promote a real tag to "does not exist" and collide
        // the bump.
        assert!(
            hit("crate::git::tag_exists_in(").is_empty(),
            "gem::bump's seed_from_tags arm must NOT call \
             `crate::git::tag_exists_in` per iteration — the joint typed \
             peer `released_semver_tags_typed` reads the whole prefix \
             listing once and answers membership via `BTreeSet::contains`, \
             which is pure, allocation-free, and TOTAL. Got: {:?}",
            hit("crate::git::tag_exists_in(")
        );
        // The specific `.unwrap_or(false)` error-swallow bridge that
        // used to sit under the tag_exists_in closure must NOT
        // reappear as executable code — the joint peer's
        // `BTreeSet::contains` predicate is TOTAL, so a git failure
        // propagates at the ONE fetch site rather than being silently
        // redeemed at every loop iteration.
        assert!(
            hit(".unwrap_or(false)").is_empty(),
            "gem::bump's seed_from_tags arm must NOT swallow a fallible \
             tag-exists lookup via `.unwrap_or(false)` — the joint typed \
             peer's `BTreeSet::contains` predicate is TOTAL, so a git \
             failure propagates at the ONE fetch site rather than being \
             silently redeemed at every loop iteration. Got: {:?}",
            hit(".unwrap_or(false)")
        );
    }

    /// Regression-shield: [`super::bump`]'s function body MUST parse
    /// `--level` at ONE top-of-fn site
    /// (`let level_typed: version::BumpLevel = level.parse()?;`) and
    /// dispatch the fallback `None` (no `set_version`, no
    /// `seed_from_tags`) arm through the typed peer
    /// [`crate::version::bump_semver_typed`], NEVER through the stringly
    /// wrapper [`crate::version::bump_semver`] that re-parses the level
    /// grammar inside its own body.
    ///
    /// Sibling of [`crate::commands::tool::bump_level_typed_dispatch_tests`]
    /// (commit fa0c6d9) at the two-consumer `commands/tool.rs::bump`
    /// surface (Rust arm + Zig arm). Same discipline: parse at the
    /// boundary, thread the typed variant through every consumer, so a
    /// future grammar extension (a `Prerelease` variant strictly below
    /// [`crate::version::BumpLevel::Patch`], an `Epoch` ceiling strictly
    /// above [`crate::version::BumpLevel::Major`] for semver4 /
    /// `0ver`-style incompatible-by-design rewrites) is a compile error
    /// at every consumer the exhaustive match on the typed sum reaches,
    /// rather than a silent parse-error surface a stringly consumer
    /// would leave unchecked.
    ///
    /// Negative side: pins that `version::bump_semver(&` — the
    /// stringly-wrapper call form — does NOT appear as executable code
    /// inside [`super::bump`]'s body. Positive side: pins that (a)
    /// `version::bump_semver_typed(&` appears at EXACTLY one code line
    /// (the fallback `None => ...` arm — the seed_from_tags arm reaches
    /// its typed result through [`crate::version::next_free_version_all_typed`]
    /// on a different code path, so a regression that dropped this
    /// delegation cannot leave the negative scan trivially satisfied by
    /// absence), and (b) `let level_typed: version::BumpLevel = level.parse()?;`
    /// — the typed parse itself — appears at EXACTLY one code line
    /// (the top-of-fn boundary parse, before the manifest read and
    /// before the `match set_version` branch selection). Both scans
    /// route through [`crate::test_support::code_line_hits`] for
    /// anti-docstring-self-match discipline: the `//` narration above
    /// the boundary parse necessarily mentions the forbidden
    /// `version::bump_semver` wrapper by name as the trap the lift
    /// closes, and those `//` prefixes are skipped by construction.
    ///
    /// Fail-before-pass-after: restoring the pre-lift shape at the
    /// fallback arm (`None => version::bump_semver(&old_version, level)?`)
    /// fires the negative scan by naming the forbidden
    /// `version::bump_semver(&` needle on an executable line, and drops
    /// the positive `version::bump_semver_typed(&` count below the
    /// pinned one; restoring the typed routing returns both scans to
    /// green. Restoring the inner-arm `let level_typed: version::BumpLevel = ...`
    /// duplicate — the pre-lift seed_from_tags arm's own parse — pushes
    /// the parse count above one; hoisting it back to the top-of-fn
    /// boundary returns it to one.
    #[test]
    fn bump_routes_level_through_typed_peer_at_exactly_one_boundary_parse() {
        const SOURCE: &str = include_str!("gem.rs");

        let body = crate::test_support::fn_body_slice_between_markers(
            SOURCE,
            "commands/gem.rs",
            "pub fn bump(",
            "\npub fn build(",
        );

        let stringly_needle = "version::bump_semver(&";
        let stringly_hits = crate::test_support::code_line_hits(body, stringly_needle);
        assert!(
            stringly_hits.is_empty(),
            "commands/gem.rs::bump must NOT call the stringly \
             `version::bump_semver` wrapper on the fallback `None` arm — \
             the typed peer `version::bump_semver_typed` takes an \
             already-parsed `BumpLevel` and dispatches directly to the \
             const arithmetic on `SemverTriple::bumped`, so parsing \
             lives at ONE top-of-fn site rather than being re-derived \
             inside the wrapper per consumer. Hits: {stringly_hits:?}"
        );

        let typed_needle = "version::bump_semver_typed(&";
        let typed_hits = crate::test_support::code_line_hits(body, typed_needle);
        assert_eq!(
            typed_hits.len(),
            1,
            "commands/gem.rs::bump must call `{typed_needle}` at \
             EXACTLY one code line — the fallback `None` arm's \
             `version::bump_semver_typed(&old_version, level_typed)?` \
             — so a regression that dropped that delegation cannot \
             leave the negative `version::bump_semver(&` scan \
             trivially satisfied by absence, and a regression that \
             duplicated it into (say) an added third bump path is \
             caught the same way. The seed_from_tags arm reaches its \
             typed result through `version::next_free_version_all_typed` \
             (a separate code path pinned by the sibling shield above), \
             so this count is one, not two. Hits: {typed_hits:?}"
        );

        let parse_needle = "let level_typed: version::BumpLevel = level.parse()?;";
        let parse_hits = crate::test_support::code_line_hits(body, parse_needle);
        assert_eq!(
            parse_hits.len(),
            1,
            "commands/gem.rs::bump must parse `--level` at EXACTLY \
             one top-of-fn site (`{parse_needle}`) — the boundary \
             parse hoisted above the `match set_version` branch \
             selection. A regression that (a) dropped the boundary \
             parse would fire the positive `version::bump_semver_typed(&` \
             count above (the typed peer's second argument would no \
             longer type-check on the untyped `level: &str`), and (b) \
             duplicated it back inside the seed_from_tags arm — the \
             pre-lift shape — would fire this count above 1. Hits: \
             {parse_hits:?}"
        );
    }

    /// Whole-module shield: every `HOME` env-var read in
    /// `commands/gem.rs` routes through
    /// [`crate::repo::path_from_env`], never a hand-rolled inline
    /// `std::env::var("HOME").context("HOME not set")?` +
    /// `Path::new(&home).join(...)` stanza.
    ///
    /// Pre-lift `push` spelled the two-line stanza verbatim at TWO
    /// sites — the API-key file resolve
    /// (`Path::new(&home).join(".config/rubygems/api-key")`) and the
    /// credentials-dir resolve (`Path::new(&home).join(".gem")`). Both
    /// consumers now delegate to
    /// `crate::repo::path_from_env("HOME", "HOME not set")?.join(...)`,
    /// the shared primitive that owns the `env::var` read at ONE body
    /// across the crate (sibling of the SERVICE_DIR consumers landed
    /// at ab5a8db / e9e0c5b / d8e6626 / 1452f53).
    ///
    /// Scan bounds at the whole-module boundary via
    /// [`crate::test_support::module_body_before_first_cfg_test`] so
    /// this shield's docstring mentions of `env::var("HOME")` — living
    /// inside the `#[cfg(test)]` block below that first marker — stay
    /// out of scope. Every hit routes through
    /// [`crate::test_support::code_line_hits`] for anti-docstring-
    /// self-match discipline.
    #[test]
    fn test_gem_home_env_routes_through_path_from_env() {
        let body = crate::test_support::module_body_before_first_cfg_test(
            include_str!("gem.rs"),
            "commands/gem.rs",
        );
        // Negative side: the raw `env::var("HOME")` needle must NOT
        // appear anywhere in the module body post-lift — every read
        // routes through `crate::repo::path_from_env`. Substring match
        // catches both `std::env::var("HOME")` and `env::var("HOME")`.
        let raw_env_needle = "env::var(\"HOME\")";
        let env_hits = crate::test_support::code_line_hits(body, raw_env_needle);
        assert!(
            env_hits.is_empty(),
            "commands/gem.rs must NOT spell `{raw_env_needle}` inline \
             in the module body — every consumer must route through \
             `crate::repo::path_from_env`. Found {} code-line hit(s): \
             {env_hits:#?}",
            env_hits.len()
        );
        // Positive side: the delegating call to
        // `crate::repo::path_from_env("HOME"` must appear at EXACTLY
        // TWO code lines — the two `push` consumer sites. A regression
        // that dropped either delegation leaves the negative scan
        // trivially satisfied by absence.
        let delegate_needle = "crate::repo::path_from_env(\"HOME\"";
        let delegate_hits = crate::test_support::code_line_hits(body, delegate_needle);
        assert_eq!(
            delegate_hits.len(),
            2,
            "commands/gem.rs must delegate `HOME` resolution to \
             `crate::repo::path_from_env(\"HOME\", ...)` at EXACTLY \
             two code lines — the two `push` consumer sites (API-key \
             file resolve and credentials-dir resolve). Found {} \
             code-line hit(s): {delegate_hits:#?}",
            delegate_hits.len()
        );
        // Wording-preservation side: the canonical miss wording
        // `"HOME not set"` must stay grep-visible at both delegating
        // call sites so a future refactor that reshaped the wording
        // cannot silently drift the message the operator has been
        // coached to grep for.
        let wording_needle = "\"HOME not set\"";
        let wording_hits = crate::test_support::code_line_hits(body, wording_needle);
        assert_eq!(
            wording_hits.len(),
            2,
            "commands/gem.rs must spell the canonical miss wording \
             `{wording_needle}` at EXACTLY two code lines — one per \
             delegating call's second argument. Found {} code-line \
             hit(s): {wording_hits:#?}",
            wording_hits.len()
        );
    }
}
