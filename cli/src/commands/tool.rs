//! Tool release lifecycle commands
//!
//! Provides release, bump, check, and regenerate operations for
//! standalone tool repos (Rust and Zig).
//! Replaces substrate's release-helpers.nix and rust-tool-release.nix.

use anyhow::{bail, Context, Result};
use std::path::Path;
use std::process::Command;
use tracing::{info, warn};

use crate::git;
use crate::nix::{build_flake_attr_in, run_nix_build_typed};
use crate::repo::get_tool_path;
use crate::store_path::StorePath;
use crate::version;

/// Resolve the `cargo` binary via the `CARGO` env override, falling
/// back to PATH. Every `cargo` spawn in this module reads through this
/// sigil so the resolve happens in exactly one place — mirrors the
/// `cargo_bin()` sigil at `commands/test_ci.rs:28` (916f1a4),
/// `commands/prerelease.rs:109` (79e03a5),
/// `commands/developer_tools.rs:36` (534ef48), and
/// `commands/e2e.rs:87` (170ecac), and the sibling `bun_bin()` /
/// `crossplane_bin()` / `cosign_bin()` / `jsonnet_bin()` sigil
/// discipline on other command modules (9986f11 / 6b3ac16 / a070a3c /
/// a826ac0). Solve-once at the sigil (THEORY §I.5 — duplication budget
/// zero; every recurring shape becomes a helper before it becomes
/// duplicated code) means a future added `cargo` spawn cannot silently
/// re-copy the two-argument resolve and drift away from the `CARGO`
/// override at exactly the tier the hermetic-runner contract binds.
/// Pre-lift the four consumer sites (`bump`'s `cargo set-version
/// --bump <level>`, `check`'s `cargo fmt --check` + `cargo test`,
/// `lock`'s `cargo test --quiet`, and `run_clippy`'s `cargo clippy --
/// -D warnings`) each spelled the two-argument resolve verbatim.
fn cargo_bin() -> String {
    get_tool_path("CARGO", "cargo")
}

/// Resolve the `crate2nix` binary via the `CRATE2NIX` env override,
/// falling back to `crate2nix` on PATH. Every `crate2nix` spawn AND
/// every `which::which(&crate2nix)` probe in this module reads through
/// this sigil so the resolve happens in exactly one place — mirrors
/// the sibling `cargo_bin()` sigil above and the `<tool>_bin()` sigil
/// discipline every substrate-`<TOOL>` / `<TOOL>_BIN`-routed spawn
/// surface in forge with more than one consumer site honors
/// (`commands/test_ci.rs:28` per 916f1a4, `commands/prerelease.rs:109`
/// per 79e03a5, `commands/developer_tools.rs:36` per 534ef48,
/// `commands/e2e.rs:87` per 170ecac, the `bun_bin()` sibling on
/// `commands/frontend_validation.rs` per 9986f11, and the `nix_bin()`
/// sibling on `commands/rust_service.rs` per 63d4fe7). Solve-once at
/// the sigil (THEORY §I.5 — duplication budget zero; every recurring
/// shape becomes a helper before it becomes duplicated code) means a
/// future added `crate2nix` spawn cannot silently re-copy the two-
/// argument resolve and drift away from the `CRATE2NIX` override at
/// exactly the tier the hermetic-runner contract binds.
///
/// Pre-lift the two consumer sites — `bump`'s optional Cargo.nix
/// regeneration (both the `which::which` probe and the subsequent
/// `Command::new` spawn) and `regenerate`'s explicit `crate2nix
/// generate` invocation (via `run_cmd`) — each spelled the two-
/// argument resolve verbatim. A Nix-hermetic runner exporting
/// `CRATE2NIX=/nix/store/…/bin/crate2nix` while omitting `crate2nix`
/// from PATH would previously make each consumer re-derive the same
/// two-argument resolve independently, so a future edit to the
/// override contract (say, switching to a derived `CRATE2NIX_BIN`
/// spelling) would have to touch each site rather than one. The
/// probe-and-spawn pair inside `bump` now share the same resolved
/// path by construction: no risk of the probe passing against one
/// binary and the spawn racing against another.
fn crate2nix_bin() -> String {
    get_tool_path("CRATE2NIX", "crate2nix")
}

/// Release a tool: read version, verify clean tree, build targets, tag, push, create GitHub release.
pub async fn release(
    name: &str,
    repo: &str,
    language: &str,
    working_dir: &str,
    dry_run: bool,
) -> Result<()> {
    let dir = Path::new(working_dir);
    if !dir.exists() {
        bail!("Working directory not found: {}", working_dir);
    }

    // 1. Read version from the appropriate manifest
    let ver = read_version_for_language(dir, language)?;
    let tag = format!("v{}", ver);
    info!("{} version: {} (tag: {})", name, ver, tag);

    // 2. Verify clean working tree
    if !git::is_working_tree_clean()? {
        bail!("Working tree is dirty — commit or stash changes before releasing");
    }

    // 3. Check tag doesn't already exist
    if git::tag_exists(&tag)? {
        bail!("Tag {} already exists — bump the version first", tag);
    }

    // 4. Build targets
    let targets = [
        "x86_64-linux",
        "aarch64-linux",
        "x86_64-darwin",
        "aarch64-darwin",
    ];

    let tmp = tempfile::tempdir().context("Failed to create temp directory")?;
    let mut artifacts: Vec<String> = Vec::new();

    for target in &targets {
        let flake_attr = format!(".#{}-{}", name, target);
        info!("Building {}...", flake_attr);

        // Sub-flake build under the working directory routed through the
        // canonical [`build_flake_attr_in`] primitive — typed
        // `NixBuildError` discrimination, structured `(exit_code, stderr)`
        // extraction. Recoverable across the anyhow boundary via
        // `err.downcast_ref::<NixBuildError>()`.
        let store_path = build_flake_attr_in(&flake_attr, Some(dir))
            .await?
            .store_path;

        // Copy binary to temp dir with descriptive name
        let binary_name = format!("{}-{}", name, target);
        let dest = tmp.path().join(&binary_name);
        let src = <StorePath as AsRef<Path>>::as_ref(&store_path)
            .join("bin")
            .join(name);

        if src.exists() {
            std::fs::copy(&src, &dest)
                .with_context(|| format!("Failed to copy binary for {}", target))?;
            artifacts.push(dest.to_string_lossy().to_string());
            info!("  Collected: {}", binary_name);
        } else {
            // Some builds produce the binary directly at the store path
            std::fs::copy(&store_path, &dest)
                .with_context(|| format!("Failed to copy artifact for {}", target))?;
            artifacts.push(dest.to_string_lossy().to_string());
            info!("  Collected: {}", binary_name);
        }
    }

    // 5. Dry run check
    if dry_run {
        info!(
            "Dry run — would create tag {} and GitHub release with {} artifacts",
            tag,
            artifacts.len()
        );
        for a in &artifacts {
            info!("  {}", a);
        }
        return Ok(());
    }

    // 6. Create and push tag
    info!("Creating tag {}...", tag);
    git::create_tag(&tag, &format!("Release {} {}", name, ver))?;
    git::push_tag(&tag)?;
    info!("Tag {} pushed", tag);

    // 7. Create GitHub release with artifacts
    info!("Creating GitHub release...");
    let mut gh_args = vec![
        "release".to_string(),
        "create".to_string(),
        tag.clone(),
        "--repo".to_string(),
        repo.to_string(),
        "--title".to_string(),
        format!("{} {}", name, ver),
        "--generate-notes".to_string(),
    ];

    for artifact in &artifacts {
        gh_args.push(artifact.clone());
    }

    let gh_bin = get_tool_path("GH_BIN", "gh");
    let gh_status = Command::new(&gh_bin)
        .args(&gh_args)
        .current_dir(dir)
        .status()
        .context("Failed to run gh release create")?;

    if !gh_status.success() {
        bail!("GitHub release creation failed for {}", tag);
    }

    info!(
        "Released {} {} with {} artifacts",
        name,
        ver,
        artifacts.len()
    );
    Ok(())
}

/// Bump the version for a tool.
pub fn bump(name: &str, language: &str, level: &str, working_dir: &str) -> Result<()> {
    let dir = Path::new(working_dir);
    if !dir.exists() {
        bail!("Working directory not found: {}", working_dir);
    }

    match language {
        "rust" => {
            // Use cargo set-version for Rust
            let cargo = cargo_bin();
            let status = Command::new(&cargo)
                .args(["set-version", "--bump", level])
                .current_dir(dir)
                .status()
                .context("Failed to run cargo set-version (is cargo-edit installed?)")?;

            if !status.success() {
                bail!("cargo set-version --bump {} failed", level);
            }

            // Regenerate Cargo.nix if crate2nix is available.
            //
            // Probe the substrate-resolved `CRATE2NIX` sigil (not the bare
            // literal): a Nix-hermetic runner may export
            // `CRATE2NIX=/nix/store/…/bin/crate2nix` while omitting
            // `crate2nix` from PATH. `which::which` accepts absolute paths
            // and checks executability, so a single sigil-form probe
            // covers both the substrate-exported path and the PATH-fallback.
            let crate2nix = crate2nix_bin();
            if which::which(&crate2nix).is_ok() {
                info!("Regenerating Cargo.nix...");
                let status = Command::new(&crate2nix)
                    .args(["generate"])
                    .current_dir(dir)
                    .status()
                    .context("Failed to run crate2nix generate")?;

                if !status.success() {
                    bail!("crate2nix generate failed");
                }
            }

            let new_ver = version::read_cargo_version(&dir.join("Cargo.toml"))?;
            info!("{}: bumped to {} ({})", name, new_ver, level);
        }
        "zig" => {
            let zon_path = dir.join("build.zig.zon");
            let old_ver = version::read_zig_version(&zon_path)?;
            let new_ver = version::bump_semver(&old_ver, level)?;
            version::write_zig_version(&zon_path, &new_ver)?;
            info!("{}: {} → {} ({})", name, old_ver, new_ver, level);
        }
        _ => bail!("Unsupported language '{}' — use rust or zig", language),
    }

    Ok(())
}

/// Run checks for a tool (format, lint, test).
pub fn check(name: &str, language: &str, working_dir: &str) -> Result<()> {
    let dir = Path::new(working_dir);
    if !dir.exists() {
        bail!("Working directory not found: {}", working_dir);
    }

    match language {
        "rust" => {
            let cargo = cargo_bin();
            info!("{}: running cargo fmt --check...", name);
            run_cmd(dir, &cargo, &["fmt", "--check"])?;

            info!("{}: running cargo clippy...", name);
            // Held in a binding: dropping the TempDir deletes the clippy.toml
            // inside it, so it must outlive the clippy process.
            let clippy_conf = provide_clippy_conf(dir);
            run_clippy(dir, clippy_conf.as_ref().map(tempfile::TempDir::path))?;

            info!("{}: running cargo test...", name);
            run_cmd(dir, &cargo, &["test"])?;

            info!("{}: all checks passed", name);
        }
        "zig" => {
            info!("{}: running zig build...", name);
            run_cmd(dir, "zig", &["build"])?;

            info!("{}: running zig build test...", name);
            run_cmd(dir, "zig", &["build", "test"])?;

            info!("{}: all checks passed", name);
        }
        _ => bail!("Unsupported language '{}' — use rust or zig", language),
    }

    Ok(())
}

/// Regenerate lockfiles / build metadata.
pub fn regenerate(language: &str, working_dir: &str) -> Result<()> {
    let dir = Path::new(working_dir);
    if !dir.exists() {
        bail!("Working directory not found: {}", working_dir);
    }

    match language {
        "rust" => {
            let crate2nix = crate2nix_bin();
            info!("Running crate2nix generate...");
            run_cmd(dir, &crate2nix, &["generate"])?;
            info!("Cargo.nix regenerated");
        }
        "zig" => {
            info!("No regeneration needed for Zig");
        }
        _ => bail!("Unsupported language '{}' — use rust or zig", language),
    }

    Ok(())
}

// --- Helpers ---

fn read_version_for_language(dir: &Path, language: &str) -> Result<String> {
    match language {
        "rust" => version::read_cargo_version(&dir.join("Cargo.toml")),
        "zig" => version::read_zig_version(&dir.join("build.zig.zon")),
        _ => bail!("Unsupported language '{}' — use rust or zig", language),
    }
}

/// Lock platform — build, test, and write a JSON lock certifying this platform.
///
/// The lock file at `locks/<platform>.json` proves that the tool at a specific
/// git rev successfully built and tested on this platform. Commit the lock files
/// to expand the confirmed compatibility matrix.
pub async fn lock(name: &str, language: &str, platform: &str, working_dir: &str) -> Result<()> {
    let dir = Path::new(working_dir);
    if !dir.exists() {
        bail!("Working directory not found: {}", working_dir);
    }

    let rev = git::get_full_sha().unwrap_or_else(|_| "unknown".to_string());
    let date = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

    info!("=== Locking {} for {} ===", platform, name);

    // Step 1: Build via nix
    // Use --impure for builds requiring system tools (e.g. Xcode for Ghostty)
    info!("[1/3] Building...");
    let store_path = build_lock_target(dir, platform).await?;
    info!("  -> {}", store_path);

    // Step 2: Run tests (language-specific; "nix" = build-only, no test runner)
    info!("[2/3] Testing...");
    let test_result = match language {
        "rust" => {
            let cargo = cargo_bin();
            run_cmd(dir, &cargo, &["test", "--quiet"])?;
            "pass"
        }
        "zig" => {
            run_cmd(dir, "zig", &["build", "test"])?;
            "pass"
        }
        "nix" => {
            info!("  (nix-only build — test phase is the nix build itself)");
            "build-only"
        }
        other => {
            info!("  (no test runner for {other})");
            "skipped"
        }
    };
    info!("  -> {}", test_result);

    // Step 3: Write lock file
    info!("[3/3] Writing lock...");
    let lock_dir = dir.join("locks");
    std::fs::create_dir_all(&lock_dir)
        .with_context(|| format!("Failed to create locks directory: {}", lock_dir.display()))?;

    let lock_path = lock_dir.join(format!("{}.json", platform));
    let lock_content = serde_json::json!({
        "tool": name,
        "platform": platform,
        "rev": rev,
        "date": date,
        "store_path": store_path.as_str(),
        "tests": test_result,
    });

    std::fs::write(&lock_path, serde_json::to_string_pretty(&lock_content)?)
        .with_context(|| format!("Failed to write lock file: {}", lock_path.display()))?;

    info!("=== {} locked ===", platform);
    info!("{}", serde_json::to_string_pretty(&lock_content)?);

    Ok(())
}

/// Build the flake at `dir` (with `--impure` for sub-flakes that need
/// system tools — Ghostty needs Xcode, etc.) and return the validated
/// store path.
///
/// Routes through [`run_nix_build_typed`] at the nix-frontier so this
/// site inherits four load-bearing properties the pre-lift raw-`Command::
/// new("nix")` stanza dropped:
///
/// 1. **`NIX_BIN` env override.** Pre-lift the site spelled
///    `Command::new("nix")`, ignoring the env var every other nix-
///    invocation site in forge honors via `get_tool_path("NIX_BIN",
///    "nix")` — a Nix-hermetic runner with a store-path `nix` binary
///    silently fell through to whatever `nix` happened to be first on
///    `PATH` at this site specifically.
/// 2. **Typed error dispatch.** Pre-lift a spawn failure went through
///    `.context("nix build failed to execute")?` (fatal anyhow chain
///    with no typed variant to pattern-match on); a non-zero exit
///    collapsed into `bail!("nix build failed on {}: {}", platform,
///    stderr.trim())` — a fused stringly bag that dropped the exit
///    code and forced downstream telemetry to re-parse the message.
///    Post-lift both surface as typed [`crate::error::NixBuildError`]
///    variants (`ExecFailed { flake_attr = platform, .. }` and
///    `BuildFailed { flake_attr = platform, exit_code, stderr }`)
///    recoverable across the anyhow boundary via
///    `err.downcast_ref::<NixBuildError>()`.
/// 3. **Store-path grammar oracle at the nix-frontier.** Pre-lift the
///    trimmed stdout flowed unchecked into the lock-file's
///    `store_path` JSON field via `String::from_utf8_lossy(&stdout)
///    .trim().to_string()`, so a malformed nix echo (a `/nix/store/…`
///    with a subpath, an `unknown-*` sentinel, a nix-daemon error
///    string that happened to escape onto stdout) would silently
///    persist as the "canonical" store path for `<tool>/<platform>`.
///    A future consumer reading `locks/<platform>.json` to substitute
///    the closure would then hit a cryptic remote-substituter error
///    rather than a legible grammar-violation diagnostic. Post-lift
///    [`StorePath::parse`] at the frontier rejects any such value as
///    `NixBuildError::MalformedStorePath { raw, source }`, carrying
///    the raw stdout and the exact [`crate::store_path::StorePathError`]
///    grammar clause under `#[source]`.
/// 4. **`classify_capture_query` spawn/exit unification.** The trim +
///    UTF-8-lossy decode of a successful stdout lives at ONE
///    construction surface inside the typed primitive rather than
///    being re-derived at this call site.
///
/// `platform` is the human-readable label attached to any returned
/// [`crate::error::NixBuildError`] — the same value the lock-file's
/// `platform` field holds — so a failure record carries the offending
/// platform by construction. Sibling of `nix_hooks::build_and_get_path`
/// and `nix::path_info_recursive`: the canonical shape for lifting a
/// `Command::new("nix")` command-module site onto the typed frontier
/// primitive.
async fn build_lock_target(dir: &Path, platform: &str) -> Result<StorePath> {
    let nix_bin = get_tool_path("NIX_BIN", "nix");
    build_lock_target_with_bin(&nix_bin, dir, platform).await
}

/// Test-injection sibling of [`build_lock_target`]: accepts the resolved
/// `nix_bin` as an explicit argument so unit tests can point at a
/// hermetic [`crate::test_support::make_executable_shim`] fixture
/// without mutating the process-wide `NIX_BIN` environment variable.
/// Same discipline as
/// [`crate::nix_hooks::NixHooks::build_and_get_path_with_bin`],
/// `nix::path_info_recursive_with_bin`, and
/// `AtticClient::with_attic_bin`. Splitting resolution from execution
/// keeps the test surface hermetic AND parallel-safe:
/// `#[tokio::test]` on this module can run concurrent tests without
/// racing on env-var writes.
async fn build_lock_target_with_bin(
    nix_bin: &str,
    dir: &Path,
    platform: &str,
) -> Result<StorePath> {
    run_nix_build_typed(
        nix_bin,
        &["build", "--print-out-paths", "--impure"],
        platform,
        Some(dir),
    )
    .await
    .with_context(|| format!("nix build failed on {}", platform))
}

/// The fleet's canonical `clippy.toml` payload, embedded so that `forge tool
/// check` enforces ★★ TYPED EMISSION even for repos whose build path never
/// hands clippy a configuration.
///
/// Mirrors `substrate/lib/build/rust/format-ban.clippy.toml`. substrate
/// delivers that file via `CLIPPY_CONF_DIR` on the *library* flake path
/// (`lib/build/rust/library.nix` -> `mkCargoReleaseApps { formatBan = true; }`),
/// which reaches 16 flakes. The *workspace* path routes its `check-all`
/// through `release-helpers.nix` into this command instead, and arrived here
/// with no configuration at all — so the ban silently checked nothing.
///
/// ## The `disallowed-macros` line MUST stay on ONE line
///
/// A TOML inline table cannot span lines, and clippy does not skip a
/// configuration it cannot parse — it **aborts the compile** (exit 101). A
/// malformed payload here would therefore break every consuming build rather
/// than guard it. `embedded_fleet_clippy_toml_parses_and_bans_std_format` is
/// the gate that keeps this honest; do not reformat this constant without
/// keeping it green.
const FLEET_CLIPPY_TOML: &str = r#"# pleme-io typed-emission enforcement — supplied by `forge tool check`.
#
# Canonical: https://github.com/pleme-io/theory/blob/main/TYPED-EMISSION.md
# Mirrors:   substrate/lib/build/rust/format-ban.clippy.toml
#
# `format!()` is banned across pleme-io Rust crates. Use:
#   - `write!()` / `writeln!()` inside `Display`/`Debug`/`Serialize` impls
#   - typed logging macros (`tracing::*`)
#   - typed error macros (`anyhow::anyhow!()` / `anyhow::bail!()`)
#   - typed AST renderers / value builders
#
# MUST STAY ON ONE LINE — see FLEET_CLIPPY_TOML's doc comment in
# forge/cli/src/commands/tool.rs. A multi-line inline table is invalid TOML and
# makes clippy abort the compile instead of linting.
disallowed-macros = [{ path = "std::format", reason = "format!() is banned per pleme-io/theory/TYPED-EMISSION.md. Use write!() inside Display/Debug impls, tracing::* for logs, anyhow::anyhow!()/bail!() for errors, or a typed AST renderer. Free-form string composition is a substrate gap; close it." }]
"#;

/// Decide what configuration directory clippy should read for `dir`.
///
/// Returns the temp directory holding the fleet default when forge supplied
/// one — the caller MUST keep it alive across the clippy run. `None` means
/// "inject nothing", which happens in three cases, each deliberate:
///
/// 1. **The caller already chose one.** An inherited `CLIPPY_CONF_DIR` wins
///    outright. This is the de-coupling seam: substrate (or any caller) can
///    point at its own canonical file without forge changing.
/// 2. **The repo carries its own.** Mirrors clippy's own upward search, so a
///    repo-local `clippy.toml` keeps its authority instead of being shadowed
///    by ours — including repos that deliberately configure extra lints.
/// 3. **Materializing ours failed.** Then clippy still runs, unconfigured.
///    A lint that cannot be delivered must not become a build failure.
fn provide_clippy_conf(dir: &Path) -> Option<tempfile::TempDir> {
    if std::env::var_os("CLIPPY_CONF_DIR").is_some() {
        info!("clippy: honoring inherited CLIPPY_CONF_DIR");
        return None;
    }

    if repo_supplies_clippy_conf(dir) {
        info!("clippy: using the repo's own clippy.toml");
        return None;
    }

    match write_fleet_clippy_conf() {
        Ok(conf) => Some(conf),
        Err(e) => {
            // Deliberately not fatal — see case 3 above.
            warn!("clippy: could not supply the fleet clippy.toml ({e:#}); running unconfigured");
            None
        }
    }
}

/// Whether clippy would find a configuration on its own, starting at `dir`.
///
/// Mirrors clippy's `lookup_conf_file`: start at the directory and walk up
/// through every ancestor, accepting either spelling.
fn repo_supplies_clippy_conf(dir: &Path) -> bool {
    let start = dir.canonicalize().unwrap_or_else(|_| dir.to_path_buf());
    start
        .ancestors()
        .any(|dir| dir.join("clippy.toml").is_file() || dir.join(".clippy.toml").is_file())
}

/// Materialize [`FLEET_CLIPPY_TOML`] into a fresh temp directory.
///
/// Writing it fresh each run is what satisfies the "known-good at the point of
/// use" requirement: the payload is a compile-time constant that a test parses,
/// so it can be neither absent nor stale nor edited out from under us.
fn write_fleet_clippy_conf() -> Result<tempfile::TempDir> {
    let conf = tempfile::tempdir().context("Failed to create a temp dir for clippy config")?;
    std::fs::write(conf.path().join("clippy.toml"), FLEET_CLIPPY_TOML)
        .context("Failed to write the fleet clippy.toml")?;
    Ok(conf)
}

/// Run `cargo clippy -- -D warnings`, optionally pointing it at `conf_dir`.
fn run_clippy(dir: &Path, conf_dir: Option<&Path>) -> Result<()> {
    let cargo = cargo_bin();
    let mut cmd = Command::new(&cargo);
    cmd.args(["clippy", "--", "-D", "warnings"])
        .current_dir(dir);

    if let Some(conf_dir) = conf_dir {
        cmd.env("CLIPPY_CONF_DIR", conf_dir);
    }

    let status = cmd.status().context("Failed to run cargo clippy")?;
    if !status.success() {
        bail!("cargo clippy -- -D warnings failed");
    }

    Ok(())
}

fn run_cmd(dir: &Path, program: &str, args: &[&str]) -> Result<()> {
    let status = Command::new(program)
        .args(args)
        .current_dir(dir)
        .status()
        .with_context(|| format!("Failed to run {} {}", program, args.join(" ")))?;

    if !status.success() {
        bail!("{} {} failed", program, args.join(" "));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ★★ The load-bearing gate.
    ///
    /// clippy does not skip a configuration it cannot parse — it aborts the
    /// compile (exit 101). Since `forge tool check` now hands this payload to
    /// every Rust repo that has no `clippy.toml` of its own, a malformed
    /// constant would break those builds instead of guarding them. This test
    /// is what makes "known-good at the point of use" true rather than hoped.
    #[test]
    fn embedded_fleet_clippy_toml_parses_and_bans_std_format() {
        let parsed: toml::Value =
            toml::from_str(FLEET_CLIPPY_TOML).expect("FLEET_CLIPPY_TOML must be valid TOML");

        let banned = parsed
            .get("disallowed-macros")
            .expect("must set the hyphenated `disallowed-macros` key")
            .as_array()
            .expect("`disallowed-macros` must be an array");

        assert!(
            banned.iter().any(|entry| {
                entry.get("path").and_then(toml::Value::as_str) == Some("std::format")
            }),
            "the fleet config must ban std::format"
        );
    }

    /// The underscore spelling is a hard clippy error, not a silent no-op.
    #[test]
    fn embedded_fleet_clippy_toml_uses_the_hyphenated_key() {
        assert!(FLEET_CLIPPY_TOML.contains("disallowed-macros"));
        assert!(
            !FLEET_CLIPPY_TOML.contains("disallowed_macros"),
            "the underscore spelling makes clippy abort the compile"
        );
    }

    /// A TOML inline table cannot span lines; keeping the entry on one line is
    /// the difference between a lint and a broken build.
    #[test]
    fn embedded_fleet_clippy_toml_keeps_the_inline_table_on_one_line() {
        let entry = FLEET_CLIPPY_TOML
            .lines()
            .find(|line| line.starts_with("disallowed-macros"))
            .expect("the ban entry must start a line of its own");

        assert!(
            entry.trim_end().ends_with(']'),
            "the inline table must open and close on one line, got: {entry}"
        );
    }

    /// What actually reaches disk must parse, not just the constant.
    #[test]
    fn written_fleet_clippy_conf_lands_a_parseable_file() {
        let conf = write_fleet_clippy_conf().expect("should materialize");
        let written =
            std::fs::read_to_string(conf.path().join("clippy.toml")).expect("should be readable");

        toml::from_str::<toml::Value>(&written).expect("the written file must be valid TOML");
        assert_eq!(written, FLEET_CLIPPY_TOML);
    }

    #[test]
    fn repo_supplies_clippy_conf_is_false_for_a_bare_dir() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(!repo_supplies_clippy_conf(dir.path()));
    }

    #[test]
    fn repo_supplies_clippy_conf_finds_a_file_in_the_dir_itself() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("clippy.toml"), "").expect("write");
        assert!(repo_supplies_clippy_conf(dir.path()));
    }

    #[test]
    fn repo_supplies_clippy_conf_accepts_the_dotted_spelling() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join(".clippy.toml"), "").expect("write");
        assert!(repo_supplies_clippy_conf(dir.path()));
    }

    /// Mirrors clippy's upward search, so a workspace member inherits the
    /// repo-root config rather than being handed ours.
    #[test]
    fn repo_supplies_clippy_conf_walks_up_to_an_ancestor() {
        let root = tempfile::tempdir().expect("tempdir");
        let member = root.path().join("crates").join("member");
        std::fs::create_dir_all(&member).expect("mkdir");
        std::fs::write(root.path().join("clippy.toml"), "").expect("write");

        assert!(repo_supplies_clippy_conf(&member));
    }

    /// Repo-local authority wins: we must not shadow a config clippy would
    /// have found on its own.
    #[test]
    fn provide_clippy_conf_defers_to_a_repo_local_config() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("clippy.toml"), "").expect("write");

        assert!(
            provide_clippy_conf(dir.path()).is_none(),
            "a repo carrying its own clippy.toml must keep it"
        );
    }

    // --- build_lock_target_with_bin: fail-before-pass-after tests for the
    // ---   nix-frontier lift on `commands/tool.rs::lock`'s build phase.

    use crate::error::NixBuildError;
    use crate::test_support::make_executable_shim;
    use std::error::Error as _;

    /// A `nix build` that exits non-zero must surface as
    /// [`NixBuildError::BuildFailed`] carrying `flake_attr = platform`,
    /// the exit code, and the captured stderr — recoverable across the
    /// anyhow boundary via `err.downcast_ref::<NixBuildError>()`.
    /// Pre-migration the raw stanza collapsed into
    /// `bail!("nix build failed on {}: {}", platform, stderr.trim())`
    /// — a fused stringly bag with no typed variant, so a downstream
    /// telemetry consumer had to re-parse the message to reach the
    /// exit code and platform. Fails-before-passes-after: the pre-
    /// migration `bail!` chain contained no `NixBuildError` in its
    /// `source()` walk, so the typed-record downcast returned `None`.
    #[tokio::test]
    async fn test_build_lock_target_with_bin_surfaces_build_failed_typed_variant() {
        let (_shim_dir, shim) = make_executable_shim(
            "nix",
            "#!/bin/sh\necho 'attr default missing' 1>&2\nexit 5\n",
        );
        let work = tempfile::tempdir().expect("work tempdir");
        let err = build_lock_target_with_bin(&shim, work.path(), "x86_64-linux")
            .await
            .expect_err("non-zero exit must fail");

        // Outer anyhow context must carry the platform-labelled narrative.
        let chain = format!("{:?}", err);
        assert!(
            chain.contains("nix build failed on x86_64-linux"),
            "outer context must name the offending platform, got: {chain}"
        );

        // Typed variant must be recoverable via the anyhow source walk.
        let downcast = err
            .downcast_ref::<NixBuildError>()
            .expect("must carry a typed NixBuildError under anyhow");
        match downcast {
            NixBuildError::BuildFailed {
                flake_attr,
                exit_code,
                stderr,
            } => {
                assert_eq!(
                    flake_attr, "x86_64-linux",
                    "BuildFailed.flake_attr must carry the platform label"
                );
                assert_eq!(
                    *exit_code,
                    Some(5),
                    "BuildFailed.exit_code must be preserved"
                );
                assert!(
                    stderr.contains("attr default missing"),
                    "BuildFailed.stderr must capture nix stderr verbatim, got: {stderr:?}"
                );
            }
            other => panic!("expected BuildFailed, got: {other:?}"),
        }
    }

    /// A missing `nix` binary must surface as [`NixBuildError::ExecFailed`]
    /// carrying `flake_attr = platform` — pre-migration a spawn failure
    /// flowed through `.context("nix build failed to execute")?`, which
    /// dropped both the platform label and the typed spawn-vs-op split.
    /// Post-migration the typed variant is recoverable via
    /// `err.downcast_ref::<NixBuildError>()`. Uses an absolute path that
    /// does not exist so the test is hermetic and parallel-safe (no
    /// global PATH mutation).
    #[tokio::test]
    async fn test_build_lock_target_with_bin_surfaces_exec_failed_typed_variant() {
        let work = tempfile::tempdir().expect("work tempdir");
        let err = build_lock_target_with_bin(
            "/nonexistent/path/nix-binary-for-tool-lock-exec-failed-test",
            work.path(),
            "aarch64-darwin",
        )
        .await
        .expect_err("missing nix binary must fail");

        let chain = format!("{:?}", err);
        assert!(
            chain.contains("nix build failed on aarch64-darwin"),
            "outer context must name the offending platform, got: {chain}"
        );

        let downcast = err
            .downcast_ref::<NixBuildError>()
            .expect("must carry a typed NixBuildError under anyhow");
        match downcast {
            NixBuildError::ExecFailed { flake_attr, .. } => {
                assert_eq!(
                    flake_attr, "aarch64-darwin",
                    "ExecFailed.flake_attr must carry the platform label"
                );
            }
            other => panic!("expected ExecFailed, got: {other:?}"),
        }
    }

    /// A `nix build --print-out-paths` that exits zero and prints a
    /// non-empty stdout that does NOT parse through
    /// [`StorePath::parse`] must be rejected at the nix-frontier as
    /// [`NixBuildError::MalformedStorePath`]. Strict fail-before-pass-
    /// after: pre-migration the raw stanza did
    /// `String::from_utf8_lossy(&stdout).trim().to_string()` and returned
    /// `Ok(String_of_malformed_path)`, silently smuggling a non-store-path
    /// through the `store_path` field of `locks/<platform>.json` — a
    /// future consumer would then hit a cryptic remote-substituter error
    /// rather than a legible grammar diagnostic. Post-migration
    /// [`StorePath::parse`] catches the missing `/nix/store/` prefix,
    /// preserves the raw stdout in `.raw`, and exposes the exact
    /// [`crate::store_path::StorePathError`] grammar clause under
    /// `#[source]` so a downstream telemetry walker reaches the
    /// rejection site without parsing the display string.
    #[tokio::test]
    async fn test_build_lock_target_with_bin_surfaces_malformed_store_path_typed_variant() {
        use crate::store_path::StorePathError;
        let (_shim_dir, shim) = make_executable_shim(
            "nix",
            "#!/bin/sh\necho '/nix/store/not-a-real-store-path'\nexit 0\n",
        );
        let work = tempfile::tempdir().expect("work tempdir");
        let err = build_lock_target_with_bin(&shim, work.path(), "x86_64-darwin")
            .await
            .expect_err("malformed store-path stdout must fail typed");

        let downcast = err
            .downcast_ref::<NixBuildError>()
            .expect("must carry a typed NixBuildError under anyhow");
        match downcast {
            NixBuildError::MalformedStorePath {
                flake_attr,
                raw,
                source,
            } => {
                assert_eq!(
                    flake_attr, "x86_64-darwin",
                    "MalformedStorePath.flake_attr must carry the platform label"
                );
                assert_eq!(
                    raw, "/nix/store/not-a-real-store-path",
                    "MalformedStorePath.raw must preserve the offending stdout verbatim"
                );
                assert!(
                    matches!(source, StorePathError::TooShort { .. }),
                    "expected TooShort grammar clause, got: {source:?}"
                );
            }
            other => panic!("expected MalformedStorePath, got: {other:?}"),
        }

        // The `#[source]` chain must expose the exact grammar clause so a
        // downstream telemetry consumer walking `Error::source` reaches
        // the rejection site without parsing the display string.
        let src = downcast
            .source()
            .expect("MalformedStorePath must carry a source");
        let clause = src
            .downcast_ref::<StorePathError>()
            .expect("source must downcast to StorePathError");
        assert!(matches!(clause, StorePathError::TooShort { .. }));
    }

    /// A `nix build --print-out-paths` that exits zero with empty stdout
    /// must surface as [`NixBuildError::EmptyStorePath`] carrying the
    /// platform label — pre-migration the raw stanza would return
    /// `Ok(String::new())`, writing an empty `store_path` field into
    /// `locks/<platform>.json` (a silent contract violation the frontier
    /// primitive now catches at the type level, distinct from `BuildFailed`
    /// so telemetry can tell "nix said no" from "nix contract violation").
    #[tokio::test]
    async fn test_build_lock_target_with_bin_surfaces_empty_store_path_typed_variant() {
        let (_shim_dir, shim) = make_executable_shim("nix", "#!/bin/sh\nexit 0\n");
        let work = tempfile::tempdir().expect("work tempdir");
        let err = build_lock_target_with_bin(&shim, work.path(), "aarch64-linux")
            .await
            .expect_err("empty stdout must fail typed");

        let downcast = err
            .downcast_ref::<NixBuildError>()
            .expect("must carry a typed NixBuildError under anyhow");
        match downcast {
            NixBuildError::EmptyStorePath { flake_attr } => {
                assert_eq!(
                    flake_attr, "aarch64-linux",
                    "EmptyStorePath.flake_attr must carry the platform label"
                );
            }
            other => panic!("expected EmptyStorePath, got: {other:?}"),
        }
    }

    /// Happy-path: a `nix build --print-out-paths` that exits zero and
    /// prints a well-formed store path must round-trip through the
    /// nix-frontier grammar oracle and reach the caller as a validated
    /// [`StorePath`] — the canonical accessor (`.as_str()`) returns the
    /// trimmed stdout verbatim, so the JSON payload that reads
    /// `store_path.as_str()` in [`lock`] serializes the same value the
    /// pre-migration raw-buffer path did (byte-for-byte).
    #[tokio::test]
    async fn test_build_lock_target_with_bin_success_returns_validated_store_path() {
        let (_shim_dir, shim) = make_executable_shim(
            "nix",
            "#!/bin/sh\necho '/nix/store/0123456789abcdfghijklmnpqrsvwxyz-mytool'\nexit 0\n",
        );
        let work = tempfile::tempdir().expect("work tempdir");
        let store_path = build_lock_target_with_bin(&shim, work.path(), "x86_64-linux")
            .await
            .expect("well-formed stdout must succeed");
        assert_eq!(
            store_path.as_str(),
            "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-mytool",
            "the canonical StorePath accessor must return the trimmed nix stdout verbatim"
        );
    }

    /// Whole-module shield: no `Command::new`-with-bare-`gh`-literal
    /// may live in `commands/tool.rs`. The sole `gh` spawn site —
    /// `release`'s `gh release create` step at the tag-and-publish
    /// tail of the tool-release pipeline — must resolve `GH_BIN` via
    /// [`crate::repo::get_tool_path`] first, the same substrate-
    /// exported env-override contract the sibling
    /// `infrastructure/registry.rs::try_gh_cli_token` GH_BIN lift
    /// already rides on.
    ///
    /// Pre-lift the site spelled the bare literal verbatim, ignoring
    /// `GH_BIN` at the site: a Nix-hermetic runner's substrate-derived
    /// `gh` path was lost to whatever `gh` sat first on PATH — the
    /// same silent-PATH-fallback bug class the sibling `NIX_BIN`
    /// lookup in this file's own `build_lock_target` already avoids,
    /// and the discipline the sibling `docker` / `kubectl` / `nix` /
    /// `git` / `helm` / `crossplane` / `flux` / `attic` / `redis-cli`
    /// / `doca` / `regctl` surfaces converged on across the prior
    /// claude-routine commits.
    ///
    /// This shield scans the module's own source via [`include_str!`]
    /// and forbids the fused literal shape. The forbidden shape is
    /// reconstructed via [`format!`] so this shield's own source text
    /// does not false-match itself — the whole-module scan therefore
    /// covers both the top-of-file production body AND every sibling
    /// `#[cfg(test)]` block. Also asserts the canonical two-argument
    /// `get_tool_path("GH_BIN", "gh")` lookup form is present in the
    /// module, so the sigil-body itself cannot silently drift away
    /// from the substrate-exported env-var contract. The end-to-end
    /// `GH_BIN`-routing invariant of the underlying primitive is
    /// pinned separately by `crate::repo::test_get_tool_path_with_env`;
    /// this shield only certifies that every `gh`-spawning site in
    /// this module resolves through the `get_tool_path` canonical
    /// lookup first.
    #[test]
    fn test_gh_spawn_routes_through_gh_bin_not_raw_literal() {
        const SOURCE: &str = include_str!("tool.rs");

        crate::test_support::assert_source_forbids_bare_spawn_shapes(
            SOURCE,
            "commands/tool.rs",
            "gh",
            "resolve the substrate-exported `GH_BIN` env override via `get_tool_path`",
        );
        crate::test_support::assert_source_has_get_tool_path_two_arg_call_code_line(
            SOURCE,
            "commands/tool.rs",
            "GH_BIN",
            "gh",
        );
    }

    /// Whole-module shield: no raw `Command::new("cargo")` may live in
    /// `commands/tool.rs`'s non-test body. Every `cargo` spawn in this
    /// module must first resolve `CARGO` via [`crate::repo::get_tool_path`]
    /// — the canonical env-var override idiom every sibling
    /// cargo-consuming surface honors (`commands/test_ci.rs` four cargo
    /// sites at e1677d3; `commands/developer_tools.rs` nine cargo sites
    /// at 8687093; `commands/comprehensive_release.rs` two cargo sites
    /// at f95d541; `commands/prerelease.rs` seven cargo sites at
    /// cfdba0d).
    ///
    /// Pre-lift the three consumer sites — `bump`'s `cargo set-version
    /// --bump <level>` invocation, `check`'s `cargo fmt --check` +
    /// `cargo test` pair (via `run_cmd`), `lock`'s `cargo test
    /// --quiet` invocation (via `run_cmd`), and `run_clippy`'s
    /// `cargo clippy -- -D warnings` invocation — each spelled the
    /// bare literal verbatim, ignoring `CARGO` at every site. A
    /// Nix-hermetic runner with a store-path `cargo` binary silently
    /// fell through to whatever `cargo` was first on PATH at these
    /// sites specifically — the same silent-PATH-fallback bug class
    /// the sibling shields above closed for their respective cargo
    /// surfaces, and the sibling `NIX_BIN`-lifted `build_lock_target`
    /// site in this same file already avoids at the nix-frontier.
    ///
    /// Scan bounds on the whole-module boundary — from the file start
    /// to the FIRST `\n#[cfg(test)]\nmod tests {` marker in source
    /// order, which lands at the sibling `gh` shield's `#[cfg(test)]
    /// mod tests` opener at the top of this block — so this shield's
    /// own docstring mentions of the bare literal, living in a
    /// `#[cfg(test)]` block below that marker, stay out of scope AND
    /// every current or future cargo-spawning helper landing anywhere
    /// in the top-level module body cannot silently ride along without
    /// going through `CARGO`. Mirrors the whole-module-boundary scan
    /// discipline of the sibling `comprehensive_release.rs` cargo
    /// shield (f95d541) and its lineage.
    #[test]
    fn test_cargo_spawn_routes_through_cargo_env_not_raw_literal() {
        let source = include_str!("tool.rs");
        let cutoff = source.find("\n#[cfg(test)]\nmod tests {").expect(
            "commands/tool.rs must have a `#[cfg(test)] mod tests {` marker \
             — the shield's scan boundary depends on it",
        );
        let body = &source[..cutoff];
        assert!(
            !body.contains("Command::new(\"cargo\")"),
            "commands/tool.rs must not spawn `cargo` via the bare literal — \
             every `cargo` spawn must resolve `CARGO` via \
             `crate::repo::get_tool_path(\"CARGO\", \"cargo\")` first. \
             A raw `Command::new(\"cargo\")` bypasses the hermetic-runner \
             contract substrate's mkRuntimeToolsEnv exports."
        );
        // Sigil sibling: after the cargo_bin() lift, every consumer routes
        // through the sigil, so `fn cargo_bin()` must be defined AND the
        // two-argument resolve string must appear in EXACTLY one place —
        // only the sigil body — so a future added spawn cannot silently
        // re-copy the resolve inline and drift away from the sigil's
        // single point of truth. Mirrors the sibling `cargo_bin()` shield
        // pairs on `commands/test_ci.rs` (916f1a4),
        // `commands/developer_tools.rs` (534ef48), `commands/e2e.rs`
        // (170ecac), and the `bun_bin()` sibling on
        // `commands/frontend_validation.rs` (9986f11). THEORY §I.5:
        // duplication budget zero.
        assert!(
            body.contains("fn cargo_bin()"),
            "commands/tool.rs must define `cargo_bin()` — the sigil \
             function that resolves the tools-registry `CARGO` override \
             for every cargo spawn. Mirrors the `cargo_bin()` sigil at \
             `commands/test_ci.rs:28`, `commands/prerelease.rs:109`, \
             `commands/developer_tools.rs:36`, and `commands/e2e.rs:87`."
        );
        // The needle is reconstructed via `format!` inside
        // `get_tool_path_two_arg_call_needle`, so this shield's own
        // source never contains the literal `get_tool_path("CARGO",
        // "cargo")` string and cannot false-match itself on the
        // count-eq-1 assertion. Filtering through `code_line_hits`
        // suppresses any future `///` doc-comment mention of the
        // canonical form landing above the cutoff.
        let two_arg_needle =
            crate::test_support::get_tool_path_two_arg_call_needle("CARGO", "cargo");
        let resolve_hits = crate::test_support::code_line_hits(body, &two_arg_needle);
        assert_eq!(
            resolve_hits.len(),
            1,
            "the two-argument resolve `{two_arg_needle}` must appear \
             exactly ONCE in the module body (only in the `cargo_bin()` \
             sigil), not {} times — every consumer must route through \
             `cargo_bin()`, not re-copy the resolve inline. Hits: {:?}",
            resolve_hits.len(),
            resolve_hits
        );
    }

    /// Whole-module shield: no raw `Command::new("crate2nix")` may live
    /// in `commands/tool.rs`'s non-test body. Every `crate2nix` spawn
    /// in this module must first resolve `CRATE2NIX` via
    /// [`crate::repo::get_tool_path`] — the canonical env-var override
    /// idiom every sibling crate2nix-consuming surface honors
    /// (`commands/web_service.rs::regenerate`, `commands/pangea.rs`,
    /// `commands/bootstrap.rs`).
    ///
    /// Pre-lift the two consumer sites — `bump`'s optional Cargo.nix
    /// regeneration and `regenerate`'s explicit `crate2nix generate`
    /// invocation (via `run_cmd`) — each spelled the two-argument
    /// resolve verbatim, respelling `get_tool_path("CRATE2NIX",
    /// "crate2nix")` at every consumer. The `which::which` probe in
    /// `bump` also spelled the same resolve inline, so a Nix-hermetic
    /// runner exporting `CRATE2NIX=/nix/store/…/bin/crate2nix` while
    /// omitting `crate2nix` from PATH previously required the probe
    /// and the spawn to independently agree — post-lift both the probe
    /// and the spawn resolve through the same [`crate2nix_bin`] sigil,
    /// so the substrate-exported path fully governs whether
    /// regeneration runs and, if so, which binary runs it.
    ///
    /// Scan bounds on the whole-module boundary — same discipline as
    /// the sibling `cargo` shield above and the `comprehensive_release
    /// .rs` `sqlx` shield (ecace0a) lineage. The forbidden
    /// `Command::new("crate2nix")` shape is not reconstructed via
    /// `format!` because scan-bounding already excludes this shield's
    /// own docstring from the search. The sigil-body count-eq-1
    /// assertion is reconstructed via `format!` inside
    /// [`crate::test_support::get_tool_path_two_arg_call_needle`], so
    /// this shield's own source never contains the literal
    /// `get_tool_path("CRATE2NIX", "crate2nix")` string and cannot
    /// false-match itself on the count-eq-1 assertion. Filtering
    /// through [`crate::test_support::code_line_hits`] suppresses any
    /// future `///` doc-comment mention of the canonical form landing
    /// above the cutoff.
    #[test]
    fn test_crate2nix_spawn_routes_through_crate2nix_env_not_raw_literal() {
        let source = include_str!("tool.rs");
        let cutoff = source.find("\n#[cfg(test)]\nmod tests {").expect(
            "commands/tool.rs must have a `#[cfg(test)] mod tests {` marker \
             — the shield's scan boundary depends on it",
        );
        let body = &source[..cutoff];
        assert!(
            !body.contains("Command::new(\"crate2nix\")"),
            "commands/tool.rs must not spawn `crate2nix` via the bare literal — \
             every `crate2nix` spawn must resolve `CRATE2NIX` via \
             `crate::repo::get_tool_path(\"CRATE2NIX\", \"crate2nix\")` first. \
             A raw `Command::new(\"crate2nix\")` bypasses the hermetic-runner \
             contract substrate's mkRuntimeToolsEnv exports."
        );
        // Sigil sibling: after the crate2nix_bin() lift, every consumer
        // routes through the sigil, so `fn crate2nix_bin()` must be
        // defined AND the two-argument resolve string must appear in
        // EXACTLY one place — only the sigil body — so a future added
        // spawn or probe cannot silently re-copy the resolve inline and
        // drift away from the sigil's single point of truth. Mirrors
        // the sibling `cargo_bin()` count-eq-1 shield above and the
        // fleet-wide `<tool>_bin()` shield discipline landed at 9f6046b
        // / 9986f11 / 170ecac / 534ef48 / 63d4fe7. THEORY §I.5:
        // duplication budget zero.
        assert!(
            body.contains("fn crate2nix_bin()"),
            "commands/tool.rs must define `crate2nix_bin()` — the sigil \
             function that resolves the tools-registry `CRATE2NIX` override \
             for every crate2nix spawn AND probe. Mirrors the `cargo_bin()` \
             sigil at `commands/tool.rs:36` and the sibling `<tool>_bin()` \
             sigil discipline every substrate-exported spawn surface with \
             more than one consumer site honors."
        );
        // Reconstruct via `format!` so this shield's own source never
        // contains the literal `get_tool_path("CRATE2NIX", "crate2nix")`
        // string and cannot false-match itself on the count-eq-1
        // assertion. `code_line_hits` filters `///` doc-comment mentions
        // out of scope so a future narrative aside mentioning the
        // canonical form does not silently loosen the shield.
        let two_arg_needle =
            crate::test_support::get_tool_path_two_arg_call_needle("CRATE2NIX", "crate2nix");
        let resolve_hits = crate::test_support::code_line_hits(body, &two_arg_needle);
        assert_eq!(
            resolve_hits.len(),
            1,
            "the two-argument resolve `{two_arg_needle}` must appear \
             exactly ONCE in the module body (only in the `crate2nix_bin()` \
             sigil), not {} times — every consumer must route through \
             `crate2nix_bin()`, not re-copy the resolve inline. Hits: {:?}",
            resolve_hits.len(),
            resolve_hits
        );
    }
}
