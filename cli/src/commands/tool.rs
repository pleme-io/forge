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
use crate::nix::build_flake_attr_in;
use crate::version;

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
        let src = Path::new(&store_path).join("bin").join(name);

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

    let gh_status = Command::new("gh")
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
            let status = Command::new("cargo")
                .args(["set-version", "--bump", level])
                .current_dir(dir)
                .status()
                .context("Failed to run cargo set-version (is cargo-edit installed?)")?;

            if !status.success() {
                bail!("cargo set-version --bump {} failed", level);
            }

            // Regenerate Cargo.nix if crate2nix is available
            if which::which("crate2nix").is_ok() {
                info!("Regenerating Cargo.nix...");
                let status = Command::new("crate2nix")
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
            info!("{}: running cargo fmt --check...", name);
            run_cmd(dir, "cargo", &["fmt", "--check"])?;

            info!("{}: running cargo clippy...", name);
            // Held in a binding: dropping the TempDir deletes the clippy.toml
            // inside it, so it must outlive the clippy process.
            let clippy_conf = provide_clippy_conf(dir);
            run_clippy(dir, clippy_conf.as_ref().map(tempfile::TempDir::path))?;

            info!("{}: running cargo test...", name);
            run_cmd(dir, "cargo", &["test"])?;

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
            info!("Running crate2nix generate...");
            run_cmd(dir, "crate2nix", &["generate"])?;
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
    let build_output = tokio::process::Command::new("nix")
        .args(["build", "--print-out-paths", "--impure"])
        .current_dir(dir)
        .output()
        .await
        .context("nix build failed to execute")?;

    if !build_output.status.success() {
        let stderr = String::from_utf8_lossy(&build_output.stderr);
        bail!("nix build failed on {}: {}", platform, stderr.trim());
    }

    let store_path = String::from_utf8_lossy(&build_output.stdout)
        .trim()
        .to_string();
    info!("  -> {}", store_path);

    // Step 2: Run tests (language-specific; "nix" = build-only, no test runner)
    info!("[2/3] Testing...");
    let test_result = match language {
        "rust" => {
            run_cmd(dir, "cargo", &["test", "--quiet"])?;
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
        "store_path": store_path,
        "tests": test_result,
    });

    std::fs::write(&lock_path, serde_json::to_string_pretty(&lock_content)?)
        .with_context(|| format!("Failed to write lock file: {}", lock_path.display()))?;

    info!("=== {} locked ===", platform);
    info!("{}", serde_json::to_string_pretty(&lock_content)?);

    Ok(())
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
    let mut cmd = Command::new("cargo");
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
}
