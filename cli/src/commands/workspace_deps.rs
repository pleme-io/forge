//! Workspace Dependencies Management
//!
//! Ensures all @pleme/* TypeScript workspace packages have up-to-date dist/ builds.
//! This is required before Nix builds because pleme-linker validates that workspace
//! packages have dist/ before linking them into node_modules.

use anyhow::{Context, Result};
use colored::Colorize;
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use tokio::process::Command;
use tracing::{debug, info};

/// Resolve the `npm` binary path via `NPM_BIN`, falling back to `npm` on
/// `PATH`. Wired through [`crate::tools::get_tool_path`] so a Nix-hermetic
/// runner's substrate-derived `npm` path lands at every npm-spawning site
/// in this module. Mirrors the sibling `commands/dashboards.rs::jsonnet_bin`
/// (a826ac0), `commands/rebac_validation.rs::redis_cli_bin` (9aed883), and
/// `commands/infra.rs::docker_bin` (7f49465) sigil discipline: the one
/// bridge between the forge workspace-dependency build surface and the
/// substrate-`mkRuntimeToolsEnv`-exported binary path. Pre-lift the two
/// `Command::new` sites in `build_package` (`npm install --silent` and
/// `npm run build --silent`) each spelled the bare `"npm"` literal
/// verbatim, ignoring `NPM_BIN` — a Nix-hermetic runner's
/// substrate-derived npm path lost to whatever `npm` sat first on PATH,
/// so a workspace-dependency prebuild would silently invoke the wrong
/// node/npm pair and cache the resulting `dist/` under the wrong
/// toolchain fingerprint.
fn npm_bin() -> String {
    crate::tools::get_tool_path("npm")
}

/// Package state after checking
#[derive(Debug)]
enum PackageState {
    /// dist/ is up-to-date
    UpToDate,
    /// dist/ is missing
    Missing,
    /// dist/ exists but src/ is newer (stale build)
    Stale,
}

/// Information about a workspace package
#[derive(Debug)]
struct WorkspacePackage {
    name: String,
    path: PathBuf,
    state: PackageState,
}

/// Check all @pleme/* workspace packages and build any that are missing or stale
pub async fn execute(repo_root: String) -> Result<()> {
    println!();
    println!(
        "{}",
        "╔════════════════════════════════════════════════════════════╗".bright_blue()
    );
    println!(
        "{}",
        "║  Workspace Dependencies Check                              ║".bright_blue()
    );
    println!(
        "{}",
        "╚════════════════════════════════════════════════════════════╝".bright_blue()
    );
    println!();

    let libs_dir = PathBuf::from(&repo_root).join("pkgs/libraries/typescript");

    if !libs_dir.exists() {
        info!(
            "📁 No workspace libraries directory found at {}",
            libs_dir.display()
        );
        return Ok(());
    }

    // Discover all pleme-* packages
    let packages = discover_packages(&libs_dir).await?;

    if packages.is_empty() {
        info!("📦 No @pleme/* packages found");
        return Ok(());
    }

    // Separate packages by state
    let up_to_date: Vec<_> = packages
        .iter()
        .filter(|p| matches!(p.state, PackageState::UpToDate))
        .collect();
    let needs_build: Vec<_> = packages
        .iter()
        .filter(|p| !matches!(p.state, PackageState::UpToDate))
        .collect();

    // Report status
    println!("🔍 {} Checking workspace packages...", "".bright_blue());
    println!();

    for pkg in &up_to_date {
        println!("   {} {} - dist/ up-to-date", "✓".bright_green(), pkg.name);
    }

    for pkg in &needs_build {
        let reason = match pkg.state {
            PackageState::Missing => "dist/ missing",
            PackageState::Stale => "dist/ stale",
            _ => "needs build",
        };
        println!("   {} {} - {}", "⚠".bright_yellow(), pkg.name, reason);
    }

    println!();

    if needs_build.is_empty() {
        println!(
            "{}",
            "✅ All workspace packages are up-to-date".bright_green()
        );
        println!();
        return Ok(());
    }

    // Build missing/stale packages
    println!(
        "🔨 {} Building {} package(s)...",
        "".bright_blue(),
        needs_build.len()
    );
    println!();

    for pkg in &needs_build {
        build_package(pkg).await?;
    }

    println!();
    println!(
        "{}",
        "✅ All workspace packages built successfully".bright_green()
    );
    println!();

    Ok(())
}

/// Discover all pleme-* packages in the libraries directory
async fn discover_packages(libs_dir: &Path) -> Result<Vec<WorkspacePackage>> {
    let mut packages = Vec::new();

    let entries = std::fs::read_dir(libs_dir)
        .with_context(|| format!("Failed to read directory: {}", libs_dir.display()))?;

    for entry in entries {
        let entry = entry?;
        let path = entry.path();

        // Skip non-directories and non-pleme-* entries
        if !path.is_dir() {
            continue;
        }

        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

        if !name.starts_with("pleme-") {
            continue;
        }

        // Check if it's a valid TypeScript package (has src/ and package.json)
        let src_dir = path.join("src");
        let package_json = path.join("package.json");

        if !src_dir.exists() || !package_json.exists() {
            debug!("Skipping {} - no src/ or package.json", name);
            continue;
        }

        // Determine package state
        let state = check_package_state(&path).await?;

        packages.push(WorkspacePackage {
            name: name.to_string(),
            path,
            state,
        });
    }

    // Sort by name for consistent output
    packages.sort_by(|a, b| a.name.cmp(&b.name));

    Ok(packages)
}

/// Check if a package's dist/ is up-to-date
async fn check_package_state(pkg_path: &Path) -> Result<PackageState> {
    let dist_dir = pkg_path.join("dist");
    let dist_index = dist_dir.join("index.js");

    // Check if dist/ exists
    if !dist_dir.exists() || !dist_index.exists() {
        return Ok(PackageState::Missing);
    }

    // Compare modification times
    let src_mtime = get_newest_mtime(&pkg_path.join("src"))?;
    let dist_mtime = get_newest_mtime(&dist_dir)?;

    if src_mtime > dist_mtime {
        Ok(PackageState::Stale)
    } else {
        Ok(PackageState::UpToDate)
    }
}

/// Get the newest modification time in a directory (recursive)
fn get_newest_mtime(dir: &Path) -> Result<SystemTime> {
    let mut newest = SystemTime::UNIX_EPOCH;

    fn visit(path: &Path, newest: &mut SystemTime) {
        if let Ok(metadata) = std::fs::metadata(path) {
            if let Ok(mtime) = metadata.modified() {
                if mtime > *newest {
                    *newest = mtime;
                }
            }
        }

        if path.is_dir() {
            if let Ok(entries) = std::fs::read_dir(path) {
                for entry in entries.filter_map(|e| e.ok()) {
                    let entry_path = entry.path();
                    // Skip node_modules to avoid unnecessary recursion
                    if entry.file_name() != "node_modules" {
                        visit(&entry_path, newest);
                    }
                }
            }
        }
    }

    visit(dir, &mut newest);
    Ok(newest)
}

/// Build a single package using npm
async fn build_package(pkg: &WorkspacePackage) -> Result<()> {
    println!("   📦 Building {}...", pkg.name.bright_cyan());

    let npm = npm_bin();

    // First, install dependencies
    let install_status = Command::new(&npm)
        .args(["install", "--silent"])
        .current_dir(&pkg.path)
        .status()
        .await
        .with_context(|| format!("Failed to run npm install for {}", pkg.name))?;

    if !install_status.success() {
        anyhow::bail!(
            "npm install failed for {}\n\n  \
            To fix manually:\n  \
            cd {}\n  \
            npm install && npm run build",
            pkg.name,
            pkg.path.display()
        );
    }

    // Then, build
    let build_status = Command::new(&npm)
        .args(["run", "build", "--silent"])
        .current_dir(&pkg.path)
        .status()
        .await
        .with_context(|| format!("Failed to run npm run build for {}", pkg.name))?;

    if !build_status.success() {
        anyhow::bail!(
            "npm run build failed for {}\n\n  \
            To fix manually:\n  \
            cd {}\n  \
            npm install && npm run build",
            pkg.name,
            pkg.path.display()
        );
    }

    println!("   {} {} built successfully", "✓".bright_green(), pkg.name);

    Ok(())
}

#[cfg(test)]
mod tests {
    /// Whole-module shield: no raw `"npm"`-literal spawn may live in
    /// `commands/workspace_deps.rs`. Every npm spawn must resolve
    /// `NPM_BIN` via [`super::npm_bin`] first.
    ///
    /// Pre-lift the two `Command::new` sites in `build_package` — the
    /// `npm install --silent` and `npm run build --silent` steps that
    /// materialize each `@pleme/*` workspace package's `dist/` before a
    /// pleme-linker consumer wires it into `node_modules` — each spelled
    /// the bare `"npm"` literal verbatim, ignoring `NPM_BIN`. A
    /// Nix-hermetic runner's substrate-derived npm path lost to
    /// whatever `npm` sat first on PATH — the same silent-PATH-fallback
    /// bug class the sibling `commands/dashboards.rs::jsonnet_bin`
    /// shield (a826ac0), `commands/rebac_validation.rs::redis_cli_bin`
    /// shield (9aed883), and `commands/infra.rs::docker_bin` shield
    /// (7f49465) closed for their surfaces. The bug bites doubly here
    /// because the resulting `dist/` bytes are then hashed into the
    /// pleme-linker fingerprint that determines cache reuse — a wrong
    /// npm (a wrong node runtime) silently poisons the workspace-
    /// dependency layer of every subsequent Nix build.
    ///
    /// This shield scans the module's own source via [`include_str!`]
    /// and forbids the fused literal shape. The forbidden shape is
    /// reconstructed via [`format!`] so this shield's own source text
    /// does not false-match itself — the whole-module scan therefore
    /// covers both the top-of-file production body AND every sibling
    /// `#[cfg(test)]` block (any of which could otherwise silently re-
    /// introduce a raw literal). The end-to-end `NPM_BIN`-routing
    /// invariant of the underlying primitive is pinned separately by
    /// [`crate::tools::tests::test_get_tool_path_from_env`] /
    /// [`crate::tools::tests::test_get_tool_path_fallback`]; this
    /// shield only certifies that every npm-spawning site in this
    /// module reads through `npm_bin()`.
    #[test]
    fn test_npm_spawn_routes_through_npm_bin_not_raw_literal() {
        const SOURCE: &str = include_str!("workspace_deps.rs");

        let bare = "npm";
        let raw_command = format!("Command::new(\"{}\")", bare);

        assert!(
            !SOURCE.contains(&raw_command),
            "commands/workspace_deps.rs must not spawn `npm` via the \
             bare literal — every npm spawn must resolve \
             `NPM_BIN` via `npm_bin()` first. A raw literal at \
             `Command::new` bypasses the hermetic-runner contract \
             substrate's mkRuntimeToolsEnv exports."
        );
        assert!(
            SOURCE.contains("fn npm_bin()"),
            "commands/workspace_deps.rs must define `npm_bin()` — the \
             sigil function that resolves the tools-registry \
             `NPM_BIN` override for every npm spawn."
        );
        assert!(
            SOURCE.contains("crate::tools::get_tool_path(\"npm\")"),
            "`npm_bin()` must delegate to \
             `crate::tools::get_tool_path(\"npm\")` — the canonical \
             lookup was not found in the module. A regression here \
             would silently downgrade to the PATH fallback."
        );
    }
}
