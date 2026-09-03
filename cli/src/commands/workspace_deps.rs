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
    crate::ui::print_header("Workspace Dependencies Check");

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

        let name = crate::repo::file_name_str(&path);

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
    let mut install_cmd = Command::new(&npm);
    install_cmd
        .args(["install", "--silent"])
        .current_dir(&pkg.path);
    crate::retry::run_inherited_status(
        install_cmd,
        &format!("npm install --silent for {}", pkg.name),
    )
    .await
    .with_context(|| {
        format!(
            "To fix manually:\n  \
            cd {}\n  \
            npm install && npm run build",
            pkg.path.display()
        )
    })?;

    // Then, build
    let mut build_cmd = Command::new(&npm);
    build_cmd
        .args(["run", "build", "--silent"])
        .current_dir(&pkg.path);
    crate::retry::run_inherited_status(
        build_cmd,
        &format!("npm run build --silent for {}", pkg.name),
    )
    .await
    .with_context(|| {
        format!(
            "To fix manually:\n  \
            cd {}\n  \
            npm install && npm run build",
            pkg.path.display()
        )
    })?;

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

        crate::test_support::assert_source_forbids_bare_spawn_shapes(
            SOURCE,
            "commands/workspace_deps.rs",
            "npm",
            "resolve `NPM_BIN` via `npm_bin()`",
        );
        crate::test_support::assert_source_defines_sigil_bin_fn_code_line(
            SOURCE,
            "commands/workspace_deps.rs",
            "npm_bin",
            "NPM_BIN",
            "npm",
        );
        assert!(
            SOURCE.contains("crate::tools::get_tool_path(\"npm\")"),
            "`npm_bin()` must delegate to \
             `crate::tools::get_tool_path(\"npm\")` — the canonical \
             lookup was not found in the module. A regression here \
             would silently downgrade to the PATH fallback."
        );
    }

    /// Whole-module shield: the two async status-only spawn sites in
    /// `commands/workspace_deps.rs::build_package` — the
    /// `npm install --silent` and `npm run build --silent` steps that
    /// materialize each `@pleme/*` workspace package's `dist/` before a
    /// pleme-linker consumer wires it into `node_modules` — route
    /// through [`crate::retry::run_inherited_status`], never a
    /// hand-rolled `.status().await` + `if !status.success() {
    /// bail!(…) }` stanza that drops the exit code from the operator
    /// log line.
    ///
    /// Pre-lift each site's six-line
    /// `.status().await.with_context(…)?` + `if !status.success() {
    /// anyhow::bail!("npm install failed for {}\n\n  To fix
    /// manually:\n  cd {}\n  npm install && npm run build", …) }`
    /// stanza dropped the exit code from the terminating log line: an
    /// operator seeing `"npm install failed for pleme-foo"` in a
    /// workspace-dependency prebuild against 15 `@pleme/*` packages
    /// (one per `discover_packages` hit) had no way to tell whether
    /// `npm` exited 1 (a real build failure), 2 (missing dependency),
    /// 127 (a bad `NPM_BIN` route), or was killed by a signal (a
    /// runner OOM eviction). Post-lift each site's operator log line
    /// reads the canonical `"npm install --silent for pleme-foo
    /// failed (exit {code})"` envelope every migrated sync- and async-
    /// frontier sibling module already emits at `retry.rs::
    /// classify_inherited_status`, with the multi-line
    /// `"To fix manually: cd {path} && npm install && npm run build"`
    /// remediation hint carried through as an `anyhow::Context`
    /// layer on top of the primitive's terminating envelope — the
    /// operator sees BOTH the exit code (from the primitive) AND the
    /// remediation hint (from the context layer), rather than the
    /// pre-lift trade of exit code FOR remediation hint.
    ///
    /// Negative side: no `.status().await` builder-terminator may
    /// reappear at any code line in the module body — a re-inlined
    /// spawn would bypass the primitive and re-drop the exit code.
    /// Positive side: `run_inherited_status(` must appear at ≥2 code
    /// lines (one per lifted site), so a regression that dropped the
    /// delegation cannot leave the negative scan trivially satisfied
    /// by absence. Both hits route through
    /// [`crate::test_support::code_line_hits`] for anti-docstring-
    /// self-match discipline (the `.status().await` string in this
    /// shield's own docstring is excluded because `code_line_hits`
    /// filters `///`-prefixed lines). Scan bounds from file start to
    /// the first `\n#[cfg(test)]\nmod tests {` marker so the sibling
    /// `test_npm_spawn_routes_through_npm_bin_not_raw_literal`
    /// shield's own source (which does not mention `.status().await`
    /// but shares the module) stays out of scope by construction.
    ///
    /// # Idiom lineage
    ///
    /// Sibling of the twelve async- and sync-frontier shields already
    /// migrated on this primitive family (`crossplane` 6cb9442,
    /// `e2e` 5faeecb / 2fae634, `gem` 9072905, `image_release` b5d9573,
    /// `infra` 27896e4, `local` c2922fd, `pangea_infra` a6e9b96,
    /// `product_release` bf6d836, `rust_service` 5b5c765,
    /// `test_ci` a21bd67, `tool` a3d51eb, `typescript` a3c3a49). This
    /// module was the largest surviving async holdout with the two-
    /// adjacent-status-spawn shape (twin `npm` steps in ONE
    /// `build_package` body); every other command module on the
    /// async frontier now emits the canonical failure envelope by
    /// construction.
    ///
    /// # THEORY grounding
    ///
    /// THEORY.md §V.1 (construction guarantees): the canonical
    /// failure envelope is emitted by construction at the primitive's
    /// ONE body, not asserted after the fact at every site.
    /// THEORY.md §V.4 (terminating shape): an attestation-record
    /// consumer reading the terminating shape of a failed workspace-
    /// dependency prebuild reads the `(op, exit_code)` structural
    /// tuple the primitive emits, not the ad-hoc pre-lift string.
    /// THEORY.md §VI.1 (one-oracle discipline): the "what does the
    /// operator log line for a failed npm spawn look like" question
    /// is answered at ONE typed-primitive body
    /// (`retry.rs::classify_inherited_status`); a future refinement
    /// to the envelope (structured JSON, added timing, added
    /// derivation reference) lands there once and every migrated
    /// site picks it up by construction.
    #[test]
    fn test_workspace_deps_status_spawns_route_through_run_inherited_status() {
        const SOURCE: &str = include_str!("workspace_deps.rs");

        crate::test_support::assert_source_routes_status_only_spawns_through_run_inherited_status(
            SOURCE,
            "commands/workspace_deps.rs",
            2,
            "the two `build_package` status-only spawn sites \
             (`npm install --silent` and `npm run build --silent`)",
        );
    }
}
