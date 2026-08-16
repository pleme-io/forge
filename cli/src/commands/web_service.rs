//! Web service commands for frontend projects.
//!
//! These commands handle web service operations:
//! - Regenerating frontend deps.nix + Hanabi Cargo.nix
//! - Updating Hanabi dependencies and regenerating Cargo.nix
//!
//! All web projects use shared Hanabi (花火) BFF web server.
//! Frontend deps are managed by pleme-linker, Hanabi uses crate2nix.

use std::path::Path;

use anyhow::{bail, Context, Result};
use colored::Colorize;
use tokio::process::Command;

use crate::repo::get_tool_path;

/// Resolve the `crate2nix` binary via the `CRATE2NIX` env override,
/// falling back to `crate2nix` on PATH. Every `crate2nix` spawn in this
/// module reads through this sigil so the resolve happens in exactly one
/// place — mirrors the sibling `crate2nix_bin()` sigil on
/// `commands/tool.rs` (7561329) and the `<tool>_bin()` sigil discipline
/// every substrate-`<TOOL>` / `<TOOL>_BIN`-routed spawn surface in forge
/// with more than one consumer site honors
/// (`commands/test_ci.rs:28` per 916f1a4, `commands/prerelease.rs:109`
/// per 79e03a5, `commands/developer_tools.rs:36` per 534ef48,
/// `commands/e2e.rs:87` per 170ecac, the `bun_bin()` sibling on
/// `commands/frontend_validation.rs` per 9986f11, the `nix_bin()`
/// sibling on `commands/rust_service.rs` per 63d4fe7, and the
/// `nix_bin()` sibling on `commands/developer_tools.rs` per a12c172).
/// Solve-once at the sigil (THEORY §I.5 — duplication budget zero;
/// every recurring shape becomes a helper before it becomes duplicated
/// code) means a future added `crate2nix` spawn cannot silently re-copy
/// the two-argument resolve and drift away from the `CRATE2NIX`
/// override at exactly the tier the hermetic-runner contract binds.
///
/// Pre-lift the two consumer sites — `web_regenerate`'s Hanabi
/// `Cargo.nix` regeneration (both the resolved value flowed into the
/// `--crate2nix` arg-value passed to `pleme-linker regen` AND the
/// subsequent `Command::new(&crate2nix).arg("generate")` spawn on the
/// Hanabi directory) and `web_cargo_update`'s post-update Hanabi
/// `Cargo.nix` regeneration — each spelled the two-argument resolve
/// verbatim, respelling `get_tool_path("CRATE2NIX", "crate2nix")` at
/// every consumer. A Nix-hermetic runner exporting
/// `CRATE2NIX=/nix/store/…/bin/crate2nix` while omitting `crate2nix`
/// from PATH would previously make each consumer re-derive the same
/// two-argument resolve independently, so a future edit to the override
/// contract (say, switching to a derived `CRATE2NIX_BIN` spelling)
/// would have to touch each site rather than one. The `--crate2nix`
/// arg-value passed to `pleme-linker regen` and the direct
/// `Command::new(&crate2nix)` spawn on the sibling `web_regenerate`
/// path now share the same resolved path by construction: no risk of
/// the outer pleme-linker inner spawn racing against a different
/// crate2nix than the sibling `Command::new(&crate2nix)` spawn in the
/// same function.
fn crate2nix_bin() -> String {
    get_tool_path("CRATE2NIX", "crate2nix")
}

/// Regenerate deps.nix for web frontend + Cargo.nix for Hanabi (shared BFF)
///
/// This command:
/// 1. Regenerates frontend deps.nix using pleme-linker regen
/// 2. Regenerates Hanabi Cargo.nix using crate2nix generate
///
/// Arguments:
/// - product: Product name (e.g., myapp)
/// - service: Service name (typically "web")
/// - repo_root: Git repository root path
///
/// # Environment Variables
///
/// * `PLEME_LINKER_BIN` - Path to pleme-linker binary (falls back to
///   "pleme-linker" on PATH)
/// * `CRATE2NIX` - Path to crate2nix binary (falls back to "crate2nix" on
///   PATH); also propagated into pleme-linker's `--crate2nix` arg so the
///   substrate-pinned crate2nix reaches pleme-linker's inner spawn too
pub async fn web_regenerate(product: String, service: String, repo_root: String) -> Result<()> {
    println!(
        "🔄 {} {} {}",
        "Regenerating".bold(),
        format!("{}-{}", product, service).cyan(),
        "dependencies".dimmed()
    );
    println!("{}", "=".repeat(50));
    println!();

    let repo_root_path = Path::new(&repo_root);
    let service_dir = repo_root_path
        .join("pkgs")
        .join("products")
        .join(&product)
        .join(&service);
    let hanabi_dir = repo_root_path.join("pkgs").join("platform").join("hanabi");

    // Verify paths exist
    if !service_dir.exists() {
        bail!(
            "Service directory not found: {}\n  \
             Expected structure: pkgs/products/{}/{}/",
            service_dir.display(),
            product,
            service
        );
    }

    if !hanabi_dir.exists() {
        bail!(
            "Hanabi directory not found: {}\n  \
             Expected at: pkgs/platform/hanabi/",
            hanabi_dir.display()
        );
    }

    let pleme_linker = get_tool_path("PLEME_LINKER_BIN", "pleme-linker");
    let crate2nix = crate2nix_bin();

    println!("📂 Service: {}", service_dir.display());
    println!("📂 Hanabi: {}", hanabi_dir.display());
    println!();

    // Step 1: Regenerate frontend deps.nix using pleme-linker
    println!(
        "📦 {} {}",
        "Regenerating frontend deps.nix".bold(),
        "(pleme-linker regen)".dimmed()
    );

    let mut cmd = Command::new(&pleme_linker);
    cmd.args(&[
        "regen",
        "--project-root",
        service_dir.to_str().unwrap(),
        "--crate2nix",
        &crate2nix,
    ])
    .current_dir(&repo_root);
    crate::retry::run_inherited_status(cmd, "pleme-linker regen")
        .await
        .context("Failed to regenerate frontend deps.nix")?;
    println!("   ✅ Frontend deps.nix regenerated");
    println!();

    // Step 2: Regenerate Hanabi Cargo.nix using crate2nix
    println!(
        "🦀 {} {}",
        "Regenerating Hanabi Cargo.nix".bold(),
        "(crate2nix generate)".dimmed()
    );

    let mut cmd = Command::new(&crate2nix);
    cmd.arg("generate").current_dir(&hanabi_dir);
    crate::retry::run_inherited_status(cmd, "crate2nix generate")
        .await
        .context("Failed to regenerate Hanabi Cargo.nix")?;
    println!("   ✅ Hanabi Cargo.nix regenerated");
    println!();

    // Success summary
    println!("{}", "━".repeat(80).bright_green());
    println!("{}", "✅ REGENERATION COMPLETE".green().bold());
    println!("{}", "━".repeat(80).bright_green());
    println!();
    println!("Generated files:");
    println!("  • {}", service_dir.join("deps.nix").display());
    println!("  • {}", hanabi_dir.join("Cargo.nix").display());
    println!();
    println!("Next steps:");
    println!("  1. Review the changes: git diff");
    println!("  2. Commit: git add -A && git commit -m 'chore: regenerate deps'");
    println!();

    Ok(())
}

/// Update Hanabi (shared BFF) dependencies and regenerate Cargo.nix
///
/// This command:
/// 1. Runs cargo update in Hanabi directory
/// 2. Regenerates Hanabi Cargo.nix using crate2nix generate
///
/// Arguments:
/// - product: Product name (e.g., myapp) - for context only
/// - service: Service name (typically "web") - for context only
/// - repo_root: Git repository root path
///
/// # Environment Variables
///
/// * `CARGO` - Path to cargo binary (falls back to "cargo" on PATH); matches
///   the sibling convention every cargo-spawning module in forge uses
/// * `CRATE2NIX` - Path to crate2nix binary (falls back to "crate2nix" on
///   PATH); matches `commands/bootstrap.rs::regenerate` and
///   `commands/pangea.rs`
pub async fn web_cargo_update(product: String, service: String, repo_root: String) -> Result<()> {
    println!(
        "🔄 {} {} {}",
        "Updating Hanabi".bold(),
        "(shared BFF)".cyan(),
        format!("for {}-{}", product, service).dimmed()
    );
    println!("{}", "=".repeat(50));
    println!();

    let repo_root_path = Path::new(&repo_root);
    let hanabi_dir = repo_root_path.join("pkgs").join("platform").join("hanabi");

    // Verify path exists
    if !hanabi_dir.exists() {
        bail!(
            "Hanabi directory not found: {}\n  \
             Expected at: pkgs/platform/hanabi/",
            hanabi_dir.display()
        );
    }

    let cargo = get_tool_path("CARGO", "cargo");
    let crate2nix = crate2nix_bin();

    println!("📂 Hanabi: {}", hanabi_dir.display());
    println!();

    // Step 1: Run cargo update
    println!(
        "📦 {} {}",
        "Updating dependencies".bold(),
        "(cargo update)".dimmed()
    );

    let mut cmd = Command::new(&cargo);
    cmd.arg("update").current_dir(&hanabi_dir);
    crate::retry::run_inherited_status(cmd, "cargo update")
        .await
        .context("Failed to update Hanabi dependencies")?;
    println!("   ✅ Dependencies updated");
    println!();

    // Step 2: Regenerate Cargo.nix
    println!(
        "🦀 {} {}",
        "Regenerating Cargo.nix".bold(),
        "(crate2nix generate)".dimmed()
    );

    let mut cmd = Command::new(&crate2nix);
    cmd.arg("generate").current_dir(&hanabi_dir);
    crate::retry::run_inherited_status(cmd, "crate2nix generate")
        .await
        .context("Failed to regenerate Hanabi Cargo.nix")?;
    println!("   ✅ Cargo.nix regenerated");
    println!();

    // Success summary
    println!("{}", "━".repeat(80).bright_green());
    println!("{}", "✅ UPDATE COMPLETE".green().bold());
    println!("{}", "━".repeat(80).bright_green());
    println!();
    println!("Updated files:");
    println!("  • {}", hanabi_dir.join("Cargo.lock").display());
    println!("  • {}", hanabi_dir.join("Cargo.nix").display());
    println!();
    println!("Next steps:");
    println!("  1. Review the changes: git diff");
    println!("  2. Test the build: cargo build");
    println!("  3. Commit: git add -A && git commit -m 'chore: update Hanabi deps'");
    println!();

    Ok(())
}

#[cfg(test)]
mod tests {
    /// Whole-module shield: no raw pleme-linker, crate2nix, or cargo
    /// literal spawn may live in `commands/web_service.rs`. Every spawn
    /// must resolve through the tools-registry two-argument idiom
    /// `crate::repo::get_tool_path(<env_var>, <fallback>)` first — the
    /// canonical form the sibling `commands/bootstrap.rs::regenerate`
    /// and `commands/pangea.rs` already use.
    ///
    /// Pre-lift `web_regenerate` and `web_cargo_update` spelled the bare
    /// tool-name literal at four `Command::new` sites — a Nix-hermetic
    /// runner's substrate-derived paths lost to whatever binary sat
    /// first on PATH, the exact silent-PATH-fallback bug class the
    /// sibling `commands/dashboards.rs` (a826ac0),
    /// `commands/tool.rs` (659a1e1), and prior claude-routine commits
    /// closed for their surfaces. Post-lift the two functions resolve
    /// `PLEME_LINKER_BIN`, `CRATE2NIX`, and `CARGO` env-var overrides;
    /// the `--crate2nix` arg-value passed to `pleme-linker regen` also
    /// carries the resolved `CRATE2NIX` path, so the substrate-pinned
    /// crate2nix propagates into pleme-linker's inner spawn surface too,
    /// not just the top-level spawn.
    ///
    /// This shield scans the module's own source via `include_str!` and
    /// forbids the fused literal shape at every spawn form
    /// (`std::process::Command::new(...)`, the bare `Command::new(...)`,
    /// and the `tokio::process::Command::new(...)` long form) at each of
    /// the three tool names, delegating the three-shape check to the
    /// shared `crate::test_support::assert_source_forbids_bare_spawn_shapes`
    /// helper (introduced 4e178e6). Forbidden shapes are reconstructed
    /// via `format!` so the shield's own source text does not false-match
    /// itself — the whole-module scan therefore covers both the
    /// top-of-file production body AND every sibling `#[cfg(test)]`
    /// block.
    #[test]
    fn test_web_service_spawns_route_through_tools_registry_not_raw_literals() {
        const SOURCE: &str = include_str!("web_service.rs");

        for (bare, env_var) in [
            ("pleme-linker", "PLEME_LINKER_BIN"),
            ("crate2nix", "CRATE2NIX"),
            ("cargo", "CARGO"),
        ] {
            let remediation = format!(
                "resolve the tools-registry env-var override via \
                 `crate::repo::get_tool_path(\"{env_var}\", \"{bare}\")`"
            );
            crate::test_support::assert_source_forbids_bare_spawn_shapes(
                SOURCE,
                "commands/web_service.rs",
                bare,
                &remediation,
            );
        }

        for (bare, env_var) in [
            ("pleme-linker", "PLEME_LINKER_BIN"),
            ("crate2nix", "CRATE2NIX"),
            ("cargo", "CARGO"),
        ] {
            crate::test_support::assert_source_has_get_tool_path_two_arg_call_code_line(
                SOURCE,
                "commands/web_service.rs",
                env_var,
                bare,
            );
        }

        // Sigil sibling: after the `crate2nix_bin()` lift, both
        // consumer sites (`web_regenerate`'s Hanabi Cargo.nix
        // regeneration and `web_cargo_update`'s post-update Hanabi
        // Cargo.nix regeneration) route through the sigil, so
        // `fn crate2nix_bin()` must be defined AND the two-argument
        // resolve string must appear in EXACTLY one place — only the
        // sigil body — so a future added spawn cannot silently re-copy
        // the resolve inline and drift away from the sigil's single
        // point of truth. Mirrors the `crate2nix_bin()` sigil
        // count-eq-1 shield on `commands/tool.rs` (7561329) and the
        // fleet-wide `<tool>_bin()` shield discipline landed at
        // 9f6046b / 9986f11 / 170ecac / 534ef48 / 63d4fe7 / 7561329 /
        // a12c172. THEORY §I.5: duplication budget zero.
        crate::test_support::assert_source_defines_sigil_bin_fn_code_line(
            SOURCE,
            "commands/web_service.rs",
            "crate2nix_bin",
            "CRATE2NIX",
            "crate2nix",
        );
        // Reconstruct via `format!` so this shield's own source never
        // contains the literal `get_tool_path("CRATE2NIX", "crate2nix")`
        // string and cannot false-match itself on the count-eq-1
        // assertion. `code_line_hits` filters `///` / `//!` / `//`
        // comments out of scope so a future narrative aside mentioning
        // the canonical form does not silently loosen the shield.
        let crate2nix_needle =
            crate::test_support::get_tool_path_two_arg_call_needle("CRATE2NIX", "crate2nix");
        let crate2nix_resolve_hits = crate::test_support::code_line_hits(SOURCE, &crate2nix_needle);
        assert_eq!(
            crate2nix_resolve_hits.len(),
            1,
            "the two-argument resolve `{crate2nix_needle}` must appear \
             exactly ONCE in the module (only in the `crate2nix_bin()` \
             sigil), not {} times — every consumer must route through \
             `crate2nix_bin()`, not re-copy the resolve inline. Hits: {:?}",
            crate2nix_resolve_hits.len(),
            crate2nix_resolve_hits
        );
    }
}
