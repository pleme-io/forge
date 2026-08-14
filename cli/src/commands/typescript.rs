//! TypeScript project commands
//!
//! Replaces typescript-tool.nix::mkTypescriptRegenApp.

use anyhow::{bail, Context, Result};
use std::path::Path;
use std::process::Command;
use tracing::info;

use crate::repo::get_tool_path;

/// Regenerate pleme-linker lockfiles for TypeScript projects.
///
/// # Environment Variables
///
/// * `PLEME_LINKER_BIN` - Path to pleme-linker binary (falls back to
///   `"pleme-linker"` on PATH). Matches the canonical two-argument
///   tools-registry idiom `crate::repo::get_tool_path(<env_var>,
///   <fallback>)` the sibling `commands/web_service.rs`
///   (`web_regenerate` at line 73) already rides on, so the substrate-
///   derived pleme-linker resolves identically across every forge
///   pleme-linker consumer.
pub fn regenerate(projects: &[String]) -> Result<()> {
    if projects.is_empty() {
        bail!("At least one --project is required");
    }

    let pleme_linker = get_tool_path("PLEME_LINKER_BIN", "pleme-linker");

    for project in projects {
        let dir = Path::new(project);
        if !dir.exists() {
            bail!("Project directory not found: {}", project);
        }

        info!("Regenerating lockfile for {}...", project);

        let status = Command::new(&pleme_linker)
            .args(["resolve", "--project", project])
            .status()
            .with_context(|| format!("Failed to run pleme-linker resolve for {}", project))?;

        if !status.success() {
            bail!("pleme-linker resolve failed for {}", project);
        }

        info!("  Done: {}", project);
    }

    info!("All {} project(s) regenerated", projects.len());
    Ok(())
}

#[cfg(test)]
mod tests {
    /// Whole-module shield: no bare pleme-linker literal spawn may live
    /// in `commands/typescript.rs`. The sole spawn — the
    /// `pleme-linker resolve --project <p>` step at the heart of
    /// `regenerate` — must resolve through the tools-registry two-
    /// argument idiom `crate::repo::get_tool_path("PLEME_LINKER_BIN",
    /// "pleme-linker")` first, so a Nix-hermetic runner's substrate-
    /// derived `PLEME_LINKER_BIN` path is honored just as the sibling
    /// `commands/web_service.rs::web_regenerate` (line 73, 2396779)
    /// already does.
    ///
    /// Pre-lift the site spelled the bare tool-name literal verbatim —
    /// a Nix-hermetic runner's substrate-derived pleme-linker path
    /// lost to whatever binary sat first on PATH, the exact silent-
    /// PATH-fallback bug class the sibling `commands/web_service.rs`
    /// (2396779), `commands/tool.rs` (659a1e1),
    /// `commands/dashboards.rs` (a826ac0), and the 40+ prior claude-
    /// routine commits closed for their surfaces.
    ///
    /// This shield closes the last raw pleme-linker literal spawn site
    /// anywhere in forge — the pleme-linker sub-surface is now fully
    /// closed fleet-wide.
    ///
    /// The shield scans the module's own source via `include_str!` and
    /// forbids the fused `Command::new(<bare>)` shape. The forbidden
    /// shape is reconstructed via `format!` so the shield's own source
    /// text does not false-match itself — the whole-module scan
    /// therefore covers both the top-of-file production body AND every
    /// sibling `#[cfg(test)]` block, so no future contributor can
    /// silently re-introduce a raw literal as new pleme-linker sub-
    /// commands (`resolve`, `regen`, `--check`) land in the
    /// TypeScript-regen surface.
    #[test]
    fn test_pleme_linker_spawn_routes_through_pleme_linker_bin_not_raw_literal() {
        const SOURCE: &str = include_str!("typescript.rs");

        crate::test_support::assert_source_forbids_bare_spawn_shapes(
            SOURCE,
            "commands/typescript.rs",
            "pleme-linker",
            "resolve the tools-registry env-var override via \
             `crate::repo::get_tool_path(\"PLEME_LINKER_BIN\", \"pleme-linker\")`",
        );

        crate::test_support::assert_source_has_get_tool_path_two_arg_call_code_line(
            SOURCE,
            "commands/typescript.rs",
            "PLEME_LINKER_BIN",
            "pleme-linker",
        );
    }
}
