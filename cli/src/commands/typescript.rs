//! TypeScript project commands
//!
//! Replaces typescript-tool.nix::mkTypescriptRegenApp.

use anyhow::{bail, Result};
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

        let mut cmd = Command::new(&pleme_linker);
        cmd.args(["resolve", "--project", project]);
        crate::retry::run_inherited_status_sync(
            cmd,
            &format!("pleme-linker resolve for {}", project),
        )?;

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

    /// Whole-module shield: the sole status-only spawn in
    /// `commands/typescript.rs` — the `pleme-linker resolve --project
    /// <p>` step at the heart of [`super::regenerate`] — routes
    /// through [`crate::retry::run_inherited_status_sync`], never a
    /// hand-rolled `.status()` + `if !status.success() { bail!(…) }`
    /// stanza that drops the exit code from the operator log line.
    /// Pre-lift the site spelled the inline four-line stanza with an
    /// ad-hoc `pleme-linker resolve failed for <p>` bail message that
    /// carried the project name but no exit code; post-lift the
    /// delegation is one call and the canonical
    /// `"{op} failed (exit {code})"` envelope is emitted by
    /// construction at the primitive's ONE body, with the project
    /// name folded into the `op` label so the operator log line reads
    /// `pleme-linker resolve for <p> failed (exit 1)` — pre-lift
    /// context PLUS the exit code the canonical envelope now carries
    /// by construction. The last hand-rolled inline status-only spawn
    /// on this module's surface; the pleme-linker `resolve` frontier
    /// now emits the same failure shape every migrated sibling module
    /// (`commands/gem.rs`, `commands/tool.rs`, `commands/test_ci.rs`,
    /// `commands/local.rs`, `commands/e2e.rs`, `commands/infra.rs`,
    /// `commands/rust_service.rs`, `commands/crossplane.rs`,
    /// `commands/pangea_infra.rs`, `commands/image_release.rs`) emits
    /// on its own status-only spawns.
    ///
    /// Sibling of `commands/gem.rs`'s
    /// `test_gem_status_spawns_route_through_run_inherited_status_sync`
    /// (9072905), `commands/tool.rs`'s
    /// `test_tool_status_spawns_route_through_run_inherited_status_sync`
    /// (a3d51eb), `commands/crossplane.rs`'s
    /// `test_crossplane_status_spawns_route_through_run_inherited_status_sync`
    /// (6cb9442), `commands/pangea_infra.rs`'s
    /// `test_pangea_infra_status_spawns_route_through_run_inherited_status_sync`
    /// (a6e9b96), and the seven other sibling shields riding on the
    /// same [`crate::test_support::assert_source_routes_status_only_spawns_through_run_inherited_status_sync`]
    /// primitive. Same three-primitive discipline: negative side
    /// forbids the inline `.status()` builder-terminator at any code
    /// line in the module body; positive side pins that
    /// `run_inherited_status_sync(` appears at ≥1 code line (one per
    /// pre-lift spawn), so a regression that dropped the delegation
    /// cannot leave the negative scan trivially satisfied by absence.
    /// Both hits route through [`crate::test_support::code_line_hits`]
    /// for anti-docstring-self-match discipline. Scan bounds from
    /// file start to the FIRST `\n#[cfg(test)]\n` marker (this test
    /// module's own opener), so this shield's own body — the string
    /// literal `".status()"` passed to `code_line_hits`, and the
    /// assertion message that names the forbidden terminator — stays
    /// out of scope.
    #[test]
    fn test_typescript_status_spawns_route_through_run_inherited_status_sync() {
        crate::test_support::assert_source_routes_status_only_spawns_through_run_inherited_status_sync(
            include_str!("typescript.rs"),
            "commands/typescript.rs",
            1,
            "the sole status-only spawn (`pleme-linker resolve --project <p>` \
             in `regenerate`)",
        );
    }
}
