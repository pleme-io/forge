//! Schema Export and Codegen
//!
//! This module handles exporting the GraphQL schema from the backend
//! and running GraphQL Code Generator to produce TypeScript types.
//!
//! Replaces shell script logic with pure Rust implementation.

use anyhow::{Context, Result};
use std::path::Path;
use std::time::Instant;
use tokio::fs;
use tokio::process::Command;

use crate::repo::get_tool_path;

/// Resolve the `bun` binary via the `BUN_BIN` env override, falling back
/// to `bun` on `PATH`. Wired through [`crate::repo::get_tool_path`] —
/// the canonical env-var-or-PATH lookup every bun-invocation site in
/// forge honors. Landing of the `bun_bin()` sigil onto
/// `commands/codegen.rs` alongside the sibling landings on
/// `commands/frontend_validation.rs::bun_bin` (9986f11) and
/// `commands/e2e.rs::bun_bin` — the pattern is proven; this module
/// was one of the three remaining call sites (with
/// `commands/codegen_validation.rs` and `commands/sync.rs`) still
/// respelling the two-argument `BUN_BIN` resolve inline at its bun
/// spawns.
///
/// Solve-once at the sigil (THEORY §I.5 — duplication budget zero;
/// every recurring shape becomes a helper before it becomes duplicated
/// code) means a future added `bun` spawn in this module cannot
/// silently re-copy the two-argument resolve and drift away from the
/// `BUN_BIN` override at exactly the tier the hermetic-runner contract
/// binds — the surface `forge codegen` invokes on every
/// schema-export-then-graphql-codegen run, where a wrong-`bun` resolve
/// produces stale generated hooks attributed to whichever `bun` PATH
/// resolved first rather than to the substrate-pinned `bun` derivation
/// the flake declared. The whole-module shield below asserts three
/// invariants via
/// [`crate::test_support::assert_source_routes_bare_spawn_through_sigil_bin_fn_at_exactly_one_resolve`]:
/// no bare-literal `bun` spawn in the module body, `fn bun_bin()` is
/// defined, and the two-argument resolve appears in EXACTLY one place
/// — only the sigil body.
fn bun_bin() -> String {
    get_tool_path("BUN_BIN", "bun")
}

/// Result of codegen execution
#[derive(Debug)]
pub struct CodegenResult {
    /// Schema was exported successfully
    pub schema_exported: bool,
    /// Schema size in bytes
    pub schema_size: usize,
    /// Codegen completed successfully
    pub codegen_completed: bool,
    /// Path to generated schema
    pub schema_path: String,
}

/// Export schema from backend and run codegen
///
/// This is a pure Rust implementation of the schema export + codegen flow.
/// Steps:
/// 1. Run extract-schema binary in backend directory
/// 2. Write schema to web/schema.graphql
/// 3. Run bun install --frozen-lockfile
/// 4. Run graphql-codegen
pub async fn execute(backend_dir: &Path, web_dir: &Path) -> Result<CodegenResult> {
    let start = Instant::now();

    crate::ui::print_section_header("Schema Export + Codegen");
    println!("Backend: {}", backend_dir.display());
    println!("Frontend: {}", web_dir.display());
    println!();

    // Step 1: Export schema from backend
    crate::ui::print_step_heading("Step 1: Exporting GraphQL schema...");
    let schema_start = Instant::now();

    // Route through the canonical `extract_graphql_schema` primitive —
    // the one-oracle owner of the "run cargo run --bin extract-schema
    // --quiet in a backend dir, expect non-empty stdout bytes, fail typed
    // on every failure shape" surface (THEORY §V.1, §VI.1). The typed
    // `SchemaExtractionError` is preserved across the anyhow boundary and
    // can be recovered with `err.downcast_ref::<SchemaExtractionError>()`.
    let schema_bytes = crate::graphql_schema::extract_graphql_schema(backend_dir).await?;
    let schema_size = schema_bytes.len();
    crate::ui::print_step_check(&format!(
        "Schema extracted ({} bytes, {:.1}s)",
        schema_size,
        schema_start.elapsed().as_secs_f64()
    ));

    // Step 2: Write schema to web directory
    let schema_path = web_dir.join("schema.graphql");
    fs::write(&schema_path, &schema_bytes)
        .await
        .with_context(|| format!("Failed to write schema to {}", schema_path.display()))?;

    crate::ui::print_step_check(&format!("Schema written to {}", schema_path.display()));
    println!();

    // Step 3: Install dependencies
    crate::ui::print_step_heading("Step 2: Installing dependencies...");
    let install_start = Instant::now();

    let bun = bun_bin();
    // Owns the async captured-output spawn + classify ritual at the
    // canonical `crate::retry::run_capture_anyhow` primitive.
    // `.current_dir(web_dir)` is preserved through the builder chain;
    // the surrounding `.with_context(...)` retains the web_dir hint
    // for the spawn-arm diagnostic.
    let mut install_cmd = Command::new(&bun);
    install_cmd
        .args(["install", "--frozen-lockfile"])
        .current_dir(web_dir);
    crate::retry::run_capture_anyhow(install_cmd, "bun install")
        .await
        .with_context(|| format!("bun install in {}", web_dir.display()))?;

    crate::ui::print_step_check(&format!(
        "Dependencies installed ({:.1}s)",
        install_start.elapsed().as_secs_f64()
    ));
    println!();

    // Step 4: Run codegen
    crate::ui::print_step_heading("Step 3: Running GraphQL codegen...");
    let codegen_start = Instant::now();

    let codegen_output = Command::new(&bun)
        .arg("x")
        .args(["graphql-codegen", "--config", "codegen.ts"])
        .current_dir(web_dir)
        .output()
        .await
        .with_context(|| format!("Failed to run graphql-codegen in {}", web_dir.display()))?;

    if !codegen_output.status.success() {
        let (stdout, stderr) = crate::repo::utf8_lossy_streams(&codegen_output);
        anyhow::bail!("GraphQL codegen failed:\n{}\n{}", stderr, stdout);
    }

    crate::ui::print_step_check(&format!(
        "Codegen completed ({:.1}s)",
        codegen_start.elapsed().as_secs_f64()
    ));
    println!();

    // Summary
    let total_time = start.elapsed().as_secs_f64();
    crate::ui::print_section_completion_banner(
        &format!("Codegen Complete ({:.1}s total)", total_time),
        crate::ui::SectionCompletionStyle::Success,
    );
    println!();
    println!("Generated files:");
    println!("  - src/gql/ (typed document nodes)");
    println!("  - src/lib/graphql/generated/hooks.ts (TanStack Query hooks)");
    println!();

    Ok(CodegenResult {
        schema_exported: true,
        schema_size,
        codegen_completed: true,
        schema_path: schema_path.display().to_string(),
    })
}

/// Export schema only (without running codegen)
pub async fn export_schema_only(backend_dir: &Path, output_path: &Path) -> Result<usize> {
    crate::ui::print_step_heading("Exporting GraphQL schema...");

    // One-oracle read-through: same typed primitive `execute` above uses,
    // so a future refinement of the extract-schema invocation shape
    // (CARGO env override, typed error variants, byte-preservation)
    // lands at one site (THEORY §VI.1).
    let schema_bytes = crate::graphql_schema::extract_graphql_schema(backend_dir).await?;
    let schema_size = schema_bytes.len();

    fs::write(output_path, &schema_bytes)
        .await
        .with_context(|| format!("Failed to write schema to {}", output_path.display()))?;

    crate::ui::print_step_pass(&format!(
        "Schema exported to {} ({} bytes)",
        output_path.display(),
        schema_size
    ));

    Ok(schema_size)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Whole-module shield: no raw `Command::new("bun")` may live in
    /// `commands/codegen.rs`'s non-test body, `fn bun_bin()` must be
    /// defined, and the two-argument resolve
    /// `get_tool_path("BUN_BIN", "bun")` must appear exactly ONCE
    /// (only in the sigil body).
    ///
    /// Pre-lift the two consumer sites — the `bun install
    /// --frozen-lockfile` preamble at Step 2 and the `bun x
    /// graphql-codegen` capture at Step 3 — shared one
    /// `let bun = get_tool_path("BUN_BIN", "bun");` binding. Post-lift
    /// the binding is `let bun = bun_bin();` and the two-argument
    /// resolve appears in exactly ONE place (the sigil body). Same
    /// three-invariant discipline the sibling `<tool>_bin()` shields
    /// enforce on `commands/frontend_validation.rs::bun_bin`
    /// (9986f11), `commands/e2e.rs::bun_bin`,
    /// `commands/test_ci.rs::cargo_bin`, and every other migrated
    /// module.
    ///
    /// A Nix-hermetic runner whose derivation exports
    /// `BUN_BIN=/nix/store/…-bun/bin/bun` but omits `bun` from PATH
    /// silently fell through to whatever `bun` was first on PATH at
    /// each pre-lift site — the codegen verdict was attributed to
    /// whichever `bun` PATH resolved first, not to the substrate-pinned
    /// bun derivation the flake declared. Same silent-PATH-fallback
    /// bug class the sibling
    /// `commands/frontend_validation.rs::bun_bin` shield closes for
    /// the pre-release frontend-validation surface, here closed for
    /// the schema-export + codegen surface.
    ///
    /// The two-argument-resolve needle is reconstructed via `format!`
    /// inside
    /// [`crate::test_support::get_tool_path_two_arg_call_needle`], so
    /// this shield's own source never contains the literal
    /// `get_tool_path("BUN_BIN", "bun")` string and cannot false-match
    /// itself on the count-eq-1 assertion. The scan bounds run from
    /// file start to the FIRST `\n#[cfg(test)]\n` marker (this test
    /// module's own opener), so every current or future bun-spawning
    /// helper landing anywhere in the top-level module body cannot
    /// silently ride along without going through `bun_bin()`.
    #[test]
    fn test_codegen_routes_bun_through_bun_bin_sigil_not_raw_command() {
        crate::test_support::assert_source_routes_bare_spawn_through_sigil_bin_fn_at_exactly_one_resolve(
            include_str!("codegen.rs"),
            "commands/codegen.rs",
            "bun",
            "BUN_BIN",
        );
    }

    #[test]
    fn test_codegen_result() {
        let result = CodegenResult {
            schema_exported: true,
            schema_size: 5000,
            codegen_completed: true,
            schema_path: "/tmp/schema.graphql".to_string(),
        };
        assert!(result.schema_exported);
        assert!(result.codegen_completed);
    }

    /// Regression-shield: `execute` MUST route the bun-install spawn
    /// through the canonical `crate::retry::run_capture_anyhow`
    /// primitive rather than re-spell the pre-lift
    /// `Command::new(&bun).args(...).output().await.with_context(...)?`
    /// followed by
    /// `if !install_output.status.success() { let stderr = ...; bail!("bun install failed:\n{}", stderr); }`
    /// seven-line stanza.
    ///
    /// The pre-lift bail message dropped the exit code — someone seeing
    /// `"bun install failed:"` on a hermetic runner had no way to tell
    /// whether bun exited 1 (a real lockfile mismatch), 127 (bun not on
    /// PATH, i.e. a substrate wiring bug), or was killed by a signal
    /// (an OOM on the runner). Post-lift the canonical
    /// `"bun install failed (exit {code}): {stderr}"` envelope emerges
    /// by construction at `retry::classify_capture_anyhow`, and the
    /// spawn-arm `.with_context(|| format!("bun install in {}",
    /// web_dir.display()))` retains the web_dir hint the pre-lift
    /// `with_context` carried.
    ///
    /// # Scan bounds
    ///
    /// Bounded to the `execute` function body — from
    /// `pub async fn execute(` to the next top-level `pub` marker
    /// (`pub async fn export_schema_only(`) — so:
    ///
    /// - The sibling `graphql-codegen` bail path at the same fn
    ///   (line 124-128 pre-this-commit) — which legitimately keeps
    ///   its custom `"GraphQL codegen failed:\n{stderr}\n{stdout}"`
    ///   shape carrying BOTH stderr AND stdout, and therefore does
    ///   NOT fit the primitive's `(op, exit_code, stderr)`-only
    ///   envelope — stays out of scope.
    /// - The migration-inline commentary above the migrated site
    ///   (which quotes the pre-lift bail literal for narrative
    ///   purposes) rides INSIDE the fn body, so the shield's
    ///   forbidden-literal check must exclude those comment lines —
    ///   handled here by choosing a needle (`bail!(\"bun install
    ///   failed:`) that appears only at a code line, not inside
    ///   `//` prose (the commentary spells the literal with a
    ///   `bail!("bun install failed:\n{}", stderr);` form, which
    ///   contains the escaped-newline `\\n` and thus does not match
    ///   the shield needle's `bail!(\"bun install failed:` (with
    ///   the colon-then-anything continuation).
    ///
    /// Actually to be safe against future edits to the commentary,
    /// the shield uses `code_line_hits` to filter out `//` lines
    /// automatically — the same anti-docstring-self-match discipline
    /// the sibling `<tool>_bin` sigil shields (nix_builder.rs's
    /// nc_bin, comprehensive_release.rs's cargo_bin, etc.) enforce.
    #[test]
    fn test_execute_bun_install_routes_through_run_capture_anyhow_not_inline_bail() {
        const SOURCE: &str = include_str!("codegen.rs");
        let body = crate::test_support::fn_body_slice_between_markers(
            SOURCE,
            "commands/codegen.rs::execute",
            "pub async fn execute(",
            "\npub async fn export_schema_only(",
        );

        // Forbid the pre-lift bail literal at a CODE line — a doc line
        // (`//` prose) mentioning the pre-lift shape for narrative
        // purposes must not false-match. Same discipline the
        // sibling `<tool>_bin` sigil shields use.
        let forbidden = "bail!(\"bun install failed:";
        let inline_hits = crate::test_support::code_line_hits(body, forbidden);
        assert!(
            inline_hits.is_empty(),
            "commands/codegen.rs::execute must not carry an inline \
             `bail!(\"bun install failed:...\")` terminator — the bun \
             install spawn must route through \
             `crate::retry::run_capture_anyhow`, which emits the \
             canonical `\"bun install failed (exit {{code}}): {{stderr}}\"` \
             envelope with the exit code carried. Found: {inline_hits:?}"
        );

        let delegation = "run_capture_anyhow(";
        let delegation_hits = crate::test_support::code_line_hits(body, delegation);
        assert!(
            !delegation_hits.is_empty(),
            "commands/codegen.rs::execute must delegate the bun install \
             spawn through `crate::retry::run_capture_anyhow` — the \
             delegation call was not found at any code line in the fn \
             body. A regression that both dropped the delegation AND \
             accidentally left the forbidden-literal shield satisfied \
             (e.g. by rewriting the bail into a `bail!(\"failed\")` \
             shape without the pre-lift colon suffix) fails here."
        );
    }
}
