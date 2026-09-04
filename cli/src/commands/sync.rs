//! One-Command Sync Pipeline
//!
//! Propagates changes from SSoT (Rust backend) through the entire stack:
//!   Database Migrations → SeaORM Entities → GraphQL Schema → Frontend Types/Hooks
//!
//! This module implements the sync-all functionality in pure Rust, replacing
//! the shell script with type-safe, testable code.
//!
//! Usage:
//!   forge sync --working-dir /path/to/product
//!   forge sync --working-dir /path/to/product --schema-only
//!   forge sync --working-dir /path/to/product --check

use anyhow::{bail, Context, Result};
use colored::Colorize;
use std::path::{Path, PathBuf};
use std::time::Instant;
use tokio::fs;
use tokio::process::Command;

use super::codegen;
use crate::repo::get_tool_path;

/// Resolve the `bun` binary via the `BUN_BIN` env override, falling back
/// to `bun` on `PATH`. Wired through [`crate::repo::get_tool_path`] —
/// the canonical env-var-or-PATH lookup every bun-invocation site in
/// forge honors. Landing of the `bun_bin()` sigil onto
/// `commands/sync.rs` alongside the sibling landings on
/// `commands/frontend_validation.rs::bun_bin` (9986f11),
/// `commands/e2e.rs::bun_bin`, `commands/codegen.rs::bun_bin`, and
/// `commands/codegen_validation.rs::bun_bin` — the pattern is proven;
/// this module was one of the three remaining call sites (with
/// `commands/codegen.rs` and `commands/codegen_validation.rs`) still
/// respelling the two-argument `BUN_BIN` resolve inline at its bun
/// spawns.
///
/// Solve-once at the sigil (THEORY §I.5 — duplication budget zero;
/// every recurring shape becomes a helper before it becomes duplicated
/// code) means a future added `bun` spawn in this module cannot
/// silently re-copy the two-argument resolve and drift away from the
/// `BUN_BIN` override at exactly the tier the hermetic-runner contract
/// binds — the `forge sync --check` codegen-drift branch whose
/// verdict decides whether generated frontend types are considered
/// fresh against the backend SSoT, where a wrong-`bun` resolve
/// produces a drift verdict attributed to whichever `bun` PATH
/// resolved first rather than to the substrate-pinned `bun`
/// derivation the flake declared. The whole-module shield below
/// asserts three invariants via
/// [`crate::test_support::assert_source_routes_bare_spawn_through_sigil_bin_fn_at_exactly_one_resolve`]:
/// no bare-literal `bun` spawn in the module body, `fn bun_bin()` is
/// defined, and the two-argument resolve appears in EXACTLY one place
/// — only the sigil body.
fn bun_bin() -> String {
    get_tool_path("BUN_BIN", "bun")
}

/// Configuration for sync operation
#[derive(Debug, Clone)]
pub struct SyncConfig {
    /// Working directory (product root)
    pub working_dir: PathBuf,
    /// Backend service directory
    pub backend_dir: PathBuf,
    /// Web frontend directory
    pub web_dir: PathBuf,
    /// Migrations directory
    pub migrations_dir: PathBuf,
    /// Entities directory
    pub entities_dir: PathBuf,
    /// Schema output file
    pub schema_file: PathBuf,
}

impl SyncConfig {
    pub fn from_working_dir(working_dir: &Path) -> Self {
        let backend_dir = working_dir.join("services/rust/backend");
        Self {
            working_dir: working_dir.to_path_buf(),
            backend_dir: backend_dir.clone(),
            web_dir: working_dir.join("web"),
            migrations_dir: backend_dir.join("migrations"),
            entities_dir: backend_dir.join("src/entities"),
            schema_file: working_dir.join("web/schema.graphql"),
        }
    }
}

/// Result of sync operation
#[derive(Debug)]
pub struct SyncResult {
    /// Number of migration files found
    pub migration_count: usize,
    /// Schema was exported successfully
    pub schema_exported: bool,
    /// Schema size in bytes
    pub schema_size: usize,
    /// Codegen completed successfully
    pub codegen_completed: bool,
    /// ReBAC validation passed
    pub rebac_valid: bool,
    /// Total duration
    pub duration_secs: f64,
    /// Errors encountered
    pub errors: Vec<String>,
}

/// Result of drift check
#[derive(Debug)]
pub struct DriftCheckResult {
    /// Schema has drift
    pub schema_drift: bool,
    /// Codegen has drift
    pub codegen_drift: bool,
    /// Error message if any
    pub error: Option<String>,
}

/// Execute schema-only export
pub async fn execute_schema_only(working_dir: &Path) -> Result<()> {
    let config = SyncConfig::from_working_dir(working_dir);

    crate::ui::print_section_header("Schema Export");

    codegen::export_schema_only(&config.backend_dir, &config.schema_file).await?;

    println!();
    println!(
        "{}",
        format!("Schema exported to {}", config.schema_file.display())
            .green()
            .bold()
    );

    Ok(())
}

/// Execute drift check (CI mode)
pub async fn execute_drift_check(working_dir: &Path) -> Result<DriftCheckResult> {
    let config = SyncConfig::from_working_dir(working_dir);

    crate::ui::print_section_header("Drift Check (CI Mode)");

    // Calculate current schema hash
    let old_schema_hash = if config.schema_file.exists() {
        let content = fs::read(&config.schema_file).await?;
        format!("{:x}", md5::compute(&content))
    } else {
        String::new()
    };

    // Calculate current codegen hash
    let gql_dir = config.web_dir.join("src/gql");
    let old_codegen_hash = if gql_dir.exists() {
        calculate_directory_hash(&gql_dir).await?
    } else {
        String::new()
    };

    println!("Extracting schema...");

    // Route through the canonical `extract_graphql_schema` primitive
    // (THEORY §V.1, §VI.1): pre-lift this site was the sixth raw-spawn
    // stanza the 673e4be / b02d4eb sweeps did not catch. Post-lift the
    // three failure shapes (`SpawnFailed` / `Failed` / `EmptyOutput`)
    // are structurally distinct in the primitive AND collapse into the
    // `error: Some(String)` field this DriftCheckResult already
    // surfaces. Two load-bearing bugs the raw stanza carried and this
    // lift redeems: (1) it spelled `Command::new("cargo")` bypassing
    // the `CARGO` env override honored by `commands/bootstrap.rs` via
    // `get_tool_path("CARGO", "cargo")` — so a Nix-hermetic runner
    // with a store-path cargo would fall through to whatever `cargo`
    // was first on PATH; (2) it had no empty-stdout guard — an
    // extractor that exited zero with empty stdout would hash to
    // `md5("")` = `d41d8cd98f00b204e9800998ecf8427e` and either
    // report false-positive "drift detected" (against a non-empty
    // stored schema) or, if the stored schema file was also missing/
    // empty, silently report "in sync" — a caught-nowhere corruption
    // of the drift-check contract.
    let schema_bytes =
        match crate::graphql_schema::extract_graphql_schema(&config.backend_dir).await {
            Ok(bytes) => bytes,
            Err(err) => {
                return Ok(DriftCheckResult {
                    schema_drift: false,
                    codegen_drift: false,
                    error: Some(format!("Schema extraction failed: {}", err)),
                });
            }
        };

    // Check schema drift
    let new_schema_hash = format!("{:x}", md5::compute(&schema_bytes));
    let schema_drift = !old_schema_hash.is_empty() && old_schema_hash != new_schema_hash;

    if schema_drift {
        crate::ui::print_step_failure("Schema drift detected!");
        println!("   Run 'nix run .#codegen' to sync schema");
        return Ok(DriftCheckResult {
            schema_drift: true,
            codegen_drift: false,
            error: None,
        });
    }
    crate::ui::print_step_check("Schema in sync");

    // Run codegen
    println!("Running codegen drift check...");

    // Install deps first
    let bun = bun_bin();
    let install_output = Command::new(&bun)
        .args(["install", "--frozen-lockfile"])
        .current_dir(&config.web_dir)
        .output()
        .await
        .context("Failed to run bun install")?;

    if !install_output.status.success() {
        return Ok(DriftCheckResult {
            schema_drift: false,
            codegen_drift: false,
            error: Some("bun install failed".to_string()),
        });
    }

    // Run codegen
    let codegen_output = Command::new(&bun)
        .args(["x", "graphql-codegen", "--config", "codegen.ts"])
        .current_dir(&config.web_dir)
        .output()
        .await
        .context("Failed to run graphql-codegen")?;

    if !codegen_output.status.success() {
        return Ok(DriftCheckResult {
            schema_drift: false,
            codegen_drift: false,
            error: Some("codegen failed".to_string()),
        });
    }

    // Check codegen drift
    let new_codegen_hash = if gql_dir.exists() {
        calculate_directory_hash(&gql_dir).await?
    } else {
        String::new()
    };

    let codegen_drift = !old_codegen_hash.is_empty() && old_codegen_hash != new_codegen_hash;

    if codegen_drift {
        crate::ui::print_step_failure("Codegen drift detected!");
        println!("   Generated types are out of sync with schema");
        println!("   Run 'nix run .#codegen' to regenerate");
        return Ok(DriftCheckResult {
            schema_drift: false,
            codegen_drift: true,
            error: None,
        });
    }
    crate::ui::print_step_check("Codegen in sync");

    println!();
    println!(
        "{}",
        "✅ No drift detected. All files in sync.".green().bold()
    );

    Ok(DriftCheckResult {
        schema_drift: false,
        codegen_drift: false,
        error: None,
    })
}

/// Execute full sync pipeline
pub async fn execute(working_dir: &Path, skip_entities: bool) -> Result<SyncResult> {
    let start = Instant::now();
    let config = SyncConfig::from_working_dir(working_dir);
    let mut errors = Vec::new();

    crate::ui::print_section_header("One-Command Sync Pipeline");

    // Verify we're in the right place
    if !config.working_dir.join("flake.nix").exists()
        || !config.working_dir.join("Cargo.lock").exists()
    {
        bail!(
            "Not in project directory. Expected to find flake.nix and Cargo.lock at {}",
            config.working_dir.display()
        );
    }

    // Step 1: Check migrations
    crate::ui::print_step_heading("Step 1: Check pending migrations");
    let migration_count = count_migrations(&config.migrations_dir).await;
    println!("   Found {} migration files", migration_count);
    println!();

    // Step 2: SeaORM Entity Generation (if enabled)
    crate::ui::print_step_heading("Step 2: SeaORM Entity Generation");
    if skip_entities {
        crate::ui::print_step_skip("Skipped via --skip-entities");
    } else {
        match generate_entities(&config).await {
            Ok(generated) => {
                if generated {
                    crate::ui::print_step_check("Entities generated");
                } else {
                    crate::ui::print_step_skip(
                        "Skipped (DATABASE_URL not set or sea-orm-cli not found)",
                    );
                }
            }
            Err(e) => {
                println!("   {} Entity generation failed: {}", "!".yellow(), e);
            }
        }
    }
    println!();

    // Step 3: Run full codegen pipeline
    println!(
        "{}",
        "Step 3: GraphQL Schema Export + Frontend Codegen".bold()
    );
    let codegen_result = codegen::execute(&config.backend_dir, &config.web_dir).await;

    let (schema_exported, schema_size, codegen_completed) = match codegen_result {
        Ok(result) => (
            result.schema_exported,
            result.schema_size,
            result.codegen_completed,
        ),
        Err(e) => {
            errors.push(format!("Codegen failed: {}", e));
            (false, 0, false)
        }
    };
    println!();

    // Step 4: Verify generated files
    crate::ui::print_step_heading("Step 4: Verify Generated Files");

    // Check schema
    if config.schema_file.exists() {
        let metadata = fs::metadata(&config.schema_file).await?;
        if metadata.len() > 0 {
            crate::ui::print_step_check(&format!("schema.graphql ({} bytes)", metadata.len()));
        } else {
            println!("   {} schema.graphql missing or empty", "✗".red());
            errors.push("schema.graphql missing or empty".to_string());
        }
    } else {
        println!("   {} schema.graphql missing", "✗".red());
        errors.push("schema.graphql missing".to_string());
    }

    // Check gql directory
    let gql_dir = config.web_dir.join("src/gql");
    if gql_dir.exists() {
        let file_count = count_ts_files(&gql_dir).await;
        crate::ui::print_step_check(&format!("src/gql/ ({} TypeScript files)", file_count));
    } else {
        println!("   {} src/gql/ directory missing", "✗".red());
        errors.push("src/gql/ directory missing".to_string());
    }

    // Check hooks.ts
    let hooks_file = gql_dir.join("hooks.ts");
    if hooks_file.exists() {
        let metadata = fs::metadata(&hooks_file).await?;
        let line_count = count_lines(&hooks_file).await.unwrap_or(0);
        crate::ui::print_step_check(&format!("src/gql/hooks.ts ({} lines)", line_count));
    } else {
        println!(
            "   {} src/gql/hooks.ts missing (may need operations defined)",
            "!".yellow()
        );
    }
    println!();

    // Step 5: ReBAC validation
    crate::ui::print_step_heading("Step 5: ReBAC Validation");
    let rebac_valid = match super::rebac_validation::execute(working_dir, true).await {
        Ok(result) => {
            if result.all_passed() {
                crate::ui::print_step_check("ReBAC validation passed");
                true
            } else {
                println!(
                    "   {} ReBAC validation: {} errors, {} warnings",
                    "!".yellow(),
                    result.errors,
                    result.warnings
                );
                false
            }
        }
        Err(e) => {
            crate::ui::print_step_skip(&format!("ReBAC validation skipped: {}", e));
            true // Don't fail on validation errors
        }
    };
    println!();

    // Summary
    let duration = start.elapsed().as_secs_f64();

    if errors.is_empty() {
        crate::ui::print_section_completion_banner(
            &format!("Sync Complete - All checks passed ({:.1}s)", duration),
            crate::ui::SectionCompletionStyle::Success,
        );
    } else {
        crate::ui::print_section_completion_banner(
            &format!(
                "Sync Complete - {} errors found ({:.1}s)",
                errors.len(),
                duration
            ),
            crate::ui::SectionCompletionStyle::Failure,
        );
    }
    println!();

    crate::ui::print_next_steps_heading();
    println!("  1. Review generated files in web/src/gql/");
    println!("  2. Run 'cd web && bun run type-check' to verify types");
    println!("  3. Run 'nix run .#release' for full release");

    Ok(SyncResult {
        migration_count,
        schema_exported,
        schema_size,
        codegen_completed,
        rebac_valid,
        duration_secs: duration,
        errors,
    })
}

/// Count migration files
async fn count_migrations(migrations_dir: &Path) -> usize {
    if !migrations_dir.exists() {
        return 0;
    }

    let mut count = 0;
    if let Ok(mut entries) = tokio::fs::read_dir(migrations_dir).await {
        while let Ok(Some(entry)) = entries.next_entry().await {
            if let Some(name) = entry.file_name().to_str() {
                if name.ends_with(".sql") {
                    count += 1;
                }
            }
        }
    }
    count
}

/// Probe whether the `sea-orm-cli` binary is invocable.
///
/// Fast path: if `SEA_ORM_CLI_BIN` is exported (typically by a nix-hermetic
/// runner's `mkRuntimeToolsEnv`), the substrate has already resolved and
/// pinned the binary — trust that and skip the PATH probe. Falling through
/// to a PATH probe in that world would falsely report "not available"
/// whenever bare `sea-orm-cli` isn't on PATH (the norm for nix-shell
/// derivations, which only export the specific tool paths a derivation
/// declares), silently skipping SeaORM entity generation even though the
/// substrate-pinned binary is present. Mirrors the
/// `check_novasearchctl_available` probe in `commands/search_sync.rs`
/// (19463db) — the same probe/spawn alignment discipline: whatever the
/// probe says "yes" to is what the spawn actually invokes.
///
/// Fallback: probe PATH via the `which` crate for the mixed / non-Nix
/// development environment where `SEA_ORM_CLI_BIN` is unset. Uses
/// `which::which(...)` — the same crate-backed idiom the sibling probes in
/// `commands/test_ci.rs` (`cargo-nextest`, `cargo-tarpaulin`),
/// `commands/rust_service.rs` (`qemu-aarch64-static`), and
/// `commands/tool.rs` (`crate2nix`) already ride on — rather than a
/// subprocess spawn on the `which` binary, so there is no ambient
/// dependency on a `which` binary existing on PATH itself. This matters on
/// minimal Nix containers whose derivation only exports the specific tool
/// paths declared, where a `which` subprocess spawn would fail-to-exec
/// entirely and the probe would silently report `false` for that reason
/// alone.
async fn check_sea_orm_cli_available() -> bool {
    if std::env::var("SEA_ORM_CLI_BIN").is_ok() {
        return true;
    }
    which::which("sea-orm-cli").is_ok()
}

/// Generate SeaORM entities from database
///
/// Resolves the binary via the canonical two-argument tools-registry idiom
/// `crate::repo::get_tool_path("SEA_ORM_CLI_BIN", "sea-orm-cli")` — the
/// same shape the sibling `commands/typescript.rs::regenerate` (5d87339)
/// and `commands/search_sync.rs::run_sync_direct` (19463db) already ride
/// on. A Nix-hermetic runner's substrate-derived `SEA_ORM_CLI_BIN` path
/// is honored; the bare-`"sea-orm-cli"` fallback preserves non-Nix
/// behavior.
async fn generate_entities(config: &SyncConfig) -> Result<bool> {
    if !check_sea_orm_cli_available().await {
        return Ok(false);
    }

    // Check for DATABASE_URL
    let database_url = crate::repo::env_var_optional("DATABASE_URL");
    if database_url.is_none() {
        return Ok(false);
    }

    let sea_orm_cli = get_tool_path("SEA_ORM_CLI_BIN", "sea-orm-cli");

    // Generate entities
    let _output = crate::retry::classify_capture_anyhow(
        Command::new(&sea_orm_cli)
            .args([
                "generate",
                "entity",
                "-u",
                &database_url.unwrap(),
                "-o",
                "src/entities",
                "--entity-format",
                "dense",
                "--with-serde",
                "both",
            ])
            .current_dir(&config.backend_dir)
            .output()
            .await,
        "sea-orm-cli generate entity",
    )?;

    Ok(true)
}

/// Count TypeScript files in a directory
async fn count_ts_files(dir: &Path) -> usize {
    let mut count = 0;
    if let Ok(mut entries) = tokio::fs::read_dir(dir).await {
        while let Ok(Some(entry)) = entries.next_entry().await {
            if let Some(name) = entry.file_name().to_str() {
                if name.ends_with(".ts") || name.ends_with(".tsx") {
                    count += 1;
                }
            }
        }
    }
    count
}

/// Count lines in a file
async fn count_lines(path: &Path) -> Result<usize> {
    let content = crate::repo::read_text_async(path).await?;
    Ok(content.lines().count())
}

/// Calculate MD5 hash of all files in a directory
async fn calculate_directory_hash(dir: &Path) -> Result<String> {
    use std::collections::BTreeMap;

    let mut file_hashes: BTreeMap<String, String> = BTreeMap::new();

    fn visit_dir(dir: &Path, file_hashes: &mut BTreeMap<String, String>) -> std::io::Result<()> {
        if dir.is_dir() {
            for entry in std::fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_dir() {
                    visit_dir(&path, file_hashes)?;
                } else if let Some(name) = crate::repo::file_name_opt_str(&path) {
                    if name.ends_with(".ts") || name.ends_with(".tsx") {
                        let content = std::fs::read(&path)?;
                        let hash = format!("{:x}", md5::compute(&content));
                        file_hashes.insert(crate::repo::path_to_string_lossy(&path), hash);
                    }
                }
            }
        }
        Ok(())
    }

    visit_dir(dir, &mut file_hashes)?;

    // Combine all hashes into one
    let combined: String = file_hashes.values().cloned().collect::<Vec<_>>().join("");

    Ok(format!("{:x}", md5::compute(combined.as_bytes())))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Whole-module shield: no raw `Command::new("bun")` may live in
    /// `commands/sync.rs`'s non-test body, `fn bun_bin()` must be
    /// defined, and the two-argument resolve
    /// `get_tool_path("BUN_BIN", "bun")` must appear exactly ONCE
    /// (only in the sigil body).
    ///
    /// Pre-lift the two consumer sites — the `bun install
    /// --frozen-lockfile` install-deps preamble and the
    /// `bun x graphql-codegen` capture inside `check_drift`'s codegen
    /// arm — shared one `let bun = get_tool_path("BUN_BIN", "bun");`
    /// binding. Post-lift the binding is `let bun = bun_bin();` and
    /// the two-argument resolve appears in exactly ONE place (the
    /// sigil body). Same three-invariant discipline the sibling
    /// `<tool>_bin()` shields enforce on
    /// `commands/frontend_validation.rs::bun_bin` (9986f11),
    /// `commands/e2e.rs::bun_bin`,
    /// `commands/codegen.rs::bun_bin`,
    /// `commands/codegen_validation.rs::bun_bin`, and every other
    /// migrated module.
    ///
    /// A Nix-hermetic runner whose derivation exports
    /// `BUN_BIN=/nix/store/…-bun/bin/bun` but omits `bun` from PATH
    /// silently fell through to whatever `bun` was first on PATH at
    /// each pre-lift site — the `forge sync --check` drift verdict
    /// was attributed to whichever `bun` PATH resolved first, not to
    /// the substrate-pinned bun derivation the flake declared. Same
    /// silent-PATH-fallback bug class the sibling
    /// `commands/frontend_validation.rs::bun_bin` shield closes for
    /// the pre-release frontend-validation surface, here closed for
    /// the sync-pipeline drift-detection surface.
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
    fn test_sync_routes_bun_through_bun_bin_sigil_not_raw_command() {
        crate::test_support::assert_source_routes_bare_spawn_through_sigil_bin_fn_at_exactly_one_resolve(
            include_str!("sync.rs"),
            "commands/sync.rs",
            "bun",
            "BUN_BIN",
        );
    }

    #[test]
    fn test_sync_config() {
        let config = SyncConfig::from_working_dir(Path::new("/tmp/testapp"));
        assert_eq!(
            config.backend_dir,
            PathBuf::from("/tmp/testapp/services/rust/backend")
        );
        assert_eq!(config.web_dir, PathBuf::from("/tmp/testapp/web"));
        assert_eq!(
            config.schema_file,
            PathBuf::from("/tmp/testapp/web/schema.graphql")
        );
    }

    /// Whole-module shield: no bare `sea-orm-cli` literal spawn may live
    /// in `commands/sync.rs`. The sole spawn — the `sea-orm-cli generate
    /// entity …` step at the heart of `generate_entities` — must resolve
    /// through the tools-registry two-argument idiom
    /// `crate::repo::get_tool_path("SEA_ORM_CLI_BIN", "sea-orm-cli")`
    /// first, so a Nix-hermetic runner's substrate-derived
    /// `SEA_ORM_CLI_BIN` path is honored just as the sibling
    /// `commands/search_sync.rs::run_sync_direct` (19463db) and
    /// `commands/typescript.rs::regenerate` (5d87339) already do.
    ///
    /// Pre-lift the site spelled the bare tool-name literal verbatim —
    /// a Nix-hermetic runner's substrate-derived sea-orm-cli path was
    /// lost to whatever binary sat first on PATH — and, worse, the
    /// sibling `which`-based availability probe would report "not
    /// available" in a nix-hermetic env where bare `sea-orm-cli` isn't
    /// on PATH even though `SEA_ORM_CLI_BIN` was exported, silently
    /// skipping SeaORM entity generation entirely. This shield pins
    /// the direct-path spawn onto the substrate-exported env var; the
    /// sibling probe was rewritten in the same lift to short-circuit
    /// on `SEA_ORM_CLI_BIN` before falling through to the PATH probe,
    /// so the two halves stay aligned.
    ///
    /// The `sea-orm-cli` string literal still appears in this module
    /// as (a) the `which` probe's argument name at the fallback path
    /// (`check_sea_orm_cli_available`, PATH-probe body only), (b) the
    /// diagnostic `println!` labels and `.context(...)` message, and
    /// (c) the docstring text above — none of which are local spawns
    /// of the binary. The shield forbids only the fused
    /// `Command::new(<bare>)` shape, reconstructed via
    /// [`format!`] so the shield's own source text does not
    /// false-match itself; the whole-module scan therefore covers both
    /// the top-of-file production body AND every sibling
    /// `#[cfg(test)]` block. Also asserts the canonical
    /// `get_tool_path("SEA_ORM_CLI_BIN", "sea-orm-cli")` lookup form
    /// is present in the module, so the sigil-body itself cannot
    /// silently drift away from the substrate-exported env-var
    /// contract.
    #[test]
    fn test_sea_orm_cli_spawn_routes_through_sea_orm_cli_bin_not_raw_literal() {
        const SOURCE: &str = include_str!("sync.rs");

        crate::test_support::assert_source_forbids_bare_spawn_shapes(
            SOURCE,
            "commands/sync.rs",
            "sea-orm-cli",
            "resolve the substrate-exported `SEA_ORM_CLI_BIN` env override \
             via `crate::repo::get_tool_path(\"SEA_ORM_CLI_BIN\", \"sea-orm-cli\")`",
        );

        crate::test_support::assert_source_has_get_tool_path_two_arg_call_code_line(
            SOURCE,
            "commands/sync.rs",
            "SEA_ORM_CLI_BIN",
            "sea-orm-cli",
        );
    }

    /// Whole-module shield: no bare `which`-binary spawn (a raw
    /// `Command::new` on the bare tool-name literal) may live in
    /// `commands/sync.rs`. The PATH-probe fallback in
    /// `check_sea_orm_cli_available` must resolve through the
    /// `which::which(...)` crate idiom, the same shape the sibling probes
    /// in `commands/test_ci.rs` (`cargo-nextest`, `cargo-tarpaulin`),
    /// `commands/rust_service.rs` (`qemu-aarch64-static`), and
    /// `commands/tool.rs` (`crate2nix`) already ride on.
    ///
    /// Pre-lift the probe spawned a `which` subprocess via the bare
    /// tool-name literal — a fork+exec that added an ambient dependency
    /// on a `which` binary existing on PATH itself. On a minimal Nix
    /// container whose derivation only exports the specific tool paths
    /// declared, the `which` binary is absent and the spawn
    /// fails-to-exec entirely, so the probe silently reports `false`
    /// for that reason alone — the exact same silent-false failure mode
    /// the sibling `SEA_ORM_CLI_BIN` fast-path was written to bypass,
    /// only one layer of ambient dependency deeper. Post-lift the probe
    /// resolves PATH in-process via the `which` crate; no fork+exec, no
    /// ambient binary, no silent false.
    ///
    /// The forbidden shape is reconstructed at test time via [`format!`]
    /// so this shield's own source text does not false-match itself,
    /// and the docstring above uses `which`-binary paraphrase rather
    /// than the literal shape for the same reason; the whole-module
    /// scan therefore covers both the top-of-file production body AND
    /// every sibling `#[cfg(test)]` block. Also asserts the canonical
    /// `which::which(...)` crate idiom is present in the module, so
    /// the sigil-body itself cannot silently drift back to a
    /// subprocess spawn.
    #[test]
    fn test_which_probe_routes_through_which_crate_not_command_spawn() {
        const SOURCE: &str = include_str!("sync.rs");

        crate::test_support::assert_source_forbids_bare_spawn_shapes(
            SOURCE,
            "commands/sync.rs",
            "which",
            "resolve through the in-process `which::which(...)` crate idiom",
        );
        crate::test_support::assert_source_probes_via_which_which_code_line(
            SOURCE,
            "commands/sync.rs",
            "sea-orm-cli",
        );
    }

    /// Captured-output routing shield scoped to `generate_entities`'s
    /// fn body: the sole
    /// `if !output.status.success() { bail!("Entity generation failed: {stderr}") }`
    /// stanza in the fn — the module's sole bail-drops-exit-code
    /// captured-output site — MUST route through
    /// [`crate::retry::classify_capture_anyhow`]. Pre-lift the operator
    /// log line read `"Entity generation failed: <stderr>"` and dropped
    /// the exit code: an operator seeing the message on a `sea-orm-cli
    /// generate entity` run against a stale schema had no way to tell
    /// whether sea-orm-cli exited 1 (a real schema-inspection error),
    /// 2 (`DATABASE_URL` unreachable), or 127 (a bad `SEA_ORM_CLI_BIN`
    /// route). Post-lift the canonical `"sea-orm-cli generate entity
    /// failed (exit {code}): {stderr}"` envelope emerges by
    /// construction at the primitive's ONE body.
    ///
    /// Scope is `generate_entities`'s fn body (via
    /// [`crate::test_support::fn_body_slice_between_markers`]) rather
    /// than the whole module because `check_drift` retains two
    /// legitimate `if !install_output.status.success()` /
    /// `if !codegen_output.status.success()` sites that short-circuit
    /// into `DriftCheckResult::error(...)` rather than bail — a shape
    /// the primitive intentionally does NOT cover, and a whole-module
    /// scan would false-fire on. The `end_marker` is the sibling
    /// `count_ts_files` fn signature, the first fn after
    /// `generate_entities` in module order.
    #[test]
    fn test_generate_entities_bail_routes_through_classify_capture_anyhow() {
        const SOURCE: &str = include_str!("sync.rs");
        let body = crate::test_support::fn_body_slice_between_markers(
            SOURCE,
            "commands/sync.rs",
            "async fn generate_entities(",
            "\nasync fn count_ts_files(",
        );
        crate::test_support::assert_source_routes_captured_bails_through_classify_capture_anyhow(
            body,
            "commands/sync.rs::generate_entities",
            1,
        );
    }
}
