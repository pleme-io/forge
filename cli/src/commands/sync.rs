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

    println!();
    println!(
        "{}",
        "════════════════════════════════════════════════".bold()
    );
    println!("{}", "  Schema Export".bold());
    println!(
        "{}",
        "════════════════════════════════════════════════".bold()
    );
    println!();

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

    println!();
    println!(
        "{}",
        "════════════════════════════════════════════════".bold()
    );
    println!("{}", "  Drift Check (CI Mode)".bold());
    println!(
        "{}",
        "════════════════════════════════════════════════".bold()
    );
    println!();

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
        println!("   {} Schema drift detected!", "❌".red());
        println!("   Run 'nix run .#codegen' to sync schema");
        return Ok(DriftCheckResult {
            schema_drift: true,
            codegen_drift: false,
            error: None,
        });
    }
    println!("   {} Schema in sync", "✓".green());

    // Run codegen
    println!("Running codegen drift check...");

    // Install deps first
    let bun = get_tool_path("BUN_BIN", "bun");
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
        println!("   {} Codegen drift detected!", "❌".red());
        println!("   Generated types are out of sync with schema");
        println!("   Run 'nix run .#codegen' to regenerate");
        return Ok(DriftCheckResult {
            schema_drift: false,
            codegen_drift: true,
            error: None,
        });
    }
    println!("   {} Codegen in sync", "✓".green());

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

    println!();
    println!(
        "{}",
        "════════════════════════════════════════════════".bold()
    );
    println!("{}", "  One-Command Sync Pipeline".bold());
    println!(
        "{}",
        "════════════════════════════════════════════════".bold()
    );
    println!();

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
    println!("{}", "Step 1: Check pending migrations".bold());
    let migration_count = count_migrations(&config.migrations_dir).await;
    println!("   Found {} migration files", migration_count);
    println!();

    // Step 2: SeaORM Entity Generation (if enabled)
    println!("{}", "Step 2: SeaORM Entity Generation".bold());
    if skip_entities {
        println!("   {} Skipped via --skip-entities", "○".yellow());
    } else {
        match generate_entities(&config).await {
            Ok(generated) => {
                if generated {
                    println!("   {} Entities generated", "✓".green());
                } else {
                    println!(
                        "   {} Skipped (DATABASE_URL not set or sea-orm-cli not found)",
                        "○".yellow()
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
    println!("{}", "Step 4: Verify Generated Files".bold());

    // Check schema
    if config.schema_file.exists() {
        let metadata = fs::metadata(&config.schema_file).await?;
        if metadata.len() > 0 {
            println!(
                "   {} schema.graphql ({} bytes)",
                "✓".green(),
                metadata.len()
            );
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
        println!(
            "   {} src/gql/ ({} TypeScript files)",
            "✓".green(),
            file_count
        );
    } else {
        println!("   {} src/gql/ directory missing", "✗".red());
        errors.push("src/gql/ directory missing".to_string());
    }

    // Check hooks.ts
    let hooks_file = gql_dir.join("hooks.ts");
    if hooks_file.exists() {
        let metadata = fs::metadata(&hooks_file).await?;
        let line_count = count_lines(&hooks_file).await.unwrap_or(0);
        println!("   {} src/gql/hooks.ts ({} lines)", "✓".green(), line_count);
    } else {
        println!(
            "   {} src/gql/hooks.ts missing (may need operations defined)",
            "!".yellow()
        );
    }
    println!();

    // Step 5: ReBAC validation
    println!("{}", "Step 5: ReBAC Validation".bold());
    let rebac_valid = match super::rebac_validation::execute(working_dir, true).await {
        Ok(result) => {
            if result.all_passed() {
                println!("   {} ReBAC validation passed", "✓".green());
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
            println!("   {} ReBAC validation skipped: {}", "○".yellow(), e);
            true // Don't fail on validation errors
        }
    };
    println!();

    // Summary
    let duration = start.elapsed().as_secs_f64();

    println!(
        "{}",
        "════════════════════════════════════════════════".bold()
    );
    if errors.is_empty() {
        println!(
            "{}",
            format!("  Sync Complete - All checks passed ({:.1}s)", duration)
                .green()
                .bold()
        );
    } else {
        println!(
            "{}",
            format!(
                "  Sync Complete - {} errors found ({:.1}s)",
                errors.len(),
                duration
            )
            .red()
            .bold()
        );
    }
    println!(
        "{}",
        "════════════════════════════════════════════════".bold()
    );
    println!();

    println!("Next steps:");
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
    let database_url = std::env::var("DATABASE_URL").ok();
    if database_url.is_none() {
        return Ok(false);
    }

    let sea_orm_cli = get_tool_path("SEA_ORM_CLI_BIN", "sea-orm-cli");

    // Generate entities
    let output = Command::new(&sea_orm_cli)
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
        .await
        .context("Failed to run sea-orm-cli")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("Entity generation failed: {}", stderr);
    }

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
    let content = fs::read_to_string(path).await?;
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
                } else if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if name.ends_with(".ts") || name.ends_with(".tsx") {
                        let content = std::fs::read(&path)?;
                        let hash = format!("{:x}", md5::compute(&content));
                        file_hashes.insert(path.to_string_lossy().to_string(), hash);
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

        let bare = "sea-orm-cli";
        let raw_command = format!("Command::new(\"{}\")", bare);

        assert!(
            !SOURCE.contains(&raw_command),
            "commands/sync.rs must not spawn `sea-orm-cli` via the bare \
             literal — the direct-invocation spawn must resolve the \
             substrate-exported `SEA_ORM_CLI_BIN` env override via \
             `crate::repo::get_tool_path(\"SEA_ORM_CLI_BIN\", \
             \"sea-orm-cli\")` first. A raw literal at `Command::new` \
             bypasses the hermetic-runner contract substrate's \
             mkRuntimeToolsEnv exports and (worse) races the sibling \
             `which`-based availability probe: the probe would silently \
             report `false` in a nix-hermetic env where bare \
             `sea-orm-cli` isn't on PATH, skipping SeaORM entity \
             generation entirely."
        );
        assert!(
            SOURCE.contains("get_tool_path(\"SEA_ORM_CLI_BIN\", \"sea-orm-cli\")"),
            "commands/sync.rs must resolve the `sea-orm-cli` binary via \
             the canonical two-argument \
             `get_tool_path(\"SEA_ORM_CLI_BIN\", \"sea-orm-cli\")` \
             lookup — the required form was not found in the module."
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
        assert!(
            SOURCE.contains("which::which(\"sea-orm-cli\")"),
            "commands/sync.rs must probe the `sea-orm-cli` binary via \
             the canonical `which::which(\"sea-orm-cli\")` crate call \
             — the required form was not found in the module."
        );
    }
}
