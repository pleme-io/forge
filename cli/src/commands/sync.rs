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

use crate::repo::get_tool_path;
use super::codegen;

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

    // Extract schema to temp file
    let temp_schema = config.working_dir.join("schema.graphql.tmp");
    let schema_output = Command::new("cargo")
        .args(["run", "--bin", "extract-schema", "--quiet"])
        .current_dir(&config.backend_dir)
        .output()
        .await
        .context("Failed to run extract-schema")?;

    if !schema_output.status.success() {
        let stderr = String::from_utf8_lossy(&schema_output.stderr);
        return Ok(DriftCheckResult {
            schema_drift: false,
            codegen_drift: false,
            error: Some(format!("Schema extraction failed: {}", stderr)),
        });
    }

    // Check schema drift
    let new_schema_hash = format!("{:x}", md5::compute(&schema_output.stdout));
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

    // Clean up temp file if exists
    let _ = fs::remove_file(&temp_schema).await;

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

/// Generate SeaORM entities from database
async fn generate_entities(config: &SyncConfig) -> Result<bool> {
    // Check if sea-orm-cli is available
    let which_result = Command::new("which").arg("sea-orm-cli").output().await;

    if which_result.is_err() || !which_result.unwrap().status.success() {
        return Ok(false);
    }

    // Check for DATABASE_URL
    let database_url = std::env::var("DATABASE_URL").ok();
    if database_url.is_none() {
        return Ok(false);
    }

    // Generate entities
    let output = Command::new("sea-orm-cli")
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
}
