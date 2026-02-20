//! Codegen Drift Detection Gate
//!
//! This module validates that GraphQL codegen is in sync with the backend schema.
//! It detects drift between:
//! - Backend schema (from extract-schema binary)
//! - Generated TypeScript types (from GraphQL Code Generator)
//!
//! Part of the pre-release gate system.
//!
//! ## Auto-commit Feature
//!
//! When codegen produces changes, they are automatically committed to ensure
//! the deployed code matches the regenerated types. This prevents deploying
//! stale hooks to production.

use anyhow::{bail, Context, Result};
use colored::Colorize;
use std::path::Path;
use tokio::process::Command;

use crate::repo::get_tool_path;

/// Result of codegen validation
#[derive(Debug)]
pub struct CodegenValidationResult {
    /// Whether codegen is in sync
    pub is_valid: bool,
    /// Schema export succeeded
    pub schema_exported: bool,
    /// Codegen completed successfully
    pub codegen_succeeded: bool,
    /// Whether changes were auto-committed
    pub changes_committed: bool,
    /// Error message if validation failed
    pub error: Option<String>,
}

/// Validate that codegen types are in sync with backend schema
///
/// # Process
/// 1. Export schema from backend using extract-schema binary
/// 2. Run codegen to regenerate types
/// 3. Check if there were any errors (indicating drift)
/// 4. Auto-commit any changes to ensure deployed code is fresh
///
/// Note: This uses a "regenerate and check" approach rather than diff
/// because codegen output includes timestamps and may have minor differences.
pub async fn validate_codegen(
    backend_dir: &Path,
    web_dir: &Path,
) -> Result<CodegenValidationResult> {
    validate_codegen_with_autocommit(backend_dir, web_dir, true).await
}

/// Validate codegen with optional auto-commit
///
/// When `auto_commit` is true, any changes to generated files will be
/// automatically committed. If the commit fails, the entire validation fails.
pub async fn validate_codegen_with_autocommit(
    backend_dir: &Path,
    web_dir: &Path,
    auto_commit: bool,
) -> Result<CodegenValidationResult> {
    println!("{}", "Validating GraphQL codegen...".bold());

    // Step 1: Export schema from backend
    println!("   Exporting schema from backend...");

    let schema_output = Command::new("cargo")
        .args(["run", "--bin", "extract-schema", "--quiet"])
        .current_dir(backend_dir)
        .output()
        .await
        .with_context(|| format!("Failed to run extract-schema in {}", backend_dir.display()))?;

    if !schema_output.status.success() {
        let stderr = String::from_utf8_lossy(&schema_output.stderr);
        return Ok(CodegenValidationResult {
            is_valid: false,
            schema_exported: false,
            codegen_succeeded: false,
            changes_committed: false,
            error: Some(format!("Schema extraction failed:\n{}", stderr)),
        });
    }

    if schema_output.stdout.is_empty() {
        return Ok(CodegenValidationResult {
            is_valid: false,
            schema_exported: false,
            codegen_succeeded: false,
            changes_committed: false,
            error: Some("Schema extraction produced no output".to_string()),
        });
    }

    println!(
        "   {} Schema exported ({} bytes)",
        "✓".green(),
        schema_output.stdout.len()
    );

    // Write schema to web directory
    let schema_path = web_dir.join("schema.graphql");
    tokio::fs::write(&schema_path, &schema_output.stdout)
        .await
        .with_context(|| format!("Failed to write schema to {}", schema_path.display()))?;

    // Step 2: Run codegen
    println!("   Running GraphQL codegen...");

    // First ensure dependencies are installed
    let bun = get_tool_path("BUN_BIN", "bun");
    let install_output = Command::new(&bun)
        .args(["install", "--frozen-lockfile"])
        .current_dir(web_dir)
        .output()
        .await
        .with_context(|| format!("Failed to run bun install in {}", web_dir.display()))?;

    if !install_output.status.success() {
        let stderr = String::from_utf8_lossy(&install_output.stderr);
        return Ok(CodegenValidationResult {
            is_valid: false,
            schema_exported: true,
            codegen_succeeded: false,
            changes_committed: false,
            error: Some(format!("bun install failed:\n{}", stderr)),
        });
    }

    // Run codegen
    let codegen_output = Command::new(&bun)
        .args(["x", "graphql-codegen", "--config", "codegen.ts"])
        .current_dir(web_dir)
        .output()
        .await
        .with_context(|| format!("Failed to run graphql-codegen in {}", web_dir.display()))?;

    if !codegen_output.status.success() {
        let stderr = String::from_utf8_lossy(&codegen_output.stderr);
        let stdout = String::from_utf8_lossy(&codegen_output.stdout);

        // Check for specific drift errors
        let error_msg = format!("{}\n{}", stderr, stdout);

        // Look for schema drift indicators
        let drift_indicators = [
            "Unknown type",
            "Cannot query field",
            "Field not defined",
            "Unknown argument",
            "Unknown fragment",
            "Type mismatch",
        ];

        let is_drift = drift_indicators
            .iter()
            .any(|indicator| error_msg.contains(indicator));

        if is_drift {
            return Ok(CodegenValidationResult {
                is_valid: false,
                schema_exported: true,
                codegen_succeeded: false,
                changes_committed: false,
                error: Some(format!(
                    "Schema drift detected. Frontend operations are out of sync with backend schema:\n{}",
                    error_msg
                )),
            });
        }

        return Ok(CodegenValidationResult {
            is_valid: false,
            schema_exported: true,
            codegen_succeeded: false,
            changes_committed: false,
            error: Some(format!("Codegen failed:\n{}", error_msg)),
        });
    }

    println!("   {} Codegen completed successfully", "✓".green());

    // Step 3: Auto-commit changes if enabled
    let changes_committed = if auto_commit {
        auto_commit_codegen_changes(web_dir).await?
    } else {
        false
    };

    println!("   {} No schema drift detected", "✅".green());

    Ok(CodegenValidationResult {
        is_valid: true,
        schema_exported: true,
        codegen_succeeded: true,
        changes_committed,
        error: None,
    })
}

/// Quick schema export without running full codegen
///
/// Useful for checking if the backend schema can be exported without errors.
pub async fn validate_schema_export(backend_dir: &Path) -> Result<bool> {
    println!("{}", "Validating schema export...".bold());

    let output = Command::new("cargo")
        .args(["run", "--bin", "extract-schema", "--quiet"])
        .current_dir(backend_dir)
        .output()
        .await
        .with_context(|| format!("Failed to run extract-schema in {}", backend_dir.display()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        println!("   {} Schema export failed", "❌".red());
        println!("   {}", stderr);
        return Ok(false);
    }

    if output.stdout.is_empty() {
        println!("   {} Schema export produced no output", "❌".red());
        return Ok(false);
    }

    // Parse schema to count types
    let schema = String::from_utf8_lossy(&output.stdout);
    let type_count = schema.matches("type ").count()
        + schema.matches("input ").count()
        + schema.matches("enum ").count();

    println!(
        "   {} Schema export succeeded ({} bytes, ~{} types)",
        "✅".green(),
        output.stdout.len(),
        type_count
    );

    Ok(true)
}

/// Check if codegen config exists in web directory
pub async fn check_codegen_config(web_dir: &Path) -> Result<bool> {
    let config_path = web_dir.join("codegen.ts");

    if !config_path.exists() {
        bail!(
            "GraphQL codegen config not found at {}. \
             Expected codegen.ts in web directory.",
            config_path.display()
        );
    }

    Ok(true)
}

/// Auto-commit codegen changes if there are any
///
/// Checks for changes to:
/// - web/schema.graphql
/// - web/src/gql/
///
/// If changes exist, stages and commits them with a standardized message.
/// Returns true if changes were committed, false if no changes.
///
/// # Errors
///
/// Fails loudly if git operations fail - this ensures the release pipeline
/// stops if we can't commit the regenerated code.
async fn auto_commit_codegen_changes(web_dir: &Path) -> Result<bool> {
    // Files to check and potentially commit
    let codegen_paths = ["schema.graphql", "src/gql/"];

    // Check if there are any changes to codegen files
    println!("   Checking for codegen changes...");

    let status_output = Command::new("git")
        .args(["status", "--porcelain", "--"])
        .args(&codegen_paths)
        .current_dir(web_dir)
        .output()
        .await
        .with_context(|| "Failed to check git status for codegen files")?;

    if !status_output.status.success() {
        let stderr = String::from_utf8_lossy(&status_output.stderr);
        bail!("Failed to check git status for codegen files:\n{}", stderr);
    }

    let changes = String::from_utf8_lossy(&status_output.stdout);
    if changes.trim().is_empty() {
        println!("   {} No codegen changes to commit", "✓".green());
        return Ok(false);
    }

    // There are changes - stage them
    println!(
        "   {} Codegen changes detected, auto-committing...",
        "→".yellow()
    );

    let add_output = Command::new("git")
        .args(["add", "--"])
        .args(&codegen_paths)
        .current_dir(web_dir)
        .output()
        .await
        .with_context(|| "Failed to stage codegen files")?;

    if !add_output.status.success() {
        let stderr = String::from_utf8_lossy(&add_output.stderr);
        bail!(
            "FATAL: Failed to stage codegen files for commit:\n{}\n\n\
             This is a critical error - the release cannot proceed without \
             committing the regenerated codegen files.",
            stderr
        );
    }

    // Commit with standardized message
    let commit_message = "chore(codegen): regenerate GraphQL schema and hooks\n\n\
        Auto-committed by release pipeline to ensure deployed code\n\
        matches the regenerated types from backend schema.";

    let commit_output = Command::new("git")
        .args(["commit", "-m", commit_message])
        .current_dir(web_dir)
        .output()
        .await
        .with_context(|| "Failed to commit codegen files")?;

    if !commit_output.status.success() {
        let stderr = String::from_utf8_lossy(&commit_output.stderr);
        let stdout = String::from_utf8_lossy(&commit_output.stdout);

        // Check if it's just "nothing to commit" which is actually OK
        if stdout.contains("nothing to commit") || stderr.contains("nothing to commit") {
            println!(
                "   {} No changes to commit (already up to date)",
                "✓".green()
            );
            return Ok(false);
        }

        bail!(
            "FATAL: Failed to commit codegen files:\n{}\n{}\n\n\
             This is a critical error - the release cannot proceed without \
             committing the regenerated codegen files.\n\n\
             Possible causes:\n\
             - Git hooks blocking the commit\n\
             - Git configuration issues\n\
             - Uncommitted changes in other files\n\n\
             Please resolve and retry the release.",
            stderr,
            stdout
        );
    }

    // Get the commit hash for logging
    let rev_output = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .current_dir(web_dir)
        .output()
        .await
        .ok();

    let commit_hash = rev_output
        .and_then(|o| {
            if o.status.success() {
                Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "unknown".to_string());

    println!(
        "   {} Auto-committed codegen changes ({})",
        "✅".green(),
        commit_hash
    );

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_codegen_validation_result() {
        let result = CodegenValidationResult {
            is_valid: true,
            schema_exported: true,
            codegen_succeeded: true,
            changes_committed: false,
            error: None,
        };
        assert!(result.is_valid);
        assert!(result.schema_exported);
        assert!(result.codegen_succeeded);
        assert!(!result.changes_committed);
        assert!(result.error.is_none());
    }

    #[test]
    fn test_codegen_validation_with_changes_committed() {
        let result = CodegenValidationResult {
            is_valid: true,
            schema_exported: true,
            codegen_succeeded: true,
            changes_committed: true,
            error: None,
        };
        assert!(result.is_valid);
        assert!(result.changes_committed);
    }

    #[test]
    fn test_codegen_validation_with_error() {
        let result = CodegenValidationResult {
            is_valid: false,
            schema_exported: true,
            codegen_succeeded: false,
            changes_committed: false,
            error: Some("Unknown type 'NewType'".to_string()),
        };
        assert!(!result.is_valid);
        assert!(!result.changes_committed);
        assert!(result.error.is_some());
    }
}
