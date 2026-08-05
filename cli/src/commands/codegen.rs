//! Schema Export and Codegen
//!
//! This module handles exporting the GraphQL schema from the backend
//! and running GraphQL Code Generator to produce TypeScript types.
//!
//! Replaces shell script logic with pure Rust implementation.

use anyhow::{Context, Result};
use colored::Colorize;
use std::path::Path;
use std::time::Instant;
use tokio::fs;
use tokio::process::Command;

use crate::repo::get_tool_path;

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

    println!();
    println!(
        "{}",
        "════════════════════════════════════════════════".bold()
    );
    println!("{}", "  Schema Export + Codegen".bold());
    println!(
        "{}",
        "════════════════════════════════════════════════".bold()
    );
    println!();
    println!("Backend: {}", backend_dir.display());
    println!("Frontend: {}", web_dir.display());
    println!();

    // Step 1: Export schema from backend
    println!("{}", "Step 1: Exporting GraphQL schema...".bold());
    let schema_start = Instant::now();

    // Route through the canonical `extract_graphql_schema` primitive —
    // the one-oracle owner of the "run cargo run --bin extract-schema
    // --quiet in a backend dir, expect non-empty stdout bytes, fail typed
    // on every failure shape" surface (THEORY §V.1, §VI.1). The typed
    // `SchemaExtractionError` is preserved across the anyhow boundary and
    // can be recovered with `err.downcast_ref::<SchemaExtractionError>()`.
    let schema_bytes = crate::graphql_schema::extract_graphql_schema(backend_dir).await?;
    let schema_size = schema_bytes.len();
    println!(
        "   {} Schema extracted ({} bytes, {:.1}s)",
        "✓".green(),
        schema_size,
        schema_start.elapsed().as_secs_f64()
    );

    // Step 2: Write schema to web directory
    let schema_path = web_dir.join("schema.graphql");
    fs::write(&schema_path, &schema_bytes)
        .await
        .with_context(|| format!("Failed to write schema to {}", schema_path.display()))?;

    println!(
        "   {} Schema written to {}",
        "✓".green(),
        schema_path.display()
    );
    println!();

    // Step 3: Install dependencies
    println!("{}", "Step 2: Installing dependencies...".bold());
    let install_start = Instant::now();

    let bun = get_tool_path("BUN_BIN", "bun");
    let install_output = Command::new(&bun)
        .args(["install", "--frozen-lockfile"])
        .current_dir(web_dir)
        .output()
        .await
        .with_context(|| format!("Failed to run bun install in {}", web_dir.display()))?;

    if !install_output.status.success() {
        let stderr = String::from_utf8_lossy(&install_output.stderr);
        anyhow::bail!("bun install failed:\n{}", stderr);
    }

    println!(
        "   {} Dependencies installed ({:.1}s)",
        "✓".green(),
        install_start.elapsed().as_secs_f64()
    );
    println!();

    // Step 4: Run codegen
    println!("{}", "Step 3: Running GraphQL codegen...".bold());
    let codegen_start = Instant::now();

    let codegen_output = Command::new(&bun)
        .arg("x")
        .args(["graphql-codegen", "--config", "codegen.ts"])
        .current_dir(web_dir)
        .output()
        .await
        .with_context(|| format!("Failed to run graphql-codegen in {}", web_dir.display()))?;

    if !codegen_output.status.success() {
        let stderr = String::from_utf8_lossy(&codegen_output.stderr);
        let stdout = String::from_utf8_lossy(&codegen_output.stdout);
        anyhow::bail!("GraphQL codegen failed:\n{}\n{}", stderr, stdout);
    }

    println!(
        "   {} Codegen completed ({:.1}s)",
        "✓".green(),
        codegen_start.elapsed().as_secs_f64()
    );
    println!();

    // Summary
    let total_time = start.elapsed().as_secs_f64();
    println!(
        "{}",
        "════════════════════════════════════════════════".bold()
    );
    println!(
        "{}",
        format!("  Codegen Complete ({:.1}s total)", total_time)
            .green()
            .bold()
    );
    println!(
        "{}",
        "════════════════════════════════════════════════".bold()
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
    println!("{}", "Exporting GraphQL schema...".bold());

    // One-oracle read-through: same typed primitive `execute` above uses,
    // so a future refinement of the extract-schema invocation shape
    // (CARGO env override, typed error variants, byte-preservation)
    // lands at one site (THEORY §VI.1).
    let schema_bytes = crate::graphql_schema::extract_graphql_schema(backend_dir).await?;
    let schema_size = schema_bytes.len();

    fs::write(output_path, &schema_bytes)
        .await
        .with_context(|| format!("Failed to write schema to {}", output_path.display()))?;

    println!(
        "   {} Schema exported to {} ({} bytes)",
        "✅".green(),
        output_path.display(),
        schema_size
    );

    Ok(schema_size)
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
