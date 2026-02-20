//! Migration Validation Gates
//!
//! This module provides pre-release validation for database migrations:
//!
//! ## SQLx Migrations (Legacy)
//! - Idempotency checks (IF NOT EXISTS patterns)
//! - Soft-delete compliance (no hard DELETEs on business tables)
//!
//! ## SeaORM Migrations (Current)
//! - Production safety checks (expand-contract pattern required for breaking changes)
//! - DROP COLUMN detection (must use expand-contract)
//! - RENAME COLUMN detection (must use expand-contract)
//! - ALTER COLUMN TYPE detection (must use expand-contract)
//! - INDEX creation without CONCURRENTLY detection
//!
//! Part of the pre-release gate system.
//!
//! ## Configuration
//!
//! Supports excluding migrations from validation via `MigrationGatesConfig`:
//! - `excluded_files`: List of filenames or glob patterns to skip (SQLx)
//! - `seaorm_excluded_files`: List of filenames to skip (SeaORM)
//! - `check_after`: Only check SQLx migrations with timestamps after this prefix
//! - `seaorm_check_after`: Only check SeaORM migrations with timestamps after this prefix

use anyhow::{Context, Result};
use colored::Colorize;
use glob::Pattern;
use std::path::{Path, PathBuf};
use tokio::fs;

use crate::config::MigrationGatesConfig;

/// Issue found during migration validation
#[derive(Debug, Clone)]
pub enum MigrationIssue {
    /// DDL statement missing idempotency guard
    IdempotencyViolation {
        file: PathBuf,
        line_number: usize,
        statement: String,
        suggestion: String,
    },
    /// Hard DELETE found instead of soft delete
    HardDelete {
        file: PathBuf,
        line_number: usize,
        statement: String,
        suggestion: String,
    },
    /// DROP TABLE without safety check
    UnsafeDrop {
        file: PathBuf,
        line_number: usize,
        statement: String,
        suggestion: String,
    },
    /// SeaORM migration with unsafe operation requiring expand-contract pattern
    SeaOrmUnsafeOperation {
        file: PathBuf,
        line_number: usize,
        operation: String,
        suggestion: String,
    },
    /// Migration data completeness issue (manifest validation)
    DataMigrationIncomplete {
        file: String,
        issue_type: String,
        suggestion: String,
    },
}

impl MigrationIssue {
    pub fn format(&self) -> String {
        match self {
            MigrationIssue::IdempotencyViolation {
                file,
                line_number,
                statement,
                suggestion,
            } => {
                format!(
                    "{}:{} - Idempotency violation\n  Statement: {}\n  Suggestion: {}",
                    file.display(),
                    line_number,
                    statement.trim(),
                    suggestion
                )
            }
            MigrationIssue::HardDelete {
                file,
                line_number,
                statement,
                suggestion,
            } => {
                format!(
                    "{}:{} - Hard DELETE found\n  Statement: {}\n  Suggestion: {}",
                    file.display(),
                    line_number,
                    statement.trim(),
                    suggestion
                )
            }
            MigrationIssue::UnsafeDrop {
                file,
                line_number,
                statement,
                suggestion,
            } => {
                format!(
                    "{}:{} - Unsafe DROP\n  Statement: {}\n  Suggestion: {}",
                    file.display(),
                    line_number,
                    statement.trim(),
                    suggestion
                )
            }
            MigrationIssue::SeaOrmUnsafeOperation {
                file,
                line_number,
                operation,
                suggestion,
            } => {
                format!(
                    "{}:{} - Unsafe SeaORM operation\n  Operation: {}\n  Suggestion: {}",
                    file.display(),
                    line_number,
                    operation.trim(),
                    suggestion
                )
            }
            MigrationIssue::DataMigrationIncomplete {
                file,
                issue_type,
                suggestion,
            } => {
                format!(
                    "{} - {}\n  Suggestion: {}",
                    file, issue_type, suggestion
                )
            }
        }
    }
}

/// Result of migration validation
#[derive(Debug)]
pub struct MigrationValidationResult {
    /// Number of migration files checked
    pub files_checked: usize,
    /// Issues found during validation
    pub issues: Vec<MigrationIssue>,
}

impl MigrationValidationResult {
    pub fn is_valid(&self) -> bool {
        self.issues.is_empty()
    }
}

/// Check migrations for idempotency patterns
///
/// Validates that migrations use IF NOT EXISTS / IF EXISTS patterns
/// for DDL operations to ensure migrations can be run multiple times safely.
pub async fn check_idempotency(migrations_dir: &Path) -> Result<Vec<MigrationIssue>> {
    let mut issues = Vec::new();

    let migration_files = find_sql_files(migrations_dir).await?;

    for file_path in migration_files {
        let content = fs::read_to_string(&file_path)
            .await
            .with_context(|| format!("Failed to read migration file: {}", file_path.display()))?;

        let file_issues = check_file_idempotency(&file_path, &content);
        issues.extend(file_issues);
    }

    Ok(issues)
}

/// Check a single file for idempotency issues
fn check_file_idempotency(file_path: &Path, content: &str) -> Vec<MigrationIssue> {
    let mut issues = Vec::new();
    let lines: Vec<&str> = content.lines().collect();

    for (line_num, line) in lines.iter().enumerate() {
        let trimmed = line.trim().to_uppercase();
        let line_number = line_num + 1;

        // Skip comments and empty lines
        if trimmed.starts_with("--") || trimmed.is_empty() {
            continue;
        }

        // Check CREATE TABLE without IF NOT EXISTS
        if trimmed.contains("CREATE TABLE") && !trimmed.contains("IF NOT EXISTS") {
            // Allow if wrapped in DO $$ block (checking context)
            if !is_in_do_block(&lines, line_num) {
                issues.push(MigrationIssue::IdempotencyViolation {
                    file: file_path.to_path_buf(),
                    line_number,
                    statement: line.to_string(),
                    suggestion: "Use CREATE TABLE IF NOT EXISTS".to_string(),
                });
            }
        }

        // Check CREATE INDEX without IF NOT EXISTS
        if trimmed.contains("CREATE INDEX") && !trimmed.contains("IF NOT EXISTS") {
            if !is_in_do_block(&lines, line_num) {
                issues.push(MigrationIssue::IdempotencyViolation {
                    file: file_path.to_path_buf(),
                    line_number,
                    statement: line.to_string(),
                    suggestion: "Use CREATE INDEX IF NOT EXISTS".to_string(),
                });
            }
        }

        // Check CREATE UNIQUE INDEX without IF NOT EXISTS
        if trimmed.contains("CREATE UNIQUE INDEX") && !trimmed.contains("IF NOT EXISTS") {
            if !is_in_do_block(&lines, line_num) {
                issues.push(MigrationIssue::IdempotencyViolation {
                    file: file_path.to_path_buf(),
                    line_number,
                    statement: line.to_string(),
                    suggestion: "Use CREATE UNIQUE INDEX IF NOT EXISTS".to_string(),
                });
            }
        }

        // Check ALTER TABLE ADD COLUMN without guard
        if trimmed.contains("ALTER TABLE") && trimmed.contains("ADD COLUMN") {
            if !trimmed.contains("IF NOT EXISTS") && !is_in_do_block(&lines, line_num) {
                issues.push(MigrationIssue::IdempotencyViolation {
                    file: file_path.to_path_buf(),
                    line_number,
                    statement: line.to_string(),
                    suggestion: "Wrap in DO $$ IF NOT EXISTS check or use ADD COLUMN IF NOT EXISTS"
                        .to_string(),
                });
            }
        }

        // Check DROP TABLE without IF EXISTS
        if trimmed.contains("DROP TABLE") && !trimmed.contains("IF EXISTS") {
            issues.push(MigrationIssue::UnsafeDrop {
                file: file_path.to_path_buf(),
                line_number,
                statement: line.to_string(),
                suggestion: "Use DROP TABLE IF EXISTS".to_string(),
            });
        }

        // Check DROP INDEX without IF EXISTS
        if trimmed.contains("DROP INDEX") && !trimmed.contains("IF EXISTS") {
            issues.push(MigrationIssue::UnsafeDrop {
                file: file_path.to_path_buf(),
                line_number,
                statement: line.to_string(),
                suggestion: "Use DROP INDEX IF EXISTS".to_string(),
            });
        }
    }

    issues
}

/// Check if the current line is within a DO $$ block
fn is_in_do_block(lines: &[&str], current_line: usize) -> bool {
    let mut in_block = false;

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim().to_uppercase();

        if i >= current_line {
            break;
        }

        // Check for DO block start
        if trimmed.starts_with("DO $$") || trimmed.contains("DO $$") {
            in_block = true;
            continue; // Don't check for end on the same line as start
        }

        // Check for DO block end: "END $$;" or "$$ LANGUAGE" or just "$$;" on its own line
        if in_block
            && (trimmed.contains("END") && trimmed.contains("$$")
                || trimmed == "$$;"
                || trimmed.contains("$$ LANGUAGE"))
        {
            in_block = false;
        }
    }

    in_block
}

/// Check migrations for soft-delete compliance
///
/// Validates that migrations don't use hard DELETE statements on business tables.
/// Only system tables (like migrations tracking) are allowed to have hard deletes.
pub async fn check_soft_delete_compliance(migrations_dir: &Path) -> Result<Vec<MigrationIssue>> {
    let mut issues = Vec::new();

    let migration_files = find_sql_files(migrations_dir).await?;

    for file_path in migration_files {
        let content = fs::read_to_string(&file_path)
            .await
            .with_context(|| format!("Failed to read migration file: {}", file_path.display()))?;

        let file_issues = check_file_soft_delete(&file_path, &content);
        issues.extend(file_issues);
    }

    Ok(issues)
}

/// System tables that are allowed to have hard deletes
const ALLOWED_HARD_DELETE_TABLES: &[&str] = &[
    "_sqlx_migrations",
    "schema_migrations",
    "__migrations",
    "flyway_schema_history",
    "diesel_schema_migrations",
    "pg_temp",
    "pg_toast",
];

/// Check a single file for soft-delete compliance
fn check_file_soft_delete(file_path: &Path, content: &str) -> Vec<MigrationIssue> {
    let mut issues = Vec::new();
    let lines: Vec<&str> = content.lines().collect();

    for (line_num, line) in lines.iter().enumerate() {
        let trimmed = line.trim().to_uppercase();
        let line_number = line_num + 1;

        // Skip comments
        if trimmed.starts_with("--") || trimmed.is_empty() {
            continue;
        }

        // Check for DELETE FROM statements
        if trimmed.starts_with("DELETE FROM") || trimmed.contains(" DELETE FROM ") {
            // Extract table name
            if let Some(table_name) = extract_table_name_from_delete(&trimmed) {
                // Check if it's a system table (allowed)
                let is_system_table = ALLOWED_HARD_DELETE_TABLES
                    .iter()
                    .any(|t| table_name.to_uppercase().contains(&t.to_uppercase()));

                if !is_system_table {
                    issues.push(MigrationIssue::HardDelete {
                        file: file_path.to_path_buf(),
                        line_number,
                        statement: line.to_string(),
                        suggestion: format!(
                            "Use UPDATE {} SET deleted_at = NOW() WHERE ... instead of DELETE",
                            table_name
                        ),
                    });
                }
            }
        }

        // Also check for TRUNCATE (which is a hard delete)
        if trimmed.starts_with("TRUNCATE") || trimmed.contains(" TRUNCATE ") {
            if let Some(table_name) = extract_table_name_from_truncate(&trimmed) {
                let is_system_table = ALLOWED_HARD_DELETE_TABLES
                    .iter()
                    .any(|t| table_name.to_uppercase().contains(&t.to_uppercase()));

                if !is_system_table {
                    issues.push(MigrationIssue::HardDelete {
                        file: file_path.to_path_buf(),
                        line_number,
                        statement: line.to_string(),
                        suggestion:
                            "TRUNCATE removes all data permanently. Consider soft-delete pattern."
                                .to_string(),
                    });
                }
            }
        }
    }

    issues
}

/// Extract table name from DELETE FROM statement
fn extract_table_name_from_delete(line: &str) -> Option<String> {
    let upper = line.to_uppercase();

    // Find "DELETE FROM" and extract the next word
    if let Some(pos) = upper.find("DELETE FROM") {
        let after_from = &line[pos + 11..].trim_start();
        let table_name = after_from
            .split_whitespace()
            .next()?
            .trim_matches(|c| c == '"' || c == '`' || c == '[' || c == ']');

        return Some(table_name.to_string());
    }

    None
}

/// Extract table name from TRUNCATE statement
fn extract_table_name_from_truncate(line: &str) -> Option<String> {
    let upper = line.to_uppercase();

    // Handle "TRUNCATE TABLE" and just "TRUNCATE"
    let pos = if upper.contains("TRUNCATE TABLE") {
        upper.find("TRUNCATE TABLE").map(|p| p + 14)
    } else {
        upper.find("TRUNCATE").map(|p| p + 8)
    };

    if let Some(start) = pos {
        let after_truncate = &line[start..].trim_start();
        let table_name = after_truncate
            .split_whitespace()
            .next()?
            .trim_matches(|c| c == '"' || c == '`' || c == '[' || c == ']');

        return Some(table_name.to_string());
    }

    None
}

/// Check if a file should be excluded from validation
fn should_exclude_file(file_path: &Path, config: &MigrationGatesConfig) -> bool {
    let filename = file_path.file_name().and_then(|n| n.to_str()).unwrap_or("");

    // Check check_after threshold
    if let Some(ref threshold) = config.check_after {
        // Extract timestamp prefix from filename (e.g., "20240101" from "20240101_migration.sql")
        let file_prefix: String = filename
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect();
        if !file_prefix.is_empty() && file_prefix < *threshold {
            return true;
        }
    }

    // Check excluded_files patterns
    for pattern in &config.excluded_files {
        // Try as glob pattern first
        if let Ok(glob_pattern) = Pattern::new(pattern) {
            if glob_pattern.matches(filename) {
                return true;
            }
        }
        // Fall back to exact match
        if filename == pattern {
            return true;
        }
    }

    false
}

/// Find all SQL files in the migrations directory, optionally filtering by config
async fn find_sql_files(dir: &Path) -> Result<Vec<PathBuf>> {
    find_sql_files_with_config(dir, &MigrationGatesConfig::default()).await
}

/// Find all SQL files in the migrations directory, filtering by config
async fn find_sql_files_with_config(
    dir: &Path,
    config: &MigrationGatesConfig,
) -> Result<Vec<PathBuf>> {
    let mut sql_files = Vec::new();

    if !dir.exists() {
        return Ok(sql_files);
    }

    let mut entries = fs::read_dir(dir)
        .await
        .with_context(|| format!("Failed to read migrations directory: {}", dir.display()))?;

    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();

        if path.is_file() {
            if let Some(ext) = path.extension() {
                if ext == "sql" && !should_exclude_file(&path, config) {
                    sql_files.push(path);
                }
            }
        }
    }

    // Sort by filename for consistent ordering
    sql_files.sort();

    Ok(sql_files)
}

/// Validate all migrations in a directory (using default config)
///
/// Runs both idempotency and soft-delete compliance checks.
pub async fn validate_migrations(migrations_dir: &Path) -> Result<MigrationValidationResult> {
    validate_migrations_with_config(migrations_dir, &MigrationGatesConfig::default()).await
}

/// Validate migrations in a directory with custom configuration
///
/// Supports excluding files via `config.excluded_files` and `config.check_after`.
pub async fn validate_migrations_with_config(
    migrations_dir: &Path,
    config: &MigrationGatesConfig,
) -> Result<MigrationValidationResult> {
    println!(
        "{}",
        format!("Validating migrations in {}...", migrations_dir.display()).bold()
    );

    // Get all SQL files, applying exclusion filters
    let sql_files = find_sql_files_with_config(migrations_dir, config).await?;
    let files_checked = sql_files.len();

    // Count excluded files for reporting
    let all_sql_files =
        find_sql_files_with_config(migrations_dir, &MigrationGatesConfig::default()).await?;
    let excluded_count = all_sql_files.len().saturating_sub(files_checked);

    if files_checked == 0 {
        if excluded_count > 0 {
            println!(
                "   No migration files to check ({} excluded)",
                excluded_count
            );
        } else {
            println!("   No migration files found");
        }
        return Ok(MigrationValidationResult {
            files_checked: 0,
            issues: vec![],
        });
    }

    if excluded_count > 0 {
        println!(
            "   Found {} migration files ({} excluded by config)",
            files_checked, excluded_count
        );
    } else {
        println!("   Found {} migration files", files_checked);
    }

    // Run checks only on non-excluded files
    let mut all_issues = Vec::new();

    if config.idempotency_check {
        for file_path in &sql_files {
            let content = fs::read_to_string(file_path)
                .await
                .with_context(|| format!("Failed to read: {}", file_path.display()))?;
            let issues = check_file_idempotency(file_path, &content);
            all_issues.extend(issues);
        }
    }

    if config.soft_delete_check {
        for file_path in &sql_files {
            let content = fs::read_to_string(file_path)
                .await
                .with_context(|| format!("Failed to read: {}", file_path.display()))?;
            let issues = check_file_soft_delete(file_path, &content);
            all_issues.extend(issues);
        }
    }

    if all_issues.is_empty() {
        println!("   {} All migrations valid", "✅".green());
    } else {
        println!("   {} Found {} issues", "❌".red(), all_issues.len());
        for issue in &all_issues {
            println!("\n   {}", issue.format());
        }
    }

    Ok(MigrationValidationResult {
        files_checked,
        issues: all_issues,
    })
}

// =============================================================================
// SeaORM Migration Validation (Rust files)
// =============================================================================

/// Result of SeaORM migration validation
#[derive(Debug)]
pub struct SeaOrmValidationResult {
    /// Number of migration files checked
    pub files_checked: usize,
    /// Issues found during validation
    pub issues: Vec<MigrationIssue>,
}

impl SeaOrmValidationResult {
    pub fn is_valid(&self) -> bool {
        self.issues.is_empty()
    }
}

/// Dangerous SQL patterns that require expand-contract pattern
/// These are detected within execute_unprepared() calls in SeaORM migrations
const DANGEROUS_PATTERNS: &[(&str, &str)] = &[
    (
        "DROP COLUMN",
        "DROP COLUMN causes outages during rolling deployment. Use expand-contract pattern: \
         1) Add new column, 2) Migrate data, 3) Update code, 4) DROP old column in separate migration. \
         See docs/arch/database-migrations.md"
    ),
    (
        "RENAME COLUMN",
        "RENAME COLUMN breaks running code during deployment. Use expand-contract pattern: \
         1) Add new column, 2) Create sync trigger, 3) Migrate code, 4) DROP old column. \
         See docs/arch/database-migrations.md"
    ),
    (
        "ALTER COLUMN .* TYPE",
        "Changing column type can break running code. Use expand-contract pattern: \
         1) Add new column with new type, 2) Backfill data, 3) Update code, 4) DROP old column. \
         See docs/arch/database-migrations.md"
    ),
];

/// Patterns that are warnings but may be acceptable with proper justification
const WARNING_PATTERNS: &[(&str, &str)] = &[
    (
        "CREATE INDEX(?! CONCURRENTLY)",
        "CREATE INDEX without CONCURRENTLY locks the table. Use CREATE INDEX CONCURRENTLY for production. \
         If this is intentional (small table, maintenance window), add comment: // SAFETY: <reason>"
    ),
    (
        "ALTER TABLE .* SET NOT NULL",
        "SET NOT NULL without prior backfill may fail or lock table. \
         Recommended pattern: 1) Add nullable column, 2) Backfill data, 3) SET NOT NULL. \
         If backfill is done in same migration, add comment: // SAFETY: backfilled above"
    ),
];

/// Check if a SeaORM migration file should be excluded
fn should_exclude_seaorm_file(file_path: &Path, config: &MigrationGatesConfig) -> bool {
    let filename = file_path.file_name().and_then(|n| n.to_str()).unwrap_or("");

    // Check seaorm_check_after threshold (e.g., "m20260128")
    if let Some(ref threshold) = config.seaorm_check_after {
        // Extract the timestamp part (e.g., "m20260126" from "m20260126_000001_feature_flags.rs")
        let file_prefix: String = filename
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .take(9) // "m" + 8 digits
            .collect();
        if !file_prefix.is_empty() && file_prefix < *threshold {
            return true;
        }
    }

    // Check excluded files list
    for pattern in &config.seaorm_excluded_files {
        if let Ok(glob_pattern) = Pattern::new(pattern) {
            if glob_pattern.matches(filename) {
                return true;
            }
        }
        if filename == pattern {
            return true;
        }
    }

    false
}

/// Find all SeaORM migration files (m*.rs) in a directory
async fn find_seaorm_migration_files(
    dir: &Path,
    config: &MigrationGatesConfig,
) -> Result<Vec<PathBuf>> {
    let mut rs_files = Vec::new();

    if !dir.exists() {
        return Ok(rs_files);
    }

    let mut entries = fs::read_dir(dir).await.with_context(|| {
        format!(
            "Failed to read SeaORM migrations directory: {}",
            dir.display()
        )
    })?;

    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();

        if path.is_file() {
            if let Some(filename) = path.file_name().and_then(|n| n.to_str()) {
                // Match m*.rs pattern (SeaORM migrations)
                if filename.starts_with('m')
                    && filename.ends_with(".rs")
                    && filename != "mod.rs"
                    && !should_exclude_seaorm_file(&path, config)
                {
                    rs_files.push(path);
                }
            }
        }
    }

    rs_files.sort();
    Ok(rs_files)
}

/// Check a SeaORM migration file for unsafe operations
fn check_seaorm_file_safety(file_path: &Path, content: &str) -> Vec<MigrationIssue> {
    let mut issues = Vec::new();
    let lines: Vec<&str> = content.lines().collect();

    // Track if we're inside an execute_unprepared call
    let mut in_execute_block = false;
    let mut execute_start_line = 0;
    let mut execute_content = String::new();

    for (line_num, line) in lines.iter().enumerate() {
        let line_number = line_num + 1;
        let trimmed = line.trim();

        // Skip pure comment lines
        if trimmed.starts_with("//") {
            // Check for SAFETY comment that exempts the next operation
            if trimmed.contains("// SAFETY:") || trimmed.contains("//SAFETY:") {
                // Skip next dangerous pattern check
                continue;
            }
            continue;
        }

        // Detect execute_unprepared calls
        if trimmed.contains("execute_unprepared") {
            in_execute_block = true;
            execute_start_line = line_number;
            execute_content.clear();
        }

        // Accumulate content while in execute block
        if in_execute_block {
            execute_content.push_str(line);
            execute_content.push('\n');

            // Check if block ends (simple heuristic: line ends with ");" or ".await")
            if trimmed.ends_with(");")
                || trimmed.ends_with(".await?;")
                || trimmed.ends_with(".await;")
            {
                // Check the accumulated SQL for dangerous patterns
                let sql_upper = execute_content.to_uppercase();

                // Check for dangerous patterns (errors)
                for (pattern, suggestion) in DANGEROUS_PATTERNS {
                    let regex_pattern = format!(r"(?i){}", pattern);
                    if let Ok(re) = regex::Regex::new(&regex_pattern) {
                        if re.is_match(&sql_upper) {
                            // Check if there's a SAFETY comment in the preceding lines
                            let has_safety_comment = (execute_start_line.saturating_sub(3)
                                ..execute_start_line)
                                .any(|i| {
                                    lines
                                        .get(i.saturating_sub(1))
                                        .map(|l| {
                                            l.contains("// SAFETY:")
                                                || l.contains("// EXPAND-CONTRACT:")
                                        })
                                        .unwrap_or(false)
                                });

                            if !has_safety_comment {
                                issues.push(MigrationIssue::SeaOrmUnsafeOperation {
                                    file: file_path.to_path_buf(),
                                    line_number: execute_start_line,
                                    operation: extract_sql_snippet(&execute_content),
                                    suggestion: suggestion.to_string(),
                                });
                            }
                        }
                    }
                }

                // Check for warning patterns
                for (pattern, suggestion) in WARNING_PATTERNS {
                    let regex_pattern = format!(r"(?i){}", pattern);
                    if let Ok(re) = regex::Regex::new(&regex_pattern) {
                        if re.is_match(&execute_content) {
                            // Check if there's a SAFETY comment
                            let has_safety_comment =
                                (execute_start_line.saturating_sub(3)..=line_number).any(|i| {
                                    lines
                                        .get(i.saturating_sub(1))
                                        .map(|l| l.contains("// SAFETY:"))
                                        .unwrap_or(false)
                                });

                            if !has_safety_comment {
                                // For CREATE INDEX, check if CONCURRENTLY is present
                                if pattern.contains("CREATE INDEX") {
                                    if !execute_content.to_uppercase().contains("CONCURRENTLY") {
                                        issues.push(MigrationIssue::SeaOrmUnsafeOperation {
                                            file: file_path.to_path_buf(),
                                            line_number: execute_start_line,
                                            operation: extract_sql_snippet(&execute_content),
                                            suggestion: suggestion.to_string(),
                                        });
                                    }
                                }
                            }
                        }
                    }
                }

                in_execute_block = false;
                execute_content.clear();
            }
        }

        // Also check for drop_column() SeaORM method calls
        if trimmed.contains(".drop_column(") && !trimmed.starts_with("//") {
            // Check preceding 10 lines for SAFETY or EXPAND-CONTRACT comment
            let has_safety_comment = (line_num.saturating_sub(10)..line_num).any(|i| {
                lines
                    .get(i)
                    .map(|l| l.contains("// SAFETY:") || l.contains("// EXPAND-CONTRACT:"))
                    .unwrap_or(false)
            });

            if !has_safety_comment {
                issues.push(MigrationIssue::SeaOrmUnsafeOperation {
                    file: file_path.to_path_buf(),
                    line_number,
                    operation: trimmed.to_string(),
                    suggestion: "drop_column() causes outages. Use expand-contract pattern. \
                                 See docs/arch/database-migrations.md"
                        .to_string(),
                });
            }
        }

        // Check for rename_column() SeaORM method calls
        if trimmed.contains(".rename_column(") && !trimmed.starts_with("//") {
            // Check preceding 10 lines for SAFETY or EXPAND-CONTRACT comment
            let has_safety_comment = (line_num.saturating_sub(10)..line_num).any(|i| {
                lines
                    .get(i)
                    .map(|l| l.contains("// SAFETY:") || l.contains("// EXPAND-CONTRACT:"))
                    .unwrap_or(false)
            });

            if !has_safety_comment {
                issues.push(MigrationIssue::SeaOrmUnsafeOperation {
                    file: file_path.to_path_buf(),
                    line_number,
                    operation: trimmed.to_string(),
                    suggestion: "rename_column() causes outages. Use expand-contract pattern. \
                                 See docs/arch/database-migrations.md"
                        .to_string(),
                });
            }
        }
    }

    issues
}

/// Extract a readable SQL snippet from execute_unprepared content
fn extract_sql_snippet(content: &str) -> String {
    // Try to extract just the SQL string from the Rust code
    let trimmed = content.trim();

    // Look for string content between quotes
    if let Some(start) = trimmed.find('"') {
        if let Some(end) = trimmed.rfind('"') {
            if end > start {
                let sql = &trimmed[start + 1..end];
                // Truncate if too long
                if sql.len() > 100 {
                    return format!("{}...", &sql[..100]);
                }
                return sql.to_string();
            }
        }
    }

    // Fallback: return first 100 chars
    if trimmed.len() > 100 {
        format!("{}...", &trimmed[..100])
    } else {
        trimmed.to_string()
    }
}

/// Validate SeaORM migrations in a directory
///
/// Checks for dangerous operations that require expand-contract pattern.
pub async fn validate_seaorm_migrations(
    seaorm_migrations_dir: &Path,
    config: &MigrationGatesConfig,
) -> Result<SeaOrmValidationResult> {
    println!(
        "{}",
        format!(
            "Validating SeaORM migrations in {}...",
            seaorm_migrations_dir.display()
        )
        .bold()
    );

    let rs_files = find_seaorm_migration_files(seaorm_migrations_dir, config).await?;
    let files_checked = rs_files.len();

    if files_checked == 0 {
        println!("   No SeaORM migration files found");
        return Ok(SeaOrmValidationResult {
            files_checked: 0,
            issues: vec![],
        });
    }

    println!("   Found {} SeaORM migration files", files_checked);

    let mut all_issues = Vec::new();

    for file_path in &rs_files {
        let content = fs::read_to_string(file_path)
            .await
            .with_context(|| format!("Failed to read: {}", file_path.display()))?;
        let issues = check_seaorm_file_safety(file_path, &content);
        all_issues.extend(issues);
    }

    if all_issues.is_empty() {
        println!("   {} All SeaORM migrations safe", "✅".green());
    } else {
        println!("   {} Found {} safety issues", "❌".red(), all_issues.len());
        for issue in &all_issues {
            println!("\n   {}", issue.format());
        }
    }

    Ok(SeaOrmValidationResult {
        files_checked,
        issues: all_issues,
    })
}

// =============================================================================
// Migration Manifest Validation (G8b)
// =============================================================================

use serde::Deserialize;
use std::collections::HashMap;

/// Classification of a migration in the manifest
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum MigrationClassification {
    SchemaOnly,
    DataOnly,
    SchemaAndData,
    Noop,
}

/// Entry in the migration manifest
#[derive(Debug, Clone, Deserialize)]
pub struct ManifestEntry {
    pub classification: MigrationClassification,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub data_forward: Option<String>,
    #[serde(default)]
    pub data_backward: Option<String>,
}

/// Top-level manifest structure
#[derive(Debug, Clone, Deserialize)]
pub struct MigrationManifest {
    pub migrations: HashMap<String, ManifestEntry>,
}

/// Result of manifest validation
#[derive(Debug)]
pub struct ManifestValidationResult {
    /// Number of migrations assessed in the manifest
    pub assessed_count: usize,
    /// Issues found during validation
    pub issues: Vec<MigrationIssue>,
}

/// Result of rollback compatibility check
#[derive(Debug)]
pub struct RollbackCompatibilityResult {
    /// Warnings about migrations that may affect rollback
    pub warnings: Vec<String>,
    /// Count of migrations past threshold
    pub migration_count: usize,
}

/// Validate the migration manifest against actual migration files.
///
/// Checks:
/// 1. Every m*.rs file past seaorm_check_after is declared in the manifest
/// 2. schema_and_data entries reference existing, registered companion files
/// 3. noop entries have a reason
pub async fn validate_migration_manifest(
    seaorm_dir: &Path,
    config: &MigrationGatesConfig,
) -> Result<ManifestValidationResult> {
    println!(
        "{}",
        format!(
            "Validating migration manifest in {}...",
            seaorm_dir.display()
        )
        .bold()
    );

    let manifest_path = seaorm_dir.join("migration-manifest.yaml");

    // Load manifest
    let manifest = if manifest_path.exists() {
        let content = fs::read_to_string(&manifest_path)
            .await
            .with_context(|| {
                format!(
                    "Failed to read migration manifest: {}",
                    manifest_path.display()
                )
            })?;
        serde_yaml::from_str::<MigrationManifest>(&content).with_context(|| {
            format!(
                "Failed to parse migration manifest: {}",
                manifest_path.display()
            )
        })?
    } else {
        println!(
            "   {} No migration-manifest.yaml found at {}",
            "⚠️".yellow(),
            manifest_path.display()
        );
        return Ok(ManifestValidationResult {
            assessed_count: 0,
            issues: vec![MigrationIssue::DataMigrationIncomplete {
                file: "migration-manifest.yaml".to_string(),
                issue_type: "Missing manifest file".to_string(),
                suggestion: "Create migration-manifest.yaml in the SeaORM migrations directory"
                    .to_string(),
            }],
        });
    };

    // Find all migration files past threshold
    let migration_files = find_seaorm_migration_files(seaorm_dir, config).await?;
    let mut issues = Vec::new();

    for file_path in &migration_files {
        let filename = file_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");
        // Strip .rs extension to get the migration name
        let migration_name = filename.trim_end_matches(".rs");

        // Check 1: Is this migration declared in the manifest?
        match manifest.migrations.get(migration_name) {
            None => {
                issues.push(MigrationIssue::DataMigrationIncomplete {
                    file: migration_name.to_string(),
                    issue_type: "Migration not assessed in manifest".to_string(),
                    suggestion: format!(
                        "Add '{}' to migration-manifest.yaml with a classification",
                        migration_name
                    ),
                });
            }
            Some(entry) => {
                // Check 2: noop entries must have a reason
                if entry.classification == MigrationClassification::Noop {
                    let has_reason = entry
                        .reason
                        .as_ref()
                        .map(|r| !r.trim().is_empty())
                        .unwrap_or(false);
                    if !has_reason {
                        issues.push(MigrationIssue::DataMigrationIncomplete {
                            file: migration_name.to_string(),
                            issue_type: "Noop classification without reason".to_string(),
                            suggestion:
                                "Add a 'reason' field explaining why no data migration is needed"
                                    .to_string(),
                        });
                    }
                }

                // Check 3: schema_and_data entries must reference existing companion files
                if entry.classification == MigrationClassification::SchemaAndData {
                    if let Some(ref data_forward) = entry.data_forward {
                        let forward_path = seaorm_dir.join(format!("{}.rs", data_forward));
                        if !forward_path.exists() {
                            issues.push(MigrationIssue::DataMigrationIncomplete {
                                file: migration_name.to_string(),
                                issue_type: format!(
                                    "data_forward '{}' file does not exist",
                                    data_forward
                                ),
                                suggestion: format!(
                                    "Create {}.rs or update data_forward reference",
                                    data_forward
                                ),
                            });
                        }
                        // Check 3b: data_forward companion must be classified as data_only
                        if let Some(companion_entry) = manifest.migrations.get(data_forward.as_str()) {
                            if companion_entry.classification != MigrationClassification::DataOnly {
                                issues.push(MigrationIssue::DataMigrationIncomplete {
                                    file: migration_name.to_string(),
                                    issue_type: format!(
                                        "data_forward '{}' is classified as {:?}, expected data_only",
                                        data_forward, companion_entry.classification
                                    ),
                                    suggestion: format!(
                                        "Change classification of '{}' to data_only in manifest",
                                        data_forward
                                    ),
                                });
                            }
                        } else {
                            issues.push(MigrationIssue::DataMigrationIncomplete {
                                file: migration_name.to_string(),
                                issue_type: format!(
                                    "data_forward '{}' is not declared in the manifest",
                                    data_forward
                                ),
                                suggestion: format!(
                                    "Add '{}' to migration-manifest.yaml with classification: data_only",
                                    data_forward
                                ),
                            });
                        }
                    } else {
                        issues.push(MigrationIssue::DataMigrationIncomplete {
                            file: migration_name.to_string(),
                            issue_type: "schema_and_data without data_forward".to_string(),
                            suggestion:
                                "Add 'data_forward' field referencing the companion data migration"
                                    .to_string(),
                        });
                    }

                    // Check 3c: data_backward companion (if present) must be classified as data_only
                    if let Some(ref data_backward) = entry.data_backward {
                        if let Some(companion_entry) = manifest.migrations.get(data_backward.as_str()) {
                            if companion_entry.classification != MigrationClassification::DataOnly {
                                issues.push(MigrationIssue::DataMigrationIncomplete {
                                    file: migration_name.to_string(),
                                    issue_type: format!(
                                        "data_backward '{}' is classified as {:?}, expected data_only",
                                        data_backward, companion_entry.classification
                                    ),
                                    suggestion: format!(
                                        "Change classification of '{}' to data_only in manifest",
                                        data_backward
                                    ),
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    // Check 4: Detect orphaned manifest entries (no corresponding file)
    let migration_filenames: std::collections::HashSet<String> = migration_files
        .iter()
        .filter_map(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.trim_end_matches(".rs").to_string())
        })
        .collect();

    for manifest_name in manifest.migrations.keys() {
        if !migration_filenames.contains(manifest_name.as_str()) {
            // Only warn for entries that should be past threshold (not grandfathered)
            let is_past_threshold = config
                .seaorm_check_after
                .as_ref()
                .map(|threshold| manifest_name.as_str() >= threshold.as_str())
                .unwrap_or(true);

            if is_past_threshold {
                issues.push(MigrationIssue::DataMigrationIncomplete {
                    file: manifest_name.to_string(),
                    issue_type: "Manifest entry has no corresponding migration file".to_string(),
                    suggestion: format!(
                        "Remove '{}' from migration-manifest.yaml or create {}.rs",
                        manifest_name, manifest_name
                    ),
                });
            }
        }
    }

    let assessed_count = manifest.migrations.len();

    if issues.is_empty() {
        println!(
            "   {} All {} migrations assessed in manifest",
            "✅".green(),
            assessed_count
        );
    } else {
        println!(
            "   {} Found {} manifest issues",
            "❌".red(),
            issues.len()
        );
        for issue in &issues {
            println!("\n   {}", issue.format());
        }
    }

    Ok(ManifestValidationResult {
        assessed_count,
        issues,
    })
}

/// Check rollback compatibility based on the manifest.
///
/// Returns warnings (never blocks) about migrations that may cause issues
/// when older code runs against the newer schema after a rollback.
pub async fn validate_rollback_compatibility(
    seaorm_dir: &Path,
    config: &MigrationGatesConfig,
) -> Result<RollbackCompatibilityResult> {
    let manifest_path = seaorm_dir.join("migration-manifest.yaml");
    let mut warnings = Vec::new();

    let migration_files = find_seaorm_migration_files(seaorm_dir, config).await?;
    let migration_count = migration_files.len();

    if !manifest_path.exists() {
        warnings.push(format!(
            "No migration-manifest.yaml found — cannot assess rollback safety for {} migration(s)",
            migration_count
        ));
        return Ok(RollbackCompatibilityResult {
            warnings,
            migration_count,
        });
    }

    let content = fs::read_to_string(&manifest_path).await?;
    let manifest: MigrationManifest = serde_yaml::from_str(&content)?;

    for (name, entry) in &manifest.migrations {
        if entry.classification == MigrationClassification::SchemaAndData
            && entry.data_backward.is_none()
        {
            warnings.push(format!(
                "{}: schema_and_data migration without data_backward — \
                 rollback may leave data in an inconsistent state",
                name
            ));
        }
    }

    Ok(RollbackCompatibilityResult {
        warnings,
        migration_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_file_idempotency_create_table() {
        let content = "CREATE TABLE users (\n  id UUID PRIMARY KEY\n);";
        let issues = check_file_idempotency(Path::new("test.sql"), content);
        assert_eq!(issues.len(), 1);
        assert!(matches!(
            &issues[0],
            MigrationIssue::IdempotencyViolation { .. }
        ));
    }

    #[test]
    fn test_check_file_idempotency_safe() {
        let content = "CREATE TABLE IF NOT EXISTS users (\n  id UUID PRIMARY KEY\n);";
        let issues = check_file_idempotency(Path::new("test.sql"), content);
        assert!(issues.is_empty());
    }

    #[test]
    fn test_check_file_soft_delete_violation() {
        let content = "DELETE FROM users WHERE id = '123';";
        let issues = check_file_soft_delete(Path::new("test.sql"), content);
        assert_eq!(issues.len(), 1);
        assert!(matches!(&issues[0], MigrationIssue::HardDelete { .. }));
    }

    #[test]
    fn test_check_file_soft_delete_system_table_allowed() {
        let content = "DELETE FROM _sqlx_migrations WHERE version = 1;";
        let issues = check_file_soft_delete(Path::new("test.sql"), content);
        assert!(issues.is_empty());
    }

    #[test]
    fn test_extract_table_name_from_delete() {
        assert_eq!(
            extract_table_name_from_delete("DELETE FROM users WHERE id = 1"),
            Some("users".to_string())
        );
        assert_eq!(
            extract_table_name_from_delete("delete from \"Users\" where id = 1"),
            Some("Users".to_string())
        );
    }

    #[test]
    fn test_is_in_do_block() {
        let lines = vec![
            "DO $$",
            "BEGIN",
            "  IF NOT EXISTS (SELECT 1 FROM pg_tables WHERE tablename = 'users') THEN",
            "    CREATE TABLE users (id UUID);",
            "  END IF;",
            "END $$;",
        ];

        assert!(is_in_do_block(&lines, 3)); // CREATE TABLE is inside DO block
        assert!(!is_in_do_block(&lines, 0)); // DO $$ line itself
    }

    #[test]
    fn test_should_exclude_file_by_check_after() {
        let config = MigrationGatesConfig {
            check_after: Some("20240101".to_string()),
            ..Default::default()
        };

        // Before threshold - should be excluded
        assert!(should_exclude_file(
            Path::new("20230601_initial.sql"),
            &config
        ));
        assert!(should_exclude_file(
            Path::new("20231215_add_users.sql"),
            &config
        ));

        // After threshold - should NOT be excluded
        assert!(!should_exclude_file(
            Path::new("20240101_on_threshold.sql"),
            &config
        ));
        assert!(!should_exclude_file(
            Path::new("20240615_new_migration.sql"),
            &config
        ));
    }

    #[test]
    fn test_should_exclude_file_by_pattern() {
        let config = MigrationGatesConfig {
            excluded_files: vec![
                "20230101_initial.sql".to_string(),
                "2023*".to_string(), // glob pattern
            ],
            ..Default::default()
        };

        // Exact match
        assert!(should_exclude_file(
            Path::new("20230101_initial.sql"),
            &config
        ));

        // Glob match
        assert!(should_exclude_file(
            Path::new("20230615_some_migration.sql"),
            &config
        ));

        // Not matching
        assert!(!should_exclude_file(Path::new("20240101_new.sql"), &config));
    }

    #[test]
    fn test_should_exclude_file_default_config() {
        let config = MigrationGatesConfig::default();

        // Default config excludes nothing
        assert!(!should_exclude_file(
            Path::new("20230101_initial.sql"),
            &config
        ));
        assert!(!should_exclude_file(Path::new("20240101_new.sql"), &config));
    }

    // ========================================
    // SeaORM Validation Tests
    // ========================================

    #[test]
    fn test_seaorm_detect_drop_column_in_sql() {
        let content = r#"
            manager.get_connection().execute_unprepared(
                "ALTER TABLE users DROP COLUMN old_field"
            ).await?;
        "#;
        let issues = check_seaorm_file_safety(Path::new("m20260128_test.rs"), content);
        assert_eq!(issues.len(), 1);
        assert!(matches!(
            &issues[0],
            MigrationIssue::SeaOrmUnsafeOperation { .. }
        ));
    }

    #[test]
    fn test_seaorm_detect_drop_column_method() {
        let content = r#"
            manager.alter_table(
                Table::alter()
                    .table(Users::Table)
                    .drop_column(Users::OldField)
                    .to_owned()
            ).await?;
        "#;
        let issues = check_seaorm_file_safety(Path::new("m20260128_test.rs"), content);
        assert_eq!(issues.len(), 1);
        assert!(matches!(
            &issues[0],
            MigrationIssue::SeaOrmUnsafeOperation { .. }
        ));
    }

    #[test]
    fn test_seaorm_detect_rename_column() {
        let content = r#"
            manager.get_connection().execute_unprepared(
                "ALTER TABLE users RENAME COLUMN old_name TO new_name"
            ).await?;
        "#;
        let issues = check_seaorm_file_safety(Path::new("m20260128_test.rs"), content);
        assert_eq!(issues.len(), 1);
    }

    #[test]
    fn test_seaorm_safety_comment_bypasses_check() {
        let content = r#"
            // SAFETY: This is the CONTRACT phase - expand phase was m20260115
            manager.alter_table(
                Table::alter()
                    .table(Users::Table)
                    .drop_column(Users::OldField)
                    .to_owned()
            ).await?;
        "#;
        let issues = check_seaorm_file_safety(Path::new("m20260128_test.rs"), content);
        assert!(issues.is_empty(), "SAFETY comment should bypass check");
    }

    #[test]
    fn test_seaorm_expand_contract_comment_bypasses_check() {
        let content = r#"
            // EXPAND-CONTRACT: Contract phase after m20260115 expand
            manager.alter_table(
                Table::alter()
                    .table(Users::Table)
                    .drop_column(Users::OldField)
                    .to_owned()
            ).await?;
        "#;
        let issues = check_seaorm_file_safety(Path::new("m20260128_test.rs"), content);
        assert!(
            issues.is_empty(),
            "EXPAND-CONTRACT comment should bypass check"
        );
    }

    #[test]
    fn test_seaorm_safe_operations_pass() {
        let content = r#"
            // Adding a nullable column is safe
            manager.alter_table(
                Table::alter()
                    .table(Users::Table)
                    .add_column_if_not_exists(
                        ColumnDef::new(Users::NewField).string().null()
                    )
                    .to_owned()
            ).await?;

            // Creating table with IF NOT EXISTS is safe
            manager.create_table(
                Table::create()
                    .table(NewTable::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(NewTable::Id).uuid().primary_key())
                    .to_owned()
            ).await?;
        "#;
        let issues = check_seaorm_file_safety(Path::new("m20260128_test.rs"), content);
        assert!(issues.is_empty(), "Safe operations should not raise issues");
    }

    #[test]
    fn test_should_exclude_seaorm_file_by_check_after() {
        let config = MigrationGatesConfig {
            seaorm_check_after: Some("m20260128".to_string()),
            ..Default::default()
        };

        // Before threshold - should be excluded
        assert!(should_exclude_seaorm_file(
            Path::new("m20260126_000001_feature_flags.rs"),
            &config
        ));
        assert!(should_exclude_seaorm_file(
            Path::new("m20260127_000001_something.rs"),
            &config
        ));

        // After threshold - should NOT be excluded
        assert!(!should_exclude_seaorm_file(
            Path::new("m20260128_000001_on_threshold.rs"),
            &config
        ));
        assert!(!should_exclude_seaorm_file(
            Path::new("m20260201_000001_future.rs"),
            &config
        ));
    }

    #[test]
    fn test_should_exclude_seaorm_file_by_pattern() {
        let config = MigrationGatesConfig {
            seaorm_excluded_files: vec![
                "m20260126_000001_feature_flags.rs".to_string(),
                "m20260127_*".to_string(), // glob pattern
            ],
            ..Default::default()
        };

        // Exact match
        assert!(should_exclude_seaorm_file(
            Path::new("m20260126_000001_feature_flags.rs"),
            &config
        ));

        // Glob match
        assert!(should_exclude_seaorm_file(
            Path::new("m20260127_000001_something.rs"),
            &config
        ));

        // Not matching
        assert!(!should_exclude_seaorm_file(
            Path::new("m20260128_000001_new.rs"),
            &config
        ));
    }

    // ========================================
    // Migration Manifest Tests
    // ========================================

    #[test]
    fn test_parse_manifest_yaml() {
        let yaml = r#"
migrations:
  m20260201_000001_fix_constraint:
    classification: schema_only
    reason: "FK fix"
  m20260202_000001_add_field:
    classification: noop
    reason: "Nullable column"
  m20260203_000001_backfill:
    classification: data_only
    reason: "Backfill existing data"
  m20260204_000001_rename_col:
    classification: schema_and_data
    data_forward: m20260204_000002_rename_col_data
    data_backward: m20260204_000003_rename_col_rollback
"#;
        let manifest: MigrationManifest = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(manifest.migrations.len(), 4);

        let schema_only = &manifest.migrations["m20260201_000001_fix_constraint"];
        assert_eq!(schema_only.classification, MigrationClassification::SchemaOnly);

        let noop = &manifest.migrations["m20260202_000001_add_field"];
        assert_eq!(noop.classification, MigrationClassification::Noop);
        assert_eq!(noop.reason.as_deref(), Some("Nullable column"));

        let data_only = &manifest.migrations["m20260203_000001_backfill"];
        assert_eq!(data_only.classification, MigrationClassification::DataOnly);

        let schema_and_data = &manifest.migrations["m20260204_000001_rename_col"];
        assert_eq!(
            schema_and_data.classification,
            MigrationClassification::SchemaAndData
        );
        assert_eq!(
            schema_and_data.data_forward.as_deref(),
            Some("m20260204_000002_rename_col_data")
        );
        assert_eq!(
            schema_and_data.data_backward.as_deref(),
            Some("m20260204_000003_rename_col_rollback")
        );
    }

    #[test]
    fn test_parse_manifest_empty_migrations() {
        let yaml = "migrations: {}";
        let manifest: MigrationManifest = serde_yaml::from_str(yaml).unwrap();
        assert!(manifest.migrations.is_empty());
    }

    #[test]
    fn test_parse_manifest_minimal_entry() {
        let yaml = r#"
migrations:
  m20260201_000001_test:
    classification: schema_only
"#;
        let manifest: MigrationManifest = serde_yaml::from_str(yaml).unwrap();
        let entry = &manifest.migrations["m20260201_000001_test"];
        assert_eq!(entry.classification, MigrationClassification::SchemaOnly);
        assert!(entry.reason.is_none());
        assert!(entry.data_forward.is_none());
        assert!(entry.data_backward.is_none());
    }

    #[tokio::test]
    async fn test_validate_manifest_missing_file() {
        let dir = std::env::temp_dir().join("test_manifest_missing");
        let _ = std::fs::create_dir_all(&dir);
        // No manifest file

        let config = MigrationGatesConfig::default();
        let result = validate_migration_manifest(&dir, &config).await.unwrap();
        assert_eq!(result.issues.len(), 1);
        assert!(matches!(
            &result.issues[0],
            MigrationIssue::DataMigrationIncomplete { issue_type, .. }
            if issue_type.contains("Missing manifest")
        ));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_validate_manifest_with_unassessed_migration() {
        let dir = std::env::temp_dir().join("test_manifest_unassessed");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);

        // Create a migration file
        std::fs::write(
            dir.join("m20260301_000001_new_feature.rs"),
            "// migration content",
        )
        .unwrap();

        // Create a manifest that does NOT include this migration
        std::fs::write(
            dir.join("migration-manifest.yaml"),
            "migrations: {}",
        )
        .unwrap();

        // Config with check_after before m20260301
        let config = MigrationGatesConfig {
            seaorm_check_after: Some("m20260201".to_string()),
            ..Default::default()
        };

        let result = validate_migration_manifest(&dir, &config).await.unwrap();
        assert_eq!(result.issues.len(), 1);
        assert!(matches!(
            &result.issues[0],
            MigrationIssue::DataMigrationIncomplete { issue_type, .. }
            if issue_type.contains("not assessed")
        ));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_validate_manifest_noop_without_reason() {
        let dir = std::env::temp_dir().join("test_manifest_noop_no_reason");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);

        std::fs::write(
            dir.join("m20260301_000001_add_col.rs"),
            "// migration",
        )
        .unwrap();

        std::fs::write(
            dir.join("migration-manifest.yaml"),
            r#"
migrations:
  m20260301_000001_add_col:
    classification: noop
"#,
        )
        .unwrap();

        let config = MigrationGatesConfig {
            seaorm_check_after: Some("m20260201".to_string()),
            ..Default::default()
        };

        let result = validate_migration_manifest(&dir, &config).await.unwrap();
        assert_eq!(result.issues.len(), 1);
        assert!(matches!(
            &result.issues[0],
            MigrationIssue::DataMigrationIncomplete { issue_type, .. }
            if issue_type.contains("without reason")
        ));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_validate_manifest_schema_and_data_missing_forward() {
        let dir = std::env::temp_dir().join("test_manifest_missing_forward");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);

        std::fs::write(
            dir.join("m20260301_000001_rename.rs"),
            "// migration",
        )
        .unwrap();

        std::fs::write(
            dir.join("migration-manifest.yaml"),
            r#"
migrations:
  m20260301_000001_rename:
    classification: schema_and_data
"#,
        )
        .unwrap();

        let config = MigrationGatesConfig {
            seaorm_check_after: Some("m20260201".to_string()),
            ..Default::default()
        };

        let result = validate_migration_manifest(&dir, &config).await.unwrap();
        assert_eq!(result.issues.len(), 1);
        assert!(matches!(
            &result.issues[0],
            MigrationIssue::DataMigrationIncomplete { issue_type, .. }
            if issue_type.contains("without data_forward")
        ));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_validate_manifest_all_pass() {
        let dir = std::env::temp_dir().join("test_manifest_pass");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);

        std::fs::write(
            dir.join("m20260301_000001_add_col.rs"),
            "// migration",
        )
        .unwrap();
        std::fs::write(
            dir.join("m20260301_000002_index.rs"),
            "// migration",
        )
        .unwrap();

        std::fs::write(
            dir.join("migration-manifest.yaml"),
            r#"
migrations:
  m20260301_000001_add_col:
    classification: noop
    reason: "Nullable column, no backfill needed"
  m20260301_000002_index:
    classification: schema_only
    reason: "Index only"
"#,
        )
        .unwrap();

        let config = MigrationGatesConfig {
            seaorm_check_after: Some("m20260201".to_string()),
            ..Default::default()
        };

        let result = validate_migration_manifest(&dir, &config).await.unwrap();
        assert!(result.issues.is_empty());
        assert_eq!(result.assessed_count, 2);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_rollback_compatibility_warns_on_missing_backward() {
        let dir = std::env::temp_dir().join("test_rollback_compat");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);

        std::fs::write(
            dir.join("m20260301_000001_rename.rs"),
            "// migration",
        )
        .unwrap();
        std::fs::write(
            dir.join("m20260301_000002_rename_data.rs"),
            "// data migration",
        )
        .unwrap();

        std::fs::write(
            dir.join("migration-manifest.yaml"),
            r#"
migrations:
  m20260301_000001_rename:
    classification: schema_and_data
    data_forward: m20260301_000002_rename_data
  m20260301_000002_rename_data:
    classification: data_only
"#,
        )
        .unwrap();

        let config = MigrationGatesConfig {
            seaorm_check_after: Some("m20260201".to_string()),
            ..Default::default()
        };

        let result = validate_rollback_compatibility(&dir, &config).await.unwrap();
        assert_eq!(result.warnings.len(), 1);
        assert!(result.warnings[0].contains("without data_backward"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_validate_manifest_data_forward_file_missing() {
        let dir = std::env::temp_dir().join("test_manifest_forward_file_missing");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);

        // Create the schema_and_data migration but NOT the companion file
        std::fs::write(
            dir.join("m20260301_000001_rename.rs"),
            "// migration",
        )
        .unwrap();

        std::fs::write(
            dir.join("migration-manifest.yaml"),
            r#"
migrations:
  m20260301_000001_rename:
    classification: schema_and_data
    data_forward: m20260301_000002_rename_data
  m20260301_000002_rename_data:
    classification: data_only
"#,
        )
        .unwrap();

        let config = MigrationGatesConfig {
            seaorm_check_after: Some("m20260201".to_string()),
            ..Default::default()
        };

        let result = validate_migration_manifest(&dir, &config).await.unwrap();
        // Should have 2 issues: companion file missing + orphaned manifest entry
        let forward_issue = result.issues.iter().any(|i| matches!(
            i,
            MigrationIssue::DataMigrationIncomplete { issue_type, .. }
            if issue_type.contains("file does not exist")
        ));
        assert!(forward_issue, "Should detect missing companion file");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_validate_manifest_data_forward_wrong_classification() {
        let dir = std::env::temp_dir().join("test_manifest_forward_wrong_class");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);

        std::fs::write(
            dir.join("m20260301_000001_rename.rs"),
            "// migration",
        )
        .unwrap();
        std::fs::write(
            dir.join("m20260301_000002_rename_data.rs"),
            "// companion",
        )
        .unwrap();

        // Companion is classified as schema_only instead of data_only
        std::fs::write(
            dir.join("migration-manifest.yaml"),
            r#"
migrations:
  m20260301_000001_rename:
    classification: schema_and_data
    data_forward: m20260301_000002_rename_data
  m20260301_000002_rename_data:
    classification: schema_only
    reason: "Wrong classification"
"#,
        )
        .unwrap();

        let config = MigrationGatesConfig {
            seaorm_check_after: Some("m20260201".to_string()),
            ..Default::default()
        };

        let result = validate_migration_manifest(&dir, &config).await.unwrap();
        let cross_issue = result.issues.iter().any(|i| matches!(
            i,
            MigrationIssue::DataMigrationIncomplete { issue_type, .. }
            if issue_type.contains("expected data_only")
        ));
        assert!(cross_issue, "Should detect wrong companion classification");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_validate_manifest_data_forward_not_in_manifest() {
        let dir = std::env::temp_dir().join("test_manifest_forward_not_declared");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);

        std::fs::write(
            dir.join("m20260301_000001_rename.rs"),
            "// migration",
        )
        .unwrap();
        std::fs::write(
            dir.join("m20260301_000002_rename_data.rs"),
            "// companion file exists but not in manifest",
        )
        .unwrap();

        // Companion file exists but is NOT declared in the manifest
        std::fs::write(
            dir.join("migration-manifest.yaml"),
            r#"
migrations:
  m20260301_000001_rename:
    classification: schema_and_data
    data_forward: m20260301_000002_rename_data
"#,
        )
        .unwrap();

        let config = MigrationGatesConfig {
            seaorm_check_after: Some("m20260201".to_string()),
            ..Default::default()
        };

        let result = validate_migration_manifest(&dir, &config).await.unwrap();
        // Two issues: companion not in manifest + migration file not assessed
        let not_declared = result.issues.iter().any(|i| matches!(
            i,
            MigrationIssue::DataMigrationIncomplete { issue_type, .. }
            if issue_type.contains("not declared in the manifest")
        ));
        assert!(not_declared, "Should detect companion not declared in manifest");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_validate_manifest_orphaned_entry() {
        let dir = std::env::temp_dir().join("test_manifest_orphaned");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);

        // Only one migration file exists
        std::fs::write(
            dir.join("m20260301_000001_add_col.rs"),
            "// migration",
        )
        .unwrap();

        // Manifest references a second migration that has no file
        std::fs::write(
            dir.join("migration-manifest.yaml"),
            r#"
migrations:
  m20260301_000001_add_col:
    classification: schema_only
    reason: "Index only"
  m20260301_000002_deleted:
    classification: schema_only
    reason: "This migration was deleted but entry remained"
"#,
        )
        .unwrap();

        let config = MigrationGatesConfig {
            seaorm_check_after: Some("m20260201".to_string()),
            ..Default::default()
        };

        let result = validate_migration_manifest(&dir, &config).await.unwrap();
        let orphaned = result.issues.iter().any(|i| matches!(
            i,
            MigrationIssue::DataMigrationIncomplete { issue_type, .. }
            if issue_type.contains("no corresponding migration file")
        ));
        assert!(orphaned, "Should detect orphaned manifest entry");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
