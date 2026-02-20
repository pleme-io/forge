//! Scaffold command for creating new SeaORM migrations.
//!
//! Generates properly-structured migration files and updates the migration manifest.
//!
//! Usage:
//!   forge migration-new --name my_feature --working-dir /path/to/product
//!   forge migration-new --name my_feature --with-data --working-dir /path/to/product

use anyhow::{Context, Result};
use chrono::Utc;
use colored::Colorize;
use std::path::Path;

/// Execute the migration scaffold command.
pub async fn execute(
    working_dir: String,
    name: String,
    classification: String,
    with_data: bool,
    reason: Option<String>,
) -> Result<()> {
    let base_dir = Path::new(&working_dir);
    let migrations_dir = base_dir.join("services/rust/migration/src");
    let manifest_path = migrations_dir.join("migration-manifest.yaml");

    if !migrations_dir.exists() {
        anyhow::bail!(
            "SeaORM migrations directory not found: {}",
            migrations_dir.display()
        );
    }

    // Determine today's date prefix
    let today = Utc::now().format("%Y%m%d").to_string();
    let date_prefix = format!("m{}", today);

    // Scan existing files to find next sequence number for today
    let mut max_seq: u32 = 0;
    let entries = std::fs::read_dir(&migrations_dir)
        .with_context(|| format!("Failed to read {}", migrations_dir.display()))?;

    for entry in entries {
        let entry = entry?;
        let filename = entry.file_name().to_string_lossy().to_string();
        if filename.starts_with(&date_prefix) && filename.ends_with(".rs") {
            // Extract sequence: m20260209_000001_name.rs → 000001
            let parts: Vec<&str> = filename.split('_').collect();
            if parts.len() >= 2 {
                if let Ok(seq) = parts[1].parse::<u32>() {
                    if seq > max_seq {
                        max_seq = seq;
                    }
                }
            }
        }
    }

    let next_seq = max_seq + 1;
    let sanitized_name = name
        .to_lowercase()
        .replace('-', "_")
        .replace(' ', "_");

    let migration_name = format!("{}_{:06}_{}", date_prefix, next_seq, sanitized_name);
    let migration_file = format!("{}.rs", migration_name);
    let migration_path = migrations_dir.join(&migration_file);

    println!("{}", "Creating migration scaffold...".bold());
    println!();

    // Write the schema migration file
    let scaffold = generate_migration_scaffold(&migration_name);
    std::fs::write(&migration_path, &scaffold)
        .with_context(|| format!("Failed to write {}", migration_path.display()))?;
    println!(
        "   {} Created {}",
        "✅".green(),
        migration_path.display()
    );

    // If --with-data, also create companion data migration
    let data_migration_name = if with_data {
        let data_seq = next_seq + 1;
        let data_name = format!("{}_{:06}_{}_data", date_prefix, data_seq, sanitized_name);
        let data_file = format!("{}.rs", data_name);
        let data_path = migrations_dir.join(&data_file);

        let data_scaffold = generate_data_migration_scaffold(&data_name);
        std::fs::write(&data_path, &data_scaffold)
            .with_context(|| format!("Failed to write {}", data_path.display()))?;
        println!(
            "   {} Created {}",
            "✅".green(),
            data_path.display()
        );

        Some(data_name)
    } else {
        None
    };

    // Update migration-manifest.yaml
    let manifest_entry = generate_manifest_entry(
        &migration_name,
        &classification,
        reason.as_deref(),
        data_migration_name.as_deref(),
    );

    if manifest_path.exists() {
        let mut content = std::fs::read_to_string(&manifest_path)
            .with_context(|| format!("Failed to read {}", manifest_path.display()))?;

        // Append the new entry
        content.push_str(&manifest_entry);

        // If --with-data, also add the data migration entry
        if let Some(ref data_name) = data_migration_name {
            content.push_str(&format!(
                "\n  {}:\n    classification: data_only\n    reason: \"Data migration for {}\"\n",
                data_name, sanitized_name
            ));
        }

        std::fs::write(&manifest_path, &content)
            .with_context(|| format!("Failed to update {}", manifest_path.display()))?;
        println!(
            "   {} Updated {}",
            "✅".green(),
            manifest_path.display()
        );
    } else {
        // Create new manifest
        let mut content = String::from(
            "# Migration manifest — see docs/arch/database-migrations.md\n\nmigrations:\n",
        );
        content.push_str(&manifest_entry);
        if let Some(ref data_name) = data_migration_name {
            content.push_str(&format!(
                "\n  {}:\n    classification: data_only\n    reason: \"Data migration for {}\"\n",
                data_name, sanitized_name
            ));
        }
        std::fs::write(&manifest_path, &content)
            .with_context(|| format!("Failed to create {}", manifest_path.display()))?;
        println!(
            "   {} Created {}",
            "✅".green(),
            manifest_path.display()
        );
    }

    // Print instructions for lib.rs registration
    println!();
    println!("{}", "Add to services/rust/migration/src/lib.rs:".bold());
    println!();
    println!("   // Module declaration:");
    println!("   mod {};", migration_name);
    if let Some(ref data_name) = data_migration_name {
        println!("   mod {};", data_name);
    }
    println!();
    println!("   // In Migrator::migrations() vec:");
    println!("   Box::new({}::Migration),", migration_name);
    if let Some(ref data_name) = data_migration_name {
        println!("   Box::new({}::Migration),", data_name);
    }

    println!();
    println!(
        "{}",
        "Done! Remember to register the migration in lib.rs before running."
            .green()
            .bold()
    );

    Ok(())
}

/// Generate SeaORM migration scaffold code
fn generate_migration_scaffold(name: &str) -> String {
    format!(
        r#"use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {{
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {{
        // TODO: Implement schema changes
        //
        // Safe patterns:
        //   manager.create_table(Table::create().table(...).if_not_exists()...)
        //   manager.alter_table(Table::alter().table(...).add_column_if_not_exists(...))
        //   manager.get_connection().execute_unprepared("CREATE INDEX CONCURRENTLY IF NOT EXISTS ...")
        //
        // FORBIDDEN without expand-contract:
        //   DROP COLUMN, RENAME COLUMN, ALTER COLUMN TYPE
        //   See docs/arch/database-migrations.md

        todo!("Implement {name}")
    }}

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {{
        // TODO: Implement rollback
        todo!("Implement rollback for {name}")
    }}
}}
"#,
        name = name
    )
}

/// Generate data migration scaffold code
fn generate_data_migration_scaffold(name: &str) -> String {
    format!(
        r#"use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {{
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {{
        // TODO: Implement data migration
        //
        // For large tables, use batched updates:
        //   DO $$
        //   DECLARE batch_size INT := 1000; updated INT;
        //   BEGIN LOOP
        //     WITH batch AS (SELECT id FROM table WHERE ... LIMIT batch_size FOR UPDATE SKIP LOCKED)
        //     UPDATE table SET ... FROM batch WHERE table.id = batch.id;
        //     GET DIAGNOSTICS updated = ROW_COUNT;
        //     EXIT WHEN updated < batch_size;
        //     PERFORM pg_sleep(0.1);
        //   END LOOP; END $$;

        todo!("Implement data migration {name}")
    }}

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {{
        // TODO: Implement data rollback (if possible)
        todo!("Implement data rollback for {name}")
    }}
}}
"#,
        name = name
    )
}

/// Generate a YAML manifest entry for the new migration
fn generate_manifest_entry(
    migration_name: &str,
    classification: &str,
    reason: Option<&str>,
    data_forward: Option<&str>,
) -> String {
    let mut entry = format!("\n  {}:\n    classification: {}", migration_name, classification);

    if let Some(reason) = reason {
        entry.push_str(&format!("\n    reason: \"{}\"", reason));
    }

    if let Some(data_forward) = data_forward {
        entry.push_str(&format!("\n    data_forward: {}", data_forward));
    }

    entry.push('\n');
    entry
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_migration_scaffold() {
        let scaffold = generate_migration_scaffold("m20260209_000001_test_feature");
        assert!(scaffold.contains("DeriveMigrationName"));
        assert!(scaffold.contains("MigrationTrait"));
        assert!(scaffold.contains("async fn up"));
        assert!(scaffold.contains("async fn down"));
        assert!(scaffold.contains("m20260209_000001_test_feature"));
    }

    #[test]
    fn test_generate_data_migration_scaffold() {
        let scaffold = generate_data_migration_scaffold("m20260209_000002_test_data");
        assert!(scaffold.contains("DeriveMigrationName"));
        assert!(scaffold.contains("data migration"));
        assert!(scaffold.contains("batch_size"));
    }

    #[test]
    fn test_generate_manifest_entry_schema_only() {
        let entry = generate_manifest_entry(
            "m20260209_000001_test",
            "schema_only",
            Some("New table"),
            None,
        );
        assert!(entry.contains("m20260209_000001_test"));
        assert!(entry.contains("classification: schema_only"));
        assert!(entry.contains("reason: \"New table\""));
        assert!(!entry.contains("data_forward"));
    }

    #[test]
    fn test_generate_manifest_entry_schema_and_data() {
        let entry = generate_manifest_entry(
            "m20260209_000001_rename",
            "schema_and_data",
            Some("Column rename"),
            Some("m20260209_000002_rename_data"),
        );
        assert!(entry.contains("classification: schema_and_data"));
        assert!(entry.contains("data_forward: m20260209_000002_rename_data"));
    }

    #[test]
    fn test_generate_manifest_entry_noop() {
        let entry = generate_manifest_entry(
            "m20260209_000001_add_col",
            "noop",
            Some("Nullable column"),
            None,
        );
        assert!(entry.contains("classification: noop"));
        assert!(entry.contains("reason: \"Nullable column\""));
    }
}
