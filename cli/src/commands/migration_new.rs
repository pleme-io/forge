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

/// The verb half of a `<Verb> <path>` scaffold step-pass readout — a
/// closed enum whose [`label`](Self::label) is the inverse of the
/// pre-lift `format!("<Verb> {}", <path>.display())` literal that the
/// four sibling stanzas in [`execute`] used to spell inline.
///
/// # Compounding
///
/// Pre-lift four sibling sites in [`execute`] each spelled the same
/// `crate::ui::print_step_pass(&format!("<Verb> {}", <path>.display()))`
/// stanza with `<Verb>` picking from a two-element vocabulary
/// (`Created` ×3 — the schema-migration file, the optional companion
/// data-migration file, and the freshly-created manifest — plus
/// `Updated` ×1 for the append-to-existing-manifest branch). Post-lift
/// each site names its verb by variant, and the `<Verb> <path>` byte
/// template lives at exactly one line inside
/// [`write_scaffold_path_action`]. A future gate — a `Wrote` variant
/// for a re-emit path, a `Deleted` variant for a cleanup companion, or
/// a JSON-per-line dialect under a `--report=json` flag — lands on the
/// enum plus one line of `write_scaffold_path_action`, never fanned
/// across the four call sites.
///
/// # Theory grounding
///
/// - THEORY.md §V.1 (Construction guarantees; Types → Invariants →
///   Proofs → Render Anywhere): the paired byte-oracle sibling
///   [`write_scaffold_path_action`] is the Render Anywhere half —
///   pinning the exact `<Verb> <path>` rendered bytes as a
///   `cargo test`-verifiable invariant, so a fusion that swapped the
///   space for a colon or dropped the display projection fails at
///   `cargo test` time rather than at operator readout.
/// - THEORY.md §VI.1 (three-times rule): four sibling occurrences
///   past the "two is a coincidence; three is a law" threshold, so
///   the `format!(...)` stanza lifts onto ONE typed body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ScaffoldPathVerb {
    Created,
    Updated,
}

impl ScaffoldPathVerb {
    /// The rendered leading token — the inverse of the pre-lift
    /// `"<Verb> {}"` format-string literal, exact-cased to match
    /// operator-facing precedent.
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Created => "Created",
            Self::Updated => "Updated",
        }
    }
}

/// Emit the `<Verb> <path>` in-body step-pass line through
/// [`crate::ui::print_step_pass`] (three-space indent + green `✅`
/// glyph + message).
///
/// See [`ScaffoldPathVerb`] for the compounding argument. Delegates
/// to [`write_scaffold_path_action`] against a stdout lock, matching
/// the pre-lift `println!` semantics (panic only on formatter errors,
/// not broken-pipe / OOM).
pub(crate) fn print_scaffold_path_action(verb: ScaffoldPathVerb, path: &Path) {
    let _ = write_scaffold_path_action(&mut std::io::stdout().lock(), verb, path);
}

/// Byte-oracle sibling of [`print_scaffold_path_action`] — writes the
/// same bytes to any [`std::io::Write`] so a `#[test]` can capture
/// and compare them.
///
/// Delegates to [`crate::ui::write_step_pass`] so the primitive keeps
/// a single source of truth for the outer `   {✅} {msg}` byte
/// template; the inner message is exactly `<Verb.label()> <path
/// display>`.
pub(crate) fn write_scaffold_path_action<W: std::io::Write>(
    w: &mut W,
    verb: ScaffoldPathVerb,
    path: &Path,
) -> std::io::Result<()> {
    crate::ui::write_step_pass(w, &format!("{} {}", verb.label(), path.display()))
}

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

    crate::repo::require_existing_path(&migrations_dir, "SeaORM migrations directory")?;

    // Determine today's date prefix
    let today = Utc::now().format("%Y%m%d").to_string();
    let date_prefix = format!("m{}", today);

    // Scan existing files to find next sequence number for today
    let mut max_seq: u32 = 0;
    let entries = std::fs::read_dir(&migrations_dir)
        .with_context(|| format!("Failed to read {}", migrations_dir.display()))?;

    for entry in entries {
        let entry = entry?;
        let filename = crate::repo::dir_entry_name_lossy(&entry);
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
    let sanitized_name = name.to_lowercase().replace('-', "_").replace(' ', "_");

    let migration_name = format!("{}_{:06}_{}", date_prefix, next_seq, sanitized_name);
    let migration_file = format!("{}.rs", migration_name);
    let migration_path = migrations_dir.join(&migration_file);

    crate::ui::print_step_heading("Creating migration scaffold...");
    println!();

    // Write the schema migration file
    let scaffold = generate_migration_scaffold(&migration_name);
    crate::repo::write_text_sync(&migration_path, &scaffold)?;
    print_scaffold_path_action(ScaffoldPathVerb::Created, &migration_path);

    // If --with-data, also create companion data migration
    let data_migration_name = if with_data {
        let data_seq = next_seq + 1;
        let data_name = format!("{}_{:06}_{}_data", date_prefix, data_seq, sanitized_name);
        let data_file = format!("{}.rs", data_name);
        let data_path = migrations_dir.join(&data_file);

        let data_scaffold = generate_data_migration_scaffold(&data_name);
        crate::repo::write_text_sync(&data_path, &data_scaffold)?;
        print_scaffold_path_action(ScaffoldPathVerb::Created, &data_path);

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
        let mut content = crate::repo::read_text_sync(&manifest_path)?;

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
        print_scaffold_path_action(ScaffoldPathVerb::Updated, &manifest_path);
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
        print_scaffold_path_action(ScaffoldPathVerb::Created, &manifest_path);
    }

    // Print instructions for lib.rs registration
    println!();
    crate::ui::print_step_heading("Add to services/rust/migration/src/lib.rs:");
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
    let mut entry = format!(
        "\n  {}:\n    classification: {}",
        migration_name, classification
    );

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

    /// Byte-oracle for the `Created` variant — the four-sites-post-lift
    /// primitive must render EXACTLY the same bytes as the pre-lift
    /// `crate::ui::print_step_pass(&format!("Created {}", <path>.display()))`
    /// stanza that spelled it inline. Compares against
    /// [`crate::ui::write_step_pass`] with the composed message so the
    /// oracle ties both sides to the same outer-line template — a fusion
    /// that swapped `write_step_pass` for `writeln!` on the raw glyph
    /// (or that lost the `.green()` on the ✅) fails here.
    #[test]
    fn write_scaffold_path_action_created_matches_step_pass_template() {
        let path = Path::new("services/rust/migration/src/m20260209_000001_test.rs");
        let mut got = Vec::new();
        write_scaffold_path_action(&mut got, ScaffoldPathVerb::Created, path).unwrap();

        let mut want = Vec::new();
        crate::ui::write_step_pass(&mut want, &format!("Created {}", path.display())).unwrap();

        assert_eq!(
            got, want,
            "Created variant must render `<step_pass> Created <path.display()>` \
             bytes-for-bytes; a fusion that dropped the space, transposed \
             `<Verb>` and `<path>`, or bypassed `crate::ui::write_step_pass` \
             fails here"
        );
    }

    /// Byte-oracle for the `Updated` variant — sibling of the `Created`
    /// oracle. Its own presence is what forces the `label()` inverse to
    /// stay in lockstep with the pre-lift `"<Verb> {}"` format literal
    /// across BOTH verbs (a one-verb oracle would let `Updated` silently
    /// drift to e.g. `"Modified"`).
    #[test]
    fn write_scaffold_path_action_updated_matches_step_pass_template() {
        let path = Path::new("services/rust/migration/src/migration-manifest.yaml");
        let mut got = Vec::new();
        write_scaffold_path_action(&mut got, ScaffoldPathVerb::Updated, path).unwrap();

        let mut want = Vec::new();
        crate::ui::write_step_pass(&mut want, &format!("Updated {}", path.display())).unwrap();

        assert_eq!(
            got, want,
            "Updated variant must render `<step_pass> Updated <path.display()>` \
             bytes-for-bytes; a fusion that reused the `Created` label \
             (via a wildcard match arm or a copy-paste in `label()`) \
             fails here"
        );
    }

    /// The two `ScaffoldPathVerb::label()` projections must be distinct
    /// AND exact-cased to the pre-lift `format!("Created {}", …)` /
    /// `format!("Updated {}", …)` literals — pin BOTH properties so a
    /// case fusion (`"created"` / `"CREATED"`), a shortening
    /// (`"Add"` / `"Upd"`), or a collision (`Created.label() ==
    /// Updated.label()`) is caught at `cargo test` time rather than at
    /// operator readout.
    #[test]
    fn scaffold_path_verb_labels_are_exact_and_distinct() {
        assert_eq!(ScaffoldPathVerb::Created.label(), "Created");
        assert_eq!(ScaffoldPathVerb::Updated.label(), "Updated");
        assert_ne!(
            ScaffoldPathVerb::Created.label(),
            ScaffoldPathVerb::Updated.label(),
            "the two variant labels must not collide — a re-inline \
             where every stanza spells the same verb would be a silent \
             semantic loss"
        );
    }

    /// Negative caller shield — after the lift, NO line in the module
    /// body (pre-`#[cfg(test)]`) may spell the pre-lift
    /// `crate::ui::print_step_pass(&format!("Created {}", …))` /
    /// `crate::ui::print_step_pass(&format!("Updated {}", …))` stanza
    /// inline. A re-inline would silently reopen the four-site
    /// duplication class this lift closes.
    ///
    /// The two needles are assembled at runtime via [`format!`] from a
    /// small verb-vocabulary so this shield's own source lines do not
    /// self-match, mirroring the discipline of
    /// `migration_validation::write_migration_issue_report`'s caller
    /// shield.
    #[test]
    fn scaffold_path_action_callers_do_not_reinline_pre_lift_shape() {
        let source = include_str!("migration_new.rs");
        let body = crate::test_support::module_body_before_first_cfg_test(
            source,
            "commands/migration_new.rs",
        );
        for verb in ["Created", "Updated"] {
            let needle = format!(
                "{}{}(&format!(\"{} {{}}\"",
                "crate::ui::", "print_step_pass", verb,
            );
            for (i, line) in body.lines().enumerate() {
                let lineno = i + 1;
                assert!(
                    !line.contains(&needle),
                    "commands/migration_new.rs:{lineno} spells the pre-lift \
                     `print_step_pass(&format!(\"{verb} {{}}\", …))` \
                     scaffold step-pass stanza inline — that shape was \
                     lifted onto `print_scaffold_path_action(\
                     ScaffoldPathVerb::{verb}, &<path>)`. A re-inline would \
                     silently reopen the four-site duplication class this \
                     shield exists to close. Offending line: {line:?}"
                );
            }
        }
    }

    /// Positive-delegation shield — the four pre-lift sites plus the
    /// primitive's own signature line must every one of them show up
    /// in the pre-`#[cfg(test)]` module body as
    /// `print_scaffold_path_action(` code-line hits. A hit-count below
    /// 5 means either a call site was dropped (semantic loss) or the
    /// primitive was renamed without updating this shield (drift). Pin
    /// the exact expected count so the shield does not accept "5 or
    /// more" and silently mask a follow-up regression.
    #[test]
    fn scaffold_path_action_delegation_count_pinned() {
        let source = include_str!("migration_new.rs");
        let body = crate::test_support::module_body_before_first_cfg_test(
            source,
            "commands/migration_new.rs",
        );
        let hits = body
            .lines()
            .filter(|line| line.contains("print_scaffold_path_action("))
            .count();
        assert_eq!(
            hits, 5,
            "expected exactly 5 code-line hits for \
             `print_scaffold_path_action(` in the pre-`#[cfg(test)]` \
             module body (1 fn signature + 4 call sites); got {hits}. \
             A count below 5 means a call site was dropped; a count \
             above 5 means a new site landed without a shield refresh"
        );
    }
}
