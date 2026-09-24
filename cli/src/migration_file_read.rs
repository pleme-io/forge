//! Async `tokio::fs::read_to_string(<file_path>).await
//! .with_context(|| format!("Failed to read migration file: {}",
//! <file_path>.display()))` primitive — the shared per-migration-file
//! read body every migration-validation check restated pre-lift.
//!
//! # Pre-lift census — two byte-identical sibling stanzas
//!
//! Both pre-lift sites in `cli/src/commands/migration_validation.rs`
//! spelled the same three-line async body, diverging on nothing (both
//! bind `file_path: PathBuf` from a `find_sql_files(migrations_dir)`
//! walk and reach `fs::read_to_string(&file_path)` through the
//! module-local `use tokio::fs;` import):
//!
//! ```ignore
//! let content = fs::read_to_string(&file_path)
//!     .await
//!     .with_context(|| format!("Failed to read migration file: {}", file_path.display()))?;
//! ```
//!
//! 1. `commands/migration_validation.rs::check_idempotency`
//!    (pre-lift ~L331-333) — the SQLx-legacy per-file walk that feeds
//!    each SQL migration's body into [`check_file_idempotency`] for
//!    the `IF NOT EXISTS` scan.
//! 2. `commands/migration_validation.rs::check_soft_delete_compliance`
//!    (pre-lift ~L470-472) — the SQLx-legacy per-file walk that feeds
//!    each SQL migration's body into [`check_file_soft_delete`] for
//!    the hard-DELETE scan against business tables.
//!
//! Each site propagated the `Result<String>` via `?` and named the
//! bound content on the LHS as `let content = …?;`; the post-lift
//! body preserves that propagation shape at both callers.
//!
//! # Sibling primitive for the `"Failed to read: {}"` orchestrator body
//!
//! Three OTHER sites in the same file spell a similar-shaped body
//! with a LESS specific envelope (`"Failed to read: {}"`) —
//! `validate_migrations_with_config` (two sites, one per gate branch:
//! idempotency + soft-delete) and `validate_seaorm_migrations` (one
//! site). Those sites live inside ORCHESTRATOR bodies that print a
//! `"   Found {N} migration files"` header a few lines earlier, so
//! the operator already has the "these are migration files" context
//! before any per-file error surfaces. The two sites [`read_migration_file`]
//! owns live inside the PUBLIC per-check entry points, which are
//! callable with a bare `migrations_dir` and no preamble, so their
//! canonical envelope carries the specific `"Failed to read migration
//! file:"` wording verbatim.
//!
//! Post-lift the three orchestrator-body sites forward through
//! [`read_migration_file_in_orchestrator_body`], a sibling primitive
//! that mirrors [`read_migration_file`]'s async body + UTF-8 posture +
//! `?`-propagation shape but carries the shorter operator envelope.
//! Each primitive keeps its own delegation shield (positive: primitive
//! body reaches the async read + envelope literal at exactly one
//! call), its own positive caller shield fixing the migrated forward
//! count on `commands/migration_validation.rs`, and a shared negative
//! caller shield forbidding either raw envelope literal from resurfacing
//! inline under `commands/`.
//!
//! A future audit that unified both envelope wordings onto ONE closed
//! `MigrationFileReadEnvelope` enum + one construction body would
//! surface at both negative caller shields below (which forbid BOTH
//! raw envelope literals inline under `commands/`), so the audit's
//! migration would land at one construction surface rather than
//! spreading a changed prose across five sites in lockstep.
//!
//! # Why a shared primitive, not an inline hand-copy at two sites
//!
//! Four load-bearing invariants a future edit would otherwise land at
//! two sites in lockstep:
//!
//! 1. **Async runtime choice.** Both sites reach [`tokio::fs::read_to_string`]
//!    via the module-local `use tokio::fs;` import. A future swap to
//!    `tokio::fs::File::open + read_to_string` for large-file streaming
//!    (a real concern once a migration file grows past a threshold that
//!    makes a full-buffer read wasteful), or to a `Bytes`-returning read
//!    for zero-copy propagation into the SQL parser, lands at ONE body.
//! 2. **Context-envelope wording.** The `"Failed to read migration
//!    file: <path>"` prose is the operator-facing envelope both callers
//!    propagate through `anyhow::Context`. A future rename ("Failed to
//!    load SQL migration:", a switch to a typed `#[error]` variant
//!    carrying `(file_path, io_error)`, a promotion to a structured
//!    tracing event with `file_path` as an attribute) lands at ONE
//!    edit, not two.
//! 3. **Encoding-error posture.** [`tokio::fs::read_to_string`] returns
//!    `Err(std::io::Error)` with `ErrorKind::InvalidData` when the file
//!    is not valid UTF-8. A future refinement that swapped to
//!    `read_bytes + String::from_utf8_lossy` (to survive a Windows-1252
//!    migration file authored by a legacy tool) or to a typed
//!    `MigrationEncodingError` distinct from an I/O error, lands at
//!    ONE body.
//! 4. **Observability hook.** A future OTLP `migration_file_read`
//!    span capturing (`file_path`, `bytes.len()`, `duration_ms`) —
//!    the shape forge's tracing surface already produces at other
//!    filesystem frontiers (see `crate::observability`) — lands at
//!    ONE body.
//!
//! Pre-lift each of the four invariants above lived at zero sites (no
//! caller carried any of them); post-lift each has ONE canonical home
//! the moment a future edit needs to introduce it.
//!
//! # THEORY grounding
//!
//! - `THEORY.md §V.1` (Construction guarantees; Types → Invariants →
//!   Proofs → Render Anywhere): the "read one SQL migration file into
//!   a `String` under a canonical operator-facing envelope" invariant
//!   lives at ONE construction surface — [`read_migration_file`] —
//!   and its byte-oracle tests below pin the envelope wording, the
//!   file-path interpolation, and the propagation shape as
//!   `cargo test`-verifiable invariants rather than as consumer-site
//!   conventions.
//! - `THEORY.md §VI.1` (Generation over composition; two-is-a-
//!   coincidence, three-is-a-law): two sibling occurrences sit at the
//!   coincidence threshold; combined with the three near-neighbor
//!   sites in the same file that spell a similar body with a less
//!   specific envelope, the shape is well past the "recurring" bar.
//!   The compounding-directive corollary — "every recurring shape
//!   becomes a helper before it becomes duplicated code" — is
//!   discharged at both consumers by construction.
//! - `THEORY.md §III` (Structure): the "SQL migration file at
//!   `<path>`" concept is a single named terminal in the migration-
//!   validation typescape; both consumers cite [`read_migration_file`]
//!   rather than restating the two-line body, so the terminal reads
//!   through one named surface everywhere.

use anyhow::{Context, Result};
use std::path::Path;

/// Read the SQL migration file at `file_path` into a `String` via
/// [`tokio::fs::read_to_string`], wrapped in the canonical
/// `.with_context(|| format!("Failed to read migration file: {}",
/// file_path.display()))` operator envelope every migration-validation
/// caller propagates through `anyhow::Context`. Returns `Ok(String)`
/// on success.
///
/// # UTF-8 posture
///
/// Delegates to [`tokio::fs::read_to_string`], which returns
/// [`std::io::ErrorKind::InvalidData`] when the file contents are not
/// valid UTF-8. The migration-validation callers assume UTF-8 SQL
/// throughout — the SQLx and SeaORM toolchains both write UTF-8 — so
/// an `InvalidData` failure surfaces here under the canonical envelope
/// verbatim, ready for the operator to inspect the offending byte at
/// the reported path.
///
/// # Errors
///
/// Any I/O failure from [`tokio::fs::read_to_string`] (file missing,
/// permission denied, invalid UTF-8, filesystem transient error)
/// surfaces as `Err(anyhow::Error)` carrying both the underlying
/// [`std::io::Error`] as the source chain AND the operator-facing
/// `"Failed to read migration file: <file_path>"` context.
//
// `#[allow(dead_code)]`: both pre-lift consumers (`check_idempotency`
// / `check_soft_delete_compliance` in `commands/migration_validation.rs`)
// are themselves `pub` but currently uncalled from any binary entry
// point (they carry the pre-existing dead-code warning), so this
// primitive inherits their reachability. The consumer sites still
// compile and the shielded tests below still run — the allow keeps
// clippy quiet without hiding a real reachability regression at any
// other future consumer.
#[allow(dead_code)]
pub async fn read_migration_file(file_path: &Path) -> Result<String> {
    tokio::fs::read_to_string(file_path)
        .await
        .with_context(|| format!("Failed to read migration file: {}", file_path.display()))
}

/// Read the migration file at `file_path` into a `String` via
/// [`tokio::fs::read_to_string`], wrapped in the shorter
/// `.with_context(|| format!("Failed to read: {}",
/// file_path.display()))` operator envelope every migration-validation
/// ORCHESTRATOR body propagates through `anyhow::Context`. Returns
/// `Ok(String)` on success.
///
/// # When to use this variant vs [`read_migration_file`]
///
/// This variant is the sibling primitive for ORCHESTRATOR-body
/// consumers — `commands/migration_validation.rs::{
/// validate_migrations_with_config, validate_seaorm_migrations}` — that
/// print a `"   Found {N} migration files"` header a few lines before
/// the per-file walk, so the operator already has the "these are
/// migration files" context on any per-file failure and the shorter
/// envelope reads naturally under it. Use [`read_migration_file`] at
/// PUBLIC per-check entry points that are callable with a bare
/// `migrations_dir` and no preamble; their canonical envelope carries
/// the more specific `"Failed to read migration file:"` wording.
///
/// # UTF-8 posture and errors
///
/// Same as [`read_migration_file`]: delegates to
/// [`tokio::fs::read_to_string`], returns `Err(anyhow::Error)` on any
/// I/O failure (missing file, permission denied, invalid UTF-8,
/// filesystem transient error) carrying both the underlying
/// [`std::io::Error`] as the source chain AND the operator-facing
/// `"Failed to read: <file_path>"` context.
pub async fn read_migration_file_in_orchestrator_body(file_path: &Path) -> Result<String> {
    tokio::fs::read_to_string(file_path)
        .await
        .with_context(|| format!("Failed to read: {}", file_path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-oracle: [`read_migration_file`] must round-trip the file
    /// contents verbatim — no BOM strip, no line-ending normalization,
    /// no trailing-newline trim. Pins the byte-preservation contract
    /// the SQLx / SeaORM parsers on the caller side depend on: a
    /// migration whose body ends without a trailing newline must
    /// survive the read without one appearing, and a migration whose
    /// body carries a non-ASCII UTF-8 comment (`é`) must round-trip
    /// byte-for-byte.
    #[tokio::test]
    async fn read_roundtrips_bytes_verbatim() {
        let expected = "CREATE TABLE t (id INT);\n-- caf\u{00e9}\n";
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("V1__init.sql");
        std::fs::write(&path, expected).expect("seed migration file");
        let observed = read_migration_file(&path)
            .await
            .expect("read of a valid UTF-8 file must succeed");
        assert_eq!(
            observed, expected,
            "bytes must survive the primitive round-trip byte-for-byte"
        );
    }

    /// Byte-oracle: reading a file that does not exist must surface
    /// `Err(anyhow::Error)` whose display carries the canonical
    /// `"Failed to read migration file: <file_path>"` envelope with
    /// `<file_path>` rendered via [`std::path::Path::display`]. Pinned
    /// by pointing at a path whose parent directory does not exist —
    /// a deterministic I/O failure on every supported target — and
    /// asserting both the wording and the interpolated path appear
    /// in the chained display.
    ///
    /// A future rename ("Failed to load SQL migration:", a swap to a
    /// typed `#[error]` variant that omits the file path, or a
    /// `.context` in place of `.with_context` losing the path
    /// interpolation) would surface here at the primitive body once,
    /// not at two consumer sites via observed operator prose drift.
    #[tokio::test]
    async fn read_failure_surfaces_canonical_envelope_with_file_path() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let missing = tmp
            .path()
            .join("no_such_dir")
            .join("also_missing")
            .join("V1__init.sql");
        let err = read_migration_file(&missing)
            .await
            .expect_err("read of a non-existent file must fail");
        let rendered = format!("{:#}", err);
        assert!(
            rendered.contains("Failed to read migration file:"),
            "envelope wording must be present, got: {rendered}"
        );
        assert!(
            rendered.contains(&missing.display().to_string()),
            "envelope must interpolate the file path via display, got: {rendered}"
        );
    }

    /// Byte-oracle: reading an empty migration file must succeed and
    /// produce an empty `String`. Pins the semantic that "no bytes"
    /// is a legitimate migration body — the SQLx / SeaORM engines
    /// tolerate an empty file at rest — so a future refactor that
    /// introduced a `if content.is_empty() { bail!(...) }` guard (a
    /// sensible-looking but wrong "defend against empty migrations"
    /// edit at the primitive layer) would regress this assertion.
    /// Empty-migration detection is the caller's job (see the
    /// `check_file_*` scanners), not the read primitive's.
    #[tokio::test]
    async fn read_of_empty_file_yields_empty_string() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("V0__empty.sql");
        std::fs::write(&path, b"").expect("seed empty migration file");
        let observed = read_migration_file(&path)
            .await
            .expect("empty read should succeed");
        assert!(
            observed.is_empty(),
            "empty file must produce an empty String, got {} bytes",
            observed.len()
        );
    }

    /// Byte-oracle: a file whose contents are not valid UTF-8 must
    /// surface `Err(anyhow::Error)` under the canonical envelope.
    /// Pins the encoding-error posture that composes with the
    /// SQLx / SeaORM parsers on the caller side: a Windows-1252 or
    /// Latin-1 migration authored by a legacy tool surfaces at the
    /// read primitive with the same operator envelope as a missing
    /// file, so the operator does not have to distinguish an I/O
    /// failure from an encoding failure at the callsite — both reach
    /// them through one canonical envelope with the offending path
    /// interpolated verbatim.
    ///
    /// The fixture writes a stray `0xFF` byte, which is not a valid
    /// UTF-8 leading byte, so [`tokio::fs::read_to_string`] returns
    /// [`std::io::ErrorKind::InvalidData`] and this primitive wraps
    /// the failure in the canonical envelope.
    #[tokio::test]
    async fn read_of_invalid_utf8_surfaces_canonical_envelope() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("V2__bad_utf8.sql");
        std::fs::write(&path, [0xFFu8, 0xFEu8, 0xFDu8]).expect("seed invalid-UTF-8 file");
        let err = read_migration_file(&path)
            .await
            .expect_err("read of an invalid-UTF-8 file must fail");
        let rendered = format!("{:#}", err);
        assert!(
            rendered.contains("Failed to read migration file:"),
            "envelope wording must be present even on an encoding failure, got: {rendered}"
        );
        assert!(
            rendered.contains(&path.display().to_string()),
            "envelope must interpolate the file path via display on an encoding failure, got: {rendered}"
        );
    }

    /// Delegation shield (positive half): each primitive body reaches
    /// [`tokio::fs::read_to_string`] at exactly one call — no fallback
    /// path, no double-read, no branching on `file_path`. Pins the
    /// one-oracle discipline THEORY §VI.1 requires: a future refactor
    /// that introduced a `#[cfg(target_os = "...")]` gate or a
    /// try-then-retry read body would surface here. The module carries
    /// TWO primitive bodies ([`read_migration_file`] and
    /// [`read_migration_file_in_orchestrator_body`]), so the module-wide
    /// count is exactly 2 — one per primitive.
    ///
    /// # Self-match discipline
    ///
    /// The needle is reconstructed at test time by concatenating the
    /// three tokens `tokio`, `::fs::read_to_string`, and `(` so this
    /// test body does not itself contain the literal string the count
    /// is asserted on. A shield that spelled the full literal
    /// `"tokio::fs::read_to_string("` inline would false-match itself
    /// on the count-eq-2 assertion, mirroring the self-match trap
    /// [`crate::test_support::canonical_two_arg_sigil_needle`]
    /// documents at length.
    #[test]
    fn primitive_bodies_reach_tokio_fs_read_to_string_at_expected_count() {
        let source = include_str!("migration_file_read.rs");
        let needle = format!("{}{}{}", "tokio", "::fs::read_to_string", "(");
        let hits = crate::test_support::code_line_hits(source, &needle);
        assert_eq!(
            hits.len(),
            2,
            "migration_file_read.rs must reach the async read call at exactly 2 \
             code lines — one per primitive body (`read_migration_file` + \
             `read_migration_file_in_orchestrator_body`); got {hits:#?}"
        );
    }

    /// Delegation shield (positive half): the primitive body reaches
    /// the canonical `"Failed to read migration file: {}"` operator
    /// envelope literal at exactly one code line (the primitive body).
    /// Pins the one-envelope discipline: a future edit that
    /// duplicated the wording onto a fallback path or a tracing
    /// event would surface here.
    ///
    /// # Self-match discipline
    ///
    /// The needle is reconstructed at test time from three tokens so
    /// this test body's own strings never spell the full literal.
    #[test]
    fn primitive_reaches_canonical_envelope_at_exactly_one_call() {
        let source = include_str!("migration_file_read.rs");
        let needle = format!("\"{}{}{}\"", "Failed to read migration ", "file: ", "{}");
        let hits = crate::test_support::code_line_hits(source, &needle);
        assert_eq!(
            hits.len(),
            1,
            "migration_file_read.rs primitive body must reach the canonical \
             envelope literal at exactly one code line (the primitive body); \
             got {hits:#?}"
        );
    }

    /// Caller shield (positive half): each of the two pre-lift
    /// consumer sites now reaches [`read_migration_file`]. Anchored
    /// on the fully qualified path so a future refactor that renamed
    /// the module or dropped the `crate::migration_file_read::`
    /// prefix on one call site would regress the count.
    #[test]
    fn command_modules_reach_read_migration_file_at_expected_forwards() {
        let source = include_str!("commands/migration_validation.rs");
        let hits = crate::test_support::code_line_hits(
            source,
            "crate::migration_file_read::read_migration_file(",
        );
        assert_eq!(
            hits.len(),
            2,
            "commands/migration_validation.rs must reach \
             `crate::migration_file_read::read_migration_file(` at exactly 2 \
             code lines (check_idempotency + check_soft_delete_compliance); \
             got {hits:#?}"
        );
    }

    /// Caller shield (negative half): no source line under
    /// `cli/src/commands/` may respell the pre-lift raw
    /// `.with_context(|| format!("Failed to read migration file: {}",`
    /// envelope inline any more. Both pre-lift sites migrated onto
    /// [`read_migration_file`]; any future consumer that wants the
    /// same migration-read body reaches for the primitive on first
    /// grep, not by copy-pasting the raw stanza from another command
    /// module.
    ///
    /// Mirrors the negative-half shield the sibling
    /// [`crate::graphql_schema_write`] primitive carries on the
    /// `"Failed to write schema to {}"` write envelope.
    #[test]
    fn no_command_module_still_spells_raw_failed_to_read_migration_file_envelope() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let mut offenders: Vec<(PathBuf, usize, String)> = Vec::new();
        for entry in std::fs::read_dir(&commands_dir).unwrap().flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).unwrap();
            let mut in_block_comment = false;
            for (idx, line) in source.lines().enumerate() {
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") {
                    continue;
                }
                if trimmed.starts_with("/*") {
                    in_block_comment = true;
                }
                if in_block_comment {
                    if trimmed.contains("*/") {
                        in_block_comment = false;
                    }
                    continue;
                }
                if line.contains("\"Failed to read migration file: {}\"") {
                    offenders.push((path.clone(), idx + 1, line.trim().to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "no command module may respell the pre-lift raw \
             `\"Failed to read migration file: {{}}\"` envelope inline — reach \
             for `crate::migration_file_read::read_migration_file` instead; \
             offenders: {offenders:#?}"
        );
    }

    // =========================================================================
    // Sibling primitive: `read_migration_file_in_orchestrator_body`
    // =========================================================================

    /// Byte-oracle: [`read_migration_file_in_orchestrator_body`] must
    /// round-trip the file contents verbatim — no BOM strip, no
    /// line-ending normalization, no trailing-newline trim. Pins the
    /// byte-preservation contract the SQLx / SeaORM parsers on the
    /// caller side depend on, mirroring the primary primitive's
    /// [`read_roundtrips_bytes_verbatim`] discipline.
    #[tokio::test]
    async fn orchestrator_body_read_roundtrips_bytes_verbatim() {
        let expected = "CREATE TABLE t (id INT);\n-- caf\u{00e9}\n";
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("V1__init.sql");
        std::fs::write(&path, expected).expect("seed migration file");
        let observed = read_migration_file_in_orchestrator_body(&path)
            .await
            .expect("read of a valid UTF-8 file must succeed");
        assert_eq!(
            observed, expected,
            "bytes must survive the primitive round-trip byte-for-byte"
        );
    }

    /// Byte-oracle: reading a file that does not exist must surface
    /// `Err(anyhow::Error)` whose display carries the shorter
    /// `"Failed to read: <file_path>"` envelope with `<file_path>`
    /// rendered via [`std::path::Path::display`]. Distinguishes the
    /// sibling primitive's envelope from the primary primitive's
    /// verbatim so a swap between the two at either caller class
    /// surfaces at operator readout via the envelope wording.
    #[tokio::test]
    async fn orchestrator_body_read_failure_surfaces_short_envelope_with_file_path() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let missing = tmp
            .path()
            .join("no_such_dir")
            .join("also_missing")
            .join("V1__init.sql");
        let err = read_migration_file_in_orchestrator_body(&missing)
            .await
            .expect_err("read of a non-existent file must fail");
        let rendered = format!("{:#}", err);
        // The shorter envelope prefix appears verbatim and is NOT the
        // primary primitive's `"Failed to read migration file:"` shape.
        assert!(
            rendered.contains("Failed to read: "),
            "short envelope wording must be present, got: {rendered}"
        );
        assert!(
            !rendered.contains("Failed to read migration file:"),
            "sibling primitive must NOT carry the primary primitive's specific \
             envelope wording — that would collapse the operator-facing distinction \
             this primitive exists to preserve; got: {rendered}"
        );
        assert!(
            rendered.contains(&missing.display().to_string()),
            "envelope must interpolate the file path via display, got: {rendered}"
        );
    }

    /// Byte-oracle: reading an empty migration file must succeed and
    /// produce an empty `String`. Mirrors the primary primitive's
    /// discipline that "no bytes" is a legitimate migration body —
    /// empty-migration detection is the caller's job, not the read
    /// primitive's.
    #[tokio::test]
    async fn orchestrator_body_read_of_empty_file_yields_empty_string() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("V0__empty.sql");
        std::fs::write(&path, b"").expect("seed empty migration file");
        let observed = read_migration_file_in_orchestrator_body(&path)
            .await
            .expect("empty read should succeed");
        assert!(
            observed.is_empty(),
            "empty file must produce an empty String, got {} bytes",
            observed.len()
        );
    }

    /// Delegation shield (positive half): the sibling primitive body
    /// reaches the shorter `"Failed to read: {}"` operator envelope
    /// literal at exactly one code line (the sibling primitive body).
    /// Pins the one-envelope discipline for the sibling: a future edit
    /// that duplicated the wording onto a fallback path or a tracing
    /// event would surface here. The needle is reconstructed at test
    /// time from three tokens so this test body's own strings never
    /// spell the full literal.
    #[test]
    fn orchestrator_body_primitive_reaches_short_envelope_at_exactly_one_call() {
        let source = include_str!("migration_file_read.rs");
        let needle = format!("\"{}{}{}\"", "Failed to ", "read: ", "{}");
        let hits = crate::test_support::code_line_hits(source, &needle);
        assert_eq!(
            hits.len(),
            1,
            "migration_file_read.rs sibling primitive body must reach the shorter \
             envelope literal at exactly one code line (the sibling primitive body); \
             got {hits:#?}"
        );
    }

    /// Caller shield (positive half): each of the three pre-lift
    /// orchestrator-body consumer sites now reaches
    /// [`read_migration_file_in_orchestrator_body`]. Anchored on the
    /// fully qualified path so a future refactor that renamed the
    /// module or dropped the `crate::migration_file_read::` prefix on
    /// one call site would regress the count.
    #[test]
    fn command_modules_reach_orchestrator_body_primitive_at_expected_forwards() {
        let source = include_str!("commands/migration_validation.rs");
        let hits = crate::test_support::code_line_hits(
            source,
            "crate::migration_file_read::read_migration_file_in_orchestrator_body(",
        );
        assert_eq!(
            hits.len(),
            3,
            "commands/migration_validation.rs must reach \
             `crate::migration_file_read::read_migration_file_in_orchestrator_body(` \
             at exactly 3 code lines (validate_migrations_with_config × 2 gate \
             branches + validate_seaorm_migrations); got {hits:#?}"
        );
    }

    /// Caller shield (negative half): no source line under
    /// `cli/src/commands/` may respell the pre-lift raw
    /// `"Failed to read: {}"` short envelope inline any more. All
    /// three pre-lift orchestrator-body sites migrated onto
    /// [`read_migration_file_in_orchestrator_body`]; any future
    /// consumer that wants the same short-envelope migration-read body
    /// reaches for the sibling primitive on first grep, not by
    /// copy-pasting the raw stanza from another command module.
    ///
    /// Mirrors the negative-half shield the sibling
    /// [`no_command_module_still_spells_raw_failed_to_read_migration_file_envelope`]
    /// test carries on the primary primitive's specific envelope.
    #[test]
    fn no_command_module_still_spells_raw_short_read_envelope() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let mut offenders: Vec<(PathBuf, usize, String)> = Vec::new();
        for entry in std::fs::read_dir(&commands_dir).unwrap().flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).unwrap();
            let mut in_block_comment = false;
            for (idx, line) in source.lines().enumerate() {
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") {
                    continue;
                }
                if trimmed.starts_with("/*") {
                    in_block_comment = true;
                }
                if in_block_comment {
                    if trimmed.contains("*/") {
                        in_block_comment = false;
                    }
                    continue;
                }
                if line.contains("\"Failed to read: {}\"") {
                    offenders.push((path.clone(), idx + 1, line.trim().to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "no command module may respell the pre-lift raw \
             `\"Failed to read: {{}}\"` short envelope inline — reach for \
             `crate::migration_file_read::read_migration_file_in_orchestrator_body` \
             instead; offenders: {offenders:#?}"
        );
    }
}
