//! Async `tokio::fs::write(<dest>, <schema_bytes>)` + canonical
//! `.with_context(|| format!("Failed to write schema to {}",
//! <dest>.display()))` envelope primitive — the shared post-extract
//! byte-write body every schema-consumer site restates verbatim
//! pre-lift.
//!
//! # Pre-lift census — three byte-identical sibling stanzas
//!
//! All three sites pre-lift spelled the same three-line async body,
//! diverging only on the destination-path binding:
//!
//! ```ignore
//! tokio::fs::write(<dest>, &schema_bytes)
//!     .await
//!     .with_context(|| format!("Failed to write schema to {}", <dest>.display()))?;
//! ```
//!
//! 1. `commands/codegen.rs::execute` (pre-lift ~L98-100) — the Step-1
//!    schema-export write following
//!    [`crate::graphql_schema::extract_graphql_schema`] against the
//!    backend directory. `<dest> = &schema_path` where
//!    `schema_path = web_dir.join("schema.graphql")`.
//! 2. `commands/codegen.rs::export_schema_only` (pre-lift ~L185-187) —
//!    the schema-only entry point that skips the codegen step. `<dest>
//!    = output_path` where `output_path: &Path` is the caller-supplied
//!    destination (no `web_dir.join` — the caller owns full-path
//!    selection).
//! 3. `commands/codegen_validation.rs::execute` (pre-lift ~L126-128) —
//!    the drift-check Step-1 schema-export write that must exist before
//!    the drift-detection walk over `web_dir` starts. `<dest> =
//!    &schema_path` where `schema_path = web_dir.join("schema.graphql")`.
//!
//! Each site produced `Result<()>` via the `?` propagation; the
//! post-lift body preserves that propagation shape at the caller.
//!
//! # Distinct from every peer primitive on the schema frontier
//!
//! - [`crate::graphql_schema::extract_graphql_schema`] owns the SDL
//!   BYTE-BUFFER PRODUCER side: it runs `cargo run --bin extract-schema
//!   --quiet` in a backend directory and returns the captured stdout
//!   bytes verbatim. This primitive owns the BYTE-BUFFER CONSUMER side
//!   at the destination-path terminal: the extract primitive hands off
//!   `Vec<u8>` and this primitive writes it to disk under one canonical
//!   error envelope. The two compose end-to-end at three of the four
//!   consumer sites (`commands/codegen.rs::{execute, export_schema_only}`,
//!   `commands/codegen_validation.rs::execute`); the fourth site
//!   (`commands/sync.rs::execute_drift_check`) reads the SDL bytes but
//!   does not write them to disk — it walks `web_dir` for drift-vs-schema
//!   directly against the returned buffer.
//! - [`crate::bun_x_graphql_codegen_capture`] owns the `bun x
//!   graphql-codegen --config codegen.ts` invocation surface. That
//!   primitive TRIGGERS regeneration of the TypeScript hooks from the
//!   already-written `schema.graphql` file; this primitive OWNS the
//!   write of that file. The two compose sequentially at Steps 2 and 4
//!   of `commands/codegen.rs::execute`, and again at Steps 1 and 3 of
//!   `commands/codegen_validation.rs::execute`.
//! - [`crate::bun_install_frozen_lockfile_capture`] owns the dependency
//!   preamble the codegen driver runs before `bun x graphql-codegen`.
//!   That primitive owns process spawn + capture; this primitive owns
//!   filesystem write + context envelope. Two disjoint concerns on the
//!   same codegen pipeline.
//!
//! # Why a shared primitive, not an inline hand-copy at three sites
//!
//! Four load-bearing invariants a future edit would otherwise have to
//! land at three sites in lockstep:
//!
//! 1. **Async runtime.** All three sites already reach `tokio::fs::write`
//!    (two through `use tokio::fs;`, one directly qualified). A future
//!    swap to `tokio::fs::File::create + write_all` for chunked writes,
//!    or to `tokio::fs::OpenOptions` for O_CREAT + O_EXCL to reject
//!    overwrite of an existing `schema.graphql`, lands at one body.
//! 2. **Context-envelope wording.** The `"Failed to write schema to
//!    <path>"` prose is the operator-facing envelope every caller
//!    propagates through `anyhow::Context`. A future rename ("Failed
//!    to persist schema to", "GraphQL schema write failed:", a switch
//!    to a typed `#[error]` variant carrying `(dest_path, io_error)`)
//!    is one edit at the primitive body, not three at three sites.
//! 3. **Atomicity discipline.** A future refinement to
//!    write-tmp-and-rename atomicity (write bytes to `schema.graphql.tmp`,
//!    then `tokio::fs::rename` onto `schema.graphql`) — the shape
//!    codegen consumers care about because a partial write leaves a
//!    truncated `schema.graphql` that fails downstream `bun x
//!    graphql-codegen` with a confusing parse error — lands at one
//!    body, not three.
//! 4. **Observability hook.** A future OTLP `schema_bytes_written`
//!    span capturing (`dest`, `bytes.len()`, `duration_ms`) — the shape
//!    forge's tracing surface already produces at other filesystem
//!    frontiers (see `crate::observability`) — lands at one body.
//!
//! Pre-lift each of the four invariants above lived at zero sites (no
//! caller carried any of them); post-lift each has ONE canonical
//! home the moment a future edit needs to introduce it.
//!
//! # THEORY grounding
//!
//! - `THEORY.md §V.1` (Construction guarantees; Types → Invariants →
//!   Proofs → Render Anywhere): the "schema-bytes → schema.graphql
//!   on disk under a canonical envelope" invariant lives at ONE
//!   construction surface — [`write_graphql_schema_bytes`] — and its
//!   byte-oracle tests below pin the envelope wording, the destination
//!   binding, and the propagation shape as `cargo test`-verifiable
//!   invariants rather than as consumer-site conventions.
//! - `THEORY.md §VI.1` (Generation over composition; three-times
//!   rule): three sibling occurrences past the "two is a coincidence;
//!   three is a law" threshold, so the write-then-context body lifts
//!   onto ONE typed body and all three consumers cite it. The
//!   compounding-directive corollary — "every recurring shape becomes
//!   a helper before it becomes duplicated code" — is discharged at
//!   the three consumers by construction.
//! - `THEORY.md §III.1` (typescape as root data structure): the
//!   destination-path terminal of the SDL byte buffer is a single
//!   named concept; all three consumers cite [`write_graphql_schema_bytes`]
//!   rather than each restating the two-line body.

use anyhow::{Context, Result};
use std::path::Path;

/// Write the GraphQL SDL byte buffer `bytes` to `dest` via
/// [`tokio::fs::write`], wrapped in the canonical `.with_context(||
/// format!("Failed to write schema to {}", dest.display()))` operator
/// envelope every schema-consumer site propagates through
/// `anyhow::Context`. Returns `Ok(())` on success.
///
/// # Byte preservation
///
/// The bytes reach disk verbatim; there is no UTF-8 round-trip, no
/// trim, no normalization. This matches the byte-preservation contract
/// [`crate::graphql_schema::extract_graphql_schema`] returns on the
/// producer side — the two primitives compose end-to-end so
/// non-ASCII UTF-8 in an extractor's stdout (e.g. an `é` inside a
/// schema comment) survives the extract-write round trip byte-for-byte.
///
/// # Errors
///
/// Any I/O failure from [`tokio::fs::write`] (missing parent directory,
/// permission denied, disk full, filesystem read-only, symlink loop)
/// surfaces as `Err(anyhow::Error)` carrying both the underlying
/// [`std::io::Error`] as the source chain AND the operator-facing
/// `"Failed to write schema to <dest>"` context. Downstream callers
/// that `.map_err(...)` into a typed result struct (see
/// `commands/codegen_validation.rs::CodegenValidationResult`) receive
/// the anyhow-chained display verbatim.
pub async fn write_graphql_schema_bytes(bytes: &[u8], dest: &Path) -> Result<()> {
    tokio::fs::write(dest, bytes)
        .await
        .with_context(|| format!("Failed to write schema to {}", dest.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-oracle: [`write_graphql_schema_bytes`] must land the input
    /// bytes on disk at `dest` verbatim — no UTF-8 round-trip, no trim,
    /// no BOM prepend, no trailing-newline normalization. Pins the
    /// byte-preservation contract that composes with
    /// [`crate::graphql_schema::extract_graphql_schema`]'s producer-
    /// side byte-verbatim invariant so the extract-write round trip
    /// stays lossless end-to-end. The fixture bytes include a non-ASCII
    /// UTF-8 pair (`é` = 0xC3 0xA9) and a trailing newline so a future
    /// regression that added a `.trim()` or `String::from_utf8_lossy`
    /// at the primitive surface would surface here loudly rather than
    /// silently corrupting real schemas at the three consumer sites.
    #[tokio::test]
    async fn write_lands_bytes_on_disk_verbatim() {
        let expected: &[u8] = b"type Query { hello: String }\n# comment with UTF-8: caf\xc3\xa9\n";
        let tmp = tempfile::tempdir().expect("tempdir");
        let dest = tmp.path().join("schema.graphql");
        write_graphql_schema_bytes(expected, &dest)
            .await
            .expect("write should succeed on a writable tempdir");
        let observed = std::fs::read(&dest).expect("dest must exist after successful write");
        assert_eq!(
            observed.as_slice(),
            expected,
            "bytes must survive the primitive round-trip byte-for-byte"
        );
    }

    /// Byte-oracle: a failing write must surface `Err(anyhow::Error)`
    /// whose display carries the canonical `"Failed to write schema to
    /// <dest>"` envelope with `<dest>` rendered via
    /// [`std::path::Path::display`]. Pinned by writing to a path whose
    /// parent directory does not exist — a deterministic I/O failure on
    /// every supported target — and asserting both the wording and the
    /// interpolated path appear in the chained display.
    ///
    /// A future rename ("Failed to persist schema to", a swap to a
    /// typed `#[error]` variant that omits the destination path, or a
    /// `.context` in place of `.with_context` losing the path
    /// interpolation) would surface here at the primitive body once,
    /// not at three consumer sites via observed operator prose drift.
    #[tokio::test]
    async fn write_failure_surfaces_canonical_envelope_with_dest_path() {
        let tmp = tempfile::tempdir().expect("tempdir");
        // A path under a non-existent nested directory guarantees the
        // write fails without touching any pre-existing filesystem
        // state.
        let dest = tmp
            .path()
            .join("no_such_dir")
            .join("also_missing")
            .join("schema.graphql");
        let err = write_graphql_schema_bytes(b"any bytes", &dest)
            .await
            .expect_err("write into a non-existent parent must fail");
        let rendered = format!("{:#}", err);
        assert!(
            rendered.contains("Failed to write schema to"),
            "envelope wording must be present, got: {rendered}"
        );
        assert!(
            rendered.contains(&dest.display().to_string()),
            "envelope must interpolate the dest path via display, got: {rendered}"
        );
    }

    /// Byte-oracle: writing an empty byte slice must succeed and
    /// produce an empty file at `dest`. Pins the semantic that "no
    /// bytes" is a legitimate output — [`tokio::fs::write`] creates the
    /// file and truncates to zero bytes on success — so a future
    /// refactor that introduced a `if bytes.is_empty() { bail!(...) }`
    /// guard (a sensible-looking but wrong "defend against
    /// empty-schema" edit) would regress this assertion. Empty-stdout
    /// detection is the extract primitive's job (see
    /// [`crate::graphql_schema::SchemaExtractionError::EmptyOutput`]),
    /// not the write primitive's.
    #[tokio::test]
    async fn write_of_empty_bytes_creates_empty_file() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dest = tmp.path().join("empty-schema.graphql");
        write_graphql_schema_bytes(b"", &dest)
            .await
            .expect("empty write should succeed");
        let observed = std::fs::read(&dest).expect("dest must exist after successful empty write");
        assert!(
            observed.is_empty(),
            "empty write must produce a zero-byte file, got {} bytes",
            observed.len()
        );
    }

    /// Byte-oracle: overwriting an existing file at `dest` replaces its
    /// contents in full (no append, no merge). Pins the truncate-then-
    /// write semantic [`tokio::fs::write`] carries — critical at the
    /// three consumer sites, where every `forge codegen` /
    /// `forge codegen-validation` run rewrites `schema.graphql` at the
    /// same path and must not leave residual bytes from a previous,
    /// larger schema visible past the new bytes' end.
    #[tokio::test]
    async fn write_overwrites_existing_file_in_full() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dest = tmp.path().join("schema.graphql");
        std::fs::write(&dest, b"stale bytes that must be overwritten")
            .expect("prime the file with stale bytes");
        let fresh: &[u8] = b"fresh";
        write_graphql_schema_bytes(fresh, &dest)
            .await
            .expect("overwrite should succeed");
        let observed = std::fs::read(&dest).expect("dest must exist after overwrite");
        assert_eq!(
            observed.as_slice(),
            fresh,
            "existing bytes must be truncated and replaced, not appended to"
        );
    }

    /// Delegation shield (positive half): the primitive body reaches
    /// `tokio::fs::write(` at exactly one call — no fallback path, no
    /// double-write, no branching on `dest`. Pins the one-oracle
    /// discipline THEORY §VI.1 requires: a future refactor that
    /// introduced a `#[cfg(target_os = "...")]` gate or a
    /// try-then-retry write body would surface here.
    ///
    /// # Self-match discipline
    ///
    /// The needle is reconstructed at test time by concatenating the
    /// three tokens `tokio`, `::fs::write`, and `(` so this test body
    /// does not itself contain the literal string the count is
    /// asserted on. The needle-carrying `format!` template holds the
    /// tokens in three separate string literals; a shield that
    /// spelled the full literal `"tokio::fs::write("` inline would
    /// false-match itself on the count-eq-1 assertion, mirroring the
    /// self-match trap [`crate::test_support::canonical_two_arg_sigil_needle`]
    /// documents at length.
    #[test]
    fn primitive_reaches_tokio_fs_write_at_exactly_one_call() {
        let source = include_str!("graphql_schema_write.rs");
        let needle = format!("{}{}{}", "tokio", "::fs::write", "(");
        let hits = crate::test_support::code_line_hits(source, &needle);
        assert_eq!(
            hits.len(),
            1,
            "graphql_schema_write.rs primitive body must reach the async write \
             call at exactly one code line (the primitive body); got {hits:#?}"
        );
    }

    /// Caller shield (negative half): no source line under
    /// `cli/src/commands/` may respell the pre-lift raw
    /// `.with_context(|| format!("Failed to write schema to {}",` envelope
    /// inline any more. All three pre-lift sites migrated onto
    /// [`write_graphql_schema_bytes`]; any future consumer that wants the
    /// same schema-write body reaches for the primitive on first grep,
    /// not by copy-pasting the raw stanza from another command module.
    ///
    /// Mirrors the negative half of the sibling
    /// `no_command_module_still_spells_raw_bun_install_frozen_lockfile_argv`
    /// shield on [`crate::bun_argv`] and the
    /// `no_command_module_still_spells_raw_cargo_integration_or_e2e_argv`
    /// shield on [`crate::cargo_test_argv`].
    #[test]
    fn no_command_module_still_spells_raw_failed_to_write_schema_envelope() {
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
                if line.contains("\"Failed to write schema to {}\"") {
                    offenders.push((path.clone(), idx + 1, line.trim().to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "no command module may respell the pre-lift raw \
             `\"Failed to write schema to {{}}\"` envelope inline — reach for \
             `crate::graphql_schema_write::write_graphql_schema_bytes` instead; \
             offenders: {offenders:#?}"
        );
    }

    /// Delegation shield (positive half): each of the three pre-lift
    /// consumer sites now reaches
    /// [`write_graphql_schema_bytes`]. Anchored on the fully qualified
    /// path so a future refactor that renamed the module or dropped the
    /// `crate::graphql_schema_write::` prefix on one call site would
    /// regress the count.
    #[test]
    fn command_modules_reach_write_graphql_schema_bytes_at_expected_forwards() {
        // (module source, expected forward-call count)
        let expectations: &[(&str, &str, usize)] = &[
            (
                "codegen.rs",
                include_str!("commands/codegen.rs"),
                2, // `execute` + `export_schema_only`
            ),
            (
                "codegen_validation.rs",
                include_str!("commands/codegen_validation.rs"),
                1, // `execute`
            ),
        ];
        for (label, source, expected) in expectations {
            let hits = crate::test_support::code_line_hits(
                source,
                "crate::graphql_schema_write::write_graphql_schema_bytes(",
            );
            assert_eq!(
                hits.len(),
                *expected,
                "{label} must reach \
                 `crate::graphql_schema_write::write_graphql_schema_bytes(` at exactly \
                 {expected} code line(s); got {hits:#?}"
            );
        }
    }
}
