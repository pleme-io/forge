//! Typed primitive for extracting a GraphQL schema from a Rust backend.
//!
//! Four command-module sites in forge drive the same three-step incantation
//! against the backend's `extract-schema` binary:
//! ```text
//! let output = Command::new("cargo")
//!     .args(["run", "--bin", "extract-schema", "--quiet"])
//!     .current_dir(backend_dir)
//!     .output().await
//!     .with_context(|| format!("Failed to run extract-schema in {}", backend_dir.display()))?;
//! if !output.status.success() {
//!     let stderr = String::from_utf8_lossy(&output.stderr);
//!     bail!("Schema extraction failed:\n{}", stderr);
//! }
//! if output.stdout.is_empty() {
//!     bail!("Schema extraction produced no output");
//! }
//! ```
//! carried verbatim modulo per-site failure envelope (anyhow `bail!` vs. an
//! `Ok(ValidationResult { error: Some(_), … })` field). Four identically-
//! shaped bodies past THEORY §VI.1's three-times threshold (PRIME
//! DIRECTIVE: duplication budget is zero):
//!
//! - `commands/codegen.rs::execute`
//! - `commands/codegen.rs::export_schema_only`
//! - `commands/codegen_validation.rs::execute`
//! - `commands/codegen_validation.rs::validate_schema_export`
//!
//! This module is the law-redeeming consolidation. Three load-bearing
//! properties this primitive owns that the pre-lift raw-spawn stanzas
//! dropped:
//!
//! 1. **`CARGO` env override.** Pre-lift each site spelled
//!    `Command::new("cargo")`, ignoring the env var `commands/bootstrap.rs`
//!    honors via `get_tool_path("CARGO", "cargo")` — so a Nix-hermetic
//!    runner with a store-path `cargo` would fall through to whatever
//!    `cargo` was first on PATH at these four sites specifically.
//! 2. **Typed error dispatch.** Pre-lift, spawn failure and op failure
//!    fused into anyhow strings that dropped the exit code (the `bail!`
//!    said "failed" without saying "exit N"). Post-lift both surface as
//!    typed [`SchemaExtractionError`] variants carrying the structural
//!    `(backend_dir, exit_code, stderr)` tuple THEORY §V.4 Phase 1
//!    attestation records pattern-match on. Empty-stdout gets its own
//!    variant distinct from a non-zero exit — the schema-drift call site
//!    in `codegen_validation.rs` already treated the two shapes
//!    distinctly and had to open-code the discrimination.
//! 3. **Backend-directory in every failure record.** Pre-lift, only the
//!    `with_context` spawn-failure carried `backend_dir`; the op-failure
//!    and empty-stdout `bail!`s dropped it. Post-lift every failure
//!    variant carries the offending path so a caller can attach it to
//!    a Phase 1 attestation / telemetry record without re-parsing.
//!
//! THEORY.md §V.1 (Types → Invariants → Proofs): the "extract-schema
//! ran and produced non-empty bytes" invariant is proved at the extract
//! frontier and carried by the return type `Vec<u8>`, not re-derived at
//! four consumer sites. THEORY.md §VI.1 (one-oracle): the extract-schema
//! invocation shape is named here and every consumer reads through it.

use std::path::{Path, PathBuf};
use thiserror::Error;
use tokio::process::Command;

use crate::repo::get_tool_path;
use crate::retry::classify_capture;

/// Why an `extract-schema` invocation failed to produce a usable
/// GraphQL-SDL byte buffer. Carries the offending `backend_dir` so a
/// caller can attach it to a failure record without re-parsing the
/// display string.
#[derive(Error, Debug)]
pub enum SchemaExtractionError {
    /// The `cargo` binary could not be spawned. Fires when `CARGO` (or
    /// the fallback `cargo` on `PATH`) resolves to a missing / non-
    /// executable path — distinct by construction from `Failed`, which
    /// represents a spawn that succeeded but the child exited non-zero.
    #[error("Failed to spawn cargo for extract-schema in {backend_dir}: {message}")]
    SpawnFailed {
        backend_dir: PathBuf,
        message: String,
    },

    /// `cargo run --bin extract-schema --quiet` in `backend_dir` exited
    /// non-zero. Carries the exit code and the captured stderr as
    /// separate fields — same structural-record shape as
    /// `NixBuildError::BuildFailed` / `RegistryError::PushFailed` /
    /// `AtticError::PushFailed` / `GitError::OpFailed` — so downstream
    /// telemetry can pattern-match on the failure shape without
    /// re-parsing the message.
    #[error("extract-schema in {backend_dir} failed (exit {exit_code:?}): {stderr}")]
    Failed {
        backend_dir: PathBuf,
        exit_code: Option<i32>,
        stderr: String,
    },

    /// `cargo run --bin extract-schema --quiet` exited zero but printed
    /// no bytes on stdout — a contract violation of the extract-schema
    /// binary that callers must distinguish from a real build failure.
    /// Pre-lift each site's `if output.stdout.is_empty()` guard fused
    /// this into a stringly `bail!` indistinguishable at the type level
    /// from an exit-nonzero failure; post-lift the discrimination is
    /// structural so a caller (e.g. `codegen_validation.rs`) can decide
    /// whether to treat "empty" as schema drift vs. tooling brokenness
    /// without parsing the failure text.
    #[error("extract-schema in {backend_dir} produced no output")]
    EmptyOutput { backend_dir: PathBuf },
}

/// Extract the GraphQL SDL from a Rust backend by running
/// `cargo run --bin extract-schema --quiet` in `backend_dir` and
/// returning the captured stdout bytes verbatim.
///
/// The bytes are returned as-is (not UTF-8-decoded) so a caller that
/// writes them to `schema.graphql` — the canonical shape at three of the
/// four consumer sites — feeds them straight to `tokio::fs::write` with
/// no round-trip through `String`. A caller that wants to parse the SDL
/// (`codegen_validation.rs::validate_schema_export` counts `"type "`,
/// `"input "`, `"enum "` occurrences) applies `String::from_utf8_lossy`
/// on its own; the primitive stays byte-oriented so both consumer
/// shapes are served without a lossy decode at the primitive surface.
///
/// # `CARGO` env override
///
/// The `cargo` binary resolves via `get_tool_path("CARGO", "cargo")` —
/// same discipline `commands/bootstrap.rs::run_cargo_ci_gates` honors
/// via `get_tool_path("CARGO", "cargo")`. Pre-lift the four consumer
/// sites spelled `Command::new("cargo")` bypassing the env override, so
/// a Nix-hermetic runner with a store-path cargo would fall through to
/// whatever `cargo` was first on `PATH`.
///
/// # Errors
///
/// - [`SchemaExtractionError::SpawnFailed`] — the resolved cargo binary
///   could not be spawned (missing path / non-executable / permission
///   denied). Carries `backend_dir` and the underlying io error message.
/// - [`SchemaExtractionError::Failed`] — extract-schema exited non-zero.
///   Carries `backend_dir`, `exit_code`, and the trimmed UTF-8-lossy
///   stderr.
/// - [`SchemaExtractionError::EmptyOutput`] — extract-schema exited
///   zero but printed no stdout bytes. Carries `backend_dir`.
pub async fn extract_graphql_schema(backend_dir: &Path) -> Result<Vec<u8>, SchemaExtractionError> {
    let cargo = get_tool_path("CARGO", "cargo");
    extract_graphql_schema_with_bin(&cargo, backend_dir).await
}

/// Test-injection sibling of [`extract_graphql_schema`]: accepts the
/// resolved `cargo_bin` as an explicit argument so unit tests can point
/// at a hermetic shim without mutating the process-wide `CARGO`
/// environment variable — same discipline as `nix.rs`'s
/// `path_info_recursive_with_bin` (a private `nix_bin: &str` helper the
/// public wrapper delegates to after resolving `get_tool_path`) and
/// `AtticClient::with_attic_bin` in `infrastructure/attic.rs` (a
/// `#[cfg(test)]` builder override on the client struct). Splitting the
/// resolution from the execution keeps the test surface hermetic AND
/// parallel-safe: `#[tokio::test]` on this module can run concurrent
/// tests without racing on env-var writes.
async fn extract_graphql_schema_with_bin(
    cargo_bin: &str,
    backend_dir: &Path,
) -> Result<Vec<u8>, SchemaExtractionError> {
    let captured = Command::new(cargo_bin)
        .args(["run", "--bin", "extract-schema", "--quiet"])
        .current_dir(backend_dir)
        .output()
        .await;

    // Spawn-vs-op dispatch flows through the canonical
    // [`classify_capture`] primitive — same shape as
    // `run_nix_build_typed` / `path_info_recursive_with_bin`. Spawn
    // failure -> `SpawnFailed` carrying the offending backend path;
    // non-zero exit -> `Failed` carrying the (exit_code, stderr) tuple
    // `CapturedFailure` extracts.
    let output = classify_capture(
        captured,
        |e| SchemaExtractionError::SpawnFailed {
            backend_dir: backend_dir.to_path_buf(),
            message: e.to_string(),
        },
        |cf| SchemaExtractionError::Failed {
            backend_dir: backend_dir.to_path_buf(),
            exit_code: cf.exit_code,
            stderr: cf.stderr,
        },
    )?;

    if output.stdout.is_empty() {
        return Err(SchemaExtractionError::EmptyOutput {
            backend_dir: backend_dir.to_path_buf(),
        });
    }

    Ok(output.stdout)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::make_executable_shim;

    /// When the resolved cargo binary cannot be spawned,
    /// `extract_graphql_schema_with_bin` must surface `SpawnFailed`
    /// carrying the offending backend directory — never a fused anyhow
    /// "Failed to run extract-schema" bag. Pins the typed split so
    /// telemetry can distinguish "cargo missing" from "extract-schema
    /// said no". Uses an absolute path that does not exist so
    /// Command::spawn fails deterministically without touching global
    /// PATH state.
    #[tokio::test]
    async fn spawn_failed_carries_backend_dir() {
        let backend = tempfile::tempdir().expect("tempdir");
        let result = extract_graphql_schema_with_bin(
            "/nonexistent/path/to/cargo-binary-that-does-not-exist",
            backend.path(),
        )
        .await;
        let err = result.expect_err("missing cargo binary must fail");
        match err {
            SchemaExtractionError::SpawnFailed {
                backend_dir,
                message,
            } => {
                assert_eq!(backend_dir, backend.path());
                assert!(
                    !message.is_empty(),
                    "spawn-failure message must not be empty"
                );
            }
            other => panic!("expected SpawnFailed, got: {other:?}"),
        }
    }

    /// A cargo invocation that exits non-zero must produce `Failed`
    /// carrying the backend directory, exit code, and captured stderr —
    /// never a fused stringly bag. Uses a shim invoked by absolute path
    /// so the test is hermetic and parallel-safe against PATH.
    #[tokio::test]
    async fn failed_carries_structured_fields() {
        let (_shim_dir, shim) = make_executable_shim(
            "cargo",
            "#!/bin/sh\necho 'compile error in backend' 1>&2\nexit 101\n",
        );
        let backend = tempfile::tempdir().expect("backend tempdir");
        let result = extract_graphql_schema_with_bin(&shim, backend.path()).await;
        let err = result.expect_err("nonzero exit must fail");
        match err {
            SchemaExtractionError::Failed {
                backend_dir,
                exit_code,
                stderr,
            } => {
                assert_eq!(backend_dir, backend.path());
                assert_eq!(exit_code, Some(101));
                assert!(
                    stderr.contains("compile error in backend"),
                    "stderr field must capture the extract-schema stderr verbatim, got: {stderr:?}"
                );
            }
            other => panic!("expected Failed, got: {other:?}"),
        }
    }

    /// A cargo invocation that exits zero with empty stdout must produce
    /// `EmptyOutput` — distinct from `Failed` — so callers can treat
    /// "extract-schema contract violation" differently from "extract-
    /// schema said no". Pins the three-way partition the four consumer
    /// sites currently open-code with paired `if !status.success()` +
    /// `if stdout.is_empty()` guards.
    #[tokio::test]
    async fn empty_output_distinct_from_failure() {
        let (_shim_dir, shim) = make_executable_shim("cargo", "#!/bin/sh\nexit 0\n");
        let backend = tempfile::tempdir().expect("backend tempdir");
        let result = extract_graphql_schema_with_bin(&shim, backend.path()).await;
        let err = result.expect_err("empty stdout must fail");
        match err {
            SchemaExtractionError::EmptyOutput { backend_dir } => {
                assert_eq!(backend_dir, backend.path());
            }
            other => panic!("expected EmptyOutput, got: {other:?}"),
        }
    }

    /// On the success path, `extract_graphql_schema_with_bin` must
    /// return the stdout bytes verbatim — no UTF-8 round-trip, no trim,
    /// no lossy decode. Pins the byte-preservation invariant a caller
    /// that writes the bytes straight to `schema.graphql` (three of the
    /// four consumer sites) depends on. The fixture bytes include a
    /// trailing newline AND a synthetic non-ASCII sequence (`é` =
    /// 0xC3 0xA9) so a future regression that added `.trim()` or
    /// `String::from_utf8_lossy` at the primitive surface would
    /// silently corrupt real schemas — a caught-loudly-here failure
    /// instead of a caught-nowhere corruption.
    #[tokio::test]
    async fn success_returns_bytes_verbatim() {
        let expected: &[u8] = b"type Query { hello: String }\n# comment with UTF-8: caf\xc3\xa9\n";
        // printf with numeric escapes so the shim script emits exactly
        // the expected byte sequence — including the non-ASCII 0xC3
        // 0xA9 (é) pair and the trailing newline — without any shell
        // interpolation of quotes / dollar signs / etc.
        let shim_body = "#!/bin/sh\nprintf 'type Query { hello: String }\n# comment with UTF-8: caf\\303\\251\n'\nexit 0\n";
        let (_shim_dir, shim) = make_executable_shim("cargo", shim_body);
        let backend = tempfile::tempdir().expect("backend tempdir");
        let bytes = extract_graphql_schema_with_bin(&shim, backend.path())
            .await
            .expect("success path");
        assert_eq!(
            bytes.as_slice(),
            expected,
            "stdout bytes must survive the primitive round-trip byte-for-byte"
        );
    }

    /// `extract_graphql_schema_with_bin` must spawn the cargo process
    /// inside `backend_dir` (not inherit the parent's CWD). Pinned with
    /// a shim that writes `pwd` to a side-channel marker file inside
    /// `backend_dir` — the marker's presence AND contents prove
    /// `current_dir` was honored. A future regression that silently
    /// dropped the `.current_dir` setter (e.g. via a refactor that
    /// moved the builder chain) would leave extract-schema resolving
    /// the wrong `Cargo.toml` — the canonical "wrong-workspace"
    /// silent-failure shape this test pins out.
    #[tokio::test]
    async fn honors_backend_dir_as_working_directory() {
        let (_shim_dir, shim) = make_executable_shim(
            "cargo",
            "#!/bin/sh\npwd > .observed-cwd\necho 'schema-bytes'\nexit 0\n",
        );
        let backend = tempfile::tempdir().expect("backend tempdir");
        let backend_canonical =
            std::fs::canonicalize(backend.path()).expect("canonicalize backend");
        let bytes = extract_graphql_schema_with_bin(&shim, backend.path())
            .await
            .expect("success path");
        assert_eq!(bytes.as_slice(), b"schema-bytes\n");
        let observed_raw = std::fs::read_to_string(backend.path().join(".observed-cwd"))
            .expect("shim must have written .observed-cwd inside backend_dir");
        let observed = std::fs::canonicalize(observed_raw.trim()).expect("canonicalize observed");
        assert_eq!(
            observed, backend_canonical,
            "shim's observed CWD must equal the backend_dir passed to the primitive"
        );
    }
}
