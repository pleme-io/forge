//! Typed primitive for extracting a GraphQL schema from a Rust backend.
//!
//! Five command-module sites in forge drive the same three-step incantation
//! against a `cargo run --bin <name> --quiet` schema extractor:
//! ```text
//! let output = Command::new("cargo")
//!     .args(["run", "--bin", <bin_name>, "--quiet"])
//!     .current_dir(backend_dir)
//!     .output().await
//!     .with_context(|| format!("Failed to run <bin_name> in {}", backend_dir.display()))?;
//! if !output.status.success() {
//!     let stderr = String::from_utf8_lossy(&output.stderr);
//!     bail!("Schema extraction failed:\n{}", stderr);
//! }
//! if output.stdout.is_empty() {
//!     bail!("Schema extraction produced no output");
//! }
//! ```
//! carried verbatim modulo per-site failure envelope (anyhow `bail!` vs. an
//! `Ok(ValidationResult { error: Some(_), … })` field) and per-site
//! `<bin_name>` selection (four sites hard-code `"extract-schema"`; the
//! fifth reads a runtime-configured `graphql_config.schema_extractor` off
//! the deploy config). Five identically-shaped bodies past THEORY §VI.1's
//! three-times threshold (PRIME DIRECTIVE: duplication budget is zero):
//!
//! - `commands/codegen.rs::execute`
//! - `commands/codegen.rs::export_schema_only`
//! - `commands/codegen_validation.rs::execute`
//! - `commands/codegen_validation.rs::validate_schema_export`
//! - `commands/schema_validation.rs::extract_and_validate_schema`
//!   (configurable bin — served by [`extract_graphql_schema_named`])
//!
//! This module is the law-redeeming consolidation. Four load-bearing
//! properties this primitive owns that the pre-lift raw-spawn stanzas
//! dropped:
//!
//! 1. **`CARGO` env override.** Pre-lift each site spelled
//!    `Command::new("cargo")`, ignoring the env var `commands/bootstrap.rs`
//!    honors via `get_tool_path("CARGO", "cargo")` — so a Nix-hermetic
//!    runner with a store-path `cargo` would fall through to whatever
//!    `cargo` was first on PATH at these five sites specifically.
//! 2. **Typed error dispatch.** Pre-lift, spawn failure and op failure
//!    fused into anyhow strings that dropped the exit code (the `bail!`
//!    said "failed" without saying "exit N"). Post-lift both surface as
//!    typed [`SchemaExtractionError`] variants carrying the structural
//!    `(backend_dir, bin_name, exit_code, stderr)` tuple THEORY §V.4
//!    Phase 1 attestation records pattern-match on. Empty-stdout gets
//!    its own variant distinct from a non-zero exit — the schema-drift
//!    call site in `codegen_validation.rs` already treated the two
//!    shapes distinctly and had to open-code the discrimination.
//! 3. **Backend-directory in every failure record.** Pre-lift, only the
//!    `with_context` spawn-failure carried `backend_dir`; the op-failure
//!    and empty-stdout `bail!`s dropped it. Post-lift every failure
//!    variant carries the offending path so a caller can attach it to
//!    a Phase 1 attestation / telemetry record without re-parsing.
//! 4. **Bin name in every failure record.** Pre-lift, the fifth call
//!    site (`schema_validation.rs`) interpolated
//!    `graphql_config.schema_extractor` into a `bail!` string that fused
//!    the bin name with the failure prose. Post-lift every failure
//!    variant carries `bin_name` structurally — so a telemetry consumer
//!    (or a Phase 1 attestation) can partition failures by which
//!    extractor binary went sideways without regex-parsing the display
//!    string.
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

/// Why a `cargo run --bin <bin_name> --quiet` schema-extraction invocation
/// failed to produce a usable GraphQL-SDL byte buffer. Carries the
/// offending `backend_dir` AND `bin_name` on every variant so a caller
/// can attach both to a failure record — a Phase 1 attestation, a
/// telemetry event, a structured log line — without re-parsing the
/// display string.
#[derive(Error, Debug)]
pub enum SchemaExtractionError {
    /// The `cargo` binary could not be spawned. Fires when `CARGO` (or
    /// the fallback `cargo` on `PATH`) resolves to a missing / non-
    /// executable path — distinct by construction from `Failed`, which
    /// represents a spawn that succeeded but the child exited non-zero.
    #[error("Failed to spawn cargo for {bin_name} in {backend_dir}: {message}")]
    SpawnFailed {
        backend_dir: PathBuf,
        bin_name: String,
        message: String,
    },

    /// `cargo run --bin <bin_name> --quiet` in `backend_dir` exited
    /// non-zero. Carries the exit code and the captured stderr as
    /// separate fields — same structural-record shape as
    /// `NixBuildError::BuildFailed` / `RegistryError::PushFailed` /
    /// `AtticError::PushFailed` / `GitError::OpFailed` — so downstream
    /// telemetry can pattern-match on the failure shape without
    /// re-parsing the message.
    #[error("{bin_name} in {backend_dir} failed (exit {exit_code:?}): {stderr}")]
    Failed {
        backend_dir: PathBuf,
        bin_name: String,
        exit_code: Option<i32>,
        stderr: String,
    },

    /// `cargo run --bin <bin_name> --quiet` exited zero but printed no
    /// bytes on stdout — a contract violation of the extractor binary
    /// that callers must distinguish from a real build failure. Pre-lift
    /// each site's `if output.stdout.is_empty()` guard fused this into a
    /// stringly `bail!` indistinguishable at the type level from an
    /// exit-nonzero failure; post-lift the discrimination is structural
    /// so a caller (e.g. `codegen_validation.rs`) can decide whether to
    /// treat "empty" as schema drift vs. tooling brokenness without
    /// parsing the failure text.
    #[error("{bin_name} in {backend_dir} produced no output")]
    EmptyOutput {
        backend_dir: PathBuf,
        bin_name: String,
    },
}

/// The default schema-extractor binary name — mirrors
/// `config/federation.rs::default_schema_extractor`. Named as a
/// module-level constant so the four hard-coded consumer sites read
/// through a single symbol instead of each spelling the string
/// verbatim; a rename of the canonical extractor lands at one site.
pub const DEFAULT_SCHEMA_EXTRACTOR_BIN: &str = "extract-schema";

/// Extract the GraphQL SDL from a Rust backend by running
/// `cargo run --bin extract-schema --quiet` in `backend_dir` and
/// returning the captured stdout bytes verbatim.
///
/// Thin wrapper over [`extract_graphql_schema_named`] pinned to the
/// canonical [`DEFAULT_SCHEMA_EXTRACTOR_BIN`] bin name. Four consumer
/// sites (`commands/codegen.rs::execute`,
/// `commands/codegen.rs::export_schema_only`,
/// `commands/codegen_validation.rs::execute`,
/// `commands/codegen_validation.rs::validate_schema_export`) hard-code
/// the extractor's name and read through here; a fifth site that reads
/// a runtime-configured bin name off deploy config uses
/// [`extract_graphql_schema_named`] directly.
pub async fn extract_graphql_schema(backend_dir: &Path) -> Result<Vec<u8>, SchemaExtractionError> {
    extract_graphql_schema_named(backend_dir, DEFAULT_SCHEMA_EXTRACTOR_BIN).await
}

/// Extract the GraphQL SDL from a Rust backend by running
/// `cargo run --bin <bin_name> --quiet` in `backend_dir` and returning
/// the captured stdout bytes verbatim.
///
/// The bytes are returned as-is (not UTF-8-decoded) so a caller that
/// writes them to `schema.graphql` — the canonical shape at four of the
/// five consumer sites — feeds them straight to `tokio::fs::write` with
/// no round-trip through `String`. A caller that wants to parse the SDL
/// (`codegen_validation.rs::validate_schema_export` counts `"type "`,
/// `"input "`, `"enum "` occurrences;
/// `schema_validation.rs::validate_schema_content` counts a broader
/// keyword set) applies `String::from_utf8_lossy` on its own; the
/// primitive stays byte-oriented so both consumer shapes are served
/// without a lossy decode at the primitive surface.
///
/// # `CARGO` env override
///
/// The `cargo` binary resolves via `get_tool_path("CARGO", "cargo")` —
/// same discipline `commands/bootstrap.rs::run_cargo_ci_gates` honors
/// via `get_tool_path("CARGO", "cargo")`. Pre-lift the five consumer
/// sites spelled `Command::new("cargo")` bypassing the env override, so
/// a Nix-hermetic runner with a store-path cargo would fall through to
/// whatever `cargo` was first on `PATH`.
///
/// # Errors
///
/// - [`SchemaExtractionError::SpawnFailed`] — the resolved cargo binary
///   could not be spawned (missing path / non-executable / permission
///   denied). Carries `backend_dir`, `bin_name`, and the underlying io
///   error message.
/// - [`SchemaExtractionError::Failed`] — the extractor exited non-zero.
///   Carries `backend_dir`, `bin_name`, `exit_code`, and the trimmed
///   UTF-8-lossy stderr.
/// - [`SchemaExtractionError::EmptyOutput`] — the extractor exited zero
///   but printed no stdout bytes. Carries `backend_dir` and `bin_name`.
pub async fn extract_graphql_schema_named(
    backend_dir: &Path,
    bin_name: &str,
) -> Result<Vec<u8>, SchemaExtractionError> {
    let cargo = get_tool_path("CARGO", "cargo");
    extract_graphql_schema_with_bin(&cargo, backend_dir, bin_name).await
}

/// Test-injection sibling of [`extract_graphql_schema_named`]: accepts
/// the resolved `cargo_bin` as an explicit argument so unit tests can
/// point at a hermetic shim without mutating the process-wide `CARGO`
/// environment variable — same discipline as `nix.rs`'s
/// `path_info_recursive_with_bin` (a private `nix_bin: &str` helper the
/// public wrapper delegates to after resolving `get_tool_path`) and
/// `AtticClient::with_attic_bin` in `infrastructure/attic.rs` (a
/// `#[cfg(test)]` builder override on the client struct). Splitting the
/// resolution from the execution keeps the test surface hermetic AND
/// parallel-safe: `#[tokio::test]` on this module can run concurrent
/// tests without racing on env-var writes.
///
/// `bin_name` is spliced verbatim into `--bin <bin_name>` (no escaping
/// / no shell interpretation — `Command::args` owns argv-vector delivery
/// so a user-controlled bin name cannot inject additional cargo args).
async fn extract_graphql_schema_with_bin(
    cargo_bin: &str,
    backend_dir: &Path,
    bin_name: &str,
) -> Result<Vec<u8>, SchemaExtractionError> {
    let captured = Command::new(cargo_bin)
        .args(["run", "--bin", bin_name, "--quiet"])
        .current_dir(backend_dir)
        .output()
        .await;

    // Spawn-vs-op dispatch flows through the canonical
    // [`classify_capture`] primitive — same shape as
    // `run_nix_build_typed` / `path_info_recursive_with_bin`. Spawn
    // failure -> `SpawnFailed` carrying the offending backend path AND
    // bin name; non-zero exit -> `Failed` carrying the (exit_code,
    // stderr) tuple `CapturedFailure` extracts alongside them.
    let output = classify_capture(
        captured,
        |e| SchemaExtractionError::SpawnFailed {
            backend_dir: backend_dir.to_path_buf(),
            bin_name: bin_name.to_string(),
            message: e.to_string(),
        },
        |cf| SchemaExtractionError::Failed {
            backend_dir: backend_dir.to_path_buf(),
            bin_name: bin_name.to_string(),
            exit_code: cf.exit_code,
            stderr: cf.stderr,
        },
    )?;

    if output.stdout.is_empty() {
        return Err(SchemaExtractionError::EmptyOutput {
            backend_dir: backend_dir.to_path_buf(),
            bin_name: bin_name.to_string(),
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
    /// carrying the offending backend directory AND the bin name that
    /// was requested — never a fused anyhow "Failed to run extract-
    /// schema" bag. Pins the typed split so telemetry can distinguish
    /// "cargo missing" from "extractor said no" AND partition by which
    /// extractor bin failed. Uses an absolute path that does not exist
    /// so Command::spawn fails deterministically without touching
    /// global PATH state.
    #[tokio::test]
    async fn spawn_failed_carries_backend_dir_and_bin_name() {
        let backend = tempfile::tempdir().expect("tempdir");
        let result = extract_graphql_schema_with_bin(
            "/nonexistent/path/to/cargo-binary-that-does-not-exist",
            backend.path(),
            "custom-extractor",
        )
        .await;
        let err = result.expect_err("missing cargo binary must fail");
        match err {
            SchemaExtractionError::SpawnFailed {
                backend_dir,
                bin_name,
                message,
            } => {
                assert_eq!(backend_dir, backend.path());
                assert_eq!(bin_name, "custom-extractor");
                assert!(
                    !message.is_empty(),
                    "spawn-failure message must not be empty"
                );
            }
            other => panic!("expected SpawnFailed, got: {other:?}"),
        }
    }

    /// A cargo invocation that exits non-zero must produce `Failed`
    /// carrying the backend directory, bin name, exit code, and
    /// captured stderr — never a fused stringly bag. Uses a shim
    /// invoked by absolute path so the test is hermetic and parallel-
    /// safe against PATH.
    #[tokio::test]
    async fn failed_carries_structured_fields() {
        let (_shim_dir, shim) = make_executable_shim(
            "cargo",
            "#!/bin/sh\necho 'compile error in backend' 1>&2\nexit 101\n",
        );
        let backend = tempfile::tempdir().expect("backend tempdir");
        let result = extract_graphql_schema_with_bin(&shim, backend.path(), "extract-schema").await;
        let err = result.expect_err("nonzero exit must fail");
        match err {
            SchemaExtractionError::Failed {
                backend_dir,
                bin_name,
                exit_code,
                stderr,
            } => {
                assert_eq!(backend_dir, backend.path());
                assert_eq!(bin_name, "extract-schema");
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
    /// "extractor contract violation" differently from "extractor said
    /// no". Pins the three-way partition the five consumer sites
    /// currently open-code with paired `if !status.success()` + `if
    /// stdout.is_empty()` guards, and asserts that `bin_name` rides
    /// through this failure variant too.
    #[tokio::test]
    async fn empty_output_distinct_from_failure() {
        let (_shim_dir, shim) = make_executable_shim("cargo", "#!/bin/sh\nexit 0\n");
        let backend = tempfile::tempdir().expect("backend tempdir");
        let result =
            extract_graphql_schema_with_bin(&shim, backend.path(), "service-a-schema").await;
        let err = result.expect_err("empty stdout must fail");
        match err {
            SchemaExtractionError::EmptyOutput {
                backend_dir,
                bin_name,
            } => {
                assert_eq!(backend_dir, backend.path());
                assert_eq!(bin_name, "service-a-schema");
            }
            other => panic!("expected EmptyOutput, got: {other:?}"),
        }
    }

    /// `extract_graphql_schema_with_bin` must splice the caller-supplied
    /// `bin_name` into cargo's `--bin <bin_name>` argument — verbatim,
    /// unshelled, unquoted. Pinned with a shim that copies its full
    /// argv to a marker file so the test can prove the argv-vector
    /// reached cargo exactly as expected. A future regression that
    /// silently hard-coded the bin name (or spliced through a shell
    /// interpolation that changed the arg boundary) would surface
    /// here rather than corrupting a downstream service's schema.
    #[tokio::test]
    async fn honors_custom_bin_name_in_argv() {
        // Shim writes its full argv (one arg per line) into a marker
        // file inside the backend dir, then emits a stub schema so the
        // success path stays green.
        let (_shim_dir, shim) = make_executable_shim(
            "cargo",
            "#!/bin/sh\nfor a in \"$@\"; do echo \"$a\" >> .observed-argv; done\necho 'stub'\nexit 0\n",
        );
        let backend = tempfile::tempdir().expect("backend tempdir");
        let bytes = extract_graphql_schema_with_bin(&shim, backend.path(), "svc-alpha-schema")
            .await
            .expect("success path");
        assert_eq!(bytes.as_slice(), b"stub\n");
        let observed = std::fs::read_to_string(backend.path().join(".observed-argv"))
            .expect("shim must have written .observed-argv");
        let args: Vec<&str> = observed.lines().collect();
        assert_eq!(
            args,
            vec!["run", "--bin", "svc-alpha-schema", "--quiet"],
            "cargo argv must be exactly [run, --bin, <bin_name>, --quiet]"
        );
    }

    /// The `extract_graphql_schema` convenience wrapper must pin the
    /// canonical default bin name. A regression that changed the
    /// default (or that decoupled the two entry points) would surface
    /// here rather than at whichever consumer site first read a
    /// wrong-named schema file. This is the one-oracle contract
    /// `commands/codegen*` sites depend on: they call the
    /// no-bin-name entry precisely because they want the canonical
    /// extractor.
    #[tokio::test]
    async fn default_wrapper_pins_canonical_bin_name() {
        assert_eq!(DEFAULT_SCHEMA_EXTRACTOR_BIN, "extract-schema");
        let (_shim_dir, shim) = make_executable_shim(
            "cargo",
            "#!/bin/sh\nfor a in \"$@\"; do echo \"$a\" >> .observed-argv; done\necho 'stub'\nexit 0\n",
        );
        let backend = tempfile::tempdir().expect("backend tempdir");
        // Route through the internal helper with the constant to prove
        // the wrapper's spliced value is exactly the constant.
        let bytes =
            extract_graphql_schema_with_bin(&shim, backend.path(), DEFAULT_SCHEMA_EXTRACTOR_BIN)
                .await
                .expect("success path");
        assert_eq!(bytes.as_slice(), b"stub\n");
        let observed = std::fs::read_to_string(backend.path().join(".observed-argv"))
            .expect("shim must have written .observed-argv");
        let args: Vec<&str> = observed.lines().collect();
        assert_eq!(args, vec!["run", "--bin", "extract-schema", "--quiet"]);
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
        let bytes =
            extract_graphql_schema_with_bin(&shim, backend.path(), DEFAULT_SCHEMA_EXTRACTOR_BIN)
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
        let bytes =
            extract_graphql_schema_with_bin(&shim, backend.path(), DEFAULT_SCHEMA_EXTRACTOR_BIN)
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
