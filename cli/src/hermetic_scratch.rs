//! Hermetic per-invocation on-disk scratch reservation.
//!
//! One primitive — [`hermetic_scratch_file`] — for the four sibling
//! `(TempDir, PathBuf)` sigils that had converged, over four prior
//! `Run-by: claude-routine-forge` commits, onto a byte-identical
//! reservation body across the `commands/` tree:
//!
//! - `commands/crossplane.rs::xpkg_output_file` (220b207) — the
//!   crossplane build → push handoff.
//! - `commands/e2e.rs::e2e_image_output_symlink` (ab88937) — the
//!   E2E-image `nix build -o` → `docker load` handoff.
//! - `commands/federation_tests.rs::federation_test_job_manifest_file`
//!   (76b256e) — the federation-test-Job apply → wait handoff.
//! - `commands/migrations.rs::migration_job_manifest_file` (950a0e7) —
//!   the migration-Job apply → wait handoff.
//!
//! Every one of the four opened with the same three-line body
//!
//! ```ignore
//! let dir = tempfile::Builder::new()
//!     .prefix(<prefix>)
//!     .tempdir()
//!     .context(<msg>)?;
//! let path = dir.path().join(<filename>);
//! Ok((dir, path))
//! ```
//!
//! and varied only in `<prefix>`, `<filename>`, and the surface of the
//! `context` string — the exact "recurring shape becomes a library
//! before it becomes duplicated code" trigger THEORY §I.3 (belief 5)
//! and §V.6 name a first-order lift for. Four instances is a
//! four-fold multiplier on a future `(TempDir, PathBuf)` scratch
//! consumer inheriting the drift class this primitive forecloses at
//! its return signature: a `let (_, out) = hermetic_scratch_file(…)?`
//! binding that drops the guard is a type-visible defect at review,
//! and the follow-on write to `<out>` fails reproducibly with a
//! parent-dir `ENOENT` (a fast, loud signal instead of a silent leak).
//!
//! ## Discipline this primitive carries by construction
//!
//! 1. **`tempfile::Builder::tempdir` honors `TMPDIR`.** Under a
//!    Nix-sandbox build with `sandbox = true` (the default on the
//!    fleet's build runners), the daemon exposes only `$TMPDIR` and
//!    no writable `/tmp`. The pre-lift sigils reached this
//!    discipline call-by-call; consolidating means a fifth on-disk
//!    scratch consumer inherits it in one function call.
//! 2. **`mkdtemp(3)`-appended unique suffix.** Two concurrent
//!    invocations with identical `prefix` + `filename` return
//!    strictly-distinct paths (each `tempdir()` picks its own random
//!    suffix), so no fixed-slot race is representable at the
//!    caller's typed surface.
//! 3. **`TempDir::Drop` unlinks the whole dir + its contents.** The
//!    guard `Drop` runs through `?` propagation, through panics,
//!    through operator Ctrl-C — the on-disk state is bound to the
//!    caller's stack frame and released with it.
//!
//! ## The narrow-typed sigil layer stays
//!
//! Each of the four caller-side sigils keeps its narrow signature
//! (`xpkg_output_file()` with no args, `e2e_image_output_symlink(&str)`,
//! `federation_test_job_manifest_file(&str)`,
//! `migration_job_manifest_file(&str, i64)`) so consumer call sites
//! stay unchanged. Only the body collapses to a one-liner that
//! routes prefix + filename through this primitive.

use anyhow::{Context, Result};
use std::path::PathBuf;
use tempfile::TempDir;

/// Create a fresh hermetic scratch tempdir under `$TMPDIR` (honoring
/// the Nix-sandbox daemon's per-build scratch root by construction)
/// and reserve a path to a file inside it named `filename`.
///
/// Returns `(dir, path)` — the caller MUST bind the `dir` half to a
/// scope that outlives every use of `path`. A `let (_, p) = …`
/// binding that drops the guard is a type-visible defect at review;
/// the follow-on write to `p` fails reproducibly with a parent-dir
/// `ENOENT`.
///
/// The `path`'s parent is fresh (no prior file exists at `path`), so
/// a caller invoking a tool with create-fresh-or-fail semantics
/// (`nix build -o <path>`, `kubectl apply -f <path>` after a
/// `std::fs::write`, `crossplane xpkg build -o <path>`) sees the
/// exact contract those tools require.
pub fn hermetic_scratch_file(prefix: &str, filename: &str) -> Result<(TempDir, PathBuf)> {
    let dir = tempfile::Builder::new()
        .prefix(prefix)
        .tempdir()
        .with_context(|| format!("create hermetic scratch tempdir with prefix {prefix:?}"))?;
    let path = dir.path().join(filename);
    Ok((dir, path))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Primitive pin — the basename contract: the returned path's
    /// `file_name()` is exactly `filename`, with no suffix appended
    /// and no path components inserted. The four call-site sigils
    /// each depend on this shape:
    /// - `xpkg_output_file()` → `<dir>/package.xpkg`.
    /// - `e2e_image_output_symlink("backend")` → `<dir>/backend-image`.
    /// - `federation_test_job_manifest_file("j")` → `<dir>/j.yaml`.
    /// - `migration_job_manifest_file("c", 42)` → `<dir>/c-migration-job-42.yaml`.
    ///
    /// A drift that appended a suffix or mangled the basename would
    /// break every caller's operator-facing scratch-dir archaeology
    /// (an operator dumping the scratch tempdir would no longer
    /// recognize the file by name).
    #[test]
    fn test_hermetic_scratch_file_returns_expected_basename() {
        let (_dir, path) =
            hermetic_scratch_file("test-basename-", "widget.yaml").expect("hermetic_scratch_file");
        assert_eq!(
            path.file_name().and_then(|s| s.to_str()),
            Some("widget.yaml"),
            "hermetic_scratch_file(prefix, \"widget.yaml\") must return \
             a path whose basename is exactly `widget.yaml`; got {path:?}",
        );
    }

    /// Primitive pin — the concurrent-race half: two calls with
    /// identical `prefix` + `filename` return strictly-distinct
    /// paths, so no fixed-slot race on the on-disk destination is
    /// representable at the caller's typed surface. `mkdtemp(3)`-
    /// backed unique-suffix discipline; a drift onto a fixed-dir
    /// shape would fail HERE, not as a mysterious cross-run
    /// contamination downstream.
    #[test]
    fn test_hermetic_scratch_file_returns_distinct_paths_on_each_call() {
        let (_a_dir, a) =
            hermetic_scratch_file("test-distinct-", "widget.yaml").expect("first call");
        let (_b_dir, b) =
            hermetic_scratch_file("test-distinct-", "widget.yaml").expect("second call");
        assert_ne!(
            a, b,
            "two calls to hermetic_scratch_file(same prefix + same filename) \
             must return strictly-distinct paths — a fixed-dir shape would \
             race two concurrent invocations against the same on-disk slot",
        );
    }

    /// Primitive pin — the freshness half: the returned path starts
    /// fresh (no file at `path` yet), so a caller invoking a tool
    /// with create-fresh-or-fail semantics (`nix build -o <path>`,
    /// `crossplane xpkg build -o <path>`) sees the exact contract
    /// those tools require. A drift onto a `NamedTempFile` shape
    /// that pre-created the file would change the semantics for
    /// every such caller.
    #[test]
    fn test_hermetic_scratch_file_returns_fresh_nonexistent_path() {
        let (_dir, path) =
            hermetic_scratch_file("test-fresh-", "widget.yaml").expect("hermetic_scratch_file");
        assert!(
            !path.exists(),
            "returned path must be fresh — a pre-created file at `path` \
             would change semantics for callers with create-fresh-or-fail \
             tool contracts (nix build -o, crossplane xpkg build -o)"
        );
    }

    /// Primitive pin — the RAII half: the returned `TempDir` keeps
    /// the on-disk state alive across a mid-body write, and `Drop`
    /// unlinks both dir AND its contents. A drift onto a bare
    /// `Builder::new().tempdir()` return without the guard held
    /// would flake because `Drop` ran before the caller's write
    /// touched the reserved path.
    #[test]
    fn test_hermetic_scratch_file_dir_drop_unlinks_written_contents() {
        let path = {
            let (dir, out) =
                hermetic_scratch_file("test-drop-", "widget.yaml").expect("hermetic_scratch_file");
            std::fs::write(&out, b"stub payload\n").expect("write stub payload");
            assert!(
                out.exists() && dir.path().is_dir(),
                "file exists AND dir is alive while the RAII guard is held"
            );
            out
        };
        assert!(
            !path.exists(),
            "`TempDir::Drop` must unlink the scratch dir + its contents \
             — a mid-body panic between reserve and write would otherwise \
             leak the scratch dir + payload forever"
        );
    }

    /// Primitive pin — the prefix routing half: the returned dir's
    /// path components include the caller-supplied `prefix` (via
    /// `Builder::prefix` → `mkdtemp(3)` template), so an operator
    /// dumping `$TMPDIR` after a failing forge invocation can
    /// still trace the scratch dir back to the caller by its
    /// filesystem name. A drift onto a bare `tempdir()` without
    /// the prefix would leave every caller's scratch dir named
    /// `.tmpXXXXXX` — indistinguishable in a runner post-mortem.
    #[test]
    fn test_hermetic_scratch_file_dir_name_carries_prefix() {
        let (dir, _path) = hermetic_scratch_file("test-prefix-marker-", "widget.yaml")
            .expect("hermetic_scratch_file");
        let dir_name = dir
            .path()
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or_default()
            .to_string();
        assert!(
            dir_name.starts_with("test-prefix-marker-"),
            "the scratch dir's basename must begin with the caller-supplied \
             prefix so an operator can trace a leaked dir back to its caller; \
             got {dir_name:?}",
        );
    }

    /// The four `(TempDir, PathBuf)` sigils on the `commands/` tree,
    /// as `(module path, source, `fn <name>(` open marker)` triples.
    /// Each entry's body is sliced from its open marker to the first
    /// top-level `\n}\n` — the sigil's closing brace.
    ///
    /// Adding a fifth `(TempDir, PathBuf)` sigil means adding a row
    /// here; the shield below then holds it to the same delegation
    /// contract as the four that already exist.
    const SIGIL_SITES: [(&str, &str, &str); 4] = [
        (
            "commands/crossplane.rs",
            include_str!("commands/crossplane.rs"),
            "fn xpkg_output_file(",
        ),
        (
            "commands/e2e.rs",
            include_str!("commands/e2e.rs"),
            "fn e2e_image_output_symlink(",
        ),
        (
            "commands/federation_tests.rs",
            include_str!("commands/federation_tests.rs"),
            "fn federation_test_job_manifest_file(",
        ),
        (
            "commands/migrations.rs",
            include_str!("commands/migrations.rs"),
            "fn migration_job_manifest_file(",
        ),
    ];

    /// Cross-module shield: every `(TempDir, PathBuf)` sigil on the
    /// `commands/` tree MUST reserve its scratch path through
    /// [`hermetic_scratch_file`], never a hand-rolled
    /// `tempfile::Builder::new().prefix(…).tempdir()` +
    /// `dir.path().join(…)` stanza of its own.
    ///
    /// Pre-lift all four sigils spelled that body verbatim, varying
    /// only in prefix, filename, and `context` string — four copies
    /// of one shape, each independently able to drift off the
    /// `TMPDIR`-honoring / `mkdtemp(3)`-unique-suffix / `Drop`-unlinks
    /// discipline. A fifth on-disk scratch consumer added by copying
    /// a neighbor would inherit whichever copy it happened to copy.
    ///
    /// Positive side: the delegation call `hermetic_scratch_file(`
    /// must appear at exactly ONE code line in each sigil's body, so
    /// a regression that deleted the delegation cannot leave the
    /// negative scan trivially satisfied by absence.
    ///
    /// Negative side: `tempfile::Builder` must not appear at any
    /// code line in any sigil's body. The needle is reconstructed at
    /// test time so this shield's own docstring prose citing the
    /// pre-lift stanza does not false-match itself (same discipline
    /// the per-module consumer shields carry). Doc-comment lines
    /// above each `fn` are outside the slice, and
    /// [`crate::test_support::code_line_hits`] additionally filters
    /// `//` / `///` / `//!` lines, so the delegation comments inside
    /// each body are ignored.
    #[test]
    fn test_all_temp_dir_pathbuf_sigils_route_through_hermetic_scratch_file() {
        let forbidden = format!("{}::Builder", "tempfile");
        for (module_path, source, open_marker) in SIGIL_SITES {
            let body = crate::test_support::fn_body_slice_between_markers(
                source,
                module_path,
                open_marker,
                "\n}\n",
            );

            let delegation_hits =
                crate::test_support::code_line_hits(body, "hermetic_scratch_file(");
            assert_eq!(
                delegation_hits.len(),
                1,
                "{module_path}'s `{open_marker}` sigil must delegate to \
                 `hermetic_scratch_file(` at exactly one code line; got {} \
                 — hits: {delegation_hits:#?}",
                delegation_hits.len(),
            );

            let hand_rolled = crate::test_support::code_line_hits(body, &forbidden);
            assert!(
                hand_rolled.is_empty(),
                "{module_path}'s `{open_marker}` sigil must NOT hand-roll its \
                 own tempdir builder — the shared primitive at \
                 `hermetic_scratch::hermetic_scratch_file` carries the \
                 TMPDIR-honoring / mkdtemp-unique-suffix / Drop-unlinks \
                 discipline in one place; hits: {hand_rolled:#?}",
            );
        }
    }
}
