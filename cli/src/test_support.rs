//! Shared test infrastructure for forge.
//!
//! Hermetic shims for the external CLIs forge drives — `git`, `nix`,
//! `attic`, and (forthcoming) `skopeo` / `regctl` / `cosign` / `helm` —
//! converge on the same shape: a tempdir holding a single executable
//! script with a caller-supplied body, returned as `(TempDir, absolute
//! path)`. Three test modules — `git.rs`, `nix.rs`, and
//! `infrastructure/attic.rs` — each carried a private `make_X_shim`
//! helper differing only in the binary name. Three identically-shaped
//! copies past the three-times threshold (THEORY §VI.1: "two occurrences
//! is a coincidence; three is a law"). This module is the
//! law-redeeming consolidation.
//!
//! # Why a shared helper
//!
//! The shim discipline is load-bearing for the typed-error tests:
//!
//! - Tests invoke the shim by **absolute path** so they don't have to
//!   mutate global `PATH` (which races under `cargo test`'s parallel
//!   runner — N test threads racing on `std::env::set_var("PATH", ...)`
//!   produce flakes that look like "binary not found" but are really
//!   "another thread overwrote PATH between our spawn and the OS lookup").
//!   Centralizing the absolute-path discipline at the typed primitive
//!   means a future test cannot drift onto PATH-mutation by accident.
//!
//! - The 0o755 chmod step is required on Unix (the script is otherwise
//!   spawned as a non-executable file and the OS rejects it with EACCES,
//!   producing a confusing `ExecFailed` rather than the typed `*Failed`
//!   the test is trying to drive). Centralizing the chmod means a future
//!   shim caller cannot forget it.
//!
//! - The returned `TempDir` is what keeps the shim alive: it must be
//!   bound to a local `_dir` binding for the duration of the test. The
//!   shape `(TempDir, String)` makes this binding-or-leak choice
//!   explicit at every call site.

#![cfg(test)]

use std::path::PathBuf;

/// Write an executable shim script to a fresh tempdir under `name`,
/// chmod it 0o755 (Unix), and return the `(TempDir, absolute path)` pair.
///
/// `name` is the basename the shim is written as; tests pass `"git"`,
/// `"nix"`, `"attic"` (and friends) so the OS process-lookup path
/// matches the producer site's `Command::new("git")` / `"nix"` /
/// `"attic"` invocation.
///
/// `body` is the script body (typically `#!/bin/sh\n<output>\nexit <N>\n`).
/// The body is written verbatim — callers retain full control over the
/// script's stdout/stderr/exit shape, which is what makes the shim
/// hermetic-by-construction: the test owns every byte the typed-error
/// producer site will see.
///
/// The returned `TempDir` MUST be bound to a local `_dir` (or longer-
/// lived) variable for the duration of the test. When the `TempDir`
/// drops, the shim file is unlinked and any subsequent invocation
/// fails with `ENOENT`. Pinning this contract at the type level
/// (`(TempDir, String)`, NOT bare `String`) makes a bug-by-omission
/// structurally impossible: a `let (_, shim) = make_executable_shim(...)`
/// drops the `TempDir` immediately and any later use of `shim`
/// reproducibly fails — a fast, loud signal instead of a flake.
pub fn make_executable_shim(name: &str, body: &str) -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().expect("tempdir");
    let shim: PathBuf = dir.path().join(name);
    std::fs::write(&shim, body).expect("write shim");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&shim).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&shim, perms).unwrap();
    }
    let path = shim.display().to_string();
    (dir, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    /// The returned absolute path resolves to a real file inside the
    /// returned `TempDir`. Pinning this is the floor for every shim-
    /// based test in forge: if the path the helper hands back doesn't
    /// exist the test would fail anyway, but with a confusing `ENOENT`
    /// rather than the typed `ExecFailed` / `*Failed` the test was
    /// trying to drive.
    #[test]
    fn test_make_executable_shim_returns_existing_absolute_path() {
        let (_dir, path) = make_executable_shim("alpha", "#!/bin/sh\nexit 0\n");
        let p = std::path::Path::new(&path);
        assert!(p.is_absolute(), "path must be absolute, got: {path}");
        assert!(p.exists(), "shim must exist on disk: {path}");
        assert_eq!(p.file_name().and_then(|s| s.to_str()), Some("alpha"));
    }

    /// On Unix, the shim is chmod 0o755 — executable by every user the
    /// `cargo test` runner could plausibly run as. A future drift that
    /// dropped the chmod step would surface here as a permissions test
    /// failure, not as a confusing `Permission denied (os error 13)`
    /// inside an unrelated typed-error test downstream.
    #[cfg(unix)]
    #[test]
    fn test_make_executable_shim_is_executable_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, path) = make_executable_shim("beta", "#!/bin/sh\nexit 0\n");
        let perms = std::fs::metadata(&path).expect("metadata").permissions();
        // The mode includes file-type bits in the high bits; mask to the
        // permission bits and assert they include user-execute.
        let mode = perms.mode() & 0o777;
        assert!(
            mode & 0o100 != 0,
            "shim must be user-executable, got mode: {mode:o}"
        );
    }

    /// The body the caller passes in is what the shim executes. Pinning
    /// this is the contract every typed-error test relies on — the
    /// shim's stderr/stdout/exit code is the test fixture's chosen
    /// shape, not whatever the host's real `git`/`nix`/`attic` happens
    /// to print. Without this guard a future "normalize the body"
    /// refactor would silently change every typed-error test's failure
    /// fixture.
    #[cfg(unix)]
    #[test]
    fn test_make_executable_shim_executes_caller_supplied_body() {
        let (_dir, path) =
            make_executable_shim("gamma", "#!/bin/sh\necho 'hello-stdout'\nexit 7\n");
        let output = Command::new(&path).output().expect("spawn shim");
        assert_eq!(output.status.code(), Some(7));
        assert_eq!(
            String::from_utf8_lossy(&output.stdout).trim(),
            "hello-stdout"
        );
    }

    /// The basename the shim is written as is the basename the OS
    /// surfaces when it executes the file. Pinning this means a future
    /// drift that wrote the shim under a hard-coded name (e.g.
    /// "shim" instead of `name`) would fail this test before any
    /// downstream typed-error test fired with a "binary not found" /
    /// "wrong tool" diagnostic.
    #[test]
    fn test_make_executable_shim_writes_under_caller_name() {
        let (_dir, path_a) = make_executable_shim("delta-tool", "#!/bin/sh\nexit 0\n");
        let (_dir2, path_b) = make_executable_shim("epsilon-tool", "#!/bin/sh\nexit 0\n");
        assert!(
            path_a.ends_with("/delta-tool"),
            "shim must be written under the caller-supplied name; got: {path_a}"
        );
        assert!(
            path_b.ends_with("/epsilon-tool"),
            "shim must be written under the caller-supplied name; got: {path_b}"
        );
        assert_ne!(path_a, path_b, "two shims must live in distinct tempdirs");
    }

    /// Two shims under the same `name` produce two distinct absolute
    /// paths — each `make_executable_shim` call gets its own `TempDir`.
    /// Pinning this is the load-bearing parallel-safety property: under
    /// `cargo test` two threads can independently call
    /// `make_executable_shim("git", ...)` and neither will clobber the
    /// other's binary, because the directory key is uniquely
    /// generated by `tempfile::tempdir()`. A future drift onto a fixed
    /// `/tmp/forge-shim/git` path would race; this test guards against
    /// that.
    #[test]
    fn test_make_executable_shim_two_calls_isolate_paths() {
        let (_a, p1) = make_executable_shim("zeta", "#!/bin/sh\nexit 0\n");
        let (_b, p2) = make_executable_shim("zeta", "#!/bin/sh\nexit 0\n");
        assert_ne!(
            p1, p2,
            "two shims with the same name must live in distinct tempdirs"
        );
    }

    /// When the returned `TempDir` is dropped, the shim file is
    /// unlinked. Pinning this is the lifetime contract the
    /// `(TempDir, String)` shape encodes: the `TempDir` must outlive
    /// every spawn against the path. A future helper that returned a
    /// bare `String` (or that leaked the `TempDir` into a `'static`)
    /// would silently break this guarantee — and tests that called the
    /// shim long after the `TempDir` dropped would either flake or pass
    /// against a stale binary on a reused inode. Drop is the shim's
    /// finalizer; this test pins that finalizer.
    #[test]
    fn test_make_executable_shim_drop_unlinks_shim() {
        let path = {
            let (dir, path) = make_executable_shim("eta", "#!/bin/sh\nexit 0\n");
            assert!(std::path::Path::new(&path).exists());
            drop(dir);
            path
        };
        assert!(
            !std::path::Path::new(&path).exists(),
            "shim must be unlinked after TempDir drops, but still exists at: {path}"
        );
    }
}
