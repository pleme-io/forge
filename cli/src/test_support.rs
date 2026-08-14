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
//!
//! The module also hosts the canonical **hermetic git fixture** —
//! [`init_repo_with_one_commit`] + [`add_bare_origin`] — that the three
//! release-commit test modules (`infrastructure/git.rs`,
//! `commands/release_commit.rs`, `commands/product_release.rs`) each
//! re-spelled verbatim. Same three-times-rule law-redeeming carve-out
//! as `make_executable_shim`, applied to the git fixture surface.

#![cfg(test)]

use std::path::{Path, PathBuf};

use crate::git::git_command_sync;

/// Write an executable shim script to a fresh tempdir under `name`,
/// chmod it 0o755 (Unix), and return the `(TempDir, absolute path)` pair.
///
/// `name` is the basename the shim is written as; tests pass `"git"`,
/// `"nix"`, `"attic"` (and friends) so the OS process-lookup path
/// matches whatever binary basename the producer site's spawn resolves
/// to (`git` / `nix` / `attic`, etc.).
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

/// Serial-safe guard for tests that either mutate `GIT_BIN` or invoke
/// any production entry point that resolves the `git` binary through
/// `tools::get_tool_path(tools::GIT)` — i.e. the no-bin surface on
/// [`crate::git`] (`git_capture` / `git_capture_async` /
/// `git_capture_remote`) and the no-bin surface on
/// [`crate::infrastructure::git::GitClient`] (`is_clean` / `add` /
/// `commit` / `push` / `push_to` / `has_staged_changes` when no
/// `with_git_bin` override was set).
///
/// Env-var writes are process-global; without a serial guard a
/// concurrent production-path test could pick up the wrong shim from a
/// mid-flight env-var mutation. Same discipline as `serial_test::serial`
/// but without the extra dependency.
///
/// Consumers acquire the lock at the top of the test body via
/// `let _guard = GIT_BIN_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());`.
/// The `unwrap_or_else(|p| p.into_inner())` shape is load-bearing: a
/// prior panicking test that poisoned the mutex must not chain-fail
/// every subsequent test that shares the lock — the inner-lock recovery
/// keeps the fleet moving.
pub static GIT_BIN_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// RAII scope-guard that sets `GIT_BIN=value` on construction and
/// restores the pre-scope state (either the original value or unset) on
/// drop — panic-safe by construction. Snapshots via `std::env::var` so
/// a set-to-empty original round-trips verbatim. Every caller MUST hold
/// [`GIT_BIN_ENV_LOCK`] for the duration of the scope; the guard does
/// not lock the mutex itself, so the two disciplines compose without
/// accidental re-entrancy.
///
/// Centralized here (rather than a private per-file copy) because two
/// modules — `git.rs` and `infrastructure::git` — each carry their own
/// `GIT_BIN`-resolving surface and each need to pin the same
/// env-var-routes-through discipline in tests. Two occurrences already
/// past THEORY §VI.1's three-times threshold in intent (a duplicate
/// would drift the restore-on-drop contract silently); this lift is the
/// law-anticipating consolidation.
pub struct GitBinScope {
    prior: std::result::Result<String, std::env::VarError>,
}

impl GitBinScope {
    pub fn set(value: &str) -> Self {
        let prior = std::env::var("GIT_BIN");
        std::env::set_var("GIT_BIN", value);
        Self { prior }
    }
}

impl Drop for GitBinScope {
    fn drop(&mut self) {
        match &self.prior {
            Ok(v) => std::env::set_var("GIT_BIN", v),
            Err(_) => std::env::remove_var("GIT_BIN"),
        }
    }
}

/// Initialize a hermetic git repo with one committed file under `dir`.
///
/// Runs `git init -q -b main`, configures a stable identity
/// (`user.email`, `user.name`) and disables commit signing
/// (`commit.gpgsign=false`), then writes a `seed.txt` fixture, stages
/// it, and commits with the message `"seed"`. The branch is `main` —
/// matches the branch every release-commit path in forge targets — so
/// a subsequent `add_bare_origin` + `git push origin main` round-trip
/// resolves against a real ref without dangling-HEAD ambiguity.
///
/// # Why centralized
///
/// Three test modules — `cli/src/infrastructure/git.rs`,
/// `cli/src/commands/release_commit.rs`, and
/// `cli/src/commands/product_release.rs` — each re-spelled this exact
/// thirteen-line stanza VERBATIM. Three identically-shaped copies past
/// THEORY §VI.1's three-is-a-law threshold; this helper is the
/// law-redeeming carve-out. A future fourth release-commit test (the
/// shape this fixture exists to drive — a typed commit-and-push
/// primitive that needs a real git working tree against a real bare
/// origin) inherits the canonical fixture for free.
///
/// # Why `commit.gpgsign=false`
///
/// The managed remote-execution environment forge runs in carries
/// `commit.gpgsign=true` in the host's global gitconfig, with a custom
/// signing program. Disabling signing locally on the test work-tree
/// keeps the seed commit hermetic against the host config so the
/// fixture spins up identically whether the test runs locally, on CI,
/// or in the managed remote sandbox.
///
/// # Panics
///
/// Panics on any failed git spawn or non-zero exit — a fixture-setup
/// failure should fail the test loudly before the function under test
/// fires, not be deferred into a confusing downstream "git rejected
/// the operation" diagnostic. Same loud-failure discipline as
/// [`make_executable_shim`]'s `expect("write shim")`.
///
/// # Env-var lock discipline
///
/// Acquires [`GIT_BIN_ENV_LOCK`] for the duration of every spawn.
/// Post the lift onto [`crate::git::git_command_sync`] the fixture
/// reads `GIT_BIN` at spawn — same substrate-pinned resolution every
/// production consumer honors. Without the lock a concurrently-running
/// shim test (`git.rs::test_no_bin_entry_points_route_through_git_bin_env_var`,
/// `infrastructure/git.rs::test_git_client_no_bin_surface_routes_through_git_bin_env_var`,
/// etc.) could set `GIT_BIN=<shim>` between two of the seven spawns
/// this fixture drives, so `git init` would succeed against the real
/// git while `git commit` hit the shim (or vice versa) — a race
/// masquerading as a flake. Holding the lock across the whole fixture
/// pins the resolution stable for the seven spawns; the pre-lift
/// PATH-bypass shape (`SyncCommand::new(<bare>)`) achieved the same
/// serialization only accidentally, by ignoring the env var. This
/// spelling preserves the accidental serialization AND the intentional
/// substrate-pinning — both post-lift properties are load-bearing.
pub fn init_repo_with_one_commit(dir: &Path) {
    let _guard = GIT_BIN_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let run = |args: &[&str]| {
        let status = git_command_sync()
            .args(args)
            .current_dir(dir)
            .status()
            .expect("git spawn");
        assert!(status.success(), "git {args:?} failed in {dir:?}");
    };
    run(&["init", "-q", "-b", "main"]);
    run(&["config", "user.email", "forge-test@example.invalid"]);
    run(&["config", "user.name", "forge-test"]);
    run(&["config", "commit.gpgsign", "false"]);
    std::fs::write(dir.join("seed.txt"), "seed\n").expect("write seed.txt");
    run(&["add", "seed.txt"]);
    run(&["commit", "-q", "-m", "seed"]);
}

/// Initialize a fresh bare git repo at `bare_dir` and add it as
/// `origin` on the work-tree at `work_dir`.
///
/// Runs `git init -q --bare --initial-branch=main` on `bare_dir` so
/// the bare's HEAD resolves to `main` (the branch every release-commit
/// path in forge targets) — without `--initial-branch=main` the
/// bare's HEAD would default to `master` on some git versions and a
/// subsequent `git clone <bare>` would resolve HEAD against a dangling
/// ref, surfacing as an empty probe-clone in the round-trip tests this
/// fixture drives.
///
/// Then runs `git remote add origin <bare>` on `work_dir` so a
/// subsequent `git push origin main` lands the work-tree's commits on
/// the bare without contacting any network endpoint.
///
/// # Why centralized
///
/// Three test modules carried near-identical copies of this fixture
/// with the `--initial-branch=main` flag drifting in two of three
/// (THEORY §VI.1: "two occurrences is a coincidence; three is a
/// law"). The pre-lift `cli/src/infrastructure/git.rs` copy omitted
/// the flag — papered over by the fact that its sole call site
/// asserted only on `CommitPushOutcome` and never probe-cloned. The
/// other two carried the corrected form. Centralizing here pins the
/// correct form once and prevents a future drift onto either spelling.
///
/// # Panics
///
/// Panics on any failed git spawn or non-zero exit — fixture-setup
/// failure is loud rather than deferred into a downstream "remote
/// rejected" diagnostic.
///
/// # Env-var lock discipline
///
/// Same [`GIT_BIN_ENV_LOCK`] discipline as
/// [`init_repo_with_one_commit`]: the two spawns this fixture drives
/// read `GIT_BIN` at construction, so the lock guarantees a
/// concurrently-running shim test cannot mutate the env var between
/// the `git init --bare` and the `git remote add origin` half of the
/// fixture.
pub fn add_bare_origin(work_dir: &Path, bare_dir: &Path) {
    let _guard = GIT_BIN_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let init = git_command_sync()
        .args(["init", "-q", "--bare", "--initial-branch=main"])
        .current_dir(bare_dir)
        .status()
        .expect("git init --bare spawn");
    assert!(
        init.success(),
        "git init --bare must succeed in {bare_dir:?}"
    );
    let add = git_command_sync()
        .args([
            "remote",
            "add",
            "origin",
            bare_dir.to_str().expect("bare path utf-8"),
        ])
        .current_dir(work_dir)
        .status()
        .expect("git remote add spawn");
    assert!(
        add.success(),
        "git remote add origin must succeed in {work_dir:?}"
    );
}

/// The three canonical Rust source shapes that spawn a bare tool
/// literal — the shapes every whole-module routing shield in forge
/// forbids.
///
/// Returns `[raw_std, raw_bare, raw_tokio]` reconstructed via `format!`
/// from `bare`, in the fixed order the shields destructure and emit
/// assertion messages against:
///
/// 1. `std::process::Command::new("<bare>")` — the fully-qualified sync spawn.
/// 2. `Command::new("<bare>")` — the top-of-file `use` alias sync spawn.
/// 3. `tokio::process::Command::new("<bare>")` — the fully-qualified async spawn.
///
/// # Why one canonical list
///
/// Fifteen shield tests across ten modules (`cli/src/git.rs`,
/// `cli/src/infrastructure/git.rs`, `cli/src/test_support.rs`, and
/// seven `cli/src/commands/*.rs`) each re-spelled the same three
/// `format!` lines verbatim (THEORY.md §VI.1: "when a pattern repeats
/// three times, extract an archetype/backend/synthesizer and generate
/// from it. Two occurrences is a coincidence; three is a law"). Five
/// times over the threshold. This helper is the law-redeeming
/// consolidation: a future Rust spawn shape added to the array here
/// (a new async runtime, say) is picked up by every shield in one
/// edit, and the shield-side surface for "what shapes are forbidden"
/// cannot silently drift between modules.
///
/// # Load-bearing reconstruction via `format!`
///
/// The shapes are built via `format!("Command::new(\"{}\")", bare)`
/// rather than written as literal strings. This helper's own source
/// text therefore contains only the templated form — `Command::new(\"{}\")` —
/// never the substituted form a producer-site regression would emit.
/// A shield that runs against `include_str!("test_support.rs")` does
/// not false-match itself on this helper's body. Same discipline
/// every shield already applied inline; centralizing it pins the
/// discipline once. (Note: the substituted spawn literal a shield
/// forbids is never written verbatim in this module — not in the
/// helper body, not in these docs — so a caller with `bare = "git"`
/// producing the string `Command`+`::new("git")` cannot appear as a
/// substring of this file's source text.)
///
/// # Substring semantics
///
/// Each returned shape includes the enclosing `"…"` around `bare`,
/// so any shield asserting `!SOURCE.contains(&raw_bare)` also catches
/// every fully-qualified spawn as a substring — the
/// `std::process::`-prefixed shape contains the bare-alias shape as a
/// suffix. The explicit triple exists so each shield can emit a
/// distinct assertion message per shape, not because a single check
/// would miss any of them.
pub fn forbidden_spawn_shapes(bare: &str) -> [String; 3] {
    [
        format!("std::process::Command::new(\"{}\")", bare),
        format!("Command::new(\"{}\")", bare),
        format!("tokio::process::Command::new(\"{}\")", bare),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    /// The three shapes returned by [`forbidden_spawn_shapes`] are the
    /// substituted `std::process::` / bare-alias / `tokio::process::`
    /// spawn literals wrapped around `bare`, returned in that fixed
    /// order. Prose above spells out the individual shapes in
    /// templated form (with a placeholder in place of the concrete
    /// bare tool name) to keep this shield-adjacent module free of a
    /// verbatim spawn literal that a whole-file `SOURCE.contains`
    /// shield would otherwise pick up as a false positive.
    ///
    /// Fifteen shield tests across the crate destructure this array by
    /// position (`let [raw_std, raw_bare, raw_tokio] = ...;`) and emit
    /// a distinct assertion message per index. The order therefore
    /// pins the load-bearing shield-message-to-shape mapping: a
    /// reorder here would misroute every shield's diagnostic (a
    /// `tokio::process::` violation would print the `std::process::`
    /// message and vice-versa).
    ///
    /// The exact substituted strings are also part of the shield
    /// contract — a shield with `let bare = "git"` composes to the
    /// exact literal a producer-site regression would insert. Pinning
    /// the return values verbatim guarantees a future edit that
    /// silently rewrites the format template (adding a space, dropping
    /// the quotes) breaks this test loudly before shipping.
    #[test]
    fn test_forbidden_spawn_shapes_returns_three_canonical_shapes_in_fixed_order() {
        assert_eq!(
            forbidden_spawn_shapes("git"),
            [
                "std::process::Command::new(\"git\")".to_string(),
                "Command::new(\"git\")".to_string(),
                "tokio::process::Command::new(\"git\")".to_string(),
            ]
        );
    }

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

    /// `init_repo_with_one_commit` leaves the work-tree on `main`
    /// with the seed commit at `HEAD` and `git status --porcelain`
    /// reporting a clean tree. Pins the post-condition every
    /// downstream release-commit test consumes: the fixture's
    /// `HEAD` is a real commit on `main`, not a dangling ref or an
    /// orphaned root. A future drift that initialized the repo on
    /// `master` (the system default on some git versions, the trap
    /// the `-b main` flag exists to dodge) would surface here as a
    /// branch-name mismatch instead of a confusing "remote
    /// rejected" downstream when the work-tree's `main` push hits
    /// the bare's `master` HEAD.
    #[test]
    fn test_init_repo_with_one_commit_leaves_clean_tree_on_main() {
        let dir = tempfile::tempdir().expect("tempdir");
        init_repo_with_one_commit(dir.path());

        // Acquire the env-var lock AFTER the fixture returns (the fixture
        // holds the lock internally around its own spawns; std Mutex is
        // not reentrant, so this acquisition can only happen after the
        // fixture's guard has dropped). Verification spawns below use
        // `git_command_sync()` and therefore read `GIT_BIN`; without the
        // lock a concurrently-running shim test could mutate the env var
        // mid-verification. Pre-lift this file's verification spawns
        // spelled the bare `Command::new(<bare>)` shape and were
        // insulated by ignoring `GIT_BIN`; the shield forbids that
        // shape now, and this lock is the constructive substitute.
        let _guard = GIT_BIN_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());

        let branch = git_command_sync()
            .args(["rev-parse", "--abbrev-ref", "HEAD"])
            .current_dir(dir.path())
            .output()
            .expect("git rev-parse spawn");
        assert!(branch.status.success(), "git rev-parse must succeed");
        assert_eq!(
            String::from_utf8_lossy(&branch.stdout).trim(),
            "main",
            "fixture must initialize on `main`, not `master`"
        );

        let status = git_command_sync()
            .args(["status", "--porcelain"])
            .current_dir(dir.path())
            .output()
            .expect("git status spawn");
        assert!(status.status.success(), "git status must succeed");
        assert_eq!(
            String::from_utf8_lossy(&status.stdout).trim(),
            "",
            "post-fixture work-tree must be clean"
        );

        let subject = git_command_sync()
            .args(["log", "-1", "--pretty=%s"])
            .current_dir(dir.path())
            .output()
            .expect("git log spawn");
        assert!(subject.status.success(), "git log must succeed");
        assert_eq!(
            String::from_utf8_lossy(&subject.stdout).trim(),
            "seed",
            "seed commit subject must be canonical"
        );
    }

    /// `add_bare_origin` configures `origin` such that a subsequent
    /// `git push origin main` on the work-tree lands the commit on
    /// the bare repo, and a probe `git clone <bare>` resolves HEAD
    /// against a real ref on `main`. Pins the end-to-end round-trip
    /// every typed-commit-and-push test (`commit_artifact_tags`,
    /// `commit_cluster_overlay_release`,
    /// `stage_commit_push_release`) drives through this fixture.
    ///
    /// A future drift that dropped the `--initial-branch=main` flag
    /// on `git init --bare` (the regression the pre-lift
    /// `infrastructure/git.rs` copy carried) would surface here as
    /// the probe-clone's `git log` failing or returning an empty
    /// subject — not as a confusing downstream typed-error test
    /// failure with an "everything looks fine" appearance.
    #[test]
    fn test_add_bare_origin_round_trips_push_then_clone() {
        let parent = tempfile::tempdir().expect("parent tempdir");
        let work = parent.path().join("work");
        let bare = parent.path().join("origin.git");
        std::fs::create_dir(&work).expect("mkdir work");
        std::fs::create_dir(&bare).expect("mkdir bare");
        init_repo_with_one_commit(&work);
        add_bare_origin(&work, &bare);

        // Same rationale as
        // `test_init_repo_with_one_commit_leaves_clean_tree_on_main`:
        // acquire the env-var lock AFTER both fixtures have released
        // their internal guards so the three verification spawns
        // (push, clone, log) read `GIT_BIN` under serialization.
        let _guard = GIT_BIN_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());

        let push = git_command_sync()
            .args(["push", "-u", "origin", "main"])
            .current_dir(&work)
            .status()
            .expect("git push spawn");
        assert!(push.success(), "push to fixture's bare origin must succeed");

        let probe = parent.path().join("probe");
        let clone = git_command_sync()
            .args([
                "clone",
                bare.to_str().expect("bare utf-8"),
                probe.to_str().expect("probe utf-8"),
            ])
            .status()
            .expect("git clone spawn");
        assert!(
            clone.success(),
            "probe clone of fixture's bare must succeed; \
             --initial-branch=main drift would surface here"
        );

        let subject = git_command_sync()
            .args(["log", "-1", "--pretty=%s"])
            .current_dir(&probe)
            .output()
            .expect("git log spawn");
        assert!(
            subject.status.success(),
            "probe-clone git log must succeed against a real ref"
        );
        assert_eq!(
            String::from_utf8_lossy(&subject.stdout).trim(),
            "seed",
            "probe-clone must resolve HEAD to the seed commit on main"
        );
    }

    /// Whole-module shield: no raw bare-literal `git` spawn may live in
    /// `cli/src/test_support.rs`. Every git spawn — the two `pub fn`
    /// hermetic fixtures ([`init_repo_with_one_commit`],
    /// [`add_bare_origin`]) that every release-commit test module in
    /// forge consumes, AND every sibling `#[cfg(test)]` block that
    /// probes the fixtures' own post-conditions — must resolve `GIT_BIN`
    /// via the canonical [`crate::git::git_command_sync`] constructor
    /// so a hermetic-runner (Nix `mkRuntimeToolsEnv`) invocation with a
    /// pinned substrate-derivation git falls through to that shim
    /// rather than whichever `git` sits first on `PATH`.
    ///
    /// Because this module is the SHARED fixture surface every
    /// downstream release-commit test in forge inherits, a raw literal
    /// here would silently regress the routing at every downstream
    /// consumer even after each consumer's own sibling shield
    /// (`commands/release_commit.rs`, `commands/product_release.rs`,
    /// `commands/attestation.rs`) had certified the consumer body.
    /// Pinning the fixture-side spawn routing at the shared root
    /// closes that frontier: the routing invariant compounds outward
    /// through every fixture caller without each having to re-pin it.
    ///
    /// Pre-lift the two `pub fn` fixtures used the top-of-file
    /// `use std::process::Command as SyncCommand;` alias verbatim
    /// (`SyncCommand::new(<bare>)` at `init_repo_with_one_commit`'s
    /// `run` closure and at both spawns inside `add_bare_origin`), and
    /// the six `#[cfg(test)]` sibling probes used the bare
    /// `Command::new(<bare>)` shape (the local `use std::process::Command;`
    /// alias inside the tests submodule). The alias at the top of the
    /// file was removed and every spawn now routes through
    /// `git_command_sync()`; the `Command` alias inside the tests
    /// submodule remains solely for the shim-path invocation at
    /// `test_make_executable_shim_executes_caller_supplied_body`, which
    /// spawns by absolute path (`Command::new(&path)`) — a runtime path
    /// variable, not the bare tool literal this shield forbids.
    ///
    /// The three forbidden shapes (`std::process::Command::new(...)`,
    /// bare `Command::new(...)`, `tokio::process::Command::new(...)`)
    /// are reconstructed via `format!` from the bare string `"git"` so
    /// this shield's own source text does not false-match itself — the
    /// whole-module scan therefore covers both the top-of-file
    /// production body AND every sibling `#[cfg(test)]` block, any of
    /// which could otherwise silently re-introduce a raw literal.
    /// Also asserts the canonical `crate::git::git_command_sync`
    /// delegation form is present in the module so the sigil-body
    /// itself cannot silently drift away from the substrate-exported
    /// env-var contract.
    ///
    /// The end-to-end `GIT_BIN`-routing invariant of the underlying
    /// primitive is pinned separately by
    /// [`crate::git::tests::test_git_command_sync_routes_through_git_bin_env_var`];
    /// this shield only certifies that every git-spawning site in this
    /// module reads through `git_command_sync()`.
    ///
    /// Sibling shield to
    /// `test_git_spawn_routes_through_git_command_sync_not_raw_literal`
    /// in `commands/release_commit.rs`, `commands/product_release.rs`,
    /// and `commands/attestation.rs`.
    #[test]
    fn test_git_spawn_routes_through_git_command_sync_not_raw_literal() {
        const SOURCE: &str = include_str!("test_support.rs");

        let [raw_std, raw_bare, raw_tokio] = forbidden_spawn_shapes("git");

        assert!(
            !SOURCE.contains(&raw_std),
            "cli/src/test_support.rs must not spawn `git` via the \
             bare literal — every git spawn must resolve `GIT_BIN` via \
             `crate::git::git_command_sync()` first. A raw literal at \
             `std::process::Command::new` bypasses the hermetic-runner \
             contract substrate's mkRuntimeToolsEnv exports."
        );
        assert!(
            !SOURCE.contains(&raw_bare),
            "cli/src/test_support.rs must not spawn `git` via the \
             bare literal — every git spawn must resolve `GIT_BIN` via \
             `crate::git::git_command_sync()` first. A raw literal at \
             `Command::new` (either the top-level `use` alias or the \
             bare form) bypasses the hermetic-runner contract."
        );
        assert!(
            !SOURCE.contains(&raw_tokio),
            "cli/src/test_support.rs must not spawn `git` via the \
             bare literal — every git spawn must resolve `GIT_BIN` via \
             `crate::git::git_command_sync()` first. A raw literal at \
             `tokio::process::Command::new` bypasses the \
             hermetic-runner contract."
        );
        assert!(
            SOURCE.contains("crate::git::git_command_sync"),
            "cli/src/test_support.rs must resolve the `git` binary \
             via the canonical `crate::git::git_command_sync()` \
             constructor — the required form was not found in the \
             module. A regression here would silently downgrade to the \
             PATH fallback."
        );
    }
}
