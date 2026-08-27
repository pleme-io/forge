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

/// Serial-safe guard for tests that either mutate `REPO_ROOT` /
/// `SERVICE_DIR` env vars or the process working directory (via
/// `std::env::set_current_dir`) — the composed shape
/// [`crate::repo::activate_root_flake`] owns.
///
/// The primitive touches THREE process-global surfaces at once:
/// `REPO_ROOT`, `SERVICE_DIR`, and cwd. Each is read by production code
/// paths across the crate — `repo::find_repo_root`,
/// `git::get_repo_root`, `path_builder::PathBuilder::new`,
/// `config::DeployConfig::load_for_service`, and every consumer of
/// `SERVICE_DIR` under `commands/*.rs`. A concurrent test that either
/// activated a different root or mid-flight chdir'd to a different
/// directory would race any test observing those surfaces. Same
/// discipline as [`GIT_BIN_ENV_LOCK`], applied to the root-flake
/// activation surface.
///
/// Consumers acquire the lock at the top of the test body via
/// `let _guard = ROOT_FLAKE_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());`.
/// The `unwrap_or_else(|p| p.into_inner())` shape is load-bearing: a
/// prior panicking test that poisoned the mutex must not chain-fail
/// every subsequent test that shares the lock.
pub static ROOT_FLAKE_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// RAII scope-guard that snapshots — and on drop restores — the three
/// process-global surfaces [`crate::repo::activate_root_flake`] mutates:
/// the `REPO_ROOT` env var, the `SERVICE_DIR` env var, and the current
/// working directory. Panic-safe by construction: drop runs on both
/// normal scope exit and unwind, so a test that panics mid-body cannot
/// leak `REPO_ROOT=<tempdir>` / `SERVICE_DIR=<tempdir>` / cwd=<tempdir>
/// to any subsequent test in the same process — the exact leak the
/// pre-lift manual-restore stanza silently allowed.
///
/// Callers MUST hold [`ROOT_FLAKE_ENV_LOCK`] for the duration of the
/// scope; the guard does not lock the mutex itself so a test-body can
/// nest a `catch_unwind` inside its capture without deadlocking on
/// re-entrancy through the lock. Same discipline as [`GitBinScope`]
/// applied to the three-surface root-flake activation window.
///
/// Six tests in `cli/src/repo.rs` reached for the pre-lift three-line
/// snapshot-and-nine-line-restore stanza VERBATIM
/// (`activate_root_flake_publishes_repo_root_env_var`,
/// `activate_root_flake_publishes_service_dir_env_var`,
/// `activate_root_flake_chdirs_to_repo_root_not_service_dir`,
/// `activate_root_flake_publishes_env_vars_even_when_chdir_fails`,
/// `activate_root_flake_error_context_names_the_repo_root_path`,
/// `activate_root_flake_accepts_str_and_string_and_path_args`) — 6×
/// past THEORY §VI.1's three-times-is-a-law threshold with the
/// additional defect that a panic between snapshot and restore
/// silently leaked the three surfaces to every subsequent test the
/// process ran. RAII drop closes that leak by construction.
///
/// The struct's field order is load-bearing for drop order: `prior_cwd`
/// is restored FIRST (so `set_current_dir` runs before env-var
/// mutation), mirroring the pre-lift stanza's ordering at the six
/// migrated sites. `set_current_dir`'s `Result` is deliberately ignored
/// with `let _ =` so a torn-down tempdir at drop time cannot
/// double-panic the unwind path (`set_var` / `remove_var` return `()`,
/// so they carry the same no-double-panic guarantee for free).
pub struct RootFlakeEnvSnapshot {
    prior_cwd: std::path::PathBuf,
    prior_repo: std::result::Result<String, std::env::VarError>,
    prior_svc: std::result::Result<String, std::env::VarError>,
}

impl RootFlakeEnvSnapshot {
    /// Snapshot the three surfaces `activate_root_flake` mutates at
    /// the moment of the call. Panics if the current working directory
    /// is unreadable — same `expect("cwd")` shape the pre-lift
    /// consumers spelled verbatim, so the migration is a byte-identical
    /// lift at the snapshot boundary.
    pub fn capture() -> Self {
        let prior_cwd = std::env::current_dir().expect("cwd");
        let prior_repo = std::env::var("REPO_ROOT");
        let prior_svc = std::env::var("SERVICE_DIR");
        Self {
            prior_cwd,
            prior_repo,
            prior_svc,
        }
    }
}

impl Drop for RootFlakeEnvSnapshot {
    fn drop(&mut self) {
        let _ = std::env::set_current_dir(&self.prior_cwd);
        match &self.prior_repo {
            Ok(v) => std::env::set_var("REPO_ROOT", v),
            Err(_) => std::env::remove_var("REPO_ROOT"),
        }
        match &self.prior_svc {
            Ok(v) => std::env::set_var("SERVICE_DIR", v),
            Err(_) => std::env::remove_var("SERVICE_DIR"),
        }
    }
}

/// RAII scope-guard that snapshots — and on drop restores — a single
/// process env var identified by `name`. Panic-safe by construction:
/// drop runs on both normal scope exit and unwind, so a test that
/// panics mid-body cannot leak `<NAME>=<sentinel>` to any subsequent
/// test in the same process. Callers hold the per-var lock (e.g.
/// `crate::repo::tests::SAFE_ENV_LOCK`,
/// `crate::git::tests::RELEASE_GIT_SHA_ENV_LOCK`,
/// `crate::infrastructure::attic::tests::ATTIC_SERVER_NAME_ENV_LOCK`)
/// for the duration of the scope; the guard does not lock the mutex
/// itself, so the two disciplines compose without accidental
/// re-entrancy.
///
/// # Why centralized
///
/// Three test modules — `cli/src/repo.rs` (`SafeEnvSnapshot`),
/// `cli/src/git.rs` (`ReleaseGitShaSnapshot`), and
/// `cli/src/infrastructure/attic.rs` (`AtticServerNameSnapshot`) —
/// each carried a module-private RAII struct with a byte-equivalent
/// `struct { prior: Result<String, VarError> }` + `capture()` +
/// `Drop { match &self.prior { Ok(v) => set_var(NAME, v), Err(_) =>
/// remove_var(NAME) } }` body, differing only in the hardcoded env-var
/// name string. Three isomorphic copies past THEORY §VI.1's
/// three-times threshold ("two occurrences is a coincidence; three is
/// a law"). This helper is the law-redeeming carve-out: the shape
/// (`prior: Result<String, VarError>` + snapshot-on-`capture` + restore-
/// on-`Drop`) lives at exactly ONE code line across the crate, and a
/// future refinement (e.g., telemetry on the restore path, an unset-
/// vs-empty-string canonicalization hook, a switch to
/// `std::env::VarError` recovery on the poisoned-mutex path) reaches
/// every consumer by construction.
///
/// The empty-string round-trip is deliberate: `std::env::var` returns
/// `Ok("")` when a caller explicitly exported the var to the empty
/// string, so `Drop` restores it as `set_var(NAME, "")` rather than
/// `remove_var(NAME)` — the observable state distinction between "set
/// but empty" and "unset" is preserved verbatim.
///
/// Sibling of the compound [`RootFlakeEnvSnapshot`] (three surfaces:
/// cwd + `REPO_ROOT` + `SERVICE_DIR`) and the set-then-restore
/// [`GitBinScope`] (mutates on construction, not just on drop).
/// THEORY §V (solve-once-at-the-primitive); §VI.1
/// (recurring-shape-to-helper).
pub struct EnvVarSnapshot {
    name: &'static str,
    prior: std::result::Result<String, std::env::VarError>,
}

impl EnvVarSnapshot {
    /// Snapshot the current value of the `name` env var; the returned
    /// guard restores it on drop. `name` is `&'static str` so the
    /// caller's site-level intent (a specific env-var spelling) is
    /// pinned at the type-check boundary and cannot be dynamically
    /// constructed from a mutable string that later shifts.
    pub fn capture(name: &'static str) -> Self {
        Self {
            name,
            prior: std::env::var(name),
        }
    }
}

impl Drop for EnvVarSnapshot {
    fn drop(&mut self) {
        match &self.prior {
            Ok(v) => std::env::set_var(self.name, v),
            Err(_) => std::env::remove_var(self.name),
        }
    }
}

/// RAII scope-guard that MUTATES a single process env var identified by
/// `name` — writing `value` on construction, restoring the pre-scope
/// state (either the original value or unset) on drop. Panic-safe by
/// construction: drop runs on both normal scope exit and unwind, so a
/// test that panics mid-body cannot leak `<NAME>=<sentinel>` to any
/// subsequent test in the same process. Snapshots via `std::env::var`
/// so a set-to-empty original round-trips verbatim.
///
/// Sibling of the snapshot-only [`EnvVarSnapshot`]: same restore
/// contract (`Result<String, VarError>` + panic-safe `Drop`), but
/// mutates on construction as well — the closed pair exhausts the
/// hermetic-env-var-guard surface. A fresh consumer picks its guard by
/// asking "snapshot-only ([`EnvVarSnapshot::capture`]) or set-then-
/// restore ([`EnvVarScope::set`])?" — the closed choice a per-module
/// inline struct declaration does not present.
///
/// Every caller MUST hold the appropriate per-var lock (e.g.
/// [`GIT_BIN_ENV_LOCK`], `crate::infrastructure::kubectl::tests::
/// KUBECTL_BIN_ENV_LOCK`) for the duration of the scope; the guard
/// does not lock the mutex itself, so the two disciplines compose
/// without accidental re-entrancy.
///
/// # Why centralized
///
/// Two test-support scope-guards — `test_support.rs::GitBinScope` and
/// `infrastructure/kubectl.rs::KubectlBinScope` — each carried a
/// byte-equivalent `struct { prior: Result<String, VarError> }` +
/// `set(value: &str) -> Self { let prior = std::env::var(NAME);
/// std::env::set_var(NAME, value); Self { prior } }` + `impl Drop {
/// match &self.prior { Ok(v) => set_var(NAME, v), Err(_) =>
/// remove_var(NAME) } }` triple, differing only in the hardcoded
/// env-var name string. Two isomorphic copies past THEORY §VI.1's
/// three-is-a-law threshold in intent — the pair had to agree on the
/// field type spelling, the set-then-snapshot ordering (mutate FIRST,
/// snapshot the pre-mutation value SECOND — the reverse ordering
/// would restore the sentinel instead of the pre-scope value), the
/// Drop-branch dispatch, and the panic-safety guarantee. Post-lift
/// the two consumers route through ONE body so a future refinement
/// (telemetry on the restore path, an unset-vs-empty-string
/// canonicalization hook, a `tokio::task_local!` variant) lands at
/// exactly one code line and reaches every consumer by construction.
///
/// The `KubectlBinScope`'s own docstring anticipated this lift ("a
/// second test would trigger the lift to `test_support.rs`, same rule
/// as [`make_executable_shim`] applied at the three-times threshold");
/// with 13 kubectl_bin call sites and 40+ git_bin call sites the
/// pre-lift docstring justification is well past the anticipated
/// threshold. THEORY §V (solve-once-at-the-primitive); §VI.1
/// (recurring-shape-to-helper).
pub struct EnvVarScope {
    name: &'static str,
    prior: std::result::Result<String, std::env::VarError>,
}

impl EnvVarScope {
    /// Set `name=value` and return a guard that restores the pre-scope
    /// state on drop. `name` is `&'static str` so the caller's
    /// site-level intent (a specific env-var spelling) is pinned at
    /// the type-check boundary and cannot be dynamically constructed
    /// from a mutable string that later shifts.
    ///
    /// Snapshot the pre-mutation value FIRST, mutate SECOND — the
    /// reverse ordering would snapshot the sentinel itself and restore
    /// it on drop, defeating the guard's contract.
    pub fn set(name: &'static str, value: &str) -> Self {
        let prior = std::env::var(name);
        std::env::set_var(name, value);
        Self { name, prior }
    }
}

impl Drop for EnvVarScope {
    fn drop(&mut self) {
        match &self.prior {
            Ok(v) => std::env::set_var(self.name, v),
            Err(_) => std::env::remove_var(self.name),
        }
    }
}

/// `GitBinScope::set(value)` sets `GIT_BIN=value` and returns an
/// [`EnvVarScope`] that restores the pre-scope state on drop. Preserved
/// as a zero-cost named namespace so every existing call site
/// (`let _scope = GitBinScope::set(&shim);` — 40+ across `git.rs` and
/// `infrastructure/git.rs`) keeps its identity-at-the-call-site
/// spelling: the env-var name lives at ONE body inside this impl
/// rather than being copy-pasted as a literal at every consumer, so a
/// typo `GIT_BIN` → `GIT_BINN` at a spawn shield is structurally
/// impossible.
///
/// Every caller MUST hold [`GIT_BIN_ENV_LOCK`] for the duration of
/// the scope.
pub struct GitBinScope;

impl GitBinScope {
    pub fn set(value: &str) -> EnvVarScope {
        EnvVarScope::set("GIT_BIN", value)
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

/// Stand up a hermetic bare-origin repo + work-tree pair, both
/// under a fresh parent tempdir, with the canonical seed commit on
/// `main` produced by [`init_repo_with_one_commit`] on the work-tree
/// and [`add_bare_origin`]'s `--initial-branch=main` bare + `origin`
/// remote configured on the work-tree.
///
/// Returns `(parent, bare, work)` — the parent `TempDir` MUST be
/// bound to a scope that outlives every subsequent use of `bare` /
/// `work`. A `let (_, bare, work) = …` binding that drops the parent
/// unlinks the on-disk state, and every subsequent git spawn against
/// `bare` / `work` fails reproducibly (a fast, loud signal instead
/// of a flake). Same RAII-guard contract as [`make_executable_shim`]
/// and [`crate::hermetic_scratch::hermetic_scratch_file`].
///
/// # Why centralized
///
/// Six sibling `#[test]` / `#[tokio::test]` bodies across the crate
/// each re-spelled the same seven-line stanza VERBATIM:
///
/// ```ignore
/// let parent = tempfile::tempdir().expect("parent tempdir");
/// let work = parent.path().join("work");
/// let bare = parent.path().join("origin.git");
/// std::fs::create_dir(&work).expect("mkdir work");
/// std::fs::create_dir(&bare).expect("mkdir bare");
/// init_repo_with_one_commit(&work);
/// add_bare_origin(&work, &bare);
/// ```
///
/// - `commands/release_commit.rs::test_commit_cluster_overlay_release_lands_canonical_subject_on_origin`
/// - `commands/product_release.rs::test_commit_artifact_tags_uses_canonical_commit_subject_format`
/// - `git.rs::tests::make_bare_origin_with_work` (a private local
///   fixture with FOUR call sites, plus an additional
///   `git push -u origin main` step baked into the fixture body)
/// - `test_support.rs::test_add_bare_origin_round_trips_push_then_clone`
///   (self-test of `add_bare_origin`, kept inline to exercise the
///   underlying primitives directly)
/// - `test_support.rs::test_clone_bare_and_read_head_subject_round_trips_seed_commit`
///   (self-test of `clone_bare_and_read_head_subject`, kept inline
///   for the same reason)
/// - `test_support.rs::test_clone_bare_and_read_head_subject_returns_trimmed_string`
///   (self-test of `clone_bare_and_read_head_subject`, kept inline
///   for the same reason)
///
/// Six identically-shaped copies past THEORY.md §VI.1's
/// three-times-is-a-law threshold ("two occurrences is a
/// coincidence; three is a law"). This primitive is the
/// law-redeeming consolidation. The three self-tests here in
/// `test_support.rs` intentionally stay inline — they pin the
/// composition ingredients ([`init_repo_with_one_commit`],
/// [`add_bare_origin`], [`clone_bare_and_read_head_subject`]) at
/// their own boundary rather than through the composed fixture.
///
/// # Panics
///
/// Panics on any failed tempdir reservation, mkdir, or delegated
/// fixture spawn — every consumer is a `#[test]` / `#[tokio::test]`
/// that treats fixture-setup failure as a bug, not a runtime error.
/// Loud panics map to test failures at the call site whose
/// diagnostic names the offending step; same discipline as
/// [`make_executable_shim`]'s `expect("write shim")`.
///
/// # Env-var lock discipline
///
/// The two composed fixtures ([`init_repo_with_one_commit`] and
/// [`add_bare_origin`]) each acquire + release [`GIT_BIN_ENV_LOCK`]
/// internally. This primitive does NOT hold the lock across those
/// two calls — `std::sync::Mutex` is not re-entrant and every
/// existing consumer follows the caller-acquires-lock-AFTER-setup
/// discipline this primitive inherits. A caller that needs the lock
/// held across downstream verification spawns (e.g. `git push`, or
/// the tested production entry point that reads `GIT_BIN`) acquires
/// it ONCE after this primitive returns.
pub fn make_seeded_work_and_bare_origin() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let parent = tempfile::tempdir().expect("parent tempdir");
    let bare = parent.path().join("origin.git");
    let work = parent.path().join("work");
    std::fs::create_dir(&work).expect("mkdir work");
    std::fs::create_dir(&bare).expect("mkdir bare");
    init_repo_with_one_commit(&work);
    add_bare_origin(&work, &bare);
    (parent, bare, work)
}

/// Read and return the trimmed subject line of the HEAD commit at
/// `dir` via `git log -1 --pretty=%s`. The spawn routes through
/// [`crate::git::git_command_sync`] so a `GIT_BIN` env-var override
/// wins over ambient `PATH` — the same substrate-pinned resolution
/// every production consumer honors.
///
/// # Why centralized
///
/// The read-half of every commit-and-push round-trip verification in
/// the crate — a `git log -1 --pretty=%s` spawn against a chosen
/// working directory, followed by a `String::from_utf8_lossy(&stdout)
/// .trim().to_string()` decode — appears at three sibling sites past
/// THEORY.md §VI.1's three-times-is-a-law threshold ("two occurrences
/// is a coincidence; three is a law"):
///
/// 1. The tail of [`clone_bare_and_read_head_subject`] — reads the
///    probe-clone's HEAD subject.
/// 2. `tests::test_init_repo_with_one_commit_leaves_clean_tree_on_main`
///    — reads the fixture's own HEAD subject to pin the seed commit.
/// 3. `tests::test_add_bare_origin_round_trips_push_then_clone` —
///    reads the pushed probe-clone's HEAD subject.
///
/// A future refinement (a `--pretty=%B` switch to the full message
/// body, an ambient-user-config-defeating `-c log.showSignature=false`
/// flag, a per-spawn telemetry sigil on the resolved subject, or a
/// composed subject-plus-author verifier) lands at this one primitive
/// and reaches all three consumers by construction. A drift on the
/// argv slice (`-2` instead of `-1`, `--pretty=%b` instead of `%s`)
/// or on the decode (forgotten `.trim()`, strict-UTF-8) breaks every
/// consumer through the same fixture-side seam.
///
/// # Panics
///
/// Panics on any failed spawn or non-zero exit — every consumer is
/// a `#[test]` / `#[tokio::test]` that treats these outcomes as
/// fixture bugs. The loud panic maps to a test failure at the call
/// site whose diagnostic names the offending directory and, on
/// non-zero exit, the captured stderr — giving the operator a
/// first-class breadcrumb rather than the pre-lift three-line
/// spawn+status+decode stanzas' silent empty-string fall-through.
///
/// # Env-var lock discipline
///
/// Does NOT acquire [`GIT_BIN_ENV_LOCK`] internally —
/// `std::sync::Mutex` is not re-entrant, and every consumer sits
/// inside a scope where the surrounding test body may already hold
/// the lock (both migrated test-side callers hold it across their
/// verification-spawn triple:
/// `test_init_repo_with_one_commit_leaves_clean_tree_on_main` and
/// `test_add_bare_origin_round_trips_push_then_clone`). Callers
/// running under concurrent shim tests MUST hold the lock across
/// this call so a concurrently-running shim test cannot mutate
/// `GIT_BIN` between the caller acquiring the primitive and the
/// primitive spawning `git`. Same caller-holds-lock contract as
/// [`clone_bare_and_read_head_subject`] — the two panic-on-failure
/// probes present a uniform lock discipline to every test-side
/// consumer.
pub fn read_head_subject(dir: &Path) -> String {
    let subject_out = git_command_sync()
        .args(["log", "-1", "--pretty=%s"])
        .current_dir(dir)
        .output()
        .expect("git log spawn");
    assert!(
        subject_out.status.success(),
        "git log -1 --pretty=%s at {dir:?} must succeed: stderr = {}",
        String::from_utf8_lossy(&subject_out.stderr).trim(),
    );
    String::from_utf8_lossy(&subject_out.stdout)
        .trim()
        .to_string()
}

/// Clone `bare_dir` into `probe_dir` (which MUST NOT yet exist),
/// then read and return the trimmed subject line of the resulting
/// probe's HEAD commit via `git log -1 --pretty=%s`. Both spawns
/// route through [`crate::git::git_command_sync`] so a `GIT_BIN`
/// env-var override wins over ambient `PATH` — the same
/// substrate-pinned resolution every production consumer honors.
///
/// # Why centralized
///
/// The composed shape (a fresh `git clone <bare> <probe>` immediately
/// followed by a `git log -1 --pretty=%s` decode against the cloned
/// probe) is the canonical round-trip verifier for every
/// commit-and-push test in the crate. Three test modules —
/// `cli/src/git.rs::tests::test_commit_and_push_in_lands_commit_on_origin`,
/// `cli/src/commands/product_release.rs::tests::test_commit_artifact_tags_uses_canonical_commit_subject_format`,
/// and `cli/src/commands/release_commit.rs::tests::test_commit_cluster_overlay_release_uses_canonical_commit_subject_format`
/// — each re-spelled the same ten-line stanza VERBATIM:
///
/// ```ignore
/// let clone = git_command_sync()
///     .args(["clone", bare.to_str().expect(...), probe.to_str().expect(...)])
///     .status()
///     .expect("git clone");
/// assert!(clone.success(), "probe clone must succeed");
/// let subject_out = git_command_sync()
///     .args(["log", "-1", "--pretty=%s"])
///     .current_dir(&probe)
///     .output()
///     .expect("git log");
/// let subject = String::from_utf8_lossy(&subject_out.stdout)
///     .trim()
///     .to_string();
/// ```
///
/// Three identically-shaped copies past THEORY.md §VI.1's
/// three-times-is-a-law threshold ("two occurrences is a coincidence;
/// three is a law"). This helper is the law-redeeming carve-out: the
/// `&["clone", <bare>, <probe>]` and `&["log", "-1", "--pretty=%s"]`
/// argv literals plus the `String::from_utf8_lossy(&stdout).trim()`
/// decode all live at one body. A future refinement (an
/// `--depth=1` shallow-clone shortcut for the round-trip, a
/// `--no-tags` fetch trim, a per-probe telemetry emit that reads
/// the resolved subject, or a switch from `%s` to `%B` for the
/// full message body) lands at this one primitive and reaches all
/// three consumers by construction.
///
/// # Panics
///
/// Panics on any failed spawn or non-zero exit — every consumer is
/// a `#[test]` / `#[tokio::test]` that treats these outcomes as
/// fixture bugs. The loud panic maps to a test failure at the
/// call site whose diagnostic names the offending path pair and,
/// on non-zero exit, the captured stderr — giving the operator a
/// first-class breadcrumb rather than the pre-lift silent
/// empty-string return the three inline stanzas fell through to.
///
/// # Env-var lock discipline
///
/// Does NOT acquire [`GIT_BIN_ENV_LOCK`] internally — `std::sync::Mutex`
/// is not re-entrant, and the three consumer sites all sit inside
/// test bodies where the surrounding scope may already hold the
/// lock (e.g. `cli/src/git.rs::tests::test_commit_and_push_in_lands_commit_on_origin`
/// holds it across the whole test body). Callers running under
/// concurrent shim tests MUST hold the lock across the call so a
/// concurrently-running shim test cannot mutate `GIT_BIN` between
/// the `git clone` and the `git log` spawns; the two consumers
/// that pre-lift ran without the lock
/// (`commands/product_release.rs`, `commands/release_commit.rs`)
/// acquire the lock around this call as part of the migration,
/// closing a pre-existing race hole in each.
pub fn clone_bare_and_read_head_subject(bare_dir: &Path, probe_dir: &Path) -> String {
    let clone = git_command_sync()
        .args([
            "clone",
            bare_dir.to_str().expect("bare path utf-8"),
            probe_dir.to_str().expect("probe path utf-8"),
        ])
        .status()
        .expect("git clone spawn");
    assert!(
        clone.success(),
        "git clone {bare_dir:?} -> {probe_dir:?} must succeed"
    );
    read_head_subject(probe_dir)
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

/// Assert the given `source` — typically a module's own body pulled in
/// via [`include_str!`] — contains none of the three canonical
/// bare-literal spawn shapes [`forbidden_spawn_shapes`] returns for
/// `bare`, panicking on the first offending substring with a
/// shape-specific remediation message.
///
/// - `module_path` names the module in the panic prose (e.g.
///   `"commands/gem.rs"` or `"cli/src/test_support.rs"`); every
///   caller passes the same string spelling its own shield already
///   used, so the migration is prose-identical to the pre-lift assert
///   text.
/// - `bare` is the tool basename the shield forbids as a raw
///   spawn-literal (e.g. `"gem"`, `"terraform"`, `"rover-fhs"`).
/// - `remediation` is the sigil-routing sentence the whole-module
///   shield exists to enforce, e.g.
///   `"resolve `GEM_BIN` via `gem_bin()`"` or
///   `"resolve `GIT_BIN` via `crate::git::git_command_sync()`"`. It is
///   injected verbatim after `"must "` and before `" first."` in every
///   message — the shape a reader of a failing shield already expects
///   from the pre-lift wording.
///
/// # Why one canonical helper
///
/// Thirteen whole-module routing shields — one per simple-substring
/// tool surface across `cli/src/test_support.rs`,
/// `cli/src/commands/{attestation,federation,gem,pangea_infra,
/// prerelease,product_release,release_commit}.rs` — each spelled the
/// same three-`assert!(!SOURCE.contains(...))` block verbatim,
/// differing only in `module_path` / `bare` / the remediation
/// sentence. Thirteen occurrences × three assertions each = 39
/// verbatim `!source.contains(...)`-style call sites past THEORY §VI.1's
/// three-times threshold. This helper is the law-redeeming
/// consolidation: a future edit to the message wording (say adding a
/// `"see substrate mkRuntimeToolsEnv"` link, or refining the
/// hermetic-runner phrasing) lands in one place and propagates to
/// every shield; and a new shield added by a subsequent `_BIN`-routing
/// refactor inherits the message shape as one call, not fifteen lines
/// of boilerplate.
///
/// The two bespoke shields in `cli/src/git.rs` and
/// `cli/src/infrastructure/git.rs` that filter doc-comment lines out
/// of the substring scan quote the bare `Command::new(<bare-git-literal>)`
/// shape verbatim in their own docs (the pre-lift anti-pattern they
/// forbid) and therefore cannot use a naive
/// `SOURCE.contains(&raw_git)` predicate — they remain intentionally
/// bespoke. This module's own shield avoids quoting the shape
/// literally too: mentions are templated (`Command::new(<bare>)`) so
/// the whole-module scan does not false-match this helper's own
/// prose.
///
/// # Load-bearing message shape
///
/// The three panic messages preserve the exact pre-lift semantics — a
/// reader of a failing shield sees the same `<module> must not spawn
/// `<bare>` via the bare literal — every <bare> spawn must
/// <remediation> first. A raw literal at `<spawn shape>` bypasses the
/// hermetic-runner contract...` sentence they saw before the lift.
/// The shape-specific tail differs across the three assertions so a
/// reader can tell from the message which of the three forbidden
/// spawn shapes matched, not just that some shape did.
pub fn assert_source_forbids_bare_spawn_shapes(
    source: &str,
    module_path: &str,
    bare: &str,
    remediation: &str,
) {
    let [raw_std, raw_bare, raw_tokio] = forbidden_spawn_shapes(bare);

    // Order: prefixed shapes first (raw_std, raw_tokio), then the bare
    // alias last. raw_bare (`Command::new("<bare>")`) is a suffix of
    // both raw_std and raw_tokio — so checking raw_bare first would
    // fire on ANY source containing a prefixed shape and the
    // prefix-specific messages (`std::process::` / `tokio::process::`)
    // would be unreachable. Checking prefixed shapes first pins each
    // of the three shapes to its own most-specific message: a
    // std-prefixed literal panics with the std message, a
    // tokio-prefixed literal panics with the tokio message, and only
    // a pure bare `Command::new("<bare>")` panics with the bare-alias
    // message. Pinned by the three
    // `test_assert_source_forbids_bare_spawn_shapes_panics_on_*`
    // shape-specific tests below.
    assert!(
        !source.contains(&raw_std),
        "{module_path} must not spawn `{bare}` via the bare literal — \
         every {bare} spawn must {remediation} first. A raw literal at \
         `std::process::Command::new` bypasses the hermetic-runner \
         contract substrate's mkRuntimeToolsEnv exports."
    );
    assert!(
        !source.contains(&raw_tokio),
        "{module_path} must not spawn `{bare}` via the bare literal — \
         every {bare} spawn must {remediation} first. A raw literal at \
         `tokio::process::Command::new` bypasses the hermetic-runner \
         contract."
    );
    assert!(
        !source.contains(&raw_bare),
        "{module_path} must not spawn `{bare}` via the bare literal — \
         every {bare} spawn must {remediation} first. A raw literal at \
         `Command::new` (either the top-level `use` alias or the bare \
         form) bypasses the hermetic-runner contract."
    );
}

/// Sibling of [`assert_source_forbids_bare_spawn_shapes`] that filters
/// each of the three canonical bare-literal spawn shape scans through
/// [`code_line_hits`] instead of a raw `source.contains(...)` — so
/// docstrings and shield error-prose that quote the forbidden shape
/// verbatim do NOT trip the shield. Panics on the first shape whose
/// executable-code hits are non-empty, with a shape-specific
/// remediation message that also includes the offending
/// `"line <N>: <trimmed>"` entries.
///
/// # Why one canonical helper
///
/// Two whole-module git-spawn shields — `cli/src/git.rs` and
/// `cli/src/infrastructure/git.rs` — each spelled the same three
/// `let X_hits = code_line_hits(SOURCE, &raw_X); assert!(X_hits.is_empty(), "…{X_hits:?}")`
/// blocks verbatim, differing only in the module-path prefix and the
/// remediation phrase. Two occurrences × three assertions each = six
/// verbatim four-line stanzas past THEORY §VI.1's three-times threshold
/// ("two occurrences is a coincidence; three is a law"). The
/// pre-existing [`assert_source_forbids_bare_spawn_shapes`] cannot
/// serve these two shields: its raw `source.contains(...)` predicate
/// false-fires on the top-of-module docstrings both git modules carry
/// that quote the historical `Command::new(<bare-git-literal>)`
/// anti-pattern by literal quotation (documented in that helper's
/// `# Why one canonical helper` block, which explicitly carves both git
/// modules out as intentionally bespoke).
///
/// This helper closes that carve-out: it consumes the same
/// [`forbidden_spawn_shapes`] enumeration + the same `remediation`
/// slot as its sibling and adds one line of `code_line_hits` filtering
/// per shape, so the two bespoke shields lift onto one call while
/// their docstrings continue to live where they belong (near the
/// production sigil they document). Same docstring-self-match trap the
/// positive-side [`assert_source_has_canonical_two_arg_sigil_code_line`]
/// (ffa5271) and the negative-side
/// [`assert_source_forbids_deriving_one_arg_sigil_constant_form`] /
/// [`assert_source_forbids_deriving_one_arg_sigil_literal_form`]
/// (4163c7e) close for their respective form families, here closed for
/// the bare-literal spawn-shape family.
///
/// # Load-bearing message shape
///
/// The three panic messages preserve the exact pre-lift semantics — a
/// reader of a failing shield sees the same
/// `<module> must not spawn `<bare>` via the bare literal at
/// `<shape>` — every <bare> spawn must <remediation> first. A raw
/// literal bypasses the hermetic-runner contract. Offending code
/// lines: <hits>` sentence they saw before the lift. The
/// shape-specific fragment differs across the three assertions so a
/// reader can tell from the message which of the three forbidden
/// spawn shapes matched, not just that some shape did.
///
/// # Assertion order is load-bearing
///
/// The three checks fire in the order `std_hits`, `tokio_hits`,
/// `bare_hits` — prefixed shapes first, bare alias last. Same
/// discipline the naive [`assert_source_forbids_bare_spawn_shapes`]
/// sibling honors, and for the same reason: the bare-alias needle
/// `Command::new("<bare>")` is a suffix of both prefixed needles
/// (`std::process::Command::new(...)` and
/// `tokio::process::Command::new(...)`). Checking `bare_hits` first
/// would fire on ANY source containing a prefixed shape and the
/// prefix-specific messages (`std::process::` / `tokio::process::`)
/// would be unreachable. Checking prefixed shapes first pins each of
/// the three shapes to its own most-specific message. Pinned by the
/// three shape-specific `should_panic` tests below.
pub fn assert_source_forbids_bare_spawn_shapes_code_line(
    source: &str,
    module_path: &str,
    bare: &str,
    remediation: &str,
) {
    let [raw_std, raw_bare, raw_tokio] = forbidden_spawn_shapes(bare);

    let std_hits = code_line_hits(source, &raw_std);
    assert!(
        std_hits.is_empty(),
        "{module_path} must not spawn `{bare}` via the bare literal at \
         `std::process::Command::new` — every {bare} spawn must \
         {remediation} first. A raw literal bypasses the \
         hermetic-runner contract substrate's `mkRuntimeToolsEnv` \
         exports. Offending code lines: {std_hits:?}"
    );

    let tokio_hits = code_line_hits(source, &raw_tokio);
    assert!(
        tokio_hits.is_empty(),
        "{module_path} must not spawn `{bare}` via the bare literal at \
         `tokio::process::Command::new` — every async {bare} spawn must \
         {remediation} first. A raw literal bypasses the \
         hermetic-runner contract. Offending code lines: {tokio_hits:?}"
    );

    let bare_hits = code_line_hits(source, &raw_bare);
    assert!(
        bare_hits.is_empty(),
        "{module_path} must not spawn `{bare}` via the bare literal at \
         `Command::new` (top-of-file alias) — every {bare} spawn must \
         {remediation} first. A raw literal bypasses the \
         hermetic-runner contract. Offending code lines: {bare_hits:?}"
    );
}

/// Enumerate every 1-indexed *code* line in `source` that contains
/// `needle`, returned as `"line <N>: <trimmed line>"`. A "code" line is
/// one whose trimmed-left prefix is NOT a slash comment marker (`///`,
/// `//!`, or `//`) — so docstrings and prose comments that narrate the
/// anti-pattern the caller's shield forbids (by literally quoting the
/// forbidden form inside a `///` block or a shield error message) do
/// not register as violations. The shield fires only on executable
/// code.
///
/// # Why one canonical helper
///
/// Six whole-module routing shields — `cli/src/git.rs`,
/// `cli/src/infrastructure/git.rs`, and
/// `cli/src/commands/{dashboards,infra,local,prerelease}.rs` — each
/// spelled the SAME closure verbatim:
///
/// ```ignore
/// let is_code_line = |line: &str| -> bool {
///     let t = line.trim_start();
///     !t.starts_with("///") && !t.starts_with("//!") && !t.starts_with("//")
/// };
/// let hits: Vec<String> = SOURCE
///     .lines()
///     .enumerate()
///     .filter(|(_, l)| l.contains(&needle))
///     .filter(|(_, l)| is_code_line(l))
///     .map(|(i, l)| format!("line {}: {}", i + 1, l.trim()))
///     .collect();
/// ```
///
/// Six occurrences past THEORY.md §VI.1's three-times threshold ("two
/// occurrences is a coincidence; three is a law"). This helper is the
/// law-redeeming consolidation: a future edit to the code-line
/// predicate (say adding block-comment `/*` handling, or narrowing to
/// exclude `#[cfg(test)]` bodies) lands in one place and propagates to
/// every shield, and a new shield that needs the code-line-filtered
/// scan inherits the discipline as one call, not eight lines of
/// closure-plus-collect boilerplate.
///
/// # Why the doc-comment filter is load-bearing
///
/// Two of the six shielded modules (`cli/src/git.rs` and
/// `cli/src/infrastructure/git.rs`) carry pre-existing docstrings that
/// literally quote the historical bare-`Command::new(<tool>)`
/// anti-pattern — prose narrating the regression the shield exists to
/// catch. A naive `SOURCE.contains(needle)` would false-match those
/// docstrings and fire the shield on every run. Four of the six
/// (`local.rs`, `infra.rs`, `dashboards.rs`, `prerelease.rs`) forbid a
/// deriving one-arg sigil form (`crate::tools::get_tool_path(...)`)
/// that the shield's OWN error message quotes in the "use the two-arg
/// form instead" remediation prose — same self-match trap in a
/// different disguise. The `///` / `//!` / `//` prefix filter is the
/// single spelling that dodges both traps.
///
/// This module itself uses the templated form (`<tool>` in place of the
/// concrete bare basename) rather than a fused literal so the
/// whole-module shield at [`tests::test_git_spawn_routes_through_git_command_sync_not_raw_literal`]
/// — which rides the naive [`assert_source_forbids_bare_spawn_shapes`]
/// helper without a code-line filter — does not false-match this
/// helper's own docs.
///
/// # Substring-vs-line-scan semantics
///
/// This helper returns hits per LINE, not per substring: a line
/// containing `needle` twice contributes one entry. Every existing
/// caller consumes the returned vec via `is_empty()` for the
/// assertion decision and `{:?}` / `{:#?}` for the diagnostic
/// payload — neither cares about multiplicity, only presence.
///
/// # Why not fold the assertion in
///
/// The four `deriving-form-drift` sites and the two `git-spawn`
/// sites need different assertion messages (`code line — a
/// `<TOOL>_BIN`-literal audit would miss the site` vs `bare literal
/// at `std::process::Command::new` — every git spawn must resolve
/// `GIT_BIN`...`), and the git-spawn sites emit three distinct
/// messages against three needles. Extracting the collection
/// primitive without the assertion keeps each shield in control of
/// its own diagnostic prose while sharing the underlying scan.
pub fn code_line_hits(source: &str, needle: &str) -> Vec<String> {
    source
        .lines()
        .enumerate()
        .filter(|(_, l)| l.contains(needle))
        .filter(|(_, l)| {
            let t = l.trim_start();
            !t.starts_with("///") && !t.starts_with("//!") && !t.starts_with("//")
        })
        .map(|(i, l)| format!("line {}: {}", i + 1, l.trim()))
        .collect()
}

/// Reconstruct the canonical two-arg `crate::repo::get_tool_path` sigil
/// delegation needle at test time. Returns the string
/// `crate::repo::get_tool_path("<env_var>", "<bare>")` — the
/// audit-visible two-arg spelling every `<tool>_bin()` sigil across
/// forge routes through (unified by 23241a6 onto the shape
/// [`crate::repo::get_tool_path`] exports).
///
/// # Why one canonical needle-constructor
///
/// Five whole-module routing shields — `commands/local.rs`,
/// `commands/infra.rs`, `commands/dashboards.rs`, and two shields in
/// `commands/prerelease.rs` (docker + cargo) — each spelled the same
/// `format!` template verbatim, differing only in the substituted
/// `env_var` / `bare` tokens (three called `format!` with a
/// `_BIN`-baked template; two spelled the literal directly). Five
/// occurrences past THEORY.md §VI.1's three-times threshold ("two
/// occurrences is a coincidence; three is a law"). This helper is the
/// law-redeeming carve-out: a future edit to the canonical shape (a
/// rename of `crate::repo::get_tool_path` to
/// `crate::repo::tool_path_or_env`, a switch to a three-arg
/// override-with-log form, etc.) lands in one place and propagates to
/// every shield, and a new shield that needs the canonical needle
/// inherits the discipline as one call.
///
/// # Reconstruction discipline
///
/// The needle is built via `format!` — this helper's own source text
/// contains only the templated form (with `{}` placeholders for the
/// two-arg positions), never a substituted concrete literal. A shield
/// that scans `include_str!("test_support.rs")` therefore does not
/// false-match this helper's body on any concrete tool. Sibling
/// primitive to [`forbidden_spawn_shapes`], which enforces the same
/// discipline on the negative-side spawn-literal needles.
pub fn canonical_two_arg_sigil_needle(env_var: &str, bare: &str) -> String {
    format!("crate::repo::get_tool_path(\"{}\", \"{}\")", env_var, bare)
}

/// Assert the given `source` contains the canonical two-arg
/// `crate::repo::get_tool_path("<env_var>", "<bare>")` sigil delegation
/// form at at least one *code* line — i.e., outside docstrings and
/// prose comments. Panics with a diagnostic naming `module_path`,
/// `env_var`, `bare`, and the canonical form the shield exists to
/// enforce.
///
/// # Why the code-line filter is load-bearing
///
/// A naive `source.contains(&canonical)` positive assertion silently
/// passes whenever a docstring in the module quotes the canonical form
/// verbatim — a real regression class pre-existing in two shields on
/// `main` before this helper's introduction:
///
/// - `commands/dashboards.rs::jsonnet_bin_routing_tests` — the module
///   docs at `commands/dashboards.rs:720` quote
///   `crate::repo::get_tool_path("JSONNET_BIN", "jsonnet")` verbatim
///   inside a `///` block, so the pre-lift
///   `SOURCE.contains(&canonical)` shield always passed regardless of
///   whether the production sigil at `commands/dashboards.rs:46` was
///   intact.
/// - `commands/prerelease.rs::tests::test_cargo_spawn_routes_through_cargo_bin_not_raw_literal`
///   — the module docs at `commands/prerelease.rs:1840` quote
///   `crate::repo::get_tool_path("CARGO", "cargo")` verbatim inside a
///   `///` block, so a regression at `commands/prerelease.rs:110`
///   silently passed the pre-lift shield.
///
/// Filtering the positive assertion through [`code_line_hits`] closes
/// both defects with one primitive: only executable code satisfies the
/// shield, not narration.
///
/// # Why one canonical helper
///
/// Same five-occurrence three-times-rule justification as
/// [`canonical_two_arg_sigil_needle`] — the pre-lift assertion + panic
/// message pair was spelled with per-site prose variations that all
/// collapse to the same shape: "the `<bare>_bin()` sigil in
/// `<module_path>` must delegate to the canonical two-arg form; if the
/// form is not found in code, the substrate-exported `<env_var>`
/// env-var literal is again hidden from a fleet-wide `<env_var>` audit."
/// Consolidating the message here means a future edit to the
/// remediation prose (say, adding a link to `substrate/mkRuntimeToolsEnv`
/// or refining the audit-visibility phrasing) lands in one place.
pub fn assert_source_has_canonical_two_arg_sigil_code_line(
    source: &str,
    module_path: &str,
    env_var: &str,
    bare: &str,
) {
    let canonical = canonical_two_arg_sigil_needle(env_var, bare);
    let hits = code_line_hits(source, &canonical);
    assert!(
        !hits.is_empty(),
        "{module_path} must delegate `{bare}` via the canonical two-arg \
         `{canonical}` at a *code* line — the audit-visible two-arg \
         env-var-or-fallback lookup every sibling `<tool>_bin()` sigil \
         across forge honors (unified by 23241a6). Docstrings and shield \
         narrations mentioning the form are filtered out via `///` / \
         `//!` / `//` prefix, so a regression that dropped the \
         production sigil body while a docstring still quoted the \
         canonical form no longer silently passes. If the sigil \
         regressed to the deriving one-arg form, the substrate-exported \
         `{env_var}` env-var literal is again hidden from a fleet-wide \
         `{env_var}` audit."
    );
}

/// Reconstruct the constant-driven pre-lift deriving one-arg
/// `crate::tools::get_tool_path(crate::tools::tools::<constant_name>)`
/// form — the pre-lift shape three docker-related shields
/// (`commands/local.rs`, `commands/infra.rs`, `commands/prerelease.rs`)
/// forbid at a code line as of ffa5271. The `constant_name` slot names
/// the substrate's `crate::tools::tools::<CONST>` uppercase constant
/// registry entry (see `cli/src/tools.rs`).
///
/// # Reconstruction discipline
///
/// The needle is built via `format!` — this helper's own source text
/// contains only the templated form (with a `{}` placeholder for the
/// constant-name position), never a substituted concrete literal. A
/// shield that scans `include_str!("test_support.rs")` therefore does
/// not false-match this helper's body on any concrete tool. Sibling
/// primitive to [`canonical_two_arg_sigil_needle`] (the positive-side
/// form the sigils migrated ONTO) and to
/// [`deriving_one_arg_sigil_needle_literal`] (the other pre-lift
/// deriving variant).
pub fn deriving_one_arg_sigil_needle_constant(constant_name: &str) -> String {
    format!(
        "crate::tools::get_tool_path(crate::tools::tools::{})",
        constant_name
    )
}

/// Reconstruct the literal-string pre-lift deriving one-arg
/// `crate::tools::get_tool_path("<bare>")` form — the pre-lift shape
/// the `commands/dashboards.rs::jsonnet_bin_routing_tests` shield
/// forbids at a code line as of ffa5271. Sibling to
/// [`deriving_one_arg_sigil_needle_constant`] and to
/// [`canonical_two_arg_sigil_needle`]; same `format!`-based
/// reconstruction discipline.
pub fn deriving_one_arg_sigil_needle_literal(bare: &str) -> String {
    format!("crate::tools::get_tool_path(\"{}\")", bare)
}

/// Assert the given `source` does NOT contain the constant-driven
/// pre-lift deriving one-arg
/// `crate::tools::get_tool_path(crate::tools::tools::<constant_name>)`
/// form at any *code* line — i.e., outside docstrings and shield
/// error messages narrating the anti-pattern. Panics with a diagnostic
/// naming `module_path`, `bare`, `env_var`, `constant_name`, the
/// code-line hits, and the canonical two-arg remediation.
///
/// # Why one canonical helper
///
/// The pre-lift shape was replicated verbatim across three shields
/// (`commands/local.rs`, `commands/infra.rs`, `commands/prerelease.rs`)
/// — well past THEORY §VI.1's three-times threshold. Each site
/// hand-spelled the `format!` needle constructor, a `code_line_hits`
/// call, and a fifteen-line panic-message stanza. Consolidating them
/// here means a future edit to the remediation prose (say, refining
/// the audit-visibility phrasing or naming the substrate-exported
/// env-var contract explicitly) lands in one place. Sibling to
/// [`assert_source_has_canonical_two_arg_sigil_code_line`] (positive
/// side) and to
/// [`assert_source_forbids_deriving_one_arg_sigil_literal_form`] (the
/// literal-string variant).
///
/// # Why the code-line filter is load-bearing
///
/// The three docker shields all carry a top-of-module docstring that
/// narrates the anti-pattern verbatim inside `///` blocks (e.g.,
/// `commands/local.rs:23`, `commands/infra.rs:23`, `commands/prerelease.rs:66`).
/// A naive `source.contains(&deriving)` shield would panic on the
/// docstring itself, forcing every shield to author around the
/// docstring or drop the narration. Filtering through [`code_line_hits`]
/// lets the docstring live where it belongs (near the sigil it
/// documents) while the shield tracks only real code-line regressions.
pub fn assert_source_forbids_deriving_one_arg_sigil_constant_form(
    source: &str,
    module_path: &str,
    env_var: &str,
    bare: &str,
    constant_name: &str,
) {
    let deriving = deriving_one_arg_sigil_needle_constant(constant_name);
    let hits = code_line_hits(source, &deriving);
    assert!(
        hits.is_empty(),
        "{module_path} must not resolve `{bare}` via the pre-lift \
         deriving one-arg constant-driven form at any code line — a \
         `{env_var}`-literal audit would miss the site. Use the two-arg \
         `crate::repo::get_tool_path(\"{env_var}\", \"{bare}\")` form \
         the sibling sigils honor. Code-line hits: {hits:#?}"
    );
}

/// Assert the given `source` does NOT contain the literal-string
/// pre-lift deriving one-arg `crate::tools::get_tool_path("<bare>")`
/// form at any *code* line. Sibling to
/// [`assert_source_forbids_deriving_one_arg_sigil_constant_form`]; same
/// docstring-filter rationale and same canonical two-arg remediation.
pub fn assert_source_forbids_deriving_one_arg_sigil_literal_form(
    source: &str,
    module_path: &str,
    env_var: &str,
    bare: &str,
) {
    let deriving = deriving_one_arg_sigil_needle_literal(bare);
    let hits = code_line_hits(source, &deriving);
    assert!(
        hits.is_empty(),
        "{module_path} must not resolve `{bare}` via the pre-lift \
         deriving one-arg literal-string form at any code line — a \
         `{env_var}`-literal audit would miss the site. Use the two-arg \
         `crate::repo::get_tool_path(\"{env_var}\", \"{bare}\")` form \
         the sibling sigils honor. Code-line hits: {hits:#?}"
    );
}

/// Reconstruct the suffix-form canonical two-arg
/// `get_tool_path("<env_var>", "<bare>")` call needle — the shape every
/// downstream consumer-site sigil call across forge routes through,
/// spelled either fully-qualified (`crate::repo::get_tool_path(...)`)
/// or via a top-of-file `use crate::repo::get_tool_path;` import
/// (`get_tool_path(...)` alone). This needle is the shorter suffix of
/// [`canonical_two_arg_sigil_needle`]'s output, so a substring scan
/// against it catches BOTH spellings — the shape the eleven consumer
/// sigil shields already assert on.
///
/// # Reconstruction discipline
///
/// The needle is built via `format!` — this helper's own source text
/// contains only the templated form (with `{}` placeholders for the
/// two-arg positions), never a substituted concrete literal. A shield
/// that scans `include_str!("test_support.rs")` therefore does not
/// false-match this helper's body on any concrete tool. Sibling
/// primitive to [`canonical_two_arg_sigil_needle`] (the fully-qualified
/// variant used by the five sigil-body shields).
pub fn get_tool_path_two_arg_call_needle(env_var: &str, bare: &str) -> String {
    format!("get_tool_path(\"{}\", \"{}\")", env_var, bare)
}

/// Assert the given `source` contains the canonical two-arg
/// `get_tool_path("<env_var>", "<bare>")` call form at at least one
/// *code* line — i.e., outside `///` / `//!` / `//` comments. Panics
/// with a diagnostic naming `module_path`, `env_var`, `bare`, and the
/// canonical form.
///
/// # Why one canonical helper
///
/// Eleven whole-module consumer-sigil shields across eight files
/// (`infrastructure/registry.rs`, `commands/{tool,typescript,sync,
/// integration_tests,search_sync,pangea,web_service}.rs`) each spelled
/// the same `assert!(SOURCE.contains("get_tool_path(\"<BIN>\", \"<bare>\")"),
/// "…")` block verbatim, differing only in the substituted
/// `env_var` / `bare` tokens and per-site remediation prose. Eleven
/// occurrences past THEORY §VI.1's three-times threshold ("two
/// occurrences is a coincidence; three is a law"). This helper is the
/// law-redeeming consolidation: a future edit to the remediation prose
/// (say, refining the audit-visibility phrasing or naming the
/// substrate-exported env-var contract explicitly) lands in one place
/// and propagates to every shield; and a new shield added by a
/// subsequent `_BIN`-routing refactor inherits the discipline as one
/// call, not the six-line stanza.
///
/// # Why the code-line filter is load-bearing
///
/// Five of the eleven pre-lift sites carry docstrings or `//`
/// line-comments that literally quote the canonical
/// `get_tool_path("<BIN>", "<bare>")` form (e.g. `commands/sync.rs:157,516,638,667`,
/// `commands/tool.rs:358,913`, `commands/pangea.rs:801-802`,
/// `commands/search_sync.rs:95,359`, `commands/typescript.rs:60`).
/// A naive `SOURCE.contains(&needle)` shield silently passes on
/// production regression whenever any such doc-line quotes the form —
/// deleting the production sigil call still leaves the doc-line's
/// bytes intact and the shield reports green. Filtering through
/// [`code_line_hits`] closes that class: only executable code
/// satisfies the shield, not narration. This is the same
/// docstring-self-match defect [`assert_source_has_canonical_two_arg_sigil_code_line`]
/// closes for the sibling sigil-body shields.
///
/// # Why a distinct helper from `assert_source_has_canonical_two_arg_sigil_code_line`
///
/// The sibling `_canonical_two_arg_sigil_` helper's needle is the
/// fully-qualified `crate::repo::get_tool_path("<BIN>", "<bare>")`
/// form — the shape the five sigil-body definitions
/// (`commands/{local,infra,dashboards,prerelease}.rs`, plus the second
/// `prerelease.rs` shield) spell verbatim. The eleven consumer sites
/// resolved through this helper instead call via a `use`-imported
/// unqualified `get_tool_path("<BIN>", "<bare>")`, so the qualified
/// needle would fail to match — the shorter suffix needle is required
/// to catch both spellings.
pub fn assert_source_has_get_tool_path_two_arg_call_code_line(
    source: &str,
    module_path: &str,
    env_var: &str,
    bare: &str,
) {
    let needle = get_tool_path_two_arg_call_needle(env_var, bare);
    let hits = code_line_hits(source, &needle);
    assert!(
        !hits.is_empty(),
        "{module_path} must resolve `{bare}` via the canonical two-arg \
         `{needle}` call at a *code* line — either the fully-qualified \
         `crate::repo::get_tool_path` form or the \
         `use crate::repo::get_tool_path;`-imported unqualified form \
         satisfies the shield, but a docstring-only match does not. \
         If the sigil regressed to a bare-literal spawn or a \
         wrong-env-var lookup, the substrate-exported `{env_var}` \
         env-var literal is again hidden from a fleet-wide `{env_var}` \
         audit."
    );
}

/// Reconstruct the audit-visible sigil-definition signature
/// `fn <tool_bin_name>()` — the shape every per-module `<tool>_bin()`
/// sigil across forge presents at its definition site. Returns the
/// string `fn <tool_bin_name>()`.
///
/// # Reconstruction discipline
///
/// The needle is built via `format!` — this helper's own source text
/// carries only the templated form (with a `{}` placeholder for the
/// sigil-name position), never a substituted concrete literal. A
/// shield that scans `include_str!("test_support.rs")` therefore does
/// not false-match this helper's body on any concrete sigil. Sibling
/// primitive to [`canonical_two_arg_sigil_needle`],
/// [`deriving_one_arg_sigil_needle_constant`],
/// [`deriving_one_arg_sigil_needle_literal`], and
/// [`get_tool_path_two_arg_call_needle`] — all four honor the same
/// `format!`-based self-match discipline.
pub fn sigil_bin_fn_definition_needle(tool_bin_name: &str) -> String {
    format!("fn {}()", tool_bin_name)
}

/// Assert the given `source` defines the per-module sigil function
/// `fn <tool_bin_name>()` at at least one *code* line — i.e., outside
/// `///` / `//!` / `//` comments. Panics with a diagnostic naming
/// `module_path`, `tool_bin_name`, `env_var`, and `bare`.
///
/// # Why one canonical helper
///
/// Fifteen whole-module routing shields — `commands/{local,helm,infra,
/// gem (×2),pangea_infra (×3),rebac_validation,attestation,dashboards,
/// workspace_deps,prerelease (×2),federation}.rs` — each spelled the
/// same `assert!(SOURCE.contains("fn <tool>_bin()"), "commands/X.rs
/// must define `<tool>_bin()` — the sigil function that resolves the
/// [tools-registry ]`<ENV>` override for every <bare> spawn.")` block
/// verbatim, differing only in the substituted `tool_bin_name` /
/// `env_var` / `bare` tokens plus incidental prose variance (a
/// "tools-registry" prefix present at some sites, absent at others).
/// Fifteen occurrences past THEORY.md §VI.1's three-times threshold
/// ("two occurrences is a coincidence; three is a law"). This helper
/// is the law-redeeming consolidation: a future edit to the
/// remediation prose lands in one place and propagates to every
/// shield, and a new shield added by a subsequent `_BIN`-routing
/// refactor inherits the discipline as one call rather than the
/// six-line stanza.
///
/// # Why the code-line filter is load-bearing
///
/// A naive `SOURCE.contains("fn <tool>_bin()")` positive assertion
/// silently passes whenever a `///` docstring or sibling shield's
/// panic-message prose in the same module quotes the sigil signature
/// verbatim — the same docstring-self-match defect
/// [`assert_source_has_canonical_two_arg_sigil_code_line`] and
/// [`assert_source_has_get_tool_path_two_arg_call_code_line`] close
/// for the sibling sigil-body and consumer-call shields. Several of
/// the fifteen pre-lift sites carry docstrings that narrate the
/// sigil's role and quote `fn <tool>_bin()` verbatim (e.g.
/// `commands/prerelease.rs:1837`'s panic message quotes `cargo_bin()`;
/// the analogous shield-message and docstring quoting is pervasive
/// across the family). Deleting the production definition would leave
/// those bytes intact and the pre-lift shield would report green.
/// Filtering the positive assertion through [`code_line_hits`] closes
/// that class with one primitive.
pub fn assert_source_defines_sigil_bin_fn_code_line(
    source: &str,
    module_path: &str,
    tool_bin_name: &str,
    env_var: &str,
    bare: &str,
) {
    let needle = sigil_bin_fn_definition_needle(tool_bin_name);
    let hits = code_line_hits(source, &needle);
    assert!(
        !hits.is_empty(),
        "{module_path} must define `{tool_bin_name}()` at a code line \
         — the sigil function that resolves the `{env_var}` override \
         for every {bare} spawn. A docstring-only match no longer \
         satisfies the shield, so a regression that dropped the \
         production sigil definition while a docstring still quoted \
         the signature is caught here rather than passing silently."
    );
}

/// Reconstruct the canonical constructor-call needle
/// `<constructor_name>()` — the parenthesized call form every
/// per-module constructor-delegation shield asserts on. `constructor_name`
/// is the (usually short) function name — either the imported-alias short
/// form (e.g. `"git_command_sync"`) or the fully-qualified path (e.g.
/// `"crate::git::git_command_sync"`). Passing the short form matches BOTH
/// spellings via substring semantics: `git_command_sync()` is a suffix of
/// `crate::git::git_command_sync()`, so a shield that scans for the short
/// needle catches production calls whether the module imports the
/// constructor at the top (call site `git_command_sync()`) or spells the
/// path in full at each site (`crate::git::git_command_sync()`).
///
/// # Reconstruction discipline
///
/// The needle is built via `format!` — this helper's own source text
/// carries only the templated form (with a `{}` placeholder for the
/// constructor-name position), never a substituted concrete literal. A
/// shield that scans `include_str!("test_support.rs")` therefore does
/// not false-match this helper's body on any concrete constructor.
/// Sibling primitive to [`canonical_two_arg_sigil_needle`],
/// [`deriving_one_arg_sigil_needle_constant`],
/// [`deriving_one_arg_sigil_needle_literal`],
/// [`get_tool_path_two_arg_call_needle`], and
/// [`sigil_bin_fn_definition_needle`] — all six honor the same
/// `format!`-based self-match discipline.
pub fn constructor_call_needle(constructor_name: &str) -> String {
    format!("{}()", constructor_name)
}

/// Assert the given `source` calls the canonical `<constructor_name>()`
/// constructor at at least one *code* line — i.e., outside `///` /
/// `//!` / `//` comments. Panics with a diagnostic naming `module_path`,
/// `bare`, and the canonical constructor call form.
///
/// # Why one canonical helper
///
/// Eight whole-module shields across seven files spelled the same
/// `assert!(SOURCE.contains("<constructor>[()]"), "<module>.rs must
/// resolve the `<bare>` binary via the canonical `<constructor>()`
/// constructor — the required form was not found in the module.[ A
/// regression here would silently downgrade to the PATH fallback.]")`
/// block verbatim, differing only in the substituted
/// `constructor_name` / `bare` / `module_path` tokens plus a
/// "A regression here would silently downgrade to the PATH fallback."
/// tail present on the four `crate::git::git_command_sync` sites
/// (`commands/release_commit.rs`, `commands/product_release.rs`,
/// `commands/attestation.rs`, `cli/src/test_support.rs`) and absent on
/// the four `kubectl_command_async()` sites (`commands/rust_service.rs`,
/// `commands/integration_tests.rs`, `commands/rollout.rs`,
/// `commands/search_sync.rs`). Eight occurrences past THEORY.md §VI.1's
/// three-times threshold ("two occurrences is a coincidence; three is a
/// law"). This helper is the law-redeeming consolidation: a future edit
/// to the remediation prose lands in one place and propagates to every
/// shield, and a new shield added by a subsequent constructor-family
/// refactor inherits the discipline as one call rather than the
/// six-line stanza. The consolidated message unconditionally carries
/// the PATH-fallback tail — the same substrate concern applies to every
/// constructor-delegation shield (a bypass falls back to `PATH`
/// regardless of which constructor was skipped), so promoting the more
/// informative tail to the canonical is a strict enrichment of the
/// pre-lift `kubectl_command_async` variants.
///
/// # Why the code-line filter is load-bearing
///
/// A naive `SOURCE.contains(...)` positive assertion silently passes
/// whenever the constructor's short name appears in the module's
/// docstrings, `use` imports, or sibling shield error-prose. This is a
/// real regression class pre-existing in three of the four
/// `crate::git::git_command_sync` shields on `main` before this
/// helper's introduction: each scanned for the fully-qualified name
/// WITHOUT parens (`SOURCE.contains("crate::git::git_command_sync")`),
/// which matches the module's `use crate::git::git_command_sync;`
/// import line and every docstring quoting the path — deleting every
/// production call would still leave the shield green as long as the
/// `use` import survived. The parenthesized short-name needle
/// (`git_command_sync()`) matches only actual call sites (whether
/// imported-alias short-form or fully-qualified) and the code-line
/// filter suppresses docstring and prose mentions inside `///` blocks.
///
/// # Known false-match residue
///
/// The code-line filter suppresses `///` / `//!` / `//` doc comments
/// but does NOT suppress needle mentions embedded in string literals on
/// code lines. Two of the four `git_command_sync` shields' sibling
/// [`assert_source_forbids_bare_spawn_shapes`] calls pass a
/// `remediation` argument that quotes `crate::git::git_command_sync()`
/// verbatim as prose (e.g.
/// `"resolve `GIT_BIN` via `crate::git::git_command_sync()`"`). That
/// argument's code line contains the parenthesized needle as a
/// substring and counts as a hit. The shield therefore cannot
/// distinguish "production has real calls" from "sibling shield's
/// remediation-prose quotes the call" — a regression that dropped
/// every production call would still see the sibling-shield line as a
/// hit and silently pass. The pre-lift naive shield was strictly worse
/// (matched every docstring and the `use` import too), so this
/// consolidation is a net improvement, but the sibling-remediation
/// false-match survives and is worth naming here so a future refactor
/// that closes it — either by rephrasing the sibling remediations
/// without parens, or by adding a string-literal-line filter — knows
/// what it's closing.
pub fn assert_source_delegates_via_constructor_call_code_line(
    source: &str,
    module_path: &str,
    bare: &str,
    constructor_name: &str,
) {
    let needle = constructor_call_needle(constructor_name);
    let hits = code_line_hits(source, &needle);
    assert!(
        !hits.is_empty(),
        "{module_path} must resolve the `{bare}` binary via the canonical \
         `{needle}` constructor call at a *code* line — the required call \
         form was not found in the module. A regression here would silently \
         downgrade to the PATH fallback."
    );
}

/// Reconstruct the canonical `which::which("<bare>")` in-process probe
/// call needle — the shape three sibling shields
/// (`commands/search_sync.rs`, `commands/e2e.rs`, `commands/sync.rs`)
/// assert on to certify that the module's PATH-probe surface reads
/// through the `which` crate rather than a subprocess `Command::new`
/// spawn (the pre-a46d580 / pre-671f2e2 anti-pattern the two `async` /
/// `sync` families lifted onto the in-process crate idiom).
///
/// # Reconstruction discipline
///
/// The needle is built via `format!` — this helper's own source text
/// contains only the templated form (with a `{}` placeholder for the
/// bare-tool position), never a substituted concrete literal. A shield
/// that scans `include_str!("test_support.rs")` therefore does not
/// false-match this helper's body on any concrete tool. Sibling primitive
/// to [`canonical_two_arg_sigil_needle`] / [`constructor_call_needle`] /
/// [`sigil_bin_fn_definition_needle`] / [`get_tool_path_two_arg_call_needle`]
/// and to [`deriving_one_arg_sigil_needle_constant`] /
/// [`deriving_one_arg_sigil_needle_literal`]; same `format!`-based
/// self-match discipline.
pub fn which_which_probe_needle(bare: &str) -> String {
    format!("which::which(\"{}\")", bare)
}

/// Assert the given `source` probes for the `<bare>` binary via the
/// canonical `which::which("<bare>")` in-process crate idiom at at
/// least one *code* line — i.e., outside `///` / `//!` / `//` comments.
/// Panics with a diagnostic naming `module_path`, `bare`, and the
/// canonical probe form.
///
/// # Why one canonical helper
///
/// Three whole-module shields across three files
/// (`commands/search_sync.rs::test_which_probe_routes_through_which_crate_not_command_spawn`,
/// `commands/e2e.rs::test_which_probes_route_through_which_crate_not_command_spawn`,
/// `commands/sync.rs::test_which_probe_routes_through_which_crate_not_command_spawn`)
/// spelled the same
/// `assert!(SOURCE.contains("which::which(\"<bare>\")"), "<module>.rs
/// must probe the `<bare>` binary via the canonical
/// `which::which(\"<bare>\")` crate call — the required form was not
/// found in the module.")` block verbatim, differing only in the
/// substituted `bare` / `module_path` tokens. Three occurrences at
/// THEORY.md §VI.1's three-times threshold ("two occurrences is a
/// coincidence; three is a law"). This helper is the law-redeeming
/// consolidation: a future edit to the remediation prose lands in one
/// place and propagates to every shield, and a new probe-family shield
/// added by a subsequent lift onto the `which` crate idiom inherits
/// the discipline as one call.
///
/// # Why the code-line filter is load-bearing
///
/// A naive `SOURCE.contains(...)` positive assertion silently passes
/// whenever the concrete needle appears in the module's docstrings or
/// its own shield panic-message prose. This is a real regression class
/// pre-existing in all three shields on `main` before this helper's
/// introduction: each module's shield-adjacent docstring quotes the
/// paraphrased `which::which(...)` form, but each shield's own panic
/// message quotes the CONCRETE `which::which("<bare>")` inline as
/// remediation (e.g. `commands/search_sync.rs:426`,
/// `commands/e2e.rs:1305`, `commands/sync.rs:734`), AND
/// `commands/e2e.rs`'s docstring at `commands/e2e.rs:1289` also quotes
/// the concrete `which::which("docker")` verbatim. Deleting every
/// production probe call (`commands/search_sync.rs:89`,
/// `commands/e2e.rs:671` / `commands/e2e.rs:976`,
/// `commands/sync.rs:510`) would still leave the pre-lift shield green
/// as long as those docstring or panic-message bytes survived.
///
/// Filtering through [`code_line_hits`] suppresses the `///` docstring
/// mentions so only executable code satisfies the shield; the migrated
/// panic-message text lives at one point of truth here in
/// `test_support.rs` (templated via `{needle}`) so the caller's file
/// contains only real probe sites, not the message prose. Same
/// docstring-self-match defect the code-line-filtered sigil-body /
/// sigil-definition / consumer-call / constructor-delegation helper
/// families close for their respective form families — here closed for
/// the in-process `which::which` probe form family.
pub fn assert_source_probes_via_which_which_code_line(source: &str, module_path: &str, bare: &str) {
    let needle = which_which_probe_needle(bare);
    let hits = code_line_hits(source, &needle);
    assert!(
        !hits.is_empty(),
        "{module_path} must probe the `{bare}` binary via the canonical \
         `{needle}` in-process crate call at a *code* line — the required \
         call form was not found in the module. A regression here would \
         silently downgrade to a subprocess `Command::new(\"{bare}\")` \
         spawn, bypassing the in-process probe discipline and re-adding \
         a fork+exec on the module's PATH-lookup surface."
    );
}

/// One canonical composition for a whole-module `<tool>_bin()` sigil
/// shield. Fuses three primitives so a shield reads as a one-line
/// delegation instead of a three-call stanza — the shape twelve
/// production shields carried verbatim as of `fd2f96f`.
///
/// # What it enforces
///
/// - **No bare `<bare>`-literal spawn at any of the three canonical
///   shapes** — via [`assert_source_forbids_bare_spawn_shapes`] with
///   the canonical remediation `"resolve \`<env_var>\` via
///   \`<sigil_fn>()\`"`.
/// - **The `<sigil_fn>()` definition lives at a code line** — via
///   [`assert_source_defines_sigil_bin_fn_code_line`]. A docstring
///   quoting the signature does not satisfy the shield.
/// - **The sigil delegates via the canonical two-arg form** at a code
///   line — via [`assert_source_has_canonical_two_arg_sigil_code_line`].
///   The deriving one-arg form the DOCA bug closed is not asserted
///   here; callers that also forbid it chain
///   [`assert_source_forbids_deriving_one_arg_sigil_constant_form`] or
///   [`assert_source_forbids_deriving_one_arg_sigil_literal_form`]
///   after this composed call.
///
/// # Derived tokens
///
/// - `sigil_fn = <bare>.replace('-', '_') + "_bin"` — the fleet's
///   universal `<tool>_bin()` naming convention, matching the
///   dash→underscore canonicalization the underlying
///   [`crate::tools::get_tool_path`] primitive already applies at the
///   env-var surface (`POSTGRES-BOOTSTRAP_BIN` is not a legal POSIX
///   env-var name, so `postgres-bootstrap` → `postgres_bootstrap_bin`
///   is the shell-safe form the fleet already spells at every
///   dash-bearing sigil, e.g. `rover_fhs_bin`, `redis_cli_bin`,
///   `docker_compose_bin`).
/// - `remediation = format!("resolve `{env_var}` via `{sigil_fn}()`")`
///   — the phrasing every migrated shield's `bare_spawn_shapes`
///   remediation slot uses verbatim across the family. Callers whose
///   remediation prose reads differently (e.g., `commands/local.rs`'s
///   `"resolve the substrate-exported \`DOCKER_BIN\` env override via
///   \`docker_bin()\`"`) call [`assert_source_forbids_bare_spawn_shapes`]
///   directly with their bespoke sentence.
///
/// # Why one canonical helper
///
/// The three-call sequence appears at twelve whole-module shield sites
/// across the crate as of `fd2f96f`:
///
/// - `commands/gem.rs` — `gem`, `bundle`
/// - `commands/pangea_infra.rs` — `terraform`, `bundle`, `inspec`
/// - `commands/federation.rs` — `rover-fhs`
/// - `commands/prerelease.rs` — `cargo`, `docker` (docker chains the
///   deriving-form refusal after the composed call)
/// - `commands/dashboards.rs` — `jsonnet` (chains the literal deriving
///   refusal)
/// - `commands/infra.rs` — `docker` (chains the constant deriving
///   refusal)
/// - `commands/local.rs` — `docker` (bespoke remediation prose;
///   opts out of this composed call and spells the three primitives
///   directly)
/// - `infrastructure/docker.rs` — `docker`
///
/// Twelve occurrences is 4× THEORY §VI.1's three-times-is-a-law
/// threshold ("two occurrences is a coincidence; three is a law").
/// This helper is the law-redeeming consolidation: a future edit to
/// the composition (say, adding a fourth invariant every sibling
/// shield inherits — a "the sigil imports the two-arg
/// `get_tool_path` short form" invariant, a per-spawn env-injection
/// hook, a telemetry sigil) lands in one place and propagates to
/// every shield. And a new `_BIN`-routing sigil added by a
/// subsequent refactor inherits the shield as one call rather than
/// the three-call stanza.
///
/// # Load-bearing invariants
///
/// The composition preserves every semantic property the three
/// pre-lift shield calls enforced individually — the helper delegates
/// to each primitive with the same arguments the pre-lift shield
/// passed. The order matches every migrated site's call order
/// (bare-literal refusal first, sigil-definition next, canonical
/// two-arg last), so a caller that migrated its stanza onto this
/// helper receives the same "which invariant fired first" diagnostic
/// experience as pre-lift.
pub fn assert_source_routes_bare_spawn_through_two_arg_sigil(
    source: &str,
    module_path: &str,
    bare: &str,
    env_var: &str,
) {
    let sigil_fn = format!("{}_bin", bare.replace('-', "_"));
    let remediation = format!("resolve `{env_var}` via `{sigil_fn}()`");
    assert_source_forbids_bare_spawn_shapes(source, module_path, bare, &remediation);
    assert_source_defines_sigil_bin_fn_code_line(source, module_path, &sigil_fn, env_var, bare);
    assert_source_has_canonical_two_arg_sigil_code_line(source, module_path, env_var, bare);
}

/// One canonical composition for a whole-module status-only-spawn shield
/// on the SYNC frontier: every `std::process::Command`-driven status-only
/// spawn in `source` MUST route through
/// [`crate::retry::run_inherited_status_sync`], never through a hand-rolled
/// `.status()` builder-terminator that drops the exit code from the
/// operator log line.
///
/// # Arguments
///
/// - `source` — the whole module source (typically
///   `include_str!("<module>.rs")`).
/// - `module_path` — canonical repo-relative path used in panic messages
///   (e.g. `"commands/crossplane.rs"`).
/// - `min_delegations` — the ≥-floor on the SUM of
///   `run_inherited_status_sync(` (direct primitive) and
///   `run_bin_args_inherited_status_sync(` (the `(bin, args)`-front
///   wrapper introduced alongside the async sibling
///   `run_bin_args_inherited_status`) code-line hits in the module
///   body. Both forms route through the same
///   [`crate::retry::classify_inherited_status`] body, so either counts
///   as a valid delegation. The lower bound reflects the number of
///   status-only spawn sites the caller's `execute` /
///   command-entry surface currently exposes, so a regression that
///   drops even one delegation (in EITHER form) cannot leave the
///   negative `.status()` scan trivially satisfied by absence.
/// - `spawns_description` — human-readable name of WHICH spawns the
///   shield covers (e.g. `"all six status-only spawns
///   (`test`/`plan`/`apply`/`verify`/`destroy`/`status`)"`), so the
///   delegation-count assertion carries the same specificity a
///   hand-rolled shield does.
///
/// # What it enforces
///
/// The helper computes `body = &source[..cutoff]` where `cutoff` is the
/// FIRST `\n#[cfg(test)]\n` marker in `source` (which lands at the top
/// of the primary test block), then:
///
/// - `code_line_hits(body, ".status()")` MUST be empty. Any code-line
///   hit is an inline `.status()` builder-terminator that bypasses the
///   primitive and silently drops the exit code from the failure
///   envelope. Docstring / `//`-comment mentions of `.status()` are
///   filtered by [`code_line_hits`] so the shield's own prose above the
///   delegation call cannot false-match.
/// - `code_line_hits(body, "run_inherited_status_sync(").len() +
///   code_line_hits(body, "run_bin_args_inherited_status_sync(").len()
///   >= min_delegations`. A regression that deletes even one delegation
///   cannot leave the negative `.status()` scan trivially satisfied by
///   absence — the two halves are load-bearing together. The two
///   needles are DISJOINT as substrings: the wrapper form contains
///   `run_bin_args_inherited_status_sync(` while the direct form is
///   `run_inherited_status_sync(`, and neither is a substring of the
///   other (position 4 of the wrapper is `b`, not `i`), so summing
///   `code_line_hits` counts across both patterns never double-counts a
///   single call site.
///
/// # Why one canonical helper
///
/// The nine-line shield body appears verbatim across ten command
/// modules (`crossplane` 6cb9442, `e2e` 5faeecb, `gem` 9072905,
/// `image_release` b5d9573, `infra` 27896e4, `local` c2922fd,
/// `pangea_infra` a6e9b96, `rust_service` 5b5c765, `test_ci` a21bd67,
/// `tool` a3d51eb), differing only in `SOURCE`, `module_path`,
/// `min_delegations`, and `spawns_description`. Ten occurrences is
/// >3× THEORY.md §VI.1's three-times-is-a-law threshold ("two
/// occurrences is a coincidence; three is a law"); this helper is the
/// law-redeeming consolidation. A future refinement (say broadening
/// `.status()` to also flag a new terminator form, adding a third
/// `.stdout(Stdio::inherit())` cross-check, tightening the cutoff
/// discipline to require a specific marker, or attaching a structured
/// diagnostic hook) lands in ONE body and propagates to every consumer
/// by construction rather than being copy-edited at ten sites.
///
/// # Boundary marker
///
/// The `"\n#[cfg(test)]\n"` marker is the shortest form that reliably
/// identifies the top of the primary test block across every migrated
/// module (both the `#[cfg(test)]\nmod tests {` shape and the plain
/// `#[cfg(test)]` shape reduce to it). Modules with multiple
/// `#[cfg(test)]` blocks land the cutoff at the FIRST one (the primary
/// tests) — any production code AFTER the first test block would
/// escape the scan, so callers keep production code above the first
/// `#[cfg(test)]`.
pub fn assert_source_routes_status_only_spawns_through_run_inherited_status_sync(
    source: &str,
    module_path: &str,
    min_delegations: usize,
    spawns_description: &str,
) {
    let body = module_body_before_first_cfg_test(source, module_path);

    let inline = code_line_hits(body, ".status()");
    assert!(
        inline.is_empty(),
        "{module_path} must not spawn via an inline `.status()` \
         terminator — every status-only spawn must route through \
         `crate::retry::run_inherited_status_sync` (direct primitive) \
         or `crate::retry::run_bin_args_inherited_status_sync` (the \
         `(bin, args)`-front wrapper), which carry the exit code into \
         the failure envelope. Found: {inline:?}"
    );

    let direct = code_line_hits(body, "run_inherited_status_sync(").len();
    let wrapped = code_line_hits(body, "run_bin_args_inherited_status_sync(").len();
    let delegations = direct + wrapped;
    assert!(
        delegations >= min_delegations,
        "{module_path} must route {spawns_description} through \
         `run_inherited_status_sync` or \
         `run_bin_args_inherited_status_sync` — found only \
         {delegations} delegation call(s) (direct: {direct}, wrapped: \
         {wrapped}); a dropped call would leave the negative \
         `.status()` scan satisfied by absence"
    );
}

/// Async sibling of
/// [`assert_source_routes_status_only_spawns_through_run_inherited_status_sync`]:
/// every `tokio::process::Command`-driven status-only spawn in `source`
/// MUST route through [`crate::retry::run_inherited_status`] (the
/// direct primitive) OR
/// [`crate::retry::run_bin_args_inherited_status`] (the
/// `(bin, args)`-front wrapper), never through a hand-rolled
/// `.status().await` builder-terminator that drops the exit code from
/// the operator log line.
///
/// # Arguments
///
/// Same shape as the sync sibling. `spawns_description` names WHICH
/// async spawns the shield covers (e.g. `"the two `regenerate_compiler`
/// status-only spawn sites (`bundle lock --update` and `bundix`)"`).
/// `min_delegations` is the ≥-floor on the SUM of `run_inherited_status(`
/// and `run_bin_args_inherited_status(` code-line hits — both forms
/// route through the same [`crate::retry::classify_inherited_status`]
/// body, so either counts as a valid delegation.
///
/// # What it enforces
///
/// The helper computes `body = &source[..cutoff]` where `cutoff` is
/// the FIRST `\n#[cfg(test)]\n` marker in `source`, then:
///
/// - `code_line_hits(body, ".status().await")` MUST be empty. Any
///   code-line hit is an inline `.status().await` builder-terminator
///   that bypasses the primitive. The needle is `.status().await`
///   (not the sync `.status()`) so a legitimate sync `.status()`
///   consumer elsewhere in the module — should one ever land — does
///   not false-match this async shield.
/// - The sum `code_line_hits(body, "run_inherited_status(").len() +
///   code_line_hits(body, "run_bin_args_inherited_status(").len()`
///   must be at least `min_delegations`. A regression that deletes
///   even one delegation cannot leave the negative `.status().await`
///   scan trivially satisfied by absence — the two halves are
///   load-bearing together. The two needles are DISJOINT as
///   substrings: the wrapper form starts
///   `run_bin_args_inherited_status(` while the direct form is
///   `run_inherited_status(`, and neither is a substring of the
///   other (position 4 of the wrapper is `b`, not `i`), so summing
///   `code_line_hits` counts across both patterns never
///   double-counts a single call site. Both needles carry the
///   trailing `(` so neither matches its `_sync(`-suffixed sync
///   sibling — the async and sync frontiers count independently.
///
/// # Why one canonical helper
///
/// The nine-line shield body appears verbatim across three command
/// modules on the async spawn frontier (`build.rs` 72a7adf,
/// `pangea.rs` c5ff1c4, `product_release.rs` bf6d836) — past the
/// three-times-is-a-law threshold in its own right, and part of a
/// wider thirteen-shield family (10 sync + 3 async) with the sync
/// sibling above. Widening the count to sum both delegation forms
/// closes the async/sync algebra gap: pre-widening a
/// `run_inherited_status`→`run_bin_args_inherited_status` migration
/// at ANY of the three async consumers would have driven the count
/// to zero and fired the "delegation call(s)" arm even though the
/// wrapper delegates to the same
/// [`crate::retry::classify_inherited_status`] body — the same
/// composition trap the sync sibling closed by summing both forms.
/// A future refinement (structured diagnostic hook, broadened inline
/// needle, tighter cutoff) lands in one body per frontier rather
/// than at every site.
pub fn assert_source_routes_status_only_spawns_through_run_inherited_status(
    source: &str,
    module_path: &str,
    min_delegations: usize,
    spawns_description: &str,
) {
    let body = module_body_before_first_cfg_test(source, module_path);

    let inline = code_line_hits(body, ".status().await");
    assert!(
        inline.is_empty(),
        "{module_path} must not spawn via an inline `.status().await` \
         terminator — every async status-only spawn must route through \
         `crate::retry::run_inherited_status` (direct primitive) or \
         `crate::retry::run_bin_args_inherited_status` (the \
         `(bin, args)`-front wrapper), which carry the exit code into \
         the failure envelope. Found: {inline:?}"
    );

    let direct = code_line_hits(body, "run_inherited_status(").len();
    let wrapped = code_line_hits(body, "run_bin_args_inherited_status(").len();
    let delegations = direct + wrapped;
    assert!(
        delegations >= min_delegations,
        "{module_path} must route {spawns_description} through \
         `run_inherited_status` or `run_bin_args_inherited_status` — \
         found only {delegations} delegation call(s) (direct: \
         {direct}, wrapped: {wrapped}); a dropped call would leave \
         the negative `.status().await` scan satisfied by absence"
    );
}

/// Captured-output sibling of
/// [`assert_source_routes_status_only_spawns_through_run_inherited_status`]:
/// every `.output()[.await].context(…)?` + `if !output.status.success() {
/// bail!("<op> failed: {stderr}") }` bail-drops-exit-code stanza in
/// `body` MUST route through [`crate::retry::classify_capture_anyhow`],
/// which surfaces `(op, exit_code, stderr)` in ONE canonical envelope
/// rather than the per-site `(op, stderr)` dialect the pre-lift sites
/// each spelled.
///
/// # Arguments
///
/// - `body` — the source slice to scan. Callers slice with
///   [`fn_body_slice_between_markers`] (when the module has other
///   `output.status.success()` sites the shield must not false-match —
///   `commands/sync.rs` retains two control-flow-shape
///   `if !install_output.status.success()` / `if !codegen_output.status.success()`
///   sites in `check_drift`, and `commands/federation_tests.rs` retains
///   two `output.status.success()` matches in `wait_for_job_completion`
///   / `check_job_success`) or with [`module_body_before_tests`] /
///   the raw module `include_str!(...)` (when the migrated site is the
///   sole `output.status.success()` consumer in the module —
///   `commands/dashboards.rs`).
/// - `label` — a caller-supplied slug used in panic messages
///   (e.g. `"commands/sync.rs::generate_entities"`,
///   `"commands/dashboards.rs"`). Names the fn scope OR the module —
///   whichever the body slice actually covers — so a failing shield
///   points a reader at the exact scan window.
/// - `min_delegations` — minimum number of delegation call sites the
///   body MUST carry — summed across the four canonical entrypoints
///   `classify_capture_anyhow(` (the bare classifier over an already-
///   captured `Result<Output>`), `run_capture_anyhow(` (the async
///   run-wrapper), `run_capture_anyhow_sync(` (the sync run-
///   wrapper), and `kubectl_capture_anyhow(` (the
///   `kubectl_command_async()`-fronted async fusion primitive on
///   `infrastructure::kubectl` — a `run_capture_anyhow` composition
///   pre-bound to a KUBECTL_BIN-resolved constructor). All four route
///   through the ONE canonical `classify_capture_anyhow` body at
///   `retry.rs`, so any of the four satisfies "the captured-output
///   bail routes through the primitive" — a shield that only
///   recognized the bare classifier would refuse a migration that
///   spelled the higher-level run-wrapper (the canonical shape once
///   the run-* algebra closed at 06cd778), and one that only
///   recognized `run_capture_anyhow` would refuse a migration onto
///   the `kubectl_capture_anyhow` fusion primitive that lifts the
///   `kubectl_command_async() + args + run_capture_anyhow`
///   three-line stanza to one line at the two kubectl-fronted
///   control-flow-carrying capture sites
///   (`commands/flux.rs::get_pod_status_full` +
///   `commands/integration_tests.rs::fetch_secret`). A dropped
///   delegation would leave the negative
///   `if !output.status.success` scan satisfied by absence — pinning a
///   positive floor guards against that regression class.
///
/// # What it enforces
///
/// - `code_line_hits(body, "if !output.status.success")` MUST be
///   empty. The needle omits the trailing `()` so the shield catches
///   both `if !output.status.success()` (the exact pre-lift shape at
///   all three migrated sites) and any future variant that inserted a
///   whitespace or refactored the accessor chain — every such line is
///   a bail terminator that drops the exit code the primitive carries.
///   The needle deliberately does NOT scan for a bare
///   `output.status.success` (without the leading `if !`) because
///   several call-site siblings in the same modules legitimately
///   consume `output.status.success()` in a match arm or a
///   conditional-return that short-circuits into an alternative typed
///   result (`DriftCheckResult::error`, `WaitOutcome::Timeout`) rather
///   than a bail — precisely the shapes the shield MUST not false-match.
/// - The sum of `code_line_hits` for `classify_capture_anyhow(`,
///   `run_capture_anyhow(`, `run_capture_anyhow_sync(`, and
///   `kubectl_capture_anyhow(` MUST hit at least `min_delegations`
///   times. Pins the positive floor so a regression that both dropped
///   the delegation AND accidentally left the negative side satisfied
///   (e.g. by rewriting the bail into a `bail!("failed")` shape
///   without `if !output.status.success`) fails here. The four needles
///   are mutually exclusive on any code line — `classify_capture_anyhow`
///   does not contain `run_capture_anyhow` as a substring,
///   `run_capture_anyhow_sync(` does not contain `run_capture_anyhow(`
///   (the char after `run_capture_anyhow` is `_` not `(`), and
///   `kubectl_capture_anyhow(` shares no substring with either
///   `classify_capture_anyhow` or `run_capture_anyhow` (the `kubectl_`
///   prefix is disjoint), so summing without dedup is correct.
///
/// # Why one canonical helper
///
/// The eight-line shield body is spelled verbatim across the three
/// migrated consumer sites in this commit (`commands/dashboards.rs`,
/// `commands/sync.rs::generate_entities`,
/// `commands/federation_tests.rs::run_federation_tests`) — past THEORY
/// §VI.1's three-is-a-law threshold in its own right. A future
/// refinement (structured diagnostic hook, broadened inline needle,
/// tighter cutoff) lands in one body per frontier rather than at every
/// site — the same discipline
/// [`assert_source_routes_status_only_spawns_through_run_inherited_status`]
/// pins for the inherited-stdio sibling frontier.
pub fn assert_source_routes_captured_bails_through_classify_capture_anyhow(
    body: &str,
    label: &str,
    min_delegations: usize,
) {
    let inline = code_line_hits(body, "if !output.status.success");
    assert!(
        inline.is_empty(),
        "{label} must not carry an inline `if !output.status.success` \
         bail terminator — every captured-output bail-on-non-zero-exit \
         must route through `crate::retry::classify_capture_anyhow` \
         (or its higher-level run-wrappers `run_capture_anyhow` / \
         `run_capture_anyhow_sync`), which carry the exit code AND the \
         stderr into the canonical \
         `\"{{op}} failed (exit {{code}}): {{stderr}}\"` envelope. \
         Found: {inline:?}"
    );

    let via_classify = code_line_hits(body, "classify_capture_anyhow(").len();
    let via_run = code_line_hits(body, "run_capture_anyhow(").len();
    let via_run_sync = code_line_hits(body, "run_capture_anyhow_sync(").len();
    let via_kubectl = code_line_hits(body, "kubectl_capture_anyhow(").len();
    let delegations = via_classify + via_run + via_run_sync + via_kubectl;
    assert!(
        delegations >= min_delegations,
        "{label} must route captured-output bails through \
         `classify_capture_anyhow` (or `run_capture_anyhow` / \
         `run_capture_anyhow_sync` / `kubectl_capture_anyhow`) — \
         found only {delegations} delegation call(s) \
         (classify={via_classify}, run={via_run}, \
         run_sync={via_run_sync}, kubectl={via_kubectl}); a dropped \
         call would leave the negative `if !output.status.success` \
         scan satisfied by absence"
    );
}

/// One canonical composition for a whole-module `<bare>`-through-sigil
/// routing shield with the SOLITARY-RESOLVE invariant: every `<bare>`
/// spawn in `source` MUST route through the `<sigil>_bin()` sigil, AND
/// the two-argument `get_tool_path("<env_var>", "<bare>")` resolve MUST
/// appear at EXACTLY ONE place in the module body — the sigil body —
/// so a future added spawn cannot silently re-copy the resolve inline
/// and drift away from the sigil's single point of truth.
///
/// # Arguments
///
/// - `source` — the whole module source (typically
///   `include_str!("<module>.rs")`).
/// - `module_path` — canonical repo-relative path used in panic messages
///   (e.g. `"commands/test_ci.rs"`).
/// - `bare` — the tool basename the shield exists to route
///   (e.g. `"cargo"`, `"nix"`). Dash-bearing tool names are
///   canonicalized dash→underscore for the sigil-fn name.
/// - `env_var` — the tools-registry env-var name the sigil resolves
///   (e.g. `"CARGO"`, `"NIX_BIN"`).
///
/// # What it enforces
///
/// The helper computes `body = &source[..cutoff]` where `cutoff` is the
/// FIRST `\n#[cfg(test)]\n` marker in `source` (which lands at the top
/// of the primary test block), then asserts three invariants against
/// `body`:
///
/// - `!body.contains("Command::new(\"<bare>\")")` — no bare `Command`
///   spawn literal survives in the module body. The bare-literal
///   needle is reconstructed via [`format!`] at test time so this
///   helper's own source text contains only the templated form, never
///   a substituted concrete literal — a shield that scans
///   `include_str!("test_support.rs")` does not false-match this
///   helper's body on any concrete tool.
/// - `body.contains("fn <sigil>_bin()")` — the sigil function is
///   defined at some line in the module body. `sigil = bare` with
///   dashes canonicalized to underscores (matching the fleet's
///   universal `<tool>_bin()` naming: `docker_compose_bin`,
///   `rover_fhs_bin`, `redis_cli_bin` — see
///   [`assert_source_routes_bare_spawn_through_two_arg_sigil`]).
/// - `body.matches("get_tool_path(\"<env_var>\", \"<bare>\")").count()
///   == 1` — the two-argument resolve appears at EXACTLY one place in
///   the module body (only in the `<sigil>_bin()` sigil), so a future
///   added spawn cannot silently re-copy the resolve inline and drift
///   away from the sigil's single point of truth. The count-exactly-one
///   invariant is what distinguishes this shield from the at-least-one
///   sibling [`assert_source_routes_bare_spawn_through_two_arg_sigil`]:
///   the sigil's SOLE responsibility for spelling the resolve is
///   pinned by construction, not by review discipline.
///
/// # Why one canonical helper
///
/// The three-assertion block appears verbatim across five whole-module
/// sigil-routing shields as of commit `08fdb86`:
///
/// - `commands/test_ci.rs::test_test_ci_routes_cargo_through_cargo_bin_sigil_not_raw_command`
/// - `commands/developer_tools.rs::test_developer_tools_routes_nix_through_nix_bin_not_raw_command`
/// - `commands/developer_tools.rs::test_developer_tools_routes_cargo_through_cargo_env_not_raw_command`
/// - `commands/rust_service.rs::test_rust_service_routes_nix_through_nix_bin_not_raw_command`
/// - `commands/comprehensive_release.rs::test_comprehensive_release_routes_cargo_through_cargo_bin_sigil_not_raw_command`
///
/// Each site spelled the same body-cutoff + three-assertion stanza
/// verbatim, differing only in `source` / `module_path` / `bare` /
/// `env_var`. Five occurrences past THEORY.md §VI.1's three-times
/// threshold ("two occurrences is a coincidence; three is a law"), and
/// the shield's SOLITARY-RESOLVE invariant is a specific defect-class
/// the sibling [`assert_source_routes_bare_spawn_through_two_arg_sigil`]
/// does not close on its own — inline drift where a consumer re-copies
/// the resolve rather than routing through the sigil. This helper is
/// the law-redeeming consolidation: a future refinement (say tightening
/// the bare-spawn needle to also flag `std::process::` and
/// `tokio::process::` prefixed shapes, filtering the body scan through
/// [`code_line_hits`] to also drop production-body docstring quotes,
/// broadening the resolve needle to also match the fully-qualified
/// `crate::repo::get_tool_path` form) lands at ONE body and propagates
/// to every shield by construction rather than being copy-edited at
/// five sites.
///
/// # Boundary marker
///
/// The `"\n#[cfg(test)]\n"` marker is the shortest form that reliably
/// identifies the top of the primary test block across every migrated
/// module (both the `#[cfg(test)]\nmod tests {` shape and the plain
/// `#[cfg(test)]` shape — `commands/rust_service.rs` has five sibling
/// `#[cfg(test)] mod <name>_routing_tests` blocks — reduce to it).
/// Modules with multiple `#[cfg(test)]` blocks land the cutoff at the
/// FIRST one; any production code AFTER the first test block would
/// escape the scan, so callers keep production code above the first
/// `#[cfg(test)]`.
///
/// # Load-bearing invariant order
///
/// The three assertions fire in the order (bare-literal refusal,
/// sigil-definition, resolve-count-one) — the same order every migrated
/// site spelled pre-lift, so a reader of a failing shield sees the same
/// "which invariant fired first" diagnostic experience as pre-lift. A
/// missing-sigil failure surfaces AFTER a bare-literal failure (the
/// worse offense first), and a resolve-count-drift failure surfaces
/// LAST (the subtlest offense last, only reachable once the harder
/// invariants pass).
pub fn assert_source_routes_bare_spawn_through_sigil_bin_fn_at_exactly_one_resolve(
    source: &str,
    module_path: &str,
    bare: &str,
    env_var: &str,
) {
    let body = module_body_before_first_cfg_test(source, module_path);

    let sigil_fn = format!("{}_bin", bare.replace('-', "_"));

    let bare_spawn_needle = format!("Command::new(\"{bare}\")");
    assert!(
        !body.contains(&bare_spawn_needle),
        "{module_path} must not spawn `{bare}` via the bare literal — \
         every `{bare}` spawn must resolve `{env_var}` via the \
         `{sigil_fn}()` sigil first. A bare `Command::new(<{bare}>)` \
         bypasses the hermetic-runner contract substrate's \
         mkRuntimeToolsEnv exports."
    );

    let sigil_def_needle = format!("fn {sigil_fn}()");
    assert!(
        body.contains(&sigil_def_needle),
        "{module_path} must define `{sigil_fn}()` — the sigil function \
         that resolves the tools-registry `{env_var}` override for \
         every `{bare}` spawn."
    );

    let two_arg_needle = get_tool_path_two_arg_call_needle(env_var, bare);
    let resolve_count = body.matches(two_arg_needle.as_str()).count();
    assert_eq!(
        resolve_count, 1,
        "the two-argument resolve `{two_arg_needle}` must appear \
         exactly ONCE in the module body of {module_path} (only in the \
         `{sigil_fn}()` sigil), not {resolve_count} times — every \
         consumer must route through `{sigil_fn}()`, not re-copy the \
         resolve inline"
    );
}

/// Slice `source` at the top of its primary `#[cfg(test)] mod tests { … }`
/// block and return the module's non-test body — the shared shield-slice
/// primitive.
///
/// The cutoff is the FIRST occurrence of the specific
/// `"\n#[cfg(test)]\nmod tests {"` marker (a `#[cfg(test)]` attribute on
/// its own line, directly followed by `mod tests {` on the next line —
/// the shape every migrated shield module across `cli/src/commands`,
/// `cli/src/infrastructure`, and `cli/src/services` uses to introduce its
/// primary test block). `source` is typically the module's own
/// `include_str!("<file>.rs")`, and `module_path` is the canonical
/// repo-relative label (e.g. `"commands/status.rs"`) named in the panic
/// message if the marker is missing.
///
/// # Panics
///
/// If `source` does not contain `"\n#[cfg(test)]\nmod tests {"` — every
/// consumer shield's slice boundary relies on this module ordering. A
/// module without the marker cannot be sliced safely; the caller must
/// keep production code above the first `#[cfg(test)]\nmod tests {`
/// marker.
///
/// # Why one canonical helper
///
/// The seven-line stanza this helper condenses —
///
/// ```ignore
/// let tests_marker = "\n#[cfg(test)]\nmod tests {";
/// let body_end = source.find(tests_marker).expect(
///     "the `#[cfg(test)]\\nmod tests {` marker must follow \
///      the module body — the shield's slice boundary relies \
///      on this module ordering",
/// );
/// let module_body = &source[..body_end];
/// ```
///
/// — appears verbatim at 23 shield sites across `commands/status.rs`
/// (×8), `commands/flux.rs` (×2), `commands/federation_tests.rs` (×2),
/// `commands/supergraph_verification.rs` (×2), `commands/migrations.rs`
/// (×2), `commands/comprehensive_release.rs`, `commands/test.rs`,
/// `commands/integration_tests.rs`, `commands/seed.rs`,
/// `commands/sessions.rs`, `infrastructure/kubectl.rs`, and
/// `services/migration_service.rs`. Twenty-three occurrences is >7×
/// THEORY.md §VI.1's three-times-is-a-law threshold ("two occurrences
/// is a coincidence; three is a law"); this helper is the law-redeeming
/// consolidation. A future refinement (say attaching a byte-offset
/// return alongside the slice, tolerating a preceding `#[allow(...)]`
/// attribute, or attaching a structured diagnostic hook) lands in ONE
/// body and propagates to every shield by construction rather than
/// being copy-edited at 23 sites.
///
/// # Contrast with the shorter marker
///
/// The sibling helpers
/// [`assert_source_routes_status_only_spawns_through_run_inherited_status_sync`],
/// [`assert_source_routes_status_only_spawns_through_run_inherited_status`],
/// and
/// [`assert_source_routes_bare_spawn_through_sigil_bin_fn_at_exactly_one_resolve`]
/// slice at the strictly shorter marker `"\n#[cfg(test)]\n"` because
/// they intentionally cover both the `mod tests {` and plain
/// `#[cfg(test)]` block shapes. This helper deliberately keeps the more
/// specific `mod tests {`-suffixed marker to match the 23 pre-lift
/// callers verbatim, so a migration is a pure textual lift with zero
/// behaviour change at the slice boundary.
pub fn module_body_before_tests<'a>(source: &'a str, module_path: &str) -> &'a str {
    const MARKER: &str = "\n#[cfg(test)]\nmod tests {";
    let body_end = source.find(MARKER).unwrap_or_else(|| {
        panic!(
            "{module_path}: the `#[cfg(test)]\\nmod tests {{` marker \
             must follow the module body — the shield's slice boundary \
             relies on this module ordering"
        )
    });
    &source[..body_end]
}

/// Slice `source` at the top of the FIRST `#[cfg(test)]` block (of any
/// shape) and return the module's non-test body — the shorter-marker
/// sibling of [`module_body_before_tests`].
///
/// The cutoff is the FIRST occurrence of the strictly shorter marker
/// `"\n#[cfg(test)]\n"` — a `#[cfg(test)]` attribute on its own line,
/// followed by any line-terminator. Both the `#[cfg(test)]\nmod tests {`
/// shape (the discipline [`module_body_before_tests`] targets) and the
/// plain-`#[cfg(test)]\nmod <other-name>` / `#[cfg(test)]\nfn ...` shape
/// reduce to this shorter marker, so a module that carries MULTIPLE
/// `#[cfg(test)]` sub-blocks (a per-frontier `mod cargo_env_routing_tests
/// {}`, `mod docker_bin_routing_tests {}`, `mod resolve_repo_root_git_bin_routing_tests
/// {}` layout — the shape `commands/e2e.rs` and every sibling module
/// using per-frontier test buckets already carry) still has its
/// production body sliced at the FIRST attribute, which is where the
/// pre-lift `SOURCE.find("\n#[cfg(test)]\n").expect(...)` stanza already
/// bounded.
///
/// # Panics
///
/// If `source` does not contain `"\n#[cfg(test)]\n"` — every consumer
/// shield's slice boundary relies on this module ordering. A module
/// without the marker cannot be sliced safely; the caller must keep
/// production code above the first `#[cfg(test)]` block.
///
/// # Why one canonical helper
///
/// The five-line stanza this helper condenses —
///
/// ```ignore
/// let cutoff = SOURCE.find("\n#[cfg(test)]\n").expect(
///     "<file>.rs must have a `#[cfg(test)]` marker — \
///      the shield's scan boundary depends on it",
/// );
/// let body = &SOURCE[..cutoff];
/// ```
///
/// — appears verbatim at 15 shield sites across `test_support.rs`
/// itself (×3 — the three whole-module short-marker helpers), `nix.rs`
/// (×1), `commands/crossplane.rs` (×1), `commands/e2e.rs` (×5),
/// `commands/github_runner_ci.rs` (×1), `commands/nix_builder.rs` (×3),
/// and `commands/rust_service.rs` (×1). Fifteen occurrences is >5×
/// THEORY.md §VI.1's three-times-is-a-law threshold ("two occurrences
/// is a coincidence; three is a law"); this helper is the law-redeeming
/// consolidation for the shorter-marker half of the family, mirroring
/// what [`module_body_before_tests`] closed for the longer-marker half.
/// A future refinement (attaching a byte-offset return alongside the
/// slice, tolerating a preceding `#[allow(...)]` attribute, tightening
/// the marker discipline, or attaching a structured diagnostic hook)
/// lands in ONE body and propagates to every shield by construction
/// rather than being copy-edited at 15 sites.
///
/// # Contrast with the longer marker
///
/// [`module_body_before_tests`] uses the strictly longer marker
/// `"\n#[cfg(test)]\nmod tests {"` because its 23 pre-lift callers all
/// slice above a single `mod tests {}` block and want the boundary
/// pinned to that specific shape (a plain `#[cfg(test)]` attribute on
/// some helper fn would then NOT confuse the cutoff). This helper is
/// the strictly-shorter dual — pins the boundary to the FIRST
/// `#[cfg(test)]` attribute regardless of what follows it — because
/// its 15 pre-lift callers all use the shorter marker verbatim to cover
/// the per-frontier-test-bucket module layout their shields target.
pub fn module_body_before_first_cfg_test<'a>(source: &'a str, module_path: &str) -> &'a str {
    const MARKER: &str = "\n#[cfg(test)]\n";
    let body_end = source.find(MARKER).unwrap_or_else(|| {
        panic!(
            "{module_path}: the `#[cfg(test)]` marker must follow the \
             module body — the shield's slice boundary relies on this \
             module ordering"
        )
    });
    &source[..body_end]
}

/// Slice `source` at the first occurrence of `open_marker` and cap the
/// returned window at the FIRST occurrence of `end_marker` that follows
/// that opening — the `fn`-scoped sibling of [`module_body_before_tests`]
/// and the shield-side sibling of `version.rs`'s brace-nesting-aware
/// private `fn_body_after_signature`.
///
/// A shield that reads the module's own source via `include_str!` and
/// wants to bound a `.contains(...)` scan to ONE function's body (so
/// docstrings on sibling functions and this shield's own diagnostic
/// prose stay out of scope) writes the composition once:
///
/// ```text
/// const SOURCE: &str = include_str!("push.rs");
/// let fn_body = crate::test_support::fn_body_slice_between_markers(
///     SOURCE,
///     "push.rs",
///     "pub async fn update_kustomization(",
///     "\npub async fn execute(",
/// );
/// assert!(!fn_body.contains("Command::new(\"git\")"), "...");
/// ```
///
/// instead of open-coding the seven-line `SOURCE.find(fn_marker).expect(
/// ...); let after_fn = &SOURCE[start..]; let end_relative = after_fn.
/// find(end_marker).expect(...); let fn_body = &after_fn[..end_relative];`
/// stanza at each shield site.
///
/// Panics with the caller-supplied `module_path` naming which marker is
/// absent so a shield that lands on a module whose fn was renamed or
/// reordered diagnoses itself by name rather than falling through as a
/// generic `find` `None` unwrap.
///
/// Signature preserves the source lifetime (`<'a>(source: &'a str, ...)
/// -> &'a str`) so a caller can hand the sliced body to a shield and
/// still read `source` afterward without cloning — the exact shape
/// `commands/integration_tests.rs` uses at 2094-2105 / 2338-2354 to
/// cross-check the sliced fn body against the full source.
///
/// The returned slice INCLUDES the bytes of `open_marker` at its head
/// (matches the pre-lift stanza's `&SOURCE[start..]` semantics: the
/// slice starts at the marker's opening byte, not past it) and EXCLUDES
/// the bytes of `end_marker` at its tail (matches `&after_fn[..
/// end_relative]`: everything up to but not including the marker). This
/// dual-inclusive/exclusive discipline is what the 11 pre-lift callers
/// spelled verbatim; changing either boundary here would silently drift
/// every migrated shield's scan window.
pub fn fn_body_slice_between_markers<'a>(
    source: &'a str,
    module_path: &str,
    open_marker: &str,
    end_marker: &str,
) -> &'a str {
    let start = source.find(open_marker).unwrap_or_else(|| {
        panic!(
            "{module_path} must contain `{open_marker}` — the shield's \
             slice boundary depends on this signature"
        )
    });
    let after = &source[start..];
    let end_rel = after.find(end_marker).unwrap_or_else(|| {
        panic!(
            "{module_path} must contain `{end_marker}` after `{open_marker}` \
             — the shield's slice boundary depends on this ordering"
        )
    });
    &after[..end_rel]
}

/// Build a synthetic [`std::process::Output`] whose `ExitStatus` reports
/// success or a plain exit-code-1 failure, with caller-supplied stdout
/// and stderr byte buffers. The canonical fake-Output builder for shield
/// tests that drive an `&Output`-consuming primitive
/// ([`crate::commands::helm::ensure_helm_success`],
/// `commands/status.rs::kubectl_get_items` / `kubectl_get_item`, the
/// `retry::CommandAttemptFailure::from_capture` classifier, the
/// `error::GitError::from_capture` classifier, and downstream siblings)
/// without paying the fork-a-subprocess cost the alternative
/// synth-via-`true`/`false` shape would pay at every call. Every
/// consumer in the crate now routes fake-`Output` construction through
/// this ONE body.
///
/// # Why one canonical helper
///
/// Four byte-identical fork-based fake-`Output` builders lived across
/// the crate before consolidation: two `fn make_output(success: bool,
/// stdout: &[u8], stderr: &[u8]) -> std::process::Output` bodies at
/// `commands/status.rs::tests` and `commands/helm.rs::capture_tests`
/// (the `status.rs` copy's own comment described itself as "mirroring
/// the sibling `commands/helm.rs::capture_tests::make_output`
/// builder"), and two fork-based `fn synth_output(...)` /
/// `fn synth_output_for_git(...)` bodies at `retry::tests` and
/// `error::tests` (each paying `Command::new("true"/"false").status()
/// .expect(...)` per fake-`Output` construction — a few hundred
/// microseconds per call, summed across 80+ call sites in
/// `retry::tests` alone). PRIME DIRECTIVE: duplication budget is zero
/// (THEORY §VI.1). This helper is the law-redeeming consolidation for
/// both the `ExitStatusExt::from_raw` and the fork-based shapes. All
/// four consumer sites now delegate to this ONE body (the
/// `retry::tests` and `error::tests` sites via a local `use ... as
/// synth_output` / `use ... as synth_output_for_git` alias that
/// preserves their 80+/4 pre-existing call-site spellings verbatim), so
/// a future reshape (adding a captured signal detail, tracking the
/// fork-elapsed instant, widening to a cross-platform builder) lands at
/// one place.
///
/// # Exit-status encoding
///
/// The `success` bool maps to a Unix `wait(2)` status word:
///
/// - `true`  → `0x0000` (`W_EXITCODE(0, 0)`): exit code 0, no signal.
///   [`std::process::ExitStatus::code`] returns `Some(0)` and
///   [`std::process::ExitStatus::success`] returns `true`.
/// - `false` → `0x0100` (`W_EXITCODE(1, 0)` = `1 << 8`): exit code 1, no
///   signal. [`std::process::ExitStatus::code`] returns `Some(1)` and
///   `success()` returns `false`.
///
/// The low byte of the wait-status word encodes the signal (0 = normal
/// exit); the high byte encodes the exit code. `1 << 8` therefore means
/// "exited cleanly with exit code 1" — the shape a `bail!`-terminated
/// consumer primitive discriminates against `Some(0)`. This helper does
/// NOT cover the signal-killed shape
/// ([`std::process::ExitStatus::code`] returns `None`); the sole
/// signal-killed test in the crate (`retry::tests::
/// test_classify_capture_anyhow_signal_killed_surfaces_signal_detail`)
/// builds a `SIGKILL` status inline via `ExitStatus::from_raw(9)` and
/// stays in place for now.
///
/// # Unix-only
///
/// Uses [`std::os::unix::process::ExitStatusExt::from_raw`] which is
/// gated to `cfg(unix)`. The forge test runner targets Linux and macOS
/// exclusively (Nix flake's `systems = ["x86_64-linux", "aarch64-linux",
/// "aarch64-darwin"]`), so the `#[cfg(unix)]` implicit gate here is a
/// no-op on every host the test runner reaches. A future Windows target
/// would need a `#[cfg(windows)]` sibling using `ExitStatusExt` from
/// `std::os::windows::process`.
pub fn synthetic_output(success: bool, stdout: &[u8], stderr: &[u8]) -> std::process::Output {
    use std::os::unix::process::ExitStatusExt;
    std::process::Output {
        status: std::process::ExitStatus::from_raw(if success { 0 } else { 1 << 8 }),
        stdout: stdout.to_vec(),
        stderr: stderr.to_vec(),
    }
}

/// Whole-module shield: assert that `source` does NOT hand `bare` as a
/// bare-string first argument to
/// [`crate::retry::run_query_capture_sync`] in either of the two
/// rustfmt-produced call-site shapes the primitive receives.
///
/// # The two forbidden shapes
///
/// `run_query_capture_sync(cmd: &str, args: &[&str])` spawns
/// `std::process::Command::new(cmd)` verbatim per retry.rs:13167,
/// which means a bare literal at the call site bypasses the
/// substrate-exported `<TOOL>_BIN` env override every sibling
/// tools-registry-routed spawn honors. rustfmt reaches the primitive
/// in exactly two shapes depending on whether the call fits on one
/// line:
///
/// - **Inline** (`run_query_capture_sync("<bare>", &["…"])`): the
///   call fits on a single line. Matched by the reconstructed needle
///   `run_query_capture_sync("<bare>",` (open paren, quoted literal,
///   comma).
/// - **Multi-line 8-space indent** (`run_query_capture_sync(\n
///   "<bare>",\n    &["…"],\n)`): the call is broken after the open
///   paren and each argument is on its own line with a 4-space
///   additional indent. Nested two levels deep inside `impl`/`mod`
///   the leading indent is 8 spaces. Matched by the reconstructed
///   needle `run_query_capture_sync(\n        "<bare>"` (open paren,
///   newline, 8 spaces, quoted literal).
///
/// Both needles are reconstructed via [`format!`] at call time, so
/// this helper's own source text does not literally contain either
/// shape — every scan therefore covers both the top-of-file
/// production body AND every sibling `#[cfg(test)]` block without
/// the helper's own body false-matching itself.
///
/// # Why one canonical helper
///
/// Three shield sites across `commands/seed.rs`,
/// `commands/sessions.rs`, and `commands/local.rs` each carry the
/// same `let bypass_primitive = format!("run_query_capture_sync(…\"{}
/// \"…", bare); assert!(!source.contains(&bypass_primitive), "…");`
/// stanza — two guard the multi-line 8-space form (seed / sessions,
/// kubectl), one guards the inline form (local, docker). Three
/// occurrences past THEORY §VI.1's three-times-is-a-law threshold
/// (PRIME DIRECTIVE: duplication budget is zero); this helper is the
/// law-redeeming consolidation.
///
/// Consolidating also strictly TIGHTENS every migrated shield: each
/// pre-lift site checked ONE of the two shapes, so a rustfmt reflow
/// that flipped a call from multi-line to inline (or vice versa)
/// silently escaped its shield. Post-lift every shield defends BOTH
/// shapes at once — a rustfmt reflow of a bypass-primitive attempt
/// cannot escape by choosing the un-checked form.
///
/// # Panic-message shape
///
/// On a match the panic names `module_path`, `bare`, `resolver_remedy`
/// (a caller-supplied phrase like ``resolve `KUBECTL_BIN` via
/// `get_tool_path(tools::KUBECTL)```), AND the specific shape (inline
/// vs multi-line) that matched — so a reader of a failing shield sees
/// the exact rustfmt shape the regression introduced. Mirrors the
/// per-shape diagnostic discipline
/// [`assert_source_forbids_bare_spawn_shapes`] holds on the
/// `Command::new` spawn frontier.
pub fn assert_source_forbids_bare_literal_as_run_query_capture_sync_first_arg(
    source: &str,
    module_path: &str,
    bare: &str,
    resolver_remedy: &str,
) {
    let inline = format!("run_query_capture_sync(\"{bare}\",");
    assert!(
        !source.contains(&inline),
        "{module_path} must NOT hand the bare `\"{bare}\"` literal to \
         `run_query_capture_sync` as its first arg (inline form) — the \
         primitive spawns the caller-supplied `&str` verbatim via \
         `std::process::Command::new(cmd)`, so every consumer must \
         pre-resolve through {resolver_remedy}. A bare literal at the \
         primitive call site bypasses the substrate-exported env override."
    );

    let multi_line = format!("run_query_capture_sync(\n        \"{bare}\"");
    assert!(
        !source.contains(&multi_line),
        "{module_path} must NOT hand the bare `\"{bare}\"` literal to \
         `run_query_capture_sync` as its first arg (multi-line 8-space \
         form) — the primitive spawns the caller-supplied `&str` verbatim \
         via `std::process::Command::new(cmd)`, so every consumer must \
         pre-resolve through {resolver_remedy}. A bare literal at the \
         primitive call site bypasses the substrate-exported env override."
    );
}

/// RAII-safe scratch directory for tests that need on-disk state
/// (write fixture files, then assert against them, then clean up).
///
/// Builds a fresh tempdir under the system tempdir root, prefixed with
/// `prefix` so the created directory's basename embeds the caller-
/// supplied label (`tempfile::Builder`'s `prefix` becomes the leading
/// component of the OS-unique basename it hands back). Returns the
/// owning [`tempfile::TempDir`], whose `Drop` unlinks the directory
/// and every file underneath — the caller MUST bind the return value
/// to a local `_dir` (or longer-lived) variable for the duration of
/// the test. Callers reach the on-disk path via `guard.path()` — the
/// same shape [`make_executable_shim`]'s consumers use.
///
/// # Why one canonical helper
///
/// Ten tests in `commands/migration_validation.rs::tests` each carry
/// the same three-to-four-line boilerplate:
///
/// ```ignore
/// let dir = std::env::temp_dir().join("test_manifest_missing");
/// let _ = std::fs::remove_dir_all(&dir);
/// let _ = std::fs::create_dir_all(&dir);
/// // ... test body writing under `&dir` ...
/// let _ = std::fs::remove_dir_all(&dir);
/// ```
///
/// Ten occurrences is >3× THEORY.md §VI.1's three-times-is-a-law
/// threshold ("two occurrences is a coincidence; three is a law").
/// The pre-lift stanza also carries three defects the RAII lift
/// closes by construction:
///
/// 1. **A panic mid-test leaks the tempdir.** `assert_eq!` /
///    `assert!` panic on failure, so any failing test skips the
///    trailing `remove_dir_all` and leaves `/tmp/test_manifest_missing`
///    on disk. A CI reranner that lands on the same test-runner
///    machine hits the stale state (the pre-clean sweep does fire
///    at test entry, but two parallel test-binary instances of the
///    same test race the pre-clean-then-recreate window, so the
///    second instance's `create_dir_all` can observe a partially-
///    deleted state the first is still tearing down). `TempDir`'s
///    `Drop` runs unconditionally — through panics too — closing
///    the leak at the type system.
/// 2. **`std::env::temp_dir().join("<fixed-name>")` is a shared,
///    non-unique path.** Two concurrent `cargo test` runs (a
///    developer running the suite while CI runs it on the same
///    workstation, or two matrix jobs on a single self-hosted
///    runner) collide on the same subdir and produce interleaved
///    writes / deletes an operator debugging a flake reads as
///    "the test is nondeterministic". `tempfile::Builder::prefix(...)
///    .tempdir()` appends an OS-unique suffix (POSIX `mkdtemp(3)`
///    on Unix), so two concurrent calls with the same prefix return
///    strictly-distinct paths by construction.
/// 3. **Duplicate boilerplate spreads a hidden precondition.** The
///    pre-lift `let _ = std::fs::remove_dir_all(&dir);` sweep is
///    LOAD-BEARING for the fixed-name shape — without it, state
///    from a prior run silently pollutes this run. Nine of the ten
///    sites carry it; one (`test_validate_manifest_missing_file`)
///    silently omits the pre-clean because its body writes no
///    files ("no manifest file"), so a future edit that added a
///    file-write inherited the fixed-name-and-no-preclean shape and
///    would flake against a prior run's residue. The RAII lift
///    makes the shape irrelevant — every scratch dir is fresh by
///    construction, so a caller adding a file-write cannot
///    reintroduce the flake.
///
/// # Contrast with `make_executable_shim`
///
/// [`make_executable_shim`] returns a `(TempDir, String)` pair
/// because its consumers need the absolute path to the shim binary
/// inside the tempdir for `Command::new(shim_path)` — a two-slot
/// return is load-bearing there. This helper's consumers own
/// arbitrary on-disk state under the tempdir root (multiple files,
/// nested subdirs) and reach the root via `guard.path()`, so a
/// single-slot `TempDir` return is the tighter shape. Both
/// primitives share the "the returned owner is what keeps the
/// on-disk state alive, and a bare-string return would race Drop"
/// discipline.
pub fn named_scratch_dir(prefix: &str) -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix(prefix)
        .tempdir()
        .unwrap_or_else(|err| {
            panic!("named_scratch_dir({prefix:?}): failed to create tempdir: {err}")
        })
}

/// RAII-guarded per-test argv-log scratch — a hermetic tempdir plus
/// an `argv.log` path inside it, bound to `self` so `Drop` unlinks
/// both together.
///
/// Four `#[cfg(unix)]` argv-shim tests across
/// `cli/src/infrastructure/docker.rs` and
/// `cli/src/infrastructure/kubectl.rs`
/// (`test_find_first_image_id_by_name_with_bin_passes_canonical_docker_args`,
/// `test_fetch_secret_value_with_bin_passes_canonical_kubectl_args`,
/// `test_find_first_pod_name_async_with_bin_passes_canonical_kubectl_args`,
/// `test_kubectl_probe_stdout_capture_forwards_args`) reached for the
/// same three-line reservation body VERBATIM
///
/// ```ignore
/// let log_dir = tempfile::tempdir().expect("log tempdir");
/// let log_path = log_dir.path().join("argv.log");
/// let log_str = log_path.display().to_string();
/// ```
///
/// then wove `log_str` into a byte-identical POSIX-sh shim body
///
/// ```ignore
/// #!/bin/sh
/// for a in "$@"; do printf '%s\n' "$a" >> '{log_str}'; done
/// printf '%s' '{stdout_payload}'
/// ```
///
/// and read the file back with the same two-line
/// `read_to_string + .lines().collect::<Vec<_>>()` stanza. That is
/// four copies of one shape past THEORY §VI.1's three-times-is-a-law
/// threshold, each independently able to drift off:
///
/// 1. `tempfile::tempdir()` honoring `TMPDIR` (so a Nix
///    `sandbox = true` daemon build with no writable `/tmp` still
///    reserves scratch in the daemon's per-build slot).
/// 2. `TempDir::Drop` unlinking the whole dir + `argv.log` inside it
///    (panic-safe across the shim-write → spawn → read-back handoff).
/// 3. `printf '%s\n'` — not `echo` — in the shim body, so a
///    positional arg beginning with `-n` isn't swallowed as echo's
///    POSIX "no trailing newline" flag (a shell-portability trap
///    every one of the four pre-lift sites called out in prose).
///
/// This primitive collects all three at ONE definition. A fifth
/// argv-shim consumer (a `cosign verify` argv test, a `nix store
/// verify` argv test, a `helm template` argv test — every one of
/// them a plausible follow-on) inherits every discipline in one call.
///
/// A `let _ = ArgvLog::reserve();` binding that drops the guard
/// unlinks the file with it — the guard's lifetime is the log's
/// lifetime by construction (THEORY §I.1 beat 2: the declaration is
/// well-formed by its return type).
pub struct ArgvLog {
    _dir: tempfile::TempDir,
    path: PathBuf,
}

impl ArgvLog {
    /// Reserve a fresh hermetic tempdir and an `argv.log` path
    /// inside it. The tempdir is bound to `self`; `Drop` unlinks
    /// both together.
    pub fn reserve() -> Self {
        let dir = tempfile::tempdir().expect("argv log tempdir");
        let path = dir.path().join("argv.log");
        Self { _dir: dir, path }
    }

    /// Path to `argv.log` inside the guarded tempdir. Useful for
    /// callers that need to inspect the file directly instead of via
    /// [`ArgvLog::read_argv_log`].
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// A POSIX-sh shim body that appends every positional arg on its
    /// own line to this argv log, then prints `stdout_payload` to
    /// stdout (with no trailing newline) and exits 0.
    ///
    /// `printf '%s\n'` — not `echo` — so a `-n` argument isn't
    /// swallowed as echo's "no trailing newline" flag. Every one of
    /// the four pre-lift sites called this trap out in prose above
    /// the hand-rolled body; the fix now lives at one definition.
    ///
    /// Callers pass the returned string to
    /// [`make_executable_shim`]`(bin, &body)` to write a chmod +x
    /// shim on disk.
    pub fn shim_body(&self, stdout_payload: &str) -> String {
        let log = self.path.display();
        format!(
            "#!/bin/sh\n\
             for a in \"$@\"; do printf '%s\\n' \"$a\" >> '{log}'; done\n\
             printf '%s' '{stdout_payload}'\n"
        )
    }

    /// Read the argv log's raw contents as a `String`. Callers
    /// typically follow with `.lines().collect::<Vec<_>>()` for
    /// line-by-line comparison against the canonical argv slice.
    pub fn read_argv_log(&self) -> String {
        std::fs::read_to_string(&self.path).expect("read argv log")
    }
}

/// Reserve a hermetic tempdir holding a shim named `tool` whose body
/// ignores every positional argument and writes `stdout_payload` to
/// stdout with **no trailing newline**, exiting zero. Returns the
/// same `(TempDir, absolute path)` tuple as [`make_executable_shim`],
/// so consumers keep the identical binding shape
/// (`let (_dir, shim) = printf_only_shim(...)`) they already use for
/// hand-rolled shim bodies.
///
/// # Why a primitive
///
/// Six sibling tests — [`infrastructure/docker.rs`]'s two
/// `find_first_image_id_by_name`-classifier happy-path tests and
/// [`infrastructure/kubectl.rs`]'s four
/// `fetch_secret_value` / `find_first_pod_name_async` /
/// `kubectl_probe_stdout_capture` happy-path tests — each spelled
/// the same shim body verbatim:
///
/// ```ignore
/// let (_dir, shim) = make_executable_shim(
///     "<tool>",
///     "#!/bin/sh\nprintf '%s' '<literal-payload>'\n",
/// );
/// // or, for a dynamic payload:
/// let body = format!("#!/bin/sh\nprintf '%s' '{}'\n", <dynamic-payload>);
/// let (_dir, shim) = make_executable_shim("<tool>", &body);
/// ```
///
/// Four literal-payload copies plus two `format!`-derived copies is
/// six copies of one shape past THEORY §VI.1's three-times-is-a-law
/// threshold, each independently able to drift off:
///
/// 1. `printf '%s'` — not `echo` — so the emitted stdout carries **no
///    trailing newline** (matching the classifier's `.trim()`-then-
///    check-empty discipline; an `echo`-based shim would silently add
///    a `\n` and a future classifier revision that stopped trimming
///    would round-trip corrupt data through six tests at once).
/// 2. `printf '%s'` (not `printf` alone, not `%b`) — no `\n` or `\t`
///    escape expansion, so a payload containing a literal `\n` in its
///    Rust-source spelling ships to stdout as a two-character
///    backslash-n rather than a newline.
/// 3. Single-quoting the payload — no shell interpolation, no `$`
///    expansion. The primitive spells the single quotes once so a
///    caller cannot forget them.
///
/// This primitive collects all three at ONE definition. A seventh
/// print-a-fixed-payload consumer (a `cosign` classifier test, a
/// `helm` classifier test, a `regctl` classifier test — every one of
/// them a plausible follow-on) inherits every discipline in one call.
///
/// # Complement to [`ArgvLog`]
///
/// [`ArgvLog::shim_body`] is the argv-INSPECTING sibling: same
/// `printf '%s' '<payload>'` trap-fix, plus an argv-side-channel
/// write. `printf_only_shim` is the argv-IGNORING sibling for tests
/// that only need to pin the stdout classifier's happy path (no argv
/// assertion needed — that's a separate test). Both compose over
/// [`make_executable_shim`] and share the same `(TempDir, String)`
/// return-shape discipline: the tempdir MUST be bound to a local
/// `_dir` (or longer-lived) variable, else the shim file is unlinked
/// before the test spawns it.
///
/// # Payload safety
///
/// `stdout_payload` is spliced verbatim between single quotes in the
/// emitted shim body. A payload containing an apostrophe (`'`) or a
/// backslash would break the single-quoted section — every observed
/// caller uses base64 output, SHA hex, kebab-case pod names, or
/// `namespace/kind/name` strings, none of which contain an apostrophe.
/// Callers with such payloads should reach for a hand-rolled shim
/// body via [`make_executable_shim`] directly rather than escape-
/// smuggling through this primitive.
///
/// [`infrastructure/docker.rs`]: crate::infrastructure::docker
/// [`infrastructure/kubectl.rs`]: crate::infrastructure::kubectl
pub fn printf_only_shim(tool: &str, stdout_payload: &str) -> (tempfile::TempDir, String) {
    let body = format!("#!/bin/sh\nprintf '%s' '{stdout_payload}'\n");
    make_executable_shim(tool, &body)
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

    /// A shape-free source — one containing none of the three canonical
    /// bare-literal spawn shapes for `bare` — passes cleanly. The
    /// pre-lift block was the three `assert!(!SOURCE.contains(...))`
    /// early-returning on the happy path; the helper's happy path is
    /// return-without-panic. Pinning this is the floor every shield
    /// consumes: absent any forbidden shape, the helper is a no-op.
    ///
    /// The `remediation` slot is exercised with a spelling different
    /// from any real shield's ("fake-remedy") so a future refactor that
    /// silently hard-coded the remediation phrase would surface here as
    /// a substitution-drift failure, not as a passing test with
    /// wrong-message diagnostics downstream.
    #[test]
    fn test_assert_source_forbids_bare_spawn_shapes_accepts_shape_free_source() {
        assert_source_forbids_bare_spawn_shapes(
            "let cmd = crate::routing::sigil::foo_bin(); cmd.arg(\"probe\");",
            "fake/module.rs",
            "foo",
            "route through `fake-remedy`",
        );
    }

    /// The `std::process::Command::new("<bare>")` shape is caught and
    /// the panic message names the module, the bare tool, the
    /// remediation phrase, AND the specific `std::process::Command::new`
    /// spawn shape. `should_panic(expected = ...)` matches on a
    /// substring of the panic payload, so a future edit that dropped
    /// any of the four substituted / templated tokens from the message
    /// (say, condensing the shape-specific tail into a generic "raw
    /// literal") would break this test before shipping — a reader of a
    /// failing shield relies on the shape-specific tail to know which
    /// of the three forbidden spawn shapes matched.
    ///
    /// The bare tool `zeta-widget` is deliberately distinct from every
    /// real shield's `bare` so a Grep of the crate for `zeta-widget`
    /// resolves to exactly this test and its two siblings — a fast way
    /// to find the pinning tests when editing the helper.
    #[test]
    #[should_panic(
        expected = "fake/module.rs must not spawn `zeta-widget` via the bare literal — every zeta-widget spawn must route through `zeta_bin()` first. A raw literal at `std::process::Command::new`"
    )]
    fn test_assert_source_forbids_bare_spawn_shapes_panics_on_std_process_shape() {
        assert_source_forbids_bare_spawn_shapes(
            "let cmd = std::process::Command::new(\"zeta-widget\");",
            "fake/module.rs",
            "zeta-widget",
            "route through `zeta_bin()`",
        );
    }

    /// The bare-alias `Command::new("<bare>")` shape is caught and the
    /// message names the top-of-file `use` alias as the offending
    /// spawn form. Sibling pin to
    /// [`test_assert_source_forbids_bare_spawn_shapes_panics_on_std_process_shape`].
    #[test]
    #[should_panic(
        expected = "fake/module.rs must not spawn `zeta-widget` via the bare literal — every zeta-widget spawn must route through `zeta_bin()` first. A raw literal at `Command::new` (either the top-level `use` alias or the bare form)"
    )]
    fn test_assert_source_forbids_bare_spawn_shapes_panics_on_bare_alias_shape() {
        assert_source_forbids_bare_spawn_shapes(
            "let cmd = Command::new(\"zeta-widget\");",
            "fake/module.rs",
            "zeta-widget",
            "route through `zeta_bin()`",
        );
    }

    /// The `tokio::process::Command::new("<bare>")` shape is caught and
    /// the message names the async spawn form. Sibling pin to
    /// [`test_assert_source_forbids_bare_spawn_shapes_panics_on_std_process_shape`].
    #[test]
    #[should_panic(
        expected = "fake/module.rs must not spawn `zeta-widget` via the bare literal — every zeta-widget spawn must route through `zeta_bin()` first. A raw literal at `tokio::process::Command::new`"
    )]
    fn test_assert_source_forbids_bare_spawn_shapes_panics_on_tokio_process_shape() {
        assert_source_forbids_bare_spawn_shapes(
            "let cmd = tokio::process::Command::new(\"zeta-widget\");",
            "fake/module.rs",
            "zeta-widget",
            "route through `zeta_bin()`",
        );
    }

    /// A shape-free source passes cleanly under the code-line-filtered
    /// sibling too — the floor every migrated shield consumes. Sibling
    /// happy-path pin to
    /// [`test_assert_source_forbids_bare_spawn_shapes_accepts_shape_free_source`],
    /// with the same `fake-remedy` substitution-drift discipline.
    #[test]
    fn test_assert_source_forbids_bare_spawn_shapes_code_line_accepts_shape_free_source() {
        assert_source_forbids_bare_spawn_shapes_code_line(
            "let cmd = crate::routing::sigil::foo_bin(); cmd.arg(\"probe\");",
            "fake/module.rs",
            "foo",
            "route through `fake-remedy`",
        );
    }

    /// A source that mentions every one of the three forbidden bare
    /// spawn shapes ONLY inside `///` docstrings (with no code-line
    /// occurrence) passes cleanly — the load-bearing correctness
    /// property the code-line-filtered variant exists to preserve.
    ///
    /// This is the property the naive
    /// [`assert_source_forbids_bare_spawn_shapes`] cannot honor: its
    /// raw `source.contains(...)` predicate would false-fire on every
    /// docstring hit, forcing the two git modules whose top-of-module
    /// docstrings quote the historical `Command::new(<bare-git-literal>)`
    /// anti-pattern by literal quotation to author around it. Pinning
    /// this here means a future refactor that silently dropped the
    /// `code_line_hits` filtering inside the code-line-filtered helper
    /// (say, reverting to raw `source.contains(...)`) would break this
    /// test loudly before shipping — the two migrated git shields
    /// would then false-fire on their own docstrings.
    ///
    /// All three docstring shapes (`std::process::Command::new(...)`,
    /// bare `Command::new(...)`, `tokio::process::Command::new(...)`)
    /// appear in the fixture so a filter drift on any one of the
    /// three surfaces here.
    #[test]
    fn test_assert_source_forbids_bare_spawn_shapes_code_line_accepts_docstring_only_match() {
        assert_source_forbids_bare_spawn_shapes_code_line(
            "/// pre-lift the fixture spawned via \
             `std::process::Command::new(\"zeta-widget\")`\n\
             /// or the bare alias `Command::new(\"zeta-widget\")`\n\
             /// or the async form \
             `tokio::process::Command::new(\"zeta-widget\")` — all three \
             hid the ZETA_WIDGET_BIN override\n\
             fn zeta_bin() -> String { String::new() }\n",
            "fake/module.rs",
            "zeta-widget",
            "route through `zeta_bin()`",
        );
    }

    /// The `std::process::Command::new("<bare>")` shape at a code line
    /// is caught and the panic message names the module, the bare
    /// tool, the remediation phrase, the specific
    /// `std::process::Command::new` spawn shape, AND the offending
    /// `"line <N>: <trimmed>"` hit — the code-line-hit diagnostic
    /// tail is the shape-differentiator between this helper and the
    /// naive [`assert_source_forbids_bare_spawn_shapes`] sibling. A
    /// message rewrite that dropped the hits payload would break this
    /// test before shipping — a reader of a failing shield relies on
    /// the hit line number to jump straight to the regression.
    ///
    /// The bare tool `zeta-widget` is deliberately distinct from every
    /// real shield's `bare` so a Grep of the crate for `zeta-widget`
    /// resolves to exactly this test and its siblings — a fast way to
    /// find the pinning tests when editing the helper.
    #[test]
    #[should_panic(
        expected = "fake/module.rs must not spawn `zeta-widget` via the bare literal at `std::process::Command::new` — every zeta-widget spawn must route through `zeta_bin()` first. A raw literal bypasses the hermetic-runner contract substrate's `mkRuntimeToolsEnv` exports. Offending code lines: [\"line 1: let cmd = std::process::Command::new(\\\"zeta-widget\\\");\"]"
    )]
    fn test_assert_source_forbids_bare_spawn_shapes_code_line_panics_on_std_process_shape() {
        assert_source_forbids_bare_spawn_shapes_code_line(
            "let cmd = std::process::Command::new(\"zeta-widget\");",
            "fake/module.rs",
            "zeta-widget",
            "route through `zeta_bin()`",
        );
    }

    /// The bare-alias `Command::new("<bare>")` shape at a code line is
    /// caught and the message names the top-of-file `use` alias as the
    /// offending spawn form plus the offending code-line hit. Sibling
    /// panic pin to
    /// [`test_assert_source_forbids_bare_spawn_shapes_code_line_panics_on_std_process_shape`].
    #[test]
    #[should_panic(
        expected = "fake/module.rs must not spawn `zeta-widget` via the bare literal at `Command::new` (top-of-file alias) — every zeta-widget spawn must route through `zeta_bin()` first. A raw literal bypasses the hermetic-runner contract. Offending code lines: [\"line 1: let cmd = Command::new(\\\"zeta-widget\\\");\"]"
    )]
    fn test_assert_source_forbids_bare_spawn_shapes_code_line_panics_on_bare_alias_shape() {
        assert_source_forbids_bare_spawn_shapes_code_line(
            "let cmd = Command::new(\"zeta-widget\");",
            "fake/module.rs",
            "zeta-widget",
            "route through `zeta_bin()`",
        );
    }

    /// The `tokio::process::Command::new("<bare>")` shape at a code
    /// line is caught and the message names the async spawn form plus
    /// the offending code-line hit. Sibling panic pin to
    /// [`test_assert_source_forbids_bare_spawn_shapes_code_line_panics_on_std_process_shape`].
    #[test]
    #[should_panic(
        expected = "fake/module.rs must not spawn `zeta-widget` via the bare literal at `tokio::process::Command::new` — every async zeta-widget spawn must route through `zeta_bin()` first. A raw literal bypasses the hermetic-runner contract. Offending code lines: [\"line 1: let cmd = tokio::process::Command::new(\\\"zeta-widget\\\");\"]"
    )]
    fn test_assert_source_forbids_bare_spawn_shapes_code_line_panics_on_tokio_process_shape() {
        assert_source_forbids_bare_spawn_shapes_code_line(
            "let cmd = tokio::process::Command::new(\"zeta-widget\");",
            "fake/module.rs",
            "zeta-widget",
            "route through `zeta_bin()`",
        );
    }

    /// A `needle`-free source produces an empty hit vec. Pinning this is
    /// the floor every shield consumes: absent any forbidden shape, the
    /// helper is a no-op the shield's `is_empty()` guard reads as green.
    #[test]
    fn test_code_line_hits_returns_empty_on_shape_free_source() {
        let hits = code_line_hits(
            "fn ok() { let x = crate::routing::sigil::foo_bin(); }\n",
            "raw_literal_that_never_appears",
        );
        assert!(hits.is_empty(), "shape-free source must produce no hits");
    }

    /// A `needle`-bearing code line is reported with its 1-indexed line
    /// number and trimmed content in the `"line <N>: <trimmed>"` shape
    /// every shield's `assert!(hits.is_empty(), "... {hits:?}")` prose
    /// consumes. Pinning both the line number origin (1-indexed, matching
    /// what a text editor shows) and the trim (leading indentation
    /// stripped so the diagnostic reads compactly regardless of nesting
    /// depth) prevents a future refactor from silently drifting to
    /// 0-indexed line numbers or untrimmed lines — either would misalign
    /// every existing shield's diagnostic against its file view.
    #[test]
    fn test_code_line_hits_reports_one_indexed_trimmed_hits() {
        let source = "fn ok() { }\n    let _ = FORBIDDEN_MARKER;\nfn also_ok() { }\n";
        let hits = code_line_hits(source, "FORBIDDEN_MARKER");
        assert_eq!(hits, vec!["line 2: let _ = FORBIDDEN_MARKER;".to_string()]);
    }

    /// A `needle`-bearing line whose trimmed prefix is `///`, `//!`, or
    /// `//` is filtered out — the doc-comment / shield-error-prose
    /// exclusion is the load-bearing property the six shielded modules
    /// rely on. Two of them (`git.rs`, `infrastructure/git.rs`) carry
    /// docstrings that literally quote the bare-`Command::new(<tool>)`
    /// anti-pattern; four (`local.rs`, `infra.rs`, `dashboards.rs`,
    /// `prerelease.rs`) forbid a deriving sigil form their OWN error
    /// message quotes in the "use the two-arg form instead" prose.
    /// Without this filter every one of those shields would false-fire
    /// on its own body. A future edit that dropped any of the three
    /// prefixes would break this pinning test before shipping.
    #[test]
    fn test_code_line_hits_filters_out_doc_and_line_comments() {
        let source = "\
/// FORBIDDEN_MARKER inside a doc line
//! FORBIDDEN_MARKER inside a module doc line
// FORBIDDEN_MARKER inside a plain line comment
    /// FORBIDDEN_MARKER inside an indented doc line
fn ok() { let _ = FORBIDDEN_MARKER; }
";
        let hits = code_line_hits(source, "FORBIDDEN_MARKER");
        assert_eq!(
            hits,
            vec!["line 5: fn ok() { let _ = FORBIDDEN_MARKER; }".to_string()],
            "only the executable-code line must be reported"
        );
    }

    /// The canonical needle for `("DOCKER_BIN", "docker")` is the
    /// substituted two-arg literal every sibling `<tool>_bin()` sigil
    /// across forge routes through. Pinning the exact substituted string
    /// here means a future edit that silently rewrote the template
    /// (adding a space, dropping the quotes, renaming `get_tool_path`)
    /// would break this test loudly before shipping — the five callers
    /// consume the return value verbatim via
    /// `code_line_hits(SOURCE, &needle)`, so a template drift would
    /// silently disarm every migrated shield.
    ///
    /// A distinct bare `zeta-widget` sibling case pins that both
    /// substitution positions are load-bearing (a template that dropped
    /// `env_var` or `bare` would collapse the pair to the same string).
    #[test]
    fn test_canonical_two_arg_sigil_needle_reconstructs_substituted_form() {
        assert_eq!(
            canonical_two_arg_sigil_needle("DOCKER_BIN", "docker"),
            "crate::repo::get_tool_path(\"DOCKER_BIN\", \"docker\")".to_string(),
        );
        assert_eq!(
            canonical_two_arg_sigil_needle("CARGO", "cargo"),
            "crate::repo::get_tool_path(\"CARGO\", \"cargo\")".to_string(),
        );
        assert_eq!(
            canonical_two_arg_sigil_needle("ZETA_WIDGET_BIN", "zeta-widget"),
            "crate::repo::get_tool_path(\"ZETA_WIDGET_BIN\", \"zeta-widget\")".to_string(),
        );
    }

    /// A source with the canonical sigil at a code line passes cleanly.
    /// Pinning the code-line acceptance path is the floor every
    /// migrated shield consumes: absent any regression, the helper is
    /// silent. The `zeta-widget` bare is deliberately distinct from
    /// every real shield's `bare` so a Grep of the crate for
    /// `zeta-widget` resolves to exactly this test and its sibling —
    /// a fast way to find the pinning tests when editing the helper.
    #[test]
    fn test_assert_source_has_canonical_two_arg_sigil_code_line_accepts_code_line() {
        assert_source_has_canonical_two_arg_sigil_code_line(
            "fn zeta_bin() -> String {\n    \
             crate::repo::get_tool_path(\"ZETA_WIDGET_BIN\", \"zeta-widget\")\n\
             }\n",
            "fake/module.rs",
            "ZETA_WIDGET_BIN",
            "zeta-widget",
        );
    }

    /// A source that mentions the canonical form ONLY inside a `///`
    /// docstring (with no code-line occurrence) fires the shield — the
    /// docstring-self-match defect the code-line filter exists to
    /// close. Pins the load-bearing correctness property named in the
    /// helper's docs: the pre-lift `SOURCE.contains(&canonical)` shield
    /// silently passed on this exact input class in two production
    /// shields on `main` (`commands/dashboards.rs::jsonnet_bin_routing_tests`
    /// and `commands/prerelease.rs::tests::test_cargo_spawn_routes_through_cargo_bin_not_raw_literal`).
    /// A future refactor that dropped the code-line filter (say, going
    /// back to a naive `source.contains(&needle)` for the positive
    /// assertion) would break this test before shipping and re-open the
    /// silent-pass regression class.
    ///
    /// `should_panic(expected = ...)` matches on a substring of the
    /// panic payload; the substring pins the substituted `env_var` /
    /// `bare` / `module_path` tokens in the diagnostic so a message
    /// rewrite that dropped any of them would surface here.
    #[test]
    #[should_panic(
        expected = "fake/module.rs must delegate `zeta-widget` via the canonical two-arg `crate::repo::get_tool_path(\"ZETA_WIDGET_BIN\", \"zeta-widget\")` at a *code* line"
    )]
    fn test_assert_source_has_canonical_two_arg_sigil_code_line_rejects_docstring_only_match() {
        assert_source_has_canonical_two_arg_sigil_code_line(
            "/// `crate::repo::get_tool_path(\"ZETA_WIDGET_BIN\", \"zeta-widget\")` — narrated\n\
             fn zeta_bin() -> String { String::new() }\n",
            "fake/module.rs",
            "ZETA_WIDGET_BIN",
            "zeta-widget",
        );
    }

    /// A source that omits the canonical form entirely fires the shield
    /// — the plain missing-sigil regression class. Sibling pin to
    /// [`test_assert_source_has_canonical_two_arg_sigil_code_line_rejects_docstring_only_match`]:
    /// the two together certify both failure modes (docstring-only and
    /// missing-outright) trigger the same diagnostic.
    #[test]
    #[should_panic(
        expected = "fake/module.rs must delegate `zeta-widget` via the canonical two-arg"
    )]
    fn test_assert_source_has_canonical_two_arg_sigil_code_line_rejects_missing_canonical() {
        assert_source_has_canonical_two_arg_sigil_code_line(
            "fn zeta_bin() -> String { String::new() }\n",
            "fake/module.rs",
            "ZETA_WIDGET_BIN",
            "zeta-widget",
        );
    }

    /// The constant-driven needle constructor emits the exact
    /// `crate::tools::get_tool_path(crate::tools::tools::<CONST>)`
    /// substituted form the three docker shields consume verbatim via
    /// `code_line_hits(SOURCE, &needle)`. A template drift (a stray
    /// space, dropped double colon, renamed `crate::tools::tools`
    /// registry path) would silently disarm every migrated shield. The
    /// distinct `ZETA_WIDGET` sibling case pins that the constant-name
    /// position is load-bearing (a template that discarded it would
    /// collapse all three docker shields to a single string, and every
    /// future sigil-family shield with it).
    #[test]
    fn test_deriving_one_arg_sigil_needle_constant_reconstructs_substituted_form() {
        assert_eq!(
            deriving_one_arg_sigil_needle_constant("DOCKER"),
            "crate::tools::get_tool_path(crate::tools::tools::DOCKER)".to_string(),
        );
        assert_eq!(
            deriving_one_arg_sigil_needle_constant("ZETA_WIDGET"),
            "crate::tools::get_tool_path(crate::tools::tools::ZETA_WIDGET)".to_string(),
        );
    }

    /// The literal-string needle constructor emits the exact
    /// `crate::tools::get_tool_path("<bare>")` substituted form the
    /// dashboards jsonnet shield consumes verbatim. Sibling pin to
    /// [`test_deriving_one_arg_sigil_needle_constant_reconstructs_substituted_form`];
    /// the pair certifies both deriving-form variants round-trip
    /// through their respective needle constructors.
    #[test]
    fn test_deriving_one_arg_sigil_needle_literal_reconstructs_substituted_form() {
        assert_eq!(
            deriving_one_arg_sigil_needle_literal("jsonnet"),
            "crate::tools::get_tool_path(\"jsonnet\")".to_string(),
        );
        assert_eq!(
            deriving_one_arg_sigil_needle_literal("zeta-widget"),
            "crate::tools::get_tool_path(\"zeta-widget\")".to_string(),
        );
    }

    /// A source with no deriving constant-driven form passes cleanly.
    /// Pinning the happy path is the floor every migrated shield
    /// consumes: absent any regression, the helper is silent. The
    /// canonical two-arg form appears verbatim (as it does in every
    /// real production body) so this test also certifies the shield
    /// does not confuse the canonical two-arg form with the pre-lift
    /// deriving one-arg form.
    #[test]
    fn test_assert_source_forbids_deriving_one_arg_sigil_constant_form_accepts_shape_free_source() {
        assert_source_forbids_deriving_one_arg_sigil_constant_form(
            "fn zeta_bin() -> String {\n    \
             crate::repo::get_tool_path(\"ZETA_WIDGET_BIN\", \"zeta-widget\")\n\
             }\n",
            "fake/module.rs",
            "ZETA_WIDGET_BIN",
            "zeta-widget",
            "ZETA_WIDGET",
        );
    }

    /// A source with the deriving constant-driven form at a code line
    /// fires the shield. `should_panic(expected = ...)` pins the
    /// substituted `module_path` / `bare` / `env_var` tokens plus the
    /// canonical two-arg remediation phrase; a message rewrite that
    /// dropped any of them would surface here.
    #[test]
    #[should_panic(
        expected = "fake/module.rs must not resolve `zeta-widget` via the pre-lift deriving one-arg constant-driven form at any code line — a `ZETA_WIDGET_BIN`-literal audit would miss the site. Use the two-arg `crate::repo::get_tool_path(\"ZETA_WIDGET_BIN\", \"zeta-widget\")` form"
    )]
    fn test_assert_source_forbids_deriving_one_arg_sigil_constant_form_panics_on_deriving_shape() {
        assert_source_forbids_deriving_one_arg_sigil_constant_form(
            "fn zeta_bin() -> String {\n    \
             crate::tools::get_tool_path(crate::tools::tools::ZETA_WIDGET)\n\
             }\n",
            "fake/module.rs",
            "ZETA_WIDGET_BIN",
            "zeta-widget",
            "ZETA_WIDGET",
        );
    }

    /// A source that mentions the deriving constant-driven form ONLY
    /// inside a `///` docstring (with no code-line occurrence) passes
    /// cleanly — the docstring-filter property the code-line filter
    /// exists to preserve. Pinning this is what lets the top-of-module
    /// docstrings at `commands/local.rs:23`, `commands/infra.rs:23`,
    /// and `commands/prerelease.rs:66` (which each narrate the
    /// anti-pattern verbatim) continue to live where they belong
    /// without forcing the shields to author around them.
    #[test]
    fn test_assert_source_forbids_deriving_one_arg_sigil_constant_form_accepts_docstring_only_match(
    ) {
        assert_source_forbids_deriving_one_arg_sigil_constant_form(
            "/// pre-lift the sigil delegated via \
             `crate::tools::get_tool_path(crate::tools::tools::ZETA_WIDGET)` \
             which hid the ZETA_WIDGET_BIN override\n\
             fn zeta_bin() -> String { String::new() }\n",
            "fake/module.rs",
            "ZETA_WIDGET_BIN",
            "zeta-widget",
            "ZETA_WIDGET",
        );
    }

    /// A source with no deriving literal-string form passes cleanly.
    /// Sibling happy-path pin to
    /// [`test_assert_source_forbids_deriving_one_arg_sigil_constant_form_accepts_shape_free_source`].
    #[test]
    fn test_assert_source_forbids_deriving_one_arg_sigil_literal_form_accepts_shape_free_source() {
        assert_source_forbids_deriving_one_arg_sigil_literal_form(
            "fn zeta_bin() -> String {\n    \
             crate::repo::get_tool_path(\"ZETA_WIDGET_BIN\", \"zeta-widget\")\n\
             }\n",
            "fake/module.rs",
            "ZETA_WIDGET_BIN",
            "zeta-widget",
        );
    }

    /// A source with the deriving literal-string form at a code line
    /// fires the shield. Sibling panic-path pin to
    /// [`test_assert_source_forbids_deriving_one_arg_sigil_constant_form_panics_on_deriving_shape`].
    #[test]
    #[should_panic(
        expected = "fake/module.rs must not resolve `zeta-widget` via the pre-lift deriving one-arg literal-string form at any code line — a `ZETA_WIDGET_BIN`-literal audit would miss the site. Use the two-arg `crate::repo::get_tool_path(\"ZETA_WIDGET_BIN\", \"zeta-widget\")` form"
    )]
    fn test_assert_source_forbids_deriving_one_arg_sigil_literal_form_panics_on_deriving_shape() {
        assert_source_forbids_deriving_one_arg_sigil_literal_form(
            "fn zeta_bin() -> String {\n    \
             crate::tools::get_tool_path(\"zeta-widget\")\n\
             }\n",
            "fake/module.rs",
            "ZETA_WIDGET_BIN",
            "zeta-widget",
        );
    }

    /// A source that mentions the deriving literal-string form ONLY
    /// inside a `///` docstring passes cleanly — sibling docstring-
    /// filter pin to
    /// [`test_assert_source_forbids_deriving_one_arg_sigil_constant_form_accepts_docstring_only_match`].
    #[test]
    fn test_assert_source_forbids_deriving_one_arg_sigil_literal_form_accepts_docstring_only_match()
    {
        assert_source_forbids_deriving_one_arg_sigil_literal_form(
            "/// pre-lift the sigil delegated via \
             `crate::tools::get_tool_path(\"zeta-widget\")` which hid \
             the ZETA_WIDGET_BIN override\n\
             fn zeta_bin() -> String { String::new() }\n",
            "fake/module.rs",
            "ZETA_WIDGET_BIN",
            "zeta-widget",
        );
    }

    /// The suffix-form needle constructor emits the exact
    /// `get_tool_path("<BIN>", "<bare>")` substituted form the eleven
    /// consumer sigil shields consume verbatim via
    /// `code_line_hits(SOURCE, &needle)`. A template drift (a stray
    /// space, dropped double colon, quote rewrite) would silently
    /// disarm every migrated shield. Distinct sibling cases pin that
    /// both substitution positions are load-bearing — a template that
    /// discarded either would collapse the pair to the same string.
    #[test]
    fn test_get_tool_path_two_arg_call_needle_reconstructs_substituted_form() {
        assert_eq!(
            get_tool_path_two_arg_call_needle("GH_BIN", "gh"),
            "get_tool_path(\"GH_BIN\", \"gh\")".to_string(),
        );
        assert_eq!(
            get_tool_path_two_arg_call_needle("SEA_ORM_CLI_BIN", "sea-orm-cli"),
            "get_tool_path(\"SEA_ORM_CLI_BIN\", \"sea-orm-cli\")".to_string(),
        );
        assert_eq!(
            get_tool_path_two_arg_call_needle("ZETA_WIDGET_BIN", "zeta-widget"),
            "get_tool_path(\"ZETA_WIDGET_BIN\", \"zeta-widget\")".to_string(),
        );
    }

    /// A source with the canonical suffix-form call at a code line
    /// passes cleanly under either spelling — fully-qualified (with
    /// the `crate::repo::` prefix) or `use`-imported unqualified.
    /// Pinning both the acceptance-with-prefix and
    /// acceptance-without-prefix paths is the floor every migrated
    /// shield consumes: the eleven consumer sites partition into these
    /// two spellings and both must satisfy the shield. The bare
    /// `zeta-widget` is deliberately distinct from every real shield's
    /// `bare` so a Grep of the crate for `zeta-widget` resolves to
    /// this test's family — a fast way to find the pinning tests when
    /// editing the helper.
    #[test]
    fn test_assert_source_has_get_tool_path_two_arg_call_code_line_accepts_qualified_call() {
        assert_source_has_get_tool_path_two_arg_call_code_line(
            "fn regen() {\n    \
             let bin = crate::repo::get_tool_path(\"ZETA_WIDGET_BIN\", \"zeta-widget\");\n\
             }\n",
            "fake/module.rs",
            "ZETA_WIDGET_BIN",
            "zeta-widget",
        );
    }

    /// Sibling pin to
    /// [`test_assert_source_has_get_tool_path_two_arg_call_code_line_accepts_qualified_call`]
    /// — the `use crate::repo::get_tool_path;`-imported unqualified
    /// call form ALSO satisfies the shield, so consumer sites that
    /// import the sigil at the top of the module (the pattern eight
    /// of the eleven pre-lift shields protect against a regression on)
    /// need not spell the `crate::repo::` prefix at every call site.
    #[test]
    fn test_assert_source_has_get_tool_path_two_arg_call_code_line_accepts_unqualified_call() {
        assert_source_has_get_tool_path_two_arg_call_code_line(
            "use crate::repo::get_tool_path;\n\
             fn regen() {\n    \
             let bin = get_tool_path(\"ZETA_WIDGET_BIN\", \"zeta-widget\");\n\
             }\n",
            "fake/module.rs",
            "ZETA_WIDGET_BIN",
            "zeta-widget",
        );
    }

    /// A source that mentions the canonical form ONLY inside a `///`
    /// docstring (with no code-line occurrence) fires the shield —
    /// the docstring-self-match defect the code-line filter exists to
    /// close. Pins the load-bearing correctness property named in the
    /// helper's docs: the pre-lift `SOURCE.contains(&needle)` shield
    /// silently passed on this exact input class in five production
    /// shields on `main` (`commands/sync.rs`, `commands/tool.rs`,
    /// `commands/pangea.rs`, `commands/search_sync.rs`,
    /// `commands/typescript.rs`), any of which quoted the canonical
    /// form in a `///` block that the naive substring shield matched.
    /// A future refactor that dropped the code-line filter would break
    /// this test before shipping and re-open the silent-pass
    /// regression class.
    #[test]
    #[should_panic(
        expected = "fake/module.rs must resolve `zeta-widget` via the canonical two-arg `get_tool_path(\"ZETA_WIDGET_BIN\", \"zeta-widget\")` call at a *code* line"
    )]
    fn test_assert_source_has_get_tool_path_two_arg_call_code_line_rejects_docstring_only_match() {
        assert_source_has_get_tool_path_two_arg_call_code_line(
            "/// consumer resolves via `get_tool_path(\"ZETA_WIDGET_BIN\", \"zeta-widget\")` — narrated\n\
             fn regen() { }\n",
            "fake/module.rs",
            "ZETA_WIDGET_BIN",
            "zeta-widget",
        );
    }

    /// A source that omits the canonical form entirely fires the shield
    /// — the plain missing-sigil regression class. Sibling pin to
    /// [`test_assert_source_has_get_tool_path_two_arg_call_code_line_rejects_docstring_only_match`]:
    /// the two together certify both failure modes (docstring-only and
    /// missing-outright) trigger the same diagnostic. The
    /// substring-pinned `env_var` / `bare` / `module_path` tokens in
    /// the `should_panic(expected = ...)` payload guarantee a message
    /// rewrite that dropped any of them would surface here.
    #[test]
    #[should_panic(
        expected = "fake/module.rs must resolve `zeta-widget` via the canonical two-arg `get_tool_path(\"ZETA_WIDGET_BIN\", \"zeta-widget\")` call at a *code* line"
    )]
    fn test_assert_source_has_get_tool_path_two_arg_call_code_line_rejects_missing_form() {
        assert_source_has_get_tool_path_two_arg_call_code_line(
            "fn regen() { let _ = 0; }\n",
            "fake/module.rs",
            "ZETA_WIDGET_BIN",
            "zeta-widget",
        );
    }

    /// The sigil-definition needle constructor emits the exact
    /// `fn <tool_bin_name>()` substituted form the fifteen migrated
    /// shields consume verbatim via `code_line_hits(SOURCE, &needle)`.
    /// A template drift (a stray space, a missing paren, a `pub`
    /// prefix baked into the template) would silently disarm every
    /// migrated shield. Distinct sibling cases pin that the sigil-name
    /// position is load-bearing — a template that discarded it would
    /// collapse the fifteen shields to a single string.
    #[test]
    fn test_sigil_bin_fn_definition_needle_reconstructs_substituted_form() {
        assert_eq!(
            sigil_bin_fn_definition_needle("docker_bin"),
            "fn docker_bin()".to_string(),
        );
        assert_eq!(
            sigil_bin_fn_definition_needle("cargo_bin"),
            "fn cargo_bin()".to_string(),
        );
        assert_eq!(
            sigil_bin_fn_definition_needle("zeta_widget_bin"),
            "fn zeta_widget_bin()".to_string(),
        );
    }

    /// A source with the sigil-definition line at a *code* line passes
    /// cleanly. Pinning the code-line acceptance path is the floor
    /// every migrated shield consumes: absent any regression, the
    /// helper is silent. The `zeta_widget_bin` sigil name is
    /// deliberately distinct from every real shield's sigil name so a
    /// Grep of the crate for `zeta_widget_bin` resolves to exactly
    /// this test's family — a fast way to find the pinning tests when
    /// editing the helper.
    #[test]
    fn test_assert_source_defines_sigil_bin_fn_code_line_accepts_code_line() {
        assert_source_defines_sigil_bin_fn_code_line(
            "fn zeta_widget_bin() -> String {\n    \
             crate::repo::get_tool_path(\"ZETA_WIDGET_BIN\", \"zeta-widget\")\n\
             }\n",
            "fake/module.rs",
            "zeta_widget_bin",
            "ZETA_WIDGET_BIN",
            "zeta-widget",
        );
    }

    /// A source that mentions the sigil-definition signature ONLY
    /// inside a `///` docstring (with no code-line occurrence) fires
    /// the shield — the docstring-self-match defect the code-line
    /// filter exists to close. Pins the load-bearing correctness
    /// property named in the helper's docs: a naive
    /// `SOURCE.contains("fn <tool>_bin()")` shield would silently pass
    /// on this exact input class whenever a module's docstring or
    /// sibling shield's panic-message prose quotes the sigil
    /// signature. A future refactor that dropped the code-line filter
    /// (say, going back to a naive substring shield) would break this
    /// test before shipping and re-open the silent-pass regression
    /// class.
    ///
    /// `should_panic(expected = ...)` matches on a substring of the
    /// panic payload; the substring pins the substituted
    /// `module_path` / `tool_bin_name` / `env_var` / `bare` tokens in
    /// the diagnostic so a message rewrite that dropped any of them
    /// would surface here.
    #[test]
    #[should_panic(
        expected = "fake/module.rs must define `zeta_widget_bin()` at a code line — the sigil function that resolves the `ZETA_WIDGET_BIN` override for every zeta-widget spawn."
    )]
    fn test_assert_source_defines_sigil_bin_fn_code_line_rejects_docstring_only_match() {
        assert_source_defines_sigil_bin_fn_code_line(
            "/// The `fn zeta_widget_bin()` sigil resolves the override\n\
             fn other() -> String { String::new() }\n",
            "fake/module.rs",
            "zeta_widget_bin",
            "ZETA_WIDGET_BIN",
            "zeta-widget",
        );
    }

    /// A source that omits the sigil-definition line entirely fires
    /// the shield — the plain missing-sigil regression class. Sibling
    /// pin to
    /// [`test_assert_source_defines_sigil_bin_fn_code_line_rejects_docstring_only_match`]:
    /// the two together certify both failure modes (docstring-only and
    /// missing-outright) trigger the same diagnostic.
    #[test]
    #[should_panic(expected = "fake/module.rs must define `zeta_widget_bin()` at a code line")]
    fn test_assert_source_defines_sigil_bin_fn_code_line_rejects_missing_definition() {
        assert_source_defines_sigil_bin_fn_code_line(
            "fn other() -> String { String::new() }\n",
            "fake/module.rs",
            "zeta_widget_bin",
            "ZETA_WIDGET_BIN",
            "zeta-widget",
        );
    }

    /// The constructor-call needle constructor emits the exact
    /// `<constructor_name>()` substituted form the eight migrated
    /// shields consume verbatim via `code_line_hits(SOURCE, &needle)`.
    /// A template drift (a stray space, dropped paren, an extra `!`
    /// baked into the template) would silently disarm every migrated
    /// shield. Distinct sibling cases pin that the constructor-name
    /// position is load-bearing — a template that discarded it would
    /// collapse the eight shields to a single string.
    #[test]
    fn test_constructor_call_needle_reconstructs_substituted_form() {
        assert_eq!(
            constructor_call_needle("git_command_sync"),
            "git_command_sync()".to_string(),
        );
        assert_eq!(
            constructor_call_needle("kubectl_command_async"),
            "kubectl_command_async()".to_string(),
        );
        assert_eq!(
            constructor_call_needle("zeta_widget_ctor"),
            "zeta_widget_ctor()".to_string(),
        );
    }

    /// A source with the constructor call at a *code* line passes
    /// cleanly. Pinning the code-line acceptance path is the floor
    /// every migrated shield consumes: absent any regression, the
    /// helper is silent. The `zeta_widget_ctor` name is deliberately
    /// distinct from every real shield's constructor so a Grep of the
    /// crate for `zeta_widget_ctor` resolves to exactly this test's
    /// family — a fast way to find the pinning tests when editing the
    /// helper.
    #[test]
    fn test_assert_source_delegates_via_constructor_call_code_line_accepts_code_line() {
        assert_source_delegates_via_constructor_call_code_line(
            "fn regen() { let cmd = zeta_widget_ctor(); }\n",
            "fake/module.rs",
            "zeta-widget",
            "zeta_widget_ctor",
        );
    }

    /// A source with the fully-qualified call form at a code line ALSO
    /// satisfies the shield — the substring semantics catch both the
    /// imported-alias short form (`zeta_widget_ctor()`) and the
    /// fully-qualified form (`crate::infra::zeta_widget_ctor()`) with
    /// one needle. Pinning this is the load-bearing property that lets
    /// the four `git_command_sync` shields consume `"git_command_sync"`
    /// (short) while `commands/attestation.rs`'s sole call site
    /// (`crate::git::git_command_sync()`) still satisfies the shield.
    #[test]
    fn test_assert_source_delegates_via_constructor_call_code_line_accepts_qualified_call() {
        assert_source_delegates_via_constructor_call_code_line(
            "fn regen() { let cmd = crate::infra::zeta_widget_ctor(); }\n",
            "fake/module.rs",
            "zeta-widget",
            "zeta_widget_ctor",
        );
    }

    /// A source that mentions the constructor-call form ONLY inside a
    /// `///` docstring (with no code-line occurrence) fires the shield
    /// — the docstring-self-match defect the code-line filter exists
    /// to close. Pins the load-bearing correctness property named in
    /// the helper's docs: a naive `SOURCE.contains("<constructor>()")`
    /// shield would silently pass on this exact input class whenever a
    /// module's docstring quotes the constructor call verbatim. A
    /// future refactor that dropped the code-line filter would break
    /// this test before shipping and re-open the silent-pass
    /// regression class.
    ///
    /// `should_panic(expected = ...)` matches on a substring of the
    /// panic payload; the substring pins the substituted `module_path`
    /// / `bare` / `constructor_name` tokens in the diagnostic so a
    /// message rewrite that dropped any of them would surface here.
    #[test]
    #[should_panic(
        expected = "fake/module.rs must resolve the `zeta-widget` binary via the canonical `zeta_widget_ctor()` constructor call at a *code* line"
    )]
    fn test_assert_source_delegates_via_constructor_call_code_line_rejects_docstring_only_match() {
        assert_source_delegates_via_constructor_call_code_line(
            "/// production sites delegate via `zeta_widget_ctor()` — narrated\n\
             fn regen() { let _ = 0; }\n",
            "fake/module.rs",
            "zeta-widget",
            "zeta_widget_ctor",
        );
    }

    /// A source that omits the constructor-call form entirely fires
    /// the shield — the plain missing-call regression class. Sibling
    /// pin to
    /// [`test_assert_source_delegates_via_constructor_call_code_line_rejects_docstring_only_match`]:
    /// the two together certify both failure modes (docstring-only and
    /// missing-outright) trigger the same diagnostic including the
    /// PATH-fallback tail.
    #[test]
    #[should_panic(
        expected = "the required call form was not found in the module. A regression here would silently downgrade to the PATH fallback."
    )]
    fn test_assert_source_delegates_via_constructor_call_code_line_rejects_missing_call() {
        assert_source_delegates_via_constructor_call_code_line(
            "fn regen() { let _ = 0; }\n",
            "fake/module.rs",
            "zeta-widget",
            "zeta_widget_ctor",
        );
    }

    /// The `which::which("<bare>")` probe-needle constructor emits the
    /// exact substituted form the three migrated shields consume
    /// verbatim via `code_line_hits(SOURCE, &needle)`. A template drift
    /// (a stray space, dropped paren, an extra `!` baked into the
    /// template) would silently disarm every migrated shield. Distinct
    /// sibling cases pin that the bare-tool position is load-bearing —
    /// a template that discarded it would collapse the three shields
    /// to a single string.
    #[test]
    fn test_which_which_probe_needle_reconstructs_substituted_form() {
        assert_eq!(
            which_which_probe_needle("novasearchctl"),
            "which::which(\"novasearchctl\")".to_string(),
        );
        assert_eq!(
            which_which_probe_needle("docker"),
            "which::which(\"docker\")".to_string(),
        );
        assert_eq!(
            which_which_probe_needle("sea-orm-cli"),
            "which::which(\"sea-orm-cli\")".to_string(),
        );
        assert_eq!(
            which_which_probe_needle("zeta-widget"),
            "which::which(\"zeta-widget\")".to_string(),
        );
    }

    /// A source with the `which::which("<bare>")` probe at a *code*
    /// line passes cleanly. Pinning the code-line acceptance path is
    /// the floor every migrated shield consumes: absent any
    /// regression, the helper is silent. The `zeta-widget` bare is
    /// deliberately distinct from every real shield's `bare` so a
    /// Grep of the crate for `zeta-widget` resolves to exactly this
    /// test's family — a fast way to find the pinning tests when
    /// editing the helper.
    #[test]
    fn test_assert_source_probes_via_which_which_code_line_accepts_code_line() {
        assert_source_probes_via_which_which_code_line(
            "fn probe() -> bool { which::which(\"zeta-widget\").is_ok() }\n",
            "fake/module.rs",
            "zeta-widget",
        );
    }

    /// A source that mentions the `which::which("<bare>")` form ONLY
    /// inside a `///` docstring (with no code-line occurrence) fires
    /// the shield — the docstring-self-match defect the code-line
    /// filter exists to close. Pins the load-bearing correctness
    /// property named in the helper's docs: a naive
    /// `SOURCE.contains("which::which(\"<bare>\")")` shield would
    /// silently pass on this exact input class whenever a module's
    /// docstring (or the shield's own inline panic-message prose)
    /// quotes the concrete probe form verbatim. A future refactor
    /// that dropped the code-line filter would break this test before
    /// shipping and re-open the silent-pass regression class the
    /// three migrated shields carried pre-lift.
    ///
    /// `should_panic(expected = ...)` matches on a substring of the
    /// panic payload; the substring pins the substituted `module_path`
    /// / `bare` tokens in the diagnostic so a message rewrite that
    /// dropped any of them would surface here.
    #[test]
    #[should_panic(
        expected = "fake/module.rs must probe the `zeta-widget` binary via the canonical `which::which(\"zeta-widget\")` in-process crate call at a *code* line"
    )]
    fn test_assert_source_probes_via_which_which_code_line_rejects_docstring_only_match() {
        assert_source_probes_via_which_which_code_line(
            "/// production sites probe via `which::which(\"zeta-widget\")` — narrated\n\
             fn probe() -> bool { false }\n",
            "fake/module.rs",
            "zeta-widget",
        );
    }

    /// A source that omits the `which::which("<bare>")` probe entirely
    /// fires the shield — the plain missing-probe regression class.
    /// Sibling pin to
    /// [`test_assert_source_probes_via_which_which_code_line_rejects_docstring_only_match`]:
    /// the two together certify both failure modes (docstring-only
    /// and missing-outright) trigger the same diagnostic including the
    /// subprocess-downgrade remediation tail.
    #[test]
    #[should_panic(
        expected = "the required call form was not found in the module. A regression here would silently downgrade to a subprocess `Command::new(\"zeta-widget\")` spawn"
    )]
    fn test_assert_source_probes_via_which_which_code_line_rejects_missing_probe() {
        assert_source_probes_via_which_which_code_line(
            "fn probe() -> bool { false }\n",
            "fake/module.rs",
            "zeta-widget",
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

    /// [`named_scratch_dir`] hands back a real, existing directory the
    /// caller can `write` / `create_dir_all` under immediately. Floor
    /// for every consumer in `commands/migration_validation.rs::tests`:
    /// a regression that returned a `TempDir` whose backing directory
    /// had already been unlinked (or was never created) would surface
    /// here as a `Path::is_dir() == false`, not as a confusing `ENOENT`
    /// from the FIRST `std::fs::write` call inside a consumer test.
    #[test]
    fn test_named_scratch_dir_returns_existing_directory() {
        let guard = named_scratch_dir("floor-existing");
        let path = guard.path();
        assert!(path.exists(), "scratch dir must exist on disk: {path:?}");
        assert!(path.is_dir(), "scratch dir must be a directory: {path:?}");
        // A canary write proves the dir is writable in the same call, closing
        // the "dir exists but is read-only" trap a Unix chmod drift would open.
        std::fs::write(path.join("canary"), b"ok").expect("write inside scratch");
        assert_eq!(
            std::fs::read(path.join("canary")).expect("read canary"),
            b"ok"
        );
    }

    /// The caller-supplied `prefix` is embedded at the start of the
    /// created directory's basename — `tempfile::Builder::prefix` is
    /// the exact primitive backing the helper, and it appends the
    /// OS-unique suffix AFTER the prefix. Pinning this is what
    /// preserves the "descriptive name at debug time" carve-out the
    /// pre-lift `std::env::temp_dir().join("test_manifest_missing")`
    /// stanza carried: an operator dumping `ls /tmp` after a failing
    /// test can still trace the tempdir back to which test wrote it.
    /// A future drift that dropped the `.prefix(...)` slot (say a
    /// migration onto bare `tempfile::tempdir()`) would fail HERE.
    #[test]
    fn test_named_scratch_dir_embeds_prefix_in_basename() {
        let guard = named_scratch_dir("audit-me");
        let basename = guard
            .path()
            .file_name()
            .and_then(|s| s.to_str())
            .expect("basename utf-8");
        assert!(
            basename.starts_with("audit-me"),
            "basename must start with the prefix, got: {basename}"
        );
        // The unique-suffix half: the basename must be strictly LONGER than
        // the prefix (else two concurrent calls with the same prefix would
        // collide on identical paths, defeating the "no fixed-name race"
        // carve-out that motivated the lift).
        assert!(
            basename.len() > "audit-me".len(),
            "basename must include a unique suffix beyond the prefix, got: {basename}"
        );
    }

    /// Two concurrent (or sequential) calls with the SAME prefix return
    /// strictly-distinct paths — `tempfile::Builder::prefix(...).tempdir()`
    /// is backed by `mkdtemp(3)` on Unix, which guarantees an
    /// OS-unique suffix per call. Pinning this closes the fixed-name
    /// race the pre-lift `std::env::temp_dir().join("<fixed>")` shape
    /// carried: two parallel `cargo test` runs (or two matrix jobs on
    /// a shared self-hosted runner) with the same test binary would
    /// pre-clean-and-recreate the same subdir and interleave writes
    /// / deletes under it. Post-lift the paths are strictly-distinct
    /// by construction, so collision is impossible regardless of how
    /// many concurrent callers name the same prefix.
    #[test]
    fn test_named_scratch_dir_two_calls_same_prefix_return_distinct_paths() {
        let a = named_scratch_dir("dup-prefix");
        let b = named_scratch_dir("dup-prefix");
        assert_ne!(
            a.path(),
            b.path(),
            "two calls with the same prefix must return strictly-distinct paths"
        );
        assert!(a.path().exists() && b.path().exists());
    }

    /// When the returned `TempDir` is dropped — including through a
    /// panic in the test body — the on-disk directory AND every file
    /// underneath it are unlinked. This is the panic-safety carve-out
    /// the pre-lift stanza did NOT hold: a mid-body `assert_eq!` panic
    /// skipped the trailing `let _ = std::fs::remove_dir_all(&dir);`
    /// and leaked the state to the next run. Post-lift `Drop` is the
    /// unconditional cleanup by construction, and this test pins that
    /// contract at the type-system level rather than at prose in the
    /// helper's docstring.
    ///
    /// The nested-file assertion is load-bearing: `Drop` must remove
    /// the DIRECTORY (which requires it to be empty or use recursive
    /// removal internally), not just its own entry. A future drift
    /// onto a `TempDir` shape whose `Drop` only handled empty
    /// directories would leave `payload` orphaned; the shape
    /// `tempfile::TempDir` already contracts is recursive-remove per
    /// `Drop`, and this test pins forge's dependence on that contract.
    #[test]
    fn test_named_scratch_dir_drop_removes_directory_and_contents() {
        let path = {
            let guard = named_scratch_dir("drop-cleanup");
            let path = guard.path().to_path_buf();
            std::fs::write(path.join("payload"), b"contents")
                .expect("write payload inside scratch");
            assert!(path.join("payload").exists());
            drop(guard);
            path
        };
        assert!(
            !path.exists(),
            "scratch dir must be unlinked after TempDir drops, but still exists at: {path:?}"
        );
    }

    /// `commands/migration_validation.rs::tests` migrated ten pre-lift
    /// scratch-dir sites onto this primitive; a future edit that
    /// silently deleted the primitive (or renamed it without updating
    /// consumers) would break every consumer test. This pins the
    /// primitive's continued existence at the top of the module's
    /// export surface so a rename lands in one place with a compile
    /// error at the consumer, not as a mystery test breakage.
    #[test]
    fn test_named_scratch_dir_is_reachable_from_test_support_root() {
        // The mere fact that this test compiles proves the primitive is
        // reachable via `crate::test_support::named_scratch_dir` — the
        // consumer path the shield in `commands/migration_validation.rs`
        // pins. Invocation here is the runtime half.
        let _guard = crate::test_support::named_scratch_dir("reachability");
    }

    // ---------------------------------------------------------------
    // ArgvLog — RAII per-test argv-log scratch primitive.
    //
    // Consolidates the four `#[cfg(unix)]` argv-shim stanzas across
    // `infrastructure/docker.rs` and `infrastructure/kubectl.rs` that
    // hand-rolled the same three-line reservation + POSIX-sh shim
    // body + read-back triple. See the primitive's docstring for
    // the pre-lift catalog and the disciplines it centralizes.
    // ---------------------------------------------------------------

    /// The reserved path's basename is exactly `argv.log`, with no
    /// suffix appended and no extra path components inserted. Pins
    /// the file-name contract the four consumer sites depend on for
    /// their `read_argv_log` reads and the shim script's write
    /// target — a future drift that quietly renamed the log to
    /// `argv.log.tmp` (or dropped the extension) would surface here
    /// instead of as a mysterious "empty argv" downstream.
    #[test]
    fn test_argv_log_path_basename_is_argv_log() {
        let argv_log = ArgvLog::reserve();
        assert_eq!(
            argv_log.path().file_name().and_then(|n| n.to_str()),
            Some("argv.log"),
            "argv log path must end in `argv.log`, got {:?}",
            argv_log.path(),
        );
    }

    /// A freshly-reserved argv log points at a nonexistent file:
    /// the tempdir exists, but the `argv.log` inside it hasn't been
    /// created yet — the shim script's first `printf … >>` call is
    /// what creates it. Consumers that read the log before running
    /// the shim would see this contract violated and get a
    /// "no such file" error rather than an empty read.
    #[test]
    fn test_argv_log_reserve_returns_fresh_nonexistent_path() {
        let argv_log = ArgvLog::reserve();
        assert!(
            !argv_log.path().exists(),
            "argv.log must not exist until the shim writes to it, but \
             already exists at {:?}",
            argv_log.path(),
        );
        assert!(
            argv_log
                .path()
                .parent()
                .expect("argv.log has a parent dir")
                .exists(),
            "argv.log's parent tempdir must exist so `>>` from the shim \
             succeeds without a `mkdir -p`",
        );
    }

    /// Two independent `reserve()` calls return strictly-distinct
    /// paths — the `tempfile::tempdir()`-backed `mkdtemp(3)` unique
    /// suffix is the discipline the primitive carries by
    /// construction. Two concurrent test threads cannot alias one
    /// on-disk `argv.log` and race each other's argv writes.
    #[test]
    fn test_argv_log_reserve_returns_distinct_paths_on_each_call() {
        let a = ArgvLog::reserve();
        let b = ArgvLog::reserve();
        assert_ne!(
            a.path(),
            b.path(),
            "two ArgvLog::reserve() calls must return distinct paths so \
             concurrent test threads cannot race on one argv.log; got \
             {:?} vs {:?}",
            a.path(),
            b.path(),
        );
    }

    /// End-to-end: `shim_body` + `make_executable_shim` + spawn
    /// round-trips every positional arg on its own line, and
    /// `read_argv_log` reads them back verbatim. This is the
    /// integration the four consumer sites depend on; pinning it
    /// here means a future refactor that changed either half (the
    /// `printf '%s\n'` format template on the write side, the
    /// `read_to_string` on the read side) breaks this test rather
    /// than manifesting as an off-by-one argv mismatch downstream.
    #[cfg(unix)]
    #[test]
    fn test_argv_log_shim_body_round_trips_args_verbatim() {
        let argv_log = ArgvLog::reserve();
        let (_dir, shim) = make_executable_shim("probe", &argv_log.shim_body("payload"));

        let out = std::process::Command::new(&shim)
            .args(["alpha", "beta", "gamma"])
            .output()
            .expect("spawn argv-log probe shim");
        assert!(out.status.success(), "shim exit was non-zero: {out:?}");
        assert_eq!(String::from_utf8_lossy(&out.stdout), "payload");

        let logged = argv_log.read_argv_log();
        let lines: Vec<&str> = logged.lines().collect();
        assert_eq!(lines, vec!["alpha", "beta", "gamma"]);
    }

    /// `printf '%s\n'` — not `echo` — is what makes the argv log
    /// preserve a `-n` positional arg verbatim; `echo -n` on most
    /// POSIX shells writes NOTHING (interpreting `-n` as its
    /// no-trailing-newline flag), so a hand-rolled shim body that
    /// reached for `echo "$a"` would silently drop `-n` args and a
    /// consumer's argv assertion would see a missing element with
    /// no clue why. This test pins the `printf` discipline every
    /// pre-lift site called out in prose above its hand-rolled body.
    #[cfg(unix)]
    #[test]
    fn test_argv_log_shim_body_preserves_dash_n_positional_arg() {
        let argv_log = ArgvLog::reserve();
        let (_dir, shim) = make_executable_shim("probe", &argv_log.shim_body("ok"));

        let out = std::process::Command::new(&shim)
            .args(["-n", "value"])
            .output()
            .expect("spawn dash-n probe shim");
        assert!(out.status.success());

        let logged = argv_log.read_argv_log();
        let lines: Vec<&str> = logged.lines().collect();
        assert_eq!(
            lines,
            vec!["-n", "value"],
            "shim body must preserve `-n` as a positional arg; if this \
             regression lands, the shim reached for `echo` and POSIX sh \
             swallowed the flag",
        );
    }

    /// `ArgvLog::Drop` unlinks the tempdir and the `argv.log` file
    /// inside it — the guard's lifetime is the log's lifetime by
    /// construction. Same RAII discipline as `named_scratch_dir`
    /// and `hermetic_scratch_file`; a `let _ = ArgvLog::reserve();`
    /// binding that drops the guard immediately is a type-visible
    /// defect at review, and any subsequent read of the returned
    /// path reproducibly fails with `ENOENT`.
    #[test]
    fn test_argv_log_drop_unlinks_the_file() {
        let (path, parent) = {
            let argv_log = ArgvLog::reserve();
            std::fs::write(argv_log.path(), b"seed").expect("write seed argv");
            assert!(argv_log.path().exists());
            let parent = argv_log
                .path()
                .parent()
                .expect("argv.log has a parent dir")
                .to_path_buf();
            (argv_log.path().to_path_buf(), parent)
        };
        assert!(
            !path.exists(),
            "argv.log must be unlinked after ArgvLog drops, but still \
             exists at {path:?}",
        );
        assert!(
            !parent.exists(),
            "parent tempdir must be unlinked after ArgvLog drops, but \
             still exists at {parent:?}",
        );
    }

    /// `printf_only_shim` writes the payload to stdout **with no
    /// trailing newline** — the load-bearing distinction from a naive
    /// `echo`-based shim. Every one of the six pre-lift consumer
    /// sites depended on this: the downstream classifier (`docker
    /// images -q` output, kubectl jsonpath output) is fed into a
    /// `.trim()`-then-decode chain that treats a trailing `\n` as
    /// benign, but the argv-passes-canonical test suites elsewhere
    /// pin the no-newline shape. A future edit that swapped `printf
    /// '%s'` for `echo` would silently drift the emitted byte-string
    /// by one `\n` and break this test rather than round-trip through
    /// the six classifier callers as a slow-to-diagnose off-by-one
    /// on trailing whitespace.
    #[cfg(unix)]
    #[test]
    fn test_printf_only_shim_writes_payload_with_no_trailing_newline() {
        let (_dir, shim) = printf_only_shim("probe", "no-newline");
        let out = Command::new(&shim)
            .output()
            .expect("spawn printf-only shim");
        assert!(out.status.success(), "shim exit was non-zero: {out:?}");
        assert_eq!(
            out.stdout, b"no-newline",
            "shim stdout must be the payload verbatim with NO trailing \
             newline; if the trailing `\\n` reappeared, the primitive \
             reached for `echo` (which appends `\\n` unless given `-n`) \
             and the six classifier consumers now silently ship one byte \
             extra through their `.trim()` chain",
        );
    }

    /// `printf_only_shim` IGNORES every positional argument the shim
    /// receives. Pre-lift each consumer's happy-path test spawned
    /// its classifier under a distinct argv slice (`images -q
    /// my-image` / `get secret name -n ns -o jsonpath=...` / `get
    /// pods -n ns` / `get events -n my-ns --sort-by=...`) and each
    /// pinned the classifier's stdout-decoding branch, NOT the argv
    /// forwarding. That's a separate concern shielded by the
    /// `argv_log` sibling primitive.
    ///
    /// A regression that made `printf_only_shim` sensitive to argv
    /// (e.g., accidentally consuming `$1` in the shim body) would
    /// silently break every consumer whose classifier passes a
    /// specific argv slice. This test pins the "shim body ignores
    /// argv" contract independently.
    #[cfg(unix)]
    #[test]
    fn test_printf_only_shim_ignores_argv() {
        let (_dir, shim) = printf_only_shim("probe", "payload");
        let out = Command::new(&shim)
            .args(["--flag", "value", "and", "more"])
            .output()
            .expect("spawn printf-only shim with argv");
        assert!(out.status.success());
        assert_eq!(
            out.stdout,
            b"payload",
            "shim stdout must be the payload verbatim regardless of \
             positional arguments; got {:?}",
            String::from_utf8_lossy(&out.stdout),
        );
    }

    /// `printf_only_shim` SINGLE-QUOTES the payload in the emitted
    /// shim body, so a payload containing shell metacharacters (`$`,
    /// `` ` ``, `\`, `!`) is passed to `printf '%s'` verbatim rather
    /// than expanded by the shell. Pins the discipline every one of
    /// the six pre-lift sites relied on for their base64-encoded
    /// payload (base64 alphabet is metacharacter-free, but a future
    /// consumer whose payload IS a shell-quoted string would silently
    /// have `$VAR` interpolated if the primitive dropped the
    /// single-quoting).
    ///
    /// A payload containing `$HOME` reaches printf as the literal
    /// six-character string `$HOME`, not the current-user's home
    /// directory. If this test starts round-tripping the interpolated
    /// value, the primitive dropped the single quotes and the six
    /// consumers are one edit away from a payload-interpolation bug.
    #[cfg(unix)]
    #[test]
    fn test_printf_only_shim_single_quotes_payload_against_shell_expansion() {
        let (_dir, shim) = printf_only_shim("probe", "$HOME");
        let out = Command::new(&shim)
            .output()
            .expect("spawn printf-only shim with dollar-var payload");
        assert!(out.status.success());
        assert_eq!(
            out.stdout, b"$HOME",
            "payload must reach stdout as the literal six-character \
             string `$HOME`, not the interpolated home directory; if \
             this test flips, the primitive dropped the single-quoting \
             and future payloads carrying `$VAR` / backticks / `!` \
             will silently expand",
        );
    }

    /// Two independent `printf_only_shim` calls return
    /// strictly-distinct shim paths — the `tempfile::tempdir()`-backed
    /// `mkdtemp(3)` unique suffix carried by [`make_executable_shim`]
    /// is the discipline the primitive inherits by construction. Two
    /// concurrent test threads cannot alias one on-disk shim and race
    /// each other's spawns.
    #[test]
    fn test_printf_only_shim_returns_distinct_paths_on_each_call() {
        let (_dir_a, shim_a) = printf_only_shim("probe", "a");
        let (_dir_b, shim_b) = printf_only_shim("probe", "b");
        assert_ne!(
            shim_a, shim_b,
            "two printf_only_shim() calls must return distinct paths \
             so concurrent test threads cannot race on one on-disk \
             shim; got {shim_a:?} vs {shim_b:?}",
        );
    }

    /// The six `printf_only_shim` consumer tests across
    /// `infrastructure/docker.rs` and `infrastructure/kubectl.rs`,
    /// as `(module path, source, `fn <name>(` open marker)` triples.
    /// Same shape as [`ARGV_LOG_SITES`]; each entry's body is sliced
    /// from its open marker to the first top-level `\n    }\n`.
    ///
    /// Adding a seventh `printf_only_shim` consumer means adding a
    /// row here; the shield below then holds it to the same
    /// delegation contract as the six that already exist.
    const PRINTF_ONLY_SHIM_SITES: [(&str, &str, &str); 6] = [
        (
            "infrastructure/docker.rs",
            include_str!("infrastructure/docker.rs"),
            "fn test_find_first_image_id_by_name_with_bin_success_returns_trimmed_id(",
        ),
        (
            "infrastructure/docker.rs",
            include_str!("infrastructure/docker.rs"),
            "fn test_find_first_image_id_by_name_async_with_bin_success_returns_trimmed_id(",
        ),
        (
            "infrastructure/kubectl.rs",
            include_str!("infrastructure/kubectl.rs"),
            "fn test_fetch_secret_value_with_bin_success_returns_decoded_utf8(",
        ),
        (
            "infrastructure/kubectl.rs",
            include_str!("infrastructure/kubectl.rs"),
            "fn test_fetch_secret_value_with_bin_decoded_non_utf8_returns_none(",
        ),
        (
            "infrastructure/kubectl.rs",
            include_str!("infrastructure/kubectl.rs"),
            "fn test_find_first_pod_name_async_with_bin_success_returns_trimmed_name(",
        ),
        (
            "infrastructure/kubectl.rs",
            include_str!("infrastructure/kubectl.rs"),
            "fn test_kubectl_probe_stdout_capture_zero_exit_returns_lossy_stdout(",
        ),
    ];

    /// Cross-module shield: every `printf_only_shim` consumer on the
    /// `infrastructure/` tree MUST reserve its shim through
    /// [`printf_only_shim`], never a hand-rolled
    /// `make_executable_shim("<tool>", "#!/bin/sh\nprintf '%s' '…'\n")`
    /// literal (or the `format!("#!/bin/sh\nprintf '%s' '{}'\n", …)`
    /// derivation the two base64-payload sites used pre-lift).
    ///
    /// Pre-lift all six sites spelled the same shim body verbatim,
    /// varying only in the payload literal / expression — six copies
    /// of one shape past THEORY §VI.1's three-times-is-a-law
    /// threshold, each independently able to drift off:
    ///
    /// 1. `printf '%s'` (no `\n`, no `%b` escape expansion) — a
    ///    future consumer that reached for `echo` would silently add
    ///    a trailing newline.
    /// 2. The single-quoted payload — a future consumer that dropped
    ///    the single quotes would silently interpolate `$VAR` /
    ///    backticks / `!` from the shell.
    ///
    /// Positive side: the delegation call `printf_only_shim(` must
    /// appear at exactly ONE code line in each test-fn's body, so a
    /// regression that deleted the delegation cannot leave the
    /// negative scan trivially satisfied by absence.
    ///
    /// Negative side: no hand-rolled `#!/bin/sh\nprintf '%s'` shim
    /// body may appear at any code line in any test-fn's body. The
    /// needle is reconstructed at test time so this shield's own
    /// docstring prose does not false-match itself (same discipline
    /// the per-module consumer shields carry). [`code_line_hits`]
    /// additionally filters `//` / `///` / `//!` lines, so
    /// delegation comments inside each body are ignored.
    #[test]
    fn test_all_printf_only_shim_stanzas_route_through_printf_only_shim() {
        let forbidden_body = format!("{}{}{}{}", "#!/bin/", "sh\\nprintf ", "'%", "s' '");
        for (module_path, source, open_marker) in PRINTF_ONLY_SHIM_SITES {
            let body = fn_body_slice_between_markers(source, module_path, open_marker, "\n    }\n");

            let reserve_hits = code_line_hits(body, "printf_only_shim(");
            assert_eq!(
                reserve_hits.len(),
                1,
                "{module_path}'s `{open_marker}` test must delegate to \
                 `printf_only_shim(` at exactly one code line; got {} \
                 — hits: {reserve_hits:#?}",
                reserve_hits.len(),
            );

            let hand_rolled_body = code_line_hits(body, &forbidden_body);
            assert!(
                hand_rolled_body.is_empty(),
                "{module_path}'s `{open_marker}` test must NOT hand-roll \
                 its own `#!/bin/sh\\nprintf '%s' '…'` shim body — the \
                 shared primitive at `test_support::printf_only_shim` \
                 carries the no-trailing-newline and single-quoting \
                 discipline in one place; hits: {hand_rolled_body:#?}",
            );
        }
    }

    /// The four argv-shim tests across `infrastructure/docker.rs`
    /// and `infrastructure/kubectl.rs`, as `(module path, source,
    /// `fn <name>(` open marker)` triples. Each entry's body is
    /// sliced from its open marker to the first top-level `\n    }\n`
    /// — the test-fn's closing brace at its natural
    /// 4-space-indented `mod tests { ... }` depth.
    ///
    /// Adding a fifth argv-shim consumer means adding a row here;
    /// the shield below then holds it to the same delegation
    /// contract as the four that already exist.
    const ARGV_LOG_SITES: [(&str, &str, &str); 4] = [
        (
            "infrastructure/docker.rs",
            include_str!("infrastructure/docker.rs"),
            "fn test_find_first_image_id_by_name_with_bin_passes_canonical_docker_args(",
        ),
        (
            "infrastructure/kubectl.rs",
            include_str!("infrastructure/kubectl.rs"),
            "fn test_fetch_secret_value_with_bin_passes_canonical_kubectl_args(",
        ),
        (
            "infrastructure/kubectl.rs",
            include_str!("infrastructure/kubectl.rs"),
            "fn test_find_first_pod_name_async_with_bin_passes_canonical_kubectl_args(",
        ),
        (
            "infrastructure/kubectl.rs",
            include_str!("infrastructure/kubectl.rs"),
            "fn test_kubectl_probe_stdout_capture_forwards_args(",
        ),
    ];

    /// Cross-module shield: every argv-shim test on the
    /// `infrastructure/` tree MUST reserve its argv-log scratch
    /// through [`ArgvLog::reserve`] and MUST derive its POSIX-sh
    /// shim body through [`ArgvLog::shim_body`], never a hand-rolled
    /// `tempfile::tempdir()` + `.join("argv.log")` + inline
    /// `format!("#!/bin/sh…")` stanza of its own.
    ///
    /// Pre-lift all four sites spelled the same reservation +
    /// shim-body triple verbatim, varying only in the `printf
    /// '%s' '<payload>'` stdout string — four copies of one shape
    /// past THEORY §VI.1's three-times-is-a-law threshold, each
    /// independently able to drift off the `printf '%s\n'`-vs-`echo`
    /// POSIX-sh portability discipline the primitive centralizes.
    /// A fifth argv-shim test added by copying a neighbor would
    /// inherit whichever copy it happened to copy.
    ///
    /// Positive side: the delegation call `ArgvLog::reserve(` and
    /// the shim-body-derivation call `.shim_body(` must EACH appear
    /// at exactly ONE code line in each test-fn's body, so a
    /// regression that deleted the delegation cannot leave the
    /// negative scan trivially satisfied by absence.
    ///
    /// Negative side: no hand-rolled `tempfile::tempdir(` or
    /// `.join("argv.log")` call may appear at any code line in any
    /// test-fn's body. Both needles are reconstructed at test time
    /// so this shield's own docstring prose citing the pre-lift
    /// stanza does not false-match itself (same discipline the
    /// per-module consumer shields carry). [`code_line_hits`]
    /// additionally filters `//` / `///` / `//!` lines, so
    /// delegation comments inside each body are ignored.
    #[test]
    fn test_all_argv_log_shim_stanzas_route_through_argv_log_reserve() {
        let forbidden_tempdir = format!("{}::tempdir(", "tempfile");
        let forbidden_join = format!(".join({}argv.log{})", "\"", "\"");
        for (module_path, source, open_marker) in ARGV_LOG_SITES {
            let body = fn_body_slice_between_markers(source, module_path, open_marker, "\n    }\n");

            let reserve_hits = code_line_hits(body, "ArgvLog::reserve(");
            assert_eq!(
                reserve_hits.len(),
                1,
                "{module_path}'s `{open_marker}` test must delegate to \
                 `ArgvLog::reserve(` at exactly one code line; got {} \
                 — hits: {reserve_hits:#?}",
                reserve_hits.len(),
            );

            let shim_body_hits = code_line_hits(body, ".shim_body(");
            assert_eq!(
                shim_body_hits.len(),
                1,
                "{module_path}'s `{open_marker}` test must derive its \
                 shim body via `.shim_body(` at exactly one code line; \
                 got {} — hits: {shim_body_hits:#?}",
                shim_body_hits.len(),
            );

            let hand_rolled_tempdir = code_line_hits(body, &forbidden_tempdir);
            assert!(
                hand_rolled_tempdir.is_empty(),
                "{module_path}'s `{open_marker}` test must NOT hand-roll \
                 its own `tempfile::tempdir(` call — the shared primitive \
                 at `test_support::ArgvLog::reserve` carries the TMPDIR- \
                 honoring / mkdtemp-unique-suffix / Drop-unlinks discipline \
                 in one place; hits: {hand_rolled_tempdir:#?}",
            );

            let hand_rolled_join = code_line_hits(body, &forbidden_join);
            assert!(
                hand_rolled_join.is_empty(),
                "{module_path}'s `{open_marker}` test must NOT hand-roll a \
                 `.join(\"argv.log\")` call — the argv.log basename is a \
                 property of `test_support::ArgvLog`, not of each caller; \
                 hits: {hand_rolled_join:#?}",
            );
        }
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

        assert_eq!(
            read_head_subject(dir.path()),
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

        assert_eq!(
            read_head_subject(&probe),
            "seed",
            "probe-clone must resolve HEAD to the seed commit on main"
        );
    }

    /// [`make_seeded_work_and_bare_origin`] returns a parent tempdir
    /// containing exactly two sibling entries: an initialized bare at
    /// `origin.git` and an initialized work-tree at `work`, both
    /// directories. Pins the RAII layout every consumer's
    /// `parent.path().join(...)` extension (probe clones, extra
    /// scratch files) implicitly depends on — a drift that renamed
    /// or nested either half would break every consumer through the
    /// same fixture-side seam.
    #[test]
    fn test_make_seeded_work_and_bare_origin_returns_sibling_bare_and_work() {
        let (parent, bare, work) = make_seeded_work_and_bare_origin();
        assert!(bare.is_dir(), "bare must be an initialized directory");
        assert!(work.is_dir(), "work must be an initialized directory");
        assert_eq!(
            bare.parent(),
            Some(parent.path()),
            "bare must sit directly under the returned parent tempdir"
        );
        assert_eq!(
            work.parent(),
            Some(parent.path()),
            "work must sit directly under the returned parent tempdir"
        );
        assert_ne!(bare, work, "bare and work must be strictly-distinct paths");
    }

    /// [`make_seeded_work_and_bare_origin`] leaves the returned work
    /// on `main` at the canonical seed commit — inherited verbatim
    /// from [`init_repo_with_one_commit`]. Pins the post-condition
    /// every downstream consumer relies on when it invokes a
    /// production entry point that reads `HEAD` (`get_short_sha_async_in`,
    /// `read_head_sha_async`, `commit_and_push_in`'s opening
    /// `git pull origin main`).
    #[test]
    fn test_make_seeded_work_and_bare_origin_work_has_seed_commit_on_main() {
        let (_parent, _bare, work) = make_seeded_work_and_bare_origin();
        let _guard = GIT_BIN_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());

        let branch = git_command_sync()
            .args(["rev-parse", "--abbrev-ref", "HEAD"])
            .current_dir(&work)
            .output()
            .expect("git rev-parse spawn");
        assert!(branch.status.success(), "git rev-parse must succeed");
        assert_eq!(
            String::from_utf8_lossy(&branch.stdout).trim(),
            "main",
            "work must sit on `main` after the composed fixture returns"
        );
        assert_eq!(
            read_head_subject(&work),
            "seed",
            "work must carry the canonical seed commit subject on HEAD"
        );
    }

    /// [`make_seeded_work_and_bare_origin`] round-trips end-to-end:
    /// a `git push -u origin main` from work lands the seed on bare,
    /// and a subsequent probe-clone of bare resolves `HEAD` to the
    /// canonical seed subject. Pins the composed
    /// `init_repo_with_one_commit` + `add_bare_origin` invariant at
    /// the composed-fixture boundary so a drift on EITHER underlying
    /// primitive that broke the origin remote or the seed commit
    /// would fire this test — a defense-in-depth pin the four
    /// `git.rs` `commit_and_push_in` / async-SHA consumers now share
    /// through their fixture-side seam.
    #[test]
    fn test_make_seeded_work_and_bare_origin_round_trips_seed_push_then_clone() {
        let (parent, bare, work) = make_seeded_work_and_bare_origin();

        // Hold the lock across the push + clone so a concurrent
        // env-var-mutating test cannot redirect either spawn.
        let _guard = GIT_BIN_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let push = git_command_sync()
            .args(["push", "-u", "origin", "main"])
            .current_dir(&work)
            .status()
            .expect("git push spawn");
        assert!(
            push.success(),
            "seed push to composed-fixture bare origin must succeed"
        );

        let probe = parent.path().join("probe");
        let subject = clone_bare_and_read_head_subject(&bare, &probe);
        assert_eq!(
            subject, "seed",
            "probe-clone of composed-fixture bare must resolve HEAD to `seed`"
        );
    }

    /// Cross-module shield: every non-`test_support` consumer that
    /// pre-lift re-spelled the bare + work + seed + origin-remote
    /// fixture stanza inline (or as a private local fixture)
    /// MUST route through [`make_seeded_work_and_bare_origin`], and
    /// MUST NOT hand-roll its own `parent.path().join("origin.git")`
    /// stanza again.
    ///
    /// Pre-lift the three consumers spelled six copies of the same
    /// seven-line seed:
    /// - `git.rs` — one private local `make_bare_origin_with_work`
    ///   fixture (with an extra `git push -u origin main` step baked
    ///   into its body) called from four test sites (retired at this
    ///   commit).
    /// - `commands/release_commit.rs` — one inline copy in the
    ///   canonical-subject round-trip test (retired at this commit).
    /// - `commands/product_release.rs` — one inline copy in the
    ///   canonical-subject round-trip test (retired at this commit).
    ///
    /// Positive side: the delegation call `make_seeded_work_and_bare_origin(`
    /// must appear at at least ONE code line in each consumer's body,
    /// so a regression that deleted the delegation cannot leave the
    /// negative scan trivially satisfied by absence.
    ///
    /// Negative side: the load-bearing marker `parent.path().join("origin.git")`
    /// must not appear at any code line in any consumer's body — the
    /// exact string every hand-rolled copy carries, reconstructed at
    /// test time via `format!` so this shield's own docstring prose
    /// citing the pre-lift stanza does not false-match itself.
    /// `code_line_hits` additionally filters `//` / `///` / `//!`
    /// lines so any prose that quotes the pre-lift shape inside a
    /// consumer's docstring is ignored.
    ///
    /// The three `test_support.rs` self-tests
    /// (`test_add_bare_origin_round_trips_push_then_clone`,
    /// `test_clone_bare_and_read_head_subject_round_trips_seed_commit`,
    /// `test_clone_bare_and_read_head_subject_returns_trimmed_string`)
    /// intentionally stay OFF this shield's consumer list — they pin
    /// the composition ingredients ([`init_repo_with_one_commit`],
    /// [`add_bare_origin`], [`clone_bare_and_read_head_subject`]) at
    /// their own boundary rather than through the composed fixture
    /// this shield guards.
    #[test]
    fn test_all_bare_work_pair_consumers_route_through_make_seeded_work_and_bare_origin() {
        let forbidden = format!("parent.path().{}(\"origin.git\")", "join");
        const CONSUMERS: [(&str, &str); 3] = [
            ("cli/src/git.rs", include_str!("git.rs")),
            (
                "cli/src/commands/release_commit.rs",
                include_str!("commands/release_commit.rs"),
            ),
            (
                "cli/src/commands/product_release.rs",
                include_str!("commands/product_release.rs"),
            ),
        ];
        for (module_path, source) in CONSUMERS {
            let delegations = code_line_hits(source, "make_seeded_work_and_bare_origin(");
            assert!(
                !delegations.is_empty(),
                "{module_path} must delegate to `test_support::make_seeded_work_and_bare_origin(` \
                 at at least one code line — the shared primitive that consolidates the \
                 bare+work+seed+origin-remote fixture stanza; hits: {delegations:#?}",
            );

            let hand_rolled = code_line_hits(source, &forbidden);
            assert!(
                hand_rolled.is_empty(),
                "{module_path} must NOT hand-roll its own bare+work fixture stanza \
                 — the shared primitive at `test_support::make_seeded_work_and_bare_origin` \
                 carries the composed `init_repo_with_one_commit` + `add_bare_origin` \
                 discipline in one place; hits: {hand_rolled:#?}",
            );
        }
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
    /// A shape-free source that (a) omits every bare-spawn shape, (b)
    /// defines the sigil at a code line, and (c) delegates through the
    /// canonical two-arg form at a code line, passes the composed
    /// shield cleanly. Pins the happy path every migrated shield
    /// consumes: absent any regression, the helper is a no-op. The
    /// `zeta-widget` bare is deliberately distinct from every real
    /// shield's `bare` so a Grep of the crate for `zeta-widget`
    /// resolves to exactly this family of pinning tests.
    #[test]
    fn test_assert_source_routes_bare_spawn_through_two_arg_sigil_accepts_shape_free_source() {
        assert_source_routes_bare_spawn_through_two_arg_sigil(
            "fn zeta_widget_bin() -> String {\n    \
             crate::repo::get_tool_path(\"ZETA_WIDGET_BIN\", \"zeta-widget\")\n\
             }\nfn call() { let _ = zeta_widget_bin(); }\n",
            "fake/module.rs",
            "zeta-widget",
            "ZETA_WIDGET_BIN",
        );
    }

    /// A source that carries a bare `Command::new("zeta-widget")` spawn
    /// fires the composed shield's first delegated primitive
    /// ([`assert_source_forbids_bare_spawn_shapes`]) — the invariant
    /// this fusion exists to enforce. The panic message pins the
    /// substituted `bare` and the derived
    /// `remediation = "resolve \`ZETA_WIDGET_BIN\` via
    /// \`zeta_widget_bin()\`"` so a template drift in either the
    /// remediation format string or the delegation order would surface
    /// here before shipping.
    ///
    /// The `zeta-widget` fixture is spelled inline via a `concat!`
    /// split around `Command::` so this test's own source text never
    /// fuses the forbidden shape and the crate-wide spawn shield's
    /// scan across `include_str!("test_support.rs")` does not
    /// false-match this fixture.
    #[test]
    #[should_panic(
        expected = "fake/module.rs must not spawn `zeta-widget` via the bare literal — every zeta-widget spawn must resolve `ZETA_WIDGET_BIN` via `zeta_widget_bin()` first."
    )]
    fn test_assert_source_routes_bare_spawn_through_two_arg_sigil_fires_on_bare_spawn() {
        let bare_spawn = concat!("fn call() { let _ = Command::", "new(\"zeta-widget\"); }\n");
        assert_source_routes_bare_spawn_through_two_arg_sigil(
            bare_spawn,
            "fake/module.rs",
            "zeta-widget",
            "ZETA_WIDGET_BIN",
        );
    }

    /// A source that omits the sigil definition fires the composed
    /// shield's second delegated primitive
    /// ([`assert_source_defines_sigil_bin_fn_code_line`]). Pinning the
    /// missing-sigil regression class here certifies the composition
    /// delegates the sigil-definition invariant with the derived
    /// `sigil_fn = zeta_widget_bin` — a dash→underscore canonicalization
    /// regression in the helper's derivation would surface here
    /// (the fixture defines `zeta-widget_bin`, not `zeta_widget_bin`,
    /// so a helper that skipped the canonicalization would silently
    /// accept the wrong-named definition).
    #[test]
    #[should_panic(
        expected = "fake/module.rs must define `zeta_widget_bin()` at a code line — the sigil function that resolves the `ZETA_WIDGET_BIN` override for every zeta-widget spawn."
    )]
    fn test_assert_source_routes_bare_spawn_through_two_arg_sigil_fires_on_missing_sigil() {
        assert_source_routes_bare_spawn_through_two_arg_sigil(
            "fn other() -> String { String::new() }\n",
            "fake/module.rs",
            "zeta-widget",
            "ZETA_WIDGET_BIN",
        );
    }

    /// A source that defines the sigil but omits the canonical two-arg
    /// delegation fires the composed shield's third delegated primitive
    /// ([`assert_source_has_canonical_two_arg_sigil_code_line`]). Pins
    /// the sigil-body-drift class the composed shield inherits from
    /// its third delegated primitive: a sigil whose body regressed to
    /// the deriving one-arg form (`crate::tools::get_tool_path("...")`)
    /// or to a hand-rolled `env::var` lookup passes the first two
    /// invariants and fails only at the third — this test pins that
    /// the composition surfaces the third failure with its own
    /// canonical-two-arg-missing diagnostic.
    #[test]
    #[should_panic(
        expected = "fake/module.rs must delegate `zeta-widget` via the canonical two-arg `crate::repo::get_tool_path(\"ZETA_WIDGET_BIN\", \"zeta-widget\")` at a *code* line"
    )]
    fn test_assert_source_routes_bare_spawn_through_two_arg_sigil_fires_on_missing_two_arg_form() {
        assert_source_routes_bare_spawn_through_two_arg_sigil(
            "fn zeta_widget_bin() -> String { String::new() }\n\
             fn call() { let _ = zeta_widget_bin(); }\n",
            "fake/module.rs",
            "zeta-widget",
            "ZETA_WIDGET_BIN",
        );
    }

    /// The sigil-name derivation canonicalizes every `-` in `bare`
    /// into `_` before appending `_bin`, matching the underlying
    /// [`crate::tools::get_tool_path`] primitive's own
    /// dash→underscore canonicalization at the env-var surface
    /// (POSIX env-var names forbid `-`, so
    /// `POSTGRES-BOOTSTRAP_BIN` is unsettable from any shell and
    /// `postgres-bootstrap` derives `postgres_bootstrap_bin` at the
    /// shell-safe sigil surface). A regression here — a helper that
    /// dropped the `.replace('-', '_')` call — would emit a
    /// dash-bearing sigil name (`zeta-widget_bin`) that no real
    /// production sigil across the fleet ever spells, silently
    /// disarming every migrated dash-bearing shield
    /// (`commands/federation.rs::rover-fhs`, and the sibling family
    /// dash-bearing sigils listed in the helper's docstring).
    ///
    /// This test's fixture defines the *canonicalized* sigil name so
    /// the composed shield passes cleanly; the sibling
    /// [`test_assert_source_routes_bare_spawn_through_two_arg_sigil_fires_on_missing_sigil`]
    /// pins the negative side (defining the non-canonicalized name is
    /// still refused by the composed shield).
    #[test]
    fn test_assert_source_routes_bare_spawn_through_two_arg_sigil_canonicalizes_dash_to_underscore()
    {
        assert_source_routes_bare_spawn_through_two_arg_sigil(
            "fn zeta_widget_bin() -> String {\n    \
             crate::repo::get_tool_path(\"ZETA_WIDGET_BIN\", \"zeta-widget\")\n\
             }\nfn call() { let _ = zeta_widget_bin(); }\n",
            "fake/module.rs",
            "zeta-widget",
            "ZETA_WIDGET_BIN",
        );
    }

    /// `clone_bare_and_read_head_subject` round-trips the seed
    /// commit's subject line end-to-end against a hermetic
    /// `init_repo_with_one_commit` + `add_bare_origin` + `git push
    /// origin main` fixture: the returned string MUST be exactly
    /// `"seed"` (the canonical seed subject
    /// [`init_repo_with_one_commit`] commits under). Pins the
    /// composed `git clone <bare> <probe>` + `git log -1
    /// --pretty=%s` + `String::from_utf8_lossy(&stdout).trim()`
    /// shape end-to-end so a drift in either the argv slice
    /// (`--pretty=%b` instead of `%s`, `-2` instead of `-1`) or
    /// the decode (`String::from_utf8` in strict mode, forgotten
    /// `.trim()`) flips this test red before divergence can
    /// reach any of the three consumer sites.
    #[test]
    fn test_clone_bare_and_read_head_subject_round_trips_seed_commit() {
        let parent = tempfile::tempdir().expect("parent tempdir");
        let work = parent.path().join("work");
        let bare = parent.path().join("origin.git");
        std::fs::create_dir(&work).expect("mkdir work");
        std::fs::create_dir(&bare).expect("mkdir bare");
        init_repo_with_one_commit(&work);
        add_bare_origin(&work, &bare);

        // Acquire the lock AFTER the fixture returns (which released
        // its internal guard). We hold it across BOTH the push and the
        // probe so a concurrently-running shim test cannot mutate
        // `GIT_BIN` mid-round-trip.
        let _guard = GIT_BIN_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let push = git_command_sync()
            .args(["push", "-u", "origin", "main"])
            .current_dir(&work)
            .status()
            .expect("git push spawn");
        assert!(push.success(), "push to bare origin must succeed");

        let probe = parent.path().join("probe");
        let subject = clone_bare_and_read_head_subject(&bare, &probe);
        assert_eq!(
            subject, "seed",
            "round-trip must resolve HEAD's subject to the canonical seed"
        );
    }

    /// `clone_bare_and_read_head_subject` returns the TRIMMED
    /// `%s` — trailing newlines from git's output MUST NOT survive
    /// into the returned string. Pins the `.trim()` step the three
    /// consumer sites' `assert_eq!(subject, "…")` comparisons all
    /// implicitly rely on. A drift that omitted the trim would
    /// return `"seed\n"` and flip every downstream `assert_eq!`
    /// red — but at a confusing "left doesn't match right" surface
    /// rather than at this localized shape pin.
    #[test]
    fn test_clone_bare_and_read_head_subject_returns_trimmed_string() {
        let parent = tempfile::tempdir().expect("parent tempdir");
        let work = parent.path().join("work");
        let bare = parent.path().join("origin.git");
        std::fs::create_dir(&work).expect("mkdir work");
        std::fs::create_dir(&bare).expect("mkdir bare");
        init_repo_with_one_commit(&work);
        add_bare_origin(&work, &bare);

        let _guard = GIT_BIN_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let push = git_command_sync()
            .args(["push", "-u", "origin", "main"])
            .current_dir(&work)
            .status()
            .expect("git push spawn");
        assert!(push.success(), "push to bare origin must succeed");

        let probe = parent.path().join("probe");
        let subject = clone_bare_and_read_head_subject(&bare, &probe);
        assert!(
            !subject.ends_with('\n') && !subject.ends_with(' '),
            "returned subject must be right-trimmed, got {subject:?}"
        );
        assert!(
            !subject.starts_with(' '),
            "returned subject must be left-trimmed, got {subject:?}"
        );
    }

    /// `read_head_subject` round-trips the seed commit's subject
    /// line against a hermetic `init_repo_with_one_commit` fixture
    /// with no intervening clone step: the returned string MUST be
    /// exactly `"seed"` (the canonical seed subject
    /// [`init_repo_with_one_commit`] commits under). Pins the
    /// `git log -1 --pretty=%s` + `String::from_utf8_lossy(&stdout)
    /// .trim()` shape end-to-end at the primitive's OWN boundary
    /// (sibling of
    /// `test_clone_bare_and_read_head_subject_round_trips_seed_commit`,
    /// which pins the same shape but only after passing through a
    /// clone), so a drift in the argv slice (`--pretty=%b` instead
    /// of `%s`, `-2` instead of `-1`) or the decode
    /// (`String::from_utf8` in strict mode, forgotten `.trim()`)
    /// flips this test red before divergence reaches any of the
    /// three consumer sites — including the composed
    /// `clone_bare_and_read_head_subject`.
    #[test]
    fn test_read_head_subject_round_trips_seed_commit() {
        let dir = tempfile::tempdir().expect("tempdir");
        init_repo_with_one_commit(dir.path());

        // Acquire the lock AFTER the fixture returns (which released
        // its internal guard). Same caller-holds-lock discipline as
        // the two migrated test-side consumers exercise.
        let _guard = GIT_BIN_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        assert_eq!(
            read_head_subject(dir.path()),
            "seed",
            "read_head_subject must resolve HEAD's subject to the canonical seed"
        );
    }

    /// `read_head_subject` returns the TRIMMED `%s` — trailing
    /// newlines from git's output MUST NOT survive into the returned
    /// string. Pins the `.trim()` step every consumer site's
    /// `assert_eq!(subject, "…")` comparison implicitly relies on.
    /// A drift that omitted the trim would return `"seed\n"` and
    /// flip every downstream `assert_eq!` red — but at a confusing
    /// "left doesn't match right" surface rather than at this
    /// localized shape pin.
    #[test]
    fn test_read_head_subject_returns_trimmed_string() {
        let dir = tempfile::tempdir().expect("tempdir");
        init_repo_with_one_commit(dir.path());

        let _guard = GIT_BIN_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let subject = read_head_subject(dir.path());
        assert!(
            !subject.ends_with('\n') && !subject.ends_with(' '),
            "returned subject must be right-trimmed, got {subject:?}"
        );
        assert!(
            !subject.starts_with(' '),
            "returned subject must be left-trimmed, got {subject:?}"
        );
    }

    /// Sibling shield to
    /// `test_git_spawn_routes_through_git_command_sync_not_raw_literal`
    /// in `commands/release_commit.rs`, `commands/product_release.rs`,
    /// and `commands/attestation.rs`.
    #[test]
    fn test_git_spawn_routes_through_git_command_sync_not_raw_literal() {
        const SOURCE: &str = include_str!("test_support.rs");

        assert_source_forbids_bare_spawn_shapes(
            SOURCE,
            "cli/src/test_support.rs",
            "git",
            "resolve `GIT_BIN` via `crate::git::git_command_sync()`",
        );

        assert_source_delegates_via_constructor_call_code_line(
            SOURCE,
            "cli/src/test_support.rs",
            "git",
            "git_command_sync",
        );
    }

    /// Happy path for
    /// [`assert_source_routes_status_only_spawns_through_run_inherited_status_sync`]:
    /// a module body carrying no inline `.status()` terminator and
    /// enough `run_inherited_status_sync(` delegations to meet the
    /// floor passes cleanly. The `#[cfg(test)]` marker is required by
    /// the helper's cutoff scan, so the fixture carries one.
    #[test]
    fn test_assert_source_routes_status_only_spawns_through_run_inherited_status_sync_accepts_migrated_module(
    ) {
        let source = "\
            fn a() { let mut c = std::process::Command::new(\"x\"); \
             crate::retry::run_inherited_status_sync(c, \"x\").unwrap(); }\n\
            fn b() { let mut c = std::process::Command::new(\"y\"); \
             crate::retry::run_inherited_status_sync(c, \"y\").unwrap(); }\n\
            \n#[cfg(test)]\nmod tests { fn t() { panic!(\".status()\"); } }\n";
        assert_source_routes_status_only_spawns_through_run_inherited_status_sync(
            source,
            "fake/module.rs",
            2,
            "both status-only spawns",
        );
    }

    /// The negative half: an inline `.status()` terminator anywhere in
    /// the module body (above the first `#[cfg(test)]` marker) fires
    /// the shield.
    #[test]
    #[should_panic(expected = "inline `.status()` terminator")]
    fn test_assert_source_routes_status_only_spawns_through_run_inherited_status_sync_rejects_inline_status_terminator(
    ) {
        let source = "\
            fn a() { std::process::Command::new(\"x\").arg(\"probe\").status().unwrap(); }\n\
            \n#[cfg(test)]\nmod tests { }\n";
        assert_source_routes_status_only_spawns_through_run_inherited_status_sync(
            source,
            "fake/module.rs",
            0,
            "no spawns claimed",
        );
    }

    /// The positive half: a module body with too few delegations —
    /// even absent any inline `.status()` — fires the shield. This
    /// pins the "a dropped delegation cannot leave the negative scan
    /// trivially satisfied by absence" invariant the docstring cites.
    #[test]
    #[should_panic(expected = "delegation call(s)")]
    fn test_assert_source_routes_status_only_spawns_through_run_inherited_status_sync_rejects_missing_delegation(
    ) {
        let source = "\
            fn a() { let mut c = std::process::Command::new(\"x\"); \
             crate::retry::run_inherited_status_sync(c, \"x\").unwrap(); }\n\
            \n#[cfg(test)]\nmod tests { }\n";
        assert_source_routes_status_only_spawns_through_run_inherited_status_sync(
            source,
            "fake/module.rs",
            2,
            "both spawns",
        );
    }

    /// Wrapper-form pin: a call to the `(bin, args)`-front sibling
    /// [`crate::retry::run_bin_args_inherited_status_sync`] counts as
    /// a valid delegation, so a module that migrates every direct
    /// `run_inherited_status_sync(cmd, op)` call to the wrapper
    /// (`run_bin_args_inherited_status_sync(&bin, &[...], op)`) still
    /// passes the shield without the caller lowering `min_delegations`.
    /// Pre-widening the shield counted only the direct-primitive
    /// needle; a full-module lift to the wrapper would have driven the
    /// count to zero and fired the "delegation call(s)" arm even
    /// though the wrapper delegates to the same
    /// [`crate::retry::classify_inherited_status`] body. The two
    /// needles are disjoint (neither is a substring of the other), so
    /// a single call site is counted at most once across the sum.
    #[test]
    fn test_assert_source_routes_status_only_spawns_through_run_inherited_status_sync_counts_wrapper_form(
    ) {
        let source = "\
            fn a() { crate::retry::run_bin_args_inherited_status_sync(\
             &tool_bin(), &[\"probe\"], \"a\").unwrap(); }\n\
            fn b() { crate::retry::run_bin_args_inherited_status_sync(\
             &tool_bin(), &[\"probe\"], \"b\").unwrap(); }\n\
            \n#[cfg(test)]\nmod tests { }\n";
        assert_source_routes_status_only_spawns_through_run_inherited_status_sync(
            source,
            "fake/module.rs",
            2,
            "both wrapper-form spawns",
        );
    }

    /// Mixed-form pin: a module carrying a mix of direct-primitive and
    /// wrapper-form delegations sums both toward `min_delegations`. This
    /// covers the common migration state where a single wave lifts SOME
    /// of a module's status-only spawns onto the wrapper while others
    /// stay on the direct primitive (e.g. because they need
    /// `.current_dir(...)` or `.env(...)`), and the shield must still
    /// hold at the pre-migration floor.
    #[test]
    fn test_assert_source_routes_status_only_spawns_through_run_inherited_status_sync_counts_mixed_forms(
    ) {
        let source = "\
            fn a() { let mut c = std::process::Command::new(\"x\"); \
             c.current_dir(\"/tmp\"); \
             crate::retry::run_inherited_status_sync(c, \"a\").unwrap(); }\n\
            fn b() { crate::retry::run_bin_args_inherited_status_sync(\
             &tool_bin(), &[\"probe\"], \"b\").unwrap(); }\n\
            \n#[cfg(test)]\nmod tests { }\n";
        assert_source_routes_status_only_spawns_through_run_inherited_status_sync(
            source,
            "fake/module.rs",
            2,
            "one direct + one wrapper delegation",
        );
    }

    /// Happy path for the async sibling
    /// [`assert_source_routes_status_only_spawns_through_run_inherited_status`]:
    /// a module body carrying no inline `.status().await` terminator
    /// and enough `run_inherited_status(` delegations passes cleanly.
    #[test]
    fn test_assert_source_routes_status_only_spawns_through_run_inherited_status_accepts_migrated_module(
    ) {
        let source = "\
            async fn a() { let mut c = tokio::process::Command::new(\"x\"); \
             crate::retry::run_inherited_status(c, \"x\").await.unwrap(); }\n\
            async fn b() { let mut c = tokio::process::Command::new(\"y\"); \
             crate::retry::run_inherited_status(c, \"y\").await.unwrap(); }\n\
            \n#[cfg(test)]\nmod tests { }\n";
        assert_source_routes_status_only_spawns_through_run_inherited_status(
            source,
            "fake/module.rs",
            2,
            "both async spawns",
        );
    }

    /// The async sibling's needle is `.status().await`, so a sync
    /// `.status()` terminator does NOT fire — the two frontiers are
    /// scoped independently. Pinning this ensures a module that
    /// happens to carry a legitimate sync `.status()` consumer
    /// (routed through `run_inherited_status_sync`) is not
    /// misdiagnosed by the async helper as an inline terminator.
    #[test]
    fn test_assert_source_routes_status_only_spawns_through_run_inherited_status_ignores_sync_status_terminator(
    ) {
        let source = "\
            async fn a() { let mut c = tokio::process::Command::new(\"x\"); \
             crate::retry::run_inherited_status(c, \"x\").await.unwrap(); }\n\
            // sync legitimate consumer routed through the sync primitive:\n\
            fn b() { let mut c = std::process::Command::new(\"y\"); \
             crate::retry::run_inherited_status_sync(c, \"y\").unwrap(); }\n\
            \n#[cfg(test)]\nmod tests { }\n";
        assert_source_routes_status_only_spawns_through_run_inherited_status(
            source,
            "fake/module.rs",
            1,
            "one async spawn",
        );
    }

    /// An inline `.status().await` fires the async shield.
    #[test]
    #[should_panic(expected = "inline `.status().await` terminator")]
    fn test_assert_source_routes_status_only_spawns_through_run_inherited_status_rejects_inline_status_await_terminator(
    ) {
        let source = "\
            async fn a() { tokio::process::Command::new(\"x\").status().await.unwrap(); }\n\
            \n#[cfg(test)]\nmod tests { }\n";
        assert_source_routes_status_only_spawns_through_run_inherited_status(
            source,
            "fake/module.rs",
            0,
            "no spawns claimed",
        );
    }

    /// Wrapper-form pin for the async shield: a module whose async
    /// status-only spawns all route through the
    /// `run_bin_args_inherited_status(&bin, &[...], op)` wrapper (never
    /// through the direct `run_inherited_status(cmd, op)` primitive)
    /// still passes without the caller lowering `min_delegations`.
    /// Pre-widening the async shield counted only the direct-primitive
    /// needle; a full-module lift to the wrapper would have driven the
    /// count to zero and fired the "delegation call(s)" arm even
    /// though the wrapper delegates to the same
    /// [`crate::retry::classify_inherited_status`] body. Mirrors the
    /// sync sibling's
    /// `test_assert_source_routes_status_only_spawns_through_run_inherited_status_sync_counts_wrapper_form`
    /// pin at the async frontier so the composition trap is closed on
    /// both halves of the spawn matrix. The two needles are disjoint
    /// (neither is a substring of the other), so a single call site is
    /// counted at most once across the sum.
    #[test]
    fn test_assert_source_routes_status_only_spawns_through_run_inherited_status_counts_wrapper_form(
    ) {
        let source = "\
            async fn a() { crate::retry::run_bin_args_inherited_status(\
             &tool_bin(), &[\"probe\"], \"a\").await.unwrap(); }\n\
            async fn b() { crate::retry::run_bin_args_inherited_status(\
             &tool_bin(), &[\"probe\"], \"b\").await.unwrap(); }\n\
            \n#[cfg(test)]\nmod tests { }\n";
        assert_source_routes_status_only_spawns_through_run_inherited_status(
            source,
            "fake/module.rs",
            2,
            "both wrapper-form async spawns",
        );
    }

    /// Mixed-form pin for the async shield: a module carrying a mix of
    /// direct-primitive and wrapper-form async delegations sums both
    /// toward `min_delegations`. Mirrors the sync sibling's
    /// `test_assert_source_routes_status_only_spawns_through_run_inherited_status_sync_counts_mixed_forms`
    /// pin at the async frontier, covering the common migration state
    /// where a single wave lifts SOME of a module's async status-only
    /// spawns onto the wrapper while others stay on the direct primitive
    /// (e.g. because they need `.current_dir(...)` or `.env(...)`), and
    /// the shield must still hold at the pre-migration floor.
    #[test]
    fn test_assert_source_routes_status_only_spawns_through_run_inherited_status_counts_mixed_forms(
    ) {
        let source = "\
            async fn a() { let mut c = tokio::process::Command::new(\"x\"); \
             c.current_dir(\"/tmp\"); \
             crate::retry::run_inherited_status(c, \"a\").await.unwrap(); }\n\
            async fn b() { crate::retry::run_bin_args_inherited_status(\
             &tool_bin(), &[\"probe\"], \"b\").await.unwrap(); }\n\
            \n#[cfg(test)]\nmod tests { }\n";
        assert_source_routes_status_only_spawns_through_run_inherited_status(
            source,
            "fake/module.rs",
            2,
            "one direct + one wrapper async delegation",
        );
    }

    /// Happy path for
    /// [`assert_source_routes_captured_bails_through_classify_capture_anyhow`]:
    /// a body carrying a `classify_capture_anyhow(` delegation and NO
    /// `if !output.status.success` inline stanza passes cleanly. The
    /// stub body carries a control-flow-shape `output.status.success()`
    /// (without the `if !` prefix) as a match guard so the shield's
    /// negative-side needle is exercised against a legitimate sibling
    /// consumer of the same accessor chain — a future regression that
    /// widened the needle to bare `output.status.success` would fail
    /// here, catching the false-positive class before it landed on any
    /// migrated site.
    #[test]
    fn test_assert_source_routes_captured_bails_through_classify_capture_anyhow_accepts_migrated_body(
    ) {
        let body = "\
            let _output = crate::retry::classify_capture_anyhow(cmd.output(), \"jsonnet\")?;\n\
            match cmd2.output() { Ok(output) if output.status.success() => (), _ => () }\n";
        assert_source_routes_captured_bails_through_classify_capture_anyhow(
            body,
            "commands/fake.rs::fake_fn",
            1,
        );
    }

    /// An inline `if !output.status.success()` bail terminator fires the
    /// negative-side assertion. Panics before the positive-side scan
    /// runs, so a body that ALSO carried the delegation would still
    /// fail on the bail-shape refusal — matching the stanza order every
    /// migrated site enforces.
    #[test]
    #[should_panic(
        expected = "commands/fake.rs::fake_fn must not carry an inline `if !output.status.success`"
    )]
    fn test_assert_source_routes_captured_bails_through_classify_capture_anyhow_rejects_inline_bail(
    ) {
        let body = "\
            let output = cmd.output()?;\n\
            if !output.status.success() { bail!(\"nope\"); }\n\
            let _ = crate::retry::classify_capture_anyhow(other.output(), \"other\")?;\n";
        assert_source_routes_captured_bails_through_classify_capture_anyhow(
            body,
            "commands/fake.rs::fake_fn",
            1,
        );
    }

    /// A missing `classify_capture_anyhow(` delegation fires the
    /// positive-side assertion — reachable only when the negative-side
    /// bail refusal passes. Pins the positive floor against a
    /// regression that dropped the delegation and accidentally
    /// satisfied the negative scan by absence.
    #[test]
    #[should_panic(
        expected = "commands/fake.rs::fake_fn must route captured-output bails through `classify_capture_anyhow`"
    )]
    fn test_assert_source_routes_captured_bails_through_classify_capture_anyhow_rejects_missing_delegation(
    ) {
        let body = "\
            let output = cmd.output()?;\n\
            // No bail, no delegation — the positive floor still fails.\n\
            drop(output);\n";
        assert_source_routes_captured_bails_through_classify_capture_anyhow(
            body,
            "commands/fake.rs::fake_fn",
            1,
        );
    }

    /// A body that spells the higher-level async run-wrapper
    /// `run_capture_anyhow(` (rather than the bare
    /// `classify_capture_anyhow(` classifier) MUST satisfy the
    /// positive floor. The run-wrapper delegates internally to
    /// `classify_capture_anyhow`, so it IS the canonical shape once
    /// the run-* algebra closed at 06cd778 — a shield that refused
    /// this delegation would refuse the correct migration.
    #[test]
    fn test_assert_source_routes_captured_bails_through_classify_capture_anyhow_accepts_run_capture_anyhow_wrapper(
    ) {
        let body = "\
            let output = crate::retry::run_capture_anyhow(cmd, \"kubectl get pods\").await?;\n\
            match cmd2.output() { Ok(output) if output.status.success() => (), _ => () }\n";
        assert_source_routes_captured_bails_through_classify_capture_anyhow(
            body,
            "commands/fake.rs::fake_fn",
            1,
        );
    }

    /// Sync sibling: a body that spells the higher-level sync run-
    /// wrapper `run_capture_anyhow_sync(` MUST satisfy the positive
    /// floor. Pins the substring-mutual-exclusion invariant the
    /// helper's summation depends on: `run_capture_anyhow_sync(` does
    /// NOT contain `run_capture_anyhow(` as a substring (the char
    /// after `run_capture_anyhow` is `_`, not `(`), so the sum
    /// `via_classify + via_run + via_run_sync` is not inflated by
    /// double-counting on this line — the shield sees exactly one
    /// delegation from the one sync run-wrapper call.
    #[test]
    fn test_assert_source_routes_captured_bails_through_classify_capture_anyhow_accepts_run_capture_anyhow_sync_wrapper(
    ) {
        let body = "\
            let output = crate::retry::run_capture_anyhow_sync(cmd, \"doca inspect --tarball\")?;\n";
        assert_source_routes_captured_bails_through_classify_capture_anyhow(
            body,
            "commands/fake.rs::fake_fn",
            1,
        );
    }

    /// Kubectl-fronted fusion sibling: a body that spells the
    /// `kubectl_capture_anyhow(` fusion primitive
    /// (`infrastructure::kubectl` — pre-binds
    /// [`crate::infrastructure::kubectl::kubectl_command_async`] to
    /// the same `run_capture_anyhow` classifier the wrappers above
    /// route through) MUST satisfy the positive floor. Pins the
    /// substring-disjointness invariant the helper's summation
    /// depends on: `kubectl_capture_anyhow(` shares no substring
    /// with `classify_capture_anyhow(` or `run_capture_anyhow(`
    /// (the `kubectl_` prefix is disjoint from both), so the sum
    /// `via_classify + via_run + via_run_sync + via_kubectl` is
    /// not inflated by double-counting on this line — the shield
    /// sees exactly one delegation from the one kubectl-fronted
    /// fusion call.
    #[test]
    fn test_assert_source_routes_captured_bails_through_classify_capture_anyhow_accepts_kubectl_capture_anyhow_fusion(
    ) {
        let body = "\
            let output = crate::infrastructure::kubectl::kubectl_capture_anyhow(&[\"get\", \"pods\"], \"kubectl get pods\").await?;\n";
        assert_source_routes_captured_bails_through_classify_capture_anyhow(
            body,
            "commands/fake.rs::fake_fn",
            1,
        );
    }

    /// Happy path for
    /// [`assert_source_routes_bare_spawn_through_sigil_bin_fn_at_exactly_one_resolve`]:
    /// a module body carrying no bare `Command::new("<bare>")` literal,
    /// a `fn <sigil>_bin()` definition, and the two-arg resolve at
    /// EXACTLY one code line passes cleanly. The test uses a bare tool
    /// name deliberately distinct from every real shield's
    /// (`zeta-widget` → `zeta_widget_bin` after dash canonicalization)
    /// so a Grep of the crate for `zeta-widget` resolves to this test
    /// and its three siblings — the fast way to find the pinning tests
    /// when editing the helper.
    #[test]
    fn test_assert_source_routes_bare_spawn_through_sigil_bin_fn_at_exactly_one_resolve_accepts_migrated_module(
    ) {
        let source = "\
            fn zeta_widget_bin() -> String { \
             crate::repo::get_tool_path(\"ZETA_WIDGET_BIN\", \"zeta-widget\") }\n\
            fn use_a() { let _cmd = Command::new(zeta_widget_bin()); }\n\
            fn use_b() { let _cmd = Command::new(zeta_widget_bin()); }\n\
            \n#[cfg(test)]\nmod tests { }\n";
        assert_source_routes_bare_spawn_through_sigil_bin_fn_at_exactly_one_resolve(
            source,
            "fake/module.rs",
            "zeta-widget",
            "ZETA_WIDGET_BIN",
        );
    }

    /// A bare `Command::new("<bare>")` in the module body fires the
    /// negative-side assertion — the FIRST of the three invariants to
    /// surface (bare-literal refusal before sigil-definition before
    /// resolve-count-one), matching every pre-lift shield's stanza
    /// order.
    #[test]
    #[should_panic(expected = "fake/module.rs must not spawn `zeta-widget` via the bare literal")]
    fn test_assert_source_routes_bare_spawn_through_sigil_bin_fn_at_exactly_one_resolve_rejects_bare_command_literal(
    ) {
        let source = "\
            fn zeta_widget_bin() -> String { \
             crate::repo::get_tool_path(\"ZETA_WIDGET_BIN\", \"zeta-widget\") }\n\
            fn drift() { let _cmd = Command::new(\"zeta-widget\"); }\n\
            \n#[cfg(test)]\nmod tests { }\n";
        assert_source_routes_bare_spawn_through_sigil_bin_fn_at_exactly_one_resolve(
            source,
            "fake/module.rs",
            "zeta-widget",
            "ZETA_WIDGET_BIN",
        );
    }

    /// A missing `fn <sigil>_bin()` definition fires the sigil-
    /// definition assertion — the SECOND of the three invariants, only
    /// reachable once the negative-side bare-literal refusal passes.
    /// This test uses a body with the resolve inlined at a consumer
    /// (bypassing the sigil), so the shield fires on the missing sigil
    /// before the resolve-count invariant runs.
    #[test]
    #[should_panic(expected = "fake/module.rs must define `zeta_widget_bin()`")]
    fn test_assert_source_routes_bare_spawn_through_sigil_bin_fn_at_exactly_one_resolve_rejects_missing_sigil_definition(
    ) {
        let source = "\
            fn use_a() { let _bin = \
             crate::repo::get_tool_path(\"ZETA_WIDGET_BIN\", \"zeta-widget\"); }\n\
            \n#[cfg(test)]\nmod tests { }\n";
        assert_source_routes_bare_spawn_through_sigil_bin_fn_at_exactly_one_resolve(
            source,
            "fake/module.rs",
            "zeta-widget",
            "ZETA_WIDGET_BIN",
        );
    }

    /// A body whose resolve appears at more than one code line fires
    /// the SOLITARY-RESOLVE assertion — the THIRD of the three
    /// invariants, only reachable once the bare-literal refusal and
    /// sigil-definition invariants pass. This is the defect class the
    /// count-exactly-one invariant exists to close: a consumer that
    /// re-copies the resolve inline (bypassing the sigil) even while
    /// the sigil itself is intact.
    #[test]
    #[should_panic(expected = "exactly ONCE in the module body of fake/module.rs")]
    fn test_assert_source_routes_bare_spawn_through_sigil_bin_fn_at_exactly_one_resolve_rejects_duplicated_resolve_call_sites(
    ) {
        let source = "\
            fn zeta_widget_bin() -> String { \
             crate::repo::get_tool_path(\"ZETA_WIDGET_BIN\", \"zeta-widget\") }\n\
            fn drift() { let _bin = \
             crate::repo::get_tool_path(\"ZETA_WIDGET_BIN\", \"zeta-widget\"); }\n\
            \n#[cfg(test)]\nmod tests { }\n";
        assert_source_routes_bare_spawn_through_sigil_bin_fn_at_exactly_one_resolve(
            source,
            "fake/module.rs",
            "zeta-widget",
            "ZETA_WIDGET_BIN",
        );
    }

    /// The happy path — a source with a `\n#[cfg(test)]\nmod tests {`
    /// marker — returns the substring BEFORE the leading newline of the
    /// marker verbatim. Pins the load-bearing slice boundary the 23
    /// migrated shield sites depend on: everything up to (and NOT
    /// including) the newline that starts the marker survives, so a
    /// shield scanning the returned body sees the module's non-test
    /// production body and none of its `#[cfg(test)]`-guarded prose.
    #[test]
    fn test_module_body_before_tests_slices_at_first_cfg_test_mod_tests_marker() {
        let source = "fn keep() {}\n#[cfg(test)]\nmod tests { fn drop() {} }\n";
        let body = module_body_before_tests(source, "fake/module.rs");
        assert_eq!(body, "fn keep() {}");
    }

    /// The FIRST occurrence of the marker wins even when the source
    /// carries multiple `#[cfg(test)]\nmod tests {` blocks — pins the
    /// callers' pre-lift `source.find(tests_marker)` semantics. A
    /// module that (say) grew a second test block after the primary
    /// one still has its non-test body sliced at the first marker,
    /// matching the pre-lift stanza's `.find(...)` verb byte-for-byte.
    #[test]
    fn test_module_body_before_tests_slices_at_first_marker_when_multiple() {
        let source = "\
            fn keep() {}\n\
            #[cfg(test)]\nmod tests { fn one() {} }\n\
            fn stray() {}\n\
            #[cfg(test)]\nmod tests { fn two() {} }\n";
        let body = module_body_before_tests(source, "fake/module.rs");
        assert_eq!(body, "fn keep() {}");
    }

    /// A source that spells the shorter `#[cfg(test)]` marker WITHOUT
    /// the `\nmod tests {` suffix (an inline `#[cfg(test)] fn ...`
    /// attribute, or a `#[cfg(test)] mod foo {` block whose name is
    /// not `tests`) does NOT match — the primitive's marker is
    /// deliberately strict about the `mod tests {` suffix so it
    /// matches the 23 pre-lift call sites verbatim. The panic surfaces
    /// with the caller-supplied `module_path` so a shield that lands
    /// on a module without a `mod tests { ... }` block diagnoses
    /// itself by name.
    #[test]
    #[should_panic(expected = "fake/module.rs: the `#[cfg(test)]\\nmod tests {` marker")]
    fn test_module_body_before_tests_panics_with_module_path_when_marker_absent() {
        let source = "fn keep() {}\n#[cfg(test)] fn inline() {}\n";
        let _ = module_body_before_tests(source, "fake/module.rs");
    }

    /// The returned `&str` borrows from the input `source` with the
    /// same lifetime — pins the primitive's `<'a>(source: &'a str, ...)
    /// -> &'a str` signature. A migrated shield that reads
    /// `module_body` and then reads `source` afterward (e.g.
    /// `commands/supergraph_verification.rs::test_rover_fhs_spawn_
    /// routes_through_rover_fhs_bin_not_raw_literal` at line 801-802)
    /// must observe that the primitive does not consume or clone
    /// `source`; both bindings remain valid and refer to the same
    /// backing buffer.
    #[test]
    fn test_module_body_before_tests_preserves_source_lifetime() {
        let source: String = "fn keep() {}\n#[cfg(test)]\nmod tests { }\n".to_string();
        let body = module_body_before_tests(source.as_str(), "fake/module.rs");
        assert!(std::ptr::eq(body.as_ptr(), source.as_ptr()));
        assert_eq!(body, "fn keep() {}");
    }

    /// [`module_body_before_first_cfg_test`] slices above the first
    /// `#[cfg(test)]` attribute regardless of what follows it — the
    /// happy-path shape a shield that per-frontier-buckets its test
    /// modules (a `mod cargo_env_routing_tests {}`, `mod
    /// docker_bin_routing_tests {}`, `mod resolve_repo_root_git_bin_routing_tests
    /// {}` sequence) already relies on.
    #[test]
    fn test_module_body_before_first_cfg_test_slices_at_first_short_marker() {
        let source = "\
            fn keep() {}\n\
            #[cfg(test)]\nmod some_frontier_tests { fn one() {} }\n\
            #[cfg(test)]\nmod another_frontier_tests { fn two() {} }\n";
        let body = module_body_before_first_cfg_test(source, "fake/module.rs");
        assert_eq!(body, "fn keep() {}");
    }

    /// The FIRST occurrence of the shorter marker wins — a module that
    /// carries multiple `#[cfg(test)]` attributes still has its
    /// production body sliced at the first attribute, matching the
    /// pre-lift stanza's `.find("\n#[cfg(test)]\n")` verb byte-for-byte.
    /// Both the `mod tests {` shape and the plain `mod <other-name> {`
    /// shape reduce to the shorter marker, so a shield that lifts onto
    /// this primitive sees the same cutoff whether the module opens its
    /// first test block with `mod tests {` or a per-frontier name.
    #[test]
    fn test_module_body_before_first_cfg_test_slices_at_first_marker_when_multiple() {
        let source = "\
            fn keep() {}\n\
            #[cfg(test)]\nmod tests { fn one() {} }\n\
            fn stray() {}\n\
            #[cfg(test)]\nmod tests { fn two() {} }\n";
        let body = module_body_before_first_cfg_test(source, "fake/module.rs");
        assert_eq!(body, "fn keep() {}");
    }

    /// A source that carries NO `\n#[cfg(test)]\n` marker at all panics
    /// with the caller-supplied `module_path` and the shorter-marker
    /// literal in the diagnostic. Guards the pre-lift stanza's
    /// `expect("<file>.rs must have a \`#[cfg(test)]\` marker …")`
    /// discipline — a shield landing on a module that lost its
    /// test-block scan-boundary diagnoses itself by name.
    #[test]
    #[should_panic(expected = "fake/module.rs: the `#[cfg(test)]` marker")]
    fn test_module_body_before_first_cfg_test_panics_with_module_path_when_marker_absent() {
        let source = "fn only() {}\n";
        let _ = module_body_before_first_cfg_test(source, "fake/module.rs");
    }

    /// The returned `&str` borrows from the input `source` with the
    /// same lifetime — pins the primitive's `<'a>(source: &'a str, ...)
    /// -> &'a str` signature. A migrated shield that reads `body` and
    /// then reads `SOURCE` afterward must observe that the primitive
    /// does not consume or clone `source`; both bindings remain valid
    /// and refer to the same backing buffer.
    #[test]
    fn test_module_body_before_first_cfg_test_preserves_source_lifetime() {
        let source: String = "fn keep() {}\n#[cfg(test)]\nmod tests { }\n".to_string();
        let body = module_body_before_first_cfg_test(source.as_str(), "fake/module.rs");
        assert!(std::ptr::eq(body.as_ptr(), source.as_ptr()));
        assert_eq!(body, "fn keep() {}");
    }

    /// [`fn_body_slice_between_markers`] returns the byte range
    /// `[start_of_open_marker .. start_of_end_marker)` — the open marker
    /// is INCLUDED at the head, the end marker is EXCLUDED at the tail.
    /// Pins the load-bearing pre-lift semantics the 11 migrated shield
    /// sites depend on: everything from the fn signature (inclusive) to
    /// the next top-level marker (exclusive) survives, so a `.contains`
    /// scan sees the target fn's body verbatim.
    #[test]
    fn test_fn_body_slice_between_markers_returns_open_inclusive_end_exclusive() {
        let source = "\
            fn keep() {}\n\
            pub async fn target(x: u32) -> u32 {\n    x + 1\n}\n\
            pub async fn other() {}\n";
        let body = fn_body_slice_between_markers(
            source,
            "fake/module.rs",
            "pub async fn target(",
            "\npub async fn other(",
        );
        assert_eq!(body, "pub async fn target(x: u32) -> u32 {\n    x + 1\n}");
    }

    /// The FIRST occurrence of the open marker wins even when the source
    /// carries multiple matches. Pins the callers' pre-lift
    /// `SOURCE.find(fn_marker)` semantics: a shield whose target fn
    /// exists once and whose forbidden literal happens to appear later
    /// as a docstring or a sibling fn's parameter type still bounds at
    /// the FIRST hit and slices consistently.
    #[test]
    fn test_fn_body_slice_between_markers_first_open_marker_wins() {
        let source = "\
            // fake mention: pub async fn target(\n\
            pub async fn target() {}\n\
            pub async fn other() {}\n";
        let body = fn_body_slice_between_markers(
            source,
            "fake/module.rs",
            "pub async fn target(",
            "\npub async fn other(",
        );
        assert!(
            body.starts_with("pub async fn target("),
            "expected fn body to start at the fn header, got: {body:?}"
        );
    }

    /// The FIRST occurrence of the end marker AFTER the open marker
    /// wins even when the source carries multiple matches downstream.
    /// Pins the callers' pre-lift `after_fn.find(end_marker)` semantics
    /// (a `.find` walking `after_fn`, not `source`, so a matching
    /// literal BEFORE the open marker cannot confuse the boundary).
    #[test]
    fn test_fn_body_slice_between_markers_first_end_marker_after_open_wins() {
        let source = "\
            \npub async fn other() {}\n\
            pub async fn target() { let x = 1; }\n\
            pub async fn other() { let y = 2; }\n\
            pub async fn other() { let z = 3; }\n";
        let body = fn_body_slice_between_markers(
            source,
            "fake/module.rs",
            "pub async fn target(",
            "\npub async fn other(",
        );
        assert_eq!(body, "pub async fn target() { let x = 1; }");
    }

    /// Absent open marker panics with the caller-supplied `module_path`
    /// and the open-marker literal. Guards the pre-lift stanza's
    /// `expect("<file>.rs must contain <fn_marker>")` diagnostic — a
    /// shield landing on a module whose target fn was renamed diagnoses
    /// itself by name rather than the generic `None` unwrap.
    #[test]
    #[should_panic(expected = "fake/module.rs must contain `pub async fn missing(`")]
    fn test_fn_body_slice_between_markers_panics_when_open_marker_absent() {
        let source = "fn keep() {}\n";
        let _ = fn_body_slice_between_markers(
            source,
            "fake/module.rs",
            "pub async fn missing(",
            "\npub async fn other(",
        );
    }

    /// Absent end marker panics with the caller-supplied `module_path`,
    /// naming the missing end marker and the open marker it was
    /// expected to follow. Guards the pre-lift stanza's
    /// `expect("<file>.rs must contain <end_marker> after <fn_name>")`
    /// diagnostic when a reorder moved the terminating fn upstream of
    /// the target.
    #[test]
    #[should_panic(expected = "after `pub async fn target(`")]
    fn test_fn_body_slice_between_markers_panics_when_end_marker_absent() {
        let source = "pub async fn target() { let x = 1; }\n";
        let _ = fn_body_slice_between_markers(
            source,
            "fake/module.rs",
            "pub async fn target(",
            "\n#[cfg(test)]",
        );
    }

    /// The returned `&str` borrows from the input `source` with the
    /// same lifetime — pins the primitive's `<'a>(source: &'a str, ...)
    /// -> &'a str` signature. A migrated shield that reads `fn_body`
    /// and then reads `SOURCE` afterward (e.g.
    /// `commands/integration_tests.rs::test_execute_readiness_poll_
    /// consumes_typed_delay_not_bare_fixed_sleep` at line 2094-2105)
    /// must observe that the primitive does not consume or clone
    /// `source`; both bindings remain valid and refer to the same
    /// backing buffer.
    #[test]
    fn test_fn_body_slice_between_markers_preserves_source_lifetime() {
        let source: String = "\
            fn keep() {}\n\
            pub async fn target() { let x = 1; }\n\
            pub async fn other() {}\n"
            .to_string();
        let body = fn_body_slice_between_markers(
            source.as_str(),
            "fake/module.rs",
            "pub async fn target(",
            "\npub async fn other(",
        );
        // The slice's byte pointer lies WITHIN the source buffer — i.e.
        // it borrows, does not clone.
        let src_start = source.as_ptr() as usize;
        let src_end = src_start + source.len();
        let body_start = body.as_ptr() as usize;
        assert!(
            body_start >= src_start && body_start < src_end,
            "returned slice must borrow from `source` (start pointer {body_start:#x} \
             must lie within source range [{src_start:#x}, {src_end:#x}))"
        );
        assert!(body.starts_with("pub async fn target("));
    }

    /// [`RootFlakeEnvSnapshot`] MUST restore `REPO_ROOT` and
    /// `SERVICE_DIR` on drop for BOTH directions of the pre-scope
    /// state: originally-unset stays unset, originally-set restores
    /// verbatim. Same two-direction contract [`GitBinScope`]'s sibling
    /// test at `cli/src/git.rs::test_git_bin_scope_restores_pre_scope_state_on_drop`
    /// pins, applied to the two env-var surfaces this snapshot owns.
    #[test]
    fn test_root_flake_env_snapshot_restores_env_vars_on_drop() {
        let _guard = ROOT_FLAKE_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let starting_cwd = std::env::current_dir().expect("cwd");
        let starting_repo = std::env::var("REPO_ROOT");
        let starting_svc = std::env::var("SERVICE_DIR");

        // Direction 1: originally-unset REPO_ROOT / SERVICE_DIR must
        // stay unset after drop, regardless of in-scope mutation.
        std::env::remove_var("REPO_ROOT");
        std::env::remove_var("SERVICE_DIR");
        {
            let _snap = RootFlakeEnvSnapshot::capture();
            std::env::set_var("REPO_ROOT", "/tmp/in-scope-repo");
            std::env::set_var("SERVICE_DIR", "/tmp/in-scope-svc");
            assert_eq!(
                std::env::var("REPO_ROOT").ok().as_deref(),
                Some("/tmp/in-scope-repo"),
                "in-scope REPO_ROOT mutation must be visible"
            );
            assert_eq!(
                std::env::var("SERVICE_DIR").ok().as_deref(),
                Some("/tmp/in-scope-svc"),
                "in-scope SERVICE_DIR mutation must be visible"
            );
        }
        assert!(
            std::env::var("REPO_ROOT").is_err(),
            "originally-unset REPO_ROOT must be unset again after drop"
        );
        assert!(
            std::env::var("SERVICE_DIR").is_err(),
            "originally-unset SERVICE_DIR must be unset again after drop"
        );

        // Direction 2: originally-set REPO_ROOT / SERVICE_DIR must
        // restore the pre-capture value verbatim.
        std::env::set_var("REPO_ROOT", "/orig/repo");
        std::env::set_var("SERVICE_DIR", "/orig/svc");
        {
            let _snap = RootFlakeEnvSnapshot::capture();
            std::env::set_var("REPO_ROOT", "/mid/repo");
            std::env::set_var("SERVICE_DIR", "/mid/svc");
        }
        assert_eq!(
            std::env::var("REPO_ROOT").ok().as_deref(),
            Some("/orig/repo"),
            "originally-set REPO_ROOT must be restored verbatim after drop"
        );
        assert_eq!(
            std::env::var("SERVICE_DIR").ok().as_deref(),
            Some("/orig/svc"),
            "originally-set SERVICE_DIR must be restored verbatim after drop"
        );

        // Restore the process-level starting state so a subsequent
        // test (or the process teardown) sees the same env it did on
        // entry.
        match starting_repo {
            Ok(v) => std::env::set_var("REPO_ROOT", v),
            Err(_) => std::env::remove_var("REPO_ROOT"),
        }
        match starting_svc {
            Ok(v) => std::env::set_var("SERVICE_DIR", v),
            Err(_) => std::env::remove_var("SERVICE_DIR"),
        }
        let _ = std::env::set_current_dir(starting_cwd);
    }

    /// [`RootFlakeEnvSnapshot`] MUST restore the pre-scope current
    /// working directory on drop, mirroring the `let _ =
    /// std::env::set_current_dir(&prior_cwd);` line each of the 6
    /// pre-lift migrated sites spelled at teardown. Load-bearing: a
    /// test that chdirs into a tempdir and then panics leaves every
    /// subsequent test's `std::env::current_dir()` reading the
    /// (torn-down) tempdir path — an unrecoverable state without
    /// process restart. Canonicalization on both sides handles the
    /// `/private/var/...` vs `/var/...` symlink-prefix drift the
    /// pre-lift sibling test
    /// `activate_root_flake_chdirs_to_repo_root_not_service_dir`
    /// already threads through.
    #[test]
    fn test_root_flake_env_snapshot_restores_cwd_on_drop() {
        let _guard = ROOT_FLAKE_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let starting_cwd = std::env::current_dir().expect("cwd");
        let starting_repo = std::env::var("REPO_ROOT");
        let starting_svc = std::env::var("SERVICE_DIR");

        let tmp = tempfile::tempdir().expect("tempdir");
        {
            let _snap = RootFlakeEnvSnapshot::capture();
            std::env::set_current_dir(tmp.path()).expect("chdir to tempdir");
            let observed_in_scope = std::env::current_dir()
                .expect("cwd in scope")
                .canonicalize()
                .expect("canonicalize in-scope cwd");
            let expected_in_scope = tmp.path().canonicalize().expect("canonicalize tempdir");
            assert_eq!(
                observed_in_scope, expected_in_scope,
                "in-scope chdir must be visible before drop"
            );
        }
        let observed = std::env::current_dir()
            .expect("cwd after drop")
            .canonicalize()
            .expect("canonicalize observed");
        let expected = starting_cwd.canonicalize().expect("canonicalize starting");
        assert_eq!(
            observed, expected,
            "cwd must be restored to pre-scope value after drop"
        );

        match starting_repo {
            Ok(v) => std::env::set_var("REPO_ROOT", v),
            Err(_) => std::env::remove_var("REPO_ROOT"),
        }
        match starting_svc {
            Ok(v) => std::env::set_var("SERVICE_DIR", v),
            Err(_) => std::env::remove_var("SERVICE_DIR"),
        }
    }

    /// [`RootFlakeEnvSnapshot`]'s Drop MUST fire on panic-unwind, not
    /// only on normal scope exit. This is the load-bearing property the
    /// pre-lift manual-restore stanza did NOT provide: a panic between
    /// `let prior_repo = ...` and the `match prior_repo { Ok(v) =>
    /// set_var(...) ...}` epilogue silently leaked `REPO_ROOT`,
    /// `SERVICE_DIR`, and cwd to every subsequent test in the process.
    /// RAII closes that leak by construction; this test pins the
    /// closure so a future refactor that (say) moved the restore into
    /// a non-Drop path cannot silently regress the invariant.
    #[test]
    fn test_root_flake_env_snapshot_restores_env_vars_when_scope_panics() {
        let _guard = ROOT_FLAKE_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let starting_cwd = std::env::current_dir().expect("cwd");
        let starting_repo = std::env::var("REPO_ROOT");
        let starting_svc = std::env::var("SERVICE_DIR");

        std::env::set_var("REPO_ROOT", "/pre-panic/repo");
        std::env::set_var("SERVICE_DIR", "/pre-panic/svc");

        let panic_result = std::panic::catch_unwind(|| {
            let _snap = RootFlakeEnvSnapshot::capture();
            std::env::set_var("REPO_ROOT", "/panic-mid/repo");
            std::env::set_var("SERVICE_DIR", "/panic-mid/svc");
            panic!("simulated test panic mid-scope");
        });
        assert!(
            panic_result.is_err(),
            "the simulated panic must propagate out of catch_unwind"
        );
        assert_eq!(
            std::env::var("REPO_ROOT").ok().as_deref(),
            Some("/pre-panic/repo"),
            "Drop must have restored REPO_ROOT on the unwind path"
        );
        assert_eq!(
            std::env::var("SERVICE_DIR").ok().as_deref(),
            Some("/pre-panic/svc"),
            "Drop must have restored SERVICE_DIR on the unwind path"
        );

        match starting_repo {
            Ok(v) => std::env::set_var("REPO_ROOT", v),
            Err(_) => std::env::remove_var("REPO_ROOT"),
        }
        match starting_svc {
            Ok(v) => std::env::set_var("SERVICE_DIR", v),
            Err(_) => std::env::remove_var("SERVICE_DIR"),
        }
        let _ = std::env::set_current_dir(starting_cwd);
    }

    /// Success arm pins the pre-lift `if success { 0 }` branch: an
    /// `Output` returned with `success=true` reports exit code 0 AND
    /// [`std::process::ExitStatus::success`] returns `true`. The two
    /// deprecated `make_output` sites both relied on the coupled
    /// invariant — the four helm-success shields
    /// (`ensure_helm_success_returns_ok_on_success_status_regardless_
    /// of_output_streams` and its siblings) discriminate on `.success()`
    /// via `ensure_helm_success`, whereas the four
    /// `kubectl_get_item[s]` shields discriminate on `!.status.
    /// success()`. Same status; both consumer surfaces pass through
    /// verbatim after the lift.
    #[test]
    fn test_synthetic_output_success_reports_exit_code_zero_and_success_true() {
        let out = synthetic_output(true, b"ok bytes", b"stderr note");
        assert!(
            out.status.success(),
            "success=true must yield an ExitStatus::success() true — \
             the four `ensure_helm_success` positive-arm shields \
             depend on this coupling"
        );
        assert_eq!(
            out.status.code(),
            Some(0),
            "success=true must yield exit code 0, not None or nonzero"
        );
        assert_eq!(out.stdout, b"ok bytes");
        assert_eq!(out.stderr, b"stderr note");
    }

    /// Failure arm pins the pre-lift `else { 1 << 8 }` branch: an
    /// `Output` returned with `success=false` reports exit code 1 AND
    /// [`std::process::ExitStatus::success`] returns `false`, AND
    /// [`std::process::ExitStatus::code`] returns `Some(1)` (NOT
    /// `None`). The `Some(1)` shape distinguishes a clean exit-1
    /// bail from a signal-killed exit whose `.code()` returns `None`
    /// — a discriminator `retry::classify_capture_anyhow` surfaces as
    /// `"exit 1"` vs `"killed by signal"` in the operator envelope.
    /// A regression that dropped the `<< 8` (encoding failure as the
    /// wait-status word `1` instead of `1 << 8`) would silently flip
    /// `.code()` to `None`, misrouting the `code`-vs-`signal` arms of
    /// downstream discriminators.
    #[test]
    fn test_synthetic_output_failure_reports_exit_code_one_via_wait_status_high_byte() {
        let out = synthetic_output(false, b"", b"boom");
        assert!(
            !out.status.success(),
            "success=false must yield ExitStatus::success() false"
        );
        assert_eq!(
            out.status.code(),
            Some(1),
            "success=false must yield Some(1), NOT None (which would \
             signal a signal-kill) — the `<< 8` encoding is load-bearing"
        );
        assert_eq!(out.stderr, b"boom");
        assert!(out.stdout.is_empty());
    }

    /// Byte-verbatim preservation on both streams. The pre-lift
    /// `make_output` bodies both called `.to_vec()` on both slices,
    /// so any non-UTF-8 byte, an interior NUL, or a trailing newline
    /// survives into the returned `Output`. Shields that drive parse
    /// primitives (`kubectl_get_items_propagates_parse_error_on_
    /// invalid_json` handing in `b"this is not json {{["`, or the
    /// `format_failure_summary` shield handing in binary chart
    /// output) depend on that: the helper is a byte-pipe, not a
    /// UTF-8-checking round trip.
    #[test]
    fn test_synthetic_output_preserves_stdout_and_stderr_bytes_verbatim() {
        let raw_stdout: &[u8] = &[0, 1, 2, b'\n', 0xff, 0xfe];
        let raw_stderr: &[u8] = &[0xc0, 0xff, 0xee, b'\t', 0];
        let out = synthetic_output(true, raw_stdout, raw_stderr);
        assert_eq!(out.stdout, raw_stdout);
        assert_eq!(out.stderr, raw_stderr);
    }

    /// Happy-path floor for
    /// [`assert_source_forbids_bare_literal_as_run_query_capture_sync_first_arg`]:
    /// a source whose sole `run_query_capture_sync` calls resolve
    /// through a sigil-derived binding (`&kubectl`, `&docker_bin()`)
    /// contains neither the inline nor the multi-line bare-literal
    /// shape, so the helper returns without panic. Mirrors the shape-
    /// free-source discipline
    /// [`test_assert_source_forbids_bare_spawn_shapes_accepts_shape_free_source`]
    /// holds on the `Command::new` spawn frontier — every shield's
    /// floor is "absent any forbidden shape, the helper is a no-op."
    ///
    /// The `resolver_remedy` slot is exercised with a spelling
    /// different from any real shield's ("fake-remedy") so a future
    /// refactor that silently hard-coded the remediation phrase would
    /// surface here as a substitution-drift failure, not as a passing
    /// test with wrong-message diagnostics downstream.
    #[test]
    fn test_assert_source_forbids_bare_literal_as_run_query_capture_sync_first_arg_accepts_shape_free_source(
    ) {
        assert_source_forbids_bare_literal_as_run_query_capture_sync_first_arg(
            "let kubectl = get_tool_path(tools::KUBECTL);\n\
             run_query_capture_sync(&kubectl, &[\"get\", \"pods\"])?;\n\
             run_query_capture_sync(&docker_bin(), &[\"stop\", name])?;",
            "fake/module.rs",
            "kubectl",
            "route through `fake-remedy`",
        );
    }

    /// The inline shape `run_query_capture_sync("<bare>",` is caught
    /// and the panic message names the module, the bare tool, the
    /// remediation phrase, AND the specific `(inline form)` marker.
    /// `should_panic(expected = ...)` matches on a substring of the
    /// panic payload, so a future edit that dropped any of the four
    /// substituted / templated tokens from the inline-form message
    /// (say, condensing the shape-specific tail into a generic "raw
    /// literal") would break this test before shipping — a reader of
    /// a failing shield relies on the shape-specific tail to know
    /// which of the two forbidden rustfmt shapes matched.
    ///
    /// The bare tool `zeta-widget` is deliberately distinct from
    /// every real shield's `bare` so a Grep of the crate for
    /// `zeta-widget` resolves to exactly this test and its sibling —
    /// a fast way to find the pinning tests when editing the helper.
    #[test]
    #[should_panic(
        expected = "fake/module.rs must NOT hand the bare `\"zeta-widget\"` literal to `run_query_capture_sync` as its first arg (inline form)"
    )]
    fn test_assert_source_forbids_bare_literal_as_run_query_capture_sync_first_arg_panics_on_inline_shape(
    ) {
        assert_source_forbids_bare_literal_as_run_query_capture_sync_first_arg(
            "let out = run_query_capture_sync(\"zeta-widget\", &[\"probe\"]);",
            "fake/module.rs",
            "zeta-widget",
            "route through `zeta_bin()`",
        );
    }

    /// The multi-line 8-space shape
    /// `run_query_capture_sync(\n        "<bare>"` is caught and the
    /// panic message names the module, the bare tool, the
    /// remediation phrase, AND the specific `(multi-line 8-space
    /// form)` marker. Sibling pin to
    /// [`test_assert_source_forbids_bare_literal_as_run_query_capture_sync_first_arg_panics_on_inline_shape`]
    /// — pins the second of the two rustfmt shapes the helper defends
    /// so a per-shape drift surfaces distinctly. The fake source
    /// spells the exact 8-space indent depth the primitive receives
    /// from a two-level-nested (`impl`/`mod`) call body.
    #[test]
    #[should_panic(
        expected = "fake/module.rs must NOT hand the bare `\"zeta-widget\"` literal to `run_query_capture_sync` as its first arg (multi-line 8-space form)"
    )]
    fn test_assert_source_forbids_bare_literal_as_run_query_capture_sync_first_arg_panics_on_multi_line_shape(
    ) {
        assert_source_forbids_bare_literal_as_run_query_capture_sync_first_arg(
            "run_query_capture_sync(\n        \"zeta-widget\",\n        &[\"probe\"],\n    )?;",
            "fake/module.rs",
            "zeta-widget",
            "route through `zeta_bin()`",
        );
    }

    /// [`EnvVarSnapshot`] restores an originally-unset env var to
    /// unset on drop even after the guarded scope explicitly set it.
    /// Pins the `Err(_) => remove_var(self.name)` half of the Drop
    /// body — every pre-lift consumer
    /// (`repo.rs::tests::SafeEnvSnapshot`,
    /// `git.rs::tests::ReleaseGitShaSnapshot`,
    /// `infrastructure/attic.rs::tests::AtticServerNameSnapshot`)
    /// depends on this branch to keep an unset env var from leaking
    /// into subsequent tests in the same process. A drift to
    /// `Err(_) => set_var(self.name, "")` would leak `<NAME>=""` to
    /// every subsequent test — silently misrouting a `.filter(|s|
    /// !s.is_empty())` consumer at the primitive boundary.
    ///
    /// Uses a per-test-unique env-var name so no cross-test
    /// serialization lock is needed — the same discipline as
    /// `repo.rs::tests::truthy_flag_from_env_defaults_to_false_when_unset`.
    #[test]
    fn env_var_snapshot_restores_env_when_original_unset() {
        let env_var = "TEST_ENV_VAR_SNAPSHOT_UNSET_ROUND_TRIP";
        std::env::remove_var(env_var);
        {
            let _snap = EnvVarSnapshot::capture(env_var);
            std::env::set_var(env_var, "sentinel-value");
            assert_eq!(
                std::env::var(env_var).ok().as_deref(),
                Some("sentinel-value")
            );
        }
        assert!(
            std::env::var(env_var).is_err(),
            "EnvVarSnapshot must restore `{env_var}` to unset on drop \
             when the pre-capture state was unset — a drift to \
             `set_var(name, \"\")` would leak `{env_var}=\"\"` into \
             every subsequent test in this process."
        );
    }

    /// [`EnvVarSnapshot`] restores an originally-set env var to its
    /// pre-scope value on drop after the guarded scope overwrote it.
    /// Pins the `Ok(v) => set_var(self.name, v)` half of the Drop
    /// body. A drift here (e.g., `Ok(_) => remove_var(self.name)`)
    /// would silently unset the operator's `SAFE=false` /
    /// `RELEASE_GIT_SHA=<sha>` / `ATTIC_SERVER_NAME=<alias>` export
    /// after any test that snapshots one of them ran — the exact
    /// failure mode the pre-lift RAII scope-guards were introduced
    /// to prevent.
    #[test]
    fn env_var_snapshot_restores_env_when_original_set() {
        let env_var = "TEST_ENV_VAR_SNAPSHOT_SET_ROUND_TRIP";
        std::env::set_var(env_var, "prior-value");
        {
            let _snap = EnvVarSnapshot::capture(env_var);
            std::env::set_var(env_var, "sentinel-value");
            assert_eq!(
                std::env::var(env_var).ok().as_deref(),
                Some("sentinel-value")
            );
        }
        let restored = std::env::var(env_var);
        std::env::remove_var(env_var);
        assert_eq!(
            restored.ok().as_deref(),
            Some("prior-value"),
            "EnvVarSnapshot must restore `{env_var}` to its pre-scope \
             value on drop — an operator's explicit export must not \
             be silently unset by a test that snapshots it."
        );
    }

    /// [`EnvVarSnapshot`] preserves the observable distinction between
    /// "set to empty string" and "unset" across the capture-and-restore
    /// round trip. `std::env::var` returns `Ok("")` when a caller
    /// explicitly exports `<NAME>=""`, so the Drop body's `Ok(v) =>
    /// set_var(name, v)` branch must restore `""` — not fall through
    /// to `remove_var`. A drift to `.filter(|s| !s.is_empty())` at the
    /// capture boundary (folding `Ok("")` into `Err`) would silently
    /// convert every explicit-empty export into an unset env var on
    /// drop.
    #[test]
    fn env_var_snapshot_restores_env_when_original_empty_string() {
        let env_var = "TEST_ENV_VAR_SNAPSHOT_EMPTY_ROUND_TRIP";
        std::env::set_var(env_var, "");
        {
            let _snap = EnvVarSnapshot::capture(env_var);
            std::env::set_var(env_var, "sentinel-value");
        }
        let restored = std::env::var(env_var);
        std::env::remove_var(env_var);
        assert_eq!(
            restored.ok().as_deref(),
            Some(""),
            "EnvVarSnapshot must restore an originally-empty export \
             (`{env_var}=\"\"`) verbatim on drop — the set-but-empty \
             vs unset distinction is observable at the primitive \
             boundary and must round-trip."
        );
    }

    /// [`EnvVarSnapshot::drop`] fires on panic-unwind, not only on
    /// normal scope exit — the exact panic-safety property every
    /// pre-lift RAII scope-guard was introduced to provide. A drift
    /// to a `Drop`-less implementation (e.g., a `fn restore(self)`
    /// consuming call the caller has to remember) would silently
    /// leak `<NAME>=<sentinel>` to every subsequent test in the
    /// process after any panicking test that snapshotted it.
    ///
    /// `AssertUnwindSafe` on the closure — `EnvVarSnapshot` carries
    /// only a `&'static str` and a `Result<String, VarError>`, both
    /// unwind-safe, so no interior mutability crosses the boundary.
    #[test]
    fn env_var_snapshot_restores_on_panic_unwind() {
        let env_var = "TEST_ENV_VAR_SNAPSHOT_PANIC_UNWIND";
        std::env::remove_var(env_var);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _snap = EnvVarSnapshot::capture(env_var);
            std::env::set_var(env_var, "sentinel-value");
            panic!("intentional panic to drive unwind path");
        }));
        assert!(
            result.is_err(),
            "the guarded scope must have panicked as expected"
        );
        assert!(
            std::env::var(env_var).is_err(),
            "EnvVarSnapshot::drop must fire on panic-unwind — a leaked \
             `{env_var}=<sentinel>` post-unwind means the panic-safety \
             contract the RAII guard exists to provide has drifted."
        );
    }

    /// Structural regression shield: the three pre-lift module-private
    /// RAII structs (`repo.rs::tests::SafeEnvSnapshot`,
    /// `git.rs::tests::ReleaseGitShaSnapshot`,
    /// `infrastructure/attic.rs::tests::AtticServerNameSnapshot`) each
    /// carried a `struct <X>Snapshot { prior: std::result::Result<String,
    /// std::env::VarError> }` + `capture()` + panic-safe `Drop` triple —
    /// the byte-equivalent snapshot-only shape this primitive redeems.
    /// Post-lift no `.rs` file in `cli/src/` (other than `test_support.rs`
    /// itself, which owns the primitive declaration) may re-introduce a
    /// `struct <X>Snapshot { ... }` block carrying the `prior:
    /// Result<String, VarError>` field: every snapshot-only consumer must
    /// route through [`EnvVarSnapshot::capture`] instead.
    ///
    /// The needle spells `Snapshot` (not `Scope`) so the sibling
    /// set-then-restore [`EnvVarScope`] primitive — which shares the
    /// `prior:` field spelling but adds a `fn set(name, value)` mutating
    /// constructor — is unaffected by this shield. The Scope-shape
    /// analogue is pinned separately by
    /// [`env_var_scope_pre_lift_scope_struct_shape_confined_to_test_support`].
    ///
    /// Walks the crate source tree via a shallow recursive scan so a
    /// future file added under any subdirectory of `cli/src/` is
    /// covered without a per-file shield update.
    #[test]
    fn env_var_snapshot_pre_lift_snapshot_struct_shape_confined_to_test_support() {
        let crate_src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut offenders: Vec<String> = Vec::new();
        walk_rs_files(&crate_src, &mut |path| {
            if path.file_name().and_then(|s| s.to_str()) == Some("test_support.rs") {
                return;
            }
            let contents =
                std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
            let lines: Vec<&str> = contents.lines().collect();
            for (i, line) in lines.iter().enumerate() {
                let trimmed = line.trim_start();
                let is_snapshot_struct = trimmed.starts_with("struct ")
                    && trimmed.contains("Snapshot")
                    && trimmed.trim_end().ends_with('{');
                if !is_snapshot_struct {
                    continue;
                }
                let has_prior_field =
                    lines.iter().skip(i + 1).take(8).any(|l| {
                        l.contains("prior: std::result::Result<String, std::env::VarError>")
                    });
                if has_prior_field {
                    let rel = path
                        .strip_prefix(&crate_src)
                        .unwrap_or(path)
                        .display()
                        .to_string();
                    offenders.push(format!("{rel}:{}: {}", i + 1, line.trim()));
                }
            }
        });
        assert!(
            offenders.is_empty(),
            "a `struct <X>Snapshot {{ ... prior: Result<String, VarError> ... }}` \
             declaration is reserved for `test_support.rs` — the pre-lift \
             `SafeEnvSnapshot` / `ReleaseGitShaSnapshot` / \
             `AtticServerNameSnapshot` shape must not reappear anywhere \
             else in `cli/src/`; every snapshot-only consumer routes \
             through `crate::test_support::EnvVarSnapshot::capture(<NAME>)` \
             instead. Offending sites:\n{}",
            offenders.join("\n")
        );
    }

    /// [`EnvVarScope::set`] MUST snapshot the pre-mutation value BEFORE
    /// writing `value` — the reverse ordering would snapshot the
    /// sentinel itself and restore it on drop, defeating the guard's
    /// contract. Pins the mutate-second, snapshot-first invariant on
    /// the originally-unset direction: after drop the env var must be
    /// unset again, not left carrying `<NAME>=<sentinel>`.
    #[test]
    fn env_var_scope_restores_env_when_original_unset() {
        let env_var = "TEST_ENV_VAR_SCOPE_UNSET_ROUND_TRIP";
        std::env::remove_var(env_var);
        {
            let _scope = EnvVarScope::set(env_var, "sentinel-value");
            assert_eq!(
                std::env::var(env_var).ok().as_deref(),
                Some("sentinel-value"),
                "in-scope value must be visible"
            );
        }
        assert!(
            std::env::var(env_var).is_err(),
            "EnvVarScope must restore `{env_var}` to unset on drop \
             when the pre-scope state was unset — a drift to \
             `set_var(name, \"\")` or a swap of the mutate-vs-snapshot \
             ordering would leak `{env_var}=<sentinel>` into every \
             subsequent test in this process."
        );
    }

    /// [`EnvVarScope::set`] restores an originally-set env var to its
    /// pre-scope value on drop after the guarded scope overwrote it.
    /// Pins the `Ok(v) => set_var(self.name, v)` half of the Drop
    /// body. A drift to `Ok(_) => remove_var(self.name)` would silently
    /// unset the operator's `GIT_BIN=<host-git>` / `KUBECTL_BIN=<host-
    /// kubectl>` export after any test that scoped it — the exact
    /// failure mode the pre-lift RAII scope-guards were introduced to
    /// prevent.
    #[test]
    fn env_var_scope_restores_env_when_original_set() {
        let env_var = "TEST_ENV_VAR_SCOPE_SET_ROUND_TRIP";
        std::env::set_var(env_var, "prior-value");
        {
            let _scope = EnvVarScope::set(env_var, "sentinel-value");
            assert_eq!(
                std::env::var(env_var).ok().as_deref(),
                Some("sentinel-value"),
                "in-scope value must override"
            );
        }
        let restored = std::env::var(env_var);
        std::env::remove_var(env_var);
        assert_eq!(
            restored.ok().as_deref(),
            Some("prior-value"),
            "EnvVarScope must restore `{env_var}` to its pre-scope \
             value on drop — an operator's explicit export must not \
             be silently unset by a test that scopes it."
        );
    }

    /// [`EnvVarScope`] preserves the observable distinction between
    /// "set to empty string" and "unset" across the mutate-and-restore
    /// round trip. `std::env::var` returns `Ok("")` when a caller
    /// explicitly exports `<NAME>=""`, so the Drop body's `Ok(v) =>
    /// set_var(name, v)` branch must restore `""` — not fall through
    /// to `remove_var`. A drift to `.ok().filter(|s| !s.is_empty())`
    /// at the snapshot boundary (folding `Ok("")` into `Err`) would
    /// silently convert every explicit-empty export into an unset env
    /// var on drop.
    #[test]
    fn env_var_scope_restores_env_when_original_empty_string() {
        let env_var = "TEST_ENV_VAR_SCOPE_EMPTY_ROUND_TRIP";
        std::env::set_var(env_var, "");
        {
            let _scope = EnvVarScope::set(env_var, "sentinel-value");
            assert_eq!(
                std::env::var(env_var).ok().as_deref(),
                Some("sentinel-value"),
                "in-scope value must override the empty pre-scope export"
            );
        }
        let restored = std::env::var(env_var);
        std::env::remove_var(env_var);
        assert_eq!(
            restored.ok().as_deref(),
            Some(""),
            "EnvVarScope must restore an originally-empty export \
             (`{env_var}=\"\"`) verbatim on drop — the set-but-empty \
             vs unset distinction is observable at the primitive \
             boundary and must round-trip."
        );
    }

    /// [`EnvVarScope::drop`] fires on panic-unwind, not only on normal
    /// scope exit — the exact panic-safety property every pre-lift
    /// RAII scope-guard was introduced to provide. A drift to a
    /// `Drop`-less implementation (e.g., a `fn restore(self)`
    /// consuming call the caller has to remember) would silently leak
    /// `<NAME>=<sentinel>` to every subsequent test in the process
    /// after any panicking test that scoped it — the exact regression
    /// class the pre-lift `GitBinScope` / `KubectlBinScope` per-file
    /// copies were introduced to prevent.
    ///
    /// `AssertUnwindSafe` on the closure — `EnvVarScope` carries only
    /// a `&'static str` and a `Result<String, VarError>`, both
    /// unwind-safe, so no interior mutability crosses the boundary.
    #[test]
    fn env_var_scope_restores_on_panic_unwind() {
        let env_var = "TEST_ENV_VAR_SCOPE_PANIC_UNWIND";
        std::env::remove_var(env_var);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _scope = EnvVarScope::set(env_var, "sentinel-value");
            panic!("intentional panic to drive unwind path");
        }));
        assert!(
            result.is_err(),
            "the guarded scope must have panicked as expected"
        );
        assert!(
            std::env::var(env_var).is_err(),
            "EnvVarScope::drop must fire on panic-unwind — a leaked \
             `{env_var}=<sentinel>` post-unwind means the panic-safety \
             contract the RAII guard exists to provide has drifted."
        );
    }

    /// [`GitBinScope::set`] and
    /// `crate::infrastructure::kubectl::tests::KubectlBinScope::set`
    /// each MUST return an [`EnvVarScope`] whose `Drop` restores the
    /// pre-scope state on drop — the wrapper's zero-cost namespace
    /// discipline (unit struct + `impl { pub fn set(value: &str) ->
    /// EnvVarScope }`) must not silently degrade to returning `Self`
    /// (a re-inlined copy of the pre-lift struct) or `()` (a scope
    /// that leaks the sentinel on drop).
    ///
    /// The pin is behavioral, not structural: it drives the exact
    /// `GitBinScope::set(...)` call site every consumer uses, checks
    /// the returned guard mutates the env var in scope, and checks
    /// the guard restores the pre-scope state on drop. A regression
    /// that tidied the wrapper's return type to `()` or `Self` would
    /// either fail to compile (the mutate-and-drop composition
    /// requires an `EnvVarScope` return) or fail this restore check
    /// at runtime.
    #[test]
    fn git_bin_scope_wrapper_delegates_to_env_var_scope_primitive() {
        let _guard = GIT_BIN_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        std::env::remove_var("GIT_BIN");
        {
            let _scope = GitBinScope::set("/tmp/git-bin-scope-wrapper-delegation-sentinel");
            assert_eq!(
                std::env::var("GIT_BIN").ok().as_deref(),
                Some("/tmp/git-bin-scope-wrapper-delegation-sentinel"),
                "GitBinScope::set must write `GIT_BIN=<value>` on \
                 construction — a drift to a no-op wrapper would leave \
                 the env var unchanged."
            );
        }
        assert!(
            std::env::var("GIT_BIN").is_err(),
            "GitBinScope::set(...) must return an EnvVarScope whose \
             Drop restores the pre-scope state — a drift to a \
             leaked-on-drop return type would carry \
             `GIT_BIN=<sentinel>` into every subsequent test."
        );
    }

    /// Structural regression shield: the two pre-lift set-then-restore
    /// scope-guards (`test_support.rs::GitBinScope` and
    /// `infrastructure/kubectl.rs::tests::KubectlBinScope`) each
    /// carried a `struct <X>Scope { prior: std::result::Result<String,
    /// std::env::VarError> }` + `set(value: &str) -> Self { let prior
    /// = std::env::var(NAME); std::env::set_var(NAME, value); Self {
    /// prior } }` + panic-safe `Drop` triple — the byte-equivalent
    /// set-then-restore shape [`EnvVarScope`] now redeems. Post-lift
    /// no `.rs` file in `cli/src/` (other than `test_support.rs`
    /// itself, which owns the primitive declaration) may re-introduce
    /// a `struct <X>Scope { ... }` block carrying the `prior:
    /// Result<String, VarError>` field: every set-then-restore
    /// consumer must route through [`EnvVarScope::set`] (or a
    /// zero-cost wrapper like [`GitBinScope`] whose `impl { pub fn
    /// set(...) -> EnvVarScope }` returns the primitive's guard, not a
    /// re-inlined copy).
    ///
    /// The needle spells `Scope` (not `Snapshot`) so the sibling
    /// snapshot-only [`EnvVarSnapshot`] shape is unaffected by this
    /// shield; that shape has its own analogue at
    /// [`env_var_snapshot_pre_lift_snapshot_struct_shape_confined_to_test_support`].
    ///
    /// Walks the crate source tree via [`walk_rs_files`] so a future
    /// file added under any subdirectory of `cli/src/` is covered
    /// without a per-file shield update.
    #[test]
    fn env_var_scope_pre_lift_scope_struct_shape_confined_to_test_support() {
        let crate_src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut offenders: Vec<String> = Vec::new();
        walk_rs_files(&crate_src, &mut |path| {
            if path.file_name().and_then(|s| s.to_str()) == Some("test_support.rs") {
                return;
            }
            let contents =
                std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
            let lines: Vec<&str> = contents.lines().collect();
            for (i, line) in lines.iter().enumerate() {
                let trimmed = line.trim_start();
                let is_scope_struct = trimmed.starts_with("struct ")
                    && trimmed.contains("Scope")
                    && trimmed.trim_end().ends_with('{');
                if !is_scope_struct {
                    continue;
                }
                let has_prior_field =
                    lines.iter().skip(i + 1).take(8).any(|l| {
                        l.contains("prior: std::result::Result<String, std::env::VarError>")
                    });
                if has_prior_field {
                    let rel = path
                        .strip_prefix(&crate_src)
                        .unwrap_or(path)
                        .display()
                        .to_string();
                    offenders.push(format!("{rel}:{}: {}", i + 1, line.trim()));
                }
            }
        });
        assert!(
            offenders.is_empty(),
            "a `struct <X>Scope {{ ... prior: Result<String, VarError> ... }}` \
             declaration is reserved for `test_support.rs` — the pre-lift \
             `GitBinScope` / `KubectlBinScope` shape must not reappear \
             anywhere else in `cli/src/`; every set-then-restore \
             consumer routes through `crate::test_support::EnvVarScope::set(<NAME>, <value>)` \
             (or a zero-cost wrapper that returns it) instead. Offending sites:\n{}",
            offenders.join("\n")
        );
    }

    /// Structural regression shield: post-lift the inline snapshot-and-
    /// restore stanza the [`EnvVarSnapshot`] primitive redeems —
    ///
    /// ```ignore
    /// let prior = std::env::var("<NAME>");
    /// // ... mutate + call under test ...
    /// match &prior {
    ///     Ok(v) => std::env::set_var("<NAME>", v),
    ///     Err(_) => std::env::remove_var("<NAME>"),
    /// }
    /// ```
    ///
    /// — has NO business appearing in any `.rs` file outside
    /// `test_support.rs`. The primitive's `capture(<NAME>)` + panic-safe
    /// `Drop` supersedes the manual pattern verbatim AND closes an
    /// additional defect the inline stanza silently carried: any panic
    /// between the `let prior = ...` snapshot and the `match &prior
    /// { ... }` restore (e.g., an `.unwrap_err()` that unexpectedly saw
    /// `Ok`, an `.expect(...)` that fired, an assertion the pattern-
    /// author added before the restore in a later edit) leaks
    /// `<NAME>=<sentinel>` to every subsequent test in the process,
    /// because the restore is a straight-line statement rather than a
    /// `Drop` implementation. RAII closes that leak by construction —
    /// the exact panic-safety property the sibling primitive tests
    /// [`env_var_snapshot_restores_on_panic_unwind`]-style pins already
    /// enforce for the two RAII guards.
    ///
    /// Four pre-lift consumer sites redeemed the shield:
    /// `commands/developer_tools.rs`'s twin
    /// `test_service_path_from_env_*` tests and
    /// `commands/schema_validation.rs`'s twin
    /// `test_service_path_from_env_*` tests each spelled the
    /// five-line pattern VERBATIM around `super::service_path_from_env()`
    /// — 4× isomorphic copies past THEORY §VI.1's three-times threshold,
    /// each carrying the pre-lift panic-window defect.
    ///
    /// Detection: for each line matching `Err(_) => std::env::remove_var(`,
    /// check the previous line for `Ok(v) => std::env::set_var(`. The
    /// two-line pair uniquely identifies the Result-shaped restore
    /// stanza; bare `std::env::remove_var("FOO")` calls (e.g.,
    /// per-test env resets in `cli/src/repo.rs`) and Option-shaped
    /// `Some(v) => set_var / None => remove_var` matches (e.g.,
    /// `cli/src/commands/bootstrap.rs`, `cli/src/commands/helm.rs`)
    /// stay unshielded — they are morally-adjacent shapes with their
    /// own lift target, not this one.
    ///
    /// Sibling of
    /// [`env_var_snapshot_pre_lift_snapshot_struct_shape_confined_to_test_support`]
    /// (which shields the `struct <X>Snapshot { prior: ... }`
    /// declaration shape) and
    /// [`env_var_scope_pre_lift_scope_struct_shape_confined_to_test_support`]
    /// (which shields the set-then-restore `struct <X>Scope` shape) —
    /// the three shields exhaust the pre-lift Result-shaped env-var-
    /// guard surface between them.
    #[test]
    fn env_var_snapshot_pre_lift_inline_restore_stanza_confined_to_test_support() {
        let crate_src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut offenders: Vec<String> = Vec::new();
        walk_rs_files(&crate_src, &mut |path| {
            if path.file_name().and_then(|s| s.to_str()) == Some("test_support.rs") {
                return;
            }
            let contents =
                std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
            let lines: Vec<&str> = contents.lines().collect();
            for (i, line) in lines.iter().enumerate() {
                if !line.contains("Err(_) => std::env::remove_var(") {
                    continue;
                }
                let prev = match i.checked_sub(1).and_then(|j| lines.get(j)) {
                    Some(l) => l,
                    None => continue,
                };
                if !prev.contains("Ok(v) => std::env::set_var(") {
                    continue;
                }
                let rel = path
                    .strip_prefix(&crate_src)
                    .unwrap_or(path)
                    .display()
                    .to_string();
                offenders.push(format!("{rel}:{}: {}", i + 1, line.trim()));
            }
        });
        assert!(
            offenders.is_empty(),
            "the inline `match &<prior> {{ Ok(v) => std::env::set_var(<NAME>, v), \
             Err(_) => std::env::remove_var(<NAME>) }}` snapshot-and-restore stanza \
             is reserved for `test_support.rs` — every consumer must route through \
             `crate::test_support::EnvVarSnapshot::capture(<NAME>)` instead. The \
             primitive's panic-safe `Drop` closes the pre-lift panic-window defect \
             a straight-line manual restore silently carried (an `unwrap_err()` / \
             `.expect(...)` / assertion between snapshot and restore leaks \
             `<NAME>=<sentinel>` to every subsequent test in the process). \
             Offending sites:\n{}",
            offenders.join("\n")
        );
    }

    /// The Option-shaped sibling of
    /// [`env_var_snapshot_pre_lift_inline_restore_stanza_confined_to_test_support`]:
    /// the pre-lift `let prev = std::env::var("<NAME>").ok(); ...; match prev
    /// { Some(v) => std::env::set_var("<NAME>", v), None =>
    /// std::env::remove_var("<NAME>") }` stanza — the exact hand-rolled
    /// snapshot-and-restore shape the Result-shaped shield deliberately
    /// left unshielded (per its docstring: "Option-shaped `Some(v) =>
    /// set_var / None => remove_var` matches […] stay unshielded — they
    /// are morally-adjacent shapes with their own lift target, not this
    /// one"). This IS that lift target.
    ///
    /// Semantically identical to the Result-shaped stanza: `.ok()`
    /// projects `Result<String, VarError>` to `Option<String>`, so the
    /// arms restore Some(v) → set_var / None → remove_var vs Ok(v) →
    /// set_var / Err(_) → remove_var read the same env-var state on both
    /// sides. [`EnvVarSnapshot::capture`] stores the raw
    /// `Result<String, VarError>` and dispatches on it in Drop, so a
    /// consumer that previously snapshotted `.ok()` can drop the
    /// projection and just capture — the guard's semantics match.
    ///
    /// Two pre-lift consumer sites redeemed the shield:
    /// `commands/bootstrap.rs::test_bootstrap_binary_registry_url`
    /// (`BOOTSTRAP_REGISTRY`) and
    /// `commands/helm.rs::release_publish_tests::republish_is_off_unless_explicitly_enabled`
    /// (`FORGE_HELM_REPUBLISH`) each spelled the four-line pattern
    /// verbatim around the call under test. Combined with the four
    /// Result-shaped pre-lift copies the sibling shield closed
    /// (`developer_tools.rs` × 2, `schema_validation.rs` × 2), six
    /// isomorphic hand-rolled snapshot-and-restore stanzas across four
    /// modules fuse onto ONE [`EnvVarSnapshot::capture`] body — well
    /// past THEORY §VI.1's three-times-is-a-law threshold and each
    /// carrying the same panic-window defect the primitive's `Drop`
    /// closes by construction (any panic between snapshot and manual
    /// restore leaks `<NAME>=<sentinel>` to every subsequent test).
    ///
    /// Detection: for each line matching `None =>` and
    /// `unsafe { std::env::remove_var(`, check the previous line for
    /// `Some(v) =>` and `unsafe { std::env::set_var(`. The two-line pair
    /// with per-arm `unsafe { ... }` wrappers uniquely identifies the
    /// hand-rolled Option-shaped restore stanza the two consumer sites
    /// pre-lift carried — a shape the primitive's
    /// [`EnvVarSnapshot::capture`] supersedes without needing per-arm
    /// unsafe blocks (the guard's `Drop` runs safe `set_var` /
    /// `remove_var` calls under Rust 2021 semantics). Bare
    /// `std::env::remove_var(...)` calls, `Err(_) =>
    /// std::env::remove_var(...)` matches (the sibling Result-shaped
    /// shape), and the whole-match-in-one-unsafe-block form
    /// [`super::run_helm_capture_tests::with_helm_shim`] uses (which
    /// snapshots via `std::env::var_os` and belongs to the
    /// [`EnvVarScope`] surface, not this one) stay outside this shield's
    /// scope by construction — they are handled by the sibling shields
    /// on their own surfaces. The shield walks every `.rs` file under
    /// `cli/src/` via [`walk_rs_files`], skipping only `test_support.rs`
    /// so this shield's own docstring / body literal-string needles do
    /// not self-match. Together with the sibling
    /// [`env_var_snapshot_pre_lift_inline_restore_stanza_confined_to_test_support`],
    /// [`env_var_snapshot_pre_lift_snapshot_struct_shape_confined_to_test_support`],
    /// and
    /// [`env_var_scope_pre_lift_scope_struct_shape_confined_to_test_support`]
    /// shields, the four now exhaust the pre-lift env-var-guard surface
    /// (Result-shaped inline, Option-shaped inline, snapshot struct,
    /// scope struct) between them.
    #[test]
    fn env_var_snapshot_pre_lift_option_shaped_restore_stanza_confined_to_test_support() {
        let crate_src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut offenders: Vec<String> = Vec::new();
        walk_rs_files(&crate_src, &mut |path| {
            if path.file_name().and_then(|s| s.to_str()) == Some("test_support.rs") {
                return;
            }
            let contents =
                std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
            let lines: Vec<&str> = contents.lines().collect();
            for (i, line) in lines.iter().enumerate() {
                if !(line.contains("None =>")
                    && line.contains("unsafe {")
                    && line.contains("std::env::remove_var("))
                {
                    continue;
                }
                let prev = match i.checked_sub(1).and_then(|j| lines.get(j)) {
                    Some(l) => l,
                    None => continue,
                };
                if !(prev.contains("Some(v) =>")
                    && prev.contains("unsafe {")
                    && prev.contains("std::env::set_var("))
                {
                    continue;
                }
                let rel = path
                    .strip_prefix(&crate_src)
                    .unwrap_or(path)
                    .display()
                    .to_string();
                offenders.push(format!("{rel}:{}: {}", i + 1, line.trim()));
            }
        });
        assert!(
            offenders.is_empty(),
            "the inline `match <prev> {{ Some(v) => unsafe {{ std::env::set_var(<NAME>, v) }}, \
             None => unsafe {{ std::env::remove_var(<NAME>) }} }}` snapshot-and-restore stanza \
             is reserved for `test_support.rs` — every consumer must route through \
             `crate::test_support::EnvVarSnapshot::capture(<NAME>)` instead. The \
             primitive's panic-safe `Drop` closes the pre-lift panic-window defect \
             a straight-line manual restore silently carried (an `unwrap_err()` / \
             `.expect(...)` / assertion between snapshot and restore leaks \
             `<NAME>=<sentinel>` to every subsequent test in the process). \
             Offending sites:\n{}",
            offenders.join("\n")
        );
    }

    /// Recursively walk every `.rs` file under `dir`, invoking `visit`
    /// on each. Skips `target/` directories defensively even though
    /// none should live under `cli/src/`.
    fn walk_rs_files(dir: &std::path::Path, visit: &mut dyn FnMut(&std::path::Path)) {
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if path.file_name().and_then(|s| s.to_str()) == Some("target") {
                    continue;
                }
                walk_rs_files(&path, visit);
            } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
                visit(&path);
            }
        }
    }
}
