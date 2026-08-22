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
/// MUST route through [`crate::retry::run_inherited_status`], never
/// through a hand-rolled `.status().await` builder-terminator that
/// drops the exit code from the operator log line.
///
/// # Arguments
///
/// Same shape as the sync sibling. `spawns_description` names WHICH
/// async spawns the shield covers (e.g. `"the two `regenerate_compiler`
/// status-only spawn sites (`bundle lock --update` and `bundix`)"`).
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
/// - `code_line_hits(body, "run_inherited_status(").len() >=
///   min_delegations`. The needle `run_inherited_status(` has the
///   trailing `(` so it does NOT match `run_inherited_status_sync(`
///   (the character after `_status` is `_`, not `(`) — the two
///   frontiers count independently.
///
/// # Why one canonical helper
///
/// The nine-line shield body appears verbatim across three command
/// modules on the async spawn frontier (`build.rs` 72a7adf,
/// `pangea.rs` c5ff1c4, `product_release.rs` bf6d836) — past the
/// three-times-is-a-law threshold in its own right, and part of a
/// wider thirteen-shield family (10 sync + 3 async) with the sync
/// sibling above. A future refinement (structured diagnostic hook,
/// broadened inline needle, tighter cutoff) lands in one body per
/// frontier rather than at every site.
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
         `crate::retry::run_inherited_status`, which carries the exit \
         code into the failure envelope. Found: {inline:?}"
    );

    let delegations = code_line_hits(body, "run_inherited_status(").len();
    assert!(
        delegations >= min_delegations,
        "{module_path} must route {spawns_description} through \
         `run_inherited_status` — found only {delegations} \
         delegation call(s); a dropped call would leave the negative \
         `.status().await` scan satisfied by absence"
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
///   body MUST carry — summed across the three canonical entrypoints
///   `classify_capture_anyhow(` (the bare classifier over an already-
///   captured `Result<Output>`), `run_capture_anyhow(` (the async
///   run-wrapper), and `run_capture_anyhow_sync(` (the sync run-
///   wrapper). All three route through the ONE canonical
///   `classify_capture_anyhow` body at `retry.rs`, so any of the three
///   satisfies "the captured-output bail routes through the primitive"
///   — a shield that only recognized the bare classifier would refuse
///   a migration that spelled the higher-level run-wrapper (the
///   canonical shape once the run-* algebra closed at 06cd778). A
///   dropped delegation would leave the negative
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
///   `run_capture_anyhow(`, and `run_capture_anyhow_sync(` MUST hit
///   at least `min_delegations` times. Pins the positive floor so a
///   regression that both dropped the delegation AND accidentally left
///   the negative side satisfied (e.g. by rewriting the bail into a
///   `bail!("failed")` shape without `if !output.status.success`) fails
///   here. The three needles are mutually exclusive on any code line —
///   `classify_capture_anyhow` does not contain `run_capture_anyhow`
///   as a substring, `run_capture_anyhow_sync(` does not contain
///   `run_capture_anyhow(` (the char after `run_capture_anyhow` is
///   `_` not `(`), so summing without dedup is correct.
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
    let delegations = via_classify + via_run + via_run_sync;
    assert!(
        delegations >= min_delegations,
        "{label} must route captured-output bails through \
         `classify_capture_anyhow` (or `run_capture_anyhow` / \
         `run_capture_anyhow_sync`) — found only {delegations} \
         delegation call(s) (classify={via_classify}, \
         run={via_run}, run_sync={via_run_sync}); a dropped call would \
         leave the negative `if !output.status.success` scan satisfied \
         by absence"
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
}
