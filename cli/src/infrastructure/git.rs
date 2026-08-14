//! Git operations
//!
//! Async working-tree mutation surface for the bootstrap publish path —
//! pre-flight `is_clean` gate plus the `add` / `commit` / `push` triple
//! that lands FluxCD-reconciled kustomization updates. Every spawn
//! routes through the canonical typed-CLI primitives in
//! [`crate::retry`] so failures surface a structural
//! `(op, exit_code, stderr)` record on every branch instead of a
//! stringly bail.
//!
//! Synchronous SHA / repo-root discovery lives in [`crate::git`]
//! (env-var-first via `RELEASE_GIT_SHA` / `REPO_ROOT` then
//! `git rev-parse`); this module is the async mutation half and does
//! not duplicate that surface.

use anyhow::{Context, Result};
use tokio::process::Command;

use crate::error::GitError;
use crate::tools::{get_tool_path, tools};

/// Outcome of [`GitClient::stage_commit_push_release`].
///
/// `Pushed` means the index was dirty after `git add`, a commit was
/// recorded, and `git push` succeeded. `NoChangesStaged` means the
/// `git add` left the index byte-identical to `HEAD` — the file set
/// being released was already at the declared content (typical when
/// re-running a release at the same SHA after a FluxCD reconcile
/// already landed it) — so the commit and push are correctly skipped.
///
/// The enum is the typed alternative to the pre-migration
/// `commit_and_push_release` helpers that bailed on
/// `git diff --cached --quiet` returning success and otherwise
/// fell through to commit + push; pattern-matching on the typed
/// outcome gives callers a structural signal for "skipped because
/// idempotent" without parsing a log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitPushOutcome {
    /// `git add` left the index dirty; a commit was recorded and
    /// `git push origin <branch>` succeeded.
    Pushed,
    /// `git add` left the index byte-identical to `HEAD`; no commit
    /// or push was attempted. Idempotent re-release path.
    NoChangesStaged,
}

/// Client for git operations
pub struct GitClient {
    /// Working directory for git commands
    working_dir: Option<String>,
    /// Override for the `git` binary path.
    ///
    /// `None` in every production caller: [`Self::resolve_git_bin`]
    /// then resolves the binary through `get_tool_path(tools::GIT)`,
    /// which reads the `GIT_BIN` env var and falls back to the string
    /// `"git"` (PATH lookup) if unset — same idiom every other
    /// Nix-derivation-provided tool in forge honors
    /// (`SKOPEO_BIN` / `KUBECTL_BIN` / `ATTIC_BIN` / `NIX_BIN` /
    /// `FLUX_BIN` / `DOCA_BIN`, and the sibling `git`-free-function
    /// surface's own migration at commit 818ed9a).
    ///
    /// `Some(bin)` only from `#[cfg(test)]` via [`Self::with_git_bin`]:
    /// tests bind an absolute-path shim so the resolved binary is
    /// hermetic and parallel-safe (no `GIT_BIN` env mutation, no
    /// `PATH` mutation). Same shape as
    /// `AtticClient::with_attic_bin` on the sibling `attic` client
    /// (cli/src/infrastructure/attic.rs:129).
    git_bin: Option<String>,
}

impl Default for GitClient {
    fn default() -> Self {
        Self::new()
    }
}

impl GitClient {
    /// Create a new git client for current directory
    pub fn new() -> Self {
        Self {
            working_dir: None,
            git_bin: None,
        }
    }

    /// Create a git client for a specific directory
    pub fn in_dir(path: impl Into<String>) -> Self {
        Self {
            working_dir: Some(path.into()),
            git_bin: None,
        }
    }

    /// Override the path to the `git` binary. Used by tests to point at
    /// a hermetic shim; production code leaves this unset and lets
    /// [`Self::resolve_git_bin`] resolve it from `GIT_BIN` (or PATH).
    ///
    /// Mirror of `AtticClient::with_attic_bin` on the sibling attic
    /// client — same test-injection discipline, same builder shape.
    #[cfg(test)]
    pub fn with_git_bin(mut self, bin: impl Into<String>) -> Self {
        self.git_bin = Some(bin.into());
        self
    }

    /// Resolve the `git` binary path for the next spawn.
    ///
    /// Test override (`with_git_bin`) wins; otherwise
    /// `get_tool_path(tools::GIT)` — reads `GIT_BIN` env var, falls
    /// back to `"git"` (PATH). Every spawn path in this module reads
    /// through here so a future drift that hardcodes `"git"` at any
    /// site surfaces at
    /// `test_git_client_no_bin_surface_routes_through_git_bin_env_var`
    /// instead of as a silent-PATH-fallback bug at deploy time.
    fn resolve_git_bin(&self) -> String {
        self.git_bin
            .clone()
            .unwrap_or_else(|| get_tool_path(tools::GIT))
    }

    /// Check if working tree is clean.
    ///
    /// Spawn-vs-op dispatch flows through the canonical
    /// [`GitError::from_capture`] primitive — same shape
    /// `git.rs::git_capture` and `has_staged_changes` drive.
    /// Pre-this-migration this site did `cmd.output().await.context()? +
    /// return Ok(output.stdout.is_empty())` and ignored `output.status`
    /// entirely, so `git status --porcelain` exiting non-zero (the
    /// canonical "not a git repository" case is exit 128 with empty
    /// stdout, but permission-denied, signal-kill, and corrupt-index all
    /// share the same "non-zero exit + empty stdout" shape) routed
    /// silently to `Ok(true)` — i.e. "the tree is clean, proceed to
    /// skip the commit." The bootstrap publish path's lone caller
    /// (`commands/bootstrap.rs::publish_bootstrap_release` —
    /// `if git.is_clean().await? { info!("No changes to commit"); }`)
    /// then printed the no-change branch verbatim and the entire publish
    /// happily declared "✅ Bootstrap release complete!" without staging
    /// or pushing anything. Post-migration spawn failures route to
    /// `GitError::ExecFailed` and non-zero exits route to
    /// `GitError::OpFailed` carrying the structural
    /// `(exit_code, stderr)` tuple — the bootstrap caller's `?` operator
    /// surfaces the typed error verbatim instead of folding it into a
    /// silent skip.
    pub async fn is_clean(&self) -> Result<bool, GitError> {
        let mut cmd = Command::new(self.resolve_git_bin());
        cmd.args(["status", "--porcelain"]);

        if let Some(ref dir) = self.working_dir {
            cmd.current_dir(dir);
        }

        let output = GitError::from_capture(cmd.output().await, "status --porcelain")?;

        Ok(output.stdout.is_empty())
    }

    /// Stage files for commit
    ///
    /// Routes through the canonical [`crate::retry::run_inherited_status`]
    /// primitive — same shape as the thirty-plus prior status-only sites
    /// migrated across the forge command surface. Spawn failures and
    /// non-zero exits both surface a two-layer anyhow chain (outer
    /// caller-narrative + inner `git add failed (exit N)` structural
    /// record), carrying the exit code that the pre-migration
    /// `bail!("git add failed")` dropped.
    pub async fn add(&self, paths: &[&str]) -> Result<()> {
        let mut cmd = Command::new(self.resolve_git_bin());
        cmd.arg("add");
        cmd.args(paths);

        if let Some(ref dir) = self.working_dir {
            cmd.current_dir(dir);
        }

        crate::retry::run_inherited_status(cmd, "git add")
            .await
            .context("Failed to stage files for commit")
    }

    /// Create a commit
    ///
    /// Routes through [`crate::retry::run_inherited_status`]. Bootstrap's
    /// `is_clean()` guard upstream prevents the "nothing to commit"
    /// non-zero-exit shape from reaching here, so bail-on-non-zero is the
    /// correct semantic at this site (mirror of the carve-out at
    /// `commands/push.rs:194-204` which keeps warn-on-failure because its
    /// caller does NOT pre-check is_clean).
    pub async fn commit(&self, message: &str) -> Result<()> {
        let mut cmd = Command::new(self.resolve_git_bin());
        cmd.args(["commit", "-m", message]);

        if let Some(ref dir) = self.working_dir {
            cmd.current_dir(dir);
        }

        crate::retry::run_inherited_status(cmd, "git commit")
            .await
            .context("Failed to commit staged changes")
    }

    /// Push to remote
    ///
    /// Routes through [`crate::retry::run_inherited_status`]. A denied
    /// push (auth, branch protection, conflict) now surfaces with the
    /// exit code carried in the structural record, restoring symmetry
    /// with the sibling GitOps publish path migrated in fe3b1bc
    /// (`commands/push.rs::update_kustomization`).
    pub async fn push(&self) -> Result<()> {
        let mut cmd = Command::new(self.resolve_git_bin());
        cmd.arg("push");

        if let Some(ref dir) = self.working_dir {
            cmd.current_dir(dir);
        }

        crate::retry::run_inherited_status(cmd, "git push")
            .await
            .context("Failed to push commits to remote")
    }

    /// Push HEAD to an explicit `(remote, branch)` endpoint.
    ///
    /// Sibling of [`Self::push`] that targets an explicit
    /// `git push <remote> <branch>` invocation. Used by release flows
    /// that always publish to a well-known endpoint (the kenshi /
    /// kenshi-agent / nix-builder release flows that this module's
    /// [`Self::stage_commit_push_release`] primitive lifts).
    /// Routes through [`crate::retry::run_inherited_status`] so the
    /// failure record carries the exit code that the pre-migration
    /// `bail!("Failed to push release to git")` sites dropped.
    pub async fn push_to(&self, remote: &str, branch: &str) -> Result<()> {
        let mut cmd = Command::new(self.resolve_git_bin());
        cmd.args(["push", remote, branch]);

        if let Some(ref dir) = self.working_dir {
            cmd.current_dir(dir);
        }

        crate::retry::run_inherited_status(cmd, "git push")
            .await
            .context("Failed to push commits to remote")
    }

    /// Return `true` iff `git diff --cached --name-only` reports any
    /// path with staged changes — i.e. a subsequent `git commit` would
    /// produce a non-empty commit.
    ///
    /// Sibling of [`Self::is_clean`] (which inspects the working tree
    /// via `git status --porcelain`). The index-side predicate is the
    /// load-bearing precondition for [`Self::stage_commit_push_release`]'s
    /// skip-on-idempotent shape: after `git add <files>`, an empty
    /// staged diff means the files were already at their declared
    /// content and the commit + push must be skipped to preserve the
    /// idempotent-re-release contract that downstream FluxCD
    /// reconciliation depends on.
    ///
    /// Spawn-vs-op dispatch flows through the canonical
    /// [`GitError::from_capture`] primitive — same shape as
    /// [`Self::is_clean`]. A non-zero git exit (the "not a git
    /// repository" / "corrupt index" family) routes to
    /// `GitError::OpFailed` carrying the structural
    /// `(exit_code, stderr)` tuple instead of folding into a silent
    /// `Ok(false)` the way a pre-migration body that ignored
    /// `output.status` would have done.
    pub async fn has_staged_changes(&self) -> Result<bool, GitError> {
        let mut cmd = Command::new(self.resolve_git_bin());
        cmd.args(["diff", "--cached", "--name-only"]);

        if let Some(ref dir) = self.working_dir {
            cmd.current_dir(dir);
        }

        let output = GitError::from_capture(cmd.output().await, "diff --cached --name-only")?;

        Ok(!output.stdout.is_empty())
    }

    /// Stage `files`, then — if anything was actually staged — commit
    /// with `commit_message` and push to `origin/<branch>`. Idempotent
    /// re-release path: when `git add` leaves the index byte-identical
    /// to `HEAD`, return [`CommitPushOutcome::NoChangesStaged`]
    /// WITHOUT committing or pushing.
    ///
    /// # Why this primitive
    ///
    /// Three identical async helpers — `commit_and_push_release` in
    /// `commands/kenshi.rs`, `commands/kenshi_agent.rs`, and
    /// `commands/nix_builder.rs` — each spelled out the same
    /// four-step sequence verbatim, modulo the commit message format
    /// and the file-slice element type (`&[&str]` vs `&[String]`):
    ///
    /// 1. `git add <files>`
    /// 2. `git diff --cached --quiet` → bail-skip if clean
    /// 3. `git commit -m <message>`
    /// 4. `git push origin main`
    ///
    /// Each step was a hand-rolled `TokioCommand::new("git").args(…)
    /// .status().await.context(…)?` block with an `if
    /// !status.success() { bail!(…) }` envelope — exactly the
    /// eleven-line stanza that [`crate::retry::run_inherited_status`]
    /// was carved out to retire. Three occurrences is THEORY §VI.1's
    /// three-is-a-law trigger; this primitive is the law-redeeming
    /// extraction.
    ///
    /// Post-migration every step routes through the canonical typed
    /// primitive: [`Self::add`] / [`Self::commit`] / [`Self::push_to`]
    /// for the inherited-stdio user-facing ops, [`Self::has_staged_changes`]
    /// for the index predicate. A future Phase 1 attestation-record
    /// consumer (THEORY §V.4) that wants to seal each release commit
    /// pattern-matches on [`CommitPushOutcome::Pushed`] in one place
    /// instead of three.
    pub async fn stage_commit_push_release(
        &self,
        files: &[&str],
        commit_message: &str,
        branch: &str,
    ) -> Result<CommitPushOutcome> {
        self.add(files).await?;
        if !self.has_staged_changes().await? {
            return Ok(CommitPushOutcome::NoChangesStaged);
        }
        self.commit(commit_message).await?;
        self.push_to("origin", branch).await?;
        Ok(CommitPushOutcome::Pushed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::git::git_command_sync;
    use crate::test_support::{
        add_bare_origin, init_repo_with_one_commit, make_executable_shim, GitBinScope,
        GIT_BIN_ENV_LOCK,
    };

    /// Test-binding helper: build a `GitClient` in `dir` whose spawn
    /// path is pinned to the string literal `"git"` (PATH lookup) via
    /// [`GitClient::with_git_bin`]. Every existing test in this module
    /// used the pre-migration `Command::new("git")` shape verbatim; the
    /// post-migration [`GitClient::resolve_git_bin`] reads `GIT_BIN` on
    /// every call, so a concurrent test that mutates `GIT_BIN` to a
    /// hermetic shim (as
    /// [`test_git_client_no_bin_surface_routes_through_git_bin_env_var`]
    /// below does) would race into these tests' spawn paths and
    /// silently redirect them to the shim.
    ///
    /// Binding `git_bin = Some("git")` here dodges the race by making
    /// each existing test's spawn path independent of `GIT_BIN`
    /// entirely — the resolved binary is the string `"git"` regardless
    /// of what env var is set — which is the exact same PATH-lookup
    /// shape they had pre-migration.
    fn git_client_in_dir_path_git(dir: &std::path::Path) -> GitClient {
        GitClient::in_dir(dir.to_string_lossy().to_string()).with_git_bin("git")
    }

    /// On a freshly-seeded repo with no `git add` since the last
    /// commit, the index is byte-identical to `HEAD` and
    /// `has_staged_changes` MUST return `false`. Pins the predicate's
    /// happy-path quiescent behavior — the precondition for
    /// `stage_commit_push_release` returning `NoChangesStaged`.
    #[tokio::test]
    async fn test_has_staged_changes_returns_false_on_clean_index() {
        let dir = tempfile::tempdir().expect("tempdir");
        init_repo_with_one_commit(dir.path());
        let client = git_client_in_dir_path_git(dir.path());
        let staged = client
            .has_staged_changes()
            .await
            .expect("predicate must succeed");
        assert!(
            !staged,
            "clean index must report no staged changes; got staged=true"
        );
    }

    /// After staging a new file, the index diverges from `HEAD` and
    /// `has_staged_changes` MUST return `true`. Pins the predicate's
    /// dirty-path behavior — the precondition for
    /// `stage_commit_push_release` falling through to commit + push.
    #[tokio::test]
    async fn test_has_staged_changes_returns_true_when_index_dirty() {
        let dir = tempfile::tempdir().expect("tempdir");
        init_repo_with_one_commit(dir.path());
        std::fs::write(dir.path().join("staged.txt"), "fresh\n").unwrap();
        // Route the fixture-side `git add` through the canonical
        // `git_command_sync()` constructor so the resolved binary is the
        // same `GIT_BIN`-pinned store path every production consumer in
        // this module routes through. `git_command_sync()` reads
        // `GIT_BIN` at spawn time, so hold `GIT_BIN_ENV_LOCK` across the
        // spawn to serialize against every concurrent test that mutates
        // the env var (`test_git_client_no_bin_surface_routes_through_git_bin_env_var`
        // below and the sibling shim-driven tests in `cli/src/git.rs`).
        // `init_repo_with_one_commit` has already acquired + released the
        // lock by this point (it holds it internally for its own two
        // spawns), so the fresh acquisition here does not deadlock.
        let add = {
            let _guard = GIT_BIN_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
            git_command_sync()
                .args(["add", "staged.txt"])
                .current_dir(dir.path())
                .status()
                .expect("git add")
        };
        assert!(add.success());
        let client = git_client_in_dir_path_git(dir.path());
        let staged = client
            .has_staged_changes()
            .await
            .expect("predicate must succeed");
        assert!(
            staged,
            "dirty index must report staged changes; got staged=false"
        );
    }

    /// `has_staged_changes` against a non-git directory MUST surface
    /// a typed `GitError::OpFailed` carrying the structural
    /// `(exit_code, stderr)` tuple — never the silent `Ok(false)` a
    /// pre-migration body that ignored `output.status` would have
    /// produced. The structural pin is the typed split (OpFailed,
    /// NOT ExecFailed — git DID spawn, it just rejected the
    /// invocation) carrying a non-zero exit and non-empty stderr;
    /// the specific exit-code value and diagnostic text vary across
    /// git versions (some surface "not a git repository" with exit
    /// 128, others fall through to `git diff --no-index` and reject
    /// `--cached` with a usage error and a different exit code) and
    /// pinning either would couple the test to git's release-train
    /// rather than to the typed-CLI contract this primitive carves
    /// out. Sibling of
    /// `test_is_clean_non_zero_exit_surfaces_typed_op_failed` above.
    #[tokio::test]
    async fn test_has_staged_changes_non_zero_exit_surfaces_typed_op_failed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let client = git_client_in_dir_path_git(dir.path());
        let err = client
            .has_staged_changes()
            .await
            .expect_err("non-git directory must surface typed error");
        match err {
            GitError::OpFailed {
                op,
                exit_code,
                stderr,
            } => {
                assert_eq!(op, "diff --cached --name-only");
                let code = exit_code.expect("non-zero exit must travel through");
                assert!(
                    code != 0,
                    "non-git directory must surface a non-zero exit code; got {code}"
                );
                assert!(
                    !stderr.is_empty(),
                    "stderr must carry git's diagnostic (any form); got empty stderr"
                );
            }
            other => panic!("expected GitError::OpFailed, got: {other:?}"),
        }
    }

    /// `stage_commit_push_release` invoked against a file set whose
    /// content already matches `HEAD` MUST return
    /// `CommitPushOutcome::NoChangesStaged` and MUST NOT attempt the
    /// commit or push. Pins the idempotent-re-release contract: a
    /// re-run of a release at the same SHA does not produce an
    /// orphaned empty commit and does not contact the (in-test:
    /// absent) remote.
    ///
    /// We assert the "did not push" half structurally: the test repo
    /// has NO `origin` remote configured, so a fall-through to
    /// `push_to("origin", "main")` would fail with `GitError::OpFailed`
    /// or `RemoteOpFailed` and the test would surface that error.
    /// A clean `Ok(NoChangesStaged)` proves the skip happened before
    /// any push spawn.
    #[tokio::test]
    async fn test_stage_commit_push_release_skips_on_clean_index() {
        let dir = tempfile::tempdir().expect("tempdir");
        init_repo_with_one_commit(dir.path());
        let client = git_client_in_dir_path_git(dir.path());
        let outcome = client
            .stage_commit_push_release(&["seed.txt"], "should-not-commit", "main")
            .await
            .expect("re-adding already-committed file must succeed with NoChangesStaged");
        assert_eq!(
            outcome,
            CommitPushOutcome::NoChangesStaged,
            "re-staging an already-committed file must skip commit + push"
        );
    }

    /// `stage_commit_push_release` invoked with a dirty index MUST
    /// commit and push, returning `CommitPushOutcome::Pushed`. Uses
    /// a bare local repo as the `origin` remote so the push succeeds
    /// hermetically. Pins the happy-path sequence: add → commit →
    /// push, with the typed outcome surfacing the terminal step.
    #[tokio::test]
    async fn test_stage_commit_push_release_returns_pushed_on_dirty_index() {
        let work = tempfile::tempdir().expect("work tempdir");
        let bare = tempfile::tempdir().expect("bare tempdir");
        init_repo_with_one_commit(work.path());
        add_bare_origin(work.path(), bare.path());
        std::fs::write(work.path().join("change.txt"), "delta\n").unwrap();
        let client = git_client_in_dir_path_git(work.path());
        let outcome = client
            .stage_commit_push_release(&["change.txt"], "test: release", "main")
            .await
            .expect("happy-path stage+commit+push must succeed");
        assert_eq!(
            outcome,
            CommitPushOutcome::Pushed,
            "dirty index must drive through to commit + push"
        );
    }

    /// `CommitPushOutcome::Pushed` and `NoChangesStaged` MUST be
    /// distinct variants — pattern-match exhaustively. Pins the
    /// typed-discriminator contract: callers MUST handle both
    /// outcomes (logging "pushed" vs "no-op"), and a future drift
    /// that fused the two into a bool would lose the structural
    /// signal this primitive carves out.
    #[test]
    fn test_commit_push_outcome_variants_are_distinct() {
        assert_ne!(
            CommitPushOutcome::Pushed,
            CommitPushOutcome::NoChangesStaged
        );
        fn classify(o: CommitPushOutcome) -> &'static str {
            match o {
                CommitPushOutcome::Pushed => "pushed",
                CommitPushOutcome::NoChangesStaged => "skipped",
            }
        }
        assert_eq!(classify(CommitPushOutcome::Pushed), "pushed");
        assert_eq!(classify(CommitPushOutcome::NoChangesStaged), "skipped");
    }

    /// Pre-migration, `is_clean` ignored `output.status` and returned
    /// `Ok(output.stdout.is_empty())` for every spawn-succeeded
    /// invocation — including `git status --porcelain` exiting 128
    /// against a non-git directory, which prints stderr `fatal: not a
    /// git repository` and an empty stdout. The bootstrap publish path
    /// (`commands/bootstrap.rs:569`) folded that into `if
    /// git.is_clean().await? { info!("No changes to commit"); }` and
    /// silently skipped the kustomization commit + push entirely. This
    /// test pins the post-migration contract: a non-zero git exit
    /// surfaces a typed `GitError::OpFailed` carrying the
    /// `(exit_code, stderr)` tuple — never the silent `Ok(true)` the
    /// pre-migration body produced. The bootstrap caller's `?` operator
    /// now surfaces the failure verbatim instead of folding into the
    /// no-change branch.
    #[tokio::test]
    async fn test_is_clean_non_zero_exit_surfaces_typed_op_failed() {
        // `tempfile::tempdir()` creates a fresh directory under
        // `$TMPDIR` (typically `/tmp/...`) with no `.git` ancestor on
        // any reasonable host or CI runner. `git status --porcelain`
        // run against such a directory walks up to the filesystem root
        // without finding a repo and exits 128 with stderr
        // "fatal: not a git repository". The shape this test pins is
        // the canonical bug scenario the pre-migration body papered
        // over — empty stdout + non-zero exit + non-empty stderr.
        let dir = tempfile::tempdir().expect("tempdir");
        let client = git_client_in_dir_path_git(dir.path());
        let err = client.is_clean().await.expect_err(
            "is_clean against a non-git directory must surface a typed error, \
             never the silent Ok(true) the pre-migration body produced",
        );
        match err {
            GitError::OpFailed {
                op,
                exit_code,
                stderr,
            } => {
                assert_eq!(op, "status --porcelain");
                assert_eq!(
                    exit_code,
                    Some(128),
                    "git's not-a-git-repository exit code must travel through"
                );
                assert!(
                    stderr.contains("not a git repository"),
                    "stderr must carry git's diagnostic verbatim, got: {stderr:?}"
                );
            }
            other => {
                panic!("expected GitError::OpFailed carrying (exit_code, stderr), got: {other:?}")
            }
        }
    }

    /// Every no-`with_git_bin`-override entry point on `GitClient`
    /// MUST resolve the `git` binary through `get_tool_path(tools::GIT)`
    /// — i.e. read the `GIT_BIN` env var — never spawn the bare string
    /// literal `"git"`. Pre-migration all six sites (`is_clean`, `add`,
    /// `commit`, `push`, `push_to`, `has_staged_changes`) spelled
    /// `Command::new("git")` verbatim and every one bypassed `GIT_BIN`,
    /// silently degrading to whatever `git` was first on `PATH` at
    /// spawn time — the same class of bug the sibling `flux` /
    /// `cargo` / `doca` / free-function-`git` surface migrations
    /// redeemed (flake commits 621f827 / f0dfa12 / d3dd199 / 685642f /
    /// d6f6bc7 / dd5a212, 673e4be / b02d4eb / 54a9985, 139b37a,
    /// 818ed9a).
    ///
    /// The pin exercises `GIT_BIN` set to a hermetic shim whose stderr
    /// carries a distinctive sigil. Each of the six sites produces a
    /// typed failure carrying the shim's stderr verbatim, so seeing the
    /// sigil on every one is proof the resolution went through the
    /// shim, not through PATH. A regression that "tidies" any of the
    /// six back to `Command::new("git")` surfaces as a failed sigil
    /// assertion here rather than as a silent-`PATH`-fallback bug at
    /// deploy time.
    ///
    /// Runs under [`GIT_BIN_ENV_LOCK`] to serialize against every other
    /// test in the crate that either mutates `GIT_BIN` or invokes a
    /// no-bin production entry point that reads it — same discipline
    /// as `git.rs::test_no_bin_entry_points_route_through_git_bin_env_var`.
    /// The [`GitBinScope`] guard restores the pre-scope state on drop
    /// so this test cannot leak `GIT_BIN=<dropped-shim>` to the next
    /// lock-holder.
    #[tokio::test]
    async fn test_git_client_no_bin_surface_routes_through_git_bin_env_var() {
        let _guard = GIT_BIN_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());

        let sigil = "SIGIL_INFRA_GIT_CLIENT_ROUTED_c9d4e0";
        let (_shim_dir, shim) =
            make_executable_shim("git", &format!("#!/bin/sh\necho '{sigil}' 1>&2\nexit 77\n"));
        let _scope = GitBinScope::set(&shim);

        // A tempdir working directory keeps the shim spawn hermetic —
        // no ambient .git ancestor can confuse the fixture.
        let dir = tempfile::tempdir().expect("tempdir");
        let workdir = dir.path().to_string_lossy().to_string();
        // Default GitClient (no `with_git_bin` override) — the
        // production shape. Every method reads `GIT_BIN` at spawn.
        let client = GitClient::in_dir(&workdir);

        // ---- Capture-arm sites: is_clean, has_staged_changes ----
        // These return `Result<bool, GitError>` and route non-zero
        // exits through `GitError::from_capture` → `OpFailed` carrying
        // structural `(op, exit_code, stderr)`. The shim's stderr sigil
        // and exit code 77 must ride through verbatim.
        match client
            .is_clean()
            .await
            .expect_err("shim exits 77; is_clean must surface a typed error")
        {
            GitError::OpFailed {
                op,
                exit_code,
                stderr,
            } => {
                assert_eq!(op, "status --porcelain");
                assert_eq!(exit_code, Some(77), "shim exit code must ride through");
                assert!(
                    stderr.contains(sigil),
                    "is_clean stderr must carry shim sigil — proves the \
                     no-override spawn routed through GIT_BIN, not literal \"git\". \
                     Got stderr={stderr:?}"
                );
            }
            other => panic!("expected OpFailed on is_clean, got: {other:?}"),
        }

        match client
            .has_staged_changes()
            .await
            .expect_err("shim exits 77; has_staged_changes must surface a typed error")
        {
            GitError::OpFailed {
                op,
                exit_code,
                stderr,
            } => {
                assert_eq!(op, "diff --cached --name-only");
                assert_eq!(exit_code, Some(77));
                assert!(
                    stderr.contains(sigil),
                    "has_staged_changes stderr must carry shim sigil. Got stderr={stderr:?}"
                );
            }
            other => panic!("expected OpFailed on has_staged_changes, got: {other:?}"),
        }

        // ---- Inherited-stdio sites: add, commit, push, push_to ----
        // These return `anyhow::Result<()>` from
        // `retry::run_inherited_status`. Non-zero exit produces a
        // two-layer anyhow chain: outer caller-narrative + inner
        // `git <op> failed (exit N)`. The shim's exit code 77 must
        // ride through the inner chain. (The shim's stderr sigil is
        // printed on inherited stderr and is NOT captured into the
        // anyhow error chain — the exit-code carrying is the
        // structural pin for these four sites; PATH-hardcoded
        // spellings that bypassed GIT_BIN would surface a DIFFERENT
        // exit code — the ambient git's exit for the same args —
        // rather than the shim's 77.)
        for (label, err) in [
            ("add", client.add(&["nonexistent"]).await),
            ("commit", client.commit("msg").await),
            ("push", client.push().await),
            ("push_to", client.push_to("origin", "main").await),
        ] {
            let err = err.unwrap_err_or_else_pinned(label);
            let chain = format!("{err:#}");
            assert!(
                chain.contains("exit 77"),
                "{label} must carry shim exit 77 through the anyhow chain — \
                 proves the no-override spawn routed through GIT_BIN, not \
                 literal \"git\". Got chain={chain}"
            );
        }
    }

    /// `unwrap_err` with a per-label panic message. A tiny local
    /// helper — the loop above needs a labeled panic for each of the
    /// four inherited-stdio sites, and `expect_err(&format!(...))`
    /// costs a String allocation on every iteration even in the
    /// happy path.
    trait UnwrapErrOrElsePinned<T, E: std::fmt::Debug> {
        fn unwrap_err_or_else_pinned(self, label: &str) -> E;
    }

    impl<T: std::fmt::Debug, E: std::fmt::Debug> UnwrapErrOrElsePinned<T, E> for Result<T, E> {
        fn unwrap_err_or_else_pinned(self, label: &str) -> E {
            match self {
                Ok(v) => panic!("{label}: expected shim-exit-77 failure, got Ok({v:?})"),
                Err(e) => e,
            }
        }
    }

    /// Every git-spawning site in `cli/src/infrastructure/git.rs` — both
    /// the production `GitClient` methods AND the test-side fixture step
    /// in [`test_has_staged_changes_returns_true_when_index_dirty`] —
    /// must resolve `GIT_BIN` via the canonical
    /// [`crate::git::git_command_sync`] / [`crate::git::git_command_async`]
    /// constructors, or via `Command::new(self.resolve_git_bin())`
    /// (which threads `get_tool_path(tools::GIT)` through
    /// [`GitClient::resolve_git_bin`]). A Nix-hermetic runner invocation
    /// with a substrate-derivation-pinned `git` must land at that same
    /// store path, not at whichever `git` sits first on `PATH`.
    ///
    /// Pre-shield the test-side `git add` fixture at the sibling test
    /// [`test_has_staged_changes_returns_true_when_index_dirty`]
    /// spelled the raw `SyncCommand::new("git")` shape via a
    /// `use std::process::Command as SyncCommand;` alias, silently
    /// bypassing `GIT_BIN`. A hermetic test suite invoked with `GIT_BIN`
    /// pinned to a substrate-derivation shim would lose the shim at
    /// exactly this fixture step — a wrong-provenance `git` staging a
    /// file into the tempdir index while every production
    /// `has_staged_changes` / `add` / `commit` / `push` spawn in the
    /// same test resolved the substrate-pinned `git`. The two `git`s
    /// would observe different index states and the assertion could
    /// pass or fail for the wrong reason. Same class of foreign-`git`-
    /// observing-substrate-`git` inversion the sibling shields in
    /// `cli/src/git.rs` (932cddf), `cli/src/test_support.rs` (3036a55),
    /// `commands/release_commit.rs` (8f27812),
    /// `commands/product_release.rs` (0ea75ba), and
    /// `commands/attestation.rs` (1c90949) close on their modules.
    ///
    /// The four forbidden shapes (`std::process::Command::new("git")`,
    /// bare `Command::new("git")`, `tokio::process::Command::new("git")`,
    /// and the module-local `SyncCommand::new("git")` alias form the
    /// pre-shield test module used) are reconstructed via `format!` from
    /// the bare string `"git"` so this shield's own source text does not
    /// false-match itself. A per-line filter drops `///` / `//!` / `//`
    /// comment lines so the pre-existing docstrings on `stage_commit_push_release`
    /// (line 297), `git_client_in_dir_path_git` (line 340), and
    /// `test_git_client_no_bin_surface_routes_through_git_bin_env_var`
    /// (lines 581, 594) — which narrate the historical
    /// `Command::new("git")` anti-pattern by literal quotation — do not
    /// register as violations; the shield fires only on executable code.
    ///
    /// The production body of this module (`is_clean`, `add`, `commit`,
    /// `push`, `push_to`, `has_staged_changes`) spawns via
    /// `Command::new(self.resolve_git_bin())` — a variable, not the bare
    /// literal — so it does not match. The end-to-end `GIT_BIN`-routing
    /// invariant of the underlying `resolve_git_bin` predicate is pinned
    /// separately by
    /// [`test_git_client_no_bin_surface_routes_through_git_bin_env_var`]
    /// above; this shield only certifies that every git-spawning site in
    /// this module reads through one of the canonical constructors.
    #[test]
    fn test_infra_git_spawn_routes_through_git_command_sync_not_raw_literal() {
        const SOURCE: &str = include_str!("git.rs");

        let [raw_std, raw_bare, raw_tokio] = crate::test_support::forbidden_spawn_shapes("git");
        let raw_sync_alias = format!("SyncCommand::new(\"{}\")", "git");

        let is_code_line = |line: &str| -> bool {
            let t = line.trim_start();
            !t.starts_with("///") && !t.starts_with("//!") && !t.starts_with("//")
        };

        let hits_for = |needle: &str| -> Vec<String> {
            SOURCE
                .lines()
                .enumerate()
                .filter(|(_, l)| l.contains(needle))
                .filter(|(_, l)| is_code_line(l))
                .map(|(i, l)| format!("line {}: {}", i + 1, l.trim()))
                .collect()
        };

        let std_hits = hits_for(&raw_std);
        assert!(
            std_hits.is_empty(),
            "cli/src/infrastructure/git.rs must not spawn `git` via the \
             bare literal at `std::process::Command::new` — every git \
             spawn must resolve `GIT_BIN` via `git_command_sync()` / \
             `git_command_async()` (or via `Command::new(self.resolve_git_bin())` \
             on the `GitClient` production body). A raw literal bypasses \
             the hermetic-runner contract substrate's `mkRuntimeToolsEnv` \
             exports. Offending code lines: {std_hits:?}"
        );

        let bare_hits = hits_for(&raw_bare);
        assert!(
            bare_hits.is_empty(),
            "cli/src/infrastructure/git.rs must not spawn `git` via the \
             bare literal at `Command::new` (top-of-file alias) — every \
             git spawn must resolve `GIT_BIN` via `git_command_sync()` / \
             `git_command_async()` (or via `Command::new(self.resolve_git_bin())` \
             on the `GitClient` production body). A raw literal bypasses \
             the hermetic-runner contract. Offending code lines: \
             {bare_hits:?}"
        );

        let tokio_hits = hits_for(&raw_tokio);
        assert!(
            tokio_hits.is_empty(),
            "cli/src/infrastructure/git.rs must not spawn `git` via the \
             bare literal at `tokio::process::Command::new` — every \
             async git spawn must resolve `GIT_BIN` via \
             `git_command_async()` first. A raw literal bypasses the \
             hermetic-runner contract. Offending code lines: {tokio_hits:?}"
        );

        let alias_hits = hits_for(&raw_sync_alias);
        assert!(
            alias_hits.is_empty(),
            "cli/src/infrastructure/git.rs must not spawn `git` via the \
             module-local `SyncCommand` alias (`use std::process::Command as SyncCommand`) — \
             a fixture-side spawn through the alias silently bypassed \
             `GIT_BIN` for one release cycle and observed a foreign \
             `git`'s staging of the tempdir index while every production \
             consumer resolved the substrate-pinned `git`. Route via \
             `crate::git::git_command_sync()` instead. Offending code \
             lines: {alias_hits:?}"
        );

        assert!(
            SOURCE.contains("use crate::git::git_command_sync"),
            "cli/src/infrastructure/git.rs must import the canonical \
             `git_command_sync` constructor — the required form was not \
             found in the module. A regression that removed it would \
             silently downgrade the fixture-side git spawn to the raw \
             literal it was lifted from."
        );
    }
}
