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
use crate::retry::classify_capture;

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
}

impl Default for GitClient {
    fn default() -> Self {
        Self::new()
    }
}

impl GitClient {
    /// Create a new git client for current directory
    pub fn new() -> Self {
        Self { working_dir: None }
    }

    /// Create a git client for a specific directory
    pub fn in_dir(path: impl Into<String>) -> Self {
        Self {
            working_dir: Some(path.into()),
        }
    }

    /// Check if working tree is clean.
    ///
    /// Spawn-vs-op dispatch flows through the canonical
    /// [`classify_capture`] primitive — same shape `git.rs::git_capture`
    /// and `git.rs::git_capture_remote` already drive. Pre-this-migration
    /// this site did `cmd.output().await.context()? + return
    /// Ok(output.stdout.is_empty())` and ignored `output.status` entirely,
    /// so `git status --porcelain` exiting non-zero (the canonical "not a
    /// git repository" case is exit 128 with empty stdout, but permission-
    /// denied, signal-kill, and corrupt-index all share the same
    /// "non-zero exit + empty stdout" shape) routed silently to
    /// `Ok(true)` — i.e. "the tree is clean, proceed to skip the commit."
    /// The bootstrap publish path's lone caller
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
        let mut cmd = Command::new("git");
        cmd.args(["status", "--porcelain"]);

        if let Some(ref dir) = self.working_dir {
            cmd.current_dir(dir);
        }

        let output = classify_capture(
            cmd.output().await,
            |e| GitError::ExecFailed {
                op: "status --porcelain".to_string(),
                message: e.to_string(),
            },
            |cf| GitError::OpFailed {
                op: "status --porcelain".to_string(),
                exit_code: cf.exit_code,
                stderr: cf.stderr,
            },
        )?;

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
        let mut cmd = Command::new("git");
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
        let mut cmd = Command::new("git");
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
        let mut cmd = Command::new("git");
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
        let mut cmd = Command::new("git");
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
    /// [`classify_capture`] primitive — same shape as
    /// [`Self::is_clean`]. A non-zero git exit (the "not a git
    /// repository" / "corrupt index" family) routes to
    /// `GitError::OpFailed` carrying the structural
    /// `(exit_code, stderr)` tuple instead of folding into a silent
    /// `Ok(false)` the way a pre-migration body that ignored
    /// `output.status` would have done.
    pub async fn has_staged_changes(&self) -> Result<bool, GitError> {
        let mut cmd = Command::new("git");
        cmd.args(["diff", "--cached", "--name-only"]);

        if let Some(ref dir) = self.working_dir {
            cmd.current_dir(dir);
        }

        let output = classify_capture(
            cmd.output().await,
            |e| GitError::ExecFailed {
                op: "diff --cached --name-only".to_string(),
                message: e.to_string(),
            },
            |cf| GitError::OpFailed {
                op: "diff --cached --name-only".to_string(),
                exit_code: cf.exit_code,
                stderr: cf.stderr,
            },
        )?;

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
    use crate::test_support::{add_bare_origin, init_repo_with_one_commit};
    use std::process::Command as SyncCommand;

    /// On a freshly-seeded repo with no `git add` since the last
    /// commit, the index is byte-identical to `HEAD` and
    /// `has_staged_changes` MUST return `false`. Pins the predicate's
    /// happy-path quiescent behavior — the precondition for
    /// `stage_commit_push_release` returning `NoChangesStaged`.
    #[tokio::test]
    async fn test_has_staged_changes_returns_false_on_clean_index() {
        let dir = tempfile::tempdir().expect("tempdir");
        init_repo_with_one_commit(dir.path());
        let client = GitClient::in_dir(dir.path().to_string_lossy().to_string());
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
        let add = SyncCommand::new("git")
            .args(["add", "staged.txt"])
            .current_dir(dir.path())
            .status()
            .expect("git add");
        assert!(add.success());
        let client = GitClient::in_dir(dir.path().to_string_lossy().to_string());
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
        let client = GitClient::in_dir(dir.path().to_string_lossy().to_string());
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
        let client = GitClient::in_dir(dir.path().to_string_lossy().to_string());
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
        let client = GitClient::in_dir(work.path().to_string_lossy().to_string());
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
        let client = GitClient::in_dir(dir.path().to_string_lossy().to_string());
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
}
