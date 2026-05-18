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
}

#[cfg(test)]
mod tests {
    use super::*;

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
