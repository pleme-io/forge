//! Git operations
//!
//! Handles git operations like getting SHA, committing, pushing.
//! Centralizes git SHA discovery to avoid the "one-cycle lag" bug.

use anyhow::{Context, Result};
use std::path::Path;
use tokio::process::Command;
use tracing::info;

use crate::error::GitError;
use crate::retry::{classify_capture, classify_capture_query};

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

    /// Get git SHA for tagging - Single source of truth
    ///
    /// Priority:
    /// 1. RELEASE_GIT_SHA env var (set by Nix wrapper at release start)
    /// 2. GIT_SHA env var (alternative)
    /// 3. git rev-parse --short HEAD (fallback for direct CLI usage)
    ///
    /// CRITICAL: To avoid the "one-cycle lag" bug where deploy commits shift HEAD,
    /// this function checks for RELEASE_GIT_SHA environment variable FIRST.
    pub async fn get_sha(&self) -> Result<String, GitError> {
        // Check for RELEASE_GIT_SHA environment variable first
        if let Ok(sha) = std::env::var("RELEASE_GIT_SHA") {
            if !sha.is_empty() {
                return Ok(sha);
            }
        }

        // Check for GIT_SHA environment variable
        if let Ok(sha) = std::env::var("GIT_SHA") {
            if !sha.is_empty() {
                return Ok(sha);
            }
        }

        // Fallback to git rev-parse
        self.rev_parse_short().await
    }

    /// Get short git SHA via rev-parse
    ///
    /// Spawn-vs-op dispatch flows through the canonical
    /// [`classify_capture_query`] primitive — same query-shape pattern
    /// `verify_tag_exists` and `rev_parse_full` (`get_full_sha`) drive.
    /// Spawn failures (`Err(io::Error)` — git not on PATH) route to
    /// `GitError::NotARepository` (the historical mapping this site
    /// established before the typed-error split — "couldn't even run git"
    /// has long meant "not a git repository" at this surface);
    /// non-zero exits route to `GitError::ShaFailed` carrying the trimmed
    /// stderr from the canonical [`crate::retry::CapturedFailure`] tuple.
    async fn rev_parse_short(&self) -> Result<String, GitError> {
        let mut cmd = Command::new("git");
        cmd.args(["rev-parse", "--short", "HEAD"]);

        if let Some(ref dir) = self.working_dir {
            cmd.current_dir(dir);
        }

        let sha = classify_capture_query(
            cmd.output().await,
            |_e| GitError::NotARepository,
            |cf| GitError::ShaFailed(cf.stderr),
        )?;

        if sha.is_empty() {
            return Err(GitError::ShaFailed("Empty SHA returned".to_string()));
        }

        Ok(sha)
    }

    /// Get full git SHA
    ///
    /// Spawn-vs-op dispatch flows through the canonical
    /// [`classify_capture_query`] primitive — sibling of `rev_parse_short`
    /// for the 40-char form.
    pub async fn get_full_sha(&self) -> Result<String, GitError> {
        let mut cmd = Command::new("git");
        cmd.args(["rev-parse", "HEAD"]);

        if let Some(ref dir) = self.working_dir {
            cmd.current_dir(dir);
        }

        classify_capture_query(
            cmd.output().await,
            |_e| GitError::NotARepository,
            |cf| GitError::ShaFailed(cf.stderr),
        )
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

    /// Get current branch name
    pub async fn current_branch(&self) -> Result<String> {
        let mut cmd = Command::new("git");
        cmd.args(["rev-parse", "--abbrev-ref", "HEAD"]);

        if let Some(ref dir) = self.working_dir {
            cmd.current_dir(dir);
        }

        let output = cmd.output().await.context("Failed to get current branch")?;

        if !output.status.success() {
            anyhow::bail!("Failed to get current branch");
        }

        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    /// Find repository root
    pub async fn find_root(&self) -> Result<String> {
        let mut cmd = Command::new("git");
        cmd.args(["rev-parse", "--show-toplevel"]);

        if let Some(ref dir) = self.working_dir {
            cmd.current_dir(dir);
        }

        let output = cmd.output().await.context("Failed to find git root")?;

        if !output.status.success() {
            anyhow::bail!("Not in a git repository");
        }

        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }
}

/// Find repository root from current directory
pub fn find_repo_root() -> Result<std::path::PathBuf> {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .context("Failed to execute git")?;

    if !output.status.success() {
        anyhow::bail!("Not in a git repository");
    }

    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Ok(std::path::PathBuf::from(path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_git_client_sha() {
        // This test only works in a git repo
        let client = GitClient::new();
        if let Ok(sha) = client.get_sha().await {
            assert!(!sha.is_empty());
            assert!(sha.len() >= 7); // Short SHA is at least 7 chars
        }
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
