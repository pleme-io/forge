//! Git operations
//!
//! Handles git operations like getting SHA, committing, pushing.
//! Centralizes git SHA discovery to avoid the "one-cycle lag" bug.

use anyhow::{Context, Result};
use std::path::Path;
use tokio::process::Command;
use tracing::info;

use crate::error::GitError;
use crate::retry::{classify_capture_query, run_inherited_status};

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

    /// Check if working tree is clean
    pub async fn is_clean(&self) -> Result<bool> {
        let mut cmd = Command::new("git");
        cmd.args(["status", "--porcelain"]);

        if let Some(ref dir) = self.working_dir {
            cmd.current_dir(dir);
        }

        let output = cmd.output().await.context("Failed to run git status")?;

        Ok(output.stdout.is_empty())
    }

    /// Stage files for commit
    ///
    /// Routes through the canonical [`run_inherited_status`] primitive
    /// (commit 3d07250 — same primitive `commands/federation.rs::
    /// push_supergraph_changes`'s three `git add` sites consume since
    /// commit 45877e2). The pre-migration five-line "spawn with inherited
    /// stdio, await status, .context() spawn-failure envelope, if
    /// !status.success() bail with a bare message that drops the exit
    /// code" stanza becomes a three-line `Command::new + .args +
    /// run_inherited_status` chain, gaining the canonical exit-code
    /// carry on the failure surface (`"git add failed (exit {N})"`)
    /// and the `"killed by signal"` discriminator at every call site
    /// of this method by construction.
    pub async fn add(&self, paths: &[&str]) -> Result<()> {
        let mut cmd = Command::new("git");
        cmd.arg("add");
        cmd.args(paths);

        if let Some(ref dir) = self.working_dir {
            cmd.current_dir(dir);
        }

        run_inherited_status(cmd, "git add").await
    }

    /// Create a commit
    ///
    /// Sibling status-only site of [`Self::add`] / [`Self::push`] —
    /// routes through [`run_inherited_status`] so the failure surface
    /// carries the structural `(op, exit_code)` tuple uniformly across
    /// every git mutating method on `GitClient`.
    pub async fn commit(&self, message: &str) -> Result<()> {
        let mut cmd = Command::new("git");
        cmd.args(["commit", "-m", message]);

        if let Some(ref dir) = self.working_dir {
            cmd.current_dir(dir);
        }

        run_inherited_status(cmd, "git commit").await
    }

    /// Push to remote
    ///
    /// Sibling status-only site of [`Self::add`] / [`Self::commit`] —
    /// routes through [`run_inherited_status`] so the failure surface
    /// carries the structural `(op, exit_code)` tuple uniformly across
    /// every git mutating method on `GitClient`.
    pub async fn push(&self) -> Result<()> {
        let mut cmd = Command::new("git");
        cmd.arg("push");

        if let Some(ref dir) = self.working_dir {
            cmd.current_dir(dir);
        }

        run_inherited_status(cmd, "git push").await
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

    /// Initialize a hermetic empty git repo in a tempdir and return the
    /// `(TempDir, GitClient)` pair. The `TempDir` MUST outlive every
    /// `GitClient` invocation in the test — when it drops, the repo
    /// directory is unlinked. Same lifetime contract
    /// `crate::test_support::make_executable_shim` encodes for the
    /// hermetic CLI shims.
    ///
    /// Returns `None` if `git init` fails (`git` not on PATH, or env
    /// otherwise unable to host a git repo) — same `if let Some(...)`
    /// skip discipline `test_git_client_sha` carries since the original
    /// hermetic-test pattern was established. A future regression that
    /// silently broke `git init` invocation surfaces as a skip, not a
    /// flaky failure inside an unrelated assertion.
    async fn init_hermetic_repo() -> Option<(tempfile::TempDir, GitClient)> {
        let dir = tempfile::tempdir().ok()?;
        let init = tokio::process::Command::new("git")
            .args(["init", "--quiet"])
            .current_dir(dir.path())
            .status()
            .await
            .ok()?;
        if !init.success() {
            return None;
        }
        // Pin a local identity so `git commit` does not look up the
        // ambient user's `~/.gitconfig` — the only piece of host state
        // a "hermetic empty repo" would otherwise inherit. Without
        // these two configs, `git commit` exits 128 with
        // `"Author identity unknown"` rather than the exit-1
        // `"nothing to commit"` shape the commit-failure test
        // depends on.
        for (key, val) in [
            ("user.email", "claude-routine-forge@example.invalid"),
            ("user.name", "claude-routine-forge"),
        ] {
            let _ = tokio::process::Command::new("git")
                .args(["config", key, val])
                .current_dir(dir.path())
                .status()
                .await
                .ok()?;
        }
        let client = GitClient::in_dir(dir.path().to_string_lossy().to_string());
        Some((dir, client))
    }

    /// `GitClient::add` against a non-existent pathspec must fail with an
    /// `anyhow::Error` whose Display surface carries BOTH the canonical
    /// `"git add"` operation label AND the structural exit code from the
    /// underlying git binary.
    ///
    /// Pre-migration the method bailed with the bare string
    /// `"git add failed"` — the exit code that distinguishes
    /// `git add /missing/path` (exit 128, pathspec rejection) from
    /// other add-time failures (exit 1, ambiguous arg) was dropped at
    /// the operator-log surface. Post-migration the method delegates to
    /// the canonical [`run_inherited_status`] primitive, whose
    /// `anyhow::bail!("{op} failed (exit {N})")` shape carries the
    /// structural-record tuple THEORY §V.4 Phase 1 attestation-record
    /// consumers parse from log replay.
    ///
    /// The exit-code substring assertion is the load-bearing guard:
    /// pre-migration it FAILS (the string `"exit"` does not appear in
    /// the bare `"git add failed"` bail); post-migration it PASSES
    /// (the canonical `"git add failed (exit 128)"` shape carries it).
    /// A future regression that re-introduced a bare-string bail from
    /// inside the migrated method (or that swallowed the inner
    /// structural record via `.map_err(|_| anyhow!("git add failed"))`)
    /// would surface here, not in production via a less-informative
    /// operator log line on a release pipeline event.
    #[tokio::test]
    async fn test_git_client_add_failure_carries_op_and_exit_code() {
        let Some((_dir, client)) = init_hermetic_repo().await else {
            return;
        };

        let err = client
            .add(&["pathspec-that-does-not-match-any-files-in-this-repo"])
            .await
            .expect_err("git add against missing pathspec must fail");

        let chained = format!("{:#}", err);
        assert!(
            chained.contains("git add"),
            "failure must carry 'git add' op label, got: {chained}"
        );
        assert!(
            chained.contains("exit "),
            "failure must carry exit code from run_inherited_status's structural-record format, got: {chained}"
        );
    }

    /// `GitClient::commit` in a repo with nothing staged must fail with
    /// an `anyhow::Error` whose Display surface carries BOTH the
    /// `"git commit"` operation label AND the structural exit code
    /// (typically exit 1 — the `"nothing to commit"` precondition).
    ///
    /// Pre-migration the method bailed with the bare string
    /// `"git commit failed"`; post-migration the canonical
    /// `"git commit failed (exit {N})"` shape is the structural-record
    /// surface every consumer of the typed primitive parses by
    /// construction. Sibling guard of
    /// [`test_git_client_add_failure_carries_op_and_exit_code`] —
    /// closes the migration's contract on the second of three
    /// status-only sites the GitClient mutating-method surface owns.
    #[tokio::test]
    async fn test_git_client_commit_failure_carries_op_and_exit_code() {
        let Some((_dir, client)) = init_hermetic_repo().await else {
            return;
        };

        let err = client
            .commit("attempt to commit with nothing staged")
            .await
            .expect_err("git commit with nothing staged must fail");

        let chained = format!("{:#}", err);
        assert!(
            chained.contains("git commit"),
            "failure must carry 'git commit' op label, got: {chained}"
        );
        assert!(
            chained.contains("exit "),
            "failure must carry exit code from run_inherited_status's structural-record format, got: {chained}"
        );
    }

    /// `GitClient::push` in a repo with no configured remote must fail
    /// with an `anyhow::Error` whose Display surface carries BOTH the
    /// `"git push"` operation label AND the structural exit code
    /// (exit 128 — the `"No configured push destination"` precondition).
    ///
    /// Pre-migration the method bailed with the bare string
    /// `"git push failed"`. Post-migration the canonical
    /// `"git push failed (exit {N})"` shape preserves the discriminator
    /// the operator triage surface needs — exit 128 ("no remote") is
    /// structurally distinct from exit 1 ("rejected, non-fast-forward")
    /// and an exit-code-less message conflates the two failure modes.
    /// Sibling guard of
    /// [`test_git_client_add_failure_carries_op_and_exit_code`] /
    /// [`test_git_client_commit_failure_carries_op_and_exit_code`] —
    /// closes the migration's contract on the third of three
    /// status-only sites the GitClient mutating-method surface owns.
    #[tokio::test]
    async fn test_git_client_push_failure_carries_op_and_exit_code() {
        let Some((_dir, client)) = init_hermetic_repo().await else {
            return;
        };

        let err = client
            .push()
            .await
            .expect_err("git push with no remote configured must fail");

        let chained = format!("{:#}", err);
        assert!(
            chained.contains("git push"),
            "failure must carry 'git push' op label, got: {chained}"
        );
        assert!(
            chained.contains("exit "),
            "failure must carry exit code from run_inherited_status's structural-record format, got: {chained}"
        );
    }
}
