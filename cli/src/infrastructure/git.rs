//! Git operations
//!
//! Handles git operations like getting SHA, committing, pushing.
//! Centralizes git SHA discovery to avoid the "one-cycle lag" bug.

use anyhow::{Context, Result};
use std::path::Path;
use tokio::process::Command;
use tracing::info;

use crate::error::GitError;
use crate::retry::classify_capture_query;

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
    pub async fn add(&self, paths: &[&str]) -> Result<()> {
        let mut cmd = Command::new("git");
        cmd.arg("add");
        cmd.args(paths);

        if let Some(ref dir) = self.working_dir {
            cmd.current_dir(dir);
        }

        let status = cmd.status().await.context("Failed to run git add")?;

        if !status.success() {
            anyhow::bail!("git add failed");
        }

        Ok(())
    }

    /// Create a commit
    pub async fn commit(&self, message: &str) -> Result<()> {
        let mut cmd = Command::new("git");
        cmd.args(["commit", "-m", message]);

        if let Some(ref dir) = self.working_dir {
            cmd.current_dir(dir);
        }

        let status = cmd.status().await.context("Failed to run git commit")?;

        if !status.success() {
            anyhow::bail!("git commit failed");
        }

        Ok(())
    }

    /// Push to remote
    pub async fn push(&self) -> Result<()> {
        let mut cmd = Command::new("git");
        cmd.arg("push");

        if let Some(ref dir) = self.working_dir {
            cmd.current_dir(dir);
        }

        let status = cmd.status().await.context("Failed to run git push")?;

        if !status.success() {
            anyhow::bail!("git push failed");
        }

        Ok(())
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
}
