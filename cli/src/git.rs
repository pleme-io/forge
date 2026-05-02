use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::error::GitError;
use crate::retry::CapturedFailure;

/// Run `git <args>` (resolved against `workdir` if any) and return its
/// captured stdout, or a typed `GitError`.
///
/// `op` is the human-readable label attached to any returned error and
/// is what discriminates "git couldn't spawn" (`GitError::ExecFailed`)
/// from "git ran but exited non-zero" (`GitError::OpFailed`).
/// `bin` defaults to `"git"` for production callers; tests pass an
/// absolute shim path so they don't mutate global PATH and remain
/// parallel-safe — same hermetic-test discipline as `nix.rs`'s
/// `run_nix_build_typed` and `attic.rs`'s `run_attic_capture`.
fn git_capture(
    bin: &str,
    args: &[&str],
    workdir: Option<&Path>,
    op: &str,
) -> Result<Vec<u8>, GitError> {
    let mut cmd = Command::new(bin);
    cmd.args(args);
    if let Some(w) = workdir {
        cmd.current_dir(w);
    }
    let output = cmd.output().map_err(|e| GitError::ExecFailed {
        op: op.to_string(),
        message: e.to_string(),
    })?;
    if let Some(cf) = CapturedFailure::from_output_if_failed(&output) {
        return Err(GitError::OpFailed {
            op: op.to_string(),
            exit_code: cf.exit_code,
            stderr: cf.stderr,
        });
    }
    Ok(output.stdout)
}

/// Run a git operation against a specific (remote, branch) endpoint —
/// `git push origin <branch>`, `git pull origin <branch>` — and surface
/// failures as `GitError::RemoteOpFailed` so callers can recover the
/// exact endpoint from the typed record without parsing the bail!
/// string. Mirror of `git_capture` for the network half of the surface.
fn git_capture_remote(
    bin: &str,
    args: &[&str],
    workdir: Option<&Path>,
    op: &str,
    remote: &str,
    branch: &str,
) -> Result<Vec<u8>, GitError> {
    let mut cmd = Command::new(bin);
    cmd.args(args);
    if let Some(w) = workdir {
        cmd.current_dir(w);
    }
    let output = cmd.output().map_err(|e| GitError::ExecFailed {
        op: op.to_string(),
        message: e.to_string(),
    })?;
    if let Some(cf) = CapturedFailure::from_output_if_failed(&output) {
        return Err(GitError::RemoteOpFailed {
            op: op.to_string(),
            remote: remote.to_string(),
            branch: branch.to_string(),
            exit_code: cf.exit_code,
            stderr: cf.stderr,
        });
    }
    Ok(output.stdout)
}

fn stdout_string(bytes: Vec<u8>) -> Result<String> {
    Ok(String::from_utf8(bytes)
        .context("Git output is not valid UTF-8")?
        .trim()
        .to_string())
}

/// Get the root directory of the git repository
///
/// Root flake pattern (ONLY supported pattern):
/// Tries REPO_ROOT environment variable first (set by CLI --repo-root parameter),
/// then falls back to calling `git rev-parse --show-toplevel`.
///
/// This consolidated logic prevents duplicate implementations across commands.
pub fn get_repo_root() -> Result<PathBuf> {
    // Try environment variable first (for CLI --repo-root parameter)
    if let Ok(repo_root) = std::env::var("REPO_ROOT") {
        return Ok(PathBuf::from(repo_root));
    }

    // Fall back to git command
    let stdout = git_capture("git", &["rev-parse", "--show-toplevel"], None, "rev-parse")?;
    Ok(PathBuf::from(stdout_string(stdout)?))
}

/// Get full git SHA (40 characters)
pub fn get_full_sha() -> Result<String> {
    let stdout = git_capture("git", &["rev-parse", "HEAD"], None, "rev-parse")?;
    stdout_string(stdout)
}

/// Get short git SHA (7 characters)
pub fn get_short_sha() -> Result<String> {
    let stdout = git_capture(
        "git",
        &["rev-parse", "--short=7", "HEAD"],
        None,
        "rev-parse",
    )?;
    stdout_string(stdout)
}

/// Update kustomization.yaml with new image tag
/// This function updates the `images[].newTag` field in a Kustomize file
pub async fn update_manifest(manifest_path: &Path, _old_tag: &str, new_tag: &str) -> Result<()> {
    let content = tokio::fs::read_to_string(manifest_path)
        .await
        .context("Failed to read kustomization.yaml")?;

    // Parse YAML
    let mut yaml: serde_yaml::Value =
        serde_yaml::from_str(&content).context("Failed to parse kustomization.yaml as YAML")?;

    // Update images[].newTag field
    if let Some(images) = yaml.get_mut("images").and_then(|v| v.as_sequence_mut()) {
        for image in images {
            if let Some(new_tag_field) = image.get_mut("newTag") {
                // Replace the newTag value
                *new_tag_field = serde_yaml::Value::String(new_tag.to_string());
            }
        }
    } else {
        anyhow::bail!("No 'images' section found in kustomization.yaml");
    }

    // Serialize back to YAML with proper formatting
    let updated = serde_yaml::to_string(&yaml).context("Failed to serialize YAML")?;

    tokio::fs::write(manifest_path, updated)
        .await
        .context("Failed to write kustomization.yaml")?;

    Ok(())
}

/// Update service ConfigMap with GIT_SHA
/// This function updates the `data.GIT_SHA` field in a service's ConfigMap
/// For web service, it also replaces GIT_SHA_PLACEHOLDER in env.js
///
/// # Arguments
/// * `manifest_path` - Path to the kustomization.yaml file
/// * `git_sha` - Git SHA to set in the ConfigMap
///
/// # Returns
/// Returns Ok(()) if successful, or an error if the ConfigMap file is not found or cannot be updated
pub async fn update_configmap_git_sha(manifest_path: &Path, git_sha: &str) -> Result<()> {
    // Extract service name from manifest path (e.g., .../services/email/kustomization.yaml -> email)
    let service_name = manifest_path
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|s| s.to_str())
        .ok_or_else(|| anyhow::anyhow!("Could not extract service name from manifest path"))?;

    // Construct ConfigMap file path (e.g., email-config.yaml or web-config.yaml)
    let config_map_path = manifest_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Could not get parent directory"))?
        .join(format!("{}-config.yaml", service_name));

    // Check if ConfigMap exists
    if !config_map_path.exists() {
        // Not an error - some services may not have a ConfigMap
        return Ok(());
    }

    let content = tokio::fs::read_to_string(&config_map_path)
        .await
        .context("Failed to read ConfigMap file")?;

    // Parse YAML
    let mut yaml: serde_yaml::Value =
        serde_yaml::from_str(&content).context("Failed to parse ConfigMap as YAML")?;

    // Update data.GIT_SHA field
    if let Some(data) = yaml.get_mut("data").and_then(|v| v.as_mapping_mut()) {
        data.insert(
            serde_yaml::Value::String("GIT_SHA".to_string()),
            serde_yaml::Value::String(git_sha.to_string()),
        );

        // For web service, also replace GIT_SHA_PLACEHOLDER in env.js
        if service_name == "web" {
            if let Some(env_js) = data.get_mut(&serde_yaml::Value::String("env.js".to_string())) {
                if let Some(env_js_str) = env_js.as_str() {
                    let updated_env_js = env_js_str.replace("GIT_SHA_PLACEHOLDER", git_sha);
                    *env_js = serde_yaml::Value::String(updated_env_js);
                }
            }
        }
    } else {
        anyhow::bail!("No 'data' section found in ConfigMap");
    }

    // Serialize back to YAML with proper formatting
    let updated = serde_yaml::to_string(&yaml).context("Failed to serialize YAML")?;

    tokio::fs::write(&config_map_path, updated)
        .await
        .context("Failed to write ConfigMap")?;

    Ok(())
}

/// Commit and push changes in an explicit working directory.
///
/// Used for multi-repo deployments (e.g., k8s manifests in a separate repo).
pub fn commit_and_push_in(
    workdir: &Path,
    files: &[&Path],
    message: &str,
    branch: &str,
) -> Result<()> {
    // Pull from origin first to avoid conflicts
    git_capture_remote(
        "git",
        &["pull", "origin", branch],
        Some(workdir),
        "pull",
        "origin",
        branch,
    )?;

    // Add each file
    for file in files {
        let relative_path = file.strip_prefix(workdir).unwrap_or(file);
        let rel = relative_path.to_str().unwrap();
        git_capture("git", &["add", rel], Some(workdir), "add")?;
    }

    // Create commit
    git_capture("git", &["commit", "-m", message], Some(workdir), "commit")?;

    // Push
    git_capture_remote(
        "git",
        &["push", "origin", branch],
        Some(workdir),
        "push",
        "origin",
        branch,
    )?;

    Ok(())
}

/// Check if the git working tree is clean (no uncommitted changes).
pub fn is_working_tree_clean() -> Result<bool> {
    let stdout = git_capture("git", &["status", "--porcelain"], None, "status")?;
    let s = String::from_utf8_lossy(&stdout);
    Ok(s.trim().is_empty())
}

/// Check if a git tag exists locally.
pub fn tag_exists(tag: &str) -> Result<bool> {
    let stdout = git_capture("git", &["tag", "--list", tag], None, "tag --list")?;
    let s = String::from_utf8_lossy(&stdout);
    Ok(!s.trim().is_empty())
}

/// Create an annotated git tag.
pub fn create_tag(tag: &str, message: &str) -> Result<()> {
    git_capture("git", &["tag", "-a", tag, "-m", message], None, "tag -a")?;
    Ok(())
}

/// Push a git tag to the remote.
pub fn push_tag(tag: &str) -> Result<()> {
    git_capture_remote("git", &["push", "origin", tag], None, "push", "origin", tag)?;
    Ok(())
}

/// Commit and push changes
pub fn commit_and_push(manifest_path: &Path, old_tag: &str, new_tag: &str) -> Result<()> {
    let workdir = get_repo_root()?;

    // Pull from origin first to avoid conflicts
    git_capture_remote(
        "git",
        &["pull", "origin", "main"],
        Some(&workdir),
        "pull",
        "origin",
        "main",
    )?;

    // Convert absolute path to relative path from repo root
    let relative_path = manifest_path
        .strip_prefix(&workdir)
        .context("Manifest path should be inside repository")?;

    // Add manifest to index
    git_capture(
        "git",
        &["add", relative_path.to_str().unwrap()],
        Some(&workdir),
        "add",
    )?;

    // Also add ConfigMap if it exists
    let service_name = manifest_path
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|s| s.to_str())
        .unwrap_or("service");

    let config_map_path = manifest_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Could not get parent directory"))?
        .join(format!("{}-config.yaml", service_name));

    if config_map_path.exists() {
        let config_map_relative = config_map_path
            .strip_prefix(&workdir)
            .context("ConfigMap path should be inside repository")?;
        git_capture(
            "git",
            &["add", config_map_relative.to_str().unwrap()],
            Some(&workdir),
            "add",
        )?;
    }

    // Extract service name from manifest path (e.g., .../services/auth/kustomization.yaml -> auth)
    let service_name = manifest_path
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        .unwrap_or("service");

    let message = format!(
        "Deploy {} image tag {}\n\nUpdated image tag: {} → {}\nUpdated ConfigMap GIT_SHA: {}\n\nGenerated by forge",
        service_name, new_tag, old_tag, new_tag, new_tag
    );

    // Create commit
    git_capture("git", &["commit", "-m", &message], Some(&workdir), "commit")?;

    // Push using system git command (uses SSH config and agent automatically)
    git_capture_remote(
        "git",
        &["push", "origin", "main"],
        Some(&workdir),
        "push",
        "origin",
        "main",
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::GitError;

    /// Write an executable shim that pretends to be `git`. The returned
    /// tempdir keeps the shim alive until the caller drops it. Tests
    /// invoke the shim by absolute path so they don't mutate global PATH
    /// (which would race under parallel test execution). Same discipline
    /// as `nix.rs::make_nix_shim` and `attic.rs`'s shim.
    fn make_git_shim(body: &str) -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().expect("tempdir");
        let shim = dir.path().join("git");
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

    /// When the resolved git binary cannot be spawned, `git_capture` must
    /// surface `ExecFailed` carrying the offending op label — never a
    /// stringly anyhow `Failed to execute git`. Pins the typed split so
    /// telemetry can distinguish "git missing" from "git said no".
    #[test]
    fn test_git_capture_exec_failed_carries_op() {
        let result = git_capture(
            "/nonexistent/path/to/git-binary-that-does-not-exist",
            &["rev-parse", "HEAD"],
            None,
            "rev-parse",
        );
        let err = result.expect_err("missing git binary must fail");
        match err {
            GitError::ExecFailed { op, .. } => {
                assert_eq!(op, "rev-parse");
            }
            other => panic!("expected ExecFailed, got: {other:?}"),
        }
    }

    /// Non-zero exits must produce `OpFailed` carrying the op label, the
    /// exit code, and the captured stderr — never a fused stringly bag.
    /// Uses an absolute-path shim so the test is hermetic and
    /// parallel-safe.
    #[test]
    fn test_git_capture_op_failed_carries_structured_fields() {
        let (_dir, shim) = make_git_shim("#!/bin/sh\necho 'fatal: bad object' 1>&2\nexit 128\n");
        let result = git_capture(&shim, &["rev-parse", "HEAD"], None, "rev-parse");
        let err = result.expect_err("nonzero exit must fail");
        match err {
            GitError::OpFailed {
                op,
                exit_code,
                stderr,
            } => {
                assert_eq!(op, "rev-parse");
                assert_eq!(exit_code, Some(128));
                assert!(
                    stderr.contains("bad object"),
                    "stderr field must capture the git stderr verbatim, got: {stderr:?}"
                );
            }
            other => panic!("expected OpFailed, got: {other:?}"),
        }
    }

    /// Success path: `git_capture` returns the trimmed stdout verbatim.
    #[test]
    fn test_git_capture_success_returns_stdout() {
        let (_dir, shim) = make_git_shim("#!/bin/sh\necho 'deadbeef'\nexit 0\n");
        let stdout =
            git_capture(&shim, &["rev-parse", "HEAD"], None, "rev-parse").expect("must succeed");
        assert_eq!(String::from_utf8_lossy(&stdout).trim(), "deadbeef");
    }

    /// Network-side ops must surface `RemoteOpFailed` carrying the
    /// (op, remote, branch) tuple they targeted so attestation records
    /// and retry schedulers recover the exact endpoint from the typed
    /// record without parsing the bail! string (THEORY §V.4).
    #[test]
    fn test_git_capture_remote_failed_carries_endpoint() {
        let (_dir, shim) = make_git_shim("#!/bin/sh\necho 'remote: rejected' 1>&2\nexit 1\n");
        let result = git_capture_remote(
            &shim,
            &["push", "origin", "main"],
            None,
            "push",
            "origin",
            "main",
        );
        let err = result.expect_err("nonzero exit must fail");
        match err {
            GitError::RemoteOpFailed {
                op,
                remote,
                branch,
                exit_code,
                stderr,
            } => {
                assert_eq!(op, "push");
                assert_eq!(remote, "origin");
                assert_eq!(branch, "main");
                assert_eq!(exit_code, Some(1));
                assert!(stderr.contains("rejected"));
            }
            other => panic!("expected RemoteOpFailed, got: {other:?}"),
        }
    }

    /// `git_capture_remote` must surface an exec-time failure as
    /// `ExecFailed`, not as `RemoteOpFailed` — the typed split keeps
    /// "couldn't spawn git" structurally distinct from "git rejected
    /// the network operation."
    #[test]
    fn test_git_capture_remote_exec_failed_is_distinct() {
        let result = git_capture_remote(
            "/nonexistent/path/to/git",
            &["push", "origin", "main"],
            None,
            "push",
            "origin",
            "main",
        );
        let err = result.expect_err("missing binary must fail");
        match err {
            GitError::ExecFailed { op, .. } => assert_eq!(op, "push"),
            other => panic!("expected ExecFailed, got: {other:?}"),
        }
    }

    /// Success path on the network side: `git_capture_remote` returns
    /// the trimmed stdout verbatim.
    #[test]
    fn test_git_capture_remote_success_returns_stdout() {
        let (_dir, shim) = make_git_shim("#!/bin/sh\necho 'Everything up-to-date'\nexit 0\n");
        let stdout = git_capture_remote(
            &shim,
            &["push", "origin", "main"],
            None,
            "push",
            "origin",
            "main",
        )
        .expect("must succeed");
        assert!(String::from_utf8_lossy(&stdout).contains("up-to-date"));
    }

    #[test]
    fn test_git_client_sha() {
        // This test only works in a git repo
        if let Ok(sha) = get_short_sha() {
            assert!(!sha.is_empty());
            assert!(sha.len() >= 7); // Short SHA is at least 7 chars
        }
    }
}
