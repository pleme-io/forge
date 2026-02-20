use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

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
    let output = Command::new("git")
        .args(&["rev-parse", "--show-toplevel"])
        .output()
        .context("Failed to execute git rev-parse --show-toplevel")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Git command failed: {}", stderr);
    }

    let repo_root = String::from_utf8(output.stdout)
        .context("Git output is not valid UTF-8")?
        .trim()
        .to_string();

    Ok(PathBuf::from(repo_root))
}

/// Get full git SHA (40 characters)
pub fn get_full_sha() -> Result<String> {
    let output = Command::new("git")
        .args(&["rev-parse", "HEAD"])
        .output()
        .context("Failed to execute git rev-parse")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Git command failed: {}", stderr);
    }

    let sha = String::from_utf8(output.stdout)
        .context("Git output is not valid UTF-8")?
        .trim()
        .to_string();

    Ok(sha)
}

/// Get short git SHA (7 characters)
pub fn get_short_sha() -> Result<String> {
    let output = Command::new("git")
        .args(&["rev-parse", "--short=7", "HEAD"])
        .output()
        .context("Failed to execute git rev-parse")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Git command failed: {}", stderr);
    }

    let sha = String::from_utf8(output.stdout)
        .context("Git output is not valid UTF-8")?
        .trim()
        .to_string();

    Ok(sha)
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
pub fn commit_and_push_in(workdir: &Path, files: &[&Path], message: &str, branch: &str) -> Result<()> {
    // Pull from origin first to avoid conflicts
    let pull_result = Command::new("git")
        .args(&["pull", "origin", branch])
        .current_dir(workdir)
        .output()
        .context("Failed to execute git pull")?;

    if !pull_result.status.success() {
        let stderr = String::from_utf8_lossy(&pull_result.stderr);
        anyhow::bail!("Git pull failed: {}", stderr);
    }

    // Add each file
    for file in files {
        let relative_path = file
            .strip_prefix(workdir)
            .unwrap_or(file);

        let add_result = Command::new("git")
            .args(&["add", relative_path.to_str().unwrap()])
            .current_dir(workdir)
            .output()
            .context("Failed to execute git add")?;

        if !add_result.status.success() {
            let stderr = String::from_utf8_lossy(&add_result.stderr);
            anyhow::bail!("Git add failed for {}: {}", relative_path.display(), stderr);
        }
    }

    // Create commit
    let commit_result = Command::new("git")
        .args(&["commit", "-m", message])
        .current_dir(workdir)
        .output()
        .context("Failed to execute git commit")?;

    if !commit_result.status.success() {
        let stderr = String::from_utf8_lossy(&commit_result.stderr);
        anyhow::bail!("Git commit failed: {}", stderr);
    }

    // Push
    let push_result = Command::new("git")
        .args(&["push", "origin", branch])
        .current_dir(workdir)
        .output()
        .context("Failed to execute git push")?;

    if !push_result.status.success() {
        let stderr = String::from_utf8_lossy(&push_result.stderr);
        anyhow::bail!("Git push failed: {}", stderr);
    }

    Ok(())
}

/// Commit and push changes
pub fn commit_and_push(manifest_path: &Path, old_tag: &str, new_tag: &str) -> Result<()> {
    let workdir = get_repo_root()?;

    // Pull from origin first to avoid conflicts
    let pull_result = Command::new("git")
        .args(&["pull", "origin", "main"])
        .current_dir(&workdir)
        .output()
        .context("Failed to execute git pull")?;

    if !pull_result.status.success() {
        let stderr = String::from_utf8_lossy(&pull_result.stderr);
        anyhow::bail!("Git pull failed: {}", stderr);
    }

    // Convert absolute path to relative path from repo root
    let relative_path = manifest_path
        .strip_prefix(&workdir)
        .context("Manifest path should be inside repository")?;

    // Add manifest to index
    let add_result = Command::new("git")
        .args(&["add", relative_path.to_str().unwrap()])
        .current_dir(&workdir)
        .output()
        .context("Failed to execute git add")?;

    if !add_result.status.success() {
        let stderr = String::from_utf8_lossy(&add_result.stderr);
        anyhow::bail!("Git add failed: {}", stderr);
    }

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

        let add_config_result = Command::new("git")
            .args(&["add", config_map_relative.to_str().unwrap()])
            .current_dir(&workdir)
            .output()
            .context("Failed to execute git add for ConfigMap")?;

        if !add_config_result.status.success() {
            let stderr = String::from_utf8_lossy(&add_config_result.stderr);
            anyhow::bail!("Git add ConfigMap failed: {}", stderr);
        }
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
    let commit_result = Command::new("git")
        .args(&["commit", "-m", &message])
        .current_dir(&workdir)
        .output()
        .context("Failed to execute git commit")?;

    if !commit_result.status.success() {
        let stderr = String::from_utf8_lossy(&commit_result.stderr);
        anyhow::bail!("Git commit failed: {}", stderr);
    }

    // Push using system git command (uses SSH config and agent automatically)
    let push_result = Command::new("git")
        .args(&["push", "origin", "main"])
        .current_dir(&workdir)
        .output()
        .context("Failed to execute git push")?;

    if !push_result.status.success() {
        let stderr = String::from_utf8_lossy(&push_result.stderr);
        anyhow::bail!("Git push failed: {}", stderr);
    }

    Ok(())
}
