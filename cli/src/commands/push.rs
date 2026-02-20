use anyhow::{anyhow, Context, Result};
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use std::path::Path;
use std::process::Stdio;
use tokio::process::Command;
use tracing::{info, warn};

use crate::repo::get_tool_path;

/// Extract organization name from registry URL
/// Example: "ghcr.io/org/project/service" -> "org"
fn extract_organization(registry: &str) -> Result<String> {
    let parts: Vec<&str> = registry.split('/').collect();
    if parts.len() < 2 {
        return Err(anyhow!(
            "Invalid registry format: {}. Expected format: host/organization/...",
            registry
        ));
    }
    Ok(parts[1].to_string())
}

/// Get git SHA for tagging - Single source of truth
///
/// Priority:
/// 1. RELEASE_GIT_SHA env var (set by Nix wrapper at release start)
/// 2. GIT_SHA env var (alternative)
/// 3. git rev-parse --short HEAD (fallback for direct CLI usage)
pub async fn get_git_sha() -> Result<String> {
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

    // Fallback to git rev-parse for direct CLI usage
    let output = Command::new("git")
        .args(&["rev-parse", "--short", "HEAD"])
        .output()
        .await
        .context("Failed to execute git rev-parse - is git installed?")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "Failed to get git SHA for image tagging.\n  \
             Git error: {}\n  \
             Ensure you're in a git repository with committed changes.",
            stderr.trim()
        );
    }

    let hash = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if hash.is_empty() {
        anyhow::bail!("Git returned empty SHA - repository may be corrupted");
    }

    Ok(hash)
}

/// Generate architecture-prefixed tags
///
/// Returns tags like ["amd64-abc1234", "amd64-latest"] for the given architecture
pub async fn generate_auto_tags(arch: &str) -> Result<Vec<String>> {
    let sha = get_git_sha().await?;
    Ok(vec![
        format!("{}-{}", arch, sha),
        format!("{}-latest", arch),
    ])
}

/// Discover GHCR token from various sources
///
/// Delegates to the canonical RegistryCredentials::discover_token().
/// Priority: provided token → GHCR_TOKEN → GITHUB_TOKEN → gh CLI → kubectl secret
pub fn discover_ghcr_token(token: Option<String>) -> Result<String> {
    crate::infrastructure::registry::RegistryCredentials::discover_token(token)
        .map_err(|e| anyhow::anyhow!("{}", e))
}

/// Update kustomization.yaml with new image tag
///
/// Finds the image entry matching the registry and updates its newTag field.
/// Optionally commits and pushes the change to git.
pub async fn update_kustomization(
    kustomization_path: &str,
    registry: &str,
    new_tag: &str,
    commit: bool,
) -> Result<()> {
    let path = Path::new(kustomization_path);
    if !path.exists() {
        anyhow::bail!("Kustomization file not found: {}", kustomization_path);
    }

    info!("📝 Updating kustomization: {}", kustomization_path);

    // Read current content
    let content = tokio::fs::read_to_string(path)
        .await
        .context("Failed to read kustomization.yaml")?;

    // Extract service name from registry for matching (last path component)
    let service_match = registry.split('/').last().unwrap_or(registry);

    // Use targeted text replacement instead of serde_yaml round-trip.
    // Round-tripping through serde_yaml destroys comments, reformats
    // multi-line strings (patch: | blocks), and can corrupt the file.
    let lines: Vec<&str> = content.lines().collect();
    let mut result = Vec::with_capacity(lines.len());
    let mut updated = false;
    let mut matched_name = false;

    for line in &lines {
        if matched_name {
            let trimmed = line.trim();
            if trimmed.starts_with("newTag:") {
                let old_tag = trimmed.trim_start_matches("newTag:").trim();
                info!("   Updating {} from {} to {}", service_match, old_tag, new_tag);
                let indent = &line[..line.len() - line.trim_start().len()];
                result.push(format!("{}newTag: {}", indent, new_tag));
                updated = true;
                matched_name = false;
                continue;
            }
            if !trimmed.is_empty() && !trimmed.starts_with('#') {
                matched_name = false;
            }
        }

        let trimmed = line.trim();
        if trimmed.starts_with("- name:") {
            let name_value = trimmed.trim_start_matches("- name:").trim();
            if registry.contains(name_value)
                || name_value.contains(service_match)
            {
                matched_name = true;
            }
        }

        result.push(line.to_string());
    }

    if !updated {
        anyhow::bail!(
            "No matching image found in kustomization.yaml for registry: {}",
            registry
        );
    }

    let mut updated_content = result.join("\n");
    if content.ends_with('\n') {
        updated_content.push('\n');
    }
    tokio::fs::write(path, &updated_content)
        .await
        .context("Failed to write kustomization.yaml")?;

    info!("   ✅ Kustomization updated");

    // Commit and push if requested
    if commit {
        info!("📤 Committing and pushing kustomization changes...");

        // Git add
        let add_status = Command::new("git")
            .args(&["add", kustomization_path])
            .status()
            .await
            .context("Failed to stage kustomization.yaml")?;

        if !add_status.success() {
            anyhow::bail!("Failed to stage kustomization.yaml");
        }

        // Extract service name from path for commit message
        let service_name = path
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");

        // Git commit
        let commit_msg = format!("deploy: update {} to {}", service_name, new_tag);
        let commit_status = Command::new("git")
            .args(&["commit", "-m", &commit_msg])
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .await
            .context("Failed to commit kustomization.yaml")?;

        if !commit_status.success() {
            warn!("Git commit returned non-zero (may be no changes)");
        }

        // Git push
        let push_status = Command::new("git")
            .args(&["push", "origin", "main"])
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .await
            .context("Failed to push to git")?;

        if !push_status.success() {
            anyhow::bail!("Failed to push kustomization changes to git");
        }

        info!("   ✅ Kustomization committed and pushed");
    }

    Ok(())
}

pub async fn execute(
    image_path: String,
    registry: String,
    mut tags: Vec<String>,
    auto_tags: bool,
    arch: String,
    retries: u32,
    token: Option<String>,
    push_attic: bool,
    attic_cache: String,
    update_kustomization_path: Option<String>,
    commit_kustomization: bool,
) -> Result<()> {
    println!();
    println!(
        "{}",
        "╔════════════════════════════════════════════════════════════╗".bright_blue()
    );
    println!(
        "{}",
        "║  Push to Container Registry                                ║".bright_blue()
    );
    println!(
        "{}",
        "╚════════════════════════════════════════════════════════════╝".bright_blue()
    );
    println!();

    // Check if build result exists
    if !tokio::fs::try_exists(&image_path).await.unwrap_or(false) {
        anyhow::bail!(
            "Build result not found at '{}'. Run 'forge build' first.",
            image_path
        );
    }

    // If auto_tags is enabled, generate architecture-prefixed tags
    if auto_tags {
        let generated_tags = generate_auto_tags(&arch).await?;
        info!("🔧 Auto-generating tags for {}: {:?}", arch, generated_tags);
        tags.extend(generated_tags);
    }

    // Get GHCR token
    let ghcr_token = discover_ghcr_token(token)?;

    if tags.is_empty() {
        anyhow::bail!("At least one tag must be specified with --tag or use --auto-tags");
    }

    info!("🎯 Target: {}", registry);
    info!("📦 Image path: {}", image_path);
    info!("🏷️  Tags: {}", tags.join(", "));
    println!();

    // Push to Attic cache first (if requested)
    if push_attic {
        info!("📤 Pushing to Attic cache...");
        let attic_result = Command::new("attic")
            .args(&["push", &attic_cache, &image_path])
            .status()
            .await;

        match attic_result {
            Ok(status) if status.success() => {
                info!("✅ Pushed to Attic cache: {}", attic_cache);
            }
            _ => {
                warn!("⚠️  Failed to push to Attic cache (non-fatal, continuing...)");
            }
        }
        println!();
    }

    // Push with skopeo (with retries)
    info!("📤 Pushing to container registry with skopeo...");
    info!("   Retries: {} attempts per tag", retries);
    println!();

    let pb = ProgressBar::new(tags.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} {msg}")
            .unwrap()
            .progress_chars("#>-"),
    );

    // Push all tags
    for tag in &tags {
        pb.set_message(format!("Pushing {}:{}", registry, tag));

        push_with_retry(&image_path, &registry, tag, &ghcr_token, retries).await?;

        pb.inc(1);
    }

    pb.finish_with_message("Push complete");

    println!();
    println!("{}", "✅ Images pushed successfully!".bright_green().bold());
    for tag in &tags {
        println!("   • {}:{}", registry, tag);
    }
    println!();

    // Update kustomization.yaml if requested
    if let Some(kustomization_path) = update_kustomization_path {
        // Use the first tag (typically the git SHA tag) for kustomization
        let tag_for_kustomization = tags
            .first()
            .ok_or_else(|| anyhow!("No tags available for kustomization update"))?;

        update_kustomization(
            &kustomization_path,
            &registry,
            tag_for_kustomization,
            commit_kustomization,
        )
        .await?;
    }

    Ok(())
}

/// Push a single image to GHCR with retries using skopeo
///
/// This is a reusable function that can be called by other commands.
pub async fn push_with_retry(
    image_path: &str,
    registry: &str,
    tag: &str,
    token: &str,
    retries: u32,
) -> Result<()> {
    let mut attempts = 0;

    // Extract organization from registry URL for credentials
    let organization = extract_organization(&registry)?;

    loop {
        attempts += 1;

        let skopeo = get_tool_path("SKOPEO_BIN", "skopeo");
        let result = Command::new(&skopeo)
            .args(&[
                "copy",
                "--insecure-policy",
                &format!("--retry-times={}", retries),
                &format!("--dest-creds={}:{}", organization, token),
                &format!("docker-archive:{}", image_path),
                &format!("docker://{}:{}", registry, tag),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .status()
            .await;

        match result {
            Ok(status) if status.success() => return Ok(()),
            Ok(_) | Err(_) if attempts < retries => {
                warn!("Push attempt {} failed, retrying...", attempts);
                tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                continue;
            }
            Ok(status) => {
                anyhow::bail!(
                    "Push failed after {} attempts (exit code: {:?})",
                    attempts,
                    status.code()
                );
            }
            Err(e) => {
                anyhow::bail!("Push command failed: {}", e);
            }
        }
    }
}
