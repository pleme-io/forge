use anyhow::{Context, Result};
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use std::path::Path;
use tokio::process::Command;
use tracing::{info, warn};

use crate::{cloudflare, commands, config::DeployConfig, git};

pub async fn execute(
    manifest: String,
    registry: String,
    tag: String,
    namespace: String,
    name: String,
    _watch: bool,
    _timeout: String,
    skip_build: bool,
    cache_url: String,
    cache_name: String,
) -> Result<()> {
    println!();
    println!(
        "{}",
        "╔════════════════════════════════════════════════════════════╗"
            .bright_cyan()
            .bold()
    );
    println!(
        "{}",
        "║  Nexus Deploy - GitOps Workflow                           ║"
            .bright_cyan()
            .bold()
    );
    println!(
        "{}",
        "╚════════════════════════════════════════════════════════════╝"
            .bright_cyan()
            .bold()
    );
    println!();

    info!("🎯 Target: {}:{}", registry, tag);
    info!("📦 Namespace: {}", namespace);
    info!("🚀 Deployment: {}", name);
    println!();

    // Step 1: Build (unless skipped)
    if !skip_build {
        info!("━━━ Step 1/3: Build ━━━");
        commands::build::execute(
            "dockerImage".to_string(),
            ".".to_string(),
            "x86_64-linux".to_string(),
            cache_url,
            cache_name.clone(),
            true,
            "result".to_string(),
        )
        .await?;
    } else {
        info!("⏭️  Skipping build step");
        println!();
    }

    // Step 2: Push
    info!("━━━ Step 2/3: Push ━━━");
    commands::push::execute(
        "result".to_string(),
        registry.clone(),
        vec![tag.clone()],
        false,               // auto_tags
        "amd64".to_string(), // arch
        10,                  // retries
        None,                // token from env
        false,               // push_attic
        cache_name,
        None,  // update_kustomization_path - handled separately in deploy
        false, // commit_kustomization
    )
    .await?;

    // Step 3: GitOps Deploy
    info!("━━━ Step 3/3: GitOps Deploy ━━━");
    println!();

    // The manifest parameter should point to kustomization.yaml
    let kustomization_path = Path::new(&manifest);

    // Read current tag from kustomization.yaml
    let kustomization_content = tokio::fs::read_to_string(kustomization_path)
        .await
        .context("Failed to read kustomization.yaml")?;

    // Parse YAML to extract current tag from images[].newTag
    let yaml: serde_yaml::Value = serde_yaml::from_str(&kustomization_content)
        .context("Failed to parse kustomization.yaml")?;

    let old_tag = yaml
        .get("images")
        .and_then(|images| images.as_sequence())
        .and_then(|seq| seq.first())
        .and_then(|image| image.get("newTag"))
        .and_then(|tag_val| tag_val.as_str())
        .ok_or_else(|| anyhow::anyhow!("Could not find images[0].newTag in kustomization.yaml"))?
        .to_string();

    // Extract the image name from the registry (last component)
    let image_name = registry
        .rsplit('/')
        .next()
        .ok_or_else(|| anyhow::anyhow!("Invalid registry format: {}", registry))?;

    info!("📝 Updating kustomization.yaml...");
    info!("   Image: {}", image_name);
    info!("   Old tag: {}", old_tag);
    info!("   New tag: {}", tag);
    println!();

    // Update kustomization.yaml's images[].newTag
    git::update_manifest(kustomization_path, &old_tag, &tag).await?;

    // Update ConfigMap with GIT_SHA
    info!("📝 Updating ConfigMap with GIT_SHA...");
    git::update_configmap_git_sha(kustomization_path, &tag).await?;

    // Commit and push
    info!("📤 Committing to Git...");

    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .unwrap(),
    );
    pb.set_message("Pushing to main...");
    pb.enable_steady_tick(std::time::Duration::from_millis(100));

    git::commit_and_push(kustomization_path, &old_tag, &tag)?;

    pb.finish_with_message("✅ Pushed to main");
    println!();

    // Trigger FluxCD reconciliation
    // Note: Single-source architecture means infrastructure is applied directly by flux-system
    info!("🔄 Triggering FluxCD reconciliation...");
    let flux_result = Command::new("flux")
        .args(&[
            "reconcile",
            "kustomization",
            "flux-system",
            "-n",
            "flux-system",
        ])
        .output()
        .await;

    match flux_result {
        Ok(output) if output.status.success() => {
            info!("✅ FluxCD reconciliation triggered");
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!("⚠️  FluxCD reconcile failed (non-fatal): {}", stderr);
        }
        Err(e) => {
            warn!("⚠️  Could not execute flux command (non-fatal): {}", e);
        }
    }

    println!();

    // Step 4: Purge Cloudflare cache (if configured)
    // Try to load config to check for Cloudflare settings
    // This is optional - if config can't be loaded, we skip purging
    if let Ok(config) = DeployConfig::load_for_service(&name) {
        if config.global.cloudflare.enabled {
            info!("━━━ Step 4/4: Purge Cloudflare Cache ━━━");
            println!();

            if let (Some(zone_id), Some(api_token), Some(base_url)) = (
                config.global.cloudflare.zone_id.as_ref(),
                config.global.cloudflare.api_token.as_ref(),
                config.global.cloudflare.base_url.as_ref(),
            ) {
                // Build full URLs for files to purge
                let urls: Vec<String> = config
                    .global
                    .cloudflare
                    .files
                    .iter()
                    .map(|file| format!("{}{}", base_url.trim_end_matches('/'), file))
                    .collect();

                info!("🧹 Purging Cloudflare cache...");
                info!("   Zone ID: {}***", &zone_id[..8]);
                info!("   Files: {}", urls.join(", "));
                println!();

                match cloudflare::purge_cache(zone_id, api_token, &urls).await {
                    Ok(()) => {
                        info!("✅ Cloudflare cache purged successfully");
                        println!();
                    }
                    Err(e) => {
                        warn!("⚠️  Cloudflare cache purge failed (non-fatal): {}", e);
                        println!();
                    }
                }
            } else {
                warn!("⚠️  Cloudflare enabled but missing configuration (zone_id, api_token, or base_url)");
                println!();
            }
        }
    }

    println!(
        "{}",
        "╔════════════════════════════════════════════════════════════╗"
            .bright_green()
            .bold()
    );
    println!(
        "{}",
        "║  ✅ Deployment Complete!                                   ║"
            .bright_green()
            .bold()
    );
    println!(
        "{}",
        "╚════════════════════════════════════════════════════════════╝"
            .bright_green()
            .bold()
    );
    println!();
    println!("📦 Deployed: {}:{}", registry, tag);
    println!("🎯 Strategy: FluxCD GitOps");
    println!();
    println!("Monitor deployment:");
    println!("  • FluxCD status: flux get kustomizations -A");
    println!("  • Watch pods:    kubectl get pods -n {} -w", namespace);
    println!(
        "  • View logs:     kubectl logs -n {} -l app={} --tail=50",
        namespace, name
    );
    println!("  • Rollback:      git revert HEAD && git push");
    println!();

    Ok(())
}
