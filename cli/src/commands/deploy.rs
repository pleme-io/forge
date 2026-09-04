use anyhow::Result;
use colored::Colorize;
use std::path::Path;
use tracing::{info, warn};

use crate::ui::{styled_spinner, SpinnerStyle};
use crate::{cloudflare, commands, config::DeployConfig, flux_reconcile, git};

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

    // Read + parse kustomization via the async YAML load primitive so
    // the envelope carries the offending path in both arms.
    let yaml: serde_yaml::Value = crate::repo::read_yaml_async(kustomization_path).await?;

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

    let pb = styled_spinner(SpinnerStyle::Green, "Pushing to main...");

    git::commit_and_push(kustomization_path, &old_tag, &tag)?;

    pb.finish_with_message("✅ Pushed to main");
    println!();

    // Trigger FluxCD reconciliation
    // Note: Single-source architecture means infrastructure is applied directly by flux-system
    info!("🔄 Triggering FluxCD reconciliation...");
    match flux_reconcile::reconcile_kustomization("flux-system", "flux-system", false).await {
        Ok(()) => {
            info!("✅ FluxCD reconciliation triggered");
        }
        Err(e) => {
            warn!("⚠️  FluxCD reconcile failed (non-fatal): {}", e);
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
    crate::ui::print_bullet_item("FluxCD status: flux get kustomizations -A");
    crate::ui::print_bullet_item(&format!(
        "Watch pods:    kubectl get pods -n {} -w",
        namespace
    ));
    crate::ui::print_bullet_item(&format!(
        "View logs:     kubectl logs -n {} -l app={} --tail=50",
        namespace, name
    ));
    crate::ui::print_bullet_item("Rollback:      git revert HEAD && git push");
    println!();

    Ok(())
}
