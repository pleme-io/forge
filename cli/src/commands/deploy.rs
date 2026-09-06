use anyhow::Result;
use std::path::Path;
use tracing::{info, warn};

use crate::{cloudflare, commands, config::DeployConfig};

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
    crate::ui::print_boxed_banner(
        crate::ui::BoxedBannerStyle::CyanBold,
        "Nexus Deploy - GitOps Workflow",
    );

    info!("🎯 Target: {}:{}", registry, tag);
    info!("📦 Namespace: {}", namespace);
    info!("🚀 Deployment: {}", name);
    println!();

    // Step 1: Build (unless skipped)
    if !skip_build {
        crate::step_header::announce_step_header(1, 3, "Build");
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
        crate::info_skipping!("build step");
    }

    // Step 2: Push
    crate::step_header::announce_step_header(2, 3, "Push");
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
    crate::step_header::announce_step_header(3, 3, "GitOps Deploy");
    println!();

    // The manifest parameter should point to kustomization.yaml
    let kustomization_path = Path::new(&manifest);

    // Read the current `images[0].newTag` — the read+parse envelope
    // AND the not-found envelope now live at ONE typed boundary at
    // `commands::manifest_current_tag::read_current_new_tag`, shared
    // with the sibling `commands/github_runner_ci.rs` consumer so a
    // future drift on the walk shape, the not-found phrasing, or the
    // caller's `path.display()` threading flows to both flows from
    // one edit rather than through two diverging inline stanzas.
    let old_tag = commands::manifest_current_tag::read_current_new_tag(kustomization_path).await?;

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

    // Update `images[].newTag` AND the sibling ConfigMap's `data.GIT_SHA`
    // as one atomic write pair — the update-manifest + info-line
    // announcement + update-configmap-GIT_SHA fusion now lives at ONE
    // typed boundary at
    // `commands::manifest_configmap_git_sha_sync::sync_manifest_tag_and_configmap_git_sha`,
    // shared with the sibling `commands/github_runner_ci.rs` consumer
    // so the load-bearing `(newTag, GIT_SHA)` sync invariant — the SAME
    // value lands in BOTH YAML fields — stays owned by the primitive
    // rather than by a pair-of-locals convention at each call site.
    commands::manifest_configmap_git_sha_sync::sync_manifest_tag_and_configmap_git_sha(
        kustomization_path,
        &old_tag,
        &tag,
    )
    .await?;

    // Commit and push — the info-line preamble + green-spinner +
    // git::commit_and_push + canonical finish-message + trailing
    // blank line fusion now lives at ONE typed boundary at
    // `commands::manifest_push::commit_and_push_manifest_with_progress`,
    // shared with the sibling `commands/github_runner_ci.rs`
    // consumer so a future re-branding of the push target flows to
    // both flows from one edit.
    commands::manifest_push::commit_and_push_manifest_with_progress(
        kustomization_path,
        &old_tag,
        &tag,
    )?;

    // Trigger FluxCD reconciliation — the info-line announcement +
    // Ok=>info_success! + Err=>warn_nonfatal! fusion now lives at ONE
    // typed boundary at
    // `commands::flux_system_reconcile::announce_and_reconcile_flux_system`,
    // shared with the sibling `commands/github_runner_ci.rs` consumer
    // so a future re-branding of the announcement, the success phrase,
    // the failure label, or the `(kustomization, namespace)` reconcile
    // target flows to both flows from one edit. Mode `Triggered` maps
    // to `with_source=false` + success phrase `"triggered"` — the
    // single-source architecture means infrastructure is applied
    // directly by flux-system so this flow only kicks off the
    // reconciliation rather than waiting for source readiness.
    commands::flux_system_reconcile::announce_and_reconcile_flux_system(
        commands::flux_system_reconcile::FluxSystemReconcileMode::Triggered,
    )
    .await;

    println!();

    // Step 4: Purge Cloudflare cache (if configured)
    // Try to load config to check for Cloudflare settings
    // This is optional - if config can't be loaded, we skip purging
    if let Ok(config) = DeployConfig::load_for_service(&name) {
        if config.global.cloudflare.enabled {
            crate::step_header::announce_step_header(4, 4, "Purge Cloudflare Cache");
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
                        crate::info_success!("Cloudflare cache purged successfully");
                        println!();
                    }
                    Err(e) => {
                        crate::warn_nonfatal!("Cloudflare cache purge failed", e);
                        println!();
                    }
                }
            } else {
                warn!("⚠️  Cloudflare enabled but missing configuration (zone_id, api_token, or base_url)");
                println!();
            }
        }
    }

    crate::ui::print_boxed_banner(
        crate::ui::BoxedBannerStyle::GreenBold,
        "✅ Deployment Complete!",
    );
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
