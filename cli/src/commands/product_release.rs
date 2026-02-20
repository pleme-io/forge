//! Product-level release orchestration.
//!
//! Coordinates a full product release across all services and environments:
//!
//! - Phase 0: Pre-release gates (optional, skippable)
//!   - Includes E2E tests which build fresh Docker images
//! - Phase 1: Push artifacts to registry
//!   - Reuses images built during Phase 0 (E2E) when available
//!   - Falls back to Nix build when pre-release was skipped
//! - Phase 2: Deploy all services per environment with health checks
//! - Phase 3: Write artifact tags to artifact.json
//! - Phase 4: Dashboard sync (optional)
//! - Phase 5: Post-deploy verification (optional, staging only)

use anyhow::{bail, Context, Result};
use colored::Colorize;
use tokio::process::Command;

use crate::config::DeployConfig;

/// Run a forge subcommand by re-invoking the current binary.
pub(crate) async fn run_forge_subcommand(args: &[&str]) -> Result<()> {
    let exe = std::env::current_exe().context("Failed to get current executable path")?;
    println!(
        "   {} forge {}",
        ">>".dimmed(),
        args.join(" ").dimmed()
    );

    let status = Command::new(exe)
        .args(args)
        .status()
        .await
        .with_context(|| format!("Failed to run forge subcommand: {:?}", args))?;

    if !status.success() {
        bail!(
            "forge subcommand failed (exit {}): {:?}",
            status.code().unwrap_or(-1),
            args
        );
    }
    Ok(())
}

/// Run a nix release app.
///
/// - Standalone repos (product = repo root): `nix run .#release:{service} -- {extra_args}`
/// - Monorepo (product under pkgs/products): `nix run .#release:{product}:{service} -- {extra_args}`
async fn run_nix_release_app(product: &str, service: &str, standalone: bool, extra_args: &[&str]) -> Result<()> {
    let app = if standalone {
        format!(".#release:{}", service)
    } else {
        format!(".#release:{}:{}", product, service)
    };
    let mut args = vec!["run", &app, "--"];
    args.extend_from_slice(extra_args);

    println!("   {} nix {}", ">>".dimmed(), args.join(" ").dimmed());

    let status = Command::new("nix")
        .args(args)
        .status()
        .await
        .with_context(|| format!("Failed to run nix release app: {}", app))?;

    if !status.success() {
        bail!(
            "nix release app failed (exit {}): {}",
            status.code().unwrap_or(-1),
            app
        );
    }
    Ok(())
}

/// Run a kubectl health check for a deployment.
pub(crate) async fn run_health_check(deployment: &str, namespace: &str, timeout_secs: u64) -> Result<()> {
    println!(
        "   {} Checking deployment {} in {}...",
        ">>".dimmed(),
        deployment.cyan(),
        namespace.dimmed()
    );

    // Check rollout status
    let timeout_str = format!("{}s", timeout_secs);
    let status = Command::new("kubectl")
        .args([
            "rollout",
            "status",
            &format!("deployment/{}", deployment),
            "-n",
            namespace,
            &format!("--timeout={}", timeout_str),
        ])
        .status()
        .await
        .context("Failed to run kubectl rollout status")?;

    if !status.success() {
        bail!(
            "Health check failed: deployment/{} in {} (timeout: {}s)",
            deployment,
            namespace,
            timeout_secs
        );
    }

    // Verify at least one pod is Running
    let output = Command::new("kubectl")
        .args([
            "get",
            "pods",
            "-n",
            namespace,
            "-l",
            &format!("app={}", deployment),
            "-o",
            "jsonpath={.items[0].status.phase}",
        ])
        .output()
        .await
        .context("Failed to get pod status")?;

    let phase = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if phase != "Running" {
        bail!(
            "Health check failed: pod status is '{}', expected 'Running' for {}",
            phase,
            deployment
        );
    }

    println!(
        "   {} {} healthy (pods Running)",
        "OK".green(),
        deployment.cyan()
    );
    Ok(())
}

/// Check if a Docker image exists locally (built during E2E gates).
async fn check_local_image_exists(name: &str) -> Result<bool> {
    let output = Command::new("docker")
        .args(["images", "-q", name])
        .output()
        .await
        .with_context(|| format!("Failed to check for local Docker image: {}", name))?;

    Ok(!String::from_utf8_lossy(&output.stdout).trim().is_empty())
}

/// Push a locally-built Docker image to the registry.
///
/// Images are built during pre-release E2E gates and loaded into Docker.
/// This function tags them with the release SHA and pushes to the registry,
/// avoiding a redundant Nix rebuild.
async fn push_prebuilt_image(local_name: &str, registry: &str, tag: &str) -> Result<()> {
    // Get the image ID (handles any tag the Nix build assigned)
    let output = Command::new("docker")
        .args(["images", "-q", local_name])
        .output()
        .await
        .context("Failed to get Docker image ID")?;

    let image_id = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if image_id.is_empty() {
        bail!("No local Docker image found for '{}'", local_name);
    }

    // Use the first image ID if multiple exist
    let image_id = image_id.lines().next().unwrap_or(&image_id);

    let full_tag = format!("{}:amd64-{}", registry, tag);

    // Tag with registry URL and SHA
    let status = Command::new("docker")
        .args(["tag", image_id, &full_tag])
        .status()
        .await
        .with_context(|| format!("Failed to tag image {} → {}", local_name, full_tag))?;

    if !status.success() {
        bail!("docker tag failed: {} → {}", local_name, full_tag);
    }

    // Push to registry
    let status = Command::new("docker")
        .args(["push", &full_tag])
        .status()
        .await
        .with_context(|| format!("Failed to push image {}", full_tag))?;

    if !status.success() {
        bail!("docker push failed: {}", full_tag);
    }

    Ok(())
}

/// Write artifact tags to per-service JSON files and git commit.
///
/// Writes machine-managed `{service}.artifact.json` files (not YAML) to avoid
/// serialization issues with comments, formatting, and symbol escaping.
async fn write_artifact_tags(
    product: &str,
    services: &[crate::config::ProductServiceConfig],
    repo_root: &str,
    git_sha: &str,
) -> Result<()> {
    let now = chrono::Utc::now().to_rfc3339();
    let mut modified_files = Vec::new();

    for svc in services {
        let product_dir = crate::config::resolve_product_dir(std::path::Path::new(repo_root), product);
        let service_dir = product_dir.join(&svc.path);

        let json_path = crate::config::resolve_artifact_json_path(&product_dir, &svc.name);

        // Load current artifact to get previous_tag
        let current = crate::config::load_artifact_info(&product_dir, &svc.name, &service_dir);
        let previous_tag = current
            .as_ref()
            .map(|a| a.tag.clone())
            .filter(|t| !t.is_empty())
            .unwrap_or_default();

        let artifact = crate::config::ArtifactInfo {
            tag: git_sha.to_string(),
            built_at: now.clone(),
            previous_tag,
        };

        let json = serde_json::to_string_pretty(&artifact)
            .context("Failed to serialize artifact info")?;
        std::fs::write(&json_path, format!("{}\n", json))
            .with_context(|| format!("Failed to write {}", json_path.display()))?;

        modified_files.push(json_path.to_string_lossy().to_string());
        println!(
            "   {} Updated artifact tag in deploy/{}.artifact.json",
            "OK".green(),
            svc.name
        );
    }

    if !modified_files.is_empty() {
        for file in &modified_files {
            Command::new("git")
                .args(["add", file])
                .status()
                .await
                .context("Failed to git add")?;
        }

        let commit_msg = format!("chore: update artifact tags to {}", git_sha);
        Command::new("git")
            .args(["commit", "-m", &commit_msg])
            .status()
            .await
            .context("Failed to git commit artifact tags")?;

        Command::new("git")
            .args(["push", "origin", "main"])
            .status()
            .await
            .context("Failed to git push artifact tags")?;

        println!("   {} Artifact tags committed and pushed", "OK".green());
    }

    Ok(())
}

/// Product-level release orchestration.
///
/// Coordinates all services through build, deploy, and verification phases.
pub async fn product_release(
    product: String,
    repo_root: String,
    env: Option<String>,
    skip_gates: bool,
    skip_dashboards: bool,
    build_only: bool,
) -> Result<()> {
    // Load product release config
    let product_config = DeployConfig::load_product_release_config(&product, &repo_root)?;

    // Validate we have services configured
    if product_config.services.is_empty() {
        bail!(
            "No services configured in deploy.yaml release.services section.\n  \
             Add a services list to enable product-release orchestration."
        );
    }

    // Determine target environment(s)
    let target_env = env.as_deref().unwrap_or("staging");

    // Resolve git SHA for consistency across all phases
    let git_sha = std::env::var("RELEASE_GIT_SHA").unwrap_or_default();
    if git_sha.is_empty() {
        bail!(
            "RELEASE_GIT_SHA not set.\n  \
             product-release requires RELEASE_GIT_SHA to ensure consistent tagging.\n  \
             This is normally set by the nix release wrapper."
        );
    }

    println!(
        "{} {} Product Release {}",
        ">>".bold(),
        product.cyan().bold(),
        format!("(env: {}, sha: {})", target_env, git_sha).dimmed()
    );
    println!("{}", "=".repeat(60));
    println!();

    // Show release plan
    println!("{}", "Release Plan:".bold());
    println!(
        "   Services: {}",
        product_config
            .services
            .iter()
            .map(|s| s.name.as_str())
            .collect::<Vec<_>>()
            .join(", ")
            .cyan()
    );
    println!("   Target:   {}", target_env.cyan());
    println!("   SHA:      {}", git_sha.yellow());
    println!();

    // ─── Phase 0: Pre-release gates ─────────────────────────────────────────
    // Gates automatically skip for non-staging environments because production
    // promotes the same image that already passed staging gates.
    let is_staging = target_env == "staging";
    let effective_skip_gates = skip_gates || !is_staging;

    if !effective_skip_gates && product_config.prerelease {
        println!("{}", "Phase 0: Pre-release gates".bold());
        let product_dir = crate::config::resolve_product_dir(std::path::Path::new(&repo_root), &product);
        let product_dir_str = product_dir.to_string_lossy().to_string();

        run_forge_subcommand(&["prerelease", "--working-dir", &product_dir_str]).await?;

        println!();
    } else if skip_gates {
        println!(
            "{}",
            "Phase 0: Skipping pre-release gates (--skip-gates)".dimmed()
        );
        println!();
    } else if !is_staging {
        println!(
            "{}",
            format!(
                "Phase 0: Skipping pre-release gates (env={}, gates only run for staging)",
                target_env
            )
            .dimmed()
        );
        println!();
    }

    // ─── Phase 1: Push artifacts to registry ────────────────────────────────
    // Images are built during Phase 0 (E2E gates always force-rebuild).
    // Phase 1 reuses those prebuilt images when available, avoiding redundant Nix builds.
    // Falls back to Nix build when prerelease was skipped (--skip-gates).
    println!("{}", "Phase 1: Push artifacts".bold());

    // Standalone detection: if deploy.yaml is at repo root and names this product,
    // nix apps use `release:{service}` (no product prefix).
    let is_standalone = crate::config::resolve_product_dir(std::path::Path::new(&repo_root), &product)
        == std::path::Path::new(&repo_root);

    for svc in &product_config.services {
        let svc_release =
            DeployConfig::load_service_release_config(&product, &svc.path, &repo_root)?;

        if svc_release.should_build_artifact(target_env) {
            // Map service name to Docker image name (convention: {product}-{service})
            let local_image = format!("{}-{}", product, svc.name);
            let registry_url =
                DeployConfig::load_service_registry_url(&product, &svc.path, &repo_root)?;

            // Try to push prebuilt image (built during E2E in Phase 0)
            let has_local = check_local_image_exists(&local_image).await.unwrap_or(false);

            if has_local && !skip_gates {
                println!(
                    "   {} {} (push prebuilt from E2E)",
                    ">>".dimmed(),
                    svc.name.cyan()
                );
                push_prebuilt_image(&local_image, &registry_url, &git_sha).await?;
            } else {
                // Fallback: build via Nix (when --skip-gates or no local image)
                if skip_gates {
                    println!(
                        "   {} {} (build + push, gates were skipped)",
                        ">>".dimmed(),
                        svc.name.cyan()
                    );
                } else {
                    println!(
                        "   {} {} (build + push, no prebuilt image)",
                        ">>".dimmed(),
                        svc.name.cyan()
                    );
                }
                run_nix_release_app(&product, &svc.name, is_standalone, &["--push-only"]).await?;
            }
            println!("   {} {} pushed", "OK".green(), svc.name.cyan());
        } else {
            // Deploy-only: verify artifact tag exists
            let tag = svc_release
                .artifact
                .as_ref()
                .map(|a| a.tag.clone())
                .filter(|t| !t.is_empty());

            if tag.is_none() {
                bail!(
                    "No artifact tag for {} in deploy-only environment '{}'\n  \
                     Run a build release first to populate deploy/{}.artifact.json",
                    svc.name,
                    target_env,
                    svc.name
                );
            }

            println!(
                "   {} {} (deploy-only, tag: {})",
                "--".dimmed(),
                svc.name.cyan(),
                tag.as_deref().unwrap_or("?").yellow()
            );
        }
    }
    println!();

    // ─── Phase 2: Deploy per environment ────────────────────────────────────
    if build_only {
        println!(
            "{}",
            "Phase 2: Skipping deploy (--build-only)".dimmed()
        );
        println!();

        // Jump straight to Phase 3: persist artifact tags
        println!("{}", "Phase 3: Persist artifact tags".bold());
        write_artifact_tags(&product, &product_config.services, &repo_root, &git_sha).await?;
        println!();

        println!(
            "{}",
            "Phase 4: Skipping dashboard sync (--build-only)".dimmed()
        );
        println!();
        println!(
            "{}",
            "Phase 5: Skipping post-deploy verification (--build-only)".dimmed()
        );
        println!();

        println!("{}", "=".repeat(60).bright_green());
        println!(
            "{} {} {}",
            "BUILD COMPLETE".green().bold(),
            product.cyan().bold(),
            format!("(sha: {})", git_sha).dimmed()
        );
        println!("{}", "=".repeat(60).bright_green());

        return Ok(());
    }

    println!("{}", "Phase 2: Deploy services".bold());

    // Load environments from the first service's deploy.yaml
    // (all services share the same environment topology)
    let first_svc = &product_config.services[0];
    let first_release =
        DeployConfig::load_service_release_config(&product, &first_svc.path, &repo_root)?;

    let environments: Vec<String> = if env.is_some() {
        // Single environment mode
        first_release.get_environments(target_env)
    } else {
        // All active environments
        first_release.get_environments("all")
    };

    if environments.is_empty() {
        bail!(
            "No active environments to deploy to for '{}'.\n  \
             Check active_environments in service deploy.yaml.",
            target_env
        );
    }

    for env_name in &environments {
        println!("   {} {}", ">>".dimmed(), env_name.cyan().bold());

        for svc in &product_config.services {
            let svc_release =
                DeployConfig::load_service_release_config(&product, &svc.path, &repo_root)?;

            // Resolve image tag: for build environments use git_sha (just pushed in Phase 1),
            // for deploy-only environments use the stored artifact tag from deploy.yaml.
            let image_tag = if svc_release.should_build_artifact(env_name) {
                git_sha.clone()
            } else {
                svc_release
                    .artifact
                    .as_ref()
                    .map(|a| a.tag.clone())
                    .filter(|t| !t.is_empty())
                    .context("No artifact tag in deploy.yaml for deploy-only environment")?
            };

            let registry_url =
                DeployConfig::load_service_registry_url(&product, &svc.path, &repo_root)?;

            let product_dir = crate::config::resolve_product_dir(std::path::Path::new(&repo_root), &product);
            let service_dir = product_dir.join(&svc.path).to_string_lossy().to_string();

            // Always call orchestrate-release directly (not via nix run) to avoid
            // re-evaluating the nix derivation which would rebuild the docker image.
            // Phase 1 already built and pushed the image; Phase 2 only needs to deploy.
            run_forge_subcommand(&[
                "orchestrate-release",
                "--service",
                &svc.name,
                "--service-dir",
                &service_dir,
                "--repo-root",
                &repo_root,
                "--registry",
                &registry_url,
                "--deploy-only",
                "--image-tag",
                &image_tag,
                "--single-environment",
                "--environment",
                env_name,
            ])
            .await?;

            println!(
                "   {} {} deployed to {}",
                "OK".green(),
                svc.name.cyan(),
                env_name.dimmed()
            );

            // Health check after deploying each service
            if let Some(hc) = &svc.health_check {
                let namespace = DeployConfig::load_service_namespace(
                    &product,
                    &svc.path,
                    &repo_root,
                    env_name,
                )?;
                run_health_check(&hc.deployment, &namespace, hc.timeout_secs).await?;
            }
        }

        // Image verification skipped: K8s handles rollout coordination.
        // FluxCD may not have reconciled yet, so checking deployed images
        // would race with the GitOps sync.
    }
    println!();

    // ─── Phase 3: Write artifact tags ───────────────────────────────────────
    println!("{}", "Phase 3: Persist artifact tags".bold());
    write_artifact_tags(&product, &product_config.services, &repo_root, &git_sha).await?;
    println!();

    // ─── Phase 4: Dashboard sync ────────────────────────────────────────────
    if !skip_dashboards && product_config.dashboards {
        println!("{}", "Phase 4: Dashboard sync".bold());
        let product_dir = crate::config::resolve_product_dir(std::path::Path::new(&repo_root), &product);
        let product_dir_str = product_dir.to_string_lossy().to_string();
        run_forge_subcommand(&["dashboards", "--working-dir", &product_dir_str]).await?;
        println!();
    } else {
        println!("{}", "Phase 4: Skipping dashboard sync".dimmed());
        println!();
    }

    // ─── Phase 5: Post-deploy verification ──────────────────────────────────
    if target_env == "staging" && product_config.post_deploy {
        println!("{}", "Phase 5: Post-deploy verification".bold());
        // Allow failure (best-effort verification)
        match run_forge_subcommand(&[
            "post-deploy-verify",
            "--environment",
            "staging",
            "--service",
            &product,
        ])
        .await
        {
            Ok(_) => println!("   {} Post-deploy checks passed", "OK".green()),
            Err(e) => {
                eprintln!(
                    "   {} Post-deploy verification failed (non-fatal): {}",
                    "WARN".yellow(),
                    e
                );
            }
        }
        println!();
    } else {
        println!("{}", "Phase 5: Skipping post-deploy verification".dimmed());
        println!();
    }

    // ─── Done ───────────────────────────────────────────────────────────────
    println!("{}", "=".repeat(60).bright_green());
    println!(
        "{} {} {}",
        "RELEASE COMPLETE".green().bold(),
        product.cyan().bold(),
        format!("({}, {})", target_env, git_sha).dimmed()
    );
    println!("{}", "=".repeat(60).bright_green());

    Ok(())
}
