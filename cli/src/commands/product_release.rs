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

#[cfg(feature = "attestation")]
use crate::commands::attestation;
use crate::config::DeployConfig;
use crate::infrastructure::git::{CommitPushOutcome, GitClient};

/// Run a forge subcommand by re-invoking the current binary.
pub(crate) async fn run_forge_subcommand(args: &[&str]) -> Result<()> {
    let exe = std::env::current_exe().context("Failed to get current executable path")?;
    println!("   {} forge {}", ">>".dimmed(), args.join(" ").dimmed());

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
async fn run_nix_release_app(
    product: &str,
    service: &str,
    standalone: bool,
    extra_args: &[&str],
) -> Result<()> {
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
pub(crate) async fn run_health_check(
    deployment: &str,
    namespace: &str,
    timeout_secs: u64,
) -> Result<()> {
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
/// `deploy_tag` is the full deploy tag (e.g., "amd64-bb90b44").
/// This function tags the image and pushes to the registry,
/// avoiding a redundant Nix rebuild.
async fn push_prebuilt_image(local_name: &str, registry: &str, deploy_tag: &str) -> Result<()> {
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

    let full_tag = format!("{}:{}", registry, deploy_tag);

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
    attestation_info: Option<&crate::config::AttestationInfoRecord>,
) -> Result<()> {
    let now = chrono::Utc::now().to_rfc3339();
    let mut modified_files = Vec::new();

    for svc in services {
        let product_dir =
            crate::config::resolve_product_dir(std::path::Path::new(repo_root), product);
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
            attestation: attestation_info.cloned(),
        };

        let json =
            serde_json::to_string_pretty(&artifact).context("Failed to serialize artifact info")?;
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
        match commit_artifact_tags(None, &modified_files, git_sha).await? {
            CommitPushOutcome::Pushed => {
                println!("   {} Artifact tags committed and pushed", "OK".green());
            }
            CommitPushOutcome::NoChangesStaged => {
                println!(
                    "   {} Artifact tags already at SHA {} — nothing to commit",
                    "OK".green(),
                    git_sha
                );
            }
        }
    }

    Ok(())
}

/// Commit modified artifact-tag files and push to `origin/main` through
/// the canonical [`GitClient::stage_commit_push_release`] primitive
/// (the same shape every other release flow in forge —
/// `commands/kenshi.rs`, `commands/kenshi_agent.rs`,
/// `commands/nix_builder.rs` — drives, lifted in commit 32a8083). Returns
/// the typed [`CommitPushOutcome`] so the caller distinguishes the
/// idempotent re-release path (`NoChangesStaged`) from the actual-push
/// path (`Pushed`).
///
/// # Why this lift
///
/// Pre-this-commit the call site at [`write_artifact_tags`] carried three
/// inline `Command::new("git").args([...]).status().await.context(...)?`
/// invocations — for `git add`, `git commit`, `git push` — each WITHOUT
/// the `if !status.success() { bail!() }` envelope. Every step silently
/// swallowed non-zero git exits: a push rejected as non-fast-forward, an
/// auth denial, a remote unreachable — all routed to `Ok(())` and the
/// function then printed "✅ Artifact tags committed and pushed"
/// regardless of whether anything had actually been committed or pushed.
/// Post-migration every step routes through the canonical typed
/// primitive — `GitClient::add` / `commit` / `push_to`, all wrapped in
/// `run_inherited_status` which bails on non-zero exit by construction —
/// and the structural-skip path (`NoChangesStaged`, when `git add` leaves
/// the index byte-identical to `HEAD`) surfaces as a typed
/// discriminator instead of fall-through behavior.
///
/// `workdir` is `None` in production (`GitClient::new()` resolves git
/// commands against the current process cwd, which is the repo root by
/// invariant); tests pass `Some(temp_dir)` to drive the helper against
/// a hermetic bare-repo pair.
async fn commit_artifact_tags(
    workdir: Option<&str>,
    modified_files: &[String],
    git_sha: &str,
) -> Result<CommitPushOutcome> {
    let file_refs: Vec<&str> = modified_files.iter().map(String::as_str).collect();
    let commit_msg = format!("chore: update artifact tags to {}", git_sha);
    let client = match workdir {
        Some(dir) => GitClient::in_dir(dir.to_string()),
        None => GitClient::new(),
    };
    client
        .stage_commit_push_release(&file_refs, &commit_msg, "main")
        .await
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
        let product_dir =
            crate::config::resolve_product_dir(std::path::Path::new(&repo_root), &product);
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
    let is_standalone =
        crate::config::resolve_product_dir(std::path::Path::new(&repo_root), &product)
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
            let has_local = check_local_image_exists(&local_image)
                .await
                .unwrap_or(false);

            if has_local && !skip_gates {
                println!(
                    "   {} {} (push prebuilt from E2E)",
                    ">>".dimmed(),
                    svc.name.cyan()
                );
                let deploy_tag = format!("amd64-{}", git_sha);
                push_prebuilt_image(&local_image, &registry_url, &deploy_tag).await?;
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

    // ─── Phase 1.5: Compute attestation ─────────────────────────────────────
    // Compute attestation hashes after all artifacts are pushed.
    // Generates sekiban-compatible annotations for injection into HelmRelease values.
    // Requires the "attestation" feature (tameshi crate).
    // ─── Phase 1.5: Compute attestation ─────────────────────────────────────
    // Requires the "attestation" feature (tameshi crate).
    #[cfg(feature = "attestation")]
    let attestation_info: Option<crate::config::AttestationInfoRecord> = {
        println!("{}", "Phase 1.5: Compute attestation".bold());

        let repo_path = std::path::Path::new(&repo_root);
        let source_att = attestation::compute_source_attestation(repo_path, &git_sha)
            .await
            .unwrap_or_else(|e| {
                eprintln!(
                    "   {} Source attestation failed (non-fatal): {}",
                    "WARN".yellow(),
                    e
                );
                tameshi::ci::source_attestation(
                    "unknown",
                    &git_sha,
                    "refs/heads/main",
                    false,
                    tameshi::hash::Blake3Hash::digest(b"unknown"),
                    tameshi::hash::Blake3Hash::digest(b"unknown"),
                    0,
                    false,
                )
            });
        println!("   {} Source attestation computed", "OK".green());

        let mut build_atts = Vec::new();
        let mut image_atts = Vec::new();
        for svc in &product_config.services {
            match attestation::compute_build_attestation(&svc.name, repo_path).await {
                Ok(att) => {
                    build_atts.push(att);
                    println!("   {} Build attestation: {}", "OK".green(), svc.name.cyan());
                }
                Err(e) => {
                    eprintln!(
                        "   {} Build attestation for {} failed (non-fatal): {}",
                        "WARN".yellow(),
                        svc.name,
                        e
                    );
                }
            }

            let registry_url =
                DeployConfig::load_service_registry_url(&product, &svc.path, &repo_root)?;
            let image_tag = format!("amd64-{}", git_sha);
            match attestation::compute_image_attestation(&registry_url, &image_tag).await {
                Ok(att) => {
                    image_atts.push(att);
                    println!("   {} Image attestation: {}", "OK".green(), svc.name.cyan());
                }
                Err(e) => {
                    eprintln!(
                        "   {} Image attestation for {} failed (non-fatal): {}",
                        "WARN".yellow(),
                        svc.name,
                        e
                    );
                }
            }
        }

        let certification = attestation::compose_product_certification(
            &product,
            target_env,
            "plo",
            source_att,
            build_atts,
            image_atts,
            vec![],
        );

        let result = match &certification {
            Ok(cert) => {
                let values = attestation::generate_attestation_values(cert);
                let info = attestation::generate_attestation_info(cert);
                println!(
                    "   {} Product certification: {} (certified: {})",
                    "OK".green(),
                    if cert.certified {
                        "PASSED".green().to_string()
                    } else {
                        "FAILED".yellow().to_string()
                    },
                    cert.certified
                );
                println!(
                    "   {} Signature: {}",
                    ">>".dimmed(),
                    values.signature.dimmed()
                );
                Some(crate::config::AttestationInfoRecord {
                    signature: info.signature,
                    certification_hash: info.certification_hash,
                    compliance_hash: info.compliance_hash,
                    certified: info.certified,
                })
            }
            Err(e) => {
                eprintln!(
                    "   {} Product certification failed (non-fatal): {}",
                    "WARN".yellow(),
                    e
                );
                None
            }
        };
        println!();
        result
    };

    #[cfg(not(feature = "attestation"))]
    let attestation_info: Option<crate::config::AttestationInfoRecord> = {
        println!(
            "{}",
            "Phase 1.5: Attestation skipped (feature disabled)".dimmed()
        );
        println!();
        None
    };

    // ─── Phase 2: Deploy per environment ────────────────────────────────────
    if build_only {
        println!("{}", "Phase 2: Skipping deploy (--build-only)".dimmed());
        println!();

        // Jump straight to Phase 3: persist artifact tags
        println!("{}", "Phase 3: Persist artifact tags".bold());
        write_artifact_tags(
            &product,
            &product_config.services,
            &repo_root,
            &git_sha,
            attestation_info.as_ref(),
        )
        .await?;
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

            // Resolve image tag: for build environments use arch-prefixed git_sha (pushed in Phase 1),
            // for deploy-only environments use the stored artifact tag from deploy.yaml.
            let image_tag = if svc_release.should_build_artifact(env_name) {
                format!("amd64-{}", git_sha)
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

            let product_dir =
                crate::config::resolve_product_dir(std::path::Path::new(&repo_root), &product);
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
                    &product, &svc.path, &repo_root, env_name,
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
    let att_record = attestation_info
        .as_ref()
        .map(|info| crate::config::AttestationInfoRecord {
            signature: info.signature.clone(),
            certification_hash: info.certification_hash.clone(),
            compliance_hash: info.compliance_hash.clone(),
            certified: info.certified,
        });
    write_artifact_tags(
        &product,
        &product_config.services,
        &repo_root,
        &git_sha,
        att_record.as_ref(),
    )
    .await?;
    println!();

    // ─── Phase 4: Dashboard sync ────────────────────────────────────────────
    if !skip_dashboards && product_config.dashboards {
        println!("{}", "Phase 4: Dashboard sync".bold());
        let product_dir =
            crate::config::resolve_product_dir(std::path::Path::new(&repo_root), &product);
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command as SyncCommand;

    /// Initialize a hermetic git repo with one committed file under
    /// `dir`, configured with a stable identity so `git commit` works
    /// without depending on the host's global config. Mirrors the
    /// shape used by `infrastructure/git.rs`'s
    /// `init_repo_with_one_commit` test helper — the canonical
    /// hermetic-git fixture across forge's typed-CLI tests.
    fn init_repo_with_one_commit(dir: &std::path::Path) {
        let run = |args: &[&str]| {
            let status = SyncCommand::new("git")
                .args(args)
                .current_dir(dir)
                .status()
                .expect("git spawn");
            assert!(status.success(), "git {args:?} failed in {dir:?}");
        };
        run(&["init", "-q", "-b", "main"]);
        run(&["config", "user.email", "forge-test@example.invalid"]);
        run(&["config", "user.name", "forge-test"]);
        run(&["config", "commit.gpgsign", "false"]);
        std::fs::write(dir.join("seed.txt"), "seed\n").unwrap();
        run(&["add", "seed.txt"]);
        run(&["commit", "-q", "-m", "seed"]);
    }

    /// Configure `dir` to push to a fresh bare repo at `bare_dir` as
    /// the `origin` remote. The bare-repo target is what makes
    /// `git push origin main` succeed hermetically — no network, no
    /// upstream server, just two local directories.
    fn add_bare_origin(dir: &std::path::Path, bare_dir: &std::path::Path) {
        // `--initial-branch=main` aligns the bare repo's HEAD with the
        // work-tree's `main` branch so a subsequent `git clone <bare>`
        // resolves HEAD against a real ref instead of a dangling
        // `master` (the system default on some git versions).
        let init = SyncCommand::new("git")
            .args(["init", "-q", "--bare", "--initial-branch=main"])
            .current_dir(bare_dir)
            .status()
            .expect("git init --bare");
        assert!(init.success());
        let add = SyncCommand::new("git")
            .args([
                "remote",
                "add",
                "origin",
                bare_dir.to_str().expect("bare path utf-8"),
            ])
            .current_dir(dir)
            .status()
            .expect("git remote add");
        assert!(add.success());
    }

    /// `commit_artifact_tags` MUST use the canonical commit-subject
    /// format `"chore: update artifact tags to <sha>"` and MUST land
    /// that subject on origin/main via the underlying primitive's
    /// push step. Pins the commit-message contract that downstream
    /// `git log --grep='chore: update artifact tags'` audit queries
    /// rely on; pinning the format at the helper boundary means a
    /// future drift cannot change the audit-grep target silently.
    #[tokio::test]
    async fn test_commit_artifact_tags_uses_canonical_commit_subject_format() {
        let parent = tempfile::tempdir().expect("parent tempdir");
        let work = parent.path().join("work");
        let bare = parent.path().join("origin.git");
        std::fs::create_dir(&work).expect("mkdir work");
        std::fs::create_dir(&bare).expect("mkdir bare");
        init_repo_with_one_commit(&work);
        add_bare_origin(&work, &bare);
        std::fs::write(work.join("svc.artifact.json"), "{}\n").unwrap();

        let outcome = commit_artifact_tags(
            Some(&work.to_string_lossy()),
            &["svc.artifact.json".to_string()],
            "deadbeef1234",
        )
        .await
        .expect("happy-path commit_artifact_tags must succeed");
        assert_eq!(outcome, CommitPushOutcome::Pushed);

        // `git clone <bare> <probe>` requires `<probe>` to not exist (or
        // to be empty); git creates the directory. Picking a path inside
        // the parent tempdir keeps cleanup automatic.
        let probe = parent.path().join("probe");
        let clone = SyncCommand::new("git")
            .args([
                "clone",
                bare.to_str().expect("bare utf-8"),
                probe.to_str().expect("probe utf-8"),
            ])
            .status()
            .expect("git clone");
        assert!(clone.success(), "probe clone must succeed");
        let subject_out = SyncCommand::new("git")
            .args(["log", "-1", "--pretty=%s"])
            .current_dir(&probe)
            .output()
            .expect("git log");
        let subject = String::from_utf8_lossy(&subject_out.stdout)
            .trim()
            .to_string();
        assert_eq!(
            subject, "chore: update artifact tags to deadbeef1234",
            "commit subject must match the canonical artifact-tag format"
        );
    }

    /// `commit_artifact_tags` invoked against files whose content
    /// already matches `HEAD` MUST return
    /// `CommitPushOutcome::NoChangesStaged` and MUST NOT attempt a
    /// commit or push. Pins the idempotent-re-release contract for
    /// the artifact-tag commit path: re-running a release at the
    /// same SHA does not produce an orphaned empty commit and does
    /// not contact the (in-test: absent) remote.
    ///
    /// We assert the "did not push" half structurally: the test repo
    /// has NO `origin` remote configured, so a fall-through to the
    /// primitive's `push_to("origin", "main")` step would fail with
    /// `GitError::OpFailed` or `RemoteOpFailed` and the test would
    /// surface that error. A clean `Ok(NoChangesStaged)` proves the
    /// skip happened before any push spawn.
    #[tokio::test]
    async fn test_commit_artifact_tags_returns_no_changes_on_idempotent_re_release() {
        let work = tempfile::tempdir().expect("work tempdir");
        init_repo_with_one_commit(work.path());
        let outcome = commit_artifact_tags(
            Some(&work.path().to_string_lossy()),
            &["seed.txt".to_string()],
            "abc1234",
        )
        .await
        .expect("re-staging an already-committed file must succeed");
        assert_eq!(
            outcome,
            CommitPushOutcome::NoChangesStaged,
            "re-staging unchanged file must skip commit + push"
        );
    }

    /// `commit_artifact_tags` MUST surface a typed error when the
    /// push step fails — the exact regression the pre-lift inline
    /// `Command::new("git").args([...]).status().await.context(...)?`
    /// sequence at `write_artifact_tags` silently swallowed.
    ///
    /// Pre-lift each step dropped its success check, so a push
    /// rejected as non-fast-forward / auth-denied / remote-unreachable
    /// silently routed to `Ok(())` and the function declared
    /// "✅ Artifact tags committed and pushed" verbatim regardless.
    /// Post-lift the canonical primitive's per-step
    /// `run_inherited_status` envelope bails on non-zero exit and the
    /// error surfaces verbatim at the caller's `?` operator.
    ///
    /// The fixture configures `origin` to point to a non-existent
    /// path so the push step fails deterministically — same shape as
    /// every transient-push failure that escapes the retry budget in
    /// production. The post-lift contract is: a failed push must
    /// surface a typed `Err`, never an `Ok(Pushed)`.
    #[tokio::test]
    async fn test_commit_artifact_tags_surfaces_push_failure() {
        let work = tempfile::tempdir().expect("work tempdir");
        init_repo_with_one_commit(work.path());
        let bogus = work.path().join("bogus-origin.does-not-exist");
        let add = SyncCommand::new("git")
            .args([
                "remote",
                "add",
                "origin",
                bogus.to_str().expect("bogus path utf-8"),
            ])
            .current_dir(work.path())
            .status()
            .expect("git remote add");
        assert!(add.success(), "git remote add must succeed");
        std::fs::write(work.path().join("svc.artifact.json"), "{}\n").unwrap();

        let result = commit_artifact_tags(
            Some(&work.path().to_string_lossy()),
            &["svc.artifact.json".to_string()],
            "deadbeef1234",
        )
        .await;
        assert!(
            result.is_err(),
            "push to a non-existent remote MUST surface a typed error, \
             never the silent Ok(Pushed) the pre-lift inline sequence produced; \
             got: {result:?}"
        );
    }
}
