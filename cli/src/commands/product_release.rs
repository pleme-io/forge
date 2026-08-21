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
use crate::infrastructure::kubectl::kubectl_command_async;
use crate::repo::get_tool_path;

/// Run a forge subcommand by re-invoking the current binary.
pub(crate) async fn run_forge_subcommand(args: &[&str]) -> Result<()> {
    let exe = std::env::current_exe().context("Failed to get current executable path")?;
    println!("   {} forge {}", ">>".dimmed(), args.join(" ").dimmed());

    let mut cmd = Command::new(exe);
    cmd.args(args);
    crate::retry::run_inherited_status(cmd, &format!("forge {}", args.join(" "))).await
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

    let nix_bin = get_tool_path("NIX_BIN", "nix");
    let mut cmd = Command::new(&nix_bin);
    cmd.args(args);
    crate::retry::run_inherited_status(cmd, &format!("nix run {}", app)).await
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
    let mut cmd = kubectl_command_async();
    cmd.args([
        "rollout",
        "status",
        &format!("deployment/{}", deployment),
        "-n",
        namespace,
        &format!("--timeout={}", timeout_str),
    ]);
    crate::retry::run_inherited_status(
        cmd,
        &format!(
            "kubectl rollout status deployment/{} -n {} --timeout={}",
            deployment, namespace, timeout_str
        ),
    )
    .await?;

    // Verify at least one pod is Running
    let output = kubectl_command_async()
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
///
/// Delegates to the canonical
/// [`crate::infrastructure::docker::find_first_image_id_by_name_async`]
/// primitive — sibling of `e2e.rs::check_image_exists` (sync) and
/// `push_prebuilt_image`'s inline image-id fetch. All three pre-lift
/// sites spelled the same `docker images -q <name>` + trim +
/// `is_empty` body verbatim (THEORY §VI.1 three-is-a-law); the typed
/// primitive consolidates them onto one shape.
async fn check_local_image_exists(name: &str) -> Result<bool> {
    Ok(
        crate::infrastructure::docker::find_first_image_id_by_name_async(name)
            .await
            .is_some(),
    )
}

/// Push a locally-built Docker image to the registry.
///
/// Images are built during pre-release E2E gates and loaded into Docker.
/// `deploy_tag` is the full deploy tag (e.g., "amd64-bb90b44").
/// This function tags the image and pushes to the registry,
/// avoiding a redundant Nix rebuild.
async fn push_prebuilt_image(local_name: &str, registry: &str, deploy_tag: &str) -> Result<()> {
    // Get the image ID via the canonical typed primitive — sibling of
    // `check_local_image_exists` and `e2e.rs::check_image_exists`
    // (THEORY §VI.1 three-is-a-law). The primitive's classifier picks
    // the first line when multiple IDs match (the `.lines().next()`
    // arm pre-lift commented "Use the first image ID if multiple
    // exist") and collapses every failure shape to `None` so the
    // caller's bail message names the specific image rather than
    // leaking docker's stderr.
    let image_id = crate::infrastructure::docker::find_first_image_id_by_name_async(local_name)
        .await
        .ok_or_else(|| anyhow::anyhow!("No local Docker image found for '{}'", local_name))?;

    // Compose `<repository>:<tag>` via
    // `crate::oci_manifest::image_reference` — the typed
    // compositional inverse of `image_repository_and_tag` — so this
    // build path and every other `<repository>:<tag>` composition in
    // the crate route through one canonical site (theory §VI.1
    // generation over composition: the three-times rule tripped
    // across 20+ sites, extract the primitive).
    let full_tag = crate::oci_manifest::image_reference(registry, deploy_tag);

    // Resolve the `docker` binary path via `DOCKER_BIN`, falling back
    // to `docker` on `PATH`. Hoisted once and shared across the tag +
    // push spawn sites below so a Nix-hermetic runner's substrate-
    // derived `DOCKER_BIN` lands at every docker-invocation in this
    // Phase-1 registry-push path — matching the sibling docker-family
    // sigils (`commands/local.rs::docker_bin`,
    // `commands/infra.rs::docker_bin`, `commands/e2e.rs::docker_bin`)
    // and the file's own established `get_tool_path("NIX_BIN", "nix")`
    // idiom for `run_nix_release_app` above.
    let docker = get_tool_path("DOCKER_BIN", "docker");

    // Tag with registry URL and SHA
    let mut tag_cmd = Command::new(&docker);
    tag_cmd.args(["tag", &image_id, &full_tag]);
    crate::retry::run_inherited_status(tag_cmd, &format!("docker tag {} {}", image_id, full_tag))
        .await?;

    // Push to registry
    let mut push_cmd = Command::new(&docker);
    push_cmd.args(["push", &full_tag]);
    crate::retry::run_inherited_status(push_cmd, &format!("docker push {}", full_tag)).await?;

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
/// inline sync `git`-spawn invocations — `git add` / `git commit` /
/// `git push` — each WITHOUT the `if !status.success() { bail!() }`
/// envelope. Every step silently
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
    let att_record = attestation_info.as_ref().cloned();
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
    use crate::git::git_command_sync;
    use crate::test_support::{add_bare_origin, init_repo_with_one_commit};

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
        //
        // Hold `GIT_BIN_ENV_LOCK` across the probe so a concurrently-running
        // shim test cannot mutate `GIT_BIN` between the clone and the log
        // spawns inside `clone_bare_and_read_head_subject` — closes a
        // pre-lift race hole the inline probe pair carried.
        let probe = parent.path().join("probe");
        let _guard = crate::test_support::GIT_BIN_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let subject = crate::test_support::clone_bare_and_read_head_subject(&bare, &probe);
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
    /// sync `git`-spawn sequence at `write_artifact_tags` silently
    /// swallowed.
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
        let add = git_command_sync()
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

    /// Regression-shield: every `kubectl`-spawning site in
    /// `commands/product_release.rs::run_health_check` MUST resolve
    /// the binary through
    /// [`crate::infrastructure::kubectl::kubectl_command_async`]
    /// rather than the pre-lift `Command::new("kubectl")` literal.
    /// Pre-migration two sites (rollout status + pod-phase probe)
    /// bypassed the `KUBECTL_BIN` env override the
    /// `tools::get_tool_path(tools::KUBECTL)` idiom
    /// (cli/src/tools.rs:102-105) resolves — the same class of bug
    /// the sibling `flux` / `cargo` / `doca` / free-function-`git` /
    /// `GitClient` / `commands/federation.rs` / `commands/push.rs` /
    /// `commands/rollback.rs` / `commands/helm.rs` migrations redeemed
    /// at 621f827 / f0dfa12 / d3dd199 / 685642f / d6f6bc7 / dd5a212 /
    /// 673e4be / b02d4eb / 54a9985 / 139b37a / 818ed9a / badcdf4 /
    /// 8653403 / f6be190 / 8a1958e / 81d7486 / 0d922f6 / 82376e1 /
    /// 34661e3.
    ///
    /// This test reads this module's own source via [`include_str!`]
    /// and asserts the raw `Command::new("kubectl")` string does not
    /// reappear in `run_health_check` while the delegation to
    /// `kubectl_command_async` does. A future regression that re-fuses
    /// the raw-spawn body fails here, not silently in production where
    /// a Nix-hermetic runner's `KUBECTL_BIN`-provided `kubectl` would
    /// lose to whatever `kubectl` is first on `PATH` at deploy time.
    ///
    /// The check is deliberately structural (substring on the source
    /// text) rather than behavioral — the end-to-end `KUBECTL_BIN`-
    /// routing invariant is already pinned by
    /// [`crate::infrastructure::kubectl::tests::test_kubectl_command_async_routes_through_kubectl_bin_env_var`]
    /// on the primitive itself; this shield only certifies that every
    /// `run_health_check` kubectl spawn reads through that primitive.
    #[test]
    fn test_run_health_check_routes_kubectl_through_kubectl_command_async_not_raw_command() {
        const SOURCE: &str = include_str!("product_release.rs");

        // Bound the scan to `run_health_check` — the two kubectl spawn
        // sites all live inside it. The wrapping `push_prebuilt_image`
        // still uses `Command::new(&docker)` legitimately, and the
        // tests / docstrings below reference the pre-migration string.
        let fn_marker = "pub(crate) async fn run_health_check(";
        let start = SOURCE.find(fn_marker).expect(
            "product_release.rs must contain `pub(crate) async fn run_health_check(` \
             — module invariant",
        );
        let after_fn = &SOURCE[start..];
        // Bound at the next top-level function marker in source order.
        // `check_local_image_exists` follows `run_health_check`.
        let end_relative = after_fn
            .find("\nasync fn check_local_image_exists(")
            .expect(
                "product_release.rs must contain `async fn check_local_image_exists(` \
                 after `run_health_check`",
            );
        let fn_body = &after_fn[..end_relative];

        assert!(
            !fn_body.contains("Command::new(\"kubectl\")"),
            "run_health_check() must NOT spawn `kubectl` directly — route \
             through `crate::infrastructure::kubectl::kubectl_command_async()` \
             so `KUBECTL_BIN` overrides land at the shared primitive. \
             Found the pre-migration spawn body in run_health_check()."
        );
        assert!(
            fn_body.contains("kubectl_command_async()"),
            "run_health_check() must delegate every kubectl spawn to \
             `kubectl_command_async()` — the delegation string was not \
             found in run_health_check()."
        );
    }

    /// Regression-shield: the sole `nix`-spawning site in
    /// `commands/product_release.rs::run_nix_release_app` MUST resolve
    /// the binary through
    /// [`crate::repo::get_tool_path`]`("NIX_BIN", "nix")` rather than
    /// the pre-lift `Command::new("nix")` literal. Pre-migration the
    /// Phase-1 `nix run .#release:{product}:{service}` app spawn
    /// bypassed the `NIX_BIN` env override every other nix-invocation
    /// surface in forge honors (`commands/build.rs::execute` at
    /// d8ef0d5, `commands/tool.rs::build_lock_target`,
    /// `commands/developer_tools.rs::rust_update_cargo_nix` /
    /// `rust_regenerate` / `rust_cargo_update` at 4dfb2b3,
    /// `commands/rust_service.rs`'s three sites at 7c34e57,
    /// `nix.rs::build_flake_attr_in` /
    /// `nix.rs::build_docker_image_from_dir` /
    /// `nix.rs::path_info_recursive`, and
    /// `nix_hooks.rs::NixHooks::build_and_get_path`). A Nix-hermetic
    /// runner with a store-path `nix` binary silently fell through to
    /// whatever `nix` was first on PATH at exactly the moment
    /// release-orchestration consistency matters most — the release
    /// app's tag is what deploy.yaml pins.
    ///
    /// The scan bounds to `run_nix_release_app`'s function body
    /// (from the fn header to the next top-level `async fn` in source
    /// order, `run_health_check`) so the sibling `Command::new(exe)`
    /// self-exec in `run_forge_subcommand` above and this shield's own
    /// docstring mentions of `Command::new("nix")` stay out of scope.
    /// (The `push_prebuilt_image` docker sites below have since been
    /// lifted onto `get_tool_path("DOCKER_BIN", "docker")` and pinned
    /// by their own sibling shield
    /// [`tests::test_push_prebuilt_image_routes_docker_through_docker_bin_not_raw_command`].)
    /// Mirrors the sibling scoped shield on `run_health_check` above
    /// and matches the bounded-fn-body scan discipline used across
    /// `commands/product_release.rs`.
    #[test]
    fn test_run_nix_release_app_routes_nix_through_nix_bin_not_raw_command() {
        const SOURCE: &str = include_str!("product_release.rs");

        let fn_marker = "async fn run_nix_release_app(";
        let start = SOURCE.find(fn_marker).expect(
            "product_release.rs must contain `async fn run_nix_release_app(` \
             — module invariant",
        );
        let after_fn = &SOURCE[start..];
        // Bound at the next top-level fn marker in source order.
        // `run_health_check` follows `run_nix_release_app`.
        let end_relative = after_fn
            .find("\n/// Run a kubectl health check for a deployment.")
            .expect(
                "product_release.rs must contain the `run_health_check` doc-comment \
                 after `run_nix_release_app`",
            );
        let fn_body = &after_fn[..end_relative];

        assert!(
            !fn_body.contains("Command::new(\"nix\")"),
            "run_nix_release_app() must NOT spawn `nix` directly — resolve \
             `NIX_BIN` via `crate::repo::get_tool_path(\"NIX_BIN\", \"nix\")` \
             first so the hermetic-runner contract substrate's \
             mkRuntimeToolsEnv exports land at every spawn site. Found the \
             pre-migration spawn body in run_nix_release_app()."
        );
        assert!(
            fn_body.contains("get_tool_path(\"NIX_BIN\", \"nix\")"),
            "run_nix_release_app() must resolve the nix binary via \
             `get_tool_path(\"NIX_BIN\", \"nix\")` — the canonical lookup \
             was not found in run_nix_release_app()."
        );
    }

    /// Regression-shield: every `docker`-spawning site in
    /// `commands/product_release.rs::push_prebuilt_image` MUST
    /// resolve the binary through
    /// [`crate::repo::get_tool_path`]`("DOCKER_BIN", "docker")`
    /// rather than the pre-lift `Command::new(&docker)` literal.
    /// Pre-migration the two Phase-1 registry-push spawn sites
    /// (`docker tag <image_id> <full_tag>` + `docker push <full_tag>`)
    /// each spelled the bare `"docker"` literal verbatim, ignoring
    /// `DOCKER_BIN` at every site — a Nix-hermetic runner's
    /// substrate-derived docker path lost to whatever `docker` was
    /// first on PATH at exactly the moment release-orchestration tag
    /// stability matters most (deploy.yaml pins the tag the push
    /// wrote). Mirrors the sibling `docker_bin` sigils at
    /// `commands/local.rs` (1a984dd), `commands/e2e.rs` (23241a6),
    /// `commands/infra.rs` (7f49465) and the file's own established
    /// `get_tool_path("NIX_BIN", "nix")` idiom for
    /// `run_nix_release_app` above.
    ///
    /// The scan bounds to `push_prebuilt_image`'s function body (from
    /// the fn header to the next top-level `async fn` in source order,
    /// `write_artifact_tags`) so the sibling `Command::new(exe)`
    /// self-exec in `run_forge_subcommand`, the `Command::new(&nix_bin)`
    /// spawn in `run_nix_release_app`, and the tests-mod docstring
    /// references to the pre-migration `Command::new(&docker)` string
    /// (including this shield's own) stay out of scope. Matches the
    /// bounded-fn-body scan discipline used by the sibling shields on
    /// `run_health_check` and `run_nix_release_app` above.
    #[test]
    fn test_push_prebuilt_image_routes_docker_through_docker_bin_not_raw_command() {
        const SOURCE: &str = include_str!("product_release.rs");

        let fn_marker = "async fn push_prebuilt_image(";
        let start = SOURCE.find(fn_marker).expect(
            "product_release.rs must contain `async fn push_prebuilt_image(` \
             — module invariant",
        );
        let after_fn = &SOURCE[start..];
        // Bound at the next top-level fn marker in source order.
        // `write_artifact_tags` follows `push_prebuilt_image`.
        let end_relative = after_fn.find("\nasync fn write_artifact_tags(").expect(
            "product_release.rs must contain `async fn write_artifact_tags(` \
                 after `push_prebuilt_image`",
        );
        let fn_body = &after_fn[..end_relative];

        assert!(
            !fn_body.contains("Command::new(\"docker\")"),
            "push_prebuilt_image() must NOT spawn `docker` directly — resolve \
             `DOCKER_BIN` via `crate::repo::get_tool_path(\"DOCKER_BIN\", \"docker\")` \
             first so the hermetic-runner contract substrate's \
             mkRuntimeToolsEnv exports land at every spawn site. Found the \
             pre-migration spawn body in push_prebuilt_image()."
        );
        assert!(
            fn_body.contains("get_tool_path(\"DOCKER_BIN\", \"docker\")"),
            "push_prebuilt_image() must resolve the docker binary via \
             `get_tool_path(\"DOCKER_BIN\", \"docker\")` — the canonical lookup \
             was not found in push_prebuilt_image()."
        );
    }

    /// Whole-module shield: no raw `Command::new(<bare>)` on the `git`
    /// binary may live in `commands/product_release.rs`. Every git spawn
    /// on this surface must resolve `GIT_BIN` via the canonical
    /// [`crate::git::git_command_sync`] constructor so a hermetic-runner
    /// (Nix `mkRuntimeToolsEnv`) invocation with a pinned
    /// substrate-derivation git falls through to that shim rather than
    /// whichever `git` sits first on `PATH`. Pre-lift the three test-side
    /// probe sites (`git clone` at the origin-round-trip pin in
    /// `test_commit_artifact_tags_uses_canonical_commit_subject_format`,
    /// `git log -1 --pretty=%s` at the subject-verification pin in the
    /// same test, and `git remote add origin` at the push-failure pin in
    /// `test_commit_artifact_tags_surfaces_push_failure`) each spelled
    /// the bare shape `SyncCommand::new(<bare>)` verbatim (the local
    /// `use std::process::Command as SyncCommand` alias resolves to the
    /// same shape the sibling shields forbid). The alias was removed at
    /// the top of the `tests` module and the three sites now route
    /// through `git_command_sync()` — same discipline as the sibling
    /// `test_git_spawn_routes_through_git_command_sync_not_raw_literal`
    /// shield in `commands/release_commit.rs` (8f27812).
    ///
    /// The three forbidden shapes (`std::process::Command::new(...)`,
    /// bare `Command::new(...)`, `tokio::process::Command::new(...)`) are
    /// reconstructed via `format!` from the bare string `"git"` so this
    /// shield's own source text does not false-match itself — the
    /// whole-module scan therefore covers both the top-of-file production
    /// body AND every sibling `#[cfg(test)]` block, any of which could
    /// otherwise silently re-introduce a raw literal. Also asserts the
    /// canonical `crate::git::git_command_sync` delegation form is
    /// present in the module so the sigil-body itself cannot silently
    /// drift away from the substrate-exported env-var contract.
    ///
    /// The end-to-end `GIT_BIN`-routing invariant of the underlying
    /// primitive is pinned separately by
    /// [`crate::git::tests::test_git_command_sync_routes_through_git_bin_env_var`];
    /// this shield only certifies that every git-spawning site in this
    /// module reads through `git_command_sync()`.
    #[test]
    fn test_git_spawn_routes_through_git_command_sync_not_raw_literal() {
        const SOURCE: &str = include_str!("product_release.rs");

        crate::test_support::assert_source_forbids_bare_spawn_shapes(
            SOURCE,
            "commands/product_release.rs",
            "git",
            "resolve `GIT_BIN` via `crate::git::git_command_sync()`",
        );

        crate::test_support::assert_source_delegates_via_constructor_call_code_line(
            SOURCE,
            "commands/product_release.rs",
            "git",
            "git_command_sync",
        );
    }
}

#[cfg(test)]
mod status_spawn_routing_tests {
    /// Whole-module shield: every async status-only spawn in
    /// `commands/product_release.rs` routes through
    /// [`crate::retry::run_inherited_status`], never a hand-rolled
    /// inline builder terminated by `.status().await` +
    /// `if !status.success() { bail!(…) }` that drops the exit code
    /// from the operator log line.
    ///
    /// Pre-lift five sites — `run_forge_subcommand`,
    /// `run_nix_release_app`, `run_health_check`'s rollout-status
    /// probe, and `push_prebuilt_image`'s docker-tag and docker-push
    /// spawns — spelled the eleven-line `.status().await` +
    /// `with_context(…)?` + `if !status.success() { bail!(FAIL_MSG) }`
    /// stanza with per-site ad-hoc `FAIL_MSG`s that either dropped the
    /// exit code entirely (`"docker tag failed: {} → {}"`,
    /// `"docker push failed: {}"`, `"Health check failed: …"`) or
    /// leaked a `Debug`-formatted `Option<i32>` via
    /// `status.code().unwrap_or(-1)` — the same exit-code-drop
    /// regression the sync sibling shields
    /// (`commands/{crossplane, pangea_infra, gem, infra, tool,
    /// test_ci, local, e2e, rust_service}.rs`, 6cb9442 through 5b5c765)
    /// closed on the sync frontier and the async sibling
    /// `commands/build.rs` shield (72a7adf) closed on the async
    /// `nix build` site. Post-lift each site is a
    /// `let mut cmd = Command::new(...); cmd.args(...);
    /// run_inherited_status(cmd, "...").await?;` triple and the
    /// canonical `"{op} failed (exit {code})"` envelope emerges by
    /// construction at the primitive's ONE body (THEORY.md §V.1
    /// knowable-platform construction guarantee; THEORY.md §VI.1
    /// three-times-rule redeemed by lifting to the archetype rather
    /// than re-spelling the stanza).
    ///
    /// Negative side: no `.status().await` builder terminator may
    /// reappear at any code line in the module body — a re-inlined
    /// spawn would bypass the primitive and re-drop the exit code.
    /// Positive side: `run_inherited_status(` must appear at ≥5 code
    /// lines (one per lifted site), so a regression that deleted a
    /// delegation call cannot leave the negative scan trivially
    /// satisfied by absence. Both hits route through
    /// [`crate::test_support::code_line_hits`] for anti-docstring-
    /// self-match discipline (the `.status().await` string in this
    /// shield's own docstring is excluded because
    /// [`code_line_hits`] filters `///`-prefixed lines). Scan bounds
    /// from file start to the first `\n#[cfg(test)]\nmod tests {`
    /// marker so this whole shield's own source (the string literal
    /// `".status().await"` passed to `code_line_hits`, and the
    /// assertion message that names the forbidden terminator) stays
    /// out of scope — this shield lives in a SIBLING
    /// `mod status_spawn_routing_tests { … }` opened after the
    /// primary `mod tests { … }` block precisely so the boundary the
    /// production body ends at also bounds every shield in this file
    /// away from self-match.
    #[test]
    fn test_product_release_status_spawns_route_through_run_inherited_status() {
        crate::test_support::assert_source_routes_status_only_spawns_through_run_inherited_status(
            include_str!("product_release.rs"),
            "commands/product_release.rs",
            5,
            "the five status-only spawn sites (`run_forge_subcommand`, \
             `run_nix_release_app`, `run_health_check` rollout-status, \
             `push_prebuilt_image` docker-tag, `push_prebuilt_image` \
             docker-push)",
        );
    }
}
