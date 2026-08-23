//! Product rollback command.
//!
//! Reads `previous_tag` from each service's deploy.yaml and redeploys
//! that image to the target environment. No image build — deploy-only
//! using the stored previous tag.
//!
//! After rollback, swaps current↔previous tags in deploy.yaml so a
//! subsequent rollback becomes a "roll forward" to the original version.

use anyhow::{bail, Context, Result};
use colored::Colorize;
use std::io::Write;

use crate::config::DeployConfig;
use crate::infrastructure::registry::{extract_organization, RegistryClient};

use super::product_release::{run_forge_subcommand, run_health_check};

/// A rollback plan entry for a single service.
struct RollbackEntry {
    name: String,
    path: String,
    current_tag: String,
    previous_tag: String,
    registry_url: String,
}

/// Execute the rollback command.
pub async fn execute(
    product: String,
    repo_root: String,
    env: Option<String>,
    skip_health_check: bool,
    force: bool,
) -> Result<()> {
    let product_config = DeployConfig::load_product_release_config(&product, &repo_root)?;

    if product_config.services.is_empty() {
        bail!("No services configured in deploy.yaml release.services section.");
    }

    let target_env = env.as_deref().unwrap_or("staging");

    // ─── Build rollback plan ────────────────────────────────────────────────
    let mut entries = Vec::new();

    for svc in &product_config.services {
        let svc_release =
            DeployConfig::load_service_release_config(&product, &svc.path, &repo_root)?;

        let artifact = svc_release.artifact.as_ref().with_context(|| {
            format!(
                "No artifact info for {} — nothing to roll back.\n  \
                 Check deploy/{}.artifact.json or release.artifact in deploy.yaml.",
                svc.name, svc.name
            )
        })?;

        if artifact.previous_tag.is_empty() {
            bail!(
                "No previous_tag for {} — cannot rollback.\n  \
                 A successful release must run first to populate previous_tag.",
                svc.name
            );
        }

        let registry_url =
            DeployConfig::load_service_registry_url(&product, &svc.path, &repo_root)?;

        entries.push(RollbackEntry {
            name: svc.name.clone(),
            path: svc.path.clone(),
            current_tag: artifact.tag.clone(),
            previous_tag: artifact.previous_tag.clone(),
            registry_url,
        });
    }

    // ─── Verify rollback images exist in registry ─────────────────────────
    println!("{}", "Verifying rollback images in registry...".bold());

    for entry in &entries {
        let org = extract_organization(&entry.registry_url)
            .context("Failed to extract organization from registry URL")?;
        let client = RegistryClient::discover(None, org)
            .context("Failed to discover registry credentials for image verification")?;

        let rollback_tag = format!("amd64-{}", entry.previous_tag);
        match client
            .verify_tag_exists(&entry.registry_url, &rollback_tag)
            .await
        {
            Ok(digest) => {
                println!(
                    "   {} {} ({})",
                    "OK".green(),
                    crate::oci_manifest::image_reference(&entry.registry_url, &rollback_tag)
                        .dimmed(),
                    &digest[..std::cmp::min(19, digest.len())]
                );
            }
            Err(_) => {
                bail!(
                    "Rollback image does not exist: {}:{}\n  \
                     The previous_tag '{}' for {} points to a non-existent image.\n  \
                     This can happen when the release pipeline had a SHA mismatch.\n  \
                     Fix: manually set previous_tag in deploy/{}.artifact.json to a known-good tag.",
                    entry.registry_url,
                    rollback_tag,
                    entry.previous_tag,
                    entry.name,
                    entry.name
                );
            }
        }
    }
    println!();

    // ─── Show rollback plan ─────────────────────────────────────────────────
    println!(
        "{} {} Rollback {}",
        ">>".bold(),
        product.cyan().bold(),
        format!("(env: {})", target_env).dimmed()
    );
    println!("{}", "=".repeat(60));
    println!();
    println!("{}", "Rollback Plan:".bold());

    for entry in &entries {
        println!(
            "   {} {} → {}",
            entry.name.cyan(),
            entry.current_tag.red(),
            entry.previous_tag.green()
        );
    }
    println!();

    // ─── Confirm ────────────────────────────────────────────────────────────
    if !force {
        print!("Proceed with rollback? [Y/n] ");
        std::io::stdout().flush()?;

        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let answer = input.trim().to_lowercase();

        if !answer.is_empty() && answer != "y" && answer != "yes" {
            println!("{}", "Rollback cancelled.".yellow());
            return Ok(());
        }
    }

    // ─── Resolve target environments ────────────────────────────────────────
    let first_svc = &product_config.services[0];
    let first_release =
        DeployConfig::load_service_release_config(&product, &first_svc.path, &repo_root)?;

    let environments: Vec<String> = if env.is_some() {
        first_release.get_environments(target_env)
    } else {
        first_release.get_environments("staging")
    };

    if environments.is_empty() {
        bail!(
            "No active environments for '{}'. Check active_environments in deploy.yaml.",
            target_env
        );
    }

    // ─── Migration awareness ─────────────────────────────────────────────────
    // Warn about forward-only migrations (shinka never runs down())
    {
        let product_dir =
            crate::config::resolve_product_dir(std::path::Path::new(&repo_root), &product);
        let seaorm_dir = product_dir.join("services/rust/migration/src");
        let deploy_yaml_path = product_dir.join("deploy/backend.yaml");

        // Load seaorm_check_after from deploy.yaml
        let seaorm_check_after = if let Ok(content) = std::fs::read_to_string(&deploy_yaml_path) {
            if let Ok(value) = serde_yaml::from_str::<serde_yaml::Value>(&content) {
                value
                    .get("prerelease")
                    .and_then(|p| p.get("migrations"))
                    .and_then(|m| m.get("seaorm_check_after"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            } else {
                None
            }
        } else {
            None
        };

        if let Ok(rollback_result) = super::migration_validation::validate_rollback_compatibility(
            &seaorm_dir,
            &crate::config::MigrationGatesConfig {
                seaorm_check_after,
                ..Default::default()
            },
        )
        .await
        {
            if rollback_result.migration_count > 0 {
                println!(
                    "{}",
                    format!(
                        "Note: {} SeaORM migration(s) are applied in the database.",
                        rollback_result.migration_count
                    )
                    .yellow()
                );
                println!(
                    "{}",
                    "   Rollback deploys older code against the current schema.".yellow()
                );
                println!(
                    "{}",
                    "   Migrations are forward-only (shinka does not run down()).".yellow()
                );

                for warning in &rollback_result.warnings {
                    println!("   {} {}", "Warning:".red().bold(), warning.yellow());
                }
                println!();
            }
        }
    }

    // ─── Deploy previous tags ───────────────────────────────────────────────
    println!("{}", "Deploying previous tags...".bold());

    for env_name in &environments {
        println!("   {} {}", ">>".dimmed(), env_name.cyan().bold());

        for (i, entry) in entries.iter().enumerate() {
            let product_dir =
                crate::config::resolve_product_dir(std::path::Path::new(&repo_root), &product);
            let service_dir = product_dir.join(&entry.path).to_string_lossy().to_string();

            run_forge_subcommand(&[
                "orchestrate-release",
                "--service",
                &entry.name,
                "--service-dir",
                &service_dir,
                "--repo-root",
                &repo_root,
                "--registry",
                &entry.registry_url,
                "--deploy-only",
                "--image-tag",
                &entry.previous_tag,
                "--single-environment",
                "--environment",
                env_name,
            ])
            .await?;

            println!(
                "   {} {} rolled back to {} in {}",
                "OK".green(),
                entry.name.cyan(),
                entry.previous_tag.yellow(),
                env_name.dimmed()
            );

            // Health check (unless skipped or last service)
            if !skip_health_check {
                if let Some(svc_config) = product_config
                    .services
                    .iter()
                    .find(|s| s.name == entry.name)
                {
                    if let Some(hc) = &svc_config.health_check {
                        if i < entries.len() - 1 {
                            let namespace = format!("{}-{}", product, env_name);
                            run_health_check(&hc.deployment, &namespace, hc.timeout_secs).await?;
                        }
                    }
                }
            }
        }
    }
    println!();

    // ─── Swap tags in artifact.json ────────────────────────────────────────
    println!("{}", "Swapping tags in artifact.json...".bold());

    let now = chrono::Utc::now().to_rfc3339();
    let mut modified_files = Vec::new();

    for entry in &entries {
        let product_dir =
            crate::config::resolve_product_dir(std::path::Path::new(&repo_root), &product);

        let json_path = crate::config::resolve_artifact_json_path(&product_dir, &entry.name);

        // Swap: previous_tag becomes tag, current_tag becomes previous_tag
        let artifact = crate::config::ArtifactInfo {
            tag: entry.previous_tag.clone(),
            built_at: now.clone(),
            previous_tag: entry.current_tag.clone(),
            attestation: None, // Attestation is not preserved during rollback
        };

        let json =
            serde_json::to_string_pretty(&artifact).context("Failed to serialize artifact info")?;
        std::fs::write(&json_path, format!("{}\n", json))
            .with_context(|| format!("Failed to write {}", json_path.display()))?;

        modified_files.push(json_path.to_string_lossy().to_string());
        println!(
            "   {} Swapped tags in deploy/{}.artifact.json",
            "OK".green(),
            entry.name
        );
    }

    // ─── Git commit + push ──────────────────────────────────────────────────
    //
    // Every git spawn in this block resolves the binary through
    // `crate::git::git_command_async()` so a Nix-hermetic runner's
    // `GIT_BIN` override wins over ambient `PATH` — same discipline the
    // sibling `commands/push.rs::update_kustomization` /
    // `commands/federation.rs` / `commands/codegen_validation.rs`
    // git-mutation sites honor, redeemed at f6be190 / 8653403 / 81d7486
    // and enforced by the source-scan shield at the bottom of this
    // module.
    //
    // Failure-dispatch shape mirrors the sibling `update_kustomization`
    // lift (f6be190): `git add` and `git push` bail on non-zero exit
    // via `crate::retry::run_inherited_status` — the pre-lift bare
    // `.status().await.context(...)?` shape here silently accepted a
    // non-zero exit because `?` only propagated exec failure, so a
    // denied `push` (auth, branch protection, conflict) let the caller
    // fall through to the "Rollback tags committed and pushed" success
    // print against an unpushed branch. `git commit` retains the bare
    // `.status()` + warn-on-non-zero shape because the sibling
    // update-kustomization commit path documents the same idempotent
    // "commit with nothing to commit returns non-zero" no-op.
    if !modified_files.is_empty() {
        for file in &modified_files {
            crate::git::git_run_inherited_status(["add", file.as_str()], "git add")
                .await
                .context("Failed to stage rollback artifact.json")?;
        }

        let rolled_back_to: Vec<String> = entries
            .iter()
            .map(|e| format!("{}:{}", e.name, e.previous_tag))
            .collect();

        let commit_msg = format!(
            "chore: rollback {} ({})",
            product,
            rolled_back_to.join(", ")
        );
        let commit_status = crate::git::git_command_async()
            .args(["commit", "-m", &commit_msg])
            .status()
            .await
            .context("Failed to commit rollback tags")?;

        if !commit_status.success() {
            eprintln!(
                "{}",
                "Warning: git commit returned non-zero (may be no changes)".yellow()
            );
        }

        crate::git::git_run_inherited_status(["push", "origin", "main"], "git push")
            .await
            .context("Failed to push rollback tags")?;

        println!("   {} Rollback tags committed and pushed", "OK".green());
    }

    // ─── Done ───────────────────────────────────────────────────────────────
    println!();
    println!("{}", "=".repeat(60).bright_green());
    println!(
        "{} {} {}",
        "ROLLBACK COMPLETE".green().bold(),
        product.cyan().bold(),
        format!("({})", target_env).dimmed()
    );
    println!("{}", "=".repeat(60).bright_green());

    Ok(())
}

#[cfg(test)]
mod tests {
    /// Regression-shield: every `git`-spawning site in
    /// `commands/rollback.rs::execute` MUST resolve the binary through
    /// [`crate::git::git_command_async`] rather than the pre-lift
    /// `Command::new("git")` literal. Pre-migration three sites
    /// (add / commit / push at lines 326 / 339 / 345) bypassed the
    /// `GIT_BIN` env override the `tools::get_tool_path(tools::GIT)`
    /// idiom (cli/src/tools.rs:102-105) resolves — the same class of
    /// bug the sibling `flux` / `cargo` / `doca` / free-function-`git` /
    /// `GitClient` / `commands/federation.rs` / `commands/push.rs` /
    /// `commands/codegen_validation.rs` migrations redeemed at
    /// 621f827 / f0dfa12 / d3dd199 / 685642f / d6f6bc7 / dd5a212 /
    /// 673e4be / b02d4eb / 54a9985 / 139b37a / 818ed9a / badcdf4 /
    /// 8653403 / f6be190 / 81d7486.
    ///
    /// This test reads this module's own source via [`include_str!`]
    /// and asserts the raw `Command::new("git")` string does not
    /// reappear in `execute` while the delegation to
    /// `git_command_async` does. A future regression that re-fuses the
    /// raw-spawn body fails here, not silently in production where a
    /// Nix-hermetic runner's `GIT_BIN`-provided `git` would lose to
    /// whatever `git` is first on `PATH` at rollback-commit-and-push
    /// time.
    ///
    /// The check is deliberately structural (substring on the source
    /// text) rather than behavioral — the end-to-end `GIT_BIN`-routing
    /// invariant is already pinned by
    /// [`crate::git::tests::test_git_command_async_routes_through_git_bin_env_var`]
    /// on the primitive itself; this shield only certifies that every
    /// `rollback::execute` git spawn reads through that primitive.
    /// Mirrors the sibling shields on `commands/push.rs` /
    /// `commands/codegen_validation.rs`.
    #[test]
    fn test_execute_routes_git_through_git_command_async_not_raw_command() {
        const SOURCE: &str = include_str!("rollback.rs");

        // Bound the scan to `execute` — the three git spawn sites all
        // live inside it. The `#[cfg(test)] mod tests` module below
        // references the pre-migration string legitimately in this
        // docstring; the bound stops before it.
        // Bound the fn body between `execute`'s header and the
        // `#[cfg(test)]` marker, which follows `execute` in source
        // order and contains a legitimate mention of the pre-migration
        // literal in this docstring.
        let fn_body = crate::test_support::fn_body_slice_between_markers(
            SOURCE,
            "rollback.rs",
            "pub async fn execute(",
            "\n#[cfg(test)]",
        );

        assert!(
            !fn_body.contains("Command::new(\"git\")"),
            "execute() must NOT spawn `git` directly — route through \
             `crate::git::git_run_inherited_status(&[...], \"git …\")` \
             (the async fusion primitive) or `crate::git::git_command_async()` \
             so `GIT_BIN` overrides land at the shared primitive. Found the \
             pre-migration spawn body in execute()."
        );
        assert!(
            fn_body.contains("crate::git::git_run_inherited_status(")
                || fn_body.contains("crate::git::git_command_async()"),
            "execute() must delegate every git spawn to \
             `crate::git::git_run_inherited_status(&[...], \"git …\")` \
             (the async fusion primitive, which internally routes through \
             `git_command_async()` + `run_inherited_status`) OR to \
             `crate::git::git_command_async()` for the documented \
             idempotent-no-op bare-`.status()` `git commit` carve-out — \
             neither delegation string was found in execute()."
        );
        assert!(
            fn_body.contains("crate::git::git_run_inherited_status(")
                || fn_body.contains("crate::retry::run_inherited_status"),
            "execute() must dispatch `git add` / `git push` through \
             the structural `(op, exit_code)`-envelope surface — either \
             the async fusion primitive \
             `crate::git::git_run_inherited_status(&[...], \"git …\")` \
             (which internally delegates through \
             `crate::retry::run_inherited_status`) or directly through \
             `crate::retry::run_inherited_status`. Neither delegation \
             string was found in execute()."
        );
    }
}
