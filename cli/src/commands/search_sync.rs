//! Search service GitOps sync command
//!
//! Runs `novasearchctl sync` to apply index and lifecycle policy configurations
//! to the search service after K8s deployment rollout completes.
//!
//! This is a special case post-deploy hook for the search service that manages
//! its own GitOps reconciliation for search resources (indexes, policies).

use anyhow::{bail, Context, Result};
use colored::Colorize;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;

use crate::config::{DeployConfig, NovaSearchConfig};
use crate::infrastructure::kubectl::kubectl_command_async;

/// Run search service GitOps sync using novasearchctl
///
/// This function is called after K8s deployment rollout to sync index/policy
/// configurations to the running search service instance.
pub async fn run_novasearch_sync(
    service_dir: &Path,
    namespace: &str,
    deploy_config: &DeployConfig,
) -> Result<()> {
    let novasearch_config = &deploy_config.service.novasearch;

    if !novasearch_config.enabled {
        println!("ℹ️  Search sync is disabled, skipping");
        return Ok(());
    }

    println!("🔄 Running search service GitOps sync...");

    // Build config path
    let config_path = service_dir.join(&novasearch_config.config_path);
    if !config_path.exists() {
        bail!(
            "Search config directory not found: {}\n\
             Expected to find kustomization.yaml and index/policy YAML files.",
            config_path.display()
        );
    }

    // Check for novasearchctl availability
    // First try nix run, then fall back to direct binary
    let novasearchctl_available = check_novasearchctl_available().await;

    if !novasearchctl_available {
        println!("⚠️  novasearchctl not found in PATH, using kubectl exec fallback");
        return run_sync_via_kubectl(&config_path, namespace, novasearch_config).await;
    }

    // Run novasearchctl sync directly
    run_sync_direct(&config_path, novasearch_config).await
}

/// Check if novasearchctl is available
async fn check_novasearchctl_available() -> bool {
    Command::new("which")
        .arg("novasearchctl")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Run sync using novasearchctl directly
async fn run_sync_direct(config_path: &Path, config: &NovaSearchConfig) -> Result<()> {
    let mut cmd = Command::new("novasearchctl");
    cmd.arg("--server").arg(&config.api_url);
    cmd.arg("sync");
    cmd.arg("--source").arg(config_path);

    if config.dry_run {
        cmd.arg("--dry-run");
    }

    if config.prune {
        cmd.arg("--prune");
    }

    println!(
        "  {} novasearchctl --server {} sync --source {}{}{}",
        "→".cyan(),
        config.api_url,
        config_path.display(),
        if config.dry_run { " --dry-run" } else { "" },
        if config.prune { " --prune" } else { "" },
    );

    let timeout_duration = Duration::from_secs(config.timeout_secs);

    let result = timeout(
        timeout_duration,
        crate::retry::run_inherited_status(cmd, "novasearchctl sync"),
    )
    .await;

    match result {
        Ok(Ok(())) => {
            println!("  {} Search sync completed successfully", "✓".green());
            Ok(())
        }
        Ok(Err(e)) => Err(e),
        Err(_) => {
            bail!(
                "Search sync timed out after {} seconds",
                config.timeout_secs
            );
        }
    }
}

/// Run sync via kubectl exec (fallback when novasearchctl not available locally)
///
/// This copies the config to a pod and runs novasearchctl inside the search service pod.
async fn run_sync_via_kubectl(
    config_path: &Path,
    namespace: &str,
    config: &NovaSearchConfig,
) -> Result<()> {
    println!(
        "  {} Using kubectl to run sync inside search service pod",
        "→".cyan()
    );

    // Find the search service pod
    let pod_name =
        crate::infrastructure::kubectl::find_first_pod_name_async(namespace, "app=novasearch")
            .await
            .with_context(|| {
                format!(
                    "Failed to find search service pod in namespace {}",
                    namespace
                )
            })?;

    println!("  {} Found pod: {}", "→".cyan(), pod_name);

    // Copy config files to the pod
    let remote_config_path = "/tmp/search-sync-config";

    let cp_status = kubectl_command_async()
        .args([
            "cp",
            &config_path.to_string_lossy(),
            &format!("{}/{}:{}", namespace, pod_name, remote_config_path),
        ])
        .status()
        .await
        .context("Failed to copy config to pod")?;

    if !cp_status.success() {
        bail!("Failed to copy config directory to pod");
    }

    // Run novasearchctl sync inside the pod
    let mut exec_args = vec![
        "exec",
        "-n",
        namespace,
        &pod_name,
        "--",
        "novasearchctl",
        "--server",
        "http://localhost:8081",
        "sync",
        "--source",
        remote_config_path,
    ];

    if config.dry_run {
        exec_args.push("--dry-run");
    }

    if config.prune {
        exec_args.push("--prune");
    }

    println!(
        "  {} kubectl exec -n {} {} -- novasearchctl sync --source {}",
        "→".cyan(),
        namespace,
        pod_name,
        remote_config_path,
    );

    let timeout_duration = Duration::from_secs(config.timeout_secs);

    let mut exec_cmd = kubectl_command_async();
    exec_cmd.args(&exec_args);

    let result = timeout(
        timeout_duration,
        crate::retry::run_inherited_status(exec_cmd, "kubectl exec novasearchctl sync"),
    )
    .await;

    // Clean up: remove config from pod
    let _ = kubectl_command_async()
        .args([
            "exec",
            "-n",
            namespace,
            &pod_name,
            "--",
            "rm",
            "-rf",
            remote_config_path,
        ])
        .status()
        .await;

    match result {
        Ok(Ok(())) => {
            println!("  {} Search sync completed successfully", "✓".green());
            Ok(())
        }
        Ok(Err(e)) => Err(e),
        Err(_) => {
            bail!(
                "Search sync timed out after {} seconds",
                config.timeout_secs
            );
        }
    }
}

/// Check if search sync should run based on deploy config
pub fn should_run_novasearch_sync(deploy_config: &DeployConfig) -> bool {
    deploy_config.service.novasearch.enabled
}

#[cfg(test)]
mod tests {
    /// Whole-module shield: no raw `Command::new`-with-bare-`kubectl`-
    /// literal may live in `commands/search_sync.rs`. Every `kubectl`
    /// spawn on this module's `run_sync_via_kubectl` fallback path
    /// (the `kubectl cp` config-copy, the `kubectl exec … --
    /// novasearchctl sync` invocation, and the `kubectl exec … --
    /// rm -rf` cleanup) must resolve through
    /// [`crate::infrastructure::kubectl::kubectl_command_async`] —
    /// the async constructor that reads the `KUBECTL_BIN` env
    /// override via [`crate::tools::get_tool_path`] on the canonical
    /// `tools::KUBECTL` name.
    ///
    /// Pre-lift each of the three `kubectl` spawn sites spelled the
    /// bare `"kubectl"` literal verbatim, ignoring `KUBECTL_BIN` at
    /// the site. A Nix-hermetic runner's substrate-derived `kubectl`
    /// path was lost to whatever `kubectl` sat first on PATH — the
    /// same silent-PATH-fallback bug class the sibling consumer
    /// sites in forge already avoid (`commands/rollout.rs::execute`
    /// at c5fcf83, `commands/migrations.rs` at 946e573,
    /// `commands/status.rs` at c2760df, `commands/flux.rs` at
    /// f8da719, `commands/federation_tests.rs` at 9a409e8,
    /// `commands/supergraph_verification.rs` at 65283fb,
    /// `services/migration_service.rs` at 5986a10,
    /// `commands/github_runner_ci.rs` at 5566415,
    /// `commands/product_release.rs::run_health_check` at 5bb7cff).
    ///
    /// This shield scans the module's own source via [`include_str!`]
    /// and forbids the fused literal shape. The forbidden shape is
    /// reconstructed via [`format!`] so this shield's own source text
    /// does not false-match itself — the whole-module scan therefore
    /// covers both the top-of-file production body AND every sibling
    /// `#[cfg(test)]` block (any of which could otherwise silently
    /// re-introduce a raw literal). The end-to-end
    /// `KUBECTL_BIN`-routing invariant of the underlying primitive
    /// is pinned separately by
    /// [`crate::infrastructure::kubectl::tests::test_kubectl_command_async_routes_through_kubectl_bin_env_var`];
    /// this shield only certifies that every `kubectl`-spawning site
    /// in this module resolves through the constructor first.
    #[test]
    fn test_kubectl_spawn_routes_through_kubectl_command_async_not_raw_literal() {
        const SOURCE: &str = include_str!("search_sync.rs");

        let bare = "kubectl";
        let raw_command = format!("Command::new(\"{}\")", bare);

        assert!(
            !SOURCE.contains(&raw_command),
            "commands/search_sync.rs must not spawn `kubectl` via the \
             bare literal — every `kubectl` spawn must resolve the \
             substrate-exported `KUBECTL_BIN` env override via \
             `kubectl_command_async` first. A raw literal at \
             `Command::new` bypasses the hermetic-runner contract \
             substrate's mkRuntimeToolsEnv exports."
        );
        assert!(
            SOURCE.contains("kubectl_command_async()"),
            "commands/search_sync.rs must resolve the `kubectl` binary \
             via the canonical `kubectl_command_async()` constructor \
             — the required form was not found in the module."
        );
    }
}
