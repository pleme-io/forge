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

    let result = timeout(timeout_duration, async {
        let output = cmd
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .await
            .context("Failed to execute novasearchctl")?;

        if !output.success() {
            bail!(
                "novasearchctl sync failed with exit code: {:?}",
                output.code()
            );
        }

        Ok(())
    })
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
    let pod_output = Command::new("kubectl")
        .args([
            "get",
            "pods",
            "-n",
            namespace,
            "-l",
            "app=novasearch",
            "-o",
            "jsonpath={.items[0].metadata.name}",
        ])
        .output()
        .await
        .context("Failed to get search service pod name")?;

    if !pod_output.status.success() {
        bail!("Failed to find search service pod in namespace {}", namespace);
    }

    let pod_name = String::from_utf8_lossy(&pod_output.stdout)
        .trim()
        .to_string();
    if pod_name.is_empty() {
        bail!("No search service pod found in namespace {}", namespace);
    }

    println!("  {} Found pod: {}", "→".cyan(), pod_name);

    // Copy config files to the pod
    let remote_config_path = "/tmp/search-sync-config";

    let cp_status = Command::new("kubectl")
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

    let result = timeout(timeout_duration, async {
        let output = Command::new("kubectl")
            .args(&exec_args)
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .await
            .context("Failed to execute kubectl exec")?;

        if !output.success() {
            bail!("kubectl exec novasearchctl sync failed");
        }

        Ok(())
    })
    .await;

    // Clean up: remove config from pod
    let _ = Command::new("kubectl")
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
