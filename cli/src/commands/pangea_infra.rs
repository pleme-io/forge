//! Pangea infrastructure SDLC commands
//!
//! Provides test, plan, apply, verify, cycle, destroy, drift, and status
//! operations for Pangea-managed infrastructure. Each command follows the
//! gated workspace pattern: tests must pass before any infrastructure changes.

use anyhow::{Context, Result, bail, ensure};
use std::process::Command;
use tracing::info;

/// Run RSpec synthesis tests for a pangea architecture.
///
/// Executes `bundle exec rspec` targeting the architecture spec and
/// its corresponding security spec (if it exists).
pub fn test(working_dir: &str, architecture: &str) -> Result<()> {
    info!("Running RSpec synthesis tests for architecture: {}", architecture);

    let spec_file = format!("spec/architectures/{}_spec.rb", architecture);
    let security_spec = format!("spec/security/{}_security_spec.rb", architecture);

    let mut args = vec![
        "exec".to_string(),
        "rspec".to_string(),
        spec_file,
        "--format".to_string(),
        "documentation".to_string(),
    ];

    // Add security spec if it exists
    let security_path = std::path::Path::new(working_dir).join(&security_spec);
    if security_path.exists() {
        args.insert(2, security_spec);
    }

    let status = Command::new("bundle")
        .args(&args)
        .current_dir(working_dir)
        .status()
        .context("Failed to run bundle exec rspec")?;

    ensure!(status.success(), "RSpec synthesis tests failed for architecture: {}", architecture);

    info!("All synthesis tests passed for: {}", architecture);
    Ok(())
}

/// Run terraform plan for a pangea workspace.
pub fn plan(workspace: &str, working_dir: &str) -> Result<()> {
    info!("Running terraform plan for workspace: {}", workspace);

    let status = Command::new("terraform")
        .args(["plan", "-input=false"])
        .current_dir(working_dir)
        .env("TF_WORKSPACE", workspace)
        .status()
        .context("Failed to run terraform plan")?;

    ensure!(status.success(), "Terraform plan failed for workspace: {}", workspace);

    info!("Plan complete for workspace: {}", workspace);
    Ok(())
}

/// Apply terraform changes for a pangea workspace.
pub fn apply(workspace: &str, working_dir: &str, auto_approve: bool) -> Result<()> {
    if !auto_approve {
        confirm(&format!("Apply infrastructure changes to workspace '{}'?", workspace))?;
    }

    info!("Applying terraform changes for workspace: {}", workspace);

    let mut args = vec!["apply", "-input=false"];
    if auto_approve {
        args.push("-auto-approve");
    }

    let status = Command::new("terraform")
        .args(&args)
        .current_dir(working_dir)
        .env("TF_WORKSPACE", workspace)
        .status()
        .context("Failed to run terraform apply")?;

    ensure!(status.success(), "Terraform apply failed for workspace: {}", workspace);

    info!("Apply complete for workspace: {}", workspace);
    Ok(())
}

/// Run InSpec verification against live infrastructure.
pub fn verify(workspace: &str, inspec_profile: &str, target: &str) -> Result<()> {
    info!("Running InSpec verification for workspace: {}", workspace);

    let status = Command::new("inspec")
        .args([
            "exec",
            inspec_profile,
            "-t",
            target,
            "--reporter",
            "cli",
        ])
        .status()
        .context("Failed to run inspec exec")?;

    ensure!(status.success(), "InSpec verification failed for workspace: {}", workspace);

    info!("InSpec verification passed for workspace: {}", workspace);
    Ok(())
}

/// Full lifecycle: test → plan → confirm → apply → verify.
pub fn cycle(
    workspace: &str,
    working_dir: &str,
    architecture: &str,
    inspec_profile: Option<&str>,
    inspec_target: &str,
) -> Result<()> {
    info!("Starting full infrastructure cycle for workspace: {}", workspace);

    // Phase 1: Test
    info!("Phase 1/5: Running synthesis tests...");
    test(working_dir, architecture)?;

    // Phase 2: Plan
    info!("Phase 2/5: Running terraform plan...");
    plan(workspace, working_dir)?;

    // Phase 3: Confirm
    info!("Phase 3/5: Awaiting confirmation...");
    confirm(&format!("Apply changes to workspace '{}'?", workspace))?;

    // Phase 4: Apply
    info!("Phase 4/5: Applying changes...");
    apply(workspace, working_dir, true)?;

    // Phase 5: Verify (optional)
    if let Some(profile) = inspec_profile {
        info!("Phase 5/5: Running InSpec verification...");
        verify(workspace, profile, inspec_target)?;
    } else {
        info!("Phase 5/5: Skipped (no InSpec profile provided)");
    }

    info!("Infrastructure cycle complete for workspace: {}", workspace);
    Ok(())
}

/// Destroy infrastructure for a pangea workspace.
pub fn destroy(workspace: &str, working_dir: &str, auto_approve: bool) -> Result<()> {
    if !auto_approve {
        confirm(&format!(
            "DESTROY all infrastructure in workspace '{}'? This cannot be undone.",
            workspace
        ))?;
    }

    info!("Destroying infrastructure for workspace: {}", workspace);

    let mut args = vec!["destroy", "-input=false"];
    if auto_approve {
        args.push("-auto-approve");
    }

    let status = Command::new("terraform")
        .args(&args)
        .current_dir(working_dir)
        .env("TF_WORKSPACE", workspace)
        .status()
        .context("Failed to run terraform destroy")?;

    ensure!(status.success(), "Terraform destroy failed for workspace: {}", workspace);

    info!("Destroy complete for workspace: {}", workspace);
    Ok(())
}

/// Detect drift: test → plan (no apply).
pub fn drift(workspace: &str, working_dir: &str, architecture: &str) -> Result<()> {
    info!("Detecting drift for workspace: {}", workspace);

    // Phase 1: Test (ensure architecture is still valid)
    info!("Phase 1/2: Running synthesis tests...");
    test(working_dir, architecture)?;

    // Phase 2: Plan (detect drift)
    info!("Phase 2/2: Running terraform plan to detect drift...");
    plan(workspace, working_dir)?;

    info!("Drift detection complete for workspace: {}", workspace);
    Ok(())
}

/// Show workspace status.
pub fn status(workspace: &str, working_dir: &str) -> Result<()> {
    info!("Checking status for workspace: {}", workspace);

    let status = Command::new("terraform")
        .args(["show", "-no-color"])
        .current_dir(working_dir)
        .env("TF_WORKSPACE", workspace)
        .status()
        .context("Failed to run terraform show")?;

    if !status.success() {
        bail!("Failed to get status for workspace: {}", workspace);
    }

    Ok(())
}

// --- Helpers ---

/// Prompt user for confirmation.
fn confirm(message: &str) -> Result<()> {
    use std::io::{Write, BufRead};

    print!("{} [y/N] ", message);
    std::io::stdout().flush()?;

    let stdin = std::io::stdin();
    let mut line = String::new();
    stdin.lock().read_line(&mut line)?;

    let answer = line.trim().to_lowercase();
    if answer != "y" && answer != "yes" {
        bail!("Operation cancelled by user");
    }

    Ok(())
}
