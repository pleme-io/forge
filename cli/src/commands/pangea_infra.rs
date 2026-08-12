//! Pangea infrastructure SDLC commands
//!
//! Provides test, plan, apply, verify, cycle, destroy, drift, and status
//! operations for Pangea-managed infrastructure. Each command follows the
//! gated workspace pattern: tests must pass before any infrastructure changes.

use anyhow::{Context, Result, bail, ensure};
use std::process::Command;
use tracing::info;

/// Resolve the `terraform` binary path via `TERRAFORM`, falling back to
/// `terraform` on `PATH`. Wired through [`crate::repo::get_tool_path`] —
/// the two-arg form, because the substrate-exported override for
/// terraform is the unadorned `TERRAFORM` var (the same var the HashiCorp
/// tooling ecosystem itself honors), not a derived `TERRAFORM_BIN`. The
/// one bridge between the pangea-infra SDLC surface and the substrate-
/// `mkRuntimeToolsEnv`-exported binary path. Mirrors the sibling
/// `cargo_bin` idiom in `commands/prerelease.rs` (cfdba0d) and the same
/// idiom every tool-invocation site in forge honors
/// (`commands/test_ci.rs` per e1677d3, `commands/developer_tools.rs`
/// per 8687093, `commands/comprehensive_release.rs` per f95d541; the
/// doc-comment idiom lives at `repo.rs:92`).
///
/// Pre-lift the four consumer sites — `plan` (`terraform plan`), `apply`
/// (`terraform apply`), `destroy` (`terraform destroy`), and `status`
/// (`terraform show`) — each spelled the bare-literal tool-name form
/// (a `Command::new` call with the tool name inline as a string)
/// verbatim, ignoring `TERRAFORM` at every one. A Nix-hermetic runner
/// with a substrate-derived terraform
/// binary silently fell through to whichever `terraform` was first on
/// PATH at these four SDLC-phase-verdict-producing sites: the plan phase
/// that decides whether the infrastructure-change diff is acceptable,
/// the apply phase that mutates the workspace, the destroy phase that
/// tears it down, and the status phase whose read-only view feeds the
/// drift-detection verdict. Same silent-PATH-fallback bug class the
/// sibling `CARGO` / `DOCKER_BIN` / `KUBECTL_BIN` / `GIT_BIN`
/// migrations closed on their respective spawn surfaces.
fn terraform_bin() -> String {
    crate::repo::get_tool_path("TERRAFORM", "terraform")
}

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

    let terraform = terraform_bin();
    let status = Command::new(&terraform)
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

    let terraform = terraform_bin();
    let status = Command::new(&terraform)
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

    let terraform = terraform_bin();
    let status = Command::new(&terraform)
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

    let terraform = terraform_bin();
    let status = Command::new(&terraform)
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

#[cfg(test)]
mod tests {
    /// Whole-module shield: no raw `terraform`-literal spawn may live in
    /// `commands/pangea_infra.rs`. Every terraform spawn must resolve
    /// `TERRAFORM` via [`super::terraform_bin`] first — the canonical
    /// env-var override every sibling tool-invocation site in forge
    /// honors (`commands/prerelease.rs` per cfdba0d,
    /// `commands/test_ci.rs` per e1677d3,
    /// `commands/developer_tools.rs` per 8687093,
    /// `commands/comprehensive_release.rs` per f95d541; the doc-comment
    /// idiom lives at `repo.rs:92`).
    ///
    /// Pre-lift the four consumer sites — `plan` (`terraform plan`),
    /// `apply` (`terraform apply`), `destroy` (`terraform destroy`),
    /// and `status` (`terraform show`) — each spelled the bare-literal
    /// tool-name form (a `Command::new` call with the tool name inline
    /// as a string) verbatim, ignoring `TERRAFORM` at every one.
    /// Pangea SDLC commands are invoked from a
    /// hermetic-runner sandbox that exports
    /// `TERRAFORM=/nix/store/...-terraform/bin/terraform`; pre-lift each
    /// SDLC-phase verdict (plan / apply / destroy / status) was
    /// attributed to whichever `terraform` the wrapper's PATH found
    /// first, not to the substrate-pinned terraform derivation the flake
    /// declared. Same silent-PATH-fallback bug class the sibling `CARGO`
    /// / `DOCKER_BIN` / `KUBECTL_BIN` / `GIT_BIN` migrations closed on
    /// their respective spawn surfaces.
    ///
    /// This shield scans the module's own source via [`include_str!`] and
    /// forbids the fused literal shape at every spawn form
    /// (`std::process::Command::new(...)`, the bare `Command::new(...)`,
    /// and the `tokio::process::Command::new(...)` long form). The
    /// forbidden shapes are reconstructed via [`format!`] so this
    /// shield's own source text does not false-match itself — the
    /// whole-module scan therefore covers both the top-of-file
    /// production body AND every sibling `#[cfg(test)]` block (any of
    /// which could otherwise silently re-introduce a raw literal — the
    /// most likely growth site as new SDLC-phase stanzas land in the
    /// pangea-infra surface). Also asserts the canonical
    /// `crate::repo::get_tool_path("TERRAFORM", "terraform")` delegation
    /// form is present so the sigil-body itself cannot silently drift
    /// away from the substrate-exported env-var contract.
    ///
    /// The end-to-end `TERRAFORM`-routing invariant of the underlying
    /// primitive is pinned separately by
    /// [`crate::tools::tests::test_get_tool_path_from_env`] and
    /// [`crate::tools::tests::test_get_tool_path_fallback`]; this
    /// shield only certifies that every terraform-spawning site in
    /// this module reads through `terraform_bin()`.
    #[test]
    fn test_terraform_spawn_routes_through_terraform_bin_not_raw_literal() {
        const SOURCE: &str = include_str!("pangea_infra.rs");

        let bare = "terraform";
        let raw_std = format!("std::process::Command::new(\"{}\")", bare);
        let raw_bare = format!("Command::new(\"{}\")", bare);
        let raw_tokio = format!("tokio::process::Command::new(\"{}\")", bare);

        assert!(
            !SOURCE.contains(&raw_std),
            "commands/pangea_infra.rs must not spawn `terraform` via the \
             bare literal — every terraform spawn must resolve `TERRAFORM` \
             via `terraform_bin()` first. A raw literal at \
             `std::process::Command::new` bypasses the hermetic-runner \
             contract substrate's mkRuntimeToolsEnv exports."
        );
        assert!(
            !SOURCE.contains(&raw_bare),
            "commands/pangea_infra.rs must not spawn `terraform` via the \
             bare literal — every terraform spawn must resolve `TERRAFORM` \
             via `terraform_bin()` first. A raw literal at `Command::new` \
             (either the top-level `use` alias or the bare form) bypasses \
             the hermetic-runner contract."
        );
        assert!(
            !SOURCE.contains(&raw_tokio),
            "commands/pangea_infra.rs must not spawn `terraform` via the \
             bare literal — every terraform spawn must resolve `TERRAFORM` \
             via `terraform_bin()` first. A raw literal at \
             `tokio::process::Command::new` bypasses the hermetic-runner \
             contract."
        );
        assert!(
            SOURCE.contains("fn terraform_bin()"),
            "commands/pangea_infra.rs must define `terraform_bin()` — the \
             sigil function that resolves the `TERRAFORM` override for \
             every terraform spawn."
        );
        assert!(
            SOURCE.contains("crate::repo::get_tool_path(\"TERRAFORM\", \"terraform\")"),
            "`terraform_bin()` must delegate to \
             `crate::repo::get_tool_path(\"TERRAFORM\", \"terraform\")` — \
             the canonical lookup was not found in the module."
        );
    }
}
