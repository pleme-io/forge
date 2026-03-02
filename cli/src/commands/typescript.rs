//! TypeScript project commands
//!
//! Replaces typescript-tool.nix::mkTypescriptRegenApp.

use anyhow::{Context, Result, bail};
use std::path::Path;
use std::process::Command;
use tracing::info;

/// Regenerate pleme-linker lockfiles for TypeScript projects.
pub fn regenerate(projects: &[String]) -> Result<()> {
    if projects.is_empty() {
        bail!("At least one --project is required");
    }

    for project in projects {
        let dir = Path::new(project);
        if !dir.exists() {
            bail!("Project directory not found: {}", project);
        }

        info!("Regenerating lockfile for {}...", project);

        let status = Command::new("pleme-linker")
            .args(["resolve", "--project", project])
            .status()
            .with_context(|| format!("Failed to run pleme-linker resolve for {}", project))?;

        if !status.success() {
            bail!("pleme-linker resolve failed for {}", project);
        }

        info!("  Done: {}", project);
    }

    info!("All {} project(s) regenerated", projects.len());
    Ok(())
}
