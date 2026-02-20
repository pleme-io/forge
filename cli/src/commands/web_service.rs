//! Web service commands for frontend projects.
//!
//! These commands handle web service operations:
//! - Regenerating frontend deps.nix + Hanabi Cargo.nix
//! - Updating Hanabi dependencies and regenerating Cargo.nix
//!
//! All web projects use shared Hanabi (花火) BFF web server.
//! Frontend deps are managed by pleme-linker, Hanabi uses crate2nix.

use std::path::Path;
use std::process::Stdio;

use anyhow::{bail, Context, Result};
use colored::Colorize;
use tokio::process::Command;

/// Regenerate deps.nix for web frontend + Cargo.nix for Hanabi (shared BFF)
///
/// This command:
/// 1. Regenerates frontend deps.nix using pleme-linker regen
/// 2. Regenerates Hanabi Cargo.nix using crate2nix generate
///
/// Arguments:
/// - product: Product name (e.g., myapp)
/// - service: Service name (typically "web")
/// - repo_root: Git repository root path
pub async fn web_regenerate(product: String, service: String, repo_root: String) -> Result<()> {
    println!(
        "🔄 {} {} {}",
        "Regenerating".bold(),
        format!("{}-{}", product, service).cyan(),
        "dependencies".dimmed()
    );
    println!("{}", "=".repeat(50));
    println!();

    let repo_root_path = Path::new(&repo_root);
    let service_dir = repo_root_path
        .join("pkgs")
        .join("products")
        .join(&product)
        .join(&service);
    let hanabi_dir = repo_root_path.join("pkgs").join("platform").join("hanabi");

    // Verify paths exist
    if !service_dir.exists() {
        bail!(
            "Service directory not found: {}\n  \
             Expected structure: pkgs/products/{}/{}/",
            service_dir.display(),
            product,
            service
        );
    }

    if !hanabi_dir.exists() {
        bail!(
            "Hanabi directory not found: {}\n  \
             Expected at: pkgs/platform/hanabi/",
            hanabi_dir.display()
        );
    }

    println!("📂 Service: {}", service_dir.display());
    println!("📂 Hanabi: {}", hanabi_dir.display());
    println!();

    // Step 1: Regenerate frontend deps.nix using pleme-linker
    // pleme-linker is available in PATH from the Nix environment
    println!(
        "📦 {} {}",
        "Regenerating frontend deps.nix".bold(),
        "(pleme-linker regen)".dimmed()
    );

    let status = Command::new("pleme-linker")
        .args(&[
            "regen",
            "--project-root",
            service_dir.to_str().unwrap(),
            "--crate2nix",
            "crate2nix", // crate2nix is in PATH from Nix wrapper
        ])
        .current_dir(&repo_root)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .await
        .context("Failed to run pleme-linker regen - ensure pleme-linker is in PATH")?;

    if !status.success() {
        bail!("❌ pleme-linker regen failed");
    }
    println!("   ✅ Frontend deps.nix regenerated");
    println!();

    // Step 2: Regenerate Hanabi Cargo.nix using crate2nix
    // crate2nix is available in PATH from the Nix environment
    println!(
        "🦀 {} {}",
        "Regenerating Hanabi Cargo.nix".bold(),
        "(crate2nix generate)".dimmed()
    );

    let status = Command::new("crate2nix")
        .arg("generate")
        .current_dir(&hanabi_dir)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .await
        .context("Failed to run crate2nix generate - ensure crate2nix is in PATH")?;

    if !status.success() {
        bail!("❌ crate2nix generate failed for Hanabi");
    }
    println!("   ✅ Hanabi Cargo.nix regenerated");
    println!();

    // Success summary
    println!("{}", "━".repeat(80).bright_green());
    println!("{}", "✅ REGENERATION COMPLETE".green().bold());
    println!("{}", "━".repeat(80).bright_green());
    println!();
    println!("Generated files:");
    println!("  • {}", service_dir.join("deps.nix").display());
    println!("  • {}", hanabi_dir.join("Cargo.nix").display());
    println!();
    println!("Next steps:");
    println!("  1. Review the changes: git diff");
    println!("  2. Commit: git add -A && git commit -m 'chore: regenerate deps'");
    println!();

    Ok(())
}

/// Update Hanabi (shared BFF) dependencies and regenerate Cargo.nix
///
/// This command:
/// 1. Runs cargo update in Hanabi directory
/// 2. Regenerates Hanabi Cargo.nix using crate2nix generate
///
/// Arguments:
/// - product: Product name (e.g., myapp) - for context only
/// - service: Service name (typically "web") - for context only
/// - repo_root: Git repository root path
pub async fn web_cargo_update(product: String, service: String, repo_root: String) -> Result<()> {
    println!(
        "🔄 {} {} {}",
        "Updating Hanabi".bold(),
        "(shared BFF)".cyan(),
        format!("for {}-{}", product, service).dimmed()
    );
    println!("{}", "=".repeat(50));
    println!();

    let repo_root_path = Path::new(&repo_root);
    let hanabi_dir = repo_root_path.join("pkgs").join("platform").join("hanabi");

    // Verify path exists
    if !hanabi_dir.exists() {
        bail!(
            "Hanabi directory not found: {}\n  \
             Expected at: pkgs/platform/hanabi/",
            hanabi_dir.display()
        );
    }

    println!("📂 Hanabi: {}", hanabi_dir.display());
    println!();

    // Step 1: Run cargo update
    println!(
        "📦 {} {}",
        "Updating dependencies".bold(),
        "(cargo update)".dimmed()
    );

    let status = Command::new("cargo")
        .arg("update")
        .current_dir(&hanabi_dir)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .await
        .context("Failed to run cargo update")?;

    if !status.success() {
        bail!("❌ cargo update failed");
    }
    println!("   ✅ Dependencies updated");
    println!();

    // Step 2: Regenerate Cargo.nix
    // crate2nix is available in PATH from the Nix environment
    println!(
        "🦀 {} {}",
        "Regenerating Cargo.nix".bold(),
        "(crate2nix generate)".dimmed()
    );

    let status = Command::new("crate2nix")
        .arg("generate")
        .current_dir(&hanabi_dir)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .await
        .context("Failed to run crate2nix generate - ensure crate2nix is in PATH")?;

    if !status.success() {
        bail!("❌ crate2nix generate failed");
    }
    println!("   ✅ Cargo.nix regenerated");
    println!();

    // Success summary
    println!("{}", "━".repeat(80).bright_green());
    println!("{}", "✅ UPDATE COMPLETE".green().bold());
    println!("{}", "━".repeat(80).bright_green());
    println!();
    println!("Updated files:");
    println!("  • {}", hanabi_dir.join("Cargo.lock").display());
    println!("  • {}", hanabi_dir.join("Cargo.nix").display());
    println!();
    println!("Next steps:");
    println!("  1. Review the changes: git diff");
    println!("  2. Test the build: cargo build");
    println!("  3. Commit: git add -A && git commit -m 'chore: update Hanabi deps'");
    println!();

    Ok(())
}
