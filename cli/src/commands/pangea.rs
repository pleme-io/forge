//! Pangea infrastructure platform commands
//!
//! Handles building and pushing Pangea components:
//! - pangea-operator (Kubernetes operator)
//! - pangea-cli (CLI tool)
//! - pangea-web (WASM frontend)
//!
//! Uses pure Rust - NO SHELL SCRIPTS.

use anyhow::{Context, Result};
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use tracing::info;

use super::push::{discover_ghcr_token, generate_auto_tags, push_with_retry};
use crate::nix::build_docker_image_from_dir;
use crate::repo::{find_repo_root, get_tool_path, in_directory, verify_directory};

// ============================================================================
// Configuration
// ============================================================================

/// Pangea component definitions
const PANGEA_COMPONENTS: &[PangeaComponent] = &[
    PangeaComponent {
        name: "operator",
        description: "Kubernetes operator with GraphQL API",
        flake_attr: "pangea-operator-image",
        has_dedicated_flake: false,
        external_repo: None,
    },
    PangeaComponent {
        name: "cli",
        description: "CLI tool for infrastructure management",
        flake_attr: "pangea-cli-image",
        has_dedicated_flake: false,
        external_repo: None,
    },
    PangeaComponent {
        name: "web",
        description: "WASM frontend with Yew + Hanabi",
        flake_attr: "pangea-web-image",
        has_dedicated_flake: true, // Uses fenix WASM toolchain
        external_repo: None,
    },
    PangeaComponent {
        name: "compiler",
        description: "Ruby DSL compiler sidecar (terraform-synthesizer)",
        flake_attr: "compilerImage",
        has_dedicated_flake: true, // Uses ruby-nix for gem dependencies
        external_repo: None,       // Built from monorepo pkgs/tools/ruby/pangea
    },
];

/// Registry base URL for Pangea components (from PANGEA_REGISTRY env var or default)
fn get_registry_base() -> String {
    std::env::var("PANGEA_REGISTRY").unwrap_or_else(|_| "ghcr.io/org/project".to_string())
}

/// Default architecture for Pangea binaries
const DEFAULT_ARCH: &str = "amd64";

// ============================================================================
// Types
// ============================================================================

/// A Pangea component definition
#[derive(Debug, Clone, Copy)]
struct PangeaComponent {
    name: &'static str,
    description: &'static str,
    flake_attr: &'static str,
    has_dedicated_flake: bool,
    /// External repository name (if not in nexus monorepo)
    external_repo: Option<&'static str>,
}

impl PangeaComponent {
    /// Get the registry URL for this component
    fn registry_url(&self) -> String {
        format!("{}/pangea-{}", get_registry_base(), self.name)
    }

    /// Get the path to the component directory
    fn component_dir(&self, repo_root: &std::path::Path) -> std::path::PathBuf {
        match self.name {
            // Compiler lives in tools directory (Ruby gem with WEBrick HTTP server)
            "compiler" => repo_root.join("pkgs/tools/ruby/pangea"),
            // Other components live in products directory
            _ => repo_root.join(format!("pkgs/products/pangea/pangea-{}", self.name)),
        }
    }
}

/// Result of building and pushing a Pangea component
#[derive(Debug)]
pub struct PushResult {
    pub component: String,
    pub registry: String,
    pub tags: Vec<String>,
}

// ============================================================================
// UI Helpers
// ============================================================================

fn print_header(title: &str) {
    println!();
    println!(
        "{}",
        "╔════════════════════════════════════════════════════════════╗".bright_blue()
    );
    println!("{}", format!("║  {:58} ║", title).bright_blue());
    println!(
        "{}",
        "╚════════════════════════════════════════════════════════════╝".bright_blue()
    );
    println!();
}

fn create_progress_bar(total: u64) -> ProgressBar {
    let pb = ProgressBar::new(total);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} {msg}")
            .expect("Invalid progress bar template")
            .progress_chars("#>-"),
    );
    pb
}

// ============================================================================
// Public API
// ============================================================================

/// Find a Pangea component by name
fn find_component(name: &str) -> Result<&'static PangeaComponent> {
    PANGEA_COMPONENTS
        .iter()
        .find(|c| c.name == name)
        .ok_or_else(|| {
            let valid_names: Vec<_> = PANGEA_COMPONENTS.iter().map(|c| c.name).collect();
            anyhow::anyhow!(
                "Unknown Pangea component: '{}'\n\n  \
                 Valid options:\n  \
                 {}",
                name,
                valid_names
                    .iter()
                    .map(|n| format!("  - {}", n))
                    .collect::<Vec<_>>()
                    .join("\n")
            )
        })
}

/// Push a single Pangea component to GHCR
pub async fn push_single(
    component: String,
    token: Option<String>,
    retries: u32,
    skip_build: bool,
    image_path: Option<String>,
) -> Result<()> {
    let component_def = find_component(&component)?;

    print_header(&format!("Push Pangea: {}", component_def.name));

    // Get git SHA for tagging
    let tags = generate_auto_tags(DEFAULT_ARCH).await?;
    info!("Git SHA: {}", &tags[0]);

    // Build or use provided image path
    let image_path = if skip_build {
        image_path.ok_or_else(|| {
            anyhow::anyhow!(
                "--image-path is required when using --skip-build\n\n  \
                 Either remove --skip-build to build the image, or provide\n  \
                 the path to an existing image with --image-path"
            )
        })?
    } else {
        build_component(component_def).await?
    };

    // Get GHCR token
    let ghcr_token = discover_ghcr_token(token)?;

    // Push
    let registry = component_def.registry_url();
    info!("Registry: {}", registry);
    info!("Tags: {}", tags.join(", "));
    println!();

    let pb = create_progress_bar(tags.len() as u64);
    for tag in &tags {
        pb.set_message(format!("Pushing {}:{}", registry, tag));
        push_with_retry(&image_path, &registry, tag, &ghcr_token, retries).await?;
        pb.inc(1);
    }
    pb.finish_with_message("Push complete");

    // Success message
    println!();
    println!(
        "{}",
        "Pangea image pushed successfully!".bright_green().bold()
    );
    for tag in &tags {
        println!("   - {}:{}", registry, tag);
    }
    println!();

    Ok(())
}

/// Push all Pangea components to GHCR
pub async fn push_all(token: Option<String>, retries: u32, parallel: bool) -> Result<()> {
    print_header("Push All Pangea Components");

    // Get git SHA for tagging (once, for consistency)
    let tags = generate_auto_tags(DEFAULT_ARCH).await?;
    info!("Git SHA: {}", &tags[0]);

    // Get GHCR token (once, for all pushes)
    let ghcr_token = discover_ghcr_token(token)?;

    let results = if parallel {
        push_all_parallel(&tags, &ghcr_token, retries).await?
    } else {
        push_all_sequential(&tags, &ghcr_token, retries).await?
    };

    // Print summary
    println!();
    println!(
        "{}",
        "All Pangea images pushed successfully!"
            .bright_green()
            .bold()
    );
    for result in &results {
        println!("   {}", result.component);
        for tag in &result.tags {
            println!("      - {}:{}", result.registry, tag);
        }
    }
    println!();

    Ok(())
}

/// Build a Pangea component
async fn build_component(component: &PangeaComponent) -> Result<String> {
    let repo_root = find_repo_root()?;

    if let Some(external_repo) = component.external_repo {
        // For external repos (like pangea Ruby gem), look in standard locations
        let external_dir = find_external_repo(external_repo)?;
        verify_directory(&external_dir, &["flake.nix"])?;

        info!(
            "Building {} from external repo ({})...",
            component.name, external_repo
        );

        // External repos use exact flake attr (no -image suffix)
        let result =
            build_docker_image_from_dir(&external_dir, component.flake_attr, Some("")).await?;
        Ok(result.store_path)
    } else if component.has_dedicated_flake {
        // For web/compiler components, use their dedicated flakes
        let component_dir = component.component_dir(&repo_root);
        verify_directory(&component_dir, &["flake.nix"])?;

        info!("Building {} from dedicated flake...", component.name);

        // Use exact flake attr (no suffix) - the flake_attr already contains the full name
        let result =
            build_docker_image_from_dir(&component_dir, component.flake_attr, Some("")).await?;
        Ok(result.store_path)
    } else {
        // For operator/cli, use root flake
        info!("Building {} from root flake...", component.name);

        // Use exact flake attr (no suffix) - the flake_attr already contains the full name
        let result =
            build_docker_image_from_dir(&repo_root, component.flake_attr, Some("")).await?;
        Ok(result.store_path)
    }
}

/// Find an external repository by name
fn find_external_repo(name: &str) -> Result<std::path::PathBuf> {
    // Check environment variable first: PANGEA_DIR, etc.
    let env_var = format!("{}_DIR", name.to_uppercase());
    if let Ok(dir) = std::env::var(&env_var) {
        let path = std::path::PathBuf::from(&dir);
        if path.exists() {
            return Ok(path);
        }
    }

    // Check standard locations relative to home directory
    let home = std::env::var("HOME").context("HOME not set")?;
    let locations = [
        format!("{}/code/{}", home, name),
        format!("{}/.local/src/{}", home, name),
    ];

    for location in &locations {
        let path = std::path::PathBuf::from(location);
        if path.exists() {
            return Ok(path);
        }
    }

    Err(anyhow::anyhow!(
        "External repository '{}' not found.\n\n  \
         Set {} environment variable or clone to one of:\n  \
         {}",
        name,
        env_var,
        locations
            .iter()
            .map(|l| format!("  - {}", l))
            .collect::<Vec<_>>()
            .join("\n")
    ))
}

/// Push all components in parallel
async fn push_all_parallel(
    tags: &[String],
    ghcr_token: &str,
    retries: u32,
) -> Result<Vec<PushResult>> {
    info!(
        "Building and pushing {} components in parallel...",
        PANGEA_COMPONENTS.len()
    );
    println!();

    let mut handles = Vec::new();

    for component in PANGEA_COMPONENTS {
        let tags = tags.to_vec();
        let ghcr_token = ghcr_token.to_string();

        let handle = tokio::spawn(async move {
            build_and_push_component(component, &tags, &ghcr_token, retries).await
        });

        handles.push(handle);
    }

    // Collect results
    let mut results = Vec::new();
    for handle in handles {
        let result = handle
            .await
            .context("Build/push task panicked")?
            .context("Build/push failed")?;
        results.push(result);
    }

    Ok(results)
}

/// Push all components sequentially
async fn push_all_sequential(
    tags: &[String],
    ghcr_token: &str,
    retries: u32,
) -> Result<Vec<PushResult>> {
    info!(
        "Building and pushing {} components sequentially...",
        PANGEA_COMPONENTS.len()
    );
    println!();

    let pb = create_progress_bar(PANGEA_COMPONENTS.len() as u64);
    let mut results = Vec::new();

    for component in PANGEA_COMPONENTS {
        pb.set_message(format!("Building {}", component.name));

        let result = build_and_push_component(component, tags, ghcr_token, retries).await?;
        results.push(result);

        pb.inc(1);
    }

    pb.finish_with_message("All components pushed");

    Ok(results)
}

/// Build and push a single component
async fn build_and_push_component(
    component: &PangeaComponent,
    tags: &[String],
    ghcr_token: &str,
    retries: u32,
) -> Result<PushResult> {
    // Build
    let image_path = build_component(component).await?;

    // Push
    let registry = component.registry_url();
    for tag in tags {
        push_with_retry(&image_path, &registry, tag, ghcr_token, retries).await?;
    }

    Ok(PushResult {
        component: component.name.to_string(),
        registry,
        tags: tags.to_vec(),
    })
}

/// List available Pangea components
pub fn list_components() {
    print_header("Available Pangea Components");

    for component in PANGEA_COMPONENTS {
        println!("   {} {}", "-".bright_cyan(), component.name.bright_white());
        println!("     {}", component.description.dimmed());
        println!(
            "     {} {}",
            "Registry:".dimmed(),
            component.registry_url().dimmed()
        );
        if component.has_dedicated_flake {
            println!(
                "     {} {}",
                "Build:".dimmed(),
                "dedicated flake (WASM)".dimmed()
            );
        }
        println!();
    }

    println!("Usage:");
    println!(
        "   {} pangea push --component <name>",
        "forge".bright_cyan()
    );
    println!("   {} pangea push-all", "forge".bright_cyan());
    println!(
        "   {} pangea push-all --parallel",
        "forge".bright_cyan()
    );
    println!();
}

/// Regenerate Cargo.nix for Pangea workspace (Rust components)
pub async fn regenerate(pangea_dir: Option<String>) -> Result<()> {
    use crate::nix::{run_cargo_update, run_crate2nix};

    print_header("Regenerate Pangea Cargo.nix");

    let repo_root = find_repo_root()?;
    let pangea_dir = pangea_dir
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| repo_root.join("pkgs/products/pangea"));

    info!("Repository root: {}", repo_root.display());
    info!("Pangea directory: {}", pangea_dir.display());

    verify_directory(&pangea_dir, &["Cargo.toml"])?;

    let cargo = get_tool_path("CARGO", "cargo");
    let crate2nix = get_tool_path("CRATE2NIX", "crate2nix");

    info!("Using cargo: {}", cargo);
    info!("Using crate2nix: {}", crate2nix);

    in_directory(&pangea_dir, || async {
        run_cargo_update(&cargo).await?;
        run_crate2nix(&crate2nix).await?;
        Ok(())
    })
    .await?;

    println!();
    println!(
        "{}",
        "Pangea Cargo.nix regenerated successfully!"
            .bright_green()
            .bold()
    );
    println!("   Don't forget to commit the updated Cargo.lock and Cargo.nix files.");
    println!();

    Ok(())
}

/// Regenerate gemset.nix for Pangea Ruby compiler
pub async fn regenerate_compiler() -> Result<()> {
    print_header("Regenerate Pangea Compiler gemset.nix");

    let pangea_dir = find_external_repo("pangea")?;
    info!("Pangea directory: {}", pangea_dir.display());

    verify_directory(&pangea_dir, &["Gemfile"])?;

    let bundler = get_tool_path("BUNDLER", "bundle");
    let bundix = get_tool_path("BUNDIX", "bundix");

    info!("Using bundler: {}", bundler);
    info!("Using bundix: {}", bundix);

    in_directory(&pangea_dir, || async {
        // Update Gemfile.lock
        info!("Updating Gemfile.lock...");
        let status = tokio::process::Command::new(&bundler)
            .args(["lock", "--update"])
            .status()
            .await
            .context("Failed to run bundle lock")?;

        if !status.success() {
            anyhow::bail!("bundle lock --update failed");
        }

        // Regenerate gemset.nix
        info!("Regenerating gemset.nix...");
        let status = tokio::process::Command::new(&bundix)
            .status()
            .await
            .context("Failed to run bundix")?;

        if !status.success() {
            anyhow::bail!("bundix failed");
        }

        Ok(())
    })
    .await?;

    println!();
    println!(
        "{}",
        "Pangea gemset.nix regenerated successfully!"
            .bright_green()
            .bold()
    );
    println!("   Don't forget to commit the updated Gemfile.lock and gemset.nix files.");
    println!();

    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_component_valid() {
        let result = find_component("operator");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().name, "operator");
    }

    #[test]
    fn test_find_component_invalid() {
        let result = find_component("nonexistent");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Unknown Pangea component"));
        assert!(err.contains("operator")); // Should list valid options
    }

    #[test]
    fn test_component_registry_url() {
        let component = PANGEA_COMPONENTS
            .iter()
            .find(|c| c.name == "operator")
            .unwrap();
        // Registry uses get_registry_base() which defaults to "ghcr.io/org/project"
        assert!(component.registry_url().ends_with("/pangea-operator"));
    }
}
