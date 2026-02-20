//! Bootstrap binary build and push commands
//!
//! Handles building and pushing infrastructure bootstrap binaries:
//! - postgres-bootstrap
//! - dragonfly-bootstrap
//! - openbao-bootstrap
//!
//! Uses pure Rust - NO SHELL SCRIPTS.
//!
//! # Architecture
//!
//! Bootstrap binaries are infrastructure initialization tools that run as
//! Kubernetes Jobs to set up databases, caches, and secrets. They are built
//! as Docker images using Nix and pushed to GHCR.
//!
//! # Usage
//!
//! ```bash
//! # Push a single binary
//! forge bootstrap push --binary postgres-bootstrap
//!
//! # Push all binaries
//! forge bootstrap push-all
//!
//! # Push all in parallel (faster, but more resource intensive)
//! forge bootstrap push-all --parallel
//!
//! # List available binaries
//! forge bootstrap list
//!
//! # Regenerate Cargo.nix after dependency changes
//! forge bootstrap regenerate
//! ```

use anyhow::{Context, Result};
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use tracing::info;

use super::push::{discover_ghcr_token, generate_auto_tags, push_with_retry};
use crate::infrastructure::git::GitClient;
use crate::nix::build_docker_image_from_dir;
use crate::repo::{find_repo_root, get_tool_path, in_directory, verify_directory};

// ============================================================================
// Configuration
// ============================================================================

/// Bootstrap binary definitions - add new binaries here
const BOOTSTRAP_BINARIES: &[BootstrapBinary] = &[
    BootstrapBinary {
        name: "postgres-bootstrap",
        description: "PostgreSQL database initialization (users, schemas, extensions)",
    },
    BootstrapBinary {
        name: "dragonfly-bootstrap",
        description: "DragonflyDB cache initialization (ACLs, configuration)",
    },
    BootstrapBinary {
        name: "openbao-bootstrap",
        description: "OpenBao secrets initialization (policies, secrets engines)",
    },
    BootstrapBinary {
        name: "kanidm-bootstrap",
        description: "Kanidm identity provider initialization (groups, persons, OAuth2 clients)",
    },
];

/// Registry base URL for bootstrap binaries (from BOOTSTRAP_REGISTRY env var or default)
fn get_registry_base() -> String {
    std::env::var("BOOTSTRAP_REGISTRY")
        .expect("BOOTSTRAP_REGISTRY environment variable must be set (e.g., ghcr.io/myorg)")
}

/// Default architecture for bootstrap binaries (built with musl for x86_64)
const DEFAULT_ARCH: &str = "amd64";

// ============================================================================
// Types
// ============================================================================

/// A bootstrap binary definition
#[derive(Debug, Clone, Copy)]
struct BootstrapBinary {
    /// Binary name (e.g., "postgres-bootstrap")
    name: &'static str,
    /// Human-readable description
    description: &'static str,
}

impl BootstrapBinary {
    /// Get the registry URL for this binary
    fn registry_url(&self) -> String {
        format!("{}/{}", get_registry_base(), self.name)
    }
}

/// Result of building and pushing a bootstrap binary
#[derive(Debug)]
pub struct PushResult {
    /// Binary name
    pub binary: String,
    /// Registry URL
    pub registry: String,
    /// Tags that were pushed
    pub tags: Vec<String>,
}

// ============================================================================
// UI Helpers
// ============================================================================

/// Print a styled header box
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

/// Create a standard progress bar
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
// Core Functions
// ============================================================================

/// Find a bootstrap binary by name
fn find_binary(name: &str) -> Result<&'static BootstrapBinary> {
    BOOTSTRAP_BINARIES
        .iter()
        .find(|b| b.name == name)
        .ok_or_else(|| {
            let valid_names: Vec<_> = BOOTSTRAP_BINARIES.iter().map(|b| b.name).collect();
            anyhow::anyhow!(
                "Unknown bootstrap binary: '{}'\n\n  \
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

/// Get the bootstrap directory path
fn get_bootstrap_dir() -> Result<std::path::PathBuf> {
    // Check SERVICE_DIR env var first (set by Nix wrapper)
    if let Ok(dir) = std::env::var("SERVICE_DIR") {
        return Ok(std::path::PathBuf::from(dir));
    }

    // Otherwise, find repo root and compute path
    let repo_root = find_repo_root()?;
    Ok(repo_root.join("pkgs/platform/bootstrap"))
}

/// Build and push a single bootstrap binary
async fn build_and_push_binary(
    binary: &BootstrapBinary,
    tags: &[String],
    ghcr_token: &str,
    retries: u32,
) -> Result<PushResult> {
    // Get bootstrap directory
    let bootstrap_dir = get_bootstrap_dir()?;
    verify_directory(&bootstrap_dir, &["flake.nix"])?;

    // Build the image from the bootstrap flake
    let build_result = build_docker_image_from_dir(&bootstrap_dir, binary.name, None).await?;

    // Push all tags
    let registry = binary.registry_url();
    for tag in tags {
        push_with_retry(
            &build_result.store_path,
            &registry,
            tag,
            ghcr_token,
            retries,
        )
        .await?;
    }

    Ok(PushResult {
        binary: binary.name.to_string(),
        registry,
        tags: tags.to_vec(),
    })
}

// ============================================================================
// Public API
// ============================================================================

/// Push a single bootstrap binary to GHCR
///
/// # Arguments
///
/// * `binary` - Name of the bootstrap binary to push
/// * `token` - Optional GHCR token (will auto-discover if not provided)
/// * `retries` - Number of push retry attempts
/// * `skip_build` - Skip building, use existing image
/// * `image_path` - Path to existing image (required if skip_build is true)
///
/// # Errors
///
/// Returns an error if the binary is unknown, build fails, or push fails.
pub async fn push_single(
    binary: String,
    token: Option<String>,
    retries: u32,
    skip_build: bool,
    image_path: Option<String>,
) -> Result<()> {
    let binary_def = find_binary(&binary)?;

    print_header(&format!("Push Bootstrap: {}", binary_def.name));

    // Get git SHA for tagging
    let tags = generate_auto_tags(DEFAULT_ARCH).await?;
    info!("🔖 Git SHA: {}", &tags[0]);

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
        let bootstrap_dir = get_bootstrap_dir()?;
        verify_directory(&bootstrap_dir, &["flake.nix"])?;
        build_docker_image_from_dir(&bootstrap_dir, binary_def.name, None)
            .await?
            .store_path
    };

    // Get GHCR token
    let ghcr_token = discover_ghcr_token(token)?;

    // Push
    let registry = binary_def.registry_url();
    info!("🎯 Registry: {}", registry);
    info!("🏷️  Tags: {}", tags.join(", "));
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
        "✅ Bootstrap image pushed successfully!"
            .bright_green()
            .bold()
    );
    for tag in &tags {
        println!("   • {}:{}", registry, tag);
    }
    println!();

    Ok(())
}

/// Push all bootstrap binaries to GHCR
///
/// # Arguments
///
/// * `token` - Optional GHCR token (will auto-discover if not provided)
/// * `retries` - Number of push retry attempts
/// * `parallel` - Build and push in parallel (faster but more resource intensive)
///
/// # Errors
///
/// Returns an error if any build or push fails.
pub async fn push_all(token: Option<String>, retries: u32, parallel: bool) -> Result<()> {
    print_header("Push All Bootstrap Binaries");

    // Get git SHA for tagging (once, for consistency across all binaries)
    let tags = generate_auto_tags(DEFAULT_ARCH).await?;
    info!("🔖 Git SHA: {}", &tags[0]);

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
        "✅ All bootstrap images pushed successfully!"
            .bright_green()
            .bold()
    );
    for result in &results {
        println!("   📦 {}:", result.binary);
        for tag in &result.tags {
            println!("      • {}:{}", result.registry, tag);
        }
    }
    println!();

    Ok(())
}

/// Push all binaries in parallel
async fn push_all_parallel(
    tags: &[String],
    ghcr_token: &str,
    retries: u32,
) -> Result<Vec<PushResult>> {
    info!(
        "🚀 Building and pushing {} binaries in parallel...",
        BOOTSTRAP_BINARIES.len()
    );
    println!();

    let mut handles = Vec::new();

    for binary in BOOTSTRAP_BINARIES {
        let tags = tags.to_vec();
        let ghcr_token = ghcr_token.to_string();

        let handle = tokio::spawn(async move {
            build_and_push_binary(binary, &tags, &ghcr_token, retries).await
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

/// Push all binaries sequentially
async fn push_all_sequential(
    tags: &[String],
    ghcr_token: &str,
    retries: u32,
) -> Result<Vec<PushResult>> {
    info!(
        "🔧 Building and pushing {} binaries sequentially...",
        BOOTSTRAP_BINARIES.len()
    );
    println!();

    let pb = create_progress_bar(BOOTSTRAP_BINARIES.len() as u64);
    let mut results = Vec::new();

    for binary in BOOTSTRAP_BINARIES {
        pb.set_message(format!("Building {}", binary.name));

        let result = build_and_push_binary(binary, tags, ghcr_token, retries).await?;
        results.push(result);

        pb.inc(1);
    }

    pb.finish_with_message("All pushes complete");

    Ok(results)
}

/// List available bootstrap binaries
///
/// Prints a formatted list of all bootstrap binaries with their descriptions
/// and registry URLs.
pub fn list_binaries() {
    print_header("Available Bootstrap Binaries");

    for binary in BOOTSTRAP_BINARIES {
        println!("   {} {}", "•".bright_cyan(), binary.name.bright_white());
        println!("     {}", binary.description.dimmed());
        println!(
            "     {} {}",
            "Registry:".dimmed(),
            binary.registry_url().dimmed()
        );
        println!();
    }

    println!("Usage:");
    println!(
        "   {} bootstrap push --binary <name>",
        "forge".bright_cyan()
    );
    println!("   {} bootstrap push-all", "forge".bright_cyan());
    println!(
        "   {} bootstrap push-all --parallel",
        "forge".bright_cyan()
    );
    println!();
}

/// Release bootstrap binaries to a target environment
///
/// This function performs the full release workflow:
/// 1. Builds all bootstrap binaries
/// 2. Pushes them to GHCR with git SHA tags
/// 3. Updates the kustomization.yaml with new image tags
/// 4. Commits and pushes the changes to git
///
/// # Arguments
///
/// * `product` - Product name (e.g., "myapp")
/// * `environment` - Target environment (e.g., "production")
/// * `cluster` - Target cluster name. If None, defaults to "primary"
/// * `token` - Optional GHCR token (will auto-discover if not provided)
/// * `retries` - Number of push retry attempts
/// * `skip_git` - Skip git commit/push (for testing)
///
/// # Errors
///
/// Returns an error if build, push, manifest update, or git operations fail.
pub async fn release(
    product: String,
    environment: String,
    cluster: Option<String>,
    token: Option<String>,
    retries: u32,
    skip_git: bool,
) -> Result<()> {
    print_header(&format!("Bootstrap Release: {} {}", product, environment));

    // Determine cluster (default: primary)
    let cluster = cluster.unwrap_or_else(|| "primary".to_string());

    info!("📦 Product: {}", product);
    info!("🌍 Environment: {}", environment);
    info!("☸️  Cluster: {}", cluster);
    println!();

    // Get git SHA for tagging (once, for consistency)
    let tags = generate_auto_tags(DEFAULT_ARCH).await?;
    let tag_suffix = &tags[0]; // e.g., "amd64-abc1234"
    info!("🔖 Tag: {}", tag_suffix);

    // Get GHCR token
    let ghcr_token = discover_ghcr_token(token)?;

    // Step 1: Build and push all bootstrap binaries
    println!();
    println!(
        "{}",
        "Step 1/3: Building and pushing bootstrap images...".bold()
    );
    let results = push_all_sequential(&tags, &ghcr_token, retries).await?;

    // Step 2: Update kustomization.yaml
    println!();
    println!("{}", "Step 2/3: Updating Kubernetes manifests...".bold());

    let repo_root = find_repo_root()?;
    let kustomization_path = repo_root
        .join("nix/k8s/clusters")
        .join(&cluster)
        .join("products")
        .join(&product)
        .join(&environment)
        .join("bootstrap/kustomization.yaml");

    info!("📝 Manifest: {}", kustomization_path.display());

    // Read kustomization and update bootstrap image tags using targeted text replacement.
    // CRITICAL: Do NOT round-trip through serde_yaml - it destroys comments,
    // reformats multi-line strings (patch: | blocks), and can corrupt the file.
    let manifest_content = tokio::fs::read_to_string(&kustomization_path)
        .await
        .context("Failed to read kustomization.yaml")?;

    let lines: Vec<&str> = manifest_content.lines().collect();
    let mut result = Vec::with_capacity(lines.len());
    let mut matched_bootstrap = false;

    for line in &lines {
        if matched_bootstrap {
            let trimmed = line.trim();
            if trimmed.starts_with("newTag:") {
                let indent = &line[..line.len() - line.trim_start().len()];
                result.push(format!("{}newTag: {}", indent, tag_suffix));
                matched_bootstrap = false;
                continue;
            }
            if !trimmed.is_empty() && !trimmed.starts_with('#') {
                matched_bootstrap = false;
            }
        }

        let trimmed = line.trim();
        if trimmed.starts_with("- name:") {
            let name_value = trimmed.trim_start_matches("- name:").trim();
            if name_value.contains("bootstrap") {
                info!("   Updated: {} -> {}", name_value, tag_suffix);
                matched_bootstrap = true;
            }
        }

        result.push(line.to_string());
    }

    let mut updated_manifest = result.join("\n");
    if manifest_content.ends_with('\n') {
        updated_manifest.push('\n');
    }
    tokio::fs::write(&kustomization_path, &updated_manifest)
        .await
        .context("Failed to write kustomization.yaml")?;

    // Step 3: Git commit and push (using shared GitClient)
    if skip_git {
        println!();
        println!(
            "{}",
            "Step 3/3: Skipping git commit (--skip-git)".bold().dimmed()
        );
    } else {
        println!();
        println!("{}", "Step 3/3: Committing and pushing changes...".bold());

        let git = GitClient::in_dir(repo_root.to_string_lossy().to_string());
        let commit_message = format!(
            "release(bootstrap): {} {} [{}]",
            product, environment, tag_suffix
        );

        // Check if there are changes to commit
        if git.is_clean().await? {
            info!("   No changes to commit (images already at this version)");
        } else {
            // Stage, commit, and push
            git.add(&[&kustomization_path.to_string_lossy()]).await?;
            git.commit(&commit_message).await?;
            git.push().await?;
            info!("   ✅ Committed: {}", commit_message);
        }
    }

    // Success summary
    println!();
    println!("{}", "✅ Bootstrap release complete!".bright_green().bold());
    println!();
    println!("   📦 Images pushed:");
    for result in &results {
        println!("      • {}:{}", result.registry, tag_suffix);
    }
    println!();
    println!("   📝 Manifest updated:");
    println!("      • {}", kustomization_path.display());
    println!();
    println!("   💡 FluxCD will automatically reconcile the changes.");
    println!(
        "      To force reconcile: flux reconcile kustomization {}-{}-bootstrap",
        product, environment
    );
    println!();

    Ok(())
}

/// Regenerate Cargo.nix for bootstrap workspace
///
/// Runs `cargo update` followed by `crate2nix generate` in the bootstrap
/// directory to regenerate the Cargo.lock and Cargo.nix files.
///
/// # Environment Variables
///
/// * `CARGO` - Path to cargo binary (defaults to "cargo" in PATH)
/// * `CRATE2NIX` - Path to crate2nix binary (defaults to "crate2nix" in PATH)
/// * `SERVICE_DIR` - Override the bootstrap directory path
/// * `REPO_ROOT` - Override the repository root path
///
/// # Errors
///
/// Returns an error if the bootstrap directory is not found, or if
/// cargo/crate2nix commands fail.
pub async fn regenerate() -> Result<()> {
    use crate::nix::{run_cargo_update, run_crate2nix};

    print_header("Regenerate Bootstrap Cargo.nix");

    // Find repository root
    let repo_root = find_repo_root()?;
    info!("📁 Repository root: {}", repo_root.display());

    // Get bootstrap directory
    let bootstrap_dir = std::env::var("SERVICE_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| repo_root.join("pkgs/platform/bootstrap"));

    info!("📁 Bootstrap directory: {}", bootstrap_dir.display());

    // Verify directory exists with required files
    verify_directory(&bootstrap_dir, &["Cargo.toml"])?;

    // Get tool paths
    let cargo = get_tool_path("CARGO", "cargo");
    let crate2nix = get_tool_path("CRATE2NIX", "crate2nix");

    info!("🔧 Using cargo: {}", cargo);
    info!("🔧 Using crate2nix: {}", crate2nix);

    // Run commands in bootstrap directory
    in_directory(&bootstrap_dir, || async {
        run_cargo_update(&cargo).await?;
        run_crate2nix(&crate2nix).await?;
        Ok(())
    })
    .await?;

    println!();
    println!(
        "{}",
        "✅ Bootstrap Cargo.nix regenerated successfully!"
            .bright_green()
            .bold()
    );
    println!("   Don't forget to commit the updated Cargo.lock and Cargo.nix files.");
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
    fn test_find_binary_valid() {
        let result = find_binary("postgres-bootstrap");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().name, "postgres-bootstrap");
    }

    #[test]
    fn test_find_binary_invalid() {
        let result = find_binary("nonexistent-bootstrap");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Unknown bootstrap binary"));
        assert!(err.contains("postgres-bootstrap")); // Should list valid options
    }

    #[test]
    fn test_bootstrap_binary_registry_url() {
        let binary = BootstrapBinary {
            name: "test-bootstrap",
            description: "Test",
        };
        // Registry uses get_registry_base() which reads BOOTSTRAP_REGISTRY env var
        assert!(binary.registry_url().ends_with("/test-bootstrap"));
    }
}
