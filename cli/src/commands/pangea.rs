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
// Tool sigils
// ============================================================================

/// Resolve the `cargo` binary via the `CARGO` env override, falling
/// back to `cargo` on PATH. Every `cargo` spawn in this module reads
/// through this sigil so the two-argument resolve happens in exactly
/// one place — mirrors the `<tool>_bin()` sigil discipline every
/// substrate-`<TOOL>` / `<TOOL>_BIN`-routed spawn surface in forge
/// honors (`test_ci.rs`, `e2e.rs`, `developer_tools.rs`,
/// `prerelease.rs`, `tool.rs`, `comprehensive_release.rs`, and the
/// `bun_bin()` siblings on `codegen.rs`, `codegen_validation.rs`,
/// `sync.rs` per 8407021).
///
/// The lone consumer is `regenerate`'s `run_cargo_update(&cargo)`
/// call. Pre-lift the site spelled the two-argument resolve inline.
/// A Nix-hermetic runner whose derivation exports
/// `CARGO=/nix/store/…/bin/cargo` but omits `cargo` from PATH
/// silently fell through to whatever `cargo` was first on PATH,
/// defeating the substrate-pinned toolchain the pangea flake
/// declared. Post-lift the resolve lives at ONE place — this sigil
/// body — so a future added `cargo` spawn cannot silently re-copy
/// the resolve inline and drift away from the `CARGO` override.
fn cargo_bin() -> String {
    get_tool_path("CARGO", "cargo")
}

/// Resolve the `crate2nix` binary via the `CRATE2NIX` env override,
/// falling back to `crate2nix` on PATH. Same sigil discipline as
/// `cargo_bin()` above; the lone consumer is `regenerate`'s
/// `run_crate2nix(&crate2nix)` call. Post-lift the two-argument
/// resolve lives at ONE place — this sigil body — so a future added
/// `crate2nix` spawn cannot silently re-copy the resolve inline and
/// drift away from the `CRATE2NIX` override at exactly the tier the
/// hermetic-runner contract binds.
fn crate2nix_bin() -> String {
    get_tool_path("CRATE2NIX", "crate2nix")
}

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
    crate::repo::env_var_or_default("PANGEA_REGISTRY", "ghcr.io/org/project")
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
    /// External repository name (if not in the product repository)
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
        Ok(result.store_path.into_string())
    } else if component.has_dedicated_flake {
        // For web/compiler components, use their dedicated flakes
        let component_dir = component.component_dir(&repo_root);
        verify_directory(&component_dir, &["flake.nix"])?;

        info!("Building {} from dedicated flake...", component.name);

        // Use exact flake attr (no suffix) - the flake_attr already contains the full name
        let result =
            build_docker_image_from_dir(&component_dir, component.flake_attr, Some("")).await?;
        Ok(result.store_path.into_string())
    } else {
        // For operator/cli, use root flake
        info!("Building {} from root flake...", component.name);

        // Use exact flake attr (no suffix) - the flake_attr already contains the full name
        let result =
            build_docker_image_from_dir(&repo_root, component.flake_attr, Some("")).await?;
        Ok(result.store_path.into_string())
    }
}

/// Find an external repository by name
fn find_external_repo(name: &str) -> Result<std::path::PathBuf> {
    // Check environment variable first: PANGEA_DIR, etc.
    let env_var = format!("{}_DIR", name.to_uppercase());
    if let Some(path) = crate::repo::path_from_env_optional(&env_var) {
        if path.exists() {
            return Ok(path);
        }
    }

    // Check standard locations relative to home directory
    let home = crate::repo::path_from_env("HOME", "HOME not set")?
        .display()
        .to_string();
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
    println!("   {} pangea push-all --parallel", "forge".bright_cyan());
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

    let cargo = cargo_bin();
    let crate2nix = crate2nix_bin();

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

    // Env-var names honor the derived-`_BIN`-suffix convention every
    // sibling substrate-exported Ruby-toolchain surface uses
    // (`BUNDLE_BIN` per `commands/gem.rs:72` and `commands/pangea_infra.rs`,
    // `INSPEC_BIN` per `commands/pangea_infra.rs`). `BUNDIX_BIN` follows
    // the same derivation. The pre-lift `BUNDLER` / `BUNDIX` bare names
    // were exported by nothing in the fleet, so both lookups silently
    // fell through to whichever `bundle` / `bundix` sat first on PATH —
    // defeating the substrate-pinned Ruby toolchain at the pangea-
    // compiler gemset regen surface. See
    // `test_regenerate_compiler_ruby_toolchain_env_vars_route_through_bin_suffix`.
    let bundler = get_tool_path("BUNDLE_BIN", "bundle");
    let bundix = get_tool_path("BUNDIX_BIN", "bundix");

    info!("Using bundler: {}", bundler);
    info!("Using bundix: {}", bundix);

    in_directory(&pangea_dir, || async {
        // Update Gemfile.lock. Rides `crate::retry::run_bin_args_inherited_status`
        // — the async `(bin, args)`-front wrapper (c7cb181) over the direct
        // `run_inherited_status` primitive — so the fixed-argv `bundle lock
        // --update` shape lives at ONE `(bin, args, op)` call and the
        // canonical `Stdio::inherit()` + `classify_inherited_status`
        // envelope is preserved by construction.
        info!("Updating Gemfile.lock...");
        crate::retry::run_bin_args_inherited_status(
            &bundler,
            &["lock", "--update"],
            "bundle lock --update",
        )
        .await?;

        // Regenerate gemset.nix. Same `(bin, args)`-front wrapper as the
        // sibling `bundle lock --update` above; the empty `&[]` argv slice
        // carries the zero-arg `bundix` invocation faithfully because the
        // wrapper forwards its slice verbatim to the underlying
        // `std::process::Command::args` (retry.rs::run_bin_args_inherited_status
        // pins this at `test_run_bin_args_inherited_status_success_returns_ok`).
        info!("Regenerating gemset.nix...");
        crate::retry::run_bin_args_inherited_status(&bundix, &[], "bundix").await?;

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
// Spec Generation
// ============================================================================

/// Auto-generate RSpec synthesis specs for pangea provider resources.
///
/// Scans a provider gem directory for resources that lack synthesis specs,
/// then generates them using the resource.rb and types.rb files as input.
pub fn spec_gen(
    provider_dir: &str,
    resource: Option<&str>,
    force: bool,
    dry_run: bool,
) -> Result<()> {
    let provider_path = std::path::Path::new(provider_dir);
    if !provider_path.exists() {
        anyhow::bail!("Provider directory not found: {}", provider_dir);
    }

    let resources_dir = provider_path.join("lib/pangea/resources");
    let spec_dir = provider_path.join("spec/resources");

    if !resources_dir.exists() {
        anyhow::bail!(
            "No resources directory found at: {}",
            resources_dir.display()
        );
    }

    // Find resource directories
    let resource_dirs: Vec<_> = std::fs::read_dir(&resources_dir)?
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
        .filter(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            // Match provider-prefixed directories (aws_*, akeyless_*, etc.)
            name.contains('_') && !name.starts_with('.')
        })
        .filter(|e| {
            // Filter to specific resource if requested
            match resource {
                Some(r) => e.file_name().to_string_lossy() == r,
                None => true,
            }
        })
        .collect();

    let mut generated = 0;
    let mut skipped = 0;

    for entry in &resource_dirs {
        let resource_name = entry.file_name().to_string_lossy().to_string();
        let spec_path = spec_dir.join(&resource_name).join("synthesis_spec.rb");

        // Skip if spec exists and not forcing
        if spec_path.exists() && !force {
            skipped += 1;
            continue;
        }

        let resource_rb = entry.path().join("resource.rb");

        if !resource_rb.exists() {
            continue;
        }

        // Read resource.rb to extract method name and basic info
        let resource_content = std::fs::read_to_string(&resource_rb)?;

        // Extract the def method_name line
        let method_re = regex::Regex::new(r"def\s+([\w]+)\s*\(").unwrap();
        let method_name = match method_re.captures(&resource_content) {
            Some(caps) => caps[1].to_string(),
            None => continue,
        };

        // Extract provider module (look for "module AWS" or "module Akeyless" etc.)
        let module_re = regex::Regex::new(
            r"module\s+(AWS|Akeyless|Cloudflare|Google|Azure|Hcloud|Datadog|Splunk)",
        )
        .unwrap();
        let provider_module = match module_re.captures(&resource_content) {
            Some(caps) => format!("Pangea::Resources::{}", &caps[1]),
            None => continue,
        };

        // Detect tags support
        let has_tags = resource_content.contains("tags");

        // Generate spec
        let spec_content =
            generate_synthesis_spec(&provider_module, &method_name, &resource_name, has_tags);

        if dry_run {
            println!("=== {} ===", spec_path.display());
            println!("{}", spec_content);
            println!();
        } else {
            // Create spec directory
            if let Some(parent) = spec_path.parent() {
                crate::repo::create_dir_all_sync(parent)?;
            }
            std::fs::write(&spec_path, &spec_content)?;
            info!("Generated: {}", spec_path.display());
        }
        generated += 1;
    }

    info!(
        "Spec generation complete: {} generated, {} skipped (already exist)",
        generated, skipped
    );
    Ok(())
}

fn generate_synthesis_spec(
    provider_module: &str,
    method_name: &str,
    resource_name: &str,
    has_tags: bool,
) -> String {
    let mut spec = format!(
        r#"# frozen_string_literal: true
# Auto-generated by forge pangea spec-gen
# Regenerate: forge pangea spec-gen --provider-dir <path> --resource {resource_name} --force

require 'spec_helper'

RSpec.describe '{method_name}' do
  let(:synthesizer) {{ TerraformSynthesizer.new }}

  it 'synthesizes with valid attributes' do
    synthesizer.instance_eval do
      extend {provider_module}
      {method_name}(:test, {{}})
    end
    result = synthesizer.synthesis
    expect(result[:resource][:{method_name}][:test]).to be_a(Hash)
  end

  it 'returns ResourceReference' do
    ref = synthesizer.instance_eval do
      extend {provider_module}
      {method_name}(:test, {{}})
    end
    expect(ref).to be_a(Pangea::Resources::ResourceReference)
    expect(ref.type).to eq('{method_name}')
    expect(ref.name).to eq(:test)
    expect(ref.outputs[:id]).to eq('${{{method_name}}}.test.id}}')
  end
"#
    );

    if has_tags {
        spec.push_str(&format!(
            r#"
  it 'synthesizes with tags' do
    synthesizer.instance_eval do
      extend {provider_module}
      {method_name}(:test, {{ tags: {{ Environment: 'test' }} }})
    end
    result = synthesizer.synthesis
    config = result[:resource][:{method_name}][:test]
    expect(config[:tags]).to be_a(Hash) if config[:tags]
  end
"#
        ));
    }

    spec.push_str("end\n");
    spec
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

    /// Whole-module shield: `regenerate_compiler` must resolve `bundle`
    /// and `bundix` through the derived-`_BIN`-suffix env vars
    /// (`BUNDLE_BIN`, `BUNDIX_BIN`) that substrate's `mkRuntimeToolsEnv`
    /// exports, mirroring the sibling `bundle_bin()` sigils in
    /// `commands/gem.rs` (f201d24) and `commands/pangea_infra.rs`
    /// (e26787c). The pre-lift bare `BUNDLER` / `BUNDIX` env-var names
    /// were exported by nothing in the fleet — a source grep of the
    /// entire `cli/` tree finds `BUNDLER` at exactly one call-site
    /// (this one) and no substrate module writes it — so both
    /// [`crate::repo::get_tool_path`] calls silently fell through to
    /// the PATH-based fallback at every invocation. That's the exact
    /// silent-PATH-fallback bug class the sibling `BUNDLE_BIN` /
    /// `INSPEC_BIN` migrations on `commands/pangea_infra.rs` (e26787c)
    /// and `commands/gem.rs` (f201d24) closed on their respective
    /// Ruby-toolchain surfaces, and the same class the DOCA regression
    /// test at `tools.rs:200` pins on the doca frontier: an env-var
    /// name mismatch between what substrate exports and what the Rust
    /// call-site reads defeats every Nix-hermetic binding at that
    /// spawn surface without a visible failure mode.
    ///
    /// The `bundle`-spawn produces the updated `Gemfile.lock` the
    /// downstream `bundix` step feeds on for the `gemset.nix`
    /// regeneration verdict every Pangea compiler build downstream
    /// trusts as its Ruby-dependency-graph fingerprint. A wrong-binary
    /// verdict at either step attributes the regenerated `gemset.nix`
    /// (and therefore every downstream compiler-image build) to
    /// whichever `bundle` / `bundix` PATH resolved to at the time,
    /// not to the substrate-pinned Ruby derivation the flake declared —
    /// the same failure class the sibling Ruby-toolchain migrations
    /// closed on their gates.
    ///
    /// Scans this module's own source via [`include_str!`] for the
    /// canonical `crate::repo::get_tool_path("BUNDLE_BIN", "bundle")`
    /// and `crate::repo::get_tool_path("BUNDIX_BIN", "bundix")`
    /// delegation forms (present-check) and the pre-lift bare
    /// `BUNDLER` / `BUNDIX` env-var forms (absence-check, so a
    /// regression that spells the wrong-env-var lookup at either
    /// site fires the shield). The bare-name string literals below
    /// are reconstructed via `format!` so this shield's own source
    /// text does not false-match itself. Fail-before-pass-after:
    /// briefly reverting `BUNDLE_BIN` back to `BUNDLER` at the
    /// call-site fires the `BUNDLER`-absence assertion; restoring
    /// the fix makes both pass.
    #[test]
    fn test_regenerate_compiler_ruby_toolchain_env_vars_route_through_bin_suffix() {
        const SOURCE: &str = include_str!("pangea.rs");

        crate::test_support::assert_source_has_get_tool_path_two_arg_call_code_line(
            SOURCE,
            "commands/pangea.rs",
            "BUNDLE_BIN",
            "bundle",
        );
        crate::test_support::assert_source_has_get_tool_path_two_arg_call_code_line(
            SOURCE,
            "commands/pangea.rs",
            "BUNDIX_BIN",
            "bundix",
        );

        let bare_bundler = "BUNDLER";
        let bare_bundix_env = format!("get_tool_path(\"{}\", \"bundle\")", bare_bundler);
        assert!(
            !SOURCE.contains(&bare_bundix_env),
            "commands/pangea.rs must not resolve `bundle` via the bare \
             `{}` env-var name — substrate's `mkRuntimeToolsEnv` \
             exports `BUNDLE_BIN`, not `{}`. A `get_tool_path(\"{}\", …)` \
             lookup silently falls through to the PATH-based fallback \
             at every invocation, defeating the substrate-pinned Ruby \
             toolchain at the pangea-compiler gemset regen surface \
             (same silent-PATH-fallback bug class the sibling \
             `BUNDLE_BIN` migrations on `commands/gem.rs` and \
             `commands/pangea_infra.rs` closed).",
            bare_bundler,
            bare_bundler,
            bare_bundler
        );

        let bare_bundix = "BUNDIX";
        let bare_bundix_only_env = format!("get_tool_path(\"{}\", \"bundix\")", bare_bundix);
        assert!(
            !SOURCE.contains(&bare_bundix_only_env),
            "commands/pangea.rs must not resolve `bundix` via the bare \
             `{}` env-var name — the derived-`_BIN`-suffix convention \
             every substrate-exported tool honors requires `BUNDIX_BIN`. \
             A `get_tool_path(\"{}\", …)` lookup silently falls through \
             to PATH-based invocation, defeating the substrate-pinned \
             bundix derivation at the gemset.nix regeneration verdict.",
            bare_bundix,
            bare_bundix
        );
    }

    /// Whole-module shield: no raw `Command::new("cargo")` may live in
    /// `commands/pangea.rs`'s non-test body, `fn cargo_bin()` must be
    /// defined, and the two-argument resolve must appear exactly ONCE
    /// (only in the sigil body).
    ///
    /// Pre-lift `regenerate` spelled `let cargo = get_tool_path("CARGO",
    /// "cargo");` inline. Post-lift the binding is
    /// `let cargo = cargo_bin();` and the two-argument resolve appears
    /// only in the sigil body. Same three-invariant discipline every
    /// migrated `<tool>_bin()` shield enforces via the canonical
    /// primitive — see the sibling `bun_bin()` landings on
    /// `commands/codegen.rs`, `commands/codegen_validation.rs`, and
    /// `commands/sync.rs` per 8407021.
    #[test]
    fn test_pangea_routes_cargo_through_cargo_bin_sigil_not_raw_command() {
        crate::test_support::assert_source_routes_bare_spawn_through_sigil_bin_fn_at_exactly_one_resolve(
            include_str!("pangea.rs"),
            "commands/pangea.rs",
            "cargo",
            "CARGO",
        );
    }

    /// Whole-module shield: no raw `Command::new("crate2nix")` may live
    /// in `commands/pangea.rs`'s non-test body, `fn crate2nix_bin()`
    /// must be defined, and the two-argument resolve must appear
    /// exactly ONCE (only in the sigil body).
    ///
    /// Pre-lift `regenerate` spelled `let crate2nix = get_tool_path(
    /// "CRATE2NIX", "crate2nix");` inline. Post-lift the binding is
    /// `let crate2nix = crate2nix_bin();`. Sibling to the `cargo_bin()`
    /// shield above and the `crate2nix_bin()` sigils on
    /// `commands/web_service.rs` and `commands/tool.rs`.
    #[test]
    fn test_pangea_routes_crate2nix_through_crate2nix_bin_sigil_not_raw_command() {
        crate::test_support::assert_source_routes_bare_spawn_through_sigil_bin_fn_at_exactly_one_resolve(
            include_str!("pangea.rs"),
            "commands/pangea.rs",
            "crate2nix",
            "CRATE2NIX",
        );
    }
}

#[cfg(test)]
mod status_spawn_routing_tests {
    /// Whole-module shield: every async status-only spawn in
    /// `commands/pangea.rs` routes through
    /// [`crate::retry::run_inherited_status`] (the direct primitive)
    /// OR [`crate::retry::run_bin_args_inherited_status`] (the
    /// `(bin, args)`-front wrapper introduced by c7cb181), never a
    /// hand-rolled inline builder terminated by `.status().await` +
    /// `if !status.success() { bail!(…) }` that drops the exit code
    /// from the operator log line.
    ///
    /// Pre-lift the two spawns in `regenerate_compiler` — the
    /// `bundle lock --update` run that produces the updated
    /// `Gemfile.lock` and the `bundix` run that regenerates
    /// `gemset.nix` from it — each spelled the seven-line
    /// `.status().await` + `.context(…)?` + `if !status.success() {
    /// anyhow::bail!(FAIL_MSG) }` stanza with a per-site ad-hoc
    /// `FAIL_MSG` (`"bundle lock --update failed"`, `"bundix
    /// failed"`) that named the phase but dropped the exit code the
    /// child process actually returned. First lift (c5ff1c4) collapsed
    /// each site onto a two-line
    /// `let cmd = tokio::process::Command::new(...); …;
    /// crate::retry::run_inherited_status(cmd, "...").await?;` pair;
    /// second lift consolidates the fixed-argv shape onto a
    /// single-call
    /// `crate::retry::run_bin_args_inherited_status(&bin, &[...], op).await?`
    /// through the wrapper the sibling async-frontier consumers
    /// (`developer_tools.rs`, `nix.rs`) already ride. Either form
    /// routes through the same
    /// [`crate::retry::classify_inherited_status`] body, so the
    /// canonical `"{op} failed (exit {code})"` envelope emerges by
    /// construction — the shape every other lifted status-only spawn
    /// in forge now emits (sibling shields at
    /// `commands/{build, image_release, product_release, rust_service,
    /// tool, crossplane, pangea_infra, gem, infra, test_ci, local,
    /// e2e}.rs`, 72a7adf through b5d9573).
    ///
    /// The exit-code carry is the load-bearing part: pre-lift, a
    /// non-zero `bundle lock --update` at `regenerate_compiler`
    /// produced the operator log line `"bundle lock --update failed"`
    /// with no `code`, indistinguishable from a `bundix` that
    /// segfaulted (SIGSEGV — `status.code() == None`) at the same
    /// scan-of-the-log-line surface. Post-lift the two worlds
    /// separate at construction: `"bundle lock --update failed (exit
    /// 1)"` vs `"bundle lock --update failed (signal 11)"`, the same
    /// `(op, exit_code, stderr)` structural-record tuple THEORY.md
    /// §V.4 Phase 1 attestation-record consumers pattern-match on.
    ///
    /// Negative side: no `.status().await` builder terminator may
    /// reappear at any code line in the module body — a re-inlined
    /// spawn would bypass the primitive and re-drop the exit code.
    /// Positive side: the SUM of `run_inherited_status(` and
    /// `run_bin_args_inherited_status(` code-line hits must be ≥2
    /// (one per lifted site) — a regression that dropped a delegation
    /// call in EITHER form cannot leave the negative scan trivially
    /// satisfied by absence. The two needles are disjoint substrings
    /// (position 4 of the wrapper is `b`, not `i`), so a single call
    /// site counts at most once across the sum. All hits route through
    /// [`crate::test_support::code_line_hits`] for anti-docstring-
    /// self-match discipline (the `.status().await` string in this
    /// shield's own docstring is excluded because
    /// [`code_line_hits`] filters `///`-prefixed lines). Scan bounds
    /// from file start to the first `\n#[cfg(test)]\nmod tests {`
    /// marker so this whole shield's own source (the string literal
    /// `".status().await"` passed to `code_line_hits`, the assertion
    /// message that names the forbidden terminator) stays out of
    /// scope — this shield lives in a SIBLING
    /// `mod status_spawn_routing_tests { … }` block opened after the
    /// primary `mod tests { … }` precisely so the scan boundary the
    /// production body ends at also bounds every shield in this file
    /// away from self-match.
    #[test]
    fn test_pangea_status_spawns_route_through_run_inherited_status() {
        crate::test_support::assert_source_routes_status_only_spawns_through_run_inherited_status(
            include_str!("pangea.rs"),
            "commands/pangea.rs",
            2,
            "the two `regenerate_compiler` status-only spawn sites \
             (`bundle lock --update` and `bundix`)",
        );
    }

    /// Whole-module shield: the sole `HOME` env-var read in
    /// `commands/pangea.rs` (the `find_external_repo` fallback that
    /// probes `$HOME/code/<name>` and `$HOME/.local/src/<name>`)
    /// routes through [`crate::repo::path_from_env`], never a
    /// hand-rolled inline `std::env::var("HOME").context("HOME not
    /// set")?` stanza.
    ///
    /// Pre-lift `find_external_repo` spelled the read inline; post-
    /// lift it delegates to `crate::repo::path_from_env("HOME", "HOME
    /// not set")`, sibling of `commands/gem.rs::push`'s two consumer
    /// sites (test_gem_home_env_routes_through_path_from_env above) —
    /// the third and final `env::var("HOME")` consumer in the crate,
    /// closing the three-times-is-a-law recurrence THEORY §VI.1
    /// admits.
    ///
    /// Scan bounds at the whole-module boundary via
    /// [`crate::test_support::module_body_before_first_cfg_test`] so
    /// this shield's docstring mentions of `env::var("HOME")` — living
    /// inside a `#[cfg(test)]` block below that first marker — stay
    /// out of scope. Every hit routes through
    /// [`crate::test_support::code_line_hits`] for anti-docstring-
    /// self-match discipline.
    #[test]
    fn test_pangea_home_env_routes_through_path_from_env() {
        let body = crate::test_support::module_body_before_first_cfg_test(
            include_str!("pangea.rs"),
            "commands/pangea.rs",
        );
        let raw_env_needle = "env::var(\"HOME\")";
        let env_hits = crate::test_support::code_line_hits(body, raw_env_needle);
        assert!(
            env_hits.is_empty(),
            "commands/pangea.rs must NOT spell `{raw_env_needle}` \
             inline in the module body — the `find_external_repo` \
             consumer must route through `crate::repo::path_from_env`. \
             Found {} code-line hit(s): {env_hits:#?}",
            env_hits.len()
        );
        let delegate_needle = "crate::repo::path_from_env(\"HOME\"";
        let delegate_hits = crate::test_support::code_line_hits(body, delegate_needle);
        assert_eq!(
            delegate_hits.len(),
            1,
            "commands/pangea.rs must delegate `HOME` resolution to \
             `crate::repo::path_from_env(\"HOME\", ...)` at EXACTLY \
             one code line — the `find_external_repo` fallback. Found \
             {} code-line hit(s): {delegate_hits:#?}",
            delegate_hits.len()
        );
        let wording_needle = "\"HOME not set\"";
        let wording_hits = crate::test_support::code_line_hits(body, wording_needle);
        assert_eq!(
            wording_hits.len(),
            1,
            "commands/pangea.rs must spell the canonical miss wording \
             `{wording_needle}` at EXACTLY one code line — the \
             delegating call's second argument. Found {} code-line \
             hit(s): {wording_hits:#?}",
            wording_hits.len()
        );
    }
}
