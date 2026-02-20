//! # GraphQL Federation Module
//!
//! Handles GraphQL Federation supergraph composition for Hive Router.
//!
//! ## Architecture
//!
//! - **Schema Extraction**: Extract GraphQL schemas from Rust services
//! - **Supergraph Composition**: Compose schemas using Apollo Rover
//! - **Verification**: Pre and post-composition validation
//! - **GitOps**: Commit and push supergraph changes

use anyhow::{anyhow, bail, Context, Result};
use colored::Colorize;
use std::collections::BTreeMap;
use std::env;
use std::path::PathBuf;
use std::process::Stdio;
use tokio::process::Command;

use crate::config::DeployConfig;
use crate::path_builder::PathBuilder;

/// Extract GraphQL schema from a service
///
/// Uses the new schema validation module which:
/// - Detects schema extraction binary (extract-schema or extract_schema)
/// - Validates schema content (size, expected types)
/// - Provides detailed error messages
///
/// # Configuration
/// Schema extraction is configured in deploy.yaml:
/// ```yaml
/// graphql:
///   enabled: true
///   schema_extractor: "extract-schema"
///   min_schema_size: 100
///   expected_types: [Query, Mutation]
/// ```
pub async fn extract_schema(_service: String, deploy_config: &DeployConfig) -> Result<()> {
    println!();

    // Use new schema validation module
    use crate::commands::schema_validation::extract_and_validate_schema;

    let result = extract_and_validate_schema(deploy_config).await?;

    match result {
        Some(extraction_result) => {
            println!();
            println!("✅ {}", "Schema extraction complete".green());
            println!("   Path: {}", extraction_result.schema_path.display());
            println!("   Size: {} bytes", extraction_result.schema_size);
            println!("   Types: {}", extraction_result.type_count);
            Ok(())
        }
        None => {
            println!("ℹ️  GraphQL not enabled for this service - skipping schema extraction");
            Ok(())
        }
    }
}

/// Update GraphQL Federation supergraph for Hive Router
///
/// Composes supergraph schema from all subgraph .graphql files using Rover.
/// This replaces the TypeScript federation-updater.ts script with native Rust.
pub async fn update_federation(
    service: String,
    namespace: String,
    deploy_config: &DeployConfig,
) -> Result<()> {
    println!();
    println!("🔄 {}", "Updating Hive Router federation...".bold());

    // Skip federation update if GraphQL is not enabled for this service
    if !deploy_config.service.graphql.enabled {
        println!("ℹ️  GraphQL not enabled for this service - skipping federation update");
        return Ok(());
    }

    let federation_dir = deploy_config.federation_directory()?;

    if !federation_dir.exists() {
        bail!(
            "Federation directory not found: {}",
            federation_dir.display()
        );
    }

    // Get repo root for path resolution (not current service directory)
    let current_dir = env::current_dir()?;
    let repo_root = DeployConfig::find_repo_root(&current_dir)?;

    // Initialize PathBuilder for config-driven path construction
    let paths = PathBuilder::new(deploy_config)?;

    // Change to federation directory
    env::set_current_dir(&federation_dir).context("Failed to change to federation directory")?;

    // PRE-COMPOSITION VALIDATION
    use crate::commands::supergraph_verification::{
        run_post_composition_checks, run_pre_composition_checks,
    };

    println!("🔍 Running pre-composition validation...");
    let subgraphs_dir = PathBuf::from("subgraphs");

    let pre_check = run_pre_composition_checks(&subgraphs_dir).await?;

    // Print all check results
    for check in &pre_check.checks {
        if check.passed {
            println!("   {}", check.message.green());
        } else {
            eprintln!("   {}", check.message.red());
        }
    }

    if !pre_check.passed {
        bail!("Pre-composition validation failed. Cannot proceed with composition.");
    }

    println!("✅ {}", "Pre-composition validation passed".green());
    println!();

    // Generate supergraph config YAML from subgraph schemas
    println!("🔨 Generating supergraph configuration...");

    // Collect all .graphql files
    // Use exact Federation version to avoid Rover warnings and ensure deterministic composition
    // This should match the version Hive Router expects (Federation v2 compatible)
    let mut supergraph_config = String::from("federation_version: =2.11.3\nsubgraphs:\n");

    for entry in std::fs::read_dir(&subgraphs_dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.extension().and_then(|s| s.to_str()) == Some("graphql") {
            if let Some(service_name) = path.file_stem().and_then(|s| s.to_str()) {
                // Build routing URL using config pattern (supports {service}, {product}, {environment}, {port}, {protocol})
                let federation = deploy_config
                    .service
                    .federation
                    .as_ref()
                    .unwrap_or(&deploy_config.global.federation);
                let routing_url = federation
                    .routing_url_pattern
                    .replace("{protocol}", &federation.protocol)
                    .replace("{service}", service_name)
                    .replace("{product}", &deploy_config.product.name)
                    .replace("{environment}", &deploy_config.product.environment)
                    .replace("{port}", &federation.port.to_string());

                // Each subgraph entry in the config
                supergraph_config.push_str(&format!(
                    "  {}:\n    routing_url: {}\n    schema:\n      file: ./subgraphs/{}.graphql\n",
                    service_name, routing_url, service_name
                ));
            }
        }
    }

    // Write temporary supergraph config
    let config_path = PathBuf::from("supergraph-config.yaml");
    tokio::fs::write(&config_path, &supergraph_config)
        .await
        .context("Failed to write supergraph config")?;

    println!(
        "📋 Supergraph config generated with {} service(s)",
        supergraph_config.matches("routing_url").count()
    );

    // Run rover supergraph compose via rover-fhs (FHS environment for dynamic linking)
    // Rover downloads pre-built supergraph binaries that need dynamic linking (not available in pure Nix)
    println!("🔨 Composing supergraph schema with Rover...");
    let output = Command::new("rover-fhs")
        .args(&[
            "supergraph",
            "compose",
            "--config",
            "supergraph-config.yaml",
            "--elv2-license",
            "accept", // Accept ELv2 license for Federation spec
        ])
        .env("TMPDIR", "/tmp") // Ensure temp directory is accessible in FHS env
        .output()
        .await
        .context("Failed to run rover-fhs")?;

    // Check stderr first - Rover may output errors even on status 0
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.is_empty() {
        eprintln!("Rover stderr: {}", stderr);
    }

    if !output.status.success() {
        bail!("Rover composition failed:\n{}", stderr);
    }

    // Check if we got valid output
    if output.stdout.is_empty() {
        bail!("Rover produced empty output. stderr:\n{}", stderr);
    }

    // Write composed supergraph schema
    let supergraph_path = PathBuf::from("supergraph.graphql");
    tokio::fs::write(&supergraph_path, &output.stdout)
        .await
        .context("Failed to write supergraph schema")?;

    println!("✅ {}", "Supergraph composed successfully".green());
    println!("   Schema: {}", supergraph_path.display());
    println!();

    // POST-COMPOSITION VALIDATION
    println!("🔍 Running post-composition validation...");

    let post_check = run_post_composition_checks(&supergraph_path, &subgraphs_dir).await?;

    // Print all check results
    for check in &post_check.checks {
        if check.passed {
            println!("   {}", check.message.green());
        } else if check.message.contains("Warning") {
            println!("   {}", check.message.yellow());
        } else {
            eprintln!("   {}", check.message.red());
        }
    }

    if !post_check.passed {
        bail!("Post-composition validation failed. Supergraph may be invalid.");
    }

    println!("✅ {}", "Post-composition validation passed".green());
    println!(
        "   Supergraph size: {} KB",
        post_check.supergraph_size / 1024
    );
    println!("   Services included: {}", post_check.service_count);
    println!();

    // Get git SHA for metadata tracking
    let git_sha = Command::new("git")
        .args(&["rev-parse", "--short", "HEAD"])
        .output()
        .await
        .context("Failed to get git SHA")?;
    let git_sha = String::from_utf8_lossy(&git_sha.stdout).trim().to_string();

    // Generate and save supergraph metadata for deterministic verification
    use crate::commands::supergraph_verification::SupergraphMetadata;
    println!("🔐 Generating supergraph verification metadata...");

    let metadata =
        SupergraphMetadata::generate(&federation_dir, service.clone(), git_sha.clone()).await?;

    metadata.save(&federation_dir).await?;

    println!("✅ Metadata saved:");
    println!("   Hash: {}", &metadata.supergraph_hash[..16]);
    println!("   Services: {}", metadata.services.len());
    println!("   Rover: {}", metadata.rover_version);

    // Copy supergraph.graphql to hive-router kustomization directory for FluxCD
    // FluxCD/kustomize cannot load files from outside the kustomization directory
    // So we copy the supergraph to the hive-router directory before committing
    println!("📋 Copying supergraph to hive-router kustomization...");

    let hive_router_full_path = deploy_config
        .supergraph_router_path()
        .context("Failed to compute supergraph router path from config")?;

    let hive_router_path = hive_router_full_path
        .strip_prefix(&repo_root)
        .unwrap_or(&hive_router_full_path)
        .display()
        .to_string();

    // Ensure parent directory exists
    if let Some(parent) = hive_router_full_path.parent() {
        if !parent.exists() {
            bail!(
                "Hive Router directory not found: {}\nExpected at: {}",
                parent.display(),
                hive_router_path
            );
        }
    }

    // Copy supergraph.graphql to hive-router directory
    tokio::fs::copy(&supergraph_path, &hive_router_full_path)
        .await
        .with_context(|| {
            format!(
                "Failed to copy supergraph to hive-router directory: {}",
                hive_router_full_path.display()
            )
        })?;

    println!("✅ Supergraph copied to: {}", hive_router_path);

    // Calculate supergraph hash for deterministic deployment verification
    println!("🔐 Calculating supergraph hash for deployment annotation...");
    let supergraph_content = tokio::fs::read(&hive_router_full_path)
        .await
        .context("Failed to read supergraph for hashing")?;

    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(&supergraph_content);
    let hash_bytes = hasher.finalize();
    let supergraph_hash = format!("{:x}", hash_bytes);
    let supergraph_hash_short = &supergraph_hash[..16]; // First 16 chars

    println!("   Hash: {}", supergraph_hash_short);

    // Update hive-router deployment with supergraph hash annotation
    // This forces pod restart and provides undeniable proof of supergraph version
    let router_deployment_path = paths
        .hive_router_deployment()
        .context("Failed to compute hive-router deployment path")?;

    if router_deployment_path.exists() {
        let deployment_content = tokio::fs::read_to_string(&router_deployment_path)
            .await
            .context("Failed to read hive-router deployment")?;

        // Parse as proper Kubernetes Deployment object
        use k8s_openapi::api::apps::v1::Deployment;

        // Split multi-document YAML file by "---" delimiter
        let documents: Vec<&str> = deployment_content
            .split("\n---\n")
            .filter(|s| !s.trim().is_empty())
            .collect();

        if documents.is_empty() {
            bail!("No YAML documents found in hive-router deployment file");
        }

        // Find and parse the Deployment document (kind: Deployment)
        let mut deployment: Option<Deployment> = None;
        let mut deployment_index = 0;

        for (idx, doc) in documents.iter().enumerate() {
            // Try to parse as a generic YAML value to check the kind
            if let Ok(value) = serde_yaml::from_str::<serde_yaml::Value>(doc) {
                if let Some(kind) = value.get("kind").and_then(|k| k.as_str()) {
                    if kind == "Deployment" {
                        // Parse as Deployment
                        deployment = Some(
                            serde_yaml::from_str(doc)
                                .context("Failed to parse Deployment document")?,
                        );
                        deployment_index = idx;
                        break;
                    }
                }
            }
        }

        let mut deployment = deployment.ok_or_else(|| {
            anyhow!("No Deployment document found in hive-router deployment file")
        })?;

        // Update supergraph.hash annotation in pod template
        if let Some(ref mut spec) = deployment.spec {
            if let Some(ref mut template) = spec.template.metadata {
                // Ensure annotations map exists
                let annotations = template.annotations.get_or_insert_with(BTreeMap::new);

                // Update the supergraph hash
                annotations.insert(
                    "supergraph.hash".to_string(),
                    supergraph_hash_short.to_string(),
                );
            }
        }

        // Serialize updated Deployment back to YAML
        let updated_deployment = serde_yaml::to_string(&deployment)
            .context("Failed to serialize updated Deployment to YAML")?;

        // Reconstruct the multi-document YAML file
        let updated_documents: Vec<String> = documents
            .iter()
            .enumerate()
            .map(|(idx, doc)| {
                if idx == deployment_index {
                    // Replace with updated deployment
                    updated_deployment.clone()
                } else {
                    // Keep original document
                    doc.to_string()
                }
            })
            .collect();

        // Join documents with YAML document separator
        let final_content = updated_documents.join("\n---\n");

        tokio::fs::write(&router_deployment_path, final_content)
            .await
            .context("Failed to write updated hive-router deployment")?;

        println!(
            "✅ Hive Router deployment updated with supergraph hash: {}",
            supergraph_hash_short
        );
    } else {
        println!(
            "⚠️  Warning: Hive Router deployment not found at: {}",
            router_deployment_path.display()
        );
    }

    // Clean up temporary config
    let _ = tokio::fs::remove_file(&config_path).await;

    // Change to repo root for git operations (CRITICAL: paths are relative to repo root)
    env::set_current_dir(&repo_root)?;

    // Commit and push supergraph changes via GitOps
    println!("📝 Committing supergraph changes...");

    // Note: git_sha was already fetched earlier for metadata generation

    // Stage federation files
    // Build relative path from repo root for git operations
    let federation_path = format!(
        "{}/{}/{}",
        deploy_config.global.paths.products_root,
        deploy_config.product.name,
        deploy_config.global.paths.federation_path
    );

    // Verify federation directory exists before staging
    if !repo_root.join(&federation_path).exists() {
        bail!("Federation directory not found at: {}", federation_path);
    }

    let git_add_status = Command::new("git")
        .args(&["add", &federation_path])
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .await
        .context("Failed to execute git add for federation files")?;

    if !git_add_status.success() {
        bail!("Failed to stage federation files at: {}", federation_path);
    }

    // Verify hive-router supergraph exists before staging
    if !hive_router_full_path.exists() {
        bail!("Hive Router supergraph not found at: {}", hive_router_path);
    }

    // Also stage the hive-router supergraph copy
    let git_add_router_status = Command::new("git")
        .args(&["add", &hive_router_path])
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .await
        .context("Failed to execute git add for hive-router supergraph")?;

    if !git_add_router_status.success() {
        bail!(
            "Failed to stage hive-router supergraph at: {}",
            hive_router_path
        );
    }

    // Also stage the hive-router deployment (contains updated supergraph hash annotation)
    let router_deployment_rel_path = paths.to_relative_string(&router_deployment_path);

    let git_add_deployment_status = Command::new("git")
        .args(&["add", &router_deployment_rel_path])
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .await
        .context("Failed to execute git add for hive-router deployment")?;

    if !git_add_deployment_status.success() {
        bail!(
            "Failed to stage hive-router deployment at: {}",
            router_deployment_rel_path
        );
    }

    // Check if there are changes to commit
    let status = Command::new("git")
        .args(&["diff", "--staged", "--quiet"])
        .status()
        .await?;

    if !status.success() {
        // There are changes to commit
        let commit_msg = format!(
            "Update {} supergraph for {} service\n\n🤖 Generated with forge",
            deploy_config.product.name, service
        );

        let commit_status = Command::new("git")
            .args(&["commit", "-m", &commit_msg])
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .await
            .context("Failed to execute git commit")?;

        if !commit_status.success() {
            bail!("Git commit failed for supergraph changes");
        }

        println!("📤 Pushing to remote...");
        let push_status = Command::new("git")
            .args(&["push", "origin", "main"])
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .await
            .context("Failed to execute git push")?;

        if !push_status.success() {
            bail!("Git push failed for supergraph changes");
        }

        println!("✅ {}", "Supergraph changes pushed to git".green());
    } else {
        // CRITICAL: If there are no changes, the supergraph is already up to date
        // This is only OK if we're re-running the same deployment
        println!("ℹ️  No supergraph changes to commit (schema unchanged)");
    }

    // Flux reconcile to apply the changes
    println!("🔄 Reconciling Flux to deploy Hive Router updates...");

    crate::commands::flux::reconcile(namespace.clone()).await?;

    println!("✅ {}", "Hive Router update triggered via GitOps".green());
    println!(
        "ℹ️  Flux will handle deployment - use 'kubectl get pods -n {}' to monitor",
        namespace
    );

    // Notify BFF to reload supergraph (if configured)
    // This provides instant propagation without waiting for file watcher polling
    if let Some(bff_url) = deploy_config
        .service
        .federation
        .as_ref()
        .and_then(|f| f.bff_admin_url.as_ref())
        .or_else(|| deploy_config.global.federation.bff_admin_url.as_ref())
    {
        println!();
        println!("🔔 {}", "Notifying BFF to reload supergraph...".bold());
        match notify_bff_supergraph_reload(bff_url).await {
            Ok(result) => {
                println!("✅ BFF supergraph reloaded successfully");
                println!("   Hash: {}", result.hash);
                println!("   Subgraphs: {}", result.subgraph_count);
            }
            Err(e) => {
                // Don't fail the release, just warn - file watcher will pick up changes eventually
                println!("⚠️  {}", format!("BFF notification failed: {}", e).yellow());
                println!("   The BFF will reload automatically via file watcher");
            }
        }
    }

    Ok(())
}

/// Response from BFF supergraph reload endpoint
#[derive(Debug, serde::Deserialize)]
pub struct BffReloadResponse {
    pub success: bool,
    pub hash: String,
    pub subgraph_count: usize,
    pub subscription_route_count: usize,
    pub source: String,
    #[serde(default)]
    pub error: Option<String>,
}

/// Notify BFF to reload supergraph via admin API
///
/// Calls POST /admin/reload-supergraph on the BFF to trigger an immediate
/// supergraph reload. This provides instant propagation without waiting
/// for the file watcher polling interval.
///
/// # Arguments
/// * `bff_url` - Base URL of the BFF (e.g., "http://web:8000" or "https://staging.example.com")
///
/// # Returns
/// * `Ok(BffReloadResponse)` - Reload result with hash and stats
/// * `Err` - If the request failed or BFF returned an error
pub async fn notify_bff_supergraph_reload(bff_url: &str) -> Result<BffReloadResponse> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .context("Failed to create HTTP client for BFF notification")?;

    let url = format!("{}/admin/reload-supergraph", bff_url.trim_end_matches('/'));

    let response = client
        .post(&url)
        .send()
        .await
        .with_context(|| format!("Failed to connect to BFF at {}", url))?;

    let status = response.status();
    let body = response
        .text()
        .await
        .context("Failed to read BFF response body")?;

    if !status.is_success() {
        bail!("BFF returned error status {}: {}", status, body);
    }

    let result: BffReloadResponse = serde_json::from_str(&body)
        .with_context(|| format!("Failed to parse BFF response: {}", body))?;

    if !result.success {
        bail!(
            "BFF reload failed: {}",
            result.error.unwrap_or_else(|| "unknown error".to_string())
        );
    }

    Ok(result)
}
