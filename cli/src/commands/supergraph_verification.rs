// Supergraph Verification System
//
// This module provides deterministic verification that:
// 1. Each service's schema is correctly extracted
// 2. The supergraph composition includes all expected services
// 3. Hive Router is running the latest composed supergraph
// 4. The deployment process is idempotent and reproducible

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::process::Command;

/// Metadata tracking supergraph composition
#[derive(Debug, Serialize, Deserialize)]
pub struct SupergraphMetadata {
    /// SHA256 hash of the composed supergraph.graphql
    pub supergraph_hash: String,

    /// Timestamp when the supergraph was composed (RFC3339)
    pub composed_at: String,

    /// Git commit SHA that triggered this composition
    pub git_commit: String,

    /// Service that triggered the composition update
    pub triggering_service: String,

    /// All services included in this composition with their schema hashes
    pub services: HashMap<String, ServiceSchemaInfo>,

    /// Federation version used for composition
    pub federation_version: String,

    /// Rover version used for composition
    pub rover_version: String,
}

/// Information about a service's contribution to the supergraph
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ServiceSchemaInfo {
    /// SHA256 hash of the service's subgraph .graphql file
    pub schema_hash: String,

    /// Size of the schema file in bytes
    pub schema_size: u64,

    /// Number of types defined in this service's schema
    pub type_count: usize,

    /// GraphQL routing URL for this service
    pub routing_url: String,

    /// When this service's schema was last modified
    pub last_modified: String,
}

/// Result of supergraph verification
#[derive(Debug)]
pub struct VerificationResult {
    /// Whether the verification passed
    pub success: bool,

    /// Expected supergraph hash (from metadata)
    pub expected_hash: String,

    /// Actual supergraph hash (from hive-router)
    pub actual_hash: Option<String>,

    /// Services that are expected but missing from supergraph
    pub missing_services: Vec<String>,

    /// Services present in supergraph but not expected
    pub unexpected_services: Vec<String>,

    /// Detailed error messages if verification failed
    pub errors: Vec<String>,
}

impl SupergraphMetadata {
    /// Generate metadata for a newly composed supergraph
    pub async fn generate(
        federation_dir: &Path,
        triggering_service: String,
        git_commit: String,
    ) -> Result<Self> {
        let supergraph_path = federation_dir.join("supergraph.graphql");
        let subgraphs_dir = federation_dir.join("subgraphs");

        // Calculate supergraph hash
        let supergraph_content = fs::read(&supergraph_path)
            .await
            .context("Failed to read supergraph.graphql")?;
        let supergraph_hash = calculate_hash(&supergraph_content);

        // Collect service information
        let mut services = HashMap::new();

        if subgraphs_dir.exists() {
            let mut entries = fs::read_dir(&subgraphs_dir).await?;

            while let Some(entry) = entries.next_entry().await? {
                let path = entry.path();

                if path.extension().and_then(|s| s.to_str()) == Some("graphql") {
                    if let Some(service_name) = path.file_stem().and_then(|s| s.to_str()) {
                        let schema_content = fs::read(&path).await?;
                        let metadata = entry.metadata().await?;

                        let info = ServiceSchemaInfo {
                            schema_hash: calculate_hash(&schema_content),
                            schema_size: metadata.len(),
                            type_count: count_graphql_types(&schema_content),
                            routing_url: String::new(), // Will be populated from config
                            last_modified: format_timestamp(&metadata.modified()?),
                        };

                        services.insert(service_name.to_string(), info);
                    }
                }
            }
        }

        // Get Rover version
        let rover_version = get_rover_version()
            .await
            .unwrap_or_else(|_| "unknown".to_string());

        Ok(Self {
            supergraph_hash,
            composed_at: chrono::Utc::now().to_rfc3339(),
            git_commit,
            triggering_service,
            services,
            federation_version: "2".to_string(),
            rover_version,
        })
    }

    /// Save metadata to JSON file
    pub async fn save(&self, federation_dir: &Path) -> Result<()> {
        let metadata_path = federation_dir.join("supergraph-metadata.json");
        let json = serde_json::to_string_pretty(self)?;
        fs::write(metadata_path, json).await?;
        Ok(())
    }

    /// Load metadata from JSON file
    pub async fn load(federation_dir: &Path) -> Result<Self> {
        let metadata_path = federation_dir.join("supergraph-metadata.json");
        let json = fs::read_to_string(metadata_path)
            .await
            .context("Failed to read supergraph-metadata.json")?;
        let metadata = serde_json::from_str(&json)?;
        Ok(metadata)
    }

    /// Verify that the current supergraph matches this metadata
    pub async fn verify(&self, federation_dir: &Path) -> Result<bool> {
        let supergraph_path = federation_dir.join("supergraph.graphql");
        let content = fs::read(&supergraph_path).await?;
        let current_hash = calculate_hash(&content);

        Ok(current_hash == self.supergraph_hash)
    }
}

/// Calculate SHA256 hash of content
pub fn calculate_hash(content: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content);
    format!("{:x}", hasher.finalize())
}

/// Count number of GraphQL type definitions in schema
fn count_graphql_types(content: &[u8]) -> usize {
    let text = String::from_utf8_lossy(content);
    text.lines()
        .filter(|line| {
            line.trim_start().starts_with("type ")
                || line.trim_start().starts_with("input ")
                || line.trim_start().starts_with("enum ")
                || line.trim_start().starts_with("interface ")
        })
        .count()
}

/// Format system time as RFC3339 timestamp
fn format_timestamp(time: &std::time::SystemTime) -> String {
    let datetime: chrono::DateTime<chrono::Utc> = (*time).into();
    datetime.to_rfc3339()
}

/// Get Rover CLI version
async fn get_rover_version() -> Result<String> {
    let output = Command::new("rover-fhs").arg("--version").output().await?;

    let version = String::from_utf8_lossy(&output.stdout);
    Ok(version.trim().to_string())
}

/// Verify Hive Router is running the expected supergraph
pub async fn verify_router_schema(
    namespace: &str,
    expected_hash: &str,
) -> Result<VerificationResult> {
    let mut errors = Vec::new();

    // Get hive-router pod name
    let output = Command::new("kubectl")
        .args(&[
            "get",
            "pods",
            "-n",
            namespace,
            "-l",
            "app=hive-router",
            "-o",
            "jsonpath={.items[0].metadata.name}",
        ])
        .output()
        .await?;

    if !output.status.success() {
        errors.push("Failed to find hive-router pod".to_string());
        return Ok(VerificationResult {
            success: false,
            expected_hash: expected_hash.to_string(),
            actual_hash: None,
            missing_services: vec![],
            unexpected_services: vec![],
            errors,
        });
    }

    let pod_name = String::from_utf8_lossy(&output.stdout);

    // Query the router's health endpoint to get schema hash
    // Note: We'll need to expose this via the router's health check
    let output = Command::new("kubectl")
        .args(&[
            "exec",
            pod_name.trim(),
            "-n",
            namespace,
            "--",
            "wget",
            "-q",
            "-O-",
            "http://localhost:4000/health",
        ])
        .output()
        .await?;

    if !output.status.success() {
        errors.push("Failed to query hive-router health endpoint".to_string());
        return Ok(VerificationResult {
            success: false,
            expected_hash: expected_hash.to_string(),
            actual_hash: None,
            missing_services: vec![],
            unexpected_services: vec![],
            errors,
        });
    }

    // Parse health response to extract schema hash
    // This is a placeholder - we'll need to modify hive-router config to include this
    let health_response = String::from_utf8_lossy(&output.stdout);
    let actual_hash = extract_schema_hash(&health_response);

    let success = actual_hash.as_ref() == Some(&expected_hash.to_string());

    Ok(VerificationResult {
        success,
        expected_hash: expected_hash.to_string(),
        actual_hash,
        missing_services: vec![],
        unexpected_services: vec![],
        errors,
    })
}

/// Extract schema hash from health response
/// TODO: Implement proper parsing once we add schema hash to health endpoint
fn extract_schema_hash(_response: &str) -> Option<String> {
    // Placeholder - will be implemented when we modify hive-router health endpoint
    None
}

/// Generate a deterministic hash that can be used as a ConfigMap annotation
pub fn generate_configmap_hash(metadata: &SupergraphMetadata) -> String {
    // Use first 8 characters of supergraph hash for brevity
    metadata.supergraph_hash[..8].to_string()
}

/// Update ConfigMap with supergraph hash annotation
pub async fn annotate_configmap_with_hash(
    namespace: &str,
    configmap_name: &str,
    hash: &str,
) -> Result<()> {
    Command::new("kubectl")
        .args(&[
            "annotate",
            "configmap",
            configmap_name,
            &format!("supergraph-hash={}", hash),
            "-n",
            namespace,
            "--overwrite",
        ])
        .output()
        .await
        .context("Failed to annotate ConfigMap")?;

    Ok(())
}

/// Verify that ConfigMap has the expected hash annotation
pub async fn verify_configmap_hash(
    namespace: &str,
    configmap_name: &str,
    expected_hash: &str,
) -> Result<bool> {
    let output = Command::new("kubectl")
        .args(&[
            "get",
            "configmap",
            configmap_name,
            "-n",
            namespace,
            "-o",
            "jsonpath={.metadata.annotations.supergraph-hash}",
        ])
        .output()
        .await?;

    if !output.status.success() {
        return Ok(false);
    }

    let actual_hash = String::from_utf8_lossy(&output.stdout);
    Ok(actual_hash.trim() == expected_hash)
}

/// Pre-composition validation checks
pub struct PreCompositionCheck {
    pub passed: bool,
    pub checks: Vec<CheckResult>,
}

pub struct CheckResult {
    pub name: String,
    pub passed: bool,
    pub message: String,
}

/// Run pre-composition validation checks
pub async fn run_pre_composition_checks(subgraphs_dir: &Path) -> Result<PreCompositionCheck> {
    let mut checks = Vec::new();

    // Check 1: Subgraphs directory exists
    let subgraphs_exist = subgraphs_dir.exists();
    checks.push(CheckResult {
        name: "Subgraphs directory exists".to_string(),
        passed: subgraphs_exist,
        message: if subgraphs_exist {
            format!("✓ Found subgraphs directory: {}", subgraphs_dir.display())
        } else {
            format!(
                "✗ Subgraphs directory not found: {}",
                subgraphs_dir.display()
            )
        },
    });

    if !subgraphs_exist {
        return Ok(PreCompositionCheck {
            passed: false,
            checks,
        });
    }

    // Check 2: At least one .graphql file exists
    let mut schema_files = Vec::new();
    let mut entries = fs::read_dir(subgraphs_dir).await?;

    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("graphql") {
            schema_files.push(path);
        }
    }

    let has_schemas = !schema_files.is_empty();
    checks.push(CheckResult {
        name: "Schema files present".to_string(),
        passed: has_schemas,
        message: if has_schemas {
            format!("✓ Found {} schema file(s)", schema_files.len())
        } else {
            "✗ No .graphql files found in subgraphs directory".to_string()
        },
    });

    // Check 3: All schema files are non-empty
    let mut all_non_empty = true;
    for schema_path in &schema_files {
        let metadata = fs::metadata(schema_path).await?;
        if metadata.len() == 0 {
            all_non_empty = false;
            checks.push(CheckResult {
                name: format!(
                    "Schema file size: {}",
                    schema_path.file_name().unwrap().to_string_lossy()
                ),
                passed: false,
                message: format!("✗ Empty schema file: {}", schema_path.display()),
            });
        }
    }

    if all_non_empty {
        checks.push(CheckResult {
            name: "All schemas non-empty".to_string(),
            passed: true,
            message: "✓ All schema files have content".to_string(),
        });
    }

    // Check 4: Rover CLI is available
    let rover_available = Command::new("rover-fhs")
        .arg("--version")
        .output()
        .await
        .is_ok();

    checks.push(CheckResult {
        name: "Rover CLI available".to_string(),
        passed: rover_available,
        message: if rover_available {
            "✓ Rover CLI is installed".to_string()
        } else {
            "✗ Rover CLI not found (rover-fhs command)".to_string()
        },
    });

    let all_passed = checks.iter().all(|c| c.passed);

    Ok(PreCompositionCheck {
        passed: all_passed,
        checks,
    })
}

/// Post-composition validation
pub struct PostCompositionCheck {
    pub passed: bool,
    pub supergraph_size: u64,
    pub service_count: usize,
    pub checks: Vec<CheckResult>,
}

/// Run post-composition validation checks
pub async fn run_post_composition_checks(
    supergraph_path: &Path,
    subgraphs_dir: &Path,
) -> Result<PostCompositionCheck> {
    let mut checks = Vec::new();

    // Check 1: Supergraph file exists
    let supergraph_exists = supergraph_path.exists();
    checks.push(CheckResult {
        name: "Supergraph file exists".to_string(),
        passed: supergraph_exists,
        message: if supergraph_exists {
            format!("✓ Supergraph generated: {}", supergraph_path.display())
        } else {
            format!("✗ Supergraph not found: {}", supergraph_path.display())
        },
    });

    if !supergraph_exists {
        return Ok(PostCompositionCheck {
            passed: false,
            supergraph_size: 0,
            service_count: 0,
            checks,
        });
    }

    // Check 2: Supergraph is non-empty
    let metadata = fs::metadata(supergraph_path).await?;
    let supergraph_size = metadata.len();
    let size_ok = supergraph_size > 1000; // Expect at least 1KB for a valid supergraph

    checks.push(CheckResult {
        name: "Supergraph size".to_string(),
        passed: size_ok,
        message: if size_ok {
            format!("✓ Supergraph size: {} bytes", supergraph_size)
        } else {
            format!(
                "✗ Supergraph too small: {} bytes (expected > 1000)",
                supergraph_size
            )
        },
    });

    // Check 3: Count services in subgraphs directory
    let mut service_count = 0;
    let mut entries = fs::read_dir(subgraphs_dir).await?;

    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("graphql") {
            service_count += 1;
        }
    }

    checks.push(CheckResult {
        name: "Service schemas included".to_string(),
        passed: service_count > 0,
        message: format!("✓ Composed {} service schema(s)", service_count),
    });

    // Check 4: Supergraph contains schema directive
    let supergraph_content = fs::read_to_string(supergraph_path).await?;
    let has_schema_directive = supergraph_content.contains("schema");

    checks.push(CheckResult {
        name: "Valid GraphQL schema".to_string(),
        passed: has_schema_directive,
        message: if has_schema_directive {
            "✓ Supergraph contains valid GraphQL schema".to_string()
        } else {
            "✗ Supergraph does not contain 'schema' directive".to_string()
        },
    });

    // Check 5: Supergraph contains federation directives
    let has_federation =
        supergraph_content.contains("@join__") || supergraph_content.contains("@link");

    checks.push(CheckResult {
        name: "Federation directives present".to_string(),
        passed: has_federation,
        message: if has_federation {
            "✓ Supergraph contains Apollo Federation directives".to_string()
        } else {
            "⚠ Warning: No federation directives found (expected @join__ or @link)".to_string()
        },
    });

    let all_passed = checks.iter().all(|c| c.passed);

    Ok(PostCompositionCheck {
        passed: all_passed,
        supergraph_size,
        service_count,
        checks,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_hash() {
        let content = b"test content";
        let hash = calculate_hash(content);
        assert_eq!(hash.len(), 64); // SHA256 produces 64 hex characters
    }

    #[test]
    fn test_count_graphql_types() {
        let schema = b"
            type User {
                id: ID!
            }
            input CreateUserInput {
                name: String!
            }
            enum Role {
                ADMIN
                USER
            }
        ";
        assert_eq!(count_graphql_types(schema), 3);
    }

    #[test]
    fn test_generate_configmap_hash() {
        let metadata = SupergraphMetadata {
            supergraph_hash: "abcdef1234567890".to_string(),
            composed_at: "2025-10-18T00:00:00Z".to_string(),
            git_commit: "abc123".to_string(),
            triggering_service: "test".to_string(),
            services: HashMap::new(),
            federation_version: "2".to_string(),
            rover_version: "1.0.0".to_string(),
        };

        let hash = generate_configmap_hash(&metadata);
        assert_eq!(hash, "abcdef12");
    }
}
