// Schema Extraction and Validation
//
// This module handles:
// 1. Running schema extraction binaries
// 2. Validating extracted schemas meet quality requirements
// 3. Detecting schema extractor binaries

use anyhow::{bail, Context, Result};
use colored::Colorize;
use std::path::{Path, PathBuf};
use tokio::fs;

use crate::config::{DeployConfig, ServiceFederationConfig};
use crate::graphql_schema::{extract_graphql_schema_named, SchemaExtractionError};

/// Result of schema extraction
pub struct SchemaExtractionResult {
    /// Path to the extracted schema file
    pub schema_path: PathBuf,

    /// Size of the schema file in bytes
    pub schema_size: u64,

    /// Number of GraphQL types found in the schema
    pub type_count: usize,

    /// List of type names found
    pub type_names: Vec<String>,
}

/// Validate and extract GraphQL schema for a service
///
/// # Steps
/// 1. Check if GraphQL is enabled for this service
/// 2. Locate schema extraction binary
/// 3. Run extraction
/// 4. Validate output
/// 5. Return schema path and metadata
///
/// # Errors
/// Returns error if:
/// - Schema extraction is required but binary not found
/// - Extraction fails
/// - Schema doesn't meet quality requirements
pub async fn extract_and_validate_schema(
    deploy_config: &DeployConfig,
) -> Result<Option<SchemaExtractionResult>> {
    let service_name = &deploy_config.service.name;
    let graphql_config = &deploy_config.service.graphql;

    // Skip if GraphQL is not enabled
    if !graphql_config.enabled {
        println!("ℹ️  GraphQL not enabled for service '{}'", service_name);
        return Ok(None);
    }

    println!(
        "📝 {}",
        format!("Extracting GraphQL schema for '{}'...", service_name).bold()
    );

    // Find schema extraction binary
    let extractor_binary = find_schema_extractor(&graphql_config.schema_extractor)
        .await
        .with_context(|| {
            format!(
                "Failed to find schema extraction binary '{}' for service '{}'.\n  \
                 Expected location: src/bin/{}.rs\n  \
                 Make sure the binary is defined in Cargo.toml [[bin]] section.",
                graphql_config.schema_extractor, service_name, graphql_config.schema_extractor
            )
        })?;

    println!("   Extractor: {}", extractor_binary.display());

    // Get service directory to run cargo from the correct location
    let service_dir =
        std::env::var("SERVICE_DIR").context("SERVICE_DIR environment variable not set")?;
    let service_dir_path = PathBuf::from(&service_dir);

    // Route through the canonical `extract_graphql_schema_named`
    // primitive — the one-oracle owner of the "run cargo run --bin
    // <name> --quiet in a backend dir, expect non-empty stdout bytes,
    // fail typed on every failure shape" surface (THEORY §V.1, §VI.1).
    // Pre-lift the four sibling sites in codegen* had already been
    // absorbed by the primitive's fixed-bin-name entry (673e4be); this
    // fifth site is the one that survived because it reads a runtime-
    // configured bin name (`graphql_config.schema_extractor`) off the
    // deploy config. The `_named` entry serves it. Load-bearing
    // properties recovered here:
    //
    //   - `CARGO` env override honored (pre-lift `Command::new("cargo")`
    //     bypassed the env-var discipline `commands/bootstrap.rs` uses).
    //   - `bin_name` carried in every failure record (pre-lift, the
    //     `bail!` interpolated it into free-form prose).
    //   - `service_dir` carried in every failure record (pre-lift, only
    //     the spawn-failure `with_context` had it; the two `bail!`s
    //     dropped it).
    //
    // NOTE: All services must use pure Rust dependencies (e.g., rustls
    // instead of OpenSSL) to ensure schema extraction works without
    // system library dependencies.
    let output_stdout =
        match extract_graphql_schema_named(&service_dir_path, &graphql_config.schema_extractor)
            .await
        {
            Ok(bytes) => bytes,
            Err(SchemaExtractionError::SpawnFailed {
                backend_dir,
                bin_name,
                message,
            }) => bail!(
            "Failed to run schema extraction binary '{}' for service '{}' from directory '{}': {}",
            bin_name,
            service_name,
            backend_dir.display(),
            message,
        ),
            Err(SchemaExtractionError::Failed {
                bin_name,
                exit_code,
                stderr,
                ..
            }) => bail!(
                "Schema extraction failed for service '{}' (bin '{}', exit {:?}):\n{}",
                service_name,
                bin_name,
                exit_code,
                stderr,
            ),
            Err(SchemaExtractionError::EmptyOutput { bin_name, .. }) => bail!(
                "Schema extraction produced no output for service '{}'. \
                 Check that '{}' binary prints schema to stdout.",
                service_name,
                bin_name,
            ),
        };

    // Get subgraph schema path from config
    let schema_path = deploy_config
        .subgraph_schema_path()
        .context("Failed to compute subgraph schema path from config")?;

    // Create parent directory if it doesn't exist
    if let Some(parent) = schema_path.parent() {
        fs::create_dir_all(parent).await.with_context(|| {
            format!("Failed to create subgraph directory: {}", parent.display())
        })?;
    }

    fs::write(&schema_path, &output_stdout)
        .await
        .with_context(|| {
            format!(
                "Failed to write extracted schema to {}",
                schema_path.display()
            )
        })?;

    println!("   ✅ Schema written: {}", schema_path.display());

    // Validate schema
    let validation_result = validate_schema_content(&output_stdout, graphql_config, service_name)?;

    println!("   📊 Schema size: {} bytes", validation_result.schema_size);
    println!("   📊 Types found: {}", validation_result.type_count);

    // Validate minimum size requirement
    if validation_result.schema_size < graphql_config.min_schema_size {
        bail!(
            "Schema for service '{}' is too small: {} bytes (minimum: {} bytes).\n  \
             This may indicate an incomplete schema extraction.\n  \
             Expected types: Query, Mutation, service-specific types",
            service_name,
            validation_result.schema_size,
            graphql_config.min_schema_size
        );
    }

    // Validate expected types if configured
    if !graphql_config.expected_types.is_empty() {
        let missing_types: Vec<&String> = graphql_config
            .expected_types
            .iter()
            .filter(|expected| !validation_result.type_names.contains(expected))
            .collect();

        if !missing_types.is_empty() {
            bail!(
                "Schema for service '{}' is missing expected types: {}\n  \
                 Found types: {}\n  \
                 Check that your schema defines all required types.",
                service_name,
                missing_types
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
                validation_result.type_names.join(", ")
            );
        }

        println!(
            "   ✅ All expected types present: {}",
            graphql_config.expected_types.join(", ")
        );
    }

    println!("✅ {}", "Schema extraction and validation complete".green());

    Ok(Some(SchemaExtractionResult {
        schema_path,
        schema_size: validation_result.schema_size,
        type_count: validation_result.type_count,
        type_names: validation_result.type_names,
    }))
}

/// Find schema extraction binary in src/bin/
async fn find_schema_extractor(binary_name: &str) -> Result<PathBuf> {
    // Get service directory from environment (set by CLI --service-dir)
    let service_dir =
        std::env::var("SERVICE_DIR").context("SERVICE_DIR environment variable not set")?;
    let service_path = PathBuf::from(service_dir);

    // Check common locations relative to service directory
    let candidates = vec![
        format!("src/bin/{}.rs", binary_name),
        format!("src/bin/{}.rs", binary_name.replace('-', "_")),
        format!("src/bin/{}.rs", binary_name.replace('_', "-")),
    ];

    for candidate in &candidates {
        let path = service_path.join(candidate);
        if path.exists() {
            return Ok(path);
        }
    }

    bail!(
        "Schema extraction binary '{}' not found in {}. Tried:\n  {}",
        binary_name,
        service_path.display(),
        candidates.join("\n  ")
    );
}

struct ValidationResult {
    schema_size: u64,
    type_count: usize,
    type_names: Vec<String>,
}

/// Validate extracted schema content
fn validate_schema_content(
    schema_bytes: &[u8],
    _config: &ServiceFederationConfig,
    _service_name: &str,
) -> Result<ValidationResult> {
    let schema_text = String::from_utf8_lossy(schema_bytes);

    // Count GraphQL type definitions
    let mut type_names = Vec::new();

    for line in schema_text.lines() {
        let trimmed = line.trim();

        // Match type definitions
        if let Some(type_name) = extract_type_name(trimmed, "type ") {
            type_names.push(type_name);
        } else if let Some(type_name) = extract_type_name(trimmed, "input ") {
            type_names.push(type_name);
        } else if let Some(type_name) = extract_type_name(trimmed, "enum ") {
            type_names.push(type_name);
        } else if let Some(type_name) = extract_type_name(trimmed, "interface ") {
            type_names.push(type_name);
        } else if let Some(type_name) = extract_type_name(trimmed, "scalar ") {
            type_names.push(type_name);
        } else if let Some(type_name) = extract_type_name(trimmed, "union ") {
            type_names.push(type_name);
        }
    }

    Ok(ValidationResult {
        schema_size: schema_bytes.len() as u64,
        type_count: type_names.len(),
        type_names,
    })
}

/// Extract type name from a GraphQL type definition line
fn extract_type_name(line: &str, keyword: &str) -> Option<String> {
    if !line.starts_with(keyword) {
        return None;
    }

    let after_keyword = &line[keyword.len()..];
    let name = after_keyword
        .split_whitespace()
        .next()?
        .split('{')
        .next()?
        .split('(')
        .next()?
        .trim();

    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_type_name() {
        assert_eq!(
            extract_type_name("type User {", "type "),
            Some("User".to_string())
        );
        assert_eq!(
            extract_type_name("input CreateUserInput {", "input "),
            Some("CreateUserInput".to_string())
        );
        assert_eq!(
            extract_type_name("enum Role {", "enum "),
            Some("Role".to_string())
        );
        assert_eq!(
            extract_type_name("scalar DateTime", "scalar "),
            Some("DateTime".to_string())
        );
        assert_eq!(
            extract_type_name("  type Query implements Node {", "type "),
            None // doesn't start with "type "
        );
    }

    #[test]
    fn test_validate_schema_content() {
        let schema = br#"
            type Query {
                hello: String!
            }

            type Mutation {
                createUser(input: CreateUserInput!): User!
            }

            input CreateUserInput {
                name: String!
            }

            type User {
                id: ID!
                name: String!
            }

            enum Role {
                ADMIN
                USER
            }

            scalar DateTime
        "#;

        let config = ServiceFederationConfig::default();
        let result = validate_schema_content(schema, &config, "test").unwrap();

        assert_eq!(result.type_count, 6); // Query, Mutation, CreateUserInput, User, Role, DateTime
        assert!(result.type_names.contains(&"Query".to_string()));
        assert!(result.type_names.contains(&"Mutation".to_string()));
        assert!(result.type_names.contains(&"User".to_string()));
    }
}
