//! ReBAC Validation
//!
//! Validates that Redis Tuple Store relations match SeaORM entity definitions.
//! Ensures permission engine configuration stays in sync with database schema.
//!
//! Usage:
//!   forge rebac-validate --working-dir /path/to/product
//!   forge rebac-validate --working-dir /path/to/product --check-redis
//!   forge rebac-validate --working-dir /path/to/product --quiet

use anyhow::{Context, Result};
use colored::Colorize;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::process::Command;

/// Configuration for ReBAC validation
#[derive(Debug, Clone)]
pub struct RebacValidationConfig {
    /// Working directory (root of product)
    pub working_dir: PathBuf,
    /// Backend service directory (None = not configured, checks will be skipped)
    pub backend_dir: Option<PathBuf>,
    /// Docs architecture directory (None = not configured, checks will be skipped)
    pub docs_dir: Option<PathBuf>,
    /// Web directory (None = not configured, checks will be skipped)
    pub web_dir: Option<PathBuf>,
    /// Quiet mode
    pub quiet: bool,
    /// Check Redis connectivity
    pub check_redis: bool,
    /// Redis key prefix for ReBAC keys (e.g., "myapp" → "myapp:rel:*")
    pub redis_key_prefix: String,
}

impl RebacValidationConfig {
    pub fn from_product(
        working_dir: &Path,
        quiet: bool,
        check_redis: bool,
        product: &crate::config::ProductConfig,
    ) -> Self {
        Self {
            working_dir: working_dir.to_path_buf(),
            backend_dir: product.backend_dir(working_dir),
            docs_dir: product.docs_arch_dir(working_dir),
            web_dir: product.web_dir(working_dir),
            quiet,
            check_redis,
            redis_key_prefix: product.redis_key_prefix().to_string(),
        }
    }
}

/// Result of ReBAC validation
#[derive(Debug, Default)]
pub struct RebacValidationResult {
    /// Number of errors found
    pub errors: usize,
    /// Number of warnings found
    pub warnings: usize,
    /// Detailed messages
    pub messages: Vec<ValidationMessage>,
}

impl RebacValidationResult {
    pub fn all_passed(&self) -> bool {
        self.errors == 0
    }
}

#[derive(Debug)]
pub struct ValidationMessage {
    pub level: ValidationLevel,
    pub check: String,
    pub message: String,
}

#[derive(Debug, PartialEq)]
pub enum ValidationLevel {
    Success,
    Warning,
    Error,
}

/// Execute ReBAC validation
pub async fn execute(working_dir: &Path, quiet: bool) -> Result<RebacValidationResult> {
    execute_with_options(working_dir, quiet, false).await
}

/// Execute ReBAC validation with full options
pub async fn execute_with_options(
    working_dir: &Path,
    quiet: bool,
    check_redis: bool,
) -> Result<RebacValidationResult> {
    let product = crate::config::load_product_config_from_dir(working_dir)?;
    let config = RebacValidationConfig::from_product(working_dir, quiet, check_redis, &product);
    let mut result = RebacValidationResult::default();

    if !quiet {
        println!();
        println!(
            "{}",
            "════════════════════════════════════════════════".bold()
        );
        println!("{}", "  ReBAC Validation".bold());
        println!(
            "{}",
            "════════════════════════════════════════════════".bold()
        );
        println!();
    }

    // Check 1: Verify ReBAC documentation exists
    check_rebac_documentation(&config, &mut result).await?;

    // Check 2: Verify permission engine source files
    check_permission_engine_files(&config, &mut result).await?;

    // Check 3: Validate object types match SeaORM entities
    check_object_type_mapping(&config, &mut result).await?;

    // Check 4: Validate relation hierarchy consistency
    check_relation_hierarchy(&config, &mut result).await?;

    // Check 5: Validate Redis key patterns
    check_redis_key_patterns(&config, &mut result).await?;

    // Check 6: Redis connectivity (optional)
    if check_redis {
        check_redis_connectivity(&config, &mut result).await?;
    }

    // Check 7: GraphQL permission operations
    check_graphql_operations(&config, &mut result).await?;

    // Print summary
    if !quiet {
        println!();
        println!(
            "{}",
            "════════════════════════════════════════════════".bold()
        );

        if result.all_passed() && result.warnings == 0 {
            println!("{}", "  All ReBAC validations passed".green().bold());
        } else if result.all_passed() {
            println!(
                "{}",
                format!("  Validation complete with {} warning(s)", result.warnings)
                    .yellow()
                    .bold()
            );
        } else {
            println!(
                "{}",
                format!(
                    "  Validation failed: {} error(s), {} warning(s)",
                    result.errors, result.warnings
                )
                .red()
                .bold()
            );
        }
        println!(
            "{}",
            "════════════════════════════════════════════════".bold()
        );
    }

    Ok(result)
}

/// Check 1: ReBAC documentation exists
async fn check_rebac_documentation(
    config: &RebacValidationConfig,
    result: &mut RebacValidationResult,
) -> Result<()> {
    if !config.quiet {
        println!("{}", "Check 1: ReBAC Documentation".blue());
    }

    let Some(docs_dir) = &config.docs_dir else {
        if !config.quiet {
            println!("   (skipped — docs_arch dir not configured)");
        }
        return Ok(());
    };

    let rebac_doc = docs_dir.join("security-rebac.md");

    if rebac_doc.exists() {
        log_success(
            config,
            result,
            "ReBAC Documentation",
            "security-rebac.md exists",
        );
    } else {
        log_error(
            config,
            result,
            "ReBAC Documentation",
            &format!("security-rebac.md not found at {}", rebac_doc.display()),
        );
    }

    Ok(())
}

/// Check 2: Permission engine source files
async fn check_permission_engine_files(
    config: &RebacValidationConfig,
    result: &mut RebacValidationResult,
) -> Result<()> {
    if !config.quiet {
        println!();
        println!("{}", "Check 2: Permission Engine Source Files".blue());
    }

    let Some(backend_dir) = &config.backend_dir else {
        if !config.quiet {
            println!("   (skipped — backend dir not configured)");
        }
        return Ok(());
    };

    let expected_files = ["src/auth/mod.rs", "src/auth/permission_engine.rs"];

    for file in &expected_files {
        let path = backend_dir.join(file);
        if path.exists() {
            log_success(config, result, "Permission Engine", file);
        } else {
            log_warning(
                config,
                result,
                "Permission Engine",
                &format!("Missing: {} (expected for full ReBAC implementation)", file),
            );
        }
    }

    Ok(())
}

/// Check 3: Object type → Entity mapping
async fn check_object_type_mapping(
    config: &RebacValidationConfig,
    result: &mut RebacValidationResult,
) -> Result<()> {
    if !config.quiet {
        println!();
        println!("{}", "Check 3: Object Type → Entity Mapping".blue());
    }

    let (Some(docs_dir), Some(backend_dir)) = (&config.docs_dir, &config.backend_dir) else {
        if !config.quiet {
            println!("   (skipped — docs_arch and/or backend dir not configured)");
        }
        return Ok(());
    };

    let rebac_doc = docs_dir.join("security-rebac.md");
    if !rebac_doc.exists() {
        return Ok(());
    }

    let content = fs::read_to_string(&rebac_doc).await?;

    // Extract object types from documentation
    // Look for patterns like ("ritual", "viewer") or ("provider_profile", "editor")
    let mut object_types: HashSet<String> = HashSet::new();
    for line in content.lines() {
        // Match pattern: ("object_type", "relation")
        if let Some(start) = line.find("(\"") {
            if let Some(end) = line[start + 2..].find("\",") {
                let obj_type = &line[start + 2..start + 2 + end];
                if !obj_type.is_empty() && obj_type.chars().all(|c| c.is_alphanumeric() || c == '_')
                {
                    object_types.insert(obj_type.to_string());
                }
            }
        }
    }

    // Check each object type has a corresponding entity
    let entities_dir = backend_dir.join("src/entities");
    let example_types: HashSet<String> = ["dog", "ritual"].iter().map(|s| s.to_string()).collect();

    let mut mapped = 0;
    let mut unmapped = 0;

    for object_type in &object_types {
        let entity_file = entities_dir.join(format!("{}.rs", object_type));

        if entity_file.exists() {
            log_success(
                config,
                result,
                "Object Type Mapping",
                &format!("{} → entities/{}.rs", object_type, object_type),
            );
            mapped += 1;
        } else if example_types.contains(object_type) {
            if !config.quiet {
                println!(
                    "   {} {} (example type, no entity required)",
                    "○".yellow(),
                    object_type
                );
            }
        } else {
            log_warning(
                config,
                result,
                "Object Type Mapping",
                &format!("Object type '{}' has no matching entity", object_type),
            );
            unmapped += 1;
        }
    }

    if !config.quiet {
        println!();
        println!("   Mapped: {}, Unmapped warnings: {}", mapped, unmapped);
    }

    Ok(())
}

/// Check 4: Relation hierarchy consistency
async fn check_relation_hierarchy(
    config: &RebacValidationConfig,
    result: &mut RebacValidationResult,
) -> Result<()> {
    if !config.quiet {
        println!();
        println!("{}", "Check 4: Relation Hierarchy Consistency".blue());
    }

    let Some(backend_dir) = &config.backend_dir else {
        if !config.quiet {
            println!("   (skipped — backend dir not configured)");
        }
        return Ok(());
    };

    // Check for get_implied_relations function in permission engine files
    let potential_files = [
        backend_dir.join("src/auth/permission_engine.rs"),
        backend_dir.join("src/auth/redis_permission_engine.rs"),
    ];

    for impl_file in &potential_files {
        if !impl_file.exists() {
            continue;
        }

        let content = fs::read_to_string(impl_file).await?;

        if content.contains("get_implied_relations") {
            log_success(
                config,
                result,
                "Relation Hierarchy",
                &format!(
                    "Found get_implied_relations in {}",
                    impl_file.file_name().unwrap().to_string_lossy()
                ),
            );

            // Check for standard hierarchies
            if content.contains("editor") && content.contains("owner") {
                log_success(
                    config,
                    result,
                    "Relation Hierarchy",
                    "editor → owner hierarchy defined",
                );
            }

            if content.contains("viewer") && content.contains("editor") {
                log_success(
                    config,
                    result,
                    "Relation Hierarchy",
                    "viewer → editor hierarchy defined",
                );
            }

            break;
        }
    }

    // Check documentation
    if let Some(docs_dir) = &config.docs_dir {
        let rebac_doc = docs_dir.join("security-rebac.md");
        if rebac_doc.exists() {
            let content = fs::read_to_string(&rebac_doc).await?;
            if content.contains("owner → editor → viewer") || content.contains("owner → editor") {
                log_success(
                    config,
                    result,
                    "Relation Hierarchy",
                    "Standard permission hierarchy documented",
                );
            } else {
                log_warning(
                    config,
                    result,
                    "Relation Hierarchy",
                    "Standard hierarchy (owner → editor → viewer) not clearly documented",
                );
            }
        }
    }

    Ok(())
}

/// Check 5: Redis key patterns
async fn check_redis_key_patterns(
    config: &RebacValidationConfig,
    result: &mut RebacValidationResult,
) -> Result<()> {
    if !config.quiet {
        println!();
        println!("{}", "Check 5: Redis Key Pattern Validation".blue());
    }

    let Some(docs_dir) = &config.docs_dir else {
        if !config.quiet {
            println!("   (skipped — docs_arch dir not configured)");
        }
        return Ok(());
    };

    let rebac_doc = docs_dir.join("security-rebac.md");
    if !rebac_doc.exists() {
        return Ok(());
    }

    let content = fs::read_to_string(&rebac_doc).await?;

    let prefix = &config.redis_key_prefix;
    let rel_pattern = format!("{}:rel:", prefix);
    let rel_reverse_pattern = format!("{}:rel:reverse:", prefix);
    let perm_pattern = format!("{}:perm:", prefix);
    let key_patterns = [
        (rel_pattern.as_str(), "Forward lookup pattern"),
        (rel_reverse_pattern.as_str(), "Reverse lookup pattern"),
        (perm_pattern.as_str(), "Permission cache pattern"),
    ];

    for (pattern, description) in &key_patterns {
        if content.contains(pattern) {
            log_success(
                config,
                result,
                "Redis Key Patterns",
                &format!("{} documented", description),
            );
        } else {
            log_warning(
                config,
                result,
                "Redis Key Patterns",
                &format!("{} not documented: {}", description, pattern),
            );
        }
    }

    Ok(())
}

/// Check 6: Redis connectivity (optional)
async fn check_redis_connectivity(
    config: &RebacValidationConfig,
    result: &mut RebacValidationResult,
) -> Result<()> {
    if !config.quiet {
        println!();
        println!("{}", "Check 6: Redis Connectivity".blue());
    }

    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".to_string());

    // Try to ping Redis
    let output = Command::new("redis-cli")
        .args(["-u", &redis_url, "ping"])
        .output()
        .await;

    match output {
        Ok(out) if out.status.success() => {
            log_success(
                config,
                result,
                "Redis Connectivity",
                "Connection successful",
            );

            // Count keys
            let rel_glob = format!("{}:rel:*", config.redis_key_prefix);
            let keys_output = Command::new("redis-cli")
                .args(["-u", &redis_url, "KEYS", &rel_glob])
                .output()
                .await;

            if let Ok(keys) = keys_output {
                let key_count = String::from_utf8_lossy(&keys.stdout)
                    .lines()
                    .filter(|l| !l.is_empty())
                    .count();
                if !config.quiet {
                    println!("   Found {} relation keys", key_count);
                }
            }

            let perm_glob = format!("{}:perm:*", config.redis_key_prefix);
            let perm_output = Command::new("redis-cli")
                .args(["-u", &redis_url, "KEYS", &perm_glob])
                .output()
                .await;

            if let Ok(keys) = perm_output {
                let key_count = String::from_utf8_lossy(&keys.stdout)
                    .lines()
                    .filter(|l| !l.is_empty())
                    .count();
                if !config.quiet {
                    println!("   Found {} permission cache keys", key_count);
                }
            }
        }
        Ok(_) => {
            log_warning(
                config,
                result,
                "Redis Connectivity",
                &format!("Cannot connect to Redis at {}", redis_url),
            );
        }
        Err(_) => {
            log_warning(
                config,
                result,
                "Redis Connectivity",
                "redis-cli not found, skipping connectivity check",
            );
        }
    }

    Ok(())
}

/// Check 7: GraphQL permission operations
async fn check_graphql_operations(
    config: &RebacValidationConfig,
    result: &mut RebacValidationResult,
) -> Result<()> {
    if !config.quiet {
        println!();
        println!("{}", "Check 7: GraphQL Permission Operations".blue());
    }

    let Some(web_dir) = &config.web_dir else {
        if !config.quiet {
            println!("   (skipped — web dir not configured)");
        }
        return Ok(());
    };

    let schema_file = web_dir.join("schema.graphql");
    if !schema_file.exists() {
        log_warning(
            config,
            result,
            "GraphQL Operations",
            "schema.graphql not found, skipping GraphQL checks",
        );
        return Ok(());
    }

    let content = fs::read_to_string(&schema_file).await?;

    // Check for permission-related operations
    if content.contains("checkPermission") {
        log_success(
            config,
            result,
            "GraphQL Operations",
            "checkPermission query defined",
        );
    } else {
        log_warning(
            config,
            result,
            "GraphQL Operations",
            "checkPermission query not found in schema",
        );
    }

    if content.contains("grantPermission") || content.contains("revokePermission") {
        log_success(
            config,
            result,
            "GraphQL Operations",
            "Permission mutations defined",
        );
    } else {
        log_warning(
            config,
            result,
            "GraphQL Operations",
            "Permission mutations (grantPermission/revokePermission) not found",
        );
    }

    if content.contains("permissionChanged") {
        log_success(
            config,
            result,
            "GraphQL Operations",
            "permissionChanged subscription defined",
        );
    } else {
        log_warning(
            config,
            result,
            "GraphQL Operations",
            "permissionChanged subscription not found",
        );
    }

    Ok(())
}

/// Log a success message
fn log_success(
    config: &RebacValidationConfig,
    result: &mut RebacValidationResult,
    check: &str,
    message: &str,
) {
    if !config.quiet {
        println!("   {} {}", "✓".green(), message);
    }
    result.messages.push(ValidationMessage {
        level: ValidationLevel::Success,
        check: check.to_string(),
        message: message.to_string(),
    });
}

/// Log a warning message
fn log_warning(
    config: &RebacValidationConfig,
    result: &mut RebacValidationResult,
    check: &str,
    message: &str,
) {
    if !config.quiet {
        println!("   {} {}", "!".yellow(), message);
    }
    result.warnings += 1;
    result.messages.push(ValidationMessage {
        level: ValidationLevel::Warning,
        check: check.to_string(),
        message: message.to_string(),
    });
}

/// Log an error message
fn log_error(
    config: &RebacValidationConfig,
    result: &mut RebacValidationResult,
    check: &str,
    message: &str,
) {
    println!("   {} {}", "✗".red(), message);
    result.errors += 1;
    result.messages.push(ValidationMessage {
        level: ValidationLevel::Error,
        check: check.to_string(),
        message: message.to_string(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validation_result() {
        let mut result = RebacValidationResult::default();
        assert!(result.all_passed());

        result.errors = 1;
        assert!(!result.all_passed());
    }

    #[test]
    fn test_config() {
        let mut product = crate::config::ProductConfig {
            name: "myapp".to_string(),
            environment: crate::config::default_environment(),
            cluster: crate::config::default_cluster(),
            release: None,
            k8s: None,
            domain: None,
            observability: Default::default(),
            seed: Default::default(),
            dirs: crate::config::DirsConfig {
                backend: Some("services/rust/backend".to_string()),
                docs_arch: Some("docs/arch".to_string()),
                web: None,
                observability_scripts: None,
                dashboards_output: None,
            },
            endpoints: Default::default(),
        };
        let config = RebacValidationConfig::from_product(
            Path::new("/tmp/myapp"),
            false,
            true,
            &product,
        );
        assert_eq!(
            config.backend_dir,
            Some(PathBuf::from("/tmp/myapp/services/rust/backend"))
        );
        assert_eq!(
            config.docs_dir,
            Some(PathBuf::from("/tmp/myapp/docs/arch"))
        );
        assert!(config.check_redis);
        assert!(!config.quiet);

        // When dirs not configured, paths are None
        product.dirs.backend = None;
        product.dirs.docs_arch = None;
        let config2 = RebacValidationConfig::from_product(
            Path::new("/tmp/myapp"),
            false,
            false,
            &product,
        );
        assert_eq!(config2.backend_dir, None);
        assert_eq!(config2.docs_dir, None);
    }
}
