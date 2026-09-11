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
use tokio::process::Command;

/// Resolve the `redis-cli` binary path via `REDIS_CLI_BIN`, falling back to
/// `redis-cli` on `PATH`. Wired through [`crate::tools::get_tool_path`] —
/// which canonicalizes the dash-bearing tool name to the shell-safe
/// `REDIS_CLI_BIN` env var — so a Nix-hermetic runner's substrate-derived
/// `redis-cli` path lands at every redis-cli-spawning site in this module.
/// Mirrors the sibling `commands/infra.rs::docker_bin` (7f49465) sigil
/// discipline: the one bridge between the forge rebac-validation surface
/// and the substrate-`mkRuntimeToolsEnv`-exported binary path. Pre-lift
/// the three `Command::new` sites in `check_redis_connectivity`
/// (`ping`, `KEYS <prefix>:rel:*`, `KEYS <prefix>:perm:*`) each spelled
/// the bare `"redis-cli"` literal verbatim, ignoring `REDIS_CLI_BIN` at
/// every site — a Nix-hermetic runner's substrate-derived redis-cli path
/// lost to whatever `redis-cli` sat first on PATH.
fn redis_cli_bin() -> String {
    crate::tools::get_tool_path("redis-cli")
}

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
        crate::ui::print_section_header("ReBAC Validation");
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
        if result.all_passed() && result.warnings == 0 {
            crate::ui::print_section_completion_banner(
                "All ReBAC validations passed",
                crate::ui::SectionCompletionStyle::Success,
            );
        } else if result.all_passed() {
            crate::ui::print_section_completion_banner(
                &format!("Validation complete with {} warning(s)", result.warnings),
                crate::ui::SectionCompletionStyle::Warning,
            );
        } else {
            crate::ui::print_section_completion_banner(
                &format!(
                    "Validation failed: {} error(s), {} warning(s)",
                    result.errors, result.warnings
                ),
                crate::ui::SectionCompletionStyle::Failure,
            );
        }
    }

    Ok(result)
}

/// Check 1: ReBAC documentation exists
async fn check_rebac_documentation(
    config: &RebacValidationConfig,
    result: &mut RebacValidationResult,
) -> Result<()> {
    if !config.quiet {
        crate::ui::print_numbered_check_heading(1, "ReBAC Documentation");
    }

    let Some(docs_dir) = &config.docs_dir else {
        crate::commands::rebac_check_skipped_missing_dir::print_rebac_check_skipped_missing_dir(
            config.quiet,
            crate::commands::rebac_check_skipped_missing_dir::RebacValidationSkippedReason::DocsArchDir,
        );
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
    crate::commands::rebac_check_heading_with_gap::print_rebac_check_heading_with_gap(
        config.quiet,
        2,
        "Permission Engine Source Files",
    );

    let Some(backend_dir) = &config.backend_dir else {
        crate::commands::rebac_check_skipped_missing_dir::print_rebac_check_skipped_missing_dir(
            config.quiet,
            crate::commands::rebac_check_skipped_missing_dir::RebacValidationSkippedReason::BackendDir,
        );
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
    crate::commands::rebac_check_heading_with_gap::print_rebac_check_heading_with_gap(
        config.quiet,
        3,
        "Object Type → Entity Mapping",
    );

    let (Some(docs_dir), Some(backend_dir)) = (&config.docs_dir, &config.backend_dir) else {
        crate::commands::rebac_check_skipped_missing_dir::print_rebac_check_skipped_missing_dir(
            config.quiet,
            crate::commands::rebac_check_skipped_missing_dir::RebacValidationSkippedReason::DocsArchAndOrBackendDir,
        );
        return Ok(());
    };

    let rebac_doc = docs_dir.join("security-rebac.md");
    if !rebac_doc.exists() {
        return Ok(());
    }

    let content = crate::repo::read_text_async(&rebac_doc).await?;

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
                crate::ui::print_step_skip(&format!(
                    "{} (example type, no entity required)",
                    object_type
                ));
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
    crate::commands::rebac_check_heading_with_gap::print_rebac_check_heading_with_gap(
        config.quiet,
        4,
        "Relation Hierarchy Consistency",
    );

    let Some(backend_dir) = &config.backend_dir else {
        crate::commands::rebac_check_skipped_missing_dir::print_rebac_check_skipped_missing_dir(
            config.quiet,
            crate::commands::rebac_check_skipped_missing_dir::RebacValidationSkippedReason::BackendDir,
        );
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

        let content = crate::repo::read_text_async(impl_file).await?;

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
            let content = crate::repo::read_text_async(&rebac_doc).await?;
            if content.contains("owner → editor → viewer") || content.contains("owner → editor")
            {
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
    crate::commands::rebac_check_heading_with_gap::print_rebac_check_heading_with_gap(
        config.quiet,
        5,
        "Redis Key Pattern Validation",
    );

    let Some(docs_dir) = &config.docs_dir else {
        crate::commands::rebac_check_skipped_missing_dir::print_rebac_check_skipped_missing_dir(
            config.quiet,
            crate::commands::rebac_check_skipped_missing_dir::RebacValidationSkippedReason::DocsArchDir,
        );
        return Ok(());
    };

    let rebac_doc = docs_dir.join("security-rebac.md");
    if !rebac_doc.exists() {
        return Ok(());
    }

    let content = crate::repo::read_text_async(&rebac_doc).await?;

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
    crate::commands::rebac_check_heading_with_gap::print_rebac_check_heading_with_gap(
        config.quiet,
        6,
        "Redis Connectivity",
    );

    let redis_url = crate::repo::env_var_or_default("REDIS_URL", "redis://localhost:6379");

    // Try to ping Redis
    let redis_cli = redis_cli_bin();
    let output = Command::new(&redis_cli)
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

            // Count keys — both KEYS-glob probes route through the typed
            // `probe_and_report_rebac_key_count` fusion primitive, which
            // owns the 12-line `format! + Command::args + KEYS + count
            // non-empty lines + println! under a quiet-gate` stanza. The
            // (glob-infix, report-description) pair is closed under the
            // `RebacKeyKind` enum so a future third family (session,
            // cache, …) is a single-variant edit rather than a fourth
            // inline copy.
            crate::rebac_keys_probe::probe_and_report_rebac_key_count(
                &redis_cli,
                &redis_url,
                &config.redis_key_prefix,
                crate::rebac_keys_probe::RebacKeyKind::Relation,
                config.quiet,
            )
            .await;

            crate::rebac_keys_probe::probe_and_report_rebac_key_count(
                &redis_cli,
                &redis_url,
                &config.redis_key_prefix,
                crate::rebac_keys_probe::RebacKeyKind::Permission,
                config.quiet,
            )
            .await;
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
    crate::commands::rebac_check_heading_with_gap::print_rebac_check_heading_with_gap(
        config.quiet,
        7,
        "GraphQL Permission Operations",
    );

    let Some(web_dir) = &config.web_dir else {
        crate::commands::rebac_check_skipped_missing_dir::print_rebac_check_skipped_missing_dir(
            config.quiet,
            crate::commands::rebac_check_skipped_missing_dir::RebacValidationSkippedReason::WebDir,
        );
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

    let content = crate::repo::read_text_async(&schema_file).await?;

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
        crate::ui::print_step_check(message);
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
    crate::ui::print_step_uncheck(message);
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
        let config =
            RebacValidationConfig::from_product(Path::new("/tmp/myapp"), false, true, &product);
        assert_eq!(
            config.backend_dir,
            Some(PathBuf::from("/tmp/myapp/services/rust/backend"))
        );
        assert_eq!(config.docs_dir, Some(PathBuf::from("/tmp/myapp/docs/arch")));
        assert!(config.check_redis);
        assert!(!config.quiet);

        // When dirs not configured, paths are None
        product.dirs.backend = None;
        product.dirs.docs_arch = None;
        let config2 =
            RebacValidationConfig::from_product(Path::new("/tmp/myapp"), false, false, &product);
        assert_eq!(config2.backend_dir, None);
        assert_eq!(config2.docs_dir, None);
    }

    /// Whole-module shield: no raw `"redis-cli"`-literal spawn may live in
    /// `commands/rebac_validation.rs`. Every redis-cli spawn must resolve
    /// `REDIS_CLI_BIN` via [`super::redis_cli_bin`] first.
    ///
    /// Pre-lift the three `Command::new` sites in
    /// `check_redis_connectivity` — the `ping` probe, the `KEYS
    /// <prefix>:rel:*` scan, and the `KEYS <prefix>:perm:*` scan — each
    /// spelled the bare `"redis-cli"` literal verbatim, ignoring
    /// `REDIS_CLI_BIN` at every site. A Nix-hermetic runner's substrate-
    /// derived redis-cli path lost to whatever `redis-cli` sat first on
    /// PATH — the same silent-PATH-fallback bug class the sibling
    /// `commands/infra.rs::docker_bin_routing_tests` shield (7f49465)
    /// closed for the docker surface.
    ///
    /// This shield scans the module's own source via [`include_str!`]
    /// and forbids the fused literal shape. The forbidden shape is
    /// reconstructed via [`format!`] so this shield's own source text
    /// does not false-match itself — the whole-module scan therefore
    /// covers both the top-of-file production body AND every sibling
    /// `#[cfg(test)]` block (any of which could otherwise silently re-
    /// introduce a raw literal). The end-to-end `REDIS_CLI_BIN`-routing
    /// invariant of the underlying primitive is pinned separately by
    /// [`crate::tools::tests::test_get_tool_path_canonicalizes_single_dash_to_underscore`];
    /// this shield only certifies that every redis-cli-spawning site in
    /// this module reads through `redis_cli_bin()`.
    #[test]
    fn test_redis_cli_spawns_route_through_redis_cli_bin_not_raw_literal() {
        const SOURCE: &str = include_str!("rebac_validation.rs");

        crate::test_support::assert_source_forbids_bare_spawn_shapes(
            SOURCE,
            "commands/rebac_validation.rs",
            "redis-cli",
            "resolve `REDIS_CLI_BIN` via `redis_cli_bin()`",
        );
        crate::test_support::assert_source_defines_sigil_bin_fn_code_line(
            SOURCE,
            "commands/rebac_validation.rs",
            "redis_cli_bin",
            "REDIS_CLI_BIN",
            "redis-cli",
        );
        assert!(
            SOURCE.contains("crate::tools::get_tool_path(\"redis-cli\")"),
            "`redis_cli_bin()` must delegate to \
             `crate::tools::get_tool_path(\"redis-cli\")` — the canonical \
             lookup was not found in the module. The dash-bearing tool \
             name is canonicalized to `REDIS_CLI_BIN` by the underlying \
             primitive; a regression here would silently downgrade to \
             the PATH fallback."
        );
    }

    /// Whole-module negative caller shield: no raw pre-lift
    /// `println!("   (skipped — <label> not configured)")` skip-line
    /// literal may live in `commands/rebac_validation.rs`. Every
    /// per-check `let Some(<dir>) = &config.<dir_opt> else { … }`
    /// early-out MUST route through
    /// [`crate::commands::rebac_check_skipped_missing_dir::print_rebac_check_skipped_missing_dir`]
    /// so the 3-space indent, the parenthesized `(skipped — …)`
    /// grammar, and the ` not configured` suffix — plus the
    /// `if !config.quiet { … }` gate — live at ONE typed body
    /// (`commands/rebac_check_skipped_missing_dir.rs`).
    ///
    /// Pre-lift 6 sibling sites — `check_rebac_documentation`,
    /// `check_permission_engine`, `check_object_type_mapping`,
    /// `check_relation_hierarchy`, `check_redis_key_patterns`,
    /// `check_graphql_permissions` — each spelled the entire skip
    /// stanza (guard + `println!` + `return Ok(())`) verbatim in
    /// its `else { … }` branch, differing only in the directory
    /// phrase baked into the `println!` format string.
    ///
    /// The needle scans for the fused prefix
    /// `println!("   (skipped — ` (three spaces of indent, the
    /// parenthesis, and the em-dash separator). The prefix is
    /// reconstructed at test time via [`format!`] so this shield's
    /// own diagnostic prose does not false-match itself.
    #[test]
    fn no_raw_rebac_check_skipped_missing_dir_line_survives_in_rebac_validation_rs() {
        const SOURCE: &str = include_str!("rebac_validation.rs");
        let needle = format!("println!({}   (skipped — ", '"');
        let hits = crate::test_support::code_line_hits(SOURCE, &needle);
        assert!(
            hits.is_empty(),
            "commands/rebac_validation.rs must NOT carry an inline \
             `println!({DQ}   (skipped — <label> not configured){DQ})` \
             literal — every per-check missing-dir skip branch must \
             route through `crate::commands::rebac_check_skipped_missing_dir::\
             print_rebac_check_skipped_missing_dir(config.quiet, \
             RebacValidationSkippedReason::<variant>)`. Found code-line \
             hits: {hits:#?}",
            DQ = '"',
        );
    }

    /// Positive-delegation shield: `commands/rebac_validation.rs`
    /// MUST forward through the primitive at ≥6 sites — the
    /// pre-lift `check_rebac_documentation`,
    /// `check_permission_engine`, `check_object_type_mapping`,
    /// `check_relation_hierarchy`, `check_redis_key_patterns`, and
    /// `check_graphql_permissions` early-outs. A drop below the
    /// floor cannot leave the negative shield above trivially
    /// satisfied by absence (a "just delete the skip announcement,
    /// the silent early-out suffices" cleanup that quietly stops
    /// telling the operator why a check produced no output).
    #[test]
    fn rebac_validation_rs_forwards_through_rebac_check_skipped_missing_dir_primitive_at_six_sites()
    {
        const SOURCE: &str = include_str!("rebac_validation.rs");
        let needle = format!(
            "rebac_check_skipped_missing_dir::{}(",
            "print_rebac_check_skipped_missing_dir",
        );
        let hits = crate::test_support::code_line_hits(SOURCE, &needle);
        assert!(
            hits.len() >= 6,
            "commands/rebac_validation.rs must forward through the \
             `print_rebac_check_skipped_missing_dir` primitive at ≥6 \
             sites (one per pre-lift check whose `let Some(<dir>) = …` \
             else-branch previously carried a raw `println!`). Found \
             code-line hits: {hits:#?}"
        );
    }

    /// Whole-module negative caller shield: no raw
    /// `crate::ui::print_numbered_check_heading(<N>, "<title>")` may
    /// live in `commands/rebac_validation.rs` for `N ∈ {2..=7}`.
    /// Every non-first per-check heading MUST route through
    /// [`crate::commands::rebac_check_heading_with_gap::print_rebac_check_heading_with_gap`]
    /// so the `if !config.quiet { … }` gate, the framing blank, and
    /// the fusion of the blank with the delegated heading live at
    /// ONE typed body (`commands/rebac_check_heading_with_gap.rs`).
    ///
    /// The check-1 seat (`check_rebac_documentation`) is the sole
    /// legitimate un-gapped delegation and stays on the plain
    /// heading adapter — the pre-lift site emitted the heading
    /// directly at the top of the report with no upstream check to
    /// visually separate from. The shield accepts that single
    /// occurrence and forbids every other bare delegate reference
    /// under the module.
    ///
    /// The needle scans for the fused `crate::ui::<fn>(` prefix. It
    /// is reconstructed at test time via [`format!`] AND the
    /// assertion message keeps the module segment and the function
    /// segment concatenated at runtime via `format!` so this
    /// shield's own diagnostic prose does not false-match itself.
    #[test]
    fn no_raw_numbered_check_heading_delegate_beyond_the_check1_seat_survives() {
        const SOURCE: &str = include_str!("rebac_validation.rs");
        let fn_name = "print_numbered_check_heading";
        let needle = format!("crate::ui::{}(", fn_name);
        let hits = crate::test_support::code_line_hits(SOURCE, &needle);
        assert!(
            hits.len() <= 1,
            "commands/rebac_validation.rs must carry AT MOST ONE `{needle}` \
             reference (the check-1 seat inside `check_rebac_documentation`). \
             Every other per-check heading MUST route through \
             `crate::commands::rebac_check_heading_with_gap::\
             print_rebac_check_heading_with_gap(config.quiet, <N>, \
             \"<title>\")` so the framing blank + heading fusion lives \
             at ONE typed body. Found code-line hits: {hits:#?}"
        );
    }

    /// Positive-delegation shield: `commands/rebac_validation.rs`
    /// MUST forward through the with-gap heading primitive at ≥6
    /// sites — the pre-lift `check_permission_engine_files`,
    /// `check_object_type_mapping`, `check_relation_hierarchy`,
    /// `check_redis_key_patterns`, `check_redis_connectivity`, and
    /// `check_graphql_permissions` phase openings. A drop below the
    /// floor cannot leave the negative shield above trivially
    /// satisfied by absence (a "just delete the heading, the
    /// silent check body suffices" cleanup that quietly stops
    /// telling the operator which check is running).
    #[test]
    fn rebac_validation_rs_forwards_through_rebac_check_heading_with_gap_primitive_at_six_sites() {
        const SOURCE: &str = include_str!("rebac_validation.rs");
        let needle = format!(
            "rebac_check_heading_with_gap::{}(",
            "print_rebac_check_heading_with_gap",
        );
        let hits = crate::test_support::code_line_hits(SOURCE, &needle);
        assert!(
            hits.len() >= 6,
            "commands/rebac_validation.rs must forward through the \
             `print_rebac_check_heading_with_gap` primitive at ≥6 \
             sites (one per pre-lift check whose \
             `if !config.quiet {{ println!(); print_numbered_check_heading(…); }}` \
             phase opening previously restated the fusion inline). \
             Found code-line hits: {hits:#?}"
        );
    }
}
