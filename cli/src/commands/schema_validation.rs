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

/// Resolve the service directory from the `SERVICE_DIR` env var,
/// returning a [`PathBuf`] with the canonical
/// `"SERVICE_DIR environment variable not set"` context on the miss.
/// Every command in this module that reads `SERVICE_DIR` routes through
/// this sigil so the env-var name, the operator-facing miss wording,
/// and the [`PathBuf`] projection live at EXACTLY one body — mirrors
/// the sibling `service_path_from_env()` sigil on
/// `commands/developer_tools.rs:114` (ab5a8db) and the broader
/// `<TOOL>_BIN` / `SERVICE_DIR` env-var sigil family across forge
/// modules, converging every substrate-declared environment contract
/// in this module onto the solve-once-at-the-sigil idiom (THEORY §I.5
/// — duplication budget zero; every recurring shape becomes a helper
/// before it becomes duplicated code). Pre-lift the two consumer sites
/// (`extract_and_validate_schema`, `find_schema_extractor`) each
/// spelled the same two-line stanza
/// `let service_dir = std::env::var("SERVICE_DIR").context("SERVICE_DIR
/// environment variable not set")?; let <_> = PathBuf::from(service_dir);`
/// verbatim, so the miss wording drifted only by convention — the
/// shield below now enforces that convention structurally.
///
/// Post-lift a future refinement of the `SERVICE_DIR` contract — a
/// canonicalize hook, a substrate-path validation step, a telemetry
/// sigil on the resolved path, or a swap to a typed
/// `substrate::ServiceDir(PathBuf)` newtype — lands at ONE body
/// ([`crate::repo::path_from_env`]) and reaches every consumer by
/// construction. The per-module sigil now delegates to that shared
/// primitive with the module's domain-specific miss wording preserved
/// verbatim — the twin `commands/developer_tools.rs:114` sigil
/// (ab5a8db) delegates through the same primitive with its own
/// distinct wording, so the read-and-project shape lives at ONE body
/// across the crate while each module's operator-facing diagnostic
/// prose stays grep-visible at the delegating call.
fn service_path_from_env() -> Result<PathBuf> {
    crate::repo::path_from_env("SERVICE_DIR", "SERVICE_DIR environment variable not set")
}

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
    let service_dir_path = service_path_from_env()?;

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
    let service_path = service_path_from_env()?;

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
    let schema_text = crate::repo::utf8_lossy_borrow(schema_bytes);

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

    /// Whole-module shield: every read of the `SERVICE_DIR` env var in
    /// this module's non-test body must route through the module-local
    /// [`super::service_path_from_env`] sigil, which itself delegates
    /// to the shared [`crate::repo::path_from_env`] primitive — never
    /// through an inline `std::env::var("SERVICE_DIR").context(...)?` +
    /// `PathBuf::from(service_dir)` two-line stanza.
    ///
    /// Pre-lift the two consumer sites (`extract_and_validate_schema`,
    /// `find_schema_extractor`) each spelled the same two-line stanza
    /// verbatim — a byte-identical operator-facing miss wording that
    /// had drifted only by convention. THEORY §VI.1 admits "two
    /// occurrences is a coincidence; three is a law" — this shield
    /// closes the drift class at two on the same idiom the sibling
    /// `commands/developer_tools.rs:1107` shield (ab5a8db) landed at
    /// four. Post-e9e0c5b the two per-module sigils themselves
    /// became a two-copy recurrence of the same read-and-project shape;
    /// this shield now pins the shared-primitive delegation, so a
    /// future refinement of the `SERVICE_DIR` contract — a canonicalize
    /// hook, a substrate-path validation step, a telemetry sigil on
    /// the resolved path, or a swap to a typed
    /// `substrate::ServiceDir(PathBuf)` newtype — lands at ONE body
    /// ([`crate::repo::path_from_env`]) and reaches every consumer in
    /// this module (and the sibling `commands/developer_tools.rs`) by
    /// construction.
    ///
    /// The scan bounds on the whole-module boundary (from the file
    /// start to the FIRST `\n#[cfg(test)]\nmod tests {` marker in
    /// source order, which lands at the parent `#[cfg(test)] mod
    /// tests` opener above) so this shield's own docstring mentions of
    /// `env::var("SERVICE_DIR")` — living inside a `#[cfg(test)]` block
    /// below that first marker — stay out of scope AND every current
    /// or future `SERVICE_DIR`-reading consumer landing anywhere in
    /// the top-level module body cannot silently ride along without
    /// routing through the sigil. Every hit routes through
    /// [`crate::test_support::code_line_hits`] for anti-docstring-
    /// self-match discipline. Mirrors the sibling
    /// `service_path_from_env()` sigil-shield on
    /// `commands/developer_tools.rs:1107` (ab5a8db).
    #[test]
    fn test_schema_validation_service_dir_routes_through_service_path_from_env() {
        let body = crate::test_support::module_body_before_tests(
            include_str!("schema_validation.rs"),
            "commands/schema_validation.rs",
        );
        // Negative side: the raw `env::var("SERVICE_DIR")` needle must
        // NOT appear anywhere in the module body post-lift — the sigil
        // now delegates to `crate::repo::path_from_env`, which owns the
        // read at ONE body across the crate. A future consumer that
        // re-copies the two-line stanza pushes this count above zero
        // and fails the shield before it can drift the miss wording or
        // the `PathBuf` projection away from the shared primitive's
        // single point of truth.
        let raw_env_needle = "env::var(\"SERVICE_DIR\")";
        let env_hits = crate::test_support::code_line_hits(body, raw_env_needle);
        assert!(
            env_hits.is_empty(),
            "commands/schema_validation.rs must NOT spell \
             `{raw_env_needle}` inline in the module body — every \
             consumer must route through `service_path_from_env()`, \
             which delegates to `crate::repo::path_from_env`, the \
             shared primitive that owns the `env::var` read at ONE \
             body across the crate. Found {} code-line hit(s): \
             {env_hits:#?}. A hand-rolled inline copy re-opens the \
             drift class the primitive was landed to close.",
            env_hits.len()
        );
        // Positive side: `service_path_from_env` must delegate to
        // `crate::repo::path_from_env(` at EXACTLY one code line — the
        // sigil body. A regression that inlined the read back into the
        // sigil (or into any consumer) would break the delegation and
        // be caught here. The needle matches the call opener only
        // (matches the schema_validation.rs sibling shield's shape one-
        // for-one so both modules share the same audit surface, even
        // though this module's shorter miss wording keeps the two-arg
        // call on one line while `commands/developer_tools.rs`'s longer
        // wording wraps under rustfmt).
        let delegate_needle = "crate::repo::path_from_env(";
        let delegate_hits = crate::test_support::code_line_hits(body, delegate_needle);
        assert_eq!(
            delegate_hits.len(),
            1,
            "commands/schema_validation.rs must delegate `SERVICE_DIR` \
             resolution to `crate::repo::path_from_env(...)` at EXACTLY \
             one code line — the `service_path_from_env()` sigil body. \
             Found {} code-line hit(s): {delegate_hits:#?}. A missing \
             delegation would leave the negative scan above trivially \
             satisfied by absence (zero raw `env::var` hits, but also \
             zero delegating calls), and the module would have stopped \
             resolving `SERVICE_DIR` at all.",
            delegate_hits.len()
        );
        // Sigil-defined side: `fn service_path_from_env()` must be
        // defined in the module body — a regression that removed the
        // sigil would leave the negative scan trivially satisfied by
        // absence (zero hits on the raw needle, not one), so pin the
        // presence of the sigil definition too.
        let sigil_def_needle = "fn service_path_from_env()";
        let sigil_def_hits = crate::test_support::code_line_hits(body, sigil_def_needle);
        assert_eq!(
            sigil_def_hits.len(),
            1,
            "commands/schema_validation.rs must define \
             `{sigil_def_needle}` at EXACTLY one code line — the sigil \
             function that resolves `SERVICE_DIR` into a `PathBuf` for \
             every `SERVICE_DIR`-reading consumer in this module. \
             Found {} code-line hit(s): {sigil_def_hits:#?}. Mirrors \
             the sibling `service_path_from_env()` sigil on \
             `commands/developer_tools.rs:114` (ab5a8db).",
            sigil_def_hits.len()
        );
        // Positive-side sibling: at least two consumers in this
        // module route through the sigil. A regression that dropped
        // every `service_path_from_env()` call from this module would
        // leave the negative scan trivially satisfied by an
        // env-var-free body, so pin the positive presence too — the
        // two pre-lift sites (`extract_and_validate_schema`,
        // `find_schema_extractor`) each land one
        // `service_path_from_env()?` hit.
        let call_needle = "service_path_from_env()?";
        let call_hits = crate::test_support::code_line_hits(body, call_needle);
        assert!(
            call_hits.len() >= 2,
            "commands/schema_validation.rs must delegate `SERVICE_DIR` \
             reads through `{call_needle}` at at least two code lines \
             (one per pre-lift consumer: `extract_and_validate_schema`, \
             `find_schema_extractor`). Found {} code-line hit(s): \
             {call_hits:#?}.",
            call_hits.len()
        );
    }

    /// Functional shield: [`super::service_path_from_env`] surfaces
    /// the canonical `"SERVICE_DIR environment variable not set"`
    /// context on a `SERVICE_DIR`-unset environment, byte-identical to
    /// what each pre-lift consumer site spelled at its own
    /// `.context(...)` call. Pins the operator-facing miss wording at
    /// the sigil body so a future refactor that reshapes the sigil (a
    /// swap from `.context()` to a `bail!` with drifted wording, a
    /// canonicalize prefix landed in front of the context, a lift to
    /// a typed error variant) cannot silently drift the message every
    /// consumer's caller has been coached to grep for.
    ///
    /// Holds [`crate::test_support::ROOT_FLAKE_ENV_LOCK`] for the
    /// duration of the env mutation — `SERVICE_DIR` is process-global
    /// state, and the sibling `RootFlakeEnvSnapshot` discipline
    /// guarantees no concurrent `SERVICE_DIR`-reading test races the
    /// scope. Restores the pre-scope `SERVICE_DIR` value on drop via
    /// [`crate::test_support::EnvVarSnapshot`]'s RAII guard — the
    /// panic-safe primitive that closes the pre-lift `let prior =
    /// std::env::var("SERVICE_DIR"); ...; match &prior { Ok(v) =>
    /// set_var, Err(_) => remove_var }` inline stanza's window where
    /// an `unwrap_err()` panic between snapshot and restore silently
    /// leaked `SERVICE_DIR=<unset>` to every subsequent test.
    #[test]
    fn test_service_path_from_env_surfaces_canonical_miss_wording_when_unset() {
        let _guard = crate::test_support::ROOT_FLAKE_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let _snapshot = crate::test_support::EnvVarSnapshot::capture("SERVICE_DIR");
        std::env::remove_var("SERVICE_DIR");
        let err = super::service_path_from_env().unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("SERVICE_DIR environment variable not set"),
            "service_path_from_env() must surface the canonical miss \
             wording on a `SERVICE_DIR`-unset environment — the same \
             wording every pre-lift consumer site's `.context(...)` \
             call spelled verbatim. Got: {msg}"
        );
    }

    /// Functional shield: [`super::service_path_from_env`] returns a
    /// [`PathBuf`] equal to `PathBuf::from(SERVICE_DIR)` when the env
    /// var is set. Pins the `SERVICE_DIR` → `PathBuf` projection at
    /// the sigil body so a future refinement (a canonicalize hook, a
    /// substrate-path validation step) that drifts the projection is
    /// caught here rather than at each consumer's downstream
    /// `.join(...)` / `.display()` call. Uses the same
    /// [`crate::test_support::ROOT_FLAKE_ENV_LOCK`] discipline as the
    /// sibling unset-side shield above.
    #[test]
    fn test_service_path_from_env_returns_path_of_set_env_var() {
        let _guard = crate::test_support::ROOT_FLAKE_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let _snapshot = crate::test_support::EnvVarSnapshot::capture("SERVICE_DIR");
        let sentinel = "/tmp/forge-schema-validation-service-path-sigil-shield";
        std::env::set_var("SERVICE_DIR", sentinel);
        let result = super::service_path_from_env();
        let path = result.expect("service_path_from_env must succeed when SERVICE_DIR is set");
        assert_eq!(
            path,
            PathBuf::from(sentinel),
            "service_path_from_env() must return `PathBuf::from(SERVICE_DIR)` \
             verbatim — the projection every pre-lift consumer site \
             spelled via `PathBuf::from(&service_dir)` / \
             `PathBuf::from(service_dir)`."
        );
    }
}
