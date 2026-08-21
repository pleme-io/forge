//! Session management commands
//!
//! Provides utilities for managing Redis/Valkey sessions in Kubernetes clusters.
//! Primary use case: Flushing stale sessions when permissions are updated.

use anyhow::{Context, Result};
use std::io::{self, Write};
use tracing::{info, warn};

use crate::retry::run_query_capture_sync;
use crate::tools::{get_tool_path, tools};

/// Product configuration for session management
struct ProductConfig {
    valkey_pod: String,
    password_secret: String,
    password_key: String,
}

impl ProductConfig {
    /// Create configuration from product name using standard patterns.
    /// Override patterns via environment variables:
    /// - VALKEY_POD_PATTERN: Default "{product}-valkey-0"
    /// - PASSWORD_SECRET_PATTERN: Default "{product}-backend-secrets"
    /// - PASSWORD_KEY: Default "REDIS_PASSWORD"
    fn for_product(product: &str) -> Result<Self> {
        let valkey_pod_pattern = std::env::var("VALKEY_POD_PATTERN")
            .unwrap_or_else(|_| "{product}-valkey-0".to_string());
        let password_secret_pattern = std::env::var("PASSWORD_SECRET_PATTERN")
            .unwrap_or_else(|_| "{product}-backend-secrets".to_string());
        let password_key =
            std::env::var("PASSWORD_KEY").unwrap_or_else(|_| "REDIS_PASSWORD".to_string());

        Ok(Self {
            valkey_pod: valkey_pod_pattern.replace("{product}", product),
            password_secret: password_secret_pattern.replace("{product}", product),
            password_key,
        })
    }
}

/// Get Valkey password from Kubernetes secret.
///
/// kubectl is driven through the canonical
/// [`crate::retry::run_query_capture_sync`] primitive — the
/// `(cmd, args) -> Result<String>` consolidation for the sync no-cwd
/// "spawn an external CLI, capture trimmed stdout" shape. Pre-this-
/// commit the three call sites in this module delegated through a
/// private `kubectl` wrapper; that wrapper was one of three identically
/// -shaped shape-adapters (`seed.rs::run_command_output`,
/// `local.rs::run_command_output`) past THEORY §VI.1's three-is-a-law
/// threshold, all collapsed onto `run_query_capture_sync` in one
/// commit.
///
/// The `kubectl` binary name is resolved via
/// [`crate::tools::get_tool_path`] on the canonical `tools::KUBECTL`
/// name BEFORE it reaches `run_query_capture_sync`, because the
/// primitive itself takes the tool as a bare `&str` and spawns it
/// verbatim (retry.rs:13167) — every consumer that wants the
/// `KUBECTL_BIN`-or-PATH lookup discipline must pre-resolve at the
/// call site. Pre-lift this site handed the primitive the bare
/// `"kubectl"` literal and thereby bypassed the env override the
/// sibling `commands/seed.rs::find_primary_pod` (docstring at
/// seed.rs:127-156) redeemed on its own migration. A Nix-hermetic
/// runner whose `KUBECTL_BIN` points at a specific store-path
/// `kubectl` (substrate's `mkRuntimeToolsEnv`) would otherwise lose
/// to whatever `kubectl` is first on `PATH` at every `forge sessions
/// flush` invocation.
fn get_valkey_password(namespace: &str, secret_name: &str, key: &str) -> Result<String> {
    let jsonpath = format!("{{.data.{}}}", key);
    let kubectl = get_tool_path(tools::KUBECTL);
    let base64_password = run_query_capture_sync(
        &kubectl,
        &[
            "get",
            "secret",
            secret_name,
            "-n",
            namespace,
            "-o",
            &format!("jsonpath={}", jsonpath),
        ],
    )?;

    if base64_password.is_empty() {
        anyhow::bail!(
            "Could not retrieve Valkey password from secret {}/{}",
            namespace,
            secret_name
        );
    }

    // Decode base64
    let decoded = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        base64_password.trim(),
    )
    .context("Failed to decode base64 password")?;

    String::from_utf8(decoded).context("Password is not valid UTF-8")
}

/// Count session keys in Valkey
fn count_sessions(namespace: &str, pod: &str, password: &str) -> Result<usize> {
    let kubectl = get_tool_path(tools::KUBECTL);
    let output = run_query_capture_sync(
        &kubectl,
        &[
            "exec",
            "-n",
            namespace,
            pod,
            "--",
            "valkey-cli",
            "-a",
            password,
            "--no-auth-warning",
            "keys",
            "session:*",
        ],
    )?;

    // Count non-empty lines
    let count = output.lines().filter(|l| !l.trim().is_empty()).count();
    Ok(count)
}

/// Delete all session keys using SCAN + DEL pattern (safer for large datasets)
fn delete_sessions(namespace: &str, pod: &str, password: &str) -> Result<usize> {
    // Use SCAN for safer iteration over large keyspaces
    let script = format!(
        "valkey-cli -a '{}' --no-auth-warning --scan --pattern 'session:*' | xargs -r valkey-cli -a '{}' --no-auth-warning DEL",
        password, password
    );

    let kubectl = get_tool_path(tools::KUBECTL);
    let output = run_query_capture_sync(
        &kubectl,
        &["exec", "-n", namespace, pod, "--", "sh", "-c", &script],
    )?;

    // Parse output to get count of deleted keys
    // DEL returns the number of keys deleted
    let deleted: usize = output
        .lines()
        .filter_map(|l| l.trim().parse::<usize>().ok())
        .sum();

    Ok(deleted)
}

/// Flush all sessions for a product
pub async fn flush(product: String, environment: String, force: bool, dry_run: bool) -> Result<()> {
    let config = ProductConfig::for_product(&product)?;
    let namespace = format!("{}-{}", product, environment);

    println!("🔄 Session Flush for {} ({})", product, environment);
    println!("   Namespace: {}", namespace);
    println!("   Valkey Pod: {}", config.valkey_pod);
    println!();

    // Get Valkey password
    info!("Retrieving Valkey password from secret...");
    let password = get_valkey_password(&namespace, &config.password_secret, &config.password_key)?;

    // Count sessions
    info!("Counting session keys...");
    let session_count = count_sessions(&namespace, &config.valkey_pod, &password)?;
    println!("   Found {} session(s)", session_count);

    if session_count == 0 {
        println!("✅ No sessions to flush");
        return Ok(());
    }

    if dry_run {
        println!();
        println!("🔍 Dry run mode - no sessions deleted");
        println!("   Would delete {} session(s)", session_count);
        return Ok(());
    }

    // Confirm unless --force
    if !force {
        println!();
        print!(
            "⚠️  This will log out {} user(s). Continue? (y/N) ",
            session_count
        );
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Cancelled");
            return Ok(());
        }
    }

    // Delete sessions
    info!("Flushing sessions...");
    let deleted = delete_sessions(&namespace, &config.valkey_pod, &password)?;

    println!();
    println!("✅ Sessions flushed successfully!");
    println!("   Deleted {} session key(s)", deleted);
    println!("   Users will need to log in again to get updated permissions.");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_product_config_pattern() {
        let config = ProductConfig::for_product("myproduct").unwrap();
        assert_eq!(config.valkey_pod, "myproduct-valkey-0");
        assert_eq!(config.password_secret, "myproduct-backend-secrets");
        assert_eq!(config.password_key, "REDIS_PASSWORD");
    }

    #[test]
    fn test_product_config_another_product() {
        let config = ProductConfig::for_product("testapp").unwrap();
        assert_eq!(config.valkey_pod, "testapp-valkey-0");
        assert_eq!(config.password_secret, "testapp-backend-secrets");
    }

    /// Whole-module shield: no raw `Command::new`-with-bare-`kubectl`-
    /// literal, and no bare-`kubectl`-literal-as-first-arg to
    /// [`crate::retry::run_query_capture_sync`], may live in
    /// `commands/sessions.rs`'s non-test body. Every `kubectl` spawn on
    /// this module's three entry points — [`get_valkey_password`],
    /// [`count_sessions`], and [`delete_sessions`] (all sync captures
    /// via `run_query_capture_sync`, whose primitive body spawns the
    /// caller-supplied `&str` verbatim via
    /// `std::process::Command::new(cmd)` per retry.rs:13167 and
    /// therefore requires the caller to pre-resolve through
    /// [`crate::tools::get_tool_path`] on the canonical
    /// `tools::KUBECTL` name) MUST resolve the binary through
    /// `KUBECTL_BIN` (or PATH) via
    /// [`crate::tools::get_tool_path`] first.
    ///
    /// Pre-lift the three `kubectl` spawns spelled the bare `"kubectl"`
    /// string verbatim at `run_query_capture_sync`'s first argument.
    /// All three silently bypassed the substrate-exported
    /// `KUBECTL_BIN` env override the tools-registry idiom
    /// (`crate::tools::get_tool_path(tools::KUBECTL)`,
    /// cli/src/tools.rs:102-105) resolves — the same class of bug the
    /// sibling `commands/seed.rs` shield
    /// (test_kubectl_spawns_resolve_through_tools_kubectl_not_bare_literal)
    /// redeemed on its own migration. A Nix-hermetic runner whose
    /// `KUBECTL_BIN` points at a specific store-path `kubectl`
    /// (substrate's `mkRuntimeToolsEnv`) would otherwise lose to
    /// whatever `kubectl` is first on `PATH` at every `forge sessions
    /// flush` invocation — the exact failure mode a staging cluster
    /// runner with two `kubectl` versions coexisting would hit.
    ///
    /// This test reads this module's own source via [`include_str!`]
    /// and asserts neither forbidden shape appears in the non-test
    /// body while the canonical `get_tool_path(tools::KUBECTL)`
    /// delegation does. The forbidden `run_query_capture_sync`-with-
    /// bare-`"kubectl"`-literal shape is reconstructed via [`format!`]
    /// so this shield's own docstring and body do not false-match
    /// themselves. The scan is bounded strictly to the module's
    /// non-test body — from the file start to the `#[cfg(test)]`
    /// marker — so this shield's own text stays out of scope AND every
    /// current or future kubectl-spawning helper landing anywhere in
    /// the top-level module body (across the three migrated entry
    /// points or any as-yet unadded sibling) is covered by the same
    /// shield without a per-function narrowing. Mirrors the
    /// whole-module boundary discipline the sibling `commands/seed.rs`
    /// shield holds.
    ///
    /// The end-to-end `KUBECTL_BIN`-routing invariant of the
    /// underlying primitives is pinned separately by
    /// [`crate::infrastructure::kubectl::tests::test_kubectl_command_async_routes_through_kubectl_bin_env_var`]
    /// on the async surface and by
    /// [`crate::tools::tests::test_get_tool_path_from_env`] on the
    /// sync resolver; this shield only certifies that every
    /// `kubectl`-spawning site in this module resolves through the
    /// canonical resolver first.
    #[test]
    fn test_kubectl_spawns_resolve_through_tools_kubectl_not_bare_literal() {
        let module_body = crate::test_support::module_body_before_tests(
            include_str!("sessions.rs"),
            "commands/sessions.rs",
        );

        let bare = "kubectl";
        let bypass_primitive = format!("run_query_capture_sync(\n        \"{}\"", bare);

        crate::test_support::assert_source_forbids_bare_spawn_shapes(
            module_body,
            "commands/sessions.rs",
            "kubectl",
            "resolve the substrate-exported `KUBECTL_BIN` env override via `get_tool_path(tools::KUBECTL)`",
        );
        assert!(
            !module_body.contains(&bypass_primitive),
            "commands/sessions.rs must NOT hand the bare `\"kubectl\"` \
             literal to `run_query_capture_sync` as its first arg — \
             the primitive spawns the caller-supplied `&str` verbatim \
             via `std::process::Command::new(cmd)`, so every consumer \
             must pre-resolve through `get_tool_path(tools::KUBECTL)` \
             first. A bare literal at the primitive call site bypasses \
             the `KUBECTL_BIN` env override every sibling site honors."
        );
        assert!(
            module_body.contains("get_tool_path(tools::KUBECTL)"),
            "commands/sessions.rs must resolve the `kubectl` binary via \
             the canonical `get_tool_path(tools::KUBECTL)` lookup — \
             the required form was not found in the module body."
        );
    }
}
