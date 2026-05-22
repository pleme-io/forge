//! Session management commands
//!
//! Provides utilities for managing Redis/Valkey sessions in Kubernetes clusters.
//! Primary use case: Flushing stale sessions when permissions are updated.

use anyhow::{Context, Result};
use std::io::{self, Write};
use std::process::Command;
use tracing::{info, warn};

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

/// Execute `kubectl` with `args` and return its trimmed UTF-8-lossy stdout.
///
/// Third sibling of `commands/seed.rs::run_command_output` and
/// `commands/attestation.rs::run_command_output` — all three shape-adapt
/// for [`crate::retry::classify_capture_query_anyhow`] (the canonical
/// "anyhow envelope over a queried external CLI" primitive). The pre-lift
/// body fused into a `.context("Failed to execute kubectl")` envelope on
/// the spawn arm that dropped both the offending args and the underlying
/// `io::Error::Display`, plus an `if !output.status.success() { bail!(
/// "kubectl failed: {}", stderr) }` op arm that dropped both the exit
/// code AND the args entirely. Post-lift the spawn arm carries
/// `Failed to spawn kubectl {args:?}: {io_error}` and the op arm carries
/// `kubectl {args:?} failed (exit {code:?}): {trimmed_stderr}` — the
/// `(cmd, args, exit_code, stderr)` structural-record tuple THEORY §V.4
/// Phase 1 attestation telemetry pattern-matches on.
///
/// Third-occurrence-is-a-law consolidation (THEORY §VI.1): the prior
/// commit (4612831) explicitly anticipated this site as one of the
/// "future shape-adapter[s] that want[] the same anyhow envelope around
/// a queried external CLI" siblings — `seed.rs` and `attestation.rs`
/// were the first two, this is the third.
fn kubectl(args: &[&str]) -> Result<String> {
    crate::retry::classify_capture_query_anyhow(
        Command::new("kubectl").args(args).output(),
        "kubectl",
        args,
    )
}

/// Get Valkey password from Kubernetes secret
fn get_valkey_password(namespace: &str, secret_name: &str, key: &str) -> Result<String> {
    let jsonpath = format!("{{.data.{}}}", key);
    let base64_password = kubectl(&[
        "get",
        "secret",
        secret_name,
        "-n",
        namespace,
        "-o",
        &format!("jsonpath={}", jsonpath),
    ])?;

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
    let output = kubectl(&[
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
    ])?;

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

    let output = kubectl(&["exec", "-n", namespace, pod, "--", "sh", "-c", &script])?;

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
}
