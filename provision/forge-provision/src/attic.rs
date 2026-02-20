//! Attic binary cache provisioning
//!
//! Handles idempotent provisioning of Attic binary caches with configuration
//! file generation and API-based cache creation.

use anyhow::{Context, Result};
use reqwest::Client;
use serde_json::json;
use std::env;
use std::fs;
use std::path::Path;
use tracing::{error, info, warn};

use crate::config::{AtticConfigFile, AtticProvisionConfig, ServerEntry};

/// Provision an Attic binary cache from YAML configuration (idempotent)
///
/// Creates both the Attic configuration file and the cache via API.
/// Safe to run multiple times - will skip if cache already exists.
///
/// # Arguments
/// * `config` - Attic provisioning configuration
pub async fn provision_from_config(config: AtticProvisionConfig) -> Result<()> {
    info!("=== Attic Cache Provisioning (Idempotent) ===");
    info!("Cache name: {}", config.cache_name);
    info!("Server endpoint: {}", config.server.endpoint);
    info!("Server name: {}", config.server.name);

    // Validate configuration
    info!("Validating configuration...");
    config
        .validate()
        .context("Configuration validation failed")?;

    // Read JWT token from environment
    let token = env::var(&config.token_env).with_context(|| {
        format!(
            "Failed to read JWT token from environment variable: {}",
            config.token_env
        )
    })?;

    if token.trim().is_empty() {
        anyhow::bail!(
            "JWT token from environment variable {} is empty or whitespace-only",
            config.token_env
        );
    }

    // Create config directory
    let config_dir = Path::new(&config.config_dir);
    fs::create_dir_all(config_dir)
        .with_context(|| format!("Failed to create config directory: {:?}", config_dir))?;

    // Write attic config
    let config_path = config_dir.join("config.toml");
    write_config_file(&config_path, &config.server.name, &config.server.endpoint, &token)?;
    info!("✓ Config written to: {:?}", config_path);

    // Create cache via Attic API
    create_cache_via_api(&config, &token).await?;

    info!("");
    info!("=== Attic Cache Provisioning Complete ===");
    info!("✓ Cache '{}' is ready for Nix builds", config.cache_name);
    info!(
        "✓ Config available at: {}",
        config_path.display()
    );

    Ok(())
}

/// Write Attic configuration file in TOML format
///
/// Creates a properly formatted Attic client configuration file with server
/// endpoint and authentication token.
fn write_config_file(
    path: &Path,
    server_name: &str,
    endpoint: &str,
    token: &str,
) -> Result<()> {
    let mut servers = std::collections::HashMap::new();
    servers.insert(
        server_name.to_string(),
        ServerEntry {
            endpoint: endpoint.to_string(),
            token: token.to_string(),
        },
    );

    let config = AtticConfigFile {
        default_server: server_name.to_string(),
        servers,
    };

    let toml_content = toml::to_string_pretty(&config)
        .context("Failed to serialize Attic configuration to TOML format")?;

    fs::write(path, toml_content).with_context(|| {
        format!(
            "Failed to write Attic configuration file to path: {}",
            path.display()
        )
    })?;

    Ok(())
}

/// Create cache via Attic API (idempotent)
///
/// Attempts to create a new cache. If the cache already exists (HTTP 409 or 400
/// with CacheAlreadyExists), treats it as success for idempotency.
/// Retries on network failures based on http_max_retries configuration.
async fn create_cache_via_api(config: &AtticProvisionConfig, token: &str) -> Result<()> {
    use std::time::Duration;

    let client = Client::builder()
        .timeout(Duration::from_secs(config.http_timeout_secs))
        .build()
        .context("Failed to build HTTP client for Attic API")?;

    let create_url = format!(
        "{}/_api/v1/cache-config/{}",
        config.server.endpoint.trim_end_matches('/'),
        config.cache_name
    );

    info!("Sending cache creation request to: {}", create_url);

    // Attic API request body with configuration
    let request_body = json!({
        "keypair": config.cache.keypair_strategy,  // Configurable keypair strategy
        "is_public": config.cache.is_public,
        "store_dir": config.cache.store_dir,
        "priority": config.cache.priority,
        "upstream_cache_key_names": config.cache.upstream_cache_key_names
    });

    let mut last_error_msg = String::from("No error details available");

    for attempt in 0..=config.http_max_retries {
        match client
            .post(&create_url)
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/json")
            .json(&request_body)
            .send()
            .await
        {
            Ok(response) => return handle_cache_creation_response(response, &config.cache_name).await,
            Err(e) => {
                last_error_msg = e.to_string();
                if attempt < config.http_max_retries {
                    warn!(
                        "HTTP request failed (attempt {}/{}): {} - retrying in {}s",
                        attempt + 1,
                        config.http_max_retries + 1,
                        last_error_msg,
                        config.http_retry_interval_secs
                    );
                    tokio::time::sleep(Duration::from_secs(config.http_retry_interval_secs)).await;
                }
            }
        }
    }

    anyhow::bail!(
        "Failed to send cache creation request to {} after {} attempts: {}",
        create_url,
        config.http_max_retries + 1,
        last_error_msg
    )
}

/// Handle the HTTP response from cache creation API
async fn handle_cache_creation_response(
    response: reqwest::Response,
    cache_name: &str,
) -> Result<()> {
    let status = response.status();

    if status.is_success() {
        info!("✓ Cache '{}' created successfully", cache_name);
        return Ok(());
    }

    // Handle idempotent cases - cache already exists
    if status.as_u16() == 409 {
        // Standard HTTP 409 Conflict (cache already exists)
        info!("✓ Cache '{}' already exists (idempotent, skipping)", cache_name);
        return Ok(());
    }

    // Attic server quirk: sometimes uses 400 instead of 409 for duplicate caches
    if status.as_u16() == 400 {
        let error_text = response
            .text()
            .await
            .unwrap_or_else(|_| "Unable to read error response body".to_string());

        if error_text.contains("CacheAlreadyExists") {
            info!("✓ Cache '{}' already exists (idempotent, skipping)", cache_name);
            return Ok(());
        }

        error!(
            "Cache creation failed for '{}': HTTP {} - {}",
            cache_name, status, error_text
        );
        anyhow::bail!(
            "Cache creation failed with HTTP {}: {}",
            status,
            error_text
        );
    }

    // Unexpected HTTP error
    let error_text = response
        .text()
        .await
        .unwrap_or_else(|_| "Unable to read error response body".to_string());

    error!(
        "Unexpected cache creation failure for '{}': HTTP {} - {}",
        cache_name, status, error_text
    );
    anyhow::bail!(
        "Cache creation failed with unexpected HTTP {}: {}",
        status,
        error_text
    )
}
