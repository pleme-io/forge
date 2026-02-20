//! Cloudflare cache purging integration
//!
//! This module handles automatic Cloudflare cache purging after deployments
//! to ensure users receive fresh content (env.js, version.json, etc.).

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::{error, info};

/// Cloudflare API response for cache purge
#[derive(Debug, Deserialize)]
struct CloudflareResponse {
    success: bool,
    errors: Vec<CloudflareError>,
    #[allow(dead_code)]
    messages: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct CloudflareError {
    code: i32,
    message: String,
}

/// Request body for cache purge
#[derive(Debug, Serialize)]
struct PurgeRequest {
    files: Vec<String>,
}

/// Purge Cloudflare cache for specific URLs
///
/// This MUST be called after every web deployment to prevent users from
/// receiving stale configuration or version information.
///
/// # Arguments
/// * `zone_id` - Cloudflare zone ID for the domain
/// * `api_token` - Cloudflare API token with cache purge permissions
/// * `urls` - List of full URLs to purge (e.g., ["https://staging.example.com/env.js"])
///
/// # Returns
/// * `Ok(())` - Cache purged successfully
/// * `Err` - Purge failed (deployment should fail)
///
/// # Example
/// ```rust,ignore
/// purge_cache(
///     "YOUR_CLOUDFLARE_ZONE_ID",
///     "YOUR_CLOUDFLARE_API_TOKEN",
///     &["https://example.com/env.js".to_string()]
/// ).await?;
/// ```
pub async fn purge_cache(zone_id: &str, api_token: &str, urls: &[String]) -> Result<()> {
    info!("☁️  Purging Cloudflare cache");
    info!("   Zone ID: {}***", &zone_id[..8.min(zone_id.len())]);

    let client = reqwest::Client::new();

    info!("   Files to purge:");
    for file in urls {
        info!("   • {}", file);
    }

    let request_body = PurgeRequest {
        files: urls.to_vec(),
    };

    let url = format!(
        "https://api.cloudflare.com/client/v4/zones/{}/purge_cache",
        zone_id
    );

    let response = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", api_token))
        .header("Content-Type", "application/json")
        .json(&request_body)
        .send()
        .await
        .context("Failed to send Cloudflare cache purge request")?;

    let status = response.status();
    let response_text = response
        .text()
        .await
        .context("Failed to read Cloudflare API response")?;

    // Parse JSON response
    let cf_response: CloudflareResponse = serde_json::from_str(&response_text).context(format!(
        "Failed to parse Cloudflare response: {}",
        response_text
    ))?;

    if !cf_response.success {
        let error_messages: Vec<String> = cf_response
            .errors
            .iter()
            .map(|e| format!("[{}] {}", e.code, e.message))
            .collect();

        error!("❌ Cloudflare cache purge failed!");
        error!("   Status: {}", status);
        error!("   Errors: {}", error_messages.join(", "));

        anyhow::bail!(
            "Cloudflare cache purge failed: {}",
            error_messages.join(", ")
        );
    }

    info!("✅ Cloudflare cache purged successfully");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_purge_request_serialization() {
        let request = PurgeRequest {
            files: vec![
                "https://example.com/env.js".to_string(),
                "https://example.com/version.json".to_string(),
            ],
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("env.js"));
        assert!(json.contains("version.json"));
    }
}
