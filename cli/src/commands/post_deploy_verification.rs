//! Post-Deploy Verification Gates
//!
//! This module provides post-deployment health checks and smoke tests:
//! - G12: Health endpoint verification
//! - G13: GraphQL introspection check
//! - G14: Basic smoke tests
//!
//! These gates verify that the deployment was successful and the service
//! is responding correctly.

use anyhow::{Context, Result};
use colored::Colorize;
use reqwest::Client;
use std::time::{Duration, Instant};

use crate::retry::RetryPolicy;

/// The typed exponential-backoff policy for [`verify_health_endpoint`]
/// retries — `initial_backoff` 1s × `factor` 2 capped at `max_backoff`
/// 30s. Consumes the pre-existing typed primitive at
/// [`crate::retry::RetryPolicy`] so the per-attempt delay lands at
/// [`RetryPolicy::compute_delay`], which the retry module's docstring
/// names as its raison d'être: "the pre-existing fixed `sleep(2s)`
/// schedule ... is the worst of both worlds ... Exponential backoff
/// (Bazel-style: 250ms × factor=2 capped at 30s) covers both regimes
/// by construction." Pre-lift the two verbatim
/// `tokio::time::sleep(Duration::from_secs(2_u64.pow(attempt))).await`
/// sites in [`verify_health_endpoint`] carried two defects the typed-
/// primitive body forecloses:
/// 1. **Unbounded schedule.** `2_u64.pow(attempt)` grew without cap, so
///    a caller passing `retries: 20` produced a final pre-retry sleep of
///    `2^19 = 524_288s ≈ 6.1 days` before the loop released the caller
///    — the exact "too short when it's a 30-second upstream incident,
///    12 days too long when it's the same" failure mode the Bazel /
///    Buck2 / BuildKit frontier hermetic-build systems close under
///    their [`RetryPolicy::max_backoff`] cap.
/// 2. **`u64::pow` overflow panic.** `2_u64.pow(attempt)` panics for
///    `attempt >= 64` (`u64::MAX < 2^64`), converting a `retries: 64`+
///    config into a hard panic at the post-deploy health-probe surface
///    — the exact fail-loud defect [`RetryPolicy::compute_delay`]'s
///    `checked_pow` saturating body was written to foreclose ("the cap
///    is enforced even when `factor.pow(n-2)` overflows `u32`, so the
///    schedule is safe for arbitrarily-large `n` without panic").
///
/// The 1s initial / 30s cap preserves the pre-lift schedule at the
/// first five retries (`1s → 2s → 4s → 8s → 16s`, matching the pre-lift
/// `2_u64.pow(0..=4)`) and diverges only at the sixth retry onward
/// where the pre-lift `32s → 64s → 128s → …` climb is replaced by the
/// bounded `30s` ceiling — a strictly-better schedule at every
/// beyond-cap attempt and identical at every within-cap attempt.
///
/// `max_attempts: 1` is a placeholder — the health-endpoint retry loop
/// drives its own attempt budget through the caller-supplied `retries`
/// parameter of the `for attempt in 0..=retries` loop and consumes
/// only [`RetryPolicy::compute_delay`] from this policy, not
/// [`RetryPolicy::max_attempts`]. The `max_attempts` field is
/// unconsulted at this consumption site.
const HEALTH_ENDPOINT_BACKOFF: RetryPolicy =
    RetryPolicy::caller_driven_backoff(Duration::from_secs(1));

/// Backoff between health-endpoint probe retries, given a 0-indexed
/// local `attempt` counter (the `for attempt in 0..=retries` shape
/// [`verify_health_endpoint`] drives).
///
/// Maps the local 0-indexed counter to the 1-indexed
/// [`RetryPolicy::compute_delay`] attempt axis via `saturating_add(2)`:
/// local `attempt == 0` (the pre-retry sleep after the first failed
/// call) reads as `compute_delay(2) = initial_backoff * factor^0 =
/// initial_backoff`; local `attempt == 1` reads as
/// `compute_delay(3) = initial_backoff * factor^1`; and so on. The
/// `saturating_add` clamp forecloses the `u32` overflow class at the
/// bridge — an unlikely-but-possible `attempt == u32::MAX` from a
/// pathological caller reads as `compute_delay(u32::MAX)`, which
/// itself saturates to [`HEALTH_ENDPOINT_BACKOFF::max_backoff`] via
/// the `checked_pow`-then-cap body inside [`RetryPolicy::compute_delay`]
/// without panic.
fn health_endpoint_retry_delay(attempt: u32) -> Duration {
    HEALTH_ENDPOINT_BACKOFF.compute_delay(attempt.saturating_add(2))
}

/// Configuration for post-deploy verification
#[derive(Debug, Clone)]
pub struct PostDeployConfig {
    /// Environment name (staging, production)
    pub environment: String,
    /// Service name
    pub service_name: String,
    /// Health endpoint URL
    pub health_endpoint: String,
    /// GraphQL endpoint URL
    pub graphql_endpoint: String,
    /// Timeout for health checks
    pub timeout: Duration,
    /// Number of retries
    pub retries: u32,
    /// Whether smoke queries are enabled (default: true)
    pub smoke_queries_enabled: bool,
}

/// Result of post-deploy verification
#[derive(Debug)]
pub struct PostDeployResult {
    /// Health check passed
    pub health_passed: bool,
    /// GraphQL check passed
    pub graphql_passed: bool,
    /// Smoke queries passed
    pub smoke_passed: bool,
    /// Response time for health check (ms)
    pub health_latency_ms: Option<u64>,
    /// Response time for GraphQL check (ms)
    pub graphql_latency_ms: Option<u64>,
    /// Error messages
    pub errors: Vec<String>,
}

impl PostDeployResult {
    pub fn is_valid(&self) -> bool {
        self.health_passed && self.graphql_passed && self.smoke_passed
    }
}

/// A smoke query to run against the GraphQL endpoint after deployment
#[derive(Debug, Clone)]
pub struct SmokeQuery {
    /// Human-readable name for this query
    pub name: String,
    /// The GraphQL query string
    pub query: String,
    /// Field that must exist in response.data for the query to pass
    pub expect_field: String,
}

/// Result of a single smoke query
#[derive(Debug)]
pub struct SmokeQueryResult {
    pub name: String,
    pub passed: bool,
    pub latency_ms: Option<u64>,
    pub error: Option<String>,
}

/// G12: Verify health endpoint returns 200
pub async fn verify_health_endpoint(
    health_url: &str,
    timeout: Duration,
    retries: u32,
) -> Result<(bool, Option<u64>)> {
    println!("{}", "G12: Health endpoint check".bold());

    let client = Client::builder()
        .timeout(timeout)
        .danger_accept_invalid_certs(true) // For staging self-signed certs
        .build()
        .context("Failed to build HTTP client")?;

    for attempt in 0..=retries {
        let start = Instant::now();

        match client.get(health_url).send().await {
            Ok(response) => {
                let latency_ms = start.elapsed().as_millis() as u64;

                if response.status().is_success() {
                    println!("   {} Health check passed ({}ms)", "✅".green(), latency_ms);
                    return Ok((true, Some(latency_ms)));
                } else {
                    let status = response.status();
                    if attempt < retries {
                        println!(
                            "   {} Attempt {}/{}: Status {} (retrying...)",
                            "⚠️".yellow(),
                            attempt + 1,
                            retries + 1,
                            status
                        );
                        tokio::time::sleep(health_endpoint_retry_delay(attempt)).await;
                    } else {
                        println!("   {} Health check failed: Status {}", "❌".red(), status);
                        return Ok((false, Some(latency_ms)));
                    }
                }
            }
            Err(e) => {
                if attempt < retries {
                    println!(
                        "   {} Attempt {}/{}: {} (retrying...)",
                        "⚠️".yellow(),
                        attempt + 1,
                        retries + 1,
                        e
                    );
                    tokio::time::sleep(health_endpoint_retry_delay(attempt)).await;
                } else {
                    println!("   {} Health check failed: {}", "❌".red(), e);
                    return Ok((false, None));
                }
            }
        }
    }

    Ok((false, None))
}

/// G13: Verify GraphQL endpoint responds to introspection
pub async fn verify_graphql_endpoint(
    graphql_url: &str,
    timeout: Duration,
) -> Result<(bool, Option<u64>)> {
    println!("{}", "G13: GraphQL introspection check".bold());

    let client = Client::builder()
        .timeout(timeout)
        .danger_accept_invalid_certs(true)
        .build()
        .context("Failed to build HTTP client")?;

    // Simple introspection query
    let query = serde_json::json!({
        "query": "{ __typename }"
    });

    let start = Instant::now();

    match client
        .post(graphql_url)
        .header("Content-Type", "application/json")
        .json(&query)
        .send()
        .await
    {
        Ok(response) => {
            let latency_ms = start.elapsed().as_millis() as u64;

            if response.status().is_success() {
                // Parse response to verify it's valid GraphQL
                match response.json::<serde_json::Value>().await {
                    Ok(json) => {
                        if json.get("data").is_some() {
                            println!("   {} GraphQL responding ({}ms)", "✅".green(), latency_ms);
                            return Ok((true, Some(latency_ms)));
                        } else if let Some(errors) = json.get("errors") {
                            println!("   {} GraphQL returned errors: {}", "❌".red(), errors);
                            return Ok((false, Some(latency_ms)));
                        }
                    }
                    Err(e) => {
                        println!("   {} Failed to parse GraphQL response: {}", "❌".red(), e);
                        return Ok((false, Some(latency_ms)));
                    }
                }
            } else {
                println!(
                    "   {} GraphQL check failed: Status {}",
                    "❌".red(),
                    response.status()
                );
                return Ok((false, Some(latency_ms)));
            }
        }
        Err(e) => {
            println!("   {} GraphQL check failed: {}", "❌".red(), e);
            return Ok((false, None));
        }
    }

    Ok((false, None))
}

/// Default smoke queries to validate deployment health
pub fn default_smoke_queries() -> Vec<SmokeQuery> {
    vec![SmokeQuery {
        name: "Schema introspection".to_string(),
        query: r#"{ __schema { queryType { name } } }"#.to_string(),
        expect_field: "__schema".to_string(),
    }]
}

/// G15: Verify smoke queries return expected data
pub async fn verify_smoke_queries(
    graphql_url: &str,
    queries: &[SmokeQuery],
    timeout: Duration,
) -> Result<(bool, Vec<SmokeQueryResult>)> {
    println!("{}", "G15: Smoke query validation".bold());

    let client = Client::builder()
        .timeout(timeout)
        .danger_accept_invalid_certs(true)
        .build()
        .context("Failed to build HTTP client")?;

    let mut results = Vec::new();
    let mut all_passed = true;

    for smoke in queries {
        let start = Instant::now();

        let query = serde_json::json!({
            "query": smoke.query
        });

        match client
            .post(graphql_url)
            .header("Content-Type", "application/json")
            .json(&query)
            .send()
            .await
        {
            Ok(response) => {
                let latency_ms = start.elapsed().as_millis() as u64;

                if !response.status().is_success() {
                    let status = response.status();
                    println!(
                        "   {} {}: HTTP {} ({}ms)",
                        "❌".red(),
                        smoke.name,
                        status,
                        latency_ms
                    );
                    results.push(SmokeQueryResult {
                        name: smoke.name.clone(),
                        passed: false,
                        latency_ms: Some(latency_ms),
                        error: Some(format!("HTTP {}", status)),
                    });
                    all_passed = false;
                    continue;
                }

                match response.json::<serde_json::Value>().await {
                    Ok(json) => {
                        let has_field = json
                            .get("data")
                            .and_then(|d| d.get(&smoke.expect_field))
                            .is_some();

                        if has_field {
                            println!("   {} {}: OK ({}ms)", "✅".green(), smoke.name, latency_ms);
                            results.push(SmokeQueryResult {
                                name: smoke.name.clone(),
                                passed: true,
                                latency_ms: Some(latency_ms),
                                error: None,
                            });
                        } else {
                            let has_errors = json.get("errors").is_some();
                            let error_msg = if has_errors {
                                format!("GraphQL errors: {}", json.get("errors").unwrap())
                            } else {
                                format!(
                                    "Missing expected field '{}' in response",
                                    smoke.expect_field
                                )
                            };
                            println!(
                                "   {} {}: {} ({}ms)",
                                "❌".red(),
                                smoke.name,
                                error_msg,
                                latency_ms
                            );
                            results.push(SmokeQueryResult {
                                name: smoke.name.clone(),
                                passed: false,
                                latency_ms: Some(latency_ms),
                                error: Some(error_msg),
                            });
                            all_passed = false;
                        }
                    }
                    Err(e) => {
                        println!(
                            "   {} {}: Failed to parse response: {} ({}ms)",
                            "❌".red(),
                            smoke.name,
                            e,
                            latency_ms
                        );
                        results.push(SmokeQueryResult {
                            name: smoke.name.clone(),
                            passed: false,
                            latency_ms: Some(latency_ms),
                            error: Some(format!("Parse error: {}", e)),
                        });
                        all_passed = false;
                    }
                }
            }
            Err(e) => {
                println!("   {} {}: {}", "❌".red(), smoke.name, e);
                results.push(SmokeQueryResult {
                    name: smoke.name.clone(),
                    passed: false,
                    latency_ms: None,
                    error: Some(e.to_string()),
                });
                all_passed = false;
            }
        }
    }

    Ok((all_passed, results))
}

/// Run all post-deploy verification gates
pub async fn verify_deployment(config: &PostDeployConfig) -> Result<PostDeployResult> {
    println!();
    println!(
        "{}",
        "════════════════════════════════════════════════".bold()
    );
    println!("{}", "  Post-Deploy Verification".bold());
    println!(
        "{}",
        "════════════════════════════════════════════════".bold()
    );
    println!();
    println!("Environment: {}", config.environment);
    println!("Service: {}", config.service_name);
    println!("Health URL: {}", config.health_endpoint);
    println!("GraphQL URL: {}", config.graphql_endpoint);
    println!();

    let mut errors = Vec::new();

    // G12: Health endpoint
    let (health_passed, health_latency_ms) =
        verify_health_endpoint(&config.health_endpoint, config.timeout, config.retries).await?;

    if !health_passed {
        errors.push(format!(
            "Health endpoint {} not responding",
            config.health_endpoint
        ));
    }
    println!();

    // G13: GraphQL introspection
    let (graphql_passed, graphql_latency_ms) =
        verify_graphql_endpoint(&config.graphql_endpoint, config.timeout).await?;

    if !graphql_passed {
        errors.push(format!(
            "GraphQL endpoint {} not responding",
            config.graphql_endpoint
        ));
    }
    println!();

    // G15: Smoke query validation
    let smoke_passed = if config.smoke_queries_enabled {
        println!();
        let smoke_queries = default_smoke_queries();
        let (passed, smoke_results) =
            verify_smoke_queries(&config.graphql_endpoint, &smoke_queries, config.timeout).await?;

        if !passed {
            for sr in &smoke_results {
                if !sr.passed {
                    if let Some(ref err) = sr.error {
                        errors.push(format!("Smoke query '{}' failed: {}", sr.name, err));
                    }
                }
            }
        }
        passed
    } else {
        println!();
        println!("   {} G15: Smoke queries (disabled)", "⏭️");
        true // Don't fail if disabled
    };

    let result = PostDeployResult {
        health_passed,
        graphql_passed,
        smoke_passed,
        health_latency_ms,
        graphql_latency_ms,
        errors,
    };

    // Print summary
    println!();
    if result.is_valid() {
        println!("{}", "✅ Post-deploy verification passed!".green().bold());
    } else {
        println!("{}", "❌ Post-deploy verification failed!".red().bold());
        for error in &result.errors {
            println!("   - {}", error);
        }
    }

    Ok(result)
}

/// Quick health check without full verification
pub async fn quick_health_check(url: &str) -> Result<bool> {
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .danger_accept_invalid_certs(true)
        .build()?;

    match client.get(url).send().await {
        Ok(response) => Ok(response.status().is_success()),
        Err(_) => Ok(false),
    }
}

/// Build endpoints from product domain configuration
///
/// Endpoints should be configured in deploy.yaml, not hardcoded.
/// This function generates URLs based on product domain and environment.
///
/// # Arguments
/// * `product_domain` - Base domain for the product (e.g., "example.com")
/// * `environment` - Environment name (staging, production)
///
/// # Returns
/// Tuple of (health_url, graphql_url)
pub fn get_product_endpoints(product_domain: &str, environment: &str) -> (String, String) {
    match environment {
        "production" => (
            format!("https://{}/health", product_domain),
            format!("https://{}/graphql", product_domain),
        ),
        env => (
            format!("https://{}.{}/health", env, product_domain),
            format!("https://{}.{}/graphql", env, product_domain),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ====================================================================
    // PostDeployResult validation
    // ====================================================================

    #[test]
    fn test_post_deploy_result_all_passing() {
        let result = PostDeployResult {
            health_passed: true,
            graphql_passed: true,
            smoke_passed: true,
            health_latency_ms: Some(50),
            graphql_latency_ms: Some(100),
            errors: vec![],
        };
        assert!(result.is_valid());
    }

    #[test]
    fn test_post_deploy_result_health_failed() {
        let result = PostDeployResult {
            health_passed: false,
            graphql_passed: true,
            smoke_passed: true,
            health_latency_ms: None,
            graphql_latency_ms: Some(100),
            errors: vec!["Health endpoint not responding".to_string()],
        };
        assert!(!result.is_valid());
    }

    #[test]
    fn test_post_deploy_result_graphql_failed() {
        let result = PostDeployResult {
            health_passed: true,
            graphql_passed: false,
            smoke_passed: true,
            health_latency_ms: Some(50),
            graphql_latency_ms: None,
            errors: vec!["GraphQL not responding".to_string()],
        };
        assert!(!result.is_valid());
    }

    #[test]
    fn test_post_deploy_result_smoke_failed() {
        let result = PostDeployResult {
            health_passed: true,
            graphql_passed: true,
            smoke_passed: false,
            health_latency_ms: Some(50),
            graphql_latency_ms: Some(100),
            errors: vec!["Smoke query failed".to_string()],
        };
        assert!(!result.is_valid());
    }

    #[test]
    fn test_post_deploy_result_all_failed() {
        let result = PostDeployResult {
            health_passed: false,
            graphql_passed: false,
            smoke_passed: false,
            health_latency_ms: None,
            graphql_latency_ms: None,
            errors: vec![
                "Health failed".to_string(),
                "GraphQL failed".to_string(),
                "Smoke failed".to_string(),
            ],
        };
        assert!(!result.is_valid());
        assert_eq!(result.errors.len(), 3);
    }

    #[test]
    fn test_post_deploy_result_no_latency() {
        let result = PostDeployResult {
            health_passed: true,
            graphql_passed: true,
            smoke_passed: true,
            health_latency_ms: None,
            graphql_latency_ms: None,
            errors: vec![],
        };
        assert!(result.is_valid());
    }

    // ====================================================================
    // SmokeQuery and SmokeQueryResult
    // ====================================================================

    #[test]
    fn test_smoke_query_construction() {
        let query = SmokeQuery {
            name: "Test query".to_string(),
            query: "{ __typename }".to_string(),
            expect_field: "__typename".to_string(),
        };
        assert_eq!(query.name, "Test query");
        assert_eq!(query.expect_field, "__typename");
    }

    #[test]
    fn test_smoke_query_result_passed() {
        let result = SmokeQueryResult {
            name: "Schema check".to_string(),
            passed: true,
            latency_ms: Some(42),
            error: None,
        };
        assert!(result.passed);
        assert!(result.error.is_none());
    }

    #[test]
    fn test_smoke_query_result_failed_with_error() {
        let result = SmokeQueryResult {
            name: "Schema check".to_string(),
            passed: false,
            latency_ms: Some(1000),
            error: Some("Missing field '__schema'".to_string()),
        };
        assert!(!result.passed);
        assert!(result.error.is_some());
        assert!(result.error.unwrap().contains("__schema"));
    }

    // ====================================================================
    // default_smoke_queries
    // ====================================================================

    #[test]
    fn test_default_smoke_queries_not_empty() {
        let queries = default_smoke_queries();
        assert!(!queries.is_empty());
    }

    #[test]
    fn test_default_smoke_queries_has_schema_introspection() {
        let queries = default_smoke_queries();
        let schema_query = queries.iter().find(|q| q.expect_field == "__schema");
        assert!(schema_query.is_some(), "Should have a __schema query");
        let sq = schema_query.unwrap();
        assert!(sq.query.contains("__schema"));
        assert!(sq.query.contains("queryType"));
    }

    #[test]
    fn test_default_smoke_queries_are_valid_graphql() {
        let queries = default_smoke_queries();
        for query in &queries {
            assert!(!query.name.is_empty(), "Query name should not be empty");
            assert!(!query.query.is_empty(), "Query string should not be empty");
            assert!(
                !query.expect_field.is_empty(),
                "Expected field should not be empty"
            );
            // Basic GraphQL syntax check
            assert!(
                query.query.contains('{') && query.query.contains('}'),
                "Query should contain curly braces: {}",
                query.query
            );
        }
    }

    // ====================================================================
    // PostDeployConfig
    // ====================================================================

    #[test]
    fn test_post_deploy_config_construction() {
        let config = PostDeployConfig {
            environment: "staging".to_string(),
            service_name: "testapp".to_string(),
            health_endpoint: "https://staging.example.com/health".to_string(),
            graphql_endpoint: "https://staging.example.com/graphql".to_string(),
            timeout: Duration::from_secs(30),
            retries: 3,
            smoke_queries_enabled: true,
        };
        assert_eq!(config.environment, "staging");
        assert_eq!(config.retries, 3);
        assert!(config.smoke_queries_enabled);
    }

    #[test]
    fn test_post_deploy_config_smoke_disabled() {
        let config = PostDeployConfig {
            environment: "staging".to_string(),
            service_name: "testapp".to_string(),
            health_endpoint: "https://staging.example.com/health".to_string(),
            graphql_endpoint: "https://staging.example.com/graphql".to_string(),
            timeout: Duration::from_secs(30),
            retries: 3,
            smoke_queries_enabled: false,
        };
        assert!(!config.smoke_queries_enabled);
    }

    // ====================================================================
    // Endpoint generation
    // ====================================================================

    #[test]
    fn test_get_product_endpoints_staging() {
        let (health, graphql) = get_product_endpoints("example.com", "staging");
        assert_eq!(health, "https://staging.example.com/health");
        assert_eq!(graphql, "https://staging.example.com/graphql");
    }

    #[test]
    fn test_get_product_endpoints_production() {
        let (health, graphql) = get_product_endpoints("example.com", "production");
        assert_eq!(health, "https://example.com/health");
        assert_eq!(graphql, "https://example.com/graphql");
    }

    #[test]
    fn test_get_product_endpoints_custom_env() {
        let (health, graphql) = get_product_endpoints("example.io", "canary");
        assert_eq!(health, "https://canary.example.io/health");
        assert_eq!(graphql, "https://canary.example.io/graphql");
    }

    #[test]
    fn test_get_product_endpoints_another_domain() {
        let (health, graphql) = get_product_endpoints("example.io", "staging");
        assert_eq!(health, "https://staging.example.io/health");
        assert_eq!(graphql, "https://staging.example.io/graphql");
    }

    // ====================================================================
    // health-endpoint retry backoff — HEALTH_ENDPOINT_BACKOFF + helper
    // ====================================================================
    //
    // These pin the RetryPolicy-consuming replacement of the pre-lift
    // `tokio::time::sleep(Duration::from_secs(2_u64.pow(attempt)))` sites
    // in `verify_health_endpoint`. The pre-lift schedule (a) grew
    // unbounded and (b) panicked at `attempt >= 64` via `u64::pow`
    // overflow; the RetryPolicy-consuming replacement inherits
    // `compute_delay`'s `checked_pow`-then-cap saturating body, so
    // (a) the schedule tops out at `max_backoff` and (b) arbitrarily-large
    // attempts return a bounded delay without panic.
    //
    // Test 1 pins the const's `(initial_backoff, factor, max_backoff)`
    // shape as a load-bearing invariant a future edit desyncs at a named
    // site rather than silently across the two consumption sites in the
    // health-endpoint loop.
    //
    // Test 2 pins the pre-lift-schedule-preservation property at every
    // in-cap attempt: `attempt in 0..=4` produces `1s / 2s / 4s / 8s /
    // 16s` verbatim, matching the pre-lift `2_u64.pow(0..=4)` at every
    // legal-schedule attempt so the lift is behavior-preserving in the
    // regime the pre-lift schedule was ever intended to reach.
    //
    // Test 3 pins the max-backoff-cap property at every past-cap
    // attempt: `attempt in 5..=20` all cap at `30s`, whereas the
    // pre-lift schedule at attempt=5 was 32s, at attempt=6 was 64s, at
    // attempt=10 was 1024s (~17 min), at attempt=20 was 1_048_576s
    // (~12 days) — a bounded ceiling that closes the "12-days-of-sleep"
    // pathology the pre-lift `retries: 20` config would silently
    // produce. Fails pre-lift because
    // `Duration::from_secs(2_u64.pow(5)) == Duration::from_secs(32)`,
    // not `Duration::from_secs(30)`.
    //
    // Test 4 pins the no-panic property at arbitrarily-large attempts,
    // the defect that would have been a hard runtime panic pre-lift.
    // A pre-lift `2_u64.pow(64)` panics with attempt-to-compute-2^64-
    // which-does-not-fit-in-u64; the RetryPolicy body's
    // `checked_pow(u128)` returns `None` on overflow, which the body
    // maps to `self.max_backoff` short-circuit. The bridge helper's
    // `saturating_add(2)` closes the outer overflow class before
    // `compute_delay` sees the argument.

    #[test]
    fn test_health_endpoint_backoff_policy_shape() {
        assert_eq!(
            HEALTH_ENDPOINT_BACKOFF.initial_backoff,
            Duration::from_secs(1)
        );
        assert_eq!(HEALTH_ENDPOINT_BACKOFF.factor, 2);
        assert_eq!(HEALTH_ENDPOINT_BACKOFF.max_backoff, Duration::from_secs(30));
    }

    #[test]
    fn test_health_endpoint_retry_delay_matches_pre_lift_schedule_at_in_cap_attempts() {
        // Pre-lift verbatim: `Duration::from_secs(2_u64.pow(attempt))`
        // for `attempt in 0..=4`. Every attempt within the 30s cap
        // is behavior-preserving under the lift.
        assert_eq!(health_endpoint_retry_delay(0), Duration::from_secs(1));
        assert_eq!(health_endpoint_retry_delay(1), Duration::from_secs(2));
        assert_eq!(health_endpoint_retry_delay(2), Duration::from_secs(4));
        assert_eq!(health_endpoint_retry_delay(3), Duration::from_secs(8));
        assert_eq!(health_endpoint_retry_delay(4), Duration::from_secs(16));
    }

    #[test]
    fn test_health_endpoint_retry_delay_caps_at_max_backoff_past_the_cap() {
        // Pre-lift these attempts produced 32s, 64s, 1024s, and
        // 1_048_576s (~12 days) — an unbounded exponential the retry-
        // module's typed primitive replaces with a bounded 30s ceiling.
        // Fails pre-lift: `2_u64.pow(5) == 32`, not `30`.
        assert_eq!(health_endpoint_retry_delay(5), Duration::from_secs(30));
        assert_eq!(health_endpoint_retry_delay(6), Duration::from_secs(30));
        assert_eq!(health_endpoint_retry_delay(10), Duration::from_secs(30));
        assert_eq!(health_endpoint_retry_delay(20), Duration::from_secs(30));
    }

    #[test]
    fn test_health_endpoint_retry_delay_saturates_without_panic_at_arbitrarily_large_attempt() {
        // Pre-lift `2_u64.pow(64)` panics with `attempt to multiply with
        // overflow` (u64::MAX == 2^64 - 1 < 2^64). The RetryPolicy
        // body's u128 checked_pow returns None on overflow, mapped to
        // `max_backoff` — no panic. The bridge helper's
        // `saturating_add(2)` closes the outer u32 overflow class
        // before `compute_delay` sees the argument.
        assert_eq!(health_endpoint_retry_delay(64), Duration::from_secs(30));
        assert_eq!(
            health_endpoint_retry_delay(u32::MAX - 1),
            Duration::from_secs(30)
        );
        assert_eq!(
            health_endpoint_retry_delay(u32::MAX),
            Duration::from_secs(30)
        );
    }
}
