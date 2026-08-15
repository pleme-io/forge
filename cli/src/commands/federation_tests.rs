//! # Federation Integration Tests Module
//!
//! Runs GraphQL federation integration tests after service deployment via Kubernetes Jobs.
//!
//! ## Architecture
//!
//! - **Post-Deployment**: Tests run AFTER service deployment and federation update complete
//! - **Dynamic Jobs**: Creates timestamped Kubernetes Jobs for each test run
//! - **Config-Driven**: Test suite, timeout, and options from deploy.yaml
//! - **Blocking**: Deployment waits for test completion (similar to database migrations)
//! - **Image Versioning**: Uses same git SHA as deployed service for consistency
//!
//! ## Federation Test Job Pattern
//!
//! Jobs are created dynamically with:
//! - Timestamped names (e.g., `myapp-auth-federation-tests-1699999999`)
//! - Git SHA-tagged test image (e.g., `federation-tests:amd64-abc123`)
//! - Automatic cleanup after 1 hour (`ttlSecondsAfterFinished: 3600`)
//! - Service-specific test suite selection (e.g., `--suite auth`)
//! - Configurable fail-fast behavior for faster feedback
//!
//! ## Workflow Integration
//!
//! 1. Service is deployed and becomes ready
//! 2. GraphQL schema is extracted and federation is updated
//! 3. Federation tests run against the updated Hive Router
//! 4. Deployment succeeds only if tests pass (or tests disabled)

use anyhow::{bail, Context, Result};
use colored::Colorize;
use std::collections::BTreeMap;
use std::process::Stdio;

use k8s_openapi::api::batch::v1::{Job, JobSpec};
use k8s_openapi::api::core::v1::{
    ConfigMapKeySelector, ConfigMapVolumeSource, Container, EnvVar, KeyToPath,
    LocalObjectReference, PodSpec, PodTemplateSpec, ResourceRequirements, Volume, VolumeMount,
};
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

use std::time::Duration;

use crate::config::DeployConfig;
use crate::infrastructure::kubectl::kubectl_command_async;
use crate::retry::RetryPolicy;

/// The typed exponential-backoff policy for [`wait_for_job_completion`]
/// federation-test k8s-Job status-poll cadence — `initial_backoff` 5s ×
/// `factor` 2 capped at `max_backoff` 30s. Consumes the pre-existing
/// typed primitive at [`crate::retry::RetryPolicy`] so the per-attempt
/// delay lands at [`RetryPolicy::compute_delay`], the same shared body
/// the sibling k8s-workload-poll surfaces `services/migration_service.rs
/// ::MIGRATION_JOB_POLL_BACKOFF` (commit ac61874), `commands/migrations
/// .rs::SHINKA_MIGRATION_POLL_BACKOFF` (commit b962db5), and
/// `commands/github_runner_ci.rs::GITHUB_RUNNER_ROLLOUT_POLL_BACKOFF`
/// (commit 7fe79de) read through.
///
/// Pre-lift the schedule was spelled inline as a bare fixed
/// `tokio::time::sleep(tokio::time::Duration::from_secs(5)).await` at
/// every non-terminal arm of the federation-test k8s-Job status-poll
/// loop. That shape carried three structural defects the typed-primitive
/// body forecloses:
/// 1. **Fixed 5s schedule.** A flat `sleep(5s)` between poll iterations
///    is "too short when the federation-test job is actually running (up
///    to ~72 kubectl probes across the 6-minute default `job_timeout +
///    60s` buffer window — noise against the k8s API), 5s too long when
///    the Complete condition landed 200ms ago" — the exact worst-of-
///    both failure mode the sibling `MIGRATION_JOB_POLL_BACKOFF` /
///    `SHINKA_MIGRATION_POLL_BACKOFF` / `GITHUB_RUNNER_ROLLOUT_POLL_
///    BACKOFF` docstrings cite for their own pre-lift fixed schedules.
///    Post-lift the first poll still waits 5s (preserving the seed
///    verbatim), then 10s / 20s / 30s / 30s / … — ~13 iterations reach
///    the 6-minute default window under the exponential-with-cap climb
///    rather than 72 iterations under the pre-lift flat 5s.
/// 2. **No caller-visible schedule invariant.** The bare
///    `Duration::from_secs(5)` literal at the poll-loop sleep carried no
///    name a shield could pin — a future edit that changed the schedule
///    at this site did not surface at any named-primitive audit path.
///    The lifted `FEDERATION_JOB_POLL_BACKOFF` const names the (seed,
///    factor, cap) triple a shield can cite and enforce.
/// 3. **Schedule desync from the sibling k8s-workload-poll quartet.**
///    The federation-test job status-poll loop observes a k8s Job's
///    `Complete`/`Failed` conditions; the sibling `wait_for_job` loop
///    (services/migration_service.rs, ac61874) observes a k8s Job's
///    `Complete`/`Failed` conditions verbatim the same way; the sibling
///    `wait_for_shinka_migration` loop (commands/migrations.rs, b962db5)
///    observes a Shinka reconciler's phase transitions; the sibling
///    StatefulSet rollout-watch loop (commands/github_runner_ci.rs,
///    7fe79de) observes per-pod status conditions. All four poll the
///    k8s API for a workload resource's terminal transition and pre-
///    lift each spelled its own local fixed-sleep schedule, so a future
///    edit to one silently diverged from the others. Post-lift all four
///    consume the same shared body via the same `RetryPolicy::network()`
///    `(factor=2, max_backoff=30s)` reference schedule, differing only
///    at their respective pre-lift seeds (5s here, 5s at the rollout-
///    watch sibling, 2s at the migration-job / shinka-reconcile
///    siblings) each preserves verbatim.
///
/// `max_attempts: u32::MAX` is a placeholder — the poll loop is bounded
/// by wall-clock via the caller-supplied `timeout_seconds + 60s` buffer
/// (`start.elapsed() > timeout` at loop head), not by attempt count —
/// and consumes only [`RetryPolicy::compute_delay`] from this policy,
/// not [`RetryPolicy::max_attempts`]. The `max_attempts` field is
/// unconsulted at this consumption site.
// `#[allow(dead_code)]` here mirrors the pre-existing baseline flags on
// `wait_for_job_completion` / `run_federation_tests` / `check_job_success`
// / `create_federation_test_job` inside this module — the whole non-test
// consumer chain in `commands/federation_tests.rs` is dead-code-flagged
// under `cargo clippy --all-targets` on the main `forge` bin target
// because clippy's cross-module reachability from
// `commands/rust_service.rs::run_rust_service_release` does not resolve
// through the enclosing async surface. The sibling k8s-workload-poll
// primitives in `services/migration_service.rs` (ac61874),
// `commands/migrations.rs` (b962db5), and
// `commands/github_runner_ci.rs` (7fe79de) do NOT need this attribute
// because each of THEIR consumer chains does resolve to a reachable
// entry point. Adding `#[allow(dead_code)]` here keeps this lift's
// clippy delta at 0 new baseline errors (the pre-lift file was already
// flagged; the post-lift file adds nothing new).
#[allow(dead_code)]
const FEDERATION_JOB_POLL_BACKOFF: RetryPolicy = RetryPolicy {
    max_attempts: u32::MAX,
    initial_backoff: Duration::from_secs(5),
    factor: 2,
    max_backoff: Duration::from_secs(30),
};

/// Backoff between federation-test k8s-Job status-poll iterations,
/// given a 0-indexed local `attempt` counter (the `loop { ... }` shape
/// [`wait_for_job_completion`] drives increments once per non-terminal
/// iteration).
///
/// Maps the local 0-indexed counter to the 1-indexed
/// [`RetryPolicy::compute_delay`] attempt axis via `saturating_add(2)`:
/// local `attempt == 0` (the sleep after the first non-terminal poll)
/// reads as `compute_delay(2) = initial_backoff * factor^0 =
/// initial_backoff = 5s`; local `attempt == 1` reads as
/// `compute_delay(3) = 10s`; local `attempt == 2` reads as
/// `compute_delay(4) = 20s`; local `attempt >= 3` reads as
/// `compute_delay(>=5) = 30s` (cap) — preserves the pre-lift
/// `sleep(Duration::from_secs(5))` seed verbatim at the first poll and
/// strictly diverges upward at every later poll.
///
/// The `saturating_add` clamp forecloses the `u32` overflow class at
/// the bridge — a pathologically-long-running poll loop that reaches
/// `attempt == u32::MAX` reads as `compute_delay(u32::MAX)`, which
/// itself saturates to [`FEDERATION_JOB_POLL_BACKOFF::max_backoff`] via
/// the `checked_pow`-then-cap body inside [`RetryPolicy::compute_delay`]
/// without panic.
#[allow(dead_code)]
fn federation_job_poll_delay(attempt: u32) -> Duration {
    FEDERATION_JOB_POLL_BACKOFF.compute_delay(attempt.saturating_add(2))
}

/// Run federation integration tests for a service
///
/// Creates a Kubernetes Job that runs the federation-tests image
/// with the specified test suite for this service.
///
/// # Arguments
/// * `federation_tests_tag_override` - Optional override for the federation-tests image tag.
///   If provided, this tag will be used instead of reading from deploy_config.
///   This is useful when the federation-tests image was just built and the deploy_config
///   hasn't been reloaded yet.
pub async fn run_federation_tests(
    service_name: &str,
    product: &str,
    environment: &str,
    namespace: &str,
    test_suite: &str,
    router_url: &str,
    timeout_seconds: u64,
    fail_fast: bool,
    git_sha: &str,
    deploy_config: &DeployConfig,
    federation_tests_tag_override: Option<&str>,
) -> Result<()> {
    println!();
    println!(
        "🧪 {}",
        format!(
            "Running federation integration tests for {}...",
            service_name
        )
        .bold()
    );
    println!("   Suite: {}", test_suite.cyan());
    println!("   Router: {}", router_url);
    println!("   Timeout: {}s", timeout_seconds);

    // Generate unique job name with timestamp
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let job_name = format!(
        "{}-{}-federation-tests-{}",
        product, service_name, timestamp
    );

    // Build the federation test job manifest
    let manifest = create_federation_test_job(
        &job_name,
        namespace,
        service_name,
        product,
        environment,
        test_suite,
        router_url,
        timeout_seconds,
        fail_fast,
        git_sha,
        deploy_config,
        federation_tests_tag_override,
    )?;

    // Write manifest to temporary file
    let manifest_path = format!("/tmp/{}.yaml", job_name);
    std::fs::write(&manifest_path, manifest)
        .context("Failed to write federation test job manifest")?;

    println!("   📝 Created job manifest: {}", manifest_path);

    // Apply the job
    println!("   🚀 Creating federation test job...");
    let output = kubectl_command_async()
        .args(&["apply", "-f", &manifest_path])
        .output()
        .await
        .context("Failed to create federation test job")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("Failed to create federation test job:\n{}", stderr);
    }

    println!("   ✅ Job created: {}", job_name.green());

    // Wait for job completion
    println!(
        "   ⏳ Waiting for tests to complete (timeout: {}s)...",
        timeout_seconds
    );
    let wait_result = wait_for_job_completion(&job_name, namespace, timeout_seconds).await;

    // Check job status (even if we timed out, check what state it's in)
    let job_succeeded = check_job_success(&job_name, namespace)
        .await
        .unwrap_or(false);

    // Clean up manifest file
    let _ = std::fs::remove_file(&manifest_path);

    // Handle results
    match (wait_result, job_succeeded) {
        (Ok(()), true) => {
            println!("   ✅ {}", "Federation tests passed!".green().bold());
            Ok(())
        }
        (wait_result, _) => {
            // Job timed out or failed - fetch logs for debugging
            let failure_reason = match wait_result {
                Err(e) => format!("Timeout: {}", e),
                Ok(()) => "Job failed".to_string(),
            };

            println!(
                "   ❌ {}",
                format!("Federation tests failed: {}", failure_reason)
                    .red()
                    .bold()
            );
            println!("   📋 Fetching job logs for debugging...");
            println!();

            // Fetch logs with better error handling
            let log_output = kubectl_command_async()
                .args(&[
                    "logs",
                    "-n",
                    namespace,
                    &format!("job/{}", job_name),
                    "--tail=100",
                ])
                .output()
                .await;

            match log_output {
                Ok(output) if output.status.success() => {
                    let logs = String::from_utf8_lossy(&output.stdout);
                    println!("{}", "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                    println!("{}", logs);
                    println!("{}", "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                    println!();
                }
                Ok(output) => {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    eprintln!("   ⚠️  Could not fetch logs: {}", stderr);
                }
                Err(e) => {
                    eprintln!("   ⚠️  Could not fetch logs: {}", e);
                }
            }

            // Also fetch job status for more details
            println!("   📋 Fetching job status...");
            let status_output = kubectl_command_async()
                .args(&["get", "job", &job_name, "-n", namespace, "-o", "yaml"])
                .output()
                .await;

            if let Ok(output) = status_output {
                if output.status.success() {
                    let status = String::from_utf8_lossy(&output.stdout);
                    // Extract just the status section
                    if let Some(status_section) = status.split("status:").nth(1) {
                        println!("{}", "Job Status:".bold());
                        println!(
                            "{}",
                            status_section
                                .lines()
                                .take(20)
                                .collect::<Vec<_>>()
                                .join("\n")
                        );
                    }
                }
            }

            bail!(
                "Federation integration tests failed for service '{}': {}",
                service_name,
                failure_reason
            );
        }
    }
}

/// Create federation test job manifest using typed Kubernetes API
///
/// This function uses k8s-openapi types instead of string templates to ensure:
/// - Compile-time type safety
/// - No indentation bugs
/// - IDE autocomplete and refactoring support
/// - Automatic validation of required fields
fn create_federation_test_job(
    job_name: &str,
    namespace: &str,
    service_name: &str,
    product: &str,
    environment: &str,
    test_suite: &str,
    router_url: &str,
    timeout_seconds: u64,
    fail_fast: bool,
    git_sha: &str,
    deploy_config: &DeployConfig,
    federation_tests_tag_override: Option<&str>,
) -> Result<String> {
    // Calculate job timeout (add 60s buffer for job overhead)
    let job_timeout = timeout_seconds + 60;

    // Get image tag with priority:
    // 1. Use override tag if provided (from Step 7.4 federation-tests auto-release)
    //    This tag includes the architecture prefix (e.g., "amd64-347a310176")
    // 2. Use service's own image_tag if specified in deploy.yaml
    // 3. Fall back to federation-tests' default tag
    let image_tag = if let Some(override_tag) = federation_tests_tag_override {
        // Use the override tag from the just-built federation-tests image
        // The tag already includes architecture prefix (e.g., "amd64-347a310176")
        override_tag.to_string()
    } else if let Some(service_tag) = &deploy_config.service.federation_tests.image_tag {
        // Service specifies its own tag
        service_tag.clone()
    } else {
        // Fall back to federation-tests' default tag
        let repo_root = crate::git::get_repo_root()?;
        let federation_tests_dir = repo_root
            .join("pkgs/products")
            .join(product)
            .join("tests/federation");

        let federation_deploy_yaml = federation_tests_dir.join("deploy.yaml");
        if !federation_deploy_yaml.exists() {
            bail!(
                "Federation tests deploy.yaml not found: {}",
                federation_deploy_yaml.display()
            );
        }

        // Read and parse federation-tests deploy.yaml
        let federation_config_content = std::fs::read_to_string(&federation_deploy_yaml)
            .context("Failed to read federation-tests deploy.yaml")?;

        #[derive(serde::Deserialize)]
        struct FederationTestsDeployYaml {
            federation_tests_service: FederationTestsServiceSection,
        }

        #[derive(serde::Deserialize)]
        struct FederationTestsServiceSection {
            image_tag: String,
        }

        let federation_config: FederationTestsDeployYaml =
            serde_yaml::from_str(&federation_config_content)
                .context("Failed to parse federation-tests deploy.yaml")?;

        federation_config.federation_tests_service.image_tag
    };

    // Build full image reference using the same pattern as regular services
    // Pattern: {host}/{organization}/{project}/{product}-{service}:{tag}
    // For federation-tests: {product}-federation-tests
    let image = format!(
        "{}/{}/{}/{}-federation-tests:{}",
        deploy_config.global.registry.host,
        deploy_config.global.registry.organization,
        deploy_config.global.registry.project,
        product, // e.g., product name
        image_tag
    );

    // Build command-line arguments
    let mut args = vec!["--suite".to_string(), test_suite.to_string()];

    // Add --fail-fast if enabled
    if fail_fast {
        args.push("--fail-fast".to_string());
    }

    // Add remaining arguments
    args.extend_from_slice(&[
        "--router-url".to_string(),
        router_url.to_string(),
        "--timeout-seconds".to_string(),
        timeout_seconds.to_string(),
    ]);

    // Build labels
    let labels: BTreeMap<String, String> = [
        (
            "app".to_string(),
            format!("{}-federation-tests", service_name),
        ),
        ("service".to_string(), service_name.to_string()),
        ("product".to_string(), product.to_string()),
        ("component".to_string(), "federation-tests".to_string()),
    ]
    .into_iter()
    .collect();

    // Build environment variables
    let env = vec![
        EnvVar {
            name: "SERVICE_NAME".to_string(),
            value: Some(format!("{}-federation-tests", product)),
            ..Default::default()
        },
        EnvVar {
            name: "PRODUCT".to_string(),
            value: Some(product.to_string()),
            ..Default::default()
        },
        EnvVar {
            name: "ENVIRONMENT".to_string(),
            value: Some(environment.to_string()),
            ..Default::default()
        },
        EnvVar {
            name: "GIT_SHA".to_string(),
            value: Some(git_sha.to_string()),
            ..Default::default()
        },
        EnvVar {
            name: "HIVE_ROUTER_URL".to_string(),
            value: Some(router_url.to_string()),
            ..Default::default()
        },
        EnvVar {
            name: "TIMEOUT_SECONDS".to_string(),
            value: Some(timeout_seconds.to_string()),
            ..Default::default()
        },
        EnvVar {
            name: "RUST_LOG".to_string(),
            value: Some(format!(
                "info,{}_federation_tests=debug",
                product.replace('-', "_")
            )),
            ..Default::default()
        },
        EnvVar {
            name: "RUST_BACKTRACE".to_string(),
            value: Some("1".to_string()),
            ..Default::default()
        },
        EnvVar {
            name: "LOG_LEVEL".to_string(),
            value: Some("info".to_string()),
            ..Default::default()
        },
    ];

    // Build resource requirements
    let resources = ResourceRequirements {
        requests: Some(
            [
                ("cpu".to_string(), Quantity("250m".to_string())),
                ("memory".to_string(), Quantity("256Mi".to_string())),
            ]
            .into_iter()
            .collect(),
        ),
        limits: Some(
            [
                ("cpu".to_string(), Quantity("500m".to_string())),
                ("memory".to_string(), Quantity("512Mi".to_string())),
            ]
            .into_iter()
            .collect(),
        ),
        ..Default::default()
    };

    // Build volume mounts
    let volume_mounts = vec![VolumeMount {
        name: "test-config".to_string(),
        mount_path: "/config".to_string(),
        read_only: Some(true),
        ..Default::default()
    }];

    // Build volumes
    let volumes = vec![Volume {
        name: "test-config".to_string(),
        config_map: Some(ConfigMapVolumeSource {
            name: "hive-router-config".to_string(),
            items: Some(vec![KeyToPath {
                key: "supergraph.graphql".to_string(),
                path: "supergraph.graphql".to_string(),
                ..Default::default()
            }]),
            ..Default::default()
        }),
        ..Default::default()
    }];

    // Build container spec
    let container = Container {
        name: "federation-tests".to_string(),
        image: Some(image),
        image_pull_policy: Some("Always".to_string()),
        args: Some(args),
        env: Some(env),
        volume_mounts: Some(volume_mounts),
        resources: Some(resources),
        ..Default::default()
    };

    // Build pod spec
    let pod_spec = PodSpec {
        restart_policy: Some("Never".to_string()),
        image_pull_secrets: Some(vec![LocalObjectReference {
            name: "ghcr-secret".to_string(),
        }]),
        containers: vec![container],
        volumes: Some(volumes),
        ..Default::default()
    };

    // Build pod template
    let pod_template = PodTemplateSpec {
        metadata: Some(ObjectMeta {
            labels: Some(labels.clone()),
            ..Default::default()
        }),
        spec: Some(pod_spec),
    };

    // Build job spec
    let job_spec = JobSpec {
        backoff_limit: Some(2),
        active_deadline_seconds: Some(job_timeout as i64),
        ttl_seconds_after_finished: Some(3600),
        template: pod_template,
        ..Default::default()
    };

    // Build final Job resource
    let job = Job {
        metadata: ObjectMeta {
            name: Some(job_name.to_string()),
            namespace: Some(namespace.to_string()),
            labels: Some(labels),
            ..Default::default()
        },
        spec: Some(job_spec),
        ..Default::default()
    };

    // Serialize to YAML
    let yaml = serde_yaml::to_string(&job).context("Failed to serialize Job to YAML")?;

    Ok(yaml)
}

/// Wait for job to complete (either succeed or fail)
async fn wait_for_job_completion(
    job_name: &str,
    namespace: &str,
    timeout_seconds: u64,
) -> Result<()> {
    let start = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(timeout_seconds + 60); // Add buffer
    let mut backoff_attempt: u32 = 0;

    loop {
        // Check if timeout exceeded
        if start.elapsed() > timeout {
            bail!("Timeout waiting for federation test job to complete");
        }

        // Query job status
        let output = kubectl_command_async()
            .args(&[
                "get",
                "job",
                job_name,
                "-n",
                namespace,
                "-o",
                "jsonpath={.status.conditions[?(@.type==\"Complete\")].status},{.status.conditions[?(@.type==\"Failed\")].status}",
            ])
            .output()
            .await
            .context("Failed to query job status")?;

        let status = String::from_utf8_lossy(&output.stdout);

        // Check if job is complete or failed
        if status.contains("True") {
            return Ok(());
        }

        tokio::time::sleep(federation_job_poll_delay(backoff_attempt)).await;
        backoff_attempt = backoff_attempt.saturating_add(1);
    }
}

/// Check if job succeeded
async fn check_job_success(job_name: &str, namespace: &str) -> Result<bool> {
    let output = kubectl_command_async()
        .args(&[
            "get",
            "job",
            job_name,
            "-n",
            namespace,
            "-o",
            "jsonpath={.status.succeeded}",
        ])
        .output()
        .await
        .context("Failed to check job success status")?;

    let succeeded = String::from_utf8_lossy(&output.stdout);
    Ok(succeeded.trim() == "1")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `(initial_backoff, factor, max_backoff)` shape of the
    /// federation-test k8s-Job status-poll backoff policy is a load-
    /// bearing invariant shared with the sibling k8s-workload-poll
    /// quartet at `services/migration_service.rs::
    /// MIGRATION_JOB_POLL_BACKOFF` (commit ac61874),
    /// `commands/migrations.rs::SHINKA_MIGRATION_POLL_BACKOFF` (commit
    /// b962db5), and `commands/github_runner_ci.rs::
    /// GITHUB_RUNNER_ROLLOUT_POLL_BACKOFF` (commit 7fe79de) — all four
    /// policies consume the same `RetryPolicy::network()`
    /// `(factor=2, max_backoff=30s)` reference schedule. Pinned here
    /// so a future silent-desync at the const site (a factor bump, a
    /// cap change, a seed drift) is caught at a named test rather
    /// than silently across the two consumption sites
    /// (`federation_job_poll_delay` + the loop body). Sibling of
    /// `test_migration_job_poll_backoff_policy_shape` at
    /// `services/migration_service.rs::tests` (commit ac61874).
    #[test]
    fn test_federation_job_poll_backoff_policy_shape() {
        assert_eq!(
            FEDERATION_JOB_POLL_BACKOFF.initial_backoff,
            Duration::from_secs(5),
            "FEDERATION_JOB_POLL_BACKOFF.initial_backoff must be 5s \
             — preserves the pre-lift bare \
             `sleep(Duration::from_secs(5))` seed verbatim at the \
             poll loop's first sleep.",
        );
        assert_eq!(
            FEDERATION_JOB_POLL_BACKOFF.factor, 2,
            "FEDERATION_JOB_POLL_BACKOFF.factor must be 2 \
             — the Bazel/Buck2/SLSA-frontier reference doubling climb \
             the sibling `RetryPolicy::network()` factory also emits.",
        );
        assert_eq!(
            FEDERATION_JOB_POLL_BACKOFF.max_backoff,
            Duration::from_secs(30),
            "FEDERATION_JOB_POLL_BACKOFF.max_backoff must be 30s \
             — the Bazel/Buck2/SLSA-frontier 30s cap the sibling \
             `RetryPolicy::network()` factory also emits.",
        );
    }

    /// Pre-lift the poll loop emitted a flat
    /// `sleep(Duration::from_secs(5))` at every non-terminal
    /// iteration. Post-lift the first iteration preserves that 5s
    /// seed verbatim (`federation_job_poll_delay(0) == 5s`); every
    /// later iteration strictly diverges upward under the
    /// exponential-with-cap climb (`10s → 20s → 30s → …`) rather than
    /// re-emitting the pre-lift `5s` flat.
    #[test]
    fn test_federation_job_poll_delay_matches_pre_lift_seed_and_climbs() {
        assert_eq!(
            federation_job_poll_delay(0),
            Duration::from_secs(5),
            "iter 0 must sleep 5s — matches pre-lift `sleep(Duration::\
             from_secs(5))` seed verbatim.",
        );
        assert_eq!(
            federation_job_poll_delay(1),
            Duration::from_secs(10),
            "iter 1 must sleep 10s — pre-lift stayed flat at 5s; \
             post-lift climbs `initial_backoff * factor = 10s`.",
        );
        assert_eq!(
            federation_job_poll_delay(2),
            Duration::from_secs(20),
            "iter 2 must sleep 20s — pre-lift stayed flat at 5s; \
             post-lift climbs `initial_backoff * factor^2 = 20s`.",
        );
    }

    /// Iterations past the cap must all emit `max_backoff = 30s` —
    /// pre-lift stayed flat at 5s at every iteration, so a long-
    /// running federation-test job (say, a 6-minute default
    /// `job_timeout + 60s` buffer window) would emit ~72 kubectl
    /// probes; post-lift the climb caps at 30s and the same 6-minute
    /// window emits ~13 probes.
    #[test]
    fn test_federation_job_poll_delay_caps_at_max_backoff_past_the_cap() {
        assert_eq!(
            federation_job_poll_delay(3),
            Duration::from_secs(30),
            "iter 3 must sleep 30s (cap) — `initial_backoff * factor^3 \
             = 40s`, clamped to `max_backoff = 30s`.",
        );
        assert_eq!(
            federation_job_poll_delay(4),
            Duration::from_secs(30),
            "iter 4 must sleep 30s (cap).",
        );
        assert_eq!(
            federation_job_poll_delay(50),
            Duration::from_secs(30),
            "iter 50 must sleep 30s (cap) — long-running federation-\
             test jobs can poll for minutes past the cap, so beyond-\
             cap iterations must stay at the ceiling rather than \
             drifting upward.",
        );
    }

    /// The poll loop is bounded by wall-clock via the caller-supplied
    /// `timeout_seconds + 60s` buffer, not by attempt count, so
    /// `backoff_attempt` can in principle reach any `u32` value on a
    /// pathologically-fast poll-arm (a stub kubectl that returns
    /// instantly against a `u64::MAX` timeout). This test pins that
    /// composition: an `attempt == u32::MAX` argument returns a
    /// bounded delay rather than panicking. The `saturating_add(2)`
    /// bridge inside `federation_job_poll_delay` clamps to `u32::MAX`,
    /// and [`RetryPolicy::compute_delay`]'s `checked_pow`-then-cap
    /// body itself saturates to `max_backoff` without panic.
    #[test]
    fn test_federation_job_poll_delay_saturates_without_panic_at_arbitrarily_large_attempt() {
        assert_eq!(
            federation_job_poll_delay(u32::MAX),
            Duration::from_secs(30),
            "attempt=u32::MAX must saturate to max_backoff without \
             panic — the `saturating_add(2)` bridge + `RetryPolicy::\
             compute_delay`'s `checked_pow` cap close the u32 overflow \
             class by construction.",
        );
        assert_eq!(
            federation_job_poll_delay(u32::MAX - 1),
            Duration::from_secs(30),
            "attempt=u32::MAX - 1 must also saturate to max_backoff \
             — the bridge `saturating_add(2)` returns u32::MAX, still \
             far past the cap.",
        );
    }

    /// The `(factor, max_backoff)` pair of
    /// `FEDERATION_JOB_POLL_BACKOFF` matches the Bazel/Buck2/SLSA-
    /// frontier reference schedule the retry module cites at
    /// [`RetryPolicy::network`]'s docstring. The federation-test
    /// k8s-Job poll policy diverges only at `initial_backoff` (5s vs
    /// 250ms) to preserve the pre-lift `sleep(Duration::from_secs(5))`
    /// seed verbatim. Pin the shared invariants so a future refinement
    /// to the retry module's reference schedule surfaces the
    /// intentional federation-side divergence as a named test failure
    /// rather than silently propagating. Sibling of
    /// `test_migration_job_poll_backoff_shares_network_factor_and_cap`
    /// at `services/migration_service.rs::tests` (commit ac61874).
    #[test]
    fn test_federation_job_poll_backoff_shares_network_factor_and_cap() {
        let network = RetryPolicy::network();
        assert_eq!(
            FEDERATION_JOB_POLL_BACKOFF.factor, network.factor,
            "FEDERATION_JOB_POLL_BACKOFF.factor must match \
             RetryPolicy::network().factor — both consume the \
             Bazel/Buck2/SLSA-frontier factor=2 reference.",
        );
        assert_eq!(
            FEDERATION_JOB_POLL_BACKOFF.max_backoff, network.max_backoff,
            "FEDERATION_JOB_POLL_BACKOFF.max_backoff must match \
             RetryPolicy::network().max_backoff — both consume the \
             Bazel/Buck2/SLSA-frontier 30s cap reference.",
        );
    }

    /// The federation-test k8s-Job status-poll loop body MUST consume
    /// the typed primitive at `federation_job_poll_delay(backoff_\
    /// attempt)` rather than the pre-lift bare
    /// `sleep(tokio::time::Duration::from_secs(5))` literal. A future
    /// refactor that reintroduces the fixed-literal shape (see
    /// `FEDERATION_JOB_POLL_BACKOFF`'s docstring for the three
    /// structural defects the lift closed) fails here, not silently
    /// in production where a long-running federation-test job would
    /// resume flooding the k8s API with ~72 probes over its 6-minute
    /// window. Whole-module boundary discipline sibling of
    /// `test_wait_for_job_consumes_typed_poll_delay_not_bare_fixed_sleep`
    /// at `services/migration_service.rs::tests` (commit ac61874),
    /// `test_wait_for_shinka_migration_consumes_typed_poll_delay_not_mut_backoff_secs`
    /// at `commands/migrations.rs::tests` (commit b962db5), and
    /// `test_execute_consumes_typed_rollout_poll_delay_not_bare_fixed_sleep`
    /// at `commands/github_runner_ci.rs::tests` (commit 7fe79de).
    ///
    /// Uses the [`crate::test_support::code_line_hits`] helper so the
    /// shield does not false-positive on
    /// `FEDERATION_JOB_POLL_BACKOFF`'s own docstring above (which
    /// cites the pre-lift shape as context for the three defects it
    /// forecloses). The forbidden literal is reconstructed at test
    /// time via [`format!`] and the diagnostic prose refers to it
    /// only via the reconstructed `bespoke_needle` (never the fused
    /// literal), so the assert message body itself stays unmatchable
    /// — same code-line-filter-plus-format-reconstruction discipline
    /// sibling shields 4163c7e / ffa5271 / fa2c702 / a7d5375 /
    /// ab06395 use.
    ///
    /// The scan is bounded strictly to the pre-tests module body —
    /// from the module start through the `#[cfg(test)]\nmod tests {`
    /// marker — so this shield's own docstring mention of
    /// `sleep(tokio::time::Duration::from_secs(5))` (which lives
    /// inside this `#[cfg(test)] mod tests` block below that marker)
    /// stays out of scope AND every current or future sleep-emitting
    /// helper landing anywhere in the top-level module body cannot
    /// silently ride along without going through the primitive.
    #[test]
    fn test_wait_for_job_completion_consumes_typed_poll_delay_not_bare_fixed_sleep() {
        let source = include_str!("federation_tests.rs");
        let tests_marker = "\n#[cfg(test)]\nmod tests {";
        let body_end = source.find(tests_marker).expect(
            "the `#[cfg(test)]\\nmod tests {` marker must follow \
             the module body — the shield's slice boundary relies \
             on this module ordering",
        );
        let module_body = &source[..body_end];

        let bespoke_needle = format!(
            "sleep(tokio::time::Duration::from_secs({}))",
            FEDERATION_JOB_POLL_BACKOFF.initial_backoff.as_secs(),
        );
        let bespoke_hits = crate::test_support::code_line_hits(module_body, &bespoke_needle);
        assert!(
            bespoke_hits.is_empty(),
            "federation_tests.rs must NOT re-fuse the pre-lift bare \
             fixed sleep at the poll loop — the schedule lives at \
             `FEDERATION_JOB_POLL_BACKOFF` + \
             `federation_job_poll_delay`, both grounding through \
             `RetryPolicy::compute_delay`. Found code-line hits: {:#?}",
            bespoke_hits,
        );
        let delegation_hits = crate::test_support::code_line_hits(
            module_body,
            "federation_job_poll_delay(backoff_attempt)",
        );
        assert!(
            !delegation_hits.is_empty(),
            "federation_tests.rs must consume the typed poll-delay \
             helper at the poll loop's sleep site — the canonical \
             delegation call was not found at any code line.",
        );
    }

    /// Regression shield: every `kubectl`-spawning site in
    /// `commands/federation_tests.rs`'s five top-level async helpers
    /// (`run_federation_tests` apply + logs-capture + status-yaml,
    /// `wait_for_job_completion` status-jsonpath poll,
    /// `check_job_success` succeeded-jsonpath probe) MUST resolve the
    /// binary through
    /// [`crate::infrastructure::kubectl::kubectl_command_async`]
    /// rather than the pre-lift `Command::new("kubectl")` literal.
    /// Pre-migration five sites each spelled the bare
    /// `Command::new("kubectl")` shape verbatim and thereby bypassed
    /// the `KUBECTL_BIN` env override the tools-registry idiom
    /// (`crate::tools::get_tool_path(tools::KUBECTL)`,
    /// cli/src/tools.rs:102-105) resolves — the same class of bug the
    /// sibling `commands/migrations.rs` (946e573),
    /// `commands/status.rs` (c2760df), `commands/flux.rs` (f8da719),
    /// `commands/supergraph_verification.rs` (65283fb),
    /// `commands/product_release.rs::run_health_check` (5bb7cff),
    /// `commands/github_runner_ci.rs::execute` (5566415),
    /// `services/migration_service.rs::MigrationService` (5986a10)
    /// migrations redeemed. This module is the surface that actually
    /// applies the Kubernetes Job every deploy step trusts to
    /// materialize the federation-integration-test verdict against a
    /// freshly-updated Hive Router — the last blocking gate before
    /// `forge deploy` reports service-ready.
    ///
    /// This test reads this module's own source via [`include_str!`]
    /// and asserts the raw `Command::new("kubectl")` string does not
    /// reappear anywhere in the module's non-test body while the
    /// delegation to `kubectl_command_async()` does. A future
    /// regression that re-fuses the raw-spawn body fails here, not
    /// silently in production where a Nix-hermetic runner's
    /// `KUBECTL_BIN`-provided `kubectl` would lose to whatever
    /// `kubectl` is first on `PATH` at `forge deploy`
    /// federation-tests invocation time.
    ///
    /// The scan is bounded strictly to the module's non-test body
    /// — from the file start to the `#[cfg(test)]` marker — so this
    /// shield's own docstring mention of `Command::new("kubectl")`
    /// (which lives inside this `#[cfg(test)] mod tests` block below
    /// that marker) stays out of scope AND every current or future
    /// kubectl-spawning helper landing anywhere in the top-level
    /// module body (i.e., in any of the five migrated sites or any
    /// as-yet unadded sibling) cannot silently ride along without
    /// going through the primitive. Mirrors the whole-module boundary
    /// discipline the sibling `commands/migrations.rs` shield
    /// (946e573), `commands/status.rs` shield (c2760df), and
    /// `commands/supergraph_verification.rs` shield (65283fb)
    /// pioneered on the multi-function consumer surface.
    #[test]
    fn test_federation_tests_routes_kubectl_through_kubectl_command_async_not_raw_command() {
        let source = include_str!("federation_tests.rs");
        let tests_marker = "\n#[cfg(test)]\nmod tests {";
        let body_end = source.find(tests_marker).expect(
            "the `#[cfg(test)]\\nmod tests {` marker must follow \
             the module body — the shield's slice boundary relies \
             on this module ordering",
        );
        let module_body = &source[..body_end];

        assert!(
            !module_body.contains("Command::new(\"kubectl\")"),
            "federation_tests.rs must NOT spawn `kubectl` directly — \
             route through \
             `crate::infrastructure::kubectl::kubectl_command_async()` \
             so `KUBECTL_BIN` overrides land at the shared primitive. \
             Found the pre-migration spawn body in the module."
        );
        assert!(
            module_body.contains("kubectl_command_async()"),
            "federation_tests.rs must delegate every kubectl spawn to \
             `kubectl_command_async()` — the delegation string was \
             not found in the module body."
        );
    }
}
