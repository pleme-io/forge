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
use tokio::process::Command;

use k8s_openapi::api::batch::v1::{Job, JobSpec};
use k8s_openapi::api::core::v1::{
    ConfigMapKeySelector, ConfigMapVolumeSource, Container, EnvVar, KeyToPath,
    LocalObjectReference, PodSpec, PodTemplateSpec, ResourceRequirements, Volume, VolumeMount,
};
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

use crate::config::DeployConfig;

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
    let output = Command::new("kubectl")
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
            let log_output = Command::new("kubectl")
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
            let status_output = Command::new("kubectl")
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
            value: Some(format!("info,{}_federation_tests=debug", product.replace('-', "_"))),
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

    loop {
        // Check if timeout exceeded
        if start.elapsed() > timeout {
            bail!("Timeout waiting for federation test job to complete");
        }

        // Query job status
        let output = Command::new("kubectl")
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

        // Wait before next check
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
    }
}

/// Check if job succeeded
async fn check_job_success(job_name: &str, namespace: &str) -> Result<bool> {
    let output = Command::new("kubectl")
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
