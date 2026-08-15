//! Status command for showing deployed version/image/tag
//!
//! Shows comprehensive deployment information by querying Kubernetes.

use anyhow::{Context, Result};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tracing::debug;

use crate::infrastructure::kubectl::kubectl_command_async;

/// Raw deploy.yaml structure for parsing kubernetes config directly
/// (Supports both web and rust service formats)
#[derive(Debug, Clone, Deserialize)]
struct RawDeployYaml {
    /// Service name (top-level)
    name: Option<String>,

    /// Kubernetes section (for web services)
    #[serde(default)]
    kubernetes: Option<RawKubernetesSection>,

    /// Environments section (for rust services)
    #[serde(default)]
    environments: Option<RawEnvironmentsSection>,
}

#[derive(Debug, Clone, Deserialize)]
struct RawKubernetesSection {
    /// Kubernetes namespace
    namespace: Option<String>,

    /// Deployment name (may be different from service name)
    deployment_name: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct RawEnvironmentsSection {
    /// Staging environment config
    staging: Option<RawEnvironmentConfig>,
}

#[derive(Debug, Clone, Deserialize)]
struct RawEnvironmentConfig {
    /// Cluster name
    cluster: Option<String>,
}

/// Output format for status command
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Text,
    Json,
}

impl OutputFormat {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "json" => Self::Json,
            _ => Self::Text,
        }
    }
}

// ============================================================================
// Data Structures
// ============================================================================

/// Complete service status information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceStatus {
    pub service: String,
    pub namespace: String,
    pub environment: String,
    pub deployment: DeploymentInfo,
    pub pods: Vec<PodInfo>,
    pub containers: Vec<ContainerInfo>,
    pub related_services: RelatedServices,
    pub migrations: Vec<MigrationInfo>,
    pub events: Vec<EventInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentInfo {
    pub name: String,
    pub image: Option<String>,
    pub tag: Option<String>,
    pub replicas: ReplicaStatus,
    pub conditions: Vec<ConditionStatus>,
    pub strategy: String,
    pub created_at: Option<String>,
    pub last_updated: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicaStatus {
    pub desired: i32,
    pub ready: i32,
    pub available: i32,
    pub updated: i32,
    pub unavailable: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConditionStatus {
    pub condition_type: String,
    pub status: String,
    pub reason: Option<String>,
    pub message: Option<String>,
    pub last_transition: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PodInfo {
    pub name: String,
    pub status: String,
    pub ready: String,
    pub restarts: i32,
    pub age: String,
    pub node: Option<String>,
    pub ip: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerInfo {
    pub pod: String,
    pub name: String,
    pub image: String,
    pub tag: String,
    pub ready: bool,
    pub restarts: i32,
    pub state: String,
    pub is_sidecar: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelatedServices {
    pub postgres: Option<StatefulSetInfo>,
    pub redis: Option<ResourceInfo>,
    pub configmap: Option<ConfigMapInfo>,
    pub secrets: Vec<String>,
    pub services: Vec<ServiceInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatefulSetInfo {
    pub name: String,
    pub ready: String,
    pub image: Option<String>,
    pub storage: Option<String>,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceInfo {
    pub name: String,
    pub status: String,
    pub ready: String,
    pub image: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigMapInfo {
    pub name: String,
    pub keys: Vec<String>,
    pub data_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub name: String,
    pub service_type: String,
    pub cluster_ip: Option<String>,
    pub ports: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationInfo {
    pub name: String,
    pub status: String,
    pub started: Option<String>,
    pub completed: Option<String>,
    pub duration: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventInfo {
    pub event_type: String,
    pub reason: String,
    pub message: String,
    pub age: String,
    pub count: i32,
}

// ============================================================================
// Execute Command
// ============================================================================

/// Execute status command
pub async fn execute(
    service: &str,
    service_dir: &str,
    repo_root: &str,
    format: OutputFormat,
) -> Result<()> {
    // Set up environment for root flake pattern
    std::env::set_var("REPO_ROOT", repo_root);
    std::env::set_var("SERVICE_DIR", service_dir);
    std::env::set_current_dir(repo_root)?;

    // Load deploy.yaml - check deploy/{service_name}.yaml first (outside Nix source tree),
    // then fall back to service_dir/deploy.yaml for backward compatibility.
    let service_dir_path = PathBuf::from(service_dir);
    let deploy_yaml_path =
        if let Some(product_dir) = find_product_dir_from_service(&service_dir_path) {
            crate::config::resolve_deploy_yaml_path(&product_dir, service, &service_dir_path)
        } else {
            service_dir_path.join("deploy.yaml")
        };
    if !deploy_yaml_path.exists() {
        anyhow::bail!("No deploy.yaml found at: {}", deploy_yaml_path.display());
    }

    let yaml_content = std::fs::read_to_string(&deploy_yaml_path).context(format!(
        "Failed to read deploy.yaml at: {}",
        deploy_yaml_path.display()
    ))?;

    let raw_config: RawDeployYaml =
        serde_yaml::from_str(&yaml_content).context("Failed to parse deploy.yaml")?;

    // Get environment
    let environment = std::env::var("FORGE_ENV").unwrap_or_else(|_| "staging".to_string());

    // Get namespace from config
    let namespace = raw_config
        .kubernetes
        .as_ref()
        .and_then(|k| k.namespace.clone())
        .or_else(|| {
            // For rust services, derive namespace from product name in path
            let path = PathBuf::from(service_dir);
            let components: Vec<_> = path.components().collect();

            for (i, comp) in components.iter().enumerate() {
                if let std::path::Component::Normal(name) = comp {
                    if name.to_str() == Some("products") && i + 1 < components.len() {
                        if let std::path::Component::Normal(product) = components[i + 1] {
                            return Some(format!(
                                "{}-{}",
                                product.to_str().unwrap_or("default"),
                                environment
                            ));
                        }
                    }
                }
            }
            None
        })
        .ok_or_else(|| anyhow::anyhow!("Could not determine namespace from deploy.yaml or path"))?;

    // Get deployment name
    let deployment_name = raw_config
        .kubernetes
        .as_ref()
        .and_then(|k| k.deployment_name.clone())
        .or_else(|| raw_config.name.clone())
        .unwrap_or_else(|| service.to_string());

    debug!(
        "Using namespace: {}, deployment: {}",
        namespace, deployment_name
    );

    // Fetch comprehensive status
    let status = fetch_service_status(service, &namespace, &deployment_name, &environment).await?;

    // Output based on format
    match format {
        OutputFormat::Text => print_text_status(&status),
        OutputFormat::Json => print_json_status(&status)?,
    }

    Ok(())
}

/// Walk up from a service directory to find the product directory (pkgs/products/{product}).
fn find_product_dir_from_service(service_dir: &Path) -> Option<PathBuf> {
    let mut current = service_dir.to_path_buf();
    loop {
        if let Some(parent) = current.parent() {
            if let Some(grandparent) = parent.parent() {
                if parent.file_name().and_then(|n| n.to_str()) == Some("products")
                    && grandparent.file_name().and_then(|n| n.to_str()) == Some("pkgs")
                {
                    return Some(current);
                }
            }
        }
        if let Some(parent) = current.parent() {
            current = parent.to_path_buf();
        } else {
            return None;
        }
    }
}

// ============================================================================
// Data Fetching
// ============================================================================

async fn fetch_service_status(
    service: &str,
    namespace: &str,
    deployment_name: &str,
    environment: &str,
) -> Result<ServiceStatus> {
    // Fetch all data concurrently
    let (deployment, pod_items, related, migrations, events) = tokio::join!(
        fetch_deployment(namespace, deployment_name),
        fetch_pods(namespace, deployment_name),
        fetch_related_services(namespace, deployment_name),
        fetch_migrations(namespace, deployment_name),
        fetch_events(namespace, deployment_name),
    );

    let deployment_info = deployment?;
    let pod_items = pod_items?;
    let (pods, containers) = extract_pod_and_container_info(&pod_items, deployment_name);

    Ok(ServiceStatus {
        service: service.to_string(),
        namespace: namespace.to_string(),
        environment: environment.to_string(),
        deployment: deployment_info,
        pods,
        containers,
        related_services: related.unwrap_or_default(),
        migrations: migrations.unwrap_or_default(),
        events: events.unwrap_or_default(),
    })
}

async fn fetch_deployment(namespace: &str, deployment_name: &str) -> Result<DeploymentInfo> {
    let output = kubectl_get_object("deployment", deployment_name, namespace).await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "Failed to get deployment '{}' in namespace '{}': {}",
            deployment_name,
            namespace,
            stderr
        );
    }

    let deployment: serde_json::Value = serde_json::from_slice(&output.stdout)?;

    // Extract image info from ghcr.io container
    let (image, tag) = extract_main_image(&deployment);

    Ok(DeploymentInfo {
        name: deployment_name.to_string(),
        image,
        tag,
        replicas: ReplicaStatus {
            desired: replica_count(&deployment, "/spec/replicas") as i32,
            ready: replica_count(&deployment, "/status/readyReplicas") as i32,
            available: replica_count(&deployment, "/status/availableReplicas") as i32,
            updated: replica_count(&deployment, "/status/updatedReplicas") as i32,
            unavailable: replica_count(&deployment, "/status/unavailableReplicas") as i32,
        },
        conditions: extract_conditions(&deployment),
        strategy: deployment
            .pointer("/spec/strategy/type")
            .and_then(|s| s.as_str())
            .unwrap_or("Unknown")
            .to_string(),
        created_at: deployment
            .pointer("/metadata/creationTimestamp")
            .and_then(|t| t.as_str())
            .map(String::from),
        last_updated: deployment
            .pointer("/status/conditions")
            .and_then(|c| c.as_array())
            .and_then(|arr| {
                arr.iter()
                    .find(|c| c.get("type").and_then(|t| t.as_str()) == Some("Progressing"))
            })
            .and_then(|c| c.get("lastUpdateTime"))
            .and_then(|t| t.as_str())
            .map(String::from),
    })
}

fn extract_main_image(deployment: &serde_json::Value) -> (Option<String>, Option<String>) {
    let containers = deployment
        .pointer("/spec/template/spec/containers")
        .and_then(|c| c.as_array());

    if let Some(containers) = containers {
        // Find ghcr.io container (our main app)
        let main_container = containers
            .iter()
            .find(|c| {
                c.get("image")
                    .and_then(|i| i.as_str())
                    .map(|i| i.contains("ghcr.io"))
                    .unwrap_or(false)
            })
            .or_else(|| containers.first());

        if let Some(container) = main_container {
            if let Some(image_str) = container.get("image").and_then(|i| i.as_str()) {
                // Route through the typed primitive at
                // `crate::oci_manifest::image_repository_and_tag`. The
                // naïve `image_str.rsplit_once(':')` predecessor read
                // the last `:` regardless of context, so a
                // `registry.example.com:5000/nginx` reference reported
                // `("registry.example.com", Some("5000/nginx"))` — a
                // path segment surfaced as if it were a tag — and a
                // `nginx@sha256:hex` reference reported
                // `("nginx@sha256", Some("hex"))` — a digest hex
                // surfaced as if it were a tag. The primitive scopes
                // the tag scan to the final path component and strips
                // the `@digest` suffix, so both bad shapes route to
                // (whole reference, None) at one site.
                let (image, tag) = crate::oci_manifest::image_repository_and_tag(image_str);
                return (Some(image.to_string()), tag.map(str::to_string));
            }
        }
    }
    (None, None)
}

fn extract_conditions(deployment: &serde_json::Value) -> Vec<ConditionStatus> {
    deployment
        .pointer("/status/conditions")
        .and_then(|c| c.as_array())
        .map(|conds| {
            conds
                .iter()
                .filter_map(|c| {
                    Some(ConditionStatus {
                        condition_type: c.get("type")?.as_str()?.to_string(),
                        status: c.get("status")?.as_str()?.to_string(),
                        reason: c.get("reason").and_then(|r| r.as_str()).map(String::from),
                        message: c.get("message").and_then(|m| m.as_str()).map(String::from),
                        last_transition: c
                            .get("lastTransitionTime")
                            .and_then(|t| t.as_str())
                            .map(String::from),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

async fn fetch_pods(namespace: &str, deployment_name: &str) -> Result<Vec<serde_json::Value>> {
    kubectl_list_items(&[
        "get",
        "pods",
        "-n",
        namespace,
        "-l",
        &format!("app={}", deployment_name),
        "-o",
        "json",
    ])
    .await
}

fn extract_pod_and_container_info(
    pod_items: &[serde_json::Value],
    deployment_name: &str,
) -> (Vec<PodInfo>, Vec<ContainerInfo>) {
    let mut pods = Vec::new();
    let mut containers = Vec::new();

    for pod in pod_items {
        let pod_name = pod
            .pointer("/metadata/name")
            .and_then(|n| n.as_str())
            .unwrap_or("unknown")
            .to_string();
        let phase = pod
            .pointer("/status/phase")
            .and_then(|p| p.as_str())
            .unwrap_or("Unknown")
            .to_string();

        let container_statuses = pod
            .pointer("/status/containerStatuses")
            .and_then(|c| c.as_array());

        let (ready_count, total_count, total_restarts) = container_statuses
            .map(|cs| {
                let ready = cs
                    .iter()
                    .filter(|c| c.get("ready").and_then(|r| r.as_bool()).unwrap_or(false))
                    .count();
                let restarts: i64 = cs
                    .iter()
                    .filter_map(|c| c.get("restartCount")?.as_i64())
                    .sum();
                (ready, cs.len(), restarts as i32)
            })
            .unwrap_or((0, 0, 0));

        pods.push(PodInfo {
            name: pod_name.clone(),
            status: phase,
            ready: format!("{}/{}", ready_count, total_count),
            restarts: total_restarts,
            age: calculate_age(
                pod.pointer("/metadata/creationTimestamp")
                    .and_then(|t| t.as_str())
                    .unwrap_or(""),
            ),
            node: pod
                .pointer("/spec/nodeName")
                .and_then(|n| n.as_str())
                .map(String::from),
            ip: pod
                .pointer("/status/podIP")
                .and_then(|i| i.as_str())
                .map(String::from),
        });

        // Extract container details
        if let Some(statuses) = container_statuses {
            for cs in statuses {
                let name = cs.get("name").and_then(|n| n.as_str()).unwrap_or("unknown");
                let image_full = cs.get("image").and_then(|i| i.as_str()).unwrap_or("");
                // Route through the typed primitive at
                // `crate::oci_manifest::image_repository_and_tag`.
                // The naïve `image_full.rsplit_once(':')`
                // predecessor surfaced the digest hex of a
                // `nginx@sha256:hex` reference and the port-bearing
                // path suffix of a `registry.example.com:5000/nginx`
                // reference as if either were a legitimate tag; the
                // primitive scopes the tag scan to the final path
                // component (per `image_tag`'s invariants) and
                // reports the whole reference with `None` on either
                // shape. The Docker default `"latest"` tag is
                // preserved as the fallback when no tag is
                // parseable, matching the display convention this
                // container-row uses.
                let (image_slice, tag_opt) =
                    crate::oci_manifest::image_repository_and_tag(image_full);
                let image = image_slice.to_string();
                let tag = tag_opt.unwrap_or("latest").to_string();

                let is_sidecar = name.contains("envoy")
                    || name.contains("istio")
                    || name.contains("proxy")
                    || !image.contains("ghcr.io");

                let state = if cs.pointer("/state/running").is_some() {
                    "Running".to_string()
                } else if let Some(waiting) = cs.pointer("/state/waiting") {
                    waiting
                        .get("reason")
                        .and_then(|r| r.as_str())
                        .unwrap_or("Waiting")
                        .to_string()
                } else if let Some(terminated) = cs.pointer("/state/terminated") {
                    terminated
                        .get("reason")
                        .and_then(|r| r.as_str())
                        .unwrap_or("Terminated")
                        .to_string()
                } else {
                    "Unknown".to_string()
                };

                containers.push(ContainerInfo {
                    pod: pod_name.clone(),
                    name: name.to_string(),
                    image,
                    tag,
                    ready: cs.get("ready").and_then(|r| r.as_bool()).unwrap_or(false),
                    restarts: cs.get("restartCount").and_then(|r| r.as_i64()).unwrap_or(0) as i32,
                    state,
                    is_sidecar,
                });
            }
        }
    }

    (pods, containers)
}

async fn fetch_related_services(namespace: &str, deployment_name: &str) -> Result<RelatedServices> {
    // Fetch postgres statefulset (naming convention: postgres-{service})
    let postgres = fetch_statefulset(namespace, &format!("postgres-{}", deployment_name))
        .await
        .ok();

    // Fetch redis - try multiple naming patterns:
    // 1. redis-{service} (Deployment) - most rust services
    // 2. {deployment_name}-redis (StatefulSet) - web service
    let redis = if let Ok(r) = fetch_redis(namespace, &format!("redis-{}", deployment_name)).await {
        Some(r)
    } else if let Ok(r) =
        fetch_redis_statefulset(namespace, &format!("{}-redis", deployment_name)).await
    {
        Some(r)
    } else {
        None
    };

    // Fetch configmap (naming convention: {service}-config)
    let configmap = fetch_configmap(namespace, &format!("{}-config", deployment_name))
        .await
        .ok();

    // Fetch secrets list
    let secrets = fetch_secrets(namespace, deployment_name)
        .await
        .unwrap_or_default();

    // Fetch k8s services
    let services = fetch_k8s_services(namespace, deployment_name)
        .await
        .unwrap_or_default();

    Ok(RelatedServices {
        postgres,
        redis,
        configmap,
        secrets,
        services,
    })
}

async fn fetch_statefulset(namespace: &str, name: &str) -> Result<StatefulSetInfo> {
    let output = kubectl_get_object("statefulset", name, namespace).await?;

    let sts = kubectl_get_item(&output, "StatefulSet not found")?;
    let (ready, status) = replica_readiness_display(&sts);

    let image = sts
        .pointer("/spec/template/spec/containers/0/image")
        .and_then(|i| i.as_str())
        .map(String::from);
    let storage = sts
        .pointer("/spec/volumeClaimTemplates/0/spec/resources/requests/storage")
        .and_then(|s| s.as_str())
        .map(String::from);

    Ok(StatefulSetInfo {
        name: name.to_string(),
        ready,
        image,
        storage,
        status,
    })
}

async fn fetch_redis(namespace: &str, name: &str) -> Result<ResourceInfo> {
    let output = kubectl_get_object("deployment", name, namespace).await?;

    let dep = kubectl_get_item(&output, "Redis deployment not found")?;
    let (ready, status) = replica_readiness_display(&dep);

    Ok(ResourceInfo {
        name: name.to_string(),
        status,
        ready,
        image: dep
            .pointer("/spec/template/spec/containers/0/image")
            .and_then(|i| i.as_str())
            .map(String::from),
    })
}

async fn fetch_redis_statefulset(namespace: &str, name: &str) -> Result<ResourceInfo> {
    let output = kubectl_get_object("statefulset", name, namespace).await?;

    let sts = kubectl_get_item(&output, "Redis statefulset not found")?;
    let (ready, status) = replica_readiness_display(&sts);

    Ok(ResourceInfo {
        name: name.to_string(),
        status,
        ready,
        image: sts
            .pointer("/spec/template/spec/containers/0/image")
            .and_then(|i| i.as_str())
            .map(String::from),
    })
}

async fn fetch_configmap(namespace: &str, name: &str) -> Result<ConfigMapInfo> {
    let output = kubectl_get_object("configmap", name, namespace).await?;

    let cm = kubectl_get_item(&output, "ConfigMap not found")?;
    let data = cm.get("data").and_then(|d| d.as_object());

    let keys: Vec<String> = data
        .map(|d| d.keys().cloned().collect())
        .unwrap_or_default();
    let data_size = data.map(|d| d.len()).unwrap_or(0);

    Ok(ConfigMapInfo {
        name: name.to_string(),
        keys,
        data_size,
    })
}

/// Spawn `kubectl get <kind> <name> -n <namespace> -o json` and return
/// the raw `std::process::Output` so the caller can compose the exit /
/// stdout classification through the sibling [`kubectl_get_item`]
/// primitive (or its own richer arm, per [`fetch_deployment`]).
///
/// # Single-object invocation peer of the list-shaped fetch helpers
///
/// Owns the seven-argument vector shape
/// `["get", <kind>, <name>, "-n", <namespace>, "-o", "json"]`
/// every single-object `fetch_*` consumer site in this module drove
/// verbatim. Five pre-lift call sites past THEORY.md §VI.1's
/// three-times threshold:
///
/// - [`fetch_deployment`] — `("deployment", <deployment>, <ns>)`; wraps
///   with a richer `stderr`-bearing bail arm on non-success exit.
/// - [`fetch_statefulset`] — `("statefulset", <name>, <ns>)`; routes
///   through [`kubectl_get_item`] with `"StatefulSet not found"`.
/// - [`fetch_redis`] — `("deployment", <name>, <ns>)`; routes through
///   [`kubectl_get_item`] with `"Redis deployment not found"`.
/// - [`fetch_redis_statefulset`] — `("statefulset", <name>, <ns>)`;
///   routes through [`kubectl_get_item`] with `"Redis statefulset not
///   found"`.
/// - [`fetch_configmap`] — `("configmap", <name>, <ns>)`; routes through
///   [`kubectl_get_item`] with `"ConfigMap not found"`.
///
/// # Why an invocation-layer primitive rather than a fully-fused
/// `kubectl_get_object(kind, name, ns, not_found_msg) -> Value`
///
/// The five call sites split on the exit-status classification: four
/// spell `kubectl_get_item(&output, "<X> not found")?` and route
/// non-success exits to a fixed operator-grep-visible diagnostic;
/// [`fetch_deployment`] instead composes a richer bail! including
/// `stderr` alongside the `namespace` and `deployment_name`, so an
/// RBAC-denied `get deployment` surfaces the exact kubectl error to
/// the operator rather than a `"Deployment not found"` misdirection
/// on a "the resource exists but the caller cannot see it" state. A
/// fully-fused primitive would either force `fetch_deployment` onto
/// the shared shape (losing the richer diagnostic) or fork the
/// primitive into two nearly-identical helpers. The invocation-layer
/// split keeps ONE body for the 7-arg vector while letting each
/// caller compose its own exit-status classification.
///
/// # Context wrapper
///
/// A `.with_context(||
/// format!("Failed to execute kubectl get {kind} {name} -n
/// {namespace}"))` wraps the `.output().await` I/O error at ONE body
/// rather than the pre-lift split where [`fetch_deployment`] carried
/// `.context("Failed to execute kubectl")` (opaque as to which
/// invocation failed) and the four sibling sites carried the bare `?`
/// with no context at all. Post-lift every spawn-failure at any of
/// the five sites surfaces with the exact `kubectl get <kind> <name>
/// -n <namespace>` invocation shape at the site of failure — a
/// "sharpen the existing promise: error fidelity" pass on the
/// spawn-failure boundary the pre-lift shapes left ambiguous.
///
/// Sibling invocation-layer peer of the sibling per-invocation
/// parsing primitives [`kubectl_get_item`] and [`kubectl_get_items`];
/// composes with either downstream.
async fn kubectl_get_object(
    kind: &str,
    name: &str,
    namespace: &str,
) -> Result<std::process::Output> {
    kubectl_command_async()
        .args(["get", kind, name, "-n", namespace, "-o", "json"])
        .output()
        .await
        .with_context(|| format!("Failed to execute kubectl get {kind} {name} -n {namespace}"))
}

/// Spawn `kubectl` with the given `argv` and parse the resulting
/// `-o json` list-shaped output into its `.items[]` array via the
/// sibling [`kubectl_get_items`] primitive.
///
/// # Invocation-layer peer of `kubectl_get_object`
///
/// Owns the "spawn `kubectl_command_async().args(argv).output().await?`,
/// then `kubectl_get_items(&output)?`" two-step composition every
/// list-shaped `fetch_*` consumer site in this module drove verbatim.
/// Five pre-lift call sites past THEORY.md §VI.1's three-times
/// threshold:
///
/// - [`fetch_pods`] — 9-arg with `-l app=<deployment>` (pod listing
///   for the deployment; the previously-straggling fifth site whose
///   pre-lift shape returned the raw `{"items": [...]}` envelope and
///   silently swallowed invalid-JSON via `.unwrap_or(json!({"items":
///   []}))`; post-lift returns the moved `.items[]` array via the
///   shared primitive and propagates the invalid-JSON parse error
///   via `?` alongside the four siblings — a "sharpen the existing
///   promise: error fidelity" pass on the pre-lift silent-swallow
///   arm the sibling `.unwrap_or(json!({"items": []}))` shape hid).
/// - [`fetch_secrets`] — 6-arg `["get", "secrets", "-n", <ns>, "-o", "json"]`
///   (unfiltered namespace list).
/// - [`fetch_k8s_services`] — 8-arg with `-l app=<deployment>`.
/// - [`fetch_migrations`] — 9-arg with `-l app=<deployment>` +
///   `--sort-by=.metadata.creationTimestamp`.
/// - [`fetch_events`] — 9-arg with `--field-selector=involvedObject.name=<X>`
///   + `--sort-by=.lastTimestamp`.
///
/// # Why an invocation-layer primitive rather than a fully-fused
/// `kubectl_list_items(kind, namespace, selector, ...) -> Vec<Value>`
///
/// The five call sites' argv shapes drift on three orthogonal axes:
/// filtered vs unfiltered, label-selector vs field-selector, and
/// sorted vs unsorted. A fully-fused helper would either force every
/// site onto one shape (losing per-caller flexibility) or fork the
/// primitive into five nearly-identical `kubectl_list_<flavor>`
/// helpers. The invocation-layer split — `argv: &[&str]` as the sole
/// input — keeps ONE body for the spawn + I/O + parse composition
/// while letting each caller spell its own argv. Same
/// invocation-vs-parsing-layer split discipline
/// [`kubectl_get_object`] applies on the single-object surface.
///
/// # Context wrapper
///
/// A `.with_context(|| format!("Failed to execute kubectl {}", argv.join(" ")))`
/// wraps the `.output().await` I/O error at ONE body — pre-lift the
/// five sites carried a bare `?` with no spawn-failure context, so a
/// PATH-lookup failure or process-limit exhaustion surfaced as an
/// opaque `no such file or directory (os error 2)` at the fetch site,
/// with no indication of which kubectl invocation failed (`fetch_pods`,
/// `fetch_secrets`, and `fetch_events` fire the same second in
/// `forge status`; a single opaque IO error offered no
/// discrimination). Post-lift every spawn-failure at any of the five
/// sites surfaces with the exact kubectl argv at the site of failure
/// — a "sharpen the existing promise: error fidelity" pass parallel
/// to [`kubectl_get_object`]'s context wrapper.
///
/// # Composition
///
/// Composes downstream through the parse-layer sibling
/// [`kubectl_get_items`], which owns the "non-success exit collapses
/// to `Ok(vec![])`, success + JSON with `.items[]` returns the moved
/// array via `std::mem::take`, success + JSON without `.items[]`
/// collapses to `Ok(vec![])`, success + invalid JSON propagates the
/// parse error" branch matrix. This helper adds nothing to that
/// matrix beyond the I/O `?` — the failure classification remains
/// exactly the discipline the four pre-lift sites already honored.
async fn kubectl_list_items(argv: &[&str]) -> Result<Vec<serde_json::Value>> {
    let output = kubectl_command_async()
        .args(argv)
        .output()
        .await
        .with_context(|| format!("Failed to execute kubectl {}", argv.join(" ")))?;
    kubectl_get_items(&output)
}

/// Parse a `kubectl get ... -o json` list-shaped output into its
/// `.items[]` array, extracted as an owned `Vec<serde_json::Value>` so
/// the caller can iterate/filter/map without threading a borrow of the
/// parsed document through the fetch site.
///
/// # Cases
///
/// - **Non-success exit** — returns `Ok(vec![])`. The five `fetch_*`
///   list-shaped consumer sites in this module already collapse kubectl
///   unavailability (RBAC-denied `get`, missing CRD, kubeconfig
///   pointing at a down cluster) to an empty-result summary rather than
///   failing the whole status render; this primitive preserves that
///   discipline at one body.
/// - **Success + valid JSON with an `.items[]` array** — returns the
///   items in document order. Extraction uses `std::mem::take` on the
///   parsed array in place of a `.cloned()` deep-copy so the primitive
///   stays O(1) in the item count and moves the item [`serde_json::
///   Value`]s rather than duplicating their nested heap allocations.
/// - **Success + valid JSON without an `.items[]` array** — returns
///   `Ok(vec![])`. The five pre-lift consumers all treated a
///   missing/non-array `.items` field as an empty list (via
///   `.and_then(|i| i.as_array()).unwrap_or(&empty_vec)` at four sites,
///   `.unwrap_or(json!({"items": []}))` at `fetch_pods`); this
///   primitive preserves that at one body.
/// - **Success + invalid JSON** — propagates the [`serde_json::Error`]
///   through `?`. Four pre-lift consumers spelled `serde_json::
///   from_slice(&output.stdout)?` verbatim; the fifth (`fetch_pods`)
///   pre-lift silently swallowed invalid-JSON via
///   `.unwrap_or(json!({"items": []}))` and rendered `forge status`'s
///   pod row as "0 pods" on a corrupt/truncated kubectl stdout — a
///   diagnosis-defeating silent-empty on a state the operator would
///   want surfaced. Post-lift `fetch_pods` propagates the parse error
///   alongside the four siblings — the four sites' pre-existing
///   discipline colonizes the fifth by lifting through this
///   primitive.
///
/// # Consumers
///
/// - [`fetch_pods`]
/// - [`fetch_secrets`]
/// - [`fetch_k8s_services`]
/// - [`fetch_migrations`]
/// - [`fetch_events`]
///
/// Five sibling call sites past the "two is a coincidence; three is a
/// law" threshold — see the retry-schedule (`RetryPolicy::compute_delay`)
/// and helm-error-branch (`ensure_helm_success`) sibling lifts on the
/// prior claude-routine chain.
fn kubectl_get_items(output: &std::process::Output) -> Result<Vec<serde_json::Value>> {
    if !output.status.success() {
        return Ok(vec![]);
    }
    let mut json: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    Ok(match json.get_mut("items") {
        Some(serde_json::Value::Array(arr)) => std::mem::take(arr),
        _ => vec![],
    })
}

/// Parse a `kubectl get <resource> <name> -o json` single-object output
/// into its JSON document, bailing with `not_found_msg` on a non-success
/// exit.
///
/// # Single-object peer of the list-shaped primitive
///
/// Sibling primitive to [`kubectl_get_items`] on the list-shaped
/// surface. The two primitives split by consumer-side default
/// discipline:
///
/// - [`kubectl_get_items`] collapses kubectl unavailability to
///   `Ok(vec![])` — list-shaped consumers (`fetch_secrets`,
///   `fetch_k8s_services`, `fetch_migrations`, `fetch_events`) treat a
///   missing collection as an empty result summary because the whole
///   status render must survive a `kubectl get secrets` RBAC-denial or
///   missing-CRD without failing the sibling fetches.
/// - [`kubectl_get_item`] collapses kubectl unavailability to
///   `Err(not_found_msg)` — single-object consumers use the fetched
///   document as an unconditional dependency for downstream field
///   extraction, so a missing document is a bail-out error, not an
///   empty-doc default that would surface a fabricated
///   `{readyReplicas: 0, replicas: 0} → "Ready"` summary in place of
///   the "the resource does not exist" world.
///
/// # Cases
///
/// - **Non-success exit** — bails with `not_found_msg` verbatim. The
///   four pre-lift consumer sites each spelled `if
///   !output.status.success() { anyhow::bail!("<caller-specific
///   msg>"); }` verbatim. Even when stdout carries a nominally valid
///   JSON document, a non-success exit MUST short-circuit before the
///   parse: kubectl's error-document shape can appear on stdout while
///   the exit status carries the real result.
/// - **Success + valid JSON** — returns the parsed
///   [`serde_json::Value`]. Consumers extract fields via `.get`,
///   `.pointer`, etc.
/// - **Success + invalid JSON** — propagates the [`serde_json::Error`]
///   through `?`. Mirrors the [`kubectl_get_items`] discipline: a
///   corrupt/truncated stdout under a success exit is an error at the
///   fetch site, not a silent empty document.
///
/// # Consumers
///
/// - [`fetch_statefulset`] — bails `"StatefulSet not found"`
/// - [`fetch_redis`] — bails `"Redis deployment not found"`
/// - [`fetch_redis_statefulset`] — bails `"Redis statefulset not found"`
/// - [`fetch_configmap`] — bails `"ConfigMap not found"`
///
/// Four sibling call sites past the "two is a coincidence; three is a
/// law" threshold — see the retry-schedule
/// (`RetryPolicy::compute_delay`), helm-error-branch
/// (`ensure_helm_success`), release-tracker HTTP-error
/// (`ensure_success` + `format_failure`), and list-shaped fetch
/// (`kubectl_get_items`) sibling lifts on the prior claude-routine
/// chain.
fn kubectl_get_item(
    output: &std::process::Output,
    not_found_msg: &str,
) -> Result<serde_json::Value> {
    if !output.status.success() {
        anyhow::bail!("{}", not_found_msg);
    }
    Ok(serde_json::from_slice(&output.stdout)?)
}

/// Summarize the replica readiness of a workload document (Deployment
/// or StatefulSet) into the display pair three sibling `fetch_*` sites
/// emit verbatim: the `"<ready>/<desired>"` ratio string and the
/// `"Ready"` (ready == desired) / `"NotReady"` (otherwise) status
/// string.
///
/// Both slots route through [`replica_count`] so the
/// `/status/readyReplicas` and `/spec/replicas` JSON-pointer reads
/// share the lenient-typing discipline (missing / malformed field
/// treated as `0`) with the wider [`fetch_deployment`] consumer at ONE
/// body rather than one-per-site. The `ready == desired` equality —
/// rather than a threshold or a `>=` — matches the pre-lift consumers'
/// behavior byte-for-byte: an over-provisioned pod count
/// (readyReplicas > replicas, transient during scale-down) surfaces as
/// `"NotReady"`, matching the pre-lift semantics rather than silently
/// promoting it to `"Ready"`.
///
/// # Consumers
///
/// - [`fetch_statefulset`] — StatefulSet document, drives `StatefulSetInfo::{ready, status}`
/// - [`fetch_redis`] — Deployment document, drives `ResourceInfo::{ready, status}`
/// - [`fetch_redis_statefulset`] — StatefulSet document, drives `ResourceInfo::{ready, status}`
///
/// Three sibling call sites past the "two is a coincidence; three is a
/// law" threshold — see the retry-schedule
/// (`RetryPolicy::compute_delay`), helm-error-branch
/// (`ensure_helm_success`), release-tracker HTTP-error
/// (`ensure_success` + `format_failure`), list-shaped fetch
/// (`kubectl_get_items`), and single-object fetch (`kubectl_get_item`)
/// sibling lifts on the prior claude-routine chain.
fn replica_readiness_display(doc: &serde_json::Value) -> (String, String) {
    let ready = replica_count(doc, "/status/readyReplicas");
    let desired = replica_count(doc, "/spec/replicas");
    let status = if ready == desired {
        "Ready".to_string()
    } else {
        "NotReady".to_string()
    };
    (format!("{}/{}", ready, desired), status)
}

/// Read a replica-count field from a workload document (Deployment or
/// StatefulSet) via JSON pointer with the lenient-typing discipline
/// every pre-lift consumer applied verbatim:
/// `.pointer(ptr).and_then(|r| r.as_i64()).unwrap_or(0)`. A missing
/// pointer, a wrong-typed value (a string, a float, a null), and an
/// absent intermediate object all collapse to `0` rather than
/// propagating a type error the fetch site cannot recover from.
///
/// Load-bearing: kubectl's Deployment status shape omits
/// `readyReplicas` when it is zero, and a fresh Deployment whose
/// controller has not yet populated `/status` reports the absent
/// intermediate. Both cases must surface as `0`, not as an error.
///
/// # Consumers
///
/// - [`replica_readiness_display`] — twice, for `/status/readyReplicas` and `/spec/replicas`
/// - [`fetch_deployment`] — five times, driving [`ReplicaStatus`] via `as i32` narrowing
///
/// Seven sibling call sites past the "two is a coincidence; three is a
/// law" threshold — see the retry-schedule
/// (`RetryPolicy::compute_delay`), helm-error-branch
/// (`ensure_helm_success`), release-tracker HTTP-error
/// (`ensure_success` + `format_failure`), list-shaped fetch
/// (`kubectl_get_items`), single-object fetch (`kubectl_get_item`),
/// and readiness-display (`replica_readiness_display`) sibling lifts on
/// the prior claude-routine chain. Closes the "future concern" the
/// sibling `replica_readiness_display` doc noted at cd1cb10: the
/// discipline the display-pair primitive owned at two sites now
/// composes at the wider [`fetch_deployment`] five-slot extraction
/// via this shared reader, so a future edit to the lenient-typing
/// arm (adding a `debug!` on the wrong-typed branch, tightening to
/// `.as_u64()` for non-negative counts, or switching to a typed
/// error) lands at ONE body across all seven pre-lift sites.
///
/// # Why an `i64` return
///
/// `serde_json::Value::as_i64` is the widest lenient extraction the
/// pre-lift consumers used: both the two display-pair sites and the
/// five `fetch_deployment` sites spelled `.as_i64().unwrap_or(0)`
/// verbatim. Returning `i64` preserves that width at the primitive
/// and pushes any narrowing (the `as i32` cast the [`ReplicaStatus`]
/// slots apply) to the caller boundary — which matches the pre-lift
/// shape byte-for-byte.
fn replica_count(doc: &serde_json::Value, ptr: &str) -> i64 {
    doc.pointer(ptr).and_then(|r| r.as_i64()).unwrap_or(0)
}

async fn fetch_secrets(namespace: &str, deployment_name: &str) -> Result<Vec<String>> {
    let items = kubectl_list_items(&["get", "secrets", "-n", namespace, "-o", "json"]).await?;

    Ok(items
        .iter()
        .filter_map(|s| s.pointer("/metadata/name").and_then(|n| n.as_str()))
        .filter(|n| n.contains(deployment_name) || n.contains("ghcr"))
        .map(String::from)
        .collect())
}

async fn fetch_k8s_services(namespace: &str, deployment_name: &str) -> Result<Vec<ServiceInfo>> {
    let items = kubectl_list_items(&[
        "get",
        "services",
        "-n",
        namespace,
        "-l",
        &format!("app={}", deployment_name),
        "-o",
        "json",
    ])
    .await?;

    Ok(items
        .iter()
        .filter_map(|svc| {
            let name = svc.pointer("/metadata/name")?.as_str()?.to_string();
            let service_type = svc
                .pointer("/spec/type")
                .and_then(|t| t.as_str())
                .unwrap_or("ClusterIP")
                .to_string();
            let cluster_ip = svc
                .pointer("/spec/clusterIP")
                .and_then(|i| i.as_str())
                .map(String::from);
            let ports: Vec<String> = svc
                .pointer("/spec/ports")
                .and_then(|p| p.as_array())
                .map(|ports| {
                    ports
                        .iter()
                        .filter_map(|p| {
                            let port = p.get("port")?.as_i64()?;
                            let target =
                                p.get("targetPort").and_then(|t| t.as_i64()).unwrap_or(port);
                            let name = p.get("name").and_then(|n| n.as_str()).unwrap_or("tcp");
                            Some(format!("{}:{}->{}", name, port, target))
                        })
                        .collect()
                })
                .unwrap_or_default();

            Some(ServiceInfo {
                name,
                service_type,
                cluster_ip,
                ports,
            })
        })
        .collect())
}

async fn fetch_migrations(namespace: &str, deployment_name: &str) -> Result<Vec<MigrationInfo>> {
    let items = kubectl_list_items(&[
        "get",
        "jobs",
        "-n",
        namespace,
        "-l",
        &format!("app={}", deployment_name),
        "-o",
        "json",
        "--sort-by=.metadata.creationTimestamp",
    ])
    .await?;

    // Take last 5 jobs
    Ok(items
        .iter()
        .rev()
        .take(5)
        .filter_map(|job| {
            let name = job.pointer("/metadata/name")?.as_str()?.to_string();
            if !name.contains("migration") && !name.contains("migrate") {
                return None;
            }

            let status = job.get("status").unwrap_or(&serde_json::Value::Null);
            let succeeded = status
                .get("succeeded")
                .and_then(|s| s.as_i64())
                .unwrap_or(0);
            let failed = status.get("failed").and_then(|f| f.as_i64()).unwrap_or(0);

            let job_status = if succeeded > 0 {
                "Succeeded".to_string()
            } else if failed > 0 {
                "Failed".to_string()
            } else {
                "Running".to_string()
            };

            let started = status
                .get("startTime")
                .and_then(|t| t.as_str())
                .map(String::from);
            let completed = status
                .get("completionTime")
                .and_then(|t| t.as_str())
                .map(String::from);

            let duration = if let (Some(start), Some(end)) = (&started, &completed) {
                calculate_duration(start, end)
            } else {
                None
            };

            Some(MigrationInfo {
                name,
                status: job_status,
                started,
                completed,
                duration,
            })
        })
        .collect())
}

async fn fetch_events(namespace: &str, deployment_name: &str) -> Result<Vec<EventInfo>> {
    let items = kubectl_list_items(&[
        "get",
        "events",
        "-n",
        namespace,
        "--field-selector",
        &format!("involvedObject.name={}", deployment_name),
        "-o",
        "json",
        "--sort-by=.lastTimestamp",
    ])
    .await?;

    // Take last 5 events
    Ok(items
        .iter()
        .rev()
        .take(5)
        .filter_map(|event| {
            Some(EventInfo {
                event_type: event.get("type")?.as_str()?.to_string(),
                reason: event.get("reason")?.as_str()?.to_string(),
                message: event
                    .get("message")
                    .and_then(|m| m.as_str())
                    .unwrap_or("")
                    .to_string(),
                age: calculate_age(
                    event
                        .get("lastTimestamp")
                        .and_then(|t| t.as_str())
                        .unwrap_or(""),
                ),
                count: event.get("count").and_then(|c| c.as_i64()).unwrap_or(1) as i32,
            })
        })
        .collect())
}

// ============================================================================
// Utilities
// ============================================================================

fn calculate_age(timestamp: &str) -> String {
    use chrono::{DateTime, Utc};

    if let Ok(created) = DateTime::parse_from_rfc3339(timestamp) {
        let now = Utc::now();
        let duration = now.signed_duration_since(created);

        if duration.num_days() > 0 {
            format!("{}d{}h", duration.num_days(), duration.num_hours() % 24)
        } else if duration.num_hours() > 0 {
            format!("{}h{}m", duration.num_hours(), duration.num_minutes() % 60)
        } else if duration.num_minutes() > 0 {
            format!(
                "{}m{}s",
                duration.num_minutes(),
                duration.num_seconds() % 60
            )
        } else {
            format!("{}s", duration.num_seconds())
        }
    } else {
        "-".to_string()
    }
}

fn calculate_duration(start: &str, end: &str) -> Option<String> {
    use chrono::DateTime;

    let start_dt = DateTime::parse_from_rfc3339(start).ok()?;
    let end_dt = DateTime::parse_from_rfc3339(end).ok()?;
    let duration = end_dt.signed_duration_since(start_dt);

    Some(if duration.num_minutes() > 0 {
        format!(
            "{}m{}s",
            duration.num_minutes(),
            duration.num_seconds() % 60
        )
    } else {
        format!("{}s", duration.num_seconds())
    })
}

impl Default for RelatedServices {
    fn default() -> Self {
        Self {
            postgres: None,
            redis: None,
            configmap: None,
            secrets: vec![],
            services: vec![],
        }
    }
}

// ============================================================================
// Output Formatting
// ============================================================================

fn print_text_status(status: &ServiceStatus) {
    let width = 80;
    let separator = "═".repeat(width);
    let thin_sep = "─".repeat(width);

    // Header
    println!();
    println!("{}", format!("╔{}╗", separator).bright_cyan().bold());
    println!(
        "{}",
        format!("║  {} Service Status: {:<54}║", "📊", status.service)
            .bright_cyan()
            .bold()
    );
    println!("{}", format!("╚{}╝", separator).bright_cyan().bold());
    println!();

    // Overview Section
    println!(
        "{}",
        "┌─ Overview ─────────────────────────────────────────────────────────────────────┐"
            .bright_white()
            .bold()
    );
    println!(
        "│  {} Environment: {:<20} {} Namespace: {:<23}│",
        "🌍",
        status.environment.bright_yellow(),
        "📦",
        status.namespace.bright_yellow()
    );
    println!(
        "│  {} Deployment:  {:<20} {} Strategy:  {:<23}│",
        "🚀",
        status.deployment.name.bright_green(),
        "⚙️ ",
        status.deployment.strategy
    );
    if let Some(tag) = &status.deployment.tag {
        println!(
            "│  {} Image Tag:  {:<63}│",
            "🏷️ ",
            tag.bright_green().bold()
        );
    }
    println!("└{}┘", thin_sep);
    println!();

    // Replicas Section
    let rep = &status.deployment.replicas;
    let health_status = if rep.ready == rep.desired && rep.unavailable == 0 {
        "✅ Healthy".bright_green()
    } else if rep.ready > 0 {
        "⚠️  Degraded".bright_yellow()
    } else {
        "❌ Unhealthy".bright_red()
    };

    println!(
        "{}",
        "┌─ Replicas ─────────────────────────────────────────────────────────────────────┐"
            .bright_white()
            .bold()
    );
    println!("│  Status: {:<70}│", health_status);
    println!(
        "│  Ready: {}/{:<5} Available: {:<5} Updated: {:<5} Unavailable: {:<11}│",
        rep.ready, rep.desired, rep.available, rep.updated, rep.unavailable
    );
    println!("└{}┘", thin_sep);
    println!();

    // Conditions
    if !status.deployment.conditions.is_empty() {
        println!(
            "{}",
            "┌─ Conditions ───────────────────────────────────────────────────────────────────┐"
                .bright_white()
                .bold()
        );
        for cond in &status.deployment.conditions {
            let icon = if cond.status == "True" { "✅" } else { "❌" };
            let reason = cond.reason.as_deref().unwrap_or("-");
            println!(
                "│  {} {:<15} {:>6}  Reason: {:<40}│",
                icon, cond.condition_type, cond.status, reason
            );
        }
        println!("└{}┘", thin_sep);
        println!();
    }

    // Pods Section
    if !status.pods.is_empty() {
        println!(
            "{}",
            "┌─ Pods ──────────────────────────────────────────────────────────────────────────┐"
                .bright_white()
                .bold()
        );
        println!(
            "│  {:<45} {:<10} {:<7} {:<8} {:<8}│",
            "NAME".dimmed(),
            "STATUS".dimmed(),
            "READY".dimmed(),
            "RESTART".dimmed(),
            "AGE".dimmed()
        );
        for pod in &status.pods {
            let status_str = match pod.status.as_str() {
                "Running" => pod.status.bright_green(),
                "Pending" => pod.status.bright_yellow(),
                _ => pod.status.bright_red(),
            };
            let restarts_str = if pod.restarts > 0 {
                pod.restarts.to_string().bright_yellow()
            } else {
                pod.restarts.to_string().normal()
            };
            println!(
                "│  {:<45} {:<10} {:<7} {:<8} {:<8}│",
                truncate(&pod.name, 45),
                status_str,
                pod.ready,
                restarts_str,
                pod.age
            );
            if let Some(ip) = &pod.ip {
                println!("│    └─ IP: {:<68}│", ip.dimmed());
            }
        }
        println!("└{}┘", thin_sep);
        println!();
    }

    // Containers Section
    if !status.containers.is_empty() {
        println!(
            "{}",
            "┌─ Containers ───────────────────────────────────────────────────────────────────┐"
                .bright_white()
                .bold()
        );

        // Group by main vs sidecar
        let main_containers: Vec<_> = status.containers.iter().filter(|c| !c.is_sidecar).collect();
        let sidecars: Vec<_> = status.containers.iter().filter(|c| c.is_sidecar).collect();

        if !main_containers.is_empty() {
            println!("│  {} {}", "📦", "Main Application".bright_white().bold());
            for c in main_containers {
                let state_str = match c.state.as_str() {
                    "Running" => c.state.bright_green(),
                    "Waiting" | "CrashLoopBackOff" => c.state.bright_yellow(),
                    _ => c.state.bright_red(),
                };
                let ready_icon = if c.ready { "✅" } else { "❌" };
                println!(
                    "│    {} {:<20} {:<12} Tag: {:<30}│",
                    ready_icon,
                    c.name,
                    state_str,
                    c.tag.bright_cyan()
                );
            }
        }

        if !sidecars.is_empty() {
            println!("│  {} {}", "🔌", "Sidecars".dimmed());
            for c in sidecars {
                let state_str = match c.state.as_str() {
                    "Running" => c.state.bright_green(),
                    _ => c.state.bright_yellow(),
                };
                let ready_icon = if c.ready { "✅" } else { "⏳" };
                println!(
                    "│    {} {:<20} {:<12} {:<35}│",
                    ready_icon,
                    c.name.dimmed(),
                    state_str,
                    truncate(&c.tag, 35).dimmed()
                );
            }
        }
        println!("└{}┘", thin_sep);
        println!();
    }

    // Related Services Section
    let related = &status.related_services;
    let has_related =
        related.postgres.is_some() || related.redis.is_some() || related.configmap.is_some();

    if has_related {
        println!(
            "{}",
            "┌─ Related Resources ────────────────────────────────────────────────────────────┐"
                .bright_white()
                .bold()
        );

        if let Some(pg) = &related.postgres {
            let status_icon = if pg.status == "Ready" { "✅" } else { "❌" };
            println!(
                "│  {} PostgreSQL: {:<15} {} {:<10} Storage: {:<20}│",
                "🐘",
                pg.name,
                status_icon,
                pg.ready,
                pg.storage.as_deref().unwrap_or("-")
            );
        }

        if let Some(redis) = &related.redis {
            let status_icon = if redis.status == "Ready" {
                "✅"
            } else {
                "❌"
            };
            println!(
                "│  {} Redis:      {:<15} {} {:<41}│",
                "🔴", redis.name, status_icon, redis.ready
            );
        }

        if let Some(cm) = &related.configmap {
            println!(
                "│  {} ConfigMap:  {:<15} {} keys: [{}]{}│",
                "📄",
                cm.name,
                cm.data_size,
                cm.keys
                    .iter()
                    .take(3)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", "),
                if cm.keys.len() > 3 { "..." } else { "" }
            );
        }

        if !related.secrets.is_empty() {
            println!(
                "│  {} Secrets:    {:<62}│",
                "🔐",
                related.secrets.join(", ")
            );
        }

        println!("└{}┘", thin_sep);
        println!();
    }

    // K8s Services
    if !related.services.is_empty() {
        println!(
            "{}",
            "┌─ Services ──────────────────────────────────────────────────────────────────────┐"
                .bright_white()
                .bold()
        );
        for svc in &related.services {
            let ip = svc.cluster_ip.as_deref().unwrap_or("-");
            println!(
                "│  {} {:<25} {:<12} IP: {:<33}│",
                "🌐", svc.name, svc.service_type, ip
            );
            if !svc.ports.is_empty() {
                println!("│    └─ Ports: {:<64}│", svc.ports.join(", ").dimmed());
            }
        }
        println!("└{}┘", thin_sep);
        println!();
    }

    // Migrations Section
    if !status.migrations.is_empty() {
        println!(
            "{}",
            "┌─ Recent Migrations ────────────────────────────────────────────────────────────┐"
                .bright_white()
                .bold()
        );
        for mig in &status.migrations {
            let status_str = match mig.status.as_str() {
                "Succeeded" => mig.status.bright_green(),
                "Failed" => mig.status.bright_red(),
                _ => mig.status.bright_yellow(),
            };
            let duration = mig.duration.as_deref().unwrap_or("-");
            println!(
                "│  {:<45} {:<12} Duration: {:<12}│",
                truncate(&mig.name, 45),
                status_str,
                duration
            );
        }
        println!("└{}┘", thin_sep);
        println!();
    }

    // Events Section
    if !status.events.is_empty() {
        println!(
            "{}",
            "┌─ Recent Events ────────────────────────────────────────────────────────────────┐"
                .bright_white()
                .bold()
        );
        for event in &status.events {
            let type_icon = match event.event_type.as_str() {
                "Warning" => "⚠️ ".bright_yellow(),
                "Normal" => "ℹ️ ".bright_blue(),
                _ => "❓".normal(),
            };
            println!(
                "│  {} {:<15} {:<55}│",
                type_icon,
                event.reason,
                truncate(&event.message, 55)
            );
            println!(
                "│    └─ Age: {:<10} Count: {:<50}│",
                event.age.dimmed(),
                event.count.to_string().dimmed()
            );
        }
        println!("└{}┘", thin_sep);
        println!();
    }

    // Footer
    println!("{}", format!("═{}═", separator).bright_cyan());
    println!();
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() > max_len {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    } else {
        s.to_string()
    }
}

fn print_json_status(status: &ServiceStatus) -> Result<()> {
    let json = serde_json::to_string_pretty(status)?;
    println!("{}", json);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_output_format_from_str_json() {
        assert_eq!(OutputFormat::from_str("json"), OutputFormat::Json);
        assert_eq!(OutputFormat::from_str("JSON"), OutputFormat::Json);
        assert_eq!(OutputFormat::from_str("Json"), OutputFormat::Json);
    }

    #[test]
    fn test_output_format_from_str_text_default() {
        assert_eq!(OutputFormat::from_str("text"), OutputFormat::Text);
        assert_eq!(OutputFormat::from_str(""), OutputFormat::Text);
        assert_eq!(OutputFormat::from_str("yaml"), OutputFormat::Text);
        assert_eq!(OutputFormat::from_str("anything"), OutputFormat::Text);
    }

    /// Regression shield: every `kubectl`-spawning site in
    /// `commands/status.rs`'s ten top-level async fetch helpers
    /// (`fetch_deployment`, `fetch_pods`, `fetch_statefulset`,
    /// `fetch_redis`, `fetch_redis_statefulset`, `fetch_configmap`,
    /// `fetch_secrets`, `fetch_k8s_services`, `fetch_migrations`,
    /// `fetch_events`) MUST resolve the binary through
    /// [`crate::infrastructure::kubectl::kubectl_command_async`]
    /// rather than the pre-lift `Command::new("kubectl")` literal.
    /// Pre-migration ten sites each spelled the bare
    /// `Command::new("kubectl")` shape verbatim and thereby
    /// bypassed the `KUBECTL_BIN` env override the tools-registry
    /// idiom (`crate::tools::get_tool_path(tools::KUBECTL)`,
    /// cli/src/tools.rs:102-105) resolves — the same class of bug
    /// the sibling `commands/supergraph_verification.rs` /
    /// `commands/product_release.rs::run_health_check` /
    /// `commands/github_runner_ci.rs::execute` /
    /// `services/migration_service.rs::MigrationService`
    /// migrations redeemed at 65283fb / 5bb7cff / 5566415 / 5986a10.
    ///
    /// This test reads this module's own source via [`include_str!`]
    /// and asserts the raw `Command::new("kubectl")` string does not
    /// reappear anywhere in the module's non-test body while the
    /// delegation to `kubectl_command_async()` does. A future
    /// regression that re-fuses the raw-spawn body fails here, not
    /// silently in production where a Nix-hermetic runner's
    /// `KUBECTL_BIN`-provided `kubectl` would lose to whatever
    /// `kubectl` is first on `PATH` at `forge status` invocation
    /// time.
    ///
    /// The scan is bounded strictly to the module's non-test body
    /// — from the file start to the `#[cfg(test)]` marker — so
    /// this shield's own docstring mention of
    /// `Command::new("kubectl")` (which lives inside the sibling
    /// `#[cfg(test)] mod tests` block below) stays out of scope
    /// AND every current or future kubectl-spawning helper landing
    /// anywhere in the top-level module body (i.e., in any of the
    /// ten migrated fetch helpers or any as-yet unadded sibling)
    /// cannot silently ride along without going through the
    /// primitive. Mirrors the whole-module boundary discipline the
    /// sibling `commands/supergraph_verification.rs` shield
    /// (65283fb) pioneered on the multi-function consumer surface.
    #[test]
    fn test_status_routes_kubectl_through_kubectl_command_async_not_raw_command() {
        let source = include_str!("status.rs");
        let tests_marker = "\n#[cfg(test)]\nmod tests {";
        let body_end = source.find(tests_marker).expect(
            "the `#[cfg(test)]\\nmod tests {` marker must follow \
                 the module body — the shield's slice boundary relies \
                 on this module ordering",
        );
        let module_body = &source[..body_end];

        assert!(
            !module_body.contains("Command::new(\"kubectl\")"),
            "status.rs must NOT spawn `kubectl` directly — route \
             through \
             `crate::infrastructure::kubectl::kubectl_command_async()` \
             so `KUBECTL_BIN` overrides land at the shared primitive. \
             Found the pre-migration spawn body in the module."
        );
        assert!(
            module_body.contains("kubectl_command_async()"),
            "status.rs must delegate every kubectl spawn to \
             `kubectl_command_async()` — the delegation string was \
             not found in the module body."
        );
    }

    // Build a synthetic `std::process::Output` for the `kubectl_get_items`
    // shields below. Centralized so a future reshape of the shape
    // (adding a captured signal, widening to a cross-platform
    // `ExitStatusExt`) lands at one place, mirroring the sibling
    // `commands/helm.rs::capture_tests::make_output` builder committed
    // at 9e8e75c.
    fn make_output(success: bool, stdout: &[u8], stderr: &[u8]) -> std::process::Output {
        use std::os::unix::process::ExitStatusExt;
        std::process::Output {
            status: std::process::ExitStatus::from_raw(if success { 0 } else { 1 << 8 }),
            stdout: stdout.to_vec(),
            stderr: stderr.to_vec(),
        }
    }

    #[test]
    fn kubectl_get_items_returns_empty_vec_on_non_success_exit_status() {
        // Pre-lift the four `fetch_*` list-shaped consumer sites each
        // spelled `if !output.status.success() { return Ok(vec![]); }`
        // verbatim — this shield pins the primitive collapses kubectl
        // unavailability to the same empty-result summary at ONE body.
        // Even when stdout carries a nominally valid `{"items":[...]}`
        // document, a non-success exit MUST short-circuit before the
        // parse: RBAC-denied `get` and missing-CRD `get` return an
        // error status alongside a helpful stderr-shaped hint, and
        // the pre-lift consumers all discarded stdout in that case.
        let out = make_output(false, br#"{"items":[{"metadata":{"name":"leaked"}}]}"#, b"");
        let items = super::kubectl_get_items(&out).expect("non-success exit is Ok(empty)");
        assert!(
            items.is_empty(),
            "non-success exit must collapse to Ok(empty); a caller \
             that saw the stdout-emitted `leaked` item would silently \
             surface a stale kubectl response as though the query \
             succeeded"
        );
    }

    #[test]
    fn kubectl_get_items_returns_items_array_in_document_order_on_success() {
        // The four pre-lift consumer sites all iterated `items.iter()`
        // — in document order — over the `.items[]` array. This shield
        // pins that document-order iteration survives the lift by
        // asserting the primitive returns items in the same order they
        // appear in the kubectl JSON. A future regression that
        // accidentally reversed (e.g., `.into_iter().rev().collect()`)
        // would silently swap the "last 5 jobs" / "last 5 events"
        // semantics at `fetch_migrations` and `fetch_events` — those
        // two sites apply `.rev().take(5)` post-primitive, so an
        // upstream reverse would surface the FIRST 5 (oldest) instead
        // of the LAST 5 (newest).
        let out = make_output(
            true,
            br#"{"items":[
                {"metadata":{"name":"alpha"}},
                {"metadata":{"name":"beta"}},
                {"metadata":{"name":"gamma"}}
            ]}"#,
            b"",
        );
        let items = super::kubectl_get_items(&out).expect("success + valid JSON is Ok(items)");
        let names: Vec<&str> = items
            .iter()
            .map(|i| {
                i.pointer("/metadata/name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("")
            })
            .collect();
        assert_eq!(names, vec!["alpha", "beta", "gamma"]);
    }

    #[test]
    fn kubectl_get_items_returns_empty_vec_when_items_field_missing() {
        // Pre-lift the four consumer sites all spelled
        // `.get("items").and_then(|i| i.as_array()).unwrap_or(&empty_vec)`
        // verbatim — a missing `.items` field silently collapsed to an
        // empty items list. This shield pins that: kubectl's `-o json`
        // for a not-found single-object query (e.g., `get deployment
        // nonexistent`) returns a JSON error document without an
        // `.items[]` array — the pre-lift consumers treated that as
        // empty rather than as an error. Preserved at the primitive.
        let out = make_output(
            true,
            br#"{"kind":"Status","status":"Failure","message":"deployment not found"}"#,
            b"",
        );
        let items = super::kubectl_get_items(&out).expect("success + missing items is Ok(empty)");
        assert!(items.is_empty());
    }

    #[test]
    fn kubectl_get_items_returns_empty_vec_when_items_field_is_not_an_array() {
        // Pre-lift the four consumer sites all guarded the `.items`
        // extraction with `.and_then(|i| i.as_array())` — a `.items`
        // field whose value was NOT an array (a `null`, a string, an
        // object) collapsed to an empty items list rather than a type
        // error. This shield pins that same lenient-typing discipline
        // at the primitive: a well-formed JSON with `"items":null` or
        // `"items":"unexpected"` yields `Ok(vec![])`, not a parse
        // error. Symmetric to the missing-field shield above.
        let out_null = make_output(true, br#"{"items":null}"#, b"");
        assert!(super::kubectl_get_items(&out_null)
            .expect("success + null items is Ok(empty)")
            .is_empty());
        let out_str = make_output(true, br#"{"items":"nope"}"#, b"");
        assert!(super::kubectl_get_items(&out_str)
            .expect("success + string items is Ok(empty)")
            .is_empty());
        let out_obj = make_output(true, br#"{"items":{"nested":"object"}}"#, b"");
        assert!(super::kubectl_get_items(&out_obj)
            .expect("success + object items is Ok(empty)")
            .is_empty());
    }

    #[test]
    fn kubectl_get_items_propagates_parse_error_on_invalid_json() {
        // Pre-lift the four consumer sites all spelled
        // `serde_json::from_slice(&output.stdout)?` verbatim — a
        // success-status output whose stdout is not valid JSON
        // propagates the parse error through `?` to the caller. The
        // primitive preserves that: a shellshock-style scenario where
        // kubectl exits 0 but emits corrupt or truncated bytes
        // surfaces at the fetch site as an error, not as an empty
        // items list masquerading as a healthy empty response.
        let out = make_output(true, b"this is not json {{[", b"");
        assert!(super::kubectl_get_items(&out).is_err());
    }

    /// Regression shield: `kubectl_get_items` is the ONLY consumer of
    /// the pre-lift `if !output.status.success() { return Ok(vec![]); }
    /// let X: serde_json::Value = serde_json::from_slice(&output.stdout)?;`
    /// stanza in `commands/status.rs`. Pre-lift four `fetch_*`
    /// list-shaped consumer sites (`fetch_secrets`, `fetch_k8s_services`,
    /// `fetch_migrations`, `fetch_events`) each spelled the verbatim
    /// eight-line stanza:
    /// ```text
    /// if !output.status.success() {
    ///     return Ok(vec![]);
    /// }
    ///
    /// let X: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    /// let empty_vec = vec![];
    /// let items = X
    ///     .get("items")
    ///     .and_then(|i| i.as_array())
    ///     .unwrap_or(&empty_vec);
    /// ```
    /// A future regression that re-fused the pre-lift stanza at one
    /// of the four sites (or at a new sixth list-shaped fetch helper —
    /// `fetch_pods` is the fifth, lifted onto `kubectl_list_items` via
    /// its `.unwrap_or(serde_json::json!({"items": []}))` sibling
    /// pre-lift shape pinned by
    /// [`fetch_pods_pre_lift_items_envelope_default_does_not_reappear`])
    /// would silently split the "kubectl unavailability → empty
    /// result" discipline across the primitive and the re-fused site,
    /// re-introducing the "seven-line stanza per site" duplication
    /// this lift redeems. The shield pins the discipline at ONE call
    /// site — the primitive itself — by asserting the `let empty_vec
    /// = vec![];` needle (the only unique load-bearing token from the
    /// pre-lift stanza, present at exactly zero sites post-lift)
    /// appears zero times in the module's non-test body.
    ///
    /// The scan is bounded strictly to the module's non-test body via
    /// the `\n#[cfg(test)]\nmod tests {` marker (same slice boundary
    /// the sibling
    /// `test_status_routes_kubectl_through_kubectl_command_async_not_raw_command`
    /// shield uses) so this shield's own docstring mention of `let
    /// empty_vec = vec![];` stays out of scope. And routes through
    /// [`crate::test_support::code_line_hits`] so `///`-prefixed
    /// doc-comment mentions in the module body's fn docs — should
    /// any future doc reference the pre-lift shape as prose — do not
    /// self-match as phantom hits, the same code-line-filter discipline
    /// the sibling `code_line_hits` consumers established at prior
    /// claude-routine commits (ab06395 / a7d5375 / fa2c702 / fd02aa6 /
    /// cc81215 / 3e26bbc / 4163c7e / ffa5271 / 8eed602).
    #[test]
    fn kubectl_get_items_is_only_json_items_parse_at_the_fetch_helper_bail_surface() {
        let source = include_str!("status.rs");
        let tests_marker = "\n#[cfg(test)]\nmod tests {";
        let body_end = source.find(tests_marker).expect(
            "the `#[cfg(test)]\\nmod tests {` marker must follow \
             the module body — the shield's slice boundary relies \
             on this module ordering",
        );
        let module_body = &source[..body_end];

        let hits = crate::test_support::code_line_hits(module_body, "let empty_vec = vec![];");
        assert!(
            hits.is_empty(),
            "status.rs must route every list-shaped fetch helper's \
             `.items[]` extraction through `kubectl_get_items(&output)` \
             so a future regression that re-fuses the pre-lift \
             `let empty_vec = vec![]; let items = X.get(\"items\")\
             .and_then(|i| i.as_array()).unwrap_or(&empty_vec);` stanza \
             at any of the four `fetch_*` consumer sites (or at a new \
             sixth list-shaped helper) fails here rather than silently \
             splitting the discipline across the primitive and the \
             re-fused site. Found: {hits:?}"
        );
    }

    /// Regression shield: the pre-lift `fetch_pods_json` silent-swallow
    /// shape `serde_json::json!({"items": []})` does NOT reappear in
    /// the module body. Pre-lift `fetch_pods_json` spelled this
    /// value literal at two lines — a `Ok(serde_json::json!({"items":
    /// []}))` early-return on non-success exit, and an
    /// `.unwrap_or(serde_json::json!({"items": []}))` on the JSON
    /// parse — so a corrupt/truncated kubectl stdout on a `-o json`
    /// success exit collapsed to an empty pods list at the fetch site
    /// rather than propagating the parse error via `?`. Post-lift
    /// `fetch_pods` routes both arms through [`kubectl_list_items`]:
    /// the non-success arm collapses to `Ok(vec![])` at the shared
    /// primitive body (parallel to the four sibling `fetch_*`
    /// consumers), and the invalid-JSON arm propagates the
    /// [`serde_json::Error`] via `?` alongside the four siblings —
    /// closing the pre-lift "kubectl `-o json` succeeded, stdout is
    /// nonsense → `forge status` reports 0 pods with no diagnostic"
    /// silent-empty on the state the operator would want surfaced.
    /// A future regression that re-fused either pre-lift arm at
    /// `fetch_pods` (or at a new `fetch_*` helper of the same
    /// silent-swallow shape) fails here rather than silently
    /// re-introducing the empty-envelope-on-parse-error default the
    /// lift redeems.
    ///
    /// Sibling shield to [`kubectl_get_items_is_only_json_items_parse_at_the_fetch_helper_bail_surface`]:
    /// that shield pins the four `let empty_vec = vec![];`
    /// consumer-side pre-lift stanza; this shield pins the distinct
    /// `fetch_pods_json` `.unwrap_or(serde_json::json!({"items":
    /// []}))` pre-lift stanza whose value-literal spelling does not
    /// share a needle with the four siblings but whose silent-empty
    /// discipline is the same class of pre-lift bug.
    ///
    /// The scan is bounded strictly to the module's non-test body
    /// via the `\n#[cfg(test)]\nmod tests {` marker (same slice
    /// boundary the sibling shields use) so this shield's own
    /// docstring mentions of the pre-lift needle stay out of scope.
    /// And routes through [`crate::test_support::code_line_hits`] so
    /// `///`-prefixed doc-comment mentions in the module body's fn
    /// docs — the primitive's own docstring references the pre-lift
    /// shape in prose — do not self-match as phantom hits, the same
    /// code-line-filter discipline the sibling `code_line_hits`
    /// consumers established at prior claude-routine commits
    /// (ab06395 / a7d5375 / fa2c702 / fd02aa6 / cc81215 / 3e26bbc /
    /// 4163c7e / ffa5271 / 8eed602 / f6b4229 / 59c3391 / 695a8cc /
    /// cd1cb10 / 89e3231 / 8216981 / 521bda3).
    #[test]
    fn fetch_pods_pre_lift_items_envelope_default_does_not_reappear() {
        let source = include_str!("status.rs");
        let tests_marker = "\n#[cfg(test)]\nmod tests {";
        let body_end = source.find(tests_marker).expect(
            "the `#[cfg(test)]\\nmod tests {` marker must follow \
             the module body — the shield's slice boundary relies \
             on this module ordering",
        );
        let module_body = &source[..body_end];

        let hits =
            crate::test_support::code_line_hits(module_body, r#"serde_json::json!({"items": []})"#);
        assert!(
            hits.is_empty(),
            "status.rs must route `fetch_pods` (and every future \
             list-shaped fetch helper) through `kubectl_list_items` \
             so the pre-lift `fetch_pods_json` silent-swallow shape \
             `serde_json::json!({{\"items\": []}})` — used as both \
             an `Ok(...)` early-return on non-success exit and as an \
             `.unwrap_or(...)` default on the JSON parse — does not \
             reappear in the module body. Pre-lift a corrupt/truncated \
             kubectl `-o json` success stdout collapsed to \"0 pods\" \
             at `forge status` with no diagnostic; post-lift the \
             invalid-JSON arm propagates the `serde_json::Error` via \
             `?` at the shared primitive alongside the four sibling \
             list-shaped fetch consumers. A future regression that \
             re-fuses the pre-lift envelope-default at `fetch_pods` \
             or at any new `fetch_*` helper of the same silent-swallow \
             shape fails here rather than silently re-introducing the \
             empty-envelope-on-parse-error default the lift redeems. \
             Found: {hits:?}"
        );
    }

    #[test]
    fn kubectl_get_item_bails_with_msg_on_non_success_exit_status() {
        // Pre-lift the four `fetch_*` single-object consumer sites
        // (`fetch_statefulset`, `fetch_redis`, `fetch_redis_statefulset`,
        // `fetch_configmap`) each spelled `if !output.status.success() {
        // anyhow::bail!("<msg>"); }` verbatim before the JSON parse.
        // This shield pins the primitive bails with the caller-supplied
        // message verbatim on non-success exit — a downstream operator's
        // grep target ("StatefulSet not found" in the render error stream)
        // survives the lift byte-for-byte.
        let out = make_output(false, b"", b"kubectl error");
        let err = super::kubectl_get_item(&out, "StatefulSet not found")
            .expect_err("non-success exit must bail");
        assert_eq!(err.to_string(), "StatefulSet not found");
    }

    #[test]
    fn kubectl_get_item_bails_ignoring_stdout_bytes_on_non_success_exit_status() {
        // The pre-lift consumers all discarded stdout when exit was
        // non-success: the `if !output.status.success() { bail!(); }`
        // arm short-circuits BEFORE the `serde_json::from_slice` parse.
        // This shield pins that: even when stdout carries a nominally
        // valid single-object JSON document (the fabricated shape a
        // kubectl-server-side error might leak alongside a non-zero
        // exit — a "success"-shaped body with a failure exit), the
        // primitive MUST bail with the caller message rather than
        // parse-and-return the stdout doc. A caller that saw the
        // stdout-emitted `readyReplicas: 999` payload would silently
        // surface a stale kubectl response as if the resource were
        // healthy.
        let out = make_output(
            false,
            br#"{"status":{"readyReplicas":999,"replicas":999}}"#,
            b"",
        );
        let err = super::kubectl_get_item(&out, "Redis deployment not found")
            .expect_err("non-success exit must bail regardless of stdout payload");
        assert_eq!(err.to_string(), "Redis deployment not found");
    }

    #[test]
    fn kubectl_get_item_returns_parsed_json_on_success_with_valid_json() {
        // Pre-lift the four consumer sites all spelled `let X:
        // serde_json::Value = serde_json::from_slice(&output.stdout)?;`
        // immediately after the success guard. This shield pins the
        // primitive returns the parsed document verbatim so downstream
        // `.get("status")`, `.pointer("/spec/replicas")`, and `.as_object()`
        // extractions the four consumers apply post-lift compose
        // identically against the returned `serde_json::Value`.
        let out = make_output(
            true,
            br#"{"metadata":{"name":"cache"},"status":{"readyReplicas":3,"replicas":3}}"#,
            b"",
        );
        let doc = super::kubectl_get_item(&out, "unused not-found msg")
            .expect("success + valid JSON is Ok(doc)");
        assert_eq!(
            doc.pointer("/status/readyReplicas")
                .and_then(|v| v.as_i64()),
            Some(3)
        );
        assert_eq!(
            doc.pointer("/metadata/name").and_then(|v| v.as_str()),
            Some("cache")
        );
    }

    #[test]
    fn kubectl_get_item_propagates_parse_error_on_invalid_json_with_success_exit() {
        // Pre-lift the four consumer sites all spelled the parse as
        // `serde_json::from_slice(&output.stdout)?` — a corrupt or
        // truncated stdout under a success exit propagates the parse
        // error through `?` to the caller. This shield pins that
        // discipline at the primitive: a kubectl that exits 0 but
        // emits invalid JSON (a shellshock-style scenario, or a
        // truncated read from a slow kubectl-proxy) surfaces at the
        // fetch site as a parse error, NOT as the caller-supplied
        // `not_found_msg` (which would mislead the operator into
        // believing the resource is absent when it is actually present
        // with a corrupt response payload). Symmetric to the
        // `kubectl_get_items_propagates_parse_error_on_invalid_json`
        // shield the sibling list-shaped primitive carries.
        let out = make_output(true, b"this is not json {{[", b"");
        let err = super::kubectl_get_item(&out, "ConfigMap not found")
            .expect_err("success + invalid JSON must propagate parse error");
        // The parse error must NOT be the caller's not-found message;
        // distinguishing the two failure modes is load-bearing for
        // operator diagnosis.
        assert_ne!(err.to_string(), "ConfigMap not found");
    }

    /// Regression shield: `kubectl_get_item` is the ONLY consumer of
    /// the pre-lift `if !output.status.success() { anyhow::bail!("<X>
    /// not found"); } let <var>: serde_json::Value = serde_json::
    /// from_slice(&output.stdout)?;` stanza in `commands/status.rs`.
    /// Pre-lift the four `fetch_*` single-object consumer sites
    /// (`fetch_statefulset`, `fetch_redis`, `fetch_redis_statefulset`,
    /// `fetch_configmap`) each spelled the verbatim four-line stanza:
    /// ```text
    /// if !output.status.success() {
    ///     anyhow::bail!("<caller-specific msg>");
    /// }
    ///
    /// let X: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    /// ```
    /// where the two lines differ only in the `<caller-msg>` literal
    /// and the pre-parse `let X` binding name. A future regression
    /// that re-fused the pre-lift stanza at one of the four sites (or
    /// at a new fifth single-object fetch helper) would silently
    /// split the "kubectl unavailability → bail with a caller-visible
    /// diagnostic" discipline across the primitive and the re-fused
    /// site, re-introducing the "four-line stanza per site"
    /// duplication this lift redeems. The shield pins the discipline
    /// at ONE call site — the primitive itself — by asserting no code
    /// line in the module body spells both `anyhow::bail!("` (the
    /// one-line bail! literal invocation form) and `not found");` (the
    /// pre-lift caller-visible diagnostic suffix). The one existing
    /// `bail!(` at [`fetch_deployment`] uses the multi-line
    /// `bail!(\n"Failed to get deployment '{}' in namespace '{}': {}"`
    /// form whose `bail!(` opener has no `"` immediately after so
    /// falls outside the compound needle, and whose diagnostic
    /// carries `stderr` rather than `not found` so is orthogonal to
    /// the lifted shape.
    ///
    /// The scan is bounded strictly to the module's non-test body via
    /// the `\n#[cfg(test)]\nmod tests {` marker (same slice boundary
    /// the sibling
    /// `kubectl_get_items_is_only_json_items_parse_at_the_fetch_helper_bail_surface`
    /// shield uses) so this shield's own docstring mention of
    /// `anyhow::bail!("<X> not found");` stays out of scope. And
    /// routes through [`crate::test_support::code_line_hits`] so
    /// `///`-prefixed doc-comment mentions in the module body's fn
    /// docs — should any future doc reference the pre-lift shape as
    /// prose — do not self-match as phantom hits, the same
    /// code-line-filter discipline the sibling `code_line_hits`
    /// consumers established at prior claude-routine commits
    /// (ab06395 / a7d5375 / fa2c702 / fd02aa6 / cc81215 / 3e26bbc /
    /// 4163c7e / ffa5271 / 8eed602 / f6b4229 / 59c3391).
    #[test]
    fn kubectl_get_item_is_only_bail_not_found_parse_stanza_at_the_single_item_fetch_helper_surface(
    ) {
        let source = include_str!("status.rs");
        let tests_marker = "\n#[cfg(test)]\nmod tests {";
        let body_end = source.find(tests_marker).expect(
            "the `#[cfg(test)]\\nmod tests {` marker must follow \
             the module body — the shield's slice boundary relies \
             on this module ordering",
        );
        let module_body = &source[..body_end];

        let bail_hits = crate::test_support::code_line_hits(module_body, "anyhow::bail!(\"");
        let compound_hits: Vec<String> = bail_hits
            .into_iter()
            .filter(|l| l.contains("not found\");"))
            .collect();
        assert!(
            compound_hits.is_empty(),
            "status.rs must route every single-object fetch helper's \
             `if !output.status.success() {{ bail!(\"<X> not found\"); }} \
             let <var>: serde_json::Value = serde_json::from_slice\
             (&output.stdout)?;` stanza through `kubectl_get_item\
             (&output, \"<X> not found\")?` so a future regression \
             that re-fuses the pre-lift stanza at any of the four \
             `fetch_*` single-object consumer sites (or at a new \
             fifth single-object fetch helper) fails here rather than \
             silently splitting the bail-with-diagnostic discipline \
             across the primitive and the re-fused site. Found: \
             {compound_hits:?}"
        );
    }

    // Build a synthetic workload document (Deployment / StatefulSet
    // shape) for the `replica_readiness_display` shields below. Only
    // the `/status/readyReplicas` and `/spec/replicas` fields are
    // load-bearing at the primitive; the other pre-lift consumer-side
    // extractions (`/spec/template/spec/containers/0/image`, etc.)
    // remain at the consumer and are exercised by those consumers'
    // own coverage.
    fn make_workload_doc(ready: Option<i64>, desired: Option<i64>) -> serde_json::Value {
        let mut root = serde_json::Map::new();
        if let Some(d) = desired {
            let mut spec = serde_json::Map::new();
            spec.insert("replicas".to_string(), serde_json::json!(d));
            root.insert("spec".to_string(), serde_json::Value::Object(spec));
        }
        if let Some(r) = ready {
            let mut status = serde_json::Map::new();
            status.insert("readyReplicas".to_string(), serde_json::json!(r));
            root.insert("status".to_string(), serde_json::Value::Object(status));
        }
        serde_json::Value::Object(root)
    }

    #[test]
    fn replica_readiness_display_emits_ready_when_ready_equals_desired() {
        // Pre-lift the three `fetch_*` consumer sites each spelled `if
        // ready == desired { "Ready".to_string() } else { "NotReady".
        // to_string() }` verbatim. This shield pins the primitive
        // emits `"Ready"` on the equality arm — the exact literal
        // string every downstream text-render / JSON-render consumer
        // greps against for the healthy-workload status marker.
        let doc = make_workload_doc(Some(3), Some(3));
        let (ratio, status) = super::replica_readiness_display(&doc);
        assert_eq!(ratio, "3/3");
        assert_eq!(status, "Ready");
    }

    #[test]
    fn replica_readiness_display_emits_not_ready_when_ready_lt_desired() {
        // The unhealthy arm every pre-lift consumer emitted: fewer
        // ready pods than the spec desires (a scale-up mid-rollout or
        // a crashlooping pod). Pinned separately from the healthy arm
        // so a regression that inverted the equality (e.g., swapping
        // `==` for `!=`) fails on exactly one arm rather than
        // silently passing both via a compensating swap.
        let doc = make_workload_doc(Some(1), Some(3));
        let (ratio, status) = super::replica_readiness_display(&doc);
        assert_eq!(ratio, "1/3");
        assert_eq!(status, "NotReady");
    }

    #[test]
    fn replica_readiness_display_emits_not_ready_when_ready_gt_desired() {
        // Over-provisioned pod count — readyReplicas > replicas — is a
        // transient state during scale-down (old pods still ready
        // while the spec has already been reduced). The pre-lift
        // consumers all emitted `if ready == desired` — a strict
        // equality, not a `>=` threshold — so this transient state
        // surfaced as `"NotReady"`. The primitive preserves that
        // discipline: a future regression that softened the equality
        // to `ready >= desired` would silently promote the transient
        // over-provisioned state to `"Ready"` and mislead the operator
        // watching a scale-down finish.
        let doc = make_workload_doc(Some(5), Some(3));
        let (ratio, status) = super::replica_readiness_display(&doc);
        assert_eq!(ratio, "5/3");
        assert_eq!(status, "NotReady");
    }

    #[test]
    fn replica_readiness_display_treats_missing_ready_replicas_as_zero() {
        // Pre-lift the three consumer sites all spelled `.get
        // ("readyReplicas").and_then(|r| r.as_i64()).unwrap_or(0)`
        // verbatim — a missing `/status/readyReplicas` field
        // (kubectl's Deployment status shape omits `readyReplicas`
        // when it's zero) collapsed to 0 rather than a type error.
        // This shield pins that same lenient-typing discipline at
        // the primitive: a Deployment document with a `/status`
        // object that does NOT carry `readyReplicas` at all still
        // reports `0/N` with `NotReady` (when N > 0), matching the
        // pre-lift consumers byte-for-byte.
        let doc = make_workload_doc(None, Some(2));
        let (ratio, status) = super::replica_readiness_display(&doc);
        assert_eq!(ratio, "0/2");
        assert_eq!(status, "NotReady");
    }

    #[test]
    fn replica_readiness_display_treats_missing_spec_replicas_as_zero() {
        // Symmetric to the missing-readyReplicas shield above: a
        // workload document whose `/spec/replicas` field is absent
        // (a Deployment created without an explicit `replicas` field,
        // relying on the API-server default of 1 but whose
        // pre-defaulting document is being read from an admission
        // hook) collapses to 0 at the primitive rather than a type
        // error. Preserves the pre-lift `.pointer("/spec/replicas").
        // and_then(|r| r.as_i64()).unwrap_or(0)` discipline.
        let doc = make_workload_doc(Some(3), None);
        let (ratio, status) = super::replica_readiness_display(&doc);
        assert_eq!(ratio, "3/0");
        assert_eq!(status, "NotReady");
    }

    #[test]
    fn replica_readiness_display_treats_both_missing_as_zero_ready() {
        // Both fields absent — the fresh-object-just-after-create
        // window where the API server has accepted the manifest but
        // the controller has not yet populated `/status` and the
        // manifest itself did not set `/spec/replicas`. Pre-lift
        // consumers surfaced `"0/0"` with `"Ready"` (per the strict
        // equality) in this window; the primitive preserves that.
        // Load-bearing: a future regression that special-cased the
        // both-zero shape to `"Unknown"` would break the status-line
        // grep at every downstream text-render consumer that expects
        // exactly `"Ready"` or `"NotReady"`.
        let doc = make_workload_doc(None, None);
        let (ratio, status) = super::replica_readiness_display(&doc);
        assert_eq!(ratio, "0/0");
        assert_eq!(status, "Ready");
    }

    #[test]
    fn replica_readiness_display_ignores_non_integer_field_types() {
        // Pre-lift the three consumers guarded the extraction with
        // `.and_then(|r| r.as_i64())` — a well-formed JSON with a
        // non-integer value at `/status/readyReplicas` or
        // `/spec/replicas` (a string, a float, a null) collapsed to
        // 0 rather than propagating a type error. The primitive
        // preserves that lenient-typing discipline: a manifest that
        // spelled `replicas: "3"` (string) or `readyReplicas: null`
        // yields `0/0` rather than an error the fetch site cannot
        // recover from.
        let doc = serde_json::json!({
            "spec": { "replicas": "3" },
            "status": { "readyReplicas": null },
        });
        let (ratio, status) = super::replica_readiness_display(&doc);
        assert_eq!(ratio, "0/0");
        assert_eq!(status, "Ready");
    }

    /// Regression shield: `replica_readiness_display` is the ONLY
    /// consumer of the pre-lift `if ready == desired { "Ready".
    /// to_string() } else { "NotReady".to_string() }` conditional in
    /// `commands/status.rs`. Pre-lift the three simple `fetch_*`
    /// consumer sites (`fetch_statefulset`, `fetch_redis`,
    /// `fetch_redis_statefulset`) each spelled the verbatim `if ready
    /// == desired { "Ready".to_string() } else { "NotReady".to_string()
    /// }` conditional alongside the `format!("{}/{}", ready, desired)`
    /// ratio-string. A future regression that re-fused the pre-lift
    /// conditional at one of the three sites (or at a new fourth
    /// consumer of the same shape) would silently split the
    /// `"Ready"`/`"NotReady"` discipline across the primitive and the
    /// re-fused site, re-introducing the "seven-line stanza per site"
    /// duplication this lift redeems.
    ///
    /// The shield pins the discipline at ONE call site — the
    /// primitive itself — by asserting the `if ready == desired {`
    /// needle appears at exactly ONE code line in the module's
    /// non-test body. The one legitimate hit is the primitive's own
    /// body; a second hit fails this shield.
    ///
    /// The scan is bounded strictly to the module's non-test body via
    /// the `\n#[cfg(test)]\nmod tests {` marker (same slice boundary
    /// the sibling `kubectl_get_items_is_only_json_items_parse_at_the_fetch_helper_bail_surface`
    /// and `kubectl_get_item_is_only_bail_not_found_parse_stanza_at_the_single_item_fetch_helper_surface`
    /// shields use) so this shield's own docstring mention of `if
    /// ready == desired {` stays out of scope. And routes through
    /// [`crate::test_support::code_line_hits`] so `///`-prefixed
    /// doc-comment mentions in the module body's fn docs — the
    /// primitive's own docstring references the `ready == desired`
    /// discipline in prose — do not self-match as phantom hits, the
    /// same code-line-filter discipline the sibling `code_line_hits`
    /// consumers established at prior claude-routine commits
    /// (ab06395 / a7d5375 / fa2c702 / fd02aa6 / cc81215 / 3e26bbc /
    /// 4163c7e / ffa5271 / 8eed602 / f6b4229 / 59c3391 / 695a8cc).
    #[test]
    fn replica_readiness_display_is_only_ready_equals_desired_conditional_at_fetch_helpers() {
        let source = include_str!("status.rs");
        let tests_marker = "\n#[cfg(test)]\nmod tests {";
        let body_end = source.find(tests_marker).expect(
            "the `#[cfg(test)]\\nmod tests {` marker must follow \
             the module body — the shield's slice boundary relies \
             on this module ordering",
        );
        let module_body = &source[..body_end];

        let hits = crate::test_support::code_line_hits(module_body, "if ready == desired {");
        assert_eq!(
            hits.len(),
            1,
            "status.rs must route every fetch helper's `if ready == \
             desired {{ \"Ready\".to_string() }} else {{ \"NotReady\"\
             .to_string() }}` conditional through \
             `replica_readiness_display(&doc)` so a future regression \
             that re-fuses the pre-lift conditional at any of the \
             three `fetch_*` consumer sites (or at a new fourth \
             consumer of the same shape) fails here rather than \
             silently splitting the `\"Ready\"`/`\"NotReady\"` \
             discipline across the primitive and the re-fused site. \
             Expected exactly one hit (the primitive body itself). \
             Found: {hits:?}"
        );
    }

    #[test]
    fn replica_count_returns_i64_on_present_integer_field() {
        // The golden path every pre-lift consumer exercised: kubectl
        // populates `/status/readyReplicas` (and the four other
        // replica-count slots at `fetch_deployment`) with an integer,
        // and the extraction yields that integer verbatim. Pinned as a
        // discrete shield so a regression that widened the primitive
        // to (say) return `Option<i64>` and forgot to `.unwrap_or(0)`
        // at the site fails here rather than surfacing as an
        // `unwrap_or(0)` at the caller.
        let doc = serde_json::json!({
            "spec": { "replicas": 3 },
            "status": { "readyReplicas": 2 },
        });
        assert_eq!(super::replica_count(&doc, "/spec/replicas"), 3);
        assert_eq!(super::replica_count(&doc, "/status/readyReplicas"), 2);
    }

    #[test]
    fn replica_count_treats_missing_leaf_field_as_zero() {
        // Pre-lift the two display-pair sites and the five
        // `fetch_deployment` sites all spelled `.and_then(|r| r.
        // as_i64()).unwrap_or(0)` verbatim — a missing leaf field
        // (kubectl's Deployment status shape omits `readyReplicas`
        // when its value is zero, and analogously for the other
        // conditional replica counters) MUST collapse to `0` rather
        // than propagating a type error the fetch site cannot
        // recover from. Pins the primitive owns that discipline at
        // ONE body across all seven pre-lift consumer sites.
        let doc = serde_json::json!({
            "spec": { "replicas": 3 },
            "status": {},
        });
        assert_eq!(super::replica_count(&doc, "/status/readyReplicas"), 0);
        assert_eq!(super::replica_count(&doc, "/status/availableReplicas"), 0);
    }

    #[test]
    fn replica_count_treats_missing_intermediate_object_as_zero() {
        // The fresh-object-just-after-create window the sibling
        // `replica_readiness_display_treats_both_missing_as_zero_ready`
        // shield pins for the display-pair primitive, re-asserted at
        // the underlying reader: a Deployment document whose
        // controller has not yet populated `/status` at all (the
        // intermediate object is absent, not just the leaf) still
        // yields `0` at the reader. Load-bearing: `.pointer("/status/
        // readyReplicas")` returns `None` when `/status` is absent
        // *or* when `/status` is present but `readyReplicas` is not,
        // and both routes MUST collapse to `0` through the same
        // `.unwrap_or(0)` arm at the primitive rather than diverging.
        let doc = serde_json::json!({ "spec": { "replicas": 3 } });
        assert_eq!(super::replica_count(&doc, "/status/readyReplicas"), 0);
        assert_eq!(super::replica_count(&doc, "/status/availableReplicas"), 0);
        assert_eq!(super::replica_count(&doc, "/status/updatedReplicas"), 0);
        assert_eq!(super::replica_count(&doc, "/status/unavailableReplicas"), 0);
    }

    #[test]
    fn replica_count_treats_wrong_typed_leaf_as_zero() {
        // Pre-lift the seven consumer sites all guarded the
        // extraction with `.and_then(|r| r.as_i64())` — a
        // well-formed JSON with a non-integer value at the pointer
        // (a string, a float, a null, a bool) MUST collapse to `0`
        // rather than propagating a type error. Preserves the
        // lenient-typing discipline verbatim: a manifest that
        // spelled `replicas: "3"` (string) or `readyReplicas: null`
        // yields `0` at the primitive, mirroring the shield the
        // sibling `replica_readiness_display_ignores_non_integer_field_types`
        // pins for the display-pair caller.
        let doc = serde_json::json!({
            "spec": { "replicas": "3" },
            "status": {
                "readyReplicas": null,
                "availableReplicas": 1.5,
                "updatedReplicas": true,
            },
        });
        assert_eq!(super::replica_count(&doc, "/spec/replicas"), 0);
        assert_eq!(super::replica_count(&doc, "/status/readyReplicas"), 0);
        assert_eq!(super::replica_count(&doc, "/status/availableReplicas"), 0);
        assert_eq!(super::replica_count(&doc, "/status/updatedReplicas"), 0);
    }

    /// Regression shield: `replica_count` is the ONLY consumer of the
    /// pre-lift `.pointer("/…").and_then(|r| r.as_i64()).unwrap_or(0)`
    /// stanza in `commands/status.rs`. Pre-lift the two
    /// `replica_readiness_display` slots spelled the pointer-based
    /// shape directly (`.pointer("/status/readyReplicas") \n .and_then
    /// (|r| r.as_i64()) \n .unwrap_or(0)`), and the five
    /// `fetch_deployment` slots spelled the semantically-equivalent
    /// two-step `deployment.get("status").unwrap_or(&Null).get(
    /// "readyReplicas").and_then(|r| r.as_i64()).unwrap_or(0)` shape.
    /// Both shapes reduce to the same lenient-typed i64 read; the
    /// post-lift primitive owns the canonical pointer-based spelling
    /// so any future consumer of a replica-count field lands on the
    /// same shape. Seven consumer sites past THEORY.md §VI.1's
    /// three-times threshold. A future regression that re-fused the
    /// pre-lift stanza at one of the seven sites (or at a new eighth
    /// replica-count consumer of the same shape) would silently split
    /// the lenient-typing discipline across the primitive and the
    /// re-fused site, re-introducing the "extract an i64 replica
    /// count per site" duplication this lift redeems.
    ///
    /// The shield pins the discipline at ONE code line — the
    /// primitive body itself — by asserting the compound needle
    /// `.and_then(|r| r.as_i64()).unwrap_or(0)` appears at exactly
    /// ONE code line in the module's non-test body, further filtered
    /// to lines that also spell `.pointer(` on the same code line
    /// (the primitive's `doc.pointer(ptr).and_then(...)` shape). The
    /// tightening excludes the orthogonal container-status
    /// restart-count extraction at `fetch_pods` (`cs.get(
    /// "restartCount").and_then(|r| r.as_i64()).unwrap_or(0)`) whose
    /// `.get("restartCount")`-based two-step extraction against a
    /// container-status object is a distinct shape from this
    /// primitive's pointer-based extraction against a workload
    /// document. The scan is bounded strictly to the module's
    /// non-test body via the `\n#[cfg(test)]\nmod tests {` marker
    /// (same slice boundary the sibling
    /// `replica_readiness_display_is_only_ready_equals_desired_conditional_at_fetch_helpers`
    /// and `kubectl_get_items_is_only_json_items_parse_at_the_fetch_helper_bail_surface`
    /// shields use) so this shield's own docstring mention of the
    /// needle stays out of scope. And routes through
    /// [`crate::test_support::code_line_hits`] so `///`-prefixed
    /// doc-comment mentions in the module body's fn docs — the
    /// primitive's own docstring references the `.and_then(|r| r.
    /// as_i64()).unwrap_or(0)` shape in prose — do not self-match as
    /// phantom hits, the same code-line-filter discipline the sibling
    /// `code_line_hits` consumers established at prior claude-routine
    /// commits (ab06395 / a7d5375 / fa2c702 / fd02aa6 / cc81215 /
    /// 3e26bbc / 4163c7e / ffa5271 / 8eed602 / f6b4229 / 59c3391 /
    /// 695a8cc / cd1cb10).
    #[test]
    fn replica_count_is_only_pointer_as_i64_unwrap_or_zero_at_the_replica_reader_surface() {
        let source = include_str!("status.rs");
        let tests_marker = "\n#[cfg(test)]\nmod tests {";
        let body_end = source.find(tests_marker).expect(
            "the `#[cfg(test)]\\nmod tests {` marker must follow \
             the module body — the shield's slice boundary relies \
             on this module ordering",
        );
        let module_body = &source[..body_end];

        let tail_hits = crate::test_support::code_line_hits(
            module_body,
            ".and_then(|r| r.as_i64()).unwrap_or(0)",
        );
        let compound_hits: Vec<String> = tail_hits
            .into_iter()
            .filter(|l| l.contains(".pointer("))
            .collect();
        assert_eq!(
            compound_hits.len(),
            1,
            "status.rs must route every replica-count extraction \
             through `replica_count(&doc, \"/…\")` so a future \
             regression that re-fuses the pre-lift `.pointer(\"/…\")\
             .and_then(|r| r.as_i64()).unwrap_or(0)` stanza at any \
             of the seven pre-lift consumer sites (two in \
             `replica_readiness_display`, five in `fetch_deployment`) \
             or at a new eighth replica-count consumer of the same \
             shape fails here rather than silently splitting the \
             lenient-typing discipline across the primitive and the \
             re-fused site. Expected exactly one hit (the primitive \
             body itself). Found: {compound_hits:?}"
        );
    }

    /// Regression shield: `kubectl_get_object` is the ONLY consumer of
    /// the pre-lift seven-argument vector shape
    /// `.args(["get", "<kind>", <name>, "-n", namespace, "-o", "json"])`
    /// in `commands/status.rs`. Pre-lift the five single-object
    /// `fetch_*` consumer sites (`fetch_deployment`, `fetch_statefulset`,
    /// `fetch_redis`, `fetch_redis_statefulset`, `fetch_configmap`) each
    /// spelled the verbatim seven-argument vector against
    /// `kubectl_command_async()` immediately followed by
    /// `.output().await` (four sites bare-`?`; `fetch_deployment` with
    /// `.context("Failed to execute kubectl")`). A future regression
    /// that re-fused any of the five pre-lift argument vectors at the
    /// fetch site would silently split the invocation-layer discipline
    /// across the primitive and the re-fused site and re-introduce the
    /// "seven-line arg-vector per site" duplication this lift redeems.
    ///
    /// The shield pins the discipline at ONE call site — the primitive
    /// itself — by asserting each of the five pre-lift caller-specific
    /// argument-vector spellings appears at exactly ZERO code lines in
    /// the module's non-test body. The primitive's own body spells the
    /// canonical shape with `kind`/`name`/`namespace` identifier
    /// placeholders (no literal `"deployment"`/`"statefulset"`/
    /// `"configmap"` triple-quote form) so does not self-match any of
    /// the five pre-lift needles.
    ///
    /// The scan is bounded strictly to the module's non-test body via
    /// the `\n#[cfg(test)]\nmod tests {` marker (same slice boundary
    /// the sibling
    /// `kubectl_get_item_is_only_bail_not_found_parse_stanza_at_the_single_item_fetch_helper_surface`
    /// and `kubectl_get_items_is_only_json_items_parse_at_the_fetch_helper_bail_surface`
    /// shields use) so this shield's own docstring mentions of the
    /// pre-lift needles stay out of scope. And routes through
    /// [`crate::test_support::code_line_hits`] so `///`-prefixed
    /// doc-comment mentions in the module body's fn docs — the
    /// primitive's own docstring references the pre-lift shapes in
    /// prose — do not self-match as phantom hits, the same
    /// code-line-filter discipline the sibling `code_line_hits`
    /// consumers established at prior claude-routine commits
    /// (ab06395 / a7d5375 / fa2c702 / fd02aa6 / cc81215 / 3e26bbc /
    /// 4163c7e / ffa5271 / 8eed602 / f6b4229 / 59c3391 / 695a8cc /
    /// cd1cb10 / 89e3231).
    #[test]
    fn kubectl_get_object_is_only_seven_arg_get_vector_at_the_single_object_fetch_helper_surface() {
        let source = include_str!("status.rs");
        let tests_marker = "\n#[cfg(test)]\nmod tests {";
        let body_end = source.find(tests_marker).expect(
            "the `#[cfg(test)]\\nmod tests {` marker must follow \
             the module body — the shield's slice boundary relies \
             on this module ordering",
        );
        let module_body = &source[..body_end];

        for pre_lift in [
            r#".args(["get", "deployment", deployment_name, "-n", namespace, "-o", "json"])"#,
            r#".args(["get", "deployment", name, "-n", namespace, "-o", "json"])"#,
            r#".args(["get", "statefulset", name, "-n", namespace, "-o", "json"])"#,
            r#".args(["get", "configmap", name, "-n", namespace, "-o", "json"])"#,
        ] {
            let hits = crate::test_support::code_line_hits(module_body, pre_lift);
            assert!(
                hits.is_empty(),
                "status.rs must route every single-object fetch helper's \
                 `kubectl_command_async().args([\"get\", <kind>, <name>, \
                 \"-n\", namespace, \"-o\", \"json\"]).output().await` \
                 seven-argument spawn through \
                 `kubectl_get_object(<kind>, <name>, namespace).await?` \
                 so a future regression that re-fuses the pre-lift \
                 argument vector at any of the five `fetch_*` consumer \
                 sites (or at a new sixth single-object fetch helper) \
                 fails here rather than silently splitting the \
                 invocation-layer discipline across the primitive and \
                 the re-fused site. Pre-lift needle {pre_lift:?} must \
                 not reappear; found: {hits:?}"
            );
        }
    }

    /// Regression shield: the seven-argument `["get", <kind>, <name>,
    /// "-n", <namespace>, "-o", "json"]` vector with identifier
    /// placeholders in the `<kind>` and `<name>` slots — the canonical
    /// shape [`kubectl_get_object`] owns — MUST live at exactly ONE
    /// code line in the module's non-test body: the primitive's own
    /// `.args(...)` chain. A future consumer that re-fuses the
    /// identifier-placeholder shape (`.args(["get", k, n, "-n", ns,
    /// "-o", "json"])` with any variable-triple in slots 2 and 3)
    /// fails here rather than silently colonizing the invocation
    /// surface with a second copy of the primitive's spelling.
    ///
    /// Complements the sibling
    /// `kubectl_get_object_is_only_seven_arg_get_vector_at_the_single_object_fetch_helper_surface`
    /// shield above: that shield forbids the four pre-lift
    /// literal-`kind` spellings at the caller; this shield pins the
    /// identifier-placeholder spelling to exactly ONE site.
    #[test]
    fn kubectl_get_object_owns_the_seven_arg_vector_at_exactly_one_line() {
        let source = include_str!("status.rs");
        let tests_marker = "\n#[cfg(test)]\nmod tests {";
        let body_end = source.find(tests_marker).expect(
            "the `#[cfg(test)]\\nmod tests {` marker must follow \
             the module body — the shield's slice boundary relies \
             on this module ordering",
        );
        let module_body = &source[..body_end];

        let hits = crate::test_support::code_line_hits(
            module_body,
            r#".args(["get", kind, name, "-n", namespace, "-o", "json"])"#,
        );
        assert_eq!(
            hits.len(),
            1,
            "status.rs must own the seven-argument single-object `kubectl \
             get` vector at exactly ONE code line — the \
             `kubectl_get_object` primitive body. Expected exactly one \
             hit; found: {hits:?}"
        );
    }
}
