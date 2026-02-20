//! Status command for showing deployed version/image/tag
//!
//! Shows comprehensive deployment information by querying Kubernetes.

use anyhow::{Context, Result};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tokio::process::Command;
use tracing::debug;

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
    let deploy_yaml_path = if let Some(product_dir) = find_product_dir_from_service(&service_dir_path) {
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
    let (deployment, pods_json, related, migrations, events) = tokio::join!(
        fetch_deployment(namespace, deployment_name),
        fetch_pods_json(namespace, deployment_name),
        fetch_related_services(namespace, deployment_name),
        fetch_migrations(namespace, deployment_name),
        fetch_events(namespace, deployment_name),
    );

    let deployment_info = deployment?;
    let pods_json = pods_json?;
    let (pods, containers) = extract_pod_and_container_info(&pods_json, deployment_name);

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
    let output = Command::new("kubectl")
        .args([
            "get",
            "deployment",
            deployment_name,
            "-n",
            namespace,
            "-o",
            "json",
        ])
        .output()
        .await
        .context("Failed to execute kubectl")?;

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

    let status = deployment.get("status").unwrap_or(&serde_json::Value::Null);

    Ok(DeploymentInfo {
        name: deployment_name.to_string(),
        image,
        tag,
        replicas: ReplicaStatus {
            desired: deployment
                .pointer("/spec/replicas")
                .and_then(|r| r.as_i64())
                .unwrap_or(0) as i32,
            ready: status
                .get("readyReplicas")
                .and_then(|r| r.as_i64())
                .unwrap_or(0) as i32,
            available: status
                .get("availableReplicas")
                .and_then(|r| r.as_i64())
                .unwrap_or(0) as i32,
            updated: status
                .get("updatedReplicas")
                .and_then(|r| r.as_i64())
                .unwrap_or(0) as i32,
            unavailable: status
                .get("unavailableReplicas")
                .and_then(|r| r.as_i64())
                .unwrap_or(0) as i32,
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
        last_updated: status
            .get("conditions")
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
                if let Some((image, tag)) = image_str.rsplit_once(':') {
                    return (Some(image.to_string()), Some(tag.to_string()));
                }
                return (Some(image_str.to_string()), None);
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

async fn fetch_pods_json(namespace: &str, deployment_name: &str) -> Result<serde_json::Value> {
    let output = Command::new("kubectl")
        .args([
            "get",
            "pods",
            "-n",
            namespace,
            "-l",
            &format!("app={}", deployment_name),
            "-o",
            "json",
        ])
        .output()
        .await?;

    if !output.status.success() {
        return Ok(serde_json::json!({"items": []}));
    }

    Ok(serde_json::from_slice(&output.stdout).unwrap_or(serde_json::json!({"items": []})))
}

fn extract_pod_and_container_info(
    pods_json: &serde_json::Value,
    deployment_name: &str,
) -> (Vec<PodInfo>, Vec<ContainerInfo>) {
    let mut pods = Vec::new();
    let mut containers = Vec::new();

    if let Some(items) = pods_json.get("items").and_then(|i| i.as_array()) {
        for pod in items {
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
                    let (image, tag) = image_full
                        .rsplit_once(':')
                        .map(|(i, t)| (i.to_string(), t.to_string()))
                        .unwrap_or((image_full.to_string(), "latest".to_string()));

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
                        restarts: cs.get("restartCount").and_then(|r| r.as_i64()).unwrap_or(0)
                            as i32,
                        state,
                        is_sidecar,
                    });
                }
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
    let output = Command::new("kubectl")
        .args(["get", "statefulset", name, "-n", namespace, "-o", "json"])
        .output()
        .await?;

    if !output.status.success() {
        anyhow::bail!("StatefulSet not found");
    }

    let sts: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    let status = sts.get("status").unwrap_or(&serde_json::Value::Null);

    let ready = status
        .get("readyReplicas")
        .and_then(|r| r.as_i64())
        .unwrap_or(0);
    let desired = sts
        .pointer("/spec/replicas")
        .and_then(|r| r.as_i64())
        .unwrap_or(0);

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
        ready: format!("{}/{}", ready, desired),
        image,
        storage,
        status: if ready == desired {
            "Ready".to_string()
        } else {
            "NotReady".to_string()
        },
    })
}

async fn fetch_redis(namespace: &str, name: &str) -> Result<ResourceInfo> {
    let output = Command::new("kubectl")
        .args(["get", "deployment", name, "-n", namespace, "-o", "json"])
        .output()
        .await?;

    if !output.status.success() {
        anyhow::bail!("Redis deployment not found");
    }

    let dep: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    let status = dep.get("status").unwrap_or(&serde_json::Value::Null);

    let ready = status
        .get("readyReplicas")
        .and_then(|r| r.as_i64())
        .unwrap_or(0);
    let desired = dep
        .pointer("/spec/replicas")
        .and_then(|r| r.as_i64())
        .unwrap_or(0);

    Ok(ResourceInfo {
        name: name.to_string(),
        status: if ready == desired {
            "Ready".to_string()
        } else {
            "NotReady".to_string()
        },
        ready: format!("{}/{}", ready, desired),
        image: dep
            .pointer("/spec/template/spec/containers/0/image")
            .and_then(|i| i.as_str())
            .map(String::from),
    })
}

async fn fetch_redis_statefulset(namespace: &str, name: &str) -> Result<ResourceInfo> {
    let output = Command::new("kubectl")
        .args(["get", "statefulset", name, "-n", namespace, "-o", "json"])
        .output()
        .await?;

    if !output.status.success() {
        anyhow::bail!("Redis statefulset not found");
    }

    let sts: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    let status = sts.get("status").unwrap_or(&serde_json::Value::Null);

    let ready = status
        .get("readyReplicas")
        .and_then(|r| r.as_i64())
        .unwrap_or(0);
    let desired = sts
        .pointer("/spec/replicas")
        .and_then(|r| r.as_i64())
        .unwrap_or(0);

    Ok(ResourceInfo {
        name: name.to_string(),
        status: if ready == desired {
            "Ready".to_string()
        } else {
            "NotReady".to_string()
        },
        ready: format!("{}/{}", ready, desired),
        image: sts
            .pointer("/spec/template/spec/containers/0/image")
            .and_then(|i| i.as_str())
            .map(String::from),
    })
}

async fn fetch_configmap(namespace: &str, name: &str) -> Result<ConfigMapInfo> {
    let output = Command::new("kubectl")
        .args(["get", "configmap", name, "-n", namespace, "-o", "json"])
        .output()
        .await?;

    if !output.status.success() {
        anyhow::bail!("ConfigMap not found");
    }

    let cm: serde_json::Value = serde_json::from_slice(&output.stdout)?;
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

async fn fetch_secrets(namespace: &str, deployment_name: &str) -> Result<Vec<String>> {
    let output = Command::new("kubectl")
        .args(["get", "secrets", "-n", namespace, "-o", "json"])
        .output()
        .await?;

    if !output.status.success() {
        return Ok(vec![]);
    }

    let secrets: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    let empty_vec = vec![];
    let items = secrets
        .get("items")
        .and_then(|i| i.as_array())
        .unwrap_or(&empty_vec);

    Ok(items
        .iter()
        .filter_map(|s| s.pointer("/metadata/name").and_then(|n| n.as_str()))
        .filter(|n| n.contains(deployment_name) || n.contains("ghcr"))
        .map(String::from)
        .collect())
}

async fn fetch_k8s_services(namespace: &str, deployment_name: &str) -> Result<Vec<ServiceInfo>> {
    let output = Command::new("kubectl")
        .args([
            "get",
            "services",
            "-n",
            namespace,
            "-l",
            &format!("app={}", deployment_name),
            "-o",
            "json",
        ])
        .output()
        .await?;

    if !output.status.success() {
        return Ok(vec![]);
    }

    let services: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    let empty_vec = vec![];
    let items = services
        .get("items")
        .and_then(|i| i.as_array())
        .unwrap_or(&empty_vec);

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
    let output = Command::new("kubectl")
        .args([
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
        .output()
        .await?;

    if !output.status.success() {
        return Ok(vec![]);
    }

    let jobs: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    let empty_vec = vec![];
    let items = jobs
        .get("items")
        .and_then(|i| i.as_array())
        .unwrap_or(&empty_vec);

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
    let output = Command::new("kubectl")
        .args([
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
        .output()
        .await?;

    if !output.status.success() {
        return Ok(vec![]);
    }

    let events: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    let empty_vec = vec![];
    let items = events
        .get("items")
        .and_then(|i| i.as_array())
        .unwrap_or(&empty_vec);

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
