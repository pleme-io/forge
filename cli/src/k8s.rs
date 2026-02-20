use anyhow::{Context, Result};
use k8s_openapi::api::apps::v1::{Deployment, StatefulSet};
use k8s_openapi::api::core::v1::{Event, Pod};
use k8s_openapi::chrono::{DateTime, Utc};
use kube::{
    api::{Api, ListParams},
    Client, Config,
};
use tracing::debug;

#[derive(Debug, Clone)]
pub struct ContainerStateInfo {
    pub state: String, // "running", "waiting", "terminated"
    pub reason: Option<String>,
    pub message: Option<String>,
    pub restart_count: i32,
    pub started: bool,
}

#[derive(Debug, Clone)]
pub struct PodStatus {
    pub name: String,
    pub phase: String,
    pub ready: bool,
    pub image_tag: String,
    pub container_state: Option<ContainerStateInfo>,
    pub creation_time: Option<DateTime<Utc>>,
}

/// Create Kubernetes client
pub async fn create_client() -> Result<Client> {
    let config = Config::infer()
        .await
        .context("Failed to infer kubeconfig")?;

    Client::try_from(config).context("Failed to create Kubernetes client")
}

/// Get replica count from Deployment or StatefulSet (auto-detects resource type)
pub async fn get_replicas(client: &Client, namespace: &str, name: &str) -> Result<i32> {
    // Try Deployment first
    let deployments: Api<Deployment> = Api::namespaced(client.clone(), namespace);
    if let Ok(deployment) = deployments.get(name).await {
        debug!("Found Deployment: {}", name);
        return Ok(deployment.spec.and_then(|s| s.replicas).unwrap_or(1));
    }

    // Try StatefulSet
    let statefulsets: Api<StatefulSet> = Api::namespaced(client.clone(), namespace);
    if let Ok(sts) = statefulsets.get(name).await {
        debug!("Found StatefulSet: {}", name);
        return Ok(sts.spec.and_then(|s| s.replicas).unwrap_or(0));
    }

    anyhow::bail!(
        "Could not find Deployment or StatefulSet named '{}' in namespace '{}'",
        name,
        namespace
    )
}

/// Get expected image tag from Deployment or StatefulSet (auto-detects resource type)
pub async fn get_expected_image_tag(
    client: &Client,
    namespace: &str,
    name: &str,
) -> Result<String> {
    // Try Deployment first
    let deployments: Api<Deployment> = Api::namespaced(client.clone(), namespace);
    if let Ok(deployment) = deployments.get(name).await {
        debug!("Found Deployment: {}", name);

        // Get image from first container (regardless of name)
        let image = deployment
            .spec
            .and_then(|spec| spec.template.spec)
            .and_then(|pod_spec| pod_spec.containers.first().and_then(|c| c.image.clone()))
            .ok_or_else(|| anyhow::anyhow!("Could not find container image in Deployment spec"))?;

        // Extract tag from image (format: registry/image:tag)
        let tag = image
            .split(':')
            .last()
            .ok_or_else(|| anyhow::anyhow!("Invalid image format: {}", image))?
            .to_string();

        return Ok(tag);
    }

    // Try StatefulSet
    let statefulsets: Api<StatefulSet> = Api::namespaced(client.clone(), namespace);
    if let Ok(sts) = statefulsets.get(name).await {
        debug!("Found StatefulSet: {}", name);

        // Get image from first container (regardless of name)
        let image = sts
            .spec
            .and_then(|spec| spec.template.spec)
            .and_then(|pod_spec| pod_spec.containers.first().and_then(|c| c.image.clone()))
            .ok_or_else(|| anyhow::anyhow!("Could not find container image in StatefulSet spec"))?;

        // Extract tag from image (format: registry/image:tag)
        let tag = image
            .split(':')
            .last()
            .ok_or_else(|| anyhow::anyhow!("Invalid image format: {}", image))?
            .to_string();

        return Ok(tag);
    }

    anyhow::bail!(
        "Could not find Deployment or StatefulSet named '{}' in namespace '{}'",
        name,
        namespace
    )
}

/// Get pod statuses with label selector
pub async fn get_pod_statuses(
    client: &Client,
    namespace: &str,
    label_selector: &str,
) -> Result<Vec<PodStatus>> {
    let pods: Api<Pod> = Api::namespaced(client.clone(), namespace);

    let lp = ListParams::default().labels(label_selector);

    let pod_list = pods.list(&lp).await.context("Failed to list pods")?;

    let mut statuses = Vec::new();

    for pod in pod_list {
        let name = pod.metadata.name.unwrap_or_else(|| "unknown".to_string());

        let phase = pod
            .status
            .as_ref()
            .and_then(|s| s.phase.clone())
            .unwrap_or_else(|| "Unknown".to_string());

        let creation_time = pod.metadata.creation_timestamp.as_ref().map(|t| t.0);

        let container_statuses = pod
            .status
            .as_ref()
            .and_then(|s| s.container_statuses.as_ref());

        let ready = container_statuses
            .and_then(|cs| cs.first())
            .map(|c| c.ready)
            .unwrap_or(false);

        let image = pod
            .spec
            .as_ref()
            .and_then(|s| s.containers.first())
            .and_then(|c| c.image.as_ref())
            .unwrap_or(&"unknown".to_string())
            .clone();

        // Extract tag from image
        let image_tag = image.split(':').last().unwrap_or("unknown").to_string();

        // Extract detailed container state
        let container_state = container_statuses.and_then(|cs| cs.first()).map(|c| {
            let restart_count = c.restart_count;
            let started = c.started.unwrap_or(false);

            // Check state
            if let Some(waiting) = &c.state.as_ref().and_then(|s| s.waiting.as_ref()) {
                ContainerStateInfo {
                    state: "waiting".to_string(),
                    reason: waiting.reason.clone(),
                    message: waiting.message.clone(),
                    restart_count,
                    started,
                }
            } else if let Some(running) = &c.state.as_ref().and_then(|s| s.running.as_ref()) {
                ContainerStateInfo {
                    state: "running".to_string(),
                    reason: None,
                    message: Some(format!(
                        "Started at {}",
                        running
                            .started_at
                            .as_ref()
                            .map(|t| t.0.to_rfc3339())
                            .unwrap_or_default()
                    )),
                    restart_count,
                    started,
                }
            } else if let Some(terminated) = &c.state.as_ref().and_then(|s| s.terminated.as_ref()) {
                ContainerStateInfo {
                    state: "terminated".to_string(),
                    reason: terminated.reason.clone(),
                    message: terminated.message.clone(),
                    restart_count,
                    started,
                }
            } else {
                ContainerStateInfo {
                    state: "unknown".to_string(),
                    reason: None,
                    message: None,
                    restart_count,
                    started,
                }
            }
        });

        statuses.push(PodStatus {
            name,
            phase,
            ready,
            image_tag,
            container_state,
            creation_time,
        });
    }

    // Sort by name
    statuses.sort_by(|a, b| a.name.cmp(&b.name));

    Ok(statuses)
}

/// Check if a pod is in a bad state
pub fn is_bad_state(pod: &PodStatus) -> bool {
    if let Some(state) = &pod.container_state {
        if let Some(reason) = &state.reason {
            matches!(
                reason.as_str(),
                "CrashLoopBackOff"
                    | "ImagePullBackOff"
                    | "ErrImagePull"
                    | "CreateContainerConfigError"
                    | "InvalidImageName"
                    | "CreateContainerError"
                    | "RunContainerError"
            )
        } else {
            false
        }
    } else {
        false
    }
}

/// Get pod logs (last N lines)
pub async fn get_pod_logs(
    client: &Client,
    namespace: &str,
    pod_name: &str,
    lines: i64,
) -> Result<String> {
    use kube::api::LogParams;

    let pods: Api<Pod> = Api::namespaced(client.clone(), namespace);

    let log_params = LogParams {
        tail_lines: Some(lines),
        ..Default::default()
    };

    let logs = pods
        .logs(pod_name, &log_params)
        .await
        .context(format!("Failed to get logs for pod {}", pod_name))?;

    Ok(logs)
}

/// Get events for a specific pod
pub async fn get_pod_events(
    client: &Client,
    namespace: &str,
    pod_name: &str,
) -> Result<Vec<String>> {
    let events: Api<Event> = Api::namespaced(client.clone(), namespace);

    let lp = ListParams::default().fields(&format!("involvedObject.name={}", pod_name));

    let event_list = events
        .list(&lp)
        .await
        .context(format!("Failed to get events for pod {}", pod_name))?;

    let mut event_messages = Vec::new();

    for event in event_list {
        if let (Some(reason), Some(message), Some(last_timestamp)) = (
            event.reason,
            event.message,
            event.last_timestamp.or(event.first_timestamp),
        ) {
            event_messages.push(format!(
                "[{}] {}: {}",
                last_timestamp.0.format("%H:%M:%S"),
                reason,
                message
            ));
        }
    }

    // Sort by timestamp (already in the string)
    event_messages.sort();

    Ok(event_messages)
}
