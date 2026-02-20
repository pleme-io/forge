//! Dashboard Sync - Observability as Code
//!
//! Generates Grafana dashboards from code metadata using:
//! 1. Rust entity scanning (finds #[observe] attributes)
//! 2. Jsonnet templates (generates dashboard JSON)
//! 3. FluxCD CRD output (GrafanaDashboard resources)
//!
//! Usage:
//!   forge dashboards --working-dir /path/to/product
//!   forge dashboards --working-dir /path/to/product --check

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{debug, info, warn};

/// Configuration for dashboard generation
#[derive(Debug, Clone)]
pub struct DashboardConfig {
    /// Path to the product directory
    pub working_dir: PathBuf,
    /// Path to output FluxCD dashboard CRDs (None = not configured, generation skipped)
    pub output_dir: Option<PathBuf>,
    /// Path to Jsonnet templates (None = not configured, uses built-in generation)
    pub templates_dir: Option<PathBuf>,
    /// Whether to only check for drift (no generation)
    pub check_only: bool,
    /// Prometheus metric name prefix (e.g., product name)
    pub metric_prefix: String,
    /// Product name for K8s labels and dashboard naming
    pub product_name: String,
    /// Grafana folder name for dashboards
    pub dashboard_folder: String,
}

/// Metadata extracted from #[observe] attributes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservedEntity {
    /// Entity name (e.g., "dog", "ritual", "booking")
    pub name: String,
    /// Module path where the entity is defined
    pub module_path: String,
    /// Operations observed (e.g., ["create", "update", "delete"])
    pub operations: Vec<String>,
    /// Custom metrics defined for this entity
    pub metrics: Vec<MetricDefinition>,
    /// Span attributes extracted from parameters
    pub span_attributes: Vec<String>,
}

/// Custom metric definition from code
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricDefinition {
    /// Metric name
    pub name: String,
    /// Metric type (counter, histogram, gauge)
    pub metric_type: String,
    /// Description
    pub description: String,
    /// Labels
    pub labels: Vec<String>,
}

/// Result of dashboard generation
#[derive(Debug)]
pub struct DashboardResult {
    /// Number of entities scanned
    pub entities_scanned: usize,
    /// Number of dashboards generated
    pub dashboards_generated: usize,
    /// Dashboards that would be pruned (deleted entities)
    pub dashboards_pruned: Vec<String>,
    /// Any errors encountered
    pub errors: Vec<String>,
}

/// Execute dashboard sync
pub async fn execute(working_dir: &Path, check_only: bool) -> Result<DashboardResult> {
    let product = crate::config::load_product_config_from_dir(working_dir)?;

    info!(
        "Starting dashboard sync for {} (check_only: {})",
        product.name,
        check_only
    );

    let config = DashboardConfig {
        working_dir: working_dir.to_path_buf(),
        output_dir: product.dashboards_output_dir(working_dir),
        templates_dir: product.observability_scripts_dir(working_dir),
        check_only,
        metric_prefix: product.metric_prefix().to_string(),
        product_name: product.name.clone(),
        dashboard_folder: product.dashboard_folder(),
    };

    // Step 1: Scan Rust code for observed entities
    info!("Step 1/4: Scanning Rust code for observed entities...");
    let entities = scan_entities(&config).await?;
    info!("Found {} observed entities", entities.len());

    // Step 2: Generate dashboard metadata JSON for Jsonnet (only if templates dir is configured)
    info!("Step 2/4: Generating dashboard metadata...");
    if let Some(templates_dir) = &config.templates_dir {
        let metadata_path = templates_dir.join("metadata.json");
        generate_metadata(&entities, &metadata_path)?;
    }

    // Step 3: Run Jsonnet to generate dashboards
    info!("Step 3/4: Running Jsonnet templates...");
    let dashboards = run_jsonnet(&config)?;

    // Step 4: Check for pruned dashboards (deleted entities)
    info!("Step 4/4: Checking for stale dashboards...");
    let pruned = check_pruned_dashboards(&config, &entities)?;

    if check_only {
        // In check mode, verify no drift
        if !pruned.is_empty() {
            warn!(
                "Drift detected: {} stale dashboards would be pruned",
                pruned.len()
            );
        }
    } else if config.output_dir.is_some() {
        // Generate actual dashboard files (only if output dir is configured)
        write_dashboards(&config, &dashboards)?;

        // Prune stale dashboards
        if let Some(output_dir) = &config.output_dir {
            for dashboard in &pruned {
                let path = output_dir.join(format!("{}.yaml", dashboard));
                if path.exists() {
                    info!("Pruning stale dashboard: {}", dashboard);
                    fs::remove_file(&path)?;
                }
            }
        }
    } else {
        warn!("No dashboards_output dir configured — skipping file generation. Set dirs.dashboards_output in deploy.yaml");
    }

    Ok(DashboardResult {
        entities_scanned: entities.len(),
        dashboards_generated: dashboards.len(),
        dashboards_pruned: pruned,
        errors: vec![],
    })
}

/// Scan Rust code for #[observe] attributes
async fn scan_entities(config: &DashboardConfig) -> Result<Vec<ObservedEntity>> {
    // Load product config to get configured backend dir
    let product = crate::config::load_product_config_from_dir(&config.working_dir)?;
    let Some(backend_dir) = product.backend_dir(&config.working_dir) else {
        info!("backend dir not configured in deploy.yaml — skipping entity scan");
        return Ok(vec![]);
    };
    let src_dir = backend_dir.join("src");

    if !src_dir.exists() {
        warn!("Backend src directory not found: {:?}", src_dir);
        return Ok(vec![]);
    }

    let mut entities = Vec::new();

    // Scan all Rust files for observe attributes
    for entry in walkdir::WalkDir::new(&src_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map_or(false, |ext| ext == "rs"))
    {
        let content = fs::read_to_string(entry.path())?;
        let file_entities = parse_observed_entities(&content, entry.path())?;
        entities.extend(file_entities);
    }

    // Also scan entity definitions for SeaORM models
    let entities_dir = src_dir.join("entity");
    if entities_dir.exists() {
        for entry in walkdir::WalkDir::new(&entities_dir)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map_or(false, |ext| ext == "rs"))
        {
            let content = fs::read_to_string(entry.path())?;
            let model_entities =
                parse_seaorm_entities(&content, entry.path(), &config.metric_prefix)?;
            entities.extend(model_entities);
        }
    }

    // Deduplicate by name
    let mut seen = std::collections::HashSet::new();
    entities.retain(|e| seen.insert(e.name.clone()));

    Ok(entities)
}

/// Parse #[observe] attributes from Rust source
fn parse_observed_entities(content: &str, path: &Path) -> Result<Vec<ObservedEntity>> {
    let mut entities = Vec::new();
    let module_path = path.to_string_lossy().to_string();

    // Pattern: #[observe(entity = "...", ...)]
    let re = regex::Regex::new(
        r#"#\[observe\s*\(\s*entity\s*=\s*"([^"]+)"(?:\s*,\s*extractIds\s*=\s*\[([^\]]*)\])?\s*\)\]"#,
    )?;

    for cap in re.captures_iter(content) {
        let entity_name = cap
            .get(1)
            .map(|m| m.as_str().to_string())
            .unwrap_or_default();
        let extract_ids: Vec<String> = cap
            .get(2)
            .map(|m| {
                m.as_str()
                    .split(',')
                    .map(|s| s.trim().trim_matches('"').to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default();

        if !entity_name.is_empty() {
            entities.push(ObservedEntity {
                name: entity_name,
                module_path: module_path.clone(),
                operations: vec![
                    "create".into(),
                    "read".into(),
                    "update".into(),
                    "delete".into(),
                ],
                metrics: vec![],
                span_attributes: extract_ids,
            });
        }
    }

    Ok(entities)
}

/// Parse SeaORM entity definitions
fn parse_seaorm_entities(
    content: &str,
    path: &Path,
    metric_prefix: &str,
) -> Result<Vec<ObservedEntity>> {
    let mut entities = Vec::new();
    let module_path = path.to_string_lossy().to_string();

    // Pattern: #[sea_orm(table_name = "...")]
    let re = regex::Regex::new(r#"#\[sea_orm\s*\(\s*table_name\s*=\s*"([^"]+)"\s*\)\]"#)?;

    for cap in re.captures_iter(content) {
        let table_name = cap
            .get(1)
            .map(|m| m.as_str().to_string())
            .unwrap_or_default();

        if !table_name.is_empty() {
            // Convert table_name to entity name (dogs -> dog, user_profiles -> user_profile)
            let entity_name = table_name.trim_end_matches('s').to_string();

            entities.push(ObservedEntity {
                name: entity_name.clone(),
                module_path: module_path.clone(),
                operations: vec![
                    "create".into(),
                    "read".into(),
                    "update".into(),
                    "delete".into(),
                    "list".into(),
                ],
                metrics: vec![
                    MetricDefinition {
                        name: format!("{}_{}_operations_total", metric_prefix, entity_name),
                        metric_type: "counter".into(),
                        description: format!("Total operations on {} entity", entity_name),
                        labels: vec!["operation".into(), "status".into()],
                    },
                    MetricDefinition {
                        name: format!(
                            "{}_{}_operation_duration_seconds",
                            metric_prefix, entity_name
                        ),
                        metric_type: "histogram".into(),
                        description: format!("Duration of {} operations", entity_name),
                        labels: vec!["operation".into()],
                    },
                ],
                span_attributes: vec![format!("{}_id", entity_name)],
            });
        }
    }

    Ok(entities)
}

/// Generate metadata JSON for Jsonnet consumption
fn generate_metadata(entities: &[ObservedEntity], output_path: &Path) -> Result<()> {
    // Ensure parent directory exists
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let metadata = serde_json::json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "version": "1.0.0",
        "entities": entities,
        "dashboard_config": {
            "datasource": "Mimir",
            "logs_datasource": "Loki",
            "traces_datasource": "Tempo",
            "refresh_interval": "30s",
            "time_range": "1h"
        }
    });

    fs::write(output_path, serde_json::to_string_pretty(&metadata)?)?;
    info!("Generated metadata: {:?}", output_path);

    Ok(())
}

/// Run Jsonnet to generate dashboard JSON
fn run_jsonnet(config: &DashboardConfig) -> Result<HashMap<String, serde_json::Value>> {
    let Some(templates_dir) = &config.templates_dir else {
        info!("No observability_scripts dir configured — using built-in dashboard templates");
        return generate_builtin_dashboards(config);
    };

    let main_jsonnet = templates_dir.join("dashboards.jsonnet");

    if !main_jsonnet.exists() {
        info!(
            "Jsonnet templates not found at {:?}, using built-in templates",
            main_jsonnet
        );
        return generate_builtin_dashboards(config);
    }

    // Run jsonnet command
    let output = Command::new("jsonnet")
        .arg("-J")
        .arg(templates_dir.join("vendor"))
        .arg(&main_jsonnet)
        .output()
        .context("Failed to run jsonnet command")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Jsonnet failed: {}", stderr);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let dashboards: HashMap<String, serde_json::Value> = serde_json::from_str(&stdout)?;

    Ok(dashboards)
}

/// Generate built-in dashboards when Jsonnet is not available
fn generate_builtin_dashboards(
    config: &DashboardConfig,
) -> Result<HashMap<String, serde_json::Value>> {
    let metadata: serde_json::Value = if let Some(templates_dir) = &config.templates_dir {
        let metadata_path = templates_dir.join("metadata.json");
        if metadata_path.exists() {
            serde_json::from_str(&fs::read_to_string(&metadata_path)?)?
        } else {
            serde_json::json!({ "entities": [] })
        }
    } else {
        serde_json::json!({ "entities": [] })
    };

    let entities = metadata["entities"].as_array().cloned().unwrap_or_default();

    let mut dashboards = HashMap::new();
    let product_name = &config.product_name;

    // Generate entity operation dashboards
    for entity in &entities {
        let name = entity["name"].as_str().unwrap_or("unknown");
        let dashboard = generate_entity_dashboard(name, entity, config);
        dashboards.insert(format!("{}-entity-{}", product_name, name), dashboard);
    }

    // Generate overview dashboard
    dashboards.insert(
        format!("{}-entity-overview", product_name),
        generate_overview_dashboard(&entities, config),
    );

    Ok(dashboards)
}

/// Generate a dashboard for a specific entity
fn generate_entity_dashboard(
    name: &str,
    entity: &serde_json::Value,
    config: &DashboardConfig,
) -> serde_json::Value {
    let title = format!("{}: {} Operations", config.dashboard_folder, name.to_uppercase());
    let metric_prefix = &config.metric_prefix;
    let product_name = &config.product_name;
    let _metrics = entity["metrics"].as_array().cloned().unwrap_or_default();

    serde_json::json!({
        "annotations": { "list": [] },
        "editable": true,
        "fiscalYearStartMonth": 0,
        "graphTooltip": 0,
        "id": null,
        "links": [],
        "panels": [
            {
                "datasource": { "type": "prometheus", "uid": "mimir" },
                "fieldConfig": {
                    "defaults": { "color": { "mode": "palette-classic" }, "unit": "ops" }
                },
                "gridPos": { "h": 8, "w": 12, "x": 0, "y": 0 },
                "id": 1,
                "options": {},
                "targets": [{
                    "expr": format!("sum(rate({}_{}_operations_total{{}}[5m])) by (operation)", metric_prefix, name),
                    "legendFormat": "{{operation}}"
                }],
                "title": format!("{} Operations Rate", name),
                "type": "timeseries"
            },
            {
                "datasource": { "type": "prometheus", "uid": "mimir" },
                "fieldConfig": {
                    "defaults": { "color": { "mode": "palette-classic" }, "unit": "s" }
                },
                "gridPos": { "h": 8, "w": 12, "x": 12, "y": 0 },
                "id": 2,
                "targets": [{
                    "expr": format!("histogram_quantile(0.95, sum(rate({}_{}_operation_duration_seconds_bucket{{}}[5m])) by (le, operation))", metric_prefix, name),
                    "legendFormat": "p95 {{operation}}"
                }],
                "title": format!("{} Operation Latency (p95)", name),
                "type": "timeseries"
            },
            {
                "datasource": { "type": "prometheus", "uid": "mimir" },
                "fieldConfig": {
                    "defaults": { "color": { "mode": "thresholds" } }
                },
                "gridPos": { "h": 8, "w": 6, "x": 0, "y": 8 },
                "id": 3,
                "targets": [{
                    "expr": format!("sum(increase({}_{}_operations_total{{status=\"error\"}}[1h]))", metric_prefix, name)
                }],
                "title": format!("{} Errors (1h)", name),
                "type": "stat"
            },
            {
                "datasource": { "type": "loki", "uid": "loki" },
                "gridPos": { "h": 8, "w": 18, "x": 6, "y": 8 },
                "id": 4,
                "options": { "showTime": true },
                "targets": [{
                    "expr": format!("{{app=\"{}-backend\"}} |= `{}` | json", product_name, name)
                }],
                "title": format!("{} Logs", name),
                "type": "logs"
            }
        ],
        "refresh": "30s",
        "schemaVersion": 39,
        "tags": [product_name.as_str(), "entity", name],
        "templating": { "list": [] },
        "time": { "from": "now-1h", "to": "now" },
        "timepicker": {},
        "timezone": "browser",
        "title": title,
        "uid": format!("{}-entity-{}", product_name, name),
        "version": 1,
        "weekStart": ""
    })
}

/// Generate overview dashboard for all entities
fn generate_overview_dashboard(
    entities: &[serde_json::Value],
    config: &DashboardConfig,
) -> serde_json::Value {
    let entity_names: Vec<&str> = entities.iter().filter_map(|e| e["name"].as_str()).collect();
    let metric_prefix = &config.metric_prefix;
    let product_name = &config.product_name;
    let dashboard_folder = &config.dashboard_folder;

    let entity_panels: Vec<serde_json::Value> = entity_names
        .iter()
        .enumerate()
        .map(|(i, name)| {
            serde_json::json!({
                "datasource": { "type": "prometheus", "uid": "mimir" },
                "fieldConfig": {
                    "defaults": { "unit": "ops" }
                },
                "gridPos": { "h": 4, "w": 6, "x": (i % 4) * 6, "y": 4 + (i / 4) * 4 },
                "id": 10 + i,
                "targets": [{
                    "expr": format!("sum(rate({}_{}_operations_total{{}}[5m]))", metric_prefix, name)
                }],
                "title": format!("{} ops/s", name),
                "type": "stat"
            })
        })
        .collect();

    let mut panels = vec![serde_json::json!({
        "datasource": { "type": "prometheus", "uid": "mimir" },
        "gridPos": { "h": 4, "w": 24, "x": 0, "y": 0 },
        "id": 1,
        "targets": [{
            "expr": format!("sum(rate({}_function_calls_total{{}}[5m]))", metric_prefix)
        }],
        "title": "Total Throughput",
        "type": "stat"
    })];
    panels.extend(entity_panels);

    serde_json::json!({
        "annotations": { "list": [] },
        "editable": true,
        "panels": panels,
        "refresh": "30s",
        "schemaVersion": 39,
        "tags": [product_name.as_str(), "overview"],
        "time": { "from": "now-1h", "to": "now" },
        "title": format!("{}: Entity Overview", dashboard_folder),
        "uid": format!("{}-entity-overview", product_name)
    })
}

/// Check for dashboards that should be pruned (deleted entities)
fn check_pruned_dashboards(
    config: &DashboardConfig,
    current_entities: &[ObservedEntity],
) -> Result<Vec<String>> {
    let mut pruned = Vec::new();

    let Some(output_dir) = &config.output_dir else {
        return Ok(pruned);
    };

    if !output_dir.exists() {
        return Ok(pruned);
    }

    let entity_prefix = format!("{}-entity-", config.product_name);
    let current_names: std::collections::HashSet<_> =
        current_entities.iter().map(|e| e.name.as_str()).collect();

    for entry in fs::read_dir(output_dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.extension().map_or(false, |ext| ext == "yaml") {
            let filename = path.file_stem().unwrap_or_default().to_string_lossy();

            // Check if this is an entity dashboard
            if filename.starts_with(&entity_prefix) {
                let entity_name = filename.trim_start_matches(entity_prefix.as_str());

                // Skip overview dashboard
                if entity_name == "overview" {
                    continue;
                }

                // If entity no longer exists, mark for pruning
                if !current_names.contains(entity_name) {
                    pruned.push(filename.to_string());
                }
            }
        }
    }

    Ok(pruned)
}

/// Write dashboard files to output directory
fn write_dashboards(
    config: &DashboardConfig,
    dashboards: &HashMap<String, serde_json::Value>,
) -> Result<()> {
    let output_dir = config.output_dir.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "No dashboards_output dir configured. Set dirs.dashboards_output in deploy.yaml"
        )
    })?;

    // Ensure output directory exists
    fs::create_dir_all(output_dir)?;

    for (name, dashboard) in dashboards {
        // Write JSON file
        let json_path = output_dir.join(format!("{}.json", name));
        fs::write(&json_path, serde_json::to_string_pretty(dashboard)?)?;
        debug!("Generated dashboard JSON: {:?}", json_path);

        // Write GrafanaDashboard CRD
        let crd = generate_grafana_dashboard_crd(name, dashboard, config);
        let yaml_path = output_dir.join(format!("{}.yaml", name));
        fs::write(&yaml_path, serde_yaml::to_string(&crd)?)?;
        info!("Generated dashboard CRD: {:?}", yaml_path);
    }

    // Update kustomization.yaml
    let kustomization_path = output_dir.join("kustomization.yaml");
    let kustomization = generate_kustomization(dashboards);
    fs::write(&kustomization_path, serde_yaml::to_string(&kustomization)?)?;
    info!("Updated kustomization.yaml");

    Ok(())
}

/// Generate GrafanaDashboard CRD for FluxCD
fn generate_grafana_dashboard_crd(
    name: &str,
    dashboard: &serde_json::Value,
    config: &DashboardConfig,
) -> serde_json::Value {
    let dashboard_json = serde_json::to_string(dashboard).unwrap_or_default();
    let product_name = &config.product_name;
    let dashboard_folder = &config.dashboard_folder;

    serde_json::json!({
        "apiVersion": "grafana.integreatly.org/v1beta1",
        "kind": "GrafanaDashboard",
        "metadata": {
            "name": name,
            "namespace": "observability",
            "labels": {
                "app.kubernetes.io/name": "grafana-dashboard",
                "app.kubernetes.io/component": "observability",
                "app.kubernetes.io/part-of": product_name,
                "grafana.integreatly.org/folder": dashboard_folder,
                "oac.nexus.io/generated": "true"
            },
            "annotations": {
                "oac.nexus.io/source": format!("{}-dashboards", product_name),
                "oac.nexus.io/version": "1.0.0"
            }
        },
        "spec": {
            "instanceSelector": {
                "matchLabels": {
                    "dashboards": "grafana"
                }
            },
            "folder": dashboard_folder,
            "json": dashboard_json
        }
    })
}

/// Generate kustomization.yaml for the generated dashboards
fn generate_kustomization(dashboards: &HashMap<String, serde_json::Value>) -> serde_json::Value {
    let resources: Vec<String> = dashboards
        .keys()
        .map(|name| format!("{}.yaml", name))
        .collect();

    serde_json::json!({
        "apiVersion": "kustomize.config.k8s.io/v1beta1",
        "kind": "Kustomization",
        "resources": resources,
        "commonLabels": {
            "oac.nexus.io/generated": "true"
        }
    })
}
