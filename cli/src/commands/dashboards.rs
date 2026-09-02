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

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{debug, info, warn};

/// Resolve the `jsonnet` binary path via `JSONNET_BIN`, falling back to
/// `jsonnet` on `PATH`. Wired through [`crate::repo::get_tool_path`] so
/// a Nix-hermetic runner's substrate-derived `jsonnet` path lands at
/// every jsonnet-spawning site in this module. Mirrors the sibling
/// `commands/local.rs::docker_bin` (947ea7c), `commands/e2e.rs::docker_bin`
/// (23241a6), `commands/test_ci.rs::cargo_bin` (916f1a4), and every
/// `<tool>_bin()` sigil landed since 23241a6 that spells the resolve
/// as `crate::repo::get_tool_path("<TOOL>_BIN", "<tool>")` — the
/// explicit two-arg form that makes the substrate-exported env-var
/// literal visible to a fleet-wide `grep JSONNET_BIN cli/src/` audit.
/// Pre-lift the sigil used the deriving one-arg form
/// `crate::tools::get_tool_path("jsonnet")`, which hid the
/// `JSONNET_BIN` literal behind an implicit `to_uppercase() + "_BIN"`
/// derivation — an audit-time reader had to mentally suffix `"jsonnet"`
/// to know which env var this sigil reads. Post-unify the resolve
/// spells the env var at the sigil site verbatim.
///
/// The unify also closes the DOCA-class silent-divergence bug the
/// deriving form structurally allows: if a future rename ever makes
/// the tool-name argument disagree with the substrate-exported env
/// var (as `tools::DOCA = "oci-push"` did, pinned by
/// `cli/src/tools.rs::tests::doca_resolves_from_doca_bin_and_the_deriving_lookup_does_not`),
/// the deriving form would silently read the wrong env var and
/// downgrade to PATH; the explicit two-arg form cannot express that
/// divergence.
fn jsonnet_bin() -> String {
    crate::repo::get_tool_path("JSONNET_BIN", "jsonnet")
}

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
        product.name, check_only
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
    let module_path = crate::repo::path_to_string_lossy(path);

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
    let module_path = crate::repo::path_to_string_lossy(path);

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
        crate::repo::create_dir_all_sync(parent)?;
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

    let jsonnet = jsonnet_bin();
    let output = crate::retry::classify_capture_anyhow(
        Command::new(&jsonnet)
            .arg("-J")
            .arg(templates_dir.join("vendor"))
            .arg(&main_jsonnet)
            .output(),
        "jsonnet",
    )?;

    let stdout = crate::repo::utf8_lossy_borrow(&output.stdout);
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
    let title = format!(
        "{}: {} Operations",
        config.dashboard_folder,
        name.to_uppercase()
    );
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
    crate::repo::create_dir_all_sync(output_dir)?;

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

#[cfg(test)]
mod tests {
    /// Whole-module shield: no raw `"jsonnet"`-literal spawn may live in
    /// `commands/dashboards.rs`. Every jsonnet spawn must resolve
    /// `JSONNET_BIN` via [`super::jsonnet_bin`] first, AND the sigil
    /// itself must spell its resolve as the explicit two-arg
    /// `crate::repo::get_tool_path("JSONNET_BIN", "jsonnet")` — the
    /// audit-visible form the sibling `<tool>_bin()` sigils across
    /// forge already ride (947ea7c unified the four `docker_bin`
    /// sigils onto this shape).
    ///
    /// Pre-lift the single `Command::new` site in `run_jsonnet` — the
    /// dashboard-templates renderer that reads `dashboards.jsonnet` from
    /// the product's `observability_scripts` dir — spelled the bare
    /// `"jsonnet"` literal verbatim, ignoring `JSONNET_BIN`. A
    /// Nix-hermetic runner's substrate-derived jsonnet path lost to
    /// whatever `jsonnet` sat first on PATH — the same silent-PATH-
    /// fallback bug class the sibling
    /// `commands/rebac_validation.rs::test_redis_cli_spawns_route_through_redis_cli_bin_not_raw_literal`
    /// shield (9aed883) and `commands/infra.rs::docker_bin_routing_tests`
    /// shield (7f49465) closed for their surfaces.
    ///
    /// This shield scans the module's own source via [`include_str!`]
    /// and forbids the fused literal shape. The forbidden shape is
    /// reconstructed via [`format!`] so this shield's own source text
    /// does not false-match itself — the whole-module scan therefore
    /// covers both the top-of-file production body AND every sibling
    /// `#[cfg(test)]` block (any of which could otherwise silently re-
    /// introduce a raw literal). The end-to-end `JSONNET_BIN`-routing
    /// invariant of the underlying primitive is pinned separately by
    /// [`crate::repo::tests::test_get_tool_path_with_env`] /
    /// [`crate::repo::tests::test_get_tool_path_fallback`]; this
    /// shield only certifies that every jsonnet-spawning site in this
    /// module reads through `jsonnet_bin()`.
    ///
    /// Also asserts the pre-lift deriving one-arg form
    /// `crate::tools::get_tool_path("jsonnet")` does NOT reappear at
    /// any *code* line — a `JSONNET_BIN`-literal audit would miss the
    /// site under that form. Docstring and shield-message narrations
    /// of the anti-pattern are excluded via a `///` / `//!` / `//`
    /// per-line filter, the same discipline the sibling
    /// `commands/local.rs::docker_bin_routing_tests` shield rides
    /// (947ea7c).
    #[test]
    fn test_jsonnet_spawn_routes_through_jsonnet_bin_not_raw_literal() {
        const SOURCE: &str = include_str!("dashboards.rs");

        // Composed three-primitive stanza — bare-spawn refusal, sigil
        // definition, canonical two-arg delegation — through the
        // shared `assert_source_routes_bare_spawn_through_two_arg_sigil`
        // (e108260). Sigil name (`jsonnet_bin`) and remediation
        // (`resolve \`JSONNET_BIN\` via \`jsonnet_bin()\``) are derived
        // by the helper from `bare` and `env_var`.
        crate::test_support::assert_source_routes_bare_spawn_through_two_arg_sigil(
            SOURCE,
            "commands/dashboards.rs",
            "jsonnet",
            "JSONNET_BIN",
        );
        // Also assert the pre-lift deriving one-arg literal-string
        // form does NOT reappear at any *code* line. This site's
        // uniqueness vs the docker shields: jsonnet has no
        // `crate::tools::tools::JSONNET` constant, so only the
        // literal-string deriving form is possible.
        crate::test_support::assert_source_forbids_deriving_one_arg_sigil_literal_form(
            SOURCE,
            "commands/dashboards.rs",
            "JSONNET_BIN",
            "jsonnet",
        );
    }

    /// Captured-output routing shield: the sole
    /// `if !output.status.success() { bail!("Jsonnet failed: {stderr}") }`
    /// stanza in `generate_dashboards_from_jsonnet` — the module's ONE
    /// captured-output bail site — MUST route through
    /// [`crate::retry::classify_capture_anyhow`]. Pre-lift the operator
    /// log line read `"Jsonnet failed: <stderr>"` and dropped the exit
    /// code: an operator reading that message on a jsonnet render
    /// against an ill-formed `dashboards.jsonnet` had no way to tell
    /// whether jsonnet exited 1 (a real parse error), 2 (a missing
    /// `-J vendor` import), or 127 (a bad `JSONNET_BIN` route past the
    /// sigil's own PATH-fallback). Post-lift the canonical
    /// `"jsonnet failed (exit {code}): {stderr}"` envelope emerges by
    /// construction at [`crate::retry::classify_capture_anyhow`]'s ONE
    /// body — the same `(op, exit_code, stderr)` envelope the sibling
    /// `commands/sync.rs::generate_entities` and
    /// `commands/federation_tests.rs::run_federation_tests` shields
    /// pin against this commit.
    ///
    /// The shield uses the whole-module include (rather than an
    /// `fn_body_slice_between_markers` cut) because
    /// `commands/dashboards.rs` carries NO other
    /// `output.status.success` consumer sites — the pre-lift stanza
    /// was the module's sole occurrence, and the helper's needle
    /// (`if !output.status.success`) cannot false-match the whole
    /// module.
    #[test]
    fn test_generate_dashboards_from_jsonnet_bail_routes_through_classify_capture_anyhow() {
        const SOURCE: &str = include_str!("dashboards.rs");
        let body = crate::test_support::module_body_before_tests(SOURCE, "commands/dashboards.rs");
        crate::test_support::assert_source_routes_captured_bails_through_classify_capture_anyhow(
            body,
            "commands/dashboards.rs::generate_dashboards_from_jsonnet",
            1,
        );
    }
}
