//! Helm chart lifecycle commands
//!
//! Provides lint, package, push, deploy, release, template, and bump operations
//! for pleme-io Helm charts distributed via OCI registries.

use anyhow::{Context, Result, bail};
use std::path::Path;
use std::process::Command;
use tracing::{info, warn};

/// Run `helm lint` + `helm template` validation on a chart directory.
pub fn lint(chart_dir: &str) -> Result<()> {
    let chart_path = Path::new(chart_dir);
    if !chart_path.exists() {
        bail!("Chart directory not found: {}", chart_dir);
    }

    info!("Linting chart: {}", chart_dir);

    // helm dependency update (resolves file:// references)
    let dep_status = Command::new("helm")
        .args(["dependency", "update", chart_dir])
        .status()
        .context("Failed to run helm dependency update")?;

    if !dep_status.success() {
        warn!("helm dependency update had warnings (non-fatal)");
    }

    // helm lint
    let lint_status = Command::new("helm")
        .args(["lint", chart_dir])
        .status()
        .context("Failed to run helm lint")?;

    if !lint_status.success() {
        bail!("helm lint failed for {}", chart_dir);
    }

    // helm template (validation)
    let template_status = Command::new("helm")
        .args([
            "template", "test", chart_dir,
            "--set", "image.repository=test",
        ])
        .status()
        .context("Failed to run helm template")?;

    if !template_status.success() {
        bail!("helm template validation failed for {}", chart_dir);
    }

    info!("Lint passed: {}", chart_dir);
    Ok(())
}

/// Lint with optional library chart workspace isolation.
///
/// If `lib_chart_dir` is provided, creates a temp workspace with the chart
/// and its library dependency for file:// resolution.
pub fn lint_with_lib(chart_dir: &str, lib_chart_dir: Option<&str>, lib_chart_name: &str) -> Result<()> {
    match lib_chart_dir {
        Some(lib_dir) => {
            let chart_path = Path::new(chart_dir);
            let chart_name = chart_path
                .file_name()
                .and_then(|n| n.to_str())
                .context("Invalid chart directory name")?;

            let parent_dir = chart_path
                .parent()
                .and_then(|p| p.to_str())
                .context("Invalid chart parent directory")?;

            let (_tmpdir, tmp_chart_path) =
                prepare_chart_workspace(chart_name, parent_dir, Some(lib_dir), lib_chart_name)?;

            lint(&tmp_chart_path)
        }
        None => lint(chart_dir),
    }
}

/// Release with optional library chart workspace isolation.
pub fn release_with_lib(
    chart_dir: &str,
    registry: &str,
    version: Option<&str>,
    lib_chart_dir: Option<&str>,
    lib_chart_name: &str,
) -> Result<()> {
    match lib_chart_dir {
        Some(lib_dir) => {
            let chart_path = Path::new(chart_dir);
            let chart_name = chart_path
                .file_name()
                .and_then(|n| n.to_str())
                .context("Invalid chart directory name")?;

            let parent_dir = chart_path
                .parent()
                .and_then(|p| p.to_str())
                .context("Invalid chart parent directory")?;

            let (_tmpdir, tmp_chart_path) =
                prepare_chart_workspace(chart_name, parent_dir, Some(lib_dir), lib_chart_name)?;

            release(&tmp_chart_path, registry, version)
        }
        None => release(chart_dir, registry, version),
    }
}

/// Package a chart directory into a .tgz tarball.
pub fn package(chart_dir: &str, output: &str, version: Option<&str>) -> Result<String> {
    let chart_path = Path::new(chart_dir);
    if !chart_path.exists() {
        bail!("Chart directory not found: {}", chart_dir);
    }

    std::fs::create_dir_all(output)?;

    info!("Packaging chart: {} → {}", chart_dir, output);

    // helm dependency update
    let _ = Command::new("helm")
        .args(["dependency", "update", chart_dir])
        .status();

    // helm package
    let mut args = vec!["package", chart_dir, "--destination", output];
    let version_str;
    if let Some(v) = version {
        version_str = format!("--version={}", v);
        args.push(&version_str);
    }

    let status = Command::new("helm")
        .args(&args)
        .status()
        .context("Failed to run helm package")?;

    if !status.success() {
        bail!("helm package failed for {}", chart_dir);
    }

    // Find the generated tarball — use name from Chart.yaml, not the directory
    // basename (which may contain a Nix store hash prefix).
    let chart_yaml = chart_path.join("Chart.yaml");
    let chart_name = if chart_yaml.exists() {
        let content = std::fs::read_to_string(&chart_yaml).unwrap_or_default();
        extract_yaml_field(&content, "name").unwrap_or_else(|_| "chart".to_string())
    } else {
        chart_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("chart")
            .to_string()
    };

    let tgz_path = find_latest_tgz(output, &chart_name)?;
    info!("Packaged: {}", tgz_path);
    Ok(tgz_path)
}

/// Push a chart tarball to an OCI registry.
pub fn push(chart: &str, registry: &str) -> Result<()> {
    if !Path::new(chart).exists() {
        bail!("Chart tarball not found: {}", chart);
    }

    info!("Pushing {} → {}", chart, registry);

    let status = Command::new("helm")
        .args(["push", chart, registry])
        .status()
        .context("Failed to run helm push")?;

    if !status.success() {
        bail!("helm push failed for {}", chart);
    }

    info!("Push succeeded");
    Ok(())
}

/// Deploy a service by updating the HelmRelease image tag in the k8s repo.
pub fn deploy(
    service: &str,
    image_tag: &str,
    k8s_repo: &str,
    environment: &str,
    commit: bool,
    _watch: bool,
) -> Result<()> {
    let k8s_path = Path::new(k8s_repo);
    if !k8s_path.exists() {
        bail!("K8s repo not found: {}", k8s_repo);
    }

    // Find the HelmRelease file for this service
    // Convention: clusters/{cluster}/{category}/{service}/kustomization.yaml patches the HelmRelease
    info!(
        "Deploying {} with tag {} in {} environment",
        service, image_tag, environment
    );

    // Look for kustomization.yaml that patches the HelmRelease
    let cluster = match environment {
        "staging" => "plo",
        "production" => "plo",
        _ => environment,
    };

    // Search for the service's kustomization.yaml in the cluster overlay
    let kustomization_paths = [
        format!("{}/clusters/{}/infrastructure/{}/kustomization.yaml", k8s_repo, cluster, service),
        format!("{}/clusters/{}/products/{}/kustomization.yaml", k8s_repo, cluster, service),
    ];

    let kustomization_path = kustomization_paths
        .iter()
        .find(|p| Path::new(p).exists())
        .context(format!(
            "No kustomization.yaml found for service '{}' in cluster '{}'",
            service, cluster
        ))?;

    info!("Updating image tag in: {}", kustomization_path);

    // Read the kustomization.yaml
    let content = std::fs::read_to_string(kustomization_path)?;

    // Update the HelmRelease image tag via JSON patch
    // Look for: value: amd64-<hash> and replace with the new tag
    let updated = update_helmrelease_image_tag(&content, image_tag)?;

    std::fs::write(kustomization_path, &updated)?;

    if commit {
        info!("Committing changes...");
        let _ = Command::new("git")
            .args(["add", kustomization_path])
            .current_dir(k8s_repo)
            .status();

        let commit_msg = format!("deploy: update {} to {}", service, image_tag);
        let _ = Command::new("git")
            .args(["commit", "-m", &commit_msg])
            .current_dir(k8s_repo)
            .status();

        let _ = Command::new("git")
            .args(["push"])
            .current_dir(k8s_repo)
            .status();

        info!("Changes committed and pushed");
    }

    Ok(())
}

/// Full chart lifecycle: lint → package → push.
pub fn release(chart_dir: &str, registry: &str, version: Option<&str>) -> Result<()> {
    info!("=== Lint ===");
    lint(chart_dir)?;

    info!("=== Package ===");
    let tgz = package(chart_dir, "dist", version)?;

    info!("=== Push ===");
    push(&tgz, registry)?;

    info!("=== Release complete ===");
    Ok(())
}

/// Render chart templates for debugging.
pub fn template(chart_dir: &str, values: Option<&str>, set_values: &[String]) -> Result<()> {
    let chart_path = Path::new(chart_dir);
    if !chart_path.exists() {
        bail!("Chart directory not found: {}", chart_dir);
    }

    // helm dependency update
    let _ = Command::new("helm")
        .args(["dependency", "update", chart_dir])
        .status();

    let mut args = vec!["template".to_string(), "test".to_string(), chart_dir.to_string()];

    if let Some(v) = values {
        args.push("-f".to_string());
        args.push(v.to_string());
    }

    for sv in set_values {
        args.push("--set".to_string());
        args.push(sv.clone());
    }

    if values.is_none() && set_values.is_empty() {
        args.push("--set".to_string());
        args.push("image.repository=test".to_string());
    }

    let status = Command::new("helm")
        .args(&args.iter().map(|s| s.as_str()).collect::<Vec<_>>())
        .status()
        .context("Failed to run helm template")?;

    if !status.success() {
        bail!("helm template failed for {}", chart_dir);
    }

    Ok(())
}

/// Bump a library chart version and update all dependent Chart.yaml files.
///
/// Workflow:
///   1. Read current version from lib_chart_name/Chart.yaml
///   2. Compute new semver version (patch/minor/major)
///   3. Update library Chart.yaml
///   4. Update all dependent Chart.yaml files that reference the library
///   5. Git commit + tag (unless --no-commit)
///
/// Returns (old_version, new_version).
pub fn bump(
    charts_dir: &str,
    lib_chart_name: &str,
    level: &str,
    commit: bool,
) -> Result<(String, String)> {
    let charts_path = Path::new(charts_dir);
    if !charts_path.exists() {
        bail!("Charts directory not found: {}", charts_dir);
    }

    let lib_chart_yaml = charts_path.join(lib_chart_name).join("Chart.yaml");
    if !lib_chart_yaml.exists() {
        bail!(
            "Library chart not found: {}",
            lib_chart_yaml.display()
        );
    }

    // Read current version
    let content = std::fs::read_to_string(&lib_chart_yaml)
        .with_context(|| format!("Failed to read {}", lib_chart_yaml.display()))?;

    let old_version = extract_yaml_field(&content, "version")
        .context("Failed to read version from Chart.yaml")?;

    info!("Current version: {}", old_version);

    // Parse and bump
    let (major, minor, patch) = parse_semver(&old_version)?;
    let new_version = match level {
        "patch" => format!("{}.{}.{}", major, minor, patch + 1),
        "minor" => format!("{}.{}.0", major, minor + 1),
        "major" => format!("{}.0.0", major + 1),
        _ => bail!("Invalid bump level '{}' — use patch, minor, or major", level),
    };

    info!("New version:     {}", new_version);

    // Update library chart
    info!("Updating {}/Chart.yaml", lib_chart_name);
    let updated = content.replace(
        &format!("version: {}", old_version),
        &format!("version: {}", new_version),
    );
    std::fs::write(&lib_chart_yaml, &updated)
        .with_context(|| format!("Failed to write {}", lib_chart_yaml.display()))?;

    // Update all dependent charts
    let mut updated_count = 0u32;
    for entry in std::fs::read_dir(charts_path)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }

        let dir_name = entry.file_name();
        let dir_name_str = dir_name.to_string_lossy();
        if dir_name_str == lib_chart_name {
            continue;
        }

        let dep_chart_yaml = entry.path().join("Chart.yaml");
        if !dep_chart_yaml.exists() {
            continue;
        }

        let dep_content = std::fs::read_to_string(&dep_chart_yaml)?;

        // Check if this chart depends on the library
        // Look for: version: "X.Y.Z" under a dependency with name: lib_chart_name
        let old_dep = format!("version: \"{}\"", old_version);
        let new_dep = format!("version: \"{}\"", new_version);

        if dep_content.contains(&old_dep) && dep_content.contains(&format!("name: {}", lib_chart_name)) {
            info!("Updating {}/Chart.yaml", dir_name_str);
            let updated_dep = dep_content.replace(&old_dep, &new_dep);
            std::fs::write(&dep_chart_yaml, &updated_dep)?;
            updated_count += 1;
        }
    }

    info!(
        "Updated {} + {} dependent charts",
        lib_chart_name, updated_count
    );

    if commit {
        info!("Committing changes...");
        // Find repo root
        let repo_root = Command::new("git")
            .args(["rev-parse", "--show-toplevel"])
            .output()
            .context("Failed to run git rev-parse")?;

        let repo_root = String::from_utf8(repo_root.stdout)?
            .trim()
            .to_string();

        let status = Command::new("git")
            .args(["add", &format!("{}/*/Chart.yaml", charts_dir)])
            .current_dir(&repo_root)
            .status()
            .context("Failed to git add")?;

        if !status.success() {
            // Fallback: add individual files
            let _ = Command::new("git")
                .args(["add", "-A", charts_dir])
                .current_dir(&repo_root)
                .status();
        }

        let commit_msg = format!("release: {} v{}", lib_chart_name, new_version);
        let status = Command::new("git")
            .args(["commit", "-m", &commit_msg])
            .current_dir(&repo_root)
            .status()
            .context("Failed to git commit")?;

        if !status.success() {
            bail!("git commit failed");
        }

        let tag = format!("v{}", new_version);
        let status = Command::new("git")
            .args(["tag", &tag])
            .current_dir(&repo_root)
            .status()
            .context("Failed to git tag")?;

        if !status.success() {
            warn!("git tag failed (tag may already exist)");
        }

        info!("Tagged {}", tag);
        info!("Next: git push && git push --tags");
    }

    Ok((old_version, new_version))
}

/// Discover chart directories inside a parent directory.
///
/// Returns chart names that have a Chart.yaml, excluding `exclude_name`.
fn discover_charts(charts_dir: &str, exclude_name: &str) -> Result<Vec<String>> {
    let dir = Path::new(charts_dir);
    if !dir.exists() {
        bail!("Charts directory not found: {}", charts_dir);
    }

    let mut charts: Vec<String> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|ft| ft.is_dir()).unwrap_or(false))
        .filter(|e| {
            let name = e.file_name();
            let name_str = name.to_string_lossy();
            name_str != exclude_name && e.path().join("Chart.yaml").exists()
        })
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();

    charts.sort();
    Ok(charts)
}

/// Prepare a temp directory with a chart and its library dependency.
///
/// Copies the chart and (optionally) the library chart into a temp dir
/// so `helm dependency update` can resolve `file://` references.
/// Returns (temp_dir_path, chart_path_inside_temp).
fn prepare_chart_workspace(
    chart_name: &str,
    charts_dir: &str,
    lib_chart_dir: Option<&str>,
    lib_chart_name: &str,
) -> Result<(tempfile::TempDir, String)> {
    let tmpdir = tempfile::tempdir().context("Failed to create temp directory")?;
    let tmp_path = tmpdir.path();

    // Copy chart
    let src_chart = Path::new(charts_dir).join(chart_name);
    let dst_chart = tmp_path.join(chart_name);
    copy_dir_recursive(&src_chart, &dst_chart)
        .with_context(|| format!("Failed to copy chart {}", chart_name))?;

    // Copy library chart (either from external dir or from charts_dir)
    let lib_src = match lib_chart_dir {
        Some(ext) => Path::new(ext).to_path_buf(),
        None => Path::new(charts_dir).join(lib_chart_name),
    };

    if lib_src.exists() {
        let dst_lib = tmp_path.join(lib_chart_name);
        copy_dir_recursive(&lib_src, &dst_lib)
            .with_context(|| format!("Failed to copy library chart from {}", lib_src.display()))?;
    }

    let chart_path = dst_chart.to_string_lossy().to_string();
    Ok((tmpdir, chart_path))
}

/// Recursively copy a directory.
fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let dst_path = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_dir_recursive(&entry.path(), &dst_path)?;
        } else {
            std::fs::copy(entry.path(), dst_path)?;
        }
    }
    Ok(())
}

/// Lint all charts in a directory.
///
/// Discovers charts, sets up temp workspaces with library dependencies,
/// and runs lint on each. Returns error if any chart fails.
pub fn lint_all(charts_dir: &str, lib_chart_dir: Option<&str>, lib_chart_name: &str) -> Result<()> {
    let charts = discover_charts(charts_dir, lib_chart_name)?;
    if charts.is_empty() {
        bail!("No charts found in {}", charts_dir);
    }

    info!("Discovered {} charts: {}", charts.len(), charts.join(", "));

    let mut failed = Vec::new();

    for chart_name in &charts {
        println!();
        println!("==========================================");
        println!("  Linting {}", chart_name);
        println!("==========================================");

        let (_tmpdir, chart_path) =
            prepare_chart_workspace(chart_name, charts_dir, lib_chart_dir, lib_chart_name)?;

        match lint(&chart_path) {
            Ok(()) => println!("PASS: {}", chart_name),
            Err(e) => {
                println!("FAIL: {} — {}", chart_name, e);
                failed.push(chart_name.clone());
            }
        }
    }

    println!();
    if failed.is_empty() {
        info!("All {} charts passed lint", charts.len());
        Ok(())
    } else {
        bail!(
            "{}/{} charts failed lint: {}",
            failed.len(),
            charts.len(),
            failed.join(", ")
        )
    }
}

/// Release all charts: lint → package → push to OCI registry.
///
/// Discovers charts, sets up temp workspaces, and runs the full
/// release lifecycle for each chart.
pub fn release_all(
    charts_dir: &str,
    lib_chart_dir: Option<&str>,
    lib_chart_name: &str,
    registry: &str,
) -> Result<()> {
    let charts = discover_charts(charts_dir, lib_chart_name)?;
    if charts.is_empty() {
        bail!("No charts found in {}", charts_dir);
    }

    info!("Discovered {} charts: {}", charts.len(), charts.join(", "));

    let output_dir = "dist";
    std::fs::create_dir_all(output_dir)?;

    let mut failed = Vec::new();
    let mut released = Vec::new();

    for chart_name in &charts {
        println!();
        println!("==========================================");
        println!("  Releasing {}", chart_name);
        println!("==========================================");

        let (_tmpdir, chart_path) =
            prepare_chart_workspace(chart_name, charts_dir, lib_chart_dir, lib_chart_name)?;

        // Lint
        println!("--- Lint ---");
        if let Err(e) = lint(&chart_path) {
            println!("FAIL: {} lint — {}", chart_name, e);
            failed.push(chart_name.clone());
            continue;
        }

        // Package
        println!("--- Package ---");
        let tgz = match package(&chart_path, output_dir, None) {
            Ok(t) => t,
            Err(e) => {
                println!("FAIL: {} package — {}", chart_name, e);
                failed.push(chart_name.clone());
                continue;
            }
        };

        // Push
        println!("--- Push ---");
        if let Err(e) = push(&tgz, registry) {
            println!("FAIL: {} push — {}", chart_name, e);
            failed.push(chart_name.clone());
            continue;
        }

        println!("DONE: {}", chart_name);
        released.push(chart_name.clone());
    }

    println!();
    info!("Released {}/{} charts", released.len(), charts.len());

    if !failed.is_empty() {
        bail!(
            "{} chart(s) failed: {}",
            failed.len(),
            failed.join(", ")
        )
    }

    Ok(())
}

// --- Helpers ---

/// Parse a semver version string "X.Y.Z" into components.
fn parse_semver(version: &str) -> Result<(u64, u64, u64)> {
    let parts: Vec<&str> = version.split('.').collect();
    if parts.len() != 3 {
        bail!("Invalid version format '{}' — expected X.Y.Z", version);
    }

    let major = parts[0].parse::<u64>().context("Invalid major version")?;
    let minor = parts[1].parse::<u64>().context("Invalid minor version")?;
    let patch = parts[2].parse::<u64>().context("Invalid patch version")?;

    Ok((major, minor, patch))
}

/// Extract a top-level YAML field value (simple key: value parsing).
fn extract_yaml_field(content: &str, field: &str) -> Result<String> {
    let prefix = format!("{}: ", field);
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with(&prefix) {
            return Ok(trimmed[prefix.len()..].trim().trim_matches('"').to_string());
        }
    }
    bail!("Field '{}' not found", field)
}

fn find_latest_tgz(dir: &str, prefix: &str) -> Result<String> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_name()
                .to_str()
                .map(|n| n.starts_with(prefix) && n.ends_with(".tgz"))
                .unwrap_or(false)
        })
        .collect();

    entries.sort_by(|a, b| {
        b.metadata()
            .and_then(|m| m.modified())
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
            .cmp(
                &a.metadata()
                    .and_then(|m| m.modified())
                    .unwrap_or(std::time::SystemTime::UNIX_EPOCH),
            )
    });

    entries
        .first()
        .map(|e| e.path().to_string_lossy().to_string())
        .context(format!("No .tgz found for {} in {}", prefix, dir))
}

fn update_helmrelease_image_tag(content: &str, new_tag: &str) -> Result<String> {
    // Look for image tag patterns in kustomize patches:
    // value: amd64-<hash>
    let re = regex::Regex::new(r"(value:\s*)(amd64-[a-f0-9]+|latest)")
        .context("Failed to compile regex")?;

    if re.is_match(content) {
        Ok(re
            .replace_all(content, format!("${{1}}{}", new_tag).as_str())
            .to_string())
    } else {
        // Also try images[].newTag pattern (kustomize style)
        let re2 = regex::Regex::new(r"(newTag:\s*)(amd64-[a-f0-9]+|latest)")
            .context("Failed to compile regex")?;

        if re2.is_match(content) {
            Ok(re2
                .replace_all(content, format!("${{1}}{}", new_tag).as_str())
                .to_string())
        } else {
            bail!(
                "Could not find image tag pattern (value: amd64-* or newTag: amd64-*) in content"
            );
        }
    }
}
