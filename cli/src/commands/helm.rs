//! Helm chart lifecycle commands
//!
//! Provides lint, package, push, deploy, release, template, and bump operations
//! for pleme-io Helm charts distributed via OCI registries.

use anyhow::{Context, Result, bail};
use std::path::Path;
use std::process::Command;
use std::thread::sleep;
use std::time::{Duration, Instant};
use tracing::{info, warn};

/// Per-attempt wall-clock cap on `helm dependency update`. pleme-io wrapper
/// charts pull third-party subcharts (victoria-metrics-k8s-stack, cert-manager,
/// authentik, …) from upstream `*.github.io` repos at release time — those
/// downloads are not vendored in git (`.gitignore` excludes `charts/*/*.tgz`),
/// so a slow or unreachable upstream would otherwise block `helm dependency
/// update` indefinitely and wedge the entire monorepo auto-release. The cap
/// converts a hang into a typed per-chart failure that `release_all` collects
/// and continues past.
const DEP_TIMEOUT_SECS: u64 = 240;
/// Extra attempts after the first (so `DEP_RETRIES + 1` total) — absorbs
/// transient upstream slowness / index flakiness with linear backoff.
const DEP_RETRIES: u32 = 1;

/// A digest-pinned placeholder image tag for lint/template validation. Charts
/// under a fedramp-high (or stricter) compliance baseline `fail()` rendering
/// unless the image is digest-pinned (CM-2, SI-7); a bare repository left the
/// tag at the chart default (e.g. `v1.18.0`) and made every such workload chart
/// unlintable. The value is the sha256 of the empty string — a recognizable
/// placeholder that satisfies the digest check; non-compliance charts ignore it.
/// Applied to BOTH `helm lint` and `helm template` so the fail() can't fire in
/// either pass.
const LINT_IMAGE_TAG: &str =
    "image.tag=sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const LINT_IMAGE_REPO: &str = "image.repository=test";

/// Run `program <args>` with a hard wall-clock timeout, inheriting stdio so
/// output still streams to CI. Returns `Ok(true)` on success, `Ok(false)` on a
/// clean non-zero exit, and `Err` if the process had to be killed at the
/// timeout. Generic over the program so the timeout machinery is unit-testable
/// without a real `helm` on PATH.
fn run_program_timed(program: &str, args: &[&str], timeout: Duration) -> Result<bool> {
    let mut child = Command::new(program)
        .args(args)
        .spawn()
        .with_context(|| format!("failed to spawn {} {}", program, args.join(" ")))?;
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status.success());
        }
        if start.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            bail!("{} {} timed out after {}s", program, args.join(" "), timeout.as_secs());
        }
        sleep(Duration::from_millis(50));
    }
}

/// Run `helm <args>` with a hard wall-clock timeout (see [`run_program_timed`]).
fn run_helm_timed(args: &[&str], timeout: Duration) -> Result<bool> {
    run_program_timed("helm", args, timeout)
}

/// `helm dependency update` for a chart, bounded by [`DEP_TIMEOUT_SECS`] and
/// retried [`DEP_RETRIES`] times with linear backoff. A genuinely unreachable
/// dependency surfaces as a typed error (so the chart is marked failed rather
/// than shipped against unresolved deps); the caller (`release_all`/`lint_all`)
/// records the failure and proceeds to the next chart. file://-only charts
/// resolve offline and exit 0 even when an unrelated repo index is unreachable.
fn helm_dependency_update(chart_dir: &str) -> Result<()> {
    let timeout = Duration::from_secs(DEP_TIMEOUT_SECS);
    let mut last = String::new();
    for attempt in 1..=(DEP_RETRIES + 1) {
        match run_helm_timed(&["dependency", "update", chart_dir], timeout) {
            Ok(true) => return Ok(()),
            Ok(false) => last = "helm dependency update exited non-zero".to_string(),
            Err(e) => last = e.to_string(),
        }
        if attempt <= DEP_RETRIES {
            warn!(
                "helm dependency update attempt {}/{} failed for {} ({}); retrying",
                attempt,
                DEP_RETRIES + 1,
                chart_dir,
                last
            );
            sleep(Duration::from_secs(5 * u64::from(attempt)));
        }
    }
    bail!(
        "helm dependency update failed after {} attempts for {}: {}",
        DEP_RETRIES + 1,
        chart_dir,
        last
    )
}

/// Run `helm lint` + `helm template` validation on a chart directory.
///
/// Library charts (type: library) skip `helm template` since they are not
/// directly installable.
pub fn lint(chart_dir: &str) -> Result<()> {
    let chart_path = Path::new(chart_dir);
    if !chart_path.exists() {
        bail!("Chart directory not found: {}", chart_dir);
    }

    info!("Linting chart: {}", chart_dir);

    // Detect library charts — they cannot be templated
    let is_library = {
        let chart_yaml = chart_path.join("Chart.yaml");
        chart_yaml.exists()
            && std::fs::read_to_string(&chart_yaml)
                .unwrap_or_default()
                .lines()
                .any(|line| line.trim() == "type: library")
    };

    // helm dependency update (resolves file:// references + fetches remote
    // subcharts) — bounded + retried so a slow/unreachable upstream fails this
    // chart cleanly instead of hanging the whole release.
    helm_dependency_update(chart_dir)?;

    // Common value arguments for lint + template. The digest-pinned placeholder
    // image (see LINT_IMAGE_TAG) keeps a fedramp-high chart's compliance fail()
    // from firing; an optional `ci/lint-values.yaml` (helm chart-testing
    // convention) supplies any values the chart `required`s to render (e.g.
    // pleme-discord-bot's botName), so a chart can keep its deploy-time guard AND
    // still lint generically.
    let mut value_args: Vec<String> = vec![
        "--set".into(), LINT_IMAGE_REPO.into(),
        "--set".into(), LINT_IMAGE_TAG.into(),
    ];
    let ci_values = chart_path.join("ci").join("lint-values.yaml");
    if ci_values.exists() {
        value_args.push("-f".into());
        value_args.push(ci_values.to_string_lossy().into_owned());
    }

    // helm lint
    let mut lint_args: Vec<String> = vec!["lint".into(), chart_dir.into()];
    lint_args.extend(value_args.iter().cloned());
    let lint_status = Command::new("helm")
        .args(&lint_args)
        .status()
        .context("Failed to run helm lint")?;

    if !lint_status.success() {
        bail!("helm lint failed for {}", chart_dir);
    }

    // helm template (validation) — skip for library charts. Discard rendered
    // stdout (keep stderr for errors): this is an exit-code validation, not a
    // render, and a wrapper chart like lareira-vm-stack emits MEGABYTES of
    // rendered manifests (victoria-metrics-k8s-stack + Grafana dashboards) that
    // otherwise blow past GitHub's per-step log limit, truncating the log and
    // hiding any later chart's real failure.
    if is_library {
        info!("Skipping helm template for library chart");
    } else {
        let mut tmpl_args: Vec<String> =
            vec!["template".into(), "test".into(), chart_dir.into()];
        tmpl_args.extend(value_args.iter().cloned());
        let template_status = Command::new("helm")
            .args(&tmpl_args)
            .stdout(std::process::Stdio::null())
            .status()
            .context("Failed to run helm template")?;

        if !template_status.success() {
            bail!("helm template validation failed for {}", chart_dir);
        }
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

    // Resolve dependencies — but skip the (network) re-fetch when `charts/` is
    // already populated by a prior `lint` pass on this same workspace (the
    // release_all path lints then packages the same temp dir). Avoids a second
    // upstream download per chart and the hang risk that comes with it.
    let charts_sub = chart_path.join("charts");
    let already_resolved = std::fs::read_dir(&charts_sub)
        .map(|mut d| d.next().is_some())
        .unwrap_or(false);
    if !already_resolved {
        helm_dependency_update(chart_dir)?;
    }

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

/// A parsed chart dependency (name + version + repository).
struct ChartDep {
    name: String,
    version: String,
    repository: String,
}

/// Parse a Chart.yaml's `dependencies:` into name/version/repository triples.
/// Handles both block and flow YAML styles (serde_yaml).
fn parse_deps(chart_yaml_content: &str) -> Vec<ChartDep> {
    #[derive(serde::Deserialize)]
    struct ChartYaml {
        #[serde(default)]
        dependencies: Vec<Dep>,
    }
    #[derive(serde::Deserialize)]
    struct Dep {
        #[serde(default)]
        name: String,
        #[serde(default)]
        version: String,
        #[serde(default)]
        repository: String,
    }
    serde_yaml::from_str::<ChartYaml>(chart_yaml_content)
        .map(|c| {
            c.dependencies
                .into_iter()
                .map(|d| ChartDep { name: d.name, version: d.version, repository: d.repository })
                .collect()
        })
        .unwrap_or_default()
}

/// The canonical pleme-io OCI registry. Third-party Helm subchart deps are
/// transparently routed through this mirror at release time (see
/// [`redirect_remote_deps_to_mirror`]) — the hermetic supply-chain law.
pub const PLEME_OCI_REGISTRY: &str = "oci://ghcr.io/pleme-io/charts";

/// `true` for a third-party (non-pleme-io-OCI) Helm repository — an `http(s)://`
/// repo or an `oci://` repo that is NOT already the pleme-io mirror. These are
/// the deps the mirror copies and the redirect reroutes.
fn is_third_party_repo(repo: &str, registry: &str) -> bool {
    let remote = repo.starts_with("http://") || repo.starts_with("https://") || repo.starts_with("oci://");
    remote && !repo.trim_end_matches('/').starts_with(registry.trim_end_matches('/'))
}

/// Mirror every third-party Helm subchart a wrapper chart depends on into the
/// pleme-io OCI registry, so the auto-release never fetches from a third-party
/// repo at release time (the hermetic supply-chain law).
///
/// Everything is derived from the wrapper charts' own `Chart.yaml` dependencies
/// under `charts_dir` — the operator declares the real upstream + version once,
/// in the dependency, and the substrate mirrors it. There is NO separate catalog
/// to drift. For each `{name, upstreamRepo, version}` dependency whose repository
/// is third-party, the chart is pulled from its upstream and pushed to
/// `registry`. Idempotent: a `(name, version)` already in `registry` is skipped,
/// so only a NEW upstream version ever touches the third-party repo. A repo with
/// no third-party deps is a clean no-op (so the action is safe to run anywhere).
/// Every helm call is bounded by [`DEP_TIMEOUT_SECS`].
pub fn mirror(charts_dir: &str, registry: &str) -> Result<()> {
    // Derive (name, upstream, version) from the wrapper deps themselves.
    let mut wanted: std::collections::BTreeMap<(String, String), String> =
        std::collections::BTreeMap::new();
    for entry in std::fs::read_dir(charts_dir)?.filter_map(std::result::Result::ok) {
        let cy = entry.path().join("Chart.yaml");
        if !cy.exists() {
            continue;
        }
        let content = std::fs::read_to_string(&cy).unwrap_or_default();
        for d in parse_deps(&content) {
            if !d.version.is_empty() && is_third_party_repo(&d.repository, registry) {
                wanted.insert((d.name, d.version), d.repository);
            }
        }
    }
    if wanted.is_empty() {
        info!("Mirror: no third-party subchart deps under {charts_dir} — nothing to mirror");
        return Ok(());
    }

    let timeout = Duration::from_secs(DEP_TIMEOUT_SECS);
    let reg = registry.trim_end_matches('/');
    let mut mirrored = 0u32;
    let mut skipped = 0u32;
    for ((name, version), upstream) in &wanted {
        let oci_ref = format!("{reg}/{name}");

        // Already mirrored? `helm show chart` succeeds iff the ref exists.
        if run_program_timed("helm", &["show", "chart", &oci_ref, "--version", version], timeout)
            .unwrap_or(false)
        {
            info!("Mirror: {name}:{version} already in {reg} — skip");
            skipped += 1;
            continue;
        }

        let tmp = tempfile::tempdir().context("mirror tempdir")?;
        let tmps = tmp.path().to_string_lossy().to_string();

        // Pull from upstream — OCI repos take the chart name in the path, HTTP
        // repos take it via --repo.
        let pulled = if upstream.starts_with("oci://") {
            let r = format!("{}/{}", upstream.trim_end_matches('/'), name);
            run_program_timed("helm", &["pull", &r, "--version", version, "-d", &tmps], timeout)?
        } else {
            run_program_timed(
                "helm",
                &["pull", name, "--repo", upstream, "--version", version, "-d", &tmps],
                timeout,
            )?
        };
        if !pulled {
            bail!("helm pull failed for {name} {version} from {upstream}");
        }

        // The pulled tarball name may carry a `v` prefix or differ from
        // {name}-{version}; find the .tgz rather than assume.
        let tgz = std::fs::read_dir(tmp.path())?
            .filter_map(std::result::Result::ok)
            .map(|e| e.path())
            .find(|p| p.extension().is_some_and(|x| x == "tgz"))
            .with_context(|| format!("no .tgz pulled for {name} {version}"))?;

        if !run_program_timed("helm", &["push", &tgz.to_string_lossy(), registry], timeout)? {
            bail!("helm push failed for {name} {version} → {registry}");
        }
        info!("Mirrored {name}:{version} ({upstream}) → {registry}");
        mirrored += 1;
    }

    info!("Mirror complete: {mirrored} pushed, {skipped} already present ({} total)", wanted.len());
    Ok(())
}

/// Rewrite a chart's third-party Helm subchart dependency repositories to the
/// pleme-io OCI mirror, in place. Called on the temp workspace copy before
/// `helm dependency update` so the release fetches every subchart from ghcr (which
/// we control) instead of a third-party `*.github.io` repo — the release half of
/// the hermetic supply-chain law. The committed Chart.yaml is left untouched
/// (it honestly declares the real upstream); only the per-release temp copy is
/// rerouted. A no-op when there are no third-party deps. Requires the subchart to
/// have been mirrored first (the `mirror` step / `helm-mirror` action runs ahead
/// of the release).
fn redirect_remote_deps_to_mirror(chart_dir: &Path, registry: &str) -> Result<()> {
    let chart_yaml = chart_dir.join("Chart.yaml");
    if !chart_yaml.exists() {
        return Ok(());
    }
    let original = std::fs::read_to_string(&chart_yaml)?;
    let mut doc: serde_yaml::Value = match serde_yaml::from_str(&original) {
        Ok(v) => v,
        Err(_) => return Ok(()), // leave unparseable Chart.yaml to helm to surface
    };
    let Some(deps) = doc.get_mut("dependencies").and_then(|d| d.as_sequence_mut()) else {
        return Ok(());
    };
    let mut changed = false;
    for dep in deps.iter_mut() {
        let Some(map) = dep.as_mapping_mut() else { continue };
        let repo = map
            .get(serde_yaml::Value::from("repository"))
            .and_then(|r| r.as_str())
            .unwrap_or("")
            .to_string();
        if is_third_party_repo(&repo, registry) {
            map.insert(
                serde_yaml::Value::from("repository"),
                serde_yaml::Value::from(registry),
            );
            changed = true;
        }
    }
    if changed {
        let rendered = serde_yaml::to_string(&doc).context("re-serialize redirected Chart.yaml")?;
        std::fs::write(&chart_yaml, rendered).context("write redirected Chart.yaml")?;
        // A stale Chart.lock would now disagree with the rerouted deps; drop it so
        // `helm dependency update` regenerates it against the mirror.
        let lock = chart_dir.join("Chart.lock");
        if lock.exists() {
            let _ = std::fs::remove_file(lock);
        }
    }
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

    // helm dependency update (bounded + retried)
    helm_dependency_update(chart_dir)?;

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

    let mut charts: Vec<String> = Vec::new();
    for entry in std::fs::read_dir(dir)?.filter_map(std::result::Result::ok) {
        if !entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        if name == exclude_name || !entry.path().join("Chart.yaml").exists() {
            continue;
        }
        // Per-chart opt-out: a digest-substituted / GitOps-local chart (not a
        // generic OCI library chart — e.g. it pins an all-zero placeholder image
        // digest a separate flow substitutes at release) declares
        // `annotations: { pleme.io/oci-auto-release: "false" }` and is skipped.
        // Logged, never silently dropped (no-silent-caps).
        if chart_oci_auto_release_disabled(&entry.path()) {
            info!("Skipping {} (pleme.io/oci-auto-release: \"false\")", name);
            continue;
        }
        charts.push(name);
    }

    charts.sort();
    Ok(charts)
}

/// Whether a chart opts OUT of OCI auto-release via
/// `annotations["pleme.io/oci-auto-release"] == "false"` in its Chart.yaml.
fn chart_oci_auto_release_disabled(chart_dir: &Path) -> bool {
    #[derive(serde::Deserialize)]
    struct ChartYaml {
        #[serde(default)]
        annotations: std::collections::BTreeMap<String, String>,
    }
    std::fs::read_to_string(chart_dir.join("Chart.yaml"))
        .ok()
        .and_then(|c| serde_yaml::from_str::<ChartYaml>(&c).ok())
        .and_then(|c| c.annotations.get("pleme.io/oci-auto-release").cloned())
        .map(|v| v == "false")
        .unwrap_or(false)
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

    // Stage the chart's file:// SIBLING chart deps (anything beyond the lib
    // chart) as flat siblings in the temp dir, recursively — so a wrapper chart
    // (e.g. lareira-jellyfin → file://../pleme-lareira → file://../pleme-microservice)
    // resolves every `file://../X` to tmp/X under helm dependency update. Without
    // this the tmp-copy isolates the chart away from its siblings and lint fails
    // with "directory .../pleme-lareira not found". The lib chart + the chart
    // itself are already staged, so seed `copied` with them to avoid re-copy / loops.
    let mut copied: std::collections::HashSet<String> =
        [chart_name.to_string(), lib_chart_name.to_string()].into_iter().collect();
    stage_file_sibling_deps(&src_chart, tmp_path, &mut copied)?;

    // Hermetic supply-chain law: reroute any third-party subchart deps in the
    // TEMP copy to the pleme-io OCI mirror, so lint/package/release fetch from
    // ghcr (which we control), never from a third-party repo. The committed
    // Chart.yaml keeps declaring the real upstream; only this per-release copy is
    // redirected. Requires the subchart to have been mirrored first.
    redirect_remote_deps_to_mirror(&dst_chart, PLEME_OCI_REGISTRY)?;

    let chart_path = dst_chart.to_string_lossy().to_string();
    Ok((tmpdir, chart_path))
}

/// The `file://` repository paths declared in a Chart.yaml's `dependencies`.
/// Parsed with serde_yaml so BOTH block style (`repository: file://…` on its own
/// line) AND flow style (`- {name: …, repository: "file://…"}` inline) are
/// caught — a line-scan misses the flow form and was leaving siblings unstaged.
fn file_dep_paths(chart_yaml_content: &str) -> Vec<String> {
    #[derive(serde::Deserialize)]
    struct ChartYaml {
        #[serde(default)]
        dependencies: Vec<Dep>,
    }
    #[derive(serde::Deserialize)]
    struct Dep {
        #[serde(default)]
        repository: String,
    }
    serde_yaml::from_str::<ChartYaml>(chart_yaml_content)
        .map(|c| {
            c.dependencies
                .into_iter()
                .map(|d| d.repository)
                .filter(|r| r.starts_with("file://"))
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod file_dep_tests {
    use super::file_dep_paths;

    #[test]
    fn parses_block_and_flow_dependency_styles() {
        let block = "dependencies:\n  - name: pleme-lareira\n    repository: \"file://../pleme-lareira\"\n";
        assert_eq!(file_dep_paths(block), vec!["file://../pleme-lareira"]);

        let flow = "dependencies:\n  - {name: pleme-lareira, version: \"~0.1.0\", repository: \"file://../pleme-lareira\"}\n";
        assert_eq!(file_dep_paths(flow), vec!["file://../pleme-lareira"]);

        // OCI/HTTP repos are not file:// and must be ignored; no deps → empty.
        let oci = "dependencies:\n  - name: pleme-lib\n    repository: \"oci://ghcr.io/pleme-io/charts\"\n";
        assert!(file_dep_paths(oci).is_empty());
        assert!(file_dep_paths("name: x\nversion: 0.1.0\n").is_empty());
    }
}

#[cfg(test)]
mod parse_deps_tests {
    use super::parse_deps;

    #[test]
    fn extracts_name_version_repository_for_mirror() {
        // A wrapper chart with a remote subchart + a file:// lib — the mirror only
        // cares about (name, version); repository is carried for the http/oci split.
        let cy = "\
apiVersion: v2
name: lareira-vm-stack
version: 0.1.0
dependencies:
  - name: pleme-lib
    version: \">=0.18.1 <0.19.0\"
    repository: \"file://../pleme-lib\"
  - name: victoria-metrics-k8s-stack
    version: \"0.39.0\"
    repository: \"https://victoriametrics.github.io/helm-charts/\"
";
        let deps = parse_deps(cy);
        assert_eq!(deps.len(), 2);
        let vm = deps.iter().find(|d| d.name == "victoria-metrics-k8s-stack").unwrap();
        assert_eq!(vm.version, "0.39.0");
        assert_eq!(vm.repository, "https://victoriametrics.github.io/helm-charts/");
        // flow style + a v-prefixed version (cert-manager shape) parses too.
        let flow = "dependencies:\n  - {name: cert-manager, version: \"v1.17.1\", repository: \"https://charts.jetstack.io\"}\n";
        let d = parse_deps(flow);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].name, "cert-manager");
        assert_eq!(d[0].version, "v1.17.1");
        // no deps → empty, never panics.
        assert!(parse_deps("name: x\n").is_empty());
    }
}

#[cfg(test)]
mod hermetic_mirror_tests {
    use super::{is_third_party_repo, redirect_remote_deps_to_mirror, PLEME_OCI_REGISTRY};

    #[test]
    fn classifies_third_party_repos() {
        let reg = PLEME_OCI_REGISTRY;
        // third-party: any http(s) repo, or an oci repo that is NOT the mirror.
        assert!(is_third_party_repo("https://charts.jetstack.io", reg));
        assert!(is_third_party_repo("http://example.com/charts", reg));
        assert!(is_third_party_repo("oci://ghcr.io/actions/actions-runner-controller-charts", reg));
        // NOT third-party: file:// siblings, and the mirror itself (with/without slash).
        assert!(!is_third_party_repo("file://../pleme-lib", reg));
        assert!(!is_third_party_repo("oci://ghcr.io/pleme-io/charts", reg));
        assert!(!is_third_party_repo("oci://ghcr.io/pleme-io/charts/", reg));
        assert!(!is_third_party_repo("", reg));
    }

    #[test]
    fn redirect_reroutes_third_party_keeps_file_and_drops_lock() {
        let dir = tempfile::tempdir().unwrap();
        let chart = dir.path();
        std::fs::write(
            chart.join("Chart.yaml"),
            "apiVersion: v2\nname: w\nversion: 0.1.0\ndependencies:\n  - name: pleme-lib\n    version: \">=0.18.1 <0.19.0\"\n    repository: \"file://../pleme-lib\"\n  - name: victoria-metrics-k8s-stack\n    version: \"0.39.0\"\n    repository: \"https://victoriametrics.github.io/helm-charts/\"\n",
        )
        .unwrap();
        std::fs::write(chart.join("Chart.lock"), "stale\n").unwrap();

        redirect_remote_deps_to_mirror(chart, PLEME_OCI_REGISTRY).unwrap();

        let out = std::fs::read_to_string(chart.join("Chart.yaml")).unwrap();
        let deps = super::parse_deps(&out);
        let lib = deps.iter().find(|d| d.name == "pleme-lib").unwrap();
        let vm = deps.iter().find(|d| d.name == "victoria-metrics-k8s-stack").unwrap();
        // file:// dep is left untouched; the third-party dep is rerouted to the mirror.
        assert_eq!(lib.repository, "file://../pleme-lib");
        assert_eq!(vm.repository, PLEME_OCI_REGISTRY);
        // the now-stale lock is removed so helm regenerates against the mirror.
        assert!(!chart.join("Chart.lock").exists());
    }

    #[test]
    fn redirect_is_noop_without_third_party_deps() {
        let dir = tempfile::tempdir().unwrap();
        let chart = dir.path();
        std::fs::write(
            chart.join("Chart.yaml"),
            "apiVersion: v2\nname: w\nversion: 0.1.0\ndependencies:\n  - name: pleme-lib\n    version: \">=0.18.1 <0.19.0\"\n    repository: \"file://../pleme-lib\"\n",
        )
        .unwrap();
        std::fs::write(chart.join("Chart.lock"), "keep\n").unwrap();
        redirect_remote_deps_to_mirror(chart, PLEME_OCI_REGISTRY).unwrap();
        // nothing rerouted ⇒ the lock is preserved.
        assert_eq!(std::fs::read_to_string(chart.join("Chart.lock")).unwrap(), "keep\n");
    }
}

#[cfg(test)]
mod timeout_tests {
    use super::run_program_timed;
    use std::time::Duration;

    #[test]
    fn fast_success_returns_ok_true() {
        // `true` exits 0 immediately, well within the timeout.
        assert!(run_program_timed("true", &[], Duration::from_secs(5)).unwrap());
    }

    #[test]
    fn clean_nonzero_returns_ok_false() {
        // `false` exits 1 — a clean non-zero, not a timeout-kill.
        assert!(!run_program_timed("false", &[], Duration::from_secs(5)).unwrap());
    }

    #[test]
    fn slow_process_is_killed_at_timeout() {
        // `sleep 5` cannot finish within a 1s cap — the process is killed and a
        // typed timeout error is returned (the property that stops a hung
        // upstream from wedging the release).
        let err = run_program_timed("sleep", &["5"], Duration::from_secs(1)).unwrap_err();
        assert!(err.to_string().contains("timed out"), "got: {err}");
    }
}

/// Recursively copy a chart's `file://` sibling chart dependencies into `tmp_path`
/// as flat siblings (matching helm's `file://../X` resolution from the copied
/// chart). `copied` tracks already-staged chart dir names so a dep shared by many
/// wrappers (pleme-lareira, pleme-microservice, …) is copied once and cycles
/// terminate. `chart_src` is the dep's ORIGINAL on-disk dir, so nested file://
/// deps resolve against the real charts directory.
fn stage_file_sibling_deps(
    chart_src: &Path,
    tmp_path: &Path,
    copied: &mut std::collections::HashSet<String>,
) -> Result<()> {
    let chart_yaml = chart_src.join("Chart.yaml");
    if !chart_yaml.exists() {
        return Ok(());
    }
    let content = std::fs::read_to_string(&chart_yaml)
        .with_context(|| format!("Failed to read {}", chart_yaml.display()))?;

    for rel in file_dep_paths(&content) {
        let rel_path = rel.strip_prefix("file://").unwrap_or(&rel);
        let dep_src = match chart_src.join(rel_path).canonicalize() {
            Ok(p) => p,
            Err(_) => continue, // unresolved file:// dep — let helm surface it
        };
        let Some(dep_name) = dep_src.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if copied.contains(dep_name) || !dep_src.is_dir() {
            continue;
        }
        copy_dir_recursive(&dep_src, &tmp_path.join(dep_name))
            .with_context(|| format!("Failed to copy sibling chart dep {}", dep_name))?;
        copied.insert(dep_name.to_string());
        // Recurse against the dep's ORIGINAL dir so ITS file:// siblings resolve.
        stage_file_sibling_deps(&dep_src, tmp_path, copied)?;
    }
    Ok(())
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
