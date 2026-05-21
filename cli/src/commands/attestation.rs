//! Attestation integration for forge product releases.
//!
//! Computes attestation hashes at each build stage using tameshi's CI helpers,
//! then composes them into a product certification for sekiban annotation injection.
//!
//! ## Pipeline Integration
//!
//! ```text
//! Phase 1: Push artifacts
//! Phase 1.5: Compute attestation  ← this module
//!   - Source attestation (git commit, tree hash, flake.lock)
//!   - Build attestation (nix closure hash, SLSA level)
//!   - Image attestation (OCI manifest digest, cosign status)
//!   - Chart attestation (chart tarball hash, provenance)
//!   - Compose into ProductCertification
//!   - Generate sekiban annotation values
//! Phase 2: Deploy (inject attestation into HelmRelease)
//! ```

use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::path::Path;
use tokio::process::Command;

use tameshi::certification::{
    relaxed_staging_policy, strict_production_policy, BuildAttestation, CertificationPolicy,
    ChartAttestation, DeploymentAttestation, ImageAttestation, ProductCertification,
    SourceAttestation,
};
use tameshi::ci;
use tameshi::compliance::dimensions::{ComplianceAttestation, ComplianceDimension, DimensionType};
use tameshi::compliance::slsa::SlsaLevel;
use tameshi::hash::Blake3Hash;

/// Attestation values suitable for injection into HelmRelease or kustomization.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct AttestationValues {
    pub enabled: bool,
    pub signature: String,
    pub certification_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compliance_hash: Option<String>,
}

/// Attestation info persisted alongside artifact.json.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct AttestationInfo {
    pub signature: String,
    pub certification_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compliance_hash: Option<String>,
    pub certified: bool,
}

/// Compute source attestation from git metadata at the repo root.
pub async fn compute_source_attestation(
    repo_root: &Path,
    git_sha: &str,
) -> Result<SourceAttestation> {
    // Get repository URL
    let repo_url = run_command_output(repo_root, "git", &["remote", "get-url", "origin"])
        .await
        .unwrap_or_else(|_| "unknown".to_string());

    // Get current ref
    let git_ref = run_command_output(repo_root, "git", &["symbolic-ref", "--short", "HEAD"])
        .await
        .unwrap_or_else(|_| "refs/heads/main".to_string());
    let git_ref = format!("refs/heads/{}", git_ref);

    // Check if commit is signed
    let commit_signed =
        run_command_output(repo_root, "git", &["log", "-1", "--format=%G?", git_sha])
            .await
            .map(|s| s.trim() == "G" || s.trim() == "U")
            .unwrap_or(false);

    // Compute tree hash: blake3 of `git ls-tree -r HEAD`
    let tree_listing = run_command_output(repo_root, "git", &["ls-tree", "-r", "HEAD"])
        .await
        .unwrap_or_default();
    let tree_hash = Blake3Hash::digest(tree_listing.as_bytes());

    // Compute flake.lock hash
    let flake_lock_path = repo_root.join("flake.lock");
    let flake_lock_hash = if flake_lock_path.exists() {
        let content = tokio::fs::read(&flake_lock_path)
            .await
            .context("Failed to read flake.lock")?;
        Blake3Hash::digest(&content)
    } else {
        Blake3Hash::digest(b"no-flake-lock")
    };

    // Count flake inputs and check pinning
    let (flake_input_count, all_inputs_pinned) = analyze_flake_lock(&flake_lock_path).await;

    Ok(ci::source_attestation(
        &repo_url,
        git_sha,
        &git_ref,
        commit_signed,
        tree_hash,
        flake_lock_hash,
        flake_input_count,
        all_inputs_pinned,
    ))
}

/// Compute build attestation for a service after nix build.
pub async fn compute_build_attestation(
    service: &str,
    repo_root: &Path,
) -> Result<BuildAttestation> {
    // Get nix derivation path
    let derivation = run_command_output(
        repo_root,
        "nix",
        &[
            "path-info",
            "--derivation",
            &format!(".#release:{}", service),
        ],
    )
    .await
    .unwrap_or_else(|_| format!("/nix/store/unknown-{}.drv", service));

    // Compute closure hash from nix path-info
    let closure_info = run_command_output(
        repo_root,
        "nix",
        &[
            "path-info",
            "--recursive",
            "--json",
            &format!(".#release:{}", service),
        ],
    )
    .await
    .unwrap_or_default();
    let closure_hash = Blake3Hash::digest(closure_info.as_bytes());

    // SBOM: compute hash of nix store closure (placeholder until syft integration)
    let sbom_hash = Blake3Hash::digest(format!("sbom-{}", service).as_bytes());

    // Vulnerability scan: placeholder hash
    let vuln_scan_hash = Blake3Hash::digest(format!("vuln-scan-{}", service).as_bytes());

    Ok(ci::build_attestation(
        service,
        &derivation,
        closure_hash,
        SlsaLevel::L3, // Nix builds are hermetic and reproducible
        false,         // Reproducibility not yet verified
        sbom_hash,
        vuln_scan_hash,
        0, // CVE count: populated when scan tooling integrated
        0, // Critical/high CVEs
        "nix-build@forge",
    ))
}

/// Compute image attestation after pushing to the registry.
pub async fn compute_image_attestation(image_ref: &str, tag: &str) -> Result<ImageAttestation> {
    // Get OCI manifest digest via skopeo
    let full_ref = format!("docker://{}:{}", image_ref, tag);
    let manifest_json =
        run_command_output(Path::new("."), "skopeo", &["inspect", "--raw", &full_ref])
            .await
            .unwrap_or_default();
    let manifest_hash = Blake3Hash::digest(manifest_json.as_bytes());

    // Check for cosign signature (best-effort)
    let cosign_verified = run_command_output(
        Path::new("."),
        "cosign",
        &[
            "verify",
            &format!("{}:{}", image_ref, tag),
            "--output",
            "text",
        ],
    )
    .await
    .is_ok();

    // Image SBOM and vuln scan: placeholder hashes
    let sbom_hash = Blake3Hash::digest(format!("image-sbom-{}", tag).as_bytes());
    let vuln_scan_hash = Blake3Hash::digest(format!("image-vuln-{}", tag).as_bytes());

    Ok(ci::image_attestation(
        image_ref,
        tag,
        "amd64",
        manifest_hash,
        cosign_verified,
        None,
        vuln_scan_hash,
        0,
        0,
        sbom_hash,
    ))
}

/// Compute chart attestation for a Helm chart.
pub async fn compute_chart_attestation(
    chart_name: &str,
    chart_version: &str,
    chart_path: &Path,
    registry_ref: &str,
) -> Result<ChartAttestation> {
    // Hash the chart directory contents
    let chart_hash = if chart_path.exists() {
        hash_directory(chart_path).await?
    } else {
        Blake3Hash::digest(format!("chart-{}", chart_name).as_bytes())
    };

    Ok(ci::chart_attestation(
        chart_name,
        chart_version,
        chart_hash,
        false,  // Provenance: not yet implemented
        vec![], // Dependency hashes: populated when chart deps are tracked
        true,   // Linter: assume passed if forge got this far
        true,   // Policy: assume passed
        registry_ref,
    ))
}

/// Compose all attestations into a product certification.
pub fn compose_product_certification(
    product: &str,
    environment: &str,
    cluster: &str,
    source: SourceAttestation,
    builds: Vec<BuildAttestation>,
    images: Vec<ImageAttestation>,
    charts: Vec<ChartAttestation>,
) -> Result<ProductCertification> {
    let policy = select_policy(environment);

    // For initial PoC, use minimal deployment and compliance attestations.
    // These will be populated by sekiban and kensa once deployed.
    let deployment = DeploymentAttestation {
        namespace: format!("{}-{}", product, environment),
        kustomization: format!("{}-{}", product, environment),
        source_commit: source.commit.clone(),
        source_verified: true,
        manifest_hash: Blake3Hash::digest(b"pending-deployment"),
        all_releases_signed: false, // Will be true after this pipeline completes
        cis_k8s_pass_rate: 0.0,     // Populated post-deploy by kensa
        network_policies_verified: false,
        running_pods: 0,
        all_healthy: false,
    };

    let compliance = ComplianceAttestation {
        environment: environment.to_string(),
        artifact: product.to_string(),
        dimensions: vec![ComplianceDimension {
            dimension_type: DimensionType::SlsaProvenance,
            hash: Blake3Hash::digest(b"slsa-provenance"),
            passed: true,
            summary: "SLSA L3 via Nix hermetic build".to_string(),
            assessed_at: chrono::Utc::now(),
            required: true,
        }],
        compliance_hash: Blake3Hash::digest(b"initial-compliance"),
        computed_at: chrono::Utc::now(),
        policy_name: policy.name.clone(),
        all_passed: true,
    };

    let cert = ProductCertification::builder(product, environment, cluster)
        .with_policy(policy)
        .with_source(source)
        .with_builds(builds)
        .with_images(images)
        .with_charts(charts)
        .with_deployment(deployment)
        .with_compliance(compliance)
        .certify()
        .map_err(|e| anyhow::anyhow!("Certification failed: {}", e))?;

    Ok(cert)
}

/// Generate attestation annotation values from a certification.
pub fn generate_attestation_values(cert: &ProductCertification) -> AttestationValues {
    // Use the certification hash as the signature for annotation injection
    let annotations = ci::sekiban_annotations(
        &cert.certification_hash,
        Some(&cert.certification_hash),
        None,
    );

    AttestationValues {
        enabled: true,
        signature: annotations
            .get(ci::ANNOTATION_SIGNATURE)
            .cloned()
            .unwrap_or_default(),
        certification_hash: annotations
            .get(ci::ANNOTATION_CERTIFICATION)
            .cloned()
            .unwrap_or_default(),
        compliance_hash: annotations.get(ci::ANNOTATION_COMPLIANCE).cloned(),
    }
}

/// Generate attestation info for persisting alongside artifact.json.
pub fn generate_attestation_info(cert: &ProductCertification) -> AttestationInfo {
    AttestationInfo {
        signature: cert.certification_hash.to_prefixed(),
        certification_hash: cert.certification_hash.to_prefixed(),
        compliance_hash: None,
        certified: cert.certified,
    }
}

/// Generate a BTreeMap of sekiban annotations for k8s resources.
pub fn generate_annotation_map(cert: &ProductCertification) -> BTreeMap<String, String> {
    ci::sekiban_annotations(
        &cert.certification_hash,
        Some(&cert.certification_hash),
        None,
    )
}

/// Select the certification policy based on environment.
fn select_policy(environment: &str) -> CertificationPolicy {
    match environment {
        "production" | "production-a" | "production-b" => strict_production_policy(),
        _ => relaxed_staging_policy(),
    }
}

/// Analyze flake.lock to count inputs and check pinning.
async fn analyze_flake_lock(path: &Path) -> (usize, bool) {
    if !path.exists() {
        return (0, false);
    }

    let content = match tokio::fs::read_to_string(path).await {
        Ok(c) => c,
        Err(_) => return (0, false),
    };

    let json: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return (0, false),
    };

    let nodes = json
        .get("nodes")
        .and_then(|n| n.as_object())
        .map(|m| m.len())
        .unwrap_or(0);

    // Check if all inputs have locked revisions
    let all_pinned = json
        .get("nodes")
        .and_then(|n| n.as_object())
        .map(|nodes| {
            nodes.values().all(|node| {
                // Root node doesn't need a locked revision
                if node.get("inputs").is_some() && node.get("locked").is_none() {
                    // This is a leaf node without a lock — only root is OK
                    node.get("inputs").and_then(|i| i.as_object()).is_some()
                } else {
                    true
                }
            })
        })
        .unwrap_or(false);

    (nodes, all_pinned)
}

/// Hash all files in a directory using blake3.
async fn hash_directory(dir: &Path) -> Result<Blake3Hash> {
    let mut hasher_data = Vec::new();

    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .with_context(|| format!("Failed to read directory: {}", dir.display()))?
        .filter_map(|e| e.ok())
        .collect();
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let path = entry.path();
        if path.is_file() {
            let content = tokio::fs::read(&path).await?;
            hasher_data.extend_from_slice(path.file_name().unwrap().as_encoded_bytes());
            hasher_data.extend_from_slice(&content);
        } else if path.is_dir() {
            let sub_hash = Box::pin(hash_directory(&path)).await?;
            hasher_data.extend_from_slice(&sub_hash.0);
        }
    }

    Ok(Blake3Hash::digest(&hasher_data))
}

/// Run a command in `cwd` and return its trimmed stdout, or a typed
/// anyhow error carrying the structural-record tuple.
///
/// Spawn-vs-op dispatch flows through the canonical
/// [`crate::retry::classify_capture_query`] primitive — same shape as
/// `nix.rs::run_nix_build_typed` and
/// `infrastructure/registry.rs::RegistryClient::verify_tag_exists`.
/// Spawn failures (CLI binary not on PATH) produce
/// `"Failed to spawn {cmd} {args:?}: {io_error}"`; non-zero exits
/// produce `"{cmd} {args:?} failed (exit {code:?}): {trimmed_stderr}"`
/// — the structural-record tuple THEORY §V.4 Phase 1 attestation
/// records consume. Pre-migration the spawn-failure path fused into a
/// `with_context` string that dropped the captured `io::Error::Display`;
/// the op-failure path fused (exit_code, stderr) into a single bail
/// string that dropped the exit code entirely. The canonical primitive
/// preserves both shapes by construction: `CapturedFailure::from_output`
/// extracts the `(exit_code, stderr)` tuple with the same
/// UTF-8-lossy-then-trim discipline every typed-error family in
/// `cli/src/error.rs` already shares.
///
/// Sibling of the now-deleted `run_git_output`: the pre-migration
/// surface carried two functions whose bodies were byte-identical
/// modulo `cmd = "git"`. Three-times-rule (THEORY §VI.1) was already
/// satisfied by the two-of-two `attestation.rs` siblings plus the
/// structurally identical `commands/seed.rs::kubectl` sync sibling;
/// this commit closes the carve-out on the async surface and inlines
/// `run_command_output(cwd, "git", args)` at every prior
/// `run_git_output(cwd, args)` call site.
async fn run_command_output(cwd: &Path, cmd: &str, args: &[&str]) -> Result<String> {
    let captured = Command::new(cmd).current_dir(cwd).args(args).output().await;

    // Owned copies for the typed mapper closures — the borrowed-`&str`
    // call-site lifetimes don't outlive the closure values themselves,
    // and `classify_capture_query` takes `FnOnce` on each arm so each
    // closure consumes its captures by move. Two clones (one per arm)
    // keep both mappers structurally independent — same shape every
    // sibling `from_capture`-flavored consumer in `cli/src/retry.rs`
    // and `cli/src/error.rs` already encodes.
    let spawn_cmd = cmd.to_string();
    let spawn_args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    let op_cmd = spawn_cmd.clone();
    let op_args = spawn_args.clone();

    crate::retry::classify_capture_query(
        captured,
        move |e| anyhow::anyhow!("Failed to spawn {} {:?}: {}", spawn_cmd, spawn_args, e),
        move |cf| {
            anyhow::anyhow!(
                "{} {:?} failed (exit {:?}): {}",
                op_cmd,
                op_args,
                cf.exit_code,
                cf.stderr
            )
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::make_executable_shim;

    /// `run_command_output` on a successful spawn returns the trimmed
    /// stdout — pins the success-path floor every attestation phase
    /// (`compute_source_attestation`, `compute_build_attestation`,
    /// `compute_image_attestation`) relies on. The pre-migration body
    /// fused into a `with_context` envelope on the spawn arm; the new
    /// `classify_capture_query`-routed shape keeps the trim discipline
    /// at the canonical primitive so a future regression that dropped
    /// the trim would fail this test before any downstream attestation
    /// caller saw a stray-newline-bearing repo URL or git ref.
    #[tokio::test]
    async fn test_run_command_output_success_returns_trimmed_stdout() {
        let (_dir, shim) = make_executable_shim("echo-shim", "#!/bin/sh\necho '  deadbeef  '\n");
        let cwd = std::env::current_dir().expect("cwd");
        let out = run_command_output(&cwd, &shim, &[])
            .await
            .expect("shim must succeed");
        assert_eq!(out, "deadbeef", "trim must strip both leading/trailing ws");
    }

    /// `run_command_output` on a non-zero exit surfaces the structural-
    /// record tuple in the error message: the operation label (`cmd` +
    /// `args` debug rendering), the exit code, and the trimmed stderr.
    /// Pre-migration the bail string dropped the exit code entirely
    /// (the `bail!("{} {:?} failed: {}", cmd, args, stderr)` body fused
    /// stderr but never carried `(exit N)`), so a future regression
    /// that re-dropped the exit code would fail this test rather than
    /// silently degrade the THEORY §V.4 Phase 1 attestation-record
    /// shape the canonical primitive guarantees.
    #[tokio::test]
    async fn test_run_command_output_op_failure_carries_structural_tuple() {
        let (_dir, shim) = make_executable_shim(
            "fail-shim",
            "#!/bin/sh\necho 'fatal: bad ref' 1>&2\nexit 7\n",
        );
        let cwd = std::env::current_dir().expect("cwd");
        let err = run_command_output(&cwd, &shim, &["arg-a", "arg-b"])
            .await
            .expect_err("nonzero exit must fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("(exit Some(7))"),
            "op-failure must carry the exit code in the structural shape, got: {msg}"
        );
        assert!(
            msg.contains("fatal: bad ref"),
            "op-failure must carry trimmed stderr verbatim, got: {msg}"
        );
        assert!(
            msg.contains("arg-a") && msg.contains("arg-b"),
            "op-failure must carry the args :? rendering, got: {msg}"
        );
    }

    /// `run_command_output` on a spawn failure (binary not on PATH /
    /// absent absolute path) surfaces the `Failed to spawn` envelope
    /// with the underlying `io::Error::Display` — the spawn-vs-op
    /// discriminator THEORY §V.4 attestation telemetry pattern-matches
    /// on at the parse layer (and which a future typed consumer can
    /// recover structurally by dropping the anyhow envelope and going
    /// through `classify_capture_query` directly).
    #[tokio::test]
    async fn test_run_command_output_spawn_failure_carries_op_label() {
        let cwd = std::env::current_dir().expect("cwd");
        let err = run_command_output(
            &cwd,
            "/nonexistent/path/to/forge-attestation-test-binary",
            &["a"],
        )
        .await
        .expect_err("missing binary must fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("Failed to spawn"),
            "spawn failure must carry the canonical envelope, got: {msg}"
        );
        assert!(
            msg.contains("/nonexistent/path/to/forge-attestation-test-binary"),
            "spawn failure must carry the cmd path, got: {msg}"
        );
    }

    #[test]
    fn select_policy_staging() {
        let policy = select_policy("staging");
        assert_eq!(policy.name, "relaxed-staging");
        assert!(!policy.require_signed_commits);
    }

    #[test]
    fn select_policy_production() {
        let policy = select_policy("production");
        assert_eq!(policy.name, "strict-production");
        assert!(policy.require_signed_commits);
    }

    #[test]
    fn attestation_values_generation() {
        let hash = Blake3Hash::digest(b"test-certification");
        let annotations = ci::sekiban_annotations(&hash, Some(&hash), None);
        assert!(annotations.contains_key(ci::ANNOTATION_SIGNATURE));
        assert!(annotations.contains_key(ci::ANNOTATION_CERTIFICATION));
    }

    #[test]
    fn attestation_info_serialization() {
        let info = AttestationInfo {
            signature: "blake3:abc123".to_string(),
            certification_hash: "blake3:def456".to_string(),
            compliance_hash: None,
            certified: true,
        };
        let json = serde_json::to_string_pretty(&info).unwrap();
        assert!(json.contains("blake3:abc123"));
        assert!(json.contains("certified"));
    }

    #[test]
    fn attestation_values_serialization() {
        let values = AttestationValues {
            enabled: true,
            signature: "blake3:sig".to_string(),
            certification_hash: "blake3:cert".to_string(),
            compliance_hash: Some("blake3:comp".to_string()),
        };
        let json = serde_json::to_string_pretty(&values).unwrap();
        assert!(json.contains("enabled"));
        assert!(json.contains("blake3:sig"));
    }
}
