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
use tameshi::compliance::slsa::{determine_slsa_level, SlsaLevel};
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

/// Derive the SLSA level for a Nix build from the evidence actually
/// collected, rather than asserting a fixed level.
///
/// `compute_build_attestation` previously hardcoded [`SlsaLevel::L3`]
/// while recording `reproducible: false` — a self-contradiction, since L3
/// is the *reproducible*, hardened-build grade. Worse, when `nix
/// path-info` failed the closure JSON was swallowed to empty and the
/// derivation to the `/nix/store/unknown-*` fallback, yet the build still
/// claimed L3: an attestation asserting hermetic provenance it never
/// gathered. This routes the level through tameshi's own
/// [`determine_slsa_level`] rubric over honest inputs:
///
/// - **provenance** exists only when the closure JSON is non-empty *and*
///   the derivation is a real store path (not the `unknown-*` I/O-error
///   fallback). Without it there is nothing to attest → `L0`.
/// - forge drives the build on a hosted Nix builder inside the sandbox,
///   so **hosted** and **hermetic** hold exactly when provenance was
///   collected.
/// - **reproducible** is threaded from the caller; until reproducibility
///   is independently re-verified it is `false`, so a fully-substantiated
///   build tops out at `L2`, never the L3 it cannot yet back.
///
/// Two-person review is not modelled (`false`), so `L4` is unreachable.
/// Mirrors the `summarize_flake_lock` honesty fix: an attestation must
/// not claim a guarantee its inputs do not substantiate.
fn build_slsa_level(derivation: &str, closure_info: &str, reproducible: bool) -> SlsaLevel {
    let has_provenance =
        !closure_info.trim().is_empty() && !derivation.starts_with("/nix/store/unknown-");
    determine_slsa_level(
        has_provenance,
        has_provenance,
        has_provenance,
        reproducible,
        false,
    )
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

    // Reproducibility is not independently re-verified yet; until it is,
    // the build cannot honestly claim the reproducible-grade SLSA level.
    // The level is derived from the evidence actually collected, so a
    // build whose closure could not be materialized claims nothing.
    let reproducible = false;
    let slsa_level = build_slsa_level(&derivation, &closure_info, reproducible);

    Ok(ci::build_attestation(
        service,
        &derivation,
        closure_hash,
        slsa_level,
        reproducible,
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

/// Derive the product-level SLSA-provenance compliance dimension from the
/// build attestations actually collected, rather than asserting a fixed
/// `"SLSA L3 via Nix hermetic build"` claim.
///
/// This is the same honesty fix as [`build_slsa_level`], one layer up:
/// `compute_build_attestation` now rates each build's `slsa_level` from
/// the evidence it gathered (L0 / L2 / L3), but the compliance dimension
/// composed into the certification still hardcoded `passed: true` and an
/// `"SLSA L3"` summary regardless. A product is only as
/// hermetically-provenanced as its *weakest* build, so the effective level
/// is the **minimum** [`SlsaLevel`] across `builds`; a product with no
/// builds has no provenance to attest (`L0`). The dimension passes iff that
/// effective level meets `policy.min_slsa_level` — the same floor
/// `evaluate_build` enforces per build — so the compliance claim cannot
/// assert a grade the builds do not substantiate (THEORY §V.2: attestation
/// is evidence, not a wish).
fn slsa_compliance_dimension(
    builds: &[BuildAttestation],
    policy: &CertificationPolicy,
) -> ComplianceDimension {
    let effective = builds
        .iter()
        .map(|b| b.slsa_level.clone())
        .min()
        .unwrap_or(SlsaLevel::L0);
    let passed = effective >= policy.min_slsa_level;
    let summary = if builds.is_empty() {
        format!(
            "no builds attested; SLSA provenance unsubstantiated (< required {})",
            policy.min_slsa_level
        )
    } else {
        format!(
            "{} (min across {} build(s)) {} required {}",
            effective,
            builds.len(),
            if passed { ">=" } else { "<" },
            policy.min_slsa_level
        )
    };
    ComplianceDimension {
        dimension_type: DimensionType::SlsaProvenance,
        hash: Blake3Hash::digest(summary.as_bytes()),
        passed,
        summary,
        assessed_at: chrono::Utc::now(),
        required: true,
    }
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

    let slsa_dimension = slsa_compliance_dimension(&builds, &policy);
    let all_passed = slsa_dimension.passed;
    let compliance = ComplianceAttestation {
        environment: environment.to_string(),
        artifact: product.to_string(),
        dimensions: vec![slsa_dimension],
        compliance_hash: Blake3Hash::digest(b"initial-compliance"),
        computed_at: chrono::Utc::now(),
        policy_name: policy.name.clone(),
        all_passed,
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

/// Pinning summary derived from a parsed `flake.lock`.
///
/// `all_inputs_pinned` is the hermeticity claim that flows into the SLSA
/// source attestation (THEORY §V.4 Phase 1 source record, §I.1 beat 5):
/// a flake input counts as *pinned* only when its lock node carries a
/// content-addressed `narHash`. That hash is what makes the input
/// byte-reproducible (THEORY §VI.1: "regenerating an artifact produces a
/// byte-identical result given the same inputs") and content-addressable
/// (THEORY §III.1.7 render state). An unpinned input breaks the
/// determinism the SLSA L3 build claim rests on, so the attestation must
/// not assert pinning when it does not hold.
///
/// Named fields rather than a bare `(usize, bool)` tuple so the
/// positional meaning of the count and the pinning flag cannot be
/// transposed at the call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FlakeLockSummary {
    /// Number of locked nodes in the `flake.lock` graph (root included),
    /// the same proxy `flake_input_count` carried before.
    input_count: usize,
    /// True iff every non-root node carries a non-empty `narHash`.
    all_inputs_pinned: bool,
}

impl FlakeLockSummary {
    /// The summary for an absent / unreadable / malformed lock: zero
    /// inputs, not pinned. Pinning defaults to `false` so a missing or
    /// corrupt lock can never silently inflate the hermeticity claim.
    const UNPINNED_EMPTY: Self = Self {
        input_count: 0,
        all_inputs_pinned: false,
    };
}

/// Parse `flake.lock` JSON and summarize its pinning state.
///
/// A node is *pinned* iff its `locked` object carries a non-empty
/// `narHash` string — the content hash CppNix/sui write for every locked
/// input (github / git / tarball / path alike) and the one field that
/// makes the input reproducible. The root node (the flake itself, named
/// by the top-level `root` key, conventionally `"root"`) carries no
/// `locked` section and is exempt. `follows` redirections are encoded in
/// the referencing node's `inputs` as array paths, not as separate
/// lock-less nodes, so every non-root node is expected to carry a lock;
/// one that does not is an unpinned input and fails the claim.
///
/// Returns [`FlakeLockSummary::UNPINNED_EMPTY`] when the JSON is
/// malformed or has no `nodes` object — a lock we cannot read cannot
/// substantiate a pinning claim.
fn summarize_flake_lock(content: &str) -> FlakeLockSummary {
    let json: serde_json::Value = match serde_json::from_str(content) {
        Ok(v) => v,
        Err(_) => return FlakeLockSummary::UNPINNED_EMPTY,
    };
    let Some(nodes) = json.get("nodes").and_then(|n| n.as_object()) else {
        return FlakeLockSummary::UNPINNED_EMPTY;
    };
    let root = json.get("root").and_then(|r| r.as_str()).unwrap_or("root");
    let all_inputs_pinned = nodes.iter().all(|(name, node)| {
        if name == root {
            return true;
        }
        node.get("locked")
            .and_then(|l| l.get("narHash"))
            .and_then(|h| h.as_str())
            .is_some_and(|h| !h.is_empty())
    });
    FlakeLockSummary {
        input_count: nodes.len(),
        all_inputs_pinned,
    }
}

/// Analyze flake.lock to count inputs and check pinning. I/O wrapper over
/// the pure [`summarize_flake_lock`]; an absent or unreadable file yields
/// the unpinned-empty summary.
async fn analyze_flake_lock(path: &Path) -> (usize, bool) {
    if !path.exists() {
        return (0, false);
    }
    let summary = match tokio::fs::read_to_string(path).await {
        Ok(content) => summarize_flake_lock(&content),
        Err(_) => FlakeLockSummary::UNPINNED_EMPTY,
    };
    (summary.input_count, summary.all_inputs_pinned)
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
/// Async sibling of `commands/seed.rs::run_command_output`. Both
/// shape-adapt for [`crate::retry::classify_capture_query_anyhow`] —
/// the canonical "anyhow envelope over a queried external CLI"
/// primitive — at the async (`tokio::process::Command`) and sync
/// (`std::process::Command`) spawn surfaces respectively. The
/// `io::Result<std::process::Output>` post-spawn shape is sync/async-
/// agnostic, so the classifier and the mapper-pair body
/// (`"Failed to spawn {cmd} {args:?}: {io}"` /
/// `"{cmd} {args:?} failed (exit {code:?}): {stderr}"`) live once
/// at the typed primitive; this shape-adapter just builds the
/// `io::Result<Output>` from the async surface (`cwd`-anchored
/// `tokio::process::Command::output().await`) and delegates. The
/// `(exit_code, stderr)` tuple THEORY §V.4 Phase 1 attestation
/// records pattern-match on is preserved by construction.
async fn run_command_output(cwd: &Path, cmd: &str, args: &[&str]) -> Result<String> {
    crate::retry::classify_capture_query_anyhow(
        Command::new(cmd).current_dir(cwd).args(args).output().await,
        cmd,
        args,
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

    /// A well-formed v7 lock whose every non-root node carries a
    /// `narHash` is fully pinned, and the count includes the root node.
    #[test]
    fn test_summarize_flake_lock_all_pinned_true() {
        let lock = r#"{
            "nodes": {
                "root": { "inputs": { "nixpkgs": "nixpkgs", "flake-utils": "flake-utils" } },
                "nixpkgs": {
                    "locked": { "narHash": "sha256-aaa", "rev": "deadbeef", "type": "github" },
                    "original": { "owner": "NixOS", "repo": "nixpkgs", "type": "github" }
                },
                "flake-utils": {
                    "inputs": { "systems": "systems" },
                    "locked": { "narHash": "sha256-bbb", "rev": "cafef00d", "type": "github" }
                },
                "systems": {
                    "locked": { "narHash": "sha256-ccc", "rev": "1234abcd", "type": "github" }
                }
            },
            "root": "root",
            "version": 7
        }"#;
        let s = summarize_flake_lock(lock);
        assert_eq!(s.input_count, 4, "count includes root + 3 dep nodes");
        assert!(
            s.all_inputs_pinned,
            "every non-root node carries a narHash, so the lock is fully pinned"
        );
    }

    /// A non-root node that carries a `locked` block WITHOUT a `narHash`
    /// is unpinned, so the hermeticity claim must be `false`. This is the
    /// load-bearing regression pin: the prior check returned `true` for
    /// every node shape (a node with `inputs` and no `locked` returned
    /// `inputs.is_object()` == true; every other node returned `true`
    /// unconditionally), so `all_inputs_pinned` was effectively a
    /// constant `true` whenever the lock had any nodes — silently
    /// inflating the SLSA source attestation's pinning claim
    /// (THEORY §V.4 Phase 1). With that buggy logic this assertion
    /// fails; with the narHash check it passes.
    #[test]
    fn test_summarize_flake_lock_unpinned_node_is_false() {
        let lock = r#"{
            "nodes": {
                "root": { "inputs": { "nixpkgs": "nixpkgs", "loose": "loose" } },
                "nixpkgs": {
                    "locked": { "narHash": "sha256-aaa", "rev": "deadbeef", "type": "github" }
                },
                "loose": {
                    "locked": { "rev": "no-narhash-here", "type": "git" },
                    "original": { "type": "git", "url": "https://example.invalid/x" }
                }
            },
            "root": "root",
            "version": 7
        }"#;
        let s = summarize_flake_lock(lock);
        assert_eq!(s.input_count, 3);
        assert!(
            !s.all_inputs_pinned,
            "the `loose` node has a locked block but no narHash, so the lock is not pinned"
        );
    }

    /// A non-root node with `inputs` but no `locked` at all is unpinned —
    /// the prior logic's exact false-positive path (it special-cased this
    /// shape to `true`, treating any lock-less node as an honorary root).
    #[test]
    fn test_summarize_flake_lock_lockless_non_root_node_is_false() {
        let lock = r#"{
            "nodes": {
                "root": { "inputs": { "dangling": "dangling" } },
                "dangling": { "inputs": { "x": "x" } },
                "x": { "locked": { "narHash": "sha256-xxx", "type": "github" } }
            },
            "root": "root",
            "version": 7
        }"#;
        let s = summarize_flake_lock(lock);
        assert!(
            !s.all_inputs_pinned,
            "a non-root node with inputs but no locked block is an unpinned input"
        );
    }

    /// The root node is identified by the top-level `root` key, not by the
    /// literal name "root". A custom root name must still be exempted from
    /// the narHash requirement.
    #[test]
    fn test_summarize_flake_lock_respects_custom_root_name() {
        let lock = r#"{
            "nodes": {
                "self": { "inputs": { "nixpkgs": "nixpkgs" } },
                "nixpkgs": { "locked": { "narHash": "sha256-aaa", "type": "github" } }
            },
            "root": "self",
            "version": 7
        }"#;
        let s = summarize_flake_lock(lock);
        assert!(
            s.all_inputs_pinned,
            "the custom-named root carries no lock but must be exempt"
        );
    }

    /// Malformed JSON and a JSON object with no `nodes` both yield the
    /// unpinned-empty summary — a lock we cannot read cannot substantiate
    /// a pinning claim, so the default is the conservative `false`.
    #[test]
    fn test_summarize_flake_lock_malformed_is_unpinned_empty() {
        assert_eq!(
            summarize_flake_lock("not json at all {{{"),
            FlakeLockSummary::UNPINNED_EMPTY
        );
        assert_eq!(
            summarize_flake_lock(r#"{"version": 7}"#),
            FlakeLockSummary::UNPINNED_EMPTY,
            "no nodes object means no substantiated pinning claim"
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

    /// A build whose closure could not be materialized — `nix path-info`
    /// failed, so the derivation is the `/nix/store/unknown-*` fallback
    /// and the closure JSON is empty — has no provenance to attest and
    /// must rate `L0`. Fail-before: the prior body hardcoded `L3` here
    /// regardless of whether any closure evidence was collected, minting
    /// a hermetic-provenance claim for a build that never produced one.
    #[test]
    fn test_build_slsa_level_unsubstantiated_build_is_l0() {
        let level = build_slsa_level("/nix/store/unknown-mysvc.drv", "", false);
        assert_eq!(
            level,
            SlsaLevel::L0,
            "no closure + unknown derivation = no provenance = L0"
        );
    }

    /// A real derivation path but an empty closure JSON (the recursive
    /// `path-info` failed while the `--derivation` probe happened to
    /// succeed) is still unsubstantiated: provenance requires the closure
    /// the hermeticity claim hashes over.
    #[test]
    fn test_build_slsa_level_empty_closure_is_l0() {
        let level = build_slsa_level("/nix/store/abc123-mysvc.drv", "", false);
        assert_eq!(level, SlsaLevel::L0, "empty closure = no provenance = L0");
    }

    /// Whitespace-only closure output (a tool that emitted only a trailing
    /// newline) is treated as empty — the `trim()` guard prevents a blank
    /// line from inflating the provenance claim.
    #[test]
    fn test_build_slsa_level_whitespace_closure_is_l0() {
        let level = build_slsa_level("/nix/store/abc123-mysvc.drv", "  \n\t ", false);
        assert_eq!(
            level,
            SlsaLevel::L0,
            "whitespace-only closure trims to empty"
        );
    }

    /// A fully-substantiated build — real derivation, non-empty closure —
    /// that is NOT independently re-verified for reproducibility tops out
    /// at `L2`, the hosted+hermetic-but-not-reproducible grade. This is
    /// the load-bearing correction: the prior code claimed `L3` (the
    /// reproducible grade) while simultaneously recording
    /// `reproducible: false`, a self-contradiction the attestation must
    /// not carry.
    #[test]
    fn test_build_slsa_level_substantiated_nonreproducible_is_l2() {
        let level = build_slsa_level(
            "/nix/store/abc123-mysvc.drv",
            r#"[{"path":"/nix/store/abc123-mysvc","narHash":"sha256-x"}]"#,
            false,
        );
        assert_eq!(
            level,
            SlsaLevel::L2,
            "hermetic but not reproducibility-verified = L2, not the prior false L3"
        );
    }

    /// The level still reaches `L3` when it is honestly earned: a
    /// substantiated build whose reproducibility HAS been verified. Pins
    /// that the honesty fix narrows the claim to the evidence rather than
    /// capping it below what a reproducible build deserves.
    #[test]
    fn test_build_slsa_level_substantiated_reproducible_is_l3() {
        let level = build_slsa_level(
            "/nix/store/abc123-mysvc.drv",
            r#"[{"path":"/nix/store/abc123-mysvc","narHash":"sha256-x"}]"#,
            true,
        );
        assert_eq!(
            level,
            SlsaLevel::L3,
            "substantiated + reproducible-verified earns L3"
        );
    }

    /// Build a `BuildAttestation` carrying a chosen SLSA level; the other
    /// fields are irrelevant to `slsa_compliance_dimension`.
    fn build_at(service: &str, level: SlsaLevel) -> BuildAttestation {
        let h = Blake3Hash::digest(service.as_bytes());
        ci::build_attestation(
            service,
            &format!("/nix/store/abc-{service}.drv"),
            h.clone(),
            level,
            false,
            h.clone(),
            h,
            0,
            0,
            "nix-build@forge",
        )
    }

    /// A product with no build attestations has no provenance to attest, so
    /// the SLSA-provenance dimension rates `L0` and fails any policy with a
    /// non-`L0` floor. Fail-before: the prior body hardcoded `passed: true`
    /// and an `"SLSA L3"` summary regardless of whether any build existed.
    #[test]
    fn test_slsa_compliance_dimension_no_builds_is_unsubstantiated() {
        let dim = slsa_compliance_dimension(&[], &relaxed_staging_policy());
        assert!(
            !dim.passed,
            "no builds = no provenance = L0 < staging floor L2"
        );
        assert!(
            dim.summary.contains("unsubstantiated"),
            "summary must name the missing provenance, got: {}",
            dim.summary
        );
    }

    /// A product whose builds all meet the staging floor passes, and the
    /// summary reports the honest effective (minimum) level — not the
    /// hardcoded `"SLSA L3"` the prior body always emitted.
    #[test]
    fn test_slsa_compliance_dimension_meets_floor_passes() {
        let builds = [
            build_at("backend", SlsaLevel::L3),
            build_at("web", SlsaLevel::L2),
        ];
        let dim = slsa_compliance_dimension(&builds, &relaxed_staging_policy());
        assert!(dim.passed, "min L2 >= staging floor L2");
        assert!(
            dim.summary.contains("SLSA L2") && dim.summary.contains(">="),
            "summary must report the effective (min) level L2, got: {}",
            dim.summary
        );
    }

    /// The load-bearing correction: a product containing an `L2` build under
    /// a policy requiring `L3` must FAIL the SLSA-provenance dimension. The
    /// prior body asserted `passed: true` and `"SLSA L3 via Nix hermetic
    /// build"` here — a false compliance record claiming a grade the weakest
    /// build does not substantiate. The product is only as
    /// hermetically-provenanced as its weakest component.
    #[test]
    fn test_slsa_compliance_dimension_weakest_build_below_floor_fails() {
        let builds = [
            build_at("backend", SlsaLevel::L3),
            build_at("web", SlsaLevel::L2),
        ];
        let dim = slsa_compliance_dimension(&builds, &strict_production_policy());
        assert!(
            !dim.passed,
            "min across builds is L2 < production floor L3, so the dimension must fail"
        );
        assert!(
            dim.summary.contains("SLSA L2") && dim.summary.contains('<'),
            "summary must report the failing effective level L2 < required L3, got: {}",
            dim.summary
        );
    }

    /// `compose_product_certification` threads the dimension's `passed` into
    /// `all_passed`: a single substantiated build meeting the floor yields a
    /// passing compliance attestation carrying the honest summary.
    #[test]
    fn test_compose_propagates_honest_compliance() {
        let source = ci::source_attestation(
            "https://example.invalid/repo",
            "deadbeef",
            "refs/heads/main",
            false,
            Blake3Hash::digest(b"tree"),
            Blake3Hash::digest(b"lock"),
            1,
            true,
        );
        let cert = compose_product_certification(
            "myproduct",
            "staging",
            "plo",
            source,
            vec![build_at("backend", SlsaLevel::L2)],
            vec![],
            vec![],
        )
        .expect("certification composes");
        assert!(
            cert.compliance.all_passed,
            "L2 meets the staging floor, so compliance passes"
        );
        let dim = &cert.compliance.dimensions[0];
        assert!(
            dim.passed && dim.summary.contains("SLSA L2"),
            "the composed dimension carries the honest effective level, got: {}",
            dim.summary
        );
    }
}
