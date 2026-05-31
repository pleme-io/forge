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

    // Get current ref: prefer a branch HEAD via `symbolic-ref`, fall back
    // to an exact tag match on HEAD, then to the SHA itself when HEAD is
    // detached at no named ref (the GitHub-Actions default checkout
    // state). `git describe --exact-match --tags` is only spawned when the
    // branch probe failed — common case is a branch HEAD and we keep one
    // git invocation.
    let branch_probe = run_command_output(repo_root, "git", &["symbolic-ref", "--short", "HEAD"])
        .await
        .ok();
    let tag_probe = if branch_probe.is_none() {
        run_command_output(
            repo_root,
            "git",
            &["describe", "--exact-match", "--tags", "HEAD"],
        )
        .await
        .ok()
    } else {
        None
    };
    let git_ref = resolve_source_ref(branch_probe.as_deref(), tag_probe.as_deref(), git_sha);

    // `git log -1 --format=%G?` against a commit reports one of eight
    // single-character codes documented in git-log(1) — `G` (good and
    // trusted), `U` (good, unknown trust path), `X` (good but signature
    // expired), `Y` (good but key expired), `R` (good but key revoked),
    // `B` (bad signature — cryptographic verification failed), `E`
    // (signature cannot be checked, missing key), `N` (no signature).
    // The prior `.map(|s| s.trim() == "G" || s.trim() == "U")
    // .unwrap_or(false)` fold flattened all nine operational worlds
    // (the eight codes plus the probe-failed world) into a single bool,
    // silently routing `B` (evidence of compromise — cryptographic
    // verification failed) into the same bucket as `N` (no signature
    // ever) and into the same bucket as the probe-failed world. A
    // downstream verifier reading `commit_signed: false` on the
    // Phase 1 source attestation could not distinguish "no probe ran"
    // from "operator chose not to sign" from "signature failed
    // cryptographic verification" — the load-bearing
    // evidence-of-compromise discriminator `B` carries was lost
    // (THEORY §V.2: attestation is cryptographic evidence, not a
    // wish; a bool that flattens "no evidence" and "evidence of
    // compromise" cannot substantiate either claim). The typed
    // `GitCommitSignatureOutcome` (nine arms over the eight `%G?`
    // codes plus `ProbeAbsent`) preserves each world structurally;
    // `is_signed()` collapses to the pre-fix bool semantics exactly
    // (`G` and `U` → `true`, every other arm → `false`), so this
    // is a pure honesty refactor at the bool surface and an
    // arm-distinguishing widening at the type surface a future
    // enrichment commit can route into a richer `signature_verdict`
    // field on `SourceAttestation`. Same shape as commit c1e83d5
    // (`KensaPolicyOutcome` for chart-policy), commit d81f639
    // (`HelmLintOutcome` for chart-quality), and commit 0ff67e1
    // (`CosignVerifyOutcome` for image-signature).
    let commit_signed =
        run_command_output(repo_root, "git", &["log", "-1", "--format=%G?", git_sha])
            .await
            .map(|s| crate::git_signature::GitCommitSignatureOutcome::from_format_code(&s))
            .unwrap_or(crate::git_signature::GitCommitSignatureOutcome::ProbeAbsent)
            .is_signed();

    // Compute tree hash from `git ls-tree -r HEAD`. Two honesty
    // disciplines apply, mirroring `flake_lock_hash` above:
    //   * A probe failure (no git on PATH, no HEAD, I/O error) routes
    //     through the explicit `b"no-tree-listing"` sentinel — never
    //     silent `Blake3Hash::digest(b"")`, which would stamp the
    //     constant blake3-of-empty into every Phase 1 source
    //     attestation as the source-tree identity. Mirrors the
    //     `b"no-flake-lock"` sentinel used for the absent-flake case.
    //   * A successful probe is hashed over its canonical
    //     content-addressed fingerprint (the sorted, deduplicated set
    //     of validated `(mode, type, hash, path)` entries) rather than
    //     the raw bytes, so the tree hash cannot drift on git output
    //     formatting alone for a byte-identical tree (THEORY §VI.1).
    let tree_hash = match run_command_output(repo_root, "git", &["ls-tree", "-r", "HEAD"]).await {
        Ok(listing) => {
            Blake3Hash::digest(crate::tree_listing::canonical_tree_fingerprint(&listing).as_bytes())
        }
        Err(_) => Blake3Hash::digest(b"no-tree-listing"),
    };

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

/// Resolve the symbolic ref the working tree's HEAD points at into the
/// refspec string the SLSA source attestation's `git_ref` field carries.
///
/// Pure function over the two git probe results so each fallback arm is
/// unit-testable without spawning git. The probe ladder mirrors how a
/// supply-chain verifier reads a source provenance record: prefer a named
/// branch (`refs/heads/<name>`), accept an exact tag match
/// (`refs/tags/<name>`) on a detached-HEAD tag checkout, and as the
/// honest last resort record the bare commit SHA — never silently
/// synthesize a branch name the build did not actually come from.
///
/// The pre-fix path swallowed `symbolic-ref` failure to the literal string
/// `"refs/heads/main"` and then wrapped it with `format!("refs/heads/{}",
/// _)`, producing the malformed `"refs/heads/refs/heads/main"` on every
/// detached HEAD (the GitHub-Actions default checkout state) and on every
/// tag checkout. Both arms are dishonest twice over: a Phase 1 source
/// attestation (THEORY §V.4) cannot truthfully claim the build came from
/// `refs/heads/main` when it does not know the ref, and the doubled
/// prefix is not a parseable refname for any consumer to recover from.
///
/// `branch` is the trimmed stdout of `git symbolic-ref --short HEAD`
/// (e.g. `"main"`, `"feature/foo-bar"`); `None` or whitespace-only marks
/// the probe as failed. `tag` is the trimmed stdout of `git describe
/// --exact-match --tags HEAD` (e.g. `"v1.0.0"`); same emptiness rule.
/// `sha` is the commit SHA the caller already resolved — it never falls
/// back to a synthetic ref. The branch arm wins over the tag arm when
/// both probe successfully (a tagged commit on a branch HEAD is most
/// semantically described by the branch the operator is on).
fn resolve_source_ref(branch: Option<&str>, tag: Option<&str>, sha: &str) -> String {
    if let Some(b) = branch {
        let b = b.trim();
        if !b.is_empty() {
            return format!("refs/heads/{b}");
        }
    }
    if let Some(t) = tag {
        let t = t.trim();
        if !t.is_empty() {
            return format!("refs/tags/{t}");
        }
    }
    sha.trim().to_string()
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
///   the derivation parses as a well-formed, content-addressed Nix store
///   *derivation* path via [`crate::store_path::StorePath`]. The prior gate
///   asked the negative question `!derivation.starts_with("/nix/store/
///   unknown-")`, recognising only the one `unknown-*` I/O-error sentinel
///   and silently treating an empty, relative, or otherwise malformed
///   derivation as if it carried provenance. The positive grammar accepts
///   a derivation iff its 32-char base-32 content hash — the hermetic
///   fingerprint the provenance claim rests on — is actually present.
///   Without provenance there is nothing to attest → `L0`.
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
    let derivation_is_real = crate::store_path::StorePath::parse(derivation)
        .map(|p| p.is_derivation())
        .unwrap_or(false);
    let has_provenance = !closure_info.trim().is_empty() && derivation_is_real;
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
    // Hash the closure's canonical content-addressed fingerprint — the
    // sorted, deduplicated set of store-object content hashes — rather than
    // the raw `path-info` document, whose `registrationTime`, signatures,
    // and path ordering drift run-to-run for a byte-identical closure and
    // would otherwise make this hermeticity hash irreproducible.
    let closure_hash = Blake3Hash::digest(
        crate::store_path::canonical_closure_fingerprint(&closure_info).as_bytes(),
    );

    // SBOM and vulnerability-scan claims for the build artifact route
    // through the typed `crate::security_scan` probe outcomes. No syft /
    // grype probe layer is integrated yet, so both currently take the
    // `Absent` arm — the attestation field collapses to the explicit
    // `Blake3Hash::digest(b"no-sbom")` / `Blake3Hash::digest(
    // b"no-vuln-scan")` sentinels, and the CVE counts collapse to
    // `(0, 0)` honestly ("no evidence collected", never "real scan
    // found zero"). The prior `Blake3Hash::digest(format!("sbom-{}",
    // service))` / `format!("vuln-scan-{}", service)` per-service
    // constants stamped a deterministic-but-name-derived hash into
    // every Phase 1 build record as SBOM / vuln-scan evidence even
    // when no probe layer existed, false by construction (THEORY §V.2:
    // attestation is cryptographic evidence, not a wish). When a syft
    // / grype probe is wired in, only the typed-outcome constructor
    // changes (Absent → Collected { hash, ... }); the call-site shape
    // and the triple-from-one-source discipline survive — mirrors the
    // cosign / helm-provenance / oci-architecture typed-outcome arcs.
    let sbom_outcome = crate::security_scan::SbomProbeOutcome::Absent;
    let vuln_scan_outcome = crate::security_scan::VulnScanProbeOutcome::Absent;
    let sbom_hash = sbom_outcome.to_attestation_hash();
    let (vuln_scan_hash, cve_count, critical_high_cves) = vuln_scan_outcome.to_attestation_fields();

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
        cve_count,
        critical_high_cves,
        "nix-build@forge",
    ))
}

/// Compute image attestation after pushing to the registry.
pub async fn compute_image_attestation(image_ref: &str, tag: &str) -> Result<ImageAttestation> {
    // Get OCI manifest digest via skopeo. Two honesty disciplines apply,
    // mirroring `tree_hash` / `flake_lock_hash` / closure_hash above:
    //   * A probe failure (skopeo not on PATH, registry 404, network
    //     error, auth refusal) routes through the explicit `b"no-manifest"`
    //     sentinel — never silent `Blake3Hash::digest(b"")`, which would
    //     stamp the constant blake3-of-empty into every Phase 1 image
    //     attestation as the OCI manifest identity. Mirrors the
    //     `b"no-tree-listing"` and `b"no-flake-lock"` sentinels used at
    //     the source-attestation layer.
    //   * A successful probe is hashed over its canonical content-
    //     addressed fingerprint (the sorted, deduplicated set of
    //     role-prefixed config / layer / manifest / fsLayer digests)
    //     rather than the raw bytes, so the manifest hash cannot drift on
    //     registry-side JSON formatting, key ordering, mutable
    //     `annotations`, or the manifest-format negotiation skopeo may
    //     have driven via Accept headers (THEORY §VI.1).
    // The same `skopeo inspect --raw` JSON drives two typed primitives:
    // `oci_manifest::canonical_manifest_fingerprint` → manifest_hash, and
    // `oci_architecture::parse_manifest_architectures` → architecture.
    // Both must collapse to a probe-failed sentinel on the Err arm so the
    // attestation does not silently inflate either claim. The pre-fix
    // `architecture: "amd64"` hardcode is the dishonesty this branch
    // closes; see the module docs on `crate::oci_architecture` for the
    // five operational worlds it preserves (Single / Multi / EmbeddedInConfig
    // / Absent, plus the v1 explicit case).
    let full_ref = format!("docker://{}:{}", image_ref, tag);
    let (manifest_hash, architecture) = match run_command_output(
        Path::new("."),
        "skopeo",
        &["inspect", "--raw", &full_ref],
    )
    .await
    {
        Ok(json) => {
            let hash = Blake3Hash::digest(
                crate::oci_manifest::canonical_manifest_fingerprint(&json).as_bytes(),
            );
            let arch =
                crate::oci_architecture::parse_manifest_architectures(&json).to_attestation_arch();
            (hash, arch)
        }
        Err(_) => (
            Blake3Hash::digest(b"no-manifest"),
            crate::oci_architecture::OciArchitectureOutcome::Absent.to_attestation_arch(),
        ),
    };

    // Probe cosign for an image-signature receipt. Three operational
    // worlds, all conflated by the prior `is_ok()` fold: probe-absent
    // (cosign not on PATH), verify-failed (cosign returned non-zero),
    // verified-with-payload (cosign returned exit 0 with a structured
    // `SimpleContainerImage` envelope). The typed primitive
    // `cosign::CosignVerifyOutcome` preserves the four-arm distinction
    // (Verified / Unverified / VerifyFailed / ProbeAbsent), and the
    // call site routes through `classify_capture_query` so the
    // spawn-vs-op discriminator survives at the type level rather than
    // being recovered by string-parsing an anyhow envelope. The Phase
    // 1 `cosign_verified` bool is computed by
    // `CosignVerifyOutcome::is_verified` over the typed shape — the
    // empty-array case (`[]`, exit 0) that the prior fold incorrectly
    // reported `true` for now collapses to `Unverified`. The signer
    // identity recovered from the receipt populates the
    // `ImageAttestation::signer_identity` field, which previously
    // hardcoded `None` because the boolean fold had nowhere to recover
    // it from (THEORY §V.4 Phase 1: every claim a typed primitive can
    // populate must be populated honestly, not stubbed).
    let cosign_image_ref = format!("{}:{}", image_ref, tag);
    let cosign_captured = Command::new("cosign")
        .current_dir(Path::new("."))
        .args(["verify", &cosign_image_ref, "--output", "json"])
        .output()
        .await;
    let cosign_outcome =
        match crate::retry::classify_capture_query::<crate::cosign::CosignVerifyOutcome, _, _>(
            cosign_captured,
            |_io_err| crate::cosign::CosignVerifyOutcome::ProbeAbsent,
            |_captured| crate::cosign::CosignVerifyOutcome::VerifyFailed,
        ) {
            Ok(stdout) => crate::cosign::parse_verify_output(&stdout),
            Err(outcome) => outcome,
        };
    let cosign_verified = cosign_outcome.is_verified();
    let signer_identity = cosign_outcome.signer_identity().map(String::from);

    // Image SBOM and vuln-scan claims route through the same typed
    // `crate::security_scan` probe outcomes as `compute_build_
    // attestation` — one typed primitive, two artifact kinds
    // (build closure / container image), one honest sentinel per kind
    // when no probe layer is integrated. The prior
    // `Blake3Hash::digest(format!("image-sbom-{}", tag))` /
    // `format!("image-vuln-{}", tag)` per-tag constants are the
    // image-side peer of the `format!("sbom-{}", service)` /
    // `format!("vuln-scan-{}", service)` constants commit-this-commit
    // closes at the build-attestation surface; both inflate Phase 1
    // claims with name-keyed deterministic hashes that have no
    // relationship to a probe response (THEORY §V.2). Two tagged
    // images pointing at the same manifest now yield the same
    // `sbom_hash` (because no probe ran for either) instead of two
    // distinct hashes incidentally derived from the tag string.
    let image_sbom_outcome = crate::security_scan::SbomProbeOutcome::Absent;
    let image_vuln_scan_outcome = crate::security_scan::VulnScanProbeOutcome::Absent;
    let sbom_hash = image_sbom_outcome.to_attestation_hash();
    let (vuln_scan_hash, vuln_count, critical_high_vulns) =
        image_vuln_scan_outcome.to_attestation_fields();

    Ok(ci::image_attestation(
        image_ref,
        tag,
        &architecture,
        manifest_hash,
        cosign_verified,
        signer_identity,
        vuln_scan_hash,
        vuln_count,
        critical_high_vulns,
        sbom_hash,
    ))
}

/// Compute chart attestation for a Helm chart.
///
/// The `chart_hash` is the chart-content identity Phase 1 seals: the
/// BLAKE3 digest of the canonical chart fingerprint — the sorted,
/// deduplicated set of `(rel-path, blake3-of-content)` pairs over every
/// regular file in the chart directory. Two honesty disciplines apply
/// to it, mirroring [`compute_source_attestation`] (tree-listing) and
/// [`compute_image_attestation`] (skopeo manifest):
///
///   * A missing chart directory routes through the explicit
///     `b"no-chart-dir"` sentinel — never the prior silent fallback
///     `Blake3Hash::digest(format!("chart-{name}", ...))`, which stamped
///     a deterministic constant-but-name-derived hash into every Phase 1
///     chart record as the chart-content identity even when no chart had
///     been collected on disk, false by construction (THEORY §V.4).
///   * A successful walk is hashed over the canonical fingerprint
///     (boundary-framed by TAB, content-addressed per file, path-aware
///     over the full repo-relative path) rather than the prior
///     raw-byte concatenation of `(basename, content)` chunks, which
///     could collide on either the path/content boundary (`"ab"+"cd"` vs
///     `"abc"+"d"`) or the basename-only path (`templates/NOTES.txt` vs
///     `charts/sub/templates/NOTES.txt`) — the structural collisions the
///     typed canonical form forecloses (THEORY §VI.1).
///
/// The `provenance_verified` bool is computed by
/// [`crate::helm_provenance::HelmProvenanceOutcome::is_verified`] over
/// the typed shape recovered from a sibling `.prov` probe — never the
/// prior `false` hardcode that flattened all four operational worlds
/// (probe-absent, framing-failed, framing-ok-no-digest, verified) into
/// a single negative claim. `tarball_dir` is the directory holding the
/// `helm package --sign` output (the `.tgz` and `.tgz.prov` siblings).
/// When `None`, the parent directory of `chart_path` is probed — the
/// conventional location whenever `helm package` is invoked from the
/// chart's parent (the common case). The four-arm typed outcome
/// mirrors [`crate::cosign::CosignVerifyOutcome`] over the OpenPGP
/// cleartext signature framing Helm writes, so the spawn-vs-op-vs-
/// empty distinction the prior hardcode discarded survives at the type
/// level rather than being recovered by string-parsing an anyhow
/// envelope (THEORY §V.4 Phase 1: every claim a typed primitive can
/// populate must be populated honestly, not stubbed).
pub async fn compute_chart_attestation(
    chart_name: &str,
    chart_version: &str,
    chart_path: &Path,
    registry_ref: &str,
    tarball_dir: Option<&Path>,
) -> Result<ChartAttestation> {
    let chart_hash = if chart_path.exists() {
        let entries = collect_chart_entries(chart_path).await?;
        Blake3Hash::digest(crate::chart_listing::canonical_chart_fingerprint(entries).as_bytes())
    } else {
        Blake3Hash::digest(b"no-chart-dir")
    };

    let provenance_outcome =
        probe_chart_provenance(chart_name, chart_version, chart_path, tarball_dir).await;

    // `helm lint <chart-dir>` is the chart-quality probe whose `[INFO]`
    // / `[WARNING]` / `[ERROR]` diagnostics and `N chart(s) linted, M
    // chart(s) failed` summary populate the Phase 1 chart attestation's
    // `linter_passed` claim. The prior `true` literal at this call site
    // (`// Linter: assume passed if forge got this far`) sealed a green-
    // lint claim from inter-function flow control — false by construction
    // whenever `compute_chart_attestation` is called outside the canonical
    // `commands/helm.rs::lint` precondition or whenever that upstream
    // probe's bail logic was bypassed (THEORY §V.2: attestation is
    // cryptographic evidence, not a wish). The typed `HelmLintOutcome`
    // (`Passed { warning_count, info_count }` /
    // `Failed { failed_chart_count, error_count, warning_count,
    // info_count }` / `Malformed` / `ProbeAbsent`) preserves the four
    // operational worlds the prior `true` flattened into a single
    // positive claim; the call site routes through `is_passed()` which
    // returns `true` only on the `Passed` arm. Today the certification
    // function does not yet spawn `helm lint` itself — the outcome
    // collapses to `ProbeAbsent` → `linter_passed: false`, honestly
    // naming "no lint probe ran inside the certification surface"
    // rather than asserting a green-lint claim that flow-control alone
    // cannot substantiate. Same deferral shape as commit b98eb5a's
    // `SbomProbeOutcome::Absent` / `VulnScanProbeOutcome::Absent` at
    // the SBOM / vuln-scan layer: typed primitive available, real
    // probe wired in by a follow-up that adds the `tokio::process::
    // Command::new("helm").args(["lint", &chart_path.to_string_lossy()]).
    // output().await` shell-out and routes the captured output through
    // `crate::helm_lint::parse_lint_output`.
    let lint_outcome = crate::helm_lint::HelmLintOutcome::ProbeAbsent;

    // `kensa verify chart <chart-path>` is the compliance-engine
    // probe whose pass/fail evaluation against the declared OSCAL /
    // NIST 800-53 baseline (THEORY §V.3, §VII.1) populates the
    // Phase 1 chart attestation's `policy_passed` claim. The prior
    // `true` literal at this call site (`// Policy: assume passed`)
    // sealed a green-policy claim from nothing — false by
    // construction whenever `compute_chart_attestation` was called
    // outside any kensa pre-deploy gate (THEORY §V.2: attestation
    // is cryptographic evidence, not a wish; THEORY §III.3:
    // compliance is a structural dimension every renderer carries,
    // never a value asserted without evidence). The typed
    // `KensaPolicyOutcome` (`Passed { evaluated_control_count }` /
    // `Failed { failed_control_count, evaluated_control_count }` /
    // `ProbeAbsent`) preserves the three operational worlds the
    // prior `true` flattened into a single positive claim; the call
    // site routes through `is_passed()` which returns `true` only
    // on the `Passed` arm. Today the certification function does
    // not yet spawn `kensa` itself — the outcome collapses to
    // `ProbeAbsent` → `policy_passed: false`, honestly naming "no
    // policy probe ran inside the certification surface" rather
    // than asserting a green-policy claim flow-control alone
    // cannot substantiate. Same deferral shape as the sibling
    // `lint_outcome = HelmLintOutcome::ProbeAbsent` one line above
    // (commit d81f639) and commit b98eb5a's
    // `SbomProbeOutcome::Absent` / `VulnScanProbeOutcome::Absent`
    // at the SBOM / vuln-scan layer: typed primitive available,
    // real probe wired in by a follow-up that adds the
    // `tokio::process::Command::new("kensa").args(["verify",
    // "chart", &chart_path.to_string_lossy()]).output().await`
    // shell-out and deserializes the resulting
    // `OutcomeVerificationReport` (VOCABULARY §kensa) into one of
    // the two evidence-bearing arms.
    let policy_outcome = crate::kensa_policy::KensaPolicyOutcome::ProbeAbsent;

    Ok(ci::chart_attestation(
        chart_name,
        chart_version,
        chart_hash,
        provenance_outcome.is_verified(),
        vec![], // Dependency hashes: populated when chart deps are tracked
        lint_outcome.is_passed(),
        policy_outcome.is_passed(),
        registry_ref,
    ))
}

/// Probe a Helm `.prov` provenance file alongside the packaged chart
/// tarball and route the result through the typed
/// [`crate::helm_provenance::HelmProvenanceOutcome`].
///
/// The conventional `.prov` location after `helm package --sign
/// [-d <dest>] <chart-dir>` is `<dest>/<chart-name>-<version>.tgz.prov`
/// (or in the chart's parent directory when `-d` is absent). The
/// `tarball_dir` argument lets the caller override the search root;
/// when `None`, we fall back to `chart_path.parent()` — the helm-package
/// default for a chart at `<dir>/<chart>` where `helm package` is
/// invoked from `<dir>`.
///
/// The function returns the four-arm typed outcome directly so the
/// call site can collapse to a bool via `is_verified()` for the
/// `ChartAttestation::provenance_verified` field while a future
/// enrichment commit can still recover the `signed_chart_hash` /
/// `signer_key_id` discriminators for richer reconciliation.
async fn probe_chart_provenance(
    chart_name: &str,
    chart_version: &str,
    chart_path: &Path,
    tarball_dir: Option<&Path>,
) -> crate::helm_provenance::HelmProvenanceOutcome {
    let tarball_name = format!("{}-{}.tgz", chart_name, chart_version);
    let dir = tarball_dir
        .map(Path::to_path_buf)
        .or_else(|| chart_path.parent().map(Path::to_path_buf));
    let Some(dir) = dir else {
        return crate::helm_provenance::HelmProvenanceOutcome::ProbeAbsent;
    };
    let prov_path = dir.join(format!("{}.prov", tarball_name));
    match tokio::fs::read_to_string(&prov_path).await {
        Ok(contents) => crate::helm_provenance::parse_provenance(&contents, &tarball_name),
        Err(_) => crate::helm_provenance::HelmProvenanceOutcome::ProbeAbsent,
    }
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

/// Walk a chart directory recursively and collect every regular file's
/// [`crate::chart_listing::ChartEntry`] — the typed input to
/// [`crate::chart_listing::canonical_chart_fingerprint`].
///
/// The walk is sync (`std::fs::read_dir`) at the directory traversal layer
/// and async (`tokio::fs::read`) at the per-file content read, so the
/// recursion fits an ordinary `fn` (no `Box::pin` ladder). Symlinks and
/// non-file / non-directory entries are skipped — chart content on disk
/// is a directory of regular files; anything else is not chart
/// content. Paths are normalised to forward slashes for canonical-form
/// portability across the (rare in practice but possible) case of a
/// Windows host building a chart.
async fn collect_chart_entries(root: &Path) -> Result<Vec<crate::chart_listing::ChartEntry>> {
    let mut paths = Vec::new();
    collect_chart_file_paths(root, &mut paths)?;
    let mut out = Vec::with_capacity(paths.len());
    for path in paths {
        let rel = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        let content = tokio::fs::read(&path)
            .await
            .with_context(|| format!("Failed to read chart file: {}", path.display()))?;
        out.push(crate::chart_listing::ChartEntry::new(rel, &content));
    }
    Ok(out)
}

fn collect_chart_file_paths(dir: &Path, out: &mut Vec<std::path::PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(dir)
        .with_context(|| format!("Failed to read chart subdir: {}", dir.display()))?
    {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let path = entry.path();
        if file_type.is_file() {
            out.push(path);
        } else if file_type.is_dir() {
            collect_chart_file_paths(&path, out)?;
        }
        // Symlinks, devices, sockets — skipped. Not chart content.
    }
    Ok(())
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

    /// A successful `git symbolic-ref --short HEAD` probe renders the
    /// canonical `refs/heads/<name>` refspec. The trim is load-bearing —
    /// `run_command_output` already trims, but the pure resolver is
    /// independently tested against raw shim output that may carry a
    /// trailing newline.
    #[test]
    fn test_resolve_source_ref_branch_wins() {
        assert_eq!(
            resolve_source_ref(Some("main"), None, "deadbeef"),
            "refs/heads/main"
        );
        // Branch names with slashes are full refnames — the format must
        // not re-split them.
        assert_eq!(
            resolve_source_ref(Some("feature/foo-bar"), None, "deadbeef"),
            "refs/heads/feature/foo-bar"
        );
        // A whitespace-only branch probe is treated as failed; the SHA
        // wins (no tag probe in this fixture).
        assert_eq!(
            resolve_source_ref(Some("  \n"), None, "deadbeef"),
            "deadbeef"
        );
    }

    /// When the branch probe failed (detached HEAD) but HEAD is at an
    /// exact tag, the resolver records the tag as `refs/tags/<name>` —
    /// the honest provenance refspec for a tag-checkout build.
    #[test]
    fn test_resolve_source_ref_tag_when_branch_absent() {
        assert_eq!(
            resolve_source_ref(None, Some("v1.0.0"), "deadbeef"),
            "refs/tags/v1.0.0"
        );
        // The branch arm wins over the tag arm when both probe — the
        // branch the operator is on is the more semantically informative
        // refspec for the build's source.
        assert_eq!(
            resolve_source_ref(Some("main"), Some("v1.0.0"), "deadbeef"),
            "refs/heads/main"
        );
    }

    /// The load-bearing fail-before/pass-after pin: with the branch
    /// probe failed AND no exact tag at HEAD — the detached-HEAD
    /// no-tag state that is the default GitHub-Actions checkout — the
    /// resolver records the bare commit SHA. Pre-fix the call site
    /// stamped `refs/heads/refs/heads/main` (the `unwrap_or_else(|_|
    /// "refs/heads/main")` swallow re-prefixed by `format!("refs/heads/
    /// {}", _)`): a dishonest claim *and* a malformed refname. The
    /// honest fallback is the SHA the build was actually produced from.
    #[test]
    fn test_resolve_source_ref_detached_head_falls_back_to_sha() {
        let sha = "deadbeefcafef00d1234567890abcdef00000000";
        assert_eq!(resolve_source_ref(None, None, sha), sha);
        // Whitespace probes are treated as failed, and the SHA trims —
        // a stray newline from the caller cannot leak into the refspec.
        assert_eq!(
            resolve_source_ref(Some("  "), Some("\n"), &format!("{sha}\n")),
            sha
        );
        // The pre-fix synthesis is explicitly NOT produced by the new
        // resolver; the malformed `refs/heads/refs/heads/main` shape is
        // unreachable by construction.
        assert_ne!(
            resolve_source_ref(None, None, sha),
            "refs/heads/refs/heads/main"
        );
        assert_ne!(resolve_source_ref(None, None, sha), "refs/heads/main");
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
        // A realistic 32-char Nix base-32 derivation hash (the alphabet
        // itself is exactly 32 valid symbols) so the derivation parses as a
        // well-formed store path under the positive provenance grammar.
        let level = build_slsa_level(
            "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-mysvc.drv",
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
            "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-mysvc.drv",
            r#"[{"path":"/nix/store/abc123-mysvc","narHash":"sha256-x"}]"#,
            true,
        );
        assert_eq!(
            level,
            SlsaLevel::L3,
            "substantiated + reproducible-verified earns L3"
        );
    }

    /// Closing the gap the negative-sentinel gate left open: a derivation
    /// that is malformed but does NOT match the one `/nix/store/unknown-`
    /// sentinel — an empty string, a relative path, or a build *output*
    /// path mistakenly fed where the `.drv` belongs — must rate `L0` even
    /// when a non-empty closure was collected, because provenance requires
    /// a real content-addressed derivation. Fail-before: the prior
    /// `!derivation.starts_with("/nix/store/unknown-")` check returned
    /// `true` for every one of these (none start with the sentinel), so a
    /// non-empty closure alongside a bogus derivation minted `L2`.
    #[test]
    fn test_build_slsa_level_malformed_non_sentinel_derivation_is_l0() {
        let closure = r#"[{"path":"/nix/store/abc","narHash":"sha256-x"}]"#;
        // Empty derivation (a `nix path-info --derivation` that exited zero
        // with no stdout) — does not start with the sentinel.
        assert_eq!(build_slsa_level("", closure, false), SlsaLevel::L0);
        // A relative, non-store path.
        assert_eq!(
            build_slsa_level("result/mysvc.drv", closure, false),
            SlsaLevel::L0
        );
        // A well-formed store *output* path (no `.drv`) where the
        // derivation was expected: provenance for the build graph wasn't
        // collected, so it cannot earn an L2 hermetic-provenance grade.
        assert_eq!(
            build_slsa_level(
                "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-mysvc",
                closure,
                true
            ),
            SlsaLevel::L0,
            "an output path is not a derivation; no build-graph provenance"
        );
    }

    /// The build attestation's closure hash must be reproducible: two `nix
    /// path-info --recursive --json` documents describing the *same* closure
    /// content — differing only in path emission order and volatile
    /// metadata (`registrationTime`) — must hash identically.
    /// `compute_build_attestation` now digests the closure's canonical
    /// content-addressed fingerprint
    /// ([`crate::store_path::canonical_closure_fingerprint`]) rather than
    /// the raw document, so the metadata drift cancels. Fail-before: the
    /// prior `Blake3Hash::digest(closure_info.as_bytes())` hashed the raw
    /// text, so the two equivalent closures produced DIFFERENT closure
    /// hashes — the contrast assertion against the raw-byte digest makes the
    /// closed gap explicit.
    #[test]
    fn test_closure_hash_reproducible_across_metadata_and_order() {
        let h_a = "0123456789abcdfghijklmnpqrsvwxyz";
        let h_b = "zyxwvsrqpnmlkjihgfdcba9876543210";
        let doc1 = format!(
            r#"[{{"path":"/nix/store/{h_a}-a","registrationTime":111}},
                {{"path":"/nix/store/{h_b}-b","registrationTime":111}}]"#
        );
        let doc2 = format!(
            r#"[{{"path":"/nix/store/{h_b}-b","registrationTime":999}},
                {{"path":"/nix/store/{h_a}-a","registrationTime":999}}]"#
        );
        let canon = |d: &str| {
            Blake3Hash::digest(crate::store_path::canonical_closure_fingerprint(d).as_bytes())
                .to_hex()
        };
        assert_eq!(
            canon(&doc1),
            canon(&doc2),
            "canonical closure hash must be order- and metadata-independent"
        );
        // The prior raw-byte scheme conflated metadata/order into the hash,
        // so the same closure hashed differently — the bug this closes.
        assert_ne!(
            Blake3Hash::digest(doc1.as_bytes()).to_hex(),
            Blake3Hash::digest(doc2.as_bytes()).to_hex(),
            "raw-byte hashing (the prior scheme) drifts with metadata/order"
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

    /// Load-bearing source-attestation honesty pin: the `git ls-tree`
    /// probe failure mode must NOT collapse to the silent blake3-of-
    /// empty value the prior `unwrap_or_default()` produced. The
    /// probe-failed sentinel (`b"no-tree-listing"`) must hash to a
    /// distinct value from a *successful* probe that yielded an empty
    /// tree (or a listing with no parseable entries) — the two cases
    /// describe different worlds (no evidence collected vs. evidence
    /// collected and trivially empty) and the attestation must record
    /// them honestly. Fail-before: the prior body produced
    /// `Blake3Hash::digest(b"")` for both, conflating them.
    #[test]
    fn test_tree_hash_probe_failure_distinguishable_from_empty_listing() {
        let probe_failed = Blake3Hash::digest(b"no-tree-listing");
        let empty_listing_hash =
            Blake3Hash::digest(crate::tree_listing::canonical_tree_fingerprint("").as_bytes());
        assert_ne!(
            probe_failed.to_hex(),
            empty_listing_hash.to_hex(),
            "the probe-failed sentinel and a successful-but-empty listing \
             must hash to distinct values; conflating them was the prior \
             honesty bug"
        );
        // The pre-fix path hashed `b""` (the `unwrap_or_default()`
        // result) for the probe-failed case. The sentinel must be
        // strictly distinct from that constant so a Phase 1 attestation
        // record carrying the sentinel hash is not mistakable for a
        // legitimate "empty tree" record.
        assert_ne!(
            probe_failed.to_hex(),
            Blake3Hash::digest(b"").to_hex(),
            "the sentinel must differ from blake3-of-empty (the prior \
             silent fallback value)"
        );
    }

    /// Load-bearing image-attestation honesty pin: the `skopeo inspect
    /// --raw` probe failure mode must NOT collapse to the silent
    /// blake3-of-empty value the prior `unwrap_or_default()` produced.
    /// The probe-failed sentinel (`b"no-manifest"`) must hash to a
    /// distinct value from a *successful* probe that yielded an empty
    /// manifest (or one with no parseable digest in any recognised
    /// role) — the two cases describe different worlds (no evidence
    /// collected vs. evidence collected and trivially empty) and the
    /// attestation must record them honestly. Fail-before: the prior
    /// body produced `Blake3Hash::digest(b"")` for both, conflating
    /// them. Same shape as `test_tree_hash_probe_failure_distinguishable
    /// _from_empty_listing` one layer up.
    #[test]
    fn test_manifest_hash_probe_failure_distinguishable_from_empty_manifest() {
        let probe_failed = Blake3Hash::digest(b"no-manifest");
        let empty_manifest_hash =
            Blake3Hash::digest(crate::oci_manifest::canonical_manifest_fingerprint("").as_bytes());
        assert_ne!(
            probe_failed.to_hex(),
            empty_manifest_hash.to_hex(),
            "the probe-failed sentinel and a successful-but-empty manifest \
             must hash to distinct values; conflating them was the prior \
             honesty bug"
        );
        // The pre-fix path hashed `b""` (the `unwrap_or_default()` result)
        // for the probe-failed case. The sentinel must be strictly distinct
        // from that constant so a Phase 1 image attestation carrying the
        // sentinel hash is not mistakable for a legitimate "empty manifest"
        // record.
        assert_ne!(
            probe_failed.to_hex(),
            Blake3Hash::digest(b"").to_hex(),
            "the sentinel must differ from blake3-of-empty (the prior \
             silent fallback value)"
        );
        // And distinct from the two sibling sentinels at the source layer,
        // so an attestation record carrying ONE of them cannot be confused
        // with another. The one-sentinel-per-probe discipline relies on
        // these being structurally distinct strings.
        assert_ne!(
            probe_failed.to_hex(),
            Blake3Hash::digest(b"no-tree-listing").to_hex()
        );
        assert_ne!(
            probe_failed.to_hex(),
            Blake3Hash::digest(b"no-flake-lock").to_hex()
        );
    }

    /// The manifest hash must be canonical over the manifest's content-
    /// addressed digests: two OCI manifests describing the *same* image
    /// (same config digest, same layer digest set) but emitted with
    /// different top-level key order and different volatile metadata
    /// (`annotations` carrying a fresh `created` timestamp on every push)
    /// must hash identically. `compute_image_attestation` now digests the
    /// canonical fingerprint rather than the raw manifest bytes, so any
    /// future drift in registry-side JSON formatting, key ordering, or
    /// Accept-header-negotiated manifest format cannot drift the image
    /// claim for a byte-identical image. Fail-before: the prior
    /// `Blake3Hash::digest(manifest_json.as_bytes())` hashed the raw text,
    /// so the two equivalent manifests produced different image-attestation
    /// hashes — the contrast against the raw-byte digest makes the closed
    /// gap explicit. Same shape as `test_closure_hash_reproducible_across_
    /// metadata_and_order` for the build closure.
    #[test]
    fn test_manifest_hash_stable_across_key_order_and_metadata() {
        let d1 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let d2 = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
        let json_a = format!(
            r#"{{
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": {{"digest": "sha256:{d1}", "size": 100}},
                "layers": [{{"digest": "sha256:{d2}", "size": 200}}],
                "annotations": {{"org.opencontainers.image.created": "2025-01-01T00:00:00Z"}}
            }}"#
        );
        let json_b = format!(
            r#"{{
                "layers":  [{{"digest" : "sha256:{d2}", "size": 999}}] ,
                "config" : {{"digest": "sha256:{d1}", "size": 999}},
                "mediaType" : "application/vnd.docker.distribution.manifest.v2+json",
                "schemaVersion" : 2,
                "annotations": {{"org.opencontainers.image.created": "2026-05-28T12:34:56Z"}}
            }}"#
        );
        let canon = |j: &str| {
            Blake3Hash::digest(crate::oci_manifest::canonical_manifest_fingerprint(j).as_bytes())
                .to_hex()
        };
        assert_eq!(
            canon(&json_a),
            canon(&json_b),
            "canonical manifest hash must be JSON-formatting, key-order, and metadata-independent"
        );
        // The prior raw-byte scheme conflated formatting / metadata into
        // the hash, so the same image hashed differently — the bug this
        // closes.
        assert_ne!(
            Blake3Hash::digest(json_a.as_bytes()).to_hex(),
            Blake3Hash::digest(json_b.as_bytes()).to_hex(),
            "raw-byte hashing (the prior scheme) drifts with formatting / metadata"
        );
    }

    /// The tree hash must be canonical over the listing content: two
    /// `git ls-tree` outputs naming the *same* tree (same set of
    /// `(mode, type, hash, path)` entries) in different orders must
    /// hash identically. `compute_source_attestation` now digests the
    /// canonical fingerprint rather than the raw `ls-tree` bytes, so
    /// any future formatting drift in git's output cannot drift the
    /// source-tree claim for a byte-identical tree. Fail-before: the
    /// prior `Blake3Hash::digest(tree_listing.as_bytes())` hashed the
    /// raw text, so the two equivalent listings produced different
    /// source-tree hashes — the contrast against the raw-byte digest
    /// makes the closed gap explicit.
    #[test]
    fn test_tree_hash_stable_across_listing_order() {
        let h1 = "0123456789abcdef0123456789abcdef01234567";
        let h2 = "fedcba9876543210fedcba9876543210fedcba98";
        let listing1 = format!("100644 blob {h1}\ta\n100644 blob {h2}\tb\n");
        let listing2 = format!("100644 blob {h2}\tb\n100644 blob {h1}\ta\n");
        let canon = |l: &str| {
            Blake3Hash::digest(crate::tree_listing::canonical_tree_fingerprint(l).as_bytes())
                .to_hex()
        };
        assert_eq!(
            canon(&listing1),
            canon(&listing2),
            "canonical tree hash must be order-independent"
        );
        // The prior raw-byte scheme would conflate emission order into
        // the hash — the bug this closes.
        assert_ne!(
            Blake3Hash::digest(listing1.as_bytes()).to_hex(),
            Blake3Hash::digest(listing2.as_bytes()).to_hex(),
            "raw-byte hashing (the prior scheme) drifts with listing order"
        );
    }

    /// **Load-bearing cosign-honesty pin (fail-before/pass-after).**
    /// The prior `compute_image_attestation` body folded the cosign
    /// probe through `run_command_output(...).await.is_ok()` — true
    /// whenever the spawn succeeded AND the exit was 0, regardless of
    /// whether cosign actually emitted a signature receipt. The empty
    /// JSON array `[]` (what cosign returns when the upstream registry
    /// stripped sigstore receipts, exit 0) thus caused the Phase 1
    /// image attestation to claim `cosign_verified: true` against
    /// zero collected evidence — a false Phase 1 record a Phase 2
    /// signature composes over (THEORY §V.4). The typed primitive
    /// now collapses the empty-bag case to
    /// [`crate::cosign::CosignVerifyOutcome::Unverified`], whose
    /// `is_verified()` returns `false`. The pre-fix `is_ok()` fold
    /// against the same exit-0 stdout would assert this test backwards.
    #[test]
    fn test_cosign_empty_bag_does_not_claim_verification() {
        // The shape `compute_image_attestation` now writes into
        // `cosign_verified`: parse the exit-0 stdout, ask the typed
        // outcome whether it's verified, populate the bool. The
        // pre-fix `is_ok()` would have been `true` here because the
        // probe spawned successfully and exited 0.
        let outcome = crate::cosign::parse_verify_output("[]");
        assert!(
            !outcome.is_verified(),
            "an empty cosign payload must not assert cosign_verified=true; \
             the pre-fix is_ok() fold inflated this claim against zero evidence"
        );
        assert_eq!(outcome.signer_identity(), None);
        assert_eq!(outcome, crate::cosign::CosignVerifyOutcome::Unverified);
    }

    /// The spawn-vs-op discriminator survives at the type level:
    /// probe-absent (cosign not on PATH) and verify-failed (cosign
    /// returned non-zero) collapse to distinct typed arms, where the
    /// prior `is_ok()` fold mapped both to `false` and lost the
    /// distinction. A downstream verifier that wants to escalate
    /// "absent probe" differently from "explicit negative" can now
    /// recover the distinction structurally rather than by parsing an
    /// anyhow envelope. Both still report `is_verified() == false` so
    /// the Phase 1 `cosign_verified` bool is honest in both cases.
    #[test]
    fn test_cosign_spawn_vs_op_failures_are_distinct_arms() {
        let absent = crate::cosign::CosignVerifyOutcome::ProbeAbsent;
        let failed = crate::cosign::CosignVerifyOutcome::VerifyFailed;
        assert_ne!(
            absent, failed,
            "ProbeAbsent and VerifyFailed must be structurally distinct \
             arms — the prior is_ok() fold mapped both to `false` and lost \
             the discriminator the Phase 1 attestation needs"
        );
        assert!(!absent.is_verified());
        assert!(!failed.is_verified());
    }

    /// The `signer_identity` field on `ImageAttestation` is now
    /// populated from the cosign receipt rather than hardcoded
    /// `None`. A verified probe with a keyless Fulcio Subject
    /// surfaces the principal identity into the Phase 1 record so a
    /// downstream verifier can cross-check WHO signed the image,
    /// not merely that SOMETHING did. Pin the end-to-end shape:
    /// parsed receipt → typed outcome → string the call site passes
    /// into `ci::image_attestation`'s `signer_identity` parameter.
    #[test]
    fn test_cosign_signer_identity_flows_into_attestation() {
        let stdout = r#"[
            {
                "critical": {
                    "image": {"docker-manifest-digest": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}
                },
                "optional": {"Subject": "ci@pleme-io.example"}
            }
        ]"#;
        let outcome = crate::cosign::parse_verify_output(stdout);
        assert!(outcome.is_verified());
        // This is exactly the expression `compute_image_attestation`
        // now passes for `signer_identity` — the prior code passed
        // `None` here unconditionally, losing the parsed principal.
        let passed_to_attestation = outcome.signer_identity().map(String::from);
        assert_eq!(
            passed_to_attestation.as_deref(),
            Some("ci@pleme-io.example"),
            "the signer identity parsed from the cosign receipt must flow \
             into ImageAttestation::signer_identity, not be dropped to None"
        );
    }

    /// Load-bearing chart-attestation honesty pin: the missing
    /// chart-directory case must NOT collapse to the silent
    /// `Blake3Hash::digest(format!("chart-{name}", ...))` fallback the
    /// prior body produced. The missing-dir sentinel (`b"no-chart-dir"`)
    /// must hash to a value distinct from every name-derived
    /// chart-placeholder hash AND from every sibling probe-failed
    /// sentinel at the source / build / image layers, so a Phase 1
    /// chart record carrying the sentinel hash cannot be confused with
    /// a legitimate chart-content claim or with a different probe's
    /// failure mode. Fail-before: the prior body emitted
    /// `Blake3Hash::digest(b"chart-mysvc")` for chart `mysvc` even when
    /// no chart had ever been collected on disk, conflating "no
    /// evidence collected" with "chart `mysvc` has this content."
    /// Same shape as `test_tree_hash_probe_failure_distinguishable_
    /// from_empty_listing` and
    /// `test_manifest_hash_probe_failure_distinguishable_from_empty_
    /// manifest` two layers up.
    #[test]
    fn test_chart_hash_probe_failure_distinguishable_from_empty_chart() {
        let missing_dir = Blake3Hash::digest(b"no-chart-dir");
        let empty_chart_hash = Blake3Hash::digest(
            crate::chart_listing::canonical_chart_fingerprint(std::iter::empty()).as_bytes(),
        );
        assert_ne!(
            missing_dir.to_hex(),
            empty_chart_hash.to_hex(),
            "the missing-dir sentinel and a successful-but-empty chart \
             walk must hash to distinct values; conflating them was the \
             prior honesty bug",
        );
        // The pre-fix path emitted `Blake3Hash::digest(format!(
        // "chart-{chart_name}", ...))` for the missing-dir case,
        // shadowing the no-evidence record with a deterministic
        // name-derived hash. The sentinel must be strictly distinct
        // from every such name-keyed placeholder so a Phase 1 chart
        // record carrying the sentinel hash cannot be mistaken for a
        // legitimate chart-content claim under any plausible chart
        // name.
        for name in ["mysvc", "foo", "bar-baz", ""] {
            assert_ne!(
                missing_dir.to_hex(),
                Blake3Hash::digest(format!("chart-{name}").as_bytes()).to_hex(),
                "the sentinel must differ from the prior name-derived \
                 fallback for any chart name (here: {name:?})",
            );
        }
        // And distinct from the sibling sentinels at the source / build /
        // image layers, so an attestation record carrying ONE of them
        // cannot be confused with another. The one-sentinel-per-probe
        // discipline relies on these being structurally distinct strings.
        for sibling in [
            b"no-tree-listing".as_slice(),
            b"no-flake-lock".as_slice(),
            b"no-manifest".as_slice(),
            b"".as_slice(),
        ] {
            assert_ne!(
                missing_dir.to_hex(),
                Blake3Hash::digest(sibling).to_hex(),
                "the chart-dir sentinel must differ from sibling \
                 probe-failure sentinels and from blake3-of-empty",
            );
        }
    }

    /// The chart hash must be canonical over the chart's per-file
    /// content-addressed identities: two chart layouts whose per-file
    /// `(path, content)` pairs coincide but whose filesystem ordering /
    /// dedup-shape differs must hash identically. `compute_chart_
    /// attestation` now digests the canonical fingerprint
    /// ([`crate::chart_listing::canonical_chart_fingerprint`]) rather
    /// than the raw-byte `(basename, content)` concatenation, so any
    /// future drift in filesystem iteration order cannot drift the
    /// chart claim for a byte-identical chart, and basename-collision
    /// failure modes the prior `hash_directory` carried cannot recur.
    /// Fail-before: the prior raw-byte scheme conflated filesystem
    /// ordering AND lost the path-vs-basename distinction at the
    /// canonical primitive, so two structurally distinct chart layouts
    /// could collapse to the same chart-content hash. Same shape as
    /// `test_manifest_hash_stable_across_key_order_and_metadata` and
    /// `test_tree_hash_stable_across_listing_order` two layers up.
    #[test]
    fn test_chart_hash_stable_and_collision_resistant() {
        use crate::chart_listing::{canonical_chart_fingerprint, ChartEntry};
        let canon = |entries: Vec<ChartEntry>| {
            Blake3Hash::digest(canonical_chart_fingerprint(entries).as_bytes()).to_hex()
        };
        let e = |p: &str, c: &[u8]| ChartEntry::new(p.to_string(), c);

        // Order-independence: two iteration orders over the same
        // `(path, content)` set hash identically — the load-bearing
        // canonical-form property.
        let forward = vec![
            e("Chart.yaml", b"name: foo\n"),
            e("templates/svc.yaml", b"kind: Service\n"),
            e("values.yaml", b"replicas: 3\n"),
        ];
        let reversed: Vec<ChartEntry> = forward.iter().rev().cloned().collect();
        assert_eq!(
            canon(forward),
            canon(reversed),
            "canonical chart hash must be order-independent",
        );

        // Basename-collision resistance: a `NOTES.txt` in the parent
        // chart's `templates/` and a `NOTES.txt` in a subchart's
        // `templates/` are different chart content; the prior
        // `hash_directory` hashed only `path.file_name()` and could
        // collapse them.
        let parent_only = vec![e("templates/NOTES.txt", b"hello\n")];
        let subchart_only = vec![e("charts/sub/templates/NOTES.txt", b"hello\n")];
        assert_ne!(
            canon(parent_only),
            canon(subchart_only),
            "basename-only paths must produce distinct chart hashes — \
             the basename-collision failure the canonical form forecloses",
        );

        // Path/content boundary safety: ("ab","cd") must not collide
        // with ("abc","d") — the prior raw-byte
        // `extend_from_slice(filename) + extend_from_slice(content)`
        // shape reduced both to b"abcd", a structural collision.
        let left = vec![e("ab", b"cd")];
        let right = vec![e("abc", b"d")];
        assert_ne!(
            canon(left),
            canon(right),
            "TAB framing must keep the path/content boundary unambiguous",
        );
    }

    /// **Load-bearing fail-before/pass-after pin.** A chart packaged
    /// with `helm package --sign` writes a `.tgz.prov` cleartext-signed
    /// document alongside the tarball whose signed body names the
    /// chart-tarball `sha256:<hex>` digest. The prior call site
    /// hardcoded `provenance_verified: false` regardless of whether a
    /// `.prov` existed, lived structurally, or named the chart we are
    /// sealing — flattening four operational worlds (probe-absent,
    /// framing-failed, framing-ok-no-digest, verified) into one
    /// negative claim. The typed shape recovers the verified arm
    /// directly: `compute_chart_attestation` now reads the sibling
    /// `.prov`, routes it through
    /// [`crate::helm_provenance::parse_provenance`], and writes
    /// `provenance_verified: true` iff the framing parsed AND the
    /// `files:` map carried a sha256 for the chart's tarball.
    ///
    /// Same shape as
    /// `test_cosign_verified_recovered_from_typed_outcome` one layer
    /// up (the image-side peer): a Phase 1 claim whose typed
    /// primitive's `Verified` arm fires must drive a `true` bool into
    /// the attestation, where the prior hardcode forced `false`.
    #[tokio::test]
    async fn test_chart_provenance_verified_recovered_from_typed_outcome() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let chart_dir = tmp.path().join("example");
        std::fs::create_dir(&chart_dir).expect("mkdir chart");
        std::fs::write(
            chart_dir.join("Chart.yaml"),
            "apiVersion: v2\nname: example\nversion: 0.1.0\n",
        )
        .expect("write Chart.yaml");

        // A realistic Helm .prov adjacent to the (would-be) packaged
        // tarball, naming `example-0.1.0.tgz: sha256:<64-hex>`.
        let digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let prov = format!(
            "-----BEGIN PGP SIGNED MESSAGE-----\n\
             Hash: SHA512\n\
             \n\
             apiVersion: v2\n\
             name: example\n\
             version: 0.1.0\n\
             \n\
             files:\n  example-0.1.0.tgz: sha256:{}\n\
             -----BEGIN PGP SIGNATURE-----\n\
             \n\
             wsBcBAABCgAQ==\n\
             -----END PGP SIGNATURE-----\n",
            digest
        );
        std::fs::write(tmp.path().join("example-0.1.0.tgz.prov"), prov).expect("write .prov");

        let att = compute_chart_attestation(
            "example",
            "0.1.0",
            &chart_dir,
            "oci://ghcr.io/example/example",
            Some(tmp.path()),
        )
        .await
        .expect("compute_chart_attestation");

        assert!(
            att.provenance_verified,
            "a well-framed .prov whose files: map names the expected \
             tarball must drive provenance_verified=true into the Phase 1 \
             chart attestation; the prior `false` hardcode flattened this \
             arm into a false-negative claim",
        );
    }

    /// **Probe-absent vs verify-failed vs unverified vs verified are
    /// structurally distinct at the typed-outcome layer.** The prior
    /// `false` hardcode could not distinguish "no .prov on disk" from
    /// "ill-formed .prov" from "well-formed .prov naming a different
    /// tarball" — all flattened to `provenance_verified: false`. The
    /// typed primitive preserves the four arms so a downstream
    /// verifier (or a future enrichment commit) can recover the
    /// discriminator from the typed shape directly. Same shape as
    /// `test_is_verified_pins_all_arms` over `CosignVerifyOutcome` one
    /// layer up — the image-side peer at the four-arm-truth-table
    /// level.
    #[tokio::test]
    async fn test_chart_provenance_four_arms_collapse_to_distinct_bools() {
        use crate::helm_provenance::HelmProvenanceOutcome;
        // Verified is the only arm whose bool collapse is `true`.
        assert!(HelmProvenanceOutcome::Verified {
            signed_chart_hash: Some(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string()
            ),
            signer_key_id: None,
        }
        .is_verified());
        // The other three arms each collapse to `false` at the bool
        // surface but stay structurally distinct at the enum level.
        assert!(!HelmProvenanceOutcome::Unverified.is_verified());
        assert!(!HelmProvenanceOutcome::VerifyFailed.is_verified());
        assert!(!HelmProvenanceOutcome::ProbeAbsent.is_verified());

        // End-to-end through compute_chart_attestation: a missing
        // `.prov` directory collapses to ProbeAbsent → false.
        let tmp = tempfile::tempdir().expect("tempdir");
        let chart_dir = tmp.path().join("example");
        std::fs::create_dir(&chart_dir).expect("mkdir chart");
        std::fs::write(chart_dir.join("Chart.yaml"), "name: example\n").expect("write Chart.yaml");
        let att = compute_chart_attestation(
            "example",
            "0.1.0",
            &chart_dir,
            "oci://ghcr.io/example/example",
            Some(tmp.path()),
        )
        .await
        .expect("compute_chart_attestation");
        assert!(
            !att.provenance_verified,
            "ProbeAbsent must collapse to provenance_verified=false",
        );
    }

    /// Load-bearing image-attestation honesty pin: the prior
    /// `architecture: "amd64"` literal at the `ci::image_attestation` call
    /// site flattened five operational worlds (single-arch v1, index-
    /// single, index-multi, image-manifest-embedded-in-config, probe-
    /// absent) into one false claim. The typed primitive
    /// `OciArchitectureOutcome` recovers the honest architecture from the
    /// same `skopeo inspect --raw` JSON the call site already fetches for
    /// `manifest_hash`, and the resulting attestation string is the value
    /// that flows into `ImageAttestation::architecture`. Pin the
    /// fail-before / pass-after end-to-end: an arm64-only index manifest
    /// produces `"arm64"` (the prior hardcode produced `"amd64"`); the
    /// four other arms produce their respective sentinels. Same shape as
    /// `test_chart_provenance_verified_recovered_from_typed_outcome` and
    /// `test_cosign_signer_identity_flows_into_attestation` one layer
    /// down — each pins that the typed primitive's output reaches the
    /// attestation field rather than being dropped to a hardcode.
    #[test]
    fn test_image_architecture_recovered_from_typed_outcome() {
        use crate::oci_architecture::{parse_manifest_architectures, OciArchitectureOutcome};
        const D1: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        const D2: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

        // Fail-before pin: an arm64-only index manifest. The pre-fix
        // body wrote `"amd64"` into `ImageAttestation::architecture`
        // regardless of what skopeo returned. After the fix the call
        // site passes `parse_manifest_architectures(&json).
        // to_attestation_arch()` — the same expression this test pins.
        let arm64_index = format!(
            r#"{{
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "manifests": [
                    {{"digest": "sha256:{D1}",
                      "platform": {{"architecture": "arm64", "os": "linux"}}}}
                ]
            }}"#
        );
        let attestation_arch = parse_manifest_architectures(&arm64_index).to_attestation_arch();
        assert_eq!(
            attestation_arch, "arm64",
            "an arm64-only index manifest must yield architecture=\"arm64\"; \
             the pre-fix hardcode flattened this to \"amd64\""
        );

        // A multi-arch index produces the `multi:`-prefixed composite
        // claim, unmistakable for any literal architecture string the
        // pre-fix hardcode would have produced.
        let multi_index = format!(
            r#"{{
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "manifests": [
                    {{"digest": "sha256:{D1}",
                      "platform": {{"architecture": "arm64", "os": "linux"}}}},
                    {{"digest": "sha256:{D2}",
                      "platform": {{"architecture": "amd64", "os": "linux"}}}}
                ]
            }}"#
        );
        assert_eq!(
            parse_manifest_architectures(&multi_index).to_attestation_arch(),
            "multi:amd64,arm64",
            "a multi-arch index must compose into a multi: prefixed claim, \
             not silently collapse to one architecture"
        );

        // An OCI image manifest references a config blob by digest; the
        // architecture lives inside that config blob, which the `--raw`
        // probe did not fetch. Honest record: the sentinel string, not
        // a guess.
        let image_manifest = format!(
            r#"{{
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": {{
                    "mediaType": "application/vnd.oci.image.config.v1+json",
                    "digest": "sha256:{D1}",
                    "size": 1234
                }},
                "layers": [{{"digest": "sha256:{D2}", "size": 5000}}]
            }}"#
        );
        assert_eq!(
            parse_manifest_architectures(&image_manifest).to_attestation_arch(),
            "embedded-in-config",
            "an image manifest must record the embedded-in-config sentinel, \
             not synthesise an architecture the `--raw` probe never fetched"
        );

        // The probe-failed arm (the `Err(_)` branch of
        // `run_command_output` for skopeo) produces the `Absent`
        // outcome, which collapses to the `"unknown"` sentinel — the
        // value the call site now passes for `ImageAttestation::
        // architecture` on a failed skopeo probe instead of the prior
        // unconditional `"amd64"`.
        assert_eq!(
            OciArchitectureOutcome::Absent.to_attestation_arch(),
            "unknown",
            "the skopeo-probe-failed arm must record \"unknown\", not a \
             hardcoded architecture the probe never substantiated"
        );
    }

    /// Load-bearing SBOM / vuln-scan honesty pin: the prior call sites
    /// in `compute_build_attestation` and `compute_image_attestation`
    /// stamped four name-keyed deterministic constants into every
    /// Phase 1 record as the SBOM / vuln-scan identity:
    /// `Blake3Hash::digest(format!("sbom-{service}", ...))`,
    /// `format!("vuln-scan-{service}", ...)`,
    /// `format!("image-sbom-{tag}", ...)`,
    /// `format!("image-vuln-{tag}", ...)`. No syft / grype probe layer
    /// was integrated, so each was the BLAKE3 of a name template — a
    /// pure function of the artifact's name, with zero relationship
    /// to a real SBOM / scan document. Worse, the paired `(0, 0)` CVE
    /// counts asserted "real scan found zero CVEs" when in fact no
    /// scan was run. The typed primitives
    /// [`crate::security_scan::SbomProbeOutcome::Absent`] and
    /// [`crate::security_scan::VulnScanProbeOutcome::Absent`] are the
    /// honest record: a single per-kind sentinel hash
    /// (`b"no-sbom"` / `b"no-vuln-scan"`), invariant across artifact
    /// name, paired with zero counts that honestly mean "no evidence
    /// collected, never to be confused with a real scan that found
    /// zero". Same shape as
    /// `test_chart_hash_probe_failure_distinguishable_from_empty_chart`
    /// one layer over.
    ///
    /// Fail-before: two services / tags `alpha` and `beta` produced
    /// DIFFERENT `sbom_hash` and `vuln_scan_hash` values (the name was
    /// the only input). After the fix: both yield the same sentinel
    /// (because the same fact — "no probe ran" — holds for both), and
    /// the sentinel is structurally distinct from every pre-fix name-
    /// derived constant under any plausible service / tag.
    #[test]
    fn test_sbom_and_vuln_scan_route_through_typed_probe_outcome() {
        use crate::security_scan::{SbomProbeOutcome, VulnScanProbeOutcome};

        // These are the exact expressions `compute_build_attestation`
        // and `compute_image_attestation` now pass for the SBOM /
        // vuln-scan claims. Pinning them at the call-site expression
        // level (mirrors `test_cosign_signer_identity_flows_into_
        // attestation` and `test_image_architecture_recovered_from_
        // typed_outcome` one layer over) means a future refactor that
        // dropped the typed-primitive route would fail this test
        // before any Phase 1 record was published under the regression.
        let sbom_now = SbomProbeOutcome::Absent.to_attestation_hash();
        let (vuln_now, cve_now, crit_now) = VulnScanProbeOutcome::Absent.to_attestation_fields();

        // The honest sentinels.
        assert_eq!(sbom_now, Blake3Hash::digest(b"no-sbom"));
        assert_eq!(vuln_now, Blake3Hash::digest(b"no-vuln-scan"));
        // Counts default to zero because no scan was run, not because
        // a scan found zero (the latter would carry a real scan-
        // document BLAKE3 in the hash slot — never the b"no-vuln-scan"
        // sentinel paired with zero counts).
        assert_eq!((cve_now, crit_now), (0, 0));

        // The post-fix sbom_hash is invariant across artifact name.
        // The pre-fix `format!("sbom-{}", service)` /
        // `format!("image-sbom-{}", tag)` constants drifted per
        // service / tag; the typed sentinel does not, because the
        // dishonesty being closed is "no probe layer was integrated",
        // which is the same fact regardless of which service or tag
        // is being attested.
        for name in ["alpha", "beta", "service-with-dashes", ""] {
            for pre_fix_template in [
                format!("sbom-{name}"),
                format!("vuln-scan-{name}"),
                format!("image-sbom-{name}"),
                format!("image-vuln-{name}"),
            ] {
                assert_ne!(
                    sbom_now.to_hex(),
                    Blake3Hash::digest(pre_fix_template.as_bytes()).to_hex(),
                    "the post-fix sbom_hash must differ from every \
                     pre-fix name-derived placeholder (here: {pre_fix_template:?}); \
                     conflating them was the prior honesty bug",
                );
                assert_ne!(
                    vuln_now.to_hex(),
                    Blake3Hash::digest(pre_fix_template.as_bytes()).to_hex(),
                    "the post-fix vuln_scan_hash must differ from every \
                     pre-fix name-derived placeholder (here: {pre_fix_template:?})",
                );
            }
        }

        // And distinct from each other and from sibling probe-failure
        // sentinels at the source / build / image / chart layers. The
        // one-sentinel-per-probe discipline relies on these being
        // structurally distinct byte strings; a verifier reading any
        // ONE sentinel hash must be able to recover the kind-of-claim
        // from the value alone, without re-resolving the artifact.
        assert_ne!(sbom_now, vuln_now);
        for sibling in [
            b"no-tree-listing".as_slice(),
            b"no-flake-lock".as_slice(),
            b"no-manifest".as_slice(),
            b"no-chart-dir".as_slice(),
            b"".as_slice(),
        ] {
            assert_ne!(
                sbom_now.to_hex(),
                Blake3Hash::digest(sibling).to_hex(),
                "the b\"no-sbom\" sentinel must differ from sibling \
                 probe-failure sentinels and from blake3-of-empty",
            );
            assert_ne!(
                vuln_now.to_hex(),
                Blake3Hash::digest(sibling).to_hex(),
                "the b\"no-vuln-scan\" sentinel must differ from sibling \
                 probe-failure sentinels and from blake3-of-empty",
            );
        }
    }

    /// **Load-bearing chart-attestation honesty pin: the prior
    /// `true, // Linter: assume passed if forge got this far` literal
    /// at the `ci::chart_attestation` call site stamped a positive
    /// `linter_passed` claim into every Phase 1 chart attestation
    /// regardless of whether `helm lint` had actually probed the
    /// chart inside the certification function.** The typed primitive
    /// `crate::helm_lint::HelmLintOutcome` preserves the four
    /// operational worlds the prior `true` flattened — Passed,
    /// Failed, Malformed, ProbeAbsent — and the call site routes
    /// through `is_passed()`, which returns `true` only on the
    /// `Passed` arm.
    ///
    /// Until a follow-up commit wires `helm lint` shell-out at the
    /// call site, the outcome collapses to `ProbeAbsent` →
    /// `linter_passed: false` — honestly naming "no lint probe ran
    /// inside the certification surface" rather than asserting a
    /// green-lint claim that flow-control alone cannot substantiate.
    /// Same fail-before / pass-after shape as
    /// `test_sbom_and_vuln_scan_route_through_typed_probe_outcome`
    /// one layer over (typed probe-absent sentinel at the call
    /// site, real probe deferred to a follow-up).
    ///
    /// Pin the post-fix call-site expression directly so a future
    /// regression that re-introduced a hardcoded `true` would fail
    /// before any Phase 1 record was published under it: the value
    /// the call site now passes for `linter_passed` is exactly
    /// `HelmLintOutcome::ProbeAbsent.is_passed()`, and that is
    /// structurally `false`. The end-to-end pin then walks
    /// `compute_chart_attestation` against a minimal chart and
    /// confirms `att.linter_passed == false`, where the pre-fix
    /// body would have produced `true` regardless of any probe
    /// evidence.
    #[tokio::test]
    async fn test_linter_passed_routes_through_typed_probe_outcome() {
        use crate::helm_lint::HelmLintOutcome;

        // Call-site expression pin: this is the exact expression
        // `compute_chart_attestation` now passes for `linter_passed`.
        // The pre-fix call site passed the literal `true`; pinning
        // the post-fix expression at this layer means a future
        // refactor that dropped the typed-primitive route would
        // fail this test before any Phase 1 record was published
        // under the regression. Same shape as
        // `test_sbom_and_vuln_scan_route_through_typed_probe_outcome`
        // (`SbomProbeOutcome::Absent.to_attestation_hash()`).
        assert!(
            !HelmLintOutcome::ProbeAbsent.is_passed(),
            "ProbeAbsent must collapse to linter_passed=false in the \
             Phase 1 chart attestation; the pre-fix `true` hardcode \
             sealed a green-lint claim from flow control rather than \
             from evidence",
        );

        // The other three arms also have well-defined bool collapses
        // — Passed → true, Failed → false, Malformed → false. The
        // four-arm distinction is structurally preserved at the enum
        // level even though `is_passed` discards three of them at
        // the bool surface (mirrors the
        // `test_chart_provenance_four_arms_collapse_to_distinct_bools`
        // shape one layer over).
        assert!(HelmLintOutcome::Passed {
            warning_count: 0,
            info_count: 0,
        }
        .is_passed());
        assert!(!HelmLintOutcome::Failed {
            failed_chart_count: 1,
            error_count: 1,
            warning_count: 0,
            info_count: 0,
        }
        .is_passed());
        assert!(!HelmLintOutcome::Malformed.is_passed());

        // End-to-end through compute_chart_attestation: a minimal
        // chart whose `compute_chart_attestation` invocation does
        // not yet spawn `helm lint` produces `linter_passed: false`,
        // where the pre-fix body returned `true` unconditionally.
        // The provenance probe is absent (no `.prov` file), so
        // `provenance_verified` is also `false` here — separately
        // pinned by `test_chart_provenance_four_arms_collapse_to_
        // distinct_bools`, this test isolates the linter claim.
        let tmp = tempfile::tempdir().expect("tempdir");
        let chart_dir = tmp.path().join("example");
        std::fs::create_dir(&chart_dir).expect("mkdir chart");
        std::fs::write(
            chart_dir.join("Chart.yaml"),
            "apiVersion: v2\nname: example\nversion: 0.1.0\n",
        )
        .expect("write Chart.yaml");
        let att = compute_chart_attestation(
            "example",
            "0.1.0",
            &chart_dir,
            "oci://ghcr.io/example/example",
            Some(tmp.path()),
        )
        .await
        .expect("compute_chart_attestation");
        assert!(
            !att.linter_passed,
            "the typed-primitive route at the call site must drive \
             linter_passed=false through to the ChartAttestation \
             record when no lint probe ran; the pre-fix `true` \
             hardcode produced `true` here regardless of any probe \
             evidence",
        );
    }

    /// **Load-bearing chart-attestation honesty pin: the prior
    /// `true, // Policy: assume passed` literal at the
    /// `ci::chart_attestation` call site stamped a positive
    /// `policy_passed` claim into every Phase 1 chart attestation
    /// regardless of whether `kensa` had actually evaluated the
    /// chart inside the certification function.** The typed
    /// primitive `crate::kensa_policy::KensaPolicyOutcome` preserves
    /// the three operational worlds the prior `true` flattened —
    /// `Passed`, `Failed`, `ProbeAbsent` — and the call site routes
    /// through `is_passed()`, which returns `true` only on the
    /// `Passed` arm.
    ///
    /// Until a follow-up commit wires `kensa verify chart` shell-out
    /// at the call site, the outcome collapses to `ProbeAbsent` →
    /// `policy_passed: false` — honestly naming "no policy probe ran
    /// inside the certification surface" rather than asserting a
    /// green-policy claim flow-control alone cannot substantiate.
    /// Same fail-before / pass-after shape as the sibling
    /// `test_linter_passed_routes_through_typed_probe_outcome` one
    /// line up (commit d81f639) and
    /// `test_sbom_and_vuln_scan_route_through_typed_probe_outcome`
    /// two layers over (typed probe-absent at the call site, real
    /// probe deferred to a follow-up).
    ///
    /// Pin the post-fix call-site expression directly so a future
    /// regression that re-introduced a hardcoded `true` would fail
    /// before any Phase 1 record was published under it: the value
    /// the call site now passes for `policy_passed` is exactly
    /// `KensaPolicyOutcome::ProbeAbsent.is_passed()`, and that is
    /// structurally `false`. The end-to-end pin then walks
    /// `compute_chart_attestation` against a minimal chart and
    /// confirms `att.policy_passed == false`, where the pre-fix
    /// body would have produced `true` regardless of any probe
    /// evidence — closes the sibling gap commit d81f639 named
    /// directly in its "Why it compounds" section as the
    /// named-next consumer (b).
    #[tokio::test]
    async fn test_policy_passed_routes_through_typed_probe_outcome() {
        use crate::kensa_policy::KensaPolicyOutcome;

        // Call-site expression pin: this is the exact expression
        // `compute_chart_attestation` now passes for `policy_passed`.
        // The pre-fix call site passed the literal `true`; pinning
        // the post-fix expression at this layer means a future
        // refactor that dropped the typed-primitive route would
        // fail this test before any Phase 1 record was published
        // under the regression. Same shape as
        // `test_linter_passed_routes_through_typed_probe_outcome`
        // one line up (`HelmLintOutcome::ProbeAbsent.is_passed()`).
        assert!(
            !KensaPolicyOutcome::ProbeAbsent.is_passed(),
            "ProbeAbsent must collapse to policy_passed=false in \
             the Phase 1 chart attestation; the pre-fix `true` \
             hardcode sealed a green-policy claim from nothing \
             rather than from evidence",
        );

        // The other two arms also have well-defined bool collapses
        // — Passed → true, Failed → false. The three-arm distinction
        // is structurally preserved at the enum level even though
        // `is_passed` discards two of them at the bool surface
        // (mirrors the `test_chart_provenance_four_arms_collapse_to
        // _distinct_bools` shape one layer over).
        assert!(KensaPolicyOutcome::Passed {
            evaluated_control_count: 17,
        }
        .is_passed());
        assert!(!KensaPolicyOutcome::Failed {
            failed_control_count: 3,
            evaluated_control_count: 17,
        }
        .is_passed());

        // End-to-end through compute_chart_attestation: a minimal
        // chart whose `compute_chart_attestation` invocation does
        // not yet spawn `kensa` produces `policy_passed: false`,
        // where the pre-fix body returned `true` unconditionally.
        // The provenance and linter probes are also absent (no
        // `.prov` file, no `helm lint` shell-out), so
        // `provenance_verified` and `linter_passed` are also
        // `false` here — separately pinned by
        // `test_chart_provenance_four_arms_collapse_to_distinct_
        // bools` and `test_linter_passed_routes_through_typed_
        // probe_outcome`; this test isolates the policy claim.
        let tmp = tempfile::tempdir().expect("tempdir");
        let chart_dir = tmp.path().join("example");
        std::fs::create_dir(&chart_dir).expect("mkdir chart");
        std::fs::write(
            chart_dir.join("Chart.yaml"),
            "apiVersion: v2\nname: example\nversion: 0.1.0\n",
        )
        .expect("write Chart.yaml");
        let att = compute_chart_attestation(
            "example",
            "0.1.0",
            &chart_dir,
            "oci://ghcr.io/example/example",
            Some(tmp.path()),
        )
        .await
        .expect("compute_chart_attestation");
        assert!(
            !att.policy_passed,
            "the typed-primitive route at the call site must drive \
             policy_passed=false through to the ChartAttestation \
             record when no kensa probe ran; the pre-fix `true` \
             hardcode produced `true` here regardless of any probe \
             evidence",
        );
    }

    /// **Load-bearing source-attestation honesty pin: the prior
    /// `.map(|s| s.trim() == "G" || s.trim() == "U").unwrap_or(false)`
    /// fold at the `compute_source_attestation` call site flattened
    /// nine operational worlds (the eight `%G?` codes documented in
    /// git-log(1) plus the probe-failed world) into a single bool,
    /// silently routing `B` (cryptographic verification failed —
    /// evidence of compromise) into the same bucket as `N` (no
    /// signature ever) and into the same bucket as the probe-failed
    /// world.** The typed primitive
    /// `crate::git_signature::GitCommitSignatureOutcome` preserves
    /// each operational world structurally; `is_signed()` collapses
    /// to the pre-fix bool semantics exactly (`G` and `U` → `true`,
    /// every other arm → `false`), so the bool-surface behaviour is
    /// preserved while the type-surface distinction is widened.
    ///
    /// Until a follow-up commit widens `SourceAttestation` to carry
    /// the verdict discriminator directly (a `signature_verdict`
    /// field whose `Bad` / `Expired` / `Revoked` / `Unsigned`
    /// distinction sekiban / in-toto-verify could escalate
    /// differently), the call site routes through `is_signed()` and
    /// the Phase 1 `commit_signed` bool retains its pre-fix value
    /// on every documented input. Same fail-before / pass-after
    /// shape as the sibling
    /// `test_linter_passed_routes_through_typed_probe_outcome` and
    /// `test_policy_passed_routes_through_typed_probe_outcome` two
    /// layers over (typed primitive routes the call site, bool
    /// surface matches the prior collapse exactly, downstream
    /// enrichment deferred to a follow-up).
    ///
    /// Pin the post-fix call-site routing directly so a future
    /// regression that re-introduced the inline `s.trim() == "G" ||
    /// s.trim() == "U"` string match (which silently flattens nine
    /// worlds into one bool) would fail before any Phase 1 record
    /// was published under it: the value the call site now passes
    /// for `commit_signed` is exactly
    /// `GitCommitSignatureOutcome::from_format_code(&captured)
    /// .is_signed()` on success and
    /// `GitCommitSignatureOutcome::ProbeAbsent.is_signed()` on
    /// probe failure, and both routes are structurally pinned here.
    /// The end-to-end pin then walks `compute_source_attestation`
    /// against the hermetic git fixture and confirms the seed
    /// commit (which `init_repo_with_one_commit` produces with
    /// `commit.gpgsign=false` → `%G?` = "N" →
    /// `GitCommitSignatureOutcome::NotSigned` → `is_signed() ==
    /// false`) drives `att.commit_signed == false` — the bool
    /// value the pre-fix call site would have produced too, but
    /// now routed through the typed arm that a future enrichment
    /// can recover the `NotSigned` discriminator from.
    #[tokio::test]
    async fn test_commit_signed_routes_through_typed_signature_outcome() {
        use crate::git_signature::GitCommitSignatureOutcome;

        // Call-site expression pin: the parser-then-`is_signed` route
        // collapses every documented `%G?` code to the same bool the
        // pre-fix inline match would have produced. Pinning the
        // round-trip at this layer means a future refactor that
        // dropped the typed-primitive route would fail this test
        // before any Phase 1 record was published under the
        // regression. Mirrors
        // `test_policy_passed_routes_through_typed_probe_outcome`
        // and `test_linter_passed_routes_through_typed_probe_outcome`
        // one layer up.
        for (code, want) in [
            ("G", true),
            ("U", true),
            ("X", false),
            ("Y", false),
            ("R", false),
            ("B", false),
            ("E", false),
            ("N", false),
            ("G\n", true),
            ("", false),
            ("Z", false),
        ] {
            assert_eq!(
                GitCommitSignatureOutcome::from_format_code(code).is_signed(),
                want,
                "parser→is_signed must match the pre-fix `s.trim() == \"G\" \
                 || s.trim() == \"U\"` collapse exactly for code {code:?}; \
                 the honesty refactor preserves bool-surface semantics while \
                 widening the type surface",
            );
        }
        // Probe-absent route pin: the value the call site falls back
        // to when `run_command_output(...)` errors is exactly
        // `GitCommitSignatureOutcome::ProbeAbsent.is_signed()`, which
        // is structurally `false`. The pre-fix path's
        // `.unwrap_or(false)` produced the same bool here but routed
        // through an inline literal that lost the "no probe ran"
        // discriminator a downstream verifier could otherwise recover
        // from the typed arm.
        assert!(
            !GitCommitSignatureOutcome::ProbeAbsent.is_signed(),
            "ProbeAbsent must collapse to commit_signed=false at the \
             Phase 1 attestation surface; the structural distinction \
             from NotSigned / BadSignature is what a future enrichment \
             walks",
        );

        // End-to-end through compute_source_attestation: the hermetic
        // git fixture produces a seed commit with `commit.gpgsign=false`,
        // so `git log -1 --format=%G?` reports "N" (no signature) →
        // `GitCommitSignatureOutcome::NotSigned` → `is_signed() ==
        // false` → `att.commit_signed == false`. The pre-fix path
        // would have produced the same bool here, but the typed-route
        // pin above ensures the value flows through the structural
        // discriminator a future enrichment can recover the `NotSigned`
        // arm from.
        let tmp = tempfile::tempdir().expect("tempdir");
        crate::test_support::init_repo_with_one_commit(tmp.path());
        let sha_out = std::process::Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(tmp.path())
            .output()
            .expect("git rev-parse spawn");
        assert!(
            sha_out.status.success(),
            "git rev-parse HEAD must succeed in {:?}",
            tmp.path(),
        );
        let sha = String::from_utf8(sha_out.stdout)
            .expect("git sha utf-8")
            .trim()
            .to_string();
        let att = compute_source_attestation(tmp.path(), &sha)
            .await
            .expect("compute_source_attestation");
        assert!(
            !att.commit_signed,
            "the typed-primitive route at the call site must drive \
             commit_signed=false through to the SourceAttestation \
             record for an unsigned commit (`%G?` = \"N\" → \
             GitCommitSignatureOutcome::NotSigned → is_signed() = \
             false); the pre-fix `s.trim() == \"G\" || s.trim() == \
             \"U\"` collapse produced the same bool here but routed \
             through an inline literal that flattened the discriminator",
        );
    }
}
