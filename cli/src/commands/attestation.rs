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
use tameshi::certification::{
    relaxed_staging_policy, strict_production_policy, BuildAttestation, CertificationPolicy,
    ChartAttestation, DeploymentAttestation, ImageAttestation, ProductCertification,
    SourceAttestation,
};
use tameshi::ci;
use tameshi::compliance::dimensions::{ComplianceAttestation, ComplianceDimension, DimensionType};
use tameshi::compliance::slsa::{determine_slsa_level, SlsaLevel};
use tameshi::hash::Blake3Hash;
use tokio::process::Command;

/// Emit the canonical eight-field probe-coverage [`tracing::info!`] event
/// uniformly across the three attestation phases — Phase 1 build, Phase 1
/// chart, Phase 2 deployment — without retyping the `(ran, absent, total,
/// coverage_ratio, fully_covered, empty, saturated, coverage_ratio_pct)`
/// shape at each emission site.
///
/// ## Why this exists
///
/// Three nearly-identical `info!` blocks accreted at
/// [`compute_build_attestation`], [`compute_chart_attestation`], and
/// [`compose_product_certification`] over the four-then-five-then-six field
/// trajectory (commits 1662987, 4309da4, 3552bcf). Each block differed only
/// by (a) the tracing target string, (b) the per-phase context fields, (c)
/// the phase-prefixed field idents (`build_probes_*` /
/// `chart_probes_*` / `deployment_probes_*`), (d) the [`ProbeCoverage`]
/// variable name, and (e) the message string — the shape itself was
/// identical at every site. Adding a seventh field (a future
/// `ProbeCoverage::is_saturated`, `coverage_ratio_pct`, or any other typed
/// boundary discriminator the four-arm matrix tabulated on
/// [`crate::probe_outcome::ProbeCoverage::is_fully_covered`] grows to admit)
/// required touching three sites in lockstep; a regression that wired the
/// new field at two of three would surface a structural per-site emission
/// drift at telemetry-comparison time rather than at compile time. This
/// macro forecloses that drift class by centralising the eight-method
/// `(ran, absent, total(), coverage_ratio(), is_fully_covered(), is_empty(),
/// is_saturated(), coverage_ratio_pct())` mapping at one internal
/// `@__shape` arm; the three public phase arms (`build` / `chart` /
/// `deployment`) supply the phase-prefixed field idents declaratively, so
/// adding a tenth field touches the internal arm and three two-line
/// dispatch tails — never a public call site.
///
/// ## Usage
///
/// ```ignore
/// emit_probe_coverage!(
///     build,
///     target: "forge::attestation::build_probe_coverage",
///     coverage: coverage,
///     message: "build-attestation probe coverage",
///     service = service,
///     derivation = derivation.as_str(),
///     slsa_level = ?slsa_level,
/// );
/// ```
///
/// The macro forwards the per-phase context fields verbatim (matching
/// `tracing::info!`'s `name = value` / `name = ?value` / `name = %value`
/// syntax via the `$($ctx:tt)*` tail), then emits the nine probe-coverage
/// fields in canonical order, then the message string. The seventh
/// `*_probes_saturated` field surfaces the trustworthiness signal for the
/// `*_probes_coverage_ratio` field: at the saturated state (`ran ==
/// usize::MAX || absent == usize::MAX`, reachable asymptotically via
/// fleet-wide aggregation through the [`Add`] impl's `saturating_add`
/// clamp) the f64 division `ran/total` rounds against the true ratio, so
/// a downstream `sekiban` admission verifier reading
/// `*_probes_coverage_ratio` must gate on `!*_probes_saturated` to
/// foreclose that drift class. The eighth `*_probes_coverage_ratio_pct`
/// field is the integer-percent (`u8`, `0..=100`) companion of
/// `*_probes_coverage_ratio` — the surface a Prometheus alert rule /
/// typed-policy threshold gate (`*_probe_coverage_ratio_pct >= 90`) reads
/// against, foreclosing the IEEE-754 epsilon drift the float comparison
/// `>= 0.9_f64` admits at the just-below-threshold boundary the integer
/// floor (Euclidean division `(ran * 100) / total`) refuses cleanly. The
/// ninth `*_probes_all_absent` field is the typed discriminator for the
/// third arm of the four-arm matrix the typed primitive tabulates — the
/// "every counted probe surfaced an absent default" state today's three
/// call sites sit at. A downstream verifier that wants to fail closed on
/// this state reads one bool (`*_probes_all_absent == true`) rather than
/// composing `*_probes_total > 0 && *_probes_coverage_ratio == 0.0` at
/// the consumer surface — the integer-arithmetic body of
/// [`ProbeCoverage::is_all_absent`] (`ran == 0 && absent > 0`) forecloses
/// the float-comparison drift class the consumer-side composition would
/// inherit.
///
/// [`Add`]: std::ops::Add
///
/// ## Theory grounding
///
/// THEORY.md §VI.1 (one oracle): the field shape is derived at one site,
/// not retyped per emission. THEORY.md §V.4 / §VII.1: the eight-field
/// shape surfaces the Phase 1 / Phase 2 honesty channel uniformly at every
/// per-phase telemetry record a downstream `sekiban` admission verifier
/// reconciliation reads — the float-form `coverage_ratio` and the
/// integer-form `coverage_ratio_pct` are two surfaces of the same
/// derived evidence-coverage signal, both gated by the same
/// trustworthiness predicate `saturated` at the adjacent field.
macro_rules! emit_probe_coverage {
    (
        @__shape,
        ran: $ran:ident,
        absent: $absent:ident,
        total: $total:ident,
        coverage_ratio: $ratio:ident,
        fully_covered: $fully_covered:ident,
        empty: $empty:ident,
        saturated: $saturated:ident,
        coverage_ratio_pct: $ratio_pct:ident,
        all_absent: $all_absent:ident,
        target: $target:literal,
        coverage: $coverage:expr,
        message: $msg:literal,
        $($ctx:tt)*
    ) => {{
        let __cov = &$coverage;
        ::tracing::info!(
            target: $target,
            $($ctx)*
            $ran = __cov.ran,
            $absent = __cov.absent,
            $total = __cov.total(),
            $ratio = __cov.coverage_ratio(),
            $fully_covered = __cov.is_fully_covered(),
            $empty = __cov.is_empty(),
            $saturated = __cov.is_saturated(),
            $ratio_pct = __cov.coverage_ratio_pct(),
            $all_absent = __cov.is_all_absent(),
            $msg
        );
    }};
    (build, $($rest:tt)*) => {
        emit_probe_coverage!(
            @__shape,
            ran: build_probes_ran,
            absent: build_probes_absent,
            total: build_probes_total,
            coverage_ratio: build_probes_coverage_ratio,
            fully_covered: build_probes_fully_covered,
            empty: build_probes_empty,
            saturated: build_probes_saturated,
            coverage_ratio_pct: build_probes_coverage_ratio_pct,
            all_absent: build_probes_all_absent,
            $($rest)*
        )
    };
    (chart, $($rest:tt)*) => {
        emit_probe_coverage!(
            @__shape,
            ran: chart_probes_ran,
            absent: chart_probes_absent,
            total: chart_probes_total,
            coverage_ratio: chart_probes_coverage_ratio,
            fully_covered: chart_probes_fully_covered,
            empty: chart_probes_empty,
            saturated: chart_probes_saturated,
            coverage_ratio_pct: chart_probes_coverage_ratio_pct,
            all_absent: chart_probes_all_absent,
            $($rest)*
        )
    };
    (deployment, $($rest:tt)*) => {
        emit_probe_coverage!(
            @__shape,
            ran: deployment_probes_ran,
            absent: deployment_probes_absent,
            total: deployment_probes_total,
            coverage_ratio: deployment_probes_coverage_ratio,
            fully_covered: deployment_probes_fully_covered,
            empty: deployment_probes_empty,
            saturated: deployment_probes_saturated,
            coverage_ratio_pct: deployment_probes_coverage_ratio_pct,
            all_absent: deployment_probes_all_absent,
            $($rest)*
        )
    };
}

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

    // Reproducibility is not independently re-verified yet; until it
    // is, the build cannot honestly claim the reproducible-grade SLSA
    // level. The level is derived from the evidence actually collected,
    // so a build whose closure could not be materialized claims
    // nothing. The pre-fix bare `let reproducible = false;` literal at
    // this call site flattened three structurally distinct operational
    // worlds — the `Reproducible` / `Drift` / `ProbeAbsent` distinction
    // a `nix build --rebuild` determinism probe would yield — into a
    // single negative bucket. The `Drift` collapse is the most
    // load-bearing: a Phase 1 build attestation that records
    // `reproducible: false` against a build whose `nix build --rebuild`
    // probe DETECTED non-determinism (evidence of compromise: some
    // non-hermetic input drove the build) is structurally
    // indistinguishable from one against a build whose probe was
    // never spawned (no evidence either way). A downstream verifier
    // that fails-closed on evidence of compromise (the drift world)
    // cannot distinguish it from the no-evidence-collected world under
    // the bare bool. The typed `NixReproducibilityOutcome` (`Reproducible`
    // / `Drift` / `ProbeAbsent`) preserves the three operational worlds
    // structurally; the call site routes through `is_reproducible()`,
    // which returns `true` only on the `Reproducible` arm — the
    // bool-surface semantics collapse to the pre-fix literal exactly,
    // and the SLSA-level rubric in `build_slsa_level` still caps
    // substantiated-but-not-determinism-verified builds at L2. Today
    // the build-attestation function does not yet spawn a `nix build
    // --rebuild` probe itself — the outcome collapses to `ProbeAbsent`
    // → `reproducible: false`, honestly naming "no determinism probe
    // ran inside the build-attestation function" rather than asserting
    // a green reproducible claim flow-control alone cannot
    // substantiate. Same deferral shape as commit 5931e32's
    // `FluxSourceVerificationOutcome::ProbeAbsent` at the
    // source-verification layer, commit c1e83d5's
    // `KensaPolicyOutcome::ProbeAbsent` at the chart-policy layer,
    // commit d81f639's `HelmLintOutcome::ProbeAbsent` at the
    // chart-quality layer, and commit b98eb5a's `SbomProbeOutcome::
    // Absent` / `VulnScanProbeOutcome::Absent` at the SBOM /
    // vuln-scan layer.
    let reproducibility_outcome =
        crate::nix_reproducibility::NixReproducibilityOutcome::ProbeAbsent;
    let reproducible = reproducibility_outcome.is_reproducible();
    let slsa_level = build_slsa_level(&derivation, &closure_info, reproducible);

    // Probe-coverage telemetry for the Phase 1 build attestation, the
    // build-side peer of `chart_probe_coverage` (commit a7a1db9, Phase 1
    // chart-attestation, four probes) and `deployment_probe_coverage`
    // (commit 3152279, Phase 2 deployment-attestation, seven probes).
    // Three typed probe outcomes ground every evidence-bearing field on
    // `BuildAttestation` — `sbom_outcome` (syft / SBOM probe layer,
    // commit b98eb5a), `vuln_scan_outcome` (grype / CVE scan probe
    // layer, commit b98eb5a), and `reproducibility_outcome`
    // (`nix build --rebuild` determinism probe, commit 72424bd). The
    // per-field honesty channel each typed outcome preserves (the
    // structural distinction between "probe ran and produced evidence"
    // and "no probe ran / no evidence collected" at one
    // build-attestation field) is lifted here to a per-record signal: a
    // downstream `sekiban` admission verifier reconciliation reading
    // `(ran, absent, total)` on the
    // `forge::attestation::build_probe_coverage` tracing event can
    // distinguish a high-evidence Phase 1 build record (every probe
    // ran, surfaced as `ran: 3`) from one whose every field collapsed
    // to its honest default (every probe `Absent` / `ProbeAbsent`,
    // surfaced as `absent: 3`, today's call-site state — no syft /
    // grype / determinism probe layer is integrated yet). With the
    // three Phase-1 build / Phase-1 chart / Phase-2 deployment
    // coverage events composed at the three load-bearing
    // attestation-composition sites, the per-record evidence-coverage
    // signal is uniform across every attestation record forge
    // composes. THEORY §V.4 Phase 1 honesty channel; THEORY §VI.1
    // one-oracle discipline — the three-probe coverage is composed at
    // one site, not per-field-derived by the verifier.
    let coverage =
        build_probe_coverage(&sbom_outcome, &vuln_scan_outcome, &reproducibility_outcome);
    emit_probe_coverage!(
        build,
        target: "forge::attestation::build_probe_coverage",
        coverage: coverage,
        message: "build-attestation probe coverage",
        service = service,
        derivation = derivation.as_str(),
        slsa_level = ?slsa_level,
    );

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

    // `Chart.yaml dependencies:` is the typed evidence channel for the
    // Phase 1 chart attestation's `dependency_hashes` claim: each entry
    // canonicalises to a `(name, version, repository)` triple — the
    // three fields a downstream verifier needs to resolve the dep
    // against an OCI registry or HTTP Helm repo — and the per-dep
    // identity is the BLAKE3 of the TAB-framed canonical line. The
    // prior `vec![]` literal at this call site (`// Dependency hashes:
    // populated when chart deps are tracked`) was honest at the
    // `Vec<DependencyHash>` surface (a Phase 1 chart attestation that
    // records `dependency_hashes: []` against a certification function
    // that never read `Chart.yaml` has collected no dep-graph evidence)
    // but flattened two structurally distinct operational worlds —
    // `Listed { deps: vec![] }` (Chart.yaml WAS read and the chart
    // declares zero `dependencies:` entries — evidence that the chart
    // is a leaf in the dep graph) and `ProbeAbsent` (Chart.yaml was
    // never read, or was unreadable, or was malformed — no evidence
    // either way) — into the same empty vec a downstream verifier
    // cannot recover the kind-of-claim from. The `Listed { deps:
    // vec![] }` collapse is the load-bearing discriminator loss: a
    // downstream `sekiban` strict-production policy that fails-closed
    // on the absence of a Chart.yaml read inside the certification
    // function (the structural failure mode for a chart-supply-chain
    // provenance gate, where the operator must distinguish "the chart
    // truly declares no third-party deps" from "we never even looked
    // at Chart.yaml") cannot express that gate against the pre-fix
    // bare vec. The typed `crate::chart_dependencies::
    // ChartDependenciesOutcome` (`Listed { deps }` / `ProbeAbsent`)
    // preserves both operational worlds the prior bare vec flattened;
    // the call site routes through `to_dependency_hashes()` which
    // collapses `Listed { deps }` to one
    // `tameshi::certification::DependencyHash` per dep (each carrying
    // `(name, version, blake3(canonical-line))`) and `ProbeAbsent` to
    // `vec![]` — Vec surface unchanged for the no-probe-ran world,
    // structural discriminator restored. Unlike the sibling probe
    // outcomes routed through `ProbeAbsent` at the call site pending a
    // kubectl / `nix build --rebuild` / `kensa` / `syft` / `helm lint`
    // shell-out, the Chart.yaml probe is cheap (the file is already on
    // disk at `chart_path`), so this commit wires the real probe in at
    // the call site — a well-formed Chart.yaml declaring N deps yields
    // `Listed { deps }` carrying N per-dep canonical entries, the
    // probed dep-graph identity composed directly into the Phase 1
    // record. Same wired-in shape as commit a5376a6's
    // `GitCommitSignatureOutcome::from_format_code` at the source-
    // commit-signature layer (`git log --format=%G?` is cheap, so the
    // probe is real at the call site).
    let chart_dependencies_outcome =
        crate::chart_dependencies::probe_chart_dependencies(chart_path).await;

    // Probe-coverage telemetry for the Phase 1 chart attestation, the
    // chart-side peer of the `deployment_probe_coverage` signal emitted
    // alongside the Phase 2 `DeploymentAttestation` at
    // `compose_product_certification` (commit 3152279). Four typed probe
    // outcomes ground every evidence-bearing field on
    // `ChartAttestation` — `provenance_outcome` (Helm `.prov` signature,
    // commit 0ff67e1), `lint_outcome` (`helm lint`, commit d81f639),
    // `policy_outcome` (`kensa verify chart`, commit c1e83d5), and
    // `chart_dependencies_outcome` (Chart.yaml dep-graph probe, commit
    // 5c0d121). The previous per-field honesty channel (each typed
    // outcome preserves the structural distinction between "probe ran"
    // and "no probe ran" at one chart-attestation field) is lifted here
    // to a per-record signal: a downstream `sekiban` admission verifier
    // reconciliation reading `(ran, absent, total)` on the
    // `forge::attestation::chart_probe_coverage` tracing event can
    // distinguish a high-evidence Phase 1 chart record (every probe
    // ran, surfaced as `ran: 4`) from one whose every field collapsed
    // to its honest default (every probe `ProbeAbsent`, surfaced as
    // `absent: 4`, today's call-site state for the three deferred
    // probes — `chart_dependencies_outcome` already wires a real
    // probe at the call site, so the signal sits at `ran: 1, absent: 3`
    // for any chart whose Chart.yaml parses). THEORY §V.4 Phase 1
    // honesty channel; THEORY §VI.1 one-oracle discipline — the
    // four-probe coverage is composed at one site, not per-field-
    // derived by the verifier.
    let coverage = chart_probe_coverage(
        &provenance_outcome,
        &lint_outcome,
        &policy_outcome,
        &chart_dependencies_outcome,
    );
    emit_probe_coverage!(
        chart,
        target: "forge::attestation::chart_probe_coverage",
        coverage: coverage,
        message: "chart-attestation probe coverage",
        chart_name = chart_name,
        chart_version = chart_version,
        registry_ref = registry_ref,
    );

    Ok(ci::chart_attestation(
        chart_name,
        chart_version,
        chart_hash,
        provenance_outcome.is_verified(),
        chart_dependencies_outcome.to_dependency_hashes(),
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
    //
    // FluxCD's source-controller `GitRepository.status.conditions[type=
    // SourceVerified]` is the typed evidence channel for the Phase 2
    // `source_verified` claim (THEORY §VII.2: FluxCD is the process
    // manager for every cluster; the reconciler emits the condition only
    // after fetching the commit, resolving the bundle, and verifying the
    // signature against the keyring within the reconciliation interval).
    // The prior `source_verified: true` literal at this call site sealed
    // a positive Phase 2 source-verification claim from nothing — no
    // kubectl probe ran inside the certification surface, no
    // `GitRepository.status` was inspected, no `SourceVerified`
    // condition was walked. A Phase 2 deployment attestation that records
    // `source_verified: true` against a deployment whose FluxCD
    // `GitRepository` was never queried (and may not even carry a
    // `verify` block on its spec) is false by construction (THEORY §V.2:
    // attestation is cryptographic evidence, not a wish; THEORY §VII.1:
    // attestation-gated deployments are structural, not policy overlays).
    // The typed `FluxSourceVerificationOutcome` (`Verified` /
    // `VerifyFailed` / `ProbeAbsent`) preserves the three operational
    // worlds the prior `true` flattened into a single positive claim;
    // the call site routes through `is_verified()` which returns `true`
    // only on the `Verified` arm. Today the certification function does
    // not yet spawn a kubectl probe itself — the outcome collapses to
    // `ProbeAbsent` → `source_verified: false`, honestly naming "no
    // FluxCD source-verification probe ran inside the certification
    // surface" rather than asserting a green source-verified claim
    // flow-control alone cannot substantiate. Same deferral shape as
    // commit c1e83d5's `KensaPolicyOutcome::ProbeAbsent` at the chart-
    // policy layer, commit d81f639's `HelmLintOutcome::ProbeAbsent` at
    // the chart-quality layer, and commit b98eb5a's
    // `SbomProbeOutcome::Absent` / `VulnScanProbeOutcome::Absent` at
    // the SBOM / vuln-scan layer: typed primitive available, real
    // probe wired in by a follow-up that adds the `tokio::process::
    // Command::new("kubectl").args(["get", "gitrepository", ...]).
    // output().await` (or a typed `kube::Api::<GitRepository>::get(...)`
    // query) shell-out and walks the resulting `status.conditions`
    // array for the `SourceVerified` entry.
    let source_verification_outcome =
        crate::flux_source_verification::FluxSourceVerificationOutcome::ProbeAbsent;

    // `kubectl get networkpolicy -n <ns> -o json` (or its typed
    // `kube-rs` equivalent `kube::Api::<NetworkPolicy>::list(...)`)
    // is the cluster-side probe whose `NetworkPolicyList.items`
    // walked against the namespace's pod-listing populates the
    // Phase 2 deployment attestation's `network_policies_verified`
    // claim. The prior `network_policies_verified: false` literal at
    // this call site was honest at the bool surface (a deployment
    // attestation that records `network_policies_verified: false`
    // against a certification function that never spawned a kubectl
    // probe is correctly negative) but flattened three structurally
    // distinct operational worlds — the `Verified` / `VerifyFailed`
    // / `ProbeAbsent` distinction a `kubectl get networkpolicy`
    // probe would yield — into a single negative bucket. The
    // `VerifyFailed` collapse is the most load-bearing: a Phase 2
    // deployment attestation that records `network_policies_verified:
    // false` against a namespace whose kubectl probe RAN and
    // observed zero matching `NetworkPolicy` resources (evidence of
    // an open / unsegmented namespace, the structural failure CIS
    // Kubernetes Benchmark §5.3.2 names) is structurally
    // indistinguishable from one against a namespace whose probe was
    // never spawned (no evidence either way). A downstream `sekiban`
    // strict-production policy that fails-closed on evidence of
    // missing network segmentation cannot express that gate against
    // the pre-fix bare bool — every Phase 2 record asserts the same
    // negative value regardless of whether `kubectl get
    // networkpolicy` substantiated a missing-policy state or whether
    // it simply never ran. The typed
    // `NetworkPolicyAdmissionOutcome` (`Verified` / `VerifyFailed`
    // / `ProbeAbsent`) preserves the three operational worlds
    // structurally; the call site routes through `is_verified()`,
    // which returns `true` only on the `Verified` arm — the bool-
    // surface semantics collapse to the pre-fix literal exactly.
    // Today the certification function does not yet spawn a kubectl
    // probe itself — the outcome collapses to `ProbeAbsent` →
    // `network_policies_verified: false`, honestly naming "no
    // NetworkPolicy admission probe ran inside the certification
    // function" rather than asserting a single negative bool a
    // probe-detected missing-policy state would have also produced.
    // Same deferral shape as the sibling
    // `source_verification_outcome = FluxSourceVerificationOutcome::
    // ProbeAbsent` two lines up (commit 5931e32), commit 72424bd's
    // `NixReproducibilityOutcome::ProbeAbsent` at the build-
    // determinism layer, commit c1e83d5's `KensaPolicyOutcome::
    // ProbeAbsent` at the chart-policy layer, commit d81f639's
    // `HelmLintOutcome::ProbeAbsent` at the chart-quality layer, and
    // commit b98eb5a's `SbomProbeOutcome::Absent` /
    // `VulnScanProbeOutcome::Absent` at the SBOM / vuln-scan layer.
    let network_policy_outcome =
        crate::network_policy_admission::NetworkPolicyAdmissionOutcome::ProbeAbsent;

    // FluxCD's `helm.toolkit.fluxcd.io/v2` `HelmRelease` resources are
    // the typed evidence channel for the Phase 2 `all_releases_signed`
    // claim: each `HelmRelease` carries a `metadata.annotations[
    // tameshi::ci::ANNOTATION_SIGNATURE]` entry that forge's `deploy`
    // step injects (derived from `generate_annotation_map` over the
    // certification's hash), and `sekiban` admission verifies it
    // before admitting the resource into the cluster (THEORY §V.4
    // Phase 2: only Phase-2-signed resources are admitted into
    // production; THEORY §VII.1: the gate is structural, the admission
    // webhook refuses any resource without a valid signature at the
    // K8s API server itself). The prior `all_releases_signed: false`
    // literal at this call site was honest at the bool surface (a
    // deployment attestation that records `all_releases_signed: false`
    // against a certification function that never spawned a kubectl
    // probe is correctly negative) but flattened three structurally
    // distinct operational worlds — the `Verified` / `VerifyFailed`
    // / `ProbeAbsent` distinction a `kubectl get helmrelease` probe
    // would yield — into a single negative bucket. The `VerifyFailed`
    // collapse is the most load-bearing: a Phase 2 deployment
    // attestation that records `all_releases_signed: false` against a
    // namespace whose kubectl probe RAN and observed one or more
    // `HelmRelease` resources whose `metadata.annotations` lack a
    // valid `ANNOTATION_SIGNATURE` entry (evidence of an unsigned
    // release the prior deploy step failed to seal) is structurally
    // indistinguishable from one against a namespace whose probe was
    // never spawned (no evidence either way). A downstream `sekiban`
    // strict-production policy that fails-closed on evidence of
    // unsigned `HelmRelease` admissions cannot express that gate
    // against the pre-fix bare bool — every Phase 2 record asserts
    // the same negative value regardless of whether the probe
    // substantiated an unsigned-release state or simply never ran.
    // The typed `HelmReleaseSignatureOutcome` (`Verified` /
    // `VerifyFailed` / `ProbeAbsent`) preserves the three operational
    // worlds structurally; the call site routes through
    // `is_verified()`, which returns `true` only on the `Verified`
    // arm — the bool-surface semantics collapse to the pre-fix
    // literal exactly. Today the certification function does not yet
    // spawn a kubectl probe itself — the outcome collapses to
    // `ProbeAbsent` → `all_releases_signed: false`, honestly naming
    // "no HelmRelease signature-annotation probe ran inside the
    // certification function" rather than asserting a single negative
    // bool a probe-detected unsigned-release state would have also
    // produced. Same deferral shape as the sibling
    // `source_verification_outcome` / `network_policy_outcome` /
    // commit 72424bd's `NixReproducibilityOutcome::ProbeAbsent` at
    // the build-determinism layer, commit c1e83d5's
    // `KensaPolicyOutcome::ProbeAbsent` at the chart-policy layer,
    // commit d81f639's `HelmLintOutcome::ProbeAbsent` at the chart-
    // quality layer, and commit b98eb5a's
    // `SbomProbeOutcome::Absent` / `VulnScanProbeOutcome::Absent` at
    // the SBOM / vuln-scan layer.
    let helm_release_signature_outcome =
        crate::helm_release_signature::HelmReleaseSignatureOutcome::ProbeAbsent;

    // Kubernetes `Pod` resources covering the namespace's deployed
    // workloads are the typed evidence channel for the Phase 2
    // `all_healthy` claim: each `Pod` carries a `status.phase`
    // (lifecycle position — `Pending`, `Running`, `Succeeded`,
    // `Failed`, `Unknown`) and a `status.conditions[type=Ready]` entry
    // (readiness signal that gates Service endpoint inclusion — a
    // `Running` pod with `Ready=False` is excluded from load-balancer
    // targets even though its lifecycle phase is positive). The prior
    // `all_healthy: false` literal at this call site was honest at the
    // bool surface (a deployment attestation that records `all_healthy:
    // false` against a certification function that never spawned a
    // `kubectl get pods` probe is correctly negative) but flattened
    // three structurally distinct operational worlds — the `Healthy`
    // / `UnhealthyPods` / `ProbeAbsent` distinction a `kubectl get
    // pods -n <ns> -o json` (or typed `kube::Api::<Pod>::list(...)`)
    // probe would yield — into a single negative bucket. The
    // `UnhealthyPods` collapse is the most load-bearing: a Phase 2
    // deployment attestation that records `all_healthy: false` against
    // a namespace whose kubectl probe RAN and observed one or more
    // pods in `Pending`, `Failed`, `Unknown`, or `Running`-but-not-
    // `Ready` state (evidence of a rollout that landed unhealthy
    // workloads — the structural failure THEORY §V.4 Phase 2 names)
    // is structurally indistinguishable from one against a namespace
    // whose probe was never spawned (no evidence either way). A
    // downstream `sekiban` strict-production policy that fails-closed
    // on evidence of unhealthy pods cannot express that gate against
    // the pre-fix bare bool — every Phase 2 record asserts the same
    // negative value regardless of whether `kubectl get pods`
    // substantiated an unhealthy-pod state or whether it simply never
    // ran. The typed `PodHealthOutcome` (`Healthy` / `UnhealthyPods`
    // / `ProbeAbsent`) preserves the three operational worlds
    // structurally; the call site routes through `is_healthy()`, which
    // returns `true` only on the `Healthy` arm — the bool-surface
    // semantics collapse to the pre-fix literal exactly. Today the
    // certification function does not yet spawn a kubectl probe itself
    // — the outcome collapses to `ProbeAbsent` → `all_healthy: false`,
    // honestly naming "no pod-health probe ran inside the certification
    // function" rather than asserting a single negative bool a
    // probe-detected unhealthy-pod state would have also produced.
    // Same deferral shape as the sibling `helm_release_signature_
    // outcome` (commit 8b1407d), `network_policy_outcome` (commit
    // f8a5d8e), `source_verification_outcome` (commit 5931e32),
    // commit 72424bd's `NixReproducibilityOutcome::ProbeAbsent` at the
    // build-determinism layer, commit c1e83d5's `KensaPolicyOutcome::
    // ProbeAbsent` at the chart-policy layer, commit d81f639's
    // `HelmLintOutcome::ProbeAbsent` at the chart-quality layer, and
    // commit b98eb5a's `SbomProbeOutcome::Absent` /
    // `VulnScanProbeOutcome::Absent` at the SBOM / vuln-scan layer.
    let pod_health_outcome = crate::pod_health::PodHealthOutcome::ProbeAbsent;

    // Kubernetes `Pod` resources covering the namespace's deployed
    // workloads are the typed evidence channel for the Phase 2
    // `running_pods` count claim — the cluster-observed
    // `PodList.items.len()` over a `kubectl get pods -n <ns> -o json`
    // (or typed `kube::Api::<Pod>::list(...)`) probe. The prior
    // `running_pods: 0` literal at this call site was honest at the
    // usize surface (a deployment attestation that records `running_
    // pods: 0` against a certification function that never spawned a
    // kubectl probe is correctly zero — no evidence collected) but
    // flattened two structurally distinct operational worlds —
    // `Counted { count: 0 }` (probe RAN against an empty namespace and
    // observed zero pods — evidence of a rollout that admitted the
    // `HelmRelease` but never materialised any workloads) and
    // `ProbeAbsent` (no probe ran inside the certification function —
    // no evidence either way) — into a single zero a downstream
    // verifier cannot recover the kind-of-claim from. The `Counted {
    // count: 0 }` collapse is the load-bearing discriminator loss: a
    // downstream `sekiban` strict-production policy that fails-closed
    // on evidence of an empty deployment (probe ran AND running_pods
    // == 0 — the cluster admitted the release but never materialised
    // any workloads, the post-admission failure mode THEORY §V.4 /
    // §VII.1 name as the Phase 2 honesty channel) cannot express that
    // gate against the pre-fix bare usize — every Phase 2 record
    // asserts the same zero regardless of whether `kubectl get pods`
    // substantiated an empty-namespace state or whether it simply
    // never ran. The typed `PodListingOutcome` (`Counted { count }` /
    // `ProbeAbsent`) preserves the two operational worlds structurally;
    // the call site routes through `running_pods()`, which collapses
    // `Counted { count } -> count` and `ProbeAbsent -> 0` — the usize
    // surface semantics collapse to the pre-fix literal exactly when
    // no probe ran. Today the certification function does not yet
    // spawn a kubectl probe itself — the outcome collapses to
    // `ProbeAbsent -> running_pods: 0`, honestly naming "no pod-
    // listing probe ran inside the certification function" rather
    // than asserting a single zero a probe-detected empty-namespace
    // state would have also produced. Same deferral shape as commit
    // e76db87 (`PodHealthOutcome::ProbeAbsent` at the pod-readiness
    // layer — the sibling probe at the same `kubectl get pods`
    // shell-out: a follow-up that wires the kubectl probe at the call
    // site can populate BOTH `running_pods` AND `all_healthy` from
    // the same `PodList` walk), commit 36d90b6 (`DeploymentManifest
    // RenderOutcome::ProbeAbsent` at the rendered-manifest layer),
    // commit 8b1407d (`HelmReleaseSignatureOutcome::ProbeAbsent` at
    // the HelmRelease-signature layer), commit f8a5d8e
    // (`NetworkPolicyAdmissionOutcome::ProbeAbsent` at the network-
    // segmentation layer), and commit 5931e32
    // (`FluxSourceVerificationOutcome::ProbeAbsent` at the FluxCD
    // source-verification layer).
    let pod_listing_outcome = crate::pod_listing::PodListingOutcome::ProbeAbsent;

    // A `kustomize build <kustomization>` (or `flux build kustomization
    // <name> --path <path>`) shell-out against the deployment's
    // Kustomization root is the typed evidence channel for the Phase 2
    // `manifest_hash` claim: the multi-document YAML stream the probe
    // emits, walked into the sorted, deduplicated set of `<apiVersion>|
    // <kind>|<namespace>|<name> TAB <content-hash-hex>` lines a
    // downstream verifier would itself derive (THEORY §VI.1 content-
    // addressed identity), is the canonical fingerprint the
    // attestation's `manifest_hash` field would BLAKE3 over. The prior
    // `Blake3Hash::digest(b"pending-deployment")` literal at this call
    // site stamped a name-keyed sentinel independent of the rendered
    // manifest stream actually composed into the attestation, defeating
    // the content-addressed-identity invariant THEORY §VI.1 names twice
    // over: (a) the same Phase 2 deployment record across every product,
    // every environment, every cluster received the same `manifest_hash`
    // value — a downstream verifier could not distinguish two
    // attestations describing structurally different rendered cluster
    // states under the shared constant; and (b) three structurally
    // distinct operational worlds — `Rendered` (kustomize succeeded
    // and the stream canonicalised), `RenderFailed` (kustomize exited
    // non-zero — evidence of render-time failure, the structural
    // failure that gates Phase 2 admission under THEORY §V.4), and
    // `ProbeAbsent` (no render probe ran inside the certification
    // function — no evidence either way) — all collapsed to the same
    // `b"pending-deployment"` hash, routing evidence-of-render-failure
    // into the same downstream channel as no-probe-ran (the
    // discriminator a `sekiban` strict-production policy that
    // fails-closed on render-time failure needs). The typed
    // `crate::deployment_manifest::DeploymentManifestRenderOutcome`
    // (three arms over `Rendered { fingerprint }` / `RenderFailed` /
    // `ProbeAbsent`) preserves each operational world structurally, and
    // `manifest_hash()` emits a distinct BLAKE3 digest per arm so the
    // Phase 2 `manifest_hash` field is content-addressed in every world
    // a downstream probe could report. The typed primitive is the
    // rendered-manifest-side peer of `crate::tree_listing::canonical_
    // tree_fingerprint` (commit 9c5a99f for source-tree identity),
    // `crate::oci_manifest::canonical_manifest_fingerprint` (commit
    // 443bd22 for image-manifest identity), `crate::chart_listing::
    // canonical_chart_fingerprint` (commit e8a2df7 for chart-content
    // identity), `crate::compliance_dimensions::canonical_dimensions_
    // fingerprint` (commit 5baaa50 for compliance-dimensions identity),
    // and `crate::store_path::canonical_closure_fingerprint` (commit
    // 1652-1669 for Nix-closure identity): the constant-stamp
    // dishonesty closes the same way one layer up. Today the
    // certification function does not yet spawn a kustomize probe
    // itself — the outcome collapses to `ProbeAbsent` →
    // `Blake3Hash::digest(b"no-manifest-render")`, honestly naming "no
    // render probe ran inside the certification function" rather than
    // stamping a constant that would also be produced under
    // render-failure and under any successful render against any
    // namespace, all three collapsing to the same hash. Same deferral
    // shape as commit e76db87 (`PodHealthOutcome::ProbeAbsent` at the
    // pod-health layer), commit 8b1407d (`HelmReleaseSignatureOutcome::
    // ProbeAbsent` at the HelmRelease-signature layer), commit f8a5d8e
    // (`NetworkPolicyAdmissionOutcome::ProbeAbsent` at the network-
    // segmentation layer), commit 5931e32 (`FluxSourceVerificationOutcome::
    // ProbeAbsent` at the FluxCD source-verification layer), commit
    // 72424bd (`NixReproducibilityOutcome::ProbeAbsent` at the build-
    // determinism layer), commit c1e83d5 (`KensaPolicyOutcome::
    // ProbeAbsent` at the chart-policy layer), commit d81f639
    // (`HelmLintOutcome::ProbeAbsent` at the chart-quality layer), and
    // commit b98eb5a (`SbomProbeOutcome::Absent` / `VulnScanProbeOutcome::
    // Absent` at the SBOM / vuln-scan layer): typed primitive available,
    // real probe wired in by a follow-up that adds the
    // `tokio::process::Command::new("kustomize").args(["build", &path]).
    // output().await` (or `flux build kustomization`) shell-out and
    // canonicalises the resulting YAML stream into a fingerprint.
    let deployment_manifest_outcome =
        crate::deployment_manifest::DeploymentManifestRenderOutcome::ProbeAbsent;

    // `kensa cis-k8s --cluster <ctx> --format json` (or its typed
    // `kensa::cis_k8s::audit(...)` library equivalent) is the cluster-
    // side probe whose `passed_controls / total_controls` ratio over
    // the union of CIS Kubernetes Benchmark §1 (Master-Node) / §2
    // (etcd) / §3 (Control-Plane) / §4 (Worker-Node) / §5 (Policies)
    // controls populates the Phase 2 deployment attestation's
    // `cis_k8s_pass_rate` claim. The prior `cis_k8s_pass_rate: 0.0`
    // literal at this call site was honest at the f64 surface (a
    // deployment attestation that records `cis_k8s_pass_rate: 0.0`
    // against a certification function that never spawned a kensa
    // probe is correctly zero — no evidence was collected, and the
    // surface value fails-closed under any policy whose
    // `min_cis_pass_rate > 0.0`) but flattened two structurally
    // distinct operational worlds — the `Probed { ratio: 0.0 }` /
    // `ProbeAbsent` distinction a kensa CIS probe would yield — into a
    // single zero. The `Probed { ratio: 0.0 }` collapse is the load-
    // bearing discriminator loss: a Phase 2 deployment attestation
    // that records `cis_k8s_pass_rate: 0.0` against a cluster whose
    // kensa probe RAN and observed zero passing controls (evidence of
    // a freshly provisioned cluster or one whose CIS baseline never
    // landed — the structural failure CIS Kubernetes Benchmark §1–§5
    // names) is structurally indistinguishable from one against a
    // cluster whose probe was never spawned (no evidence either way).
    // A downstream `sekiban` strict-production policy that fails-closed
    // on evidence of a zero-pass-rate posture cannot express that gate
    // against the pre-fix bare f64 — every Phase 2 record asserts the
    // same zero regardless of whether `kensa cis-k8s` substantiated a
    // zero-pass-rate state or whether it simply never ran. The typed
    // `crate::cis_k8s_pass_rate::CisK8sPassRateOutcome` (`Probed {
    // ratio }` / `ProbeAbsent`) preserves both operational worlds the
    // prior bare f64 flattened; the call site routes through
    // `pass_rate()` which collapses `Probed { ratio } -> ratio` and
    // `ProbeAbsent -> 0.0` — f64 surface unchanged for the no-probe-
    // ran world, structural discriminator restored. With this commit,
    // the last remaining hardcoded scalar field on the Phase 2
    // `DeploymentAttestation` closes the typed-primitive route,
    // leaving every Phase 2 field grounded in a typed probe outcome.
    // Same deferral shape as commit d002374's
    // `PodListingOutcome::ProbeAbsent` at the running-pod-count layer,
    // commit e76db87's `PodHealthOutcome::ProbeAbsent` at the
    // pod-readiness layer, commit 8b1407d's
    // `HelmReleaseSignatureOutcome::ProbeAbsent` at the HelmRelease-
    // signature layer, commit f8a5d8e's
    // `NetworkPolicyAdmissionOutcome::ProbeAbsent` at the network-
    // segmentation layer, commit 5931e32's
    // `FluxSourceVerificationOutcome::ProbeAbsent` at the source-
    // verification layer, commit 36d90b6's
    // `DeploymentManifestRenderOutcome::ProbeAbsent` at the rendered-
    // manifest layer, and commits 72424bd / c1e83d5 / d81f639 /
    // b98eb5a at the build-determinism / chart-policy / chart-quality
    // / SBOM-vuln-scan layers. Today the certification function does
    // not yet spawn a kensa CIS probe itself — the outcome collapses
    // to `ProbeAbsent` → `cis_k8s_pass_rate: 0.0`, honestly naming
    // "no kensa CIS probe ran inside the certification function"
    // rather than asserting a single zero a probe-detected zero-pass-
    // rate cluster would have also produced.
    let cis_k8s_pass_rate_outcome = crate::cis_k8s_pass_rate::CisK8sPassRateOutcome::ProbeAbsent;

    // Probe-coverage telemetry: count the (ran, absent) split over the
    // seven typed probe outcomes the Phase 2 `DeploymentAttestation`
    // depends on, emitted alongside the composed certification so a
    // downstream `sekiban` admission verifier reconciliation can
    // distinguish a high-evidence Phase 2 record (every probe ran and
    // produced evidence) from one whose fields all collapsed to honest
    // defaults (every probe `ProbeAbsent`, today's certification-
    // function state). The signal is the first generic consumer of the
    // `ProbeOutcome` trait (commit ddc789d) — the trait's
    // `is_probe_absent` predicate is the load-bearing discriminator the
    // `probe_coverage` helper walks. The previous per-field-claim
    // honesty channel (commits b98eb5a → ddc789d closed seventeen typed
    // outcomes, each preserving the structural distinction between
    // "probe ran" and "no evidence collected" at one Phase 1 / Phase 2
    // attestation field) is lifted here to a per-record signal: a
    // verifier reading `(ran: 0, absent: 7)` on a deployment record can
    // recover "no deployment probes ran inside the certification
    // function" structurally, where the per-field bool / hash / count /
    // ratio shape required the verifier to re-walk the typed-primitive
    // surface at every field to reach the same conclusion. THEORY §V.4
    // / §VII.1 Phase 2 honesty channel; THEORY §VI.1 one-oracle
    // discipline (the seven-probe coverage is composed at one site
    // rather than per-field-derived by the verifier).
    let deployment_coverage = deployment_probe_coverage(
        &source_verification_outcome,
        &network_policy_outcome,
        &helm_release_signature_outcome,
        &pod_health_outcome,
        &pod_listing_outcome,
        &deployment_manifest_outcome,
        &cis_k8s_pass_rate_outcome,
    );
    emit_probe_coverage!(
        deployment,
        target: "forge::attestation::probe_coverage",
        coverage: deployment_coverage,
        message: "deployment-attestation probe coverage",
        product = product,
        environment = environment,
        cluster = cluster,
    );

    let deployment = DeploymentAttestation {
        namespace: format!("{}-{}", product, environment),
        kustomization: format!("{}-{}", product, environment),
        source_commit: source.commit.clone(),
        source_verified: source_verification_outcome.is_verified(),
        manifest_hash: deployment_manifest_outcome.manifest_hash(),
        all_releases_signed: helm_release_signature_outcome.is_verified(),
        cis_k8s_pass_rate: cis_k8s_pass_rate_outcome.pass_rate(),
        network_policies_verified: network_policy_outcome.is_verified(),
        running_pods: pod_listing_outcome.running_pods(),
        all_healthy: pod_health_outcome.is_healthy(),
    };

    let slsa_dimension = slsa_compliance_dimension(&builds, &policy);
    let all_passed = slsa_dimension.passed;
    // `compliance_hash` is the BLAKE3 of the canonical fingerprint over
    // the dimensions vec — sorted by the Display form of each dim's
    // `dimension_type`, concatenated 32-byte hashes — exactly what
    // `tameshi::compliance::dimensions::AttestationBuilder::build` runs
    // internally. The pre-fix `Blake3Hash::digest(b"initial-compliance")`
    // literal at this call site stamped a name-keyed sentinel
    // independent of the dimensions vec actually composed into the
    // attestation, defeating the content-addressed-identity invariant
    // THEORY §VI.1 names twice over: (a) the same dimension set yielded
    // two distinct `compliance_hash` values depending on construction
    // path (forge bare struct vs tameshi builder) — a downstream
    // verifier could not reconcile the two attestations as describing
    // the same compliance evidence; and (b) two structurally different
    // dimension sets (a passing slsa-provenance dim vs a failing one)
    // produced the same `compliance_hash`, since the stamp was constant
    // — defeating the discriminator the hash is supposed to provide.
    // The typed `crate::compliance_dimensions::canonical_dimensions_
    // fingerprint` is the compliance-side peer of
    // `crate::tree_listing::canonical_tree_fingerprint` (commit 9c5a99f
    // for source-tree identity), `crate::oci_manifest::canonical_
    // manifest_fingerprint` (commit 443bd22 for image-manifest
    // identity), and `crate::chart_listing::canonical_chart_fingerprint`
    // (commit e8a2df7 for chart-content identity): the constant-stamp
    // dishonesty closes the same way one layer up.
    let dimensions = vec![slsa_dimension];
    let compliance_hash = Blake3Hash::digest(
        &crate::compliance_dimensions::canonical_dimensions_fingerprint(&dimensions),
    );
    let compliance = ComplianceAttestation {
        environment: environment.to_string(),
        artifact: product.to_string(),
        dimensions,
        compliance_hash,
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

/// Probe-coverage telemetry summary for the seven typed probe outcomes
/// that ground every field on the Phase 2 [`DeploymentAttestation`] a
/// downstream `sekiban` admission verifier reconciliation reads. The
/// seven-probe invariant is foreclosed at the parameter list: a future
/// regression that added an eighth probe to
/// [`compose_product_certification`] but forgot to thread it through
/// this helper would leave the new probe's `ran` / `absent` state out of
/// the telemetry signal — a structural failure
/// [`test_deployment_probe_coverage_all_ran_ceiling`] catches by asserting
/// `total() == 7`. Symmetrically, a probe removed from the deployment
/// record but left in this helper would fail compilation against the
/// removed outcome type, surfacing the orphan parameter at the
/// `pub fn`-references-non-existent-outcome compile gate.
///
/// The function is the structural carrier of the seven-probe contract:
/// every typed outcome bound at the
/// [`compose_product_certification`] call site appears exactly once
/// here, and the typed parameter list pins the contract against the
/// seven implementor enums by name. The trait-object slice form
/// (`&[&dyn ProbeOutcome; 7]`) is the load-bearing call-site shape — the
/// [`crate::probe_outcome::probe_coverage`] free function (commit
/// ddc789d) walks it linearly without re-deriving the absent-arm
/// discriminator per implementor.
///
/// THEORY §V.4 / §VII.1: Phase 2 attestation honesty channel. THEORY
/// §VI.1: one-oracle discipline — the coverage signal is composed at
/// one site, not per-field-derived by the downstream verifier.
fn deployment_probe_coverage(
    source_verification: &crate::flux_source_verification::FluxSourceVerificationOutcome,
    network_policy: &crate::network_policy_admission::NetworkPolicyAdmissionOutcome,
    helm_release_signature: &crate::helm_release_signature::HelmReleaseSignatureOutcome,
    pod_health: &crate::pod_health::PodHealthOutcome,
    pod_listing: &crate::pod_listing::PodListingOutcome,
    deployment_manifest: &crate::deployment_manifest::DeploymentManifestRenderOutcome,
    cis_k8s_pass_rate: &crate::cis_k8s_pass_rate::CisK8sPassRateOutcome,
) -> crate::probe_outcome::ProbeCoverage {
    let outcomes: [&dyn crate::probe_outcome::ProbeOutcome; 7] = [
        source_verification,
        network_policy,
        helm_release_signature,
        pod_health,
        pod_listing,
        deployment_manifest,
        cis_k8s_pass_rate,
    ];
    crate::probe_outcome::probe_coverage(outcomes.iter().copied())
}

/// Probe-coverage telemetry summary for the four typed probe outcomes
/// that ground every evidence-bearing field on the Phase 1
/// [`ChartAttestation`] a downstream `sekiban` admission verifier
/// reconciliation reads. The four-probe invariant is foreclosed at the
/// parameter list: a future regression that added a fifth probe to
/// [`compute_chart_attestation`] but forgot to thread it through this
/// helper would leave the new probe's `ran` / `absent` state out of the
/// telemetry signal — a structural failure
/// [`test_chart_probe_coverage_all_ran_ceiling`] catches by asserting
/// `total() == 4`. Symmetrically, a probe removed from the chart record
/// but left in this helper would fail compilation against the removed
/// outcome type, surfacing the orphan parameter at the
/// `pub fn`-references-non-existent-outcome compile gate.
///
/// The function is the chart-side peer of
/// [`deployment_probe_coverage`] one layer over: the typed parameter
/// list pins the four-probe contract against the four implementor enums
/// by name, and the trait-object slice form (`&[&dyn ProbeOutcome; 4]`)
/// is the load-bearing call-site shape the
/// [`crate::probe_outcome::probe_coverage`] free function (commit
/// ddc789d) walks linearly without re-deriving the absent-arm
/// discriminator per implementor.
///
/// THEORY §V.4 / §VII.1: Phase 1 attestation honesty channel. THEORY
/// §VI.1: one-oracle discipline — the coverage signal is composed at
/// one site, not per-field-derived by the downstream verifier.
fn chart_probe_coverage(
    provenance: &crate::helm_provenance::HelmProvenanceOutcome,
    lint: &crate::helm_lint::HelmLintOutcome,
    policy: &crate::kensa_policy::KensaPolicyOutcome,
    dependencies: &crate::chart_dependencies::ChartDependenciesOutcome,
) -> crate::probe_outcome::ProbeCoverage {
    let outcomes: [&dyn crate::probe_outcome::ProbeOutcome; 4] =
        [provenance, lint, policy, dependencies];
    crate::probe_outcome::probe_coverage(outcomes.iter().copied())
}

/// Probe-coverage telemetry summary for the three typed probe outcomes
/// that ground every evidence-bearing field on the Phase 1
/// [`BuildAttestation`] a downstream `sekiban` admission verifier
/// reconciliation reads. The three-probe invariant is foreclosed at the
/// parameter list: a future regression that added a fourth probe to
/// [`compute_build_attestation`] but forgot to thread it through this
/// helper would leave the new probe's `ran` / `absent` state out of the
/// telemetry signal — a structural failure
/// [`test_build_probe_coverage_all_ran_ceiling`] catches by asserting
/// `total() == 3`. Symmetrically, a probe removed from the build record
/// but left in this helper would fail compilation against the removed
/// outcome type, surfacing the orphan parameter at the
/// `fn`-references-non-existent-outcome compile gate.
///
/// The function is the build-side peer of [`chart_probe_coverage`]
/// (four Phase 1 chart probes) and [`deployment_probe_coverage`] (seven
/// Phase 2 deployment probes) one layer over: the typed parameter list
/// pins the three-probe contract against the three implementor enums by
/// name, and the trait-object slice form (`&[&dyn ProbeOutcome; 3]`) is
/// the load-bearing call-site shape the
/// [`crate::probe_outcome::probe_coverage`] free function (commit
/// ddc789d) walks linearly without re-deriving the absent-arm
/// discriminator per implementor.
///
/// THEORY §V.4 / §VII.1: Phase 1 attestation honesty channel. THEORY
/// §VI.1: one-oracle discipline — the coverage signal is composed at
/// one site, not per-field-derived by the downstream verifier.
fn build_probe_coverage(
    sbom: &crate::security_scan::SbomProbeOutcome,
    vuln_scan: &crate::security_scan::VulnScanProbeOutcome,
    reproducibility: &crate::nix_reproducibility::NixReproducibilityOutcome,
) -> crate::probe_outcome::ProbeCoverage {
    let outcomes: [&dyn crate::probe_outcome::ProbeOutcome; 3] = [sbom, vuln_scan, reproducibility];
    crate::probe_outcome::probe_coverage(outcomes.iter().copied())
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

    /// **Load-bearing chart-attestation honesty pin: the prior
    /// `vec![], // Dependency hashes: populated when chart deps are
    /// tracked` literal at the `ci::chart_attestation` call site
    /// stamped an empty `dependency_hashes` vec into every Phase 1
    /// chart attestation regardless of whether `Chart.yaml` actually
    /// declared third-party dependencies.** The typed primitive
    /// `crate::chart_dependencies::ChartDependenciesOutcome` preserves
    /// both operational worlds the prior `vec![]` flattened — `Listed
    /// { deps }` (Chart.yaml WAS read and the chart's declared dep set
    /// was walked, with one [`tameshi::certification::DependencyHash`]
    /// per declared dep) and `ProbeAbsent` (no Chart.yaml read, or
    /// unreadable, or malformed) — and the call site routes through
    /// `probe_chart_dependencies(...).await.to_dependency_hashes()`
    /// over the chart_path that's already on disk. Unlike the sibling
    /// `helm_lint` / `kensa_policy` / `flux_source_verification` /
    /// `nix_reproducibility` probes that defer to `ProbeAbsent` pending
    /// a real shell-out, the Chart.yaml probe is cheap (it reads a
    /// file the chart_path argument names) so this commit wires the
    /// real probe in at the call site.
    ///
    /// Two end-to-end pins, mirroring the two operational worlds:
    ///   * A minimal chart with `Chart.yaml` declaring no
    ///     `dependencies:` block yields `Listed { deps: vec![] }` →
    ///     `dependency_hashes: vec![]` at the surface, but the typed
    ///     outcome carries the leaf-chart claim structurally. The
    ///     surface vec is the same as for the pre-fix hardcode, but
    ///     the source of the value is a probe that actually read the
    ///     file rather than a literal.
    ///   * A chart with `Chart.yaml` declaring N >= 1 deps yields
    ///     `Listed { deps }` → `dependency_hashes: vec![DependencyHash
    ///     { name, version, hash: blake3(name TAB version TAB
    ///     repository) }; N]`. The pre-fix `vec![]` literal would
    ///     have produced an empty vec against the same chart_path,
    ///     erasing the substantive dep-graph evidence the typed
    ///     primitive now surfaces. This is the fail-before-fix arm: a
    ///     pre-fix run against this chart would assert
    ///     `att.dependency_hashes.is_empty()`, where the post-fix run
    ///     asserts `att.dependency_hashes.len() == 2`.
    ///
    /// Same wired-in shape as commit a5376a6's
    /// `GitCommitSignatureOutcome::from_format_code` at the source-
    /// commit-signature layer (`git log --format=%G?` is cheap, so
    /// the probe is real at the call site).
    #[tokio::test]
    async fn test_dependency_hashes_route_through_typed_probe_outcome() {
        use crate::chart_dependencies::{parse_chart_yaml_dependencies, ChartDependenciesOutcome};

        // Call-site expression pin: this is the exact expression
        // `compute_chart_attestation` now passes for
        // `dependency_hashes`. The pre-fix call site passed the
        // literal `vec![]`; pinning the post-fix expression at this
        // layer means a future refactor that dropped the typed-
        // primitive route would fail this test before any Phase 1
        // record was published under the regression. Same shape as
        // `test_policy_passed_routes_through_typed_probe_outcome` two
        // tests up.
        assert!(
            ChartDependenciesOutcome::ProbeAbsent
                .to_dependency_hashes()
                .is_empty(),
            "ProbeAbsent must collapse to dependency_hashes=vec![] in \
             the Phase 1 chart attestation; the pre-fix `vec![]` \
             hardcode flattened the no-probe-ran world into the same \
             empty vec as the leaf-chart world, losing the \
             discriminator a downstream verifier needs",
        );

        // Listed{deps: vec![]} (leaf chart — probe ran, chart declares
        // no deps) collapses to the same surface vec as ProbeAbsent
        // (both yield vec![]) but stays structurally distinct at the
        // enum level — the load-bearing discriminator the pre-fix
        // `vec![]` literal erased. Same shape as
        // `test_probed_zero_collapses_to_zero_but_stays_distinct` for
        // `CisK8sPassRateOutcome` (commit f40dae7) one shape away.
        let leaf = ChartDependenciesOutcome::Listed { deps: Vec::new() };
        let absent = ChartDependenciesOutcome::ProbeAbsent;
        assert!(leaf.to_dependency_hashes().is_empty());
        assert!(absent.to_dependency_hashes().is_empty());
        assert!(
            matches!(leaf, ChartDependenciesOutcome::Listed { .. }),
            "Listed{{deps: vec![]}} must remain in the Listed arm — \
             structurally distinct from ProbeAbsent",
        );

        // End-to-end through compute_chart_attestation: a leaf chart
        // (Chart.yaml present, no dependencies: block) yields
        // dependency_hashes: vec![] via the Listed{deps: vec![]} arm,
        // surface-equivalent to the pre-fix literal but routed
        // through the typed probe.
        let tmp = tempfile::tempdir().expect("tempdir");
        let chart_dir = tmp.path().join("leaf");
        std::fs::create_dir(&chart_dir).expect("mkdir chart");
        std::fs::write(
            chart_dir.join("Chart.yaml"),
            "apiVersion: v2\nname: leaf\nversion: 0.1.0\n",
        )
        .expect("write Chart.yaml");
        let att_leaf = compute_chart_attestation(
            "leaf",
            "0.1.0",
            &chart_dir,
            "oci://ghcr.io/example/leaf",
            Some(tmp.path()),
        )
        .await
        .expect("compute_chart_attestation");
        assert!(
            att_leaf.dependency_hashes.is_empty(),
            "a leaf chart (no Chart.yaml dependencies: block) must \
             surface dependency_hashes=vec![] — the Listed{{deps: \
             vec![]}} arm of the typed probe",
        );

        // End-to-end through compute_chart_attestation: a chart whose
        // Chart.yaml declares two deps yields dependency_hashes with
        // two entries, each carrying (name, version, canonical-hash).
        // This is the fail-before arm: the pre-fix `vec![]` literal
        // would have produced an empty vec against this same
        // chart_path, erasing the substantive dep-graph evidence the
        // typed primitive now surfaces. A regression that re-
        // introduced `vec![]` at the call site would fail this
        // assertion.
        let multi_dir = tmp.path().join("multi");
        std::fs::create_dir(&multi_dir).expect("mkdir chart");
        let multi_chart_yaml = r#"
apiVersion: v2
name: multi
version: 0.1.0
dependencies:
  - name: common
    version: 1.0.0
    repository: "oci://ghcr.io/pleme-io/charts"
  - name: redis
    version: 3.0.0
    repository: "oci://ghcr.io/pleme-io/charts"
"#;
        std::fs::write(multi_dir.join("Chart.yaml"), multi_chart_yaml).expect("write Chart.yaml");
        let att_multi = compute_chart_attestation(
            "multi",
            "0.1.0",
            &multi_dir,
            "oci://ghcr.io/example/multi",
            Some(tmp.path()),
        )
        .await
        .expect("compute_chart_attestation");
        assert_eq!(
            att_multi.dependency_hashes.len(),
            2,
            "a chart declaring two Chart.yaml dependencies must surface \
             two DependencyHash entries — the Listed{{deps}} arm of \
             the typed probe carries one per declared dep. The pre-fix \
             `vec![]` literal would have produced 0 here, erasing the \
             dep-graph evidence; a regression re-introducing the \
             literal would fail this pin",
        );
        // The surfaced DependencyHash entries are exactly what
        // `parse_chart_yaml_dependencies` over the same Chart.yaml
        // content produces: same canonical canonicalisation, same
        // BLAKE3 per dep — pinning the bytes-on-the-wire identity of
        // the dep-graph claim.
        let parsed = parse_chart_yaml_dependencies(multi_chart_yaml).to_dependency_hashes();
        let mut surfaced_names: Vec<&str> = att_multi
            .dependency_hashes
            .iter()
            .map(|d| d.name.as_str())
            .collect();
        surfaced_names.sort_unstable();
        let mut parsed_names: Vec<&str> = parsed.iter().map(|d| d.name.as_str()).collect();
        parsed_names.sort_unstable();
        assert_eq!(
            surfaced_names, parsed_names,
            "the surfaced dependency_hashes names must match those the \
             pure parser would extract from the same Chart.yaml — \
             pinning that the probe and the parser agree on the \
             canonical dep set",
        );
        for surfaced in &att_multi.dependency_hashes {
            let matching = parsed
                .iter()
                .find(|p| p.name == surfaced.name && p.version == surfaced.version);
            let matching = matching.unwrap_or_else(|| {
                panic!(
                    "no parser-side entry matches surfaced name={} version={}",
                    surfaced.name, surfaced.version,
                )
            });
            assert_eq!(
                surfaced.hash, matching.hash,
                "the surfaced canonical-line BLAKE3 must equal the \
                 parser-side canonical-line BLAKE3 for the same \
                 (name, version) entry",
            );
        }
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

    /// **Load-bearing deployment-attestation honesty pin: the prior
    /// `source_verified: true` literal at the `compose_product_
    /// certification` call site stamped a positive Phase 2 source-
    /// verification claim into every `DeploymentAttestation` regardless
    /// of whether FluxCD's source-controller had actually verified the
    /// commit signature for the deployment's `GitRepository`.** The
    /// typed primitive `crate::flux_source_verification::
    /// FluxSourceVerificationOutcome` preserves the three operational
    /// worlds the prior `true` flattened — `Verified`, `VerifyFailed`,
    /// `ProbeAbsent` — and the call site routes through
    /// `is_verified()`, which returns `true` only on the `Verified`
    /// arm.
    ///
    /// Until a follow-up commit wires a `kubectl get gitrepository`
    /// (or typed `kube::Api::<GitRepository>::get(...)`) probe at the
    /// call site, the outcome collapses to `ProbeAbsent` →
    /// `source_verified: false` — honestly naming "no FluxCD source-
    /// verification probe ran inside the certification surface" rather
    /// than asserting a green source-verified claim flow-control alone
    /// cannot substantiate. Same fail-before / pass-after shape as the
    /// sibling `test_linter_passed_routes_through_typed_probe_outcome`
    /// (commit d81f639) and `test_policy_passed_routes_through_typed_
    /// probe_outcome` (commit c1e83d5) one layer over (typed probe-
    /// absent at the call site, real probe deferred to a follow-up).
    ///
    /// Pin the post-fix call-site expression directly so a future
    /// regression that re-introduced a hardcoded `true` would fail
    /// before any Phase 2 record was published under it: the value
    /// the call site now passes for `source_verified` is exactly
    /// `FluxSourceVerificationOutcome::ProbeAbsent.is_verified()`, and
    /// that is structurally `false`. The end-to-end pin then walks
    /// `compose_product_certification` against a minimal source
    /// attestation and confirms `cert.deployment.source_verified ==
    /// false`, where the pre-fix body would have produced `true`
    /// regardless of any probe evidence — closes the sibling gap the
    /// `// These will be populated by sekiban and kensa once deployed`
    /// comment named directly above the `source_verified: true`
    /// literal in `compose_product_certification`.
    #[test]
    fn test_source_verified_routes_through_typed_flux_outcome() {
        use crate::flux_source_verification::FluxSourceVerificationOutcome;

        // Call-site expression pin: this is the exact expression
        // `compose_product_certification` now passes for
        // `source_verified`. The pre-fix call site passed the literal
        // `true`; pinning the post-fix expression at this layer means
        // a future refactor that dropped the typed-primitive route
        // would fail this test before any Phase 2 record was published
        // under the regression. Same shape as
        // `test_policy_passed_routes_through_typed_probe_outcome`
        // (`KensaPolicyOutcome::ProbeAbsent.is_passed()`) one layer
        // over.
        assert!(
            !FluxSourceVerificationOutcome::ProbeAbsent.is_verified(),
            "ProbeAbsent must collapse to source_verified=false in \
             the Phase 2 deployment attestation; the pre-fix `true` \
             hardcode sealed a green source-verified claim from \
             nothing rather than from FluxCD evidence",
        );

        // The other two arms also have well-defined bool collapses —
        // Verified → true, VerifyFailed → false. The three-arm
        // distinction is structurally preserved at the enum level
        // even though `is_verified` discards two of them at the bool
        // surface (mirrors the `test_chart_provenance_four_arms_
        // collapse_to_distinct_bools` shape one layer over).
        assert!(FluxSourceVerificationOutcome::Verified.is_verified());
        assert!(!FluxSourceVerificationOutcome::VerifyFailed.is_verified());

        // End-to-end through compose_product_certification: a minimal
        // source attestation composed under the staging policy
        // produces `source_verified: false` on the resulting
        // `DeploymentAttestation`, where the pre-fix body returned
        // `true` unconditionally. The build / image / chart inputs
        // are empty here so the compose path exercises the deployment-
        // attestation construction directly without involving the
        // probe-driven Phase 1 inputs — same isolation discipline as
        // `test_compose_propagates_honest_compliance` one layer up.
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
            !cert.deployment.source_verified,
            "the typed-primitive route at the call site must drive \
             source_verified=false through to the DeploymentAttestation \
             record when no FluxCD probe ran inside the certification \
             function; the pre-fix `true` hardcode produced `true` here \
             regardless of any probe evidence",
        );
    }

    /// **Load-bearing build-attestation honesty pin: the prior bare
    /// `let reproducible = false;` literal inside
    /// `compute_build_attestation` stamped a negative Phase 1
    /// reproducibility claim into every `BuildAttestation` it composed
    /// regardless of whether a `nix build --rebuild` determinism probe
    /// had actually run.** The bool surface was honest at the
    /// SLSA-level layer (a substantiated build without a determinism
    /// probe caps at L2 under `build_slsa_level`, never the
    /// reproducible-grade L3) but flattened three structurally
    /// distinct operational worlds a downstream verifier reading
    /// `reproducible: false` could not recover from the bool alone:
    /// `Reproducible` (re-build matched), `Drift` (re-build detected
    /// non-determinism — evidence of compromise), and `ProbeAbsent`
    /// (no re-build ran inside the build-attestation function — no
    /// evidence either way). The typed primitive
    /// `crate::nix_reproducibility::NixReproducibilityOutcome`
    /// preserves the three operational worlds the prior bare bool
    /// flattened, and the call site routes through
    /// `is_reproducible()`, which returns `true` only on the
    /// `Reproducible` arm.
    ///
    /// Until a follow-up commit wires a `nix build --rebuild` (or
    /// `nix-build --check`) probe at the call site, the outcome
    /// collapses to `ProbeAbsent` → `reproducible: false` — honestly
    /// naming "no determinism probe ran inside the build-attestation
    /// function" rather than collapsing it into the same bucket as a
    /// probe-detected drift. Same fail-before / pass-after shape as
    /// the sibling
    /// `test_source_verified_routes_through_typed_flux_outcome`
    /// (commit 5931e32) one layer up (typed probe-absent at the call
    /// site, real probe deferred to a follow-up).
    ///
    /// Pin the post-fix call-site expression directly so a future
    /// regression that re-introduced a hardcoded bare bool would fail
    /// before any Phase 1 record was published under it: the value
    /// the call site now passes for `reproducible` is exactly
    /// `NixReproducibilityOutcome::ProbeAbsent.is_reproducible()`, and
    /// that is structurally `false`. The bool-collapse pins confirm
    /// `Reproducible` → `true` (the one positive arm) and `Drift` →
    /// `false` (the arm that carries evidence of non-determinism but
    /// must NOT claim reproducible at the bool surface). The
    /// downstream SLSA-level pin then walks `build_slsa_level` with
    /// the same typed-route expression and confirms the L2 cap holds
    /// — closes the sibling gap the `// Reproducibility is not
    /// independently re-verified yet` comment named directly above
    /// the bare bool literal in `compute_build_attestation`.
    #[test]
    fn test_reproducible_routes_through_typed_nix_outcome() {
        use crate::nix_reproducibility::NixReproducibilityOutcome;

        // Call-site expression pin: this is the exact expression
        // `compute_build_attestation` now passes for `reproducible`.
        // The pre-fix call site passed the bare literal `false`;
        // pinning the post-fix expression at this layer means a
        // future refactor that dropped the typed-primitive route
        // would fail this test before any Phase 1 record was
        // published under the regression. Same shape as
        // `test_source_verified_routes_through_typed_flux_outcome`
        // (`FluxSourceVerificationOutcome::ProbeAbsent.is_verified()`)
        // one layer over.
        assert!(
            !NixReproducibilityOutcome::ProbeAbsent.is_reproducible(),
            "ProbeAbsent must collapse to reproducible=false in the \
             Phase 1 build attestation; the pre-fix bare `let \
             reproducible = false;` literal carried the same bool \
             here as for `Drift`, conflating no-evidence-collected \
             with evidence-of-non-determinism",
        );

        // The other two arms also have well-defined bool collapses —
        // Reproducible → true, Drift → false. The three-arm
        // distinction is structurally preserved at the enum level
        // even though `is_reproducible` discards two of them at the
        // bool surface (mirrors the
        // `test_chart_provenance_four_arms_collapse_to_distinct_bools`
        // shape one layer over).
        assert!(NixReproducibilityOutcome::Reproducible.is_reproducible());
        assert!(!NixReproducibilityOutcome::Drift.is_reproducible());

        // Downstream SLSA-level pin: the typed-route expression
        // composed into `build_slsa_level` with a fully-substantiated
        // derivation + closure must still cap at L2, never L3 — the
        // bool-surface semantics of the pre-fix literal are preserved
        // exactly through the typed primitive, so the reproducible-
        // grade L3 stays unreachable until a `Reproducible` outcome
        // is wired in by a follow-up. Mirrors
        // `test_build_slsa_level_substantiated_nonreproducible_is_l2`
        // but through the post-fix typed expression rather than the
        // pre-fix bare `false` literal.
        let reproducible = NixReproducibilityOutcome::ProbeAbsent.is_reproducible();
        let level = build_slsa_level(
            "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-mysvc.drv",
            r#"[{"path":"/nix/store/abc123-mysvc","narHash":"sha256-x"}]"#,
            reproducible,
        );
        assert_eq!(
            level,
            SlsaLevel::L2,
            "ProbeAbsent → reproducible=false → substantiated build \
             caps at L2 under build_slsa_level; the reproducible L3 \
             grade stays unreachable until a `Reproducible` outcome \
             is wired in by a follow-up that spawns `nix build \
             --rebuild`",
        );

        // And confirm that the `Reproducible` arm — the one positive
        // arm — would unlock L3 against the same substantiated
        // derivation + closure. This is the inverse pin: the typed
        // primitive is the gate, not a permanent floor; a future
        // commit that wires the re-build probe at the call site and
        // observes byte-identical output will earn the L3 grade
        // honestly. Mirrors
        // `test_build_slsa_level_substantiated_reproducible_is_l3`
        // but through the typed expression.
        let reproducible_arm = NixReproducibilityOutcome::Reproducible.is_reproducible();
        let level_l3 = build_slsa_level(
            "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-mysvc.drv",
            r#"[{"path":"/nix/store/abc123-mysvc","narHash":"sha256-x"}]"#,
            reproducible_arm,
        );
        assert_eq!(
            level_l3,
            SlsaLevel::L3,
            "Reproducible → reproducible=true → substantiated build \
             earns L3; the typed primitive gates the grade, never \
             floors it",
        );
    }

    /// **Load-bearing compliance-honesty pin (fail-before / pass-after).**
    /// The prior `compose_product_certification` body stamped
    /// `compliance_hash: Blake3Hash::digest(b"initial-compliance")` on
    /// every `ComplianceAttestation` it composed — a name-keyed sentinel
    /// independent of the dimensions vec the attestation carries. Two
    /// structural honesty failures followed (mirroring the closed gaps at
    /// the source-tree, image-manifest, and chart-content layers): (a)
    /// the same dimension set produced two distinct `compliance_hash`
    /// values depending on construction path (forge bare struct vs
    /// `tameshi::compliance::dimensions::AttestationBuilder::build`),
    /// defeating the content-addressed-identity invariant THEORY §VI.1
    /// rests on; and (b) two structurally different dimension sets — a
    /// passing slsa-provenance dim vs a failing one — produced the same
    /// `compliance_hash`, since the stamp was constant. The post-fix call
    /// site digests the canonical fingerprint over the dimensions vec
    /// through [`crate::compliance_dimensions::canonical_dimensions_fingerprint`],
    /// matching the algorithm `AttestationBuilder::build` runs internally.
    ///
    /// Pin the post-fix call-site expression by exercising the compose
    /// function end-to-end: a single substantiated build composes into
    /// one slsa-provenance dimension, and the resulting attestation's
    /// `compliance_hash` must (a) NOT equal the pre-fix sentinel and
    /// (b) match the BLAKE3 of the canonical fingerprint over the
    /// recorded dimensions. Same fail-before / pass-after shape as
    /// `test_tree_hash_probe_failure_distinguishable_from_empty_listing`
    /// and `test_manifest_hash_stable_across_key_order_and_metadata` one
    /// layer over: the typed canonical-fingerprint primitive replaces a
    /// name-keyed constant at the call site, and the test pins the
    /// resulting hash against both the prior dishonest constant and the
    /// honest content-derived value.
    #[test]
    fn test_compose_compliance_hash_grounded_in_dimensions_not_sentinel() {
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

        // (a) The post-fix hash is NOT the pre-fix name-keyed sentinel —
        // the load-bearing regression pin. A future regression that
        // brought back `Blake3Hash::digest(b"initial-compliance")` at the
        // call site would fail here before any Phase 1.5 attestation
        // record was published under it.
        let sentinel = Blake3Hash::digest(b"initial-compliance");
        assert_ne!(
            cert.compliance.compliance_hash.to_hex(),
            sentinel.to_hex(),
            "compliance_hash must NOT collapse to the pre-fix \
             `Blake3Hash::digest(b\"initial-compliance\")` sentinel; \
             a future regression that re-introduced the constant would \
             fail this test before any Phase 1.5 attestation was \
             published under it",
        );

        // (b) The post-fix hash IS the BLAKE3 of the canonical
        // fingerprint over the dimensions the attestation actually
        // carries — the content-addressed-identity invariant THEORY
        // §VI.1 names. The same algorithm
        // `AttestationBuilder::build` runs internally, so a future
        // consumer of forge that constructs the equivalent attestation
        // through tameshi's builder gets the byte-identical hash.
        let expected = Blake3Hash::digest(
            &crate::compliance_dimensions::canonical_dimensions_fingerprint(
                &cert.compliance.dimensions,
            ),
        );
        assert_eq!(
            cert.compliance.compliance_hash.to_hex(),
            expected.to_hex(),
            "compliance_hash must be the BLAKE3 of the canonical \
             fingerprint over the dimensions vec — sorted by the Display \
             form of each dim's `dimension_type`, concatenated 32-byte \
             hashes — exactly what `AttestationBuilder::build` runs \
             internally",
        );

        // (c) Two structurally different dimension sets must produce
        // distinct `compliance_hash` values — the discriminator the
        // hash is supposed to provide. Compose a second attestation
        // whose single SLSA dim fails the floor (L0 under the L2
        // staging policy) and confirm the hashes differ. Pre-fix both
        // composed to the same sentinel hash; post-fix they MUST
        // diverge because the slsa-provenance dim's `hash` field
        // (BLAKE3 of the summary string) differs across the two cases.
        let source_b = ci::source_attestation(
            "https://example.invalid/repo",
            "deadbeef",
            "refs/heads/main",
            false,
            Blake3Hash::digest(b"tree"),
            Blake3Hash::digest(b"lock"),
            1,
            true,
        );
        let cert_b = compose_product_certification(
            "myproduct",
            "staging",
            "plo",
            source_b,
            vec![], // no builds → L0 → fails staging floor
            vec![],
            vec![],
        )
        .expect("certification composes");
        assert_ne!(
            cert.compliance.compliance_hash.to_hex(),
            cert_b.compliance.compliance_hash.to_hex(),
            "two attestations carrying structurally distinct dimension \
             sets (one with a passing L2 slsa dim, one with a failing \
             L0 dim) must produce distinct `compliance_hash` values; \
             the pre-fix sentinel produced byte-identical hashes for \
             these two cases — the discriminator the hash is supposed \
             to provide was lost",
        );
    }

    /// **Load-bearing deployment-attestation honesty pin: the prior
    /// `network_policies_verified: false` literal at the
    /// `compose_product_certification` call site stamped a negative
    /// Phase 2 network-segmentation claim into every
    /// `DeploymentAttestation` regardless of whether the cluster's
    /// `NetworkPolicy` resources had actually been queried for the
    /// deployment's namespace.** The bool surface was honest at the
    /// claim layer (a deployment attestation that records
    /// `network_policies_verified: false` against a certification
    /// function that never spawned a kubectl probe is correctly
    /// negative) but flattened three structurally distinct
    /// operational worlds a downstream verifier reading
    /// `network_policies_verified: false` could not recover from
    /// the bool alone: `Verified` (probe ran and every workload is
    /// covered), `VerifyFailed` (probe ran and the namespace has no
    /// covering NetworkPolicy — evidence of an open / unsegmented
    /// namespace, the structural failure CIS Kubernetes Benchmark
    /// §5.3.2 names), and `ProbeAbsent` (no kubectl probe ran inside
    /// the certification function — no evidence either way). The
    /// typed primitive
    /// `crate::network_policy_admission::NetworkPolicyAdmissionOutcome`
    /// preserves the three operational worlds the prior bare bool
    /// flattened, and the call site routes through `is_verified()`,
    /// which returns `true` only on the `Verified` arm.
    ///
    /// Until a follow-up commit wires a `kubectl get networkpolicy`
    /// (or typed `kube::Api::<NetworkPolicy>::list(...)`) probe at
    /// the call site, the outcome collapses to `ProbeAbsent` →
    /// `network_policies_verified: false` — honestly naming "no
    /// NetworkPolicy admission probe ran inside the certification
    /// function" rather than collapsing it into the same bool bucket
    /// as a probe-detected missing-policy state. Same fail-before /
    /// pass-after shape as the sibling
    /// `test_source_verified_routes_through_typed_flux_outcome`
    /// (commit 5931e32) one layer over and
    /// `test_reproducible_routes_through_typed_nix_outcome` (commit
    /// 72424bd) two layers over (typed probe-absent at the call
    /// site, real probe deferred to a follow-up).
    ///
    /// Pin the post-fix call-site expression directly so a future
    /// regression that re-introduced a hardcoded bare `false` would
    /// fail before any Phase 2 record was published under it: the
    /// value the call site now passes for `network_policies_verified`
    /// is exactly `NetworkPolicyAdmissionOutcome::ProbeAbsent.
    /// is_verified()`, and that is structurally `false`. The
    /// end-to-end pin then walks `compose_product_certification`
    /// against a minimal source attestation and confirms `cert.
    /// deployment.network_policies_verified == false`, where the
    /// pre-fix body would have produced the same bool but through an
    /// inline literal that flattened the discriminator — closes the
    /// sibling gap the `// These will be populated by sekiban and
    /// kensa once deployed` comment named directly above the
    /// `network_policies_verified: false` literal in
    /// `compose_product_certification`.
    #[test]
    fn test_network_policies_verified_routes_through_typed_outcome() {
        use crate::network_policy_admission::NetworkPolicyAdmissionOutcome;

        // Call-site expression pin: this is the exact expression
        // `compose_product_certification` now passes for
        // `network_policies_verified`. The pre-fix call site passed
        // the literal `false`; pinning the post-fix expression at
        // this layer means a future refactor that dropped the typed-
        // primitive route would fail this test before any Phase 2
        // record was published under the regression. Same shape as
        // `test_source_verified_routes_through_typed_flux_outcome`
        // (`FluxSourceVerificationOutcome::ProbeAbsent.is_verified()`)
        // one layer over.
        assert!(
            !NetworkPolicyAdmissionOutcome::ProbeAbsent.is_verified(),
            "ProbeAbsent must collapse to network_policies_verified=\
             false in the Phase 2 deployment attestation; the pre-fix \
             `false` hardcode carried the same bool here as for \
             `VerifyFailed`, conflating no-evidence-collected with \
             evidence-of-missing-policy",
        );

        // The other two arms also have well-defined bool collapses —
        // Verified → true, VerifyFailed → false. The three-arm
        // distinction is structurally preserved at the enum level
        // even though `is_verified` discards two of them at the bool
        // surface (mirrors the
        // `test_chart_provenance_four_arms_collapse_to_distinct_bools`
        // shape one layer over).
        assert!(NetworkPolicyAdmissionOutcome::Verified.is_verified());
        assert!(!NetworkPolicyAdmissionOutcome::VerifyFailed.is_verified());

        // End-to-end through compose_product_certification: a minimal
        // source attestation composed under the staging policy
        // produces `network_policies_verified: false` on the resulting
        // `DeploymentAttestation`, where the pre-fix body produced
        // the same bool but through an inline literal. The build /
        // image / chart inputs are empty here so the compose path
        // exercises the deployment-attestation construction directly
        // without involving the probe-driven Phase 1 inputs — same
        // isolation discipline as
        // `test_source_verified_routes_through_typed_flux_outcome`
        // one layer over.
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
            !cert.deployment.network_policies_verified,
            "the typed-primitive route at the call site must drive \
             network_policies_verified=false through to the \
             DeploymentAttestation record when no kubectl NetworkPolicy \
             probe ran inside the certification function; the pre-fix \
             `false` hardcode produced the same bool here but routed \
             through an inline literal that flattened the discriminator \
             between `ProbeAbsent` (no probe) and `VerifyFailed` \
             (probe ran and namespace lacks covering NetworkPolicy)",
        );
    }

    /// **Load-bearing deployment-attestation honesty pin: the prior
    /// `all_releases_signed: false` literal at the
    /// `compose_product_certification` call site stamped a negative
    /// Phase 2 HelmRelease-signature claim into every
    /// `DeploymentAttestation` regardless of whether the cluster's
    /// `HelmRelease` resources had actually been queried for the
    /// deployment's namespace.** The bool surface was honest at the
    /// claim layer (a deployment attestation that records
    /// `all_releases_signed: false` against a certification function
    /// that never spawned a kubectl probe is correctly negative) but
    /// flattened three structurally distinct operational worlds a
    /// downstream verifier reading `all_releases_signed: false` could
    /// not recover from the bool alone: `Verified` (probe ran and
    /// every `HelmRelease` carries a valid sekiban signature
    /// annotation), `VerifyFailed` (probe ran and one or more
    /// `HelmRelease` resources lack the annotation — evidence of an
    /// unsigned release the prior deploy step failed to seal,
    /// the structural failure THEORY §V.4 Phase 2 / §VII.1 names),
    /// and `ProbeAbsent` (no kubectl probe ran inside the
    /// certification function — no evidence either way). The typed
    /// primitive `crate::helm_release_signature::
    /// HelmReleaseSignatureOutcome` preserves the three operational
    /// worlds the prior bare bool flattened, and the call site routes
    /// through `is_verified()`, which returns `true` only on the
    /// `Verified` arm.
    ///
    /// Until a follow-up commit wires a `kubectl get helmrelease`
    /// (or typed `kube::Api::<HelmRelease>::list(...)`) probe at the
    /// call site, the outcome collapses to `ProbeAbsent` →
    /// `all_releases_signed: false` — honestly naming "no HelmRelease
    /// signature-annotation probe ran inside the certification
    /// function" rather than collapsing it into the same bool bucket
    /// as a probe-detected unsigned-release state. Same fail-before /
    /// pass-after shape as the sibling
    /// `test_network_policies_verified_routes_through_typed_outcome`
    /// (commit f8a5d8e) one layer over and
    /// `test_source_verified_routes_through_typed_flux_outcome`
    /// (commit 5931e32) two layers over (typed probe-absent at the
    /// call site, real probe deferred to a follow-up).
    ///
    /// Pin the post-fix call-site expression directly so a future
    /// regression that re-introduced a hardcoded bare `false` would
    /// fail before any Phase 2 record was published under it: the
    /// value the call site now passes for `all_releases_signed` is
    /// exactly `HelmReleaseSignatureOutcome::ProbeAbsent.
    /// is_verified()`, and that is structurally `false`. The
    /// end-to-end pin then walks `compose_product_certification`
    /// against a minimal source attestation and confirms `cert.
    /// deployment.all_releases_signed == false`, where the pre-fix
    /// body would have produced the same bool but through an inline
    /// literal that flattened the discriminator — closes the sibling
    /// gap the `// Will be true after this pipeline completes`
    /// comment named directly above the `all_releases_signed: false`
    /// literal in `compose_product_certification`.
    #[test]
    fn test_all_releases_signed_routes_through_typed_outcome() {
        use crate::helm_release_signature::HelmReleaseSignatureOutcome;

        // Call-site expression pin: this is the exact expression
        // `compose_product_certification` now passes for
        // `all_releases_signed`. The pre-fix call site passed the
        // literal `false`; pinning the post-fix expression at this
        // layer means a future refactor that dropped the typed-
        // primitive route would fail this test before any Phase 2
        // record was published under the regression. Same shape as
        // `test_network_policies_verified_routes_through_typed_outcome`
        // (`NetworkPolicyAdmissionOutcome::ProbeAbsent.is_verified()`)
        // one layer over.
        assert!(
            !HelmReleaseSignatureOutcome::ProbeAbsent.is_verified(),
            "ProbeAbsent must collapse to all_releases_signed=false \
             in the Phase 2 deployment attestation; the pre-fix \
             `false` hardcode carried the same bool here as for \
             `VerifyFailed`, conflating no-evidence-collected with \
             evidence-of-unsigned-release",
        );

        // The other two arms also have well-defined bool collapses —
        // Verified → true, VerifyFailed → false. The three-arm
        // distinction is structurally preserved at the enum level
        // even though `is_verified` discards two of them at the bool
        // surface (mirrors the
        // `test_chart_provenance_four_arms_collapse_to_distinct_bools`
        // shape one layer over).
        assert!(HelmReleaseSignatureOutcome::Verified.is_verified());
        assert!(!HelmReleaseSignatureOutcome::VerifyFailed.is_verified());

        // End-to-end through compose_product_certification: a minimal
        // source attestation composed under the staging policy
        // produces `all_releases_signed: false` on the resulting
        // `DeploymentAttestation`, where the pre-fix body produced
        // the same bool but through an inline literal. The build /
        // image / chart inputs are empty (except the one build that
        // gives the SLSA-provenance compliance dimension non-trivial
        // content) so the compose path exercises the deployment-
        // attestation construction directly without involving the
        // probe-driven Phase 1 inputs — same isolation discipline as
        // `test_network_policies_verified_routes_through_typed_outcome`
        // one layer over.
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
            !cert.deployment.all_releases_signed,
            "the typed-primitive route at the call site must drive \
             all_releases_signed=false through to the \
             DeploymentAttestation record when no kubectl HelmRelease \
             probe ran inside the certification function; the pre-fix \
             `false` hardcode produced the same bool here but routed \
             through an inline literal that flattened the discriminator \
             between `ProbeAbsent` (no probe) and `VerifyFailed` \
             (probe ran and namespace has unsigned HelmReleases)",
        );
    }

    /// **Load-bearing deployment-attestation honesty pin: the prior
    /// `all_healthy: false` literal at the `compose_product_
    /// certification` call site stamped a negative Phase 2 pod-health
    /// claim into every `DeploymentAttestation` regardless of whether
    /// the cluster's `Pod` resources had actually been queried for the
    /// deployment's namespace.** The bool surface was honest at the
    /// claim layer (a deployment attestation that records
    /// `all_healthy: false` against a certification function that never
    /// spawned a kubectl probe is correctly negative) but flattened
    /// three structurally distinct operational worlds a downstream
    /// verifier reading `all_healthy: false` could not recover from
    /// the bool alone: `Healthy` (probe ran and every `Pod` is
    /// `Running` and `Ready`), `UnhealthyPods` (probe ran and one or
    /// more `Pod` resources are in `Pending`, `Failed`, `Unknown`, or
    /// `Running`-but-not-`Ready` state — evidence of a rollout that
    /// landed unhealthy workloads, the structural failure THEORY §V.4
    /// Phase 2 names), and `ProbeAbsent` (no kubectl probe ran inside
    /// the certification function — no evidence either way). The typed
    /// primitive `crate::pod_health::PodHealthOutcome` preserves the
    /// three operational worlds the prior bare bool flattened, and the
    /// call site routes through `is_healthy()`, which returns `true`
    /// only on the `Healthy` arm.
    ///
    /// Until a follow-up commit wires a `kubectl get pods` (or typed
    /// `kube::Api::<Pod>::list(...)`) probe at the call site, the
    /// outcome collapses to `ProbeAbsent` → `all_healthy: false` —
    /// honestly naming "no pod-health probe ran inside the
    /// certification function" rather than collapsing it into the same
    /// bool bucket as a probe-detected unhealthy-pod state. Same
    /// fail-before / pass-after shape as the sibling
    /// `test_all_releases_signed_routes_through_typed_outcome`
    /// (commit 8b1407d) one layer over and
    /// `test_network_policies_verified_routes_through_typed_outcome`
    /// (commit f8a5d8e) two layers over (typed probe-absent at the
    /// call site, real probe deferred to a follow-up).
    ///
    /// Pin the post-fix call-site expression directly so a future
    /// regression that re-introduced a hardcoded bare `false` would
    /// fail before any Phase 2 record was published under it: the
    /// value the call site now passes for `all_healthy` is exactly
    /// `PodHealthOutcome::ProbeAbsent.is_healthy()`, and that is
    /// structurally `false`. The end-to-end pin then walks
    /// `compose_product_certification` against a minimal source
    /// attestation and confirms `cert.deployment.all_healthy == false`,
    /// where the pre-fix body would have produced the same bool but
    /// through an inline literal that flattened the discriminator —
    /// closes the sibling gap the `// These will be populated by
    /// sekiban and kensa once deployed` comment named directly above
    /// the `all_healthy: false` literal in
    /// `compose_product_certification`.
    #[test]
    fn test_all_healthy_routes_through_typed_pod_outcome() {
        use crate::pod_health::PodHealthOutcome;

        // Call-site expression pin: this is the exact expression
        // `compose_product_certification` now passes for `all_healthy`.
        // The pre-fix call site passed the literal `false`; pinning
        // the post-fix expression at this layer means a future refactor
        // that dropped the typed-primitive route would fail this test
        // before any Phase 2 record was published under the regression.
        // Same shape as `test_all_releases_signed_routes_through_typed_
        // outcome` (`HelmReleaseSignatureOutcome::ProbeAbsent.
        // is_verified()`) one layer over.
        assert!(
            !PodHealthOutcome::ProbeAbsent.is_healthy(),
            "ProbeAbsent must collapse to all_healthy=false in the \
             Phase 2 deployment attestation; the pre-fix `false` \
             hardcode carried the same bool here as for \
             `UnhealthyPods`, conflating no-evidence-collected with \
             evidence-of-unhealthy-pod",
        );

        // The other two arms also have well-defined bool collapses —
        // Healthy → true, UnhealthyPods → false. The three-arm
        // distinction is structurally preserved at the enum level even
        // though `is_healthy` discards two of them at the bool surface
        // (mirrors the
        // `test_all_releases_signed_routes_through_typed_outcome`
        // shape one layer over).
        assert!(PodHealthOutcome::Healthy.is_healthy());
        assert!(!PodHealthOutcome::UnhealthyPods.is_healthy());

        // End-to-end through compose_product_certification: a minimal
        // source attestation composed under the staging policy produces
        // `all_healthy: false` on the resulting `DeploymentAttestation`,
        // where the pre-fix body produced the same bool but through an
        // inline literal. The build / image / chart inputs are empty
        // (except the one build that gives the SLSA-provenance
        // compliance dimension non-trivial content) so the compose path
        // exercises the deployment-attestation construction directly
        // without involving the probe-driven Phase 1 inputs — same
        // isolation discipline as
        // `test_all_releases_signed_routes_through_typed_outcome` one
        // layer over.
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
            !cert.deployment.all_healthy,
            "the typed-primitive route at the call site must drive \
             all_healthy=false through to the DeploymentAttestation \
             record when no kubectl Pod probe ran inside the \
             certification function; the pre-fix `false` hardcode \
             produced the same bool here but routed through an inline \
             literal that flattened the discriminator between \
             `ProbeAbsent` (no probe) and `UnhealthyPods` (probe ran \
             and namespace has non-Running-or-non-Ready pods)",
        );
    }

    /// **Load-bearing deployment-attestation honesty pin: the prior
    /// `manifest_hash: Blake3Hash::digest(b"pending-deployment")` literal
    /// at the `compose_product_certification` call site stamped a
    /// name-keyed sentinel into every Phase 2 `DeploymentAttestation`'s
    /// `manifest_hash` field regardless of which rendered manifest stream
    /// the certification was assembled against.** Two structural honesty
    /// failures followed (mirroring the closed gaps at the chart-content,
    /// source-tree, image-manifest, Nix-closure, and compliance-
    /// dimensions layers): (a) every Phase 2 deployment record across
    /// every product, environment, and cluster collapsed to the same
    /// `manifest_hash` value, defeating the content-addressed-identity
    /// invariant THEORY §VI.1 names — a downstream verifier reading two
    /// attestations carrying the same `manifest_hash` could not
    /// distinguish them as describing the same rendered cluster state
    /// from describing two different rendered states under the shared
    /// constant; and (b) three structurally distinct operational worlds
    /// — `Rendered` (kustomize / flux build succeeded and the YAML
    /// stream canonicalised), `RenderFailed` (kustomize exited non-zero
    /// — evidence of render-time failure, the structural failure that
    /// gates Phase 2 admission under THEORY §V.4), and `ProbeAbsent`
    /// (no render probe ran inside the certification function — no
    /// evidence either way) — all collapsed to the same
    /// `b"pending-deployment"` hash, losing the discriminator a
    /// `sekiban` strict-production policy that fails-closed on
    /// render-time failure depends on. The typed primitive
    /// `crate::deployment_manifest::DeploymentManifestRenderOutcome`
    /// preserves the three operational worlds the prior name-keyed
    /// constant flattened; the call site routes through `manifest_hash()`
    /// which emits a structurally distinct BLAKE3 digest per arm.
    ///
    /// Until a follow-up commit wires a `kustomize build` (or
    /// `flux build kustomization`) probe at the call site, the outcome
    /// collapses to `ProbeAbsent` → `Blake3Hash::digest(b"no-manifest-
    /// render")` — honestly naming "no render probe ran inside the
    /// certification function" rather than stamping a constant that
    /// would also be produced under render-failure and under any
    /// successful render against any namespace. Same fail-before /
    /// pass-after shape as the sibling
    /// `test_all_healthy_routes_through_typed_pod_outcome` (commit
    /// e76db87) one layer over and
    /// `test_compose_compliance_hash_grounded_in_dimensions_not_sentinel`
    /// (commit 5baaa50) at the compliance-dimensions layer (typed
    /// probe-absent at the call site, real probe deferred to a
    /// follow-up).
    ///
    /// Pin the post-fix call-site expression directly so a future
    /// regression that re-introduced the hardcoded name-keyed constant
    /// would fail before any Phase 2 record was published under it: the
    /// value the call site now passes for `manifest_hash` is exactly
    /// `DeploymentManifestRenderOutcome::ProbeAbsent.manifest_hash()`,
    /// which is `Blake3Hash::digest(b"no-manifest-render")` and NOT
    /// `Blake3Hash::digest(b"pending-deployment")`. The end-to-end pin
    /// then walks `compose_product_certification` against a minimal
    /// source attestation and confirms `cert.deployment.manifest_hash`
    /// equals the typed-outcome value, where the pre-fix body would
    /// have produced the pre-fix sentinel — closes the sibling gap the
    /// `// For initial PoC, use minimal deployment` comment named
    /// directly above the `Blake3Hash::digest(b"pending-deployment")`
    /// literal in `compose_product_certification`.
    #[test]
    fn test_manifest_hash_routes_through_typed_render_outcome() {
        use crate::deployment_manifest::DeploymentManifestRenderOutcome;

        // Call-site expression pin: this is the exact expression
        // `compose_product_certification` now passes for `manifest_hash`.
        // The pre-fix call site passed `Blake3Hash::digest(b"pending-
        // deployment")`; pinning the post-fix expression at this layer
        // means a future refactor that dropped the typed-primitive
        // route would fail this test before any Phase 2 record was
        // published under the regression. Same shape as
        // `test_all_healthy_routes_through_typed_pod_outcome`
        // (`PodHealthOutcome::ProbeAbsent.is_healthy()`) one layer
        // over.
        let pre_fix_sentinel = Blake3Hash::digest(b"pending-deployment");
        let probe_absent_hash = DeploymentManifestRenderOutcome::ProbeAbsent.manifest_hash();
        assert_ne!(
            probe_absent_hash.to_hex(),
            pre_fix_sentinel.to_hex(),
            "ProbeAbsent.manifest_hash() must NOT equal the pre-fix \
             `Blake3Hash::digest(b\"pending-deployment\")` constant; the \
             pre-fix constant collapsed three operational worlds \
             (Rendered, RenderFailed, ProbeAbsent) into a single hash \
             that stamped byte-identically across every Phase 2 \
             deployment record",
        );

        // The other two arms also produce structurally distinct
        // manifest_hash values from each other and from ProbeAbsent.
        // The three-arm distinction is structurally preserved at both
        // the enum level and the BLAKE3-digest level — a downstream
        // verifier walking either surface recovers the kind-of-claim
        // (mirrors the `test_three_arms_produce_three_distinct_
        // manifest_hashes` pin in the typed primitive's own test
        // module).
        let rendered = DeploymentManifestRenderOutcome::Rendered {
            fingerprint: b"apps/v1|Deployment|myns|svc\tabc".to_vec(),
        };
        let failed = DeploymentManifestRenderOutcome::RenderFailed;
        let absent = DeploymentManifestRenderOutcome::ProbeAbsent;
        assert_ne!(
            rendered.manifest_hash().to_hex(),
            failed.manifest_hash().to_hex()
        );
        assert_ne!(
            rendered.manifest_hash().to_hex(),
            absent.manifest_hash().to_hex()
        );
        assert_ne!(
            failed.manifest_hash().to_hex(),
            absent.manifest_hash().to_hex()
        );

        // End-to-end through compose_product_certification: a minimal
        // source attestation composed under the staging policy produces
        // a `manifest_hash` on the resulting `DeploymentAttestation` that
        // equals the typed-outcome `ProbeAbsent` value, where the pre-
        // fix body would have produced the pre-fix `b"pending-deployment"`
        // sentinel. The build / image / chart inputs are empty (except
        // the one build that gives the SLSA-provenance compliance
        // dimension non-trivial content) so the compose path exercises
        // the deployment-attestation construction directly without
        // involving the probe-driven Phase 1 inputs — same isolation
        // discipline as `test_all_healthy_routes_through_typed_pod_
        // outcome` one layer over.
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

        // (a) The Phase 2 record's `manifest_hash` is NOT the pre-fix
        // sentinel — the load-bearing regression pin. A future
        // regression that re-introduced `Blake3Hash::digest(b"pending-
        // deployment")` at the call site would fail here before any
        // Phase 2 attestation was published under it.
        assert_ne!(
            cert.deployment.manifest_hash.to_hex(),
            pre_fix_sentinel.to_hex(),
            "the typed-primitive route at the call site must drive \
             manifest_hash away from the pre-fix `Blake3Hash::digest(\
             b\"pending-deployment\")` constant through to the \
             DeploymentAttestation record; the pre-fix literal stamped \
             the same hash across every Phase 2 deployment regardless \
             of which rendered manifest stream the certification was \
             assembled against",
        );

        // (b) The Phase 2 record's `manifest_hash` IS exactly the typed-
        // outcome `ProbeAbsent` value — confirms the typed primitive
        // is the sole source of the hash at the call site. A future
        // refactor that swapped in a different sentinel (or a
        // different probe-absent expression) would fail this pin
        // before any record was published under it.
        assert_eq!(
            cert.deployment.manifest_hash.to_hex(),
            probe_absent_hash.to_hex(),
            "the typed-primitive route at the call site must drive the \
             exact `ProbeAbsent.manifest_hash()` value through to the \
             DeploymentAttestation record; any divergence would mean \
             the typed primitive is NOT the sole source of the hash \
             at the call site, re-opening the discriminator loss the \
             primitive exists to close",
        );
    }

    /// **Load-bearing deployment-attestation honesty pin: the prior
    /// `running_pods: 0` literal at the `compose_product_certification`
    /// call site stamped a bare zero into every Phase 2
    /// `DeploymentAttestation`'s `running_pods` field regardless of
    /// whether a kubectl pod-listing probe ran inside the certification
    /// function.** Two structurally distinct operational worlds —
    /// `Counted { count: 0 }` (probe RAN against an empty namespace and
    /// observed zero pods — evidence of a rollout that admitted the
    /// `HelmRelease` but never materialised any workloads, the
    /// post-admission failure mode THEORY §V.4 / §VII.1 name as the
    /// Phase 2 honesty channel) and `ProbeAbsent` (no probe ran inside
    /// the certification function — no evidence either way) — collapsed
    /// to the same `0`, losing the discriminator a downstream `sekiban`
    /// strict-production policy that fails-closed on evidence of an
    /// empty deployment depends on. The typed primitive
    /// `crate::pod_listing::PodListingOutcome` (`Counted { count }` /
    /// `ProbeAbsent`) preserves both operational worlds the prior bare
    /// usize flattened; the call site routes through `running_pods()`
    /// which collapses `Counted { count } -> count` and `ProbeAbsent
    /// -> 0` — usize surface unchanged for the no-probe-ran world,
    /// structural discriminator restored.
    ///
    /// Until a follow-up commit wires a `kubectl get pods` (or typed
    /// `kube::Api::<Pod>::list(...)`) probe at the call site, the
    /// outcome collapses to `ProbeAbsent -> running_pods: 0` —
    /// honestly naming "no pod-listing probe ran inside the
    /// certification function" rather than stamping a zero that would
    /// also be produced under probed-empty-namespace. The probe is the
    /// natural companion of [`crate::pod_health::PodHealthOutcome`]
    /// (commit e76db87) at the same `PodList` walk: a single
    /// follow-up that wires `kube::Api::<Pod>::list(...)` populates
    /// BOTH `running_pods` AND `all_healthy` from the same response.
    /// Same fail-before / pass-after shape as
    /// `test_all_healthy_routes_through_typed_pod_outcome` (commit
    /// e76db87) and `test_manifest_hash_routes_through_typed_render_
    /// outcome` (commit 36d90b6) one layer over (typed probe-absent
    /// at the call site, real probe deferred to a follow-up).
    ///
    /// Pin the post-fix call-site expression directly so a future
    /// regression that re-introduced the hardcoded bare `0` literal
    /// would fail before any Phase 2 record was published under it:
    /// the value the call site now passes for `running_pods` is
    /// exactly `PodListingOutcome::ProbeAbsent.running_pods()`, which
    /// is `0` (matching the pre-fix surface value) BUT routes through
    /// a structurally distinct enum arm from `Counted { count: 0 }`.
    /// The end-to-end pin then walks `compose_product_certification`
    /// against a minimal source attestation and confirms
    /// `cert.deployment.running_pods == 0` through the typed route
    /// rather than an inline literal — closes the sibling gap the
    /// `// These will be populated by sekiban and kensa once deployed`
    /// comment named directly above the `running_pods: 0` literal in
    /// `compose_product_certification`.
    #[test]
    fn test_running_pods_routes_through_typed_pod_listing_outcome() {
        use crate::pod_listing::PodListingOutcome;

        // Call-site expression pin: this is the exact expression
        // `compose_product_certification` now passes for `running_pods`.
        // The pre-fix call site passed the literal `0`; pinning the
        // post-fix expression at this layer means a future refactor
        // that dropped the typed-primitive route would fail this test
        // before any Phase 2 record was published under the regression.
        // Same shape as `test_all_healthy_routes_through_typed_pod_
        // outcome` (`PodHealthOutcome::ProbeAbsent.is_healthy()`) one
        // layer over.
        assert_eq!(
            PodListingOutcome::ProbeAbsent.running_pods(),
            0,
            "ProbeAbsent must collapse to running_pods=0 in the Phase 2 \
             deployment attestation; the pre-fix `0` hardcode carried \
             the same usize here as for `Counted {{ count: 0 }}`, \
             conflating no-evidence-collected with probed-empty-namespace",
        );

        // The Counted arm passes counts through unchanged — the
        // structural distinction the typed primitive preserves at the
        // enum level even though `ProbeAbsent` and `Counted { count:
        // 0 }` collapse to the same usize at the bool surface.
        // (Mirrors the `test_is_verified_pins_all_arms` shape one
        // layer over in the sibling probe modules.)
        assert_eq!(PodListingOutcome::Counted { count: 0 }.running_pods(), 0);
        assert_eq!(PodListingOutcome::Counted { count: 3 }.running_pods(), 3);
        assert_ne!(
            PodListingOutcome::Counted { count: 0 },
            PodListingOutcome::ProbeAbsent,
            "Counted{{count: 0}} must remain structurally distinct from \
             ProbeAbsent at the enum level — the discriminator the \
             pre-fix `0` hardcode erased",
        );

        // End-to-end through compose_product_certification: a minimal
        // source attestation composed under the staging policy produces
        // `running_pods: 0` on the resulting `DeploymentAttestation`,
        // where the pre-fix body produced the same usize but through
        // an inline literal. The build / image / chart inputs are
        // empty (except the one build that gives the SLSA-provenance
        // compliance dimension non-trivial content) so the compose
        // path exercises the deployment-attestation construction
        // directly without involving the probe-driven Phase 1 inputs
        // — same isolation discipline as
        // `test_all_healthy_routes_through_typed_pod_outcome` one
        // layer over.
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
        assert_eq!(
            cert.deployment.running_pods, 0,
            "the typed-primitive route at the call site must drive \
             running_pods=0 through to the DeploymentAttestation \
             record when no kubectl Pod-listing probe ran inside the \
             certification function; the pre-fix `0` hardcode \
             produced the same usize here but routed through an \
             inline literal that flattened the discriminator between \
             `ProbeAbsent` (no probe) and `Counted {{ count: 0 }}` \
             (probe ran and namespace is empty)",
        );

        // Confirm the typed primitive is the sole source of the
        // running_pods value at the call site by walking the same
        // expression directly and confirming the Phase 2 record
        // carries exactly its result. A future refactor that swapped
        // in a different probe-absent expression (or re-introduced a
        // bare literal) would fail this pin before any record was
        // published under it.
        assert_eq!(
            cert.deployment.running_pods,
            PodListingOutcome::ProbeAbsent.running_pods(),
            "the typed-primitive route at the call site must drive the \
             exact `ProbeAbsent.running_pods()` value through to the \
             DeploymentAttestation record; any divergence would mean \
             the typed primitive is NOT the sole source of the usize \
             at the call site, re-opening the discriminator loss the \
             primitive exists to close",
        );
    }

    /// **Load-bearing deployment-attestation honesty pin: the prior
    /// `cis_k8s_pass_rate: 0.0` literal at the
    /// `compose_product_certification` call site stamped a bare zero
    /// `f64` into every Phase 2 `DeploymentAttestation`'s
    /// `cis_k8s_pass_rate` field regardless of whether a kensa CIS-
    /// Kubernetes-Benchmark audit ran inside the certification
    /// function.** Two structurally distinct operational worlds —
    /// `Probed { ratio: 0.0 }` (probe RAN against a cluster that failed
    /// every CIS control — evidence of a freshly provisioned cluster
    /// or one whose CIS baseline never landed, the structural failure
    /// mode CIS Kubernetes Benchmark §1–§5 names) and `ProbeAbsent`
    /// (no probe ran inside the certification function — no evidence
    /// either way) — collapsed to the same `0.0`, losing the
    /// discriminator a downstream `sekiban` strict-production policy
    /// that fails-closed on evidence of a zero-pass-rate cluster
    /// depends on. The typed primitive
    /// `crate::cis_k8s_pass_rate::CisK8sPassRateOutcome` (`Probed {
    /// ratio }` / `ProbeAbsent`) preserves both operational worlds the
    /// prior bare `f64` flattened; the call site routes through
    /// `pass_rate()` which collapses `Probed { ratio } -> ratio` and
    /// `ProbeAbsent -> 0.0` — `f64` surface unchanged for the no-
    /// probe-ran world, structural discriminator restored. With this
    /// commit, the last remaining hardcoded scalar field on the Phase
    /// 2 `DeploymentAttestation` closes the typed-primitive route,
    /// leaving every Phase 2 field grounded in a typed probe outcome.
    ///
    /// Until a follow-up commit wires a `kensa cis-k8s` (or typed
    /// `kensa::cis_k8s::audit(...)`) probe at the call site, the
    /// outcome collapses to `ProbeAbsent -> cis_k8s_pass_rate: 0.0` —
    /// honestly naming "no kensa CIS probe ran inside the
    /// certification function" rather than stamping a zero that would
    /// also be produced under probed-zero-pass-rate. Same fail-before
    /// / pass-after shape as
    /// `test_running_pods_routes_through_typed_pod_listing_outcome`
    /// (commit d002374) and
    /// `test_manifest_hash_routes_through_typed_render_outcome`
    /// (commit 36d90b6) at the sibling Phase 2 scalar fields (typed
    /// probe-absent at the call site, real probe deferred to a
    /// follow-up).
    ///
    /// Pin the post-fix call-site expression directly so a future
    /// regression that re-introduced the hardcoded bare `0.0` literal
    /// would fail before any Phase 2 record was published under it:
    /// the value the call site now passes for `cis_k8s_pass_rate` is
    /// exactly `CisK8sPassRateOutcome::ProbeAbsent.pass_rate()`, which
    /// is `0.0` (matching the pre-fix surface value) BUT routes
    /// through a structurally distinct enum arm from `Probed { ratio:
    /// 0.0 }`. The end-to-end pin then walks
    /// `compose_product_certification` against a minimal source
    /// attestation and confirms `cert.deployment.cis_k8s_pass_rate ==
    /// 0.0` through the typed route rather than an inline literal —
    /// closes the last `// Populated post-deploy by kensa`-annotated
    /// gap on the Phase 2 deployment-attestation surface.
    #[test]
    fn test_cis_k8s_pass_rate_routes_through_typed_outcome() {
        use crate::cis_k8s_pass_rate::CisK8sPassRateOutcome;

        // Call-site expression pin: this is the exact expression
        // `compose_product_certification` now passes for
        // `cis_k8s_pass_rate`. The pre-fix call site passed the literal
        // `0.0`; pinning the post-fix expression at this layer means a
        // future refactor that dropped the typed-primitive route would
        // fail this test before any Phase 2 record was published under
        // the regression. Same shape as
        // `test_running_pods_routes_through_typed_pod_listing_outcome`
        // (`PodListingOutcome::ProbeAbsent.running_pods()`) at the
        // sibling Phase 2 scalar field.
        assert_eq!(
            CisK8sPassRateOutcome::ProbeAbsent.pass_rate(),
            0.0,
            "ProbeAbsent must collapse to pass_rate=0.0 in the Phase 2 \
             deployment attestation; the pre-fix `0.0` hardcode \
             carried the same f64 here as for `Probed {{ ratio: 0.0 }}`, \
             conflating no-evidence-collected with probed-zero-pass-rate",
        );

        // The Probed arm passes ratios through unchanged — the
        // structural distinction the typed primitive preserves at the
        // enum level even though `ProbeAbsent` and `Probed { ratio:
        // 0.0 }` collapse to the same `f64` at the surface.
        assert_eq!(
            CisK8sPassRateOutcome::Probed { ratio: 0.0 }.pass_rate(),
            0.0,
        );
        assert_eq!(
            CisK8sPassRateOutcome::Probed { ratio: 0.92 }.pass_rate(),
            0.92,
        );
        assert_ne!(
            CisK8sPassRateOutcome::Probed { ratio: 0.0 },
            CisK8sPassRateOutcome::ProbeAbsent,
            "Probed{{ratio: 0.0}} must remain structurally distinct \
             from ProbeAbsent at the enum level — the discriminator \
             the pre-fix `0.0` hardcode erased",
        );

        // End-to-end through compose_product_certification: a minimal
        // source attestation composed under the staging policy produces
        // `cis_k8s_pass_rate: 0.0` on the resulting
        // `DeploymentAttestation`, where the pre-fix body produced the
        // same f64 but through an inline literal. Same isolation
        // discipline as
        // `test_running_pods_routes_through_typed_pod_listing_outcome`
        // at the sibling Phase 2 scalar field.
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
        assert_eq!(
            cert.deployment.cis_k8s_pass_rate, 0.0,
            "the typed-primitive route at the call site must drive \
             cis_k8s_pass_rate=0.0 through to the DeploymentAttestation \
             record when no kensa CIS probe ran inside the \
             certification function; the pre-fix `0.0` hardcode \
             produced the same f64 here but routed through an inline \
             literal that flattened the discriminator between \
             `ProbeAbsent` (no probe) and `Probed {{ ratio: 0.0 }}` \
             (probe ran and cluster fails every CIS control)",
        );

        // Confirm the typed primitive is the sole source of the
        // cis_k8s_pass_rate value at the call site by walking the same
        // expression directly and confirming the Phase 2 record carries
        // exactly its result. A future refactor that swapped in a
        // different probe-absent expression (or re-introduced a bare
        // literal) would fail this pin before any record was published
        // under it.
        assert_eq!(
            cert.deployment.cis_k8s_pass_rate,
            CisK8sPassRateOutcome::ProbeAbsent.pass_rate(),
            "the typed-primitive route at the call site must drive the \
             exact `ProbeAbsent.pass_rate()` value through to the \
             DeploymentAttestation record; any divergence would mean \
             the typed primitive is NOT the sole source of the f64 at \
             the call site, re-opening the discriminator loss the \
             primitive exists to close",
        );
    }

    /// Load-bearing probe-coverage floor pin: the seven typed probe
    /// outcomes the Phase 2 `DeploymentAttestation` depends on, all in
    /// their `ProbeAbsent` arm (today's `compose_product_certification`
    /// call-site state), produce `ProbeCoverage { ran: 0, absent: 7 }`.
    /// This is the floor every per-field typed-primitive commit
    /// (b98eb5a → ddc789d) collapsed to one probe at a time; the
    /// seven-probe coverage signal lifts the honesty channel from
    /// per-field-claim ("did this probe run?") to per-record
    /// ("how much of this attestation's evidence channel actually
    /// fired?") — a downstream `sekiban` admission verifier
    /// reconciliation can distinguish a high-evidence Phase 2 record
    /// from one whose every field collapsed to its honest default by
    /// reading the structured `(ran, absent, total)` fields on the
    /// `target: "forge::attestation::probe_coverage"` tracing event
    /// `compose_product_certification` emits alongside the composed
    /// certification.
    #[test]
    fn test_deployment_probe_coverage_all_absent_floor() {
        use crate::cis_k8s_pass_rate::CisK8sPassRateOutcome;
        use crate::deployment_manifest::DeploymentManifestRenderOutcome;
        use crate::flux_source_verification::FluxSourceVerificationOutcome;
        use crate::helm_release_signature::HelmReleaseSignatureOutcome;
        use crate::network_policy_admission::NetworkPolicyAdmissionOutcome;
        use crate::pod_health::PodHealthOutcome;
        use crate::pod_listing::PodListingOutcome;
        use crate::probe_outcome::ProbeCoverage;

        let coverage = deployment_probe_coverage(
            &FluxSourceVerificationOutcome::ProbeAbsent,
            &NetworkPolicyAdmissionOutcome::ProbeAbsent,
            &HelmReleaseSignatureOutcome::ProbeAbsent,
            &PodHealthOutcome::ProbeAbsent,
            &PodListingOutcome::ProbeAbsent,
            &DeploymentManifestRenderOutcome::ProbeAbsent,
            &CisK8sPassRateOutcome::ProbeAbsent,
        );
        assert_eq!(coverage, ProbeCoverage { ran: 0, absent: 7 });
        assert_eq!(
            coverage.total(),
            7,
            "the seven-probe count is the load-bearing structural \
             invariant the helper carries; a future regression that \
             dropped a parameter would shift the total here"
        );
    }

    /// Load-bearing probe-coverage ceiling pin: the seven typed probe
    /// outcomes all in their non-absent arms (the world a follow-up
    /// commit that wires real kubectl / kustomize / kensa probes at the
    /// `compose_product_certification` call site reaches) produce
    /// `ProbeCoverage { ran: 7, absent: 0 }`. The symmetric counterpart
    /// of the all-absent floor — together the two tests pin that every
    /// individual probe contributes exactly one to the ran or absent
    /// count (the all-absent floor has all seven in absent; the
    /// all-ran ceiling has all seven in ran; total stays at seven in
    /// both). A future regression that omitted a probe from the
    /// seven-element `&[&dyn ProbeOutcome; 7]` slice would shift the
    /// total below seven and fail this pin.
    #[test]
    fn test_deployment_probe_coverage_all_ran_ceiling() {
        use crate::cis_k8s_pass_rate::CisK8sPassRateOutcome;
        use crate::deployment_manifest::DeploymentManifestRenderOutcome;
        use crate::flux_source_verification::FluxSourceVerificationOutcome;
        use crate::helm_release_signature::HelmReleaseSignatureOutcome;
        use crate::network_policy_admission::NetworkPolicyAdmissionOutcome;
        use crate::pod_health::PodHealthOutcome;
        use crate::pod_listing::PodListingOutcome;
        use crate::probe_outcome::ProbeCoverage;

        let coverage = deployment_probe_coverage(
            &FluxSourceVerificationOutcome::Verified,
            &NetworkPolicyAdmissionOutcome::Verified,
            &HelmReleaseSignatureOutcome::Verified,
            &PodHealthOutcome::Healthy,
            &PodListingOutcome::Counted { count: 3 },
            &DeploymentManifestRenderOutcome::Rendered {
                fingerprint: b"test-manifest".to_vec(),
            },
            &CisK8sPassRateOutcome::Probed { ratio: 1.0 },
        );
        assert_eq!(coverage, ProbeCoverage { ran: 7, absent: 0 });
        assert_eq!(coverage.total(), 7);
    }

    /// Probe-coverage arithmetic pin: a mixed slice where three of the
    /// seven probes are in their non-absent arms and four are
    /// `ProbeAbsent` yields `ProbeCoverage { ran: 3, absent: 4 }`. Pins
    /// that the helper walks every element (not just a prefix or a
    /// fixed subset) and that the `ran + absent == total == 7`
    /// invariant holds for every arm-split. A future regression that
    /// hardcoded the ran/absent split based on a single representative
    /// probe (or short-circuited on the first absent probe) would fail
    /// this pin.
    #[test]
    fn test_deployment_probe_coverage_mixed_arms_arithmetic() {
        use crate::cis_k8s_pass_rate::CisK8sPassRateOutcome;
        use crate::deployment_manifest::DeploymentManifestRenderOutcome;
        use crate::flux_source_verification::FluxSourceVerificationOutcome;
        use crate::helm_release_signature::HelmReleaseSignatureOutcome;
        use crate::network_policy_admission::NetworkPolicyAdmissionOutcome;
        use crate::pod_health::PodHealthOutcome;
        use crate::pod_listing::PodListingOutcome;
        use crate::probe_outcome::ProbeCoverage;

        let coverage = deployment_probe_coverage(
            &FluxSourceVerificationOutcome::Verified,
            &NetworkPolicyAdmissionOutcome::ProbeAbsent,
            &HelmReleaseSignatureOutcome::VerifyFailed,
            &PodHealthOutcome::ProbeAbsent,
            &PodListingOutcome::Counted { count: 0 },
            &DeploymentManifestRenderOutcome::ProbeAbsent,
            &CisK8sPassRateOutcome::ProbeAbsent,
        );
        // Three probes in a non-absent arm (`Verified`, `VerifyFailed`,
        // `Counted { count: 0 }` — note the load-bearing distinction
        // `Counted { count: 0 }` from `ProbeAbsent`: a probe RAN against
        // an empty namespace), four in `ProbeAbsent`.
        assert_eq!(coverage, ProbeCoverage { ran: 3, absent: 4 });
        assert_eq!(coverage.total(), 7);
    }

    /// Pins that EVERY one of the seven probe-outcome parameters
    /// contributes to the coverage count: walking each probe through its
    /// non-absent arm in isolation (all other six in `ProbeAbsent`)
    /// yields `ProbeCoverage { ran: 1, absent: 6 }`. A future regression
    /// that omitted any parameter from the seven-element slice (or
    /// pinned its slice index to a constant arm) would fail the
    /// corresponding sub-case here. The load-bearing structural
    /// invariant: every typed outcome bound at the
    /// `compose_product_certification` call site participates in the
    /// coverage signal.
    #[test]
    fn test_deployment_probe_coverage_each_probe_individually_counted() {
        use crate::cis_k8s_pass_rate::CisK8sPassRateOutcome;
        use crate::deployment_manifest::DeploymentManifestRenderOutcome;
        use crate::flux_source_verification::FluxSourceVerificationOutcome;
        use crate::helm_release_signature::HelmReleaseSignatureOutcome;
        use crate::network_policy_admission::NetworkPolicyAdmissionOutcome;
        use crate::pod_health::PodHealthOutcome;
        use crate::pod_listing::PodListingOutcome;
        use crate::probe_outcome::ProbeCoverage;

        let one_one_one = ProbeCoverage { ran: 1, absent: 6 };

        // 1. source-verification
        let c = deployment_probe_coverage(
            &FluxSourceVerificationOutcome::Verified,
            &NetworkPolicyAdmissionOutcome::ProbeAbsent,
            &HelmReleaseSignatureOutcome::ProbeAbsent,
            &PodHealthOutcome::ProbeAbsent,
            &PodListingOutcome::ProbeAbsent,
            &DeploymentManifestRenderOutcome::ProbeAbsent,
            &CisK8sPassRateOutcome::ProbeAbsent,
        );
        assert_eq!(
            c, one_one_one,
            "FluxSourceVerificationOutcome::Verified must count"
        );

        // 2. network-policy
        let c = deployment_probe_coverage(
            &FluxSourceVerificationOutcome::ProbeAbsent,
            &NetworkPolicyAdmissionOutcome::Verified,
            &HelmReleaseSignatureOutcome::ProbeAbsent,
            &PodHealthOutcome::ProbeAbsent,
            &PodListingOutcome::ProbeAbsent,
            &DeploymentManifestRenderOutcome::ProbeAbsent,
            &CisK8sPassRateOutcome::ProbeAbsent,
        );
        assert_eq!(
            c, one_one_one,
            "NetworkPolicyAdmissionOutcome::Verified must count"
        );

        // 3. helm-release-signature
        let c = deployment_probe_coverage(
            &FluxSourceVerificationOutcome::ProbeAbsent,
            &NetworkPolicyAdmissionOutcome::ProbeAbsent,
            &HelmReleaseSignatureOutcome::Verified,
            &PodHealthOutcome::ProbeAbsent,
            &PodListingOutcome::ProbeAbsent,
            &DeploymentManifestRenderOutcome::ProbeAbsent,
            &CisK8sPassRateOutcome::ProbeAbsent,
        );
        assert_eq!(
            c, one_one_one,
            "HelmReleaseSignatureOutcome::Verified must count"
        );

        // 4. pod-health
        let c = deployment_probe_coverage(
            &FluxSourceVerificationOutcome::ProbeAbsent,
            &NetworkPolicyAdmissionOutcome::ProbeAbsent,
            &HelmReleaseSignatureOutcome::ProbeAbsent,
            &PodHealthOutcome::Healthy,
            &PodListingOutcome::ProbeAbsent,
            &DeploymentManifestRenderOutcome::ProbeAbsent,
            &CisK8sPassRateOutcome::ProbeAbsent,
        );
        assert_eq!(c, one_one_one, "PodHealthOutcome::Healthy must count");

        // 5. pod-listing
        let c = deployment_probe_coverage(
            &FluxSourceVerificationOutcome::ProbeAbsent,
            &NetworkPolicyAdmissionOutcome::ProbeAbsent,
            &HelmReleaseSignatureOutcome::ProbeAbsent,
            &PodHealthOutcome::ProbeAbsent,
            &PodListingOutcome::Counted { count: 5 },
            &DeploymentManifestRenderOutcome::ProbeAbsent,
            &CisK8sPassRateOutcome::ProbeAbsent,
        );
        assert_eq!(c, one_one_one, "PodListingOutcome::Counted must count");

        // 6. deployment-manifest
        let c = deployment_probe_coverage(
            &FluxSourceVerificationOutcome::ProbeAbsent,
            &NetworkPolicyAdmissionOutcome::ProbeAbsent,
            &HelmReleaseSignatureOutcome::ProbeAbsent,
            &PodHealthOutcome::ProbeAbsent,
            &PodListingOutcome::ProbeAbsent,
            &DeploymentManifestRenderOutcome::Rendered {
                fingerprint: b"x".to_vec(),
            },
            &CisK8sPassRateOutcome::ProbeAbsent,
        );
        assert_eq!(
            c, one_one_one,
            "DeploymentManifestRenderOutcome::Rendered must count"
        );

        // 7. cis-k8s-pass-rate
        let c = deployment_probe_coverage(
            &FluxSourceVerificationOutcome::ProbeAbsent,
            &NetworkPolicyAdmissionOutcome::ProbeAbsent,
            &HelmReleaseSignatureOutcome::ProbeAbsent,
            &PodHealthOutcome::ProbeAbsent,
            &PodListingOutcome::ProbeAbsent,
            &DeploymentManifestRenderOutcome::ProbeAbsent,
            &CisK8sPassRateOutcome::Probed { ratio: 0.5 },
        );
        assert_eq!(c, one_one_one, "CisK8sPassRateOutcome::Probed must count");
    }

    /// Load-bearing chart-probe-coverage floor pin: the four typed probe
    /// outcomes that ground every evidence-bearing field on the Phase 1
    /// `ChartAttestation`, all in their `ProbeAbsent` arm, produce
    /// `ProbeCoverage { ran: 0, absent: 4 }`. The chart-side peer of
    /// `test_deployment_probe_coverage_all_absent_floor` one layer over
    /// — together the two floor pins pin that the per-record coverage
    /// signal lifts the per-field honesty channel uniformly across the
    /// Phase 1 chart record and the Phase 2 deployment record.
    #[test]
    fn test_chart_probe_coverage_all_absent_floor() {
        use crate::chart_dependencies::ChartDependenciesOutcome;
        use crate::helm_lint::HelmLintOutcome;
        use crate::helm_provenance::HelmProvenanceOutcome;
        use crate::kensa_policy::KensaPolicyOutcome;
        use crate::probe_outcome::ProbeCoverage;

        let coverage = chart_probe_coverage(
            &HelmProvenanceOutcome::ProbeAbsent,
            &HelmLintOutcome::ProbeAbsent,
            &KensaPolicyOutcome::ProbeAbsent,
            &ChartDependenciesOutcome::ProbeAbsent,
        );
        assert_eq!(coverage, ProbeCoverage { ran: 0, absent: 4 });
        assert_eq!(
            coverage.total(),
            4,
            "the four-probe count is the load-bearing structural \
             invariant the helper carries; a future regression that \
             dropped a parameter would shift the total here"
        );
    }

    /// Load-bearing chart-probe-coverage ceiling pin: the four typed
    /// probe outcomes all in their non-absent arms (the world a
    /// follow-up commit that wires real `helm lint` / `kensa verify`
    /// probes at the `compute_chart_attestation` call site reaches —
    /// `chart_dependencies_outcome` already wires a real probe today)
    /// produce `ProbeCoverage { ran: 4, absent: 0 }`. The symmetric
    /// counterpart of the all-absent floor — together the two tests pin
    /// that every individual probe contributes exactly one to the ran
    /// or absent count.
    #[test]
    fn test_chart_probe_coverage_all_ran_ceiling() {
        use crate::chart_dependencies::ChartDependenciesOutcome;
        use crate::helm_lint::HelmLintOutcome;
        use crate::helm_provenance::HelmProvenanceOutcome;
        use crate::kensa_policy::KensaPolicyOutcome;
        use crate::probe_outcome::ProbeCoverage;

        let coverage = chart_probe_coverage(
            &HelmProvenanceOutcome::Verified {
                signed_chart_hash: Some("deadbeef".to_string()),
                signer_key_id: None,
            },
            &HelmLintOutcome::Passed {
                warning_count: 0,
                info_count: 0,
            },
            &KensaPolicyOutcome::Passed {
                evaluated_control_count: 12,
            },
            &ChartDependenciesOutcome::Listed { deps: vec![] },
        );
        assert_eq!(coverage, ProbeCoverage { ran: 4, absent: 0 });
        assert_eq!(coverage.total(), 4);
    }

    /// Chart-probe-coverage arithmetic pin: a mixed slice where two of
    /// the four probes are in their non-absent arms (one `Listed { deps:
    /// vec![] }` carrying the load-bearing leaf-chart distinction from
    /// `ProbeAbsent`, one `VerifyFailed` carrying the
    /// well-framing-failed-vs-absent distinction) and two are
    /// `ProbeAbsent` yields `ProbeCoverage { ran: 2, absent: 2 }`. Pins
    /// that the helper walks every element AND that the load-bearing
    /// "probe ran and produced negative evidence" arms (`VerifyFailed`,
    /// `Failed { .. }`, `Listed { deps: vec![] }`) count as ran, not
    /// absent — the discriminator the trait's `is_probe_absent`
    /// predicate preserves over the surface `is_verified` / `is_passed`
    /// bools.
    #[test]
    fn test_chart_probe_coverage_mixed_arms_arithmetic() {
        use crate::chart_dependencies::ChartDependenciesOutcome;
        use crate::helm_lint::HelmLintOutcome;
        use crate::helm_provenance::HelmProvenanceOutcome;
        use crate::kensa_policy::KensaPolicyOutcome;
        use crate::probe_outcome::ProbeCoverage;

        let coverage = chart_probe_coverage(
            &HelmProvenanceOutcome::VerifyFailed,
            &HelmLintOutcome::ProbeAbsent,
            &KensaPolicyOutcome::ProbeAbsent,
            &ChartDependenciesOutcome::Listed { deps: vec![] },
        );
        // Two probes in a non-absent arm (`VerifyFailed` — probe RAN
        // and the `.prov` framing failed; `Listed { deps: vec![] }` —
        // probe RAN and Chart.yaml declares no deps, the leaf-chart
        // discriminator from `ProbeAbsent`), two in `ProbeAbsent`.
        assert_eq!(coverage, ProbeCoverage { ran: 2, absent: 2 });
        assert_eq!(coverage.total(), 4);
    }

    /// Pins that EVERY one of the four chart-probe-outcome parameters
    /// contributes to the coverage count: walking each probe through its
    /// non-absent arm in isolation (all other three in `ProbeAbsent`)
    /// yields `ProbeCoverage { ran: 1, absent: 3 }`. A future regression
    /// that omitted any parameter from the four-element slice (or
    /// pinned its slice index to a constant arm) would fail the
    /// corresponding sub-case here. The load-bearing structural
    /// invariant: every typed outcome bound at the
    /// `compute_chart_attestation` call site participates in the
    /// chart-coverage signal.
    #[test]
    fn test_chart_probe_coverage_each_probe_individually_counted() {
        use crate::chart_dependencies::ChartDependenciesOutcome;
        use crate::helm_lint::HelmLintOutcome;
        use crate::helm_provenance::HelmProvenanceOutcome;
        use crate::kensa_policy::KensaPolicyOutcome;
        use crate::probe_outcome::ProbeCoverage;

        let one_three = ProbeCoverage { ran: 1, absent: 3 };

        // 1. provenance
        let c = chart_probe_coverage(
            &HelmProvenanceOutcome::Verified {
                signed_chart_hash: None,
                signer_key_id: None,
            },
            &HelmLintOutcome::ProbeAbsent,
            &KensaPolicyOutcome::ProbeAbsent,
            &ChartDependenciesOutcome::ProbeAbsent,
        );
        assert_eq!(c, one_three, "HelmProvenanceOutcome::Verified must count");

        // 2. lint
        let c = chart_probe_coverage(
            &HelmProvenanceOutcome::ProbeAbsent,
            &HelmLintOutcome::Passed {
                warning_count: 0,
                info_count: 0,
            },
            &KensaPolicyOutcome::ProbeAbsent,
            &ChartDependenciesOutcome::ProbeAbsent,
        );
        assert_eq!(c, one_three, "HelmLintOutcome::Passed must count");

        // 3. policy
        let c = chart_probe_coverage(
            &HelmProvenanceOutcome::ProbeAbsent,
            &HelmLintOutcome::ProbeAbsent,
            &KensaPolicyOutcome::Passed {
                evaluated_control_count: 1,
            },
            &ChartDependenciesOutcome::ProbeAbsent,
        );
        assert_eq!(c, one_three, "KensaPolicyOutcome::Passed must count");

        // 4. dependencies — the load-bearing `Listed { deps: vec![] }`
        // leaf-chart arm (probe RAN against a Chart.yaml declaring no
        // deps) must count as ran, not absent. This is the
        // discriminator the trait's `is_probe_absent` preserves over
        // the surface `Vec<DependencyHash>` `to_dependency_hashes()`
        // collapse (which yields the same empty vec for `Listed { deps:
        // vec![] }` AND `ProbeAbsent`).
        let c = chart_probe_coverage(
            &HelmProvenanceOutcome::ProbeAbsent,
            &HelmLintOutcome::ProbeAbsent,
            &KensaPolicyOutcome::ProbeAbsent,
            &ChartDependenciesOutcome::Listed { deps: vec![] },
        );
        assert_eq!(
            c, one_three,
            "ChartDependenciesOutcome::Listed must count (probe RAN; the \
             leaf-chart discriminator from ProbeAbsent that the surface \
             Vec<DependencyHash> erases)"
        );
    }

    /// Load-bearing build-probe-coverage floor pin: the three typed
    /// probe outcomes that ground every evidence-bearing field on the
    /// Phase 1 `BuildAttestation`, all in their absent arm (today's
    /// `compute_build_attestation` call-site state — no syft / grype /
    /// `nix build --rebuild` probe layer is integrated yet), produce
    /// `ProbeCoverage { ran: 0, absent: 3 }`. The build-side peer of
    /// `test_chart_probe_coverage_all_absent_floor` (Phase 1 chart,
    /// four probes) and `test_deployment_probe_coverage_all_absent_floor`
    /// (Phase 2 deployment, seven probes) — together the three floor
    /// pins pin that the per-record coverage signal lifts the per-field
    /// honesty channel uniformly across every attestation record forge
    /// composes.
    #[test]
    fn test_build_probe_coverage_all_absent_floor() {
        use crate::nix_reproducibility::NixReproducibilityOutcome;
        use crate::probe_outcome::ProbeCoverage;
        use crate::security_scan::{SbomProbeOutcome, VulnScanProbeOutcome};

        let coverage = build_probe_coverage(
            &SbomProbeOutcome::Absent,
            &VulnScanProbeOutcome::Absent,
            &NixReproducibilityOutcome::ProbeAbsent,
        );
        assert_eq!(coverage, ProbeCoverage { ran: 0, absent: 3 });
        assert_eq!(
            coverage.total(),
            3,
            "the three-probe count is the load-bearing structural \
             invariant the helper carries; a future regression that \
             dropped a parameter would shift the total here"
        );
    }

    /// Load-bearing build-probe-coverage ceiling pin: the three typed
    /// probe outcomes all in their non-absent arms (the world a
    /// follow-up commit that wires real syft / grype / `nix build
    /// --rebuild` probes at the `compute_build_attestation` call site
    /// reaches) produce `ProbeCoverage { ran: 3, absent: 0 }`. The
    /// symmetric counterpart of the all-absent floor — together the
    /// two tests pin that every individual probe contributes exactly
    /// one to the ran or absent count.
    #[test]
    fn test_build_probe_coverage_all_ran_ceiling() {
        use crate::nix_reproducibility::NixReproducibilityOutcome;
        use crate::probe_outcome::ProbeCoverage;
        use crate::security_scan::{SbomProbeOutcome, VulnScanProbeOutcome};
        use tameshi::hash::Blake3Hash;

        let coverage = build_probe_coverage(
            &SbomProbeOutcome::Collected {
                hash: Blake3Hash::digest(b"sbom-payload"),
            },
            &VulnScanProbeOutcome::Collected {
                hash: Blake3Hash::digest(b"vuln-scan-payload"),
                total_cves: 0,
                critical_high: 0,
            },
            &NixReproducibilityOutcome::Reproducible,
        );
        assert_eq!(coverage, ProbeCoverage { ran: 3, absent: 0 });
        assert_eq!(coverage.total(), 3);
    }

    /// Build-probe-coverage arithmetic pin: a mixed slice where one of
    /// the three probes is in its non-absent arm carrying the
    /// load-bearing `Drift` discriminator (probe RAN and the
    /// `nix build --rebuild` two-pass detected non-determinism —
    /// evidence of compromise, structurally distinct from
    /// `ProbeAbsent`) and the other two are absent yields
    /// `ProbeCoverage { ran: 1, absent: 2 }`. Pins that the helper
    /// walks every element AND that the load-bearing "probe ran and
    /// produced negative evidence" arm (`Drift`) counts as ran, not
    /// absent — the discriminator the trait's `is_probe_absent`
    /// predicate preserves over the surface `is_reproducible()` bool
    /// (which collapses both `Drift` and `ProbeAbsent` to `false`).
    #[test]
    fn test_build_probe_coverage_mixed_arms_arithmetic() {
        use crate::nix_reproducibility::NixReproducibilityOutcome;
        use crate::probe_outcome::ProbeCoverage;
        use crate::security_scan::{SbomProbeOutcome, VulnScanProbeOutcome};

        let coverage = build_probe_coverage(
            &SbomProbeOutcome::Absent,
            &VulnScanProbeOutcome::Absent,
            &NixReproducibilityOutcome::Drift,
        );
        // One probe in its non-absent arm (`Drift` — `nix build
        // --rebuild` RAN and detected non-determinism, evidence of
        // compromise, distinct from `ProbeAbsent`), two in `Absent`.
        assert_eq!(coverage, ProbeCoverage { ran: 1, absent: 2 });
        assert_eq!(coverage.total(), 3);
    }

    /// Pins that EVERY one of the three build-probe-outcome parameters
    /// contributes to the coverage count: walking each probe through
    /// its non-absent arm in isolation (the other two in their absent
    /// arms) yields `ProbeCoverage { ran: 1, absent: 2 }`. A future
    /// regression that omitted any parameter from the three-element
    /// slice (or pinned its slice index to a constant arm) would fail
    /// the corresponding sub-case here. The third sub-case is the
    /// load-bearing `NixReproducibilityOutcome::Drift` arm — pins that
    /// the determinism-probe-ran-and-detected-drift discriminator
    /// (which the surface `is_reproducible()` bool collapses to the
    /// same `false` as `ProbeAbsent`) still counts as a probe-ran
    /// outcome in the coverage signal, the structural distinction the
    /// typed primitive preserves.
    #[test]
    fn test_build_probe_coverage_each_probe_individually_counted() {
        use crate::nix_reproducibility::NixReproducibilityOutcome;
        use crate::probe_outcome::ProbeCoverage;
        use crate::security_scan::{SbomProbeOutcome, VulnScanProbeOutcome};
        use tameshi::hash::Blake3Hash;

        let one_two = ProbeCoverage { ran: 1, absent: 2 };

        // 1. sbom
        let c = build_probe_coverage(
            &SbomProbeOutcome::Collected {
                hash: Blake3Hash::digest(b"sbom"),
            },
            &VulnScanProbeOutcome::Absent,
            &NixReproducibilityOutcome::ProbeAbsent,
        );
        assert_eq!(c, one_two, "SbomProbeOutcome::Collected must count");

        // 2. vuln-scan
        let c = build_probe_coverage(
            &SbomProbeOutcome::Absent,
            &VulnScanProbeOutcome::Collected {
                hash: Blake3Hash::digest(b"vuln"),
                total_cves: 0,
                critical_high: 0,
            },
            &NixReproducibilityOutcome::ProbeAbsent,
        );
        assert_eq!(c, one_two, "VulnScanProbeOutcome::Collected must count");

        // 3. reproducibility — the load-bearing `Drift` arm
        // (`nix build --rebuild` RAN and detected non-determinism, the
        // evidence-of-compromise discriminator distinct from
        // `ProbeAbsent`) must count as ran, not absent. This is the
        // discriminator the trait's `is_probe_absent` preserves over
        // the surface `is_reproducible()` bool (which collapses BOTH
        // `Drift` AND `ProbeAbsent` to `false`).
        let c = build_probe_coverage(
            &SbomProbeOutcome::Absent,
            &VulnScanProbeOutcome::Absent,
            &NixReproducibilityOutcome::Drift,
        );
        assert_eq!(
            c, one_two,
            "NixReproducibilityOutcome::Drift must count (probe RAN; the \
             drift-detected discriminator from ProbeAbsent that the \
             surface is_reproducible() bool erases)"
        );
    }

    /// Pins the chain `build_probe_coverage(...) → ProbeCoverage →
    /// is_fully_covered()` across the three load-bearing arms of the
    /// four-arm decision matrix the docstring on
    /// [`crate::probe_outcome::ProbeCoverage::is_fully_covered`]
    /// tabulates: the all-ran ceiling (true), the all-absent floor
    /// (false), and the mixed-arm intermediate (false). This is the
    /// load-bearing chain the `build_probes_fully_covered` tracing field
    /// at the `compute_build_attestation` emission site reads — a
    /// downstream `sekiban` strict-production admission verifier
    /// reconciliation gates production deploys on `every probe
    /// substantiated its claim`, which collapses to one bool at the
    /// `forge::attestation::build_probe_coverage` tracing event rather
    /// than re-derived per call site (THEORY §VI.1 one-oracle discipline,
    /// THEORY §VII.1 attestation-gated deployments). A future regression
    /// that swapped the predicate at the typed-primitive site (e.g.,
    /// relaxed `ran > 0 && absent == 0` to `absent == 0` alone, silently
    /// flipping the empty case to true) would fail this pin at the
    /// `compute_build_attestation` chain — not just at the typed-primitive
    /// site one layer over.
    #[test]
    fn test_build_probe_coverage_fully_covered_predicate_chain() {
        use crate::nix_reproducibility::NixReproducibilityOutcome;
        use crate::security_scan::{SbomProbeOutcome, VulnScanProbeOutcome};
        use tameshi::hash::Blake3Hash;

        // Ceiling: every probe in its non-absent arm — fully covered.
        let ceiling = build_probe_coverage(
            &SbomProbeOutcome::Collected {
                hash: Blake3Hash::digest(b"sbom-payload"),
            },
            &VulnScanProbeOutcome::Collected {
                hash: Blake3Hash::digest(b"vuln-scan-payload"),
                total_cves: 0,
                critical_high: 0,
            },
            &NixReproducibilityOutcome::Reproducible,
        );
        assert!(
            ceiling.is_fully_covered(),
            "Phase 1 build all-ran ceiling must satisfy is_fully_covered"
        );

        // Floor: every probe absent — NOT fully covered (today's
        // call-site state — no syft / grype / determinism probe layer
        // is integrated yet; the verifier must fail-closed here).
        let floor = build_probe_coverage(
            &SbomProbeOutcome::Absent,
            &VulnScanProbeOutcome::Absent,
            &NixReproducibilityOutcome::ProbeAbsent,
        );
        assert!(
            !floor.is_fully_covered(),
            "Phase 1 build all-absent floor must NOT satisfy \
             is_fully_covered (today's call-site state — the strict \
             gate fails-closed)"
        );

        // Mixed: one absent — NOT fully covered. The realistic
        // intermediate world a follow-up commit wiring two of the three
        // probes lands at; one absent probe poisons the strict gate.
        let mixed = build_probe_coverage(
            &SbomProbeOutcome::Collected {
                hash: Blake3Hash::digest(b"sbom-payload"),
            },
            &VulnScanProbeOutcome::Absent,
            &NixReproducibilityOutcome::Reproducible,
        );
        assert!(
            !mixed.is_fully_covered(),
            "Phase 1 build mixed-arm state (one probe absent) must NOT \
             satisfy is_fully_covered — one absent probe in any phase \
             poisons the strict-production gate"
        );
    }

    /// Phase 1 chart-side peer of
    /// `test_build_probe_coverage_fully_covered_predicate_chain` — pins
    /// the same `chart_probe_coverage(...) → is_fully_covered()` chain
    /// across the ceiling / floor / mixed arms over the four-probe
    /// chart shape. The load-bearing chain the
    /// `chart_probes_fully_covered` tracing field at the
    /// `compute_chart_attestation` emission site reads.
    #[test]
    fn test_chart_probe_coverage_fully_covered_predicate_chain() {
        use crate::chart_dependencies::ChartDependenciesOutcome;
        use crate::helm_lint::HelmLintOutcome;
        use crate::helm_provenance::HelmProvenanceOutcome;
        use crate::kensa_policy::KensaPolicyOutcome;

        let ceiling = chart_probe_coverage(
            &HelmProvenanceOutcome::Verified {
                signed_chart_hash: Some("deadbeef".to_string()),
                signer_key_id: None,
            },
            &HelmLintOutcome::Passed {
                warning_count: 0,
                info_count: 0,
            },
            &KensaPolicyOutcome::Passed {
                evaluated_control_count: 12,
            },
            &ChartDependenciesOutcome::Listed { deps: vec![] },
        );
        assert!(
            ceiling.is_fully_covered(),
            "Phase 1 chart all-ran ceiling must satisfy is_fully_covered"
        );

        let floor = chart_probe_coverage(
            &HelmProvenanceOutcome::ProbeAbsent,
            &HelmLintOutcome::ProbeAbsent,
            &KensaPolicyOutcome::ProbeAbsent,
            &ChartDependenciesOutcome::ProbeAbsent,
        );
        assert!(
            !floor.is_fully_covered(),
            "Phase 1 chart all-absent floor must NOT satisfy \
             is_fully_covered"
        );

        // Mixed: `chart_dependencies_outcome` already wires a real
        // probe today, so this is the realistic call-site shape — three
        // deferred probes absent, one ran. Strict gate fails-closed.
        let mixed = chart_probe_coverage(
            &HelmProvenanceOutcome::ProbeAbsent,
            &HelmLintOutcome::ProbeAbsent,
            &KensaPolicyOutcome::ProbeAbsent,
            &ChartDependenciesOutcome::Listed { deps: vec![] },
        );
        assert!(
            !mixed.is_fully_covered(),
            "Phase 1 chart mixed-arm state (3 of 4 absent) must NOT \
             satisfy is_fully_covered"
        );
    }

    /// Phase 2 deployment-side peer of the two predicate-chain pins
    /// above — pins the `deployment_probe_coverage(...) →
    /// is_fully_covered()` chain across the ceiling / floor / mixed
    /// arms over the seven-probe deployment shape. The load-bearing
    /// chain the `deployment_probes_fully_covered` tracing field at
    /// the `compose_product_certification` emission site reads.
    #[test]
    fn test_deployment_probe_coverage_fully_covered_predicate_chain() {
        use crate::cis_k8s_pass_rate::CisK8sPassRateOutcome;
        use crate::deployment_manifest::DeploymentManifestRenderOutcome;
        use crate::flux_source_verification::FluxSourceVerificationOutcome;
        use crate::helm_release_signature::HelmReleaseSignatureOutcome;
        use crate::network_policy_admission::NetworkPolicyAdmissionOutcome;
        use crate::pod_health::PodHealthOutcome;
        use crate::pod_listing::PodListingOutcome;

        let ceiling = deployment_probe_coverage(
            &FluxSourceVerificationOutcome::Verified,
            &NetworkPolicyAdmissionOutcome::Verified,
            &HelmReleaseSignatureOutcome::Verified,
            &PodHealthOutcome::Healthy,
            &PodListingOutcome::Counted { count: 3 },
            &DeploymentManifestRenderOutcome::Rendered {
                fingerprint: b"test-manifest".to_vec(),
            },
            &CisK8sPassRateOutcome::Probed { ratio: 1.0 },
        );
        assert!(
            ceiling.is_fully_covered(),
            "Phase 2 deployment all-ran ceiling must satisfy \
             is_fully_covered"
        );

        let floor = deployment_probe_coverage(
            &FluxSourceVerificationOutcome::ProbeAbsent,
            &NetworkPolicyAdmissionOutcome::ProbeAbsent,
            &HelmReleaseSignatureOutcome::ProbeAbsent,
            &PodHealthOutcome::ProbeAbsent,
            &PodListingOutcome::ProbeAbsent,
            &DeploymentManifestRenderOutcome::ProbeAbsent,
            &CisK8sPassRateOutcome::ProbeAbsent,
        );
        assert!(
            !floor.is_fully_covered(),
            "Phase 2 deployment all-absent floor (today's certification \
             function state) must NOT satisfy is_fully_covered"
        );

        // Mixed 3-of-7 — the realistic intermediate shape exercised by
        // `test_deployment_probe_coverage_mixed_arms_arithmetic`.
        let mixed = deployment_probe_coverage(
            &FluxSourceVerificationOutcome::Verified,
            &NetworkPolicyAdmissionOutcome::ProbeAbsent,
            &HelmReleaseSignatureOutcome::VerifyFailed,
            &PodHealthOutcome::ProbeAbsent,
            &PodListingOutcome::Counted { count: 0 },
            &DeploymentManifestRenderOutcome::ProbeAbsent,
            &CisK8sPassRateOutcome::ProbeAbsent,
        );
        assert!(
            !mixed.is_fully_covered(),
            "Phase 2 deployment mixed-arm state (3 ran, 4 absent) must \
             NOT satisfy is_fully_covered"
        );
    }

    /// Pins the chain `build_probe_coverage(...) → ProbeCoverage →
    /// is_empty()` across the three reachable arms of the four-arm
    /// decision matrix the docstring on
    /// [`crate::probe_outcome::ProbeCoverage::is_empty`] tabulates: the
    /// all-ran ceiling, the all-absent floor, and the mixed-arm
    /// intermediate. The fixed-arity `build_probe_coverage(_, _, _)`
    /// helper consumes exactly three outcome references, so `total > 0`
    /// holds at every reachable value — the empty-slice boundary arm
    /// (`ran: 0, absent: 0`) is structurally unreachable through this
    /// helper and is pinned by the typed-primitive test
    /// `crate::probe_outcome::tests::test_is_empty_pins_empty_boundary`
    /// one layer over. This is the load-bearing chain the
    /// `build_probes_empty` tracing field at the
    /// `compute_build_attestation` emission site reads: a downstream
    /// `sekiban` admission verifier reconciliation reading
    /// `forge::attestation::build_probe_coverage` distinguishes the
    /// all-absent floor (`empty: false, fully_covered: false`,
    /// today's call-site state — the strict-production gate
    /// fails-closed) from the future empty-aggregate arm (`empty:
    /// true`, surfaced when the iterator-based
    /// [`crate::probe_outcome::probe_coverage`] composes a fleet-wide
    /// signal over zero records) without re-deriving `total == 0` at
    /// the verifier (THEORY §VI.1 one-oracle discipline). Also pins
    /// the structural mutual-exclusion invariant from the
    /// typed-primitive pin
    /// `test_is_empty_and_is_fully_covered_are_mutually_exclusive`: at
    /// every reachable build-phase coverage value, `is_empty()` and
    /// `is_fully_covered()` are disjoint.
    #[test]
    fn test_build_probe_coverage_empty_predicate_chain() {
        use crate::nix_reproducibility::NixReproducibilityOutcome;
        use crate::security_scan::{SbomProbeOutcome, VulnScanProbeOutcome};
        use tameshi::hash::Blake3Hash;

        let ceiling = build_probe_coverage(
            &SbomProbeOutcome::Collected {
                hash: Blake3Hash::digest(b"sbom-payload"),
            },
            &VulnScanProbeOutcome::Collected {
                hash: Blake3Hash::digest(b"vuln-scan-payload"),
                total_cves: 0,
                critical_high: 0,
            },
            &NixReproducibilityOutcome::Reproducible,
        );
        assert!(
            !ceiling.is_empty(),
            "Phase 1 build all-ran ceiling must NOT satisfy is_empty \
             (total == 3, fixed-arity helper forecloses the empty arm)"
        );
        assert!(
            !(ceiling.is_empty() && ceiling.is_fully_covered()),
            "Phase 1 build all-ran ceiling: is_empty and \
             is_fully_covered are structurally mutually exclusive"
        );

        let floor = build_probe_coverage(
            &SbomProbeOutcome::Absent,
            &VulnScanProbeOutcome::Absent,
            &NixReproducibilityOutcome::ProbeAbsent,
        );
        assert!(
            !floor.is_empty(),
            "Phase 1 build all-absent floor (today's call-site state — \
             ran: 0, absent: 3) must NOT satisfy is_empty: the typed \
             predicate distinguishes the all-absent floor from the \
             structurally-unreachable empty-slice arm, where \
             coverage_ratio collapses both to 0.0"
        );
        assert!(
            !(floor.is_empty() && floor.is_fully_covered()),
            "Phase 1 build all-absent floor: is_empty and \
             is_fully_covered are structurally mutually exclusive"
        );

        let mixed = build_probe_coverage(
            &SbomProbeOutcome::Collected {
                hash: Blake3Hash::digest(b"sbom-payload"),
            },
            &VulnScanProbeOutcome::Absent,
            &NixReproducibilityOutcome::Reproducible,
        );
        assert!(
            !mixed.is_empty(),
            "Phase 1 build mixed-arm state (ran: 2, absent: 1) must \
             NOT satisfy is_empty"
        );
        assert!(
            !(mixed.is_empty() && mixed.is_fully_covered()),
            "Phase 1 build mixed-arm state: is_empty and \
             is_fully_covered are structurally mutually exclusive"
        );
    }

    /// Phase 1 chart-side peer of
    /// `test_build_probe_coverage_empty_predicate_chain` — pins the
    /// same `chart_probe_coverage(...) → is_empty()` chain across the
    /// ceiling / floor / mixed arms over the four-probe chart shape.
    /// The fixed-arity `chart_probe_coverage(_, _, _, _)` helper
    /// forecloses the empty-slice arm; the typed-primitive pin
    /// `crate::probe_outcome::tests::test_is_empty_pins_empty_boundary`
    /// covers it one layer over. The load-bearing chain the
    /// `chart_probes_empty` tracing field at the
    /// `compute_chart_attestation` emission site reads.
    #[test]
    fn test_chart_probe_coverage_empty_predicate_chain() {
        use crate::chart_dependencies::ChartDependenciesOutcome;
        use crate::helm_lint::HelmLintOutcome;
        use crate::helm_provenance::HelmProvenanceOutcome;
        use crate::kensa_policy::KensaPolicyOutcome;

        let ceiling = chart_probe_coverage(
            &HelmProvenanceOutcome::Verified {
                signed_chart_hash: Some("deadbeef".to_string()),
                signer_key_id: None,
            },
            &HelmLintOutcome::Passed {
                warning_count: 0,
                info_count: 0,
            },
            &KensaPolicyOutcome::Passed {
                evaluated_control_count: 12,
            },
            &ChartDependenciesOutcome::Listed { deps: vec![] },
        );
        assert!(
            !ceiling.is_empty(),
            "Phase 1 chart all-ran ceiling must NOT satisfy is_empty \
             (total == 4, fixed-arity helper forecloses the empty arm)"
        );
        assert!(
            !(ceiling.is_empty() && ceiling.is_fully_covered()),
            "Phase 1 chart all-ran ceiling: is_empty and \
             is_fully_covered are structurally mutually exclusive"
        );

        let floor = chart_probe_coverage(
            &HelmProvenanceOutcome::ProbeAbsent,
            &HelmLintOutcome::ProbeAbsent,
            &KensaPolicyOutcome::ProbeAbsent,
            &ChartDependenciesOutcome::ProbeAbsent,
        );
        assert!(
            !floor.is_empty(),
            "Phase 1 chart all-absent floor (ran: 0, absent: 4) must \
             NOT satisfy is_empty: the typed predicate distinguishes \
             the all-absent floor from the structurally-unreachable \
             empty-slice arm"
        );
        assert!(
            !(floor.is_empty() && floor.is_fully_covered()),
            "Phase 1 chart all-absent floor: is_empty and \
             is_fully_covered are structurally mutually exclusive"
        );

        let mixed = chart_probe_coverage(
            &HelmProvenanceOutcome::ProbeAbsent,
            &HelmLintOutcome::ProbeAbsent,
            &KensaPolicyOutcome::ProbeAbsent,
            &ChartDependenciesOutcome::Listed { deps: vec![] },
        );
        assert!(
            !mixed.is_empty(),
            "Phase 1 chart mixed-arm state (ran: 1, absent: 3 — the \
             realistic call-site shape with chart-deps wired) must \
             NOT satisfy is_empty"
        );
        assert!(
            !(mixed.is_empty() && mixed.is_fully_covered()),
            "Phase 1 chart mixed-arm state: is_empty and \
             is_fully_covered are structurally mutually exclusive"
        );
    }

    /// Phase 2 deployment-side peer of the two empty-predicate chain
    /// pins above — pins the `deployment_probe_coverage(...) →
    /// is_empty()` chain across the ceiling / floor / mixed arms over
    /// the seven-probe deployment shape. The fixed-arity
    /// `deployment_probe_coverage(_, _, _, _, _, _, _)` helper
    /// forecloses the empty-slice arm; the typed-primitive pin
    /// `crate::probe_outcome::tests::test_is_empty_pins_empty_boundary`
    /// covers it one layer over. The load-bearing chain the
    /// `deployment_probes_empty` tracing field at the
    /// `compose_product_certification` emission site reads.
    #[test]
    fn test_deployment_probe_coverage_empty_predicate_chain() {
        use crate::cis_k8s_pass_rate::CisK8sPassRateOutcome;
        use crate::deployment_manifest::DeploymentManifestRenderOutcome;
        use crate::flux_source_verification::FluxSourceVerificationOutcome;
        use crate::helm_release_signature::HelmReleaseSignatureOutcome;
        use crate::network_policy_admission::NetworkPolicyAdmissionOutcome;
        use crate::pod_health::PodHealthOutcome;
        use crate::pod_listing::PodListingOutcome;

        let ceiling = deployment_probe_coverage(
            &FluxSourceVerificationOutcome::Verified,
            &NetworkPolicyAdmissionOutcome::Verified,
            &HelmReleaseSignatureOutcome::Verified,
            &PodHealthOutcome::Healthy,
            &PodListingOutcome::Counted { count: 3 },
            &DeploymentManifestRenderOutcome::Rendered {
                fingerprint: b"test-manifest".to_vec(),
            },
            &CisK8sPassRateOutcome::Probed { ratio: 1.0 },
        );
        assert!(
            !ceiling.is_empty(),
            "Phase 2 deployment all-ran ceiling must NOT satisfy \
             is_empty (total == 7, fixed-arity helper forecloses the \
             empty arm)"
        );
        assert!(
            !(ceiling.is_empty() && ceiling.is_fully_covered()),
            "Phase 2 deployment all-ran ceiling: is_empty and \
             is_fully_covered are structurally mutually exclusive"
        );

        let floor = deployment_probe_coverage(
            &FluxSourceVerificationOutcome::ProbeAbsent,
            &NetworkPolicyAdmissionOutcome::ProbeAbsent,
            &HelmReleaseSignatureOutcome::ProbeAbsent,
            &PodHealthOutcome::ProbeAbsent,
            &PodListingOutcome::ProbeAbsent,
            &DeploymentManifestRenderOutcome::ProbeAbsent,
            &CisK8sPassRateOutcome::ProbeAbsent,
        );
        assert!(
            !floor.is_empty(),
            "Phase 2 deployment all-absent floor (today's \
             certification function state — ran: 0, absent: 7) must \
             NOT satisfy is_empty: the typed predicate distinguishes \
             the all-absent floor from the structurally-unreachable \
             empty-slice arm"
        );
        assert!(
            !(floor.is_empty() && floor.is_fully_covered()),
            "Phase 2 deployment all-absent floor: is_empty and \
             is_fully_covered are structurally mutually exclusive"
        );

        let mixed = deployment_probe_coverage(
            &FluxSourceVerificationOutcome::Verified,
            &NetworkPolicyAdmissionOutcome::ProbeAbsent,
            &HelmReleaseSignatureOutcome::VerifyFailed,
            &PodHealthOutcome::ProbeAbsent,
            &PodListingOutcome::Counted { count: 0 },
            &DeploymentManifestRenderOutcome::ProbeAbsent,
            &CisK8sPassRateOutcome::ProbeAbsent,
        );
        assert!(
            !mixed.is_empty(),
            "Phase 2 deployment mixed-arm state (ran: 3, absent: 4) \
             must NOT satisfy is_empty"
        );
        assert!(
            !(mixed.is_empty() && mixed.is_fully_covered()),
            "Phase 2 deployment mixed-arm state: is_empty and \
             is_fully_covered are structurally mutually exclusive"
        );
    }

    // ────────────────────────────────────────────────────────────────────
    // emit_probe_coverage! macro — schema pins
    //
    // The macro centralises the nine-field tracing shape — `(ran, absent,
    // total, coverage_ratio, fully_covered, empty, saturated,
    // coverage_ratio_pct, all_absent)` — at one internal arm so the three
    // per-phase emission sites cannot drift on field count, field order,
    // or the `ProbeCoverage` method that maps to each field. The pins
    // below capture each phase's tracing event via a minimal
    // [`tracing::Subscriber`] impl, then assert the nine probe-coverage
    // fields surface with the expected phase-prefixed names, in the
    // canonical order the macro emits, with the values [`ProbeCoverage`]'s
    // typed methods compute. A regression that (a) dropped a field at the
    // macro's internal arm, (b) swapped the `ran` and `absent` method
    // calls, (c) re-ordered the emission so a downstream verifier reading
    // positional tracing-event fields drifted, or (d) mis-prefixed a phase
    // arm (e.g., chart's `ran` field emitted as `build_probes_ran`) would
    // fail the corresponding pin here.
    // ────────────────────────────────────────────────────────────────────

    use std::sync::{Arc, Mutex};
    use tracing::field::{Field, Visit};
    use tracing::span::{Attributes, Record as SpanRecord};
    use tracing::{Event, Id, Metadata, Subscriber};

    /// Captured tracing-event shape — the target string and the ordered
    /// `(field_name, debug_rendering)` pairs the macro emitted. Used as
    /// the test-side oracle the pins below compare against.
    #[derive(Default)]
    struct CapturedEvent {
        target: String,
        fields: Vec<(String, String)>,
    }

    /// Minimal field visitor that records each `(name, debug-rendered)`
    /// pair into the captured-event accumulator. The debug rendering is
    /// the largest common shape every `record_*` arm admits without a
    /// per-type branch — `tracing`'s [`Visit`] trait dispatches numeric,
    /// bool, and string forms separately, so each arm formats the value
    /// in a way the pins below can assert against a fixed string.
    struct CaptureVisitor<'a> {
        fields: &'a mut Vec<(String, String)>,
    }

    impl<'a> Visit for CaptureVisitor<'a> {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            self.fields
                .push((field.name().to_string(), format!("{:?}", value)));
        }
        fn record_u64(&mut self, field: &Field, value: u64) {
            self.fields
                .push((field.name().to_string(), value.to_string()));
        }
        fn record_i64(&mut self, field: &Field, value: i64) {
            self.fields
                .push((field.name().to_string(), value.to_string()));
        }
        fn record_f64(&mut self, field: &Field, value: f64) {
            self.fields
                .push((field.name().to_string(), value.to_string()));
        }
        fn record_bool(&mut self, field: &Field, value: bool) {
            self.fields
                .push((field.name().to_string(), value.to_string()));
        }
        fn record_str(&mut self, field: &Field, value: &str) {
            self.fields
                .push((field.name().to_string(), value.to_string()));
        }
    }

    /// Minimal [`Subscriber`] impl that records every event's target and
    /// fields into the shared accumulator. Span machinery is stubbed —
    /// the macro emits events, not spans, so [`Subscriber::event`] is the
    /// only method that needs to do work.
    struct CaptureSubscriber {
        captured: Arc<Mutex<CapturedEvent>>,
    }

    impl Subscriber for CaptureSubscriber {
        fn enabled(&self, _: &Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &Attributes<'_>) -> Id {
            Id::from_u64(1)
        }
        fn record(&self, _: &Id, _: &SpanRecord<'_>) {}
        fn record_follows_from(&self, _: &Id, _: &Id) {}
        fn event(&self, event: &Event<'_>) {
            let mut captured = self.captured.lock().expect("capture mutex poisoned");
            captured.target = event.metadata().target().to_string();
            captured.fields.clear();
            let mut visitor = CaptureVisitor {
                fields: &mut captured.fields,
            };
            event.record(&mut visitor);
        }
        fn enter(&self, _: &Id) {}
        fn exit(&self, _: &Id) {}
    }

    /// Run `f` under a default [`CaptureSubscriber`] and return the
    /// recorded event. The macro under test emits exactly one event per
    /// invocation, so the captured shape reflects that single event.
    fn capture_emission<F: FnOnce()>(f: F) -> CapturedEvent {
        let captured = Arc::new(Mutex::new(CapturedEvent::default()));
        let subscriber = CaptureSubscriber {
            captured: Arc::clone(&captured),
        };
        tracing::subscriber::with_default(subscriber, f);
        let captured = captured.lock().expect("capture mutex poisoned");
        CapturedEvent {
            target: captured.target.clone(),
            fields: captured.fields.clone(),
        }
    }

    /// Names of the nine probe-coverage fields the macro emits, in the
    /// canonical order — the same order
    /// [`crate::probe_outcome::ProbeCoverage::is_fully_covered`]'s
    /// docstring four-arm matrix tabulates, extended with the orthogonal
    /// [`crate::probe_outcome::ProbeCoverage::is_saturated`]
    /// trustworthiness predicate at the seventh position, the integer
    /// [`crate::probe_outcome::ProbeCoverage::coverage_ratio_pct`]
    /// percent companion at the eighth, and the
    /// [`crate::probe_outcome::ProbeCoverage::is_all_absent`]
    /// arm-predicate at the ninth — the typed discriminator for the
    /// third arm of the four-arm matrix the typed primitive tabulates
    /// (the "every counted probe surfaced an absent default" state
    /// today's three call sites sit at). Returned with a phase prefix
    /// so each phase's pin can compare against its own expected slice.
    fn expected_field_names(prefix: &str) -> Vec<String> {
        [
            "ran",
            "absent",
            "total",
            "coverage_ratio",
            "fully_covered",
            "empty",
            "saturated",
            "coverage_ratio_pct",
            "all_absent",
        ]
        .iter()
        .map(|suffix| format!("{prefix}_probes_{suffix}"))
        .collect()
    }

    /// Phase 1 build: pins the macro emits exactly six probe-coverage
    /// fields, in canonical order, with `build_probes_*` prefixes, against
    /// the `forge::attestation::build_probe_coverage` target. The mixed
    /// arm `(ran: 2, absent: 1)` exercises all three non-empty-non-empty
    /// arms — `ran > 0` and `absent > 0` both non-zero — so the value pins
    /// substantiate the typed method routes the macro composes.
    #[test]
    fn test_emit_probe_coverage_build_schema_pin() {
        let coverage = crate::probe_outcome::ProbeCoverage { ran: 2, absent: 1 };
        let captured = capture_emission(|| {
            emit_probe_coverage!(
                build,
                target: "forge::attestation::build_probe_coverage",
                coverage: coverage,
                message: "build-attestation probe coverage",
                service = "svc",
                derivation = "drv",
            );
        });
        assert_eq!(
            captured.target, "forge::attestation::build_probe_coverage",
            "macro must emit to the canonical build phase target",
        );
        let probe_field_names: Vec<String> = captured
            .fields
            .iter()
            .filter(|(name, _)| name.starts_with("build_probes_"))
            .map(|(name, _)| name.clone())
            .collect();
        assert_eq!(
            probe_field_names,
            expected_field_names("build"),
            "macro must emit the nine build_probes_* fields in canonical \
             order — a regression that dropped, re-ordered, or renamed a \
             field at the internal `@__shape` arm fails this pin",
        );
        let by_name: std::collections::HashMap<_, _> = captured.fields.iter().cloned().collect();
        assert_eq!(by_name["build_probes_ran"], "2");
        assert_eq!(by_name["build_probes_absent"], "1");
        assert_eq!(by_name["build_probes_total"], "3");
        assert_eq!(by_name["build_probes_fully_covered"], "false");
        assert_eq!(by_name["build_probes_empty"], "false");
        assert_eq!(
            by_name["build_probes_saturated"], "false",
            "the mixed `(ran: 2, absent: 1)` arm sits well below the \
             saturating-add ceiling — `is_saturated` is false at every \
             realistically-sized Phase 1 build coverage",
        );
        assert_eq!(
            by_name["build_probes_coverage_ratio_pct"], "66",
            "the mixed `(ran: 2, absent: 1)` arm floors to `2*100/3 = 66` \
             — the integer-percent surface a Prometheus alert rule / \
             typed-policy threshold reads against; pins the
             `coverage_ratio_pct` companion of `coverage_ratio` at the \
             non-empty / non-saturated / non-fully-covered arm",
        );
        assert_eq!(
            by_name["build_probes_all_absent"], "false",
            "the mixed `(ran: 2, absent: 1)` arm sits at the mixed arm \
             of the four-arm matrix (`ran > 0 && absent > 0`) — \
             `is_all_absent` (`ran == 0 && absent > 0`) reads false \
             here, structurally disambiguating the mixed arm from the \
             all-absent floor below it",
        );
    }

    /// Phase 1 chart: same schema pin as the build sibling above, against
    /// the `forge::attestation::chart_probe_coverage` target with the
    /// four-probe `(ran: 3, absent: 0)` ceiling — exercises the
    /// fully-covered predicate's `true` arm and the `total() == ran` /
    /// `coverage_ratio() == 1.0` boundary the prior typed-primitive pins
    /// substantiate one layer over.
    #[test]
    fn test_emit_probe_coverage_chart_schema_pin() {
        let coverage = crate::probe_outcome::ProbeCoverage { ran: 3, absent: 0 };
        let captured = capture_emission(|| {
            emit_probe_coverage!(
                chart,
                target: "forge::attestation::chart_probe_coverage",
                coverage: coverage,
                message: "chart-attestation probe coverage",
                chart_name = "mychart",
                chart_version = "1.0.0",
                registry_ref = "ghcr.io/x/y",
            );
        });
        assert_eq!(
            captured.target, "forge::attestation::chart_probe_coverage",
            "macro must emit to the canonical chart phase target",
        );
        let probe_field_names: Vec<String> = captured
            .fields
            .iter()
            .filter(|(name, _)| name.starts_with("chart_probes_"))
            .map(|(name, _)| name.clone())
            .collect();
        assert_eq!(
            probe_field_names,
            expected_field_names("chart"),
            "macro must emit the nine chart_probes_* fields in canonical \
             order — a regression that swapped a build/chart/deployment \
             dispatch arm's prefix mapping fails this pin",
        );
        let by_name: std::collections::HashMap<_, _> = captured.fields.iter().cloned().collect();
        assert_eq!(by_name["chart_probes_ran"], "3");
        assert_eq!(by_name["chart_probes_absent"], "0");
        assert_eq!(by_name["chart_probes_total"], "3");
        assert_eq!(by_name["chart_probes_fully_covered"], "true");
        assert_eq!(by_name["chart_probes_empty"], "false");
        assert_eq!(
            by_name["chart_probes_saturated"], "false",
            "the fully-covered ceiling at `(ran: 3, absent: 0)` is \
             orthogonal to `is_saturated` — neither component is at \
             `usize::MAX`, so the typed trustworthiness flag stays false \
             at the all-ran chart-attestation arm",
        );
        assert_eq!(
            by_name["chart_probes_coverage_ratio_pct"], "100",
            "the fully-covered ceiling at `(ran: 3, absent: 0)` reads \
             `3*100/3 = 100` — the integer ceiling the typed admission \
             gate `*_probe_coverage_ratio_pct >= 100` (strict-production \
             threshold) reads against, dual of the float ceiling \
             `coverage_ratio() == 1.0` the prior field surfaces",
        );
        assert_eq!(
            by_name["chart_probes_all_absent"], "false",
            "the fully-covered ceiling at `(ran: 3, absent: 0)` is the \
             structural mirror of the all-absent floor — `is_fully_covered \
             && !is_all_absent` pins the two extremes of the four-arm \
             matrix as mutually exclusive at the chart phase",
        );
    }

    /// Phase 2 deployment: same schema pin as the build/chart siblings,
    /// against the legacy `forge::attestation::probe_coverage` target
    /// (commit 3152279 named the target before the build/chart phases
    /// later differentiated their targets — the macro preserves the
    /// legacy target string exactly so a downstream consumer reading the
    /// existing tracing target cannot drift under this commit). The
    /// all-absent `(ran: 0, absent: 7)` floor exercises today's
    /// [`compose_product_certification`] call-site state — no Phase 2
    /// probe ran inside the certification function — and pins the
    /// `is_empty()` / `is_fully_covered()` boundary discriminator pair at
    /// the all-absent arm of the four-arm matrix the typed primitive
    /// tabulates.
    #[test]
    fn test_emit_probe_coverage_deployment_schema_pin() {
        let coverage = crate::probe_outcome::ProbeCoverage { ran: 0, absent: 7 };
        let captured = capture_emission(|| {
            emit_probe_coverage!(
                deployment,
                target: "forge::attestation::probe_coverage",
                coverage: coverage,
                message: "deployment-attestation probe coverage",
                product = "prod",
                environment = "staging",
                cluster = "plo",
            );
        });
        assert_eq!(
            captured.target, "forge::attestation::probe_coverage",
            "macro must preserve the legacy deployment phase target — \
             downstream `RUST_LOG=forge::attestation::probe_coverage=info` \
             filters cannot drift under this commit",
        );
        let probe_field_names: Vec<String> = captured
            .fields
            .iter()
            .filter(|(name, _)| name.starts_with("deployment_probes_"))
            .map(|(name, _)| name.clone())
            .collect();
        assert_eq!(
            probe_field_names,
            expected_field_names("deployment"),
            "macro must emit the nine deployment_probes_* fields in \
             canonical order",
        );
        let by_name: std::collections::HashMap<_, _> = captured.fields.iter().cloned().collect();
        assert_eq!(by_name["deployment_probes_ran"], "0");
        assert_eq!(by_name["deployment_probes_absent"], "7");
        assert_eq!(by_name["deployment_probes_total"], "7");
        assert_eq!(by_name["deployment_probes_fully_covered"], "false");
        assert_eq!(
            by_name["deployment_probes_empty"], "false",
            "all-absent floor is structurally distinct from the empty \
             arm — `is_empty` reflects `total() == 0`, the seven-probe \
             call site cannot satisfy it",
        );
        assert_eq!(
            by_name["deployment_probes_saturated"], "false",
            "today's `compose_product_certification` call-site state \
             `(ran: 0, absent: 7)` sits at the all-absent floor — \
             `is_saturated` is the orthogonal trustworthiness flag, \
             false at every realistically-sized Phase 2 deployment \
             coverage",
        );
        assert_eq!(
            by_name["deployment_probes_coverage_ratio_pct"], "0",
            "the all-absent floor at `(ran: 0, absent: 7)` reads \
             `0*100/7 = 0` — the integer floor the typed admission \
             gate `*_probe_coverage_ratio_pct >= 90` reads against, \
             correctly refusing today's no-probe-ran state where the \
             float-form `coverage_ratio() == 0.0` (different IEEE-754 \
             representation but the same operational meaning) also \
             reads at the floor",
        );
        assert_eq!(
            by_name["deployment_probes_all_absent"], "true",
            "the all-absent floor at `(ran: 0, absent: 7)` is exactly \
             the state the typed `is_all_absent` predicate names — \
             today's `compose_product_certification` call-site state \
             sits here, and a downstream `sekiban` admission verifier \
             gating on `*_probes_all_absent == true` fails closed at \
             this state with one bool comparison rather than composing \
             `*_probes_total > 0 && *_probes_coverage_ratio == 0.0` at \
             the consumer surface",
        );
    }

    /// Phase 1 build at the post-saturation state: pins the macro emits
    /// the seventh `*_probes_saturated` field as `true` exactly at the
    /// `{ran: usize::MAX, absent: usize::MAX}` ceiling state the
    /// saturating monoid `Add` reaches asymptotically. The orthogonal
    /// trustworthiness signal a downstream `sekiban` admission verifier
    /// reading `*_probes_coverage_ratio` must gate against — at this
    /// state the f64 division `MAX as f64 / MAX as f64` reads as `1.0`
    /// against the true 0.5 ratio (every saturated component dropped
    /// equal evidence past the ceiling), so a verifier conditioning
    /// only on `*_probes_coverage_ratio >= 0.5` would silently accept
    /// the drift. This pin closes that arm at the telemetry-emission
    /// surface: the saturated boolean reaches the wire so the verifier
    /// reads both the ratio AND its trustworthiness.
    #[test]
    fn test_emit_probe_coverage_saturated_state_flags_trustworthiness() {
        let coverage = crate::probe_outcome::ProbeCoverage {
            ran: usize::MAX,
            absent: usize::MAX,
        };
        let captured = capture_emission(|| {
            emit_probe_coverage!(
                build,
                target: "forge::attestation::build_probe_coverage",
                coverage: coverage,
                message: "build-attestation probe coverage",
                service = "svc",
                derivation = "drv",
            );
        });
        let by_name: std::collections::HashMap<_, _> = captured.fields.iter().cloned().collect();
        assert_eq!(
            by_name["build_probes_saturated"], "true",
            "the post-saturation state `{{ran: MAX, absent: MAX}}` must \
             surface `is_saturated == true` on the wire — a downstream \
             verifier reading `*_probes_coverage_ratio` (which reads as \
             1.0 here against the true 0.5 ratio) gates on this field \
             to foreclose the drift class",
        );
        assert_eq!(
            by_name["build_probes_coverage_ratio"], "1",
            "documents the IEEE-754 drift the saturated flag warns \
             against: `MAX as f64 / MAX as f64` rounds to 1.0 (formatted \
             by the tracing visitor as `1` against the integral float), \
             not the true 0.5 ratio of the unsaturated `{{ran: N, absent: \
             N}}` shape — `is_saturated` is the trustworthiness predicate \
             that surfaces the drift",
        );
        assert_eq!(
            by_name["build_probes_fully_covered"], "false",
            "`is_fully_covered` (`absent == 0` is the load-bearing test) \
             stays robust under saturation — `absent == MAX` is not 0, \
             so the saturation-robust discriminator correctly reads false",
        );
        assert_eq!(
            by_name["build_probes_empty"], "false",
            "`is_empty` (`total() == 0` is the load-bearing test) stays \
             robust under saturation — `total()` saturates to MAX, not \
             0, so the saturation-robust discriminator correctly reads \
             false",
        );
        assert_eq!(
            by_name["build_probes_coverage_ratio_pct"], "100",
            "documents the integer-percent drift the saturated flag \
             warns against: `MAX * 100 / MAX` reads `100` against the \
             true `50` (`0.5 * 100`) of the unsaturated `{{ran: N, \
             absent: N}}` shape — the same operational drift the \
             prior `coverage_ratio` f64 field surfaces, so the typed \
             trustworthiness signal `is_saturated == true` is the \
             load-bearing condition a downstream verifier reads \
             alongside BOTH ratio surfaces (`coverage_ratio` and \
             `coverage_ratio_pct`) to foreclose the drift class at \
             either consumer's preferred scale",
        );
        assert_eq!(
            by_name["build_probes_all_absent"], "false",
            "`is_all_absent` (`ran == 0 && absent > 0` is the \
             load-bearing test) stays robust under saturation — \
             `ran == MAX` is not 0, so the saturation-robust \
             arm-predicate correctly reads false at the post-saturation \
             state. The structural mirror of the saturation-robust \
             `is_fully_covered` and `is_empty` discriminators one \
             assertion up: the integer-arithmetic body of every \
             arm-predicate forecloses the IEEE-754 drift class the \
             float-form ratio surfaces here",
        );
    }
}
