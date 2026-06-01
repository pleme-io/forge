//! Typed Nix-build determinism probe outcome for forge's Phase 1
//! build attestation — the build-side peer of [`crate::cosign`]
//! (image-signature probe), [`crate::helm_provenance`] (chart-signature
//! probe), [`crate::helm_lint`] (chart-quality probe),
//! [`crate::kensa_policy`] (chart-policy probe), [`crate::git_signature`]
//! (source-commit-signature probe), [`crate::oci_architecture`]
//! (image-architecture probe), [`crate::oci_manifest`] (manifest-identity
//! oracle), [`crate::openpgp_signature`] (OpenPGP v4 signature packet
//! parser), [`crate::security_scan`] (SBOM / vuln-scan probes), and
//! [`crate::flux_source_verification`] (FluxCD source-verification
//! probe).
//!
//! ## What this module closes
//!
//! `commands/attestation.rs::compute_build_attestation` previously
//! stamped a bare `let reproducible = false;` literal into every
//! Phase 1 `BuildAttestation` it composed:
//!
//! ```ignore
//! // Reproducibility is not independently re-verified yet; until it is,
//! // the build cannot honestly claim the reproducible-grade SLSA level.
//! // The level is derived from the evidence actually collected, so a
//! // build whose closure could not be materialized claims nothing.
//! let reproducible = false;
//! let slsa_level = build_slsa_level(&derivation, &closure_info, reproducible);
//! ```
//!
//! The bool surface is honest at the SLSA-level layer (a Phase 1 build
//! whose determinism was never independently re-verified caps at L2
//! under [`build_slsa_level`], never the reproducible L3 grade), but
//! the bool flattens three structurally distinct operational worlds a
//! downstream verifier reading `reproducible: false` from a
//! `BuildAttestation` cannot recover from the bool alone:
//!
//! 1. **Probe absent** — `compute_build_attestation` did not spawn a
//!    determinism probe at all (no `nix build --rebuild`, no
//!    `nix-build --check`, no two-pass byte-comparison). No probe
//!    ran. There is no evidence either way. This is the current
//!    state of the call site.
//! 2. **Drift** — a re-build probe ran but produced bytes that
//!    differed from the original derivation's output. Evidence of
//!    non-determinism: some non-hermetic input drove the build, or
//!    the build graph reads volatile state (current time, network,
//!    `$PWD`, system entropy). The Phase 1 build attestation must
//!    not claim reproducible here.
//! 3. **Reproducible** — a re-build probe ran and produced
//!    byte-identical output (matching narHash, matching closure
//!    fingerprint). The Phase 1 build attestation can honestly claim
//!    `reproducible: true` and earn the SLSA L3 grade under
//!    [`build_slsa_level`] only in this arm.
//!
//! [`build_slsa_level`]: crate::commands::attestation
//!
//! A Phase 1 build attestation that records `reproducible: false`
//! against a build whose determinism was never independently
//! re-verified (the current call site) is structurally
//! indistinguishable from a build whose `nix build --rebuild` produced
//! drift — yet the two carry opposite evidence semantics. The first is
//! "no probe ran, no claim either way"; the second is "probe ran and
//! detected evidence of non-determinism". A downstream verifier that
//! fails-closed on evidence of compromise (the drift world) cannot
//! distinguish it from the no-evidence-collected world under the bare
//! bool.
//!
//! This is the same false-by-construction shape commit 5931e32 closed
//! for `source_verified` (`true` literal →
//! [`crate::flux_source_verification::FluxSourceVerificationOutcome`]),
//! commit a5376a6 closed for `commit_signed` (`.unwrap_or(false)`
//! collapse → [`crate::git_signature::GitCommitSignatureOutcome`]),
//! commit c1e83d5 closed for `policy_passed` (`true` →
//! [`crate::kensa_policy::KensaPolicyOutcome`]), commit d81f639 closed
//! for `linter_passed` (`true` → [`crate::helm_lint::HelmLintOutcome`]),
//! commit 2f3a7dc closed for `signer_key_id` (`None` →
//! [`crate::openpgp_signature::SignaturePacketOutcome`]), commit
//! b98eb5a closed for the SBOM / vuln-scan hashes (name-keyed constants
//! → [`crate::security_scan::SbomProbeOutcome`] /
//! [`crate::security_scan::VulnScanProbeOutcome`]), commit fffca30
//! closed for the image `architecture` field (`"amd64"` literal →
//! [`crate::oci_architecture::OciArchitectureOutcome`]), commit b8a1d8a
//! closed for the chart `provenance_verified` bool (`false` hardcode →
//! [`crate::helm_provenance::HelmProvenanceOutcome`]), and commit
//! 0ff67e1 closed for the image `cosign_verified` bool (`is_ok()` fold
//! → [`crate::cosign::CosignVerifyOutcome`]).
//!
//! ## Why three arms, not two or four
//!
//! - **Three rather than two** (`Reproducible` / `ProbeAbsent`): a
//!   determinism probe that ran AND detected output drift is a
//!   structurally distinct world from both `Reproducible` AND
//!   `ProbeAbsent`. Collapsing `Drift` into a single boolean
//!   re-introduces the discriminator loss the typed primitive exists
//!   to prevent (THEORY §V.1: make invalid states unrepresentable —
//!   a `reproducible: false` value that conflates "no re-build
//!   probe ran" with "re-build ran and bytes differed" is a flat
//!   state where a downstream verifier cannot recover the
//!   kind-of-claim, and the second case is evidence of compromise
//!   the first case is not).
//! - **Three rather than four** (no `Malformed` arm yet): this
//!   commit introduces the typed primitive but does NOT introduce a
//!   parser for `nix build --rebuild` output grammar — no
//!   `parse_rebuild_output` function exists here. The `Malformed`
//!   arm in [`crate::helm_lint::HelmLintOutcome::Malformed`] is
//!   paired with [`crate::helm_lint::parse_lint_output`] over Helm's
//!   canonical summary-line grammar. The actual `nix build --rebuild`
//!   determinism probe surfaces evidence as the exit code plus a
//!   `--check` stderr message naming the drifted output path, not a
//!   parseable summary-line grammar; when a follow-up commit wires
//!   the shell-out at the `compute_build_attestation` call site, a
//!   non-zero exit with `error: derivation '...' may not be
//!   deterministic` will fold into `Drift`, a zero exit will fold
//!   into `Reproducible`, and a probe-spawn / network / I/O failure
//!   will fold into `ProbeAbsent`. Same deferral discipline as
//!   [`crate::kensa_policy::KensaPolicyOutcome`] and
//!   [`crate::flux_source_verification::FluxSourceVerificationOutcome`]
//!   at the chart-policy and source-verification layers.
//!
//! ## What this commit does NOT do
//!
//! This commit introduces the typed primitive and routes the call
//! site through the `ProbeAbsent` arm: `compute_build_attestation`
//! does not yet spawn a `nix build --rebuild` (or `nix-build
//! --check`) probe itself. The Phase 1 build attestation still
//! records `reproducible: false` — the bool-surface semantics of the
//! pre-fix literal are preserved exactly via `is_reproducible()` —
//! and the `build_slsa_level` rubric still caps the SLSA level at
//! L2 for substantiated builds without a determinism probe. The
//! `Reproducible` / `Drift` arms are the future enrichment point: a
//! follow-up commit that wires `tokio::process::Command::new("nix")
//! .args(["build", "--rebuild", &attr]).output().await` at the call
//! site and walks the resulting exit-code / stderr will flip the
//! outcome to `Reproducible` for builds whose re-derivation produces
//! byte-identical output and to `Drift` for builds whose re-derivation
//! detects non-determinism. Same deferral shape as commit 5931e32's
//! `FluxSourceVerificationOutcome::ProbeAbsent` at the
//! source-verification layer.
//!
//! ## Frontier inspiration
//!
//! Nix's `--check` / `--rebuild` flag is the canonical hermetic-build
//! determinism probe in the content-addressed build lineage (cited by
//! THEORY §VI.1: "regenerating an artifact produces a byte-identical
//! result given the same inputs"). SLSA v1.0 §"Build L3" and the
//! reproducible-builds.org methodology both treat the two-pass
//! byte-comparison verdict as the evidence-bearing channel for the
//! reproducible-grade build claim — never as a constant asserted by
//! the publisher. Bazel's `--experimental_remote_execution` and
//! Buck2's `--check-determinism` carry the same probe shape one
//! ecosystem over. A Phase 1 build attestation that records
//! `reproducible: true` against a build whose re-derivation was never
//! attempted fails every reconciliation a `nix-build --check` /
//! `bazel build --experimental_remote_execution` / `buck2 build
//! --check-determinism` pass could surface against the same build
//! graph. The typed `ProbeAbsent` arm names that gap honestly rather
//! than inflating it with a constant — the same discipline
//! [`crate::cosign::CosignVerifyOutcome::ProbeAbsent`],
//! [`crate::helm_provenance::HelmProvenanceOutcome::ProbeAbsent`],
//! [`crate::helm_lint::HelmLintOutcome::ProbeAbsent`],
//! [`crate::kensa_policy::KensaPolicyOutcome::ProbeAbsent`],
//! [`crate::git_signature::GitCommitSignatureOutcome::ProbeAbsent`],
//! [`crate::security_scan::SbomProbeOutcome::Absent`],
//! [`crate::security_scan::VulnScanProbeOutcome::Absent`], and
//! [`crate::flux_source_verification::FluxSourceVerificationOutcome::
//! ProbeAbsent`] apply at the image-signature, chart-signature,
//! chart-quality, chart-policy, source-commit-signature, SBOM,
//! vuln-scan, and source-verification layers.

/// Outcome of probing a Nix build for determinism. The three arms
/// preserve the probe-absent vs drift-detected vs reproducible
/// distinction the Phase 1 build attestation depends on; the prior
/// bare `let reproducible = false;` literal conflated all three
/// worlds into a single negative bool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NixReproducibilityOutcome {
    /// A `nix build --rebuild` (or equivalent two-pass) determinism
    /// probe ran and produced byte-identical output: the
    /// re-derivation's `narHash` matched the original's. The Phase 1
    /// build attestation can honestly claim `reproducible: true` only
    /// in this arm, and the SLSA-level rubric in
    /// [`build_slsa_level`] earns the reproducible L3 grade only on
    /// this arm.
    ///
    /// [`build_slsa_level`]: crate::commands::attestation
    Reproducible,
    /// A `nix build --rebuild` determinism probe ran but the
    /// re-derivation's output bytes differed from the original's.
    /// Evidence of non-determinism: some non-hermetic input drove the
    /// build (current time, network state, `$PWD`, system entropy,
    /// non-content-addressed dependency). The Phase 1 build
    /// attestation must not claim reproducible against this state;
    /// the prior bare `false` literal would have collapsed the same
    /// bool here as for `ProbeAbsent`, conflating evidence of
    /// compromise with no-evidence-collected.
    Drift,
    /// `compute_build_attestation` did not spawn a determinism probe
    /// at all (no `nix build --rebuild`, no `nix-build --check`, no
    /// two-pass byte-comparison). No probe ran; no evidence was
    /// collected. The prior bare `false` literal reported the same
    /// value here as for the `Drift` arm, conflating "no re-build
    /// probe ran" with "re-build ran and detected drift".
    ProbeAbsent,
}

impl NixReproducibilityOutcome {
    /// True iff the Nix determinism probe ran AND produced
    /// byte-identical output across the two-pass re-derivation. The
    /// boolean the Phase 1 build attestation's `reproducible` field
    /// carries, and the boolean the SLSA-level rubric in
    /// [`build_slsa_level`] consumes to gate the reproducible L3
    /// grade. The other two arms collapse to `false` at this surface
    /// — they remain structurally distinct at the enum level so the
    /// call site can record them separately if needed (e.g. a future
    /// enrichment that surfaces the drifted-output path or the
    /// re-derivation narHash on the build attestation as a richer
    /// compliance-gap dimension).
    ///
    /// [`build_slsa_level`]: crate::commands::attestation
    pub fn is_reproducible(&self) -> bool {
        matches!(self, Self::Reproducible)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pin the three-arm `is_reproducible` truth table: only
    /// `Reproducible` collapses to `true`. The other two arms
    /// collapse to `false` at the bool surface but stay structurally
    /// distinct at the enum level — same shape as
    /// `test_is_verified_pins_all_arms` for
    /// [`crate::flux_source_verification::FluxSourceVerificationOutcome`]
    /// one layer over and `test_is_passed_pins_all_arms` for
    /// [`crate::kensa_policy::KensaPolicyOutcome`] two layers over.
    #[test]
    fn test_is_reproducible_pins_all_arms() {
        assert!(NixReproducibilityOutcome::Reproducible.is_reproducible());
        assert!(!NixReproducibilityOutcome::Drift.is_reproducible());
        assert!(!NixReproducibilityOutcome::ProbeAbsent.is_reproducible());
    }

    /// `ProbeAbsent` collapses to `reproducible: false` — the
    /// load-bearing honesty invariant the call site rests on. The
    /// pre-fix call site stamped a bare `let reproducible = false;`
    /// literal regardless of whether a determinism probe had run;
    /// the typed primitive routes through `is_reproducible()` which
    /// returns `false` here. The bool surface is unchanged from the
    /// pre-fix literal — `false` — but a downstream verifier reading
    /// `reproducible: false` from a Phase 1 build attestation can now
    /// recover "no determinism probe ran inside the build-attestation
    /// function" as one of the possible kind-of-claims (via the
    /// typed enum a future enrichment exposes), where the pre-fix
    /// bare bool would have flattened it into the same value as a
    /// probe-detected drift.
    #[test]
    fn test_probe_absent_collapses_to_false() {
        assert!(
            !NixReproducibilityOutcome::ProbeAbsent.is_reproducible(),
            "ProbeAbsent must collapse to reproducible=false; the \
             pre-fix bare `let reproducible = false;` literal carried \
             the same bool here as for `Drift`, conflating \
             no-evidence-collected with evidence-of-non-determinism",
        );
    }

    /// `Drift` also collapses to `false`, but stays structurally
    /// distinct from `ProbeAbsent` at the enum level — `Drift` is
    /// the "re-build probe ran and detected non-determinism" world
    /// (evidence of compromise: some non-hermetic input drove the
    /// build), while `ProbeAbsent` is the "no re-build probe ran
    /// inside the build-attestation function" world (no evidence
    /// either way). Both collapse to the same Phase 1 bool value
    /// but carry opposite evidence semantics a future enrichment can
    /// route into a structural verdict field on `BuildAttestation`.
    #[test]
    fn test_drift_collapses_to_false() {
        assert!(
            !NixReproducibilityOutcome::Drift.is_reproducible(),
            "Drift must collapse to reproducible=false; the pre-fix \
             bare `false` literal carried the same bool here as for \
             `ProbeAbsent`, conflating evidence-of-non-determinism \
             with no-evidence-collected",
        );
    }

    /// The three arms are mutually distinct under structural
    /// equality. Pins the load-bearing discriminator-preservation
    /// invariant the typed primitive exists to enforce:
    /// `Reproducible` (re-build matched), `Drift` (re-build
    /// mismatched), and `ProbeAbsent` (no re-build ran) all collapse
    /// to distinct `true` / `false` shapes at the bool surface but
    /// remain structurally distinct at the enum level. A downstream
    /// verifier walking the enum recovers the kind-of-claim from the
    /// variant alone — `Drift` carries evidence of compromise that
    /// `ProbeAbsent` does not. Same shape as
    /// `test_arms_are_structurally_distinct` for
    /// [`crate::flux_source_verification::FluxSourceVerificationOutcome`]
    /// one layer over.
    #[test]
    fn test_arms_are_structurally_distinct() {
        let reproducible = NixReproducibilityOutcome::Reproducible;
        let drift = NixReproducibilityOutcome::Drift;
        let absent = NixReproducibilityOutcome::ProbeAbsent;
        assert_ne!(reproducible, drift);
        assert_ne!(reproducible, absent);
        assert_ne!(drift, absent);
    }
}
