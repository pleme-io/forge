//! Typed `kensa` compliance-policy probe outcome for forge's Phase 1
//! chart attestation — the chart-policy peer of [`crate::cosign`]
//! (image-signature probe), [`crate::helm_provenance`] (chart-signature
//! probe), [`crate::helm_lint`] (chart-quality probe),
//! [`crate::oci_architecture`] (image-architecture probe),
//! [`crate::oci_manifest`] (manifest-identity oracle),
//! [`crate::openpgp_signature`] (OpenPGP v4 signature packet parser),
//! and [`crate::security_scan`] (SBOM / vuln-scan probes).
//!
//! ## What this module closes
//!
//! `commands/attestation.rs::compute_chart_attestation` previously
//! stamped a literal `true` into every Phase 1 chart attestation's
//! `policy_passed` field:
//!
//! ```ignore
//! Ok(ci::chart_attestation(
//!     chart_name,
//!     chart_version,
//!     chart_hash,
//!     provenance_outcome.is_verified(),
//!     vec![],
//!     lint_outcome.is_passed(),
//!     true,   // Policy: assume passed
//!     registry_ref,
//! ))
//! ```
//!
//! The `// assume passed` comment names the gap directly: the
//! certification function records a *cryptographic claim* based on
//! nothing — no kensa probe ran inside the certification surface, no
//! compliance baseline was consulted, no OutcomeVerificationReport was
//! produced. A Phase 1 chart attestation that records `policy_passed:
//! true` against a chart whose `kensa` was never probed is false by
//! construction (THEORY §V.2: attestation is cryptographic evidence,
//! not a wish; THEORY §III.3: compliance is a structural dimension
//! every renderer carries, never a value asserted at the call site
//! without evidence).
//!
//! This is the same false-by-construction shape commit d81f639 closed
//! for `linter_passed` (`true` → [`crate::helm_lint::HelmLintOutcome`]),
//! commit 2f3a7dc closed for `signer_key_id` (`None` →
//! [`crate::openpgp_signature::SignaturePacketOutcome`]), commit b98eb5a
//! closed for the SBOM / vuln-scan hashes (name-keyed constants →
//! [`crate::security_scan::SbomProbeOutcome`] /
//! [`crate::security_scan::VulnScanProbeOutcome`]), commit fffca30
//! closed for the image `architecture` field (`"amd64"` literal →
//! [`crate::oci_architecture::OciArchitectureOutcome`]), commit b8a1d8a
//! closed for the chart `provenance_verified` bool (`false` hardcode →
//! [`crate::helm_provenance::HelmProvenanceOutcome`]), commit e8a2df7
//! closed for `chart_hash` (`Blake3Hash::digest(format!("chart-{name}",
//! ...))` → `b"no-chart-dir"`), commit 443bd22 closed for
//! `manifest_hash` (`b"no-manifest"`), and commit 9c5a99f closed for
//! `tree_hash` (`b"no-tree-listing"`).
//!
//! ## The three operational worlds
//!
//! `kensa` (the compliance-engine probe — OSCAL/NIST mapping per
//! THEORY §V.3, pre-deploy gate per THEORY §VII.1) against a chart
//! source distinguishes three operational worlds the prior `true`
//! hardcode flattened into a single positive claim:
//!
//! 1. **Probe absent** — kensa is not on PATH, the certification
//!    function did not spawn a probe at all, or the probe could not
//!    reach the chart (e.g. an integration-test path that constructed
//!    the attestation directly without going through a kensa
//!    invocation). No probe ran. There is no evidence either way.
//! 2. **Failed** — kensa ran AND reported at least one failing control
//!    against the declared baseline. The chart has compliance
//!    violations that fail the policy gate; the prior `true` hardcode
//!    would have falsely sealed a green-policy claim against this
//!    state.
//! 3. **Passed** — kensa ran AND every evaluated control passed
//!    against the declared baseline. The Phase 1 chart attestation
//!    can honestly claim `policy_passed: true` only in this arm.
//!
//! ## Why three arms, not two or four
//!
//! - **Three rather than two** (`Passed` / `ProbeAbsent`): the policy
//!   probe is binary pass/fail by construction — a `Failed` outcome
//!   is a structurally distinct world from `Passed` AND from
//!   `ProbeAbsent`. Collapsing `Failed` into a single boolean would
//!   re-introduce the discriminator loss the typed primitive exists
//!   to prevent (THEORY §V.1: make invalid states unrepresentable —
//!   a `policy_passed: false` value that conflates "no probe ran"
//!   with "probe ran and reported failures" is a flat state where
//!   a downstream verifier cannot recover the kind-of-claim).
//! - **Three rather than four** (no `Malformed` arm yet): this commit
//!   introduces the typed primitive but does NOT introduce a parser
//!   for kensa's output grammar — no `parse_kensa_output` function
//!   exists here. The `Malformed` arm in
//!   [`crate::helm_lint::HelmLintOutcome::Malformed`] is paired with
//!   [`crate::helm_lint::parse_lint_output`] over the canonical
//!   `helm lint` summary-line grammar (Helm is an external project
//!   with a stable, documented output shape). `kensa` is a pleme-io
//!   internal tool whose canonical output grammar is the typed
//!   `OutcomeVerificationReport` (VOCABULARY §kensa) — when a
//!   follow-up commit wires the kensa shell-out at the
//!   `compute_chart_attestation` call site, the integration will
//!   deserialize the typed report directly rather than re-parse a
//!   text-mode summary, and the malformed-output world will fold
//!   into `ProbeAbsent` (spawn-succeeded-but-no-typed-report =
//!   no-evidence-collected). Adding a speculative `Malformed` arm
//!   today would force every consumer to handle a world the actual
//!   probe layer will not produce. The enum stays additive: a
//!   future commit may widen to four arms without changing the
//!   `Passed` / `Failed` / `ProbeAbsent` semantics this commit
//!   pins.
//!
//! ## What this commit does NOT do
//!
//! This commit introduces the typed primitive and routes the call
//! site through the `ProbeAbsent` arm: `compute_chart_attestation`
//! does not yet spawn `kensa` itself. The Phase 1 chart attestation
//! now records `policy_passed: false` instead of an unconditional
//! `true`, honestly naming "no policy probe ran inside the
//! certification function" rather than asserting a green-policy
//! claim flow-control cannot substantiate. The `Passed { ... }` /
//! `Failed { ... }` arms are the future enrichment point: a
//! follow-up commit that wires `tokio::process::Command::new("kensa")
//! .args(["verify", "chart", &chart_path.to_string_lossy()]).output()
//! .await` at the call site and deserializes the resulting
//! `OutcomeVerificationReport` JSON into one of the two evidence-
//! bearing arms will flip the call-site outcome to `Passed` for
//! compliant charts without changing the typed primitive surface.
//! Same deferral shape as commit b98eb5a's
//! [`crate::security_scan::SbomProbeOutcome::Collected`] arm and
//! commit d81f639's [`crate::helm_lint::HelmLintOutcome::Passed`]
//! arm (typed primitive available, real probe wired in by a
//! follow-up).
//!
//! ## Frontier inspiration
//!
//! OSCAL (NIST 800-53 Open Security Controls Assessment Language)
//! and in-toto's layout/link grammar both treat compliance-control
//! evaluations as evidence-bearing predicates a downstream verifier
//! reconciles against a witnessed probe response — never against a
//! call-site constant. SLSA v1.0 §"Build Provenance" requires every
//! claimed policy outcome to be a content-addressed witness of a
//! real evaluation, not a hardcoded bool. An attestation that
//! records `policy_passed: true` against a chart whose kensa was
//! never probed fails every reconciliation an `in-toto verify` /
//! `kensa verify outcome-chain` (VOCABULARY §kensa verify
//! outcome-chain) pass could run. The typed `ProbeAbsent` arm names
//! that gap honestly rather than inflating it with a constant — the
//! same discipline
//! [`crate::cosign::CosignVerifyOutcome::ProbeAbsent`],
//! [`crate::helm_provenance::HelmProvenanceOutcome::ProbeAbsent`],
//! [`crate::helm_lint::HelmLintOutcome::ProbeAbsent`],
//! [`crate::security_scan::SbomProbeOutcome::Absent`], and
//! [`crate::security_scan::VulnScanProbeOutcome::Absent`] apply at
//! the image-signature, chart-signature, chart-quality, SBOM, and
//! vuln-scan layers.

/// Outcome of probing the `kensa` compliance engine against a chart
/// source for compliance-policy evaluation. The three arms preserve
/// the probe-absent vs policy-failed vs policy-passed distinction the
/// Phase 1 chart attestation depends on; the prior `true` hardcode
/// conflated all three into a single positive claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KensaPolicyOutcome {
    /// `kensa` ran AND every evaluated compliance control passed
    /// against the declared baseline. The Phase 1 chart attestation
    /// can honestly claim `policy_passed: true` only in this arm.
    ///
    /// `evaluated_control_count` is the total number of controls the
    /// kensa run evaluated — reserved for a future enrichment commit
    /// that records the breadth of the evaluation on the attestation
    /// (a chart evaluated against a single control is a structurally
    /// different claim from a chart evaluated against the full
    /// NIST 800-53 / FedRAMP / SOC 2 baseline, even if both produce
    /// `policy_passed: true` at the bool surface). Shape mirrors
    /// [`crate::helm_lint::HelmLintOutcome::Passed`]'s
    /// `warning_count` / `info_count` fields one layer over.
    Passed { evaluated_control_count: usize },
    /// `kensa` ran AND reported at least one failing control against
    /// the declared baseline. The probe ran and reported a negative
    /// result: the chart has compliance violations that fail the
    /// pre-deploy policy gate (THEORY §VII.1). The prior `true`
    /// hardcode would have falsely sealed a green-policy claim
    /// against this state.
    ///
    /// `failed_control_count` is the number of controls the kensa
    /// run flagged as failing; `evaluated_control_count` is the
    /// total number of controls evaluated. The two are related but
    /// distinct: `failed_control_count <= evaluated_control_count`
    /// always holds (a control cannot fail without being evaluated),
    /// but the ratio names the severity of the gap a downstream
    /// `kensa replay outcome-chain` (VOCABULARY §kensa replay
    /// outcome-chain) would surface.
    Failed {
        failed_control_count: usize,
        evaluated_control_count: usize,
    },
    /// `kensa` could not be spawned (kensa not on PATH, absent
    /// absolute path, permission error, OS-level fork failure), or
    /// the certification function did not run a probe at all, or
    /// the probe could not reach the chart (e.g. integration-test
    /// path that constructed the attestation directly without going
    /// through a kensa invocation). No probe was made; no evidence
    /// was collected. The prior `true` hardcode reported the same
    /// value here as for the `Passed` arm, conflating "no probe ran"
    /// with "probe ran and the chart passed every control".
    ProbeAbsent,
}

impl KensaPolicyOutcome {
    /// True iff the `kensa` probe ran AND every evaluated control
    /// passed. The boolean the Phase 1 chart attestation's
    /// `policy_passed` field carries. The other two arms collapse
    /// to `false` at this surface — they remain structurally
    /// distinct at the enum level so the call site can record them
    /// separately if needed (e.g. a future enrichment that surfaces
    /// `failed_control_count` on the attestation as a richer
    /// compliance-gap dimension).
    pub fn is_passed(&self) -> bool {
        matches!(self, Self::Passed { .. })
    }

    /// Total number of controls the kensa run evaluated, across both
    /// pass and fail outcomes. `0` for `ProbeAbsent` (no probe ran,
    /// no controls evaluated) — same per-kind sentinel discipline as
    /// [`crate::security_scan::VulnScanProbeOutcome::Absent`]'s
    /// `(0, 0)` counts paired with the `b"no-vuln-scan"` hash:
    /// zero because no evidence was collected, never to be confused
    /// with a probe that found zero controls applicable (which would
    /// be `Passed { evaluated_control_count: 0 }` — a vacuously-true
    /// claim a downstream verifier could flag).
    #[allow(dead_code)]
    pub fn evaluated_control_count(&self) -> usize {
        match self {
            Self::Passed {
                evaluated_control_count,
            }
            | Self::Failed {
                evaluated_control_count,
                ..
            } => *evaluated_control_count,
            Self::ProbeAbsent => 0,
        }
    }

    /// Number of controls the kensa run flagged as failing. `0` for
    /// arms that carry no failures (`Passed`, `ProbeAbsent`). The
    /// `Failed` arm's `failed_control_count` is the compliance-gap
    /// discriminator a downstream `kensa replay outcome-chain` would
    /// walk to render the per-control violation breakdown.
    #[allow(dead_code)]
    pub fn failed_control_count(&self) -> usize {
        match self {
            Self::Failed {
                failed_control_count,
                ..
            } => *failed_control_count,
            Self::Passed { .. } | Self::ProbeAbsent => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pin the three-arm `is_passed` truth table: only `Passed`
    /// collapses to `true`. The other two arms collapse to `false`
    /// at the bool surface but stay structurally distinct at the
    /// enum level — same shape as `test_is_passed_pins_all_arms`
    /// for [`crate::helm_lint::HelmLintOutcome`] one layer over,
    /// and `test_is_verified_pins_all_arms` for
    /// [`crate::cosign::CosignVerifyOutcome`] two layers over.
    #[test]
    fn test_is_passed_pins_all_arms() {
        assert!(KensaPolicyOutcome::Passed {
            evaluated_control_count: 0,
        }
        .is_passed());
        assert!(KensaPolicyOutcome::Passed {
            evaluated_control_count: 42,
        }
        .is_passed());
        assert!(!KensaPolicyOutcome::Failed {
            failed_control_count: 1,
            evaluated_control_count: 42,
        }
        .is_passed());
        assert!(!KensaPolicyOutcome::ProbeAbsent.is_passed());
    }

    /// `ProbeAbsent` collapses to `policy_passed: false` — the
    /// load-bearing honesty invariant. The pre-fix call site
    /// stamped `true` regardless of whether kensa had been probed;
    /// the typed primitive routes through `is_passed()` which
    /// returns `false` here. A downstream verifier reading
    /// `policy_passed: false` from a Phase 1 chart attestation can
    /// recover "no policy probe ran inside the certification
    /// function" as one of the possible kind-of-claims, where the
    /// pre-fix `true` would have asserted "policy passed" with no
    /// evidence to back it.
    #[test]
    fn test_probe_absent_collapses_to_false() {
        assert!(
            !KensaPolicyOutcome::ProbeAbsent.is_passed(),
            "ProbeAbsent must collapse to policy_passed=false; the \
             pre-fix `true` hardcode sealed a green-policy claim \
             from nothing",
        );
    }

    /// Pin the counter accessors against every arm. Arms without
    /// the relevant counter yield `0` — honestly meaning "no
    /// evidence collected", never to be confused with "real probe
    /// found zero controls" (which would be `Passed {
    /// evaluated_control_count: 0 }` carrying explicit evidence of
    /// a vacuous evaluation). Same per-kind sentinel discipline as
    /// [`crate::helm_lint::HelmLintOutcome`]'s
    /// `warning_count`/`error_count` accessors and
    /// [`crate::security_scan::VulnScanProbeOutcome::Absent`]'s
    /// `(0, 0)` counts paired with the `b"no-vuln-scan"` hash.
    #[test]
    fn test_counter_accessors_yield_zero_for_unevidenced_arm() {
        assert_eq!(KensaPolicyOutcome::ProbeAbsent.evaluated_control_count(), 0,);
        assert_eq!(KensaPolicyOutcome::ProbeAbsent.failed_control_count(), 0,);
        assert_eq!(
            KensaPolicyOutcome::Passed {
                evaluated_control_count: 17,
            }
            .evaluated_control_count(),
            17,
        );
        assert_eq!(
            KensaPolicyOutcome::Passed {
                evaluated_control_count: 17,
            }
            .failed_control_count(),
            0,
            "Passed has no failed_control_count by construction; the \
             accessor must yield 0",
        );
        assert_eq!(
            KensaPolicyOutcome::Failed {
                failed_control_count: 3,
                evaluated_control_count: 17,
            }
            .failed_control_count(),
            3,
        );
        assert_eq!(
            KensaPolicyOutcome::Failed {
                failed_control_count: 3,
                evaluated_control_count: 17,
            }
            .evaluated_control_count(),
            17,
        );
    }

    /// The three arms are mutually distinct under structural
    /// equality even when they share counter values. Pins the
    /// load-bearing discriminator-preservation invariant the typed
    /// primitive exists to enforce: a `Passed { evaluated_control_
    /// count: 0 }` (vacuously-true evaluation), a `Failed {
    /// failed_control_count: 0, evaluated_control_count: 0 }` (also
    /// vacuous, but on the negative side — kensa ran and found no
    /// applicable controls AND classified the empty evaluation as
    /// failed; surfaces only under degenerate kensa baselines), and
    /// a `ProbeAbsent` (no kensa ran at all) all collapse to
    /// distinct `false` / `true` shapes at the bool surface but
    /// remain structurally distinct at the enum level. A downstream
    /// verifier walking the enum recovers the kind-of-claim from
    /// the variant alone.
    #[test]
    fn test_arms_are_structurally_distinct() {
        let passed_vacuous = KensaPolicyOutcome::Passed {
            evaluated_control_count: 0,
        };
        let failed_vacuous = KensaPolicyOutcome::Failed {
            failed_control_count: 0,
            evaluated_control_count: 0,
        };
        let absent = KensaPolicyOutcome::ProbeAbsent;
        assert_ne!(passed_vacuous, failed_vacuous);
        assert_ne!(passed_vacuous, absent);
        assert_ne!(failed_vacuous, absent);
    }

    /// `Failed` arms with the same `failed_control_count` but
    /// different `evaluated_control_count` are structurally
    /// distinct — the ratio names the severity of the compliance
    /// gap (3 failed / 4 evaluated is a different claim from
    /// 3 failed / 100 evaluated). Pins that both fields ride into
    /// the arm as one tuple and a future regression that hand-
    /// rolled them separately cannot drift them apart at the call
    /// site (the canonical "one source, one record" discipline
    /// THEORY §VI.1 names).
    #[test]
    fn test_failed_arm_pairs_counts_as_one_tuple() {
        let narrow = KensaPolicyOutcome::Failed {
            failed_control_count: 3,
            evaluated_control_count: 4,
        };
        let broad = KensaPolicyOutcome::Failed {
            failed_control_count: 3,
            evaluated_control_count: 100,
        };
        assert_ne!(
            narrow, broad,
            "the (failed, evaluated) ratio is the compliance-gap \
             discriminator and must be preserved as one tuple",
        );
        assert!(!narrow.is_passed());
        assert!(!broad.is_passed());
        assert_eq!(narrow.failed_control_count(), 3);
        assert_eq!(broad.failed_control_count(), 3);
        assert_eq!(narrow.evaluated_control_count(), 4);
        assert_eq!(broad.evaluated_control_count(), 100);
    }
}
