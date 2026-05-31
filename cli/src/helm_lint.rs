//! Typed `helm lint` probe outcome for forge's Phase 1 chart attestation
//! — the chart-quality peer of [`crate::cosign`] (image-signature probe),
//! [`crate::helm_provenance`] (chart-signature probe),
//! [`crate::oci_architecture`] (image-architecture probe),
//! [`crate::oci_manifest`] (manifest-identity oracle), and
//! [`crate::security_scan`] (SBOM / vuln-scan probes).
//!
//! ## What this module closes
//!
//! `commands/attestation.rs::compute_chart_attestation` previously stamped
//! a literal `true` into every Phase 1 chart attestation's `linter_passed`
//! field:
//!
//! ```ignore
//! Ok(ci::chart_attestation(
//!     chart_name,
//!     chart_version,
//!     chart_hash,
//!     provenance_outcome.is_verified(),
//!     vec![],
//!     true,   // Linter: assume passed if forge got this far
//!     true,   // Policy: assume passed
//!     registry_ref,
//! ))
//! ```
//!
//! The `// assume passed if forge got this far` comment names the gap
//! directly: the certification function records a *cryptographic claim*
//! based on inter-function flow control rather than evidence it collected
//! itself. A Phase 1 chart attestation that records `linter_passed: true`
//! against a chart whose `helm lint` was never probed inside the
//! certification surface — or whose lint produced ERROR-level diagnostics
//! that an upstream caller failed to bail on — is false by construction
//! (THEORY §V.2: attestation is cryptographic evidence, not a wish). The
//! same false-by-construction shape commit e8a2df7 closed for
//! `chart_hash` (`Blake3Hash::digest(format!("chart-{name}", ...))` →
//! `b"no-chart-dir"`), commit 9c5a99f closed for `tree_hash`
//! (`Blake3Hash::digest(b"")` → `b"no-tree-listing"`), commit 443bd22
//! closed for `manifest_hash` (`b"no-manifest"`), commit fffca30 closed
//! for the image `architecture` field (`"amd64"` literal →
//! [`crate::oci_architecture::OciArchitectureOutcome`]), commit b98eb5a
//! closed for the SBOM / vuln-scan hashes (name-keyed constants →
//! [`crate::security_scan::SbomProbeOutcome`] /
//! [`crate::security_scan::VulnScanProbeOutcome`]), and commit b8a1d8a
//! closed for the chart `provenance_verified` bool (`false` hardcode →
//! [`crate::helm_provenance::HelmProvenanceOutcome`]).
//!
//! ## The four operational worlds
//!
//! `helm lint <chart-dir>` distinguishes four operational worlds the
//! prior `true` hardcode flattened into a single positive claim:
//!
//! 1. **Probe absent** — helm is not on PATH / the spawn surface itself
//!    fails. No probe ran. There is no evidence either way.
//! 2. **Malformed** — helm ran but neither stdout nor stderr carried the
//!    canonical `N chart(s) linted, M chart(s) failed` summary line
//!    (helm binary crashed mid-output, version drift broke the summary
//!    grammar, the invocation hit an internal error). The probe ran and
//!    we cannot recover pass-or-fail evidence from the output.
//! 3. **Failed** — the summary line parsed AND named at least one failed
//!    chart (`M >= 1`). The chart has structural problems that prevent
//!    installation; the prior `true` hardcode would have falsely sealed
//!    a green-lint claim against this state.
//! 4. **Passed** — the summary line parsed AND named zero failed charts
//!    (`M == 0`). Warnings are allowed (helm convention; only
//!    `--strict` promotes them to errors); their count rides into the
//!    arm so a future enrichment commit can record them on the
//!    attestation. The Phase 1 chart attestation can honestly claim
//!    `linter_passed: true` only in this arm.
//!
//! ## Why a typed enum, not a bool
//!
//! THEORY §V.4 Phase 1 attestation pattern-matches on the structural
//! record of one external probe to recover the probe shape
//! (probe-absent vs probe-found-nothing vs probe-found-malformed vs
//! probe-found-evidence). A collapsed `bool` discards three of the four
//! discriminators. This module is the chart-quality peer of
//! [`crate::cosign`] (four-arm `cosign verify` probe outcome over
//! sigstore's `SimpleContainerImage` envelope) and
//! [`crate::helm_provenance`] (four-arm `.prov` probe outcome over the
//! OpenPGP cleartext framing); the typed-outcome idiom is the one
//! [`crate::oci_manifest`] / [`crate::tree_listing`] /
//! [`crate::store_path`] / [`crate::chart_listing`] established for the
//! canonical-form identity oracles. Each names the structured shape of
//! one external probe the attestation chain depends on so the call
//! site cannot accidentally lose a discriminator at the boundary.
//!
//! ## What this commit does NOT do
//!
//! This commit introduces the typed primitive and routes the call site
//! through the `ProbeAbsent` arm: `compute_chart_attestation` does not
//! yet spawn `helm lint` itself. The Phase 1 chart attestation now
//! records `linter_passed: false` instead of an unconditional `true`,
//! honestly naming "no lint probe ran inside the certification
//! function" rather than asserting a green-lint claim flow-control
//! cannot substantiate. The `Passed { ... }` / `Failed { ... }` /
//! `Malformed` arms are the future enrichment point: a follow-up
//! commit that wires `tokio::process::Command::new("helm").args(
//! ["lint", &chart_path.to_string_lossy()]).output().await` at the
//! call site and routes the result through [`parse_lint_output`] will
//! flip the call-site outcome to `Passed` for well-formed charts
//! without changing the typed primitive surface. Same deferral shape as
//! commit b98eb5a's [`crate::security_scan::SbomProbeOutcome::Collected`]
//! arm (typed primitive available, real probe wired in by a follow-up).
//!
//! ## Frontier inspiration
//!
//! Helm's own `helm lint` (`cmd/helm/lint.go` + `pkg/lint/lint.go`) is
//! the canonical chart-quality probe: it walks the chart directory,
//! parses Chart.yaml, validates required fields, templates every file
//! under templates/, and emits `[INFO]` / `[WARNING]` / `[ERROR]`
//! diagnostics terminated by the `N chart(s) linted, M chart(s) failed`
//! summary. SLSA v1.0 §"Build Provenance" and in-toto's link / layout
//! grammar both treat chart-quality checks as evidence-bearing
//! predicates a downstream verifier reconciles against a witnessed
//! probe response. An attestation that records `linter_passed: true`
//! against a chart whose `helm lint` was never probed fails every
//! reconciliation an `in-toto verify` / chart-policy pass could run.
//! The typed `ProbeAbsent` arm names that gap honestly rather than
//! inflating it with a constant — the same discipline
//! [`crate::cosign::CosignVerifyOutcome::ProbeAbsent`] and
//! [`crate::helm_provenance::HelmProvenanceOutcome::ProbeAbsent`] apply
//! at the image-signature and chart-signature layers.

/// Outcome of probing `helm lint <chart-dir>` against a chart source
/// directory. The four arms preserve the
/// probe-absent vs malformed vs lint-failed vs lint-passed distinction
/// the Phase 1 chart attestation depends on; the prior `true` hardcode
/// conflated all four into a single positive claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelmLintOutcome {
    /// `helm lint` ran AND the summary line `N chart(s) linted, 0
    /// chart(s) failed` parsed. The Phase 1 chart attestation can
    /// honestly claim `linter_passed: true` only in this arm.
    ///
    /// `warning_count` and `info_count` are the `[WARNING]` and
    /// `[INFO]` diagnostic counts recovered from stdout / stderr —
    /// reserved for a future enrichment commit that records them on
    /// the attestation as a richer chart-quality dimension. Warnings
    /// are allowed under helm's default policy (only `--strict`
    /// promotes them to errors); their count rides into the arm so
    /// the typed primitive does not have to widen later.
    Passed {
        warning_count: usize,
        info_count: usize,
    },
    /// `helm lint` ran AND the summary line parsed AND named at
    /// least one failed chart (`M >= 1`). The probe ran and reported
    /// a negative result: the chart has structural problems that
    /// prevent installation. The prior `true` hardcode would have
    /// falsely sealed a green-lint claim against this state.
    ///
    /// `failed_chart_count` is the `M` the summary line named;
    /// `error_count`, `warning_count`, and `info_count` are the
    /// `[ERROR]` / `[WARNING]` / `[INFO]` diagnostic counts recovered
    /// from stdout / stderr (reserved for the same future enrichment
    /// commit as the `Passed` arm's counters).
    Failed {
        failed_chart_count: usize,
        error_count: usize,
        warning_count: usize,
        info_count: usize,
    },
    /// `helm lint` ran (spawn succeeded) but neither stdout nor stderr
    /// carried the canonical `N chart(s) linted, M chart(s) failed`
    /// summary line. The probe ran but we cannot recover pass-or-fail
    /// evidence from the output (helm binary crashed mid-output,
    /// version drift broke the summary grammar, internal error). The
    /// prior `true` hardcode could not distinguish this from a real
    /// pass.
    Malformed,
    /// `helm lint` could not be spawned (helm not on PATH, absent
    /// absolute path, permission error, OS-level fork failure), or
    /// the call site did not run a probe at all. No probe was made;
    /// no evidence was collected. The prior `true` hardcode reported
    /// the same value here as for the `Passed` arm, conflating "no
    /// probe ran" with "probe ran and the chart passed".
    ProbeAbsent,
}

impl HelmLintOutcome {
    /// True iff the `helm lint` probe ran AND the summary line named
    /// zero failed charts. The boolean the Phase 1 chart attestation's
    /// `linter_passed` field carries. The other three arms collapse to
    /// `false` at this surface — they remain structurally distinct at
    /// the enum level so the call site can record them separately if
    /// needed.
    pub fn is_passed(&self) -> bool {
        matches!(self, Self::Passed { .. })
    }

    /// Total `[WARNING]` diagnostics recovered from the probe output.
    /// `0` for arms that carry no warnings (`ProbeAbsent`, `Malformed`)
    /// — same shape as `0` counts on the `Absent` arm of
    /// [`crate::security_scan::VulnScanProbeOutcome`]: zero because no
    /// evidence was collected, never to be confused with a probe that
    /// found zero warnings (which would be `Passed { warning_count: 0,
    /// .. }`).
    #[allow(dead_code)]
    pub fn warning_count(&self) -> usize {
        match self {
            Self::Passed { warning_count, .. } | Self::Failed { warning_count, .. } => {
                *warning_count
            }
            Self::Malformed | Self::ProbeAbsent => 0,
        }
    }

    /// Total `[ERROR]` diagnostics recovered from the probe output.
    /// `0` for arms that carry no errors (`Passed`, `ProbeAbsent`,
    /// `Malformed`). The `Failed` arm's `error_count` is the
    /// structured diagnostic count; the `failed_chart_count` is the
    /// summary-line count of charts that failed. The two are related
    /// but distinct: a single chart with three `[ERROR]` lines
    /// produces `failed_chart_count == 1` and `error_count == 3`.
    #[allow(dead_code)]
    pub fn error_count(&self) -> usize {
        match self {
            Self::Failed { error_count, .. } => *error_count,
            Self::Passed { .. } | Self::Malformed | Self::ProbeAbsent => 0,
        }
    }
}

/// Parse the captured stdout AND stderr of a `helm lint <chart-dir>`
/// probe into a [`HelmLintOutcome`].
///
/// helm lint emits diagnostics prefixed with `[INFO]` / `[WARNING]` /
/// `[ERROR]` markers on either stream depending on version, and
/// terminates with a single canonical summary line of the form
/// `N chart(s) linted, M chart(s) failed` (optionally prefixed with
/// `Error:` when `M >= 1`). The parser walks both streams, tallies
/// the three diagnostic counts, and recovers `M` from the summary
/// line; the `M` value alone discriminates Passed vs Failed, so the
/// parser does not need to consult the exit code. Absence of the
/// summary line (helm crashed mid-output, output truncated, version
/// drift) collapses to [`HelmLintOutcome::Malformed`] — the probe
/// ran but we cannot recover pass-or-fail evidence honestly.
///
/// The diagnostic counts are recovered by case-insensitive substring
/// match on the trimmed line; ANSI escape sequences helm sometimes
/// emits around the markers do not defeat the match. Lines that
/// happen to contain multiple markers (rare; would be a template
/// embedding a marker literally) are counted once per first match
/// arm so the totals stay an upper bound on what helm actually
/// emitted.
pub fn parse_lint_output(stdout: &str, stderr: &str) -> HelmLintOutcome {
    let mut info_count: usize = 0;
    let mut warning_count: usize = 0;
    let mut error_count: usize = 0;
    let mut summary_failed: Option<usize> = None;

    for line in stdout.lines().chain(stderr.lines()) {
        let trimmed = line.trim();
        if trimmed.contains("[ERROR]") {
            error_count += 1;
        } else if trimmed.contains("[WARNING]") {
            warning_count += 1;
        } else if trimmed.contains("[INFO]") {
            info_count += 1;
        }
        if let Some(m) = parse_summary_line(trimmed) {
            summary_failed = Some(m);
        }
    }

    match summary_failed {
        Some(0) => HelmLintOutcome::Passed {
            warning_count,
            info_count,
        },
        Some(failed_chart_count) => HelmLintOutcome::Failed {
            failed_chart_count,
            error_count,
            warning_count,
            info_count,
        },
        None => HelmLintOutcome::Malformed,
    }
}

/// Recover `M` from a canonical helm-lint summary line of the form
/// `N chart(s) linted, M chart(s) failed`, optionally prefixed with
/// `Error:` (helm writes the `Error:` prefix on stderr when `M >= 1`).
/// Returns `None` on any structural mismatch — the parser collapses to
/// [`HelmLintOutcome::Malformed`] in that case rather than guessing.
fn parse_summary_line(line: &str) -> Option<usize> {
    let line = line.trim_start_matches("Error:").trim();
    let (before, after) = line.split_once(", ")?;
    if !before.contains("chart(s) linted") || !after.contains("chart(s) failed") {
        return None;
    }
    after.split_whitespace().next()?.parse::<usize>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A canonical successful `helm lint` invocation against a chart
    /// with one INFO-level diagnostic and no warnings or errors.
    /// Parses to [`HelmLintOutcome::Passed`] with `info_count: 1` and
    /// `warning_count: 0`. The summary line's `0 chart(s) failed` is
    /// the discriminator that places the outcome in the `Passed`
    /// arm — exit code is not consulted (the parser is exit-agnostic
    /// by construction so a future regression that flipped exit-code
    /// handling would not silently re-conflate Passed and Failed).
    #[test]
    fn test_parse_passed_with_info_diagnostic() {
        let stdout = "\
==> Linting ./example
[INFO] Chart.yaml: icon is recommended

1 chart(s) linted, 0 chart(s) failed
";
        let out = parse_lint_output(stdout, "");
        assert!(out.is_passed(), "summary line names 0 failed → Passed arm");
        let HelmLintOutcome::Passed {
            warning_count,
            info_count,
        } = out
        else {
            panic!("expected Passed arm, got {out:?}");
        };
        assert_eq!(warning_count, 0);
        assert_eq!(info_count, 1);
    }

    /// A `helm lint` invocation that produced a structural ERROR
    /// diagnostic and exited with `M >= 1` in the summary line.
    /// Parses to [`HelmLintOutcome::Failed`] with `failed_chart_count:
    /// 1` and `error_count: 1`. The prior `true` hardcode would have
    /// falsely sealed `linter_passed: true` against this state; the
    /// typed primitive makes that conflation structurally impossible.
    #[test]
    fn test_parse_failed_with_error_diagnostic() {
        let stdout = "\
==> Linting ./broken
[INFO] Chart.yaml: icon is recommended
[ERROR] Chart.yaml: name is required
";
        let stderr = "\
Error: 1 chart(s) linted, 1 chart(s) failed
";
        let out = parse_lint_output(stdout, stderr);
        assert!(!out.is_passed(), "summary line names 1 failed → not Passed");
        let HelmLintOutcome::Failed {
            failed_chart_count,
            error_count,
            warning_count,
            info_count,
        } = out
        else {
            panic!("expected Failed arm, got {out:?}");
        };
        assert_eq!(failed_chart_count, 1);
        assert_eq!(error_count, 1);
        assert_eq!(warning_count, 0);
        assert_eq!(info_count, 1);
    }

    /// helm lint with multiple charts, some of which fail. The summary
    /// line `3 chart(s) linted, 2 chart(s) failed` discriminates as
    /// Failed regardless of the per-stream diagnostic distribution.
    /// Pins the `failed_chart_count` recovery against the summary
    /// line's `M` (not against the `error_count` over diagnostic
    /// lines, which can be a different number — one chart with three
    /// ERROR diagnostics produces `failed_chart_count == 1` and
    /// `error_count == 3`).
    #[test]
    fn test_parse_failed_count_from_summary_not_diagnostic_lines() {
        let stdout = "\
==> Linting ./a
[ERROR] e1
[ERROR] e2
[ERROR] e3
==> Linting ./b
[ERROR] e4
==> Linting ./c

Error: 3 chart(s) linted, 2 chart(s) failed
";
        let out = parse_lint_output(stdout, "");
        let HelmLintOutcome::Failed {
            failed_chart_count,
            error_count,
            ..
        } = out
        else {
            panic!("expected Failed arm");
        };
        assert_eq!(
            failed_chart_count, 2,
            "failed_chart_count comes from the summary line's M, not from the [ERROR] line count",
        );
        assert_eq!(
            error_count, 4,
            "error_count is the diagnostic line count, distinct from failed_chart_count",
        );
    }

    /// helm lint output with WARNINGs only and `0 chart(s) failed`
    /// stays in the Passed arm — warnings are allowed under helm's
    /// default policy (only `--strict` promotes them to errors).
    /// `warning_count` is recovered for future enrichment but does
    /// NOT flip the bool to false. Pins the warning-tolerance
    /// invariant the typed primitive carries from helm's own
    /// convention.
    #[test]
    fn test_parse_warnings_only_stays_passed() {
        let stdout = "\
==> Linting ./example
[INFO] Chart.yaml: icon is recommended
[WARNING] templates/_helpers.tpl: missing template helpers

1 chart(s) linted, 0 chart(s) failed
";
        let out = parse_lint_output(stdout, "");
        assert!(out.is_passed());
        assert_eq!(out.warning_count(), 1);
    }

    /// Output without the canonical summary line is [`HelmLintOutcome::
    /// Malformed`], regardless of which diagnostic markers fired.
    /// helm crashed mid-output, version drift broke the summary
    /// grammar, the invocation hit an internal error — in any of
    /// these cases the probe ran but we cannot recover pass-or-fail
    /// evidence. The honest record is Malformed, not a guessed
    /// Passed (the prior `true` hardcode flattened this case into
    /// `linter_passed: true`).
    #[test]
    fn test_parse_no_summary_line_is_malformed() {
        let stdout = "\
==> Linting ./example
[INFO] Chart.yaml: icon is recommended
[ERROR] internal error before summary
";
        let out = parse_lint_output(stdout, "");
        assert_eq!(out, HelmLintOutcome::Malformed);
        assert!(
            !out.is_passed(),
            "Malformed must collapse to linter_passed=false"
        );
    }

    /// Empty stdout AND empty stderr is [`HelmLintOutcome::Malformed`].
    /// Some helm-version / shell combinations produce no output at all
    /// on internal error; the parser must not silently classify this
    /// as Passed.
    #[test]
    fn test_parse_empty_output_is_malformed() {
        assert_eq!(parse_lint_output("", ""), HelmLintOutcome::Malformed);
    }

    /// The summary line may appear on stderr (helm writes the
    /// `Error: N chart(s) linted, M chart(s) failed` line to stderr
    /// when `M >= 1`). The parser must walk both streams to find it;
    /// pinning here that stdout-only parsing would miss this case.
    #[test]
    fn test_parse_summary_line_on_stderr_is_recovered() {
        let stdout = "==> Linting ./broken\n[ERROR] something\n";
        let stderr = "Error: 1 chart(s) linted, 1 chart(s) failed\n";
        let out = parse_lint_output(stdout, stderr);
        let HelmLintOutcome::Failed {
            failed_chart_count, ..
        } = out
        else {
            panic!("expected Failed arm, got {out:?}");
        };
        assert_eq!(failed_chart_count, 1);
    }

    /// Pin the four-arm `is_passed` truth table: only `Passed`
    /// collapses to `true`. The other three arms collapse to `false`
    /// at the bool surface but stay structurally distinct at the enum
    /// level — same shape as `test_is_verified_pins_all_arms` for
    /// [`crate::cosign::CosignVerifyOutcome`] and the four-arm bool
    /// pin in `test_chart_provenance_four_arms_collapse_to_distinct_
    /// bools` for [`crate::helm_provenance::HelmProvenanceOutcome`].
    #[test]
    fn test_is_passed_pins_all_arms() {
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
        assert!(!HelmLintOutcome::ProbeAbsent.is_passed());
    }

    /// Pin the `warning_count` / `error_count` accessors against
    /// every arm. Arms without the relevant counter (Malformed,
    /// ProbeAbsent for both; Passed for error_count) yield `0` —
    /// honestly meaning "no evidence collected", never to be
    /// confused with "real probe found zero" (which would be `Passed
    /// { warning_count: 0, .. }` carrying explicit evidence that the
    /// probe found nothing). Same per-kind sentinel discipline as
    /// [`crate::security_scan::VulnScanProbeOutcome::Absent`]'s
    /// `(0, 0)` counts paired with the `b"no-vuln-scan"` hash.
    #[test]
    fn test_counter_accessors_yield_zero_for_unevidenced_arms() {
        assert_eq!(HelmLintOutcome::ProbeAbsent.warning_count(), 0);
        assert_eq!(HelmLintOutcome::ProbeAbsent.error_count(), 0);
        assert_eq!(HelmLintOutcome::Malformed.warning_count(), 0);
        assert_eq!(HelmLintOutcome::Malformed.error_count(), 0);
        assert_eq!(
            HelmLintOutcome::Passed {
                warning_count: 3,
                info_count: 5,
            }
            .warning_count(),
            3
        );
        assert_eq!(
            HelmLintOutcome::Passed {
                warning_count: 3,
                info_count: 5,
            }
            .error_count(),
            0,
            "Passed has no error_count by construction; the accessor must yield 0",
        );
        assert_eq!(
            HelmLintOutcome::Failed {
                failed_chart_count: 1,
                error_count: 7,
                warning_count: 2,
                info_count: 0,
            }
            .error_count(),
            7
        );
    }

    /// The summary-line parser tolerates the `Error:` prefix helm
    /// emits on stderr for failed-lint summaries and recovers the
    /// same `M`. Pinning the prefix-tolerance discipline here means
    /// a future helm version that dropped the prefix on some
    /// platform would not silently flip Failed to Malformed.
    #[test]
    fn test_parse_summary_line_tolerates_error_prefix() {
        let with_prefix = parse_summary_line("Error: 1 chart(s) linted, 1 chart(s) failed");
        let without_prefix = parse_summary_line("1 chart(s) linted, 1 chart(s) failed");
        assert_eq!(with_prefix, Some(1));
        assert_eq!(without_prefix, Some(1));
    }

    /// The summary-line parser rejects malformed inputs structurally
    /// rather than guessing — a line missing the `chart(s) failed`
    /// suffix, a line whose `M` slot is not a number, an entirely
    /// unrelated line. Pinning here so the four-arm enum's Malformed
    /// arm cannot be silently bypassed by a near-miss output.
    #[test]
    fn test_parse_summary_line_rejects_malformed_inputs() {
        assert_eq!(parse_summary_line(""), None);
        assert_eq!(parse_summary_line("==> Linting ./x"), None);
        assert_eq!(parse_summary_line("1 chart(s) linted"), None);
        assert_eq!(
            parse_summary_line("xxx chart(s) linted, yyy chart(s) failed"),
            None,
            "non-numeric M must collapse to None, never to a guessed 0",
        );
    }
}
