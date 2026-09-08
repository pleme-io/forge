//! Typed primitive for the sibling `println!("FAIL: {chart_name}
//! <phase> — {e}"); failed.push((chart_name.clone(), format!("<phase>:
//! {e}")))` two-line failure-record stanzas across
//! `commands/helm.rs::{lint_all, release_all}` chart-batch loops.
//!
//! # Compounding
//!
//! Pre-lift 5 sibling call sites in `commands/helm.rs` each restated the
//! same two-line record stanza:
//!
//! - `lint_all`   / workspace prep failure branch (~:2610)
//! - `release_all` / workspace prep failure branch (~:2703)
//! - `release_all` / lint failure branch (~:2712)
//! - `release_all` / package failure branch (~:2722)
//! - `release_all` / push failure branch (~:2750)
//!
//! Each restated the phase-label at TWO literal positions per site — the
//! operator-facing `println!("FAIL: {chart} {phase} — {err}")` line AND
//! the `format!("{phase}: {err}")` batch-summary reason (which
//! [`super::helm::format_failure_summary`] reads back at the end of the
//! batch as `"  - <chart>: <reason>"`). A single-site typo — a
//! `format!("workspace: {e}")` where the sibling reads `"workspace prep"`
//! in the FAIL line — would silently drift the two axes out of alignment
//! (the FAIL line names one phase, the batch summary at the tail of the
//! run names a different one), with the operator seeing a self-inconsistent
//! release report.
//!
//! Post-lift the phase closes over BOTH axes at ONE `match` arm in
//! [`ChartReleasePhase::label`]. Callers pass a variant, not a string;
//! the compiler refuses a phase name that is not part of the closed set;
//! the two axes are byte-identical by construction.
//!
//! A future refinement — a red glyph on the FAIL line, promotion to
//! `crate::ui::print_error` for the stderr sibling, an OTLP
//! `chart_release.step_failure` observability event carrying the chart
//! + phase + error as SEPARATE structured attributes, tightening
//! `"workspace prep"` to `"workspace-prep"` for grep-anchoring — lands
//! at ONE typed body and reaches every consumer by construction.
//!
//! THEORY.md §V (Compounding Directive: solve once), §VI.1
//! (three-times-is-a-law — 5 verbatim sibling sites redeemed by
//! extraction).

use std::io::Write;

use anyhow::Error;

/// Chart-batch release phase enumerated at compile time. Every variant
/// closes over BOTH the operator-facing phase wording in the FAIL line
/// AND the failure-summary phase key in the pushed reason string — one
/// source of truth, no drift between the two axes a pre-lift site
/// authored independently.
///
/// The variant set exhausts the phases the two chart-batch loops
/// (`lint_all` and `release_all`) currently record failures for. A
/// future phase (e.g. `Sign`, `Verify`) is one new variant plus one
/// arm in [`Self::label`] — the printed-line grammar stays fixed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChartReleasePhase {
    /// The `prepare_chart_workspace(...)` step — copies the chart, stages
    /// the library dependency, and rewrites relative paths. Emitted at
    /// BOTH `lint_all` and `release_all` failure branches.
    WorkspacePrep,
    /// The `lint(&chart_path)` step. Emitted at `release_all`'s lint
    /// failure branch (the `lint_all` in-loop lint failure has its own
    /// pre-lift wording without a phase suffix in the FAIL line, so it
    /// keeps its bespoke shape and is not covered by this primitive).
    Lint,
    /// The `package(&chart_path, output_dir, None)` step. Emitted at
    /// `release_all`'s package failure branch.
    Package,
    /// The `push(&tgz, registry)` step. Emitted at `release_all`'s push
    /// failure branch.
    Push,
}

impl ChartReleasePhase {
    /// The phase label used verbatim in BOTH the FAIL line
    /// (`"FAIL: <chart> <label> — <err>"`) AND the failure-summary
    /// reason (`format!("<label>: <err>")`). One source of truth for
    /// both axes.
    pub const fn label(self) -> &'static str {
        match self {
            Self::WorkspacePrep => "workspace prep",
            Self::Lint => "lint",
            Self::Package => "package",
            Self::Push => "push",
        }
    }
}

/// Record a chart-release phase failure onto `failed` and emit the
/// operator-facing `FAIL: <chart> <phase> — <err>` line to stdout.
///
/// The one body that composes BOTH axes of the record stanza (the
/// operator-facing FAIL line and the pushed batch-summary reason) so
/// they cannot silently drift. Delegates the line emission to
/// [`write_chart_release_phase_failure_line`] against a locked
/// [`std::io::stdout`] handle; the writer split exists so the
/// fail-before-pass byte-oracle tests can pin the exact rendered bytes
/// against a `Vec<u8>` sink.
pub fn record_chart_release_phase_failure(
    failed: &mut Vec<(String, String)>,
    chart_name: &str,
    phase: ChartReleasePhase,
    error: &Error,
) {
    let _ = write_chart_release_phase_failure_line(
        &mut std::io::stdout().lock(),
        chart_name,
        phase,
        error,
    );
    failed.push((
        chart_name.to_string(),
        format!("{}: {}", phase.label(), error),
    ));
}

/// Writer-taking sibling to [`record_chart_release_phase_failure`]. Emits
/// the single `FAIL: <chart> <phase-label> — <err>` line via
/// [`writeln!`] against the supplied writer.
pub fn write_chart_release_phase_failure_line<W: Write>(
    w: &mut W,
    chart_name: &str,
    phase: ChartReleasePhase,
    error: &Error,
) -> std::io::Result<()> {
    writeln!(w, "FAIL: {} {} — {}", chart_name, phase.label(), error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;

    #[test]
    fn phase_label_matches_pre_lift_wording_for_every_variant() {
        assert_eq!(ChartReleasePhase::WorkspacePrep.label(), "workspace prep");
        assert_eq!(ChartReleasePhase::Lint.label(), "lint");
        assert_eq!(ChartReleasePhase::Package.label(), "package");
        assert_eq!(ChartReleasePhase::Push.label(), "push");
    }

    #[test]
    fn write_chart_release_phase_failure_line_pins_workspace_prep_bytes() {
        let mut buf = Vec::new();
        let err = anyhow!("missing lib chart directory");
        write_chart_release_phase_failure_line(
            &mut buf,
            "pleme-lib",
            ChartReleasePhase::WorkspacePrep,
            &err,
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "FAIL: pleme-lib workspace prep — missing lib chart directory\n"
        );
    }

    #[test]
    fn write_chart_release_phase_failure_line_pins_lint_bytes() {
        let mut buf = Vec::new();
        let err = anyhow!("bad template");
        write_chart_release_phase_failure_line(&mut buf, "chartA", ChartReleasePhase::Lint, &err)
            .unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "FAIL: chartA lint — bad template\n"
        );
    }

    #[test]
    fn write_chart_release_phase_failure_line_pins_package_bytes() {
        let mut buf = Vec::new();
        let err = anyhow!("dependency unresolved");
        write_chart_release_phase_failure_line(
            &mut buf,
            "chartB",
            ChartReleasePhase::Package,
            &err,
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "FAIL: chartB package — dependency unresolved\n"
        );
    }

    #[test]
    fn write_chart_release_phase_failure_line_pins_push_bytes() {
        let mut buf = Vec::new();
        let err = anyhow!("registry unreachable");
        write_chart_release_phase_failure_line(&mut buf, "chartC", ChartReleasePhase::Push, &err)
            .unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "FAIL: chartC push — registry unreachable\n"
        );
    }

    #[test]
    fn record_chart_release_phase_failure_pushes_phase_label_prefixed_reason() {
        let mut failed: Vec<(String, String)> = Vec::new();
        let err = anyhow!("underlying failure");
        record_chart_release_phase_failure(
            &mut failed,
            "chart-x",
            ChartReleasePhase::WorkspacePrep,
            &err,
        );
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0].0, "chart-x");
        assert_eq!(failed[0].1, "workspace prep: underlying failure");
    }

    /// The phase-label is spelled verbatim in BOTH axes of the record
    /// stanza — the printed FAIL line AND the pushed reason string —
    /// with no drift between them. Pre-lift a typo on either axis
    /// would silently diverge the release report; post-lift both axes
    /// route through the same [`ChartReleasePhase::label`] projection.
    #[test]
    fn record_chart_release_phase_failure_pushed_reason_shares_phase_label_with_written_line() {
        for phase in [
            ChartReleasePhase::WorkspacePrep,
            ChartReleasePhase::Lint,
            ChartReleasePhase::Package,
            ChartReleasePhase::Push,
        ] {
            let mut buf = Vec::new();
            let err = anyhow!("shared");
            write_chart_release_phase_failure_line(&mut buf, "c", phase, &err).unwrap();
            let line = String::from_utf8(buf).unwrap();
            let label = phase.label();
            assert!(
                line.contains(&format!(" {label} — ")),
                "printed FAIL line for {phase:?} must carry phase label `{label}`; got: {line}"
            );

            let mut failed: Vec<(String, String)> = Vec::new();
            record_chart_release_phase_failure(&mut failed, "c", phase, &err);
            assert!(
                failed[0].1.starts_with(&format!("{label}: ")),
                "pushed reason for {phase:?} must carry phase label `{label}`; got: {}",
                failed[0].1
            );
        }
    }
}
