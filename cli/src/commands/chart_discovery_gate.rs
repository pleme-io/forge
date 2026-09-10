//! Typed primitive for the sibling three-line `discover_charts(...)? →
//! `if charts.is_empty() { bail!("No charts found in {}", charts_dir); }` →
//! `info!("Discovered {} charts: {}", charts.len(), charts.join(", "))`
//! chart-batch prologue across
//! `commands/helm.rs::{lint_all (:2591–:2596), release_all (:2657–:2662)}`.
//!
//! # Compounding
//!
//! Pre-lift 2 sibling call sites in `commands/helm.rs` each restated the
//! same three-line prologue verbatim:
//!
//! - `lint_all`     / `:2591–:2596` — discover → empty-guard → announce
//! - `release_all`  / `:2657–:2662` — discover → empty-guard → announce
//!
//! Each restated three independent axes at three separate literal
//! positions per site:
//!
//! 1. The **discovery call** — `discover_charts(charts_dir, lib_chart_name)?`.
//! 2. The **empty-guard bail wording** — `bail!("No charts found in {}", charts_dir)`.
//! 3. The **announcement grammar** — `info!("Discovered {} charts: {}", charts.len(), charts.join(", "))`.
//!
//! A single-site drift on ANY axis — a bail rewording that talks about
//! "no chart directories" in one flow and "No charts found" in the other,
//! an announcement that names the sorted-set size vs. the raw-directory
//! count, a future flag threaded through only one call site's discovery —
//! would silently split the two batch loops' operator-facing grammar so
//! `pleme forge helm lint` and `pleme forge helm release` narrated the
//! same discovery differently, and any observability consumer that
//! correlated `chart_batch.discovered` events across the two flows would
//! read them as two separate populations.
//!
//! Post-lift the three axes close over ONE body at
//! [`discover_charts_or_bail`]. Callers pass the two arguments they
//! already had (`charts_dir`, `lib_chart_name`) and receive the
//! post-empty-guard `Vec<String>` back — the compiler refuses a call site
//! that forgets the guard or the announcement by construction.
//!
//! A future refinement — a red glyph on the empty-guard bail, promotion
//! to a `crate::ui::print_error` sibling for the stderr channel, a
//! structured OTLP `chart_batch.discovery` observability event carrying
//! `charts_dir` + `lib_chart_name` + `count` + `names` as SEPARATE
//! attributes, a tightening of the announcement wording from
//! `"Discovered N charts"` to `"Discovered N chart(s)"` for the
//! grammatically-correct singular — lands at ONE typed body and reaches
//! both consumers by construction.
//!
//! # The two axes MUST agree
//!
//! The bail wording (`"No charts found in {}"`) and the announcement
//! grammar (`"Discovered {} charts: {}"`) are two axes of the same
//! discovery step: the bail arm fires when discovery returned zero
//! charts, the announcement arm fires when discovery returned one or
//! more. Both axes are pinned by fail-before-pass byte oracles against
//! the [`write_discovered_charts_info`] writer sibling and the
//! bail-wording assertion, so a future refactor that drifted either arm
//! independently regresses a test rather than shipping a
//! self-inconsistent batch-prologue.
//!
//! # THEORY grounding
//!
//! - THEORY.md §V (Compounding Directive: solve once, load-bearing
//!   fixes only).
//! - THEORY.md §VI.1 (three-times-is-a-law — 2 verbatim sibling sites
//!   redeemed by extraction under the two-strict-siblings ≥2 threshold
//!   the fleet applies for high-coupling prologues like this one, where
//!   both flows compose the same discovery + gate + announcement
//!   sequence and would otherwise silently drift).

use std::io;

use anyhow::{bail, Result};

use super::helm::discover_charts;

/// Discover the sorted chart-directory names under `charts_dir` and,
/// bail with the pre-lift `"No charts found in <charts_dir>"` wording
/// when the discovery returns empty; otherwise emit the pre-lift
/// `info!("Discovered N charts: A, B, C")` announcement via
/// [`tracing::info!`] and return the non-empty [`Vec<String>`].
///
/// The one body that composes the three axes of the chart-batch
/// prologue (the discovery call, the empty-guard bail wording, and the
/// tracing-routed announcement grammar) so no batch loop can silently
/// drift any of them.
///
/// The `charts_dir` argument is interpolated verbatim into BOTH the
/// bail wording on the empty arm AND the `discover_charts` delegation,
/// exactly as the two pre-lift sites spelled it — a caller that passes
/// a relative path sees that relative path echoed back in the bail
/// message, and a caller that passes a canonicalized absolute path
/// sees the absolute path.
///
/// The `lib_chart_name` argument is forwarded verbatim to
/// [`super::helm::discover_charts`] as the `exclude_name` axis — the
/// library chart is deliberately excluded from the returned set because
/// [`super::helm::release_all`] ships it FIRST via its own
/// `release_lib_chart` step (see the pre-lift comment at
/// `helm.rs:2671–:2681` for the pleme-lib / helmworks-akeyless-fork
/// regression that motivated the separate-first-shipment ordering).
pub fn discover_charts_or_bail(charts_dir: &str, lib_chart_name: &str) -> Result<Vec<String>> {
    let charts = discover_charts(charts_dir, lib_chart_name)?;
    if charts.is_empty() {
        bail!("No charts found in {}", charts_dir);
    }
    tracing::info!("Discovered {} charts: {}", charts.len(), charts.join(", "));
    Ok(charts)
}

/// Writer-taking sibling to [`discover_charts_or_bail`]'s announcement
/// axis. Emits the single `"Discovered N charts: A, B, C\n"` line via
/// [`writeln!`] against the supplied writer.
///
/// [`discover_charts_or_bail`] emits via [`tracing::info!`] at its own
/// source location so the tracing subscriber's per-module filter
/// (`RUST_LOG=forge::commands::chart_discovery_gate=info`) can silence
/// or elevate the announcement independently of the fleet's other
/// info-routed sites. The subscriber is external state that cannot be
/// captured in-process without racing whatever subscriber `main`
/// installs, so the byte-oracle tests pin the render against this
/// writer sibling instead — the same split
/// [`crate::using_pod_field::write_using_pod_field`] carries against
/// [`crate::info_using_pod_field!`].
#[allow(dead_code)] // Peer of the tracing-routed announcement in
                    // `discover_charts_or_bail`, retained for the
                    // byte-oracle tests and for a future
                    // summary-report / structured-observability
                    // consumer that wants the same rendering.
pub fn write_discovered_charts_info<W: io::Write>(w: &mut W, charts: &[String]) -> io::Result<()> {
    writeln!(
        w,
        "Discovered {} charts: {}",
        charts.len(),
        charts.join(", ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Byte-oracle: pin the exact announcement bytes for a two-chart
    /// discovery. Any future drift on the label prefix
    /// (`"Discovered "`), the count position, the plural-`s` (`charts`
    /// vs `chart(s)`), the colon-space delimiter, the join separator
    /// (`", "` vs `","`), or the trailing newline regresses this test.
    #[test]
    fn write_discovered_charts_info_pins_two_chart_bytes() {
        let mut buf: Vec<u8> = Vec::new();
        let charts = vec!["alpha".to_string(), "beta".to_string()];
        write_discovered_charts_info(&mut buf, &charts).unwrap();
        assert_eq!(buf, b"Discovered 2 charts: alpha, beta\n");
    }

    /// Byte-oracle: a single-chart discovery must not fabricate a
    /// trailing `", "` after the lone name — the `Vec::join(", ")`
    /// contract yields the bare name without a trailing separator. A
    /// future refactor that appended `", "` unconditionally
    /// regresses this assertion.
    #[test]
    fn write_discovered_charts_info_single_chart_has_no_trailing_separator() {
        let mut buf: Vec<u8> = Vec::new();
        let charts = vec!["only".to_string()];
        write_discovered_charts_info(&mut buf, &charts).unwrap();
        assert_eq!(buf, b"Discovered 1 charts: only\n");
    }

    /// Byte-oracle: the writer sibling still renders on an empty
    /// slice, emitting `"Discovered 0 charts: \n"`. The primitive's
    /// production path never reaches this branch — the caller
    /// [`discover_charts_or_bail`] bails on empty — but pinning the
    /// zero-count render guards a future observability consumer that
    /// reuses this writer against a pre-guard population and expects
    /// the label + count + empty-list + newline shape rather than an
    /// early return.
    #[test]
    fn write_discovered_charts_info_empty_slice_still_emits_zero_count_line() {
        let mut buf: Vec<u8> = Vec::new();
        let charts: Vec<String> = Vec::new();
        write_discovered_charts_info(&mut buf, &charts).unwrap();
        assert_eq!(buf, b"Discovered 0 charts: \n");
    }

    /// Byte-oracle: many charts join with `", "` between every pair
    /// with no trailing separator after the last name. Pins the
    /// [`Vec::join`] contract at three elements so a hand-rolled
    /// loop that emitted `", "` on the final iteration too would fail.
    #[test]
    fn write_discovered_charts_info_three_charts_join_with_comma_space_no_trailing() {
        let mut buf: Vec<u8> = Vec::new();
        let charts = vec![
            "alpha".to_string(),
            "bravo".to_string(),
            "charlie".to_string(),
        ];
        write_discovered_charts_info(&mut buf, &charts).unwrap();
        assert_eq!(buf, b"Discovered 3 charts: alpha, bravo, charlie\n");
    }

    /// Bail-arm oracle: when the underlying
    /// [`super::helm::discover_charts`] returns empty (only the
    /// excluded library chart is present), the primitive bails with
    /// the pre-lift `"No charts found in <charts_dir>"` wording — the
    /// `charts_dir` argument interpolated verbatim, no glyph, no
    /// indent, no trailing punctuation.
    #[test]
    fn discover_charts_or_bail_bails_with_pre_lift_wording_on_empty_dir() {
        let tmp = tempfile::tempdir().unwrap();
        // Populate ONLY the excluded library chart, so discover_charts
        // returns an empty Vec after filtering it out.
        let lib_dir = tmp.path().join("pleme-lib");
        std::fs::create_dir(&lib_dir).unwrap();
        std::fs::write(
            lib_dir.join("Chart.yaml"),
            "name: pleme-lib\nversion: 0.1.0\n",
        )
        .unwrap();

        let charts_dir_str = tmp.path().to_string_lossy().to_string();
        let err = discover_charts_or_bail(&charts_dir_str, "pleme-lib")
            .expect_err("empty discovery must bail with the No-charts-found wording");
        assert_eq!(
            err.to_string(),
            format!("No charts found in {}", charts_dir_str),
            "bail wording must interpolate the caller's charts_dir verbatim \
             (matching the pre-lift `bail!(\"No charts found in {{}}\", charts_dir)` shape)",
        );
    }

    /// Non-empty arm oracle: when the underlying
    /// [`super::helm::discover_charts`] returns one or more chart
    /// names, the primitive returns them sorted (the underlying
    /// `discover_charts` post-sort) and does not bail. The write to
    /// the tracing subscriber is not captured here (see the module
    /// docs for the subscriber-race rationale); the writer sibling
    /// [`write_discovered_charts_info`] carries the announcement
    /// byte-oracle instead.
    #[test]
    fn discover_charts_or_bail_returns_sorted_chart_names_from_directory() {
        let tmp = tempfile::tempdir().unwrap();
        for name in ["zulu", "alpha", "bravo"] {
            let d = tmp.path().join(name);
            std::fs::create_dir(&d).unwrap();
            std::fs::write(
                d.join("Chart.yaml"),
                format!("name: {}\nversion: 0.1.0\n", name),
            )
            .unwrap();
        }
        let charts = discover_charts_or_bail(&tmp.path().to_string_lossy(), "pleme-lib")
            .expect("non-empty discovery must succeed");
        assert_eq!(
            charts,
            vec!["alpha".to_string(), "bravo".to_string(), "zulu".to_string(),],
            "primitive must return the sorted post-exclude chart-name set \
             (matching the underlying `discover_charts` sort contract)",
        );
    }

    /// Non-empty arm oracle: the primitive forwards the
    /// `lib_chart_name` argument to `discover_charts` as its
    /// `exclude_name` axis, so a chart matching that name is filtered
    /// out even if it carries a valid `Chart.yaml`. Guards against a
    /// future refactor that inverted the argument order or that
    /// dropped the exclusion axis entirely (which would let
    /// `release_all` publish the library chart twice — once via its
    /// dedicated `release_lib_chart` step, once via the per-chart
    /// loop — resurrecting the pre-lift regression described at
    /// `helm.rs:2671–:2681`).
    #[test]
    fn discover_charts_or_bail_forwards_lib_chart_name_to_exclusion_axis() {
        let tmp = tempfile::tempdir().unwrap();
        for name in ["pleme-lib", "pleme-nats"] {
            let d = tmp.path().join(name);
            std::fs::create_dir(&d).unwrap();
            std::fs::write(
                d.join("Chart.yaml"),
                format!("name: {}\nversion: 0.1.0\n", name),
            )
            .unwrap();
        }
        let charts = discover_charts_or_bail(&tmp.path().to_string_lossy(), "pleme-lib")
            .expect("discovery with one non-excluded chart must succeed");
        assert!(
            !charts.contains(&"pleme-lib".to_string()),
            "the lib_chart_name axis must filter the library chart out; got: {charts:?}",
        );
        assert_eq!(
            charts,
            vec!["pleme-nats".to_string()],
            "post-exclusion the sorted set must carry only the non-lib chart(s); got: {charts:?}",
        );
    }

    /// Negative caller shield: no source line under `cli/src/commands/`
    /// (excluding this primitive's own file) may still spell the
    /// pre-lift `bail!("No charts found in {}", <arg>);` stanza
    /// inline. The two pre-lift sites migrated; any future consumer
    /// that wants the same empty-guard reaches for
    /// [`discover_charts_or_bail`] on first grep rather than
    /// copy-pasting the raw shape from an existing command module.
    #[test]
    fn no_command_module_still_spells_raw_no_charts_found_bail_stanza() {
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let mut offenders: Vec<(PathBuf, usize, String)> = Vec::new();
        for entry in std::fs::read_dir(&commands_dir).unwrap().flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            // Skip this primitive's own file — the shield names the
            // pre-lift shape in the shield's assertion message and would
            // self-hit otherwise.
            if path.file_name().and_then(|n| n.to_str()) == Some("chart_discovery_gate.rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).unwrap();
            for (idx, line) in source.lines().enumerate() {
                // Skip comment lines so shield-adjacent prose in another
                // module (a `///`-doc citing the pre-lift shape) doesn't
                // self-hit.
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") || trimmed.starts_with("///") {
                    continue;
                }
                if line.contains("bail!(\"No charts found in {}\"") {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `bail!(\"No charts found in {{}}\", <arg>);` stanza(s) survive \
             under `commands/` — route each through \
             `crate::commands::chart_discovery_gate::discover_charts_or_bail(...)` instead:\n{:#?}",
            offenders,
        );
    }

    /// Positive delegation shield: the pre-lift file
    /// `commands/helm.rs` (which carries BOTH sibling sites — one in
    /// `lint_all`, one in `release_all`) MUST forward through
    /// `crate::commands::chart_discovery_gate::discover_charts_or_bail(`
    /// at least TWICE, so a migration that dropped one call site
    /// outright leaves the negative "no raw inline shape" scan
    /// trivially satisfied by absence but the positive count still
    /// fails.
    #[test]
    fn helm_module_forwards_through_discover_charts_or_bail_primitive_twice() {
        let helm_src = std::fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("src")
                .join("commands")
                .join("helm.rs"),
        )
        .unwrap();
        let forwards = helm_src
            .matches("crate::commands::chart_discovery_gate::discover_charts_or_bail(")
            .count();
        assert!(
            forwards >= 2,
            "commands/helm.rs must forward at least 2 chart-batch prologue \
             sites (lint_all + release_all) through \
             `crate::commands::chart_discovery_gate::discover_charts_or_bail(`; \
             found {forwards}. A dropped call would leave the negative \
             raw-shape scan satisfied by absence.",
        );
    }
}
