//! Frontend-lint diagnostic-collection primitive — the "walk the
//! first 15 lines of a captured lint stream, print + collect every
//! error / warning / `✖`-carrying row" grammar the two sibling failure
//! branches of `commands/frontend_validation.rs::{run_lint_with_config
//! (ESLint arm), run_biome_lint (check arm)}` respell byte-for-byte
//! pre-lift.
//!
//! # Pre-lift census — two byte-identical stanzas
//!
//! Both stanzas were 7 lines long and byte-for-byte identical:
//!
//! ```ignore
//! // Collect error/warning lines for summary details
//! let mut details = Vec::new();
//! for line in combined.lines().take(15) {
//!     if line.contains("error") || line.contains("warning") || line.contains("✖") {
//!         crate::ui::print_diagnostic_line(line);
//!         details.push(line.to_string());
//!     }
//! }
//! ```
//!
//! 1. `commands/frontend_validation.rs::run_lint_with_config` (line
//!    258-264, pre-lift) — the ESLint `bun run lint` failure branch,
//!    after the `print_step_failure(&format!("{} failed ({} errors, {}
//!    warnings, {:.1}s)", …))` header. `combined` here is the joined
//!    `stdout + stderr` of the ESLint spawn.
//! 2. `commands/frontend_validation.rs::run_biome_lint` (line 346-352,
//!    pre-lift) — the Biome `bun x biome check src` failure branch,
//!    after the `print_step_failure(&format!("Biome check failed ({}
//!    errors, {} warnings, {:.1}s)", …))` header. `combined` here is
//!    the joined `stdout + stderr` of the biome-check spawn.
//!
//! Both sites feed a `Vec<String>` of the matched rows back to the
//! outer `Ok((false, details))` return, which the pre-release summary
//! renderer at [`crate::commands::prerelease`] shows to the operator.
//! Post-lift both consumers route through [`print_and_collect_lint_diagnostic_lines`];
//! a future refinement of the collection grammar — a bump of the cap
//! from 15 to 25, a swap of the three-keyword filter for a
//! syntax-aware structured-diagnostic parser, a promotion of the print
//! to a JSON-line emit under structured observability, or an OTLP
//! `lint_diagnostic_captured` span — lands at ONE typed body and
//! reaches both consumers by construction.
//!
//! # Two axes, both currently collapsed
//!
//! Pre-lift the two sites shared BOTH the cap (`15`) and the
//! three-keyword predicate (`["error", "warning", "✖"]`) verbatim, so
//! this primitive currently accepts only `combined: &str` and hard-
//! codes both. If a future third consumer (say, a `tsc --noEmit`
//! failure branch) needs a different cap or keyword set, the two axes
//! promote to parameters at that call — until then, keeping both fixed
//! removes an entire family of caller-side drift (a call with `cap =
//! 10` producing a report shorter than its sibling's for the same
//! underlying tool output).
//!
//! # Distinct from every peer diagnostic-collection helper
//!
//! - [`crate::ui::print_diagnostic_line`] emits ONE indented row and
//!   is the per-line adapter this primitive consumes internally. This
//!   primitive owns the LOOP + CAP + FILTER + COLLECT algebra above
//!   that adapter.
//! - `commands/prerelease.rs::run_e2e_gate`'s in-body `for line in
//!   stderr.lines().rev().take(50).collect::<Vec<_>>().into_iter().rev()`
//!   loop is a DISTINCT shape — it takes the LAST 50 lines (not the
//!   first 15), uses a per-line severity classifier (`FAILED` /
//!   `panicked` / `error` → red highlight; else plain), and does NOT
//!   return the matched lines as a `Vec<String>` (it prints only). A
//!   future lift would produce a separate `crate::e2e_tail_diagnostic_
//!   collect` primitive.
//! - `run_biome_lint`'s auto-fix-failed branch has an even simpler
//!   `for line in stderr.lines().take(5) { print_diagnostic_line(line); }`
//!   (no filter, no collect, cap = 5) — also OUT OF SCOPE.
//!
//! # THEORY grounding
//!
//! - `THEORY.md §I.5` (duplication budget zero): two byte-identical
//!   7-line stanzas across two failure branches were past the two-
//!   occurrence coincidence threshold. Post-lift the primitive owns
//!   the grammar at ONE construction surface.
//! - `THEORY.md §V.2` (typed absorption): the "walk-cap-filter-print-
//!   collect" composition is a single named concept; both callers cite
//!   it rather than restating its five component steps.
//! - `THEORY.md §II.1` invariant 4 (closed enums are proofs of case-
//!   completeness) does NOT bind here — the three keywords are a slice,
//!   not a closed enum — because the keyword vocabulary is a matter of
//!   linter output convention (Biome / ESLint each use these three
//!   substrings), not a case-complete classification of a discrete
//!   domain.
//!
//! # Frontier grounding
//!
//! Bazel BEP's `TestSummary` event caps captured test output at a
//! configurable byte / line budget before the summary rolls out, so
//! the fleet-wide report renders in bounded time. This primitive is
//! the same shape at the CLI-ceremony surface: cap = 15 lines,
//! filter on three severity substrings, return the collected rows for
//! the higher-level `prerelease` summary to render alongside the
//! per-gate verdicts.

use std::io;

/// The cap on how many of `combined`'s leading lines the collection
/// walks before returning. Pre-lift both callers spelled `15`
/// verbatim in `combined.lines().take(15)`; post-lift the cap lives
/// at ONE constant so a future adjustment (a bump to `25` under a
/// deeper diagnostic budget, a drop to `10` under a tighter
/// terminal-fit budget) lands here.
pub(crate) const LINT_DIAGNOSTIC_LINE_CAP: usize = 15;

/// The three severity substrings the collection predicate matches
/// against. Pre-lift both callers spelled the same
/// `line.contains("error") || line.contains("warning") ||
/// line.contains("✖")` disjunction inline. Post-lift the keyword set
/// lives at ONE slice; a future addition (a `"⚠"` warning glyph
/// mirroring biome's own count on line 335, a `"panic"` promotion
/// under a broader classifier) lands here.
///
/// # Why a `&[&str]`, not a `[&str; 3]`
///
/// The array-length axis is not load-bearing at the caller site — the
/// caller only iterates for `.contains(kw)`, not by index — and a
/// slice keeps the callers' `.iter().any(...)` predicate typed against
/// `&&str` uniformly whether the constant grows or shrinks. A `&[&str;
/// 3]` would leak the exact count into every consumer's type-checked
/// call and force a coordinated bump on any future keyword-list edit.
pub(crate) const LINT_DIAGNOSTIC_KEYWORDS: &[&str] = &["error", "warning", "✖"];

/// Walk the first [`LINT_DIAGNOSTIC_LINE_CAP`] lines of `combined`,
/// print each line whose text contains any of the
/// [`LINT_DIAGNOSTIC_KEYWORDS`] via [`crate::ui::print_diagnostic_line`],
/// and return the matched lines as owned `String`s.
///
/// This is the stdout adapter over [`write_lint_diagnostic_lines`];
/// the writer split exists so the byte-oracle test can pin the exact
/// `"   <line>\n"` rendering of every matched row without capturing
/// stdout.
///
/// # Pre-lift consumers
///
/// - `commands/frontend_validation.rs::run_lint_with_config` (ESLint
///   arm failure branch)
/// - `commands/frontend_validation.rs::run_biome_lint` (check-arm
///   failure branch)
///
/// Both delegate through this function post-lift; the pre-lift 7-line
/// inline stanza no longer respells at either site.
pub fn print_and_collect_lint_diagnostic_lines(combined: &str) -> Vec<String> {
    let mut sink = io::stdout().lock();
    write_lint_diagnostic_lines(&mut sink, combined).unwrap_or_else(|_| {
        // A stdout write failure at the diagnostic-print step is not
        // load-bearing: the caller still needs the `Vec<String>` back
        // for the summary renderer. Re-run the pure classification
        // without any print side-effect and return the same rows the
        // successful path would have collected.
        collect_lint_diagnostic_lines(combined)
    })
}

/// Writer-taking sibling to [`print_and_collect_lint_diagnostic_lines`].
///
/// For each line in the first [`LINT_DIAGNOSTIC_LINE_CAP`] lines of
/// `combined` that contains any of the [`LINT_DIAGNOSTIC_KEYWORDS`],
/// writes `"   <line>\n"` to `w` via [`crate::ui::write_diagnostic_line`]
/// (matching the byte grammar the stdout adapter
/// [`crate::ui::print_diagnostic_line`] pins at
/// [`crate::ui::write_diagnostic_line`]) and pushes the line's owned
/// `String` into the returned `Vec<String>`.
///
/// # Byte shape
///
/// For a `combined` whose first-15-lines subset contains matches
/// `["A error", "B warning", "C ✖"]`, this writes exactly
/// `"   A error\n   B warning\n   C ✖\n"` to `w` and returns
/// `vec!["A error", "B warning", "C ✖"]`. The three-space indent, the
/// per-line trailing `\n`, and the ABSENCE of every `\x1b[<..>m` ANSI
/// palette sequence are inherited unchanged from
/// [`crate::ui::write_diagnostic_line`].
pub fn write_lint_diagnostic_lines<W: io::Write>(
    w: &mut W,
    combined: &str,
) -> io::Result<Vec<String>> {
    let mut details = Vec::new();
    for line in combined.lines().take(LINT_DIAGNOSTIC_LINE_CAP) {
        if LINT_DIAGNOSTIC_KEYWORDS.iter().any(|kw| line.contains(*kw)) {
            crate::ui::write_diagnostic_line(w, line)?;
            details.push(line.to_string());
        }
    }
    Ok(details)
}

/// Pure classifier: return the matched rows of `combined` under the
/// same [`LINT_DIAGNOSTIC_LINE_CAP`] + [`LINT_DIAGNOSTIC_KEYWORDS`]
/// contract, WITHOUT emitting anything to any sink. Used as the
/// fallback path in [`print_and_collect_lint_diagnostic_lines`] when
/// the stdout write itself fails, so the caller still gets its
/// `Vec<String>` for the summary render.
fn collect_lint_diagnostic_lines(combined: &str) -> Vec<String> {
    combined
        .lines()
        .take(LINT_DIAGNOSTIC_LINE_CAP)
        .filter(|line| LINT_DIAGNOSTIC_KEYWORDS.iter().any(|kw| line.contains(*kw)))
        .map(|line| line.to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-oracle: the writer sibling emits the exact `"   <line>\n"`
    /// rendering for each matched row and returns the matched lines
    /// as owned strings, in walk order.
    #[test]
    fn write_lint_diagnostic_lines_emits_three_space_indent_and_returns_matches_in_order() {
        let combined = "\
harmless preamble
2 errors reported here
still fine
1 warning found
sneaky ✖ marker line
plain tail
";
        let mut sink: Vec<u8> = Vec::new();
        let details = write_lint_diagnostic_lines(&mut sink, combined).unwrap();
        assert_eq!(
            String::from_utf8(sink).unwrap(),
            "   2 errors reported here\n   1 warning found\n   sneaky ✖ marker line\n",
        );
        assert_eq!(
            details,
            vec![
                "2 errors reported here".to_string(),
                "1 warning found".to_string(),
                "sneaky ✖ marker line".to_string(),
            ],
        );
    }

    /// Cap-oracle: the walk stops at [`LINT_DIAGNOSTIC_LINE_CAP`]
    /// input lines. A match on line 16 or later never emits and never
    /// enters `details`, matching the pre-lift `.take(15)` cut-off at
    /// both consumer sites.
    #[test]
    fn write_lint_diagnostic_lines_stops_at_line_cap() {
        assert_eq!(LINT_DIAGNOSTIC_LINE_CAP, 15);
        let mut lines: Vec<String> = (0..14).map(|_| "quiet".to_string()).collect();
        // Line 15 (0-indexed 14) — the last one inside the cap.
        lines.push("boundary error inside cap".to_string());
        // Line 16 (0-indexed 15) — the first one past the cap.
        lines.push("past-cap error must not print".to_string());
        // Line 17 — belt-and-suspenders.
        lines.push("another past-cap ✖ marker".to_string());
        let combined = lines.join("\n");

        let mut sink: Vec<u8> = Vec::new();
        let details = write_lint_diagnostic_lines(&mut sink, &combined).unwrap();
        assert_eq!(
            String::from_utf8(sink).unwrap(),
            "   boundary error inside cap\n",
        );
        assert_eq!(details, vec!["boundary error inside cap".to_string()]);
    }

    /// Predicate-oracle: each of the three keywords in
    /// [`LINT_DIAGNOSTIC_KEYWORDS`] matches independently. A line
    /// containing ONLY `"error"` matches; a line containing ONLY
    /// `"warning"` matches; a line containing ONLY `"✖"` matches; a
    /// line containing none of the three does not match.
    #[test]
    fn write_lint_diagnostic_lines_matches_each_keyword_independently() {
        assert_eq!(LINT_DIAGNOSTIC_KEYWORDS, &["error", "warning", "✖"]);
        let combined = "\
error alone
warning alone
✖ alone
none of the three keywords
";
        let mut sink: Vec<u8> = Vec::new();
        let details = write_lint_diagnostic_lines(&mut sink, combined).unwrap();
        assert_eq!(
            details,
            vec![
                "error alone".to_string(),
                "warning alone".to_string(),
                "✖ alone".to_string(),
            ],
        );
        assert_eq!(
            String::from_utf8(sink).unwrap(),
            "   error alone\n   warning alone\n   ✖ alone\n",
        );
    }

    /// Empty-input oracle: no input, no output, no matches. Preserves
    /// the pre-lift `Vec::new()` initialiser + zero-iteration loop
    /// behavior at both consumer sites when the linter's captured
    /// stream is empty.
    #[test]
    fn write_lint_diagnostic_lines_on_empty_input_returns_empty_vec_and_writes_nothing() {
        let mut sink: Vec<u8> = Vec::new();
        let details = write_lint_diagnostic_lines(&mut sink, "").unwrap();
        assert!(details.is_empty());
        assert!(sink.is_empty());
    }

    /// No-match oracle: an input with `LINT_DIAGNOSTIC_LINE_CAP` lines
    /// none of which contains any keyword produces zero output and
    /// zero collected rows — the walk completes to the cap and then
    /// stops, matching the pre-lift `.take(15)` exhaustive-walk
    /// behavior when no line qualifies.
    #[test]
    fn write_lint_diagnostic_lines_on_no_match_input_writes_nothing() {
        let combined = (0..LINT_DIAGNOSTIC_LINE_CAP)
            .map(|_| "plain")
            .collect::<Vec<_>>()
            .join("\n");
        let mut sink: Vec<u8> = Vec::new();
        let details = write_lint_diagnostic_lines(&mut sink, &combined).unwrap();
        assert!(details.is_empty());
        assert!(sink.is_empty());
    }

    /// Order preservation: matched lines emerge in the same order they
    /// appear in `combined`. The primitive is a walk-and-filter, not
    /// a re-sort, so the pre-lift caller's per-severity display
    /// ordering (as it appears in the tool's output) is preserved.
    #[test]
    fn write_lint_diagnostic_lines_preserves_input_order() {
        let combined = "\
✖ first
warning second
error third
";
        let mut sink: Vec<u8> = Vec::new();
        let details = write_lint_diagnostic_lines(&mut sink, combined).unwrap();
        assert_eq!(
            details,
            vec![
                "✖ first".to_string(),
                "warning second".to_string(),
                "error third".to_string(),
            ],
        );
    }

    /// The pure classifier [`collect_lint_diagnostic_lines`] returns
    /// the same rows [`write_lint_diagnostic_lines`] would collect,
    /// without any side effect. Pins the "write-failed-fallback"
    /// equivalence [`print_and_collect_lint_diagnostic_lines`]
    /// depends on: a stdout write error must not corrupt the returned
    /// `Vec<String>` the caller passes to the summary renderer.
    #[test]
    fn collect_lint_diagnostic_lines_matches_writer_sibling_on_the_same_input() {
        let combined = "\
alpha error
beta plain
gamma warning
delta ✖
epsilon nothing
";
        let mut sink: Vec<u8> = Vec::new();
        let via_writer = write_lint_diagnostic_lines(&mut sink, combined).unwrap();
        let via_collector = collect_lint_diagnostic_lines(combined);
        assert_eq!(via_writer, via_collector);
    }

    /// Caller shield (negative half): no `.rs` file under
    /// `cli/src/commands/` may spell the pre-lift raw
    /// `.lines().take(15)` walk-and-cap composition inline any more.
    /// The two `commands/frontend_validation.rs` sites migrated; a
    /// future consumer that wants the same walk reaches for
    /// [`print_and_collect_lint_diagnostic_lines`] on first grep, not
    /// by copy-pasting the `.take(15)` literal.
    ///
    /// The shield's own docstring mention of `.lines().take(15)` above
    /// (and the identical mention inside the `#[cfg(test)] mod tests`
    /// block that houses THIS assertion) stays out of scope because
    /// the walk targets `cli/src/commands/`, and this module lives at
    /// `cli/src/` — one directory up.
    #[test]
    fn no_command_module_still_spells_raw_lines_take_15() {
        use std::path::PathBuf as StdPathBuf;
        let commands_dir = StdPathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let needle = ".lines().take(15)";
        let mut offenders: Vec<(StdPathBuf, usize, String)> = Vec::new();
        for entry in std::fs::read_dir(&commands_dir).unwrap().flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).unwrap();
            for (idx, line) in source.lines().enumerate() {
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") || trimmed.starts_with("///") {
                    continue;
                }
                if line.contains(needle) {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `{needle}` walk survives under `commands/` — route each through \
             `crate::frontend_lint_diagnostic_collect::print_and_collect_lint_diagnostic_lines(\
             <combined>)` instead:\n{:#?}",
            offenders,
        );
    }

    /// Caller shield (positive half, migrated): the fused frontend-
    /// lint failure-report primitive at
    /// `cli/src/frontend_lint_failure_report.rs` must forward through
    /// [`print_and_collect_lint_diagnostic_lines`] exactly once — the
    /// two pre-lift `commands/frontend_validation.rs` sibling sites
    /// migrated onto that primitive, so the collection call now lands
    /// at ONE call site inside the failure-report primitive (its
    /// `report_frontend_lint_failure` body), not at the two consumer
    /// sites in `commands/frontend_validation.rs`.
    ///
    /// A count of `0` at the new target means the primitive's body
    /// dropped its forward through the collection pass (a re-inline
    /// or a rename without updating the composition); a count above
    /// `1` at that target means the primitive's body spawned a
    /// duplicate collection pass the fusion was supposed to
    /// eliminate.
    ///
    /// A stray forward-through in `commands/frontend_validation.rs`
    /// itself means a caller re-adopted the collection call inline
    /// and bypassed the failure-report primitive — the negative half
    /// of this shield.
    #[test]
    fn frontend_lint_failure_report_forwards_through_diagnostic_collect_primitive() {
        use std::path::PathBuf as StdPathBuf;
        let needle = "print_and_collect_lint_diagnostic_lines(";
        // Positive: the primitive's body carries exactly one forward.
        let primitive_path = StdPathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("frontend_lint_failure_report.rs");
        let primitive_source = std::fs::read_to_string(&primitive_path).unwrap();
        let primitive_forwards = primitive_source
            .lines()
            .filter(|line| {
                let trimmed = line.trim_start();
                !trimmed.starts_with("//") && !trimmed.starts_with("///")
            })
            .filter(|line| line.contains(needle))
            .count();
        assert_eq!(
            primitive_forwards, 1,
            "cli/src/frontend_lint_failure_report.rs must forward the \
             lint-diagnostic collection pass through `{needle}` exactly \
             once (in `report_frontend_lint_failure`); found \
             {primitive_forwards}. A count of 0 means the primitive \
             dropped its forward-through; a count above 1 means the \
             primitive's body spawned a duplicate collection pass the \
             fusion was supposed to eliminate."
        );
        // Negative: the pre-lift consumer file must no longer respell
        // the collection call inline — every consumer now reaches the
        // failure-report primitive, which owns the sole collection
        // forward.
        let consumer_path = StdPathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands")
            .join("frontend_validation.rs");
        let consumer_source = std::fs::read_to_string(&consumer_path).unwrap();
        let consumer_forwards = consumer_source
            .lines()
            .filter(|line| {
                let trimmed = line.trim_start();
                !trimmed.starts_with("//") && !trimmed.starts_with("///")
            })
            .filter(|line| line.contains(needle))
            .count();
        assert_eq!(
            consumer_forwards, 0,
            "commands/frontend_validation.rs must NOT respell the \
             lint-diagnostic collection call inline any more — the two \
             pre-lift sites migrated onto \
             `crate::frontend_lint_failure_report::report_frontend_lint_failure(` \
             which now owns the sole `{needle}` forward. \
             Found {consumer_forwards} respell(s)."
        );
    }
}
