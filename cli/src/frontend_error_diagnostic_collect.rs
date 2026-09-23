//! Frontend error-diagnostic collection primitive — the "walk the
//! first 20 lines of a captured frontend output stream, print + collect
//! every keyword-carrying row through the RED
//! [`crate::ui::print_diagnostic_error_line`] highlight grammar"
//! primitive shared across
//! `commands/frontend_validation.rs::{run_type_check,run_unit_tests}`.
//!
//! # Pre-lift census — two byte-identical stanzas, keyword-parameterized
//!
//! Both pre-lift stanzas were 7 lines long, walked the SAME cap of `20`
//! leading lines of a `combined` output stream, and shared the SAME
//! print-and-collect body — the only differences were (a) the keyword
//! slice fed to the `line.contains(<kw>)` disjunction and (b) whether
//! the walk was spelled `combined.lines().take(20)` or
//! `let lines: Vec<&str> = combined.lines().collect(); for &line in
//! lines.iter().take(20)`.
//!
//! ```ignore
//! // run_type_check (pre-lift ~L190-198):
//! let mut details = Vec::new();
//! for line in combined.lines().take(20) {
//!     if line.contains("error") || line.contains("Error") {
//!         crate::ui::print_diagnostic_error_line(line);
//!         details.push(line.to_string());
//!     }
//! }
//! ```
//!
//! ```ignore
//! // run_unit_tests (pre-lift ~L385-392):
//! let mut details = Vec::new();
//! let lines: Vec<&str> = combined.lines().collect();
//! for &line in lines.iter().take(20) {
//!     if line.contains("FAIL") || line.contains("Error") || line.contains("✕") {
//!         crate::ui::print_diagnostic_error_line(line);
//!         details.push(line.to_string());
//!     }
//! }
//! ```
//!
//! 1. `commands/frontend_validation.rs::run_type_check` (pre-lift
//!    ~L190-198) — the TypeScript type-check failure branch, after the
//!    `print_step_failure(&msg_with_count_noun_secs_1("Type check failed",
//!    error_count, "errors", duration))` header. `combined` here is
//!    `format!("{}\n{}", stderr, stdout)` from the `bun run type-check`
//!    spawn; the pre-lift keyword slice was `["error", "Error"]`.
//! 2. `commands/frontend_validation.rs::run_unit_tests` (pre-lift
//!    ~L384-392) — the vitest unit-test failure branch, after the
//!    `print_step_failure_timed("Unit tests failed", duration)` header.
//!    `combined` here is `crate::repo::utf8_lossy_streams_joined(&output)`
//!    from the `bun run test -- --run` spawn; the pre-lift keyword
//!    slice was `["FAIL", "Error", "✕"]`. Pre-lift the site further
//!    materialised `let lines: Vec<&str> = combined.lines().collect();`
//!    before the `.iter().take(20)` walk — a redundant intermediate
//!    `Vec<&str>` allocation the walk-once form does not need.
//!
//! Both sites feed a `Vec<String>` of the matched rows back to the
//! outer `Ok((_, _, details))` return, which the pre-release summary
//! renderer at [`crate::commands::prerelease`] shows to the operator.
//! Post-lift both consumers route through
//! [`print_and_collect_error_diagnostic_lines`]; a future refinement of
//! the collection grammar — a bump of the cap from 20 to 30 under a
//! deeper diagnostic budget, a swap of the print for a JSON-line emit
//! under structured observability, or an OTLP
//! `frontend_diagnostic_captured` span — lands at ONE typed body and
//! reaches both consumers by construction.
//!
//! # One axis fixed, one axis parameterized
//!
//! Pre-lift both sites shared the cap (`20`) verbatim but carried
//! DIFFERENT keyword slices — `["error", "Error"]` vs
//! `["FAIL", "Error", "✕"]`. The cap is a shared invariant; the keyword
//! slice is a caller-owned classification of what "counts as failure"
//! in that tool's stderr dialect (vitest's `"FAIL"` / `"✕"` glyphs vs
//! `tsc`'s `"error"` prose). So this primitive hard-codes the cap at
//! ONE constant ([`FRONTEND_ERROR_DIAGNOSTIC_LINE_CAP`]) and takes the
//! keyword slice as a `&[&str]` argument. A future third consumer that
//! shares the cap (an ESLint highlight branch, a `bun x tsc` alt-invoke
//! branch, a `bun x vitest --reporter=verbose` re-run branch) reaches
//! this same primitive with its own keyword slice; a consumer with a
//! different cap promotes that axis to a parameter at that call.
//!
//! # Distinct from every peer diagnostic-collection helper
//!
//! - [`crate::frontend_lint_diagnostic_collect`] owns the LINT
//!   verification-branch grammar: cap = 15 lines, hard-coded
//!   `["error", "warning", "✖"]` keyword set, print via the PLAIN
//!   [`crate::ui::print_diagnostic_line`] adapter (uncolored). This
//!   primitive is its sibling for the ERROR-highlight branch: cap =
//!   20, caller-supplied keyword slice, print via the RED
//!   [`crate::ui::print_diagnostic_error_line`] adapter. Different cap,
//!   different keyword contract, DIFFERENT COLOR — the two live at
//!   distinct construction surfaces because a caller migrating a red
//!   error-branch stanza onto the plain-lint primitive would silently
//!   drop the `.red()` ANSI envelope and dim its own diagnostic-block
//!   header.
//! - [`crate::auto_fix_stderr_head_diagnostic`] owns the AUTO-FIX
//!   failure-branch grammar: cap = 5 lines, NO keyword filter (walks
//!   every leading line), print via the PLAIN
//!   [`crate::ui::print_diagnostic_line`] adapter. Different cap, no
//!   filter, different color — out of scope.
//! - [`crate::ui::print_diagnostic_error_line`] emits ONE indented
//!   red-highlighted row and is the per-line adapter this primitive
//!   consumes internally. This primitive owns the LOOP + CAP + FILTER
//!   + COLLECT algebra above that adapter.
//! - `commands/prerelease.rs::run_cargo_check` / `run_cargo_clippy`
//!   both walk `.take(10)` (not 20), print via the mixed
//!   `print_diagnostic_error_line` / `print_diagnostic_line` adapters
//!   depending on per-line severity, and do NOT collect the walked
//!   rows into a `Vec<String>`. Different cap, different color-dispatch
//!   discipline, print-only — out of scope.
//!
//! # THEORY grounding
//!
//! - `THEORY.md §I.5` (duplication budget zero): two sibling 7-line
//!   stanzas across two sibling failure branches in the same command
//!   module were past the two-occurrence coincidence threshold.
//!   Post-lift the primitive owns the walk-cap-filter-print-collect
//!   grammar at ONE construction surface.
//! - `THEORY.md §V.2` (typed absorption): the
//!   "walk-cap-filter-print-collect" composition is a single named
//!   concept; both callers cite it rather than restating its five
//!   component steps.
//! - `THEORY.md §III.1` (typescape as root data structure): the cap
//!   sits at ONE typed constant so a future adjustment reaches both
//!   consumers in lockstep, without a caller-side literal drift.
//!
//! # Frontier grounding
//!
//! Bazel BEP's `TestSummary` event caps captured test output at a
//! configurable byte / line budget before the summary rolls out, so the
//! fleet-wide report renders in bounded time. Buildkite's
//! `--stderr-tail` on failed steps prints only the last N lines of
//! stderr for the same reason. Dagger's `error.Details()` mirrors
//! Bazel BEP's cap-and-summarize discipline for its own step-failure
//! render. This primitive is the same shape at the frontend
//! diagnostic-collect surface — cap the head of a joined
//! stdout+stderr stream at 20 lines, filter on caller-owned keyword
//! substrings, return the collected rows for the higher-level
//! pre-release summary to render alongside the per-gate verdicts.

use std::io;

/// The cap on how many of `combined`'s leading lines the collection
/// walks before returning. Pre-lift both callers spelled `20` verbatim
/// in `.lines().take(20)` / `.iter().take(20)`; post-lift the cap lives
/// at ONE constant so a future adjustment (a bump to `30` under a
/// deeper diagnostic budget, a drop to `10` under a tighter
/// terminal-fit budget) lands here and reaches both consumers by
/// construction.
pub(crate) const FRONTEND_ERROR_DIAGNOSTIC_LINE_CAP: usize = 20;

/// Walk the first [`FRONTEND_ERROR_DIAGNOSTIC_LINE_CAP`] lines of
/// `combined`, print each line whose text contains any of the caller-
/// supplied `keywords` via [`crate::ui::print_diagnostic_error_line`]
/// (the RED-highlighted indented-row adapter), and return the matched
/// lines as owned `String`s for the caller's summary render.
///
/// This is the stdout adapter over [`write_error_diagnostic_lines`];
/// the writer split exists so the byte-oracle test can pin the exact
/// `"   <line.red()>\n"` rendering of every matched row without
/// capturing stdout.
///
/// On stdout write failure the caller still receives the matched rows
/// — a stdout write failure at the diagnostic-print step is not
/// load-bearing; the outer summary renderer still needs the
/// `Vec<String>` back to attach the failed-step details to its per-
/// gate verdict.
///
/// # Pre-lift consumers
///
/// - `commands/frontend_validation.rs::run_type_check` (TypeScript
///   type-check failure branch) — keyword slice `["error", "Error"]`.
/// - `commands/frontend_validation.rs::run_unit_tests` (vitest
///   unit-test failure branch) — keyword slice
///   `["FAIL", "Error", "✕"]`.
///
/// Both delegate through this function post-lift; the pre-lift 7-line
/// inline stanza no longer respells at either site.
pub fn print_and_collect_error_diagnostic_lines(combined: &str, keywords: &[&str]) -> Vec<String> {
    let mut sink = io::stdout().lock();
    write_error_diagnostic_lines(&mut sink, combined, keywords).unwrap_or_else(|_| {
        // A stdout write failure at the diagnostic-print step is not
        // load-bearing: the caller still needs the `Vec<String>` back
        // for the summary renderer. Re-run the pure classification
        // without any print side-effect and return the same rows the
        // successful path would have collected.
        collect_error_diagnostic_lines(combined, keywords)
    })
}

/// Writer-taking sibling to [`print_and_collect_error_diagnostic_lines`].
///
/// For each line in the first [`FRONTEND_ERROR_DIAGNOSTIC_LINE_CAP`]
/// lines of `combined` that contains any of `keywords`, writes
/// `"   <line.red()>\n"` to `w` via
/// [`crate::ui::write_diagnostic_error_line`] (matching the byte
/// grammar the stdout adapter [`crate::ui::print_diagnostic_error_line`]
/// pins) and pushes the line's owned `String` into the returned
/// `Vec<String>`.
///
/// # Byte shape
///
/// For a `combined` whose first-20-lines subset contains matches
/// `["A error", "B Error", "C fine"]` under keywords
/// `["error", "Error"]`, this writes exactly
/// `"   \x1b[31mA error\x1b[0m\n   \x1b[31mB Error\x1b[0m\n"` to `w`
/// (matching [`crate::ui::write_diagnostic_error_line`]'s three-space
/// indent + `.red()` ANSI envelope + trailing `\n` byte grammar) and
/// returns `vec!["A error", "B Error"]` (the third line `"C fine"` is
/// discarded because it matches no keyword). The three-space indent,
/// the per-line trailing `\n`, and the surrounding `\x1b[31m` /
/// `\x1b[0m` ANSI red palette sequences are inherited unchanged from
/// [`crate::ui::write_diagnostic_error_line`].
pub fn write_error_diagnostic_lines<W: io::Write>(
    w: &mut W,
    combined: &str,
    keywords: &[&str],
) -> io::Result<Vec<String>> {
    let mut details = Vec::new();
    for line in combined.lines().take(FRONTEND_ERROR_DIAGNOSTIC_LINE_CAP) {
        if keywords.iter().any(|kw| line.contains(*kw)) {
            crate::ui::write_diagnostic_error_line(w, line)?;
            details.push(line.to_string());
        }
    }
    Ok(details)
}

/// Pure classifier: return the matched rows of `combined` under the
/// same [`FRONTEND_ERROR_DIAGNOSTIC_LINE_CAP`] + caller-supplied
/// `keywords` contract, WITHOUT emitting anything to any sink. Used as
/// the fallback path in [`print_and_collect_error_diagnostic_lines`]
/// when the stdout write itself fails, so the caller still gets its
/// `Vec<String>` for the summary render.
fn collect_error_diagnostic_lines(combined: &str, keywords: &[&str]) -> Vec<String> {
    combined
        .lines()
        .take(FRONTEND_ERROR_DIAGNOSTIC_LINE_CAP)
        .filter(|line| keywords.iter().any(|kw| line.contains(*kw)))
        .map(|line| line.to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Serialize the ANSI-override toggle across every byte-oracle test
    /// in this module — [`colored::control::set_override`] is a global
    /// switch, so a parallel test that reads a `.red()` byte-shape while
    /// a sibling has flipped the override off would flap between the
    /// "ANSI on" and "ANSI off" arms. Same discipline the sibling
    /// `workflow_complete_banner.rs` / `workflow_intro_banner.rs` /
    /// `stage_completion_ack.rs` byte-oracle test modules apply for the
    /// same reason.
    static ANSI_OVERRIDE_LOCK: Mutex<()> = Mutex::new(());

    /// RAII guard that force-enables [`colored`] ANSI emission for the
    /// duration of a writer-level byte-oracle test — the colored crate
    /// otherwise strips ANSI sequences when the test binary's stdout is
    /// not a TTY, which would collapse `.red()` to a no-op and defeat
    /// the byte-shape assertions below.
    struct AnsiOverrideForTest {
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl AnsiOverrideForTest {
        fn acquire() -> Self {
            let lock = ANSI_OVERRIDE_LOCK
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            colored::control::set_override(true);
            Self { _lock: lock }
        }
    }

    impl Drop for AnsiOverrideForTest {
        fn drop(&mut self) {
            colored::control::unset_override();
        }
    }

    /// The cap pinned to the pre-lift `.take(20)` literal both consumer
    /// sites spelled. A change here rotates the byte-shape reachable at
    /// both post-lift consumers.
    #[test]
    fn test_frontend_error_diagnostic_line_cap_matches_pre_lift_literal() {
        assert_eq!(FRONTEND_ERROR_DIAGNOSTIC_LINE_CAP, 20);
    }

    /// Byte-oracle: the writer sibling emits the exact
    /// `"   <line.red()>\n"` rendering for each matched row and returns
    /// the matched lines as owned strings, in walk order. Pins the
    /// three-space indent, the `\x1b[31m` red ANSI envelope around the
    /// line body (never the indent), the per-line trailing newline, and
    /// the walk-order-preserving collect against the pre-lift 7-line
    /// stanza both consumer sites spelled.
    #[test]
    fn write_error_diagnostic_lines_emits_indented_red_and_returns_matches_in_order() {
        let _override_guard = AnsiOverrideForTest::acquire();
        let combined = "\
harmless preamble
error TS2322: Type 'string' is not assignable to type 'number'
still fine
Error: something else
plain tail
";
        let mut sink: Vec<u8> = Vec::new();
        let details = write_error_diagnostic_lines(&mut sink, combined, &["error", "Error"])
            .expect("write against a Vec<u8> writer must succeed");
        let out = String::from_utf8(sink).expect("writer emits valid UTF-8");
        assert_eq!(
            out,
            "   \u{1b}[31merror TS2322: Type 'string' is not assignable to type 'number'\u{1b}[0m\n   \u{1b}[31mError: something else\u{1b}[0m\n",
        );
        assert_eq!(
            details,
            vec![
                "error TS2322: Type 'string' is not assignable to type 'number'".to_string(),
                "Error: something else".to_string(),
            ],
        );
    }

    /// Cap-oracle: the walk stops at
    /// [`FRONTEND_ERROR_DIAGNOSTIC_LINE_CAP`] input lines. A match on
    /// line 21 or later never emits and never enters `details`,
    /// matching the pre-lift `.take(20)` cut-off at both consumer
    /// sites.
    #[test]
    fn write_error_diagnostic_lines_stops_at_line_cap() {
        let _override_guard = AnsiOverrideForTest::acquire();
        assert_eq!(FRONTEND_ERROR_DIAGNOSTIC_LINE_CAP, 20);
        let mut lines: Vec<String> = (0..19).map(|_| "quiet".to_string()).collect();
        // Line 20 (0-indexed 19) — the last one inside the cap.
        lines.push("boundary error inside cap".to_string());
        // Line 21 (0-indexed 20) — the first one past the cap.
        lines.push("past-cap error must not print".to_string());
        // Line 22 — belt-and-suspenders.
        lines.push("another past-cap Error line".to_string());
        let combined = lines.join("\n");

        let mut sink: Vec<u8> = Vec::new();
        let details = write_error_diagnostic_lines(&mut sink, &combined, &["error", "Error"])
            .expect("write against a Vec<u8> writer must succeed");
        assert_eq!(details, vec!["boundary error inside cap".to_string()]);
        let out = String::from_utf8(sink).expect("writer emits valid UTF-8");
        assert_eq!(out, "   \u{1b}[31mboundary error inside cap\u{1b}[0m\n",);
    }

    /// Predicate-oracle: each caller-supplied keyword matches
    /// independently, and a line containing none of the keywords does
    /// not match. Pins the "keyword slice is an ANY-of-them
    /// disjunction" contract both consumer sites spelled inline as
    /// `line.contains(A) || line.contains(B) || …`.
    #[test]
    fn write_error_diagnostic_lines_matches_each_caller_keyword_independently() {
        let combined = "\
FAIL alone
Error alone
✕ alone
none of the three keywords
";
        let mut sink: Vec<u8> = Vec::new();
        let details = write_error_diagnostic_lines(&mut sink, combined, &["FAIL", "Error", "✕"])
            .expect("write against a Vec<u8> writer must succeed");
        assert_eq!(
            details,
            vec![
                "FAIL alone".to_string(),
                "Error alone".to_string(),
                "✕ alone".to_string(),
            ],
        );
    }

    /// Empty-input oracle: no input, no output, no matches. Preserves
    /// the pre-lift `Vec::new()` initialiser + zero-iteration loop
    /// behavior at both consumer sites when the frontend tool's
    /// captured stream is empty.
    #[test]
    fn write_error_diagnostic_lines_on_empty_input_returns_empty_vec_and_writes_nothing() {
        let mut sink: Vec<u8> = Vec::new();
        let details = write_error_diagnostic_lines(&mut sink, "", &["error", "Error"]).unwrap();
        assert!(details.is_empty());
        assert!(sink.is_empty());
    }

    /// No-match oracle: an input with
    /// [`FRONTEND_ERROR_DIAGNOSTIC_LINE_CAP`] lines none of which
    /// contains any keyword produces zero output and zero collected
    /// rows — the walk completes to the cap and then stops, matching
    /// the pre-lift `.take(20)` exhaustive-walk behavior when no line
    /// qualifies.
    #[test]
    fn write_error_diagnostic_lines_on_no_match_input_writes_nothing() {
        let combined = (0..FRONTEND_ERROR_DIAGNOSTIC_LINE_CAP)
            .map(|_| "plain")
            .collect::<Vec<_>>()
            .join("\n");
        let mut sink: Vec<u8> = Vec::new();
        let details =
            write_error_diagnostic_lines(&mut sink, &combined, &["error", "Error"]).unwrap();
        assert!(details.is_empty());
        assert!(sink.is_empty());
    }

    /// Empty keyword slice: matches nothing. Pins the
    /// "no-keywords means no-matches" degenerate contract — a
    /// caller passing `&[]` gets an empty `Vec<String>` and an empty
    /// sink, rather than every line qualifying (which a naive
    /// `.any(|_| true)` fallback might produce).
    #[test]
    fn write_error_diagnostic_lines_on_empty_keywords_matches_nothing() {
        let combined = "\
first line
second line
third line
";
        let mut sink: Vec<u8> = Vec::new();
        let details = write_error_diagnostic_lines(&mut sink, combined, &[]).unwrap();
        assert!(details.is_empty());
        assert!(sink.is_empty());
    }

    /// Order preservation: matched lines emerge in the same order they
    /// appear in `combined`. The primitive is a walk-and-filter, not a
    /// re-sort, so the pre-lift caller's per-severity display ordering
    /// (as it appears in the tool's output) is preserved.
    #[test]
    fn write_error_diagnostic_lines_preserves_input_order() {
        let combined = "\
✕ first
Error second
FAIL third
";
        let mut sink: Vec<u8> = Vec::new();
        let details =
            write_error_diagnostic_lines(&mut sink, combined, &["FAIL", "Error", "✕"]).unwrap();
        assert_eq!(
            details,
            vec![
                "✕ first".to_string(),
                "Error second".to_string(),
                "FAIL third".to_string(),
            ],
        );
    }

    /// The pure classifier [`collect_error_diagnostic_lines`] returns
    /// the same rows [`write_error_diagnostic_lines`] would collect,
    /// without any side effect. Pins the "write-failed-fallback"
    /// equivalence [`print_and_collect_error_diagnostic_lines`] depends
    /// on: a stdout write error must not corrupt the returned
    /// `Vec<String>` the caller passes to the summary renderer.
    #[test]
    fn collect_error_diagnostic_lines_matches_writer_sibling_on_the_same_input() {
        let combined = "\
alpha error
beta plain
gamma Error
delta ✕
epsilon nothing
";
        let mut sink: Vec<u8> = Vec::new();
        let via_writer =
            write_error_diagnostic_lines(&mut sink, combined, &["error", "Error", "✕"]).unwrap();
        let via_collector = collect_error_diagnostic_lines(combined, &["error", "Error", "✕"]);
        assert_eq!(via_writer, via_collector);
    }

    /// Caller shield (negative half): no `.rs` file under
    /// `cli/src/commands/` may spell the pre-lift raw
    /// `.lines().take(20)` walk-and-cap composition inline any more.
    /// The two `commands/frontend_validation.rs` sites migrated; a
    /// future consumer that wants the same walk reaches for
    /// [`print_and_collect_error_diagnostic_lines`] on first grep, not
    /// by copy-pasting the `.take(20)` literal.
    ///
    /// Also refuses the pre-lift `.iter().take(20)` variant `run_unit_tests`
    /// spelled after materialising a `Vec<&str>` — the walk-once form
    /// this primitive commits to does not need the intermediate
    /// allocation, so re-inlining the `Vec<&str>` + `.iter()` chain is
    /// also out.
    ///
    /// The shield's own docstring mentions of `.lines().take(20)` /
    /// `.iter().take(20)` above stay out of scope because the walk
    /// targets `cli/src/commands/`, and this module lives at
    /// `cli/src/` — one directory up.
    #[test]
    fn no_command_module_still_spells_raw_lines_or_iter_take_20() {
        use std::path::PathBuf as StdPathBuf;
        let commands_dir = StdPathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let needles = [".lines().take(20)", ".iter().take(20)"];
        let mut offenders: Vec<(StdPathBuf, usize, String, &str)> = Vec::new();
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
                for needle in needles.iter() {
                    if line.contains(needle) {
                        offenders.push((path.clone(), idx + 1, line.to_string(), *needle));
                    }
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `.lines().take(20)` / `.iter().take(20)` walk survives under \
             `commands/` — route each through \
             `crate::frontend_error_diagnostic_collect::print_and_collect_error_diagnostic_lines(\
             <combined>, &[<keywords>])` instead:\n{:#?}",
            offenders,
        );
    }

    /// Caller shield (positive half): the two pre-lift
    /// `commands/frontend_validation.rs` sites now forward through
    /// [`print_and_collect_error_diagnostic_lines`] — the count must
    /// hold at exactly `2` there, so a future re-inline of either
    /// stanza (or a re-migration onto a sibling primitive) is refused.
    ///
    /// A count of `0` at the target file means both consumers dropped
    /// their forward-through (a re-inline or a rename without updating
    /// the composition); a count of `1` means one of the two consumers
    /// silently re-inlined; a count above `2` means a duplicate
    /// collection pass leaked back into the file.
    #[test]
    fn frontend_validation_forwards_through_error_diagnostic_collect_primitive_twice() {
        use std::path::PathBuf as StdPathBuf;
        let needle = "print_and_collect_error_diagnostic_lines(";
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
            consumer_forwards, 2,
            "commands/frontend_validation.rs must forward through \
             `{needle}` exactly twice (one call each in `run_type_check` and \
             `run_unit_tests`); found {consumer_forwards}. A count of 0 \
             means both consumers dropped their forward-through; a count \
             of 1 means one consumer silently re-inlined; a count above 2 \
             means a duplicate collection pass leaked back into the file."
        );
    }
}
