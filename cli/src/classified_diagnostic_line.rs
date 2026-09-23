//! Classified diagnostic-line dispatch primitive — the pre-lift
//! 3 sibling `if line.contains(<KW1>) || line.contains(<KW2>) [ ||
//! line.contains(<KW3>) ] { crate::ui::print_diagnostic_error_line(
//! line); } else { crate::ui::print_diagnostic_line(line); }`
//! per-line if/else bodies that respell the "route this diagnostic
//! line to the highlighted-red adapter when it carries any of a
//! caller-chosen error-marker vocabulary, otherwise to the plain
//! adapter" grammar byte-for-byte across the three failed-cargo-run
//! reporting bodies of `commands/prerelease.rs`, collapsed onto one
//! typed dispatch surface.
//!
//! # Pre-lift census — three byte-identical if/else bodies
//!
//! All three bodies were 5 lines and structurally byte-identical
//! (differing only in the marker vocabulary):
//!
//! ```ignore
//! if line.contains(<KW1>) || line.contains(<KW2>) || line.contains(<KW3>) {
//!     crate::ui::print_diagnostic_error_line(line);
//! } else {
//!     crate::ui::print_diagnostic_line(line);
//! }
//! ```
//!
//! 1. `commands/prerelease.rs::run_e2e_gate` (pre-lift ~L1132-1139) —
//!    the failed-E2E-cargo-test stderr walk, driven off
//!    `stderr.lines().rev().take(50).collect::<Vec<_>>().into_iter().rev()`
//!    (last 50 stderr lines in original order). Marker vocabulary:
//!    `["FAILED", "panicked", "error"]`.
//! 2. `commands/prerelease.rs::run_cargo_test` (pre-lift ~L1355-1360)
//!    — the failed-`cargo test` stdout walk, driven off
//!    `stdout.lines()` (full stdout). Marker vocabulary:
//!    `["FAILED", "panicked", "error["]` — the trailing `[`
//!    disambiguates `error[E0308]:` and friends from prose containing
//!    the bare word `error`.
//! 3. `commands/prerelease.rs::run_cargo_test` (pre-lift ~L1368-1373)
//!    — the failed-`cargo test` stderr last-40-lines walk. Marker
//!    vocabulary: `["error", "FAILED", "panicked"]`.
//!
//! Each site's `for` walk shape (full, last-40, rev-take-50) is
//! preserved as-is at the call site; only the 5-line if/else body
//! collapses to one call.
//!
//! # Distinct from every peer diagnostic-print helper
//!
//! - [`crate::auto_fix_stderr_head_diagnostic`] owns the AUTO-FIX
//!   head-of-stderr walk: cap = 5, no filter, unconditionally routes
//!   every walked row through `print_diagnostic_line`. This primitive
//!   is the CLASSIFIER sibling: the caller owns the walk and the
//!   marker vocabulary, and this primitive owns the per-line dispatch
//!   between `print_diagnostic_error_line` and `print_diagnostic_line`.
//! - [`crate::frontend_lint_diagnostic_collect`] owns the LINT
//!   verification-branch walk: cap = 15, three-keyword filter,
//!   ONE-sided route (matched rows only, through
//!   `print_diagnostic_error_line`, plus a collect). This primitive
//!   is the TWO-sided sibling: matched rows through
//!   `print_diagnostic_error_line`, non-matched rows through
//!   `print_diagnostic_line`, no collect.
//! - [`crate::ui::print_diagnostic_error_line`] /
//!   [`crate::ui::print_diagnostic_line`] each emit ONE indented row.
//!   This primitive owns the DISPATCH algebra above those adapters —
//!   the per-line "any marker → red; no marker → plain" branch.
//!
//! # `error_markers` as a slice, not a fixed enum
//!
//! The three pre-lift sites carry three DIFFERENT marker vocabularies
//! (`["FAILED", "panicked", "error"]` vs
//! `["FAILED", "panicked", "error["]` vs
//! `["error", "FAILED", "panicked"]`). A closed-enum `MarkerSet`
//! would fold them, but the differences are load-bearing:
//! - E2E uses the bare `"error"` marker so `cargo test`'s panic
//!   header `thread 'test_x' panicked at ...` and prose lines
//!   containing `error:` both light up red.
//! - Cargo-test-stdout uses `"error["` to target compile-error
//!   IDs (`error[E0308]:`) without red-painting every prose line
//!   that happens to include the word `error` inside a passing test
//!   name (`test_error_path::x ... ok`).
//! - Cargo-test-stderr walks the last 40 lines, where the bare
//!   `"error"` marker is intentional — the compile-error banner
//!   itself is what we want highlighted.
//!
//! Keeping the marker vocabulary as a caller-passed slice preserves
//! each site's semantic choice at ONE line, with no coupling.
//!
//! # THEORY grounding
//!
//! - `THEORY.md §V.1` (Types → Invariants → Proofs → Render Anywhere):
//!   the byte-shape invariant lives at ONE construction surface —
//!   [`write_classified_diagnostic_line`] — and its byte-oracle
//!   tests pin both the matched-marker (red) and no-marker (plain)
//!   projections against the exact bytes each `ui::write_*` peer
//!   emits. A future rotation of the dispatch grammar reaches all
//!   three consumers in lockstep.
//! - `THEORY.md §III.1` (typescape as root data structure): the
//!   "classify-and-print" composition is a single named concept;
//!   all three callers cite it rather than restating its two-branch
//!   dispatch body.
//! - `THEORY.md §VI.1` (three-times rule): three sibling occurrences
//!   past the "two is a coincidence; three is a law" threshold, so
//!   the if/else body lifts onto ONE typed dispatch surface.
//!
//! # Frontier grounding
//!
//! Bazel's `--experimental_stderr_test_output` and Cargo's own
//! `--message-format=json` diagnostic streams both classify emitted
//! lines against a fixed severity vocabulary before styling — the
//! severity classifier lives at ONE place, not fanned across every
//! consumer. This primitive is the same shape at the CLI-ceremony
//! surface: the per-line severity dispatch is ONE typed body, and
//! each consumer supplies only the marker vocabulary it wants
//! recognized.

use std::io;

/// Dispatch `line` to the highlighted (`.red()`) diagnostic-line
/// adapter if it contains ANY element of `error_markers`, otherwise
/// to the plain-verbatim diagnostic-line adapter.
///
/// This is the stdout adapter over
/// [`write_classified_diagnostic_line`]; the writer split exists so
/// the byte-oracle tests can pin both projections without capturing
/// stdout.
///
/// A stdout write failure is not load-bearing: the caller's
/// diagnostic-loop continues walking regardless. This matches the
/// pre-lift `println!`-based inline shape, whose write failures were
/// also silently discarded.
///
/// # Semantics
///
/// - `error_markers.iter().any(|m| line.contains(m))` → route through
///   [`crate::ui::print_diagnostic_error_line`] (three-space indent
///   + `.red()` on the whole line body).
/// - Otherwise → route through [`crate::ui::print_diagnostic_line`]
///   (three-space indent, no color, no glyph).
/// - An empty `error_markers` slice ALWAYS falls through to the
///   plain adapter (nothing to match against).
///
/// # Pre-lift consumers
///
/// - `commands/prerelease.rs::run_e2e_gate` (E2E stderr rev-take-50
///   walk) — marker vocabulary `["FAILED", "panicked", "error"]`.
/// - `commands/prerelease.rs::run_cargo_test` (stdout full walk) —
///   marker vocabulary `["FAILED", "panicked", "error["]`.
/// - `commands/prerelease.rs::run_cargo_test` (stderr last-40 walk) —
///   marker vocabulary `["error", "FAILED", "panicked"]`.
pub fn print_classified_diagnostic_line(line: &str, error_markers: &[&str]) {
    let _ = write_classified_diagnostic_line(&mut io::stdout().lock(), line, error_markers);
}

/// Writer-taking sibling to [`print_classified_diagnostic_line`].
///
/// If `line` contains any element of `error_markers`, delegates to
/// [`crate::ui::write_diagnostic_error_line`] (three-space indent +
/// `\x1b[31m<line>\x1b[0m`); otherwise delegates to
/// [`crate::ui::write_diagnostic_line`] (three-space indent + plain
/// line body). Both peers emit a single trailing `\n`.
///
/// # Byte shape
///
/// For `line = "error[E0308]: mismatched types"` and
/// `error_markers = &["error["]`, this writes
/// `"   \x1b[31merror[E0308]: mismatched types\x1b[0m\n"`.
///
/// For `line = "test tests::x ... ok"` and the same marker set, this
/// writes `"   test tests::x ... ok\n"` (no ANSI, the plain adapter).
///
/// The three-space indent, the per-branch ANSI palette contract, and
/// the per-line trailing `\n` are inherited unchanged from the two
/// `crate::ui::write_diagnostic_*_line` peers.
pub fn write_classified_diagnostic_line<W: io::Write>(
    w: &mut W,
    line: &str,
    error_markers: &[&str],
) -> io::Result<()> {
    if line_matches_any_marker(line, error_markers) {
        crate::ui::write_diagnostic_error_line(w, line)
    } else {
        crate::ui::write_diagnostic_line(w, line)
    }
}

/// Pure classifier: does `line` contain ANY element of
/// `error_markers`? Extracted so the two writer branches share ONE
/// dispatch check and the byte-oracle tests can independently pin
/// the classifier without going through a writer.
fn line_matches_any_marker(line: &str, error_markers: &[&str]) -> bool {
    error_markers.iter().any(|m| line.contains(m))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-oracle: a line containing one of the error markers routes
    /// through [`crate::ui::write_diagnostic_error_line`] — i.e. the
    /// three-space indent, the `\x1b[31m` red ANSI palette around the
    /// line body, the `\x1b[0m` reset, and the trailing `\n`. Pins
    /// the matched-branch projection byte-for-byte against the
    /// pre-lift inline `crate::ui::print_diagnostic_error_line(line);`
    /// stanza.
    #[test]
    fn write_classified_diagnostic_line_matched_projects_error_line_bytes() {
        let line = "error[E0308]: mismatched types";
        let markers = &["FAILED", "panicked", "error["];

        let mut got: Vec<u8> = Vec::new();
        write_classified_diagnostic_line(&mut got, line, markers)
            .expect("write against Vec<u8> must succeed");

        let mut want: Vec<u8> = Vec::new();
        crate::ui::write_diagnostic_error_line(&mut want, line).expect("peer write must succeed");

        assert_eq!(
            got, want,
            "matched-marker branch must project the same bytes as \
             `crate::ui::write_diagnostic_error_line(w, line)`; a fusion \
             that swapped the adapter or dropped the `.red()` on the \
             line body fails here"
        );
    }

    /// Byte-oracle: a line containing NONE of the error markers routes
    /// through [`crate::ui::write_diagnostic_line`] — i.e. the
    /// three-space indent + verbatim line body + trailing `\n`, with
    /// NO `\x1b[<..>m` ANSI palette sequences from the primitive
    /// itself. Pins the no-marker-branch projection byte-for-byte
    /// against the pre-lift inline
    /// `crate::ui::print_diagnostic_line(line);` stanza.
    #[test]
    fn write_classified_diagnostic_line_unmatched_projects_plain_line_bytes() {
        let line = "test tests::example ... ok";
        let markers = &["FAILED", "panicked", "error["];

        let mut got: Vec<u8> = Vec::new();
        write_classified_diagnostic_line(&mut got, line, markers)
            .expect("write against Vec<u8> must succeed");

        let mut want: Vec<u8> = Vec::new();
        crate::ui::write_diagnostic_line(&mut want, line).expect("peer write must succeed");

        assert_eq!(
            got, want,
            "no-marker branch must project the same bytes as \
             `crate::ui::write_diagnostic_line(w, line)`; a fusion \
             that always applied `.red()` (collapsing the two branches) \
             fails here"
        );
    }

    /// Byte-oracle: an empty `error_markers` slice ALWAYS falls
    /// through to the plain adapter — nothing to match against, so
    /// every line goes through [`crate::ui::write_diagnostic_line`].
    /// Pins the "empty vocabulary is a no-op classifier" contract.
    #[test]
    fn write_classified_diagnostic_line_with_empty_markers_falls_through_to_plain() {
        let line = "FAILED test whatever";
        let mut got: Vec<u8> = Vec::new();
        write_classified_diagnostic_line(&mut got, line, &[])
            .expect("write against Vec<u8> must succeed");

        let mut want: Vec<u8> = Vec::new();
        crate::ui::write_diagnostic_line(&mut want, line).expect("peer write must succeed");

        assert_eq!(got, want);
    }

    /// The classifier fires on the FIRST match — any element of the
    /// slice contained in `line` flips the dispatch to the red
    /// branch. Pins the `any(|m| line.contains(m))` semantic against
    /// a hypothetical drift to `all` or to a first-marker-only check.
    #[test]
    fn line_matches_any_marker_fires_on_first_contained_element() {
        assert!(line_matches_any_marker(
            "thread 'x' panicked at src/lib.rs:42",
            &["FAILED", "panicked", "error"],
        ));
        assert!(line_matches_any_marker(
            "test result: FAILED. 1 passed",
            &["FAILED", "panicked", "error"],
        ));
        assert!(line_matches_any_marker(
            "error[E0308]: mismatched types",
            &["FAILED", "panicked", "error"],
        ));
        assert!(!line_matches_any_marker(
            "test tests::normal_case ... ok",
            &["FAILED", "panicked", "error"],
        ));
    }

    /// The `"error["` marker (the cargo-test-stdout vocabulary)
    /// deliberately EXCLUDES prose lines containing only the bare
    /// word `error` — a discipline that keeps passing test names
    /// like `test error_path::x ... ok` from lighting up red inside
    /// the stdout walk. Pins the semantic difference from the
    /// `"error"` marker used by the two other consumer sites.
    #[test]
    fn error_bracket_marker_excludes_bare_error_word_from_red_route() {
        let markers = &["FAILED", "panicked", "error["];
        assert!(
            !line_matches_any_marker("test error_path::normal ... ok", markers),
            "the `error[` marker must NOT fire on the bare word `error` \
             inside a passing test name — otherwise the cargo-test-stdout \
             walk would red-paint every passing test whose name mentioned \
             `error`"
        );
        assert!(
            line_matches_any_marker("error[E0308]: mismatched types", markers),
            "the `error[` marker MUST fire on `error[Ennnn]` compile-error \
             IDs — that is the whole point of the trailing `[` in the \
             vocabulary the cargo-test-stdout consumer supplies"
        );
    }

    /// Byte-oracle: the primitive projects the same bytes as the
    /// pre-lift 5-line inline if/else stanza expressed against the
    /// two `crate::ui::write_diagnostic_*_line` peers. This is the
    /// invariant the migration MUST preserve: the three post-lift
    /// consumers see the same operator-facing output byte-for-byte
    /// as they did pre-lift.
    #[test]
    fn write_classified_diagnostic_line_projects_prelift_inline_stanza_byte_shape() {
        let markers: &[&str] = &["FAILED", "panicked", "error"];
        for line in [
            "thread 'x' panicked at src/lib.rs:42",
            "test result: FAILED. 1 passed",
            "test tests::normal ... ok",
            "",
            "some prose line with no marker at all",
        ] {
            let mut primitive: Vec<u8> = Vec::new();
            write_classified_diagnostic_line(&mut primitive, line, markers)
                .expect("primitive write must succeed");

            let mut inline: Vec<u8> = Vec::new();
            if markers.iter().any(|m| line.contains(m)) {
                crate::ui::write_diagnostic_error_line(&mut inline, line)
                    .expect("inline peer write must succeed");
            } else {
                crate::ui::write_diagnostic_line(&mut inline, line)
                    .expect("inline peer write must succeed");
            }

            assert_eq!(
                primitive, inline,
                "primitive must project the same bytes as the pre-lift \
                 5-line inline if/else stanza against \
                 `crate::ui::write_diagnostic_*_line` peers — case: {line:?}"
            );
        }
    }

    /// Caller shield (negative half): no source line under
    /// `cli/src/commands/` may spell the raw pre-lift
    /// `crate::ui::print_diagnostic_error_line(line);` /
    /// `crate::ui::print_diagnostic_line(line);` two-branch if/else
    /// inline stanza any more. The three pre-lift sites migrated;
    /// any future consumer that wants the same classify-and-print
    /// dispatch grammar reaches for
    /// [`print_classified_diagnostic_line`] on first grep, not by
    /// copy-pasting the raw dispatch from an existing module.
    ///
    /// The needle is reconstructed at test time via [`format!`] so
    /// this shield's own source text does not false-match itself.
    #[test]
    fn no_command_module_spells_raw_classified_dispatch_body_inline() {
        use std::path::PathBuf;
        let crate_src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let commands_dir = crate_src.join("commands");

        // Reconstruct the two forbidden shapes via `format!` so
        // this shield's own source lines do not self-match.
        let red_call = format!("{}{}(line);", "crate::ui::", "print_diagnostic_error_line",);
        let plain_call = format!("{}{}(line);", "crate::ui::", "print_diagnostic_line",);

        // Walk every commands/*.rs line: an offender is a line
        // matching `red_call` that has a `plain_call` line within
        // the next 3 lines (the pre-lift if/else stanza spelled
        // both across at most 5 lines). Comment lines are skipped
        // so a future module quoting the pre-lift shape as
        // historical prose does not trip the shield.
        let mut offenders: Vec<(PathBuf, usize, String)> = Vec::new();
        let read = std::fs::read_dir(&commands_dir)
            .unwrap_or_else(|_| panic!("expected {} to exist", commands_dir.display()));
        for entry in read.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).unwrap();
            let lines: Vec<&str> = source.lines().collect();
            for (idx, line) in lines.iter().enumerate() {
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") {
                    continue;
                }
                if line.contains(&red_call) {
                    let look_ahead = lines
                        .iter()
                        .skip(idx + 1)
                        .take(3)
                        .any(|l| l.contains(&plain_call) && !l.trim_start().starts_with("//"));
                    if look_ahead {
                        offenders.push((path.clone(), idx + 1, line.to_string()));
                    }
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `if line.contains(<KW>) {{ print_diagnostic_error_line(line); }} \
             else {{ print_diagnostic_line(line); }}` two-branch dispatch survives \
             under `commands/` — route each through \
             `crate::classified_diagnostic_line::print_classified_diagnostic_line()` \
             instead:\n{:#?}",
            offenders
        );
    }

    /// Caller shield (positive half): the pre-lift command module
    /// (`commands/prerelease.rs`) MUST forward through
    /// [`print_classified_diagnostic_line`] at least 3 times (the
    /// three pre-lift sites). A dropped call site would leave the
    /// sibling negative shield satisfied by absence; this positive
    /// count still fails on a regression that reverts one site to
    /// spelling the pre-lift 5-line if/else stanza inline.
    #[test]
    fn prerelease_module_forwards_all_three_prelift_sites_through_primitive() {
        use std::path::PathBuf;
        let crate_src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let path = crate_src.join("commands").join("prerelease.rs");
        let source = std::fs::read_to_string(&path)
            .unwrap_or_else(|_| panic!("expected {} to exist", path.display()));
        let needle = "print_classified_diagnostic_line(";
        let forwards = source.matches(needle).count();
        assert!(
            forwards >= 3,
            "{} must forward at least 3 classified-dispatch site(s) through `{}`; \
             found {}. A dropped call would leave the negative raw-shape scan \
             satisfied by absence.",
            path.display(),
            needle,
            forwards,
        );
    }
}
