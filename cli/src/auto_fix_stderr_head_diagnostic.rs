//! Auto-fix stderr-head diagnostic-print primitive — the pre-lift
//! 2 sibling `for line in stderr.lines().take(5) {
//! crate::ui::print_diagnostic_line(line); }` stanzas that respell
//! the "walk the first 5 lines of the failed auto-fix step's stderr
//! and print each row through `print_diagnostic_line`" grammar
//! byte-for-byte across the cargo-fmt and biome-check auto-fix
//! failure branches, collapsed onto one typed construction surface.
//!
//! # Pre-lift census — two byte-identical stanzas
//!
//! Both stanzas were 3 lines long and byte-for-byte identical:
//!
//! ```ignore
//! for line in stderr.lines().take(5) {
//!     crate::ui::print_diagnostic_line(line);
//! }
//! ```
//!
//! 1. `commands/prerelease.rs::run_cargo_fmt_check` (line 1282-1284,
//!    pre-lift) — the G3 cargo-fmt auto-fix branch. Runs after a
//!    non-zero-exit `cargo fmt` spawn, ahead of the
//!    `return Ok(false);` short-circuit that skips the sibling
//!    verification `cargo fmt -- --check` and reports the gate red.
//!    `stderr` here is the joined stderr of the failed `cargo fmt`
//!    output. Print-only: the walked rows are not collected.
//! 2. `commands/frontend_validation.rs::run_biome_lint` (line 294-296,
//!    pre-lift) — the biome auto-fix branch (`bun x biome check
//!    --write src`). Runs inside the `Could not resolve` / `ENOENT`
//!    fingerprint arm — the only branch that treats an auto-fix
//!    non-zero exit as a real failure (the sibling arm silently
//!    continues to the verification step). `stderr` here is the
//!    joined stderr of the failed biome-fix output. Pre-lift the
//!    caller then walked `stderr.lines().take(5)` a SECOND time to
//!    build a `Vec<String>` for the `Ok((false, details))` return —
//!    two identical walks over the same input. Post-lift the print
//!    walk and the collect walk are fused: the primitive returns
//!    the walked rows so the caller reuses them in place of the
//!    second walk.
//!
//! Both stanzas cap at 5 lines, use no severity filter, and reach
//! the same [`crate::ui::print_diagnostic_line`] per-line adapter.
//! Post-lift both consumers route through
//! [`print_and_collect_auto_fix_stderr_head_diagnostic_lines`]; a
//! future refinement of the auto-fix head-diagnostic grammar — a
//! bump of the cap from 5 to 10 under a deeper diagnostic budget, a
//! swap of the print for a JSON-line emit under structured
//! observability, or a fold onto the fleet-standard `⚠️` glyph —
//! lands at ONE typed body and reaches both consumers by
//! construction.
//!
//! # Distinct from every peer diagnostic-print helper
//!
//! - [`crate::frontend_lint_diagnostic_collect`] owns the LINT
//!   verification-branch grammar: cap = 15 lines, three-keyword
//!   filter (`["error", "warning", "✖"]`), print AND collect the
//!   matched rows. This primitive is its sibling for the AUTO-FIX
//!   grammar: cap = 5, no filter, print AND (optionally) collect.
//!   Different consumers, different cap, different filter contract.
//! - [`crate::ui::print_diagnostic_line`] emits ONE indented row.
//!   This primitive owns the LOOP + CAP + no-filter algebra above
//!   that adapter.
//! - `commands/prerelease.rs::run_e2e_gate`'s in-body
//!   `for line in stderr.lines().rev().take(50).collect::<Vec<_>>().into_iter().rev()`
//!   loop walks the LAST 50 lines (not the first 5), uses a per-line
//!   severity classifier, and lives on the E2E test-failure body
//!   (not an auto-fix step failure). Distinct shape, out of scope.
//! - `commands/prerelease.rs::run_cargo_check` (G1) / `run_cargo_clippy`
//!   (G2) both walk `.take(10)` (not 5), and each carries a distinct
//!   severity filter — G1 filters on `"error"`, G2 on `"warning:"`
//!   /`"error:"`. Different cap and filter contracts, out of scope.
//!
//! # Why cap = 5 stays hard-coded
//!
//! Pre-lift both sites spelled `.take(5)` verbatim, so this primitive
//! currently accepts only `stderr: &str` and hard-codes the cap.
//! If a future third consumer (a `nix flake check` auto-fix branch, a
//! `bun x biome format --write` auto-fix branch, etc.) needs a
//! different cap, the axis promotes to a parameter at that call —
//! until then, keeping the cap fixed removes an entire family of
//! caller-side drift (a call with `cap = 3` producing a report
//! shorter than its sibling's for the same underlying tool output).
//!
//! # THEORY grounding
//!
//! - `THEORY.md §V.1` (Types → Invariants → Proofs → Render Anywhere):
//!   the byte-shape invariant lives at ONE construction surface —
//!   [`write_auto_fix_stderr_head_diagnostic_lines`] — and its
//!   byte-oracle test pins the exact `"   <line>\n"` rendering of
//!   every walked row. Both stdout adapters project through the
//!   same writer, so a future rotation of the per-line grammar
//!   reaches both consumers in lockstep.
//! - `THEORY.md §III.1` (typescape as root data structure): the
//!   "walk-cap-print-collect" composition is a single named concept;
//!   both callers cite it rather than restating its four component
//!   steps.
//!
//! # Frontier grounding
//!
//! Bazel BEP's `TestSummary` event caps captured test output at a
//! configurable byte / line budget before the summary rolls out, so
//! the fleet-wide report renders in bounded time. Buildkite's
//! `--stderr-tail` on failed steps prints only the last N lines of
//! stderr for the same reason. This primitive is the same shape at
//! the CLI-ceremony surface — cap the head of stderr at 5 lines
//! (the "install-time preamble" of most auto-fix tools' errors, which
//! is where the actionable failure lives) — the small cap keeps the
//! failure line and its immediate context on-screen without scrolling
//! past the gate's summary header.

use std::io;

/// The cap on how many of `stderr`'s leading lines the primitive
/// walks before returning. Pre-lift both callers spelled `5`
/// verbatim in `stderr.lines().take(5)`; post-lift the cap lives at
/// ONE constant so a future adjustment (a bump to `10` under a
/// deeper diagnostic budget, a drop to `3` under a tighter
/// terminal-fit budget) lands here.
pub(crate) const AUTO_FIX_STDERR_HEAD_LINE_CAP: usize = 5;

/// Walk the first [`AUTO_FIX_STDERR_HEAD_LINE_CAP`] lines of
/// `stderr`, print each line via
/// [`crate::ui::print_diagnostic_line`], and return the walked
/// lines as owned `String`s.
///
/// This is the stdout adapter over
/// [`write_auto_fix_stderr_head_diagnostic_lines`]; the writer split
/// exists so the byte-oracle test can pin the exact `"   <line>\n"`
/// rendering of every walked row without capturing stdout.
///
/// On stdout write failure the caller still receives the walked
/// rows — a stdout write failure at the diagnostic-print step is
/// not load-bearing; the outer summary renderer still needs the
/// `Vec<String>` back to attach the failed-step details to its
/// per-gate verdict.
///
/// # Pre-lift consumers
///
/// - `commands/prerelease.rs::run_cargo_fmt_check` (G3 auto-fix
///   failure branch) — discards the returned `Vec<String>` because
///   pre-lift the site was print-only.
/// - `commands/frontend_validation.rs::run_biome_lint` (auto-fix
///   `Could not resolve` / `ENOENT` branch) — uses the returned
///   `Vec<String>` in place of the pre-lift `stderr.lines().take(5)
///   .map(|l| l.to_string()).collect()` second walk that respelled
///   the same cap-and-walk grammar for the `Ok((false, details))`
///   return.
///
/// Both delegate through this function post-lift; the pre-lift
/// 3-line inline stanza no longer respells at either site.
pub fn print_and_collect_auto_fix_stderr_head_diagnostic_lines(stderr: &str) -> Vec<String> {
    let mut sink = io::stdout().lock();
    write_auto_fix_stderr_head_diagnostic_lines(&mut sink, stderr).unwrap_or_else(|_| {
        // A stdout write failure at the diagnostic-print step is not
        // load-bearing: the biome caller still needs the walked rows
        // back for the `Ok((false, details))` return. Re-run the
        // pure classification without any print side-effect and
        // return the same rows the successful path would have
        // collected.
        collect_auto_fix_stderr_head_diagnostic_lines(stderr)
    })
}

/// Writer-taking sibling to
/// [`print_and_collect_auto_fix_stderr_head_diagnostic_lines`].
///
/// For each line in the first [`AUTO_FIX_STDERR_HEAD_LINE_CAP`]
/// lines of `stderr`, writes `"   <line>\n"` to `w` via
/// [`crate::ui::write_diagnostic_line`] (matching the byte grammar
/// the stdout adapter [`crate::ui::print_diagnostic_line`] pins)
/// and pushes the line's owned `String` into the returned
/// `Vec<String>`.
///
/// # Byte shape
///
/// For a `stderr` whose first-5-lines subset is
/// `["a", "b", "c", "d", "e", "f"]`, this writes exactly
/// `"   a\n   b\n   c\n   d\n   e\n"` to `w` and returns
/// `vec!["a", "b", "c", "d", "e"]` (the sixth line `"f"` is
/// discarded because the cap is 5). The three-space indent, the
/// per-line trailing `\n`, and the ABSENCE of every `\x1b[<..>m`
/// ANSI palette sequence are inherited unchanged from
/// [`crate::ui::write_diagnostic_line`].
pub fn write_auto_fix_stderr_head_diagnostic_lines<W: io::Write>(
    w: &mut W,
    stderr: &str,
) -> io::Result<Vec<String>> {
    let mut details = Vec::new();
    for line in stderr.lines().take(AUTO_FIX_STDERR_HEAD_LINE_CAP) {
        crate::ui::write_diagnostic_line(w, line)?;
        details.push(line.to_string());
    }
    Ok(details)
}

/// Pure classifier: return the first
/// [`AUTO_FIX_STDERR_HEAD_LINE_CAP`] lines of `stderr` as owned
/// `String`s WITHOUT emitting anything to any sink. Used as the
/// fallback path in
/// [`print_and_collect_auto_fix_stderr_head_diagnostic_lines`] when
/// the stdout write itself fails, so the caller still gets its
/// `Vec<String>` back for the summary render.
fn collect_auto_fix_stderr_head_diagnostic_lines(stderr: &str) -> Vec<String> {
    stderr
        .lines()
        .take(AUTO_FIX_STDERR_HEAD_LINE_CAP)
        .map(|line| line.to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The cap pinned to the pre-lift `.take(5)` literal. A change
    /// here rotates the byte-shape reachable at both post-lift
    /// consumer sites.
    #[test]
    fn test_auto_fix_stderr_head_line_cap_matches_pre_lift_literal() {
        assert_eq!(AUTO_FIX_STDERR_HEAD_LINE_CAP, 5);
    }

    /// Byte-oracle: the writer sibling emits the exact
    /// `"   <line>\n"` rendering for every line in the first
    /// [`AUTO_FIX_STDERR_HEAD_LINE_CAP`] lines of the input, in walk
    /// order, AND returns the walked rows as owned `String`s. Pins
    /// the three-space indent, the per-line trailing newline, the
    /// cap-at-5 boundary, and the walk-order-preserving collect
    /// against the pre-lift three-line inline stanza both consumer
    /// sites spelled.
    #[test]
    fn write_auto_fix_stderr_head_diagnostic_lines_emits_indented_head_and_caps_at_five() {
        let stderr = "\
first line
second line
third line
fourth line
fifth line
sixth line should not appear
seventh line should not appear
";
        let mut buf: Vec<u8> = Vec::new();
        let details = write_auto_fix_stderr_head_diagnostic_lines(&mut buf, stderr)
            .expect("write against a Vec<u8> writer must succeed");
        let out = String::from_utf8(buf).expect("writer emits valid UTF-8");
        assert_eq!(
            out,
            "   first line\n   second line\n   third line\n   fourth line\n   fifth line\n",
        );
        assert_eq!(
            details,
            vec![
                "first line".to_string(),
                "second line".to_string(),
                "third line".to_string(),
                "fourth line".to_string(),
                "fifth line".to_string(),
            ],
        );
    }

    /// Byte-oracle: fewer input lines than the cap emits every
    /// available line and stops naturally at end-of-input. Pins the
    /// "cap is a maximum, not a padding target" contract.
    #[test]
    fn write_auto_fix_stderr_head_diagnostic_lines_emits_all_lines_when_under_cap() {
        let stderr = "only one line\nand a second";
        let mut buf: Vec<u8> = Vec::new();
        let details = write_auto_fix_stderr_head_diagnostic_lines(&mut buf, stderr)
            .expect("write against a Vec<u8> writer must succeed");
        let out = String::from_utf8(buf).expect("writer emits valid UTF-8");
        assert_eq!(out, "   only one line\n   and a second\n");
        assert_eq!(
            details,
            vec!["only one line".to_string(), "and a second".to_string()]
        );
    }

    /// Byte-oracle: an empty `stderr` emits nothing and returns an
    /// empty `Vec`. Pins the no-panic-on-empty contract — the pre-
    /// lift `for line in stderr.lines().take(5) { ... }` stanza's
    /// empty-iterator behavior carried through unchanged.
    #[test]
    fn write_auto_fix_stderr_head_diagnostic_lines_emits_nothing_for_empty_stderr() {
        let mut buf: Vec<u8> = Vec::new();
        let details = write_auto_fix_stderr_head_diagnostic_lines(&mut buf, "")
            .expect("write against a Vec<u8> writer must succeed");
        assert!(
            buf.is_empty(),
            "empty stderr must produce no output; got {:?}",
            buf
        );
        assert!(
            details.is_empty(),
            "empty stderr must return an empty Vec; got {:?}",
            details
        );
    }

    /// Byte-oracle: the writer sibling projects the same byte-shape
    /// as the pre-lift 3-line inline stanza expressed against
    /// [`crate::ui::write_diagnostic_line`]. This is the invariant
    /// the migration MUST preserve: the two post-lift consumers see
    /// the same operator-facing output byte-for-byte as they did
    /// pre-lift.
    #[test]
    fn write_auto_fix_stderr_head_projects_prelift_inline_stanza_byte_shape() {
        let stderr = "line-A\nline-B\nline-C\nline-D\nline-E\nline-F\n";

        let mut primitive: Vec<u8> = Vec::new();
        write_auto_fix_stderr_head_diagnostic_lines(&mut primitive, stderr)
            .expect("primitive write must succeed");

        let mut inline: Vec<u8> = Vec::new();
        for line in stderr.lines().take(AUTO_FIX_STDERR_HEAD_LINE_CAP) {
            crate::ui::write_diagnostic_line(&mut inline, line)
                .expect("inline peer write must succeed");
        }

        assert_eq!(
            primitive, inline,
            "primitive must project the same bytes as the pre-lift \
             `for line in stderr.lines().take(5) {{ write_diagnostic_line(w, line)?; }}` \
             stanza"
        );
    }

    /// Byte-oracle: the collect walk returns exactly the same rows
    /// the pre-lift Biome caller's second
    /// `stderr.lines().take(5).map(|l| l.to_string()).collect()`
    /// walk would have returned. This is the invariant the fused
    /// print+collect contract MUST preserve for the biome consumer:
    /// the `Ok((false, details))` return payload is byte-identical
    /// pre-lift and post-lift.
    #[test]
    fn write_auto_fix_stderr_head_collect_matches_prelift_second_walk() {
        let stderr = "row-1\nrow-2\nrow-3\nrow-4\nrow-5\nrow-6\nrow-7\n";

        let mut sink: Vec<u8> = Vec::new();
        let primitive_details = write_auto_fix_stderr_head_diagnostic_lines(&mut sink, stderr)
            .expect("primitive write must succeed");

        let prelift_second_walk: Vec<String> = stderr
            .lines()
            .take(AUTO_FIX_STDERR_HEAD_LINE_CAP)
            .map(|l| l.to_string())
            .collect();

        assert_eq!(
            primitive_details, prelift_second_walk,
            "primitive's returned Vec<String> must equal the pre-lift Biome \
             `.take(5).map(...).collect()` second walk row-for-row"
        );
    }

    /// The pure collect classifier (fallback path when the stdout
    /// write fails) returns the same rows the successful path would
    /// have collected. Pins the "print failure does not lose
    /// details" invariant.
    #[test]
    fn collect_auto_fix_stderr_head_diagnostic_lines_matches_write_path_details() {
        let stderr = "one\ntwo\nthree\nfour\nfive\nsix\n";

        let mut sink: Vec<u8> = Vec::new();
        let write_details = write_auto_fix_stderr_head_diagnostic_lines(&mut sink, stderr)
            .expect("write path must succeed");
        let collect_details = collect_auto_fix_stderr_head_diagnostic_lines(stderr);

        assert_eq!(write_details, collect_details);
    }

    /// Caller shield (negative half): no source line under
    /// `cli/src/commands/` may spell the raw pre-lift
    /// `stderr.lines().take(5)` walk inline any more. The two pre-
    /// lift sites migrated; any future consumer that wants the same
    /// auto-fix-stderr-head grammar reaches for
    /// [`print_and_collect_auto_fix_stderr_head_diagnostic_lines`]
    /// on first grep, not by copy-pasting the raw walk from an
    /// existing module.
    ///
    /// Reconstructed at test time via [`format!`] so this shield's
    /// own source text does not false-match itself; the whole-scan
    /// therefore covers both the top-of-file production body AND
    /// every sibling `#[cfg(test)]` block. Line-comment lines are
    /// skipped so a future module that quotes the pre-lift shape as
    /// historical prose does not trip the shield.
    #[test]
    fn no_command_module_still_spells_raw_stderr_lines_take_five_walk() {
        use std::path::PathBuf;
        let crate_src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let commands_dir = crate_src.join("commands");

        // Reconstruct the forbidden call via `format!` so this
        // shield's own source text does not false-match itself.
        let forbidden = format!("stderr.lines().take({})", AUTO_FIX_STDERR_HEAD_LINE_CAP);

        let mut offenders: Vec<(PathBuf, usize, String)> = Vec::new();
        let read = std::fs::read_dir(&commands_dir)
            .unwrap_or_else(|_| panic!("expected {} to exist", commands_dir.display()));
        for entry in read.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).unwrap();
            for (idx, line) in source.lines().enumerate() {
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") {
                    continue;
                }
                if line.contains(&forbidden) {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `stderr.lines().take(5)` walk(s) survive under `commands/` — \
             route each through \
             `crate::auto_fix_stderr_head_diagnostic::print_and_collect_auto_fix_stderr_head_diagnostic_lines()` \
             instead:\n{:#?}",
            offenders
        );
    }

    /// Caller shield (positive half): the two pre-lift command
    /// modules (`commands/prerelease.rs`,
    /// `commands/frontend_validation.rs`) MUST each forward through
    /// [`print_and_collect_auto_fix_stderr_head_diagnostic_lines`]
    /// at least once. A dropped call site would leave the sibling
    /// negative
    /// `no_command_module_still_spells_raw_stderr_lines_take_five_walk`
    /// shield satisfied by absence; this positive count still fails
    /// on a regression that reverts one gate to spelling the pre-
    /// lift 3-line stanza inline.
    #[test]
    fn every_prelift_module_forwards_through_auto_fix_stderr_head_diagnostic() {
        use std::path::PathBuf;
        let crate_src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let expectations: &[(PathBuf, usize)] = &[
            (crate_src.join("commands").join("prerelease.rs"), 1),
            (crate_src.join("commands").join("frontend_validation.rs"), 1),
        ];
        let needle = "print_and_collect_auto_fix_stderr_head_diagnostic_lines(";
        for (path, min_count) in expectations {
            let source = std::fs::read_to_string(path)
                .unwrap_or_else(|_| panic!("expected {} to exist", path.display()));
            let forwards = source.matches(needle).count();
            assert!(
                forwards >= *min_count,
                "{} must forward at least {} auto-fix-stderr-head site(s) through `{}`; \
                 found {}. A dropped call would leave the negative raw-shape scan \
                 satisfied by absence.",
                path.display(),
                min_count,
                needle,
                forwards,
            );
        }
    }
}
