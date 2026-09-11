//! Typed primitive for the sibling
//! `if !config.quiet { println!(); crate::ui::print_numbered_check_heading(<N>, "<title>"); }`
//! blank-line-then-numbered-check-heading stanzas that open every
//! per-check phase EXCEPT the first across
//! `commands/rebac_validation.rs`.
//!
//! # Compounding
//!
//! Pre-lift 6 sibling call sites in `commands/rebac_validation.rs`
//! each restated the same three-line prelude verbatim under the
//! `if !config.quiet { … }` gate — a bare `println!();` framing
//! blank followed by a delegated
//! `crate::ui::print_numbered_check_heading(<index>, <title>)` blue
//! heading:
//!
//! - `check_permission_engine_files`  / index 2 (~:215)
//! - `check_object_type_mapping`      / index 3 (~:252)
//! - `check_relation_hierarchy`       / index 4 (~:337)
//! - `check_redis_key_patterns`       / index 5 (~:429)
//! - `check_redis_connectivity`       / index 6 (~:485)
//! - `check_graphql_permissions`      / index 7 (~:560)
//!
//! The very first check (`check_rebac_documentation` / index 1)
//! opens WITHOUT a leading `println!();` — it is the top-of-report
//! solo, so no upstream check has just printed output that needs a
//! visual gap ahead of the second heading. That site stays on the
//! plain [`crate::ui::print_numbered_check_heading`] adapter under
//! its own `if !config.quiet { … }` gate, and does NOT forward
//! through this primitive — the negative caller shield in the
//! consumer module accepts one un-gapped delegation at the check-1
//! seat and forbids every other bare `crate::ui::print_numbered_check_heading(`
//! reference.
//!
//! # Distinct from the sibling ReBAC-validation primitives
//!
//! - [`super::rebac_check_skipped_missing_dir::print_rebac_check_skipped_missing_dir`]
//!   emits the check's `"   (skipped — <dir-label> not configured)"`
//!   MID-check announce that fires from a per-check
//!   `let Some(<dir>) = &config.<dir_opt> else { … }` early-out.
//!   The two primitives are the entry/skip halves of the same
//!   validation check's operator-facing frame; this primitive owns
//!   the heading (blank-line + `Check <N>: <title>`), the skipped
//!   sibling owns the skip announce. Both accept a `bool quiet` gate
//!   the pre-lift `if !config.quiet { … }` guard supplied.
//!
//! # Grammar delegation
//!
//! The heading grammar itself — the `Check <index>: <title>` layout,
//! the `\x1b[34m` blue ANSI palette, the trailing newline — stays
//! owned by [`crate::ui::write_numbered_check_heading`]. This
//! primitive owns only the FUSION of the leading framing blank with
//! that heading: a `writeln!(w)?;` blank followed by delegation to
//! `write_numbered_check_heading`. A future palette adjustment
//! (a bold sweep on the heading, a dimmed variant on the framing
//! blank, a numbered-check-heading rename) lands at ONE typed body
//! and reaches this primitive by construction — the sibling module
//! narrates the heading grammar; this module narrates the two-line
//! fusion.
//!
//! # Compounding surface
//!
//! Post-lift a future refinement — a promotion of the framing blank
//! to a dimmed rule (`println!("{}", "─".repeat(60).dimmed())`), an
//! OTLP `rebac_validation.check_started` observability event carrying
//! `(index, title)` as SEPARATE structured attributes, a shift from
//! numeric `Check N:` to a fraction `Check N/7:` progress cue —
//! lands at ONE typed body and reaches every consumer by construction.
//!
//! THEORY.md §VI.1 (three-times-is-a-law — "two occurrences is a
//! coincidence; three is a law"; 6 verbatim sibling sites redeemed
//! by extraction), §V.1 (Construction guarantees — a fused
//! blank+heading stanza is emitted by ONE typed body; a caller
//! cannot drift the framing blank away from the heading it belongs
//! to).

use std::io;

/// Emit the standard sibling stanza
/// `println!(); crate::ui::print_numbered_check_heading(<index>, <title>);`
/// — a leading blank line then a `Check <index>: <title>` blue
/// heading — used by every per-check phase EXCEPT the first in
/// `commands/rebac_validation.rs`.
///
/// `quiet` mirrors `RebacValidationConfig::quiet`; when `true` both
/// the framing blank and the heading are suppressed, matching the
/// pre-lift `if !config.quiet { println!(); crate::ui::print_numbered_check_heading(…); }`
/// gate every site carried. Delegates the two-line emission to
/// [`write_rebac_check_heading_with_gap`] against a locked
/// [`std::io::stdout`] handle; the writer split exists so the
/// fail-before-pass byte-oracle tests can pin the exact rendered
/// bytes against a `Vec<u8>` sink without capturing stdout.
///
/// [`RebacValidationConfig`]: super::rebac_validation::RebacValidationConfig
pub fn print_rebac_check_heading_with_gap(quiet: bool, index: u32, title: &str) {
    if quiet {
        return;
    }
    let _ = write_rebac_check_heading_with_gap(&mut io::stdout().lock(), index, title);
}

/// Writer-taking sibling to [`print_rebac_check_heading_with_gap`].
/// Emits a bare `\n` framing blank via [`writeln!`], then delegates
/// the `Check <index>: <title>` blue heading to
/// [`crate::ui::write_numbered_check_heading`] against the same
/// writer.
///
/// [`print_rebac_check_heading_with_gap`] is the stdout adapter; this
/// variant exists so tests can pin the two-line body — the leading
/// `\n`, the `Check <index>: <title>` layout, the `\x1b[34m` blue
/// ANSI sequence wrapping the whole composed heading, and the
/// trailing `\n` — by inspecting emitted bytes rather than
/// capturing stdout. The heading grammar itself stays owned by
/// [`crate::ui::write_numbered_check_heading`]; a regression in the
/// heading's palette or layout lands at ONE upstream site and
/// propagates through this delegation.
pub fn write_rebac_check_heading_with_gap<W: io::Write>(
    w: &mut W,
    index: u32,
    title: &str,
) -> io::Result<()> {
    writeln!(w)?;
    crate::ui::write_numbered_check_heading(w, index, title)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-oracle pin for the fused two-line stanza at index 2.
    /// The pre-lift `check_permission_engine_files` site emitted a
    /// bare `\n` framing blank followed by the `Check 2: Permission
    /// Engine Source Files\n` heading. The palette (`\x1b[34m` blue
    /// ANSI wrapping) is owned by
    /// [`crate::ui::write_numbered_check_heading`] and pinned by its
    /// own byte-oracle at `src/ui.rs`; this test pins the fusion
    /// contract only — the framing blank precedes the heading, the
    /// composed `Check <index>: <title>` layout reaches the writer
    /// verbatim, and the stanza is exactly two lines.
    ///
    /// A regression that dropped the leading blank, dropped the
    /// `Check ` prefix, dropped the `: ` separator between index
    /// and title, or emitted more than two lines regresses this.
    #[test]
    fn write_check2_permission_engine_line_pins_two_line_fusion() {
        let mut buf = Vec::new();
        write_rebac_check_heading_with_gap(&mut buf, 2, "Permission Engine Source Files").unwrap();
        let bytes = String::from_utf8(buf).unwrap();
        assert!(
            bytes.starts_with('\n'),
            "fusion must open with the framing blank (a bare `\\n`) — \
             the pre-lift `println!(); print_numbered_check_heading(…)` \
             order places the blank AHEAD of the heading. Bytes: {bytes:?}",
        );
        assert!(
            bytes.contains("Check 2: Permission Engine Source Files"),
            "fusion must carry the composed `Check <index>: <title>` \
             layout verbatim on the heading line — a regression that \
             dropped the `Check ` prefix or the `: ` separator between \
             index and title regresses this. Bytes: {bytes:?}",
        );
        assert!(
            bytes.ends_with('\n'),
            "fusion must terminate with a trailing `\\n` — the pre-lift \
             stanza's `print_numbered_check_heading` delegate closed \
             on `writeln!`, not `write!`. Bytes: {bytes:?}",
        );
        let lines: Vec<&str> = bytes.split('\n').collect();
        // A leading `\n` + `Check 2: …\n` splits into three parts:
        // `["", "Check 2: …", ""]` — the pre-lift stanza is exactly
        // two `println!`s (the framing blank + the heading), and a
        // regression that spilled a third line (a trailing blank,
        // a doubled heading) fails here.
        assert_eq!(
            lines.len(),
            3,
            "fusion must split into exactly three parts via `\\n` — \
             leading empty, heading, trailing empty — matching the \
             pre-lift `println!(); println!(<heading>);` two-`println!` \
             shape. Got {} parts: {:?}",
            lines.len(),
            lines,
        );
    }

    /// Byte-oracle pin for a second variant (index 3, the em-dash-
    /// bearing `Object Type → Entity Mapping` title). The em-dash
    /// (`→`, U+2192) is a 3-byte UTF-8 code point that survives the
    /// `writeln!` render intact — a regression that swapped it for
    /// ASCII `->` or dropped it entirely regresses this. The two
    /// oracles together pin variance across index AND title, so a
    /// hard-code of either would fail one arm.
    #[test]
    fn write_check3_object_type_mapping_line_pins_two_line_fusion() {
        let mut buf = Vec::new();
        write_rebac_check_heading_with_gap(&mut buf, 3, "Object Type → Entity Mapping").unwrap();
        let bytes = String::from_utf8(buf).unwrap();
        assert!(
            bytes.starts_with('\n'),
            "fusion must open with the framing blank. Bytes: {bytes:?}",
        );
        assert!(
            bytes.contains("Check 3: Object Type → Entity Mapping"),
            "fusion must carry the U+2192 em-dash-bearing title \
             verbatim — a swap to ASCII `->` regresses this. \
             Bytes: {bytes:?}",
        );
        assert!(
            bytes.ends_with('\n'),
            "fusion must terminate with a trailing `\\n`. Bytes: {bytes:?}",
        );
    }

    /// The leading framing blank MUST precede the heading, not follow
    /// it. Pre-lift the sites spelled
    /// `println!(); crate::ui::print_numbered_check_heading(…)` in
    /// that order — the blank frames the SPACE between the prior
    /// check's output and this check's heading, not the space between
    /// this heading and the check body that follows. A regression
    /// that swapped the order would surface a heading at the tail of
    /// the previous check and float THIS check's body under a
    /// trailing blank, breaking the operator-trained visual grouping.
    #[test]
    fn write_emits_framing_blank_before_heading_not_after() {
        let mut buf = Vec::new();
        write_rebac_check_heading_with_gap(&mut buf, 5, "Redis Key Pattern Validation").unwrap();
        let bytes = String::from_utf8(buf).unwrap();
        // Byte-0 is the framing blank; byte-1..$ is the heading line
        // delegated to `write_numbered_check_heading`. The first
        // occurrence of `Check ` sits AFTER byte-0, not at byte-0.
        assert_eq!(
            bytes.as_bytes().first(),
            Some(&b'\n'),
            "framing blank must be the FIRST byte, not the last — the \
             pre-lift `println!(); print_numbered_check_heading(…)` \
             order places the blank ahead of the heading. Bytes: {bytes:?}",
        );
        let check_pos = bytes.find("Check ").expect(
            "fusion must carry the `Check <N>: <title>` heading layout \
             somewhere after the framing blank",
        );
        assert!(
            check_pos > 0,
            "the `Check ` heading prefix must sit AFTER byte-0 (the \
             framing blank), not AT byte-0. Bytes: {bytes:?}",
        );
    }

    /// Quiet-gate contract: [`print_rebac_check_heading_with_gap`]
    /// must suppress BOTH the framing blank and the heading when
    /// `quiet == true`, matching the pre-lift
    /// `if !config.quiet { println!(); print_numbered_check_heading(…); }`
    /// gate every site carried. The negative caller shield in the
    /// consumer module forbids bare
    /// `crate::ui::print_numbered_check_heading(<N>, …)` calls for
    /// `N ∈ {2..=7}` — but only this contract prevents a "silently
    /// drop the quiet gate" cleanup from surfacing headings under
    /// `--quiet` where the operator has explicitly asked for silence.
    ///
    /// The behavioural pin is a structural scan of the primitive
    /// body for the `if quiet { return; }` early-out — a naked
    /// `writeln!` at the top of the body would emit the framing
    /// blank unconditionally.
    #[test]
    fn primitive_body_carries_quiet_early_return_gate() {
        let source = include_str!("rebac_check_heading_with_gap.rs");
        let body = crate::test_support::module_body_before_first_cfg_test(
            source,
            "rebac_check_heading_with_gap.rs",
        );
        assert!(
            body.contains("if quiet {"),
            "primitive body must carry a `if quiet {{ return; }}` early-out — a \
             cleanup that dropped the gate would print the heading under \
             `--quiet` where the operator explicitly asked for silence.",
        );
        assert!(
            body.contains("return;"),
            "primitive body must return early when `quiet` — the gate cannot be \
             a no-op `if quiet {{ }}` that falls through to the unconditional \
             writeln.",
        );
    }

    /// Delegation shield: the writer body must forward the heading
    /// grammar through [`crate::ui::write_numbered_check_heading`]
    /// rather than restating the `Check <N>: <title>` layout, the
    /// `\x1b[34m` blue palette, or the trailing newline inline. A
    /// regression that re-spelled the heading here would fork the
    /// grammar off its ONE typed body in `cli/src/ui.rs`, so a
    /// future palette or layout adjustment would land at
    /// `write_numbered_check_heading` and drift silently past this
    /// module.
    #[test]
    fn primitive_body_delegates_heading_grammar_to_write_numbered_check_heading() {
        let source = include_str!("rebac_check_heading_with_gap.rs");
        let body = crate::test_support::module_body_before_first_cfg_test(
            source,
            "rebac_check_heading_with_gap.rs",
        );
        assert!(
            body.contains("crate::ui::write_numbered_check_heading("),
            "primitive body must delegate the `Check <N>: <title>` heading \
             grammar to `crate::ui::write_numbered_check_heading` — a \
             restated `writeln!(w, \"{{}}\", format!(\"Check {{}}: {{}}\", …).blue())` \
             would fork the palette off its ONE typed body in `cli/src/ui.rs`.",
        );
    }
}
