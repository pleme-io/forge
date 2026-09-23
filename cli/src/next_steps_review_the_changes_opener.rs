//! Two-line opener stanza for the "Next steps:" post-completion
//! instruction list every `crate2nix`-driven regenerate / update
//! workflow emits after
//! [`crate::cargo_lock_and_cargo_nix_bullets::print_cargo_lock_and_cargo_nix_bullets_with_blank`]
//! (or, in the `web_regenerate` case, after the ad-hoc `deps.nix` +
//! `Cargo.nix` bullet pair) — the fused pairing of
//! [`crate::ui::print_next_steps_heading`] followed immediately by
//! [`crate::ui::print_next_step`] with index `1` and the literal
//! instruction text `"Review the changes: git diff"`.
//!
//! # Pre-lift census — four sibling two-line openers
//!
//! Four pre-lift sibling two-line stanzas — two in
//! `commands/web_service.rs` (`web_regenerate` at :185-186;
//! `web_cargo_update` at :269-270) and two in
//! `commands/developer_tools.rs` (`rust_regenerate` at :386-387;
//! `rust_cargo_update` at :432-433) each restated
//!
//! ```ignore
//! crate::ui::print_next_steps_heading();
//! crate::ui::print_next_step(1, "Review the changes: git diff");
//! ```
//!
//! byte-for-byte, differing only in the step-2 (and optional step-3)
//! instruction rows that trail the shared step-1 opener:
//!
//! 1. `commands/web_service.rs::web_regenerate` (:185-186) — Hanabi
//!    `deps.nix` + `Cargo.nix` regeneration closer; step-2 tail is
//!    `"Commit: git add -A && git commit -m 'chore: regenerate deps'"`.
//! 2. `commands/web_service.rs::web_cargo_update` (:269-270) — Hanabi
//!    `cargo update` closer; step-2 tail is
//!    `"Test the build: cargo build"` and step-3 tail is
//!    `"Commit: git add -A && git commit -m 'chore: update Hanabi deps'"`.
//! 3. `commands/developer_tools.rs::rust_regenerate` (:386-387) —
//!    generic rust-service `Regeneration`-ceremony closer; step-2 tail
//!    is `"Commit both files: git add Cargo.lock Cargo.nix && git commit"`.
//! 4. `commands/developer_tools.rs::rust_cargo_update` (:432-433) —
//!    generic rust-service `Update`-ceremony closer; step-2 tail is
//!    `"Test the build: cargo build"` and step-3 tail is
//!    `"Commit both files: git add Cargo.lock Cargo.nix && git commit"`.
//!
//! Four sibling occurrences clear THEORY.md §VI.1's "two is a
//! coincidence, three is a law" threshold. Post-lift the four stanzas
//! route through [`print_next_steps_heading_then_review_the_changes`];
//! a rename of the shared step-1 instruction (say to
//! `"Diff the changes: git diff --stat"`), a renumbering (say to a
//! step-0 opener), or an insertion of a blank between the heading and
//! the step-1 line lands at ONE typed body and reaches all four
//! consumers by construction.
//!
//! # Coupling being pinned
//!
//! The heading label and the step-1 instruction are not independent:
//! every one of the four pre-lift ceremony closers uses the same
//! `"Review the changes: git diff"` as its step-1 row — the shared
//! convention that a `crate2nix` / `cargo update` completion invites
//! the operator to inspect the working-tree delta before proceeding.
//! Pre-lift each site nailed the same instruction into two
//! independent inline calls, and a copy-paste that renumbered the
//! opener to step 2, dropped the heading, or misspelled the
//! instruction text compiled clean and silently mismatched the
//! operator's read. Post-lift the pairing lives at one function body
//! and the copy-paste hazard is foreclosed at the type level.
//!
//! # Distinct from the sibling `print_next_steps_heading` frontier
//!
//! [`crate::ui::print_next_steps_heading`] owns the ONE
//! `Next steps:\n` plain-heading grammar used across the fleet's
//! post-completion instruction surfaces (this primitive plus the
//! `commands/sync.rs::codegen` closer, whose step-1 row emits
//! `"Review generated files in web/src/gql/"` rather than the shared
//! `"Review the changes: git diff"` this primitive owns). This
//! primitive is one dedicated fusion specialization for the
//! (`Next steps:`, `1. Review the changes: git diff`) pairing — the
//! same architectural split
//! [`crate::cargo_lock_and_cargo_nix_bullets`] carries against
//! [`crate::ui::print_bullet_path`], and
//! [`crate::cargo_nix_ceremony_banner`] carries against
//! [`crate::ui::print_success_banner`]. The primitive stays a
//! pairing-and-ordering owner (heading → step-1), not a
//! heading-render-behavior owner, so a future re-shaping of the
//! underlying `Next steps:` label or the `  <N>. <text>\n` numbered
//! row grammar lands at [`crate::ui::write_next_steps_heading`] /
//! [`crate::ui::write_next_step`] and this primitive inherits by
//! composition.
//!
//! # THEORY grounding
//!
//! - THEORY.md §V.1 (Construction guarantees; Types → Invariants →
//!   Proofs → Render Anywhere): the paired byte-oracle sibling
//!   [`write_next_steps_heading_then_review_the_changes`] is the
//!   Render Anywhere half — pinning the exact two-line rendered
//!   bytes as a `cargo test`-verifiable invariant so a fusion that
//!   dropped the heading, inverted the two lines, or misspelled the
//!   instruction text fails at `cargo test` time rather than at
//!   operator readout.
//! - THEORY.md §VI.1 (three-times rule): four sibling occurrences
//!   past the "two is a coincidence; three is a law" threshold, so
//!   the two-line stanza lifts onto ONE typed body.

use std::io;

/// Canonical instruction text every pre-lift consumer spelled inline
/// as the second argument to `crate::ui::print_next_step(1, ...)` —
/// the shared step-1 opener that invites the operator to inspect the
/// working-tree delta before proceeding to the ceremony-specific
/// step-2 / step-3 rows. Pinned as a `pub const` so consumers that
/// want to assert against the instruction text (a fleet-wide sweep,
/// a downstream log filter) read the same constant the writer emits
/// rather than re-typing the string literal.
pub const REVIEW_THE_CHANGES_STEP_1_TEXT: &str = "Review the changes: git diff";

/// Print the two-line
/// `Next steps:\n  1. Review the changes: git diff\n` opener to
/// stdout — the fusion primitive four pre-lift sibling sites in
/// `commands/{web_service.rs, developer_tools.rs}` each spelled
/// inline via two independent
/// [`crate::ui::print_next_steps_heading`] + [`crate::ui::print_next_step`]
/// calls with the shared step-1 index and instruction text.
///
/// Delegates through [`crate::ui::print_next_steps_heading`] /
/// [`crate::ui::print_next_step`] so the underlying `Next steps:\n`
/// plain-heading grammar and the `  <N>. <text>\n` numbered-row
/// grammar keep single sources of truth — a future re-shaping of
/// either half rides through this primitive by construction.
pub fn print_next_steps_heading_then_review_the_changes() {
    crate::ui::print_next_steps_heading();
    crate::ui::print_next_step(1, REVIEW_THE_CHANGES_STEP_1_TEXT);
}

/// Byte-oracle sibling of
/// [`print_next_steps_heading_then_review_the_changes`] — writes the
/// same two lines to any [`std::io::Write`] so a `#[test]` can
/// capture and compare them without shelling out and grepping stdout.
///
/// Delegates to [`crate::ui::write_next_steps_heading`] and
/// [`crate::ui::write_next_step`] so the primitive keeps a single
/// source of truth for the outer heading and numbered-row byte
/// templates; the pairing owns only the ordering and the shared
/// step-1 instruction text.
///
/// # `#[allow(dead_code)]` intent
///
/// The production entry point
/// [`print_next_steps_heading_then_review_the_changes`] delegates to
/// the stdout-adapter forms
/// ([`crate::ui::print_next_steps_heading`] /
/// [`crate::ui::print_next_step`]) rather than this writer sibling,
/// so a non-test build sees no caller. The writer split exists so
/// byte-oracle tests can pin the exact two-line rendered bytes; the
/// same pattern
/// [`crate::cargo_lock_and_cargo_nix_bullets::write_cargo_lock_and_cargo_nix_bullets_with_blank`]
/// carries against its stdout sibling.
#[allow(dead_code)]
pub fn write_next_steps_heading_then_review_the_changes<W: io::Write>(w: &mut W) -> io::Result<()> {
    crate::ui::write_next_steps_heading(w)?;
    crate::ui::write_next_step(w, 1, REVIEW_THE_CHANGES_STEP_1_TEXT)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Const-anchor pin: the canonical `"Review the changes: git diff"`
    /// step-1 instruction text all four pre-lift sites spelled
    /// verbatim.
    #[test]
    fn review_the_changes_step_1_text_carries_pre_lift_bytes() {
        assert_eq!(
            REVIEW_THE_CHANGES_STEP_1_TEXT,
            "Review the changes: git diff"
        );
    }

    /// Byte-oracle: the opener emits exactly two lines — a plain
    /// uncolored `Next steps:` heading and a two-space indented
    /// `  1. Review the changes: git diff` numbered row — each
    /// terminated by a single `\n`. A future refactor that dropped
    /// the heading, renumbered the opener to step 2, or misspelled
    /// the instruction text regresses this assertion.
    #[test]
    fn write_opener_emits_exact_two_line_shape() {
        let mut buf: Vec<u8> = Vec::new();
        write_next_steps_heading_then_review_the_changes(&mut buf)
            .expect("write against a Vec<u8> writer must succeed");
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "Next steps:\n  1. Review the changes: git diff\n",
        );
    }

    /// Order pin: the `Next steps:` heading MUST precede the
    /// numbered `1. Review the changes: git diff` row — matching
    /// the pre-lift emission order across all four sites. A future
    /// refactor that inverted the two lines (rendering the row
    /// before its heading label) would break the operator's mental
    /// model.
    #[test]
    fn write_opener_emits_heading_before_step_1() {
        let mut buf: Vec<u8> = Vec::new();
        write_next_steps_heading_then_review_the_changes(&mut buf).unwrap();
        let rendered = String::from_utf8(buf).unwrap();
        let heading_pos = rendered.find("Next steps:").expect("heading present");
        let step_pos = rendered.find("1.").expect("step row present");
        assert!(
            heading_pos < step_pos,
            "`Next steps:` must appear before `1.` — got heading \
             at {heading_pos}, step at {step_pos}",
        );
    }

    /// Line-count pin: exactly two `\n` bytes (one heading + one
    /// numbered row). A future refactor that inserted a blank
    /// between them or dropped one line would flip this assertion.
    #[test]
    fn write_opener_emits_exactly_two_newlines() {
        let mut buf: Vec<u8> = Vec::new();
        write_next_steps_heading_then_review_the_changes(&mut buf).unwrap();
        let newlines = buf.iter().filter(|&&b| b == b'\n').count();
        assert_eq!(
            newlines, 2,
            "expected exactly two `\\n` bytes (heading + step-1); \
             got {newlines}. Bytes: {buf:?}",
        );
    }

    /// No-ANSI guard: the byte-oracle writer's payload carries no
    /// ANSI escape byte (0x1B). Matches the pre-lift
    /// `print_next_steps_heading` / `print_next_step` convention
    /// that the "Next steps:" family carries no palette on either
    /// the heading label or the numbered instruction body.
    #[test]
    fn write_opener_emits_no_ansi_escape() {
        let mut buf: Vec<u8> = Vec::new();
        write_next_steps_heading_then_review_the_changes(&mut buf).unwrap();
        assert!(
            !buf.contains(&0x1b),
            "opener must emit no ANSI escape (0x1B) — the \
             `Next steps:` family carries no palette on either the \
             heading or the numbered instruction row. Bytes: {buf:?}",
        );
    }

    /// Const shares the heading label with the underlying writer:
    /// the primitive's byte-oracle output re-uses
    /// [`crate::ui::NEXT_STEPS_HEADING_TEXT`] via
    /// [`crate::ui::write_next_steps_heading`], so a rename of the
    /// underlying constant rides through this primitive automatically.
    #[test]
    fn write_opener_reuses_ui_next_steps_heading_text_constant() {
        let mut buf: Vec<u8> = Vec::new();
        write_next_steps_heading_then_review_the_changes(&mut buf).unwrap();
        let rendered = String::from_utf8(buf).unwrap();
        assert!(
            rendered.starts_with(crate::ui::NEXT_STEPS_HEADING_TEXT),
            "opener must begin with `crate::ui::NEXT_STEPS_HEADING_TEXT` \
             — a drift in the heading label would reach this primitive \
             through the underlying writer. Got: {rendered:?}",
        );
    }

    /// Caller shield (negative half): no source line under
    /// `cli/src/commands/` may spell the pre-lift raw two-call
    /// `print_next_steps_heading()` + `print_next_step(1, "Review the
    /// changes: git diff")` pair inline any more. The four pre-lift
    /// sites migrated; any future consumer that wants the same
    /// opener reaches for
    /// [`print_next_steps_heading_then_review_the_changes`] on first
    /// grep, not by copy-pasting the two-line shape from an existing
    /// site. The scan looks for a `print_next_steps_heading()` call
    /// on one line followed immediately by a
    /// `print_next_step(1, "Review the changes: git diff")` call on
    /// the next — the exact pre-lift fingerprint — so unrelated
    /// inline `print_next_steps_heading` calls elsewhere in the file
    /// (e.g. the `sync.rs::codegen` closer, which pairs the heading
    /// with a different step-1 instruction) are not caught.
    #[test]
    fn no_command_module_still_spells_raw_next_steps_review_pair() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let mut offenders: Vec<(PathBuf, usize, String)> = Vec::new();
        for entry in std::fs::read_dir(&commands_dir).unwrap().flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).unwrap();
            let lines: Vec<&str> = source.lines().collect();
            for i in 0..lines.len().saturating_sub(1) {
                let a = lines[i];
                let b = lines[i + 1];
                let a_trim = a.trim_start();
                let b_trim = b.trim_start();
                if a_trim.starts_with("//") || b_trim.starts_with("//") {
                    continue;
                }
                if a.contains("print_next_steps_heading()")
                    && b.contains("print_next_step(")
                    && b.contains("\"Review the changes: git diff\"")
                {
                    offenders.push((path.clone(), i + 1, format!("{}\n{}", a, b)));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `print_next_steps_heading() + \
             print_next_step(1, \"Review the changes: git diff\")` \
             opener pair(s) survive under `commands/` — route each \
             through `crate::next_steps_review_the_changes_opener::\
             print_next_steps_heading_then_review_the_changes()` \
             instead:\n{:#?}",
            offenders
        );
    }

    /// Caller shield (positive half): the pre-lift modules that
    /// housed the four sites MUST forward through
    /// [`print_next_steps_heading_then_review_the_changes`] — either
    /// DIRECTLY or INDIRECTLY via
    /// [`crate::cargo_nix_ceremony_summary_opener::print_cargo_nix_ceremony_summary_opener`],
    /// which delegates through this primitive — at least the pre-lift
    /// count of times, so a migration that dropped a call site
    /// outright leaves the negative "no raw inline shape" scan
    /// trivially satisfied by absence but the positive count still
    /// fails. Mirrors the sibling
    /// `every_prelift_module_forwards_through_cargo_lock_and_cargo_nix_bullets`
    /// shield in [`crate::cargo_lock_and_cargo_nix_bullets`].
    #[test]
    fn every_prelift_module_forwards_through_next_steps_review_opener() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let expectations: &[(&str, usize)] = &[("web_service.rs", 2), ("developer_tools.rs", 2)];
        let direct_needle = "print_next_steps_heading_then_review_the_changes(";
        // Reconstruct the indirect needle via `format!` so this
        // shield's own source text does not false-match itself.
        let indirect_needle = format!("{}(", "print_cargo_nix_ceremony_summary_opener");
        for (basename, min_count) in expectations {
            let path = commands_dir.join(basename);
            let source = std::fs::read_to_string(&path)
                .unwrap_or_else(|_| panic!("expected {} to exist", path.display()));
            let direct = source.matches(direct_needle).count();
            let indirect = source.matches(indirect_needle.as_str()).count();
            let forwards = direct + indirect;
            assert!(
                forwards >= *min_count,
                "{basename} must forward at least {min_count} \
                 (Next steps: heading + Review-the-changes step-1) \
                 opener stanza(s) through `{direct_needle}` (direct) or \
                 `crate::cargo_nix_ceremony_summary_opener::print_cargo_nix_ceremony_summary_opener(` \
                 (indirect via the summary opener); found \
                 {direct} direct + {indirect} indirect = {forwards}. \
                 A dropped call would leave the negative raw-shape scan \
                 satisfied by absence.",
            );
        }
    }
}
