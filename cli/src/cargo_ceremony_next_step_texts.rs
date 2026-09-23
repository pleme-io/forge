//! Canonical instruction texts for the `cargo`-ceremony `Next steps:`
//! rows that trail the shared step-1 `"Review the changes: git diff"`
//! opener owned by
//! [`crate::next_steps_review_the_changes_opener`].
//!
//! Two instruction strings previously survived as inline `&str`
//! literals at every `crate::ui::print_next_step(<N>, "…")` call site:
//!
//! - `"Test the build: cargo build"` — the recommended validation
//!   step after a `cargo update`-driven closer, previously spelled
//!   inline at `commands/web_service.rs::web_cargo_update` (:254) and
//!   `commands/developer_tools.rs::rust_cargo_update` (:407).
//! - `"Commit both files: git add Cargo.lock Cargo.nix && git commit"` —
//!   the ceremony-specific commit instruction paired with every
//!   `crate2nix`-driven regenerate / update closer that produces the
//!   `Cargo.lock` + `Cargo.nix` manifest pair, previously spelled
//!   inline at `commands/developer_tools.rs::rust_regenerate` (:368)
//!   and `commands/developer_tools.rs::rust_cargo_update` (:410).
//!
//! Each string appears at TWO byte-identical sites — the "two is a
//! coincidence" floor that turns into a real duplication class the
//! moment a future edit reaches only one copy. Pinning them as
//! `pub const` constants closes the drift class at the type level: a
//! rename, a `--release` flag addition, a swap of the `&&` join for a
//! `;` join, or a change from `Cargo.lock Cargo.nix` to a broader
//! `-A` pattern lands in one place and reaches every consumer by
//! construction.
//!
//! # Distinct from
//! [`crate::next_steps_review_the_changes_opener::REVIEW_THE_CHANGES_STEP_1_TEXT`]
//!
//! The sibling module owns the ONE shared step-1 opener text every
//! `Next steps:` ceremony emits before its per-ceremony step-2 / step-3
//! tail. This module owns the step-2 / step-3 tails specific to
//! `cargo`-ceremony closers — a distinct concern with a distinct
//! (2 + 2) call-site census, kept in its own module so a future addition
//! (say a `"Push to registry: cargo publish"` step-4 tail) has an
//! obvious home without widening the step-1-opener primitive.
//!
//! # THEORY grounding
//!
//! - THEORY.md §V.1 (Construction guarantees; Types → Invariants →
//!   Proofs → Render Anywhere): the print helpers delegate to
//!   [`crate::ui::print_next_step`], which is the single source of
//!   truth for the `  <N>. <text>\n` numbered-row grammar. The
//!   constants pin the per-ceremony instruction text as a
//!   `cargo test`-verifiable invariant so a typo, a rename, or a
//!   drift in the argv-shell composition fails at build time rather
//!   than at operator readout.
//! - THEORY.md §VI.1 (three-times rule): two byte-identical siblings
//!   per string sit at the floor of the duplication class; pinning
//!   them here forecloses the third-site copy-paste before it lands.

/// Canonical step-text every `cargo`-ceremony closer emits to invite
/// the operator to validate the working-tree state with a local build
/// after the ceremony's own writes settle.
///
/// Pre-lift consumers spelled this text inline as the second argument
/// to `crate::ui::print_next_step(<N>, "Test the build: cargo build")`
/// at two sibling sites in `commands/{web_service.rs,
/// developer_tools.rs}`. A `pub const` closes the copy-paste class so
/// a future rename (say to `"Test the build: nix build .#backend"`, or
/// to `"Test the build: cargo build --release"`) lands in one place.
pub const TEST_THE_BUILD_TEXT: &str = "Test the build: cargo build";

/// Canonical step-text every `crate2nix`-driven closer emits to
/// instruct the operator on how to commit the `Cargo.lock` +
/// `Cargo.nix` manifest pair the ceremony produced or updated.
///
/// Pre-lift consumers spelled this text inline as the second argument
/// to `crate::ui::print_next_step(<N>, "Commit both files: git add
/// Cargo.lock Cargo.nix && git commit")` at two sibling sites in
/// `commands/developer_tools.rs`. A `pub const` closes the copy-paste
/// class so a future rename (say to append `-m 'chore: regenerate
/// Cargo.nix'`, or to swap the `&&` join for a `;` join) lands in one
/// place.
pub const COMMIT_CARGO_LOCK_AND_NIX_TEXT: &str =
    "Commit both files: git add Cargo.lock Cargo.nix && git commit";

/// Print the `  <index>. Test the build: cargo build\n` numbered row
/// to stdout via [`crate::ui::print_next_step`] with the canonical
/// [`TEST_THE_BUILD_TEXT`] instruction body.
///
/// `index` is the step number the caller wants — pre-lift consumers
/// pass `2` (both existing call sites). The helper takes the index
/// rather than baking it in because the two current sites both use
/// `2`, but the sibling `crate2nix`-regenerate closers use `3` for
/// analogous validation rows, and a future addition should pick its
/// own index without forking the primitive.
pub fn print_test_the_build_next_step(index: u32) {
    crate::ui::print_next_step(index, TEST_THE_BUILD_TEXT);
}

/// Print the `  <index>. Commit both files: git add Cargo.lock
/// Cargo.nix && git commit\n` numbered row to stdout via
/// [`crate::ui::print_next_step`] with the canonical
/// [`COMMIT_CARGO_LOCK_AND_NIX_TEXT`] instruction body.
///
/// `index` is the step number the caller wants — pre-lift consumers
/// pass `2` (`rust_regenerate`) or `3` (`rust_cargo_update`). The
/// helper takes the index rather than baking it in because the two
/// current sites disagree on it.
pub fn print_commit_cargo_lock_and_nix_next_step(index: u32) {
    crate::ui::print_next_step(index, COMMIT_CARGO_LOCK_AND_NIX_TEXT);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Pin the exact byte content of the two canonical constants. A
    /// future edit that rewrote either string trips this assertion
    /// before the change reaches any consumer, so the migration path
    /// is: update the constant here, update this assertion in the
    /// same commit, and every call site inherits by construction.
    #[test]
    fn canonical_texts_match_prelift_byte_form() {
        assert_eq!(TEST_THE_BUILD_TEXT, "Test the build: cargo build");
        assert_eq!(
            COMMIT_CARGO_LOCK_AND_NIX_TEXT,
            "Commit both files: git add Cargo.lock Cargo.nix && git commit"
        );
    }

    /// Signature pin: the two print helpers each accept one `u32`
    /// step index and return `()`. A future edit that widened either
    /// signature (say to take an optional prefix, or to return an
    /// `io::Result<()>`) would ripple to every caller and trip the
    /// type check.
    #[test]
    fn print_helpers_accept_step_index() {
        let _: fn(u32) = print_test_the_build_next_step;
        let _: fn(u32) = print_commit_cargo_lock_and_nix_next_step;
    }

    /// Slice the module's own source to the production body so the
    /// tests below can count delegation call sites without matching
    /// against needle-mentions inside their own `assert!` diagnostic
    /// messages.
    fn production_body() -> String {
        let source = include_str!("cargo_ceremony_next_step_texts.rs");
        let cutoff = source
            .find("#[cfg(test)]")
            .expect("production body ends at the test cfg attr");
        source[..cutoff].to_string()
    }

    /// Delegation pin: each print helper's body MUST forward through
    /// [`crate::ui::print_next_step`] with the paired canonical
    /// constant. A future edit that inlined the string literal or
    /// swapped in a sibling primitive (say [`crate::ui::print_next_steps_heading`])
    /// trips this assertion.
    #[test]
    fn print_helpers_delegate_through_ui_print_next_step_with_paired_const() {
        let body = production_body();
        let hits = crate::test_support::code_line_hits(&body, "crate::ui::print_next_step(index, ");
        assert_eq!(
            hits.len(),
            2,
            "production body must forward through \
             `crate::ui::print_next_step(index, <CONST>)` at exactly two \
             sites — one per print helper. Found {}: {:#?}",
            hits.len(),
            hits
        );
        let mentions_test_the_build = hits.iter().any(|l| l.contains("TEST_THE_BUILD_TEXT"));
        let mentions_commit_cargo_lock_and_nix = hits
            .iter()
            .any(|l| l.contains("COMMIT_CARGO_LOCK_AND_NIX_TEXT"));
        assert!(
            mentions_test_the_build,
            "one forward site must pair `crate::ui::print_next_step(index, TEST_THE_BUILD_TEXT)`; got {hits:#?}"
        );
        assert!(
            mentions_commit_cargo_lock_and_nix,
            "one forward site must pair `crate::ui::print_next_step(index, COMMIT_CARGO_LOCK_AND_NIX_TEXT)`; got {hits:#?}"
        );
    }

    /// Positive delegation shield: every pre-lift command module MUST
    /// forward through this primitive at least the migrated count, so
    /// a migration that dropped a call site outright leaves the
    /// negative "no raw instruction string literal" scan (below)
    /// trivially satisfied by absence but the positive count still
    /// fails.
    ///
    /// `web_service.rs`: 1 forward (`web_cargo_update`).
    /// `developer_tools.rs`: 3 forwards (`rust_regenerate` +
    /// `rust_cargo_update` at step-2, `rust_cargo_update` at step-3).
    #[test]
    fn every_prelift_module_forwards_through_a_print_helper() {
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let expectations: &[(&str, usize)] = &[("web_service.rs", 1), ("developer_tools.rs", 3)];
        for (basename, min_count) in expectations {
            let path = commands_dir.join(basename);
            let source = std::fs::read_to_string(&path).unwrap();
            let test_the_build_forwards =
                crate::test_support::code_line_hits(&source, "print_test_the_build_next_step(")
                    .len();
            let commit_forwards = crate::test_support::code_line_hits(
                &source,
                "print_commit_cargo_lock_and_nix_next_step(",
            )
            .len();
            let total = test_the_build_forwards + commit_forwards;
            assert!(
                total >= *min_count,
                "{basename} must forward at least {min_count} \
                 cargo-ceremony next-step stanza(s) through \
                 `crate::cargo_ceremony_next_step_texts::print_*_next_step(`; \
                 found {total}. A dropped call would leave the negative \
                 raw-literal scan satisfied by absence.",
            );
        }
    }

    /// Caller shield (negative half): no source line under
    /// `cli/src/commands/` may spell either canonical instruction
    /// text inline as the second argument to
    /// [`crate::ui::print_next_step`] any more. The four pre-lift
    /// sites migrated; any future consumer that wants the same row
    /// reaches for one of the two print helpers on first grep, not by
    /// copy-pasting the string literal from an existing site.
    #[test]
    fn no_command_module_still_spells_raw_instruction_literal() {
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let mut offenders: Vec<(PathBuf, usize, String, &'static str)> = Vec::new();
        // Reconstruct the needle at test time so this shield's own
        // source text does not false-match itself.
        let test_build_needle = TEST_THE_BUILD_TEXT.to_string();
        let commit_needle = COMMIT_CARGO_LOCK_AND_NIX_TEXT.to_string();
        for entry in std::fs::read_dir(&commands_dir).unwrap().flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).unwrap();
            for (i, line) in source.lines().enumerate() {
                let t = line.trim_start();
                if t.starts_with("//") {
                    continue;
                }
                if line.contains("print_next_step(") && line.contains(&test_build_needle) {
                    offenders.push((
                        path.clone(),
                        i + 1,
                        line.trim().to_string(),
                        "TEST_THE_BUILD_TEXT",
                    ));
                }
                if line.contains("print_next_step(") && line.contains(&commit_needle) {
                    offenders.push((
                        path.clone(),
                        i + 1,
                        line.trim().to_string(),
                        "COMMIT_CARGO_LOCK_AND_NIX_TEXT",
                    ));
                }
            }
            // Also catch the multi-line spelling where the literal
            // lands on its own indented line under a wrapped
            // `print_next_step(<N>,\n    "...",\n)` call.
            let lines: Vec<&str> = source.lines().collect();
            for i in 1..lines.len() {
                let prior = lines[i - 1].trim_start();
                if prior.starts_with("//") {
                    continue;
                }
                if !prior.contains("print_next_step(") {
                    continue;
                }
                let this_line_trimmed = lines[i].trim();
                if this_line_trimmed == format!("\"{}\",", test_build_needle)
                    || this_line_trimmed == format!("\"{}\"", test_build_needle)
                {
                    offenders.push((
                        commands_dir.join(entry.file_name()),
                        i + 1,
                        lines[i].to_string(),
                        "TEST_THE_BUILD_TEXT",
                    ));
                }
                if this_line_trimmed == format!("\"{}\",", commit_needle)
                    || this_line_trimmed == format!("\"{}\"", commit_needle)
                {
                    offenders.push((
                        commands_dir.join(entry.file_name()),
                        i + 1,
                        lines[i].to_string(),
                        "COMMIT_CARGO_LOCK_AND_NIX_TEXT",
                    ));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw cargo-ceremony next-step instruction literal(s) survive \
             under `commands/` — route each through \
             `crate::cargo_ceremony_next_step_texts::print_test_the_build_next_step(<N>)` \
             or `print_commit_cargo_lock_and_nix_next_step(<N>)` instead:\n{offenders:#?}"
        );
    }
}
