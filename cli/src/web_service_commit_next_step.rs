//! Canonical `Commit: git add -A && git commit -m 'chore: <verb>'`
//! next-step instruction texts for the two `web_service.rs` closers
//! that trail their `Cargo.lock` / `Cargo.nix` regenerate / update
//! ceremonies.
//!
//! # Duplication being lifted
//!
//! Two byte-close sibling
//! `crate::ui::print_next_step(<N>, "Commit: git add -A && git commit
//! -m 'chore: <phrase>'")` stanzas survived as inline `&str` literals
//! at the closer of every `web_service.rs` ceremony:
//!
//! - `commands/web_service.rs::web_regenerate` (~L183-186):
//!   `print_next_step(2, "Commit: git add -A && git commit -m 'chore:
//!   regenerate deps'")` — the closer instruction the frontend
//!   deps.nix + Hanabi Cargo.nix regeneration ceremony emits after
//!   the `bullet_path` list of the two produced manifests.
//! - `commands/web_service.rs::web_cargo_update` (~L255-258):
//!   `print_next_step(3, "Commit: git add -A && git commit -m 'chore:
//!   update Hanabi deps'")` — the closer instruction the Hanabi
//!   `cargo update` + `crate2nix generate` ceremony emits after the
//!   sibling `Test the build: cargo build` step-2 row.
//!
//! Each stanza carried the same 46-byte frame
//! `"Commit: git add -A && git commit -m 'chore: <phrase>'"` around
//! two byte-close chore verb-phrases — `"regenerate deps"` and
//! `"update Hanabi deps"`. The two pre-lift sites are the "two is a
//! coincidence" floor that turns into a real duplication class the
//! moment a future edit reaches only one copy — a swap of `-A` for a
//! narrower path list, a change from `&&` to `;`, or a rename of the
//! `chore:` type prefix would silently drift between the two ceremony
//! closers. Pinning the frame + phrase pair as a closed enum whose
//! render is the inverse of the pre-lift byte form closes the drift
//! class at the type level: a rename lands in one place and reaches
//! every consumer by construction.
//!
//! # Distinct from the sibling cargo-ceremony next-step primitives
//!
//! [`crate::cargo_ceremony_next_step_texts`] owns the two byte-fixed
//! `Test the build: cargo build` and `Commit both files: git add
//! Cargo.lock Cargo.nix && git commit` next-step texts every
//! `crate2nix`-driven closer emits — those are ceremony-specific
//! (Cargo.lock + Cargo.nix path list) and per-file rather than
//! all-files. This module owns the `web_service.rs`-specific
//! `git add -A && git commit -m 'chore: <phrase>'` frame, which is
//! all-files and per-ceremony rather than per-file — a distinct
//! concern with a distinct call-site census (2 sites in one file
//! today) kept in its own module so a future addition (say a
//! `commands/pangea.rs` regen closer that wants an analogous
//! `chore: <phrase>` commit row) has an obvious home without widening
//! the cargo-ceremony primitive.
//!
//! # THEORY grounding
//!
//! - THEORY.md §V.1 (Construction guarantees; Types → Invariants →
//!   Proofs → Render Anywhere): the print helper delegates through
//!   [`crate::ui::print_next_step`], which is the single source of
//!   truth for the `  <N>. <text>\n` numbered-row grammar. The
//!   closed enum pins the per-ceremony `chore: <phrase>` verb-phrase
//!   projection as a `cargo test`-verifiable invariant so a typo,
//!   a rename, or a drift in the frame composition fails at build
//!   time rather than at operator readout.
//! - THEORY.md §VI.1 (three-times rule): two byte-close siblings per
//!   frame sit at the floor of the duplication class; pinning them
//!   here forecloses the third-site copy-paste before it lands.

/// Which `web_service.rs` closer this `Commit: git add -A && git
/// commit -m 'chore: <phrase>'` row is trailing — the choice pins the
/// exact chore verb-phrase every pre-lift site spelled inline as the
/// tail of the second argument to
/// [`crate::ui::print_next_step`].
///
/// The two variants correspond to the two ceremony entry points
/// `commands/web_service.rs` ships:
///
/// - [`WebServiceCommitChoreVerb::RegenerateDeps`] — the closer
///   trailing `web_regenerate`'s frontend deps.nix + Hanabi Cargo.nix
///   regeneration.
/// - [`WebServiceCommitChoreVerb::UpdateHanabiDeps`] — the closer
///   trailing `web_cargo_update`'s Hanabi `cargo update` +
///   `crate2nix generate` update.
///
/// # Closed enum, deliberate
///
/// A new ceremony variant is a deliberate additive edit here, not an
/// open call-site choice. Exhaustiveness against the sole projection
/// [`Self::chore_verb_phrase`] then compiles as a match-arm
/// requirement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WebServiceCommitChoreVerb {
    /// The `web_regenerate` closer — the row reads
    /// `"Commit: git add -A && git commit -m 'chore: regenerate
    /// deps'"`.
    RegenerateDeps,
    /// The `web_cargo_update` closer — the row reads
    /// `"Commit: git add -A && git commit -m 'chore: update Hanabi
    /// deps'"`.
    UpdateHanabiDeps,
}

/// The fixed frame every pre-lift consumer spelled around the
/// per-ceremony chore verb-phrase. Pinning it as a `pub const` closes
/// the drift class so a future edit (say a swap of `-A` for
/// `<paths>`, or of `&&` for `;`) lands at ONE line rather than at
/// every ceremony closer.
///
/// The `{}` placeholder is the [`WebServiceCommitChoreVerb::chore_verb_phrase`]
/// projection; [`WebServiceCommitChoreVerb::commit_next_step_text`]
/// is the sole formatter that splices it in.
pub const COMMIT_ALL_CHORE_NEXT_STEP_FRAME: &str =
    "Commit: git add -A && git commit -m 'chore: {}'";

impl WebServiceCommitChoreVerb {
    /// The chore verb-phrase projection: the exact byte-close phrase
    /// every pre-lift consumer spliced into the tail of the frame's
    /// `-m 'chore: <phrase>'` payload.
    pub const fn chore_verb_phrase(self) -> &'static str {
        match self {
            Self::RegenerateDeps => "regenerate deps",
            Self::UpdateHanabiDeps => "update Hanabi deps",
        }
    }

    /// Render the full `"Commit: git add -A && git commit -m 'chore:
    /// <phrase>'"` next-step text for this ceremony. The sole
    /// formatter that splices [`Self::chore_verb_phrase`] into
    /// [`COMMIT_ALL_CHORE_NEXT_STEP_FRAME`] — every consumer that
    /// wants the byte-close pre-lift text reaches through this
    /// method, not by re-spelling the frame at the call site.
    pub fn commit_next_step_text(self) -> String {
        format!(
            "Commit: git add -A && git commit -m 'chore: {}'",
            self.chore_verb_phrase()
        )
    }
}

/// Print the `  <index>. Commit: git add -A && git commit -m 'chore:
/// <phrase>'\n` numbered row to stdout via
/// [`crate::ui::print_next_step`] with the canonical
/// [`WebServiceCommitChoreVerb::commit_next_step_text`] instruction
/// body.
///
/// `index` is the step number the caller wants — pre-lift consumers
/// pass `2` (`web_regenerate`) and `3` (`web_cargo_update`). The
/// helper takes the index rather than baking it in because the two
/// sites disagree on it.
pub fn print_web_service_commit_next_step(index: u32, verb: WebServiceCommitChoreVerb) {
    crate::ui::print_next_step(index, &verb.commit_next_step_text());
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Pin the exact byte content of the frame const. A future edit
    /// that rewrote the frame (say by swapping `-A` for `<paths>`, or
    /// `&&` for `;`) trips this assertion before the change reaches
    /// any consumer, so the migration path is: update the const here,
    /// update this assertion in the same commit, and every call site
    /// inherits by construction.
    #[test]
    fn frame_const_matches_pre_lift_byte_form() {
        assert_eq!(
            COMMIT_ALL_CHORE_NEXT_STEP_FRAME,
            "Commit: git add -A && git commit -m 'chore: {}'"
        );
    }

    /// Byte-oracle for the [`WebServiceCommitChoreVerb::RegenerateDeps`]
    /// chore-verb projection: the pre-lift verb-phrase was
    /// `"regenerate deps"` verbatim. A rename to `"regenerate
    /// dependencies"` or `"regen deps"` regresses this assertion
    /// rather than silently drifting between the two closers.
    #[test]
    fn regenerate_deps_verb_matches_pre_lift_literal() {
        assert_eq!(
            WebServiceCommitChoreVerb::RegenerateDeps.chore_verb_phrase(),
            "regenerate deps"
        );
    }

    /// Byte-oracle for the [`WebServiceCommitChoreVerb::UpdateHanabiDeps`]
    /// chore-verb projection: the pre-lift verb-phrase was
    /// `"update Hanabi deps"` verbatim. A rename to `"update Hanabi
    /// dependencies"` or `"bump Hanabi deps"` regresses this
    /// assertion.
    #[test]
    fn update_hanabi_deps_verb_matches_pre_lift_literal() {
        assert_eq!(
            WebServiceCommitChoreVerb::UpdateHanabiDeps.chore_verb_phrase(),
            "update Hanabi deps"
        );
    }

    /// Full-text byte-oracle for [`WebServiceCommitChoreVerb::RegenerateDeps`]:
    /// the pre-lift full text was
    /// `"Commit: git add -A && git commit -m 'chore: regenerate
    /// deps'"` verbatim. Pins the fusion of the frame + verb-phrase
    /// projections rather than each half independently.
    #[test]
    fn regenerate_deps_full_text_matches_pre_lift_literal() {
        assert_eq!(
            WebServiceCommitChoreVerb::RegenerateDeps.commit_next_step_text(),
            "Commit: git add -A && git commit -m 'chore: regenerate deps'"
        );
    }

    /// Full-text byte-oracle for [`WebServiceCommitChoreVerb::UpdateHanabiDeps`]:
    /// the pre-lift full text was
    /// `"Commit: git add -A && git commit -m 'chore: update Hanabi
    /// deps'"` verbatim.
    #[test]
    fn update_hanabi_deps_full_text_matches_pre_lift_literal() {
        assert_eq!(
            WebServiceCommitChoreVerb::UpdateHanabiDeps.commit_next_step_text(),
            "Commit: git add -A && git commit -m 'chore: update Hanabi deps'"
        );
    }

    /// Signature pin: the print helper accepts a `u32` step index and
    /// a [`WebServiceCommitChoreVerb`] and returns `()`. A future edit
    /// that widened the signature (say to take an optional prefix, or
    /// to return an `io::Result<()>`) would ripple to every caller and
    /// trip the type check.
    #[test]
    fn print_helper_accepts_step_index_and_verb() {
        let _: fn(u32, WebServiceCommitChoreVerb) = print_web_service_commit_next_step;
    }

    /// Slice the module's own source to the production body so the
    /// tests below can count delegation call sites without matching
    /// against needle-mentions inside their own `assert!` diagnostic
    /// messages.
    fn production_body() -> String {
        let source = include_str!("web_service_commit_next_step.rs");
        let cutoff = source
            .find("#[cfg(test)]")
            .expect("production body ends at the test cfg attr");
        source[..cutoff].to_string()
    }

    /// Delegation pin: the print helper's body MUST forward through
    /// [`crate::ui::print_next_step`] exactly once. A future edit
    /// that inlined the string literal at the caller side or swapped
    /// in a sibling primitive (say [`crate::ui::print_next_steps_heading`])
    /// trips this assertion.
    #[test]
    fn print_helper_delegates_through_ui_print_next_step_once() {
        let body = production_body();
        let hits = crate::test_support::code_line_hits(&body, "crate::ui::print_next_step(");
        assert_eq!(
            hits.len(),
            1,
            "production body must forward through \
             `crate::ui::print_next_step(...)` at exactly one \
             site — the print helper's body. Found {}: {:#?}",
            hits.len(),
            hits
        );
    }

    /// Positive delegation shield: `commands/web_service.rs` MUST
    /// forward through this primitive at least the migrated count, so
    /// a migration that dropped a call site outright leaves the
    /// negative "no raw instruction string literal" scan (below)
    /// trivially satisfied by absence but the positive count still
    /// fails.
    ///
    /// `web_service.rs`: 2 forwards (one per closer).
    #[test]
    fn web_service_module_forwards_through_print_helper() {
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let path = commands_dir.join("web_service.rs");
        let source = std::fs::read_to_string(&path).unwrap();
        let forwards =
            crate::test_support::code_line_hits(&source, "print_web_service_commit_next_step(")
                .len();
        assert!(
            forwards >= 2,
            "web_service.rs must forward at least 2 commit-all \
             next-step stanza(s) through \
             `crate::web_service_commit_next_step::print_web_service_commit_next_step(`; \
             found {forwards}. A dropped call would leave the negative \
             raw-literal scan satisfied by absence.",
        );
    }

    /// Caller shield (negative half): no source line under
    /// `cli/src/commands/` may spell either full pre-lift instruction
    /// text inline as the second argument to
    /// [`crate::ui::print_next_step`] any more. The two pre-lift
    /// sites migrated; any future consumer that wants the same row
    /// reaches for [`print_web_service_commit_next_step`] on first
    /// grep, not by copy-pasting the string literal from an existing
    /// site.
    #[test]
    fn no_command_module_still_spells_raw_instruction_literal() {
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let mut offenders: Vec<(PathBuf, usize, String, &'static str)> = Vec::new();
        // Reconstruct the two full needles at test time so this
        // shield's own source text does not false-match itself.
        let regen_needle = WebServiceCommitChoreVerb::RegenerateDeps.commit_next_step_text();
        let update_needle = WebServiceCommitChoreVerb::UpdateHanabiDeps.commit_next_step_text();
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
                if line.contains("print_next_step(") && line.contains(&regen_needle) {
                    offenders.push((
                        path.clone(),
                        i + 1,
                        line.trim().to_string(),
                        "RegenerateDeps",
                    ));
                }
                if line.contains("print_next_step(") && line.contains(&update_needle) {
                    offenders.push((
                        path.clone(),
                        i + 1,
                        line.trim().to_string(),
                        "UpdateHanabiDeps",
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
                if this_line_trimmed == format!("\"{}\",", regen_needle)
                    || this_line_trimmed == format!("\"{}\"", regen_needle)
                {
                    offenders.push((
                        commands_dir.join(entry.file_name()),
                        i + 1,
                        lines[i].to_string(),
                        "RegenerateDeps",
                    ));
                }
                if this_line_trimmed == format!("\"{}\",", update_needle)
                    || this_line_trimmed == format!("\"{}\"", update_needle)
                {
                    offenders.push((
                        commands_dir.join(entry.file_name()),
                        i + 1,
                        lines[i].to_string(),
                        "UpdateHanabiDeps",
                    ));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw commit-all next-step instruction literal(s) survive \
             under `commands/` — route each through \
             `crate::web_service_commit_next_step::print_web_service_commit_next_step(\
             <N>, WebServiceCommitChoreVerb::<Variant>)` instead:\n{offenders:#?}"
        );
    }
}
