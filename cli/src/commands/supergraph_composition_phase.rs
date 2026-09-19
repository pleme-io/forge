//! Announce-and-close supergraph-composition-validation-phase primitive.
//!
//! Two pre-lift sibling four-line stanzas in
//! `commands/federation.rs::update_federation` each spelled the same
//! open-and-close visual grammar around the PRE- and POST-composition
//! validation phases, differing only in the `pre|post` (lowercase
//! adjective in the announcement) / `Pre|Post` (capitalized adjective
//! in the success line) axis:
//!
//! ```ignore
//! println!("🔍 Running <pre|post>-composition validation...");
//! // ... run_<pre|post>_composition_checks(...) ...
//! crate::ui::print_step_success("<Pre|Post>-composition validation passed");
//! ```
//!
//! Encoding that correlated pair as [`SupergraphCompositionPhase`]
//! closes two drift risks at ONE typed boundary. First, a caller
//! cannot silently pass the pre-shaped announcement but stamp the
//! post-shaped success message (or vice versa), because the
//! phase-enum owns both mappings. Second, a future re-branding of
//! the announcement glyph, the `-composition validation...`
//! suffix, or the `-composition validation passed` suffix lands at
//! exactly one module rather than through two inline literal edits.
//!
//! Same visual-grammar-fusion pattern as
//! [`crate::commands::flux_system_reconcile`] (correlated
//! `{Triggered, Completed}` pair over the FluxCD reconcile stanza)
//! and [`crate::commands::builder_pool_edit`] (correlated
//! `{AgentImage, BuilderImage}` pair over the builder-pool overlay
//! edit): a closed enum whose two arms each carry the exact
//! adjective the pre-lift stanza spelled inline.
//!
//! # Scope boundary
//!
//! The primitive owns the announce + pass grammar around ONE
//! validation invocation. The intervening body — the actual
//! `run_pre_composition_checks` / `run_post_composition_checks` call,
//! the per-check message enumeration, and the `bail!` on failure —
//! stays at the call site because its shape varies between the two
//! phases (pre-check checks are strictly pass/fail; post-check checks
//! carry a third `.contains("Warning")` yellow arm), and the two
//! bodies do not share enough grammar to fuse further. Sibling of the
//! `commands/manifest_push.rs::commit_and_push_manifest_with_progress`
//! carve-out that owns the open+close pair while leaving the
//! subordinate operation at the caller.

use std::io;

/// The invariant emoji prefix the pre-lift two sibling
/// [`println!`] announcement lines both spelled inline —
/// `"🔍 Running "` (magnifying-glass tilted right glyph U+1F50D +
/// ASCII space + verb + trailing space). Named as a `const` so a
/// future re-branding of the verb (`🔍 Running` → `🔍 Validating`,
/// `🔍 Checking`) flows through one edit rather than through two
/// inline literal edits.
const RUNNING_ANNOUNCEMENT_PREFIX: &str = "\u{1f50d} Running ";

/// The invariant suffix each pre-lift announcement line spelled
/// after the `pre|post` adjective slot —
/// `"-composition validation..."`. Named as a `const` so a future
/// re-phrasing of the suffix (`-composition validation...` →
/// `-composition audit...`, `-supergraph validation...`) flows
/// through one edit alongside its capitalized sibling
/// [`PASS_MESSAGE_SUFFIX`].
const RUNNING_ANNOUNCEMENT_SUFFIX: &str = "-composition validation...";

/// The invariant suffix each pre-lift [`crate::ui::print_step_success`]
/// message spelled after the `Pre|Post` adjective slot —
/// `"-composition validation passed"`. Sibling of
/// [`RUNNING_ANNOUNCEMENT_SUFFIX`] under the correlated pairing the
/// primitive owns: a re-phrasing of one flows to its neighbor from
/// one edit.
const PASS_MESSAGE_SUFFIX: &str = "-composition validation passed";

/// The invariant suffix each pre-lift `bail!` composition-validation-
/// failure literal spelled after the `Pre|Post` adjective slot and
/// BEFORE the phase-specific consequence sentence —
/// `"-composition validation failed."` (period included). Sibling of
/// [`PASS_MESSAGE_SUFFIX`] under the correlated pairing: a re-phrasing
/// of the pass suffix and the failure suffix (both name the same
/// `-composition validation` narrative) flows to both from adjacent
/// const edits rather than through drift-prone inline literals across
/// `commands/federation.rs`.
const FAILURE_MESSAGE_SUFFIX: &str = "-composition validation failed.";

/// The pre-lift `bail!` consequence sentence spliced after
/// [`FAILURE_MESSAGE_SUFFIX`] on the [`SupergraphCompositionPhase::Pre`]
/// arm — `" Cannot proceed with composition."` (leading ASCII space
/// preserved so the concatenation with the shared suffix reads as one
/// English sentence pair). Byte-identical to the pre-lift inline
/// literal at `commands/federation.rs::update_federation` :161.
const PRE_FAILURE_CONSEQUENCE_TAIL: &str = " Cannot proceed with composition.";

/// The pre-lift `bail!` consequence sentence spliced after
/// [`FAILURE_MESSAGE_SUFFIX`] on the [`SupergraphCompositionPhase::Post`]
/// arm — `" Supergraph may be invalid."` (leading ASCII space
/// preserved for the same reason as
/// [`PRE_FAILURE_CONSEQUENCE_TAIL`]). Byte-identical to the pre-lift
/// inline literal at `commands/federation.rs::update_federation` :262.
const POST_FAILURE_CONSEQUENCE_TAIL: &str = " Supergraph may be invalid.";

/// The two typed variants of the announce-and-close supergraph-
/// composition-validation-phase stanza the fusion primitive
/// supports.
///
/// The pre-lift two sites each picked their announcement adjective
/// (`pre` / `post`, lowercase) and their pass-message adjective
/// (`Pre` / `Post`, capitalized) INDEPENDENTLY, at inline literal
/// call sites — a silent drift that shipped the pre-shape
/// announcement above the post-shape pass line (or vice versa)
/// would have flowed through review with nothing catching it.
/// Encoding the correlated pair as a phase enum with
/// [`Self::lowercase_adjective`] and [`Self::capitalized_adjective`]
/// mirroring the pre-lift wording makes the pairing structurally
/// impossible to break: a future re-tuning of either axis touches
/// this enum, and every caller inherits the invariant by
/// construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupergraphCompositionPhase {
    /// The pre-composition validation phase — checks that the
    /// subgraph schemas satisfy the composition preconditions
    /// (`run_pre_composition_checks`). Consumed by the pre-lift
    /// `commands/federation.rs::update_federation` site whose
    /// announcement spells `"pre"` and whose pass line spells
    /// `"Pre"`.
    Pre,
    /// The post-composition validation phase — checks that the
    /// composed supergraph satisfies the composition postconditions
    /// (`run_post_composition_checks`). Consumed by the pre-lift
    /// `commands/federation.rs::update_federation` site whose
    /// announcement spells `"post"` and whose pass line spells
    /// `"Post"`.
    Post,
}

impl SupergraphCompositionPhase {
    /// The lowercase adjective spliced into the pre-lift
    /// announcement line for this phase. Inverse of
    /// [`Self::capitalized_adjective`] under the correlated pairing:
    /// `Pre` → `"pre"`, `Post` → `"post"`.
    #[inline]
    #[must_use]
    pub const fn lowercase_adjective(self) -> &'static str {
        match self {
            SupergraphCompositionPhase::Pre => "pre",
            SupergraphCompositionPhase::Post => "post",
        }
    }

    /// The capitalized adjective spliced into the pre-lift pass
    /// message for this phase. Inverse of
    /// [`Self::lowercase_adjective`] under the correlated pairing:
    /// `Pre` → `"Pre"`, `Post` → `"Post"`.
    #[inline]
    #[must_use]
    pub const fn capitalized_adjective(self) -> &'static str {
        match self {
            SupergraphCompositionPhase::Pre => "Pre",
            SupergraphCompositionPhase::Post => "Post",
        }
    }

    /// The full announcement line for this phase — the
    /// `"🔍 Running <pre|post>-composition validation..."`
    /// composition of [`RUNNING_ANNOUNCEMENT_PREFIX`],
    /// [`Self::lowercase_adjective`], and
    /// [`RUNNING_ANNOUNCEMENT_SUFFIX`]. Byte-identical to the
    /// pre-lift inline literal each site spelled.
    #[must_use]
    pub fn announcement(self) -> String {
        format!(
            "{}{}{}",
            RUNNING_ANNOUNCEMENT_PREFIX,
            self.lowercase_adjective(),
            RUNNING_ANNOUNCEMENT_SUFFIX,
        )
    }

    /// The full pass message for this phase — the
    /// `"<Pre|Post>-composition validation passed"` composition of
    /// [`Self::capitalized_adjective`] and [`PASS_MESSAGE_SUFFIX`].
    /// Byte-identical to the string the pre-lift call site passed
    /// to [`crate::ui::print_step_success`].
    #[must_use]
    pub fn pass_message(self) -> String {
        format!("{}{}", self.capitalized_adjective(), PASS_MESSAGE_SUFFIX)
    }

    /// The phase-specific consequence tail spliced into the pre-lift
    /// `bail!` composition-validation-failure literal AFTER the shared
    /// `"<Pre|Post>-composition validation failed."` prefix. Inverse
    /// of the phase-detection axis: `Pre` →
    /// [`PRE_FAILURE_CONSEQUENCE_TAIL`], `Post` →
    /// [`POST_FAILURE_CONSEQUENCE_TAIL`]. Byte-identical to the tail
    /// each pre-lift call site spelled inline.
    #[inline]
    #[must_use]
    pub const fn failure_consequence_tail(self) -> &'static str {
        match self {
            SupergraphCompositionPhase::Pre => PRE_FAILURE_CONSEQUENCE_TAIL,
            SupergraphCompositionPhase::Post => POST_FAILURE_CONSEQUENCE_TAIL,
        }
    }

    /// The full `bail!` message for a failed composition-validation
    /// phase — the
    /// `"<Pre|Post>-composition validation failed.<consequence tail>"`
    /// composition of [`Self::capitalized_adjective`],
    /// [`FAILURE_MESSAGE_SUFFIX`], and
    /// [`Self::failure_consequence_tail`]. Byte-identical to the
    /// string each pre-lift call site passed to `anyhow::bail!`.
    #[must_use]
    pub fn failure_message(self) -> String {
        format!(
            "{}{}{}",
            self.capitalized_adjective(),
            FAILURE_MESSAGE_SUFFIX,
            self.failure_consequence_tail(),
        )
    }
}

/// Emit the canonical `🔍 Running <phase>-composition validation...`
/// announcement line to stdout via [`println!`], byte-identical to
/// the pre-lift inline literal each site spelled.
///
/// The pre-lift two callers each emitted their announcement through
/// [`println!`] (uncolored, unformatted, terminated by a single
/// `\n`) — the primitive preserves that shape verbatim so the
/// operator-facing terminal output is unchanged.
pub fn announce_composition_phase_start(phase: SupergraphCompositionPhase) {
    println!("{}", phase.announcement());
}

/// Emit the canonical `✅ <Phase>-composition validation passed`
/// pass line by routing through the fleet-standard
/// [`crate::ui::print_step_success`] primitive. Byte-identical to
/// the string the pre-lift call site passed to that same primitive.
///
/// The pre-lift two callers each routed their pass acknowledgement
/// through [`crate::ui::print_step_success`] (the green-tinted
/// `✅ <msg>.green()` step-completion marker) — the primitive
/// preserves that routing verbatim so the visual grammar is
/// unchanged.
pub fn announce_composition_phase_pass(phase: SupergraphCompositionPhase) {
    crate::ui::print_step_success(&phase.pass_message());
}

/// Writer-taking sibling to [`announce_composition_phase_start`].
/// Emits the single announcement line via [`writeln!`] against the
/// supplied writer, byte-for-byte identical to the pre-lift
/// inline literal.
///
/// The writer split exists because the production entry point
/// [`announce_composition_phase_start`] emits through [`println!`]
/// against the process stdout, which is not byte-oracle-testable in
/// a hermetic `#[cfg(test)]` block without capturing an ambient
/// stdout redirect. The direct writer emits the string into a
/// `Vec<u8>` so the fail-before-pass test can pin the grammar via
/// `String::from_utf8` — a rename of the announcement verb, a swap
/// of the emoji glyph, or a drift of the `-composition
/// validation...` suffix flips the assertion at ONE site rather
/// than silently forking the grammar across two call sites.
///
/// Same writer/print split every prior sibling-writer refactor
/// honors (see [`crate::flux_system_reconcile`],
/// [`crate::success_step`], [`crate::nonfatal_warning`],
/// [`crate::step_header`] for the canonical split rationale).
#[allow(dead_code)] // See doc comment: the writer is a test/byte-oracle
                    // peer of the stdout-routed
                    // `announce_composition_phase_start`.
pub fn write_composition_phase_start<W: io::Write>(
    w: &mut W,
    phase: SupergraphCompositionPhase,
) -> io::Result<()> {
    writeln!(w, "{}", phase.announcement())
}

/// Print every per-check result row through the fleet-standard
/// [`crate::commands::composition_check_print::print_composition_check_result`]
/// primitive, then bail with the phase-specific failure message
/// composed by [`SupergraphCompositionPhase::failure_message`] when
/// the aggregate `passed` flag is `false`.
///
/// Encoding the correlated `for check in checks { print(check); }
/// + if !passed { bail!(<phase-specific-msg>); }` sibling stanza as
/// a phase-parameterised primitive closes THREE drift risks at ONE
/// typed boundary. First, a caller cannot silently pass the
/// pre-shape aggregate `passed` flag but stamp the post-shape
/// failure message (or vice versa), because the phase-enum owns
/// both the aggregate probe (via its receiver arg) and the
/// consequence tail. Second, a future re-tuning of the shared
/// `-composition validation failed.` suffix flows to both phases
/// from one const edit. Third, a future re-tuning of the per-check
/// print grammar flows through
/// `crate::commands::composition_check_print` from one edit rather
/// than through two duplicated for-loops.
///
/// # Scope boundary
///
/// The primitive owns the report + bail grammar around ONE
/// validation invocation. The intervening state — the actual
/// `run_pre_composition_checks` / `run_post_composition_checks`
/// call receiver, the `pre_check` / `post_check` binding, and any
/// per-phase auxiliary side-effect (size probe, service-count
/// probe, per-check counter) — stays at the call site because its
/// shape varies between the two phases. Sibling of the
/// [`announce_composition_phase_start`] +
/// [`announce_composition_phase_pass`] pair that owns the visual
/// grammar around this same body.
pub fn report_and_bail_on_failed_composition_checks(
    phase: SupergraphCompositionPhase,
    checks: &[crate::commands::supergraph_verification::CheckResult],
    passed: bool,
) -> anyhow::Result<()> {
    for check in checks {
        crate::commands::composition_check_print::print_composition_check_result(check);
    }
    if !passed {
        anyhow::bail!("{}", phase.failure_message());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pin the exact announcement bytes for the
    /// [`SupergraphCompositionPhase::Pre`] arm: the
    /// `🔍 Running pre-composition validation...` line + newline.
    /// A future refactor that swapped the `🔍` glyph, changed the
    /// verb, or drifted the `-composition validation...` suffix off
    /// the pre-lift wording regresses this assertion.
    #[test]
    fn write_start_emits_pre_bytes() {
        let mut buf: Vec<u8> = Vec::new();
        write_composition_phase_start(&mut buf, SupergraphCompositionPhase::Pre).unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "\u{1f50d} Running pre-composition validation...\n"
        );
    }

    /// Pin the exact announcement bytes for the
    /// [`SupergraphCompositionPhase::Post`] arm: same emoji, same
    /// verb, same suffix, `post` slotted for `pre`. A future
    /// refactor that collapsed the two-phase announcement grammar
    /// into a single phrase regresses this assertion.
    #[test]
    fn write_start_emits_post_bytes() {
        let mut buf: Vec<u8> = Vec::new();
        write_composition_phase_start(&mut buf, SupergraphCompositionPhase::Post).unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "\u{1f50d} Running post-composition validation...\n"
        );
    }

    /// Adjective-axis pin: `Pre` splices `"pre"` (lowercase) and
    /// `Post` splices `"post"` (lowercase) — the two verbatim
    /// adjectives the pre-lift announcement sites each spelled
    /// inline.
    #[test]
    fn lowercase_adjective_maps_to_pre_lift_wording() {
        assert_eq!(SupergraphCompositionPhase::Pre.lowercase_adjective(), "pre");
        assert_eq!(
            SupergraphCompositionPhase::Post.lowercase_adjective(),
            "post"
        );
    }

    /// Adjective-axis pin: `Pre` splices `"Pre"` (capitalized) and
    /// `Post` splices `"Post"` (capitalized) — the two verbatim
    /// adjectives the pre-lift pass-message sites each spelled
    /// inline. Sibling of
    /// [`lowercase_adjective_maps_to_pre_lift_wording`] under the
    /// correlated pairing the primitive owns.
    #[test]
    fn capitalized_adjective_maps_to_pre_lift_wording() {
        assert_eq!(
            SupergraphCompositionPhase::Pre.capitalized_adjective(),
            "Pre"
        );
        assert_eq!(
            SupergraphCompositionPhase::Post.capitalized_adjective(),
            "Post"
        );
    }

    /// Pin the pass-message composition for both phases: `Pre` →
    /// `"Pre-composition validation passed"`, `Post` →
    /// `"Post-composition validation passed"` — byte-identical to
    /// the string the pre-lift call site passed to
    /// [`crate::ui::print_step_success`]. A future refactor that
    /// drifted the `-composition validation passed` suffix
    /// regresses this assertion.
    #[test]
    fn pass_message_matches_pre_lift_wording() {
        assert_eq!(
            SupergraphCompositionPhase::Pre.pass_message(),
            "Pre-composition validation passed"
        );
        assert_eq!(
            SupergraphCompositionPhase::Post.pass_message(),
            "Post-composition validation passed"
        );
    }

    /// Pin the full announcement composition for both phases: the
    /// `format!` output of [`SupergraphCompositionPhase::announcement`]
    /// matches the pre-lift inline literal for each phase. A drift
    /// in the prefix (`"🔍 Running "`) OR the suffix
    /// (`"-composition validation..."`) fails this at one site.
    #[test]
    fn announcement_matches_pre_lift_wording() {
        assert_eq!(
            SupergraphCompositionPhase::Pre.announcement(),
            "\u{1f50d} Running pre-composition validation..."
        );
        assert_eq!(
            SupergraphCompositionPhase::Post.announcement(),
            "\u{1f50d} Running post-composition validation..."
        );
    }

    /// Const-anchor pin: the five canonical strings the primitive
    /// owns each carry their exact pre-lift byte sequence. A future
    /// edit that touched one const without updating the mirrored
    /// inline literal in the caller-shield below cannot silently
    /// proceed.
    #[test]
    fn canonical_constants_carry_pre_lift_byte_sequences() {
        assert_eq!(RUNNING_ANNOUNCEMENT_PREFIX, "\u{1f50d} Running ");
        assert_eq!(RUNNING_ANNOUNCEMENT_SUFFIX, "-composition validation...");
        assert_eq!(PASS_MESSAGE_SUFFIX, "-composition validation passed");
        assert_eq!(FAILURE_MESSAGE_SUFFIX, "-composition validation failed.");
        assert_eq!(
            PRE_FAILURE_CONSEQUENCE_TAIL,
            " Cannot proceed with composition.",
        );
        assert_eq!(POST_FAILURE_CONSEQUENCE_TAIL, " Supergraph may be invalid.");
    }

    /// Pin the phase-specific consequence-tail axis: `Pre` →
    /// `" Cannot proceed with composition."`, `Post` →
    /// `" Supergraph may be invalid."` — the two verbatim tails the
    /// pre-lift `bail!` sites each spelled inline. A silent drift
    /// that shipped the pre-shape prefix but the post-shape
    /// consequence (or vice versa) regresses this assertion.
    #[test]
    fn failure_consequence_tail_maps_to_pre_lift_wording() {
        assert_eq!(
            SupergraphCompositionPhase::Pre.failure_consequence_tail(),
            " Cannot proceed with composition.",
        );
        assert_eq!(
            SupergraphCompositionPhase::Post.failure_consequence_tail(),
            " Supergraph may be invalid.",
        );
    }

    /// Pin the full failure-message composition for both phases:
    /// `Pre` →
    /// `"Pre-composition validation failed. Cannot proceed with composition."`,
    /// `Post` →
    /// `"Post-composition validation failed. Supergraph may be invalid."`
    /// — byte-identical to the string the pre-lift call site passed
    /// to `anyhow::bail!`. A drift in the shared prefix
    /// (`"-composition validation failed."`) OR either
    /// phase-specific consequence tail fails this at one site.
    #[test]
    fn failure_message_matches_pre_lift_bail_literals() {
        assert_eq!(
            SupergraphCompositionPhase::Pre.failure_message(),
            "Pre-composition validation failed. Cannot proceed with composition.",
        );
        assert_eq!(
            SupergraphCompositionPhase::Post.failure_message(),
            "Post-composition validation failed. Supergraph may be invalid.",
        );
    }

    /// Structural pin: [`report_and_bail_on_failed_composition_checks`]
    /// bails with the phase-specific
    /// [`SupergraphCompositionPhase::failure_message`] when `passed
    /// = false`, regardless of the check list content. The lifted
    /// stanza was `if !<x>_check.passed { bail!(...) }`, so a
    /// refactor that flipped the polarity of the guard or drifted
    /// the bail wording regresses here.
    #[test]
    fn report_and_bail_raises_pre_lift_wording_on_pre_arm() {
        let err = report_and_bail_on_failed_composition_checks(
            SupergraphCompositionPhase::Pre,
            &[],
            false,
        )
        .expect_err("passed = false must bail");
        assert_eq!(
            err.to_string(),
            "Pre-composition validation failed. Cannot proceed with composition.",
        );
    }

    /// Sibling to [`report_and_bail_raises_pre_lift_wording_on_pre_arm`]
    /// for the `Post` arm — same guard-polarity pin, same
    /// wording-drift regression shield.
    #[test]
    fn report_and_bail_raises_pre_lift_wording_on_post_arm() {
        let err = report_and_bail_on_failed_composition_checks(
            SupergraphCompositionPhase::Post,
            &[],
            false,
        )
        .expect_err("passed = false must bail");
        assert_eq!(
            err.to_string(),
            "Post-composition validation failed. Supergraph may be invalid.",
        );
    }

    /// Complementary pin: [`report_and_bail_on_failed_composition_checks`]
    /// returns `Ok(())` when the aggregate `passed = true`, whatever
    /// the phase — the guard is a strict `if !passed { bail }` and
    /// never fires on the pass path. A future refactor that
    /// accidentally added a per-check post-condition or flipped the
    /// guard polarity would regress this assertion.
    #[test]
    fn report_and_bail_returns_ok_on_passed_true_both_phases() {
        assert!(report_and_bail_on_failed_composition_checks(
            SupergraphCompositionPhase::Pre,
            &[],
            true,
        )
        .is_ok());
        assert!(report_and_bail_on_failed_composition_checks(
            SupergraphCompositionPhase::Post,
            &[],
            true,
        )
        .is_ok());
    }

    /// Caller shield: no source line under `cli/src/commands/` may
    /// spell the pre-lift announcement literal
    /// `println!("🔍 Running <phase>-composition validation...")`
    /// inline any more. Every announce-composition-phase-start
    /// narrative in a federation-composition flow must resolve
    /// through [`announce_composition_phase_start`] so a future
    /// drift on the announcement (a new verb, a re-branded target)
    /// flows to both phases from one edit.
    ///
    /// The forbidden shape is reconstructed at test time via
    /// [`format!`] from the bare fragments so this shield's own
    /// source text does not false-match itself. Every hit routes
    /// through [`crate::test_support::code_line_hits`] for
    /// anti-comment-line-self-match discipline.
    #[test]
    fn no_command_module_still_spells_raw_composition_phase_announce() {
        use std::path::PathBuf;
        for phase_word in ["pre", "post"] {
            let forbidden = format!(
                "println!(\"{}Running {}{}\")",
                "\u{1f50d} ", phase_word, "-composition validation...",
            );
            let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("src")
                .join("commands");
            let mut offenders: Vec<(PathBuf, Vec<String>)> = Vec::new();
            for entry in std::fs::read_dir(&commands_dir).unwrap().flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                    continue;
                }
                // Skip THIS module — its own prose and byte-oracle
                // test strings mention the pre-lift shape verbatim
                // by design.
                if path.file_name().and_then(|n| n.to_str())
                    == Some("supergraph_composition_phase.rs")
                {
                    continue;
                }
                let source = std::fs::read_to_string(&path).unwrap();
                let hits = crate::test_support::code_line_hits(&source, &forbidden);
                if !hits.is_empty() {
                    offenders.push((path, hits));
                }
            }
            assert!(
                offenders.is_empty(),
                "pre-lift `{}` announcement stanza(s) survive under \
                 `commands/` — route each through \
                 `crate::commands::supergraph_composition_phase::\
                 announce_composition_phase_start(<phase>)` \
                 instead:\n{:#?}",
                forbidden,
                offenders,
            );
        }
    }

    /// Caller shield: no source line under `cli/src/commands/` may
    /// spell the pre-lift pass-message literal
    /// `crate::ui::print_step_success("<Phase>-composition validation
    /// passed")` inline any more. Every announce-composition-phase-
    /// pass narrative must resolve through
    /// [`announce_composition_phase_pass`] so a future re-phrasing
    /// of the pass suffix flows to both phases from one edit.
    ///
    /// The forbidden shape is reconstructed at test time via
    /// [`format!`] from the bare fragments so this shield's own
    /// source text does not false-match itself.
    #[test]
    fn no_command_module_still_spells_raw_composition_phase_pass() {
        use std::path::PathBuf;
        for phase_word in ["Pre", "Post"] {
            let forbidden = format!(
                "print_step_success(\"{}{}\")",
                phase_word, "-composition validation passed",
            );
            let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("src")
                .join("commands");
            let mut offenders: Vec<(PathBuf, Vec<String>)> = Vec::new();
            for entry in std::fs::read_dir(&commands_dir).unwrap().flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                    continue;
                }
                if path.file_name().and_then(|n| n.to_str())
                    == Some("supergraph_composition_phase.rs")
                {
                    continue;
                }
                let source = std::fs::read_to_string(&path).unwrap();
                let hits = crate::test_support::code_line_hits(&source, &forbidden);
                if !hits.is_empty() {
                    offenders.push((path, hits));
                }
            }
            assert!(
                offenders.is_empty(),
                "pre-lift `{}` pass stanza(s) survive under \
                 `commands/` — route each through \
                 `crate::commands::supergraph_composition_phase::\
                 announce_composition_phase_pass(<phase>)` \
                 instead:\n{:#?}",
                forbidden,
                offenders,
            );
        }
    }

    /// Positive-half delegation shield: the sole consumer module
    /// `commands/federation.rs` MUST carry exactly one call to
    /// [`announce_composition_phase_start`], exactly one call to
    /// [`announce_composition_phase_pass`], and exactly one call
    /// to [`report_and_bail_on_failed_composition_checks`] for each
    /// of the two phases — that is, exactly two calls to each
    /// helper, one per phase. Guards against a silent removal of
    /// the announcement, the pass acknowledgement, or the report-
    /// and-bail closure from the composition flow (a refactor that
    /// accidentally dropped the fusion call while migrating a step,
    /// a merge that lost the call in a conflict resolution). Each
    /// primitive is load-bearing for the operator-facing narrative
    /// around composition, so its presence at exactly two sites per
    /// helper is a structural invariant.
    #[test]
    fn every_composition_phase_consumer_delegates_through_fusion() {
        let source = include_str!("federation.rs");
        for needle in [
            "announce_composition_phase_start(",
            "announce_composition_phase_pass(",
            "report_and_bail_on_failed_composition_checks(",
        ] {
            let count = source.matches(needle).count();
            assert_eq!(
                count, 2,
                "`commands/federation.rs` must invoke \
                 `crate::commands::supergraph_composition_phase::\
                 {needle}` exactly twice (one per phase); found \
                 {count}. A flow that runs to completion without \
                 emitting both announcements breaks the operator-\
                 facing composition narrative.",
            );
        }
    }

    /// Caller shield: no source line under `cli/src/commands/` may
    /// spell the pre-lift `bail!` composition-validation-failure
    /// literal
    /// `bail!("<Pre|Post>-composition validation failed.<tail>")`
    /// inline any more. Every composition-validation report-and-
    /// bail narrative must resolve through
    /// [`report_and_bail_on_failed_composition_checks`] so a future
    /// re-phrasing of the shared `-composition validation failed.`
    /// suffix or either phase-specific consequence tail flows to
    /// both phases from one edit.
    ///
    /// The forbidden shape is reconstructed at test time via
    /// [`format!`] from the bare fragments so this shield's own
    /// source text does not false-match itself.
    #[test]
    fn no_command_module_still_spells_raw_composition_phase_failure_bail() {
        use std::path::PathBuf;
        for (phase_word, tail) in [
            ("Pre", " Cannot proceed with composition."),
            ("Post", " Supergraph may be invalid."),
        ] {
            let forbidden = format!(
                "bail!(\"{}{}{}\")",
                phase_word, "-composition validation failed.", tail,
            );
            let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("src")
                .join("commands");
            let mut offenders: Vec<(PathBuf, Vec<String>)> = Vec::new();
            for entry in std::fs::read_dir(&commands_dir).unwrap().flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                    continue;
                }
                if path.file_name().and_then(|n| n.to_str())
                    == Some("supergraph_composition_phase.rs")
                {
                    continue;
                }
                let source = std::fs::read_to_string(&path).unwrap();
                let hits = crate::test_support::code_line_hits(&source, &forbidden);
                if !hits.is_empty() {
                    offenders.push((path, hits));
                }
            }
            assert!(
                offenders.is_empty(),
                "pre-lift `{}` failure-bail stanza(s) survive under \
                 `commands/` — route each through \
                 `crate::commands::supergraph_composition_phase::\
                 report_and_bail_on_failed_composition_checks(<phase>, \
                 <checks>, <passed>)` instead:\n{:#?}",
                forbidden,
                offenders,
            );
        }
    }
}
