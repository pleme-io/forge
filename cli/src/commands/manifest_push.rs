//! Single-manifest commit-and-push-to-main helper with progress spinner.
//!
//! Shape-adapter over [`crate::git::commit_and_push`] for the two
//! sibling single-manifest deployment flows in
//! `commands/{deploy,github_runner_ci}.rs`. Each of those flows used
//! to spell out — VERBATIM, modulo the per-flow `manifest_path`,
//! `old_tag`, and `new_tag` bindings — the same five-line stanza
//! immediately after computing the pending `git commit_and_push`
//! call arguments:
//!
//! 1. `info!("📤 Committing to Git...");`
//! 2. `let pb = styled_spinner(SpinnerStyle::Green, "Pushing to main...");`
//! 3. `git::commit_and_push(<path>, &old_tag, &new_tag)?;`
//! 4. `pb.finish_with_message("✅ Pushed to main");`
//! 5. `println!();`
//!
//! Two identical occurrences past THEORY §VI.1's "two occurrences is
//! a coincidence" threshold — but the shape is a distinctive
//! visual-grammar fusion of THREE separate primitives (a `tracing`
//! info line + an indicatif spinner-flavored progress bar + a
//! synchronous git commit-and-push) with load-bearing narrative
//! sequencing between them. A palette drift on the spinner style
//! (`SpinnerStyle::Green` → `Cyan`), a verb swap on the info line
//! (`📤 Committing to Git...` → `🚀 Committing to Git...`), or a
//! finish-message drift (`✅ Pushed to main` → `✅ Pushed to origin`)
//! at ONE site alone silently forks the operator's terminal grammar
//! across two flows that should read identically. This module is the
//! shape's redemption — post-lift each flow calls
//! [`commit_and_push_manifest_with_progress`] with
//! `(manifest_path, old_tag, new_tag)` and inherits the canonical
//! info-line + spinner-style + finish-message triple through one site.
//!
//! Sibling of `commands/release_commit.rs::announce_and_commit_cluster_overlay_release_step`
//! — same visual-grammar-fusion pattern (info-line preamble + git
//! commit-and-push + typed completion signal) applied to the
//! multi-file cluster-overlay release flows. The two primitives
//! partition the single-manifest vs. multi-file deployment surface
//! at the crate level so a future consumer that reaches for the
//! wrong shape fails at the type boundary rather than by silent
//! log-drift.

use anyhow::Result;
use std::io;
use std::path::Path;
use tracing::info;

use crate::git;
use crate::ui::{styled_spinner, SpinnerStyle};

/// The canonical `📤 Committing to Git...` info line the two
/// single-manifest deployment flows in
/// `commands/{deploy,github_runner_ci}.rs` each emitted immediately
/// before spawning the pushing-to-main spinner. Named as a `const`
/// so a future drift to a different verb (a `🚀 Publishing`, a
/// `📦 Landing`) flows to both flows from one edit rather than
/// through two inline literal edits.
const COMMITTING_TO_GIT_INFO_LINE: &str = "📤 Committing to Git...";

/// The canonical `Pushing to main...` spinner message the two
/// single-manifest deployment flows each passed to
/// [`styled_spinner`] with [`SpinnerStyle::Green`]. Named as a
/// `const` so a future re-branding of the push target (`main` →
/// `trunk`, `main` → `release`) flows to both flows from one edit.
const PUSHING_TO_MAIN_SPINNER_MESSAGE: &str = "Pushing to main...";

/// The canonical `✅ Pushed to main` finish message the two
/// single-manifest deployment flows each passed to
/// [`indicatif::ProgressBar::finish_with_message`] after the
/// underlying [`git::commit_and_push`] call returned `Ok`. Named as
/// a `const` sibling of [`PUSHING_TO_MAIN_SPINNER_MESSAGE`] so a
/// re-branding of the push target flows through the same edit as
/// its pending sibling.
const PUSHED_TO_MAIN_FINISH_MESSAGE: &str = "✅ Pushed to main";

/// Emit the canonical `📤 Committing to Git...` info-line +
/// `Pushing to main...` spinner-message + `✅ Pushed to main`
/// finish-message triple to `w` as three newline-terminated lines,
/// byte-for-byte identical to the visual grammar the two
/// single-manifest deployment flows in
/// `commands/{deploy,github_runner_ci}.rs` each present to an
/// operator watching the terminal.
///
/// The writer split exists because the production fusion primitive
/// [`commit_and_push_manifest_with_progress`] emits the info line
/// through `tracing::info!` (routed through the global
/// `tracing_subscriber` fmt layer) and the spinner messages through
/// `indicatif::ProgressBar` (routed through its own draw loop) —
/// neither of which is byte-oracle-testable in a hermetic
/// `#[cfg(test)]` block without shelling out and grepping stdout,
/// and neither of which can capture the pre-post ordering the
/// operator's terminal actually presents. The direct writer emits
/// the three strings in narrative order into a `Vec<u8>` so the
/// fail-before-pass test can pin the grammar via
/// `String::from_utf8` — a rename of ANY of the three consts (a
/// swap of `📤` for `🚀`, a drift from `main` to `origin`) flips
/// the assertion at ONE site rather than silently forking the
/// grammar across two consumers.
///
/// Same writer/print split every prior sibling-writer refactor
/// honors (see `nonfatal_warning.rs`, `success_step.rs`,
/// `skipping_step.rs`, `step_header.rs`, `release_commit.rs` for
/// the canonical split rationale).
#[allow(dead_code)] // See doc comment: the writer is a test/byte-oracle
                    // peer of the tracing+indicatif-routed
                    // `commit_and_push_manifest_with_progress`, and a
                    // future `collect_commit_and_push_narratives`
                    // audit sibling will consume it directly.
pub fn write_commit_and_push_manifest_narrative<W: io::Write>(w: &mut W) -> io::Result<()> {
    writeln!(w, "{}", COMMITTING_TO_GIT_INFO_LINE)?;
    writeln!(w, "{}", PUSHING_TO_MAIN_SPINNER_MESSAGE)?;
    writeln!(w, "{}", PUSHED_TO_MAIN_FINISH_MESSAGE)?;
    Ok(())
}

/// Emit the canonical `📤 Committing to Git...` info line, spawn a
/// green-tinted spinner with the canonical `Pushing to main...`
/// message, invoke the synchronous [`git::commit_and_push`] against
/// `(manifest_path, old_tag, new_tag)`, finish the spinner with the
/// canonical `✅ Pushed to main` message, and emit a trailing blank
/// line via `println!()`.
///
/// Fusion primitive over the two sibling five-line stanzas the
/// single-manifest deployment flows in
/// `commands/{deploy,github_runner_ci}.rs` each spelled inline
/// verbatim (modulo the per-flow `manifest_path`, `old_tag`,
/// `new_tag` triple):
///
/// ```ignore
/// info!("📤 Committing to Git...");
/// let pb = styled_spinner(SpinnerStyle::Green, "Pushing to main...");
/// git::commit_and_push(<path>, &old_tag, &new_tag)?;
/// pb.finish_with_message("✅ Pushed to main");
/// println!();
/// ```
///
/// Post-lift each flow calls
/// [`commit_and_push_manifest_with_progress`] with
/// `(manifest_path, old_tag, new_tag)` and inherits the canonical
/// info-line, the canonical spinner palette + message, the
/// canonical finish message, and the trailing blank line through
/// one site.
///
/// # Grammar pinned by the byte-oracle sibling
///
/// The three narrative strings (`📤 Committing to Git...`,
/// `Pushing to main...`, `✅ Pushed to main`) are pinned by
/// [`write_commit_and_push_manifest_narrative`] under
/// `#[cfg(test)]`; a drift here (an emoji swap, a re-branding of
/// the push target, a verb change) surfaces as a localized test
/// failure at one site, not as silent grammar-drift across two
/// deployment flows.
///
/// # Errors
///
/// Surfaces the [`git::commit_and_push`] error verbatim — the
/// spinner is finished with the canonical success message ONLY on
/// the `Ok` arm; on the `Err` arm the spinner is dropped by
/// `indicatif`'s standard `Drop` implementation and the error
/// propagates through the caller's `?` operator. Same
/// `?`-propagation shape both consumer sites exhibited pre-lift.
pub fn commit_and_push_manifest_with_progress(
    manifest_path: &Path,
    old_tag: &str,
    new_tag: &str,
) -> Result<()> {
    info!("{}", COMMITTING_TO_GIT_INFO_LINE);
    let pb = styled_spinner(SpinnerStyle::Green, PUSHING_TO_MAIN_SPINNER_MESSAGE);
    git::commit_and_push(manifest_path, old_tag, new_tag)?;
    pb.finish_with_message(PUSHED_TO_MAIN_FINISH_MESSAGE);
    println!();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pin the exact three-line narrative bytes emitted by
    /// [`write_commit_and_push_manifest_narrative`]: the
    /// `📤 Committing to Git...` info line + newline, the
    /// `Pushing to main...` spinner-message + newline, and the
    /// `✅ Pushed to main` finish-message + newline. A future
    /// refactor that swapped the `📤` glyph for `🚀`, re-branded
    /// the push target from `main` to `trunk`, or dropped the
    /// checkmark on the finish message regresses this assertion.
    #[test]
    fn write_commit_and_push_manifest_narrative_emits_the_canonical_three_line_grammar() {
        let mut buf: Vec<u8> = Vec::new();
        write_commit_and_push_manifest_narrative(&mut buf).unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "\u{1f4e4} Committing to Git...\n\
             Pushing to main...\n\
             \u{2705} Pushed to main\n"
        );
    }

    /// The three canonical constants MUST each carry their exact
    /// pre-lift byte sequence — pinning them at the const level so
    /// a future edit that touched one const without updating the
    /// mirrored inline literal in the caller-shield below cannot
    /// silently proceed.
    #[test]
    fn canonical_narrative_constants_carry_their_pre_lift_byte_sequences() {
        assert_eq!(
            COMMITTING_TO_GIT_INFO_LINE,
            "\u{1f4e4} Committing to Git..."
        );
        assert_eq!(PUSHING_TO_MAIN_SPINNER_MESSAGE, "Pushing to main...");
        assert_eq!(PUSHED_TO_MAIN_FINISH_MESSAGE, "\u{2705} Pushed to main");
    }

    /// Caller shield: no `info!("📤 Committing to Git...")` literal
    /// may survive in the two consumer modules
    /// (`commands/{deploy,github_runner_ci}.rs`). Every
    /// single-manifest commit-and-push narrative in a deployment
    /// flow must resolve through
    /// [`commit_and_push_manifest_with_progress`] so a future
    /// drift to a new narrative shape (a new verb on the info
    /// line, a re-branded push target on the finish message) flows
    /// to both flows from one edit.
    ///
    /// The forbidden shape is reconstructed at test time via
    /// `format!` from the bare string `"Committing to Git"` so
    /// this shield's own source text does not false-match itself.
    #[test]
    fn commit_and_push_manifest_narrative_routes_through_fusion_not_inline_info_literal() {
        let forbidden = format!("{}{}", "\u{1f4e4} ", "Committing to Git...");
        for (path, source) in [
            ("commands/deploy.rs", include_str!("deploy.rs")),
            (
                "commands/github_runner_ci.rs",
                include_str!("github_runner_ci.rs"),
            ),
        ] {
            assert!(
                !source.contains(&forbidden),
                "`{path}` must not spell the inline `info!(\"{forbidden}\")` line; \
                 route through `crate::commands::manifest_push::\
                 commit_and_push_manifest_with_progress` instead \
                 (the byte-oracle-covered canonical single-manifest \
                 commit-and-push narrative)."
            );
        }
    }

    /// Caller shield: neither consumer module may retain the
    /// pre-lift inline spinner-spawn literal
    /// `"Pushing to main..."` — that message is now owned by the
    /// fusion primitive's [`PUSHING_TO_MAIN_SPINNER_MESSAGE`]
    /// const so a future re-branding of the push target flows
    /// through one edit rather than two.
    #[test]
    fn commit_and_push_manifest_narrative_routes_through_fusion_not_inline_spinner_literal() {
        let forbidden = format!("{}{}", "Pushing to main", "...");
        for (path, source) in [
            ("commands/deploy.rs", include_str!("deploy.rs")),
            (
                "commands/github_runner_ci.rs",
                include_str!("github_runner_ci.rs"),
            ),
        ] {
            assert!(
                !source.contains(&forbidden),
                "`{path}` must not spell the inline spinner-spawn literal \
                 `\"{forbidden}\"`; route through \
                 `crate::commands::manifest_push::\
                 commit_and_push_manifest_with_progress` instead."
            );
        }
    }

    /// Caller shield: neither consumer module may retain the
    /// pre-lift inline finish-message literal `"✅ Pushed to main"`
    /// — that message is now owned by the fusion primitive's
    /// [`PUSHED_TO_MAIN_FINISH_MESSAGE`] const.
    #[test]
    fn commit_and_push_manifest_narrative_routes_through_fusion_not_inline_finish_literal() {
        let forbidden = format!("{}{}", "\u{2705} ", "Pushed to main");
        for (path, source) in [
            ("commands/deploy.rs", include_str!("deploy.rs")),
            (
                "commands/github_runner_ci.rs",
                include_str!("github_runner_ci.rs"),
            ),
        ] {
            assert!(
                !source.contains(&forbidden),
                "`{path}` must not spell the inline finish-message literal \
                 `\"{forbidden}\"`; route through \
                 `crate::commands::manifest_push::\
                 commit_and_push_manifest_with_progress` instead."
            );
        }
    }

    /// Positive-half delegation shield: the two consumer modules
    /// MUST each carry exactly one call to
    /// [`commit_and_push_manifest_with_progress`]. Guards against
    /// a silent removal of the commit-and-push step from a
    /// consumer (a refactor that accidentally dropped the fusion
    /// call while migrating a step, a merge that lost the call in
    /// a conflict resolution) — the commit + push is load-bearing
    /// for the deployment actually landing on `origin/main`, so
    /// its presence at exactly one site per flow is a structural
    /// invariant.
    #[test]
    fn every_single_manifest_deploy_consumer_delegates_through_commit_and_push_fusion() {
        // Match the CALL-syntax `(` suffix so a leading `use`
        // import line carrying the identifier without a call does
        // not double-count against the per-consumer invocation
        // invariant.
        let needle = "commit_and_push_manifest_with_progress(";
        for (path, source) in [
            ("commands/deploy.rs", include_str!("deploy.rs")),
            (
                "commands/github_runner_ci.rs",
                include_str!("github_runner_ci.rs"),
            ),
        ] {
            let count = source.matches(needle).count();
            assert_eq!(
                count, 1,
                "`{path}` must invoke `crate::commands::manifest_push::\
                 {needle}` exactly once for its single-manifest \
                 commit-and-push step; found {count}. A flow that runs \
                 to completion without emitting the commit + push \
                 breaks the deployment landing on `origin/main`."
            );
        }
    }
}
