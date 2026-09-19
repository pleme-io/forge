//! GreenBold `✅ <NAME> Complete!` workflow-completion boxed banner
//! immediately followed by the `📦 Deployed: <registry>:<tag>`
//! image-ref line — a fused two-line postamble stanza the two
//! terminal-command modules `commands/deploy.rs` and
//! `commands/github_runner_ci.rs` each spelled verbatim just before
//! their per-workflow `println!` monitoring / topology bullets.
//!
//! # Duplication being lifted
//!
//! Two pre-lift sibling sites each restated the same five-line
//! stanza — a
//! `crate::ui::print_boxed_banner(crate::ui::BoxedBannerStyle::GreenBold, "✅ <NAME> Complete!")`
//! call followed IMMEDIATELY by
//! `crate::ui::print_deployed_image_ref(<registry>, <tag>)` on the
//! next line, with no intervening blank or diagnostic. The only
//! per-site divergence is the `<NAME>` slot of the banner title
//! and the caller-scoped `(registry, tag)` pair fed to the
//! image-ref line:
//!
//! 1. `commands/deploy.rs::execute` (~L206) — the terminal
//!    postamble reached when the FluxCD GitOps deploy path
//!    completes. `<NAME>` = `"Deployment"`. `(registry, tag)` =
//!    the caller-scoped `(registry: String, tag: String)` command
//!    arguments carried through the `execute` fn.
//! 2. `commands/github_runner_ci.rs::execute` (~L784) — the
//!    terminal postamble reached when the GitHub Runner CI
//!    workflow's rollout watch (or its `--watch=false` skip)
//!    returns. `<NAME>` = `"GitHub Runner CI"`. `(registry, tag)`
//!    = `(registry: String, git_sha: String)` where `git_sha` is
//!    the tag actually pushed to the registry earlier in the
//!    workflow's `execute` body.
//!
//! Each of the two spellings renders the same byte shape: a
//! leading framing blank, the three-line `╔═…╗` GreenBold boxed
//! banner (top border, indented+padded `✅ <NAME> Complete!` title,
//! bottom border), a trailing framing blank, then the single
//! `📦 Deployed: <registry>:<tag>` line. A drift in the leading
//! `✅` check-mark glyph (a silent swap for `☑`, `✔`, or the
//! plain-text `[ok]`), the trailing `Complete!` verb (a
//! sibling-verb swap for `Finished!`, `Done!`, or `Ready!`), the
//! `GreenBold` palette (a demotion to `Green` alone under a
//! terminal-milestone re-branding), the immediate-adjacency
//! grammar between banner and image-ref (an inserted blank), or
//! the `📦` PACKAGE glyph + `Deployed: ` label at any one site
//! pre-lift diverged silently from the other — the operator's eye
//! caught only the local postamble, not the fleet-wide
//! terminal-milestone grammar drift across the two workflow
//! entry points.
//!
//! # Distinct from every sibling banner primitive in the crate
//!
//! - [`crate::ui::print_boxed_banner`] with
//!   [`crate::ui::BoxedBannerStyle::GreenBold`] is the primitive
//!   this fusion delegates to for the top-of-stanza box; it stays
//!   the canonical entry point for any FUTURE GreenBold boxed
//!   banner that is NOT immediately followed by an image-ref line
//!   (e.g. a green completion box for a stage that has no deployed
//!   image ref).
//! - [`crate::ui::print_deployed_image_ref`] owns the
//!   `📦 Deployed: <registry>:<tag>` line in isolation; it stays
//!   the canonical entry point for a `📦 Deployed:` announcement
//!   NOT preceded by a `✅ … Complete!` banner (e.g. a per-env
//!   progress readout in the multi-env orchestrator).
//! - [`crate::release_workflow_intro_banner::
//!   print_release_workflow_intro_banner`] owns the peer-class
//!   `🚀 <service> <label> <detail>` release-workflow INTRO banner;
//!   that primitive marks the START of a release workflow, this
//!   one marks the END of a terminal-command workflow. The two
//!   should NOT be folded — different palette (CyanBold vs.
//!   GreenBold), different glyph (`🚀` vs. `✅`), different
//!   grammar (title-with-slots vs. ASCII-box).
//! - [`crate::product_workflow_intro_banner`] owns the peer-class
//!   `>>-bold` intro for the product-scoped multi-service pipeline;
//!   distinct outer framing.
//!
//! # Delegation, not re-implementation
//!
//! The three-line ANSI-boxed banner body is delegated to
//! [`crate::ui::print_boxed_banner`] with
//! [`crate::ui::BoxedBannerStyle::GreenBold`] (which itself
//! terminates in [`crate::ui::write_boxed_banner`] and carries the
//! leading + trailing framing blanks), and the trailing `📦 Deployed:`
//! line is delegated to [`crate::ui::print_deployed_image_ref`]
//! (which itself terminates in [`crate::ui::write_deployed_image_ref`]).
//! Neither the box glyphs nor the deployed-image label are restated
//! here — a future swap of the box grammar (`╔` → `╭` under a
//! Unicode-rounded rebrand) or a rename of the `Deployed: ` label
//! lands in ONE place on the peer primitive and this fusion inherits
//! by composition.
//!
//! # THEORY grounding
//!
//! §V solve-once-at-the-primitive: the terminal-milestone
//! banner+image-ref pair lives at ONE construction surface — a
//! future refinement (an OTLP `workflow_completed` observability
//! span emitted alongside the print, a promotion of `✅` to
//! `🎉` under a stronger success-glyph rebrand, an added
//! attestation-chain footer beneath the image ref) lands in one
//! place rather than in every consumer.
//!
//! §VI.1 three-is-a-law is intentionally approached from below
//! here at two sites: the two pre-lift stanzas each carried the
//! full five-line fusion and diverged only on the workflow name
//! slot. Lifting at N=2 keeps a third `commands/<workflow>.rs`
//! module (a future `commands/deploy_v2.rs`, a
//! `commands/hotfix.rs`) from reaching for the peer primitives
//! and re-inlining the same five lines by copy-paste — the typed
//! enum below closes the workflow-name choice at build time.

use std::fmt::Display;

use crate::ui::{print_boxed_banner, print_deployed_image_ref, BoxedBannerStyle};

/// The `✅` WHITE HEAVY CHECK MARK glyph (U+2705, 3 bytes
/// `E2 9C 85`) opening the workflow-complete banner every pre-lift
/// consumer spelled inline in the fixed
/// `"✅ <NAME> Complete!"` template. Named as a `const` so a
/// future swap (`✅` → `🎉` under a stronger success-glyph rebrand)
/// lands at ONE edit rather than through two inline literal edits.
pub const WORKFLOW_COMPLETE_BANNER_GLYPH: &str = "✅";

/// The trailing verb (`Complete!`, with the exclamation mark)
/// closing the workflow-complete banner every pre-lift consumer
/// spelled inline. Named as a `const` so a future swap for a
/// sibling terminal-milestone verb (`Finished!`, `Done!`,
/// `Ready!`) lands at ONE edit rather than through two inline
/// literal edits.
pub const WORKFLOW_COMPLETE_BANNER_VERB: &str = "Complete!";

/// Which of the two terminal-command workflow's completion banner
/// is being rendered. The variants are closed to the two dialects
/// the pre-lift sites spell — the enum is deliberately not open,
/// so a future variant added without an arm on
/// [`WorkflowCompleteBanner::workflow_name`] fails the
/// exhaustiveness check at build time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkflowCompleteBanner {
    /// `commands/deploy.rs::execute` FluxCD GitOps deploy
    /// postamble. Renders as `"✅ Deployment Complete!"`.
    Deployment,
    /// `commands/github_runner_ci.rs::execute` GitHub Runner CI
    /// workflow postamble. Renders as `"✅ GitHub Runner CI
    /// Complete!"`.
    GitHubRunnerCi,
}

impl WorkflowCompleteBanner {
    /// The `<NAME>` slot the fixed `"✅ <NAME> Complete!"` banner
    /// title interpolates. The names are the human-facing workflow
    /// names the pre-lift stanzas each spelled — `"Deployment"` and
    /// `"GitHub Runner CI"`.
    ///
    /// The `Deployment` arm carries no `"Nexus "` prefix even
    /// though the sibling intro banner opens with
    /// `"Nexus Deploy - GitOps Workflow"`; the pre-lift completion
    /// title deliberately drops the product-scope prefix so the
    /// green terminal box reads as a generic deploy-workflow
    /// completion, matching the pre-lift byte shape verbatim.
    pub const fn workflow_name(self) -> &'static str {
        match self {
            Self::Deployment => "Deployment",
            Self::GitHubRunnerCi => "GitHub Runner CI",
        }
    }

    /// The pre-composed banner-title argument fed to
    /// [`crate::ui::print_boxed_banner`] /
    /// [`crate::ui::write_boxed_banner`]. Composes as
    /// `format!("{glyph} {name} {verb}")` where `glyph` is
    /// [`WORKFLOW_COMPLETE_BANNER_GLYPH`], `name` is
    /// [`WorkflowCompleteBanner::workflow_name`], and `verb` is
    /// [`WORKFLOW_COMPLETE_BANNER_VERB`]. The three-part fusion
    /// stays on ONE method so a future swap of the glyph or verb
    /// reaches both variants by construction.
    pub fn banner_title(self) -> String {
        format!(
            "{} {} {}",
            WORKFLOW_COMPLETE_BANNER_GLYPH,
            self.workflow_name(),
            WORKFLOW_COMPLETE_BANNER_VERB,
        )
    }
}

/// Prints the fused GreenBold `✅ <NAME> Complete!` boxed banner
/// immediately followed by the `📦 Deployed: <registry>:<tag>`
/// image-ref line, sharing the exact bytes the pre-lift two-line
/// stanza wrote across `commands/deploy.rs` and
/// `commands/github_runner_ci.rs`.
///
/// Delegates through the peer print primitives
/// [`print_boxed_banner`] (with [`BoxedBannerStyle::GreenBold`],
/// which itself carries the leading + trailing framing blank on
/// its own body) and [`print_deployed_image_ref`] (for the single
/// `📦 Deployed: <registry>:<tag>` line). Neither the box glyphs
/// nor the `📦 Deployed:` label are restated here — a future
/// swap of the box grammar (`╔` → `╭` under a Unicode-rounded
/// rebrand) or a rename of the `Deployed:` label lands in ONE
/// place on the peer primitive and this fusion inherits by
/// composition. The byte-shape end-to-end (leading blank + box +
/// trailing blank + `📦 Deployed:` line) is pinned by the
/// `write_workflow_complete_banner` test helper against the same
/// peer `write_` primitives. Callers pass any
/// `Display`-implementing type for both `registry` and `tag` — a
/// bare `&str`, an owned `String`, a `&String`, or a colored
/// `.cyan()` / `.dimmed()` wrapper all flow through without a
/// per-caller `.to_string()` intermediate.
///
/// # Parameters
///
/// - `kind` — which of the two closed workflow-completion
///   dialects this call renders. See [`WorkflowCompleteBanner`].
/// - `registry` — the OCI registry host + repo path fed to
///   [`print_deployed_image_ref`] as the left half of the
///   `<registry>:<tag>` connective.
/// - `tag` — the OCI image tag fed to [`print_deployed_image_ref`]
///   as the right half of the `<registry>:<tag>` connective.
///   Pre-lift the `commands/deploy.rs` consumer passed the raw
///   command-argument tag; the `commands/github_runner_ci.rs`
///   consumer passed the resolved short git SHA.
pub fn print_workflow_complete_banner<R, T>(kind: WorkflowCompleteBanner, registry: R, tag: T)
where
    R: Display,
    T: Display,
{
    print_boxed_banner(BoxedBannerStyle::GreenBold, &kind.banner_title());
    print_deployed_image_ref(registry, tag);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::{write_boxed_banner, write_deployed_image_ref};
    use std::io;
    use std::sync::Mutex;

    /// Test-only writer sibling to [`print_workflow_complete_banner`].
    /// Emits the same byte sequence [`print_workflow_complete_banner`]
    /// writes to stdout — a leading framing blank, the three-line
    /// GreenBold `╔═…╗` box, a trailing framing blank, then the
    /// single `📦 Deployed: <registry>:<tag>` line — through a
    /// [`io::Write`] sink. The byte-oracle surface for tests that
    /// pin the leading-blank + box + trailing-blank + image-ref
    /// line count without capturing stdout. Gated `#[cfg(test)]`
    /// because the runtime primitive delegates through the peer
    /// print primitives ([`print_boxed_banner`],
    /// [`print_deployed_image_ref`]) and does not need a public
    /// writer sibling at runtime.
    fn write_workflow_complete_banner<W: io::Write>(
        w: &mut W,
        kind: WorkflowCompleteBanner,
        registry: &dyn Display,
        tag: &dyn Display,
    ) -> io::Result<()> {
        writeln!(w)?;
        write_boxed_banner(w, BoxedBannerStyle::GreenBold, &kind.banner_title())?;
        writeln!(w)?;
        write_deployed_image_ref(w, registry, tag)
    }

    /// Serialize the writer-level tests against the process-global
    /// [`colored::control::set_override`] toggle — cargo runs tests
    /// in parallel by default, so without a mutex two tests racing
    /// the override toggle would flap between the "ANSI on" and
    /// "ANSI off" arms.
    static ANSI_OVERRIDE_LOCK: Mutex<()> = Mutex::new(());

    /// RAII guard that force-enables [`colored`] ANSI emission for
    /// the duration of a writer-level byte-oracle test.
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

    /// Byte-oracle #1: the `Deployment` arm renders as the exact
    /// title `"✅ Deployment Complete!"` — a byte-for-byte match
    /// against the pre-lift `commands/deploy.rs:208` inline
    /// literal.
    #[test]
    fn banner_title_deployment_matches_prelift_bytes() {
        assert_eq!(
            WorkflowCompleteBanner::Deployment.banner_title().as_bytes(),
            "✅ Deployment Complete!".as_bytes(),
        );
    }

    /// Byte-oracle #2: the `GitHubRunnerCi` arm renders as the
    /// exact title `"✅ GitHub Runner CI Complete!"` — a
    /// byte-for-byte match against the pre-lift
    /// `commands/github_runner_ci.rs:786` inline literal.
    #[test]
    fn banner_title_github_runner_ci_matches_prelift_bytes() {
        assert_eq!(
            WorkflowCompleteBanner::GitHubRunnerCi
                .banner_title()
                .as_bytes(),
            "✅ GitHub Runner CI Complete!".as_bytes(),
        );
    }

    /// Byte-oracle #3: the workflow-name slot is exactly one of
    /// two closed dialects. A future variant added to the enum
    /// must extend BOTH the [`WorkflowCompleteBanner::workflow_name`]
    /// match AND the pre-lift-parity oracle, so a silent drift is
    /// impossible.
    #[test]
    fn workflow_name_is_closed_to_two_dialects() {
        assert_eq!(
            WorkflowCompleteBanner::Deployment.workflow_name(),
            "Deployment"
        );
        assert_eq!(
            WorkflowCompleteBanner::GitHubRunnerCi.workflow_name(),
            "GitHub Runner CI"
        );
    }

    /// Byte-oracle #4: the banner-title composition is exactly
    /// `<glyph> <name> <verb>` — the two ASCII space separators
    /// (0x20) and the fixed leading-glyph / trailing-verb pair
    /// reach the output verbatim. A future `format!("{}: {} {}")`
    /// or `format!("{}-{} {}")` refactor regresses this.
    #[test]
    fn banner_title_carries_two_ascii_space_separators() {
        let title = WorkflowCompleteBanner::Deployment.banner_title();
        assert!(
            title.starts_with(WORKFLOW_COMPLETE_BANNER_GLYPH),
            "banner_title must start with the WHITE HEAVY CHECK MARK glyph; got {title:?}"
        );
        assert!(
            title.ends_with(WORKFLOW_COMPLETE_BANNER_VERB),
            "banner_title must end with the `Complete!` verb; got {title:?}"
        );
        // Exactly two ASCII spaces — one between glyph and name, one between name and verb.
        assert_eq!(
            title.matches(' ').count(),
            2,
            "banner_title must carry exactly two ASCII spaces (glyph<sp>name<sp>verb); got {title:?}"
        );
    }

    /// Byte-oracle #5: the leading glyph is the exact 3-byte
    /// `✅` WHITE HEAVY CHECK MARK (U+2705, `E2 9C 85`). A silent
    /// swap for `☑` (BALLOT BOX WITH CHECK, `E2 98 91`) or `✔`
    /// (HEAVY CHECK MARK, `E2 9C 94`) flips this.
    #[test]
    fn workflow_complete_banner_glyph_is_white_heavy_check_mark() {
        let bytes = WORKFLOW_COMPLETE_BANNER_GLYPH.as_bytes();
        assert_eq!(bytes.len(), 3, "glyph must be exactly 3 UTF-8 bytes");
        assert_eq!(bytes, &[0xE2, 0x9C, 0x85]);
    }

    /// Byte-oracle #6: [`write_workflow_complete_banner`] emits
    /// exactly six lines — leading framing blank, three box lines
    /// (top border, title middle, bottom border), trailing framing
    /// blank, then the single `📦 Deployed: <registry>:<tag>`
    /// line. A fusion that dropped either framing blank or reordered
    /// the banner and image-ref hits this.
    #[test]
    fn write_workflow_complete_banner_emits_six_lines() {
        let _guard = AnsiOverrideForTest::acquire();
        let mut buf: Vec<u8> = Vec::new();
        write_workflow_complete_banner(
            &mut buf,
            WorkflowCompleteBanner::Deployment,
            &"registry.example.com/pleme/api",
            &"v1.2.3",
        )
        .expect("write against Vec<u8> must succeed");
        let out = String::from_utf8(buf).expect("writer emits valid UTF-8");
        let lines: Vec<&str> = out.split_inclusive('\n').collect();
        assert_eq!(
            lines.len(),
            6,
            "write_workflow_complete_banner must emit exactly six lines \
             (blank + 3 box + blank + image-ref); got {}:\n{:?}",
            lines.len(),
            out
        );
    }

    /// Byte-oracle #7: line 0 is the leading framing blank (`\n`
    /// only). A fusion that dropped the leading blank hits this.
    #[test]
    fn write_workflow_complete_banner_leading_line_is_framing_blank() {
        let _guard = AnsiOverrideForTest::acquire();
        let mut buf: Vec<u8> = Vec::new();
        write_workflow_complete_banner(
            &mut buf,
            WorkflowCompleteBanner::GitHubRunnerCi,
            &"r",
            &"t",
        )
        .unwrap();
        let out = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = out.split_inclusive('\n').collect();
        assert_eq!(lines[0], "\n", "line 0 must be the leading framing blank");
    }

    /// Byte-oracle #8: line 4 is the trailing framing blank (`\n`
    /// only). A fusion that dropped the trailing blank OR
    /// re-ordered the banner and image-ref hits this.
    #[test]
    fn write_workflow_complete_banner_trailing_framing_blank_between_box_and_image_ref() {
        let _guard = AnsiOverrideForTest::acquire();
        let mut buf: Vec<u8> = Vec::new();
        write_workflow_complete_banner(&mut buf, WorkflowCompleteBanner::Deployment, &"r", &"t")
            .unwrap();
        let out = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = out.split_inclusive('\n').collect();
        assert_eq!(
            lines[4], "\n",
            "line 4 must be the trailing framing blank between the box and the image-ref"
        );
    }

    /// Byte-oracle #9: the last line is exactly the
    /// `📦 Deployed: <registry>:<tag>` byte sequence
    /// [`crate::ui::write_deployed_image_ref`] emits — the fusion
    /// delegates through the peer primitive, so a rename of the
    /// `Deployed:` label or a swap of the `📦` glyph over there
    /// reaches this test by construction.
    #[test]
    fn write_workflow_complete_banner_image_ref_line_matches_peer_primitive() {
        let _guard = AnsiOverrideForTest::acquire();
        let registry = "registry.example.com/pleme/api";
        let tag = "v1.2.3";

        let mut fused_buf: Vec<u8> = Vec::new();
        write_workflow_complete_banner(
            &mut fused_buf,
            WorkflowCompleteBanner::Deployment,
            &registry,
            &tag,
        )
        .unwrap();
        let fused = String::from_utf8(fused_buf).unwrap();
        let fused_lines: Vec<&str> = fused.split_inclusive('\n').collect();

        let mut peer_buf: Vec<u8> = Vec::new();
        write_deployed_image_ref(&mut peer_buf, &registry, &tag).unwrap();
        let peer = String::from_utf8(peer_buf).unwrap();

        assert_eq!(
            fused_lines[5], peer,
            "line 5 must match the peer `write_deployed_image_ref` byte-for-byte"
        );
    }

    /// Byte-oracle #10: the box body between the two framing blanks
    /// carries the GreenBold palette on all three lines — a demotion
    /// to `Green` alone under a terminal-milestone re-branding
    /// regresses this.
    #[test]
    fn write_workflow_complete_banner_carries_bright_green_bold_palette_on_box() {
        let _guard = AnsiOverrideForTest::acquire();
        let mut buf: Vec<u8> = Vec::new();
        write_workflow_complete_banner(&mut buf, WorkflowCompleteBanner::Deployment, &"r", &"t")
            .unwrap();
        let out = String::from_utf8(buf).unwrap();
        // `.bright_green()` = SGR 92, `.bold()` = SGR 1. `colored` folds the pair
        // into one of a few compound sequences depending on chain order; accept
        // any form that carries BOTH the bright-green (92) parameter AND the bold
        // (1) parameter reaching the wire.
        let carries_bright_green =
            out.contains("\x1b[92m") || out.contains("\x1b[1;92m") || out.contains("\x1b[92;1m");
        assert!(
            carries_bright_green,
            "box body must carry the `bright_green` SGR parameter (`92`); got {out:?}"
        );
        let carries_bold =
            out.contains("\x1b[1m") || out.contains("\x1b[1;92m") || out.contains("\x1b[92;1m");
        assert!(
            carries_bold,
            "box body must carry the `bold` SGR parameter (`1`); got {out:?}"
        );
    }

    /// Byte-oracle #11: the ordering is banner-THEN-image-ref, not
    /// the reverse. A silent swap that emitted the image-ref before
    /// the banner would still satisfy line-count and per-line pins,
    /// so pin the sequence explicitly.
    #[test]
    fn write_workflow_complete_banner_orders_banner_before_image_ref() {
        let _guard = AnsiOverrideForTest::acquire();
        let mut buf: Vec<u8> = Vec::new();
        write_workflow_complete_banner(
            &mut buf,
            WorkflowCompleteBanner::Deployment,
            &"registry.example.com",
            &"v1.0.0",
        )
        .unwrap();
        let out = String::from_utf8(buf).unwrap();
        let banner_pos = out
            .find("Deployment Complete!")
            .expect("banner title must appear");
        let image_ref_pos = out
            .find("📦 Deployed:")
            .expect("image-ref line must appear");
        assert!(
            banner_pos < image_ref_pos,
            "banner must precede the image-ref line; got banner_pos={banner_pos} \
             image_ref_pos={image_ref_pos}\nout={out:?}"
        );
    }

    /// Caller shield (negative): no source line under
    /// `cli/src/commands/{deploy,github_runner_ci}.rs` may still
    /// spell the pre-lift raw `"✅ <NAME> Complete!"` GreenBold
    /// banner-title literal inline. The two pre-lift sites migrated;
    /// any future consumer that wants the same terminal-milestone
    /// banner reaches for
    /// [`crate::workflow_complete_banner::print_workflow_complete_banner`]
    /// on first grep, not by copy-pasting the raw shape from a peer.
    #[test]
    fn no_command_module_still_spells_raw_workflow_complete_banner_title() {
        use std::path::PathBuf;
        let src_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let commands = src_dir.join("commands");
        let mut offenders: Vec<(PathBuf, usize, String)> = Vec::new();

        // The precise pre-lift needles — two exact byte spans, one per pre-lift dialect.
        let raw_needles: &[&str] = &[
            "\"✅ Deployment Complete!\"",
            "\"✅ GitHub Runner CI Complete!\"",
        ];

        for entry in std::fs::read_dir(&commands).unwrap().flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).unwrap();
            for (idx, line) in source.lines().enumerate() {
                // Skip comment lines so this shield's own prose reference to
                // the pre-lift shape doesn't self-hit.
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") {
                    continue;
                }
                for needle in raw_needles {
                    if line.contains(needle) {
                        offenders.push((path.clone(), idx + 1, line.to_string()));
                    }
                }
            }
        }

        assert!(
            offenders.is_empty(),
            "raw `\"✅ <NAME> Complete!\"` GreenBold banner-title literal(s) \
             survive under `commands/` — route each through \
             `crate::workflow_complete_banner::print_workflow_complete_banner(<kind>, <registry>, <tag>)` \
             instead:\n{offenders:#?}",
        );
    }

    /// Caller shield (positive): each of the two pre-lift command
    /// modules MUST forward through
    /// `crate::workflow_complete_banner::print_workflow_complete_banner(`
    /// at least once. A migration that dropped a call site outright
    /// would leave the negative "no raw literal" scan satisfied by
    /// absence; the positive count catches the drop.
    #[test]
    fn every_prelift_command_module_forwards_through_workflow_complete_banner() {
        use std::path::PathBuf;
        let src_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let expectations: &[&str] = &["commands/deploy.rs", "commands/github_runner_ci.rs"];
        for relpath in expectations {
            let path = src_dir.join(relpath);
            let source = std::fs::read_to_string(&path).unwrap();
            let forwards = source
                .matches("crate::workflow_complete_banner::print_workflow_complete_banner(")
                .count();
            assert!(
                forwards >= 1,
                "{relpath} must forward at least one workflow-complete banner \
                 site through \
                 `crate::workflow_complete_banner::print_workflow_complete_banner(`; \
                 found {forwards}. A dropped call would leave the negative \
                 raw-literal shield satisfied by absence.",
            );
        }
    }
}
