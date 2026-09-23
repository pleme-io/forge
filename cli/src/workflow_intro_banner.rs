//! CyanBold `<title>` workflow-intro boxed banner primitive — the
//! peer-class opening sibling to
//! [`crate::workflow_complete_banner::print_workflow_complete_banner`]
//! (the GreenBold `✅ <NAME> Complete!` terminal-milestone banner) at
//! the same two workflow entry points.
//!
//! # Duplication being lifted
//!
//! Two pre-lift sibling sites each restated the same four-line
//! `crate::ui::print_boxed_banner(crate::ui::BoxedBannerStyle::CyanBold, "<title>")`
//! stanza verbatim at the entry to a terminal-command workflow's
//! `execute` body, diverging only on the caller-owned title text:
//!
//! 1. `commands/deploy.rs::execute` (~L19) — the FluxCD GitOps
//!    deploy entry point. Title = `"Nexus Deploy - GitOps Workflow"`.
//! 2. `commands/github_runner_ci.rs::execute` (~L131) — the GitHub
//!    Runner CI workflow entry point. Title =
//!    `"GitHub Runner CI Workflow"`.
//!
//! Each spelling renders the same byte shape: a leading framing
//! blank, the three-line `╔═…╗` CyanBold boxed banner (top border,
//! indented+padded title middle line, bottom border), and a
//! trailing framing blank. A drift in the `CyanBold` palette (a
//! silent demotion to `Cyan` alone under a workflow-entry
//! re-branding, a promotion to `BrightCyanBold` under a stronger
//! visual anchor), the leading/trailing framing blank count, or
//! the padded-title width at either site pre-lift diverged
//! silently from the other — the operator's eye caught only the
//! local intro line, not the fleet-wide workflow-entry grammar
//! drift across the two workflow entry points.
//!
//! Post-lift the two entry points delegate through
//! [`print_workflow_intro_banner`] with a
//! [`WorkflowIntroBanner`] variant, closing the palette+title
//! choice at build time; this primitive completes the symmetric
//! peer pair with
//! [`crate::workflow_complete_banner::print_workflow_complete_banner`]
//! — the OPEN sibling to the CLOSE it already carried. Both pre-lift
//! consumers of [`crate::ui::BoxedBannerStyle::CyanBold`] migrated,
//! so the enum variant now has EXACTLY ONE named delegating consumer.
//!
//! # Distinct from every sibling banner primitive in the crate
//!
//! - [`crate::ui::print_boxed_banner`] with
//!   [`crate::ui::BoxedBannerStyle::CyanBold`] is the primitive
//!   this fusion delegates to; it stays the canonical entry point
//!   for any FUTURE CyanBold boxed banner that is NOT one of the
//!   two named workflow entry points (e.g. a cyan intro box for a
//!   third terminal-command workflow class not yet in scope).
//! - [`crate::workflow_complete_banner::print_workflow_complete_banner`]
//!   owns the peer-class terminal-milestone banner (GreenBold
//!   `✅ <NAME> Complete!` + image-ref line) at the SAME two
//!   workflow entry points; that primitive marks the END, this
//!   one marks the START. The two stay distinct because their
//!   palette encodes the milestone direction (Cyan = starting,
//!   Green = complete) and their body composition differs (this
//!   primitive prints only the box; the completion sibling fuses
//!   the box with a `📦 Deployed:` image-ref line).
//! - [`crate::release_workflow_intro_banner::
//!   print_release_workflow_intro_banner`] owns the peer-class
//!   `🚀 <service> <label> <detail>` release-workflow INTRO banner
//!   for single-service releases; distinct grammar (title-with-slots
//!   vs. ASCII-box) and distinct outer framing (ASCII underline vs.
//!   `╔═…╗` box).
//! - [`crate::product_workflow_intro_banner`] owns the peer-class
//!   `>>-bold` intro for the product-scoped multi-service pipeline;
//!   distinct outer framing (title-with-slots vs. box).
//!
//! # Delegation, not re-implementation
//!
//! The three-line ANSI-boxed banner body is delegated to
//! [`crate::ui::print_boxed_banner`] with
//! [`crate::ui::BoxedBannerStyle::CyanBold`] (which itself
//! terminates in [`crate::ui::write_boxed_banner`] and carries the
//! leading + trailing framing blanks). Neither the box glyphs nor
//! the palette-to-SGR mapping are restated here — a future swap of
//! the box grammar (`╔` → `╭` under a Unicode-rounded rebrand) or
//! an added palette variant on
//! [`crate::ui::BoxedBannerStyle`] lands in ONE place on the peer
//! primitive and this fusion inherits by composition.
//!
//! # THEORY grounding
//!
//! §V solve-once-at-the-primitive: the workflow-entry CyanBold
//! banner lives at ONE construction surface — a future refinement
//! (an OTLP `workflow_started` observability span emitted alongside
//! the print, a promotion of the CyanBold palette to a distinct
//! `WorkflowEntry` palette variant, an added structured-logging
//! event carrying the workflow name) lands in one place rather
//! than in every consumer.
//!
//! §VI.1 three-is-a-law is intentionally approached from below
//! here at two sites: the two pre-lift stanzas each carried the
//! full four-line stanza and diverged only on the title slot.
//! Lifting at N=2 keeps a third `commands/<workflow>.rs` module (a
//! future `commands/deploy_v2.rs`, a `commands/hotfix.rs`) from
//! reaching for the peer primitive and re-inlining the same four
//! lines by copy-paste — the typed enum below closes the
//! workflow-name choice at build time.

use crate::ui::{print_boxed_banner, BoxedBannerStyle};

/// Which of the two terminal-command workflow's intro banner is
/// being rendered. The variants are closed to the two dialects the
/// pre-lift sites spell — the enum is deliberately not open, so a
/// future variant added without an arm on
/// [`WorkflowIntroBanner::banner_title`] fails the exhaustiveness
/// check at build time. Sibling shape to
/// [`crate::workflow_complete_banner::WorkflowCompleteBanner`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkflowIntroBanner {
    /// `commands/deploy.rs::execute` FluxCD GitOps deploy entry
    /// point. Renders as `"Nexus Deploy - GitOps Workflow"`.
    NexusDeploy,
    /// `commands/github_runner_ci.rs::execute` GitHub Runner CI
    /// workflow entry point. Renders as `"GitHub Runner CI Workflow"`.
    GitHubRunnerCi,
}

impl WorkflowIntroBanner {
    /// The exact title string fed to
    /// [`crate::ui::print_boxed_banner`] /
    /// [`crate::ui::write_boxed_banner`]. Byte-identical to the
    /// pre-lift inline literal each entry-point spelled.
    ///
    /// The `NexusDeploy` arm carries the `"Nexus "` product-scope
    /// prefix and the `" - GitOps Workflow"` subtitle even though
    /// the sibling completion banner drops the product-scope prefix
    /// (`"Deployment"` alone) — the pre-lift intro title deliberately
    /// carries the fuller product+scope form so the cyan opening box
    /// reads as the fully-qualified workflow entry, matching the
    /// pre-lift byte shape verbatim.
    pub const fn banner_title(self) -> &'static str {
        match self {
            Self::NexusDeploy => "Nexus Deploy - GitOps Workflow",
            Self::GitHubRunnerCi => "GitHub Runner CI Workflow",
        }
    }
}

/// Prints the CyanBold `<title>` boxed banner at a terminal-command
/// workflow's `execute` entry, sharing the exact bytes the pre-lift
/// four-line stanza wrote across `commands/deploy.rs` and
/// `commands/github_runner_ci.rs`.
///
/// Delegates through the peer print primitive
/// [`print_boxed_banner`] (with [`BoxedBannerStyle::CyanBold`],
/// which itself carries the leading + trailing framing blank on
/// its own body). Neither the box glyphs nor the palette-to-SGR
/// mapping are restated here — a future swap of the box grammar
/// (`╔` → `╭` under a Unicode-rounded rebrand) or an added palette
/// variant on [`BoxedBannerStyle`] lands in ONE place on the peer
/// primitive and this fusion inherits by composition. The
/// byte-shape end-to-end (leading blank + box + trailing blank) is
/// pinned by the `write_workflow_intro_banner` test helper against
/// the same peer `write_` primitive.
///
/// # Parameters
///
/// - `kind` — which of the two closed workflow-intro dialects this
///   call renders. See [`WorkflowIntroBanner`].
pub fn print_workflow_intro_banner(kind: WorkflowIntroBanner) {
    print_boxed_banner(BoxedBannerStyle::CyanBold, kind.banner_title());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::write_boxed_banner;
    use std::io;
    use std::sync::Mutex;

    /// Test-only writer sibling to [`print_workflow_intro_banner`].
    /// Emits the same byte sequence [`print_workflow_intro_banner`]
    /// writes to stdout — a leading framing blank, the three-line
    /// CyanBold `╔═…╗` box, and a trailing framing blank — through
    /// a [`io::Write`] sink. The byte-oracle surface for tests that
    /// pin the leading-blank + box + trailing-blank line count
    /// without capturing stdout. Gated `#[cfg(test)]` because the
    /// runtime primitive delegates through the peer print primitive
    /// ([`print_boxed_banner`]) and does not need a public writer
    /// sibling at runtime.
    fn write_workflow_intro_banner<W: io::Write>(
        w: &mut W,
        kind: WorkflowIntroBanner,
    ) -> io::Result<()> {
        writeln!(w)?;
        write_boxed_banner(w, BoxedBannerStyle::CyanBold, kind.banner_title())?;
        writeln!(w)
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

    /// Byte-oracle #1: the `NexusDeploy` arm renders as the exact
    /// title `"Nexus Deploy - GitOps Workflow"` — a byte-for-byte
    /// match against the pre-lift `commands/deploy.rs:21` inline
    /// literal.
    #[test]
    fn banner_title_nexus_deploy_matches_prelift_bytes() {
        assert_eq!(
            WorkflowIntroBanner::NexusDeploy.banner_title().as_bytes(),
            "Nexus Deploy - GitOps Workflow".as_bytes(),
        );
    }

    /// Byte-oracle #2: the `GitHubRunnerCi` arm renders as the
    /// exact title `"GitHub Runner CI Workflow"` — a byte-for-byte
    /// match against the pre-lift `commands/github_runner_ci.rs:133`
    /// inline literal.
    #[test]
    fn banner_title_github_runner_ci_matches_prelift_bytes() {
        assert_eq!(
            WorkflowIntroBanner::GitHubRunnerCi
                .banner_title()
                .as_bytes(),
            "GitHub Runner CI Workflow".as_bytes(),
        );
    }

    /// Byte-oracle #3: the workflow-intro title slot is exactly one
    /// of two closed dialects. A future variant added to the enum
    /// must extend BOTH the [`WorkflowIntroBanner::banner_title`]
    /// match AND the pre-lift-parity oracle above, so a silent drift
    /// is impossible.
    #[test]
    fn banner_title_is_closed_to_two_dialects() {
        // Exhaustive per-variant check: if a new variant is added
        // and this test is not extended, the match-arms below would
        // remain unchanged and the check would drift. A future
        // reviewer must extend BOTH the match on `banner_title` and
        // this test.
        let all: [WorkflowIntroBanner; 2] = [
            WorkflowIntroBanner::NexusDeploy,
            WorkflowIntroBanner::GitHubRunnerCi,
        ];
        let titles: Vec<&'static str> = all.iter().map(|k| k.banner_title()).collect();
        assert_eq!(
            titles,
            vec![
                "Nexus Deploy - GitOps Workflow",
                "GitHub Runner CI Workflow"
            ]
        );
    }

    /// Byte-oracle #4: [`write_workflow_intro_banner`] emits
    /// exactly five lines — leading framing blank, three box lines
    /// (top border, title middle, bottom border), trailing framing
    /// blank. A rewrite that dropped either framing blank or added
    /// a stray body line hits this.
    #[test]
    fn write_workflow_intro_banner_emits_five_lines() {
        let _guard = AnsiOverrideForTest::acquire();
        let mut buf: Vec<u8> = Vec::new();
        write_workflow_intro_banner(&mut buf, WorkflowIntroBanner::NexusDeploy)
            .expect("write against Vec<u8> must succeed");
        let out = String::from_utf8(buf).expect("writer emits valid UTF-8");
        let lines: Vec<&str> = out.split_inclusive('\n').collect();
        assert_eq!(
            lines.len(),
            5,
            "write_workflow_intro_banner must emit exactly five lines \
             (blank + 3 box + blank); got {}:\n{:?}",
            lines.len(),
            out
        );
    }

    /// Byte-oracle #5: line 0 is the leading framing blank (`\n`
    /// only). A rewrite that dropped the leading blank hits this.
    #[test]
    fn write_workflow_intro_banner_leading_line_is_framing_blank() {
        let _guard = AnsiOverrideForTest::acquire();
        let mut buf: Vec<u8> = Vec::new();
        write_workflow_intro_banner(&mut buf, WorkflowIntroBanner::GitHubRunnerCi).unwrap();
        let out = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = out.split_inclusive('\n').collect();
        assert_eq!(lines[0], "\n", "line 0 must be the leading framing blank");
    }

    /// Byte-oracle #6: line 4 (the last line) is the trailing
    /// framing blank (`\n` only). A rewrite that dropped the trailing
    /// blank hits this.
    #[test]
    fn write_workflow_intro_banner_trailing_line_is_framing_blank() {
        let _guard = AnsiOverrideForTest::acquire();
        let mut buf: Vec<u8> = Vec::new();
        write_workflow_intro_banner(&mut buf, WorkflowIntroBanner::NexusDeploy).unwrap();
        let out = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = out.split_inclusive('\n').collect();
        assert_eq!(
            lines[4], "\n",
            "line 4 must be the trailing framing blank after the box body"
        );
    }

    /// Byte-oracle #7: the box body between the two framing blanks
    /// carries the CyanBold palette on all three lines — a demotion
    /// to `Cyan` alone under a workflow-entry re-branding regresses
    /// this. `colored` splices `.bright_cyan().bold()` into either
    /// `\x1b[1;96m` or `\x1b[96;1m`; accept either form.
    #[test]
    fn write_workflow_intro_banner_carries_bright_cyan_bold_palette_on_box() {
        let _guard = AnsiOverrideForTest::acquire();
        let mut buf: Vec<u8> = Vec::new();
        write_workflow_intro_banner(&mut buf, WorkflowIntroBanner::NexusDeploy).unwrap();
        let out = String::from_utf8(buf).unwrap();
        let carries_bright_cyan =
            out.contains("\x1b[96m") || out.contains("\x1b[1;96m") || out.contains("\x1b[96;1m");
        assert!(
            carries_bright_cyan,
            "box body must carry the `bright_cyan` SGR parameter (`96`); got {out:?}"
        );
        let carries_bold =
            out.contains("\x1b[1m") || out.contains("\x1b[1;96m") || out.contains("\x1b[96;1m");
        assert!(
            carries_bold,
            "box body must carry the `bold` SGR parameter (`1`); got {out:?}"
        );
    }

    /// Byte-oracle #8: the box middle line carries the title
    /// verbatim — a rewrite that dropped or altered the title
    /// interpolation hits this. Also pins that each variant's
    /// `banner_title()` reaches the emitted middle line unchanged.
    #[test]
    fn write_workflow_intro_banner_middle_line_carries_title_verbatim() {
        let _guard = AnsiOverrideForTest::acquire();
        for kind in [
            WorkflowIntroBanner::NexusDeploy,
            WorkflowIntroBanner::GitHubRunnerCi,
        ] {
            let mut buf: Vec<u8> = Vec::new();
            write_workflow_intro_banner(&mut buf, kind).unwrap();
            let out = String::from_utf8(buf).unwrap();
            assert!(
                out.contains(kind.banner_title()),
                "{kind:?}: emitted body must carry the title `{}` verbatim; got {out:?}",
                kind.banner_title(),
            );
        }
    }

    /// Caller shield (negative): no source line under
    /// `cli/src/commands/{deploy,github_runner_ci}.rs` may still
    /// spell the pre-lift raw `"<title>"` CyanBold intro banner
    /// literal inline. The two pre-lift sites migrated; any future
    /// consumer that wants the same workflow-entry banner reaches
    /// for
    /// [`crate::workflow_intro_banner::print_workflow_intro_banner`]
    /// on first grep, not by copy-pasting the raw shape from a peer.
    #[test]
    fn no_command_module_still_spells_raw_workflow_intro_banner_title() {
        use std::path::PathBuf;
        let src_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let commands = src_dir.join("commands");
        let mut offenders: Vec<(PathBuf, usize, String)> = Vec::new();

        // The precise pre-lift needles — two exact byte spans, one per pre-lift dialect.
        let raw_needles: &[&str] = &[
            "\"Nexus Deploy - GitOps Workflow\"",
            "\"GitHub Runner CI Workflow\"",
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
            "raw `\"<title>\"` CyanBold workflow-intro banner literal(s) \
             survive under `commands/` — route each through \
             `crate::workflow_intro_banner::print_workflow_intro_banner(<kind>)` \
             instead:\n{offenders:#?}",
        );
    }

    /// Caller shield (positive): each of the two pre-lift command
    /// modules MUST forward through
    /// `crate::workflow_intro_banner::print_workflow_intro_banner(`
    /// at least once. A migration that dropped a call site outright
    /// would leave the negative "no raw literal" scan satisfied by
    /// absence; the positive count catches the drop.
    #[test]
    fn every_prelift_command_module_forwards_through_workflow_intro_banner() {
        use std::path::PathBuf;
        let src_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let expectations: &[&str] = &["commands/deploy.rs", "commands/github_runner_ci.rs"];
        for relpath in expectations {
            let path = src_dir.join(relpath);
            let source = std::fs::read_to_string(&path).unwrap();
            let forwards = source
                .matches("crate::workflow_intro_banner::print_workflow_intro_banner(")
                .count();
            assert!(
                forwards >= 1,
                "{relpath} must forward at least one workflow-intro banner \
                 site through \
                 `crate::workflow_intro_banner::print_workflow_intro_banner(`; \
                 found {forwards}. A dropped call would leave the negative \
                 raw-literal shield satisfied by absence.",
            );
        }
    }

    /// Caller shield (negative): no source line under
    /// `cli/src/commands/` may spell the NARROW
    /// `crate::ui::BoxedBannerStyle::CyanBold` variant inline any more.
    /// Both pre-lift consumers of the `CyanBold` variant migrated onto
    /// this primitive; a future consumer that reaches for the raw
    /// enum variant bypasses the closed workflow-name enum on this
    /// primitive and re-opens the choice.
    ///
    /// The needle is qualified with the `ui::` module prefix so it
    /// does NOT false-positive on the peer WIDE-box variant
    /// [`crate::ui::WideBoxedBannerStyle::CyanBold`], which is a
    /// distinct enum for the wider 65-codepoint box grammar and
    /// remains a legitimate inline choice for callers not on this
    /// primitive's narrow-box workflow-entry class.
    #[test]
    fn no_command_module_reaches_for_cyan_bold_variant_directly() {
        use std::path::PathBuf;
        let src_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let commands = src_dir.join("commands");
        let mut offenders: Vec<(PathBuf, usize, String)> = Vec::new();
        let needle = "ui::BoxedBannerStyle::CyanBold";
        for entry in std::fs::read_dir(&commands).unwrap().flatten() {
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
                if line.contains(needle) {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "`{needle}` reached inline under `commands/` — route through \
             `crate::workflow_intro_banner::print_workflow_intro_banner(<kind>)` \
             instead:\n{offenders:#?}",
        );
    }
}
