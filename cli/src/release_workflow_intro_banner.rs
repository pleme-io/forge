//! `🚀 <service> <label> <detail>` release-workflow intro banner
//! fusion primitive — the peer-class `Pattern A` two-line stanza
//! [`crate::ui::write_command_intro_banner`]'s docstring names as
//! "outside this primitive's scope" because it carries a distinct
//! color slot ordering (`<service>.cyan().bold()` on the first slot,
//! `<label>.bold()` on the second, `<detail>.dimmed()` on the third)
//! and a divergent underline width.
//!
//! # Duplication being lifted
//!
//! Four pre-lift sibling sites each restated the same two-line
//! `println!("🚀 {} {} {}", <s>.cyan().bold(), <l>.bold(),
//! <d>.dimmed()); crate::ui::print_ascii_title_underline(<N>);`
//! stanza verbatim, diverging only on the caller-owned service /
//! label / detail slots and on the underline width `<N>`:
//!
//! 1. `commands/rust_service.rs::orchestrate_release` (~L1210) —
//!    the `Build-Once-Promote Release` / `Push-Only` / `Deploy-Only`
//!    intro at the multi-environment orchestration entry point.
//!    Underline width 60.
//! 2. `commands/rust_service.rs::orchestrate_standalone_release`
//!    (~L1748) — the `Standalone Release` intro at the no-deploy.yaml
//!    fall-through entry point. Underline width 60.
//! 3. `commands/rust_service.rs::release_rust_service` (~L2349) —
//!    the `Service Release Workflow (crate2nix)` intro at the
//!    single-service release entry point. Underline width 50.
//! 4. `commands/developer_tools.rs::rust_dev` (~L442) — the
//!    `Local Development (powered by forge)` intro at the local
//!    dev-loop entry point. Underline width 50.
//!
//! Each of the four spellings renders the same byte shape: the
//! `🚀` ROCKET glyph (U+1F680, 4 bytes F0 9F 9A 80) opening the
//! title, one ASCII space, the cyan+bold service slot, one ASCII
//! space, the bold label slot, one ASCII space, the dimmed
//! parenthesized detail slot, a trailing `\n`, then the
//! [`crate::ui::write_ascii_title_underline`]-delegated `=`-rule +
//! blank pair of the chosen width. A drift in the glyph (a
//! `"🎯"` swap under a different release-verb grammar), the slot
//! ordering (a promotion of `<label>` past `<service>` under a
//! label-first reordering), the color palette (a promotion of
//! `<label>` to `.cyan().bold()` matching `<service>`, a demotion
//! of `<service>` to `.bold()` alone), or the trailing underline
//! width at any one site pre-lift diverged silently from the
//! other three — the operator's eye caught only the local intro
//! line, not the fleet-wide grammar drift across the four workflow
//! entry points.
//!
//! # Distinct from the sibling `print_command_intro_banner`
//!
//! [`crate::ui::print_command_intro_banner`] owns the peer
//! four-part intro `<emoji> <verb.bold()> <subject.cyan()>
//! <detail.dimmed()>` at 7 pre-lift sites across
//! `commands/{rust_service, web_service, developer_tools}.rs` and
//! pins its underline width at the fixed
//! `COMMAND_INTRO_BANNER_UNDERLINE_WIDTH` (50). Its docstring
//! (`cli/src/ui.rs:4713-4719`) explicitly carves out this primitive's
//! class:
//!
//! > A distinct peer-class `Pattern A` release-workflow intro banner
//! > (`🚀 {} {} {}` with `<subject>.cyan().bold() + <mode>.bold() +
//! > <detail>.dimmed()` [...]) carries a different color slot
//! > ordering and an underline width of 60, so remains a separate
//! > class outside this primitive's scope.
//!
//! The two banners stay distinct because their color slot ordering
//! encodes a different eye-navigation contract: the peer's title
//! anchors on the VERB (`Building`, `Pushing`, `Deploying`) so the
//! reader locks onto WHAT is happening; this primitive's title
//! anchors on the SERVICE (via the `.cyan().bold()` combo) so the
//! reader locks onto WHICH service is running the workflow. The
//! width divergence (50 vs. 60) reflects the same distinction —
//! `Pattern A` sits above longer release-line pipelines whose body
//! output benefits from a wider visual anchor.
//!
//! Also distinct from [`crate::ui::print_release_stage_banner`],
//! which owns the three-line `━`-rule + `<STAGE> COMPLETE`
//! headline + rule TERMINAL-milestone banner — that primitive marks
//! the END of a stage; this one marks the START of a workflow.
//!
//! # Delegation, not re-implementation
//!
//! The `=`-rule + blank pair beneath the title is delegated to
//! [`crate::ui::write_ascii_title_underline`] — the same primitive
//! [`crate::ui::write_command_intro_banner`] delegates to. A future
//! swap of the rule glyph (`=` → `━`) or a standardization of the
//! rule width across both banner classes lands in ONE place (the
//! `ui.rs` `write_ascii_title_underline` body) and both banner
//! primitives inherit by composition.
//!
//! # THEORY grounding
//!
//! §V solve-once-at-the-primitive: the `🚀 <service> <label>
//! <detail>` release-workflow intro shape lives at ONE construction
//! surface — a future refinement (a `🚀` → `🚢` verb-glyph swap
//! under a fleet-wide release-vocabulary re-branding, an added
//! OTLP `release_workflow_started` observability span alongside the
//! print, a hoist of the underline width choice into a typed
//! `WorkflowScope::{Orchestration,Single}` enum whose `.underline_width()`
//! projection replaces the raw `usize` parameter) lands in one
//! place rather than in every consumer.
//!
//! §VI.1 three-is-a-law: four sites today
//! (`orchestrate_release`, `orchestrate_standalone_release`,
//! `release_rust_service`, `rust_dev`), clearing the duplication
//! threshold at exactly the point THEORY calls a law.

use std::io;

use colored::Colorize;

/// The `🚀` ROCKET glyph (U+1F680, 4 bytes `F0 9F 9A 80`, no
/// variation selector) opening the release-workflow intro banner
/// every pre-lift consumer spelled inline in the fixed
/// `"🚀 {} {} {}"` template. Named as a `const` so a future swap
/// (`🚀` → `🚢` under a fleet-wide release-vocabulary rebrand)
/// lands at ONE edit rather than through four inline literal edits.
pub const RELEASE_WORKFLOW_INTRO_BANNER_EMOJI: &str = "🚀";

/// Prints the two-line release-workflow intro banner — the
/// `🚀 <service.cyan().bold()> <label.bold()> <detail.dimmed()>`
/// title line followed by an `=`-rule + blank pair of the given
/// `underline_width`, delegated through
/// [`crate::ui::print_ascii_title_underline`].
///
/// Delegates to [`write_release_workflow_intro_banner`] against
/// [`std::io::stdout()`]; the writer split exists so the
/// fail-before-pass tests can pin the three-slot color ordering, the
/// ANSI escape palette on each argument, and the delegated
/// underline width by inspecting emitted bytes rather than
/// capturing stdout.
///
/// # Parameters
///
/// - `service` — the workflow's target service (e.g. `"web"`,
///   `"api"`); rendered `.cyan().bold()` so the eye locks onto
///   WHICH service is running the workflow.
/// - `label` — the workflow name (e.g. `"Build-Once-Promote
///   Release"`, `"Service Release Workflow"`, `"Local Development"`);
///   rendered `.bold()`.
/// - `detail` — the parenthesized detail (e.g. `"(2 environments)"`,
///   `"(crate2nix)"`, `"(powered by forge)"`); rendered `.dimmed()`.
/// - `underline_width` — the width of the `=`-rule beneath the
///   title. Pre-lift the four consumer sites picked either 60
///   (multi-scope release orchestration) or 50 (single-scope
///   release + local-dev). Kept as an explicit caller argument so
///   the width divergence lives at the caller — a future hoist
///   into a typed `WorkflowScope` enum whose `.underline_width()`
///   projection replaces the raw `usize` is a follow-up compounding
///   step, not a silent standardization here.
pub fn print_release_workflow_intro_banner(
    service: &str,
    label: &str,
    detail: &str,
    underline_width: usize,
) {
    let _ = write_release_workflow_intro_banner(
        &mut std::io::stdout().lock(),
        service,
        label,
        detail,
        underline_width,
    );
}

/// Writer-taking sibling to [`print_release_workflow_intro_banner`].
/// Emits the same two-line body [`print_release_workflow_intro_banner`]
/// writes to stdout, but through a [`io::Write`] sink — the
/// byte-oracle surface for tests that pin the ANSI-wrapped title
/// line, the delegated underline width, and the trailing framing
/// blank without capturing stdout.
///
/// # Byte contract
///
/// The written byte sequence is exactly:
///
/// ```text
/// 🚀 <\x1b[1;36m|\x1b[36;1m|\x1b[1m\x1b[36m><service>\x1b[0m
///    \x1b[1m<label>\x1b[0m
///    \x1b[2m<detail>\x1b[0m\n
/// <=×underline_width>\n
/// \n
/// ```
///
/// (line-broken here for readability; actually emitted as three
/// lines: title + rule + blank). The rule + blank pair is
/// delegated to [`crate::ui::write_ascii_title_underline`] so the
/// underline grammar reaches this primitive through the peer's
/// typed body rather than a second literal `"=".repeat(width)`.
pub fn write_release_workflow_intro_banner<W: io::Write>(
    w: &mut W,
    service: &str,
    label: &str,
    detail: &str,
    underline_width: usize,
) -> io::Result<()> {
    writeln!(
        w,
        "{} {} {} {}",
        RELEASE_WORKFLOW_INTRO_BANNER_EMOJI,
        service.cyan().bold(),
        label.bold(),
        detail.dimmed(),
    )?;
    crate::ui::write_ascii_title_underline(w, underline_width)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::sync::Mutex;

    /// Serialize the `.cyan().bold()` / `.bold()` / `.dimmed()`
    /// writer-level tests against the process-global
    /// [`colored::control::set_override`] toggle a peer test in
    /// `crate::ui` also acquires — a fair copy of the
    /// `AnsiOverrideForTest` guard in `cli/src/ui.rs`. Cargo runs
    /// tests in parallel by default, so without a mutex two tests
    /// racing the override toggle would flap between the "ANSI on"
    /// and "ANSI off" arms.
    static ANSI_OVERRIDE_LOCK: Mutex<()> = Mutex::new(());

    /// RAII guard that force-enables [`colored`] ANSI emission for
    /// the duration of a writer-level byte-oracle test. Drop
    /// restores [`colored`]'s auto-detection AFTER releasing the
    /// shared lock, so a peer test waiting on the mutex cannot
    /// observe the override-forced-on window between this writer
    /// finishing and the unset firing.
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

    /// Byte-oracle: [`write_release_workflow_intro_banner`] emits
    /// exactly three lines — the fused `🚀 <s> <l> <d>` title,
    /// the `=`-rule of the given width, then a framing blank.
    #[test]
    fn write_release_workflow_intro_banner_emits_three_lines() {
        let _override_guard = AnsiOverrideForTest::acquire();
        let mut buf: Vec<u8> = Vec::new();
        write_release_workflow_intro_banner(
            &mut buf,
            "web",
            "Local Development",
            "(powered by forge)",
            50,
        )
        .expect("write against Vec<u8> must succeed");
        let out = String::from_utf8(buf).expect("writer emits valid UTF-8");
        let lines: Vec<&str> = out.split_inclusive('\n').collect();
        assert_eq!(
            lines.len(),
            3,
            "write_release_workflow_intro_banner must emit exactly three \
             lines — the fused 🚀 title, the `=`-rule of the given width, \
             then a framing blank; got {}:\n{:?}",
            lines.len(),
            out
        );
    }

    /// Byte-oracle: line 0 opens with the exact 4-byte `🚀` ROCKET
    /// glyph (U+1F680, `F0 9F 9A 80`) followed by a single ASCII
    /// space, before any ANSI escape byte. A silent swap for a
    /// sibling release-verb glyph (e.g. `🚢`, `🎯`) flips this.
    #[test]
    fn write_release_workflow_intro_banner_opens_with_rocket_glyph_and_space() {
        let _override_guard = AnsiOverrideForTest::acquire();
        let mut buf: Vec<u8> = Vec::new();
        write_release_workflow_intro_banner(&mut buf, "svc", "Label", "(detail)", 50).unwrap();
        let out = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = out.split_inclusive('\n').collect();
        let bytes = lines[0].as_bytes();
        assert!(
            bytes.len() >= 5,
            "line 0 must carry at least the 4-byte rocket glyph + space; \
             got {} bytes",
            bytes.len()
        );
        assert_eq!(bytes[0], 0xF0, "byte 0 must be the first rocket-glyph byte");
        assert_eq!(
            bytes[1], 0x9F,
            "byte 1 must be the second rocket-glyph byte"
        );
        assert_eq!(bytes[2], 0x9A, "byte 2 must be the third rocket-glyph byte");
        assert_eq!(
            bytes[3], 0x80,
            "byte 3 must be the fourth rocket-glyph byte"
        );
        assert_eq!(
            bytes[4], b' ',
            "byte 4 must be a single ASCII space (0x20), NOT an ANSI \
             escape byte — the rocket glyph and space sit OUTSIDE the \
             `.cyan().bold()` coloring span on the service slot"
        );
    }

    /// Byte-oracle: the underline width parameter drives the rule
    /// length. Passing 60 yields exactly 60 `=` bytes on line 1;
    /// passing 50 yields exactly 50.
    #[test]
    fn write_release_workflow_intro_banner_rule_line_matches_underline_width() {
        let _override_guard = AnsiOverrideForTest::acquire();
        for width in [50_usize, 60] {
            let mut buf: Vec<u8> = Vec::new();
            write_release_workflow_intro_banner(&mut buf, "s", "L", "(d)", width).unwrap();
            let out = String::from_utf8(buf).unwrap();
            let lines: Vec<&str> = out.split_inclusive('\n').collect();
            let expected = format!("{}\n", "=".repeat(width));
            assert_eq!(
                lines[1], expected,
                "line 1 must be exactly {width} `=` bytes + `\\n` — the \
                 rule width is delegated to `write_ascii_title_underline` \
                 with the caller's `underline_width` argument; got {:?}",
                lines[1]
            );
        }
    }

    /// Byte-oracle: line 2 is exactly `\n`. The trailing framing
    /// blank comes from [`crate::ui::write_ascii_title_underline`]'s
    /// own second `writeln!(w)`; a fusion that dropped it fails
    /// here.
    #[test]
    fn write_release_workflow_intro_banner_trailing_line_is_framing_blank() {
        let _override_guard = AnsiOverrideForTest::acquire();
        let mut buf: Vec<u8> = Vec::new();
        write_release_workflow_intro_banner(&mut buf, "s", "L", "(d)", 50).unwrap();
        let out = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = out.split_inclusive('\n').collect();
        assert_eq!(
            lines[2], "\n",
            "line 2 must be exactly `\\n` — the trailing framing blank \
             comes from `write_ascii_title_underline`; got {:?}",
            lines[2]
        );
    }

    /// Palette pin (service slot): the `cyan` SGR parameter (`36`)
    /// AND the `bold` SGR parameter (`1`) both reach the buffer.
    /// `colored` folds `.cyan().bold()` into a single compound
    /// `\x1b[1;36m` SGR sequence on 2.x, but a future release may
    /// pick `\x1b[36;1m` or split the pair — accept any form so
    /// the contract is BOTH SGR parameters reach the wire, not
    /// which byte-encoding colored picks. A promotion to
    /// `.bright_cyan()` (`\x1b[96m`) would drift from the pre-lift
    /// SGR contract the four sites shared.
    #[test]
    fn write_release_workflow_intro_banner_carries_cyan_bold_on_service_slot() {
        let _override_guard = AnsiOverrideForTest::acquire();
        let mut buf: Vec<u8> = Vec::new();
        write_release_workflow_intro_banner(&mut buf, "svc-alpha", "L", "(d)", 50).unwrap();
        let out = String::from_utf8(buf).unwrap();
        let carries_cyan =
            out.contains("\x1b[36m") || out.contains("\x1b[1;36m") || out.contains("\x1b[36;1m");
        assert!(
            carries_cyan,
            "output must carry the `cyan` SGR parameter (`36`) on the \
             service slot — a silent drop of `.cyan()` or a promotion \
             to `.bright_cyan()` (`\\x1b[96m`) flips this; got {:?}",
            out
        );
        assert!(
            !out.contains("\x1b[96m"),
            "output must NOT carry the `bright_cyan` SGR parameter \
             (`96`) — the pre-lift coloring on the service slot was \
             `.cyan().bold()` alone (never `.bright_cyan()`); got {:?}",
            out
        );
        let carries_bold =
            out.contains("\x1b[1m") || out.contains("\x1b[1;36m") || out.contains("\x1b[36;1m");
        assert!(
            carries_bold,
            "output must carry the `bold` SGR parameter (`1`) — every \
             pre-lift consumer chained `.bold()` on both the service \
             and label slots; got {:?}",
            out
        );
    }

    /// Palette pin (detail slot): the `dim` SGR parameter (`2`)
    /// reaches the buffer — every pre-lift consumer chained
    /// `.dimmed()` on the parenthesized detail slot so the eye
    /// followed the service + label bright above rather than the
    /// contextual aside.
    #[test]
    fn write_release_workflow_intro_banner_carries_dim_on_detail_slot() {
        let _override_guard = AnsiOverrideForTest::acquire();
        let mut buf: Vec<u8> = Vec::new();
        write_release_workflow_intro_banner(&mut buf, "s", "L", "(detail-body)", 50).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(
            out.contains("\x1b[2m"),
            "output must carry the `dim` SGR parameter (`2`) on the \
             detail slot — a silent drop of `.dimmed()` flips this; \
             got {:?}",
            out
        );
    }

    /// Slot-order pin: the plain-text projection of line 0 (with
    /// ANSI stripped) places `service`, then `label`, then `detail`
    /// in that exact order between the leading `🚀 ` and the
    /// trailing `\n`. A refactor that swapped the argv order would
    /// silently retarget every intro banner and a mere length check
    /// would not catch it.
    #[test]
    fn write_release_workflow_intro_banner_places_service_label_detail_in_order() {
        let _override_guard = AnsiOverrideForTest::acquire();
        let mut buf: Vec<u8> = Vec::new();
        write_release_workflow_intro_banner(
            &mut buf,
            "SERVICE_SLOT",
            "LABEL_SLOT",
            "DETAIL_SLOT",
            50,
        )
        .unwrap();
        let out = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = out.split_inclusive('\n').collect();
        let service_pos = lines[0].find("SERVICE_SLOT").expect("service present");
        let label_pos = lines[0].find("LABEL_SLOT").expect("label present");
        let detail_pos = lines[0].find("DETAIL_SLOT").expect("detail present");
        assert!(
            service_pos < label_pos,
            "service must land before label; got service={service_pos} label={label_pos}"
        );
        assert!(
            label_pos < detail_pos,
            "label must land before detail; got label={label_pos} detail={detail_pos}"
        );
    }

    /// Equivalence oracle: passing the four sites' actual arguments
    /// yields bytes byte-for-byte identical to the pre-lift stanza
    /// spelled inline. Pins the migration end-to-end: a drift in
    /// the primitive body against the pre-lift idiom fails HERE,
    /// not after a consumer has already been re-wired.
    #[test]
    fn write_release_workflow_intro_banner_matches_pre_lift_stanza_bytes() {
        let _override_guard = AnsiOverrideForTest::acquire();
        // Reference stanza: the pre-lift shape the four consumer
        // sites each spelled inline, reconstructed here via the
        // same `writeln!` idiom against a `Vec<u8>` writer so the
        // ANSI wrapping colored applies on `.cyan().bold()`,
        // `.bold()`, and `.dimmed()` is identical.
        for (service, label, detail, width) in [
            ("web", "Local Development", "(powered by forge)", 50_usize),
            ("api", "Service Release Workflow", "(crate2nix)", 50),
            (
                "svc",
                "Standalone Release",
                "(no deploy.yaml — push only)",
                60,
            ),
            ("svc", "Build-Once-Promote Release", "(2 environments)", 60),
        ] {
            let mut via_primitive: Vec<u8> = Vec::new();
            write_release_workflow_intro_banner(&mut via_primitive, service, label, detail, width)
                .unwrap();
            let mut via_pre_lift: Vec<u8> = Vec::new();
            writeln!(
                &mut via_pre_lift,
                "🚀 {} {} {}",
                service.cyan().bold(),
                label.bold(),
                detail.dimmed(),
            )
            .unwrap();
            crate::ui::write_ascii_title_underline(&mut via_pre_lift, width).unwrap();
            assert_eq!(
                via_primitive, via_pre_lift,
                "primitive output must match the pre-lift inline stanza \
                 byte-for-byte for (service={service:?}, label={label:?}, \
                 detail={detail:?}, width={width})"
            );
        }
    }

    /// Post-lift shield (negative half): no source line under
    /// `cli/src/commands/` may still spell the pre-lift
    /// `println!("🚀 {} {} {}"` two-line stanza inline. Every
    /// consumer reaches for [`print_release_workflow_intro_banner`]
    /// on first grep, not by copy-pasting the raw `println!` from
    /// an existing sibling.
    #[test]
    fn no_commands_module_still_spells_raw_rocket_release_intro_println() {
        use std::path::PathBuf;
        let src_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let needle = "\"🚀 {} {} {}\"";
        fn walk(dir: &std::path::Path, out: &mut Vec<PathBuf>) {
            for entry in std::fs::read_dir(dir).unwrap().flatten() {
                let p = entry.path();
                if p.is_dir() {
                    walk(&p, out);
                } else if p.extension().and_then(|e| e.to_str()) == Some("rs") {
                    out.push(p);
                }
            }
        }
        let mut files: Vec<PathBuf> = Vec::new();
        walk(&src_dir, &mut files);
        let mut offenders: Vec<(PathBuf, usize, String)> = Vec::new();
        for path in files {
            let source = std::fs::read_to_string(&path).unwrap();
            let mut in_block_comment = false;
            for (idx, line) in source.lines().enumerate() {
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") {
                    continue;
                }
                if trimmed.starts_with("/*") {
                    in_block_comment = true;
                }
                if in_block_comment {
                    if trimmed.contains("*/") {
                        in_block_comment = false;
                    }
                    continue;
                }
                if line.contains(needle) {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `println!(\"🚀 {{}} {{}} {{}}\")` release-workflow \
             intro-banner literal(s) survive on a consumer site — route \
             each through `crate::release_workflow_intro_banner::\
             print_release_workflow_intro_banner(service, label, detail, \
             width)` instead:\n{offenders:#?}"
        );
    }

    /// Post-lift shield (positive half): each of the two pre-lift
    /// modules that housed the composition MUST forward through
    /// [`print_release_workflow_intro_banner`] at least the number
    /// of times matching its pre-lift site count. A migration that
    /// dropped a call site outright leaves the negative "no raw
    /// inline shape" scan trivially satisfied by absence but the
    /// positive count still fails here.
    #[test]
    fn every_prelift_module_forwards_through_release_workflow_intro_banner() {
        use std::path::PathBuf;
        let src_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let expectations: &[(&[&str], usize)] = &[
            (&["commands", "rust_service.rs"], 3),
            (&["commands", "developer_tools.rs"], 1),
        ];
        let needle = "print_release_workflow_intro_banner(";
        for (segments, min_count) in expectations {
            let mut path = src_dir.clone();
            for s in *segments {
                path.push(s);
            }
            let source = std::fs::read_to_string(&path)
                .unwrap_or_else(|_| panic!("expected {} to exist", path.display()));
            let forwards = source.matches(needle).count();
            assert!(
                forwards >= *min_count,
                "{} must forward at least {min_count} release-workflow \
                 intro-banner composition(s) through `{needle}`; found \
                 {forwards}. A dropped call would leave the negative \
                 raw-shape scan satisfied by absence.",
                path.display(),
            );
        }
    }
}
