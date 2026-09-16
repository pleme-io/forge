//! Stage-completion acknowledgement primitive — the two-line
//! `println!(); println!("✅ {}", <MSG>.green().bold())` stanza the
//! two `commands/rust_service.rs` top-level workflow entry points
//! emit at their terminal success arms.
//!
//! # Duplication being lifted
//!
//! Two pre-lift sibling sites in `cli/src/commands/rust_service.rs`
//! each restated
//!
//! ```ignore
//! println!();
//! println!("✅ {}", "<LITERAL>".green().bold());
//! ```
//!
//! byte-for-byte — the same framing blank, the same `✅ ` glyph OUTSIDE
//! the coloring span, the same message-only `.green().bold()` palette
//! wrapped around the parameter, and the same trailing newline:
//!
//! - `build_rust_service` at :666-667 (`"Build complete!"`), the
//!   terminator after the Attic-push completion note and before the
//!   `AMD64: result-amd64` / `ARM64: result-arm64` / cache-hit tail.
//! - `deploy_rust_service_gitops` at :2020-2021
//!   (`"GitOps deployment triggered!"`), the terminator after the
//!   `print_step_success("Manifest updated and pushed")` +
//!   optional `print_step_info(watch-hint)` prelude and immediately
//!   before the `Ok(tag_suffix)` return.
//!
//! Both sites were **deliberately excluded** from the earlier
//! [`crate::ui::print_step_success`] lift — see the docstring at
//! `cli/src/ui.rs::write_step_success_emits_exactly_one_check_prefixed_green_line`
//! (post-lift shield, ~line 9047), which notes the two straggler
//! `.green().bold()` sites carry a heavier milestone-level grammar
//! deliberately excluded from `print_step_success`'s sibling class.
//! This module closes that carve-out: the message-only `.green().bold()`
//! grammar with `✅ ` OUTSIDE the coloring span (distinct from every
//! peer in the `ui::print_*success*` family — see the palette-family
//! comparison below) now has ONE typed body and ONE writer sibling.
//!
//! # Distinct from every peer in the `✅ <MSG>` family
//!
//! The forge fleet already carries four `✅ <MSG>` grammar rungs; this
//! primitive is the fifth. The distinctions are ANSI byte-level, not
//! merely semantic:
//!
//! - [`crate::ui::print_success`] — MILESTONE banner
//!   (`commands/{bootstrap,build,push}.rs`), palette
//!   `format!("✅ {}", msg).bright_green().bold()`, bytes
//!   `\x1b[92m\x1b[1m✅ <MSG>\x1b[0m\n` — checkmark INSIDE the
//!   `\x1b[92m` bright_green coloring span.
//! - [`crate::ui::print_phase_success`] — phase-completion grammar
//!   (`commands/{sync,prerelease,post_deploy_verification}.rs`),
//!   palette `format!("✅ {}", msg).green().bold()`, bytes
//!   `\x1b[1;32m✅ <MSG>\x1b[0m\n` — checkmark INSIDE the
//!   `\x1b[32m` green coloring span.
//! - **THIS primitive** — stage-completion ack
//!   (`commands/rust_service.rs`), palette
//!   `"✅ {}" with message.green().bold()`, bytes
//!   `✅ \x1b[1;32m<MSG>\x1b[0m\n` — checkmark OUTSIDE the coloring
//!   span, only the message body inside; AND framed by a leading
//!   `\n` blank the peer primitives do NOT emit.
//! - [`crate::ui::print_step_success`] — in-body step-completion,
//!   palette `"✅ {}" with message.green()`, bytes
//!   `✅ \x1b[32m<MSG>\x1b[0m\n` — same checkmark-outside split as
//!   this primitive, but NO `.bold()` (`\x1b[1m`), and NO leading
//!   framing blank.
//! - [`crate::ui::print_success_line`] — plain acknowledgement,
//!   palette none, bytes `✅ <MSG>\n` — zero ANSI escape sequences.
//!
//! Folding this primitive into any peer would collapse the visual
//! grammar the operator has been trained to read at the two
//! rust_service entry points: a milestone-banner promotion
//! (`.bright_green()` on the checkmark) would confuse the terminator
//! with the top-of-command banners in `commands/{bootstrap,build,push}.rs`;
//! a demotion to `print_step_success` (dropping `.bold()`) would
//! flatten the terminator into the mid-body step-completion noise
//! floor; a fusion with `print_phase_success` (moving the checkmark
//! inside the coloring span) would silently shift 4 bytes of every
//! terminator's ANSI envelope and drift the render at the two only
//! consumers this grammar has.
//!
//! # Composition
//!
//! [`print_stage_completion_ack`] emits the two-line stanza
//! (framing blank + `✅ <MSG>` line) against [`std::io::stdout()`];
//! [`write_stage_completion_ack`] is the writer-taking sibling that
//! pins the exact emitted bytes for the fail-before-pass tests.
//! Both sites in `commands/rust_service.rs` forward through
//! [`print_stage_completion_ack`] with only the message body varying.

use std::io;

use colored::Colorize;

/// Print the two-line stage-completion acknowledgement stanza — a
/// framing blank followed by `✅ <MSG>` with `.green().bold()`
/// coloring on the message body — to [`std::io::stdout()`].
///
/// The two consumer sites in `cli/src/commands/rust_service.rs` (the
/// `build_rust_service` terminator and the `deploy_rust_service_gitops`
/// terminator) each spelled this stanza inline pre-lift; post-lift
/// they both forward through this function.
///
/// Delegates to [`write_stage_completion_ack`] against a locked
/// stdout handle; the writer split exists so the fail-before-pass
/// tests can pin the emitted bytes without capturing stdout.
pub fn print_stage_completion_ack(message: &str) {
    let _ = write_stage_completion_ack(&mut std::io::stdout().lock(), message);
}

/// Writer-taking sibling of [`print_stage_completion_ack`]. Emits the
/// TWO-LINE stage-completion stanza — a framing blank line, then
/// `✅ <message>` with the message body colored `.green().bold()`
/// (checkmark OUTSIDE the coloring span) — via [`writeln!`] against
/// the supplied writer.
///
/// # Byte contract
///
/// The rendered byte sequence is:
///
/// - `\n` (the framing blank line, from the first `writeln!` with no
///   arguments).
/// - `✅ ` — the 3-byte U+2705 WHITE HEAVY CHECK MARK glyph
///   (`E2 9C 85`, no variation selector) followed by one ASCII space
///   (`0x20`), both OUTSIDE the coloring span so a non-color terminal
///   still renders the anchor.
/// - `\x1b[1;32m` (or the semicolon-swapped `\x1b[32;1m` — [`colored`]
///   `2.1` emits one of the two compound orderings) opening the
///   `.green().bold()` ANSI span.
/// - The `message` body verbatim.
/// - `\x1b[0m\n` closing the ANSI span and terminating the line.
///
/// Two pre-lift call sites in `cli/src/commands/rust_service.rs` each
/// spelled `println!(); println!("✅ {}", "<LITERAL>".green().bold());`
/// verbatim; this writer emits the byte-identical output the pre-lift
/// stanzas would have produced.
pub fn write_stage_completion_ack<W: io::Write>(w: &mut W, message: &str) -> io::Result<()> {
    writeln!(w)?;
    writeln!(w, "\u{2705} {}", message.green().bold())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Serialize the `.green().bold()` writer-level tests against the
    /// process-global [`colored::control::set_override`] toggle a
    /// peer test in `crate::ui` also acquires — a fair copy of the
    /// `AnsiOverrideForTest` guard in `cli/src/ui.rs`. Cargo runs
    /// tests in parallel by default, so without a mutex two tests
    /// racing the override toggle would flap between the "ANSI on"
    /// and "ANSI off" arms.
    static ANSI_OVERRIDE_LOCK: Mutex<()> = Mutex::new(());

    /// RAII guard that force-enables [`colored`] ANSI emission for the
    /// duration of a writer-level byte-oracle test. Drop restores
    /// [`colored`]'s auto-detection AFTER releasing the shared lock,
    /// so a peer test waiting on the mutex cannot observe the
    /// override-forced-on window between this writer finishing and
    /// the unset firing.
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

    /// Byte-oracle: the writer emits exactly TWO lines — the leading
    /// framing blank and the `✅ <MSG>` completion line. A refactor
    /// that dropped the framing blank (a "leaner terminator"
    /// cleanup), doubled it (a "match the phase-heading two-blank
    /// preamble" cleanup), or split the writer's `writeln!(w)` +
    /// `writeln!(w, "✅ {}", ...)` composition would flip this
    /// assertion.
    #[test]
    fn write_stage_completion_ack_emits_two_lines() {
        let _override_guard = AnsiOverrideForTest::acquire();
        let mut buf: Vec<u8> = Vec::new();
        write_stage_completion_ack(&mut buf, "Build complete!").unwrap();
        let out = String::from_utf8(buf).expect("writer emits valid UTF-8");
        // `str::lines` collapses the trailing newline, so a two-line
        // stanza (blank + content) reports `["", "✅ ..."]` — 2 lines.
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(
            lines.len(),
            2,
            "write_stage_completion_ack must emit exactly two lines \
             (framing blank + completion line); got {}:\n{:?}",
            lines.len(),
            out
        );
        assert!(
            lines[0].is_empty(),
            "line 0 must be an empty framing blank; got {:?}",
            lines[0]
        );
    }

    /// Byte-oracle: the completion line opens with the literal `✅ `
    /// glyph + space OUTSIDE any coloring span. A fusion that hoisted
    /// the checkmark inside `.green().bold()` (matching
    /// `print_phase_success`) would place `\x1b[` at the start of the
    /// visible line and fail here.
    #[test]
    fn write_stage_completion_ack_checkmark_is_outside_ansi_span() {
        let _override_guard = AnsiOverrideForTest::acquire();
        let mut buf: Vec<u8> = Vec::new();
        write_stage_completion_ack(&mut buf, "Build complete!").unwrap();
        let out = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert!(
            lines[1].starts_with("\u{2705} "),
            "line 1 must begin with the literal `✅ ` prefix — every \
             pre-lift consumer spelled it OUTSIDE the coloring span; \
             got {:?}",
            lines[1]
        );
        // The `\x1b` escape byte MUST NOT appear before the space at
        // byte-index 3 (the 3-byte glyph + space prefix). If it did,
        // the checkmark would be inside the coloring span.
        let bytes = lines[1].as_bytes();
        assert!(
            bytes.len() >= 4,
            "line 1 must carry at least the 3-byte glyph + space; got {} bytes",
            bytes.len()
        );
        assert_eq!(
            &bytes[..4],
            b"\xe2\x9c\x85 ",
            "line 1 bytes 0..4 must be U+2705 WHITE HEAVY CHECK MARK \
             (E2 9C 85, no variation selector) + ASCII space (0x20); \
             got {:?}",
            &bytes[..4]
        );
    }

    /// Byte-oracle: the compound `.green().bold()` ANSI sequence
    /// wraps the message body. `colored` `2.1` emits one of two
    /// semicolon orderings for the compound (`\x1b[1;32m` or
    /// `\x1b[32;1m`); accept either. A demotion that dropped
    /// `.bold()` (regressing to `print_step_success`'s plain
    /// `.green()`) would leave only `\x1b[32m` — that flatter form
    /// fails BOTH accepted patterns.
    #[test]
    fn write_stage_completion_ack_carries_green_bold_compound_ansi() {
        let _override_guard = AnsiOverrideForTest::acquire();
        let mut buf: Vec<u8> = Vec::new();
        write_stage_completion_ack(&mut buf, "Build complete!").unwrap();
        let out = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert!(
            lines[1].contains("\x1b[1;32m") || lines[1].contains("\x1b[32;1m"),
            "line 1 must carry the compound `.green().bold()` ANSI \
             sequence (`\\x1b[1;32m` or `\\x1b[32;1m`) — a demotion to \
             plain `.green()` (matching the lighter \
             `print_step_success`) fails here; got {:?}",
            lines[1]
        );
        assert!(
            !lines[1].contains("\x1b[92m"),
            "line 1 must NOT carry the `bright_green` ANSI sequence \
             (`\\x1b[92m`) — that palette belongs to the milestone-level \
             `print_success` in `commands/{{bootstrap,build,push}}.rs`, \
             not this stage-completion primitive; got {:?}",
            lines[1]
        );
    }

    /// Byte-oracle: the message body reaches the writer verbatim
    /// between the compound ANSI opener and the ANSI reset. A fusion
    /// that pinned the message to a module-local constant would fail
    /// here — the two pre-lift consumers pass distinct literals
    /// (`"Build complete!"` vs. `"GitOps deployment triggered!"`)
    /// and the primitive must remain parameter-driven.
    #[test]
    fn write_stage_completion_ack_carries_message_verbatim() {
        let _override_guard = AnsiOverrideForTest::acquire();
        for msg in ["Build complete!", "GitOps deployment triggered!"] {
            let mut buf: Vec<u8> = Vec::new();
            write_stage_completion_ack(&mut buf, msg).unwrap();
            let out = String::from_utf8(buf).unwrap();
            assert!(
                out.contains(msg),
                "writer output must carry the message verbatim for \
                 {msg:?}; got {out:?}"
            );
            // Reset closes the coloring span AFTER the message.
            assert!(
                out.contains("\x1b[0m"),
                "writer output must carry the `\\x1b[0m` reset \
                 closing the coloring span; got {out:?}"
            );
        }
    }

    /// Post-lift shield: no source line under
    /// `cli/src/commands/rust_service.rs` may still spell the pre-lift
    /// `println!("✅ {}", "<LITERAL>".green().bold());` shape inline.
    /// Every consumer reaches for [`print_stage_completion_ack`] on
    /// first grep, not by copy-pasting the raw stanza. The pre-lift
    /// needle `println!("✅ {}", "` co-occurring with `".green().bold());`
    /// on the SAME line uniquely identifies the pre-lift restatement.
    /// Scoped to the module body BEFORE the first `#[cfg(test)]`
    /// region so a test-support mention of the raw shape does not
    /// defeat the shield.
    #[test]
    fn rust_service_no_longer_spells_raw_stage_completion_stanza() {
        const SOURCE: &str = include_str!("commands/rust_service.rs");
        let body = crate::test_support::module_body_before_first_cfg_test(
            SOURCE,
            "commands/rust_service.rs",
        );
        let mut offenders: Vec<(usize, String)> = Vec::new();
        for (idx, line) in body.lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") || trimmed.starts_with("///") {
                continue;
            }
            if line.contains("println!(\"\u{2705} {}\", \"") && line.contains("\".green().bold());")
            {
                offenders.push((idx + 1, line.to_string()));
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `println!(\"\u{2705} {{}}\", \"<LITERAL>\".green().bold());` \
             stanza(s) survive in commands/rust_service.rs — route each \
             through `crate::stage_completion_ack::print_stage_completion_ack(\
             \"<LITERAL>\")` instead (the leading `println!();` framing \
             blank is folded INTO the primitive):\n{:#?}",
            offenders
        );
    }

    /// Positive half of the shield: `commands/rust_service.rs` MUST
    /// forward through [`print_stage_completion_ack`] at least the
    /// migrated count (2). A migration that dropped a call site
    /// outright would leave the negative "no raw inline shape"
    /// shield trivially satisfied by absence but the positive count
    /// fails.
    #[test]
    fn rust_service_forwards_both_stage_completion_stanzas() {
        const SOURCE: &str = include_str!("commands/rust_service.rs");
        let forwards = SOURCE
            .matches("crate::stage_completion_ack::print_stage_completion_ack(")
            .count();
        assert!(
            forwards >= 2,
            "commands/rust_service.rs must forward at least 2 \
             stage-completion stanzas through \
             `crate::stage_completion_ack::print_stage_completion_ack(`; \
             found {forwards}. A dropped call would leave the \
             negative raw-shape scan satisfied by absence."
        );
    }
}
