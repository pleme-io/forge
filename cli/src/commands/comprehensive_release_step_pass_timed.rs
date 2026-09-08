//! Comprehensive-release step-pass-with-elapsed banner primitive.
//!
//! Five sibling step-completion stanzas across the
//! `commands/comprehensive_release.rs` orchestrator each restated the
//! same three-line stanza verbatim — a
//! `info!("{}", crate::repo::msg_took_secs_1("✅ <MESSAGE>"
//! .green().bold(), step_duration,))` tracing emission followed
//! immediately by a `println!()` blank line — differing only in the
//! per-step message body:
//!
//! - `:350` — `"✅ Unit tests passed"`
//! - `:382` — `"✅ Docker image built successfully"`
//! - `:707` — `"✅ Integration tests passed"`
//! - `:750` — `"✅ Image pushed successfully"`
//! - `:790` — `"✅ Deployment complete"`
//!
//! Each site is the terminal announcement at the exit of one of the
//! five release-pipeline STEP branches (Unit-Tests, Build-Docker,
//! Integration-Tests, Push-Image, Deploy-to-Kubernetes) in
//! [`crate::commands::comprehensive_release::execute`]; the operator's
//! eye lands on the green-bold `✅ <MESSAGE>` line with the
//! parenthesized `(took N.Ns)` elapsed-time tail before the pipeline
//! advances to the next step's header banner.
//!
//! # What this primitive owns
//!
//! Post-lift the [`info_step_pass_timed`] function owns:
//!
//! 1. The `✅ ` glyph choice (U+2705 checkmark + one ASCII space) —
//!    a future palette adjustment (a swap for a stronger `☑` /
//!    `✔` variant, a promotion to a per-step glyph anchor `🧪 / 📦 /
//!    🔬 / ⬆ / 🚀`, or dropping the glyph entirely under a
//!    `--no-emoji` flag) reaches ONE body rather than 5 sites.
//! 2. The `.green().bold()` ANSI palette on the composed
//!    `"✅ <MESSAGE>"` message — a future refinement (a promotion
//!    to `.bright_green().bold()` under CI-log-highlight pressure,
//!    dropping `.bold()` off the message under a leaner readout, a
//!    swap of the whole-message coloring for a glyph-only
//!    `.green()` under the sibling `print_step_pass_timed` dialect)
//!    reaches ONE body.
//! 3. The forwarding through [`crate::repo::msg_took_secs_1`] for
//!    the elapsed-time tail — the primitive body is the ONE call
//!    site the closed-site shield
//!    [`crate::repo::tests::msg_took_secs_1_closed_sites_do_not_reinline_the_primitive_shape`]
//!    now anchors on. A precision drift (`{:.0}` / `{:.2}`), a
//!    unit swap (`s` → `ms`), or a surround-grammar drift
//!    (` (took N.Ns)` → ` (N.Ns)`) still fails the pre-existing
//!    shield on [`crate::repo::msg_took_secs_1`] itself.
//! 4. The [`tracing::info!`] routing so the record flows through
//!    the fleet-standard tracing subscriber (`main.rs`'s
//!    `fmt().with_env_filter(...).init()`) with the caller's
//!    [`tracing::Level::INFO`] level, ensuring a future
//!    `--json` / OTLP subscriber captures the step-completion as a
//!    structured event.
//! 5. The trailing `println!()` blank line that separates the
//!    step-completion announcement from the next step's opening
//!    header — a load-bearing visual anchor the release pipeline's
//!    step-by-step readout depends on.
//!
//! # Distinct from [`crate::ui::print_step_pass_timed`]
//!
//! [`crate::ui::print_step_pass_timed`] renders a DIFFERENT byte-form
//! — a `println!` (not `tracing::info!`) of
//! `   <green ✅><space><message> ({:.1}s)` with a three-space indent,
//! the `.green()` palette on the glyph ALONE (not the whole message),
//! and the sibling [`crate::repo::msg_with_secs_1`] tail grammar
//! (` (N.Ns)`, NO `took` verb). The 6 pre-lift consumer sites for
//! that sibling live in
//! `commands/{frontend_validation,prerelease}.rs` — a distinct
//! step-completion visual dialect for pre-release-gate step
//! announcements (contrast: the comprehensive-release orchestrator
//! carries the WHOLE-LINE `.green().bold()` palette to give each of
//! its 5 top-level release phases a heavier visual weight, and uses
//! the `(took N.Ns)` verb-carrying tail so the elapsed time reads
//! as a completion narration, not a bare timer).
//!
//! # Compounding
//!
//! Pre-lift 5 sibling sites each restated the composition of the `✅
//! ` glyph, the whole-line `.green().bold()` palette, the
//! `msg_took_secs_1` tail composition, the `tracing::info!` routing,
//! and the trailing `println!()` blank line — a future refinement to
//! any one axis had to hit all 5 sites in lockstep or drift the
//! release-pipeline's step-completion visual grammar. Post-lift it
//! hits ONE typed body. The `duration: Duration` typed argument
//! stays a STRUCTURED value at the primitive boundary — a future
//! OTLP `release_step_completed` observability event lands on the
//! primitive with the message and duration as SEPARATE structured
//! attributes rather than a pre-composed string.

use std::io;
use std::time::Duration;

use colored::Colorize;

/// The `✅ ` glyph + one-space separator that opens every
/// comprehensive-release step-pass-with-elapsed banner. Named as a
/// module-scope [`&str`] so the writer body, the tracing macro
/// expansion, and the byte-oracle test all agree on the exact opener
/// bytes — a future one-place edit to the glyph flows through by
/// construction.
const CHECK_GLYPH_WITH_SPACE: &str = "\u{2705} ";

/// Compose the byte-level message body that the pre-lift 5 sibling
/// sites hand-composed at each of their `crate::repo::msg_took_secs_1(
/// "✅ <MESSAGE>".green().bold(), step_duration,)` calls: prefix the
/// caller-supplied `message` with the `✅ ` glyph opener, wrap the
/// composed string in `.green().bold()` ANSI, and suffix the
/// fleet-standard ` (took N.Ns)` elapsed-time tail via
/// [`crate::repo::msg_took_secs_1`].
///
/// The elapsed-tail composition is delegated to
/// [`crate::repo::msg_took_secs_1`] rather than re-inlined here — the
/// precision, surround-grammar, and unit-suffix invariants that
/// primitive pins at ONE body ([`crate::repo::msg_took_secs_1`]'s
/// three grammar invariants doc block) reach this consumer through
/// the delegation.
fn format_step_pass_timed(message: &str, duration: Duration) -> String {
    let composed = format!("{}{}", CHECK_GLYPH_WITH_SPACE, message);
    crate::repo::msg_took_secs_1(composed.green().bold(), duration)
}

/// Writer-taking byte-oracle sibling to [`info_step_pass_timed`]. Emits
/// the two-line body (green-bold `✅ <message> (took N.Ns)` line, then
/// blank line) via [`writeln!`] against the supplied writer.
///
/// [`info_step_pass_timed`] is the [`tracing::info!`]-routed adapter
/// production code invokes; this direct-writer variant exists so the
/// fail-before-pass tests can pin the exact emitted bytes (the `✅ `
/// glyph opener, the `.green().bold()` ANSI palette when [`colored`]
/// is enabled, the ` (took N.Ns)` elapsed-time tail, the trailing
/// newline, and the trailing blank line) without capturing a tracing
/// subscriber and without racing an ambient logger — the same split
/// [`crate::commands::test_suite_failure_banner::write_suite_failure_banner`]
/// carries against
/// [`crate::commands::test_suite_failure_banner::print_suite_failure_banner`]
/// and [`crate::advisory_warning::write_advisory_warning`] carries
/// against [`crate::warn_advisory!`]. The writer is therefore the
/// byte-format oracle for the tests AND the natural next-lift
/// consumer (a `collect_release_step_completions()` summary sibling
/// producing a release-completion report panel) rather than the
/// production emission path.
#[allow(dead_code)] // See doc comment: the writer is a test/byte-oracle
                    // peer of the tracing-routed `info_step_pass_timed`
                    // function, and the future
                    // `collect_release_step_completions` sibling will
                    // consume it directly.
pub fn write_step_pass_timed<W: io::Write>(
    w: &mut W,
    message: &str,
    duration: Duration,
) -> io::Result<()> {
    writeln!(w, "{}", format_step_pass_timed(message, duration))?;
    writeln!(w)
}

/// Emit a comprehensive-release step-completion announcement via
/// [`tracing::info!`] on the fleet-standard whole-message
/// `.green().bold()` `✅ <message>` grammar with a
/// [`crate::repo::msg_took_secs_1`]-composed ` (took N.Ns)` elapsed-
/// time tail, then emit a `println!()` blank line to separate the
/// announcement from the following step's opening header.
///
/// The pre-lift 5 sibling sites hand-composed this stanza inline; see
/// the [module docs](self) for the site census, the split against
/// [`crate::ui::print_step_pass_timed`], and the compounding
/// rationale for centralising the glyph / palette / tail /
/// tracing-routing / trailing-blank decisions at one body.
///
/// # Examples
///
/// ```ignore
/// // Pre-lift:
/// info!(
///     "{}",
///     crate::repo::msg_took_secs_1("✅ Unit tests passed".green().bold(), step_duration,)
/// );
/// println!();
///
/// // Post-lift:
/// crate::commands::comprehensive_release_step_pass_timed::info_step_pass_timed(
///     "Unit tests passed",
///     step_duration,
/// );
/// ```
pub fn info_step_pass_timed(message: &str, duration: Duration) {
    tracing::info!("{}", format_step_pass_timed(message, duration));
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Strip CSI `ESC [ … <letter>` sequences from `s`. The
    /// byte-oracle asserts against the plain-form output the
    /// operator reads regardless of whether [`colored`] emits ANSI
    /// escapes on this test binary's stdout (which depends on
    /// whether stdout is a TTY — cargo test's default parallel
    /// runner can be either). The `.green().bold()` coloring
    /// contract on the composed message is pinned separately by
    /// [`primitive_body_carries_green_bold_on_composed_message`].
    fn strip_ansi(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        let mut chars = s.chars();
        while let Some(c) = chars.next() {
            if c == '\x1b' {
                if chars.next() != Some('[') {
                    continue;
                }
                for nc in chars.by_ref() {
                    if nc.is_ascii_alphabetic() {
                        break;
                    }
                }
                continue;
            }
            out.push(c);
        }
        out
    }

    /// Pin the two-line body for the `"Unit tests passed"` pre-lift
    /// site under a 1.234s [`Duration`]: green-bold `✅ Unit tests
    /// passed (took 1.2s)` line terminated by `\n`, then a blank
    /// line. A future refactor that dropped the trailing blank
    /// line, swapped the `✅` glyph, promoted the seconds precision
    /// to `{:.2}`, or dropped the `took` verb from the tail
    /// regresses this assertion.
    #[test]
    fn write_step_pass_timed_pins_two_line_body_for_unit_tests_passed_site() {
        let mut buf: Vec<u8> = Vec::new();
        write_step_pass_timed(&mut buf, "Unit tests passed", Duration::from_millis(1234)).unwrap();
        let out = String::from_utf8(buf).unwrap();
        let plain = strip_ansi(&out);
        assert_eq!(plain, "\u{2705} Unit tests passed (took 1.2s)\n\n");
    }

    /// Pin the two-line body for the `"Deployment complete"`
    /// pre-lift site under a 5.0s [`Duration`], differing from the
    /// sibling `Unit tests passed` assertion only in the caller
    /// message and duration — the invariant the primitive owns is
    /// the surrounding grammar (glyph, palette, tail, trailing
    /// blank) not the per-caller message.
    #[test]
    fn write_step_pass_timed_pins_two_line_body_for_deployment_complete_site() {
        let mut buf: Vec<u8> = Vec::new();
        write_step_pass_timed(&mut buf, "Deployment complete", Duration::from_secs(5)).unwrap();
        let out = String::from_utf8(buf).unwrap();
        let plain = strip_ansi(&out);
        assert_eq!(plain, "\u{2705} Deployment complete (took 5.0s)\n\n");
    }

    /// Pin the trailing blank line as a SEPARATE `writeln!(w)` —
    /// the pre-lift 5 sibling sites each emitted a `println!()`
    /// after the `info!` call, and dropping that line silently
    /// collapses the visual separation between step-completion
    /// and next-step-header the operator's eye is trained on.
    #[test]
    fn write_step_pass_timed_emits_trailing_blank_line() {
        let mut buf: Vec<u8> = Vec::new();
        write_step_pass_timed(&mut buf, "Anything", Duration::from_secs(1)).unwrap();
        let plain = strip_ansi(&String::from_utf8(buf).unwrap());
        assert!(
            plain.ends_with("\n\n"),
            "render must end with exactly two newlines (the message-line \
             terminator + the trailing blank) — got {:?}",
            plain,
        );
    }

    /// Guard against the sibling [`crate::ui::write_step_pass_timed`]
    /// grammar: the sibling `ui::print_step_pass_timed` uses a
    /// three-space indent, a glyph-only `.green()` palette (not
    /// whole-message), and the ` (N.Ns)` tail (NO `took` verb).
    /// This primitive uses NO leading indent, WHOLE-MESSAGE
    /// `.green().bold()`, and the ` (took N.Ns)` tail. Explicit
    /// negative shape guard so a future contributor who reaches for
    /// the sibling grammar hits this test.
    #[test]
    fn write_step_pass_timed_does_not_use_ui_sibling_grammar() {
        let mut buf: Vec<u8> = Vec::new();
        write_step_pass_timed(&mut buf, "Anything", Duration::from_millis(500)).unwrap();
        let plain = strip_ansi(&String::from_utf8(buf).unwrap());
        assert!(
            !plain.starts_with("   \u{2705}"),
            "render must NOT open with the sibling ui::print_step_pass_timed \
             three-space indent + glyph opener; got {:?}",
            plain,
        );
        assert!(
            plain.contains("(took "),
            "render must carry the `took` verb in the elapsed-time tail — a \
             collapse to the sibling ui::print_step_pass_timed's ` (N.Ns)` \
             grammar loses the release-narration verb; got {:?}",
            plain,
        );
    }

    /// Structural coloring shield: the primitive body must chain
    /// `.green().bold()` on the composed `"✅ <MESSAGE>"` string.
    /// Pins the coloring contract that the byte-oracle above
    /// deliberately ignores (colored auto-drops ANSI on non-TTY
    /// writers, so a plain-bytes assertion cannot distinguish
    /// plain from colored on a stdout-Vec-piped `cargo test` run).
    /// A "just print the message plain, colored is noisy in CI"
    /// cleanup that dropped `.green().bold()` off the composed
    /// message regresses this assertion before the release-phase-
    /// completion semantic vanishes from the terminal.
    #[test]
    fn primitive_body_carries_green_bold_on_composed_message() {
        let source = include_str!("comprehensive_release_step_pass_timed.rs");
        let body = crate::test_support::module_body_before_first_cfg_test(
            source,
            "comprehensive_release_step_pass_timed.rs",
        );
        assert!(
            body.contains(".green().bold()"),
            "primitive body must chain `.green().bold()` on the composed \
             `✅ <MESSAGE>` string — a \"just print plain, colored is noisy \
             in CI\" cleanup that dropped `.green().bold()` here regresses \
             the release-phase-completion semantic every pre-lift site \
             carried.",
        );
        assert!(
            body.contains("msg_took_secs_1"),
            "primitive body must delegate the elapsed-time tail composition \
             through `crate::repo::msg_took_secs_1` — a re-inline of the \
             `(took {{:.1}}s)` format-string tag at this site would drift \
             the primitive's ownership of the tail grammar off the closed \
             single-body discipline.",
        );
        assert!(
            body.contains("\u{2705}"),
            "primitive body must carry the `✅` (U+2705) glyph — a silent \
             swap for a sibling checkmark variant (`✔` / `☑`) regresses \
             the visual alignment against the sibling `success_step` / \
             `print_bright_step_pass` primitives.",
        );
    }

    /// Caller shield: no source line in `commands/comprehensive_release.rs`
    /// may spell the pre-lift `msg_took_secs_1(...".green().bold(),
    /// step_duration,)` composition inline any more. Every one of the 5
    /// pre-lift release-step-completion announcements must resolve
    /// through [`info_step_pass_timed`] so a future palette adjustment
    /// on the glyph, the coloring, the tail grammar, or the trailing
    /// blank line flows to all 5 sites from one edit.
    ///
    /// The needle scans `commands/comprehensive_release.rs` specifically
    /// — the ONE pre-lift consumer file — for any line spelling the
    /// combined `msg_took_secs_1(` opener with a `.green().bold()`
    /// palette application, which uniquely identifies the pre-lift
    /// release-step-completion composition. Sibling `.green().bold()`
    /// sites in other `commands/*.rs` modules (e.g.
    /// `commands/{prerelease,post_deploy_verification,rust_service}.rs`)
    /// carry DIFFERENT pre-lift shapes (`println!` rather than
    /// `info!`, no `msg_took_secs_1` tail, or a `{}` interpolation
    /// slot rather than an inline concatenation) and are deliberately
    /// out of scope here.
    #[test]
    fn no_command_module_still_spells_raw_release_step_pass_stanza() {
        use std::path::PathBuf;
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands")
            .join("comprehensive_release.rs");
        let source = std::fs::read_to_string(&path).unwrap();
        let mut window: Vec<String> = Vec::new();
        let hits: Vec<String> = source
            .lines()
            .enumerate()
            .filter_map(|(i, line)| {
                window.push(line.to_string());
                if window.len() > 6 {
                    window.remove(0);
                }
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") {
                    return None;
                }
                // Anchor on the load-bearing combined shape: an
                // `.green().bold()` palette application landing inside
                // a `msg_took_secs_1(` call. Both markers must live
                // within the recent line window so a rustfmt-split
                // spanning up to 6 physical lines still trips.
                let combined = window.join("\n");
                if combined.contains("msg_took_secs_1(") && combined.contains(".green().bold()") {
                    Some(format!("line {}: {}", i + 1, line.trim()))
                } else {
                    None
                }
            })
            .collect();
        assert!(
            hits.is_empty(),
            "pre-lift `msg_took_secs_1(<msg>.green().bold(), <duration>,)` \
             release-step-completion composition(s) survive in \
             `commands/comprehensive_release.rs` — route each through \
             `crate::commands::comprehensive_release_step_pass_timed::\
             info_step_pass_timed(<message>, <duration>)` instead:\n{:#?}",
            hits,
        );
    }

    /// Positive-delegation shield: `commands/comprehensive_release.rs`
    /// must resolve at least FIVE step-completion announcements
    /// through [`info_step_pass_timed`] — the pre-lift count of 5
    /// sibling sites. Pairs with the negative caller shield above:
    /// the negative shield forbids the raw
    /// `"✅ <MSG>".green().bold()` stanza from surviving, and this
    /// shield forbids a "just delete a couple of banners, the flow
    /// is obvious" cleanup that quietly drops the operator's visual
    /// anchor on any of the 5 top-level release phases without
    /// regressing the negative-shield assertion.
    #[test]
    fn comprehensive_release_module_delegates_through_primitive_at_least_five_times() {
        use std::path::PathBuf;
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands")
            .join("comprehensive_release.rs");
        let source = std::fs::read_to_string(&path).unwrap();
        let forwards = source.matches("info_step_pass_timed(").count();
        assert!(
            forwards >= 5,
            "pre-lift 5 sibling release-step-completion sites in \
             `commands/comprehensive_release.rs` must each resolve through \
             `comprehensive_release_step_pass_timed::info_step_pass_timed(...)`; \
             found only {} forwarding call(s). A cleanup that dropped any of \
             the 5 top-level release-phase completion announcements regresses \
             the operator's visual anchor without tripping the negative caller \
             shield.",
            forwards,
        );
    }
}
