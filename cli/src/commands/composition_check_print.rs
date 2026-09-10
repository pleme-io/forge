//! Typed per-check printer for the two supergraph-composition
//! validation loops.
//!
//! Two sibling for-check-in-checks stanzas across
//! `commands/federation.rs::update_federation` — the pre-composition
//! loop (`:152–:158`) and the post-composition loop (`:260–:268`) — each
//! restated the same ternary-per-check-result print grammar verbatim:
//!
//! ```ignore
//! // pre-composition (2-branch)
//! for check in &pre_check.checks {
//!     if check.passed {
//!         println!("   {}", check.message.green());
//!     } else {
//!         eprintln!("   {}", check.message.red());
//!     }
//! }
//!
//! // post-composition (3-branch, adds a `Warning`-substring warn arm)
//! for check in &post_check.checks {
//!     if check.passed {
//!         println!("   {}", check.message.green());
//!     } else if check.message.contains("Warning") {
//!         println!("   {}", check.message.yellow());
//!     } else {
//!         eprintln!("   {}", check.message.red());
//!     }
//! }
//! ```
//!
//! The pre-composition loop's 2-branch shape is the subset of the
//! post-composition loop's 3-branch shape where no check message
//! carries the `"Warning"` substring: every pre-composition
//! `CheckResult` message the pre-lift check-builder emits is either
//! `✓`-prefixed (pass) or `✗`-prefixed (fail) — neither carries the
//! `"Warning"` substring — so folding the pre-composition loop through
//! the 3-branch primitive is behavior-preserving at every current
//! caller. A future check-builder that emits a `⚠ Warning`-prefixed
//! `CheckResult` reaches the warn arm identically at both sites,
//! rather than routing to stderr-red on the pre-composition loop and
//! stdout-yellow on the post-composition loop.
//!
//! Pre-lift a future palette adjustment — a swap of `.green()` for
//! `.bright_green()`, dropping `.yellow()` off the warn arm under a
//! leaner two-branch pass/fail dispatch, promoting the fail line's
//! `eprintln!` to `println!` under a "keep failure diagnostics on
//! stdout with the rest of the phase log" cleanup, shifting the
//! three-space indent to four-space under a standardized diagnostic
//! grammar, folding a leading `✓ ` / `⚠ ` / `✗ ` glyph into the
//! primitive (silently doubling any glyph already baked into
//! `check.message`), or an OTLP `composition_check_result_emitted`
//! observability event wired alongside the print — had to hit both
//! sites in lockstep or drift the visual grammar; post-lift it hits
//! ONE typed body.

use std::io::{self, Write};

use colored::Colorize;

use crate::commands::supergraph_verification::CheckResult;

/// Where the printer routes a rendered [`CheckResult`] row. Pass and
/// warn go to process stdout — the operator's normal phase log —
/// while a fail row lands on stderr so a pipeline collecting stderr
/// separately (a CI runner splitting streams into two artifacts, a
/// caller redirecting `2>` into a distinct log) sees the failing
/// checks even when the surrounding phase log is captured elsewhere.
///
/// Kept as a small local enum rather than sharing
/// [`crate::probe_dump::DiagSink`] so this module's routing table is
/// self-contained — a future re-decision on where warn rows land
/// (say, promoting them to a distinct third stream, or downgrading
/// the fail routing back to stdout) reads and edits at this one
/// site.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompositionCheckSink {
    /// Process stdout — the `println!` arm at every pre-lift site.
    Stdout,
    /// Process stderr — the `eprintln!` arm at every pre-lift site.
    Stderr,
}

/// Ternary verdict inferred from a [`CheckResult`]. The pre-lift
/// federation.rs ternary lived inline as an `if / else if / else`;
/// naming its three outcomes at compile time turns a future addition
/// of a fourth outcome (say, `Skipped` under a `check.applicable`
/// axis) into one enum variant plus one match arm rather than a
/// fourth `else if` at every caller site.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompositionCheckVerdict {
    /// `check.passed` is true — the check succeeded. Rendered
    /// `.green()` and routed to stdout at every pre-lift site.
    Pass,
    /// `check.passed` is false AND `check.message` carries the
    /// `"Warning"` substring — the check surfaced advisory content
    /// the caller wants visible without failing the phase.
    /// Rendered `.yellow()` and routed to stdout at every pre-lift
    /// site.
    Warn,
    /// `check.passed` is false AND the message lacks `"Warning"` —
    /// the check hard-failed. Rendered `.red()` and routed to stderr
    /// at every pre-lift site.
    Fail,
}

impl CompositionCheckVerdict {
    /// Route this verdict to stdout ([`CompositionCheckSink::Stdout`])
    /// or stderr ([`CompositionCheckSink::Stderr`]). Pass and warn
    /// land on stdout — the operator's normal phase log; fail lands
    /// on stderr so a pipeline splitting streams sees the failing
    /// checks even when the surrounding phase log is captured
    /// elsewhere. Pre-lift both federation.rs sites baked this
    /// mapping inline as the choice of `println!` vs `eprintln!` on
    /// each arm.
    pub const fn sink(self) -> CompositionCheckSink {
        match self {
            Self::Pass | Self::Warn => CompositionCheckSink::Stdout,
            Self::Fail => CompositionCheckSink::Stderr,
        }
    }
}

/// Classify a [`CheckResult`] into the ternary verdict the pre-lift
/// federation.rs ternary spelled inline. The classifier is total: a
/// [`CheckResult`] with `passed = true` maps to
/// [`CompositionCheckVerdict::Pass`] regardless of message content,
/// so a check-builder that emits `"⚠ Warning: …"` on a passing check
/// still lands on the green arm rather than the yellow arm (matching
/// pre-lift behavior — the post-composition loop's `if check.passed`
/// guard fires before the `else if check.message.contains("Warning")`
/// guard).
pub fn classify_composition_check_verdict(check: &CheckResult) -> CompositionCheckVerdict {
    if check.passed {
        CompositionCheckVerdict::Pass
    } else if check.message.contains("Warning") {
        CompositionCheckVerdict::Warn
    } else {
        CompositionCheckVerdict::Fail
    }
}

/// Emit the one-line `"   {}"` composition-check row to `w`, colored
/// by [`classify_composition_check_verdict`]: green for
/// [`CompositionCheckVerdict::Pass`], yellow for
/// [`CompositionCheckVerdict::Warn`], red for
/// [`CompositionCheckVerdict::Fail`]. The three-space indent is
/// emitted OUTSIDE the coloring span — every pre-lift site spelled
/// `"   {}"` with the color chained on `check.message` alone, so a
/// re-fusion that hoisted the color onto the composed line (painting
/// the indent) would misalign against every peer three-space-indent
/// primitive in the module.
///
/// This writer sibling exists so the byte-oracle tests can pin the
/// per-verdict palette by inspecting emitted bytes against a
/// `Vec<u8>` buffer rather than shelling out and grepping stdout.
/// [`print_composition_check_result`] is the stdout/stderr routing
/// adapter that chooses the right process stream by verdict.
pub fn write_composition_check_line<W: Write>(w: &mut W, check: &CheckResult) -> io::Result<()> {
    match classify_composition_check_verdict(check) {
        CompositionCheckVerdict::Pass => writeln!(w, "   {}", check.message.green()),
        CompositionCheckVerdict::Warn => writeln!(w, "   {}", check.message.yellow()),
        CompositionCheckVerdict::Fail => writeln!(w, "   {}", check.message.red()),
    }
}

/// Print one composition-check row to the process stream chosen by
/// [`CompositionCheckVerdict::sink`]: stdout for pass and warn, stderr
/// for fail. Delegates to [`write_composition_check_line`] against
/// the routed stream; the stdout/stderr split preserves the pre-lift
/// `println!`/`eprintln!` grammar every caller in
/// `commands/federation.rs::update_federation` spelled verbatim.
pub fn print_composition_check_result(check: &CheckResult) {
    let verdict = classify_composition_check_verdict(check);
    match verdict.sink() {
        CompositionCheckSink::Stdout => {
            let _ = write_composition_check_line(&mut io::stdout().lock(), check);
        }
        CompositionCheckSink::Stderr => {
            let _ = write_composition_check_line(&mut io::stderr().lock(), check);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Strip CSI `ESC [ … <letter>` sequences from `s` so the byte-
    /// oracle assertions read the plain-form output regardless of
    /// whether [`colored`] emits ANSI escapes on this test binary's
    /// stdout (which depends on TTY detection — cargo test's default
    /// parallel runner can be either). The palette contract on each
    /// verdict is pinned separately by the module-body structural
    /// shield below.
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

    fn mk_check(name: &str, passed: bool, message: &str) -> CheckResult {
        CheckResult {
            name: name.to_string(),
            passed,
            message: message.to_string(),
        }
    }

    /// Verdict classifier: a `passed = true` check maps to
    /// [`CompositionCheckVerdict::Pass`] regardless of message
    /// content — the `if check.passed` guard fires before the
    /// `else if check.message.contains("Warning")` guard at every
    /// pre-lift caller.
    #[test]
    fn classify_pass_ignores_warning_substring_on_passing_message() {
        let check = mk_check("passing", true, "⚠ Warning: cosmetic only");
        assert_eq!(
            classify_composition_check_verdict(&check),
            CompositionCheckVerdict::Pass,
        );
    }

    /// Verdict classifier: a `passed = false` check whose message
    /// carries the `"Warning"` substring maps to
    /// [`CompositionCheckVerdict::Warn`] — the pre-lift post-
    /// composition loop's `else if check.message.contains("Warning")`
    /// arm.
    #[test]
    fn classify_fail_with_warning_message_maps_to_warn() {
        let check = mk_check("federation", false, "⚠ Warning: No federation directives");
        assert_eq!(
            classify_composition_check_verdict(&check),
            CompositionCheckVerdict::Warn,
        );
    }

    /// Verdict classifier: a `passed = false` check whose message
    /// lacks `"Warning"` maps to [`CompositionCheckVerdict::Fail`] —
    /// the pre-lift `else` arm at every caller.
    #[test]
    fn classify_fail_without_warning_message_maps_to_fail() {
        let check = mk_check("size", false, "✗ Supergraph too small");
        assert_eq!(
            classify_composition_check_verdict(&check),
            CompositionCheckVerdict::Fail,
        );
    }

    /// Sink routing: pass and warn verdicts route to stdout, fail
    /// routes to stderr — the pre-lift `println!` vs `eprintln!`
    /// split every federation.rs caller spelled inline.
    #[test]
    fn verdict_sink_maps_pass_and_warn_to_stdout_fail_to_stderr() {
        assert_eq!(
            CompositionCheckVerdict::Pass.sink(),
            CompositionCheckSink::Stdout,
        );
        assert_eq!(
            CompositionCheckVerdict::Warn.sink(),
            CompositionCheckSink::Stdout,
        );
        assert_eq!(
            CompositionCheckVerdict::Fail.sink(),
            CompositionCheckSink::Stderr,
        );
    }

    /// Byte-oracle: [`write_composition_check_line`] on a passing
    /// check emits exactly one line with the three-space indent and
    /// the verbatim message. Palette assertion (green ANSI) is
    /// pinned by the structural shield below.
    #[test]
    fn write_pass_emits_three_space_indent_then_message() {
        let check = mk_check("dir", true, "✓ Found subgraphs directory");
        let mut buf: Vec<u8> = Vec::new();
        write_composition_check_line(&mut buf, &check).unwrap();
        let out = String::from_utf8(buf).unwrap();
        let plain = strip_ansi(&out);
        assert_eq!(plain, "   ✓ Found subgraphs directory\n");
    }

    /// Byte-oracle: [`write_composition_check_line`] on a warn check
    /// emits exactly one line with the three-space indent and the
    /// verbatim message.
    #[test]
    fn write_warn_emits_three_space_indent_then_message() {
        let check = mk_check("federation", false, "⚠ Warning: No federation directives");
        let mut buf: Vec<u8> = Vec::new();
        write_composition_check_line(&mut buf, &check).unwrap();
        let out = String::from_utf8(buf).unwrap();
        let plain = strip_ansi(&out);
        assert_eq!(plain, "   ⚠ Warning: No federation directives\n");
    }

    /// Byte-oracle: [`write_composition_check_line`] on a fail check
    /// emits exactly one line with the three-space indent and the
    /// verbatim message.
    #[test]
    fn write_fail_emits_three_space_indent_then_message() {
        let check = mk_check("size", false, "✗ Supergraph too small");
        let mut buf: Vec<u8> = Vec::new();
        write_composition_check_line(&mut buf, &check).unwrap();
        let out = String::from_utf8(buf).unwrap();
        let plain = strip_ansi(&out);
        assert_eq!(plain, "   ✗ Supergraph too small\n");
    }

    /// Structural coloring shield: the primitive body must chain
    /// `.green()`, `.yellow()`, and `.red()` on `check.message` and
    /// carry the exact `"   {}"` three-space-indent format string.
    /// The byte-oracle strips ANSI so a "just print the message
    /// plain, colored is noisy in CI" cleanup that dropped every
    /// coloring call would pass the byte-oracle silently — this
    /// shield closes that hole by scanning the module body itself.
    ///
    /// The needle scan is bounded to the module body before the
    /// first `#[cfg(test)]` block so this shield's own diagnostic
    /// prose does not false-match itself.
    #[test]
    fn primitive_body_carries_green_yellow_red_and_three_space_indent() {
        let source = include_str!("composition_check_print.rs");
        let body = crate::test_support::module_body_before_first_cfg_test(
            source,
            "composition_check_print.rs",
        );
        assert!(
            body.contains("check.message.green()"),
            "primitive body must chain `.green()` on `check.message` for the pass arm — \
             a cleanup that dropped the coloring regresses the pass-vs-warn-vs-fail \
             visual distinction every pre-lift site carried.",
        );
        assert!(
            body.contains("check.message.yellow()"),
            "primitive body must chain `.yellow()` on `check.message` for the warn arm — \
             a cleanup that folded warn into either pass or fail regresses the advisory \
             grammar the post-composition loop's `else if check.message.contains(\"Warning\")` \
             branch established.",
        );
        assert!(
            body.contains("check.message.red()"),
            "primitive body must chain `.red()` on `check.message` for the fail arm — \
             a cleanup that dropped the coloring loses the failure-status semantic \
             every pre-lift site carried.",
        );
        assert!(
            body.contains("\"   {}\""),
            "primitive body must carry the exact `\"   {{}}\"` format string — every \
             pre-lift site spelled the three-space indent OUTSIDE the coloring span so \
             the color painted the message alone, not the indent.",
        );
        assert!(
            body.contains("check.message.contains(\"Warning\")"),
            "primitive body must classify warn via `check.message.contains(\"Warning\")` — \
             the substring literal the pre-lift post-composition loop's `else if` guard \
             spelled verbatim. A rewrite that promoted the guard to a `starts_with` or a \
             case-insensitive scan silently reroutes existing warn messages.",
        );
    }

    /// Caller shield: no source line under `cli/src/commands/` may
    /// still spell `check.message.green()`, `check.message.yellow()`,
    /// or `check.message.red()` inline. Every composition-check row
    /// emission must resolve through [`print_composition_check_result`]
    /// so a future palette adjustment reaches both federation.rs
    /// sites (and any future third loop) from one edit.
    #[test]
    fn no_command_module_still_spells_raw_check_message_color_call() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let needles = [
            "check.message.green()",
            "check.message.yellow()",
            "check.message.red()",
        ];
        let mut offenders: Vec<(PathBuf, Vec<String>)> = Vec::new();
        for entry in std::fs::read_dir(&commands_dir).unwrap().flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            if path.file_name().and_then(|n| n.to_str()) == Some("composition_check_print.rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).unwrap();
            let hits: Vec<String> = source
                .lines()
                .enumerate()
                .filter(|(_, l)| {
                    let t = l.trim_start();
                    !t.starts_with("//") && needles.iter().any(|n| l.contains(*n))
                })
                .map(|(i, l)| format!("line {}: {}", i + 1, l.trim()))
                .collect();
            if !hits.is_empty() {
                offenders.push((path, hits));
            }
        }
        assert!(
            offenders.is_empty(),
            "pre-lift `check.message.<green|yellow|red>()` composition-check row \
             emission(s) survive under `commands/` — route each through \
             `crate::commands::composition_check_print::print_composition_check_result(check)` \
             instead:\n{:#?}",
            offenders,
        );
    }

    /// Positive-delegation shield: `commands/federation.rs` — the
    /// one pre-lift consumer — must resolve at least two
    /// composition-check row emissions through
    /// [`print_composition_check_result`]. Pairs with the negative
    /// caller shield above: the negative shield forbids the raw
    /// `check.message.<color>()` literal from surviving, and this
    /// shield forbids a "just delete the print loop, the bail
    /// message suffices" cleanup that quietly drops the operator's
    /// visible per-check trail without regressing the negative-
    /// shield assertion. The floor is two — one call for the pre-
    /// composition loop, one call for the post-composition loop —
    /// matching the two pre-lift for-check-in-checks bodies.
    #[test]
    fn federation_module_delegates_through_primitive_at_least_twice() {
        use std::path::PathBuf;
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands")
            .join("federation.rs");
        let source = std::fs::read_to_string(&path).unwrap();
        let call_count = source.matches("print_composition_check_result(").count();
        assert!(
            call_count >= 2,
            "`commands/federation.rs` must resolve at least two composition-check row \
             emissions through `print_composition_check_result` (one per pre/post \
             composition loop); found {} call(s). A cleanup that dropped either \
             delegation regresses the operator's visible per-check trail without \
             tripping the negative caller shield.",
            call_count,
        );
    }
}
