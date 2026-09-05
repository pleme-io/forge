//! Skipped-step announce grammar.
//!
//! Eight pre-lift sibling sites across `commands/{comprehensive_release
//! (×5: unit tests + build step + integration tests + push step + deploy
//! step), deploy (×1: build step), github_runner_ci (×2: build step +
//! push step)}.rs` each restated the
//!
//! ```ignore
//! info!("⏭️  Skipping <step>");
//! println!();
//! ```
//!
//! fused stanza verbatim — an `⏭️` glyph (U+23ED plus U+FE0F variation
//! selector) followed by two ASCII spaces and the literal `Skipping `
//! prefix, a per-site step noun-phrase, an `info!`-routed emission via
//! the tracing subscriber, and a trailing blank line separating the
//! announce from the next workflow step. Post-lift the sites reach for
//! [`info_skipping!`] and the prefix + trailing-blank fusion is decided
//! once here.
//!
//! # The trailing blank line is load-bearing
//!
//! Each of the eight pre-lift sites sits inside an `else` arm of a
//! `skip-this-step` branch in a multi-step orchestrator (a comprehensive
//! release, a deploy, a GitHub-runner CI run). Every executed arm of the
//! same orchestrator ends with a trailing `println!();` — the announce +
//! blank pair is the visual separator between the current step's readout
//! and the next step's `━━━ Step N/M ━━━` heading. A collapse to a bare
//! `info!(...)` would leave the skip-arm output visually adjacent to the
//! next step's heading, breaking the readout's vertical rhythm the seven
//! sibling arms deliberately establish. The fusion carries the pair as
//! one primitive so the invariant "every skip-arm ends with a blank
//! separator" is enforceable, not aspirational.
//!
//! # Preserving `tracing::info!` at the call site
//!
//! The macro expands to `::tracing::info!(...)` at the caller's location,
//! not to a function wrapper, so tracing's automatic source-location
//! capture (`file` + `line` + `module_path`) matches the pre-lift
//! behavior byte-for-byte. A function-based wrapper would collapse every
//! emission to the wrapper's own site and break structured-log
//! destinations that filter by module_path
//! (`RUST_LOG=forge::commands::deploy=info` would stop matching once the
//! emission moved to `forge::skipping_step`). The byte-oracle writer
//! sibling [`write_skipping_step`] captures the exact rendered body for
//! the tests (the `⏭️` glyph, the two-space gap, the literal
//! `Skipping ` prefix, the trailing blank line) so the invariant is
//! pinned without racing an ambient tracing subscriber — the same split
//! [`crate::nonfatal_warning::write_nonfatal_warn`] carries against
//! [`crate::warn_nonfatal!`].

use std::fmt;
use std::io;

/// Emits a two-line `"⏭️  Skipping <step>\n\n"` block via [`writeln!`]
/// against the supplied writer: line 1 carries the pre-lift `⏭️` +
/// two-space + `Skipping ` prefix + the [`fmt::Display`] step name,
/// line 2 is the trailing blank separator that eight sibling sites
/// spelled inline as `println!();`.
///
/// The [`crate::info_skipping!`] macro is the tracing adapter that
/// production code invokes; this direct-writer variant exists so the
/// fail-before-pass tests can pin the exact emitted bytes (the two-space
/// gap after the `⏭️` glyph, the literal `Skipping ` prefix, the
/// trailing blank line) without capturing a tracing subscriber and
/// without racing an ambient logger — the same split
/// [`crate::nonfatal_warning::write_nonfatal_warn`] carries against
/// [`crate::warn_nonfatal!`].
///
/// The `step` parameter accepts any [`fmt::Display`] rather than a
/// concrete `&str` so a bare literal (used by every pre-lift call site
/// today), a `String` / `Cow<str>`, and a future step-descriptor type
/// carrying structured fields all flow through the same writer without a
/// per-caller `.to_string()` intermediate.
#[allow(dead_code)] // See doc comment: the writer is a test/byte-oracle
                    // peer of the tracing-routed `info_skipping!` macro,
                    // and a future `collect_skipped_steps` summary
                    // sibling will consume it directly.
pub fn write_skipping_step<W: io::Write>(w: &mut W, step: &dyn fmt::Display) -> io::Result<()> {
    writeln!(w, "\u{23ed}\u{fe0f}  Skipping {}", step)?;
    writeln!(w)
}

/// Emit a skipped-step announce via [`tracing::info!`] on the
/// fleet-standard `"⏭️  Skipping <step>"` grammar, followed by a
/// trailing blank line to separate the skip-arm from the next
/// workflow step's readout.
///
/// The macro expands to a direct `::tracing::info!(...)` call at the
/// caller's location so tracing's automatic source-location capture is
/// preserved (a function wrapper would collapse every emission to the
/// wrapper's site — see the module docs for why that breaks per-module
/// filter routing). See the [module docs](self) for the sibling site
/// census and the compounding rationale for the load-bearing trailing
/// blank line.
///
/// # Examples
///
/// ```ignore
/// // Pre-lift
/// info!("⏭️  Skipping unit tests");
/// println!();
///
/// // Post-lift
/// crate::info_skipping!("unit tests");
/// ```
#[macro_export]
macro_rules! info_skipping {
    ($($arg:tt)*) => {{
        ::tracing::info!("\u{23ed}\u{fe0f}  Skipping {}", ::std::format_args!($($arg)*));
        ::std::println!();
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    // Pin the exact prefix bytes: `⏭️` (U+23ED U+FE0F), two ASCII
    // spaces, the literal `Skipping `, the interpolated step Display,
    // one `\n`, then a second `\n` for the trailing blank line. A
    // future refactor that drops the variation selector, collapses the
    // two-space gap to one, or drops the trailing blank regresses this
    // assertion.
    #[test]
    fn write_skipping_step_emits_prefix_step_and_trailing_blank() {
        let mut buf: Vec<u8> = Vec::new();
        write_skipping_step(&mut buf, &"unit tests").unwrap();
        assert_eq!(buf, b"\xe2\x8f\xad\xef\xb8\x8f  Skipping unit tests\n\n");
    }

    // Human-readable pin of the exact grammar so a future reader can
    // eyeball the render without decoding bytes. Doubles as a Display-
    // forwarding pin: the `&dyn Display` slot receives a step whose
    // rendered form contains parentheses and a `--flag` fragment; the
    // interior punctuation MUST survive verbatim without the writer
    // re-quoting or re-escaping the inner text.
    #[test]
    fn write_skipping_step_forwards_multi_word_step_display() {
        let mut buf: Vec<u8> = Vec::new();
        write_skipping_step(&mut buf, &"rollout watch (use --watch to enable)").unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "\u{23ed}\u{fe0f}  Skipping rollout watch (use --watch to enable)\n\n"
        );
    }

    // The macro forwards to `::tracing::info!` at the caller's location.
    // The subscriber cannot be captured in-process without racing
    // whatever subscriber `main` installs. Instead, pin that the macro
    // accepts the supported literal + format-arg shapes by expanding it
    // at compile time — a compile-fail here would fail the crate's
    // `cargo test` build gate.
    #[test]
    fn info_skipping_macro_compiles_with_supported_arg_shapes() {
        // Bare literal (every pre-lift call site today).
        crate::info_skipping!("bare literal step");
        // Runtime `&str` interpolated through `{}`.
        let step_name = "runtime string step";
        crate::info_skipping!("{}", step_name);
        // Multi-arg format string.
        crate::info_skipping!("{} step", "build");
        // Trailing comma is legal.
        crate::info_skipping!("trailing comma step",);
        // Owned `String` via `{}`.
        let owned = String::from("owned string step");
        crate::info_skipping!("{}", owned);
    }

    // Caller shield: no source line under `cli/src/commands/` may spell
    // the pre-lift fused stanza inline any more. The needle catches the
    // `info!("⏭️  Skipping ...")` line ONLY when the immediately
    // following non-blank source line is exactly `println!();` — the
    // paired shape defines the fused stanza. A lone
    // `info!("⏭️  Skipping ...")` without the trailing `println!();`
    // (e.g. github_runner_ci.rs:762, whose enclosing arms share an
    // outer separator instead) is deliberately out of scope: the fused
    // primitive would double the blank line if forced through it.
    //
    // The shield scans EVERY `commands/*.rs` module rather than only
    // the three pre-lift files so a future step-orchestrator that
    // surfaces a new skip arm (a new sub-step in a new command module)
    // reaches for `info_skipping!` on first grep, not by copy-pasting a
    // raw `info!("⏭️  Skipping ..."); println!();` stanza from
    // comprehensive_release.rs.
    #[test]
    fn no_command_module_still_spells_raw_info_skipping_fused_stanza() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let mut offenders: Vec<(PathBuf, usize, String)> = Vec::new();
        for entry in std::fs::read_dir(&commands_dir).unwrap().flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).unwrap();
            let lines: Vec<&str> = source.lines().collect();
            for (idx, line) in lines.iter().enumerate() {
                // Skip comment lines so this shield's own reference to
                // the pre-lift shape in prose doesn't self-hit.
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") || trimmed.starts_with("///") {
                    continue;
                }
                if !line.contains("info!(\"\u{23ed}\u{fe0f}  Skipping ") {
                    continue;
                }
                // Only flag as an offender when the immediately-following
                // non-blank line is exactly `println!();` — the paired
                // fused-stanza shape. A standalone skip announce (whose
                // trailing blank comes from an outer shared separator)
                // stays out of scope.
                let mut cursor = idx + 1;
                while cursor < lines.len() && lines[cursor].trim().is_empty() {
                    cursor += 1;
                }
                if cursor < lines.len() && lines[cursor].trim() == "println!();" {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `info!(\"\u{23ed}\u{fe0f}  Skipping ...\"); println!();` \
             fused stanza(s) survive under `commands/` — route each through \
             `crate::info_skipping!(<step>)` instead:\n{:#?}",
            offenders
        );
    }

    // Positive half of the shield: the three pre-lift files MUST each
    // forward through `crate::info_skipping!(` at least the pre-lift
    // count of times, so a migration that dropped a call site outright
    // leaves the negative "no raw inline shape" scan trivially
    // satisfied by absence but the positive count still fails.
    #[test]
    fn every_prelift_module_forwards_through_info_skipping_macro() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        // (module basename, minimum forward count from the pre-lift census)
        let expectations: &[(&str, usize)] = &[
            ("comprehensive_release.rs", 5),
            ("deploy.rs", 1),
            ("github_runner_ci.rs", 2),
        ];
        for (basename, min_count) in expectations {
            let path = commands_dir.join(basename);
            let source = std::fs::read_to_string(&path).unwrap();
            let forwards = source.matches("crate::info_skipping!(").count();
            assert!(
                forwards >= *min_count,
                "{basename} must forward at least {min_count} skipped-step \
                 site(s) through `crate::info_skipping!(`; found \
                 {forwards}. A dropped call would leave the negative \
                 raw-shape scan satisfied by absence.",
            );
        }
    }
}
