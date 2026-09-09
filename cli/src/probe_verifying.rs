//! Verifying-phase probe-announcement grammar.
//!
//! Four pre-lift sibling sites across `commands/{web_build_verify (×3:
//! no-hardcoded-API-URLs at :26, bundle-consistency at :85, cache-policy at
//! :151), github_runner_ci (×1: deployment at :727)}.rs` each restated the
//! `info!("🔍 Verifying <static-phrase>...")` stanza verbatim — a `🔍`
//! magnifying-glass glyph followed by one ASCII space, the literal verb
//! `Verifying `, a per-site static phrase, then the trailing ellipsis
//! `...`, routed through [`tracing::info!`]. Post-lift the four sites reach
//! for [`info_probe_verifying!`], and the glyph + verb + spacing +
//! terminal ellipsis are decided once here.
//!
//! # Distinct from `info!("🔍 Verifying <arg>", ...)` sites
//!
//! One non-ellipsis-terminated sibling survives at
//! `commands/nix_builder.rs:53`: `info!("🔍 Verifying nix-builder at
//! {}:{}", hostname, port)`. It shares the `🔍 Verifying ` opener but
//! carries a `format!`-style target-address body (`nix-builder at
//! host:port`) rather than a phase-name phrase, and it terminates without
//! `...` because it is a startup-announcement, not a phase-open ellipsis.
//! The caller shield below matches only the pre-lift shape (opener plus
//! terminal `...");`), so that site is deliberately out of scope — its
//! grammar is a startup-target announcement, not a phase-open probe, and
//! collapsing them would erase the ellipsis-vs-argument distinction the
//! operator uses to tell one grammar from the other.
//!
//! # Compounding
//!
//! Pre-lift, a future adjustment to how verifying-phase probes surface —
//! routing them through `tracing::info!(target: "forge::probe", ...)` for
//! structured observability so a downstream OTLP subscriber can count in-
//! body probes per pipeline stage, promoting the `🔍` glyph to a palette-
//! consistent paint, wrapping the rendered line in a step-header banner,
//! or elevating the ellipsis to a real progress spinner — had to hit four
//! sites in lockstep or drift the surface (glyph, verb, spacing, terminal
//! ellipsis). Post-lift the glyph, verb, spacing, and terminal ellipsis
//! live in ONE macro body; the sites carry only the per-probe phrase body.

use std::fmt;
use std::io;

/// Writer-taking byte-oracle sibling to [`info_probe_verifying!`]. Emits
/// the single `🔍 Verifying <phrase>...` line via [`writeln!`] against the
/// supplied writer.
///
/// The [`crate::info_probe_verifying!`] macro is the [`tracing::info!`]
/// adapter production code invokes; this direct-writer variant exists so
/// the fail-before-pass tests can pin the exact emitted bytes (the one-
/// space gap after the `🔍` glyph, the literal `Verifying ` verb, the
/// caller phrase, the trailing `...`, then the newline) without capturing
/// a tracing subscriber and without racing an ambient logger — the same
/// split [`crate::advisory_warning::write_advisory_warning`] carries
/// against [`crate::warn_advisory!`]. The writer is therefore the byte-
/// format oracle for the tests and the natural next-lift consumer (a
/// `collect_probes()` summary sibling) rather than the production emission
/// path.
///
/// The `phrase` parameter takes [`fmt::Arguments<'_>`] rather than
/// `&str` so the macro forwards `format_args!(...)` without an intermediate
/// `String` allocation. The pre-lift shape passed a literal string through
/// `tracing::info!`'s message-format arm, so this preserves the byte-for-
/// byte behavior AND the zero-allocation path.
#[allow(dead_code)] // See doc comment: the writer is a test/byte-oracle
                    // peer of the tracing-routed `info_probe_verifying!`
                    // macro, and the future `collect_probes` sibling will
                    // consume it directly.
pub fn write_probe_verifying<W: io::Write>(
    w: &mut W,
    phrase: fmt::Arguments<'_>,
) -> io::Result<()> {
    writeln!(w, "🔍 Verifying {}...", phrase)
}

/// Emit an operator-facing verifying-phase probe announcement via
/// [`tracing::info!`] on the fleet-standard `"🔍 Verifying <phrase>..."`
/// grammar.
///
/// The macro expands to a direct `::tracing::info!(...)` call at the
/// caller's location so tracing's automatic source-location capture is
/// preserved (a function wrapper would collapse every emission to the
/// wrapper's site and break per-`module_path` filter routing — the same
/// reason [`crate::warn_advisory!`] is a macro rather than a function).
/// See the [module docs](self) for the sibling site census, the split
/// against the `format!`-argument variants, and the compounding rationale
/// for centralising the glyph + verb + ellipsis decision at one code point.
///
/// # Examples
///
/// ```ignore
/// // Pre-lift:
/// info!("🔍 Verifying bundle consistency...");
/// // Post-lift:
/// crate::info_probe_verifying!("bundle consistency");
///
/// // Pre-lift, with formatted phrase (no pre-lift site but supported):
/// info!("🔍 Verifying {} bundles...", n);
/// // Post-lift:
/// crate::info_probe_verifying!("{} bundles", n);
/// ```
#[macro_export]
macro_rules! info_probe_verifying {
    ($($arg:tt)*) => {
        ::tracing::info!("🔍 Verifying {}...", ::std::format_args!($($arg)*))
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fail-before-pass envelope for [`write_probe_verifying`]. Pins the
    /// exact prefix bytes: `🔍` (U+1F50D — magnifying-glass-tilted-left
    /// codepoint), one ASCII space, the literal `Verifying `, one ASCII
    /// space, the caller phrase, the terminal `...`, then `\n`. A future
    /// refactor that swapped the glyph, dropped the terminal ellipsis,
    /// re-cased the verb (`verifying`, `VERIFYING`), or dropped the
    /// trailing newline flips this assertion rather than silently
    /// diverging the four consumer sites' surface.
    #[test]
    fn write_probe_verifying_emits_prefix_phrase_ellipsis_and_newline() {
        let mut buf: Vec<u8> = Vec::new();
        write_probe_verifying(&mut buf, format_args!("bundle consistency")).unwrap();
        assert_eq!(
            buf, b"\xf0\x9f\x94\x8d Verifying bundle consistency...\n",
            "write_probe_verifying must emit the U+1F50D glyph, one-space gap, \
             `Verifying `, phrase body, trailing `...`, then `\\n`"
        );
    }

    /// Pins that the writer accepts a phrase carrying uppercase-emphasis
    /// (`NO`) verbatim — the pre-lift `info!("🔍 Verifying NO hardcoded
    /// API URLs in bundles...")` site at `web_build_verify.rs:26` embeds
    /// an inline uppercase-emphasis word, and the writer MUST NOT re-case
    /// or re-quote it.
    #[test]
    fn write_probe_verifying_preserves_uppercase_emphasis_phrase() {
        let mut buf: Vec<u8> = Vec::new();
        write_probe_verifying(&mut buf, format_args!("NO hardcoded API URLs in bundles")).unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "\u{1f50d} Verifying NO hardcoded API URLs in bundles...\n"
        );
    }

    /// Pins that the writer accepts a `format_args!` spelling with an
    /// interpolation slot without an intermediate `String` allocation —
    /// no pre-lift site uses this shape, but the macro's variadic
    /// `format_args!(...)` forwarder must accept future callers that
    /// interpolate a per-run value (e.g. a bundle count) without a per-
    /// caller `.to_string()` intermediate.
    #[test]
    fn write_probe_verifying_interpolates_multi_arg_format() {
        let mut buf: Vec<u8> = Vec::new();
        write_probe_verifying(&mut buf, format_args!("{} bundles", 7)).unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "\u{1f50d} Verifying 7 bundles...\n"
        );
    }

    /// The macro forwards to `::tracing::info!` at the caller's location,
    /// but the tracing subscriber can't be captured in-process without
    /// racing whatever subscriber `main` installs. Instead, pin that the
    /// macro accepts the same argument shapes the writer accepts by
    /// expanding it at compile time — a compile-fail here would fail the
    /// crate's `cargo test` build gate.
    #[test]
    fn info_probe_verifying_macro_compiles_with_supported_arg_shapes() {
        // Bare literal (four pre-lift sites).
        crate::info_probe_verifying!("bundle consistency");
        // Single positional arg (no pre-lift site but supported for future callers).
        crate::info_probe_verifying!("{} bundles", 7);
        // Multi-arg (no pre-lift site but supported for future callers).
        crate::info_probe_verifying!("{} of {} bundles", 3, 7);
        // Trailing comma is legal.
        crate::info_probe_verifying!("bare phrase with trailing comma",);
    }

    /// Caller shield — asserts no source line under `cli/src/commands/`
    /// still spells the pre-lift shape `info!("🔍 Verifying <phrase>...");`
    /// inline. Every ellipsis-terminated verifying-phase probe emission
    /// that carries the `🔍` + `Verifying ` opener must route through
    /// [`crate::info_probe_verifying!`], which expands to the canonical
    /// `tracing::info!(...)` call at the caller's location.
    ///
    /// The shield scans EVERY `commands/*.rs` module rather than only the
    /// two pre-lift files so a future orchestrator that surfaces a new
    /// verifying-phase probe (a new sub-step in a new command module)
    /// reaches for `info_probe_verifying!` on first grep of `ui.rs` /
    /// this module, not by copy-pasting a raw
    /// `info!("🔍 Verifying ...");` stanza from
    /// `web_build_verify.rs`.
    ///
    /// The needle combines the pre-lift `info!("🔍 Verifying ` opener
    /// with the terminal `...");` closer so the sibling non-ellipsis
    /// shape at `nix_builder.rs:53` (`info!("🔍 Verifying nix-builder
    /// at {}:{}", hostname, port);` — a startup-target announcement, not
    /// a phase-open probe) is out of scope; the needle catches only the
    /// exact pre-lift shape, and the shield's positive half (the
    /// delegation-count assertion below) forces future variants of the
    /// SAME shape through the primitive too. Comment lines are skipped
    /// so this module's own docstring reference to the pre-lift shape
    /// doesn't self-hit.
    #[test]
    fn no_command_module_still_spells_raw_probe_verifying_info() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let opener = "info!(\"\u{1f50d} Verifying ";
        let closer = "...\");";
        let mut offenders: Vec<(PathBuf, usize, String)> = Vec::new();
        for entry in std::fs::read_dir(&commands_dir).unwrap().flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).unwrap();
            for (idx, line) in source.lines().enumerate() {
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") || trimmed.starts_with("///") {
                    continue;
                }
                if line.contains(opener) && line.contains(closer) {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `info!(\"\u{1f50d} Verifying <phrase>...\");` verifying-phase \
             probe stanza(s) survive under `commands/` — route each through \
             `crate::info_probe_verifying!(<phrase>)` instead:\n{:#?}",
            offenders
        );
    }

    /// Positive half of the shield: the two pre-lift files MUST each
    /// forward through `crate::info_probe_verifying!(` at least once, so
    /// a migration that dropped a call site outright leaves the negative
    /// "no raw inline shape" scan trivially satisfied by absence but the
    /// positive count still fails.
    #[test]
    fn every_prelift_module_forwards_through_probe_verifying_macro() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        // (module basename, minimum forward count from the pre-lift census)
        let expectations: &[(&str, usize)] =
            &[("web_build_verify.rs", 3), ("github_runner_ci.rs", 1)];
        for (basename, min_count) in expectations {
            let path = commands_dir.join(basename);
            let source = std::fs::read_to_string(&path).unwrap();
            let forwards = source.matches("crate::info_probe_verifying!(").count();
            assert!(
                forwards >= *min_count,
                "{basename} must forward at least {min_count} verifying-phase \
                 probe site(s) through `crate::info_probe_verifying!(`; found \
                 {forwards}. A dropped call would leave the negative raw-shape \
                 scan satisfied by absence.",
            );
        }
    }
}
