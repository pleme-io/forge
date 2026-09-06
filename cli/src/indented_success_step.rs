//! Three-space-indented info-routed success-acknowledge grammar.
//!
//! Eleven pre-lift sibling sites across `commands/{bootstrap (×1),
//! comprehensive_release (×1), kenshi (×1), kenshi_agent (×2),
//! nix_builder (×3), push (×2), release_commit (×1)}.rs` each restated
//! the `info!("   ✅ <fmt>", <args>)` stanza verbatim — three ASCII
//! spaces of indent, a `✅` glyph (U+2705, standalone, no variation
//! selector), one ASCII space, a per-site success message, and an
//! `info!`-routed emission via the tracing subscriber. Post-lift the
//! sites reach for [`info_indented_success!`] and the indent + prefix +
//! separator + tracing verbosity are decided once here.
//!
//! # Distinct from the zero-indent sibling [`crate::info_success!`]
//!
//! [`crate::info_success!`] narrates a MID-RUN top-level success at zero
//! indent (`"✅ <msg>"`), used by workflow-step orchestrators to close a
//! logical step at the flow's outer nesting. This primitive narrates a
//! SUB-STEP success at three-space indent (`"   ✅ <msg>"`), used inside
//! a step body to acknowledge one sub-action (a kustomization write, a
//! git commit-and-push, a migration application) that itself is one of
//! several the enclosing step performs. The indent shape lines up with
//! the fleet's other three-space sub-step grammars — [`crate::ui::print_step_ok`]
//! (`"   OK <msg>"`), [`crate::ui::print_step_check`] (`"   ✓ <msg>"`),
//! [`crate::ui::print_step_uncheck`] (`"   ✗ <msg>"`), and
//! [`crate::ui::print_step_failure_with_error`] (`"   ❌ <msg>: <err>"`)
//! — so a sub-step readout column-aligns with its siblings whatever the
//! grammar (success, check, failure). The two coexist rather than fusing
//! because the outer step still uses the zero-indent grammar for its own
//! terminal success readout, and a runtime indent parameter would let a
//! caller shift a top-level success into the sub-step column by
//! accident.
//!
//! # Preserving `tracing::info!` at the call site
//!
//! The macro expands to `::tracing::info!(...)` at the caller's location,
//! not to a function wrapper, so tracing's automatic source-location
//! capture (`file` + `line` + `module_path`) matches the pre-lift
//! behavior byte-for-byte. A function-based wrapper would collapse every
//! emission to the wrapper's own site and break structured-log
//! destinations that filter by module_path
//! (`RUST_LOG=forge::commands::kenshi=info` would stop matching once the
//! emission moved to `forge::indented_success_step`). The byte-oracle
//! writer sibling [`write_indented_success_step`] captures the exact
//! rendered body for the tests (the three-space indent, the `✅` glyph,
//! the one-space gap, the trailing newline) so the invariant is pinned
//! without racing an ambient tracing subscriber — the same split
//! [`crate::success_step::write_success_step`] carries against
//! [`crate::info_success!`].

use std::fmt;
use std::io;

/// Emits a single `"   ✅ <message>"` line via [`writeln!`] against the
/// supplied writer, wrapping the message with the pre-lift three-space
/// indent + `✅ ` + one-ASCII-space prefix that eleven sibling sites
/// spelled inline.
///
/// The [`crate::info_indented_success!`] macro is the [`tracing::info!`]
/// adapter that production code invokes; this direct-writer variant
/// exists so the fail-before-pass tests can pin the exact emitted bytes
/// (the three-space indent, the single-space gap after the `✅` glyph,
/// the trailing newline) without capturing a tracing subscriber and
/// without racing an ambient logger — the same split
/// [`crate::success_step::write_success_step`] carries against
/// [`crate::info_success!`].
///
/// The `message` parameter accepts any [`fmt::Display`] rather than a
/// concrete `&str` so a bare literal (used by most pre-lift call sites),
/// a `String` / `Cow<str>`, and a future sub-step-descriptor type
/// carrying structured fields all flow through the same writer without a
/// per-caller `.to_string()` intermediate.
#[allow(dead_code)] // See doc comment: the writer is a test/byte-oracle
                    // peer of the tracing-routed
                    // `info_indented_success!` macro.
pub fn write_indented_success_step<W: io::Write>(
    w: &mut W,
    message: &dyn fmt::Display,
) -> io::Result<()> {
    writeln!(w, "   \u{2705} {}", message)
}

/// Emit a sub-step success acknowledgement via [`tracing::info!`] on the
/// fleet-standard `"   ✅ <message>"` three-space-indented grammar.
///
/// The macro expands to a direct `::tracing::info!(...)` call at the
/// caller's location so tracing's automatic source-location capture is
/// preserved (a function wrapper would collapse every emission to the
/// wrapper's site — see the module docs for why that breaks per-module
/// filter routing). See the [module docs](self) for the sibling site
/// census, the split against [`crate::info_success!`] (zero-indent
/// top-level success) and [`crate::ui::print_step_ok`] /
/// [`crate::ui::print_step_check`] (three-space sub-step siblings using
/// `println!` rather than `tracing::info!`).
///
/// # Examples
///
/// ```ignore
/// // Pre-lift
/// info!("   ✅ Kustomization updated");
/// info!("   ✅ Committed: {}", commit_message);
///
/// // Post-lift
/// crate::info_indented_success!("Kustomization updated");
/// crate::info_indented_success!("Committed: {}", commit_message);
/// ```
#[macro_export]
macro_rules! info_indented_success {
    ($($arg:tt)*) => {
        ::tracing::info!("   \u{2705} {}", ::std::format_args!($($arg)*))
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    // Pin the exact prefix bytes: three ASCII spaces, `✅` (U+2705,
    // 3 bytes E2 9C 85, no variation selector), one ASCII space, the
    // interpolated message Display, then `\n`. A future refactor that
    // adds a variation selector, widens the one-space gap to two, drops
    // an indent space, or drops the trailing newline regresses this
    // assertion.
    #[test]
    fn write_indented_success_step_emits_indent_prefix_message_and_newline() {
        let mut buf: Vec<u8> = Vec::new();
        write_indented_success_step(&mut buf, &"Kustomization updated").unwrap();
        assert_eq!(buf, b"   \xe2\x9c\x85 Kustomization updated\n");
    }

    // Human-readable pin of the exact grammar so a future reader can
    // eyeball the render without decoding bytes. Doubles as a Display-
    // forwarding pin: the `&dyn Display` slot receives a message whose
    // rendered form contains a colon and interpolated substring; the
    // interior punctuation MUST survive verbatim without the writer
    // re-quoting or re-escaping the inner text.
    #[test]
    fn write_indented_success_step_forwards_multi_segment_message_display() {
        let mut buf: Vec<u8> = Vec::new();
        write_indented_success_step(&mut buf, &"Committed: chore(release): bump kraken to 1.2.3")
            .unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "   \u{2705} Committed: chore(release): bump kraken to 1.2.3\n"
        );
    }

    // Guard against the zero-indent grammar drift: the sibling
    // `crate::info_success!` primitive emits `"✅ <msg>"` at zero indent
    // for top-level workflow successes. This primitive is deliberately
    // three-space indented for sub-step successes that must
    // column-align with the fleet's `"   OK "` / `"   ✓ "` / `"   ✗ "`
    // sub-step siblings. Pin the negative shape explicitly so a future
    // reader who reaches for the zero-indent grammar hits this test.
    #[test]
    fn write_indented_success_step_does_not_use_zero_indent_grammar() {
        let mut buf: Vec<u8> = Vec::new();
        write_indented_success_step(&mut buf, &"Kustomization updated").unwrap();
        let rendered = String::from_utf8(buf).unwrap();
        assert!(
            rendered.starts_with("   \u{2705} "),
            "indented-success render must start with three ASCII spaces \
             then `✅ ` — the zero-indent shape belongs to \
             `crate::info_success!`; got: {:?}",
            rendered
        );
    }

    // The macro forwards to `::tracing::info!` at the caller's location.
    // The subscriber cannot be captured in-process without racing
    // whatever subscriber `main` installs. Instead, pin that the macro
    // accepts the supported literal + format-arg shapes by expanding it
    // at compile time — a compile-fail here would fail the crate's
    // `cargo test` build gate.
    #[test]
    fn info_indented_success_macro_compiles_with_supported_arg_shapes() {
        // Bare literal (most pre-lift call sites).
        crate::info_indented_success!("Kustomization updated");
        // Bare literal with distinct wording (nix_builder / kenshi_agent shape).
        crate::info_indented_success!("Builder pool updated");
        // Runtime `&str` interpolated through `{}` (bootstrap.rs shape).
        let commit_message = "chore(release): bump kraken to 1.2.3";
        crate::info_indented_success!("Committed: {}", commit_message);
        // Trailing comma is legal.
        crate::info_indented_success!("trailing comma message",);
        // Owned `String` via `{}`.
        let owned = String::from("owned string message");
        crate::info_indented_success!("{}", owned);
    }

    // Caller shield: no source line under `cli/src/commands/` may spell
    // the pre-lift shape `info!("   ✅ ...")` inline any more. Every
    // three-space-indented info-routed sub-step success acknowledgement
    // must route through `crate::info_indented_success!`, which expands
    // to the canonical `tracing::info!(...)` call at the caller's
    // location.
    //
    // The shield scans EVERY `commands/*.rs` module rather than only
    // the seven pre-lift files so a future workflow-step orchestrator
    // that surfaces a new mid-step success (a new sub-action in a new
    // command module) reaches for `info_indented_success!` on first
    // grep, not by copy-pasting a raw `info!("   ✅ ...")` stanza from
    // nix_builder.rs.
    //
    // The needle is anchored on the three-space indent + emoji + one-
    // space gap so a future variant that reaches for a different indent
    // width (`"  ✅ "`, `"    ✅ "`) is out of scope; the needle catches
    // only the exact pre-lift shape, and the shield's positive half
    // (the delegation-count assertion below) forces future variants of
    // the SAME shape through the primitive too.
    #[test]
    fn no_command_module_still_spells_raw_indented_info_success() {
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
            for (idx, line) in source.lines().enumerate() {
                // Skip comment lines so this shield's own reference to
                // the pre-lift shape in prose doesn't self-hit.
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") || trimmed.starts_with("///") {
                    continue;
                }
                if line.contains("info!(\"   \u{2705} ") {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `info!(\"   \u{2705} ...\")` stanza(s) survive under \
             `commands/` — route each through \
             `crate::info_indented_success!(<msg>)` instead:\n{:#?}",
            offenders
        );
    }

    // Positive half of the shield: the seven pre-lift files under
    // `commands/` MUST each forward through
    // `crate::info_indented_success!(` at least the pre-lift count of
    // times, so a migration that dropped a call site outright leaves
    // the negative "no raw inline shape" scan trivially satisfied by
    // absence but the positive count still fails.
    #[test]
    fn every_prelift_module_forwards_through_info_indented_success_macro() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        // (module basename, minimum forward count from the pre-lift census)
        let expectations: &[(&str, usize)] = &[
            ("bootstrap.rs", 1),
            ("comprehensive_release.rs", 1),
            ("kenshi.rs", 1),
            ("kenshi_agent.rs", 2),
            ("nix_builder.rs", 3),
            ("push.rs", 2),
            ("release_commit.rs", 1),
        ];
        for (basename, min_count) in expectations {
            let path = commands_dir.join(basename);
            let source = std::fs::read_to_string(&path).unwrap();
            let forwards = source.matches("crate::info_indented_success!(").count();
            assert!(
                forwards >= *min_count,
                "{basename} must forward at least {min_count} indented \
                 sub-step success acknowledgement site(s) through \
                 `crate::info_indented_success!(`; found {forwards}. A \
                 dropped call would leave the negative raw-shape scan \
                 satisfied by absence.",
            );
        }
    }
}
