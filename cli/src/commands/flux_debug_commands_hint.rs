//! FluxCD debug-commands hint block — the three-line
//! `Debug commands:\n  flux get all …\n  flux logs --all-namespaces …\n`
//! bail-preamble stanza emitted by the two `commands/flux.rs`
//! health-check-failure sites (the immediate-fail arm of the
//! initial-check body [`crate::commands::flux::check_health_status`]-adjacent
//! fanout, and the post-timeout arm of
//! [`crate::commands::flux::health_check_with_retry`]) right before the
//! `bail!("FluxCD health check failed …")` closer.
//!
//! Pre-lift each of the two sites spelled the same three lockstep
//! `println!` literals verbatim:
//!
//! ```ignore
//! println!("Debug commands:");
//! println!("  flux get all                  # Show all FluxCD resources");
//! println!("  flux logs --all-namespaces    # Check FluxCD controller logs");
//! ```
//!
//! Six identical printed bytes across two failure diagnostics is a
//! two-site duplication class: a future re-branding of the debug-command
//! vocabulary (adding a `flux events` row, promoting the block to
//! `.dimmed()` so it recedes beneath the surrounding red banner, or
//! wiring an OTLP `flux_debug_hint_shown` event alongside the print)
//! would have to touch both sites in lockstep, and a caller adding a
//! third failure diagnostic in a future FluxCD-related surface would
//! copy the stanza a third time. Post-lift each site calls
//! [`print_flux_debug_commands_hint`] and the vocabulary lives at one
//! typed body.
//!
//! # Byte-oracle
//!
//! [`write_flux_debug_commands_hint`] is the writer-taking sibling — a
//! `Vec<u8>` sink lets tests pin the exact rendered bytes (three lines,
//! each terminated by `\n`, no ANSI escape, the two `flux …` rows
//! indented with two ASCII spaces and column-aligned with an ASCII
//! `#` comment marker) at one site rather than as two lockstep
//! triples across `commands/flux.rs`.

use std::io;

/// The heading line every pre-lift site spelled — the plain ASCII
/// `Debug commands:` label with no glyph, no color, no indent. Named
/// as a `pub const` so a future re-branding (a leading `🔧 ` wrench,
/// a `.dimmed()` promotion, a translation) reaches one site rather
/// than two.
pub const FLUX_DEBUG_HINT_HEADING: &str = "Debug commands:";

/// The `flux get all` diagnostic row — two-space indent, the invocation,
/// column padding to place the `#` comment marker at the same column
/// as the sibling row below, then a human-readable purpose. The exact
/// whitespace layout is load-bearing: a re-alignment of one row without
/// the other would flip this const and the sibling
/// [`FLUX_DEBUG_HINT_LOGS_ROW`] out of column-alignment.
pub const FLUX_DEBUG_HINT_GET_ALL_ROW: &str =
    "  flux get all                  # Show all FluxCD resources";

/// The `flux logs --all-namespaces` diagnostic row — two-space indent,
/// the invocation, column padding to place the `#` comment marker at
/// the same column as the sibling row above, then a human-readable
/// purpose. See [`FLUX_DEBUG_HINT_GET_ALL_ROW`] for the column-alignment
/// invariant.
pub const FLUX_DEBUG_HINT_LOGS_ROW: &str =
    "  flux logs --all-namespaces    # Check FluxCD controller logs";

/// Emit the canonical three-line FluxCD debug-commands hint block to
/// stdout. Called immediately above the `bail!("FluxCD health check
/// failed …")` closer at each of the two `commands/flux.rs`
/// health-check-failure sites to hand the operator two ready-to-paste
/// diagnostic invocations for the FluxCD control plane.
///
/// Pre-lift each site spelled the block verbatim as three lockstep
/// `println!` literals; post-lift each site calls this function and
/// inherits the canonical vocabulary from one site. A future adjustment
/// (adding a `flux events` row, dropping the emoji-free grammar for a
/// leading `🔧 ` wrench, promoting the block to `.dimmed()` so it recedes
/// beneath the surrounding red banner) reaches ONE typed body rather
/// than two lockstep sites.
///
/// Delegates to [`write_flux_debug_commands_hint`] against
/// [`std::io::stdout`]; the writer split exists so the fail-before-pass
/// byte-oracle test pins the exact rendered bytes without capturing
/// stdout.
pub fn print_flux_debug_commands_hint() {
    let _ = write_flux_debug_commands_hint(&mut io::stdout().lock());
}

/// Writer-taking sibling to [`print_flux_debug_commands_hint`]. Emits
/// the three-line hint block via [`writeln!`] against the supplied
/// writer.
///
/// [`print_flux_debug_commands_hint`] is the stdout adapter; this
/// variant exists so tests can pin the exact heading line, the two
/// column-aligned `flux …` rows, and the absence of every ANSI palette
/// sequence without capturing stdout.
pub fn write_flux_debug_commands_hint<W: io::Write>(w: &mut W) -> io::Result<()> {
    writeln!(w, "{}", FLUX_DEBUG_HINT_HEADING)?;
    writeln!(w, "{}", FLUX_DEBUG_HINT_GET_ALL_ROW)?;
    writeln!(w, "{}", FLUX_DEBUG_HINT_LOGS_ROW)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fail-before-pass envelope for [`write_flux_debug_commands_hint`].
    /// Pins the three-line hint block every pre-lift consumer spelled
    /// verbatim: the plain ASCII `Debug commands:` heading, then the
    /// two-space-indented `flux get all` row with column-padded `#`
    /// comment, then the two-space-indented `flux logs --all-namespaces`
    /// row with column-padded `#` comment. A silent drift a future
    /// rewrite might introduce — dropping a row, re-aligning one
    /// row's `#` column without the other, re-branding the heading —
    /// flips this assertion rather than compiling and silently
    /// diverging the two consumer sites' visual grammar.
    #[test]
    fn write_flux_debug_commands_hint_emits_three_line_block_verbatim() {
        let mut buf: Vec<u8> = Vec::new();
        write_flux_debug_commands_hint(&mut buf)
            .expect("write_flux_debug_commands_hint against a Vec<u8> writer must succeed");
        let out = String::from_utf8(buf).expect(
            "write_flux_debug_commands_hint must emit valid UTF-8 \
             (the pre-lift println!s did)",
        );
        assert_eq!(
            out,
            "Debug commands:\n  \
             flux get all                  # Show all FluxCD resources\n  \
             flux logs --all-namespaces    # Check FluxCD controller logs\n",
            "byte-oracle: the three-line hint block must render verbatim — \
             `Debug commands:\\n` + two-space-indent `flux get all` row \
             + two-space-indent `flux logs --all-namespaces` row, each \
             terminated by `\\n`, no ANSI escape, no other glyph"
        );
    }

    /// A silent promotion of the primitive to `.bold()` / `.dimmed()` /
    /// any `.<color>()` chain would flatten the plain-ASCII grammar
    /// the pre-lift two sites deliberately kept as uncolored stdout so
    /// the surrounding red-banner `.red().bold()` diagnostics carry the
    /// operator's eye rather than the paste-ready invocations. This
    /// shield pins the absence of every ANSI escape byte so a color-
    /// chain promotion surfaces here rather than silently coloring two
    /// failure diagnostics.
    #[test]
    fn write_flux_debug_commands_hint_carries_no_ansi_escape_byte() {
        let mut buf: Vec<u8> = Vec::new();
        write_flux_debug_commands_hint(&mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(
            !out.contains('\x1b'),
            "write_flux_debug_commands_hint must carry NO ANSI escape byte \
             (`\\x1b`) — the pre-lift `println!(\"Debug commands:\")` block \
             reaches stdout uncolored so the surrounding red-banner \
             diagnostics carry the operator's eye. A `.bold()` / \
             `.dimmed()` / `.<color>()` promotion would flatten the \
             grammar. Got {out:?}"
        );
    }

    /// The two `flux …` rows MUST place the `#` comment marker at the
    /// same column so the human-readable purposes line up in the
    /// terminal. Compute each row's `#` byte-offset from its start and
    /// require them equal — a re-alignment of one row without the
    /// other (e.g., renaming `--all-namespaces` to `-A` without
    /// re-padding, or promoting `flux get all` to `flux get all -A`
    /// without re-padding) flips this invariant rather than silently
    /// misaligning the terminal display the pre-lift sites shipped.
    #[test]
    fn flux_debug_hint_rows_column_align_the_comment_marker() {
        let get_hash = FLUX_DEBUG_HINT_GET_ALL_ROW
            .find('#')
            .expect("FLUX_DEBUG_HINT_GET_ALL_ROW must contain a `#` comment marker");
        let logs_hash = FLUX_DEBUG_HINT_LOGS_ROW
            .find('#')
            .expect("FLUX_DEBUG_HINT_LOGS_ROW must contain a `#` comment marker");
        assert_eq!(
            get_hash, logs_hash,
            "the two pre-lift `flux …` rows column-align their `#` \
             comment markers so the human-readable purposes line up in \
             a terminal. Got `flux get all` `#` at column {get_hash} \
             and `flux logs --all-namespaces` `#` at column {logs_hash}. \
             A re-alignment of one row without the other silently \
             misaligns the two-line block the pre-lift sites shipped."
        );
    }

    /// Whole-module negative caller shield: no raw `println!(\"Debug
    /// commands:\")` may live in `commands/flux.rs`. Post-lift the two
    /// pre-lift sites each forward through [`print_flux_debug_commands_hint`];
    /// a future re-inline (a "just call `println!` directly, it's
    /// shorter" cleanup) silently reopens the two-site duplication
    /// class this lift closed.
    ///
    /// Enforced against the module body BEFORE its first `#[cfg(test)]`
    /// region so a test-support mention of the raw shape does not
    /// defeat the shield.
    #[test]
    fn no_raw_debug_commands_println_survives_in_flux() {
        const SOURCE: &str = include_str!("flux.rs");
        let body =
            crate::test_support::module_body_before_first_cfg_test(SOURCE, "commands/flux.rs");
        const NEEDLE: &str = "println!(\"Debug commands:\")";
        for (i, line) in body.lines().enumerate() {
            assert!(
                !line.contains(NEEDLE),
                "commands/flux.rs:{lineno} spells the pre-lift inline \
                 `println!(\"Debug commands:\")` heading — that shape \
                 was lifted onto `crate::commands::flux_debug_commands_hint::\
                 print_flux_debug_commands_hint`. A re-inline silently \
                 reopens the two-site duplication class this shield \
                 exists to close. Offending line: {line:?}",
                lineno = i + 1
            );
        }
    }

    /// Whole-module negative caller shield: no raw `flux get all …
    /// Show all FluxCD resources` diagnostic row may live inline in
    /// `commands/flux.rs`. Pins the sibling row alongside the heading
    /// shield above so a re-inline that copied only the two indented
    /// rows (dropping the heading, or vice versa) still trips a shield.
    #[test]
    fn no_raw_flux_get_all_diagnostic_row_survives_in_flux() {
        const SOURCE: &str = include_str!("flux.rs");
        let body =
            crate::test_support::module_body_before_first_cfg_test(SOURCE, "commands/flux.rs");
        const NEEDLE: &str = "flux get all                  # Show all FluxCD resources";
        for (i, line) in body.lines().enumerate() {
            assert!(
                !line.contains(NEEDLE),
                "commands/flux.rs:{lineno} spells the pre-lift inline \
                 `flux get all …` diagnostic-row literal — that shape \
                 was lifted onto `crate::commands::flux_debug_commands_hint::\
                 FLUX_DEBUG_HINT_GET_ALL_ROW` and reaches stdout through \
                 `print_flux_debug_commands_hint`. Offending line: {line:?}",
                lineno = i + 1
            );
        }
    }

    /// Positive delegation shield — `commands/flux.rs` must forward
    /// through [`print_flux_debug_commands_hint`] at exactly two sites
    /// (one per pre-lift consumer). A fusion that folded the two sites
    /// into one call or dropped one of the hint blocks silently fails
    /// here — the negative half above would still pass, but the
    /// positive count would fall below the pre-lift census.
    #[test]
    fn flux_module_forwards_through_debug_commands_hint_primitive_twice() {
        const SOURCE: &str = include_str!("flux.rs");
        let body =
            crate::test_support::module_body_before_first_cfg_test(SOURCE, "commands/flux.rs");
        const FORWARD_NEEDLE: &str = "flux_debug_commands_hint::print_flux_debug_commands_hint(";
        let forward_hits = body.matches(FORWARD_NEEDLE).count();
        assert_eq!(
            forward_hits, 2,
            "commands/flux.rs body must forward to \
             `crate::commands::flux_debug_commands_hint::\
             print_flux_debug_commands_hint(...)` at exactly 2 sites \
             — one per pre-lift consumer (the immediate-fail arm of \
             the initial health-check body and the post-timeout arm of \
             `health_check_with_retry`). Found {forward_hits} forwarding hits."
        );
    }
}
