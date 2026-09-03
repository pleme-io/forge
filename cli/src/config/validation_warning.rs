//! Advisory config-validation warning grammar.
//!
//! Twelve pre-lift sibling sites across `config/{deployment (×5),
//! product (×1), release (×4), federation (×1)}.rs` +
//! `commands/service_config.rs` (×1) each restated the
//! `eprintln!("⚠️  Warning: <fmt>", <args>)` stanza verbatim — a
//! `⚠️` glyph followed by two spaces, the literal `Warning: ` prefix,
//! and an ad-hoc `<fmt>` interpolating the config field or value that
//! tripped the advisory check. Post-lift the 12 sibling sites reach
//! for [`warn_config!`], and the prefix + writer + destination are
//! decided once here.
//!
//! # Distinct from [`crate::ui::print_step_warn`]
//!
//! Both wear the `⚠️` glyph, but they carry different indent grammars,
//! different palettes, different destinations, and different semantic
//! layers. [`crate::ui::print_step_warn`] is a three-space-indented
//! `.yellow()` in-body step-warn line on **stdout** narrating a step-
//! level surprise inside a command's readout (a retry attempt failing,
//! a manifest the pipeline recovered from); the site count and shape
//! were fused at commit d360d9d. The [`warn_config!`] macro is a
//! zero-indent, uncolored, `Warning: `-prefixed line on **stderr**
//! narrating a config-load advisory whose value the config parser
//! accepted but flagged (a slice `delay_secs` outside the usual range,
//! a `staging` environment misordered, a `min_schema_size` below a
//! typical schema, an unknown `database_type` string that fell through
//! to a default). Stderr rather than stdout is deliberate: the warning
//! narrates a config problem, and a `--json` or `--quiet` command run
//! that captures stdout for machine-readable output must not
//! interleave the advisory line with the payload.
//!
//! # `format_args!` rather than `String`
//!
//! [`write_validation_warning`] takes a [`std::fmt::Arguments<'_>`]
//! rather than `impl std::fmt::Display` (or `&str`) so the macro
//! forwards `format_args!(...)` without an intermediate `String`
//! allocation — the pre-lift `eprintln!("⚠️  Warning: <fmt>", ...)`
//! spelling also passed args through `format_args!` under the hood, so
//! this preserves the byte-for-byte behavior AND the zero-allocation
//! path.
//!
//! # Compounding
//!
//! Pre-lift, a future change to how the config layer surfaces
//! advisories — routing them through `tracing::warn!` for structured
//! observability, deduplicating repeated warnings across a
//! multi-service validation pass, promoting them to hard errors under
//! `--strict` mode, or collecting them into a summary panel emitted
//! after all validation finishes — had to hit all 12 sites in
//! lockstep or drift the surface. Post-lift the writer decides the
//! prefix, the glyph spacing, and the destination once; the sites
//! carry only the per-warning message.

use std::fmt;
use std::io;

/// Emits a single `"⚠️  Warning: <message>"` line via [`writeln!`]
/// against the supplied writer, wrapping the format arguments with
/// the pre-lift prefix that 12 sibling sites spelled inline.
///
/// The [`warn_config!`] macro is the stderr adapter; this variant
/// exists so the fail-before-pass tests can pin the exact emitted
/// bytes (the two-space gap after the `⚠️` glyph, the literal
/// `Warning: ` prefix, the trailing newline) without capturing
/// stderr and without racing an ambient logger.
pub fn write_validation_warning<W: io::Write>(
    w: &mut W,
    args: fmt::Arguments<'_>,
) -> io::Result<()> {
    writeln!(w, "⚠️  Warning: {}", args)
}

/// Emits an advisory config-validation warning to stderr, wrapping
/// the format arguments in the standard `"⚠️  Warning: {}\n"`
/// grammar. See the [module docs](self) for the sibling site census
/// and the split between this macro and [`crate::ui::print_step_warn`].
///
/// # Examples
///
/// ```ignore
/// crate::warn_config!("cloudflare.files is empty, no files will be purged");
/// crate::warn_config!(
///     "First slice '{}' has delay_secs = {}, should be 0",
///     name, secs,
/// );
/// ```
#[macro_export]
macro_rules! warn_config {
    ($($arg:tt)*) => {{
        let _ = $crate::config::write_validation_warning(
            &mut ::std::io::stderr().lock(),
            ::std::format_args!($($arg)*),
        );
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    // Pin the exact prefix bytes: `⚠️` (U+26A0 U+FE0F), two ASCII
    // spaces, `Warning: `, then the interpolated message, then `\n`.
    // A future refactor that drops the variation selector, collapses
    // the two-space gap to one, or swaps the prefix casing regresses
    // this assertion.
    #[test]
    fn write_validation_warning_emits_prefix_message_and_newline() {
        let mut buf: Vec<u8> = Vec::new();
        write_validation_warning(&mut buf, format_args!("no files configured")).unwrap();
        assert_eq!(
            buf,
            b"\xe2\x9a\xa0\xef\xb8\x8f  Warning: no files configured\n"
        );
    }

    // Pins that the writer accepts a multi-argument `format_args!`
    // spelling without an intermediate `String` allocation — the
    // pre-lift `eprintln!("⚠️  Warning: <fmt>", arg1, arg2)` shape.
    #[test]
    fn write_validation_warning_interpolates_multi_arg_format() {
        let mut buf: Vec<u8> = Vec::new();
        write_validation_warning(
            &mut buf,
            format_args!("First slice '{}' has delay_secs = {}", "a", 5u32),
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "\u{26a0}\u{fe0f}  Warning: First slice 'a' has delay_secs = 5\n"
        );
    }

    // Pins that the writer preserves the literal message across a
    // `\` line continuation inside the format string — the shape
    // `config/release.rs:182` and `config/release.rs:192` used to
    // wrap a long advisory across two source lines.
    #[test]
    fn write_validation_warning_preserves_continued_format_literal() {
        let mut buf: Vec<u8> = Vec::new();
        write_validation_warning(
            &mut buf,
            format_args!(
                "'staging' is in active_environments but not first. \
                 First environment is '{}'. This may cause migration ordering issues.",
                "dev"
            ),
        )
        .unwrap();
        assert!(String::from_utf8(buf).unwrap().starts_with(
            "\u{26a0}\u{fe0f}  Warning: 'staging' is in active_environments but not first. \
             First environment is 'dev'."
        ));
    }

    // The macro forwards to the writer, but stderr can't be captured
    // in-process without racing an ambient logger. Instead, pin that
    // the macro accepts the same argument shapes the writer accepts
    // by expanding it at compile time — a compile-fail here would
    // fail the crate's `cargo test` build gate.
    #[test]
    fn warn_config_macro_compiles_with_supported_arg_shapes() {
        // No-args form (a single string literal).
        crate::warn_config!("bare message with no interpolation");
        // Positional args.
        crate::warn_config!("value = {}, name = {}", 42, "svc");
        // Trailing comma.
        crate::warn_config!("trailing comma is legal",);
    }
}
