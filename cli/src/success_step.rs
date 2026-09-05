//! Info-routed success-acknowledge grammar.
//!
//! Twenty-three pre-lift sibling sites across `commands/{build (×3), comprehensive_release
//! (×1), deploy (×2), github_runner_ci (×6), integration_tests (×1),
//! nix_builder (×6), rollout (×1)}.rs` plus two crate-top-level modules
//! `cloudflare.rs` (×1) and `nix_hooks.rs` (×2) each restated the
//! `info!("✅ <fmt>", <args>)` stanza verbatim — a `✅` glyph (U+2705,
//! standalone, no variation selector), one ASCII space, a per-site
//! success message, and an `info!`-routed emission via the tracing
//! subscriber. Post-lift the sites reach for [`info_success!`] and the
//! prefix + separator + tracing verbosity are decided once here.
//!
//! # Distinct from the sibling success primitives
//!
//! The crate already carries several success-adjacent primitives, and
//! each is the sole home for its distinct semantic layer:
//!
//! - [`crate::ui::print_success`] / [`crate::ui::write_success`] narrate
//!   a MILESTONE-completion banner via `println!` on the
//!   `"✅ <MSG>".bright_green().bold()` colored-and-styled shape — a
//!   direct-to-stdout render targeted at the interactive operator's
//!   terminal at a workflow's terminal boundary (a build finished, a
//!   push finished, a bootstrap finished).
//! - [`crate::ui::print_step_ok`] narrates a mid-workflow per-step
//!   status via `println!` on the `"   OK <fmt>"` three-space-indented
//!   text-label shape used by the release-phase step readouts in
//!   `product_release` / `rollback`.
//! - [`crate::ui::print_report_item`] narrates a summary-check line via
//!   `println!` on the `"  ✓ <msg>"` two-space `.green()` shape used by
//!   the post-run report bodies.
//! - [`info_success!`] (this macro) narrates a mid-run structured
//!   success acknowledgement via [`tracing::info!`] — the subscriber
//!   pipeline (structured logging, filter, OTLP export, per-module_path
//!   routing) processes the record with the exact call site's
//!   `module_path` / `file` / `line`.
//!
//! The sites carry different destinations and different filter paths
//! deliberately; a collapse into one primitive would either drop the
//! tracing-subscriber routing [`info_success!`] needs (breaking OTLP
//! export of mid-run successes) or bolt colored terminal paint onto
//! non-interactive log records that must stay ANSI-free (the crate's
//! [`tracing_subscriber`] initialization in `main.rs` deliberately sets
//! `with_ansi(false)`).
//!
//! # The load-bearing single-space separator
//!
//! The pre-lift twenty-two sites all spell `"✅ <msg>"` with EXACTLY ONE
//! ASCII space between the glyph and the message body. This is deliberate
//! and distinct from the fleet's [`crate::warn_nonfatal!`] and
//! [`crate::info_skipping!`] siblings, both of which use TWO ASCII spaces
//! after their (variation-selector-bearing) emoji. The ✅ glyph
//! (U+2705) has no variation selector — it is already a fully-qualified
//! emoji — so a second ASCII space would visually widen the gap versus
//! the two-space `⚠️  ` / `⏭️  ` shapes rather than align with them.
//! The primitive pins the one-space grammar so a future collapse to the
//! two-space form (e.g. someone reading only `nonfatal_warning.rs` and
//! extrapolating) hits the byte-oracle test rather than shipping.
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
//! emission moved to `forge::success_step`). The byte-oracle writer
//! sibling [`write_success_step`] captures the exact rendered body for
//! the tests (the `✅` glyph, the one-space gap, the trailing newline)
//! so the invariant is pinned without racing an ambient tracing
//! subscriber — the same split
//! [`crate::nonfatal_warning::write_nonfatal_warn`] carries against
//! [`crate::warn_nonfatal!`] and
//! [`crate::skipping_step::write_skipping_step`] carries against
//! [`crate::info_skipping!`].

use std::fmt;
use std::io;

/// Emits a single `"✅ <message>"` line via [`writeln!`] against the
/// supplied writer, wrapping the message with the pre-lift `✅ ` +
/// one-ASCII-space prefix that twenty-two sibling sites spelled inline.
///
/// The [`crate::info_success!`] macro is the [`tracing::info!`] adapter
/// that production code invokes; this direct-writer variant exists so
/// the fail-before-pass tests can pin the exact emitted bytes (the
/// single-space gap after the `✅` glyph, the trailing newline) without
/// capturing a tracing subscriber and without racing an ambient logger
/// — the same split
/// [`crate::nonfatal_warning::write_nonfatal_warn`] carries against
/// [`crate::warn_nonfatal!`].
///
/// The `message` parameter accepts any [`fmt::Display`] rather than a
/// concrete `&str` so a bare literal (used by many pre-lift call sites),
/// a `String` / `Cow<str>`, an `anyhow::Error`-shaped Display, and a
/// future success-descriptor type carrying structured fields all flow
/// through the same writer without a per-caller `.to_string()`
/// intermediate.
#[allow(dead_code)] // See doc comment: the writer is a test/byte-oracle
                    // peer of the tracing-routed `info_success!` macro,
                    // and a future `collect_success_steps` summary
                    // sibling will consume it directly.
pub fn write_success_step<W: io::Write>(w: &mut W, message: &dyn fmt::Display) -> io::Result<()> {
    writeln!(w, "\u{2705} {}", message)
}

/// Emit a mid-run success acknowledgement via [`tracing::info!`] on the
/// fleet-standard `"✅ <message>"` grammar.
///
/// The macro expands to a direct `::tracing::info!(...)` call at the
/// caller's location so tracing's automatic source-location capture is
/// preserved (a function wrapper would collapse every emission to the
/// wrapper's site — see the module docs for why that breaks per-module
/// filter routing). See the [module docs](self) for the sibling site
/// census, the split against [`crate::ui::print_success`] /
/// [`crate::ui::print_step_ok`] / [`crate::ui::print_report_item`], and
/// the compounding rationale for the load-bearing single-space
/// separator.
///
/// # Examples
///
/// ```ignore
/// // Pre-lift
/// info!("✅ Attic configured");
/// info!("✅ Service {} is accessible on port {}", service, port);
///
/// // Post-lift
/// crate::info_success!("Attic configured");
/// crate::info_success!("Service {} is accessible on port {}", service, port);
/// ```
#[macro_export]
macro_rules! info_success {
    ($($arg:tt)*) => {
        ::tracing::info!("\u{2705} {}", ::std::format_args!($($arg)*))
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    // Pin the exact prefix bytes: `✅` (U+2705, 3 bytes E2 9C 85, no
    // variation selector), one ASCII space, the interpolated message
    // Display, then `\n`. A future refactor that adds a variation
    // selector, widens the one-space gap to two, or drops the trailing
    // newline regresses this assertion.
    #[test]
    fn write_success_step_emits_prefix_message_and_newline() {
        let mut buf: Vec<u8> = Vec::new();
        write_success_step(&mut buf, &"Attic configured").unwrap();
        assert_eq!(buf, b"\xe2\x9c\x85 Attic configured\n");
    }

    // Human-readable pin of the exact grammar so a future reader can
    // eyeball the render without decoding bytes. Doubles as a Display-
    // forwarding pin: the `&dyn Display` slot receives a message whose
    // rendered form contains a colon and interpolated substrings; the
    // interior punctuation MUST survive verbatim without the writer
    // re-quoting or re-escaping the inner text.
    #[test]
    fn write_success_step_forwards_multi_segment_message_display() {
        let mut buf: Vec<u8> = Vec::new();
        write_success_step(&mut buf, &"Service kraken is accessible on port 8080").unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "\u{2705} Service kraken is accessible on port 8080\n"
        );
    }

    // Guard against the two-space grammar drift: `⚠️  ` and `⏭️  `
    // siblings both use two ASCII spaces (their emoji carry variation
    // selectors and are visually narrower without the extra space).
    // `✅` is already fully-qualified emoji, so a two-space gap would
    // visually widen the label off the neighboring siblings rather than
    // align with them. Pin the negative shape explicitly so a future
    // reader who reaches for the sibling grammar hits this test.
    #[test]
    fn write_success_step_does_not_use_two_space_grammar() {
        let mut buf: Vec<u8> = Vec::new();
        write_success_step(&mut buf, &"Attic configured").unwrap();
        let rendered = String::from_utf8(buf).unwrap();
        assert!(
            !rendered.contains("\u{2705}  "),
            "success-step render must use a one-space gap after ✅, \
             not the two-space gap the ⚠️/⏭️ siblings use; got: {:?}",
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
    fn info_success_macro_compiles_with_supported_arg_shapes() {
        // Bare literal (many pre-lift call sites).
        crate::info_success!("Attic configured");
        // Bare literal with trailing punctuation (nix_builder shape).
        crate::info_success!("nix-builder verification complete!");
        // Runtime `&str` interpolated through `{}`.
        let target = "kraken";
        crate::info_success!("{}", target);
        // Multi-arg format string (nix_builder Service/port shape).
        crate::info_success!("Service {} is accessible on port {}", target, 8080);
        // Trailing comma is legal.
        crate::info_success!("trailing comma message",);
        // Owned `String` via `{}`.
        let owned = String::from("owned string message");
        crate::info_success!("{}", owned);
    }

    // Caller shield: no source line under `cli/src/commands/` may spell
    // the pre-lift shape `info!("✅ ...")` inline any more. Every
    // info-routed success acknowledgement must route through
    // `crate::info_success!`, which expands to the canonical
    // `tracing::info!(...)` call at the caller's location.
    //
    // The shield scans EVERY `commands/*.rs` module rather than only
    // the pre-lift files so a future workflow-step orchestrator that
    // surfaces a new mid-run success (a new sub-step in a new command
    // module) reaches for `info_success!` on first grep, not by copy-
    // pasting a raw `info!("✅ ...")` stanza from build.rs.
    //
    // The needle is anchored on the emoji + one-space gap so a future
    // variant that reaches for a different marker (`✔️ `, `[OK] `,
    // `SUCCESS: `) is out of scope; the needle catches only the exact
    // pre-lift shape, and the shield's positive half (the delegation-
    // count assertion below) forces future variants of the SAME shape
    // through the primitive too.
    #[test]
    fn no_command_module_still_spells_raw_info_success() {
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
                if line.contains("info!(\"\u{2705} ") {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `info!(\"\u{2705} ...\")` stanza(s) survive under \
             `commands/` — route each through `crate::info_success!(<msg>)` \
             instead:\n{:#?}",
            offenders
        );
    }

    // Positive half of the shield: the seven pre-lift files under
    // `commands/` MUST each forward through `crate::info_success!(` at
    // least the pre-lift count of times (twenty of the twenty-three
    // pre-lift sites live under `commands/`; three live in the two
    // crate-top-level sibling modules noted in the module docs), so a
    // migration that dropped a call site outright leaves the negative
    // "no raw inline shape" scan trivially satisfied by absence but the
    // positive count still fails.
    //
    // Only `commands/*.rs` files are pinned here; the two sibling sites
    // in `cli/src/cloudflare.rs` (×1) and `cli/src/nix_hooks.rs` (×2)
    // are outside the `commands/` shield's scope but still migrate to
    // `crate::info_success!` — a grep of the crate for the pre-lift
    // shape returns zero hits post-lift regardless.
    #[test]
    fn every_prelift_module_forwards_through_info_success_macro() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        // (module basename, minimum forward count from the pre-lift census)
        let expectations: &[(&str, usize)] = &[
            ("build.rs", 3),
            ("comprehensive_release.rs", 1),
            ("deploy.rs", 2),
            ("github_runner_ci.rs", 6),
            ("integration_tests.rs", 1),
            ("nix_builder.rs", 6),
            ("rollout.rs", 1),
        ];
        for (basename, min_count) in expectations {
            let path = commands_dir.join(basename);
            let source = std::fs::read_to_string(&path).unwrap();
            let forwards = source.matches("crate::info_success!(").count();
            assert!(
                forwards >= *min_count,
                "{basename} must forward at least {min_count} success \
                 acknowledgement site(s) through `crate::info_success!(`; \
                 found {forwards}. A dropped call would leave the negative \
                 raw-shape scan satisfied by absence.",
            );
        }
    }
}
