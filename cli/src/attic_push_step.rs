//! Info-routed `📤 Pushing to Attic cache...` phase-announce grammar.
//!
//! Two pre-lift sibling sites across `commands/{push (×1:
//! post-`AtticClient::discover` decision preamble inside the
//! `push_attic` arm, immediately above the
//! `AtticClient::push_optional` chain), github_runner_ci (×1:
//! post-`crate::info_success!("Build complete: result-runner")`
//! preamble inside the build-step arm, immediately above the
//! `AtticClient::push_with_retries` chain)}.rs` each restated the
//!
//! ```ignore
//! info!("📤 Pushing to Attic cache...");
//! ```
//!
//! stanza verbatim — a `📤` glyph (U+1F4E4 OUTBOX TRAY, standalone,
//! no variation selector, 4 bytes UTF-8), one ASCII space, the
//! literal `Pushing to Attic cache...` body (26 bytes ending in three
//! ASCII dots, not a U+2026 HORIZONTAL ELLIPSIS), and an `info!`-
//! routed emission via the tracing subscriber. Post-lift the sites
//! reach for [`info_attic_push!`] and the emoji, body, and tracing
//! verbosity are decided once here.
//!
//! # Distinct from the sibling Attic-phase primitives
//!
//! The crate carries a family of Attic-adjacent primitives, and each is
//! the sole home for its distinct semantic layer:
//!
//! - [`crate::infrastructure::attic::AtticClient::push_with_retries`] /
//!   `push_optional` perform the closure push itself, structured-error
//!   surfaced via [`crate::infrastructure::attic::AtticError`].
//! - [`crate::infrastructure::attic::AtticClient::login_with_retries`]
//!   performs the login itself, similarly typed.
//! - [`crate::info_attic_configure!`] narrates the *configure phase*
//!   opening (`🔧 Configuring Attic cache...`).
//! - [`info_attic_push!`] (this macro) narrates the *push phase*
//!   opening — a mid-preamble structured log record emitted before
//!   the `push_with_retries` / `push_optional` call begins, so a
//!   consumer filtering the tracing pipeline by module_path or a
//!   CI-log tail sees the phase boundary without needing to correlate
//!   the surrounding client calls.
//!
//! The sites carry different destinations and different filter paths
//! deliberately; a collapse into the client primitives would either
//! bury the phase-open narration inside the client's own body (a caller
//! that skipped the client for a probe-only path would drop the phase
//! marker) or force the client to grow a phase-narration side-effect
//! its callers do not universally want.
//!
//! # The `📤` OUTBOX TRAY glyph, not `📦` PACKAGE or `🔧` WRENCH
//!
//! Both pre-lift sites spell the glyph as `📤` (U+1F4E4 OUTBOX TRAY)
//! — the fleet's mental anchor for "this is a transmit / push
//! action". The `🔧` WRENCH glyph is reserved for configuration
//! phase-opens (`🔧 Configuring Attic cache...`), the `📦` PACKAGE
//! glyph for build-input identity readouts (`Git SHA:`, `Image
//! path:`), and the `🎯` DIRECT HIT glyph for destination readouts
//! (`Registry:`, `Target:`). A future refactor that flipped this
//! primitive's glyph to WRENCH or PACKAGE would silently merge the
//! transmit-vs-configure-vs-identify-vs-destination semantic split
//! the four-glyph convention establishes across the Attic-adjacent
//! surface.
//!
//! # The load-bearing single-space separator
//!
//! Both pre-lift sites spell `"📤 Pushing to Attic cache..."` with
//! EXACTLY ONE ASCII space between the glyph and the `Pushing`
//! body. This is deliberate and distinct from the fleet's
//! [`crate::warn_nonfatal!`] and [`crate::info_skipping!`] siblings,
//! both of which use TWO ASCII spaces after their (variation-
//! selector-bearing) emoji. The `📤` glyph (U+1F4E4) has no variation
//! selector — it is already a fully-qualified emoji — so a second
//! ASCII space would visually widen the gap versus the one-space
//! `🔧 Configuring ...` / `📦 Git SHA:` / `🎯 Registry:` sibling
//! family. The primitive pins the one-space grammar so a future
//! collapse to the two-space form (e.g. someone reading only
//! `nonfatal_warning.rs` and extrapolating) hits the byte-oracle test
//! rather than shipping.
//!
//! # Preserving `tracing::info!` at the call site
//!
//! The macro expands to `::tracing::info!(...)` at the caller's
//! location, not to a function wrapper, so tracing's automatic
//! source-location capture (`file` + `line` + `module_path`) matches
//! the pre-lift behavior byte-for-byte. A function-based wrapper
//! would collapse every emission to the wrapper's own site and break
//! structured-log destinations that filter by module_path
//! (`RUST_LOG=forge::commands::push=info` would stop matching once
//! the emission moved to `forge::attic_push_step`). The byte-oracle
//! writer sibling [`write_attic_push_step`] captures the exact
//! rendered body for the tests (the `📤` glyph, the one-space gap,
//! the literal `Pushing to Attic cache...` body, the trailing
//! newline) so the invariant is pinned without racing an ambient
//! tracing subscriber — the same split
//! [`crate::attic_configure_step::write_attic_configure_step`]
//! carries against [`crate::info_attic_configure!`] and
//! [`crate::registry_field::write_registry_field`] carries against
//! [`crate::info_registry_field!`].

use std::io;

/// Emits a single `"📤 Pushing to Attic cache...\n"` line via
/// [`writeln!`] against the supplied writer — the pre-lift `📤 ` +
/// one-ASCII-space + `Pushing to Attic cache...` phase-announce that
/// two sibling sites spelled inline.
///
/// The [`crate::info_attic_push!`] macro is the [`tracing::info!`]
/// adapter that production code invokes; this direct-writer variant
/// exists so the fail-before-pass tests can pin the exact emitted
/// bytes (the single-space gap after the `📤` glyph, the literal
/// body, the trailing newline) without capturing a tracing subscriber
/// and without racing an ambient logger — the same split
/// [`crate::attic_configure_step::write_attic_configure_step`]
/// carries against [`crate::info_attic_configure!`] and
/// [`crate::registry_field::write_registry_field`] carries against
/// [`crate::info_registry_field!`].
#[allow(dead_code)] // See doc comment: the writer is a test/byte-oracle
                    // peer of the tracing-routed `info_attic_push!`
                    // macro, and a future
                    // `collect_attic_push_events` summary sibling
                    // will consume it directly.
pub fn write_attic_push_step<W: io::Write>(w: &mut W) -> io::Result<()> {
    writeln!(w, "\u{1F4E4} Pushing to Attic cache...")
}

/// Emit an Attic-push phase-announce via [`tracing::info!`] on the
/// fleet-standard `"📤 Pushing to Attic cache..."` grammar.
///
/// The macro expands to a direct `::tracing::info!(...)` call at the
/// caller's location so tracing's automatic source-location capture
/// is preserved (a function wrapper would collapse every emission to
/// the wrapper's site — see the module docs for why that breaks per-
/// module filter routing). See the [module docs](self) for the
/// sibling site census, the split against
/// [`crate::infrastructure::attic::AtticClient`] (which performs the
/// push itself), and the compounding rationale for the load-bearing
/// single-space separator.
///
/// # Examples
///
/// ```ignore
/// // Pre-lift
/// info!("📤 Pushing to Attic cache...");
///
/// // Post-lift
/// crate::info_attic_push!();
/// ```
#[macro_export]
macro_rules! info_attic_push {
    () => {
        ::tracing::info!("\u{1F4E4} Pushing to Attic cache...")
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    // Pin the exact bytes: `📤` (U+1F4E4, 4 bytes F0 9F 93 A4, no
    // variation selector), one ASCII space, the literal `Pushing to
    // Attic cache...` (26 bytes), then `\n`. A future refactor that
    // adds a variation selector, widens the one-space gap to two,
    // changes the label capitalization, drops or adds an ellipsis
    // dot, or drops the trailing newline regresses this assertion.
    #[test]
    fn write_attic_push_step_emits_exact_bytes() {
        let mut buf: Vec<u8> = Vec::new();
        write_attic_push_step(&mut buf).unwrap();
        assert_eq!(buf, b"\xf0\x9f\x93\xa4 Pushing to Attic cache...\n");
    }

    // Human-readable pin of the exact grammar so a future reader can
    // eyeball the render without decoding bytes.
    #[test]
    fn write_attic_push_step_renders_expected_grammar() {
        let mut buf: Vec<u8> = Vec::new();
        write_attic_push_step(&mut buf).unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "\u{1F4E4} Pushing to Attic cache...\n"
        );
    }

    // Guard against the two-space grammar drift: `⚠️  ` and `⏭️  `
    // siblings both use two ASCII spaces (their emoji carry variation
    // selectors and are visually narrower without the extra space).
    // `📤` is already fully-qualified emoji, so a two-space gap would
    // visually widen the label off the neighboring one-space
    // `🔧 Configuring ...` / `📦 Git SHA:` / `🎯 Registry:` shape
    // rather than align with them. Pin the negative shape explicitly
    // so a future reader who reaches for the sibling grammar hits
    // this test.
    #[test]
    fn write_attic_push_step_does_not_use_two_space_grammar() {
        let mut buf: Vec<u8> = Vec::new();
        write_attic_push_step(&mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(
            !s.starts_with("\u{1F4E4}  "),
            "write_attic_push_step must NOT emit two ASCII spaces \
             after the `📤` glyph — the fleet-standard one-space grammar \
             for fully-qualified emoji is load-bearing. Actual: {s:?}",
        );
    }

    // Guard against variation-selector drift: `📤` (U+1F4E4) is
    // deliberately used as a bare 4-byte glyph. A future refactor
    // that appended U+FE0F would silently break byte-oracle
    // downstream comparators. Pin the exact 4-byte encoding.
    #[test]
    fn write_attic_push_step_does_not_append_variation_selector() {
        let mut buf: Vec<u8> = Vec::new();
        write_attic_push_step(&mut buf).unwrap();
        // Byte 4 must be an ASCII space (0x20), not the first byte of
        // U+FE0F (which is 0xEF).
        assert_eq!(
            buf[4], 0x20,
            "byte 4 must be an ASCII space (0x20); a U+FE0F variation \
             selector would place 0xEF there and break the byte-oracle. \
             Bytes: {buf:?}",
        );
    }

    // Guard against glyph drift: `📤` (U+1F4E4, F0 9F 93 A4) is the
    // push-phase semantic anchor. Sibling glyphs `🔧` WRENCH
    // (U+1F527, F0 9F 94 A7 — configure phase), `📦` PACKAGE
    // (U+1F4E6, F0 9F 93 A6 — Git-SHA / artifact identity), and `🎯`
    // DIRECT HIT (U+1F3AF, F0 9F 8E AF — destination registry /
    // target) each carry different semantic layers. A future refactor
    // that flipped this primitive's glyph would silently merge the
    // transmit-vs-configure-vs-identify-vs-destination semantic split
    // the four-glyph convention establishes across the Attic-adjacent
    // surface. Pin all four glyph bytes.
    #[test]
    fn write_attic_push_step_emits_outbox_tray_glyph() {
        let mut buf: Vec<u8> = Vec::new();
        write_attic_push_step(&mut buf).unwrap();
        assert_eq!(
            &buf[0..4],
            &[0xf0, 0x9f, 0x93, 0xa4],
            "write_attic_push_step must emit U+1F4E4 OUTBOX TRAY \
             (F0 9F 93 A4), NOT U+1F527 WRENCH (F0 9F 94 A7), \
             U+1F4E6 PACKAGE (F0 9F 93 A6), or U+1F3AF DIRECT HIT \
             (F0 9F 8E AF). Bytes: {buf:?}",
        );
    }

    // No-ANSI guard: the crate's `tracing_subscriber` initialization
    // in `main.rs` deliberately sets `with_ansi(false)` so CI log
    // ingestion sees clean records. Pin that this primitive's render
    // carries no ANSI escape byte (0x1B) — a future refactor that
    // reached for `colored` on the label side would break the ANSI-
    // free contract the tracing-routed sites depend on.
    #[test]
    fn write_attic_push_step_emits_no_ansi_escape() {
        let mut buf: Vec<u8> = Vec::new();
        write_attic_push_step(&mut buf).unwrap();
        assert!(
            !buf.contains(&0x1b),
            "write_attic_push_step must emit no ANSI escape (0x1B) \
             — the tracing subscriber is configured `with_ansi(false)`. \
             Bytes: {buf:?}",
        );
    }

    // Ellipsis pin: the pre-lift body ends with THREE ASCII dots
    // (0x2E 0x2E 0x2E), NOT the single-code-point Unicode HORIZONTAL
    // ELLIPSIS (U+2026, three bytes E2 80 A6). A future refactor that
    // normalized the ellipsis to the single glyph would silently
    // break byte-oracle downstream comparators. Pin the exact tail
    // bytes before the newline.
    #[test]
    fn write_attic_push_step_uses_three_ascii_dots_not_unicode_ellipsis() {
        let mut buf: Vec<u8> = Vec::new();
        write_attic_push_step(&mut buf).unwrap();
        let n = buf.len();
        assert_eq!(
            &buf[n - 4..n],
            b"...\n",
            "write_attic_push_step must end with three ASCII dots \
             (2E 2E 2E) then a newline, NOT a U+2026 HORIZONTAL \
             ELLIPSIS (E2 80 A6). Bytes: {buf:?}",
        );
    }

    // The macro forwards to `::tracing::info!` at the caller's
    // location. The subscriber cannot be captured in-process without
    // racing whatever subscriber `main` installs. Instead, pin that
    // the macro's zero-arg invocation shape expands at compile time
    // — a compile-fail here would fail the crate's `cargo test`
    // build gate.
    #[test]
    fn info_attic_push_macro_compiles() {
        crate::info_attic_push!();
    }

    // Caller shield: no source line under `cli/src/commands/` may
    // spell the pre-lift raw `info!("📤 Pushing to Attic cache...");`
    // stanza inline any more. The two pre-lift sites migrated; any
    // future consumer that wants the same grammar reaches for
    // `crate::info_attic_push!` on first grep, not by copy-pasting
    // the raw shape from an existing command module.
    #[test]
    fn no_command_module_still_spells_raw_info_attic_push_stanza() {
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
                // Skip comment lines so this shield's own reference
                // to the pre-lift shape in prose doesn't self-hit.
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") || trimmed.starts_with("///") {
                    continue;
                }
                if line.contains("info!(\"\u{1F4E4} Pushing to Attic cache...\")") {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `info!(\"\u{1F4E4} Pushing to Attic cache...\");` \
             stanza(s) survive under `commands/` — route each through \
             `crate::info_attic_push!()` instead:\n{:#?}",
            offenders
        );
    }

    // Positive half of the shield: the two pre-lift files MUST each
    // forward through `crate::info_attic_push!(` at least once, so a
    // migration that dropped a call site outright leaves the negative
    // "no raw inline shape" scan trivially satisfied by absence but
    // the positive count still fails.
    #[test]
    fn every_prelift_module_forwards_through_info_attic_push_macro() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        // (module basename, minimum forward count from the pre-lift census)
        let expectations: &[(&str, usize)] = &[("push.rs", 1), ("github_runner_ci.rs", 1)];
        for (basename, min_count) in expectations {
            let path = commands_dir.join(basename);
            let source = std::fs::read_to_string(&path).unwrap();
            let forwards = source.matches("crate::info_attic_push!(").count();
            assert!(
                forwards >= *min_count,
                "{basename} must forward at least {min_count} attic-push \
                 phase-announce site(s) through `crate::info_attic_push!(`; \
                 found {forwards}. A dropped call would leave the negative \
                 raw-shape scan satisfied by absence.",
            );
        }
    }
}
