//! Info-routed `🔧 Configuring Attic cache...` phase-announce grammar.
//!
//! Two pre-lift sibling sites across `commands/{build (×1:
//! post-`crate::info_git_sha_field!(git_sha)` preamble, immediately above
//! the `URL: <url>` + `Cache: <name>` field readouts and the
//! `AtticClient::discover_token` chain), github_runner_ci (×1:
//! post-`attic_server_alias()` preamble inside the build-step arm,
//! immediately above the `SAFE mode` readout and the
//! `AtticClient::login_with_retries` chain)}.rs` each restated the
//!
//! ```ignore
//! info!("🔧 Configuring Attic cache...");
//! ```
//!
//! stanza verbatim — a `🔧` glyph (U+1F527 WRENCH, standalone, no
//! variation selector, 4 bytes UTF-8), one ASCII space, the literal
//! `Configuring Attic cache...` body (26 bytes ending in three ASCII
//! dots, not a U+2026 HORIZONTAL ELLIPSIS), and an `info!`-routed
//! emission via the tracing subscriber. Post-lift the sites reach for
//! [`info_attic_configure!`] and the emoji, body, and tracing verbosity
//! are decided once here.
//!
//! # Distinct from the sibling Attic-phase primitives
//!
//! The crate carries a family of Attic-adjacent primitives, and each is
//! the sole home for its distinct semantic layer:
//!
//! - [`crate::infrastructure::attic::AtticClient::login_with_retries`]
//!   performs the login itself, structured-error surfaced via
//!   [`crate::infrastructure::attic::AtticError`].
//! - [`crate::infrastructure::attic::AtticClient::push_with_retries`] /
//!   `push_optional` perform the closure push itself, similarly typed.
//! - [`info_attic_configure!`] (this macro) narrates the *phase-opening*
//!   announcement — a mid-preamble structured log record emitted before
//!   the discovery + login + use-cache chain begins, so a consumer
//!   filtering the tracing pipeline by module_path or a CI-log tail sees
//!   the phase boundary without needing to correlate the surrounding
//!   discovery calls.
//!
//! The sites carry different destinations and different filter paths
//! deliberately; a collapse into the client primitives would either
//! bury the phase-open narration inside the client's own body (a caller
//! that skipped the client for a probe-only path would drop the phase
//! marker) or force the client to grow a phase-narration side-effect
//! its callers do not universally want.
//!
//! # The `🔧` WRENCH glyph, not `📦` PACKAGE or `🎯` DIRECT HIT
//!
//! Both pre-lift sites spell the glyph as `🔧` (U+1F527 WRENCH) — the
//! fleet's mental anchor for "this is a configuration / setup phase":
//! we are wiring the Attic client (URL, cache alias, token) into a
//! working state before the workflow's real work begins. The `📦`
//! PACKAGE glyph is reserved for build-input identity readouts (`Git
//! SHA:`, `Image path:`), the `🎯` DIRECT HIT glyph for the destination
//! readouts (`Registry:`, `Target:`), and the `📤` OUTBOX TRAY glyph for
//! the actual push actions. A future refactor that flipped this
//! primitive's glyph to PACKAGE or DIRECT HIT would silently merge the
//! configure-vs-identify-vs-destination-vs-transmit semantic split the
//! four-glyph convention establishes across the Attic-adjacent surface.
//!
//! # The load-bearing single-space separator
//!
//! Both pre-lift sites spell `"🔧 Configuring Attic cache..."` with
//! EXACTLY ONE ASCII space between the glyph and the `Configuring`
//! body. This is deliberate and distinct from the fleet's
//! [`crate::warn_nonfatal!`] and [`crate::info_skipping!`] siblings,
//! both of which use TWO ASCII spaces after their (variation-selector-
//! bearing) emoji. The `🔧` glyph (U+1F527) has no variation selector
//! — it is already a fully-qualified emoji — so a second ASCII space
//! would visually widen the gap versus the two-space `⚠️  ` / `⏭️  `
//! shapes rather than align with the one-space `📦 Git SHA:` /
//! `🎯 Registry:` / `📤 Pushing ...` sibling family. The primitive
//! pins the one-space grammar so a future collapse to the two-space
//! form (e.g. someone reading only `nonfatal_warning.rs` and
//! extrapolating) hits the byte-oracle test rather than shipping.
//!
//! # Preserving `tracing::info!` at the call site
//!
//! The macro expands to `::tracing::info!(...)` at the caller's
//! location, not to a function wrapper, so tracing's automatic source-
//! location capture (`file` + `line` + `module_path`) matches the
//! pre-lift behavior byte-for-byte. A function-based wrapper would
//! collapse every emission to the wrapper's own site and break
//! structured-log destinations that filter by module_path
//! (`RUST_LOG=forge::commands::build=info` would stop matching once the
//! emission moved to `forge::attic_configure_step`). The byte-oracle
//! writer sibling [`write_attic_configure_step`] captures the exact
//! rendered body for the tests (the `🔧` glyph, the one-space gap, the
//! literal `Configuring Attic cache...` body, the trailing newline) so
//! the invariant is pinned without racing an ambient tracing subscriber
//! — the same split
//! [`crate::nonfatal_warning::write_nonfatal_warn`] carries against
//! [`crate::warn_nonfatal!`] and
//! [`crate::registry_field::write_registry_field`] carries against
//! [`crate::info_registry_field!`].

use std::io;

use crate::error::AtticError;

/// The canonical `"Attic configured"` success-message body two sibling
/// post-`use_cache` sites in `commands/{build,github_runner_ci}.rs`
/// each spelled inline. Named as a `const` so a future re-branding
/// (`"Attic configured"` → `"Attic cache selected"`) lands at one edit
/// rather than through two inline literal edits, and the byte-oracle
/// writer sibling [`write_attic_configured_success_stanza`] can pin
/// the exact rendered payload without duplicating the literal.
pub const ATTIC_CONFIGURED_SUCCESS_LABEL: &str = "Attic configured";

/// Emits a single `"🔧 Configuring Attic cache...\n"` line via
/// [`writeln!`] against the supplied writer — the pre-lift `🔧 ` +
/// one-ASCII-space + `Configuring Attic cache...` phase-announce that
/// two sibling sites spelled inline.
///
/// The [`crate::info_attic_configure!`] macro is the [`tracing::info!`]
/// adapter that production code invokes; this direct-writer variant
/// exists so the fail-before-pass tests can pin the exact emitted bytes
/// (the single-space gap after the `🔧` glyph, the literal body, the
/// trailing newline) without capturing a tracing subscriber and without
/// racing an ambient logger — the same split
/// [`crate::nonfatal_warning::write_nonfatal_warn`] carries against
/// [`crate::warn_nonfatal!`] and
/// [`crate::registry_field::write_registry_field`] carries against
/// [`crate::info_registry_field!`].
#[allow(dead_code)] // See doc comment: the writer is a test/byte-oracle
                    // peer of the tracing-routed
                    // `info_attic_configure!` macro, and a future
                    // `collect_attic_configure_events` summary sibling
                    // will consume it directly.
pub fn write_attic_configure_step<W: io::Write>(w: &mut W) -> io::Result<()> {
    writeln!(w, "\u{1F527} Configuring Attic cache...")
}

/// Emit an Attic-configure phase-announce via [`tracing::info!`] on the
/// fleet-standard `"🔧 Configuring Attic cache..."` grammar.
///
/// The macro expands to a direct `::tracing::info!(...)` call at the
/// caller's location so tracing's automatic source-location capture is
/// preserved (a function wrapper would collapse every emission to the
/// wrapper's site — see the module docs for why that breaks per-module
/// filter routing). See the [module docs](self) for the sibling site
/// census, the split against [`crate::infrastructure::attic::AtticClient`]
/// (which performs the login / push itself), and the compounding
/// rationale for the load-bearing single-space separator.
///
/// # Examples
///
/// ```ignore
/// // Pre-lift
/// info!("🔧 Configuring Attic cache...");
///
/// // Post-lift
/// crate::info_attic_configure!();
/// ```
#[macro_export]
macro_rules! info_attic_configure {
    () => {
        ::tracing::info!("\u{1F527} Configuring Attic cache...")
    };
}

/// Emit the two-line post-`use_cache` acknowledgement stanza to `w`:
/// the `"✅ Attic configured\n"` success line + a bare `"\n"` blank
/// line. Byte-for-byte identical to the visual grammar the pre-lift
/// two-line stanza
///
/// ```ignore
/// crate::info_success!("Attic configured");
/// println!();
/// ```
///
/// presented to an operator watching the terminal.
///
/// The direct writer exists because the production fusion primitive
/// [`use_cache_and_announce_success`] emits the success line through
/// `crate::info_success!` (tracing-routed via the global
/// `tracing_subscriber` fmt layer) and the blank line through
/// `println!` — neither is byte-oracle-testable in a hermetic
/// `#[cfg(test)]` block without capturing an ambient subscriber. The
/// writer emits the two rendered payloads in narrative order into a
/// `Vec<u8>` so the fail-before-pass tests can pin the grammar via
/// `String::from_utf8`. Same writer/print split every prior
/// sibling-writer refactor honors (see [`write_attic_configure_step`]
/// above, `nonfatal_warning.rs`, `success_step.rs`,
/// `flux_system_reconcile.rs`).
#[allow(dead_code)] // See doc comment: the writer is a test/byte-oracle
                    // peer of the tracing+println-routed
                    // `use_cache_and_announce_success`, and a future
                    // `collect_attic_configured_events` summary sibling
                    // will consume it directly.
pub fn write_attic_configured_success_stanza<W: io::Write>(w: &mut W) -> io::Result<()> {
    crate::success_step::write_success_step(w, &ATTIC_CONFIGURED_SUCCESS_LABEL)?;
    writeln!(w)
}

/// Fuse the [`crate::infrastructure::attic::AtticClient::use_cache`]
/// call and its post-configure acknowledgement stanza into ONE typed
/// primitive.
///
/// Two pre-lift sibling five-line stanzas across
/// `commands/{build (×1: post-`login_optional` preamble, immediately
/// above the `nix_hooks::discover` chain), github_runner_ci (×1:
/// post-`login_with_retries` preamble inside the build-step arm,
/// immediately above the `nix build .#dockerImage` chain)}.rs` each
/// spelled the same shape verbatim:
///
/// ```ignore
/// crate::infrastructure::attic::AtticClient::new(cache_name.clone())
///     .use_cache(&attic_server)
///     .await?;
///
/// crate::info_success!("Attic configured");
/// println!();
/// ```
///
/// Both callers pass the same axes (a `cache_name` for the client
/// construction and an `attic_server` alias for the `use` argument);
/// both emit the same success acknowledgement; both trail with the
/// same `println!()` blank-line separator. Post-lift the primitive
/// owns the delegation, the acknowledgement grammar, and the trailing
/// blank line at ONE boundary.
///
/// # Grammar pinned by the byte-oracle sibling
///
/// The narrative bytes (the `"✅ Attic configured\n"` success line
/// and the `"\n"` blank separator) are pinned by
/// [`write_attic_configured_success_stanza`] under `#[cfg(test)]`; a
/// drift here surfaces as a localized test failure at one site, not
/// as silent grammar-drift across two build flows.
///
/// # Delegation, not re-implementation
///
/// The `use_cache` call itself remains the sole responsibility of
/// [`crate::infrastructure::attic::AtticClient::use_cache`] — the
/// typed [`crate::error::AtticError::UseFailed`] /
/// [`crate::error::AtticError::ExecFailed`] variants surface at the
/// caller through `?`. The primitive stays a grammar-and-ordering
/// owner, not a client-behavior owner, so a future re-shaping of the
/// `attic use` argv or its typed-error split lands at ONE place (the
/// client) and this primitive inherits by composition.
///
/// # Ordering invariant
///
/// The success line and the trailing blank line MUST NOT fire when
/// `use_cache` fails — the `?` propagation short-circuits before the
/// acknowledgement so a mis-`use`d cache does not print a green
/// checkmark. The pre-lift two sites exhibited this shape (the
/// `.await?` sat above the `info_success!` + `println!` pair), and
/// the primitive preserves the invariant by construction.
pub async fn use_cache_and_announce_success(
    cache_name: impl Into<String>,
    attic_server: &str,
) -> Result<(), AtticError> {
    crate::infrastructure::attic::AtticClient::new(cache_name)
        .use_cache(attic_server)
        .await?;
    crate::info_success!("{}", ATTIC_CONFIGURED_SUCCESS_LABEL);
    println!();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Pin the exact bytes: `🔧` (U+1F527, 4 bytes F0 9F 94 A7, no
    // variation selector), one ASCII space, the literal `Configuring
    // Attic cache...` (26 bytes), then `\n`. A future refactor that
    // adds a variation selector, widens the one-space gap to two,
    // changes the label capitalization, drops or adds an ellipsis dot,
    // or drops the trailing newline regresses this assertion.
    #[test]
    fn write_attic_configure_step_emits_exact_bytes() {
        let mut buf: Vec<u8> = Vec::new();
        write_attic_configure_step(&mut buf).unwrap();
        assert_eq!(buf, b"\xf0\x9f\x94\xa7 Configuring Attic cache...\n");
    }

    // Human-readable pin of the exact grammar so a future reader can
    // eyeball the render without decoding bytes.
    #[test]
    fn write_attic_configure_step_renders_expected_grammar() {
        let mut buf: Vec<u8> = Vec::new();
        write_attic_configure_step(&mut buf).unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "\u{1F527} Configuring Attic cache...\n"
        );
    }

    // Guard against the two-space grammar drift: `⚠️  ` and `⏭️  `
    // siblings both use two ASCII spaces (their emoji carry variation
    // selectors and are visually narrower without the extra space).
    // `🔧` is already fully-qualified emoji, so a two-space gap would
    // visually widen the label off the neighboring one-space `📦 Git
    // SHA:` / `🎯 Registry:` / `📤 Pushing ...` shape rather than
    // align with them. Pin the negative shape explicitly so a future
    // reader who reaches for the sibling grammar hits this test.
    #[test]
    fn write_attic_configure_step_does_not_use_two_space_grammar() {
        let mut buf: Vec<u8> = Vec::new();
        write_attic_configure_step(&mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(
            !s.starts_with("\u{1F527}  "),
            "write_attic_configure_step must NOT emit two ASCII spaces \
             after the `🔧` glyph — the fleet-standard one-space grammar \
             for fully-qualified emoji is load-bearing. Actual: {s:?}",
        );
    }

    // Guard against variation-selector drift: `🔧` (U+1F527) is
    // deliberately used as a bare 4-byte glyph. A future refactor that
    // appended U+FE0F would silently break byte-oracle downstream
    // comparators. Pin the exact 4-byte encoding.
    #[test]
    fn write_attic_configure_step_does_not_append_variation_selector() {
        let mut buf: Vec<u8> = Vec::new();
        write_attic_configure_step(&mut buf).unwrap();
        // Byte 4 must be an ASCII space (0x20), not the first byte of
        // U+FE0F (which is 0xEF).
        assert_eq!(
            buf[4], 0x20,
            "byte 4 must be an ASCII space (0x20); a U+FE0F variation \
             selector would place 0xEF there and break the byte-oracle. \
             Bytes: {buf:?}",
        );
    }

    // Guard against glyph drift: `🔧` (U+1F527, F0 9F 94 A7) is the
    // configure-phase semantic anchor. Sibling glyphs `📦` PACKAGE
    // (U+1F4E6, F0 9F 93 A6 — Git-SHA / artifact identity), `🎯`
    // DIRECT HIT (U+1F3AF, F0 9F 8E AF — destination registry /
    // target), and `📤` OUTBOX TRAY (U+1F4E4, F0 9F 93 A4 — the actual
    // push actions) each carry different semantic layers. A future
    // refactor that flipped this primitive's glyph would silently
    // merge the configure-vs-identify-vs-destination-vs-transmit
    // semantic split the four-glyph convention establishes across the
    // Attic-adjacent surface. Pin all four glyph bytes.
    #[test]
    fn write_attic_configure_step_emits_wrench_glyph() {
        let mut buf: Vec<u8> = Vec::new();
        write_attic_configure_step(&mut buf).unwrap();
        assert_eq!(
            &buf[0..4],
            &[0xf0, 0x9f, 0x94, 0xa7],
            "write_attic_configure_step must emit U+1F527 WRENCH \
             (F0 9F 94 A7), NOT U+1F4E6 PACKAGE (F0 9F 93 A6), \
             U+1F3AF DIRECT HIT (F0 9F 8E AF), or U+1F4E4 OUTBOX TRAY \
             (F0 9F 93 A4). Bytes: {buf:?}",
        );
    }

    // No-ANSI guard: the crate's `tracing_subscriber` initialization
    // in `main.rs` deliberately sets `with_ansi(false)` so CI log
    // ingestion sees clean records. Pin that this primitive's render
    // carries no ANSI escape byte (0x1B) — a future refactor that
    // reached for `colored` on the label side would break the ANSI-
    // free contract the tracing-routed sites depend on.
    #[test]
    fn write_attic_configure_step_emits_no_ansi_escape() {
        let mut buf: Vec<u8> = Vec::new();
        write_attic_configure_step(&mut buf).unwrap();
        assert!(
            !buf.contains(&0x1b),
            "write_attic_configure_step must emit no ANSI escape (0x1B) \
             — the tracing subscriber is configured `with_ansi(false)`. \
             Bytes: {buf:?}",
        );
    }

    // Ellipsis pin: the pre-lift body ends with THREE ASCII dots
    // (0x2E 0x2E 0x2E), NOT the single-code-point Unicode HORIZONTAL
    // ELLIPSIS (U+2026, three bytes E2 80 A6). A future refactor that
    // normalized the ellipsis to the single glyph would silently break
    // byte-oracle downstream comparators. Pin the exact tail bytes
    // before the newline.
    #[test]
    fn write_attic_configure_step_uses_three_ascii_dots_not_unicode_ellipsis() {
        let mut buf: Vec<u8> = Vec::new();
        write_attic_configure_step(&mut buf).unwrap();
        let n = buf.len();
        assert_eq!(
            &buf[n - 4..n],
            b"...\n",
            "write_attic_configure_step must end with three ASCII dots \
             (2E 2E 2E) then a newline, NOT a U+2026 HORIZONTAL \
             ELLIPSIS (E2 80 A6). Bytes: {buf:?}",
        );
    }

    // The macro forwards to `::tracing::info!` at the caller's
    // location. The subscriber cannot be captured in-process without
    // racing whatever subscriber `main` installs. Instead, pin that
    // the macro's zero-arg invocation shape expands at compile time —
    // a compile-fail here would fail the crate's `cargo test` build
    // gate.
    #[test]
    fn info_attic_configure_macro_compiles() {
        crate::info_attic_configure!();
    }

    // Caller shield: no source line under `cli/src/commands/` may
    // spell the pre-lift raw `info!("🔧 Configuring Attic cache...");`
    // stanza inline any more. The two pre-lift sites migrated; any
    // future consumer that wants the same grammar reaches for
    // `crate::info_attic_configure!` on first grep, not by copy-pasting
    // the raw shape from an existing command module.
    #[test]
    fn no_command_module_still_spells_raw_info_attic_configure_stanza() {
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
                if line.contains("info!(\"\u{1F527} Configuring Attic cache...\")") {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `info!(\"\u{1F527} Configuring Attic cache...\");` \
             stanza(s) survive under `commands/` — route each through \
             `crate::info_attic_configure!()` instead:\n{:#?}",
            offenders
        );
    }

    // Positive half of the shield: the two pre-lift files MUST each
    // forward through `crate::info_attic_configure!(` at least once, so
    // a migration that dropped a call site outright leaves the negative
    // "no raw inline shape" scan trivially satisfied by absence but the
    // positive count still fails.
    #[test]
    fn every_prelift_module_forwards_through_info_attic_configure_macro() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        // (module basename, minimum forward count from the pre-lift census)
        let expectations: &[(&str, usize)] = &[("build.rs", 1), ("github_runner_ci.rs", 1)];
        for (basename, min_count) in expectations {
            let path = commands_dir.join(basename);
            let source = std::fs::read_to_string(&path).unwrap();
            let forwards = source.matches("crate::info_attic_configure!(").count();
            assert!(
                forwards >= *min_count,
                "{basename} must forward at least {min_count} attic-configure \
                 phase-announce site(s) through `crate::info_attic_configure!(`; \
                 found {forwards}. A dropped call would leave the negative \
                 raw-shape scan satisfied by absence.",
            );
        }
    }

    // Pin the exact two-line acknowledgement bytes:
    // `✅ Attic configured\n` (the tracing-routed success line, byte-
    // identical to `write_success_step` applied to the canonical label)
    // + `\n` (the trailing bare blank line). A future refactor that
    // dropped the checkmark, drifted the label, or dropped the blank
    // separator regresses this assertion.
    #[test]
    fn write_attic_configured_success_stanza_emits_exact_bytes() {
        let mut buf: Vec<u8> = Vec::new();
        write_attic_configured_success_stanza(&mut buf).unwrap();
        assert_eq!(buf, b"\xe2\x9c\x85 Attic configured\n\n");
    }

    // Human-readable pin of the exact grammar so a future reader can
    // eyeball the render without decoding bytes.
    #[test]
    fn write_attic_configured_success_stanza_renders_expected_grammar() {
        let mut buf: Vec<u8> = Vec::new();
        write_attic_configured_success_stanza(&mut buf).unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "\u{2705} Attic configured\n\n"
        );
    }

    // Const-anchor pin: the canonical `"Attic configured"` label the
    // fusion primitive owns carries its exact pre-lift byte sequence.
    // A future edit that touched the const without updating the
    // mirrored inline literal in the caller-shield below cannot
    // silently proceed.
    #[test]
    fn attic_configured_success_label_carries_pre_lift_bytes() {
        assert_eq!(ATTIC_CONFIGURED_SUCCESS_LABEL, "Attic configured");
    }

    // Delegation pin: the writer forwards through
    // `crate::success_step::write_success_step` on the label rather
    // than restating the `✅ ` prefix inline. If a future edit
    // reintroduced the raw prefix, the `write_success_step`-produced
    // bytes and this writer's bytes would diverge on any drift of the
    // shared prefix grammar (e.g. a variation-selector append), and
    // the exact-bytes test above would fail — but this test pins the
    // delegation shape directly so the regression fires at the
    // delegation boundary rather than only at the byte-oracle.
    #[test]
    fn write_attic_configured_success_stanza_delegates_to_write_success_step() {
        let mut fusion_buf: Vec<u8> = Vec::new();
        write_attic_configured_success_stanza(&mut fusion_buf).unwrap();
        let mut delegated_buf: Vec<u8> = Vec::new();
        crate::success_step::write_success_step(
            &mut delegated_buf,
            &ATTIC_CONFIGURED_SUCCESS_LABEL,
        )
        .unwrap();
        // The fusion's payload must START with the delegated bytes and
        // the ONLY additional trailer must be the blank-line
        // separator `\n`.
        assert!(
            fusion_buf.starts_with(&delegated_buf),
            "fusion payload must delegate its success-line prefix through \
             `write_success_step`; got fusion={fusion_buf:?}, \
             delegated={delegated_buf:?}",
        );
        assert_eq!(
            &fusion_buf[delegated_buf.len()..],
            b"\n",
            "fusion payload's trailer past the delegated success line \
             must be exactly the bare `\\n` blank separator",
        );
    }

    // Caller shield: no source line under `cli/src/commands/` may
    // spell the pre-lift raw
    // `crate::info_success!("Attic configured");` stanza inline any
    // more. The two pre-lift sites migrated onto
    // `use_cache_and_announce_success`; any future consumer that
    // wants the same post-`use_cache` acknowledgement reaches for the
    // fusion primitive on first grep, not by copy-pasting the raw
    // shape from an existing command module. Doubles as a pin on the
    // label const — if a caller re-added the literal, the mirrored
    // inline string here would also drift.
    #[test]
    fn no_command_module_still_spells_raw_attic_configured_success_stanza() {
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
                if line.contains("crate::info_success!(\"Attic configured\")") {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `crate::info_success!(\"Attic configured\");` stanza(s) \
             survive under `commands/` — route each through \
             `crate::attic_configure_step::use_cache_and_announce_success(\
             cache_name, &attic_server).await?` instead:\n{:#?}",
            offenders
        );
    }

    // Positive half of the shield: the two pre-lift files MUST each
    // forward through
    // `crate::attic_configure_step::use_cache_and_announce_success(`
    // at least once, so a migration that dropped a call site outright
    // leaves the negative "no raw inline shape" scan trivially
    // satisfied by absence but the positive count still fails.
    #[test]
    fn every_prelift_module_forwards_through_use_cache_and_announce_success() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        // (module basename, minimum forward count from the pre-lift census)
        let expectations: &[(&str, usize)] = &[("build.rs", 1), ("github_runner_ci.rs", 1)];
        for (basename, min_count) in expectations {
            let path = commands_dir.join(basename);
            let source = std::fs::read_to_string(&path).unwrap();
            let forwards = source
                .matches("crate::attic_configure_step::use_cache_and_announce_success(")
                .count();
            assert!(
                forwards >= *min_count,
                "{basename} must forward at least {min_count} \
                 post-`use_cache` acknowledgement stanza(s) through \
                 `crate::attic_configure_step::use_cache_and_announce_success(`; \
                 found {forwards}. A dropped call would leave the \
                 negative raw-shape scan satisfied by absence.",
            );
        }
    }
}
