//! Package-phase announce line grammar primitive — the
//! `📦 <bold-label> <dimmed-detail>` colored render every
//! forge command module reaches for when it opens a package-phase
//! step (regenerate deps.nix, update Cargo.lock, generate Cargo.nix,
//! run `cargo update`, …).
//!
//! Four pre-lift sibling four-line stanzas across `commands/{
//! web_service.rs (×2: `regenerate_frontend`'s pleme-linker regen
//! announce at :152-156, `regenerate_hanabi`'s cargo-update announce
//! at :251-255), developer_tools.rs (×2: `rust_regenerate_cargo_nix`'s
//! `cargo generate-lockfile` announce at :331-335, `rust_cargo_update`'s
//! `cargo update` announce at :397-401)}.rs` each restated
//!
//! ```ignore
//! println!(
//!     "📦 {} {}",
//!     <label>.bold(),
//!     <detail>.dimmed()
//! );
//! ```
//!
//! byte-for-byte — the same `📦` PACKAGE glyph (U+1F4E6, 4 bytes
//! F0 9F 93 A6, no variation selector) opening the colored announce
//! line, the same `.bold()` on the label body, the same one-ASCII-space
//! gap flanking the label, the same `.dimmed()` on the parenthesized
//! detail body, and the same trailing newline emitted through
//! `println!`. Post-lift the sites reach for
//! [`print_package_phase_announce`] and the glyph, the argument
//! ordering, the `.bold()` / `.dimmed()` split, and the trailing
//! newline are decided once here.
//!
//! # Composition with `generate_cargo_nix_step`
//!
//! [`crate::generate_cargo_nix_step::print_generate_cargo_nix_announce`]
//! is a specialization of this grammar with the fixed
//! [`crate::generate_cargo_nix_step::GENERATE_CARGO_NIX_ANNOUNCE_LABEL`]
//! (`"Generating Cargo.nix"`) label and
//! [`crate::generate_cargo_nix_step::GENERATE_CARGO_NIX_ANNOUNCE_DETAIL`]
//! (`"(crate2nix generate)"`) detail; it delegates through this
//! primitive so the shared package-phase announce grammar has ONE
//! landing point. A future re-branding of the announce glyph
//! (`📦` → e.g. `📤`) or a widening of the flanking space gap lands
//! at this primitive and rides through `generate_cargo_nix_step` to
//! the concrete Cargo.nix generate site by construction.
//!
//! # Distinct from adjacent glyph families
//!
//! The four pre-lift sites all open with `📦` (U+1F4E6, PACKAGE) —
//! the fleet's package-phase / build-input identity glyph. Adjacent
//! grammar families in the same command modules use distinct glyphs
//! (`🦀` U+1F980 for Rust-toolchain phases, `🚀` U+1F680 for launch
//! phases, `🔧` U+1F527 for tool-configure phases, `🐳` U+1F433 for
//! docker-compose phases, `🎯` U+1F3AF for destination phases) —
//! this primitive owns ONLY the `📦` PACKAGE family and does not
//! collapse sibling families whose semantic anchor differs.

use std::io;

use colored::Colorize;

/// Print the colored package-phase announce line to stdout — a
/// `📦 <bold-label> <dimmed-detail>` colored render four pre-lift
/// sites in `commands/{web_service.rs, developer_tools.rs}` each
/// spelled inline via `println!("📦 {} {}", label.bold(),
/// detail.dimmed())`.
///
/// `label` is rendered `.bold()`; `detail` is rendered `.dimmed()`.
/// The `📦` glyph and the ASCII spaces flanking the arguments carry
/// no ANSI colorization.
pub fn print_package_phase_announce(label: &str, detail: &str) {
    println!("\u{1F4E6} {} {}", label.bold(), detail.dimmed());
}

/// Byte-oracle writer for the announce line's uncolored grammar:
/// `"📦 <label> <detail>\n"`. Emits the exact 4-byte `📦` glyph
/// (U+1F4E6, no variation selector), one ASCII space, the label body,
/// one ASCII space, the detail body, and a trailing newline.
///
/// The colored production entry point is
/// [`print_package_phase_announce`]; this writer variant exists so
/// the fail-before-pass tests can pin the exact rendered body bytes
/// without racing an ambient stdout capture and without threading a
/// `colored::control` guard through the test — same split
/// [`crate::generate_cargo_nix_step::write_generate_cargo_nix_announce`]
/// carries against its colored sibling.
#[allow(dead_code)]
pub fn write_package_phase_announce<W: io::Write>(
    w: &mut W,
    label: &str,
    detail: &str,
) -> io::Result<()> {
    writeln!(w, "\u{1F4E6} {label} {detail}")
}

#[cfg(test)]
mod tests {
    use super::*;

    // Byte-oracle pin: the exact bytes emitted for the pre-lift
    // `"Updating dependencies"` / `"(cargo update)"` variant — `📦`
    // (U+1F4E6, 4 bytes F0 9F 93 A6, no variation selector), one
    // ASCII space, the 21-byte label body, one ASCII space, the
    // 14-byte detail body, then `\n`. A future refactor that
    // appended a variation selector, widened a one-space gap to
    // two, or dropped the trailing newline regresses this
    // assertion.
    #[test]
    fn write_package_phase_announce_emits_exact_bytes_for_updating_dependencies_variant() {
        let mut buf: Vec<u8> = Vec::new();
        write_package_phase_announce(&mut buf, "Updating dependencies", "(cargo update)").unwrap();
        assert_eq!(
            buf,
            b"\xf0\x9f\x93\xa6 Updating dependencies (cargo update)\n"
        );
    }

    // Human-readable pin of the exact grammar so a future reader can
    // eyeball the render for the pre-lift
    // `"Regenerating frontend deps.nix"` / `"(pleme-linker regen)"`
    // web_service.rs::regenerate_frontend variant without decoding
    // bytes.
    #[test]
    fn write_package_phase_announce_renders_expected_grammar_for_pleme_linker_regen_variant() {
        let mut buf: Vec<u8> = Vec::new();
        write_package_phase_announce(
            &mut buf,
            "Regenerating frontend deps.nix",
            "(pleme-linker regen)",
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "\u{1F4E6} Regenerating frontend deps.nix (pleme-linker regen)\n"
        );
    }

    // Human-readable pin for the pre-lift
    // `"Generating new Cargo.lock"` / `"(cargo generate-lockfile)"`
    // developer_tools.rs::rust_regenerate_cargo_nix variant.
    #[test]
    fn write_package_phase_announce_renders_expected_grammar_for_generate_lockfile_variant() {
        let mut buf: Vec<u8> = Vec::new();
        write_package_phase_announce(
            &mut buf,
            "Generating new Cargo.lock",
            "(cargo generate-lockfile)",
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "\u{1F4E6} Generating new Cargo.lock (cargo generate-lockfile)\n"
        );
    }

    // Guard against variation-selector drift: `📦` (U+1F4E6) is
    // deliberately used as a bare 4-byte glyph, matching the
    // `write_attic_configure_step` (`🔧`), `write_built_store_path_field`
    // (`✅`), and `write_generate_cargo_nix_announce` (`📦`) conventions
    // for fully-qualified emoji on the info/announce surface. A future
    // refactor that appended U+FE0F would place 0xEF at byte 4 and
    // silently break byte-oracle downstream comparators.
    #[test]
    fn write_package_phase_announce_does_not_append_variation_selector() {
        let mut buf: Vec<u8> = Vec::new();
        write_package_phase_announce(&mut buf, "L", "D").unwrap();
        assert_eq!(
            buf[4], 0x20,
            "byte 4 must be an ASCII space (0x20); a U+FE0F variation \
             selector would place 0xEF there and break the byte-oracle. \
             Bytes: {buf:?}",
        );
    }

    // Guard against glyph drift: `📦` (U+1F4E6, F0 9F 93 A6) is the
    // build-input identity / package-phase semantic anchor across
    // the fleet's info/announce grammar family (see
    // `attic_configure_step` module docs for the four-glyph
    // convention). A future refactor that flipped this primitive's
    // glyph to `🔧` (WRENCH, configure-phase), `🎯` (DIRECT HIT,
    // destination), `📤` (OUTBOX TRAY, transmit), or `🚀` (ROCKET,
    // launch) would silently merge the
    // package-vs-configure-vs-destination-vs-transmit-vs-launch
    // semantic split the fleet-wide glyph convention establishes.
    #[test]
    fn write_package_phase_announce_emits_package_glyph() {
        let mut buf: Vec<u8> = Vec::new();
        write_package_phase_announce(&mut buf, "L", "D").unwrap();
        assert_eq!(
            &buf[0..4],
            &[0xf0, 0x9f, 0x93, 0xa6],
            "write_package_phase_announce must emit U+1F4E6 PACKAGE \
             (F0 9F 93 A6), NOT U+1F527 WRENCH (F0 9F 94 A7), U+1F3AF \
             DIRECT HIT (F0 9F 8E AF), U+1F4E4 OUTBOX TRAY (F0 9F 93 \
             A4), or U+1F680 ROCKET (F0 9F 9A 80). Bytes: {buf:?}",
        );
    }

    // No-ANSI guard: the byte-oracle writer's payload carries no ANSI
    // escape byte (0x1B) — the announce line's `.bold()` and
    // `.dimmed()` renderings live on the production
    // `print_package_phase_announce` printer, not on the writer.
    // A future refactor that reached for `colored` on the writer side
    // would break the byte-oracle contract that pins the plain grammar.
    #[test]
    fn write_package_phase_announce_emits_no_ansi_escape() {
        let mut buf: Vec<u8> = Vec::new();
        write_package_phase_announce(&mut buf, "L", "D").unwrap();
        assert!(
            !buf.contains(&0x1b),
            "write_package_phase_announce must emit no ANSI escape \
             (0x1B) — the colored rendering belongs on the production \
             `print_package_phase_announce` printer, not on the \
             byte-oracle writer. Bytes: {buf:?}",
        );
    }

    // Arity pin: the writer emits exactly the composed
    // `<4-byte-glyph><space><label><space><detail><newline>` byte
    // sequence, with no leading/trailing padding beyond the trailing
    // `\n`. A future refactor that prepended `"  "` indent or
    // appended a blank second line would regress this arithmetic.
    #[test]
    fn write_package_phase_announce_length_matches_composition_arithmetic() {
        let mut buf: Vec<u8> = Vec::new();
        write_package_phase_announce(&mut buf, "Updating dependencies", "(cargo update)").unwrap();
        // 4-byte glyph + space + 21-byte label + space + 14-byte
        // detail + newline = 42 bytes.
        assert_eq!(
            buf.len(),
            4 + 1 + "Updating dependencies".len() + 1 + "(cargo update)".len() + 1,
            "write_package_phase_announce must emit exactly \
             `<4-byte-glyph><space><label><space><detail><newline>` \
             with no ambient padding. Bytes: {buf:?}",
        );
    }

    // Caller shield: no source line under `cli/src/commands/` may
    // spell the pre-lift `"📦 {} {}"` format literal inline any more.
    // Every consumer reaches for
    // `crate::package_phase_announce::print_package_phase_announce`
    // on first grep, not by copy-pasting the raw shape from an
    // existing command module.
    #[test]
    fn no_command_module_still_spells_raw_package_phase_announce_format() {
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
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") || trimmed.starts_with("///") {
                    continue;
                }
                if line.contains("\"\u{1F4E6} {} {}\"") {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `\"\u{1F4E6} {{}} {{}}\"` format literal(s) survive \
             under `commands/` — route each through \
             `crate::package_phase_announce::print_package_phase_announce(\
             label, detail)` instead:\n{:#?}",
            offenders
        );
    }

    // Positive half of the shield: each pre-lift module MUST forward
    // through
    // `crate::package_phase_announce::print_package_phase_announce(`
    // at least the migrated count, so a migration that dropped a
    // call site outright leaves the negative "no raw inline shape"
    // scan trivially satisfied by absence but the positive count
    // still fails.
    //
    // The counts here are DIRECT forwards from each module's own
    // source. Pre-lift each of the two modules landed 2 direct
    // forwards (the `Regenerating <target>` Step-1 announce and the
    // `Updating dependencies` Step-1 cargo-update announce); post-lift
    // the cargo-update Step-1 announce migrated onto
    // `crate::cargo_update_dependencies_phase::\
    // announce_and_run_cargo_update_in`, which itself forwards through
    // `print_package_phase_announce` at one body — so the direct
    // forward count in each pre-lift module drops from 2 to 1, but the
    // shared grammar still reaches both consumer sites by construction
    // (via the new primitive's one indirection). The companion
    // sibling shield below pins the primitive's forward and its
    // consumer-count so a regression that dropped the primitive call
    // outright (from either consumer OR the primitive body) still
    // fails at the visible spot.
    #[test]
    fn every_prelift_module_forwards_through_print_package_phase_announce() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let expectations: &[(&str, usize)] = &[("web_service.rs", 1), ("developer_tools.rs", 1)];
        for (basename, min_count) in expectations {
            let path = commands_dir.join(basename);
            let source = std::fs::read_to_string(&path).unwrap();
            let forwards = source
                .matches("crate::package_phase_announce::print_package_phase_announce(")
                .count();
            assert!(
                forwards >= *min_count,
                "{basename} must forward at least {min_count} \
                 package-phase-announce stanza(s) through \
                 `crate::package_phase_announce::print_package_phase_announce(`; \
                 found {forwards}. A dropped call would leave the \
                 negative raw-shape scan satisfied by absence.",
            );
        }
    }

    // Companion positive shield to
    // [`every_prelift_module_forwards_through_print_package_phase_announce`]:
    // the migrated cargo-update Step-1 announce now flows through the
    // `crate::cargo_update_dependencies_phase::\
    // announce_and_run_cargo_update_in` fusion primitive, which itself
    // must forward through
    // `crate::package_phase_announce::print_package_phase_announce(`
    // at exactly one body — and both pre-lift command modules must
    // still call the primitive at least once. A regression that
    // dropped the primitive's own forward through
    // `print_package_phase_announce` would break the shared grammar
    // for both consumer sites at once, and a regression that dropped
    // the primitive call from either consumer would drop the migrated
    // Step-1 announce entirely.
    #[test]
    fn cargo_update_dependencies_phase_carries_migrated_package_phase_announce() {
        use std::path::PathBuf;
        let cli_src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");

        let primitive_body =
            std::fs::read_to_string(cli_src.join("cargo_update_dependencies_phase.rs")).unwrap();
        let primitive_forward_hits = primitive_body
            .matches("crate::package_phase_announce::print_package_phase_announce(")
            .count();
        assert!(
            primitive_forward_hits >= 1,
            "cargo_update_dependencies_phase.rs must forward through \
             `crate::package_phase_announce::print_package_phase_announce(` \
             at least once so the migrated Step-1 cargo-update \
             announce reaches the shared grammar. Found \
             {primitive_forward_hits} hit(s).",
        );

        let consumer_canonical = "crate::cargo_update_dependencies_phase::\
                                  announce_and_run_cargo_update_in(";
        for basename in &["web_service.rs", "developer_tools.rs"] {
            let source = std::fs::read_to_string(cli_src.join("commands").join(basename)).unwrap();
            let consumer_hits = source
                .lines()
                .filter(|line| {
                    let trimmed = line.trim_start();
                    !trimmed.starts_with("//")
                        && !trimmed.starts_with("///")
                        && line.contains(consumer_canonical)
                })
                .count();
            assert!(
                consumer_hits >= 1,
                "{basename} must forward the migrated Step-1 \
                 cargo-update stanza through `{consumer_canonical}` \
                 at least once. Found {consumer_hits} hit(s).",
            );
        }
    }

    // Composition pin: `generate_cargo_nix_step` delegates its
    // `print_generate_cargo_nix_announce` production printer through
    // this primitive so the shared package-phase-announce grammar
    // has ONE landing point across the fleet. A future refactor that
    // re-inlined the raw `println!("\u{1F4E6} {} {}", label.bold(),
    // detail.dimmed())` shape at the `generate_cargo_nix_step`
    // primitive would fork the grammar again.
    #[test]
    fn generate_cargo_nix_step_delegates_through_print_package_phase_announce() {
        let source = std::fs::read_to_string(
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("src")
                .join("generate_cargo_nix_step.rs"),
        )
        .unwrap();
        assert!(
            source.contains("crate::package_phase_announce::print_package_phase_announce("),
            "generate_cargo_nix_step.rs must forward its \
             `print_generate_cargo_nix_announce` colored render through \
             `crate::package_phase_announce::print_package_phase_announce(` \
             so the shared package-phase-announce grammar has ONE \
             landing point.",
        );
    }
}
