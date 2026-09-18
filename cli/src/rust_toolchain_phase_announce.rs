//! Rust-toolchain-phase announce line grammar primitive — the
//! `🦀 <bold-label> <dimmed-detail>` colored render every forge
//! command module reaches for when it opens a Rust-toolchain-phase
//! step (regenerate a `Cargo.nix`, run `cargo update`, drive a
//! `crate2nix generate` inside a Cargo workspace, …).
//!
//! Two pre-lift sibling four-line stanzas across
//! `commands/web_service.rs::{web_regenerate` (Step 2 Hanabi
//! `Cargo.nix` regeneration announce, at :172-176) and
//! `web_cargo_update` (Step 2 `Cargo.nix` regeneration announce
//! at :261-265)`} each restated
//!
//! ```ignore
//! println!(
//!     "🦀 {} {}",
//!     <label>.bold(),
//!     <detail>.dimmed()
//! );
//! ```
//!
//! byte-for-byte — the same `🦀` CRAB glyph (U+1F980, 4 bytes
//! F0 9F A6 80, no variation selector) opening the colored announce
//! line, the same `.bold()` on the label body, the same one-ASCII-space
//! gap flanking the label, the same `.dimmed()` on the parenthesized
//! detail body, and the same trailing newline emitted through
//! `println!`. Post-lift the sites reach for
//! [`print_rust_toolchain_phase_announce`] and the glyph, the argument
//! ordering, the `.bold()` / `.dimmed()` split, and the trailing
//! newline are decided once here.
//!
//! # Distinct from adjacent glyph families
//!
//! The two pre-lift sites all open with `🦀` (U+1F980, CRAB) — the
//! fleet's Rust-toolchain-phase semantic anchor. Adjacent grammar
//! families in the same command modules use distinct glyphs (`📦`
//! U+1F4E6 for package/build-input phases via
//! [`crate::package_phase_announce`], `🔧` U+1F527 for tool-configure
//! phases, `🚀` U+1F680 for launch phases, `🎯` U+1F3AF for destination
//! phases, `🐳` U+1F433 for docker-compose phases) — this primitive
//! owns ONLY the `🦀` CRAB family and does not collapse sibling
//! families whose semantic anchor differs.

use std::io;

use colored::Colorize;

/// Print the colored Rust-toolchain-phase announce line to stdout —
/// a `🦀 <bold-label> <dimmed-detail>` colored render two pre-lift
/// sites in `commands/web_service.rs` each spelled inline via
/// `println!("🦀 {} {}", label.bold(), detail.dimmed())`.
///
/// `label` is rendered `.bold()`; `detail` is rendered `.dimmed()`.
/// The `🦀` glyph and the ASCII spaces flanking the arguments carry
/// no ANSI colorization.
pub fn print_rust_toolchain_phase_announce(label: &str, detail: &str) {
    println!("\u{1F980} {} {}", label.bold(), detail.dimmed());
}

/// Byte-oracle writer for the announce line's uncolored grammar:
/// `"🦀 <label> <detail>\n"`. Emits the exact 4-byte `🦀` glyph
/// (U+1F980, no variation selector), one ASCII space, the label body,
/// one ASCII space, the detail body, and a trailing newline.
///
/// The colored production entry point is
/// [`print_rust_toolchain_phase_announce`]; this writer variant
/// exists so the fail-before-pass tests can pin the exact rendered
/// body bytes without racing an ambient stdout capture and without
/// threading a `colored::control` guard through the test — same
/// split [`crate::package_phase_announce::write_package_phase_announce`]
/// carries against its colored sibling.
#[allow(dead_code)]
pub fn write_rust_toolchain_phase_announce<W: io::Write>(
    w: &mut W,
    label: &str,
    detail: &str,
) -> io::Result<()> {
    writeln!(w, "\u{1F980} {label} {detail}")
}

#[cfg(test)]
mod tests {
    use super::*;

    // Byte-oracle pin: the exact bytes emitted for the pre-lift
    // `"Regenerating Hanabi Cargo.nix"` / `"(crate2nix generate)"`
    // web_service.rs::web_regenerate variant — `🦀` (U+1F980, 4 bytes
    // F0 9F A6 80, no variation selector), one ASCII space, the
    // 28-byte label body, one ASCII space, the 20-byte detail body,
    // then `\n`. A future refactor that appended a variation
    // selector, widened a one-space gap to two, or dropped the
    // trailing newline regresses this assertion.
    #[test]
    fn write_rust_toolchain_phase_announce_emits_exact_bytes_for_hanabi_regen_variant() {
        let mut buf: Vec<u8> = Vec::new();
        write_rust_toolchain_phase_announce(
            &mut buf,
            "Regenerating Hanabi Cargo.nix",
            "(crate2nix generate)",
        )
        .unwrap();
        assert_eq!(
            buf,
            b"\xf0\x9f\xa6\x80 Regenerating Hanabi Cargo.nix (crate2nix generate)\n"
        );
    }

    // Human-readable pin for the pre-lift `"Regenerating Cargo.nix"`
    // / `"(crate2nix generate)"` web_service.rs::web_cargo_update
    // variant.
    #[test]
    fn write_rust_toolchain_phase_announce_renders_expected_grammar_for_cargo_update_variant() {
        let mut buf: Vec<u8> = Vec::new();
        write_rust_toolchain_phase_announce(
            &mut buf,
            "Regenerating Cargo.nix",
            "(crate2nix generate)",
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "\u{1F980} Regenerating Cargo.nix (crate2nix generate)\n"
        );
    }

    // Guard against variation-selector drift: `🦀` (U+1F980) is
    // deliberately used as a bare 4-byte glyph, matching the sibling
    // `write_package_phase_announce` (`📦`) fully-qualified-emoji
    // convention on the info/announce surface. A future refactor
    // that appended U+FE0F would place 0xEF at byte 4 and silently
    // break byte-oracle downstream comparators.
    #[test]
    fn write_rust_toolchain_phase_announce_does_not_append_variation_selector() {
        let mut buf: Vec<u8> = Vec::new();
        write_rust_toolchain_phase_announce(&mut buf, "L", "D").unwrap();
        assert_eq!(
            buf[4], 0x20,
            "byte 4 must be an ASCII space (0x20); a U+FE0F variation \
             selector would place 0xEF there and break the byte-oracle. \
             Bytes: {buf:?}",
        );
    }

    // Guard against glyph drift: `🦀` (U+1F980, F0 9F A6 80) is the
    // Rust-toolchain-phase semantic anchor across the fleet's
    // info/announce grammar family. A future refactor that flipped
    // this primitive's glyph to `📦` (PACKAGE, package/build-input
    // phase — owned by `package_phase_announce`), `🔧` (WRENCH,
    // configure-phase), `🎯` (DIRECT HIT, destination), `📤` (OUTBOX
    // TRAY, transmit), or `🚀` (ROCKET, launch) would silently merge
    // the Rust-toolchain vs. package vs. configure vs. destination
    // vs. transmit vs. launch semantic split the fleet-wide glyph
    // convention establishes.
    #[test]
    fn write_rust_toolchain_phase_announce_emits_crab_glyph() {
        let mut buf: Vec<u8> = Vec::new();
        write_rust_toolchain_phase_announce(&mut buf, "L", "D").unwrap();
        assert_eq!(
            &buf[0..4],
            &[0xf0, 0x9f, 0xa6, 0x80],
            "write_rust_toolchain_phase_announce must emit U+1F980 CRAB \
             (F0 9F A6 80), NOT U+1F4E6 PACKAGE (F0 9F 93 A6), U+1F527 \
             WRENCH (F0 9F 94 A7), U+1F3AF DIRECT HIT (F0 9F 8E AF), \
             U+1F4E4 OUTBOX TRAY (F0 9F 93 A4), or U+1F680 ROCKET \
             (F0 9F 9A 80). Bytes: {buf:?}",
        );
    }

    // No-ANSI guard: the byte-oracle writer's payload carries no
    // ANSI escape byte (0x1B) — the announce line's `.bold()` and
    // `.dimmed()` renderings live on the production
    // `print_rust_toolchain_phase_announce` printer, not on the
    // writer. A future refactor that reached for `colored` on the
    // writer side would break the byte-oracle contract that pins
    // the plain grammar.
    #[test]
    fn write_rust_toolchain_phase_announce_emits_no_ansi_escape() {
        let mut buf: Vec<u8> = Vec::new();
        write_rust_toolchain_phase_announce(&mut buf, "L", "D").unwrap();
        assert!(
            !buf.contains(&0x1b),
            "write_rust_toolchain_phase_announce must emit no ANSI \
             escape (0x1B) — the colored rendering belongs on the \
             production `print_rust_toolchain_phase_announce` printer, \
             not on the byte-oracle writer. Bytes: {buf:?}",
        );
    }

    // Arity pin: the writer emits exactly the composed
    // `<4-byte-glyph><space><label><space><detail><newline>` byte
    // sequence, with no leading/trailing padding beyond the trailing
    // `\n`. A future refactor that prepended `"  "` indent or
    // appended a blank second line would regress this arithmetic.
    #[test]
    fn write_rust_toolchain_phase_announce_length_matches_composition_arithmetic() {
        let mut buf: Vec<u8> = Vec::new();
        write_rust_toolchain_phase_announce(
            &mut buf,
            "Regenerating Cargo.nix",
            "(crate2nix generate)",
        )
        .unwrap();
        // 4-byte glyph + space + 22-byte label + space + 20-byte
        // detail + newline = 48 bytes.
        assert_eq!(
            buf.len(),
            4 + 1 + "Regenerating Cargo.nix".len() + 1 + "(crate2nix generate)".len() + 1,
            "write_rust_toolchain_phase_announce must emit exactly \
             `<4-byte-glyph><space><label><space><detail><newline>` \
             with no ambient padding. Bytes: {buf:?}",
        );
    }

    // Caller shield: no source line under `cli/src/commands/` may
    // spell the pre-lift `"🦀 {} {}"` format literal inline any more.
    // Every consumer reaches for
    // `crate::rust_toolchain_phase_announce::print_rust_toolchain_phase_announce`
    // on first grep, not by copy-pasting the raw shape from an
    // existing command module. The distinct `"🦀 {} {} {}"` three-arg
    // help-header render in
    // `developer_tools.rs::rust_service_help` (a Forge + service +
    // `(crate2nix)` triple, not a `<label> <detail>` phase announce)
    // is excluded here by literal shape — its format string carries
    // three `{}` slots, not two, so `"🦀 {} {}"` never matches.
    #[test]
    fn no_command_module_still_spells_raw_rust_toolchain_phase_announce_format() {
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
                if line.contains("\"\u{1F980} {} {}\"") {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `\"\u{1F980} {{}} {{}}\"` format literal(s) survive \
             under `commands/` — route each through \
             `crate::rust_toolchain_phase_announce::print_rust_toolchain_phase_announce(\
             label, detail)` instead:\n{:#?}",
            offenders
        );
    }

    // Positive half of the shield: the primitive MUST have at least
    // one downstream consumer routing through
    // `print_rust_toolchain_phase_announce(`, so a migration that
    // dropped a call site outright leaves the negative "no raw
    // inline shape" scan trivially satisfied by absence but the
    // positive count still fails.
    //
    // The two pre-lift `commands/web_service.rs` stanzas that once
    // called this primitive directly now route through the fusion
    // sibling
    // [`crate::crate2nix_regenerate_step::announce_and_run_crate2nix_regenerate`],
    // which itself delegates through this primitive at ONE landing.
    // The invariant transitions from "2 direct calls in
    // web_service.rs" to "1 call in the fusion module" — the
    // positive count still fails on a migration that dropped the
    // fusion primitive's body, and the sibling shield
    // `every_prelift_module_forwards_through_announce_and_run_crate2nix_regenerate`
    // (in `crate2nix_regenerate_step.rs`) pins the two-uses count
    // at the caller site.
    #[test]
    fn every_downstream_owner_forwards_through_print_rust_toolchain_phase_announce() {
        use std::path::PathBuf;
        let src_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let expectations: &[(&str, usize)] = &[("crate2nix_regenerate_step.rs", 1)];
        for (basename, min_count) in expectations {
            let path = src_dir.join(basename);
            let source = std::fs::read_to_string(&path)
                .unwrap_or_else(|_| panic!("expected {} to exist", path.display()));
            let forwards = source
                .matches(
                    "crate::rust_toolchain_phase_announce::print_rust_toolchain_phase_announce(",
                )
                .count();
            assert!(
                forwards >= *min_count,
                "{basename} must forward at least {min_count} \
                 rust-toolchain-phase-announce stanza(s) through \
                 `crate::rust_toolchain_phase_announce::print_rust_toolchain_phase_announce(`; \
                 found {forwards}. A dropped call would leave the \
                 negative raw-shape scan satisfied by absence.",
            );
        }
    }
}
