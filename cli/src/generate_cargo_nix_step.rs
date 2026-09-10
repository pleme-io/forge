//! Pre-`run_nix_wrapped_crate2nix` announce + post-delegate success-ack
//! fusion primitive.
//!
//! Two pre-lift sibling eight-line stanzas across
//! `commands/developer_tools.rs::{regenerate (×1: :346-355 under the
//! `Step 3: Generate Cargo.nix` comment, immediately after the
//! `Cargo.lock generated` step-pass + blank separator), rust_cargo_update
//! (×1: :414-423 under the `Step 2: Generate Cargo.nix` comment,
//! immediately after the `Dependencies updated` step-pass + blank
//! separator)}` each restated
//!
//! ```ignore
//! println!(
//!     "📦 {} {}",
//!     "Generating Cargo.nix".bold(),
//!     "(crate2nix generate)".dimmed()
//! );
//! crate::nix::run_nix_wrapped_crate2nix(&nix_bin(), &["-f", "Cargo.toml", "-o", "Cargo.nix"])
//!     .await?;
//! crate::ui::print_step_pass("Cargo.nix generated");
//! println!();
//! ```
//!
//! byte-for-byte — the same `📦` PACKAGE glyph (U+1F4E6, 4 bytes
//! F0 9F 93 A6, no variation selector) opening the colored announce
//! line, the same `.bold()` on the `Generating Cargo.nix` label body,
//! the same `.dimmed()` on the parenthesized `(crate2nix generate)`
//! detail, the same fixed argv tail `["-f", "Cargo.toml", "-o",
//! "Cargo.nix"]` passed through
//! [`crate::nix::run_nix_wrapped_crate2nix`], the same `Cargo.nix
//! generated` step-pass body, and the same trailing bare-`println!()`
//! blank-line separator. Post-lift the sites reach for
//! [`announce_and_generate_cargo_nix`] and the announce grammar, the
//! delegated argv tail, the success-ack body, and the trailing
//! blank-line separator are decided once here.
//!
//! # Distinct from the sibling third `regenerate`-adjacent site
//!
//! `commands/developer_tools.rs::rust_update_cargo_nix` (:236) also
//! forwards through [`crate::nix::run_nix_wrapped_crate2nix`], but
//! spells the announce as an uncolored plain-`println!("Generating
//! Cargo.nix...")` (three-ASCII-dot ellipsis, no `📦` glyph, no
//! `.bold()`, no `.dimmed()` detail), passes the empty argv tail
//! `&[]` rather than the four-element in/out tail, and acks success
//! through [`crate::ui::print_step_success`] with a distinct
//! `"Cargo.nix updated!"` body followed by a
//! `println!("   Commit both Cargo.lock and Cargo.nix changes")`
//! footer. That third site is deliberately out of scope for this
//! primitive: its grammar, argv, and ack body are all distinct, and a
//! collapse would either lose the trailing footer or force the
//! primitive to grow an optional-footer / optional-argv-tail axis its
//! two-site sibling family does not exercise.
//!
//! # Delegation, not re-implementation
//!
//! The `nix run nixpkgs#crate2nix -- generate <argv>` call itself
//! remains the sole responsibility of
//! [`crate::nix::run_nix_wrapped_crate2nix`] — the canonical
//! `(op, exit_code)` structural record surfaces via
//! [`crate::retry::run_bin_args_inherited_status`] and the outer
//! `.context("Failed to generate Cargo.nix")` wrap at the primitive
//! reaches the anyhow chain by construction. The fusion primitive
//! stays a grammar-and-ordering owner (announce → delegate → ack →
//! blank separator), not a nix-invocation-behavior owner, so a future
//! re-shaping of the wrapped-crate2nix argv or its structured-error
//! split lands at ONE place (the nix module) and this primitive
//! inherits by composition.
//!
//! # Ordering invariant
//!
//! The step-pass ack and the trailing blank separator MUST NOT fire
//! when [`crate::nix::run_nix_wrapped_crate2nix`] fails — the `?`
//! propagation short-circuits before the ack so a failed generate
//! does not print `✅ Cargo.nix generated`. The pre-lift two sites
//! exhibited this shape (the `.await?` sat above the
//! `print_step_pass` + `println!()` pair), and the primitive
//! preserves the invariant by construction.

use std::io;

use anyhow::{Context, Result};
use colored::Colorize;

/// The bold-rendered announce label body two pre-lift sites spelled
/// inline as `"Generating Cargo.nix".bold()` on the `📦 <bold>
/// <dimmed>` announce line. Named as a `const` so a future
/// re-branding (`"Generating Cargo.nix"` → `"Emitting Cargo.nix"`)
/// lands at one edit rather than through two inline literal edits,
/// and the byte-oracle writer sibling
/// [`write_generate_cargo_nix_announce`] pins the exact rendered
/// payload without duplicating the literal.
pub const GENERATE_CARGO_NIX_ANNOUNCE_LABEL: &str = "Generating Cargo.nix";

/// The dimmed-rendered parenthesized detail body two pre-lift sites
/// spelled inline as `"(crate2nix generate)".dimmed()` on the same
/// announce line. Kept alongside its bold-label peer for the same
/// reason.
pub const GENERATE_CARGO_NIX_ANNOUNCE_DETAIL: &str = "(crate2nix generate)";

/// The one-line body two pre-lift sites passed to
/// [`crate::ui::print_step_pass`] as the post-delegate success ack.
pub const GENERATE_CARGO_NIX_SUCCESS_LABEL: &str = "Cargo.nix generated";

/// The `crate2nix generate` extra-args tail two pre-lift sites
/// spelled inline as `&["-f", "Cargo.toml", "-o", "Cargo.nix"]` on
/// the [`crate::nix::run_nix_wrapped_crate2nix`] call. The primitive
/// owns the shape so a future re-flag of the wrapped-crate2nix
/// generate contract (e.g. an added `--output-format` flag) hits
/// ONE landing rather than two inline argv literals in lockstep.
pub const CARGO_NIX_GENERATE_ARGV: &[&str] = &["-f", "Cargo.toml", "-o", "Cargo.nix"];

/// Byte-oracle writer for the announce line's uncolored grammar:
/// `"📦 Generating Cargo.nix (crate2nix generate)\n"`. Emits the
/// exact 4-byte `📦` glyph (U+1F4E6, no variation selector), one
/// ASCII space, the label body, one ASCII space, the dimmed-detail
/// body, and a trailing newline.
///
/// The colored production entry point is
/// [`print_generate_cargo_nix_announce`]; this writer variant exists
/// so the fail-before-pass tests can pin the exact rendered body
/// bytes (the `📦` glyph, the one-space gaps, the label + detail
/// literals, the trailing newline) without racing an ambient
/// stdout capture and without threading a `colored::control` guard
/// through the test — same split
/// [`crate::attic_configure_step::write_attic_configure_step`]
/// carries against its colored siblings.
#[allow(dead_code)] // See doc comment: the writer is a byte-oracle
                    // peer of the production
                    // `print_generate_cargo_nix_announce`.
pub fn write_generate_cargo_nix_announce<W: io::Write>(w: &mut W) -> io::Result<()> {
    writeln!(
        w,
        "\u{1F4E6} {} {}",
        GENERATE_CARGO_NIX_ANNOUNCE_LABEL, GENERATE_CARGO_NIX_ANNOUNCE_DETAIL
    )
}

/// Print the colored announce line to stdout — the production entry
/// point pre-lift sites reached for via
/// `println!("📦 {} {}", "Generating Cargo.nix".bold(),
/// "(crate2nix generate)".dimmed())`. The label is `.bold()`, the
/// parenthesized detail is `.dimmed()`, the `📦` glyph and the ASCII
/// spaces flanking it carry no ANSI colorization.
pub fn print_generate_cargo_nix_announce() {
    println!(
        "\u{1F4E6} {} {}",
        GENERATE_CARGO_NIX_ANNOUNCE_LABEL.bold(),
        GENERATE_CARGO_NIX_ANNOUNCE_DETAIL.dimmed()
    );
}

/// Fuse the `📦 Generating Cargo.nix (crate2nix generate)` colored
/// announce, the [`crate::nix::run_nix_wrapped_crate2nix`] delegate
/// on the fixed [`CARGO_NIX_GENERATE_ARGV`] tail, the
/// `✅ Cargo.nix generated` step-pass ack, and the trailing blank
/// separator into ONE typed primitive.
///
/// `nix_path` is the resolved `NIX_BIN` path (typically read through
/// the caller's `nix_bin()` sigil — see
/// [`crate::nix::run_nix_wrapped_crate2nix`] for the sigil family).
/// Both pre-lift sites in `commands/developer_tools.rs` pass
/// `&nix_bin()` from the module-local sigil at
/// `developer_tools.rs::nix_bin`.
///
/// # Errors
///
/// Returns an error if [`crate::nix::run_nix_wrapped_crate2nix`]
/// fails — the outer `.context("Failed to generate Cargo.nix")`
/// wrap carries the caller-narrative into the anyhow chain
/// alongside the canonical `(op, exit_code)` structural record from
/// [`crate::retry::run_bin_args_inherited_status`]. On failure the
/// `?` propagation short-circuits before the success ack, so a
/// failed generate does not print `✅ Cargo.nix generated`.
pub async fn announce_and_generate_cargo_nix(nix_path: &str) -> Result<()> {
    print_generate_cargo_nix_announce();
    crate::nix::run_nix_wrapped_crate2nix(nix_path, CARGO_NIX_GENERATE_ARGV)
        .await
        .context("Failed to generate Cargo.nix")?;
    crate::ui::print_step_pass(GENERATE_CARGO_NIX_SUCCESS_LABEL);
    println!();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Pin the exact bytes: `📦` (U+1F4E6, 4 bytes F0 9F 93 A6, no
    // variation selector), one ASCII space, the literal `Generating
    // Cargo.nix` (20 bytes), one ASCII space, the literal `(crate2nix
    // generate)` (20 bytes), then `\n`. A future refactor that
    // appended a variation selector, widened the one-space gap to
    // two, changed the label capitalization, dropped the parentheses,
    // or dropped the trailing newline regresses this assertion.
    #[test]
    fn write_generate_cargo_nix_announce_emits_exact_bytes() {
        let mut buf: Vec<u8> = Vec::new();
        write_generate_cargo_nix_announce(&mut buf).unwrap();
        assert_eq!(
            buf,
            b"\xf0\x9f\x93\xa6 Generating Cargo.nix (crate2nix generate)\n"
        );
    }

    // Human-readable pin of the exact grammar so a future reader can
    // eyeball the render without decoding bytes.
    #[test]
    fn write_generate_cargo_nix_announce_renders_expected_grammar() {
        let mut buf: Vec<u8> = Vec::new();
        write_generate_cargo_nix_announce(&mut buf).unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "\u{1F4E6} Generating Cargo.nix (crate2nix generate)\n"
        );
    }

    // Guard against variation-selector drift: `📦` (U+1F4E6) is
    // deliberately used as a bare 4-byte glyph, matching the
    // `write_attic_configure_step` (`🔧`) and
    // `write_built_store_path_field` (`✅`) conventions for
    // fully-qualified emoji on the info/announce surface. A future
    // refactor that appended U+FE0F would place 0xEF at byte 4 and
    // silently break byte-oracle downstream comparators.
    #[test]
    fn write_generate_cargo_nix_announce_does_not_append_variation_selector() {
        let mut buf: Vec<u8> = Vec::new();
        write_generate_cargo_nix_announce(&mut buf).unwrap();
        assert_eq!(
            buf[4], 0x20,
            "byte 4 must be an ASCII space (0x20); a U+FE0F variation \
             selector would place 0xEF there and break the byte-oracle. \
             Bytes: {buf:?}",
        );
    }

    // Guard against glyph drift: `📦` (U+1F4E6, F0 9F 93 A6) is the
    // build-input identity / artifact-generation semantic anchor
    // across the fleet's info/announce grammar family (see
    // `attic_configure_step` module docs for the four-glyph
    // convention). A future refactor that flipped this primitive's
    // glyph to `🔧` (WRENCH, configure-phase), `🎯` (DIRECT HIT,
    // destination), or `📤` (OUTBOX TRAY, transmit) would silently
    // merge the identify-vs-configure-vs-destination-vs-transmit
    // semantic split the four-glyph convention establishes.
    #[test]
    fn write_generate_cargo_nix_announce_emits_package_glyph() {
        let mut buf: Vec<u8> = Vec::new();
        write_generate_cargo_nix_announce(&mut buf).unwrap();
        assert_eq!(
            &buf[0..4],
            &[0xf0, 0x9f, 0x93, 0xa6],
            "write_generate_cargo_nix_announce must emit U+1F4E6 PACKAGE \
             (F0 9F 93 A6), NOT U+1F527 WRENCH (F0 9F 94 A7), U+1F3AF \
             DIRECT HIT (F0 9F 8E AF), or U+1F4E4 OUTBOX TRAY (F0 9F 93 \
             A4). Bytes: {buf:?}",
        );
    }

    // No-ANSI guard: the byte-oracle writer's payload carries no ANSI
    // escape byte (0x1B) — the announce line's `.bold()` and
    // `.dimmed()` renderings live on the production
    // `print_generate_cargo_nix_announce` printer, not on the writer.
    // A future refactor that reached for `colored` on the writer side
    // would break the byte-oracle contract that pins the plain
    // grammar.
    #[test]
    fn write_generate_cargo_nix_announce_emits_no_ansi_escape() {
        let mut buf: Vec<u8> = Vec::new();
        write_generate_cargo_nix_announce(&mut buf).unwrap();
        assert!(
            !buf.contains(&0x1b),
            "write_generate_cargo_nix_announce must emit no ANSI escape \
             (0x1B) — the colored rendering belongs on the production \
             `print_generate_cargo_nix_announce` printer, not on the \
             byte-oracle writer. Bytes: {buf:?}",
        );
    }

    // Const-anchor pin: the canonical `"Generating Cargo.nix"` bold
    // label the primitive owns carries its exact pre-lift byte
    // sequence.
    #[test]
    fn generate_cargo_nix_announce_label_carries_pre_lift_bytes() {
        assert_eq!(GENERATE_CARGO_NIX_ANNOUNCE_LABEL, "Generating Cargo.nix");
    }

    // Const-anchor pin: the canonical `"(crate2nix generate)"` dimmed
    // detail body carries its exact pre-lift byte sequence.
    #[test]
    fn generate_cargo_nix_announce_detail_carries_pre_lift_bytes() {
        assert_eq!(GENERATE_CARGO_NIX_ANNOUNCE_DETAIL, "(crate2nix generate)");
    }

    // Const-anchor pin: the canonical `"Cargo.nix generated"` step-
    // pass body the primitive routes through
    // `crate::ui::print_step_pass`.
    #[test]
    fn generate_cargo_nix_success_label_carries_pre_lift_bytes() {
        assert_eq!(GENERATE_CARGO_NIX_SUCCESS_LABEL, "Cargo.nix generated");
    }

    // Argv-shape pin: the fixed `["-f", "Cargo.toml", "-o",
    // "Cargo.nix"]` extra-args tail the primitive passes to
    // `crate::nix::run_nix_wrapped_crate2nix`. A future refactor
    // that reordered the flags, dropped an element, or renamed
    // `Cargo.nix` regresses this assertion — and, in composition
    // with `test_run_nix_wrapped_crate2nix_forwards_extra_generate_
    // args_verbatim` in `cli/src/nix.rs`, the joined `nix run
    // nixpkgs#crate2nix -- generate -f Cargo.toml -o Cargo.nix`
    // wire-format is pinned end to end.
    #[test]
    fn cargo_nix_generate_argv_carries_pre_lift_shape() {
        assert_eq!(
            CARGO_NIX_GENERATE_ARGV,
            &["-f", "Cargo.toml", "-o", "Cargo.nix"]
        );
    }

    // Caller shield: no source line under `cli/src/commands/` may
    // spell the pre-lift `"Generating Cargo.nix".bold()` colored
    // announce inline any more. The two pre-lift sites migrated;
    // any future consumer that wants the same colored announce
    // reaches for `crate::generate_cargo_nix_step::announce_and_
    // generate_cargo_nix` on first grep, not by copy-pasting the
    // raw shape from an existing command module.
    #[test]
    fn no_command_module_still_spells_raw_generate_cargo_nix_bold_announce() {
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
                if line.contains("\"Generating Cargo.nix\".bold()") {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `\"Generating Cargo.nix\".bold()` announce line(s) \
             survive under `commands/` — route each through \
             `crate::generate_cargo_nix_step::announce_and_generate_\
             cargo_nix(&nix_bin()).await?` instead:\n{:#?}",
            offenders
        );
    }

    // Caller shield: no source line under `cli/src/commands/` may
    // spell the pre-lift byte-identical `run_nix_wrapped_crate2nix`
    // call carrying the fixed
    // `&["-f", "Cargo.toml", "-o", "Cargo.nix"]` argv tail inline
    // any more. The distinct third `rust_update_cargo_nix` site
    // passes `&[]` and is deliberately not in scope, so this shield
    // narrows to the exact four-element in/out argv shape rather
    // than the broader `run_nix_wrapped_crate2nix(` symbol.
    #[test]
    fn no_command_module_still_spells_raw_run_nix_wrapped_crate2nix_with_cargo_nix_argv() {
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
                if line.contains("&[\"-f\", \"Cargo.toml\", \"-o\", \"Cargo.nix\"]") {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `&[\"-f\", \"Cargo.toml\", \"-o\", \"Cargo.nix\"]` argv \
             literal(s) survive under `commands/` — route the enclosing \
             `run_nix_wrapped_crate2nix` call through \
             `crate::generate_cargo_nix_step::announce_and_generate_\
             cargo_nix(&nix_bin()).await?` instead (the primitive owns \
             the argv tail via `CARGO_NIX_GENERATE_ARGV`):\n{:#?}",
            offenders
        );
    }

    // Positive half of the shield: the pre-lift file MUST forward
    // through
    // `crate::generate_cargo_nix_step::announce_and_generate_cargo_nix(`
    // at least twice, so a migration that dropped a call site
    // outright leaves the negative "no raw inline shape" scan
    // trivially satisfied by absence but the positive count still
    // fails.
    #[test]
    fn every_prelift_module_forwards_through_announce_and_generate_cargo_nix() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let expectations: &[(&str, usize)] = &[("developer_tools.rs", 2)];
        for (basename, min_count) in expectations {
            let path = commands_dir.join(basename);
            let source = std::fs::read_to_string(&path).unwrap();
            let forwards = source
                .matches("crate::generate_cargo_nix_step::announce_and_generate_cargo_nix(")
                .count();
            assert!(
                forwards >= *min_count,
                "{basename} must forward at least {min_count} \
                 announce+generate-cargo.nix stanza(s) through \
                 `crate::generate_cargo_nix_step::announce_and_generate_\
                 cargo_nix(`; found {forwards}. A dropped call would \
                 leave the negative raw-shape scan satisfied by absence.",
            );
        }
    }
}
