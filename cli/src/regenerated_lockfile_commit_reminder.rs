//! Regenerated-lockfile commit reminder primitive — the one-line
//! `   Don't forget to commit the updated <lock> and <generated> files.`
//! post-regenerate reminder stanza the three Cargo.nix / gemset.nix
//! regenerate commands each emit immediately after the success banner.
//!
//! # Duplication being lifted
//!
//! Three pre-lift sibling sites each restated the same
//! [`println!`] literal, differing only in the (lockfile, generated
//! file) pair spelled inline:
//!
//! 1. `commands/pangea.rs::regenerate` (~L494) — the Pangea workspace
//!    Cargo.nix regenerate command, emitting the
//!    `Cargo.lock` + `Cargo.nix` variant right after
//!    `"Pangea Cargo.nix regenerated successfully!".bright_green().bold()`.
//! 2. `commands/pangea.rs::regenerate_compiler` (~L560) — the Pangea
//!    Ruby compiler gemset.nix regenerate command, emitting the
//!    `Gemfile.lock` + `gemset.nix` variant right after
//!    `"Pangea gemset.nix regenerated successfully!".bright_green().bold()`.
//! 3. `commands/bootstrap.rs::regenerate` (~L635) — the platform
//!    bootstrap Cargo.nix regenerate command, emitting the
//!    `Cargo.lock` + `Cargo.nix` variant right after
//!    `crate::ui::print_success("Bootstrap Cargo.nix regenerated
//!    successfully!")`.
//!
//! Both Cargo sites (1) and (3) spell an identical
//! `"   Don't forget to commit the updated Cargo.lock and Cargo.nix files."`
//! literal; the Ruby site (2) swaps only the file pair to
//! `Gemfile.lock` and `gemset.nix`. A drift between the three sites —
//! a rename of `Cargo.nix` to `Cargo.nix.new`, a swap of the two
//! filenames' order, a rewording of "Don't forget to commit" to
//! "Please commit", a swap of the three-space indent for two spaces
//! or a bullet glyph — would silently diverge the operator-facing
//! reminder between the two ecosystems even though the very same
//! `git add && git commit` follow-up applies to both. Post-lift the
//! three stanzas route through ONE typed body; a rename of the
//! generated-file suffix or a rewording of the reminder lands at ONE
//! writer and reaches all three consumers by construction.
//!
//! # Closed-enum axis
//!
//! The two-file coupling — the ecosystem-specific pair `(lockfile,
//! generated file)` — lives at [`RegeneratedLockfilePair`], a closed
//! enum with two variants:
//!
//! * [`RegeneratedLockfilePair::CargoNix`] → `("Cargo.lock",
//!   "Cargo.nix")` — the Rust workspace regen pair used by every
//!   `run_cargo_update` + `run_crate2nix` composition in the crate.
//! * [`RegeneratedLockfilePair::GemsetNix`] → `("Gemfile.lock",
//!   "gemset.nix")` — the Ruby regen pair used by the
//!   `bundle lock --update` + `bundix` composition in
//!   `commands/pangea.rs::regenerate_compiler`.
//!
//! The two-slot `writeln!` at [`write_regenerated_lockfile_commit_reminder`]
//! consumes the pair via [`RegeneratedLockfilePair::file_pair`] so a
//! caller cannot (a) type `"Cargo.lock"` in the lockfile slot and
//! forget `"Cargo.nix"` in the generated slot, (b) swap the pair's
//! order, or (c) fabricate a novel pair the crate does not regenerate.
//! A future ecosystem that adds a third pair (e.g., `poetry.lock` +
//! `poetry2nix.nix`) grows a third variant at ONE place rather than
//! copying the reminder line into a fourth call site.
//!
//! # Byte contract
//!
//! [`print_regenerated_lockfile_commit_reminder`] and its writer
//! sibling [`write_regenerated_lockfile_commit_reminder`] emit exactly
//! the same bytes the pre-lift `println!("   Don't forget to commit
//! the updated {} and {} files.", <lock>, <gen>)` stanzas produced:
//! a three-ASCII-space indent, the fixed reminder body with the
//! (lockfile, generated file) pair interpolated in that order, and a
//! trailing `\n`. No ANSI escapes: the pre-lift consumers spelled
//! bare `println!` (not one of the `colored` palette wrappers), so
//! the emitted line carries zero `\x1b` bytes.
//!
//! # THEORY grounding
//!
//! §V solve-once-at-the-primitive: the reminder shape lives at ONE
//! construction surface so a future refinement — a rewording of
//! "Don't forget to commit" to a shorter "Remember to commit" imperative,
//! a promotion of the three-space indent to a bullet glyph, an OTLP
//! `regenerated_lockfile_reminder_emitted` observability hook wired
//! alongside the print — lands in one place rather than at every
//! consumer of the `Don't forget to commit ...` idiom.
//!
//! §VI.1 three-is-a-law: three sites today (two Cargo + one Ruby),
//! and the archetype closes on the (lockfile, generated file) coupling
//! so a future `poetry2nix` / `mix2nix` / `cabal2nix` regenerate
//! command reaches for the same primitive on first grep rather than
//! copying the reminder line into a fourth inline site.

use std::io;

/// The (lockfile, generated file) pair coupled by an ecosystem's
/// regeneration step. A closed enum forecloses (a) typing one filename
/// without its partner, (b) swapping the pair's order in the reminder
/// slot, and (c) fabricating a pair the crate does not actually
/// regenerate.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum RegeneratedLockfilePair {
    /// Rust workspace pair: `Cargo.lock` (lockfile) + `Cargo.nix`
    /// (generated by `crate2nix generate`). Consumed by
    /// `commands/pangea.rs::regenerate` and
    /// `commands/bootstrap.rs::regenerate`.
    CargoNix,
    /// Ruby pair: `Gemfile.lock` (lockfile updated by
    /// `bundle lock --update`) + `gemset.nix` (generated by `bundix`).
    /// Consumed by `commands/pangea.rs::regenerate_compiler`.
    GemsetNix,
}

impl RegeneratedLockfilePair {
    /// Return the `(lockfile, generated_file)` pair for this variant,
    /// in that order. The order is the invariant the pre-lift
    /// `println!("... {} and {} files.", <lock>, <gen>)` stanzas
    /// spelled and the byte-oracle
    /// [`tests::write_regenerated_lockfile_commit_reminder_orders_lockfile_before_generated_file`]
    /// pins.
    pub const fn file_pair(self) -> (&'static str, &'static str) {
        match self {
            Self::CargoNix => ("Cargo.lock", "Cargo.nix"),
            Self::GemsetNix => ("Gemfile.lock", "gemset.nix"),
        }
    }
}

/// Print the post-regenerate commit-reminder stanza — a
/// `   Don't forget to commit the updated <lock> and <generated>
/// files.` line — to [`std::io::stdout()`].
///
/// The three consumer sites in `cli/src/commands/pangea.rs::regenerate`,
/// `cli/src/commands/pangea.rs::regenerate_compiler`, and
/// `cli/src/commands/bootstrap.rs::regenerate` each spelled this
/// stanza as an inline `println!("   Don't forget to commit the
/// updated {} and {} files.", <lock>, <gen>)` pre-lift; post-lift
/// they all forward through this function.
///
/// Delegates to [`write_regenerated_lockfile_commit_reminder`] against
/// a locked stdout handle; the writer split exists so the
/// fail-before-pass tests can pin the emitted bytes without
/// capturing stdout.
pub fn print_regenerated_lockfile_commit_reminder(pair: RegeneratedLockfilePair) {
    let _ = write_regenerated_lockfile_commit_reminder(&mut std::io::stdout().lock(), pair);
}

/// Writer-taking sibling of [`print_regenerated_lockfile_commit_reminder`].
/// Emits the single `   Don't forget to commit the updated <lock> and
/// <generated> files.` line via [`writeln!`] against the supplied
/// writer.
///
/// # Byte contract
///
/// The rendered byte sequence is exactly what the pre-lift
/// `println!("   Don't forget to commit the updated {} and {} files.",
/// <lock>, <gen>)` stanzas produced: a three-ASCII-space indent, the
/// fixed reminder body with the pair interpolated in `(lockfile,
/// generated file)` order, and a single trailing `\n`. No ANSI escape
/// sequences: pre-lift consumers spelled bare `println!`, not one of
/// the [`colored`] palette wrappers.
///
/// # Pair-order invariant
///
/// The `(lockfile, generated file)` argument lands at exactly two
/// positions in the emitted line: the lockfile precedes the ` and `
/// separator, the generated file follows it. A future refactor that
/// (a) swapped the two slots, (b) added a third slot, or
/// (c) collapsed the ` and ` separator to `, ` would fail the
/// `write_regenerated_lockfile_commit_reminder_orders_lockfile_before_generated_file`
/// oracle below.
pub fn write_regenerated_lockfile_commit_reminder<W: io::Write>(
    w: &mut W,
    pair: RegeneratedLockfilePair,
) -> io::Result<()> {
    let (lockfile, generated) = pair.file_pair();
    writeln!(
        w,
        "   Don't forget to commit the updated {lockfile} and {generated} files."
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-oracle: the writer emits exactly ONE line, terminated by
    /// a single `\n`. A refactor that (a) split the reminder across
    /// two lines (e.g., moving `files.` onto a follow-up `println!`
    /// call) or (b) doubled the trailing newline (e.g., inserting a
    /// framing blank the way `print_stage_completion_ack` does) would
    /// flip this assertion.
    #[test]
    fn write_regenerated_lockfile_commit_reminder_emits_one_line() {
        for pair in [
            RegeneratedLockfilePair::CargoNix,
            RegeneratedLockfilePair::GemsetNix,
        ] {
            let mut buf: Vec<u8> = Vec::new();
            write_regenerated_lockfile_commit_reminder(&mut buf, pair).unwrap();
            let out = String::from_utf8(buf).expect("writer emits valid UTF-8");
            assert!(
                out.ends_with('\n'),
                "writer output for {pair:?} must end with exactly one `\\n`; got {out:?}"
            );
            assert_eq!(
                out.matches('\n').count(),
                1,
                "writer output for {pair:?} must emit exactly one line-terminating `\\n`; \
                 got {out:?}"
            );
        }
    }

    /// Byte-oracle: the emitted line opens with a three-ASCII-space
    /// indent (`\x20\x20\x20`) — the pre-lift `"   "` prefix every
    /// consumer spelled inline. A drift that (a) swapped the indent
    /// for two spaces, (b) promoted the reminder to a `- ` bullet
    /// glyph, (c) added a `💡 ` hint emoji, or (d) removed the indent
    /// entirely would fail here.
    #[test]
    fn write_regenerated_lockfile_commit_reminder_opens_with_three_space_indent() {
        for pair in [
            RegeneratedLockfilePair::CargoNix,
            RegeneratedLockfilePair::GemsetNix,
        ] {
            let mut buf: Vec<u8> = Vec::new();
            write_regenerated_lockfile_commit_reminder(&mut buf, pair).unwrap();
            let bytes = buf.as_slice();
            assert!(
                bytes.starts_with(b"   "),
                "writer output for {pair:?} must open with three ASCII \
                 spaces (the pre-lift indent every consumer spelled); \
                 got {bytes:?}"
            );
            // First non-space byte must be the ASCII `D` of `Don't`,
            // not a fourth space or a glyph byte.
            assert_eq!(
                bytes.get(3),
                Some(&b'D'),
                "writer output for {pair:?} must place `D` (of `Don't`) \
                 immediately after the three-space indent; got {bytes:?}"
            );
        }
    }

    /// Byte-oracle: the `CargoNix` variant renders the pre-lift Cargo
    /// literal byte-for-byte. Pins the three-space indent, the
    /// `Don't forget to commit the updated ` opener, the
    /// `Cargo.lock and Cargo.nix` pair with the ` and ` separator,
    /// and the ` files.` closer.
    #[test]
    fn write_regenerated_lockfile_commit_reminder_cargo_nix_variant_emits_pre_lift_literal() {
        let mut buf: Vec<u8> = Vec::new();
        write_regenerated_lockfile_commit_reminder(&mut buf, RegeneratedLockfilePair::CargoNix)
            .unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert_eq!(
            out, "   Don't forget to commit the updated Cargo.lock and Cargo.nix files.\n",
            "CargoNix variant must render the pre-lift Cargo literal \
             byte-for-byte; got {out:?}"
        );
    }

    /// Byte-oracle: the `GemsetNix` variant renders the pre-lift Ruby
    /// literal byte-for-byte. Pins the three-space indent, the
    /// `Don't forget to commit the updated ` opener, the
    /// `Gemfile.lock and gemset.nix` pair with the ` and ` separator
    /// (note the ASCII-lowercase `gemset` — a drift to `Gemset.nix`
    /// would flip this assertion), and the ` files.` closer.
    #[test]
    fn write_regenerated_lockfile_commit_reminder_gemset_nix_variant_emits_pre_lift_literal() {
        let mut buf: Vec<u8> = Vec::new();
        write_regenerated_lockfile_commit_reminder(&mut buf, RegeneratedLockfilePair::GemsetNix)
            .unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert_eq!(
            out, "   Don't forget to commit the updated Gemfile.lock and gemset.nix files.\n",
            "GemsetNix variant must render the pre-lift Ruby literal \
             byte-for-byte; got {out:?}"
        );
    }

    /// Interpolation-position pin: the lockfile lands BEFORE the
    /// generated file inside the emitted line, with a ` and `
    /// separator between them (single ASCII spaces on either side of
    /// `and`). A refactor that (a) swapped the two slots (rendering
    /// `Cargo.nix and Cargo.lock`), (b) collapsed the separator to
    /// `, `, or (c) doubled the lockfile echo would fail here.
    #[test]
    fn write_regenerated_lockfile_commit_reminder_orders_lockfile_before_generated_file() {
        for pair in [
            RegeneratedLockfilePair::CargoNix,
            RegeneratedLockfilePair::GemsetNix,
        ] {
            let (lockfile, generated) = pair.file_pair();
            let mut buf: Vec<u8> = Vec::new();
            write_regenerated_lockfile_commit_reminder(&mut buf, pair).unwrap();
            let out = String::from_utf8(buf).unwrap();
            let lock_pos = out.find(lockfile).unwrap_or_else(|| {
                panic!("writer output for {pair:?} must contain lockfile {lockfile:?}; got {out:?}")
            });
            let gen_pos = out.find(generated).unwrap_or_else(|| {
                panic!(
                    "writer output for {pair:?} must contain generated file {generated:?}; \
                     got {out:?}"
                )
            });
            assert!(
                lock_pos < gen_pos,
                "writer output for {pair:?} must place lockfile {lockfile:?} \
                 BEFORE generated file {generated:?}; got {out:?}"
            );
            let expected_separator = format!("{lockfile} and {generated}");
            assert!(
                out.contains(&expected_separator),
                "writer output for {pair:?} must join the pair with a single \
                 ` and ` separator (`{expected_separator}`); got {out:?}"
            );
            assert_eq!(
                out.matches(lockfile).count(),
                1,
                "lockfile {lockfile:?} must appear exactly ONCE in the emitted \
                 line for {pair:?}; got {out:?}"
            );
            assert_eq!(
                out.matches(generated).count(),
                1,
                "generated file {generated:?} must appear exactly ONCE in the \
                 emitted line for {pair:?}; got {out:?}"
            );
        }
    }

    /// Byte-oracle: the writer emits NO ANSI escape sequences. The
    /// pre-lift consumers spelled bare `println!`, not one of the
    /// [`colored`] palette wrappers (no `.bright_green()`, no
    /// `.dimmed()`, no `.yellow()` on the reminder body). A future
    /// refactor that promoted the reminder to a colored hint would
    /// fail here.
    #[test]
    fn write_regenerated_lockfile_commit_reminder_carries_no_ansi_escapes() {
        for pair in [
            RegeneratedLockfilePair::CargoNix,
            RegeneratedLockfilePair::GemsetNix,
        ] {
            let mut buf: Vec<u8> = Vec::new();
            write_regenerated_lockfile_commit_reminder(&mut buf, pair).unwrap();
            assert!(
                !buf.contains(&0x1b),
                "writer output for {pair:?} must carry no `\\x1b` ANSI \
                 escape bytes — the pre-lift consumers spelled bare \
                 `println!`, not a `colored` palette wrapper; got {buf:?}"
            );
        }
    }

    /// Variant-distinctness pin: `CargoNix` and `GemsetNix` MUST
    /// render distinct byte sequences. A drift that made both
    /// variants render the same output (e.g., a stub `file_pair`
    /// that always returned the Cargo tuple) would fail here.
    #[test]
    fn regenerated_lockfile_pair_variants_are_distinct() {
        let mut cargo_buf: Vec<u8> = Vec::new();
        let mut gem_buf: Vec<u8> = Vec::new();
        write_regenerated_lockfile_commit_reminder(
            &mut cargo_buf,
            RegeneratedLockfilePair::CargoNix,
        )
        .unwrap();
        write_regenerated_lockfile_commit_reminder(
            &mut gem_buf,
            RegeneratedLockfilePair::GemsetNix,
        )
        .unwrap();
        assert_ne!(
            cargo_buf, gem_buf,
            "CargoNix and GemsetNix must render distinct byte sequences; \
             a shared body would collapse two ecosystems onto one reminder"
        );
    }

    /// `file_pair` invariants: each variant returns a pair of
    /// non-empty distinct filenames, with the lockfile named `.lock`
    /// and the generated file named `.nix`. Pins the two-file
    /// coupling every regenerate step in the crate spells.
    #[test]
    fn regenerated_lockfile_pair_file_pair_invariants() {
        for pair in [
            RegeneratedLockfilePair::CargoNix,
            RegeneratedLockfilePair::GemsetNix,
        ] {
            let (lockfile, generated) = pair.file_pair();
            assert!(!lockfile.is_empty(), "{pair:?} lockfile must be non-empty");
            assert!(
                !generated.is_empty(),
                "{pair:?} generated file must be non-empty"
            );
            assert_ne!(
                lockfile, generated,
                "{pair:?} lockfile and generated file must differ"
            );
            assert!(
                lockfile.ends_with(".lock"),
                "{pair:?} lockfile must end in `.lock`; got {lockfile:?}"
            );
            assert!(
                generated.ends_with(".nix"),
                "{pair:?} generated file must end in `.nix`; got {generated:?}"
            );
        }
    }

    /// Post-lift shield (negative half): no source line under
    /// `cli/src/commands/` may still spell the pre-lift raw literal
    /// `"   Don't forget to commit the updated "` inline. Every
    /// consumer reaches for
    /// [`print_regenerated_lockfile_commit_reminder`] on first grep,
    /// not by copy-pasting the raw literal into a bespoke `println!`
    /// stanza.
    #[test]
    fn no_command_module_still_spells_raw_regenerated_lockfile_commit_reminder() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let needle = "Don't forget to commit the updated";
        let mut offenders: Vec<(PathBuf, usize, String)> = Vec::new();
        for entry in std::fs::read_dir(&commands_dir).unwrap().flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).unwrap();
            let mut in_block_comment = false;
            for (idx, line) in source.lines().enumerate() {
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") || trimmed.starts_with("///") {
                    continue;
                }
                if trimmed.starts_with("/*") {
                    in_block_comment = true;
                }
                if in_block_comment {
                    if trimmed.contains("*/") {
                        in_block_comment = false;
                    }
                    continue;
                }
                if line.contains(needle) {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `Don't forget to commit the updated ...` literal(s) survive \
             under `commands/` — route each through \
             `crate::regenerated_lockfile_commit_reminder::\
             print_regenerated_lockfile_commit_reminder(<pair>)` instead:\n{:#?}",
            offenders
        );
    }

    /// Post-lift shield (positive half): the two pre-lift modules
    /// that housed the three sites MUST each forward through
    /// [`print_regenerated_lockfile_commit_reminder`] at least the
    /// pre-lift count of times, so a migration that dropped a call
    /// site outright leaves the negative "no raw inline shape" scan
    /// trivially satisfied by absence but the positive count still
    /// fails. Mirrors the sibling
    /// `every_prelift_module_forwards_through_*` shields the crate
    /// carries against every other typed primitive.
    #[test]
    fn every_prelift_module_forwards_through_print_regenerated_lockfile_commit_reminder() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        // pangea.rs = 2 (regenerate + regenerate_compiler),
        // bootstrap.rs = 1 (regenerate).
        let expectations: &[(&str, usize)] = &[("pangea.rs", 2), ("bootstrap.rs", 1)];
        let needle = "print_regenerated_lockfile_commit_reminder(";
        for (basename, min_count) in expectations {
            let path = commands_dir.join(basename);
            let source = std::fs::read_to_string(&path)
                .unwrap_or_else(|_| panic!("expected {} to exist", path.display()));
            let forwards = source.matches(needle).count();
            assert!(
                forwards >= *min_count,
                "{basename} must forward at least {min_count} \
                 post-regenerate reminder stanza(s) through `{needle}`; \
                 found {forwards}. A dropped call would leave the \
                 negative raw-shape scan satisfied by absence.",
            );
        }
    }
}
