//! `Pangea <generated-file> regenerated successfully!` + commit-reminder
//! success-banner-plus-reminder primitive.
//!
//! # Duplication being lifted
//!
//! Two byte-identical sibling stanzas across `commands/pangea.rs`
//! (`regenerate` at ~L482-493 + `regenerate_compiler` at ~L551-562)
//! each spelled the same four-line success-banner + reminder
//! ceremony around one [`RegeneratedLockfilePair`] axis:
//!
//! ```ignore
//! println!();
//! println!(
//!     "{}",
//!     "Pangea <GENERATED> regenerated successfully!"
//!         .bright_green()
//!         .bold()
//! );
//! crate::regenerated_lockfile_commit_reminder::print_regenerated_lockfile_commit_reminder(
//!     crate::regenerated_lockfile_commit_reminder::RegeneratedLockfilePair::<VARIANT>,
//! );
//! println!();
//! ```
//!
//! The `<GENERATED>` slot and `<VARIANT>` slot are correlated — for
//! `regenerate` both spell the `Cargo.nix` half of
//! [`RegeneratedLockfilePair::CargoNix`], and for `regenerate_compiler`
//! both spell the `gemset.nix` half of
//! [`RegeneratedLockfilePair::GemsetNix`]. Pre-lift a drift between the
//! two — a caller who typed `"gemset.nix"` in the banner slot but
//! passed `RegeneratedLockfilePair::CargoNix` to the reminder, or vice
//! versa — was structurally possible. Post-lift the primitive projects
//! the banner's `<GENERATED>` slot from the same
//! [`RegeneratedLockfilePair::file_pair`] the reminder consumes, so
//! the two slots co-vary by construction.
//!
//! # Closed-enum axis
//!
//! The banner-plus-reminder is driven by the already-typed
//! [`RegeneratedLockfilePair`] enum defined in
//! [`crate::regenerated_lockfile_commit_reminder`]. The two variants
//! today are:
//!
//! * [`RegeneratedLockfilePair::CargoNix`] — banner spells
//!   `"Pangea Cargo.nix regenerated successfully!"` and the reminder
//!   spells the `Cargo.lock` + `Cargo.nix` pair.
//! * [`RegeneratedLockfilePair::GemsetNix`] — banner spells
//!   `"Pangea gemset.nix regenerated successfully!"` and the reminder
//!   spells the `Gemfile.lock` + `gemset.nix` pair.
//!
//! A future ecosystem that adds a third pair (e.g., `poetry.lock` +
//! `poetry2nix.nix`) grows a third variant on the shared enum and
//! reaches this primitive on first grep rather than copying the four-
//! line stanza into a fresh call site.
//!
//! # Distinct from the sibling primitives
//!
//! - [`crate::regenerated_lockfile_commit_reminder::print_regenerated_lockfile_commit_reminder`]
//!   owns ONLY the `Don't forget to commit the updated <lock> and
//!   <generated> files.` one-line reminder. That primitive is called
//!   verbatim by BOTH pre-lift sibling stanzas AND by the sibling
//!   `commands/bootstrap.rs::regenerate` (which uses a different
//!   banner shape — `crate::ui::print_success(...)`, with an `✅`
//!   glyph prefix — so it stays outside the two-sibling banner lift
//!   here). This primitive fuses the reminder call with the Pangea-
//!   specific `bright_green().bold()` banner and the framing blank
//!   lines above and below, without the `✅` glyph.
//! - [`crate::ui::write_success`] emits `✅ <msg>` in
//!   `bright_green().bold()`. Pre-lift the two Pangea sites deliberately
//!   emitted the banner WITHOUT the `✅` glyph — a byte contract this
//!   primitive preserves. A future edit that decided every Pangea
//!   regenerate command deserved the `✅` glyph would flip the
//!   [`tests::write_pangea_regenerate_success_and_reminder_banner_omits_success_glyph`]
//!   oracle and forces a conscious decision, not a silent drift.
//!
//! # Byte contract
//!
//! [`print_pangea_regenerate_success_and_reminder`] and its writer
//! sibling [`write_pangea_regenerate_success_and_reminder`] emit
//! exactly the same bytes the pre-lift four-line stanzas produced:
//!
//! 1. A leading blank line (single `\n`).
//! 2. `Pangea <generated> regenerated successfully!` wrapped in
//!    `.bright_green().bold()` (in a non-TTY sink, zero ANSI escapes;
//!    matching pre-lift `println!("{}", "…".bright_green().bold())`).
//! 3. The reminder line delegated verbatim to
//!    [`crate::regenerated_lockfile_commit_reminder::write_regenerated_lockfile_commit_reminder`].
//! 4. A trailing blank line (single `\n`).
//!
//! # THEORY grounding
//!
//! - THEORY.md §I.5 (duplication budget zero; every recurring shape
//!   becomes a helper before it becomes duplicated code): two byte-
//!   identical sibling stanzas past the two-occurrence coincidence
//!   threshold collapse to ONE construction surface.
//! - THEORY.md §V.2 (typed absorption): the already-typed
//!   [`RegeneratedLockfilePair`] enum absorbs the (banner-file,
//!   reminder-pair) correlation so a caller cannot silently type one
//!   half without the other.
//! - THEORY.md §VI.1 (solve-once-at-the-primitive): a future rewording
//!   of the `Pangea <X> regenerated successfully!` banner, promotion
//!   of the banner from `.bright_green()` to a different palette, or
//!   addition of an OTLP `pangea_regenerate_completed` observability
//!   hook alongside the banner lands at ONE writer body rather than at
//!   every consumer of the pre-lift four-line stanza.

use colored::Colorize;
use std::io;

use crate::regenerated_lockfile_commit_reminder::{
    write_regenerated_lockfile_commit_reminder, RegeneratedLockfilePair,
};

/// Print the four-line Pangea `<generated-file> regenerated
/// successfully!` success-banner + commit-reminder + framing-blank
/// stanza — the fusion of the pre-lift `println!` blank + the
/// `.bright_green().bold()` banner + the
/// [`crate::regenerated_lockfile_commit_reminder`] one-line reminder +
/// the trailing `println!` blank — to [`std::io::stdout()`].
///
/// The two consumer sites in `commands/pangea.rs::regenerate` and
/// `commands/pangea.rs::regenerate_compiler` each spelled this stanza
/// as a four-line inline sequence pre-lift; post-lift both forward
/// through this function.
///
/// Delegates to [`write_pangea_regenerate_success_and_reminder`]
/// against a locked stdout handle; the writer split exists so the
/// fail-before-pass tests can pin the emitted bytes without capturing
/// stdout.
pub fn print_pangea_regenerate_success_and_reminder(pair: RegeneratedLockfilePair) {
    let _ = write_pangea_regenerate_success_and_reminder(&mut std::io::stdout().lock(), pair);
}

/// Writer-taking sibling of
/// [`print_pangea_regenerate_success_and_reminder`]. Emits the four-
/// line stanza (leading blank, coloured banner, reminder, trailing
/// blank) via [`writeln!`] against the supplied writer.
///
/// # Byte contract
///
/// The rendered byte sequence is exactly what the pre-lift four-line
/// `println!` stanzas produced: a leading `\n`, then the
/// `Pangea <generated> regenerated successfully!` banner wrapped in
/// `.bright_green().bold()` (bare bytes in a non-TTY sink such as a
/// `Vec<u8>` — colored's control auto-detects and drops ANSI escapes
/// when the sink is not a terminal), then the reminder line as
/// [`write_regenerated_lockfile_commit_reminder`] emits it, then a
/// trailing `\n`. Total four `\n` bytes.
///
/// # Delegation invariant
///
/// The reminder half is delegated verbatim to
/// [`write_regenerated_lockfile_commit_reminder`] — a future rewording
/// of `"Don't forget to commit the updated ..."` lands at that
/// module's writer, and this primitive picks the change up by
/// construction. The composition-shield test below pins that the
/// reminder writer is actually invoked (not re-inlined).
pub fn write_pangea_regenerate_success_and_reminder<W: io::Write>(
    w: &mut W,
    pair: RegeneratedLockfilePair,
) -> io::Result<()> {
    let (_lockfile, generated) = pair.file_pair();
    writeln!(w)?;
    writeln!(
        w,
        "{}",
        format!("Pangea {generated} regenerated successfully!")
            .bright_green()
            .bold()
    )?;
    write_regenerated_lockfile_commit_reminder(w, pair)?;
    writeln!(w)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-oracle: the writer emits exactly FOUR `\n` bytes — one
    /// leading blank, one for the banner, one for the reminder, and
    /// one trailing blank. A refactor that (a) collapsed the banner
    /// onto the leading blank, (b) dropped either framing blank, or
    /// (c) added an extra separator would flip this assertion.
    #[test]
    fn write_pangea_regenerate_success_and_reminder_emits_four_lines() {
        for pair in [
            RegeneratedLockfilePair::CargoNix,
            RegeneratedLockfilePair::GemsetNix,
        ] {
            let mut buf: Vec<u8> = Vec::new();
            write_pangea_regenerate_success_and_reminder(&mut buf, pair).unwrap();
            let out = String::from_utf8(buf).expect("writer emits valid UTF-8");
            assert_eq!(
                out.matches('\n').count(),
                4,
                "writer output for {pair:?} must emit exactly four \
                 `\\n` bytes (leading blank + banner + reminder + \
                 trailing blank); got {out:?}"
            );
            assert!(
                out.starts_with('\n'),
                "writer output for {pair:?} must open with a leading \
                 blank line; got {out:?}"
            );
            assert!(
                out.ends_with('\n'),
                "writer output for {pair:?} must end with a trailing \
                 `\\n`; got {out:?}"
            );
        }
    }

    /// Byte-oracle: the `CargoNix` variant renders the pre-lift Pangea
    /// Cargo four-line stanza byte-for-byte in a non-TTY sink. Pins
    /// the leading blank, the `Pangea Cargo.nix regenerated
    /// successfully!` banner, the `Cargo.lock and Cargo.nix` reminder
    /// pair, and the trailing blank — the exact bytes the pre-lift
    /// `commands/pangea.rs::regenerate` stanza emitted.
    #[test]
    fn write_pangea_regenerate_success_and_reminder_cargo_nix_variant_emits_pre_lift_literal() {
        let mut buf: Vec<u8> = Vec::new();
        write_pangea_regenerate_success_and_reminder(&mut buf, RegeneratedLockfilePair::CargoNix)
            .unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert_eq!(
            out,
            "\n\
             Pangea Cargo.nix regenerated successfully!\n\
             \x20\x20\x20Don't forget to commit the updated Cargo.lock and Cargo.nix files.\n\
             \n",
            "CargoNix variant must render the pre-lift four-line \
             Cargo stanza byte-for-byte in a non-TTY sink; got {out:?}"
        );
    }

    /// Byte-oracle: the `GemsetNix` variant renders the pre-lift
    /// Pangea Ruby four-line stanza byte-for-byte in a non-TTY sink.
    /// Pins the leading blank, the `Pangea gemset.nix regenerated
    /// successfully!` banner (note the ASCII-lowercase `gemset` — a
    /// drift to `Gemset.nix` would flip this assertion), the
    /// `Gemfile.lock and gemset.nix` reminder pair, and the trailing
    /// blank — the exact bytes the pre-lift
    /// `commands/pangea.rs::regenerate_compiler` stanza emitted.
    #[test]
    fn write_pangea_regenerate_success_and_reminder_gemset_nix_variant_emits_pre_lift_literal() {
        let mut buf: Vec<u8> = Vec::new();
        write_pangea_regenerate_success_and_reminder(&mut buf, RegeneratedLockfilePair::GemsetNix)
            .unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert_eq!(
            out,
            "\n\
             Pangea gemset.nix regenerated successfully!\n\
             \x20\x20\x20Don't forget to commit the updated Gemfile.lock and gemset.nix files.\n\
             \n",
            "GemsetNix variant must render the pre-lift four-line \
             Ruby stanza byte-for-byte in a non-TTY sink; got {out:?}"
        );
    }

    /// Banner-slot co-variance: the banner's `<generated>` slot is
    /// projected from [`RegeneratedLockfilePair::file_pair`]`.1`, the
    /// SAME projection the reminder half consumes. A refactor that
    /// (a) hard-coded `"Cargo.nix"` in the banner regardless of the
    /// pair, (b) swapped the banner to consume `.0` (the lockfile
    /// rather than the generated file), or (c) introduced a
    /// per-caller banner override would flip this assertion for one
    /// of the two variants.
    #[test]
    fn write_pangea_regenerate_success_and_reminder_banner_uses_generated_file_of_pair() {
        for pair in [
            RegeneratedLockfilePair::CargoNix,
            RegeneratedLockfilePair::GemsetNix,
        ] {
            let (_lockfile, generated) = pair.file_pair();
            let mut buf: Vec<u8> = Vec::new();
            write_pangea_regenerate_success_and_reminder(&mut buf, pair).unwrap();
            let out = String::from_utf8(buf).unwrap();
            let expected_banner = format!("Pangea {generated} regenerated successfully!");
            assert!(
                out.contains(&expected_banner),
                "banner slot for {pair:?} must interpolate the \
                 generated file {generated:?} as `Pangea <X> \
                 regenerated successfully!`; got {out:?}"
            );
        }
    }

    /// Banner glyph shield: the Pangea banner deliberately does NOT
    /// carry the `✅` prefix the sibling
    /// [`crate::ui::print_success`] adapter prepends — pre-lift the
    /// two Pangea sites emitted `.bright_green().bold()` bytes without
    /// the check-mark glyph, and the sibling
    /// `commands/bootstrap.rs::regenerate` uses
    /// [`crate::ui::print_success`] (which DOES prefix `✅ `) instead,
    /// so bootstrap stays outside this two-sibling lift and its byte
    /// contract stays unchanged. A refactor that promoted the Pangea
    /// banner to `crate::ui::print_success(...)` internally would
    /// silently regress the pre-lift Pangea byte contract; this
    /// oracle fails it first.
    #[test]
    fn write_pangea_regenerate_success_and_reminder_banner_omits_success_glyph() {
        for pair in [
            RegeneratedLockfilePair::CargoNix,
            RegeneratedLockfilePair::GemsetNix,
        ] {
            let mut buf: Vec<u8> = Vec::new();
            write_pangea_regenerate_success_and_reminder(&mut buf, pair).unwrap();
            let out = String::from_utf8(buf).unwrap();
            assert!(
                !out.contains('\u{2705}'),
                "Pangea banner for {pair:?} must NOT carry the `✅` \
                 (U+2705) glyph — that decoration belongs to the \
                 sibling `crate::ui::print_success` adapter used by \
                 `commands/bootstrap.rs::regenerate`; got {out:?}"
            );
        }
    }

    /// Reminder delegation: the reminder half must render EXACTLY the
    /// bytes [`write_regenerated_lockfile_commit_reminder`] emits for
    /// the same pair — the primitive delegates rather than re-inlines
    /// the reminder body. A future rewording of `"Don't forget to
    /// commit ..."` at the reminder module must reach this primitive
    /// by construction; a copy-paste of the reminder body inline
    /// would silently drift once the reminder module changes.
    #[test]
    fn write_pangea_regenerate_success_and_reminder_delegates_reminder_verbatim() {
        for pair in [
            RegeneratedLockfilePair::CargoNix,
            RegeneratedLockfilePair::GemsetNix,
        ] {
            let mut reminder_buf: Vec<u8> = Vec::new();
            write_regenerated_lockfile_commit_reminder(&mut reminder_buf, pair).unwrap();
            let reminder_line = String::from_utf8(reminder_buf).unwrap();

            let mut full_buf: Vec<u8> = Vec::new();
            write_pangea_regenerate_success_and_reminder(&mut full_buf, pair).unwrap();
            let full = String::from_utf8(full_buf).unwrap();

            assert!(
                full.contains(&reminder_line),
                "primitive output for {pair:?} must contain the \
                 reminder-writer output verbatim (delegation \
                 invariant); reminder was {reminder_line:?}, full \
                 was {full:?}"
            );
        }
    }

    /// Framing invariant: the leading blank and trailing blank BOTH
    /// live inside the primitive — a caller must not need to add
    /// their own `println!()` above or below the call to reproduce
    /// the pre-lift four-line shape. A drift that dropped either
    /// framing blank inside the primitive would flip either the
    /// `starts_with('\n')` or `ends_with("\n\n")` check here.
    #[test]
    fn write_pangea_regenerate_success_and_reminder_frames_with_blank_lines() {
        for pair in [
            RegeneratedLockfilePair::CargoNix,
            RegeneratedLockfilePair::GemsetNix,
        ] {
            let mut buf: Vec<u8> = Vec::new();
            write_pangea_regenerate_success_and_reminder(&mut buf, pair).unwrap();
            let out = String::from_utf8(buf).unwrap();
            assert!(
                out.starts_with('\n'),
                "primitive output for {pair:?} must open with a \
                 leading blank line inside the primitive (not left to \
                 the caller); got {out:?}"
            );
            assert!(
                out.ends_with("\n\n"),
                "primitive output for {pair:?} must end with the \
                 reminder line's `\\n` followed by a trailing blank \
                 `\\n` inside the primitive; got {out:?}"
            );
        }
    }

    /// Signature pin: the emit helper accepts a
    /// [`RegeneratedLockfilePair`] and returns `()`. A widening (say
    /// to take a per-caller banner-prefix override, dropping the
    /// closed-enum invariant that keeps the banner slot in lockstep
    /// with the reminder pair) would ripple to both call sites and
    /// trip the type check.
    #[test]
    fn print_pangea_regenerate_success_and_reminder_signature_pins_single_pair_arg() {
        let _: fn(RegeneratedLockfilePair) = print_pangea_regenerate_success_and_reminder;
    }

    /// Delegation shield: the two `commands/pangea.rs` regenerate
    /// success-banner + reminder stanzas (`regenerate` at ~L482-493
    /// and `regenerate_compiler` at ~L551-562) MUST route through
    /// [`print_pangea_regenerate_success_and_reminder`] rather than
    /// re-spelling the pre-lift four-line stanza inline. The shield
    /// reads `commands/pangea.rs` and rejects any raw
    /// `"Pangea Cargo.nix regenerated successfully!"` /
    /// `"Pangea gemset.nix regenerated successfully!"` banner literal
    /// that survived the lift.
    #[test]
    fn pangea_regenerate_banner_callers_delegate_through_primitive() {
        let source = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/commands/pangea.rs",
        ))
        .expect("commands/pangea.rs must be readable at this manifest-relative path");

        let body =
            crate::test_support::module_body_before_first_cfg_test(&source, "commands/pangea.rs");

        for needle in [
            "\"Pangea Cargo.nix regenerated successfully!\"",
            "\"Pangea gemset.nix regenerated successfully!\"",
        ] {
            assert!(
                !body.contains(needle),
                "raw {needle} banner literal survived in \
                 commands/pangea.rs — this stanza MUST route through \
                 crate::pangea_regenerate_success_and_reminder::\
                 print_pangea_regenerate_success_and_reminder with a \
                 RegeneratedLockfilePair variant"
            );
        }

        // Positive delegation: the primitive is invoked exactly twice
        // in commands/pangea.rs (once per closed dialect). A future
        // refactor that dropped a call would slip past the negative
        // shield above, so pin the forward-hit count too.
        let hits = body
            .matches(
                "crate::pangea_regenerate_success_and_reminder::\
                 print_pangea_regenerate_success_and_reminder(",
            )
            .count();
        assert_eq!(
            hits, 2,
            "expected exactly 2 print_pangea_regenerate_success_and_reminder \
             delegations in commands/pangea.rs (regenerate + \
             regenerate_compiler); got {hits}"
        );
    }

    /// Negative sibling-body shield: neither
    /// `commands/pangea.rs::regenerate` nor
    /// `commands/pangea.rs::regenerate_compiler` may reintroduce the
    /// pre-lift four-line stanza by re-inlining the raw
    /// `.bright_green().bold()` call chain around a `"Pangea "` +
    /// `"regenerated successfully!"` literal. The
    /// bounded-fn-body scan pins that neither function body carries
    /// the pre-lift `.bright_green()` needle on its own.
    ///
    /// The Pangea-image push success banner at ~L207 of the same
    /// module also spells `.bright_green().bold()`, but its literal
    /// (`"Pangea image pushed successfully!"`) differs from the two
    /// regenerate banners this shield defends — that site stays
    /// outside the primitive's scope and outside the two bounded
    /// scans here.
    #[test]
    fn pangea_regenerate_bodies_carry_no_raw_bright_green_bold_banner() {
        let source = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/commands/pangea.rs",
        ))
        .expect("commands/pangea.rs must be readable at this manifest-relative path");

        for (fn_marker, end_marker) in [
            (
                "pub async fn regenerate(pangea_dir: Option<String>) -> Result<()> {",
                "\n/// Regenerate gemset.nix for Pangea Ruby compiler\n",
            ),
            (
                "pub async fn regenerate_compiler() -> Result<()> {",
                "\n// ============================================================================\n",
            ),
        ] {
            let fn_body = crate::test_support::fn_body_slice_between_markers(
                &source,
                "commands/pangea.rs",
                fn_marker,
                end_marker,
            );
            assert!(
                !fn_body.contains("regenerated successfully!\""),
                "fn body starting at {fn_marker:?} must NOT re-inline \
                 the pre-lift `\"...regenerated successfully!\"` \
                 banner literal — route through \
                 crate::pangea_regenerate_success_and_reminder::\
                 print_pangea_regenerate_success_and_reminder instead"
            );
        }
    }
}
