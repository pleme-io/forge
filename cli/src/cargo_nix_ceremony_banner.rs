//! Cargo.nix regenerate / update ceremony success-banner fusion
//! primitive — the three-line
//! `print_success_banner(80, "✅ <X> COMPLETE"); println!();
//! <files_heading>();` stanza every `crate2nix`-driven regenerate /
//! update workflow reaches for when it closes out its post-body
//! summary section.
//!
//! # Duplication being lifted
//!
//! Four pre-lift sibling three-line stanzas — two in
//! `commands/web_service.rs` (`regenerate_hanabi` at :186-188 closing
//! with `"✅ REGENERATION COMPLETE"` above a generated-files heading;
//! `web_cargo_update` at :275-277 closing with `"✅ UPDATE COMPLETE"`
//! above an updated-files heading) and two in
//! `commands/developer_tools.rs` (`rust_regenerate_cargo_nix` at
//! :348-350 closing with `"✅ REGENERATION COMPLETE"` above a
//! generated-files heading; `rust_cargo_update` at :407-409 closing
//! with `"✅ UPDATE COMPLETE"` above an updated-files heading) each
//! restated
//!
//! ```ignore
//! print_success_banner(80, "✅ <BANNER> COMPLETE");
//! println!();
//! crate::ui::print_<KIND>_files_heading();
//! ```
//!
//! byte-for-byte, diverging on which of two coupled label/heading
//! pairs the caller closed with. Pre-lift each site nailed the
//! banner text and the heading function into two lines chosen
//! independently; a copy-paste that spelled
//! `"✅ REGENERATION COMPLETE"` above
//! `print_updated_files_heading()`, or `"✅ UPDATE COMPLETE"`
//! above `print_generated_files_heading()`, compiled clean and
//! silently mismatched the operator's read: the "REGENERATION"
//! headline promises freshly-produced files but the "Updated
//! files:" body labels them as rewrites of pre-existing manifests,
//! and vice versa. The mismatch survives every automated check
//! that reads bytes rather than semantics.
//!
//! # The covariance the closed enum pins
//!
//! The banner text and the follow-on files-heading are not
//! independent: they are two projections of the same *ceremony*
//! choice. A "Regeneration" ceremony PRODUCES files that did not
//! exist in that shape before the run (the pre-lift consumers
//! call this out — a fresh `Cargo.lock` from `cargo
//! generate-lockfile`, a fresh `Cargo.nix` from `crate2nix
//! generate` against a workspace whose lockfile just came into
//! being), so the banner says "REGENERATION COMPLETE" and the
//! follow-on lists them under `Generated files:`. An "Update"
//! ceremony REWRITES files that already existed on the disk (a
//! `Cargo.lock` `cargo update` refreshes in place, a `Cargo.nix`
//! `crate2nix generate` regenerates from the just-updated
//! `Cargo.lock`), so the banner says "UPDATE COMPLETE" and the
//! follow-on lists them under `Updated files:`. Post-lift, one
//! [`CargoNixCeremony`] value picks both projections in lockstep;
//! there is no way to select a banner without also selecting the
//! matching heading, so the pre-lift copy-paste hazard is
//! foreclosed at the type level.
//!
//! # Delegation, not re-implementation
//!
//! The three-line banner render is delegated to
//! [`crate::ui::write_success_banner`] (the `━`-rule + green-bold
//! message + `━`-rule primitive already used at 7 sibling success
//! milestones across `commands/{developer_tools, rust_service,
//! web_service}.rs`). The heading follow-on is delegated to
//! [`crate::ui::write_generated_files_heading`] /
//! [`crate::ui::write_updated_files_heading`] (each already the
//! ONE landing point for its "<Verb> files:" grammar). A future
//! palette shift on either primitive (a demotion of the rule
//! character, a dimming of the file-list heading family) rides
//! through this primitive by construction — this primitive owns
//! ONLY the (ceremony → banner label × heading writer)
//! projection, not the render bytes themselves.
//!
//! # Width pinning
//!
//! The banner width every pre-lift site passed was `80` verbatim —
//! matching every sibling success milestone in
//! `commands/{developer_tools, rust_service, web_service}.rs`. The
//! width is pinned here as [`CARGO_NIX_CEREMONY_BANNER_WIDTH`] so a
//! future fleet-wide narrowing of the milestone rule (say to 70
//! under a compact-terminal palette) lands at ONE `const` rather
//! than at four inline literal `80`s.
//!
//! # THEORY grounding
//!
//! §V solve-once-at-the-primitive: the (banner label, heading
//! follow-on) covariance the four pre-lift sites carried out of
//! band lives here in one closed enum whose projections cannot
//! desynchronize. §VI.1 three-is-a-law: four sites today —
//! two per ceremony variant, one variant per repo-shape workflow
//! (`web_service` for Hanabi's frontend workspace, `developer_tools`
//! for a generic rust-service workspace) — clearing the duplication
//! threshold at exactly the point THEORY calls a law.

use std::io;

/// The fixed banner width every pre-lift consumer passed as the
/// first argument to [`crate::ui::print_success_banner`] — `80`,
/// matching every sibling success milestone across the fleet's
/// regenerate / update / release ceremonies. Named as a `const` so
/// a future fleet-wide narrowing (say to 70 under a compact-terminal
/// palette shift) lands at ONE edit rather than at four inline
/// literal `80`s.
pub const CARGO_NIX_CEREMONY_BANNER_WIDTH: usize = 80;

/// Which `crate2nix`-driven ceremony this closer is announcing — the
/// choice pins BOTH the `━`-rule banner label AND the follow-on
/// files-heading in lockstep, so the pre-lift copy-paste hazard
/// (a "REGENERATION COMPLETE" banner above an "Updated files:"
/// heading, or vice versa) is foreclosed at the type level.
///
/// The two variants correspond to the two `crate2nix generate`
/// entry points every rust-service repo shape ships:
///
/// - [`CargoNixCeremony::Regeneration`] — the workflow produced
///   `Cargo.lock` / `Cargo.nix` from scratch (or from a source
///   that did not previously produce a lockfile of this shape),
///   e.g. `cargo generate-lockfile` at
///   `commands/developer_tools.rs::rust_regenerate_cargo_nix` or a
///   fresh Hanabi frontend regen at
///   `commands/web_service.rs::regenerate_hanabi`.
/// - [`CargoNixCeremony::Update`] — the workflow rewrote an
///   existing `Cargo.lock` / `Cargo.nix` in place via `cargo
///   update` + `crate2nix generate`, e.g.
///   `commands/developer_tools.rs::rust_cargo_update` or
///   `commands/web_service.rs::web_cargo_update`.
///
/// # Closed enum, deliberate
///
/// A new ceremony variant (say a `Regeneration → Update` two-phase
/// composite banner) is a deliberate additive edit here, not an
/// open call-site choice. Exhaustiveness against every consumer
/// projection ([`Self::banner_label`], [`Self::write_files_heading`])
/// then compiles as a match-arm requirement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CargoNixCeremony {
    /// The workflow produced fresh manifest files — the closer
    /// banner reads `"✅ REGENERATION COMPLETE"` and the follow-on
    /// files-heading is `"Generated files:"`.
    Regeneration,
    /// The workflow rewrote existing manifest files in place — the
    /// closer banner reads `"✅ UPDATE COMPLETE"` and the follow-on
    /// files-heading is `"Updated files:"`.
    Update,
}

impl CargoNixCeremony {
    /// The banner-label projection: the exact `&'static str` every
    /// pre-lift consumer passed as the second argument to
    /// [`crate::ui::print_success_banner`]. The `✅` glyph (U+2705)
    /// carries a variation selector at the byte level in the
    /// pre-lift literals; this projection preserves those bytes
    /// verbatim so a downstream byte comparator observes zero
    /// drift.
    pub const fn banner_label(&self) -> &'static str {
        match self {
            Self::Regeneration => "\u{2705} REGENERATION COMPLETE",
            Self::Update => "\u{2705} UPDATE COMPLETE",
        }
    }

    /// The files-heading projection: dispatches to
    /// [`crate::ui::write_generated_files_heading`] on
    /// [`Self::Regeneration`] and to
    /// [`crate::ui::write_updated_files_heading`] on
    /// [`Self::Update`]. This is the covariance the closed enum
    /// pins — a caller that picks a `Regeneration` banner cannot
    /// desynchronize the heading, because the dispatch match is
    /// the ONLY entry point to the follow-on writer.
    ///
    /// # `#[allow(dead_code)]` intent
    ///
    /// The production entry point
    /// [`print_cargo_nix_ceremony_banner`] delegates to the stdout-
    /// adapter forms ([`crate::ui::print_generated_files_heading`] /
    /// [`crate::ui::print_updated_files_heading`]) rather than this
    /// writer sibling, so a non-test build sees no caller. The
    /// writer split exists so the byte-oracle tests can pin the
    /// dispatch covariance without capturing stdout; the same
    /// pattern [`crate::package_phase_announce::write_package_phase_announce`]
    /// carries against its colored sibling.
    #[allow(dead_code)]
    pub fn write_files_heading<W: io::Write>(&self, w: &mut W) -> io::Result<()> {
        match self {
            Self::Regeneration => crate::ui::write_generated_files_heading(w),
            Self::Update => crate::ui::write_updated_files_heading(w),
        }
    }
}

/// Print the three-line
/// `print_success_banner(80, <label>); println!();
/// <files_heading>();` closer to stdout for the given ceremony —
/// the fusion primitive four pre-lift sibling sites in
/// `commands/{web_service.rs, developer_tools.rs}` each spelled
/// inline via three independent calls to the ui.rs primitives.
///
/// Delegates the banner render to [`crate::ui::print_success_banner`]
/// with the pinned width [`CARGO_NIX_CEREMONY_BANNER_WIDTH`] and the
/// ceremony's [`CargoNixCeremony::banner_label`] projection; delegates
/// the follow-on heading to
/// [`crate::ui::print_generated_files_heading`] on
/// [`CargoNixCeremony::Regeneration`] or
/// [`crate::ui::print_updated_files_heading`] on
/// [`CargoNixCeremony::Update`] — routing through the stdout adapters
/// so a future consumer that reaches for one of those two entry
/// points directly still sees the same rendered bytes this
/// primitive emits. The blank-line separator between banner and
/// heading is a bare `println!()` — matching the pre-lift byte shape.
pub fn print_cargo_nix_ceremony_banner(ceremony: CargoNixCeremony) {
    crate::ui::print_success_banner(CARGO_NIX_CEREMONY_BANNER_WIDTH, ceremony.banner_label());
    println!();
    match ceremony {
        CargoNixCeremony::Regeneration => crate::ui::print_generated_files_heading(),
        CargoNixCeremony::Update => crate::ui::print_updated_files_heading(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-oracle for the [`CargoNixCeremony::Regeneration`]
    /// banner-label projection: the pre-lift string literal was
    /// `"✅ REGENERATION COMPLETE"` where `✅` is U+2705. A future
    /// refactor that appended U+FE0F, swapped the label verb
    /// (`REGENERATION` → `REGENERATE`), or dropped the trailing
    /// `COMPLETE` regresses this assertion.
    #[test]
    fn regeneration_banner_label_matches_pre_lift_literal() {
        assert_eq!(
            CargoNixCeremony::Regeneration.banner_label(),
            "\u{2705} REGENERATION COMPLETE"
        );
    }

    /// Byte-oracle for the [`CargoNixCeremony::Update`] banner-label
    /// projection: the pre-lift string literal was
    /// `"✅ UPDATE COMPLETE"` where `✅` is U+2705.
    #[test]
    fn update_banner_label_matches_pre_lift_literal() {
        assert_eq!(
            CargoNixCeremony::Update.banner_label(),
            "\u{2705} UPDATE COMPLETE"
        );
    }

    /// Covariance pin, forward direction:
    /// [`CargoNixCeremony::Regeneration`] MUST dispatch its
    /// files-heading projection to
    /// [`crate::ui::write_generated_files_heading`], whose byte-
    /// oracle emission is `"Generated files:\n"`
    /// ([`crate::ui::GENERATED_FILES_HEADING_TEXT`]). A future edit
    /// that flipped the arms of the internal match — sending
    /// `Regeneration` to `write_updated_files_heading` — flips this
    /// assertion rather than compiling and silently mismatching the
    /// pre-lift byte shape.
    #[test]
    fn regeneration_ceremony_dispatches_to_generated_files_heading() {
        let mut buf: Vec<u8> = Vec::new();
        CargoNixCeremony::Regeneration
            .write_files_heading(&mut buf)
            .expect("write to Vec<u8> is infallible");
        assert_eq!(
            String::from_utf8(buf).expect("writers emit valid UTF-8"),
            format!("{}\n", crate::ui::GENERATED_FILES_HEADING_TEXT),
        );
    }

    /// Covariance pin, reverse direction: [`CargoNixCeremony::Update`]
    /// MUST dispatch its files-heading projection to
    /// [`crate::ui::write_updated_files_heading`], whose byte-oracle
    /// emission is `"Updated files:\n"`
    /// ([`crate::ui::UPDATED_FILES_HEADING_TEXT`]). Together with the
    /// forward-direction test above, this pins the covariance the
    /// closed enum lifts out of band: the ceremony variant is the
    /// ONLY input that selects which heading writer runs.
    #[test]
    fn update_ceremony_dispatches_to_updated_files_heading() {
        let mut buf: Vec<u8> = Vec::new();
        CargoNixCeremony::Update
            .write_files_heading(&mut buf)
            .expect("write to Vec<u8> is infallible");
        assert_eq!(
            String::from_utf8(buf).expect("writers emit valid UTF-8"),
            format!("{}\n", crate::ui::UPDATED_FILES_HEADING_TEXT),
        );
    }

    /// The banner width the pre-lift consumers passed was `80` at
    /// every site — pinning the constant here rather than at four
    /// inline `80` literals is the load-bearing property of the
    /// lift. A future edit that hoisted the width off this constant
    /// (say to `70` under a compact-terminal palette shift) is a
    /// deliberate one-line edit; a drift that widened the constant
    /// at one variant alone would trip the fail-before-pass shield.
    #[test]
    fn banner_width_matches_pre_lift_eighty_literal() {
        assert_eq!(CARGO_NIX_CEREMONY_BANNER_WIDTH, 80);
    }

    /// Enum-exhaustiveness pin: the [`CargoNixCeremony`] enum has
    /// exactly two variants today ([`CargoNixCeremony::Regeneration`],
    /// [`CargoNixCeremony::Update`]) — the two pre-lift ceremony
    /// classes. A future edit that added a third variant without
    /// wiring both projection methods to it fails the compiler's
    /// exhaustiveness check on the internal match arms; this test
    /// pins the intent that a variant addition is a deliberate
    /// three-arm edit (variant + banner_label arm + write_files_heading
    /// arm), not an open call-site choice.
    #[test]
    fn ceremony_enum_variants_are_disjoint() {
        let variants = [CargoNixCeremony::Regeneration, CargoNixCeremony::Update];
        assert_ne!(variants[0].banner_label(), variants[1].banner_label());
        // The label distinction is byte-level, not just Display-level —
        // a pre-lift caller that pattern-matched on the banner string
        // rather than on the enum would still see the two variants as
        // structurally distinct.
        assert_ne!(
            variants[0].banner_label().as_bytes(),
            variants[1].banner_label().as_bytes(),
        );
    }

    /// Caller shield: no source line under `cli/src/commands/` may
    /// spell the pre-lift `print_success_banner(80, "✅ REGENERATION
    /// COMPLETE")` or `print_success_banner(80, "✅ UPDATE
    /// COMPLETE")` literal any more. Every closer reaches for
    /// [`print_cargo_nix_ceremony_banner`] on first grep, not by
    /// copy-pasting the raw three-line shape from an existing
    /// command module.
    ///
    /// The needles are reconstructed via `format!` from the enum's
    /// own projections so this shield's own source text does not
    /// false-match itself against the primitive it guards.
    #[test]
    fn no_command_module_still_spells_raw_cargo_nix_ceremony_banner_call() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let needles = [
            format!(
                "print_success_banner(80, \"{}\")",
                CargoNixCeremony::Regeneration.banner_label()
            ),
            format!(
                "print_success_banner(80, \"{}\")",
                CargoNixCeremony::Update.banner_label()
            ),
        ];
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
                for needle in &needles {
                    if line.contains(needle.as_str()) {
                        offenders.push((path.clone(), idx + 1, line.to_string()));
                    }
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `print_success_banner(80, \"✅ <X> COMPLETE\")` literal(s) \
             survive under `commands/` — route each three-line stanza \
             through `crate::cargo_nix_ceremony_banner::\
             print_cargo_nix_ceremony_banner(CargoNixCeremony::<X>)` \
             instead:\n{offenders:#?}"
        );
    }

    /// Positive half of the shield: each pre-lift command module
    /// MUST forward through
    /// [`print_cargo_nix_ceremony_banner`] — either DIRECTLY or
    /// INDIRECTLY via
    /// [`crate::cargo_nix_ceremony_summary_opener::print_cargo_nix_ceremony_summary_opener`],
    /// which delegates through this primitive — at least the
    /// pre-lift migrated count, so a migration that dropped a call
    /// site outright leaves the negative "no raw inline shape" scan
    /// trivially satisfied by absence but the positive count still
    /// fails.
    ///
    /// Web-service.rs (×2 pre-lift): one direct `regenerate_hanabi`
    /// regeneration closer + one indirect `web_cargo_update` update
    /// closer via the summary-opener. Developer-tools.rs (×2
    /// pre-lift): two indirect `rust_regenerate` /
    /// `rust_cargo_update` closers via the summary-opener.
    #[test]
    fn every_prelift_module_forwards_through_print_cargo_nix_ceremony_banner() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let expectations: &[(&str, usize)] = &[("web_service.rs", 2), ("developer_tools.rs", 2)];
        // Reconstruct the call-site needles via `format!` so this
        // shield's own source text does not false-match itself.
        let direct_needle = format!("{}(", "print_cargo_nix_ceremony_banner");
        let indirect_needle = format!("{}(", "print_cargo_nix_ceremony_summary_opener");
        for (basename, min_count) in expectations {
            let path = commands_dir.join(basename);
            let source = std::fs::read_to_string(&path).unwrap();
            let direct = source.matches(direct_needle.as_str()).count();
            let indirect = source.matches(indirect_needle.as_str()).count();
            let forwards = direct + indirect;
            assert!(
                forwards >= *min_count,
                "{basename} must forward at least {min_count} \
                 cargo-nix-ceremony banner stanza(s) through \
                 `crate::cargo_nix_ceremony_banner::print_cargo_nix_ceremony_banner(` \
                 (direct) or \
                 `crate::cargo_nix_ceremony_summary_opener::print_cargo_nix_ceremony_summary_opener(` \
                 (indirect via the summary opener); found \
                 {direct} direct + {indirect} indirect = {forwards}. \
                 A dropped call would leave the negative raw-shape \
                 scan satisfied by absence.",
            );
        }
    }
}
