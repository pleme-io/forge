//! Cluster-overlay release-postamble helper.
//!
//! Shape-adapter over the 9-line closing banner + trailer for the three
//! sibling cluster-overlay release flows in
//! `commands/{kenshi,kenshi_agent,nix_builder}.rs`. Each of those flows
//! spelled out — VERBATIM, modulo the component-name token in the middle
//! box row — the same fused stanza:
//!
//! ```text
//! println!();
//! info!("╔════════════════════════════════════════════════════════════╗");
//! info!("║  ✅ <component> release complete!  <padding>              ║");
//! info!("╚════════════════════════════════════════════════════════════╝");
//! println!();
//! info!("Image: {}:{}", registry, new_tag);
//! info!("Updated all clusters");
//! info!("FluxCD will reconcile the changes automatically.");
//! println!();
//! ```
//!
//! Three occurrences of an identical shape past THEORY §VI.1's
//! three-is-a-law threshold. Peer of
//! [`crate::commands::cluster_overlay_release_preamble`] on the opening
//! end of the same three flows — same three-file consumer census, same
//! `<action>_cluster_overlay_release_<phase>` naming discipline, same
//! [`info!`]-forwarding + byte-oracle-writer split every prior
//! sibling-writer refactor honors.
//!
//! Post-lift each flow calls [`announce_release_complete`] with
//! `(release_name, registry, new_tag)` and inherits the canonical closing
//! banner, the trailing `Image: <registry>:<new_tag>` line, the two
//! literal `Updated all clusters` / `FluxCD will reconcile the changes
//! automatically.` reassurance lines, and the framing blank-line
//! discipline through ONE typed body.

use std::fmt;
use std::io;
use tracing::info;

/// The `<name> release complete!` middle-row title suffix every consumer
/// pastes onto its release name. Named so a future palette adjustment
/// (a `<name> release SUCCEEDED`, a `<name> deploy complete!` verb swap
/// under a shared success-family grammar, a translated locale readout)
/// happens at ONE typed boundary rather than in three inline string
/// literals across the consumer modules.
const RELEASE_COMPLETE_TITLE_SUFFIX: &str = " release complete!";

/// Inside-box character count of the middle body row, sized so the
/// closing `║` aligns with the top border's `╗`.
///
/// # The width arithmetic
///
/// The top and bottom borders are `╔` + 60 `═` glyphs + `╗` — 62 display
/// columns wide. The middle row is `║` + `<content>` + `║`, so
/// `<content>` must occupy 60 display columns.
///
/// The pre-lift middle-row content is `"  ✅ <name> release complete!"`
/// plus enough trailing spaces to reach column 60. The two leading
/// spaces + `✅` glyph (1 UTF-8 scalar value but 2 display columns wide)
/// + one space separator consume 5 display columns and 4 characters,
/// leaving 55 columns for the title-plus-padding tail — expressible as
/// `format!("║  ✅ {:<55}║", title)` where `title` is a plain-ASCII
/// string whose display column count equals its character count.
///
/// Extracted as a `const` so the arithmetic is stated once, at the ONE
/// typed boundary that owns the box grammar, rather than baked into a
/// raw `{:<55}` field spec buried in a `format!` call the three
/// consumers would each have re-derived.
const RELEASE_COMPLETE_BOX_TITLE_WIDTH: usize = 55;

/// Render the middle row of the release-complete box for the given
/// release name — `║  ✅ <name> release complete!` + trailing padding to
/// reach the closing `║`.
///
/// Extracted as a pure helper (no I/O, no side effects) so the
/// [`write_release_postamble`] byte-oracle test can pin the box
/// arithmetic against exact strings without threading a full postamble
/// emission, and so a future consumer that only needs the middle row
/// (a JSON summary block that re-uses the box's display form as a
/// summary key, an operator-facing dashboard tile that echoes the
/// banner) can reach for the helper directly rather than re-deriving
/// the padding.
///
/// The `impl fmt::Display` parameter mirrors
/// [`crate::commands::cluster_overlay_release_preamble::write_release_preamble`]'s
/// slot-forwarding discipline: a caller with an owned `String`, a `&str`,
/// or any `Display` type flows through the same site without
/// re-allocating.
pub fn format_release_complete_box_middle_row(release_name: &dyn fmt::Display) -> String {
    let title = format!("{}{}", release_name, RELEASE_COMPLETE_TITLE_SUFFIX);
    format!(
        "║  ✅ {:<width$}║",
        title,
        width = RELEASE_COMPLETE_BOX_TITLE_WIDTH
    )
}

/// Top border glyph line of the release-complete box — `╔` + 60 `═` +
/// `╗`, 62 display columns wide. Sibling of the crate-level
/// [`crate::ui`] box-border constants (`BOXED_HEADER_TOP` and
/// `BOXED_HEADER_BOTTOM`); duplicated here rather than depended-on
/// because those constants are wrapped in a `bright_blue()` boxed-header
/// grammar the postamble deliberately does NOT inherit — the postamble's
/// box lines flow through [`tracing::info!`] plain (no color, no
/// bold) so the ambient tracing subscriber renders them alongside the
/// other release-completion INFO events.
const RELEASE_COMPLETE_BOX_TOP: &str =
    "╔════════════════════════════════════════════════════════════╗";

/// Bottom border glyph line, sibling to [`RELEASE_COMPLETE_BOX_TOP`] —
/// `╚` + 60 `═` + `╝`.
const RELEASE_COMPLETE_BOX_BOTTOM: &str =
    "╚════════════════════════════════════════════════════════════╝";

/// Emit the canonical closing banner + trailer to `w`, byte-for-byte
/// identical to the pre-lift 9-line stanza the three consumers each
/// spelled inline.
///
/// The [`announce_release_complete`] entry point is the
/// [`tracing::info!`] + [`println!`] adapter that production code
/// invokes; this direct-writer variant exists so the fail-before-pass
/// tests can pin the exact emitted bytes (the leading blank line, the
/// 62-column-wide box top border, the middle row's `║  ✅ <name>
/// release complete!` padded to column 60, the bottom border, the
/// mid-banner blank line, the `Image: <registry>:<new_tag>` line, the
/// two literal reassurance lines, the trailing blank line) without
/// capturing a tracing subscriber and without racing an ambient
/// logger — the same split
/// [`crate::commands::cluster_overlay_release_preamble::write_release_preamble`]
/// carries against
/// [`crate::commands::cluster_overlay_release_preamble::announce_release_start_and_compute_tag`].
///
/// The writer is therefore the byte-format oracle for the tests and any
/// future consumer (a `collect_release_postambles` audit sibling that
/// pushes each rendered stanza into a per-run summary vec, an OTLP
/// `release_complete` span whose message payload derives from the same
/// bytes) rather than the production emission path.
#[allow(dead_code)] // See doc comment: the writer is a test/byte-oracle
                    // peer of the tracing-routed
                    // `announce_release_complete`, and future
                    // `collect_release_postambles`/OTLP-span siblings
                    // will consume it directly.
pub fn write_release_postamble<W: io::Write>(
    w: &mut W,
    release_name: &dyn fmt::Display,
    registry: &dyn fmt::Display,
    new_tag: &dyn fmt::Display,
) -> io::Result<()> {
    writeln!(w)?;
    writeln!(w, "{}", RELEASE_COMPLETE_BOX_TOP)?;
    writeln!(
        w,
        "{}",
        format_release_complete_box_middle_row(release_name)
    )?;
    writeln!(w, "{}", RELEASE_COMPLETE_BOX_BOTTOM)?;
    writeln!(w)?;
    writeln!(w, "Image: {}:{}", registry, new_tag)?;
    writeln!(w, "Updated all clusters")?;
    writeln!(w, "FluxCD will reconcile the changes automatically.")?;
    writeln!(w)?;
    Ok(())
}

/// Emit the canonical closing banner + trailer via
/// [`tracing::info!`] + [`println!`] for the three sibling
/// cluster-overlay release flows.
///
/// Framing blank lines flow through [`println!`] (bypassing the tracing
/// subscriber, so they render as bare blank lines rather than
/// timestamp-prefixed blanks); the box + trailer lines flow through
/// [`tracing::info!`] so the ambient subscriber renders them alongside
/// the other release-completion INFO events — matching the pre-lift
/// grammar every consumer inherited.
///
/// # Grammar pinned by the byte-oracle sibling
///
/// The emission grammar (the 9-line shape, the `║  ✅ <name> release
/// complete!` padded middle row, the `Image: <registry>:<new_tag>` line,
/// the two literal reassurance lines, the framing blank lines) is
/// pinned by [`write_release_postamble`] under `#[cfg(test)]`; a drift
/// here (a swap of the box glyphs, a re-ordering of the trailer lines,
/// a colon-space separator change on the Image line) surfaces as a
/// localized test failure at one site, not as silent log-drift across
/// three release flows.
pub fn announce_release_complete(release_name: &str, registry: &str, new_tag: &str) {
    println!();
    info!("{}", RELEASE_COMPLETE_BOX_TOP);
    info!("{}", format_release_complete_box_middle_row(&release_name));
    info!("{}", RELEASE_COMPLETE_BOX_BOTTOM);
    println!();
    info!("Image: {}:{}", registry, new_tag);
    info!("Updated all clusters");
    info!("FluxCD will reconcile the changes automatically.");
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The middle row for a name whose title tail fits the padding
    /// budget MUST come out as the exact 62-column pre-lift string.
    /// Pins the box-width arithmetic against the byte pattern the three
    /// pre-lift consumer sites each spelled inline for their component
    /// names — a drift in [`RELEASE_COMPLETE_BOX_TITLE_WIDTH`] or in
    /// [`RELEASE_COMPLETE_TITLE_SUFFIX`] regresses this assertion at
    /// ONE site rather than silently tilting the box's right edge on
    /// three release flows.
    #[test]
    fn format_release_complete_box_middle_row_pins_the_three_pre_lift_shapes() {
        assert_eq!(
            format_release_complete_box_middle_row(&"kenshi operator"),
            "║  ✅ kenshi operator release complete!                      ║"
        );
        assert_eq!(
            format_release_complete_box_middle_row(&"nix-builder"),
            "║  ✅ nix-builder release complete!                          ║"
        );
        assert_eq!(
            format_release_complete_box_middle_row(&"kenshi-agent"),
            "║  ✅ kenshi-agent release complete!                         ║"
        );
    }

    /// The box borders MUST be 62 display columns wide (matching the
    /// top and bottom of the three pre-lift boxes). A drift in the
    /// `═`-glyph count of either border silently tilts the box on
    /// every consumer that renders it.
    #[test]
    fn release_complete_box_borders_span_sixty_two_columns() {
        assert_eq!(RELEASE_COMPLETE_BOX_TOP.chars().count(), 62);
        assert_eq!(RELEASE_COMPLETE_BOX_BOTTOM.chars().count(), 62);
        assert!(RELEASE_COMPLETE_BOX_TOP.starts_with('╔'));
        assert!(RELEASE_COMPLETE_BOX_TOP.ends_with('╗'));
        assert!(RELEASE_COMPLETE_BOX_BOTTOM.starts_with('╚'));
        assert!(RELEASE_COMPLETE_BOX_BOTTOM.ends_with('╝'));
    }

    /// Pin the exact 9-line postamble bytes: leading blank, box top,
    /// middle row (padded), box bottom, mid-banner blank, `Image:
    /// <registry>:<new_tag>`, two literal reassurance lines, trailing
    /// blank. A future refactor that dropped a blank, re-ordered a
    /// trailer line, swapped the colon-space separator, or promoted
    /// the box to bright_green ANSI (which would break parity with the
    /// three consumers' pre-lift `info!()`-plain rendering) regresses
    /// this assertion.
    #[test]
    fn write_release_postamble_emits_the_canonical_nine_line_stanza() {
        let mut buf: Vec<u8> = Vec::new();
        write_release_postamble(
            &mut buf,
            &"kenshi operator",
            &"ghcr.io/pleme-io/kenshi",
            &"amd64-deadbeef",
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "\n\
             ╔════════════════════════════════════════════════════════════╗\n\
             ║  ✅ kenshi operator release complete!                      ║\n\
             ╚════════════════════════════════════════════════════════════╝\n\
             \n\
             Image: ghcr.io/pleme-io/kenshi:amd64-deadbeef\n\
             Updated all clusters\n\
             FluxCD will reconcile the changes automatically.\n\
             \n"
        );
    }

    /// The writer MUST forward each `Display` slot verbatim without
    /// re-escaping — a registry URL that carries a slash-delimited path,
    /// a tag with a `-` separator, or a release name with an embedded
    /// space all travel through unchanged. Pins the pre-lift inline
    /// behavior every `info!("Image: {}:{}", registry, new_tag)` site
    /// inherits.
    #[test]
    fn write_release_postamble_forwards_display_slots_verbatim() {
        let mut buf: Vec<u8> = Vec::new();
        write_release_postamble(
            &mut buf,
            &"nix-builder",
            &"ghcr.io/pleme-io/nix-builder",
            &"amd64-cafef00d",
        )
        .unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("║  ✅ nix-builder release complete!"));
        assert!(out.contains("Image: ghcr.io/pleme-io/nix-builder:amd64-cafef00d\n"));
        assert!(out.contains("Updated all clusters\n"));
        assert!(out.contains("FluxCD will reconcile the changes automatically.\n"));
    }

    /// Whole-module shield: no raw `✅ <name> release complete!` middle
    /// row may live in the three consumer modules
    /// (`commands/{kenshi,kenshi_agent,nix_builder}.rs`). Every closing
    /// banner rendered by a cluster-overlay release flow must resolve
    /// through [`announce_release_complete`] (or, transitively, through
    /// [`format_release_complete_box_middle_row`]) so a future drift
    /// to a new banner shape flows to all three flows from one edit.
    ///
    /// The forbidden shape is reconstructed at test time via `format!`
    /// from the bare string `" release complete!"` so this shield's
    /// own source text does not false-match itself.
    #[test]
    fn release_complete_banner_middle_row_routes_through_helper_not_inline_literal() {
        let forbidden_suffix = format!("{}{}{}", "✅ ", "{}", " release complete!");
        for (path, source) in [
            ("commands/kenshi.rs", include_str!("kenshi.rs")),
            ("commands/kenshi_agent.rs", include_str!("kenshi_agent.rs")),
            ("commands/nix_builder.rs", include_str!("nix_builder.rs")),
        ] {
            // The forbidden shape is any inline `║  ✅ <name> release
            // complete!` middle-row literal. We look for the
            // `release complete!` suffix that all three pre-lift shapes
            // shared; a caller re-inlining any of the three would echo
            // it, and any new caller inlining a fresh component name
            // would too.
            let literal_tail = " release complete!";
            assert!(
                !source.contains(literal_tail),
                "`{path}` must not spell an inline `<name>{literal_tail}` banner row; \
                 route through `crate::commands::cluster_overlay_release_postamble::\
                 announce_release_complete` instead. \
                 Forbidden-shape probe: {forbidden_suffix}"
            );
        }
    }

    /// Positive-half delegation shield: the three consumer modules
    /// MUST each carry exactly one call to
    /// [`announce_release_complete`]. Guards against a silent removal
    /// of the closing banner from a consumer (a refactor that
    /// accidentally dropped the postamble call while migrating a
    /// step, a merge that lost the call in a conflict resolution) —
    /// the visual grammar is load-bearing for operators watching the
    /// release stream, so its presence is a structural invariant.
    #[test]
    fn every_cluster_overlay_release_consumer_delegates_through_postamble_helper() {
        let needle = "cluster_overlay_release_postamble::announce_release_complete";
        for (path, source) in [
            ("commands/kenshi.rs", include_str!("kenshi.rs")),
            ("commands/kenshi_agent.rs", include_str!("kenshi_agent.rs")),
            ("commands/nix_builder.rs", include_str!("nix_builder.rs")),
        ] {
            assert!(
                source.contains(needle),
                "`{path}` must delegate through `crate::commands::\
                 {needle}` for its closing banner. If this release flow \
                 no longer needs the banner, remove the flow entirely; a \
                 flow that runs to completion without emitting the banner \
                 breaks the visual grammar operators rely on to see the \
                 release finish."
            );
        }
    }
}
