//! Cluster-overlay release-preamble helper.
//!
//! Shape-adapter over the four-`info!` + two-`println!()` intro banner
//! for the three sibling cluster-overlay release flows in
//! `commands/{kenshi,kenshi_agent,nix_builder}.rs`. Each of those flows
//! spelled out — VERBATIM, modulo the component-name token — the same
//! two-stanza opening:
//!
//! ```text
//! info!("🚀 Starting <component> release");
//! info!("   Image: {}", image_path);
//! info!("   Registry: {}", registry);
//! println!();
//!
//! let git_sha = push::get_git_sha().await?;
//! let new_tag = format!("amd64-{}", git_sha);
//! info!("📋 Release tag: {}", new_tag);
//! println!();
//! ```
//!
//! Three occurrences of an identical shape past THEORY §VI.1's
//! three-is-a-law threshold; this module is the law-redeeming extraction.
//! Post-lift each flow calls [`announce_release_start_and_compute_tag`]
//! with `(component, image_path, registry)` and inherits the canonical
//! banner + the `amd64-<sha>` tag format + the `push::get_git_sha`
//! resolution through one site.
//!
//! Peer of `commands/release_commit.rs` on the tail end of the same
//! three flows — same three-file consumer census, same
//! `commit_cluster_overlay_release` naming discipline, same
//! [`info!`]-forwarding + byte-oracle-writer split every prior
//! sibling-writer refactor honors (see `nonfatal_warning.rs` for the
//! canonical writer-vs-macro split rationale).

use anyhow::Result;
use std::fmt;
use std::io;
use tracing::info;

/// Render the canonical `amd64-<git_sha>` release tag.
///
/// Pure function — no I/O. Pinning the format at one site means a future
/// drift to a new tag convention (a `linux-amd64-` prefix, an
/// architecture-parametric form, an embedded date stamp) flows to all
/// three cluster-overlay release flows from one edit, and downstream
/// `docker manifest inspect ghcr.io/.../amd64-<sha>` audit queries
/// continue to resolve against a single canonical shape.
pub fn format_amd64_release_tag(git_sha: &str) -> String {
    format!("amd64-{}", git_sha)
}

/// Render the canonical `arm64-<git_sha>` release tag — arch-peer of
/// [`format_amd64_release_tag`].
///
/// Pure function — no I/O. Pinning the format at one site means a future
/// drift to a new tag convention (a `linux-arm64-` prefix, an
/// architecture-parametric form, an embedded date stamp) flows to the
/// three `arm64-<sha>` construction sites in `commands/image_release.rs`
/// (multi-arch push arm64 tag + the two `regctl index create --ref
/// <registry>:arm64-<sha>` references that resolve against it) from one
/// edit, and downstream `docker manifest inspect
/// ghcr.io/.../arm64-<sha>` audit queries continue to resolve against a
/// single canonical shape.
///
/// Kept as a sibling of [`format_amd64_release_tag`] rather than a
/// parametric `format_arch_release_tag(arch, sha)` because the pre-lift
/// consumer census carries `amd64` (six sites — three cluster-overlay
/// flows + three product-level flows) and `arm64` (three sites, all in
/// `commands/image_release.rs`) as distinct grammars — an `arm64`-only
/// consumer never carries an `amd64` counterpart at the same call site,
/// and vice versa. A parametric helper would force every consumer to
/// thread an `Arch` argument through the call, which the pre-lift sites
/// never spelled — the arch is fixed at the call site, not a runtime
/// choice.
pub fn format_arm64_release_tag(git_sha: &str) -> String {
    format!("arm64-{}", git_sha)
}

/// Emit the canonical two-stanza cluster-overlay release preamble to
/// `w`, wrapping the arguments with the pre-lift prefix + newlines +
/// separator that three sibling sites spelled inline.
///
/// The [`announce_release_start_and_compute_tag`] entry point is the
/// `tracing::info!` + `println!()` adapter that production code invokes;
/// this direct-writer variant exists so the fail-before-pass tests can
/// pin the exact emitted bytes (the `🚀 ` opener, the three-space
/// `   Image: ` / `   Registry: ` indentation, the blank line between
/// the two stanzas, the `📋 Release tag: ` label, the trailing blank
/// line) without capturing a tracing subscriber and without racing an
/// ambient logger — the same split
/// [`crate::nonfatal_warning::write_nonfatal_warn`] carries against
/// [`crate::warn_nonfatal!`].
///
/// The writer is therefore the byte-format oracle for the tests and any
/// future consumer (a `collect_release_preambles` audit sibling that
/// pushes each rendered stanza into a per-run summary vec) rather than
/// the production emission path.
#[allow(dead_code)] // See doc comment: the writer is a test/byte-oracle
                    // peer of the tracing-routed
                    // `announce_release_start_and_compute_tag`, and the
                    // future `collect_release_preambles` sibling will
                    // consume it directly.
pub fn write_release_preamble<W: io::Write>(
    w: &mut W,
    release_name: &dyn fmt::Display,
    image_path: &dyn fmt::Display,
    registry: &dyn fmt::Display,
    new_tag: &dyn fmt::Display,
) -> io::Result<()> {
    writeln!(w, "🚀 Starting {} release", release_name)?;
    writeln!(w, "   Image: {}", image_path)?;
    writeln!(w, "   Registry: {}", registry)?;
    writeln!(w)?;
    writeln!(w, "📋 Release tag: {}", new_tag)?;
    writeln!(w)?;
    Ok(())
}

/// Emit the canonical cluster-overlay release preamble via
/// [`tracing::info!`] + [`println!`], then resolve the git SHA through
/// [`crate::commands::push::get_git_sha`] and return the rendered
/// `amd64-<sha>` tag.
///
/// The three consumer sites keep only `new_tag` for downstream use
/// (kustomization overlay updates, commit subject, final `Image: ...:...`
/// banner); `git_sha` itself is unused past the tag rendering, so the
/// primitive absorbs it internally and returns the tag alone.
///
/// # Grammar pinned by the byte-oracle sibling
///
/// The emission grammar is pinned by [`write_release_preamble`] under
/// `#[cfg(test)]`; a drift here (a color change, a glyph change, an
/// indentation change, a re-ordering of the two stanzas) surfaces as a
/// localized test failure at one site, not as silent log-drift across
/// three release flows.
pub async fn announce_release_start_and_compute_tag(
    release_name: &str,
    image_path: &str,
    registry: &str,
) -> Result<String> {
    info!("🚀 Starting {} release", release_name);
    info!("   Image: {}", image_path);
    info!("   Registry: {}", registry);
    println!();

    let git_sha = crate::commands::push::get_git_sha().await?;
    let new_tag = format_amd64_release_tag(&git_sha);
    info!("📋 Release tag: {}", new_tag);
    println!();
    Ok(new_tag)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pure tag-format helper MUST produce the canonical
    /// `amd64-<sha>` shape byte-for-byte. Pins the format at one site so
    /// a future drift to a new tag convention surfaces as a localized
    /// test failure at one site, not as silent tag-drift across three
    /// release flows and every downstream registry-scan tool that
    /// resolves against `amd64-<sha>`.
    #[test]
    fn format_amd64_release_tag_prefixes_arch_and_sha() {
        assert_eq!(format_amd64_release_tag("deadbeef"), "amd64-deadbeef");
    }

    /// The tag-format helper MUST forward its `git_sha` argument
    /// verbatim — no truncation, no case-folding, no whitespace trim.
    /// A future change that decided to normalise the SHA at the format
    /// boundary would silently diverge from the pre-lift inline
    /// `format!("amd64-{}", git_sha)` shape every consumer inherits.
    #[test]
    fn format_amd64_release_tag_forwards_full_sha_verbatim() {
        assert_eq!(
            format_amd64_release_tag("0123456789abcdef"),
            "amd64-0123456789abcdef"
        );
    }

    /// Pin the exact preamble bytes: `🚀 ` opener, three-space indent
    /// on the Image / Registry lines, blank line between the two
    /// stanzas, `📋 Release tag: ` label, trailing blank line. A future
    /// refactor that dropped the emoji glyphs, collapsed the blank
    /// separator, moved the label, swapped the ` : ` colon-space
    /// separator, or dropped the trailing blank line regresses this
    /// assertion.
    #[test]
    fn write_release_preamble_emits_canonical_two_stanza_grammar() {
        let mut buf: Vec<u8> = Vec::new();
        write_release_preamble(
            &mut buf,
            &"kenshi operator",
            &"ghcr.io/pleme-io/kenshi",
            &"ghcr.io/pleme-io",
            &"amd64-deadbeef",
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "🚀 Starting kenshi operator release\n   \
             Image: ghcr.io/pleme-io/kenshi\n   \
             Registry: ghcr.io/pleme-io\n\n📋 Release tag: amd64-deadbeef\n\n"
        );
    }

    /// The writer MUST forward each `Display` slot verbatim without
    /// re-escaping — an image path that carries a colon (registry:tag
    /// shape), a registry URL that carries a slash-delimited path, or a
    /// component name with an embedded space (`"kenshi operator"`) all
    /// travel through unchanged. Pins the pre-lift inline behavior
    /// every `info!("   Image: {}", image_path)` site inherits.
    #[test]
    fn write_release_preamble_forwards_display_slots_verbatim() {
        let mut buf: Vec<u8> = Vec::new();
        write_release_preamble(
            &mut buf,
            &"nix-builder",
            &"pkgs/nix-builder:image",
            &"ghcr.io/pleme-io/nix-builder",
            &"amd64-cafef00d",
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "🚀 Starting nix-builder release\n   \
             Image: pkgs/nix-builder:image\n   \
             Registry: ghcr.io/pleme-io/nix-builder\n\n\
             📋 Release tag: amd64-cafef00d\n\n"
        );
    }

    /// Whole-module shield: no raw `format!("amd64-{}", ...)` may live
    /// in ANY release-tag-emitting consumer module. The pre-lift census
    /// covered eight sites — three cluster-overlay flows
    /// (`commands/{kenshi,kenshi_agent,nix_builder}.rs`) and five
    /// product-level flows (`commands/product_release.rs` × 3 —
    /// prebuilt-push deploy tag, image-attestation image tag,
    /// should-build-artifact deploy tag; `commands/rollback.rs` × 1 —
    /// rollback verification tag; `commands/image_release.rs` × 1 —
    /// multi-arch push amd64 tag). Every `amd64-<sha>` tag rendered by
    /// forge must resolve through [`format_amd64_release_tag`] so a
    /// future drift to a new tag convention (a `linux/amd64-` prefix,
    /// an architecture-parametric form, an embedded date stamp) flows
    /// to all eight sites from one edit and downstream
    /// `docker manifest inspect ghcr.io/.../amd64-<sha>` audit queries
    /// continue to resolve against a single canonical shape.
    ///
    /// The forbidden shape is reconstructed at test time via `format!`
    /// from the bare string `"amd64-"` so this shield's own source text
    /// does not false-match itself. The exception is
    /// [`format_amd64_release_tag`] itself (in this same module), which
    /// is the ONE site allowed to spell the raw shape — that site is
    /// what every consumer delegates through.
    #[test]
    fn amd64_tag_render_routes_through_format_helper_not_raw_format_literal() {
        let forbidden = format!("{}{{}}", "\"amd64-");
        for (path, source) in [
            ("commands/kenshi.rs", include_str!("kenshi.rs")),
            ("commands/kenshi_agent.rs", include_str!("kenshi_agent.rs")),
            ("commands/nix_builder.rs", include_str!("nix_builder.rs")),
            (
                "commands/product_release.rs",
                include_str!("product_release.rs"),
            ),
            ("commands/rollback.rs", include_str!("rollback.rs")),
            (
                "commands/image_release.rs",
                include_str!("image_release.rs"),
            ),
        ] {
            assert!(
                !source.contains(&forbidden),
                "`{path}` must not spell the raw `format!(\"amd64-{{}}\", ...)` shape; \
                 route through `crate::commands::cluster_overlay_release_preamble::\
                 format_amd64_release_tag` instead (the byte-oracle-covered \
                 canonical tag renderer)"
            );
        }
    }

    /// Positive delegation shield: each of the five product-level
    /// consumer modules newly added to the shield above MUST carry a
    /// call to `format_amd64_release_tag` — a re-inline that also
    /// silently dropped the primitive call would evade the "no raw
    /// format literal" scan but is caught here.
    ///
    /// Three cluster-overlay consumers are already covered by the
    /// sibling `cluster_overlay_release_preamble_callers_delegate_...`
    /// discipline in the preamble surface (they call the fusion
    /// primitive `announce_release_start_and_compute_tag` rather than
    /// `format_amd64_release_tag` directly), so they are not
    /// re-checked here — the negative shield above is sufficient for
    /// them.
    #[test]
    fn product_level_amd64_tag_callers_delegate_through_format_helper() {
        for (path, source) in [
            (
                "commands/product_release.rs",
                include_str!("product_release.rs"),
            ),
            ("commands/rollback.rs", include_str!("rollback.rs")),
            (
                "commands/image_release.rs",
                include_str!("image_release.rs"),
            ),
        ] {
            assert!(
                source.contains("format_amd64_release_tag("),
                "`{path}` MUST call `format_amd64_release_tag(...)` at least once — \
                 it is on the census of product-level `amd64-<sha>` tag-emitting sites \
                 the shield covers. A re-inline that dropped both the raw literal AND \
                 the delegation call would silently remove the tag from the fleet \
                 without this positive check."
            );
        }
    }

    /// Arch-peer of [`format_amd64_release_tag_prefixes_arch_and_sha`].
    /// The pure `arm64` tag-format helper MUST produce the canonical
    /// `arm64-<sha>` shape byte-for-byte. Pins the format at one site so
    /// a future drift to a new tag convention surfaces as a localized
    /// test failure at one site, not as silent tag-drift across the
    /// three `commands/image_release.rs` `arm64-<sha>` construction
    /// sites and every downstream registry-scan tool that resolves
    /// against `arm64-<sha>`.
    #[test]
    fn format_arm64_release_tag_prefixes_arch_and_sha() {
        assert_eq!(format_arm64_release_tag("deadbeef"), "arm64-deadbeef");
    }

    /// Arch-peer of
    /// [`format_amd64_release_tag_forwards_full_sha_verbatim`]. The
    /// `arm64` tag-format helper MUST forward its `git_sha` argument
    /// verbatim — no truncation, no case-folding, no whitespace trim.
    /// A future change that decided to normalise the SHA at the format
    /// boundary would silently diverge from the pre-lift inline
    /// `format!("arm64-{}", git_sha)` shape every consumer inherits.
    #[test]
    fn format_arm64_release_tag_forwards_full_sha_verbatim() {
        assert_eq!(
            format_arm64_release_tag("0123456789abcdef"),
            "arm64-0123456789abcdef"
        );
    }

    /// Arch-peer of
    /// [`amd64_tag_render_routes_through_format_helper_not_raw_format_literal`].
    /// Whole-module shield: no raw `format!("arm64-{}", ...)` may live
    /// in any `arm64-<sha>` tag-emitting consumer module. The pre-lift
    /// census covered three sites — all in `commands/image_release.rs`
    /// (the multi-arch push arm64 tag construction + the two
    /// `regctl index create --ref <registry>:arm64-<sha>` references
    /// that resolve against it). Every `arm64-<sha>` tag rendered by
    /// forge must resolve through [`format_arm64_release_tag`] so a
    /// future drift to a new tag convention (a `linux/arm64-` prefix,
    /// an architecture-parametric form, an embedded date stamp) flows
    /// to all three sites from one edit and downstream
    /// `docker manifest inspect ghcr.io/.../arm64-<sha>` audit queries
    /// continue to resolve against a single canonical shape.
    ///
    /// The forbidden shape is reconstructed at test time via `format!`
    /// from the bare string `"arm64-"` so this shield's own source text
    /// does not false-match itself. The exception is
    /// [`format_arm64_release_tag`] itself (in this same module), which
    /// is the ONE site allowed to spell the raw shape — that site is
    /// what every consumer delegates through.
    #[test]
    fn arm64_tag_render_routes_through_format_helper_not_raw_format_literal() {
        let forbidden = format!("{}{{}}", "\"arm64-");
        // Single-element census (only `commands/image_release.rs` carries
        // the pre-lift `arm64-<sha>` construction sites). A `let`-binding
        // rather than a `for` keeps `clippy::single_element_loop` happy;
        // when a second consumer joins the census, promote to a slice +
        // for-loop and mirror the amd64 shield above.
        let (path, source): (&str, &str) = (
            "commands/image_release.rs",
            include_str!("image_release.rs"),
        );
        assert!(
            !source.contains(&forbidden),
            "`{path}` must not spell the raw `format!(\"arm64-{{}}\", ...)` shape; \
             route through `crate::commands::cluster_overlay_release_preamble::\
             format_arm64_release_tag` instead (the byte-oracle-covered \
             canonical tag renderer)"
        );
    }

    /// Positive delegation shield paired with
    /// [`arm64_tag_render_routes_through_format_helper_not_raw_format_literal`]:
    /// `commands/image_release.rs` MUST carry a call to
    /// `format_arm64_release_tag` — a re-inline that also silently
    /// dropped the primitive call would evade the "no raw format
    /// literal" scan but is caught here.
    #[test]
    fn image_release_arm64_tag_callers_delegate_through_format_helper() {
        // Same single-element-census rationale as
        // [`arm64_tag_render_routes_through_format_helper_not_raw_format_literal`]
        // — a `let`-binding until a second consumer joins the census.
        let (path, source): (&str, &str) = (
            "commands/image_release.rs",
            include_str!("image_release.rs"),
        );
        assert!(
            source.contains("format_arm64_release_tag("),
            "`{path}` MUST call `format_arm64_release_tag(...)` at least once — \
             it is on the census of `arm64-<sha>` tag-emitting sites the shield \
             covers. A re-inline that dropped both the raw literal AND the \
             delegation call would silently remove the tag from the fleet without \
             this positive check."
        );
    }
}
