//! Info-routed `🔖 Git SHA: <sha>` labeled-tag-field grammar — the
//! BOOKMARK-glyph sibling of [`crate::info_git_sha_field!`].
//!
//! Two pre-lift sibling sites in `commands/bootstrap.rs`
//! (`push_single` at :251 + `push_all` at :306) each restated the
//!
//! ```ignore
//! info!("🔖 Git SHA: {}", &tags[0]);
//! ```
//!
//! stanza verbatim — a `🔖` glyph (U+1F516 BOOKMARK, standalone, no
//! variation selector, 4 bytes UTF-8), one ASCII space, the four-word
//! `Git SHA:` label, one ASCII space, the interpolated
//! [`std::fmt::Display`]-formatted SHA string (the first element of a
//! resolved tag vector), and an `info!`-routed emission via the tracing
//! subscriber. Post-lift the sites reach for
//! [`info_bookmark_git_sha_field!`] and the emoji + label + separator +
//! tracing verbosity are decided once here.
//!
//! # Semantic split from [`crate::info_git_sha_field!`] (`📦 Git SHA:`)
//!
//! The crate carries two `<emoji> Git SHA: <sha>` primitives; the split
//! is deliberate and documented at [`crate::git_sha_field`]:
//!
//! - [`crate::info_git_sha_field!`] wears the `📦` PACKAGE glyph
//!   (U+1F4E6) and narrates the pre-build/push/deploy artifact-identity
//!   SHA — the SHA of the *thing* about to go into a container image.
//!   Consumers live in `commands/{build, comprehensive_release,
//!   github_runner_ci}.rs`.
//! - [`info_bookmark_git_sha_field!`] (this macro) wears the `🔖`
//!   BOOKMARK glyph (U+1F516) and narrates a tag-catalog readout inside
//!   the bootstrap flow — the SHA is one entry (`&tags[0]`) in a
//!   `generate_auto_tags(...)` vector that the caller is about to push
//!   as an addressable version tag. Consumers live in
//!   `commands/bootstrap.rs::{push_single, push_all}`.
//!
//! Merging the two primitives would erase the artifact-vs-tag semantic
//! split the two glyphs deliberately establish at the call site — a
//! future reader who greps for `🔖` or `📦` finds the right primitive
//! by the glyph the site wears, not by decoding the surrounding
//! preamble.
//!
//! # The load-bearing single-space separator
//!
//! Both pre-lift sites spell `"🔖 Git SHA: {}"` with EXACTLY ONE ASCII
//! space between the glyph and the `Git` label. This matches the
//! one-space grammar of the [`crate::info_git_sha_field!`] sibling
//! (which wears `📦`, also fully qualified with no variation selector)
//! and is distinct from the fleet's [`crate::warn_nonfatal!`] /
//! [`crate::info_skipping!`] / [`crate::info_tags_field!`] siblings,
//! all of which use TWO ASCII spaces after their (variation-selector-
//! bearing) emoji. The `🔖` glyph (U+1F516) has no variation selector
//! — it is already a fully-qualified emoji — so a second ASCII space
//! would visually widen the gap versus the two-space `⚠️  ` / `⏭️  ` /
//! `🏷️  ` shapes rather than align with them. The primitive pins the
//! one-space grammar so a future collapse to the two-space form (e.g.
//! someone reading only `tags_field.rs` and extrapolating) hits the
//! byte-oracle test rather than shipping.
//!
//! # Preserving `tracing::info!` at the call site
//!
//! The macro expands to `::tracing::info!(...)` at the caller's
//! location, not to a function wrapper, so tracing's automatic source-
//! location capture (`file` + `line` + `module_path`) matches the
//! pre-lift behavior byte-for-byte. A function-based wrapper would
//! collapse every emission to the wrapper's own site and break
//! structured-log destinations that filter by module_path
//! (`RUST_LOG=forge::commands::bootstrap=info` would stop matching once
//! the emission moved to `forge::bookmark_git_sha_field`). The
//! byte-oracle writer sibling [`write_bookmark_git_sha_field`] captures
//! the exact rendered body for the tests (the `🔖` glyph, the one-space
//! gap, the `Git SHA:` label, the trailing newline) so the invariant is
//! pinned without racing an ambient tracing subscriber — the same split
//! [`crate::git_sha_field::write_git_sha_field`] carries against
//! [`crate::info_git_sha_field!`].

use std::fmt;
use std::io;

/// Emits a single `"🔖 Git SHA: <sha>"` line via [`writeln!`] against
/// the supplied writer, wrapping the caller's SHA with the pre-lift
/// `🔖 ` + one-ASCII-space + `Git SHA: ` label prefix that two sibling
/// sites in `commands/bootstrap.rs` spelled inline.
///
/// The [`crate::info_bookmark_git_sha_field!`] macro is the
/// [`tracing::info!`] adapter that production code invokes; this
/// direct-writer variant exists so the fail-before-pass tests can pin
/// the exact emitted bytes (the single-space gap after the `🔖` glyph,
/// the `Git SHA:` label literal, the second single-space gap before
/// the SHA, the trailing newline) without capturing a tracing
/// subscriber and without racing an ambient logger — the same split
/// [`crate::git_sha_field::write_git_sha_field`] carries against
/// [`crate::info_git_sha_field!`].
///
/// The `sha` parameter accepts any [`fmt::Display`] rather than a
/// concrete `&str` so a bare `&str` (both pre-lift call sites today
/// pass `&tags[0]`, a `&String` reference into the resolved tag
/// vector), an owned `String`, and a future git-SHA / tag-suffix
/// newtype all flow through the same writer without a per-caller
/// `.to_string()` intermediate.
#[allow(dead_code)] // See doc comment: the writer is a test/byte-oracle
                    // peer of the tracing-routed
                    // `info_bookmark_git_sha_field!` macro.
pub fn write_bookmark_git_sha_field<W: io::Write>(
    w: &mut W,
    sha: &dyn fmt::Display,
) -> io::Result<()> {
    writeln!(w, "\u{1F516} Git SHA: {}", sha)
}

/// Emit a bootstrap-preamble git-SHA readout via [`tracing::info!`] on
/// the fleet-standard `"🔖 Git SHA: <sha>"` grammar.
///
/// The macro expands to a direct `::tracing::info!(...)` call at the
/// caller's location so tracing's automatic source-location capture is
/// preserved (a function wrapper would collapse every emission to the
/// wrapper's site — see the module docs for why that breaks per-module
/// filter routing). See the [module docs](self) for the sibling site
/// census, the split against [`crate::info_git_sha_field!`] (PACKAGE
/// glyph, artifact-identity readout), and the compounding rationale for
/// the load-bearing single-space separator.
///
/// # Examples
///
/// ```ignore
/// // Pre-lift
/// info!("🔖 Git SHA: {}", &tags[0]);
///
/// // Post-lift
/// crate::info_bookmark_git_sha_field!(&tags[0]);
/// ```
#[macro_export]
macro_rules! info_bookmark_git_sha_field {
    ($sha:expr) => {
        ::tracing::info!("\u{1F516} Git SHA: {}", $sha)
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    // Pin the exact prefix bytes: `🔖` (U+1F516, 4 bytes F0 9F 94 96,
    // no variation selector), one ASCII space, the literal `Git SHA:`
    // (8 bytes), one ASCII space, the interpolated SHA Display, then
    // `\n`. A future refactor that adds a variation selector, widens
    // the one-space gap to two, drops the colon, changes the label
    // capitalization, or drops the trailing newline regresses this
    // assertion.
    #[test]
    fn write_bookmark_git_sha_field_emits_prefix_label_sha_and_newline() {
        let mut buf: Vec<u8> = Vec::new();
        write_bookmark_git_sha_field(&mut buf, &"a1b2c3d").unwrap();
        assert_eq!(buf, b"\xf0\x9f\x94\x96 Git SHA: a1b2c3d\n");
    }

    // Human-readable pin of the exact grammar so a future reader can
    // eyeball the render without decoding bytes.
    #[test]
    fn write_bookmark_git_sha_field_renders_expected_short_sha_grammar() {
        let mut buf: Vec<u8> = Vec::new();
        write_bookmark_git_sha_field(&mut buf, &"a1b2c3d").unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "\u{1F516} Git SHA: a1b2c3d\n"
        );
    }

    // Both pre-lift consumers route through
    // `generate_auto_tags(DEFAULT_ARCH)` and pass `&tags[0]`, which is
    // a formatted tag like `"amd64-<7charshasha>"` — pin that a
    // typical arch-prefixed tag body flows through the writer verbatim
    // without truncation or normalization.
    #[test]
    fn write_bookmark_git_sha_field_forwards_arch_prefixed_tag_verbatim() {
        let mut buf: Vec<u8> = Vec::new();
        let arch_tag = "amd64-a1b2c3d";
        write_bookmark_git_sha_field(&mut buf, &arch_tag).unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "\u{1F516} Git SHA: amd64-a1b2c3d\n"
        );
    }

    // Guard against the two-space grammar drift: `⚠️  ` / `⏭️  ` /
    // `🏷️  ` siblings all use two ASCII spaces (their emoji carry
    // variation selectors and are visually narrower without the extra
    // space). `🔖` is already fully-qualified emoji, so a two-space gap
    // would visually widen the label off the neighboring one-space
    // `📦` / `🔖` shapes rather than align with them. Pin the negative
    // shape explicitly so a future reader who reaches for the sibling
    // grammar hits this test.
    #[test]
    fn write_bookmark_git_sha_field_does_not_use_two_space_grammar() {
        let mut buf: Vec<u8> = Vec::new();
        write_bookmark_git_sha_field(&mut buf, &"deadbee").unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(
            !s.starts_with("\u{1F516}  "),
            "write_bookmark_git_sha_field must NOT emit two ASCII spaces \
             after the `🔖` glyph — the fleet-standard one-space grammar \
             for fully-qualified emoji is load-bearing. Actual: {s:?}",
        );
    }

    // Guard against variation-selector drift: `🔖` (U+1F516) is
    // deliberately used as a bare 4-byte glyph. A future refactor that
    // appended U+FE0F would silently break byte-oracle downstream
    // comparators. Pin the exact 4-byte encoding.
    #[test]
    fn write_bookmark_git_sha_field_does_not_append_variation_selector() {
        let mut buf: Vec<u8> = Vec::new();
        write_bookmark_git_sha_field(&mut buf, &"beefface").unwrap();
        // Byte 4 must be an ASCII space (0x20), not the first byte of
        // U+FE0F (which is 0xEF).
        assert_eq!(
            buf[4], 0x20,
            "byte 4 must be an ASCII space (0x20); a U+FE0F variation \
             selector would place 0xEF there and break the byte-oracle. \
             Bytes: {buf:?}",
        );
    }

    // Guard against PACKAGE drift: `📦` (U+1F4E6, F0 9F 93 A6) is the
    // sibling `commands/{build, comprehensive_release,
    // github_runner_ci}.rs` glyph for artifact-identity readouts. A
    // future refactor that flipped this primitive's glyph to PACKAGE
    // would silently merge the artifact-vs-tag semantic split the
    // two-glyph convention deliberately establishes. Pin that this
    // primitive emits BOOKMARK, not PACKAGE.
    #[test]
    fn write_bookmark_git_sha_field_emits_bookmark_glyph_not_package() {
        let mut buf: Vec<u8> = Vec::new();
        write_bookmark_git_sha_field(&mut buf, &"cafebabe").unwrap();
        // BOOKMARK is F0 9F 94 96; PACKAGE is F0 9F 93 A6. Bytes 2 and
        // 3 differ (0x94 vs 0x93, 0x96 vs 0xA6), so pinning both
        // catches the flip in either direction.
        assert_eq!(
            &buf[0..4],
            &[0xf0, 0x9f, 0x94, 0x96],
            "write_bookmark_git_sha_field must emit U+1F516 BOOKMARK \
             (F0 9F 94 96), NOT U+1F4E6 PACKAGE (F0 9F 93 A6) — the two \
             glyphs anchor different semantic layers across the crate. \
             Bytes: {buf:?}",
        );
    }

    // The macro forwards to `::tracing::info!` at the caller's
    // location. The subscriber cannot be captured in-process without
    // racing whatever subscriber `main` installs. Instead, pin that
    // the macro accepts the supported literal + format-arg shapes by
    // expanding it at compile time — a compile-fail here would fail
    // the crate's `cargo test` build gate.
    #[test]
    fn info_bookmark_git_sha_field_macro_compiles_with_supported_arg_shapes() {
        // Bare `&str` (both pre-lift call sites today after unwrapping
        // `&tags[0]`).
        let sha_str: &str = "a1b2c3d";
        crate::info_bookmark_git_sha_field!(sha_str);
        // Owned `String`.
        let owned = String::from("deadbeef");
        crate::info_bookmark_git_sha_field!(owned);
        // `&String` reference — `&tags[0]` where `tags: Vec<String>`
        // produces exactly this shape (`&String`); an array indexes
        // identically for the purpose of the compile-check.
        let vec_of_strings: Vec<String> = ["cafebabe".to_string()].into();
        crate::info_bookmark_git_sha_field!(&vec_of_strings[0]);
        // A future substrate::GitSha newtype would implement Display —
        // simulate with a Display-wrapping newtype to prove the slot
        // takes any Display.
        struct Wrap<'a>(&'a str);
        impl<'a> fmt::Display for Wrap<'a> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }
        crate::info_bookmark_git_sha_field!(Wrap("beeff00d"));
    }

    // Caller shield: no source line under `cli/src/commands/` may
    // spell the pre-lift raw `info!("🔖 Git SHA: {}", <arg>);` stanza
    // inline any more. The two pre-lift sites migrated; any future
    // consumer that wants the same grammar reaches for
    // `crate::info_bookmark_git_sha_field!` on first grep, not by
    // copy-pasting the raw shape from an existing command module.
    #[test]
    fn no_command_module_still_spells_raw_info_bookmark_git_sha_field_stanza() {
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
                if line.contains("info!(\"\u{1F516} Git SHA: ") {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `info!(\"\u{1F516} Git SHA: {{}}\", <arg>);` stanza(s) \
             survive under `commands/` — route each through \
             `crate::info_bookmark_git_sha_field!(<sha>)` instead:\n{:#?}",
            offenders
        );
    }

    // Positive half of the shield: `commands/bootstrap.rs` — the sole
    // pre-lift home of both sites — MUST forward through
    // `crate::info_bookmark_git_sha_field!(` at least twice, so a
    // migration that dropped a call site outright leaves the negative
    // "no raw inline shape" scan trivially satisfied by absence but
    // the positive count still fails.
    #[test]
    fn bootstrap_module_forwards_through_info_bookmark_git_sha_field_macro_twice() {
        use std::path::PathBuf;
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands")
            .join("bootstrap.rs");
        let source = std::fs::read_to_string(&path).unwrap();
        let forwards = source
            .matches("crate::info_bookmark_git_sha_field!(")
            .count();
        assert!(
            forwards >= 2,
            "commands/bootstrap.rs must forward at least 2 bookmark-glyph \
             git-SHA preamble site(s) through \
             `crate::info_bookmark_git_sha_field!(`; found {forwards}. A \
             dropped call would leave the negative raw-shape scan \
             satisfied by absence.",
        );
    }
}
