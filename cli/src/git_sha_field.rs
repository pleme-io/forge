//! Info-routed `📦 Git SHA: <sha>` labeled-tag-field grammar.
//!
//! Three pre-lift sibling sites across `commands/{build (×1: initial
//! `Nix Build + Attic Cache` header preamble), comprehensive_release
//! (×1: post-input-validation preamble, above `🎯 Registry` and
//! `🌍 Namespace`), github_runner_ci (×1: post-`GitHub Runner CI
//! Workflow` banner preamble, above `🎯 Target: <registry>:<sha>`)}.rs`
//! each restated the
//!
//! ```ignore
//! info!("📦 Git SHA: {}", git_sha);
//! ```
//!
//! stanza verbatim — a `📦` glyph (U+1F4E6 PACKAGE, standalone,
//! no variation selector, 4 bytes UTF-8), one ASCII space, the
//! four-word `Git SHA:` label, one ASCII space, the interpolated
//! [`std::fmt::Display`]-formatted SHA string, and an `info!`-routed
//! emission via the tracing subscriber. Post-lift the sites reach for
//! [`info_git_sha_field!`] and the emoji + label + separator +
//! tracing verbosity are decided once here.
//!
//! # Distinct from every sibling emoji-labeled tag-field primitive
//!
//! The crate carries a small family of `<emoji> <Label>: <value>`
//! primitives; each is the sole home for its distinct semantic layer
//! and destination:
//!
//! - [`crate::ui::print_tag_field`] / [`crate::ui::write_tag_field`]
//!   emit a `🏷️  <label>: <value>` line via [`println!`] on stdout — a
//!   direct-to-stdout render targeted at the interactive operator's
//!   terminal, wearing the `🏷️` LABEL glyph (U+1F3F7 + U+FE0F variation
//!   selector, two-ASCII-space gap). The pre-lift `println!` consumers
//!   for that primitive live in `commands/{rust_service, migrations}.rs`
//!   at post-run report bodies where the label carries the caller-
//!   supplied value coloring; a merge with this primitive would either
//!   drop the tracing-subscriber routing this macro needs (breaking
//!   OTLP export of pre-build SHA readouts) or bolt colored terminal
//!   paint onto non-interactive log records that must stay ANSI-free
//!   (the crate's [`tracing_subscriber`] initialization in `main.rs`
//!   deliberately sets `with_ansi(false)`).
//! - [`info_git_sha_field!`] (this macro) narrates a mid-preamble
//!   structured git-SHA readout via [`tracing::info!`] — the subscriber
//!   pipeline (structured logging, filter, OTLP export, per-module_path
//!   routing) processes the record with the exact call site's
//!   `module_path` / `file` / `line`, and the tracing layer emits an
//!   ANSI-free record suitable for CI-log ingestion.
//!
//! The sites carry different destinations and different filter paths
//! deliberately; a collapse of `info_git_sha_field!` and
//! `print_tag_field` into one primitive would break the tracing-vs-
//! stdout split that separates pre-workflow preambles (structured logs,
//! CI-consumed) from post-workflow reports (colored terminal output for
//! the interactive operator).
//!
//! # The `📦` PACKAGE glyph, not `🔖` BOOKMARK
//!
//! Two sibling `<emoji> Git SHA: <sha>` shapes exist in the crate: this
//! primitive's `📦 Git SHA:` (U+1F4E6 PACKAGE) at three sites, and
//! `commands/bootstrap.rs`'s `🔖 Git SHA: {&tags[0]}` (U+1F516 BOOKMARK)
//! at two sites (`push_single` / `push_all` — always on the FIRST
//! element of a resolved tag vector, never on a bare SHA string). The
//! PACKAGE glyph is deliberately reserved for build-preamble git-SHA
//! readouts where the SHA identifies the *artifact* about to be built /
//! pushed / deployed (the PACKAGE emoji anchors the "this is what's
//! going into a container image" mental model); the BOOKMARK glyph is
//! reserved for tag-resolution readouts inside bootstrap flows where the
//! SHA is one entry in a computed tag catalog (the BOOKMARK emoji
//! anchors the "this is an addressable version tag" mental model). A
//! merge of the two primitives would erase the artifact-vs-tag semantic
//! split the two glyphs deliberately establish at the call site.
//!
//! # The load-bearing single-space separator
//!
//! The three pre-lift sites all spell `"📦 Git SHA: {}"` with EXACTLY
//! ONE ASCII space between the glyph and the `Git` label. This is
//! deliberate and distinct from the fleet's [`crate::warn_nonfatal!`]
//! and [`crate::info_skipping!`] siblings, both of which use TWO ASCII
//! spaces after their (variation-selector-bearing) emoji. The `📦`
//! glyph (U+1F4E6) has no variation selector — it is already a fully-
//! qualified emoji — so a second ASCII space would visually widen the
//! gap versus the two-space `⚠️  ` / `⏭️  ` shapes rather than align
//! with them. The primitive pins the one-space grammar so a future
//! collapse to the two-space form (e.g. someone reading only
//! `nonfatal_warning.rs` and extrapolating) hits the byte-oracle test
//! rather than shipping.
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
//! emission moved to `forge::git_sha_field`). The byte-oracle writer
//! sibling [`write_git_sha_field`] captures the exact rendered body for
//! the tests (the `📦` glyph, the one-space gap, the `Git SHA:` label,
//! the trailing newline) so the invariant is pinned without racing an
//! ambient tracing subscriber — the same split
//! [`crate::nonfatal_warning::write_nonfatal_warn`] carries against
//! [`crate::warn_nonfatal!`] and
//! [`crate::skipping_step::write_skipping_step`] carries against
//! [`crate::info_skipping!`].

use std::fmt;
use std::io;

/// Emits a single `"📦 Git SHA: <sha>"` line via [`writeln!`] against
/// the supplied writer, wrapping the caller's SHA with the pre-lift
/// `📦 ` + one-ASCII-space + `Git SHA: ` label prefix that three sibling
/// sites spelled inline.
///
/// The [`crate::info_git_sha_field!`] macro is the [`tracing::info!`]
/// adapter that production code invokes; this direct-writer variant
/// exists so the fail-before-pass tests can pin the exact emitted bytes
/// (the single-space gap after the `📦` glyph, the `Git SHA:` label
/// literal, the second single-space gap before the SHA, the trailing
/// newline) without capturing a tracing subscriber and without racing
/// an ambient logger — the same split
/// [`crate::nonfatal_warning::write_nonfatal_warn`] carries against
/// [`crate::warn_nonfatal!`] and
/// [`crate::success_step::write_success_step`] carries against
/// [`crate::info_success!`].
///
/// The `sha` parameter accepts any [`fmt::Display`] rather than a
/// concrete `&str` so a bare `&str` (used by every pre-lift call site
/// today after the caller unwraps `git::get_short_sha()?` /
/// `crate::git::get_full_sha()?`), a `String` / `Cow<str>`, and a
/// future git-SHA newtype (`substrate::GitSha(String)`) all flow
/// through the same writer without a per-caller `.to_string()`
/// intermediate.
#[allow(dead_code)] // See doc comment: the writer is a test/byte-oracle
                    // peer of the tracing-routed `info_git_sha_field!`
                    // macro, and a future `collect_build_preambles`
                    // summary sibling will consume it directly.
pub fn write_git_sha_field<W: io::Write>(w: &mut W, sha: &dyn fmt::Display) -> io::Result<()> {
    writeln!(w, "\u{1F4E6} Git SHA: {}", sha)
}

/// Emit a build-preamble git-SHA readout via [`tracing::info!`] on the
/// fleet-standard `"📦 Git SHA: <sha>"` grammar.
///
/// The macro expands to a direct `::tracing::info!(...)` call at the
/// caller's location so tracing's automatic source-location capture is
/// preserved (a function wrapper would collapse every emission to the
/// wrapper's site — see the module docs for why that breaks per-module
/// filter routing). See the [module docs](self) for the sibling site
/// census, the split against
/// [`crate::ui::print_tag_field`] (stdout, colored, `🏷️` glyph) and
/// `commands/bootstrap.rs`'s `🔖 Git SHA:` (BOOKMARK glyph, tag-vector
/// readout), and the compounding rationale for the load-bearing
/// single-space separator.
///
/// # Examples
///
/// ```ignore
/// // Pre-lift
/// info!("📦 Git SHA: {}", git_sha);
///
/// // Post-lift
/// crate::info_git_sha_field!(git_sha);
/// ```
#[macro_export]
macro_rules! info_git_sha_field {
    ($sha:expr) => {
        ::tracing::info!("\u{1F4E6} Git SHA: {}", $sha)
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    // Pin the exact prefix bytes: `📦` (U+1F4E6, 4 bytes F0 9F 93 A6,
    // no variation selector), one ASCII space, the literal `Git SHA:`
    // (8 bytes), one ASCII space, the interpolated SHA Display, then
    // `\n`. A future refactor that adds a variation selector, widens
    // the one-space gap to two, drops the colon, changes the label
    // capitalization, or drops the trailing newline regresses this
    // assertion.
    #[test]
    fn write_git_sha_field_emits_prefix_label_sha_and_newline() {
        let mut buf: Vec<u8> = Vec::new();
        write_git_sha_field(&mut buf, &"a1b2c3d").unwrap();
        assert_eq!(buf, b"\xf0\x9f\x93\xa6 Git SHA: a1b2c3d\n");
    }

    // Human-readable pin of the exact grammar so a future reader can
    // eyeball the render without decoding bytes.
    #[test]
    fn write_git_sha_field_renders_expected_short_sha_grammar() {
        let mut buf: Vec<u8> = Vec::new();
        write_git_sha_field(&mut buf, &"a1b2c3d").unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "\u{1F4E6} Git SHA: a1b2c3d\n"
        );
    }

    // Full-length SHA readout — the `build.rs` consumer routes through
    // `crate::git::get_full_sha()` (40-char full SHA), not the
    // `get_short_sha()` used by the other two sites. Pin that the
    // full 40-character body flows through the writer verbatim
    // without truncation, re-hashing, or trailing whitespace injection.
    #[test]
    fn write_git_sha_field_forwards_full_40char_sha_verbatim() {
        let mut buf: Vec<u8> = Vec::new();
        let full_sha = "0123456789abcdef0123456789abcdef01234567";
        write_git_sha_field(&mut buf, &full_sha).unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "\u{1F4E6} Git SHA: 0123456789abcdef0123456789abcdef01234567\n"
        );
    }

    // Guard against the two-space grammar drift: `⚠️  ` and `⏭️  `
    // siblings both use two ASCII spaces (their emoji carry variation
    // selectors and are visually narrower without the extra space).
    // `📦` is already fully-qualified emoji, so a two-space gap would
    // visually widen the label off the neighboring one-space `✅` /
    // `📦` shapes rather than align with them. Pin the negative shape
    // explicitly so a future reader who reaches for the sibling grammar
    // hits this test.
    #[test]
    fn write_git_sha_field_does_not_use_two_space_grammar() {
        let mut buf: Vec<u8> = Vec::new();
        write_git_sha_field(&mut buf, &"deadbee").unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(
            !s.starts_with("\u{1F4E6}  "),
            "write_git_sha_field must NOT emit two ASCII spaces after \
             the `📦` glyph — the fleet-standard one-space grammar for \
             fully-qualified emoji is load-bearing. Actual: {s:?}",
        );
    }

    // Guard against variation-selector drift: `📦` (U+1F4E6) is
    // deliberately used as a bare 4-byte glyph. A future refactor that
    // appended U+FE0F would silently break byte-oracle downstream
    // comparators. Pin the exact 4-byte encoding.
    #[test]
    fn write_git_sha_field_does_not_append_variation_selector() {
        let mut buf: Vec<u8> = Vec::new();
        write_git_sha_field(&mut buf, &"beefface").unwrap();
        // Byte 4 must be an ASCII space (0x20), not the first byte of
        // U+FE0F (which is 0xEF).
        assert_eq!(
            buf[4], 0x20,
            "byte 4 must be an ASCII space (0x20); a U+FE0F variation \
             selector would place 0xEF there and break the byte-oracle. \
             Bytes: {buf:?}",
        );
    }

    // Guard against BOOKMARK drift: `🔖` (U+1F516, F0 9F 94 96) is the
    // sibling `commands/bootstrap.rs` glyph for tag-vector readouts.
    // A future refactor that flipped this primitive's glyph to
    // BOOKMARK would silently merge the artifact-vs-tag semantic split
    // the two-glyph convention deliberately establishes. Pin that this
    // primitive emits PACKAGE, not BOOKMARK.
    #[test]
    fn write_git_sha_field_emits_package_glyph_not_bookmark() {
        let mut buf: Vec<u8> = Vec::new();
        write_git_sha_field(&mut buf, &"cafebabe").unwrap();
        // PACKAGE is F0 9F 93 A6; BOOKMARK is F0 9F 94 96. Only byte 2
        // differs (0x93 vs 0x94), so pinning byte 2 catches the flip.
        assert_eq!(
            &buf[0..4],
            &[0xf0, 0x9f, 0x93, 0xa6],
            "write_git_sha_field must emit U+1F4E6 PACKAGE (F0 9F 93 A6), \
             NOT U+1F516 BOOKMARK (F0 9F 94 96) — the two glyphs anchor \
             different semantic layers across the crate. Bytes: {buf:?}",
        );
    }

    // The macro forwards to `::tracing::info!` at the caller's
    // location. The subscriber cannot be captured in-process without
    // racing whatever subscriber `main` installs. Instead, pin that
    // the macro accepts the supported literal + format-arg shapes by
    // expanding it at compile time — a compile-fail here would fail
    // the crate's `cargo test` build gate.
    #[test]
    fn info_git_sha_field_macro_compiles_with_supported_arg_shapes() {
        // Bare `&str` (every pre-lift call site today).
        let sha_str: &str = "a1b2c3d";
        crate::info_git_sha_field!(sha_str);
        // Owned `String` via the same slot.
        let owned = String::from("deadbeef");
        crate::info_git_sha_field!(owned);
        // A `&String` reference — `.get_short_sha()?` may return
        // `String`, and callers routinely pass through a shared
        // reference.
        let borrowed = &String::from("cafebabe");
        crate::info_git_sha_field!(borrowed);
        // A future substrate::GitSha newtype would implement Display —
        // simulate with a Display-wrapping newtype to prove the slot
        // takes any Display.
        struct Wrap<'a>(&'a str);
        impl<'a> fmt::Display for Wrap<'a> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }
        crate::info_git_sha_field!(Wrap("beeff00d"));
    }

    // Caller shield: no source line under `cli/src/commands/` may
    // spell the pre-lift raw `info!("📦 Git SHA: {}", <arg>);` stanza
    // inline any more. The three pre-lift sites migrated; any future
    // consumer that wants the same grammar reaches for
    // `crate::info_git_sha_field!` on first grep, not by copy-pasting
    // the raw shape from an existing command module.
    #[test]
    fn no_command_module_still_spells_raw_info_git_sha_field_stanza() {
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
                if line.contains("info!(\"\u{1F4E6} Git SHA: ") {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `info!(\"\u{1F4E6} Git SHA: {{}}\", <arg>);` stanza(s) \
             survive under `commands/` — route each through \
             `crate::info_git_sha_field!(<sha>)` instead:\n{:#?}",
            offenders
        );
    }

    // Positive half of the shield: the three pre-lift files MUST each
    // forward through `crate::info_git_sha_field!(` at least once, so
    // a migration that dropped a call site outright leaves the negative
    // "no raw inline shape" scan trivially satisfied by absence but the
    // positive count still fails.
    #[test]
    fn every_prelift_module_forwards_through_info_git_sha_field_macro() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        // (module basename, minimum forward count from the pre-lift census)
        let expectations: &[(&str, usize)] = &[
            ("build.rs", 1),
            ("comprehensive_release.rs", 1),
            ("github_runner_ci.rs", 1),
        ];
        for (basename, min_count) in expectations {
            let path = commands_dir.join(basename);
            let source = std::fs::read_to_string(&path).unwrap();
            let forwards = source.matches("crate::info_git_sha_field!(").count();
            assert!(
                forwards >= *min_count,
                "{basename} must forward at least {min_count} git-SHA \
                 preamble site(s) through `crate::info_git_sha_field!(`; \
                 found {forwards}. A dropped call would leave the \
                 negative raw-shape scan satisfied by absence.",
            );
        }
    }
}
