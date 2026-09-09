//! Info-routed `   ✅ Built: <store-path>` post-nix-build store-path
//! readout grammar — the [`crate::info_built_store_path_field!`] home.
//!
//! Two pre-lift sibling sites in `cli/src/nix.rs`
//! ([`crate::nix::build_docker_image`] at :343 +
//! [`crate::nix::build_docker_image_from_dir`] at :387) each restated
//!
//! ```ignore
//! info!("   ✅ Built: {}", <store_path>);
//! ```
//!
//! verbatim — three ASCII spaces of leading indent, a fully-qualified
//! `✅` (U+2705 WHITE HEAVY CHECK MARK, 3 bytes UTF-8), one ASCII
//! space, the four-word `Built:` label, one ASCII space, the
//! [`std::fmt::Display`]-formatted store-object path
//! ([`crate::store_path::StorePath`] at both pre-lift sites), and an
//! `info!`-routed emission via the tracing subscriber. Post-lift the
//! sites reach for [`crate::info_built_store_path_field!`] and the
//! indent + glyph + label + separator + tracing verbosity are decided
//! once here — a future widening of the readout (a bytes-built column,
//! a duration column, or a substrate-provenance sigil) has one landing.
//!
//! # Split from the sibling `   ✅ Built:` shape in `commands/nix.rs`
//!
//! Both pre-lift sites emit an identical grammar under
//! `cli/src/nix.rs` — the primitive lives here, not under
//! `commands/`, because the emitting site is the nix-build primitive
//! layer itself (immediately after `run_nix_build_typed` returns a
//! validated [`crate::store_path::StorePath`]), not a downstream
//! command-module orchestrator. A future consumer under `commands/`
//! that wants the same post-build acknowledgment reaches for this
//! macro on first grep rather than restating the raw shape at the
//! call site.

use std::fmt;
use std::io;

/// Emits a single `"   ✅ Built: <store-path>"` line via [`writeln!`]
/// against the supplied writer, wrapping the caller's store-path with
/// the pre-lift three-space indent + `✅ ` + one-ASCII-space +
/// `Built: ` label prefix that two sibling sites in `cli/src/nix.rs`
/// spelled inline.
///
/// The [`crate::info_built_store_path_field!`] macro is the
/// [`tracing::info!`] adapter that production code invokes; this
/// direct-writer variant exists so the fail-before-pass tests can pin
/// the exact emitted bytes (the three-space indent, the `✅` glyph,
/// the single-space gap after the glyph, the `Built:` label literal,
/// the second single-space gap before the store path, the trailing
/// newline) without capturing a tracing subscriber and without racing
/// an ambient logger.
///
/// The `path` parameter accepts any [`fmt::Display`] so the pre-lift
/// [`crate::store_path::StorePath`] flows through the writer without
/// a per-caller `.to_string()` intermediate; a future refactor that
/// swapped [`crate::store_path::StorePath`] for a
/// `substrate::BuiltPath` newtype would flow through identically as
/// long as the new type implements [`fmt::Display`].
#[allow(dead_code)] // See doc comment: the writer is a test/byte-oracle
                    // peer of the tracing-routed
                    // `info_built_store_path_field!` macro.
pub fn write_built_store_path_field<W: io::Write>(
    w: &mut W,
    path: &dyn fmt::Display,
) -> io::Result<()> {
    writeln!(w, "   \u{2705} Built: {}", path)
}

/// Emit a post-nix-build store-path readout via [`tracing::info!`] on
/// the fleet-standard `"   ✅ Built: <store-path>"` grammar.
///
/// The macro expands to a direct `::tracing::info!(...)` call at the
/// caller's location so tracing's automatic source-location capture is
/// preserved (a function wrapper would collapse every emission to the
/// wrapper's site and break structured-log destinations that filter
/// by `module_path`, e.g. `RUST_LOG=forge::nix=info`). See the
/// [module docs](self) for the sibling site census.
///
/// # Examples
///
/// ```ignore
/// // Pre-lift
/// info!("   ✅ Built: {}", result.store_path);
///
/// // Post-lift
/// crate::info_built_store_path_field!(result.store_path);
/// ```
#[macro_export]
macro_rules! info_built_store_path_field {
    ($path:expr) => {
        ::tracing::info!("   \u{2705} Built: {}", $path)
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    // Pin the exact prefix bytes: three ASCII spaces (0x20 0x20 0x20),
    // `✅` (U+2705, 3 bytes E2 9C 85, no variation selector), one
    // ASCII space, the literal `Built:` (6 bytes), one ASCII space,
    // the interpolated store-path Display, then `\n`. A future
    // refactor that swaps the indent width, appends a variation
    // selector, widens the one-space gap to two, drops the colon, or
    // drops the trailing newline regresses this assertion.
    #[test]
    fn write_built_store_path_field_emits_prefix_label_path_and_newline() {
        let mut buf: Vec<u8> = Vec::new();
        write_built_store_path_field(&mut buf, &"/nix/store/abc-name").unwrap();
        assert_eq!(buf, b"   \xe2\x9c\x85 Built: /nix/store/abc-name\n");
    }

    // Human-readable pin of the exact grammar so a future reader can
    // eyeball the render without decoding bytes.
    #[test]
    fn write_built_store_path_field_renders_expected_short_grammar() {
        let mut buf: Vec<u8> = Vec::new();
        write_built_store_path_field(&mut buf, &"/nix/store/abc-name").unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "   \u{2705} Built: /nix/store/abc-name\n"
        );
    }

    // Guard against variation-selector drift: `✅` (U+2705) is
    // deliberately used as a bare 3-byte glyph — its Emoji_Presentation
    // property is Yes by default, so appending U+FE0F is redundant and
    // would silently shift the byte layout downstream. Pin the exact
    // 3-byte encoding at the post-indent offset.
    #[test]
    fn write_built_store_path_field_does_not_append_variation_selector() {
        let mut buf: Vec<u8> = Vec::new();
        write_built_store_path_field(&mut buf, &"/nix/store/xyz-name").unwrap();
        // Bytes 0..3 are the three-space indent; bytes 3..6 are the
        // three UTF-8 bytes of U+2705; byte 6 must be an ASCII space
        // (0x20), not the first byte of U+FE0F (0xEF).
        assert_eq!(&buf[0..3], b"   ");
        assert_eq!(&buf[3..6], &[0xe2, 0x9c, 0x85]);
        assert_eq!(
            buf[6], 0x20,
            "byte 6 must be an ASCII space (0x20); a U+FE0F variation \
             selector would place 0xEF there and break the byte-oracle. \
             Bytes: {buf:?}",
        );
    }

    // Guard against indent drift: the pre-lift shape has EXACTLY three
    // ASCII spaces of leading indent — the sub-item indent depth that
    // the fleet's other `info!("   <Label>: {}", …)` readout stanzas
    // (`   Registry:`, `   URL:`, `   Cache:`, `   Namespace:`,
    // `   Image:`, `   Zone ID:`, …) also carry. Pin the negative
    // shape explicitly so a future edit that widened to four or
    // collapsed to two spaces regresses here rather than shipping.
    #[test]
    fn write_built_store_path_field_uses_three_space_indent_exactly() {
        let mut buf: Vec<u8> = Vec::new();
        write_built_store_path_field(&mut buf, &"/nix/store/p").unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(
            s.starts_with("   \u{2705}"),
            "must start with EXACTLY three ASCII spaces + `✅`; \
             actual: {s:?}",
        );
        assert!(
            !s.starts_with("  \u{2705}"),
            "two-space indent variant leaks through the byte oracle; \
             actual: {s:?}",
        );
        assert!(
            !s.starts_with("    \u{2705}"),
            "four-space indent variant leaks through the byte oracle; \
             actual: {s:?}",
        );
    }

    // Pin that a realistic `/nix/store/<hash>-<name>` path body flows
    // through the writer verbatim without truncation or normalization
    // — mirrors the shape both pre-lift consumers pass (a validated
    // [`crate::store_path::StorePath`] rendered via its Display impl,
    // which is `f.write_str(&self.full)` — no rewriting).
    #[test]
    fn write_built_store_path_field_forwards_realistic_store_path_verbatim() {
        let mut buf: Vec<u8> = Vec::new();
        let realistic = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-postgres-bootstrap-image";
        write_built_store_path_field(&mut buf, &realistic).unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            format!("   \u{2705} Built: {realistic}\n"),
        );
    }

    // The macro forwards to `::tracing::info!` at the caller's
    // location. Pin that the macro accepts the supported argument
    // shapes by expanding it at compile time — a compile-fail here
    // would fail the crate's `cargo test` build gate.
    #[test]
    fn info_built_store_path_field_macro_compiles_with_supported_arg_shapes() {
        // Bare `&str`.
        let s: &str = "/nix/store/p";
        crate::info_built_store_path_field!(s);
        // Owned `String`.
        let owned = String::from("/nix/store/p");
        crate::info_built_store_path_field!(owned);
        // A Display-wrapping newtype that stands in for the pre-lift
        // [`crate::store_path::StorePath`] — the primitive's slot
        // takes any Display so the pre-lift `result.store_path` and
        // the standalone `store_path: StorePath` binding both flow
        // through without a per-caller `.to_string()` intermediate.
        struct Wrap<'a>(&'a str);
        impl<'a> fmt::Display for Wrap<'a> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }
        crate::info_built_store_path_field!(Wrap("/nix/store/p"));
        // Field-access expression — the pre-lift
        // `build_docker_image` site passes `result.store_path`, which
        // is a field access on a returned `NixBuildResult`. Pin that
        // the macro's `$path:expr` slot accepts this shape verbatim.
        struct Held {
            store_path: String,
        }
        let held = Held {
            store_path: String::from("/nix/store/p"),
        };
        crate::info_built_store_path_field!(held.store_path);
    }

    // Negative shield: no source line under `cli/src/` may spell the
    // pre-lift raw `info!("   ✅ Built: {}", <arg>);` stanza inline
    // any more. The two pre-lift sites migrated; any future consumer
    // that wants the same grammar reaches for
    // `crate::info_built_store_path_field!` on first grep, not by
    // copy-pasting the raw shape from `cli/src/nix.rs`.
    //
    // Skip comment lines so this shield's own reference to the
    // pre-lift shape in prose doesn't self-hit, and skip this file
    // itself (`nix_built_store_path.rs`) so the macro body doesn't
    // self-hit either.
    #[test]
    fn no_source_file_still_spells_raw_info_built_store_path_stanza() {
        use std::path::PathBuf;
        let src_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let this_file_name = "nix_built_store_path.rs";
        let mut offenders: Vec<(PathBuf, usize, String)> = Vec::new();
        walk_rs_files(&src_dir, &mut |path| {
            if path.file_name().and_then(|n| n.to_str()) == Some(this_file_name) {
                return;
            }
            let source = std::fs::read_to_string(path).unwrap();
            for (idx, line) in source.lines().enumerate() {
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") || trimmed.starts_with("///") {
                    continue;
                }
                if line.contains("info!(\"   \u{2705} Built: ") {
                    offenders.push((path.to_path_buf(), idx + 1, line.to_string()));
                }
            }
        });
        assert!(
            offenders.is_empty(),
            "raw `info!(\"   \u{2705} Built: {{}}\", <arg>);` stanza(s) \
             survive under `cli/src/` — route each through \
             `crate::info_built_store_path_field!(<store_path>)` instead:\n{:#?}",
            offenders
        );
    }

    // Positive half of the shield: `cli/src/nix.rs` — the sole
    // pre-lift home of both sites — MUST forward through
    // `crate::info_built_store_path_field!(` at least twice, so a
    // migration that dropped a call site outright leaves the negative
    // scan trivially satisfied by absence but the positive count
    // still fails.
    #[test]
    fn nix_module_forwards_through_info_built_store_path_field_macro_twice() {
        use std::path::PathBuf;
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("nix.rs");
        let source = std::fs::read_to_string(&path).unwrap();
        let forwards = source
            .matches("crate::info_built_store_path_field!(")
            .count();
        assert!(
            forwards >= 2,
            "cli/src/nix.rs must forward at least 2 post-build store-path \
             readout site(s) through \
             `crate::info_built_store_path_field!(`; found {forwards}. A \
             dropped call would leave the negative raw-shape scan \
             satisfied by absence.",
        );
    }

    fn walk_rs_files(dir: &std::path::Path, visit: &mut dyn FnMut(&std::path::Path)) {
        for entry in std::fs::read_dir(dir).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk_rs_files(&path, visit);
            } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                visit(&path);
            }
        }
    }
}
