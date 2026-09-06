//! Info-routed `🎯 Registry: <registry>` labeled-registry-field grammar.
//!
//! Two pre-lift sibling sites across `commands/{bootstrap (×1:
//! post-`build_docker_image_from_dir` push preamble inside `push_single`,
//! immediately above `crate::info_tags_field!(tags)`), comprehensive_release
//! (×1: post-`crate::info_git_sha_field!(git_sha)` preamble, immediately
//! above the sibling `🌍 Namespace: <ns> (staging)` companion field)}.rs`
//! each restated the
//!
//! ```ignore
//! info!("🎯 Registry: {}", registry);
//! ```
//!
//! stanza verbatim — a `🎯` glyph (U+1F3AF DIRECT HIT, standalone, no
//! variation selector, 4 bytes UTF-8), one ASCII space, the nine-character
//! `Registry:` label, one ASCII space, the interpolated
//! [`std::fmt::Display`]-formatted registry string, and an `info!`-routed
//! emission via the tracing subscriber. Post-lift the sites reach for
//! [`info_registry_field!`] and the emoji + label + separator + tracing
//! verbosity are decided once here.
//!
//! # Distinct from every sibling emoji-labeled tag-field primitive
//!
//! The crate carries a small family of `<emoji> <Label>: <value>`
//! primitives; each is the sole home for its distinct semantic layer
//! and destination:
//!
//! - [`crate::info_git_sha_field!`] narrates a `📦 Git SHA: <sha>`
//!   pre-workflow readout via [`tracing::info!`] using the `📦` PACKAGE
//!   glyph (U+1F4E6). Distinct semantic layer (artifact-identity SHA
//!   vs. a destination registry) and distinct glyph.
//! - [`crate::info_tags_field!`] narrates a `🏷️  Tags: <t1, t2, …>`
//!   pre-push tag-catalog readout via [`tracing::info!`] using the
//!   `🏷️` LABEL glyph (U+1F3F7 + U+FE0F, two-space grammar).
//!   Distinct semantic layer (resolved multi-tag catalog vs. a single
//!   registry) and distinct glyph.
//! - [`crate::info_deploy_target_field!`] narrates a
//!   `🎯 Target: <registry>:<tag>` pre-deploy readout via
//!   [`tracing::info!`] on the same `🎯` DIRECT HIT glyph — but with a
//!   colon-joined `<registry>:<tag>` value shape (the OCI image
//!   reference) rather than a bare `<registry>` shape. The two `🎯`
//!   primitives are deliberately kept separate: `info_deploy_target_field!`
//!   fires at the moment the pipeline has a resolved image reference in
//!   hand (build-then-deploy), while `info_registry_field!` fires earlier
//!   in the pipeline, at the pre-push preamble where only the destination
//!   registry is known and the tag catalog is emitted through the sibling
//!   `crate::info_tags_field!` on the next line. A merge of the two
//!   primitives would either force the pre-push sites to fabricate a
//!   `:<tag>` suffix they do not yet have (a `:latest` or `:{tags[0]}`
//!   invention), or force the deploy sites to drop the colon-joined tag
//!   from the target readout — either direction erases a load-bearing
//!   semantic split.
//! - [`crate::ui::print_tag_field`] / [`crate::ui::write_tag_field`]
//!   emit a `🏷️  <label>: <value>` line via [`println!`] on stdout —
//!   a direct-to-stdout render targeted at the interactive operator's
//!   terminal, wearing the `🏷️` LABEL glyph. A merge with this
//!   primitive would either drop the tracing-subscriber routing this
//!   macro needs (breaking OTLP export of pre-push registry readouts)
//!   or bolt colored terminal paint onto non-interactive log records
//!   that must stay ANSI-free (the crate's [`tracing_subscriber`]
//!   initialization in `main.rs` deliberately sets `with_ansi(false)`).
//! - [`info_registry_field!`] (this macro) narrates a mid-preamble
//!   structured registry readout via [`tracing::info!`] — the
//!   subscriber pipeline (structured logging, filter, OTLP export,
//!   per-module_path routing) processes the record with the exact call
//!   site's `module_path` / `file` / `line`, and the tracing layer
//!   emits an ANSI-free record suitable for CI-log ingestion.
//!
//! The sites carry different destinations and different value shapes
//! deliberately; a collapse of `info_registry_field!` and
//! `print_tag_field` into one primitive would break the tracing-vs-
//! stdout split that separates pre-workflow preambles (structured logs,
//! CI-consumed) from post-workflow reports (colored terminal output for
//! the interactive operator).
//!
//! # The `🎯` DIRECT HIT glyph, not `📦` PACKAGE or `🏷️` LABEL
//!
//! Both pre-lift sites spell the glyph as `🎯` (U+1F3AF DIRECT HIT) —
//! the fleet's mental anchor for "this is the target of the forthcoming
//! action": the registry a push is about to land in, and the registry a
//! release orchestrator is about to publish under. The `📦` PACKAGE
//! glyph is reserved for build-input identity readouts (`Git SHA:`)
//! where the value identifies *what* is being built, not *where* it
//! lands. The `🏷️` LABEL glyph is reserved for the multi-tag catalog
//! a push resolves. A future refactor that flipped this primitive's
//! glyph to PACKAGE or LABEL would silently merge the target-vs-input
//! semantic split the three glyphs deliberately establish across the
//! crate.
//!
//! # The load-bearing single-space separator
//!
//! Both pre-lift sites spell `"🎯 Registry: {}"` with EXACTLY ONE
//! ASCII space between the glyph and the `Registry` label. This is
//! deliberate and distinct from the fleet's [`crate::warn_nonfatal!`]
//! and [`crate::info_skipping!`] siblings, both of which use TWO ASCII
//! spaces after their (variation-selector-bearing) emoji. The `🎯`
//! glyph (U+1F3AF) has no variation selector — it is already a fully-
//! qualified emoji — so a second ASCII space would visually widen the
//! gap versus the two-space `⚠️  ` / `⏭️  ` shapes rather than align
//! with the one-space `📦 Git SHA:` / `🎯 Target:` sibling family. The
//! primitive pins the one-space grammar so a future collapse to the
//! two-space form (e.g. someone reading only `nonfatal_warning.rs` and
//! extrapolating) hits the byte-oracle test rather than shipping.
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
//! the emission moved to `forge::registry_field`). The byte-oracle
//! writer sibling [`write_registry_field`] captures the exact rendered
//! body for the tests (the `🎯` glyph, the one-space gap, the
//! `Registry:` label, the second single-space gap before the registry,
//! the trailing newline) so the invariant is pinned without racing an
//! ambient tracing subscriber — the same split
//! [`crate::nonfatal_warning::write_nonfatal_warn`] carries against
//! [`crate::warn_nonfatal!`] and
//! [`crate::git_sha_field::write_git_sha_field`] carries against
//! [`crate::info_git_sha_field!`].

use std::fmt;
use std::io;

/// Emits a single `"🎯 Registry: <registry>"` line via [`writeln!`]
/// against the supplied writer, wrapping the caller's registry with the
/// pre-lift `🎯 ` + one-ASCII-space + `Registry: ` label prefix that two
/// sibling sites spelled inline.
///
/// The [`crate::info_registry_field!`] macro is the [`tracing::info!`]
/// adapter that production code invokes; this direct-writer variant
/// exists so the fail-before-pass tests can pin the exact emitted bytes
/// (the single-space gap after the `🎯` glyph, the `Registry:` label
/// literal, the second single-space gap before the registry, the
/// trailing newline) without capturing a tracing subscriber and without
/// racing an ambient logger — the same split
/// [`crate::nonfatal_warning::write_nonfatal_warn`] carries against
/// [`crate::warn_nonfatal!`] and
/// [`crate::success_step::write_success_step`] carries against
/// [`crate::info_success!`].
///
/// The `registry` parameter accepts any [`fmt::Display`] rather than a
/// concrete `&str` so a bare `&str` (used by every pre-lift call site
/// today after the caller unwraps `binary_def.registry_url()`), a
/// `String` / `Cow<str>`, and a future OCI-registry newtype
/// (`substrate::OciRegistry(String)`) all flow through the same writer
/// without a per-caller `.to_string()` intermediate.
#[allow(dead_code)] // See doc comment: the writer is a test/byte-oracle
                    // peer of the tracing-routed `info_registry_field!`
                    // macro, and a future `collect_push_preambles`
                    // summary sibling will consume it directly.
pub fn write_registry_field<W: io::Write>(
    w: &mut W,
    registry: &dyn fmt::Display,
) -> io::Result<()> {
    writeln!(w, "\u{1F3AF} Registry: {}", registry)
}

/// Emit a push-preamble registry readout via [`tracing::info!`] on the
/// fleet-standard `"🎯 Registry: <registry>"` grammar.
///
/// The macro expands to a direct `::tracing::info!(...)` call at the
/// caller's location so tracing's automatic source-location capture is
/// preserved (a function wrapper would collapse every emission to the
/// wrapper's site — see the module docs for why that breaks per-module
/// filter routing). See the [module docs](self) for the sibling site
/// census, the split against [`crate::ui::print_tag_field`] (stdout,
/// colored, `🏷️` glyph), [`crate::info_git_sha_field!`] (PACKAGE glyph,
/// artifact-SHA), and [`crate::info_deploy_target_field!`] (DIRECT HIT
/// glyph, colon-joined `<registry>:<tag>` value), and the compounding
/// rationale for the load-bearing single-space separator.
///
/// # Examples
///
/// ```ignore
/// // Pre-lift
/// info!("🎯 Registry: {}", registry);
///
/// // Post-lift
/// crate::info_registry_field!(registry);
/// ```
#[macro_export]
macro_rules! info_registry_field {
    ($registry:expr) => {
        ::tracing::info!("\u{1F3AF} Registry: {}", $registry)
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    // Pin the exact prefix bytes: `🎯` (U+1F3AF, 4 bytes F0 9F 8E AF,
    // no variation selector), one ASCII space, the literal `Registry:`
    // (9 bytes), one ASCII space, the interpolated registry Display,
    // then `\n`. A future refactor that adds a variation selector,
    // widens the one-space gap to two, drops the colon, changes the
    // label capitalization, or drops the trailing newline regresses
    // this assertion.
    #[test]
    fn write_registry_field_emits_prefix_label_registry_and_newline() {
        let mut buf: Vec<u8> = Vec::new();
        write_registry_field(&mut buf, &"ghcr.io/pleme/svc").unwrap();
        assert_eq!(buf, b"\xf0\x9f\x8e\xaf Registry: ghcr.io/pleme/svc\n");
    }

    // Human-readable pin of the exact grammar so a future reader can
    // eyeball the render without decoding bytes.
    #[test]
    fn write_registry_field_renders_expected_grammar() {
        let mut buf: Vec<u8> = Vec::new();
        write_registry_field(&mut buf, &"ghcr.io/pleme/svc").unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "\u{1F3AF} Registry: ghcr.io/pleme/svc\n"
        );
    }

    // Long-form registry-URL readout — the `bootstrap.rs` consumer
    // routes `binary_def.registry_url()` which may include a nested path
    // (`ghcr.io/pleme-io/bootstrap/<binary>`). Pin that the long body
    // flows through the writer verbatim without truncation, host
    // extraction, or path folding.
    #[test]
    fn write_registry_field_forwards_nested_path_registry_verbatim() {
        let mut buf: Vec<u8> = Vec::new();
        let nested = "ghcr.io/pleme-io/bootstrap/attic-token-bootstrap";
        write_registry_field(&mut buf, &nested).unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "\u{1F3AF} Registry: ghcr.io/pleme-io/bootstrap/attic-token-bootstrap\n"
        );
    }

    // Guard against the two-space grammar drift: `⚠️  ` and `⏭️  `
    // siblings both use two ASCII spaces (their emoji carry variation
    // selectors and are visually narrower without the extra space).
    // `🎯` is already fully-qualified emoji, so a two-space gap would
    // visually widen the label off the neighboring one-space `📦 Git
    // SHA:` / `🎯 Target:` shape rather than align with them. Pin the
    // negative shape explicitly so a future reader who reaches for the
    // sibling grammar hits this test.
    #[test]
    fn write_registry_field_does_not_use_two_space_grammar() {
        let mut buf: Vec<u8> = Vec::new();
        write_registry_field(&mut buf, &"r").unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(
            !s.starts_with("\u{1F3AF}  "),
            "write_registry_field must NOT emit two ASCII spaces after \
             the `🎯` glyph — the fleet-standard one-space grammar for \
             fully-qualified emoji is load-bearing. Actual: {s:?}",
        );
    }

    // Guard against variation-selector drift: `🎯` (U+1F3AF) is
    // deliberately used as a bare 4-byte glyph. A future refactor that
    // appended U+FE0F would silently break byte-oracle downstream
    // comparators. Pin the exact 4-byte encoding.
    #[test]
    fn write_registry_field_does_not_append_variation_selector() {
        let mut buf: Vec<u8> = Vec::new();
        write_registry_field(&mut buf, &"r").unwrap();
        // Byte 4 must be an ASCII space (0x20), not the first byte of
        // U+FE0F (which is 0xEF).
        assert_eq!(
            buf[4], 0x20,
            "byte 4 must be an ASCII space (0x20); a U+FE0F variation \
             selector would place 0xEF there and break the byte-oracle. \
             Bytes: {buf:?}",
        );
    }

    // Guard against glyph drift: `🎯` (U+1F3AF, F0 9F 8E AF) is the
    // registry-target semantic anchor. Sibling glyphs `📦` PACKAGE
    // (U+1F4E6, F0 9F 93 A6 — Git-SHA / artifact identity) and `🏷`
    // LABEL (U+1F3F7, F0 9F 8F B7 — tag catalog) each carry different
    // semantic layers. A future refactor that flipped this primitive's
    // glyph to PACKAGE or LABEL would silently merge the target-vs-input
    // semantic split the three-glyph convention deliberately establishes.
    // Pin all four glyph bytes.
    #[test]
    fn write_registry_field_emits_direct_hit_glyph_not_package_or_label() {
        let mut buf: Vec<u8> = Vec::new();
        write_registry_field(&mut buf, &"r").unwrap();
        assert_eq!(
            &buf[0..4],
            &[0xf0, 0x9f, 0x8e, 0xaf],
            "write_registry_field must emit U+1F3AF DIRECT HIT \
             (F0 9F 8E AF), NOT U+1F4E6 PACKAGE (F0 9F 93 A6) or \
             U+1F3F7 LABEL (F0 9F 8F B7) — the three glyphs anchor \
             different semantic layers across the crate. Bytes: {buf:?}",
        );
    }

    // Guard against merge with the sibling `🎯 Target: <registry>:<tag>`
    // primitive. Both share the `🎯` DIRECT HIT glyph but the two carry
    // different value shapes: `Registry:` is a bare Display, `Target:`
    // is a colon-joined Display pair. Pin that this writer's render
    // does not contain the `Target:` label — a future collapse of the
    // two into one primitive would either invent a `:<tag>` suffix or
    // drop the tag from the deploy sibling.
    #[test]
    fn write_registry_field_uses_registry_label_not_target_label() {
        let mut buf: Vec<u8> = Vec::new();
        write_registry_field(&mut buf, &"ghcr.io/pleme/svc").unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(
            s.contains("Registry: "),
            "write_registry_field must spell the `Registry:` label — a \
             future merge with the sibling `🎯 Target: <registry>:<tag>` \
             primitive would erase the load-bearing split. Actual: {s:?}",
        );
        assert!(
            !s.contains("Target: "),
            "write_registry_field must NOT spell the `Target:` label — \
             that label belongs to the sibling `info_deploy_target_field!` \
             primitive which carries a colon-joined `<registry>:<tag>` \
             value shape rather than a bare `<registry>` shape. \
             Actual: {s:?}",
        );
    }

    // No-ANSI guard: the crate's `tracing_subscriber` initialization
    // in `main.rs` deliberately sets `with_ansi(false)` so CI log
    // ingestion sees clean records. Pin that this primitive's render
    // carries no ANSI escape byte (0x1B) — a future refactor that
    // reached for `colored` on the label side would break the ANSI-
    // free contract the tracing-routed sites depend on.
    #[test]
    fn write_registry_field_emits_no_ansi_escape() {
        let mut buf: Vec<u8> = Vec::new();
        write_registry_field(&mut buf, &"r").unwrap();
        assert!(
            !buf.contains(&0x1b),
            "write_registry_field must emit no ANSI escape (0x1B) — \
             the tracing subscriber is configured `with_ansi(false)`. \
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
    fn info_registry_field_macro_compiles_with_supported_arg_shapes() {
        // Bare `&str` (every pre-lift call site today).
        let registry_str: &str = "ghcr.io/pleme/svc";
        crate::info_registry_field!(registry_str);
        // Owned `String` via the same slot.
        let registry_owned = String::from("ghcr.io/pleme/svc");
        crate::info_registry_field!(registry_owned);
        // A `&String` reference — `binary_def.registry_url()` may
        // return `String`, and callers routinely pass through a shared
        // reference.
        let borrowed = &String::from("ghcr.io/pleme/svc");
        crate::info_registry_field!(borrowed);
        // A future substrate::OciRegistry newtype would implement
        // Display — simulate with a Display-wrapping newtype to prove
        // the slot takes any Display.
        struct Wrap<'a>(&'a str);
        impl<'a> fmt::Display for Wrap<'a> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }
        crate::info_registry_field!(Wrap("ghcr.io/pleme/svc"));
    }

    // Caller shield: no source line under `cli/src/commands/` may
    // spell the pre-lift raw `info!("🎯 Registry: {}", <arg>);` stanza
    // inline any more. The two pre-lift sites migrated; any future
    // consumer that wants the same grammar reaches for
    // `crate::info_registry_field!` on first grep, not by copy-pasting
    // the raw shape from an existing command module.
    #[test]
    fn no_command_module_still_spells_raw_info_registry_field_stanza() {
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
                if line.contains("info!(\"\u{1F3AF} Registry: {}\"") {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `info!(\"\u{1F3AF} Registry: {{}}\", <arg>);` stanza(s) \
             survive under `commands/` — route each through \
             `crate::info_registry_field!(<registry>)` instead:\n{:#?}",
            offenders
        );
    }

    // Positive half of the shield: the two pre-lift files MUST each
    // forward through `crate::info_registry_field!(` at least once, so
    // a migration that dropped a call site outright leaves the negative
    // "no raw inline shape" scan trivially satisfied by absence but the
    // positive count still fails.
    #[test]
    fn every_prelift_module_forwards_through_info_registry_field_macro() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        // (module basename, minimum forward count from the pre-lift census)
        let expectations: &[(&str, usize)] =
            &[("bootstrap.rs", 1), ("comprehensive_release.rs", 1)];
        for (basename, min_count) in expectations {
            let path = commands_dir.join(basename);
            let source = std::fs::read_to_string(&path).unwrap();
            let forwards = source.matches("crate::info_registry_field!(").count();
            assert!(
                forwards >= *min_count,
                "{basename} must forward at least {min_count} registry-preamble \
                 site(s) through `crate::info_registry_field!(`; found \
                 {forwards}. A dropped call would leave the negative raw-shape \
                 scan satisfied by absence.",
            );
        }
    }
}
