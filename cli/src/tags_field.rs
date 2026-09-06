//! Info-routed `🏷️  Tags: <t1, t2, ...>` labeled-comma-list-field grammar.
//!
//! Two pre-lift sibling sites across `commands/{push (×1: post-`ghcr_token`
//! discovery preamble, above the Attic-then-GHCR push loop),
//! bootstrap (×1: post-`build_docker_image_from_dir` preamble inside
//! `push_single`, above `push_tags_with_progress`)}.rs` each restated the
//!
//! ```ignore
//! info!("🏷️  Tags: {}", tags.join(", "));
//! ```
//!
//! stanza verbatim — a `🏷` glyph (U+1F3F7 LABEL) followed by a U+FE0F
//! VARIATION SELECTOR-16 (the fleet's fully-qualified-emoji rendering
//! anchor for LABEL), TWO ASCII spaces (matching every other
//! variation-selector-bearing `<emoji>  <Label>:` sibling — `⚠️  `,
//! `⏭️  `, `🏷️  ` — where the two-space grammar visually restores the
//! width the narrower selector-anchored glyph would otherwise consume),
//! the four-character `Tags:` label, one ASCII space, the interpolated
//! [`slice::join`] of the caller's tag vector with the fleet-standard
//! `", "` comma-space separator, and an `info!`-routed emission via the
//! tracing subscriber. Post-lift the sites reach for [`info_tags_field!`]
//! and the emoji + variation selector + two-space gap + label + join
//! separator + tracing verbosity are decided once here.
//!
//! # Distinct from every sibling emoji-labeled field primitive
//!
//! The crate carries a small family of `<emoji> <Label>: <value>`
//! primitives; each is the sole home for its distinct semantic layer,
//! destination, and separator grammar:
//!
//! - [`crate::info_git_sha_field!`] narrates a `📦 Git SHA: <sha>`
//!   pre-workflow readout via [`tracing::info!`] using the `📦` PACKAGE
//!   glyph (U+1F4E6, no variation selector) with the ONE-space grammar
//!   its fully-qualified glyph carries. Distinct semantic layer
//!   (artifact-identity SHA vs. a resolved tag catalog), distinct
//!   separator grammar (single ASCII space vs. two), distinct
//!   interpolation shape (single Display vs. `.join(", ")` of a slice).
//! - [`crate::ui::print_tag_field`] / [`crate::ui::write_tag_field`]
//!   emit a `🏷️  <label>: <value>` line via [`println!`] on stdout — a
//!   direct-to-stdout render targeted at the interactive operator's
//!   terminal, wearing the same `🏷️` LABEL glyph with the same two-space
//!   grammar this primitive uses but routed to stdout (colored-value-
//!   friendly) rather than through the tracing subscriber (ANSI-free
//!   CI-log ingestion). The pre-lift `println!` consumers for that
//!   primitive live in `commands/{rust_service, migrations}.rs` at
//!   post-run report bodies where the caller supplies the label and
//!   value inline; a merge with this primitive would either drop the
//!   tracing-subscriber routing this macro needs (breaking OTLP export
//!   of pre-push tag readouts) or bolt colored terminal paint onto
//!   non-interactive log records that must stay ANSI-free (the crate's
//!   [`tracing_subscriber`] initialization in `main.rs` deliberately
//!   sets `with_ansi(false)`).
//! - [`info_tags_field!`] (this macro) narrates a mid-preamble
//!   structured tag-catalog readout via [`tracing::info!`] — the
//!   subscriber pipeline (structured logging, filter, OTLP export,
//!   per-`module_path` routing) processes the record with the exact
//!   call site's `module_path` / `file` / `line`, and the tracing
//!   layer emits an ANSI-free record suitable for CI-log ingestion.
//!
//! The sites carry different destinations, different separator
//! grammars, and different value shapes deliberately; a collapse of
//! `info_tags_field!` and `print_tag_field` into one primitive would
//! break the tracing-vs-stdout split that separates pre-workflow
//! preambles (structured logs, CI-consumed) from post-workflow reports
//! (colored terminal output for the interactive operator).
//!
//! # The `🏷️` LABEL + `\u{FE0F}` variation selector + two-space
//! grammar
//!
//! Both pre-lift sites spell the stanza as `"🏷️  Tags: {}"` with the
//! LABEL glyph (U+1F3F7), a U+FE0F VARIATION SELECTOR-16, and TWO
//! ASCII spaces before `Tags:`. This grammar matches the fleet-wide
//! `<variation-selector-bearing emoji>  <Label>:` shape used by
//! [`crate::warn_nonfatal!`] (`⚠️  ` — U+26A0 U+FE0F + two spaces),
//! [`crate::info_skipping!`] (`⏭️  ` — U+23ED U+FE0F + two spaces),
//! and [`crate::ui::write_tag_field`] (`🏷️  ` — U+1F3F7 U+FE0F + two
//! spaces). The two-space gap is load-bearing: U+FE0F is zero-width
//! and the emoji-presentation form the selector anchors is narrower
//! than the text-presentation fallback would be, so a one-space gap
//! after a variation-selector-bearing glyph misaligns the label
//! against the two-space `📦 Git SHA:` sibling family (whose
//! fully-qualified glyphs already carry emoji presentation without a
//! selector). The primitive pins the two-space grammar so a future
//! collapse to the one-space form (e.g. someone reading only
//! `git_sha_field.rs` and extrapolating from its one-space PACKAGE
//! grammar) hits the byte-oracle test rather than shipping.
//!
//! # The load-bearing `", "` comma-space join separator
//!
//! Both pre-lift sites spell the join as `tags.join(", ")` — a comma,
//! then an ASCII space, then the next tag. This matches the fleet's
//! human-readable-list convention (see also `push.rs::execute` at the
//! `push_tags_with_progress` narrator: `"   • {}:{}"` per-tag bullet
//! rendering, where the same comma-space appears in the pre-render
//! readout so the operator sees the exact list they'll shortly see
//! bulleted). A future refactor that dropped to a bare `","`
//! separator would break the visual scan a reader depends on to
//! count tags at a glance; the byte-oracle pins the space.
//!
//! # Preserving `tracing::info!` at the call site
//!
//! The macro expands to `::tracing::info!(...)` at the caller's
//! location, not to a function wrapper, so tracing's automatic source-
//! location capture (`file` + `line` + `module_path`) matches the
//! pre-lift behavior byte-for-byte. A function-based wrapper would
//! collapse every emission to the wrapper's own site and break
//! structured-log destinations that filter by module_path
//! (`RUST_LOG=forge::commands::push=info` would stop matching once
//! the emission moved to `forge::tags_field`). The byte-oracle writer
//! sibling [`write_tags_field`] captures the exact rendered body for
//! the tests (the `🏷️` glyph + selector, the two-space gap, the
//! `Tags:` label, the space, the comma-space-joined tag vector, the
//! trailing newline) so the invariant is pinned without racing an
//! ambient tracing subscriber — the same split
//! [`crate::nonfatal_warning::write_nonfatal_warn`] carries against
//! [`crate::warn_nonfatal!`] and
//! [`crate::git_sha_field::write_git_sha_field`] carries against
//! [`crate::info_git_sha_field!`].

use std::io;

/// Emits a single `"🏷️  Tags: <t1, t2, ...>"` line via [`writeln!`]
/// against the supplied writer, wrapping the caller's tag slice with
/// the pre-lift `🏷️` + U+FE0F variation selector + two-ASCII-space +
/// `Tags:` label prefix that two sibling sites spelled inline, and
/// joining the tag vector with the fleet-standard `", "` comma-space
/// separator.
///
/// The [`crate::info_tags_field!`] macro is the [`tracing::info!`]
/// adapter that production code invokes; this direct-writer variant
/// exists so the fail-before-pass tests can pin the exact emitted
/// bytes (the LABEL glyph, the variation selector, the two-space gap,
/// the `Tags:` label literal, the comma-space join separator, the
/// trailing newline) without capturing a tracing subscriber and
/// without racing an ambient logger — the same split
/// [`crate::nonfatal_warning::write_nonfatal_warn`] carries against
/// [`crate::warn_nonfatal!`] and
/// [`crate::success_step::write_success_step`] carries against
/// [`crate::info_success!`].
///
/// The `tags` parameter accepts `&[String]` — the type both pre-lift
/// call sites hold at the lift point (`push.rs::execute` receives
/// `mut tags: Vec<String>` and dereferences to slice, and
/// `bootstrap.rs::push_single` binds `let tags = generate_auto_tags(
/// DEFAULT_ARCH).await?` whose declared return is
/// `Result<Vec<String>>`). A future call site holding
/// `&[&str]` or `Vec<Cow<'_, str>>` can adapt at its site rather than
/// forcing this signature to be generic over the element type.
#[allow(dead_code)] // See doc comment: the writer is a test/byte-oracle
                    // peer of the tracing-routed `info_tags_field!`
                    // macro. A future post-workflow summary consumer
                    // that collects the pre-push tag catalogs into a
                    // single report body will use this writer directly.
pub fn write_tags_field<W: io::Write>(w: &mut W, tags: &[String]) -> io::Result<()> {
    writeln!(w, "\u{1F3F7}\u{FE0F}  Tags: {}", tags.join(", "))
}

/// Emit a mid-workflow tag-catalog readout via [`tracing::info!`] on
/// the fleet-standard `"🏷️  Tags: <t1, t2, ...>"` grammar.
///
/// The macro expands to a direct `::tracing::info!(...)` call at the
/// caller's location so tracing's automatic source-location capture
/// is preserved (a function wrapper would collapse every emission to
/// the wrapper's site — see the module docs for why that breaks
/// per-module filter routing). The `tags` argument is expected to
/// expose a `.join(", ")` method (any `Vec<String>` / `&[String]` /
/// `&Vec<String>` will do); the macro joins with the fleet-standard
/// `", "` comma-space separator at the caller's site.
///
/// See the [module docs](self) for the sibling site census, the split
/// against [`crate::ui::print_tag_field`] (stdout, colored,
/// caller-supplied label), and the compounding rationale for the
/// two-space `🏷️  ` variation-selector grammar.
///
/// # Examples
///
/// ```ignore
/// // Pre-lift
/// info!("🏷️  Tags: {}", tags.join(", "));
///
/// // Post-lift
/// crate::info_tags_field!(tags);
/// ```
#[macro_export]
macro_rules! info_tags_field {
    ($tags:expr) => {
        ::tracing::info!("\u{1F3F7}\u{FE0F}  Tags: {}", $tags.join(", "))
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    // Pin the exact prefix bytes: `🏷` (U+1F3F7, 4 bytes F0 9F 8F B7),
    // U+FE0F VARIATION SELECTOR-16 (3 bytes EF B8 8F), two ASCII
    // spaces (0x20 0x20), the literal `Tags:` (5 bytes), one ASCII
    // space, the comma-space-joined tag Display, then `\n`. A future
    // refactor that drops the variation selector, narrows the
    // two-space gap to one, drops the colon, changes the label
    // capitalization, or drops the trailing newline regresses this
    // assertion.
    #[test]
    fn write_tags_field_emits_prefix_selector_two_spaces_label_join_and_newline() {
        let mut buf: Vec<u8> = Vec::new();
        let tags: Vec<String> = vec!["amd64-abc1234".to_string(), "amd64-latest".to_string()];
        write_tags_field(&mut buf, &tags).unwrap();
        assert_eq!(
            buf,
            b"\xf0\x9f\x8f\xb7\xef\xb8\x8f  Tags: amd64-abc1234, amd64-latest\n"
        );
    }

    // Human-readable pin of the exact grammar so a future reader can
    // eyeball the render without decoding bytes.
    #[test]
    fn write_tags_field_renders_expected_multi_tag_grammar() {
        let mut buf: Vec<u8> = Vec::new();
        let tags: Vec<String> = vec!["amd64-abc1234".to_string(), "amd64-latest".to_string()];
        write_tags_field(&mut buf, &tags).unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "\u{1F3F7}\u{FE0F}  Tags: amd64-abc1234, amd64-latest\n"
        );
    }

    // Single-element tag vector — the `push_single` call in
    // `bootstrap.rs` routes a `generate_auto_tags(DEFAULT_ARCH)`
    // vector through here that on a fresh-repo test rig can be
    // one element. Pin that a single tag renders without a
    // trailing `", "` (which `.join(", ")` guarantees but the
    // pre-lift shape trusted implicitly).
    #[test]
    fn write_tags_field_renders_single_element_without_trailing_separator() {
        let mut buf: Vec<u8> = Vec::new();
        let tags: Vec<String> = vec!["amd64-latest".to_string()];
        write_tags_field(&mut buf, &tags).unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "\u{1F3F7}\u{FE0F}  Tags: amd64-latest\n"
        );
    }

    // Empty tag vector — an `execute(tags: Vec<String>, auto_tags:
    // bool)` call with `--auto-tags=false` and no `--tag` supplied
    // bail!s at the caller BEFORE reaching this primitive (see
    // `push.rs::execute` at the `if tags.is_empty() { bail!(...) }`
    // guard above line 245). Pin that even if a future caller
    // reached this writer with an empty slice, the primitive would
    // still emit the label + trailing newline without panicking on
    // an empty join or dropping the newline — the pre-lift shape's
    // implicit invariant survives the lift.
    #[test]
    fn write_tags_field_renders_empty_vector_with_label_and_newline_only() {
        let mut buf: Vec<u8> = Vec::new();
        let tags: Vec<String> = Vec::new();
        write_tags_field(&mut buf, &tags).unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "\u{1F3F7}\u{FE0F}  Tags: \n"
        );
    }

    // Guard against variation-selector drift: the sibling
    // `git_sha_field::write_git_sha_field` primitive deliberately
    // omits U+FE0F (its `📦` glyph is already fully qualified). A
    // future reader reaching for that sibling's one-space grammar
    // would drop the selector here and misalign the label against the
    // rest of the two-space `<vs-emoji>  <Label>:` fleet family. Pin
    // the selector's presence at bytes 4..7 (EF B8 8F).
    #[test]
    fn write_tags_field_includes_u_fe0f_variation_selector() {
        let mut buf: Vec<u8> = Vec::new();
        let tags: Vec<String> = vec!["t1".to_string()];
        write_tags_field(&mut buf, &tags).unwrap();
        assert_eq!(
            &buf[4..7],
            &[0xef, 0xb8, 0x8f],
            "bytes 4..7 must be U+FE0F (EF B8 8F) — the variation \
             selector anchor for the LABEL glyph's emoji \
             presentation. Bytes: {buf:?}",
        );
    }

    // Guard against one-space-grammar drift: pin the two ASCII spaces
    // (0x20 0x20) at bytes 7..9 (immediately after the selector). A
    // future refactor that dropped one space to match the sibling
    // `📦 Git SHA:` one-space grammar would misalign this primitive
    // against the two-space `⚠️  ` / `⏭️  ` fleet family.
    #[test]
    fn write_tags_field_uses_two_space_grammar_after_variation_selector() {
        let mut buf: Vec<u8> = Vec::new();
        let tags: Vec<String> = vec!["t1".to_string()];
        write_tags_field(&mut buf, &tags).unwrap();
        assert_eq!(
            &buf[7..9],
            b"  ",
            "bytes 7..9 must be exactly two ASCII spaces (0x20 0x20) \
             — the two-space grammar of the variation-selector-bearing \
             LABEL glyph is load-bearing (see also `⚠️  `, `⏭️  `). \
             Bytes: {buf:?}",
        );
    }

    // Guard against LABEL-vs-PACKAGE glyph drift: `🏷` is U+1F3F7
    // (F0 9F 8F B7), `📦` is U+1F4E6 (F0 9F 93 A6). Byte 2 differs
    // (0x8F vs 0x93) and byte 3 differs (0xB7 vs 0xA6). A future
    // refactor that flipped this primitive's glyph to PACKAGE (a
    // reader extrapolating from the sibling `git_sha_field.rs`
    // primitive) would silently merge the tag-catalog-vs-artifact-SHA
    // semantic split. Pin byte 2 + byte 3 explicitly.
    #[test]
    fn write_tags_field_emits_label_glyph_not_package() {
        let mut buf: Vec<u8> = Vec::new();
        let tags: Vec<String> = vec!["t1".to_string()];
        write_tags_field(&mut buf, &tags).unwrap();
        assert_eq!(
            &buf[0..4],
            &[0xf0, 0x9f, 0x8f, 0xb7],
            "write_tags_field must emit U+1F3F7 LABEL (F0 9F 8F B7), \
             NOT U+1F4E6 PACKAGE (F0 9F 93 A6). Bytes: {buf:?}",
        );
    }

    // Guard against the comma-space separator drifting to a bare
    // comma. The `.join(", ")` produces `t1, t2, t3` with a space
    // after each comma; a refactor to `.join(",")` would emit
    // `t1,t2,t3` and break the visual scan the operator uses to
    // count tags at a glance.
    #[test]
    fn write_tags_field_joins_with_comma_and_space_not_bare_comma() {
        let mut buf: Vec<u8> = Vec::new();
        let tags: Vec<String> = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        write_tags_field(&mut buf, &tags).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(
            s.contains("a, b, c"),
            "write_tags_field must join tags with `, ` (comma + \
             ASCII space) — a bare `,` separator misaligns the \
             operator's visual tag count. Actual render: {s:?}",
        );
        assert!(
            !s.contains("a,b"),
            "write_tags_field must NOT emit a bare `,` (no space) \
             between tags. Actual render: {s:?}",
        );
    }

    // No-ANSI guard: the crate's `tracing_subscriber` initialization
    // in `main.rs` deliberately sets `with_ansi(false)` so CI log
    // ingestion sees clean records. Pin that this primitive's render
    // carries no ANSI escape byte (0x1B) — a future refactor that
    // reached for `colored` on the label side would break the
    // ANSI-free contract the tracing-routed sites depend on.
    #[test]
    fn write_tags_field_emits_no_ansi_escape() {
        let mut buf: Vec<u8> = Vec::new();
        let tags: Vec<String> = vec!["t1".to_string()];
        write_tags_field(&mut buf, &tags).unwrap();
        assert!(
            !buf.contains(&0x1b),
            "write_tags_field must emit no ANSI escape (0x1B) — the \
             tracing subscriber is configured `with_ansi(false)`. \
             Bytes: {buf:?}",
        );
    }

    // The macro forwards to `::tracing::info!` at the caller's
    // location. The subscriber cannot be captured in-process without
    // racing whatever subscriber `main` installs. Instead, pin that
    // the macro accepts the supported slice / Vec / &Vec shapes by
    // expanding it at compile time — a compile-fail here would fail
    // the crate's `cargo test` build gate.
    #[test]
    fn info_tags_field_macro_compiles_with_supported_arg_shapes() {
        // Owned Vec<String> (bootstrap.rs::push_single after
        // `generate_auto_tags(...).await?`).
        let owned: Vec<String> = vec!["amd64-abc1234".to_string(), "amd64-latest".to_string()];
        crate::info_tags_field!(owned);
        // Borrowed &Vec<String>.
        let borrowed: &Vec<String> = &vec!["amd64-latest".to_string()];
        crate::info_tags_field!(borrowed);
        // Slice &[String] (push.rs::execute reaches through the
        // `mut tags: Vec<String>` param and can auto-deref).
        let slice: &[String] = &["amd64-latest".to_string()];
        crate::info_tags_field!(slice);
    }

    // Caller shield: no source line under `cli/src/commands/` may
    // spell the pre-lift raw `info!("🏷️  Tags: {}", <arg>.join(", "));`
    // stanza inline any more. The two pre-lift sites migrated; any
    // future consumer that wants the same grammar reaches for
    // `crate::info_tags_field!` on first grep, not by copy-pasting
    // the raw shape from an existing command module.
    #[test]
    fn no_command_module_still_spells_raw_info_tags_field_stanza() {
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
                // Skip comment lines so this shield's own reference
                // to the pre-lift shape in prose doesn't self-hit.
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") || trimmed.starts_with("///") {
                    continue;
                }
                if line.contains("info!(\"\u{1F3F7}\u{FE0F}  Tags: ") {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `info!(\"\u{1F3F7}\u{FE0F}  Tags: {{}}\", <arg>.join(\", \"));` \
             stanza(s) survive under `commands/` — route each through \
             `crate::info_tags_field!(<tags>)` instead:\n{:#?}",
            offenders
        );
    }

    // Positive half of the shield: the two pre-lift files MUST each
    // forward through `crate::info_tags_field!(` at least once, so a
    // migration that dropped a call site outright leaves the negative
    // "no raw inline shape" scan trivially satisfied by absence but
    // the positive count still fails.
    #[test]
    fn every_prelift_module_forwards_through_info_tags_field_macro() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        // (module basename, minimum forward count from the pre-lift census)
        let expectations: &[(&str, usize)] = &[("push.rs", 1), ("bootstrap.rs", 1)];
        for (basename, min_count) in expectations {
            let path = commands_dir.join(basename);
            let source = std::fs::read_to_string(&path).unwrap();
            let forwards = source.matches("crate::info_tags_field!(").count();
            assert!(
                forwards >= *min_count,
                "{basename} must forward at least {min_count} tag-catalog \
                 preamble site(s) through `crate::info_tags_field!(`; \
                 found {forwards}. A dropped call would leave the \
                 negative raw-shape scan satisfied by absence.",
            );
        }
    }
}
