//! Info-routed `   Updated <label> to: <value>` three-space-indented
//! post-splice update-acknowledgment field-readout grammar.
//!
//! Six pre-lift sibling sites across `commands/{kenshi (×1: `images[]
//! newTag` splice acknowledgment inside `update_kenshi_image`),
//! kenshi_agent (×2: `images[] newTag` splice + `AGENT_IMAGE env`
//! registry-anchored splice acknowledgments inside
//! `update_kenshi_agent_image`), nix_builder (×2: `newTag` splice +
//! `BUILDER_IMAGE` registry-anchored splice acknowledgments inside
//! `update_nix_builder_manifest` / `update_kenshi_builder_image`),
//! builder_pool_edit (×1: parameterised `field`-selected splice
//! acknowledgment inside `update_builder_pool_field`)}.rs` each restated
//! the
//!
//! ```ignore
//! info!("   Updated <label> to: {}", <value>);
//! ```
//!
//! stanza verbatim — three ASCII spaces of indent, the seven-character
//! `Updated` verb, one ASCII space, the label (an inline literal at five
//! sites, a runtime [`std::fmt::Display`] at the parameterised sixth),
//! the four-character ` to:` separator, one ASCII space, the interpolated
//! [`std::fmt::Display`]-formatted new value, and an `info!`-routed
//! emission via the tracing subscriber. Post-lift the sites reach for
//! [`info_updated_field!`] and the indent width + verb + separator +
//! tracing verbosity are decided once here.
//!
//! # Distinct from every sibling three-space-indented field primitive
//!
//! The crate carries a small family of `   <Label>: <value>` sub-item
//! field-readout primitives ([`crate::info_namespace_field!`],
//! [`crate::info_zone_id_field!`]) that all emit a three-space-indented
//! `<Label>: <value>` line under an emoji-anchored parent header. This
//! primitive is deliberately **not** one of them: the pre-lift stanza
//! carries an `Updated <label> to: <value>` verb-plus-preposition
//! grammar — not a bare `<Label>: <value>` field readout — and it fires
//! per-splice as a per-hit acknowledgment of a mutation, not per-command
//! as a preamble readout of a configured field. A merge into any bare
//! `<Label>:` primitive would either fabricate a colon after the label
//! (turning `Updated newTag to: <v>` into `Updated newTag: <v>` and
//! erasing the load-bearing "to:" splice-direction cue), or force the
//! bare-field primitives to fabricate an `Updated` prefix they have no
//! source for.
//!
//! # Distinct from the sibling three-space-indented step-outcome primitives
//!
//! The crate also carries three-space-indented step-outcome primitives
//! ([`crate::info_indented_success!`], [`crate::ui::print_bright_step_pass`],
//! [`crate::ui::print_plain_step_warn`]) that emit
//! `   <glyph> <message>` shapes with a leading emoji (`✅`, `⚠️`) or
//! bright-colored ASCII glyph. This primitive is the GLYPHLESS
//! verb-anchored shape: the pre-lift sites emit `   Updated <label> to:
//! <value>` with no glyph anchor because the announcement pairs with a
//! sibling `📝 Updating: <path>` GLYPH-ANCHORED phase-open banner
//! emitted separately by the caller (before the splice) — the two lines
//! form an open/close pair and the closing line's glyphlessness signals
//! its sub-item status under the opener. A merge would either fabricate
//! a `✅` glyph the pre-lift sites did not carry, or force the sibling
//! step-outcome primitives to drop their glyph anchor.
//!
//! # Preserving `tracing::info!` at the call site
//!
//! The macro expands to `::tracing::info!(...)` at the caller's location,
//! not to a function wrapper, so tracing's automatic source-location
//! capture (`file` + `line` + `module_path`) matches the pre-lift
//! behavior byte-for-byte. A function-based wrapper would collapse every
//! emission to the wrapper's own site and break structured-log
//! destinations that filter by `module_path`
//! (`RUST_LOG=forge::commands::kenshi=info` would stop matching once the
//! emission moved to `forge::updated_field`). The byte-oracle writer
//! sibling [`write_updated_field`] captures the exact rendered body for
//! the tests (the three-space indent, the `Updated` verb, the interpolated
//! label, the ` to: ` separator, the interpolated value, the trailing
//! newline) so the invariant is pinned without racing an ambient tracing
//! subscriber — the same split
//! [`crate::namespace_field::write_namespace_field`] carries against
//! [`crate::info_namespace_field!`] and
//! [`crate::zone_id_field::write_zone_id_field`] carries against
//! [`crate::info_zone_id_field!`].

use std::fmt;
use std::io;

/// Emits a single `"   Updated <label> to: <value>"` line via
/// [`writeln!`] against the supplied writer, wrapping the caller's label
/// and value with the pre-lift three-ASCII-space indent + `Updated `
/// verb + ` to: ` separator that six sibling sites spelled inline.
///
/// The [`crate::info_updated_field!`] macro is the [`tracing::info!`]
/// adapter that production code invokes; this direct-writer variant
/// exists so the fail-before-pass tests can pin the exact emitted bytes
/// (the three-space indent, the `Updated` verb literal, the single-space
/// gap, the interpolated label, the ` to:` separator literal, the
/// single-space gap, the interpolated value, the trailing newline)
/// without capturing a tracing subscriber and without racing an ambient
/// logger — the same split
/// [`crate::namespace_field::write_namespace_field`] carries against
/// [`crate::info_namespace_field!`] and
/// [`crate::zone_id_field::write_zone_id_field`] carries against
/// [`crate::info_zone_id_field!`].
///
/// The `label` and `value` parameters each accept any [`fmt::Display`]
/// rather than a concrete `&str` so a bare `&str` (the five inline-label
/// pre-lift call sites' shape today), an owned `String`, `Cow<str>`, a
/// display-implementing enum (the sixth site's
/// [`crate::commands::builder_pool_edit::BuilderPoolField`], which
/// forwards through `as_str` verbatim), and a future
/// splice-target-name newtype (`substrate::YamlKeyPath(String)`) all
/// flow through the same writer without a per-caller `.to_string()`
/// intermediate.
#[allow(dead_code)] // Peer of the tracing-routed `info_updated_field!`
                    // macro, retained for the byte-oracle tests and for
                    // a future summary-report consumer.
pub fn write_updated_field<W: io::Write>(
    w: &mut W,
    label: &dyn fmt::Display,
    value: &dyn fmt::Display,
) -> io::Result<()> {
    writeln!(w, "   Updated {} to: {}", label, value)
}

/// Emit a sub-item post-splice update-acknowledgment field readout via
/// [`tracing::info!`] on the fleet-standard
/// `"   Updated <label> to: <value>"` grammar.
///
/// The macro expands to a direct `::tracing::info!(...)` call at the
/// caller's location so tracing's automatic source-location capture is
/// preserved (a function wrapper would collapse every emission to the
/// wrapper's site — see the module docs for why that breaks per-module
/// filter routing). See the [module docs](self) for the sibling site
/// census (six pre-lift call sites across four command modules), the
/// split against the sibling bare `<Label>: <value>` field primitives
/// (different verb-plus-preposition grammar), and against the sibling
/// glyph-anchored step-outcome primitives (glyphless per-hit
/// acknowledgment under a separately-emitted parent phase-open banner).
///
/// # Examples
///
/// ```ignore
/// // Pre-lift
/// info!("   Updated images[] newTag to: {}", new_tag);
/// info!("   Updated {} to: {}", field, new_image);
///
/// // Post-lift
/// crate::info_updated_field!("images[] newTag", new_tag);
/// crate::info_updated_field!(field, new_image);
/// ```
#[macro_export]
macro_rules! info_updated_field {
    ($label:expr, $value:expr) => {
        ::tracing::info!("   Updated {} to: {}", $label, $value)
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    // Pin the exact prefix bytes: three ASCII spaces (0x20 0x20 0x20),
    // the literal `Updated` (7 bytes), one ASCII space, the interpolated
    // label Display, the literal ` to:` (4 bytes including the leading
    // space), one ASCII space, the interpolated value Display, then
    // `\n`. A future refactor that changes the indent width, drops the
    // verb, changes the separator, or drops the trailing newline
    // regresses this assertion.
    #[test]
    fn write_updated_field_emits_three_space_indent_verb_label_separator_value_and_newline() {
        let mut buf: Vec<u8> = Vec::new();
        write_updated_field(&mut buf, &"newTag", &"v1.2.3").unwrap();
        assert_eq!(buf, b"   Updated newTag to: v1.2.3\n");
    }

    // Human-readable pin of the exact grammar so a future reader can
    // eyeball the render without decoding bytes.
    #[test]
    fn write_updated_field_renders_expected_grammar() {
        let mut buf: Vec<u8> = Vec::new();
        write_updated_field(
            &mut buf,
            &"BUILDER_IMAGE",
            &"ghcr.io/pleme-io/nix-builder:sha-abc",
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "   Updated BUILDER_IMAGE to: ghcr.io/pleme-io/nix-builder:sha-abc\n"
        );
    }

    // The five inline-label pre-lift sites spell labels with punctuation
    // that a bare `<Label>: <value>` primitive would find load-bearing
    // (a `newTag` field name overlaps a colon-terminated label; an
    // `images[]` field name overlaps YAML sequence-index syntax; an
    // `AGENT_IMAGE env` label overlaps whitespace-separated word pairs).
    // Pin that the writer forwards each pre-lift label byte-for-byte —
    // no case-fold, no bracket mangling, no whitespace normalization.
    #[test]
    fn write_updated_field_forwards_all_prelift_labels_verbatim() {
        for label in [
            "images[] newTag",
            "AGENT_IMAGE env",
            "newTag",
            "BUILDER_IMAGE",
            "agentImage",
            "builderImage",
        ] {
            let mut buf: Vec<u8> = Vec::new();
            write_updated_field(&mut buf, &label, &"value").unwrap();
            let expected = format!("   Updated {} to: value\n", label);
            assert_eq!(String::from_utf8(buf).unwrap(), expected);
        }
    }

    // Guard against a two-space-indent drift: the pre-lift sites carry
    // a THREE-space indent (a sub-item under a parent `📝 Updating:
    // <path>` phase-open banner emitted separately by the caller). Pin
    // the three-space width so a future collapse to a two-space (`  `)
    // or four-space (`    `) grammar hits the byte-oracle test rather
    // than shipping a misaligned sub-item under the parent header.
    #[test]
    fn write_updated_field_uses_three_space_indent_not_two_or_four() {
        let mut buf: Vec<u8> = Vec::new();
        write_updated_field(&mut buf, &"newTag", &"v").unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(
            s.starts_with("   Updated"),
            "must start with three spaces + verb; got: {s:?}"
        );
        assert!(
            !s.starts_with("  Updated"),
            "must NOT be two-space indent; got: {s:?}"
        );
        assert!(
            !s.starts_with("    Updated"),
            "must NOT be four-space indent; got: {s:?}"
        );
    }

    // Guard against a bare-field-primitive collapse: the pre-lift shape
    // is `Updated <label> to: <value>`, NOT `<label>: <value>`. Pin the
    // literal ` to: ` separator (space-t-o-colon-space) so a future
    // refactor that reached for `crate::info_namespace_field!` or
    // `crate::info_zone_id_field!` grammar would trip this assertion
    // rather than silently drop the splice-direction cue.
    #[test]
    fn write_updated_field_carries_verb_and_preposition_separator() {
        let mut buf: Vec<u8> = Vec::new();
        write_updated_field(&mut buf, &"newTag", &"v").unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(
            s.contains("Updated "),
            "must carry the `Updated ` verb literal; got: {s:?}"
        );
        assert!(
            s.contains(" to: "),
            "must carry the ` to: ` separator literal; got: {s:?}"
        );
    }

    // Guard against a glyph-anchored step-outcome collapse: the sibling
    // three-space-indented step-outcome primitives
    // (`crate::info_indented_success!`,
    // `crate::ui::print_bright_step_pass`) all emit a leading `✅` (or
    // `⚠️`) glyph anchor. This primitive is deliberately GLYPHLESS —
    // it pairs with a separately-emitted `📝 Updating: <path>`
    // GLYPH-ANCHORED phase-open banner and its own glyphlessness
    // signals its sub-item status under that opener.
    #[test]
    fn write_updated_field_emits_no_glyph_anchor() {
        let mut buf: Vec<u8> = Vec::new();
        write_updated_field(&mut buf, &"newTag", &"v").unwrap();
        let s = String::from_utf8(buf).unwrap();
        // No `✅` CHECK MARK (U+2705) or `⚠️` WARNING SIGN (U+26A0).
        assert!(
            !s.contains('\u{2705}'),
            "must NOT emit a `✅` glyph anchor; got: {s:?}"
        );
        assert!(
            !s.contains('\u{26A0}'),
            "must NOT emit a `⚠️` glyph anchor; got: {s:?}"
        );
    }

    // No-ANSI guard: the crate's `tracing_subscriber` initialization in
    // `main.rs` deliberately sets `with_ansi(false)` so CI log ingestion
    // sees clean records. Pin that this primitive's render carries no
    // ANSI escape byte (0x1B) — a future refactor that reached for
    // `colored` on the label or value side would break the ANSI-free
    // contract the tracing-routed sites depend on.
    #[test]
    fn write_updated_field_emits_no_ansi_escape() {
        let mut buf: Vec<u8> = Vec::new();
        write_updated_field(&mut buf, &"newTag", &"v").unwrap();
        assert!(
            !buf.contains(&0x1b),
            "write_updated_field must emit no ANSI escape (0x1B) — \
             the tracing subscriber is configured `with_ansi(false)`. \
             Bytes: {buf:?}",
        );
    }

    // The macro forwards to `::tracing::info!` at the caller's location.
    // The subscriber cannot be captured in-process without racing whatever
    // subscriber `main` installs. Instead, pin that the macro accepts the
    // supported arg shapes by expanding it at compile time — a compile-fail
    // here would fail the crate's `cargo test` build gate.
    #[test]
    fn info_updated_field_macro_compiles_with_supported_arg_shapes() {
        // Both slots as bare `&str` — the five inline-label pre-lift
        // call sites' shape (label a string literal, value a function
        // local sourced from a `String` parameter).
        let value_str: &str = "v1.2.3";
        crate::info_updated_field!("newTag", value_str);

        // Both slots as owned `String` — the sixth pre-lift site's
        // shape post-`BuilderPoolField::as_str` forward on the label
        // side and post-`.clone()` on the value side.
        let owned_label = String::from("agentImage");
        let owned_value = String::from("ghcr.io/pleme-io/kenshi-agent:sha-abc");
        crate::info_updated_field!(owned_label, owned_value);

        // Label as `&String` reference — the runtime-label
        // `builder_pool_edit::update_builder_pool_field` shape today,
        // where `field` is an lvalue of type `BuilderPoolField` that
        // forwards through `Display` to a `&str`.
        let borrowed_value = &String::from("v");
        crate::info_updated_field!(&"builderImage".to_string(), borrowed_value);

        // A `Display`-wrapping newtype in each slot to prove the slots
        // take any `Display` (a future
        // `substrate::YamlKeyPath(String)` newtype or a
        // `substrate::ContainerImageRef(String)` newtype would forward
        // through their own `Display` impl the same way).
        struct Wrap<'a>(&'a str);
        impl<'a> fmt::Display for Wrap<'a> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }
        crate::info_updated_field!(Wrap("k"), Wrap("v"));
    }

    // Caller shield (negative half): no source line under
    // `cli/src/commands/` may spell the pre-lift raw
    // `info!("   Updated <...> to: {}", <arg...>);` stanza inline any
    // more. The six pre-lift sites migrated; any future consumer that
    // wants the same grammar reaches for `crate::info_updated_field!`
    // on first grep, not by copy-pasting the raw shape from an existing
    // command module.
    #[test]
    fn no_command_module_still_spells_raw_info_updated_field_stanza() {
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
                // the pre-lift shape in prose doesn't self-hit (both
                // `//` line comments and `///` doc comments).
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") {
                    continue;
                }
                // Match the exact pre-lift raw shape: `info!("   Updated `
                // followed by any label bytes, ` to: {}"` and at least
                // one comma-separated arg. Anchors the `"   Updated `
                // literal + ` to: {}"` closer so an unrelated `Updated`
                // string mention does not self-hit.
                if line.contains("info!(\"   Updated ") && line.contains(" to: {}\"") {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `info!(\"   Updated <...> to: {{}}\", <arg...>);` \
             stanza(s) survive under `commands/` — route each through \
             `crate::info_updated_field!(<label>, <value>)` instead:\n{:#?}",
            offenders
        );
    }

    // Caller shield (positive half): the four pre-lift command modules
    // MUST each forward through `crate::info_updated_field!(` at least
    // once, so a migration that dropped a call site outright leaves the
    // negative "no raw inline shape" scan trivially satisfied by absence
    // but the positive count still fails. The minimum-per-module counts
    // reflect the pre-lift census: kenshi.rs (1), kenshi_agent.rs (2),
    // nix_builder.rs (2), builder_pool_edit.rs (1).
    #[test]
    fn every_prelift_module_forwards_through_info_updated_field_macro() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let expectations: &[(&str, usize)] = &[
            ("kenshi.rs", 1),
            ("kenshi_agent.rs", 2),
            ("nix_builder.rs", 2),
            ("builder_pool_edit.rs", 1),
        ];
        for (basename, min_count) in expectations {
            let path = commands_dir.join(basename);
            let source = std::fs::read_to_string(&path).unwrap();
            let forwards = source.matches("crate::info_updated_field!(").count();
            assert!(
                forwards >= *min_count,
                "{basename} must forward at least {min_count} \
                 `Updated <label> to: <value>` acknowledgment site(s) \
                 through `crate::info_updated_field!(`; found {forwards}. \
                 A dropped call would leave the negative raw-shape scan \
                 satisfied by absence.",
            );
        }
    }
}
