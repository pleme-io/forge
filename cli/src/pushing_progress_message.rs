//! Registry `Pushing <registry>:<tag>` progress-bar message-composition
//! primitive — the pre-lift
//! `format!("Pushing {}:{}", registry, tag)` shape three sibling
//! `pb.set_message(…)` per-tag progress-bar bodies each spelled inline
//! ahead of every per-tag `push_with_retry` iteration.
//!
//! # Duplication being lifted
//!
//! Three pre-lift sibling sites each restated the same
//! `Pushing <registry>:<tag>` composition, diverging only on whether
//! the tag slot was a runtime `&str` argument or the literal `"latest"`
//! spelled directly into the format template:
//!
//! 1. `commands/push.rs::push_tags_with_progress` (~L625) — the
//!    per-tag loop message inside the public `push_tags_with_progress`
//!    body every release-line consumer (`{push,pangea,bootstrap}.rs::
//!    execute`) drives.
//!    `pb.set_message(format!("Pushing {}:{}", registry, tag))`.
//! 2. `commands/github_runner_ci.rs::execute` (~L432) — the CI-runner
//!    two-tag progress-bar loop's first (`:latest`) iteration.
//!    `pb.set_message(format!("Pushing {}:latest", registry))` — the
//!    tag slot inlined as a literal `"latest"` in the template.
//! 3. `commands/github_runner_ci.rs::execute` (~L437) — the same
//!    CI-runner two-tag loop's second (`:<git-sha>`) iteration.
//!    `pb.set_message(format!("Pushing {}:{}", registry, git_sha))`.
//!
//! Each of the three spellings renders the same byte shape: the
//! ASCII gerund `Pushing`, a single ASCII space, the registry slot, a
//! single ASCII `:` separator, and the tag slot. A drift in the verb
//! (`"Pushed "` vs `"Pushing "`, `"pushing "` vs `"Pushing "` — the
//! progress-bar surface renders exactly what the caller emits, no
//! title-casing normalization runs downstream), the separator
//! (`:` → `/` or `::`), or the slot order (`format!("Pushing {}:{}",
//! tag, registry)`) at any one site pre-lift diverged silently from
//! the other two — the progress bar kept ticking and only the
//! per-iteration message surface (which registry:tag is being pushed
//! right now) shifted shape. Post-lift the composition lives at ONE
//! typed body and every consumer inherits the same shape from
//! [`pushing_progress_message`].
//!
//! # Distinct from the sibling `<verb> <registry>:<tag>` compositions
//!
//! [`crate::oci_manifest::image_reference`] owns the bare
//! `<registry>:<tag>` composition. This primitive owns the framed
//! `Pushing <ref>` progress-bar message composition and delegates the
//! bare tail through `image_reference`, mirroring the sibling
//! [`crate::push_op_label::push_op_label`] primitive (retry-log op
//! label, `"push "` lowercase framing) so a future refinement to the
//! bare shape (a separator swap, a Unicode-colon guard, an argv-order
//! check) lands at ONE site and reaches every framed peer through
//! that dependency edge rather than through a copy-paste.
//!
//! The framing verb here is title-cased (`"Pushing "`) and the
//! sibling `push_op_label`'s is lowercase (`"push "`) precisely
//! because the two surfaces have different consumer contracts —
//! `pb.set_message` renders to a human-facing spinner line where
//! the leading capital signals "in progress right now", and
//! `retry_command_logged`'s `operation` argument feeds the
//! machine-parseable retry log prefix where the lowercase imperative
//! groups every push attempt under one dashboard filter. Keeping the
//! two verbs distinct at the primitive layer pins each surface's
//! contract at the byte level rather than by convention.
//!
//! # THEORY grounding
//!
//! §V solve-once-at-the-primitive: the `Pushing <ref>` progress-bar
//! message shape lives at ONE construction surface — a future
//! refinement (a `"Pushing "` → `"↑ Pushing "` icon-prefix widening,
//! a distinct progress-bar namespace for pushes vs. pulls, a
//! structured `ProgressMessage` enum replacing the free-string
//! payload) lands in one place rather than in every consumer.
//!
//! §VI.1 three-is-a-law: three sites today (`push.rs` per-tag loop,
//! `github_runner_ci.rs` `:latest` iteration, `github_runner_ci.rs`
//! `:<git-sha>` iteration), clearing the duplication threshold at
//! exactly the point THEORY calls a law.

use std::io;

use crate::oci_manifest::image_reference;

/// Compose the pre-lift `Pushing <registry>:<tag>` progress-bar
/// message the three sibling `pb.set_message(…)` bodies pass to the
/// `indicatif::ProgressBar` ahead of every per-tag
/// `push_with_retry` iteration.
///
/// # Element layout
///
/// - Verb — literal ASCII `Pushing` (capital `P`) followed by a
///   single ASCII space (byte `0x20`). NOT `Pushed`, NOT `pushing`,
///   NOT tab-separated.
/// - Registry slot — the composed registry base
///   (e.g. `"ghcr.io/pleme-io/service"`), passed through
///   [`crate::oci_manifest::image_reference`] as its `repository`
///   argument.
/// - Separator — a single ASCII `:` (byte `0x3A`) between the
///   registry and tag slots, owned by
///   [`crate::oci_manifest::image_reference`].
/// - Tag slot — the site-local tag (`"latest"`, a git SHA, a
///   `v<semver>` release tag).
///
/// # Returned type
///
/// A fresh owned [`String`] every call. The message is consumed by
/// `indicatif::ProgressBar::set_message`'s `impl Into<Cow<'static,
/// str>>` parameter; returning an owned [`String`] avoids a
/// caller-side `.to_string()` and keeps every consumer site
/// symmetric with the pre-lift `format!` idiom.
///
/// # Invariants inherited from [`crate::oci_manifest::image_reference`]
///
/// - `registry` MUST be non-empty (debug-asserted).
/// - `tag` MUST be non-empty (debug-asserted).
/// - `registry` MUST NOT already carry a tag; a pre-tagged registry
///   would compose a double-tagged reference (debug-asserted).
pub fn pushing_progress_message(registry: &str, tag: &str) -> String {
    let mut buf: Vec<u8> = Vec::with_capacity("Pushing ".len() + registry.len() + 1 + tag.len());
    // Cannot fail: `Vec<u8>` never returns an `io::Error` on write.
    write_pushing_progress_message(&mut buf, registry, tag).expect("Vec<u8> write is infallible");
    // Cannot fail: both inputs are `&str` (already UTF-8) and the
    // verb / separator are ASCII.
    String::from_utf8(buf).expect("composition of ASCII verb + `&str` + `&str` is UTF-8")
}

/// Writer-taking sibling of [`pushing_progress_message`]. Emits the
/// same bytes [`pushing_progress_message`] returns, but through a
/// [`io::Write`] sink — the byte-oracle surface for tests that pin
/// the emitted composition against every drift class (a verb swap, a
/// separator swap, an argv-order swap) without allocating an
/// intermediate [`String`].
///
/// # Byte contract
///
/// The written byte sequence is exactly `Pushing` + ` ` + `<registry>`
/// + `:` + `<tag>`, no trailing newline, no framing punctuation.
pub fn write_pushing_progress_message<W: io::Write>(
    w: &mut W,
    registry: &str,
    tag: &str,
) -> io::Result<()> {
    write!(w, "Pushing {}", image_reference(registry, tag))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-oracle: [`pushing_progress_message`] renders the pre-lift
    /// `Pushing <registry>:<tag>` shape byte-for-byte — verb, single
    /// ASCII space, registry slot, single ASCII `:` separator, tag
    /// slot, and nothing else.
    #[test]
    fn pushing_progress_message_emits_pre_lift_literal_byte_for_byte() {
        assert_eq!(
            pushing_progress_message("ghcr.io/pleme-io/service", "abc1234"),
            "Pushing ghcr.io/pleme-io/service:abc1234",
        );
    }

    /// Byte-oracle sibling: [`write_pushing_progress_message`] emits
    /// the same bytes [`pushing_progress_message`] returns, with no
    /// trailing newline and no framing punctuation.
    #[test]
    fn write_pushing_progress_message_emits_pre_lift_literal_byte_for_byte() {
        let mut buf: Vec<u8> = Vec::new();
        write_pushing_progress_message(&mut buf, "ghcr.io/pleme-io/service", "abc1234").unwrap();
        let out = String::from_utf8(buf).expect("writer emits valid UTF-8");
        assert_eq!(out, "Pushing ghcr.io/pleme-io/service:abc1234");
        assert!(
            !out.ends_with('\n'),
            "writer must NOT emit a trailing `\\n` — the composed \
             message is consumed as `pb.set_message`'s payload, not \
             as a stand-alone log line; got {out:?}"
        );
    }

    /// Verb pin: the leading ASCII bytes are exactly `Pushing ` — a
    /// capital `P`, six lowercase letters, one ASCII space. A refactor
    /// that switched to the past tense (`"Pushed "`), to lowercase
    /// (`"pushing "`), or that swapped in a tab (`"Pushing\t"`) would
    /// shift the progress-bar surface every consumer of the bar reads
    /// mid-push, and would silently diverge from every sibling
    /// spinner line the bar template pins.
    #[test]
    fn pushing_progress_message_leads_with_ascii_capitalized_pushing_verb_and_single_space() {
        let msg = pushing_progress_message("registry", "tag");
        assert!(
            msg.starts_with("Pushing "),
            "message must lead with `Pushing ` (verb + single ASCII space); \
             got {msg:?}"
        );
        let bytes = msg.as_bytes();
        assert_eq!(bytes[0], b'P', "byte 0 must be capital ASCII `P`");
        assert_eq!(bytes[1], b'u');
        assert_eq!(bytes[2], b's');
        assert_eq!(bytes[3], b'h');
        assert_eq!(bytes[4], b'i');
        assert_eq!(bytes[5], b'n');
        assert_eq!(bytes[6], b'g');
        assert_eq!(bytes[7], b' ', "byte 7 must be a single ASCII space (0x20)");
    }

    /// Separator pin: the byte between the registry slot and the
    /// tag slot is the ASCII `:` (`0x3A`), NOT `/`, NOT `::`, NOT
    /// the Unicode fullwidth colon `：` (`EF BC 9A`). The composition
    /// delegates to [`crate::oci_manifest::image_reference`] for the
    /// bare tail, so this test pins the delegation edge as much as
    /// the byte.
    #[test]
    fn pushing_progress_message_delegates_separator_to_image_reference() {
        let msg = pushing_progress_message("registry", "tag");
        assert_eq!(msg, "Pushing registry:tag");
        assert!(
            !msg.contains('/'),
            "message must NOT carry `/` in the composed tail (except \
             inside the caller-owned registry slot); got {msg:?}"
        );
        assert!(
            !msg.contains("::"),
            "message must carry ONE colon after the registry slot, not \
             a doubled `::` sigil; got {msg:?}"
        );
        assert!(
            !msg.contains('\u{FF1A}'),
            "message must not carry Unicode fullwidth colon `：` \
             (U+FF1A); got {msg:?}"
        );
    }

    /// Slot-order pin: the registry slot lands BEFORE the `:`
    /// separator; the tag slot lands AFTER it. A refactor that
    /// swapped the argv order — rendering `Pushing <tag>:<registry>`
    /// — would silently retarget every progress-bar frame to the
    /// tag-as-registry shape, a destructive-in-production drift a
    /// mere length check would not catch.
    #[test]
    fn pushing_progress_message_places_registry_before_tag() {
        let msg = pushing_progress_message("registry-alpha", "tag-beta");
        assert_eq!(msg, "Pushing registry-alpha:tag-beta");
        let tail = msg.strip_prefix("Pushing ").expect("verb prefix present");
        let (before, after) = tail.split_once(':').expect("separator present");
        assert_eq!(
            before, "registry-alpha",
            "registry slot must land before the `:` separator"
        );
        assert_eq!(
            after, "tag-beta",
            "tag slot must land after the `:` separator"
        );
    }

    /// Equivalence oracle: [`pushing_progress_message(r, t)`] renders
    /// exactly the bytes the pre-lift
    /// `format!("Pushing {}:{}", r, t)` idiom rendered. Pins the
    /// migration end-to-end: a drift in the primitive body against
    /// the pre-lift idiom fails HERE, not after a consumer has
    /// already been re-wired.
    #[test]
    fn pushing_progress_message_matches_pre_lift_format_idiom() {
        let registry = "ghcr.io/pleme-io/svc";
        let tag = "v1.2.3";
        let via_primitive = pushing_progress_message(registry, tag);
        #[allow(clippy::useless_format)]
        let via_pre_lift = format!("Pushing {}:{}", registry, tag);
        assert_eq!(via_primitive, via_pre_lift);
    }

    /// Equivalence oracle (`:latest` literal-tail form): passing the
    /// literal `"latest"` as the tag slot renders the exact bytes the
    /// pre-lift `format!("Pushing {}:latest", registry)` idiom
    /// rendered. Pins the CI-runner two-tag loop's first iteration
    /// specifically — the one site whose pre-lift format template
    /// inlined the tag as a literal rather than a `{}` slot.
    #[test]
    fn pushing_progress_message_matches_pre_lift_latest_literal_form() {
        let registry = "ghcr.io/pleme-io/svc";
        let via_primitive = pushing_progress_message(registry, "latest");
        #[allow(clippy::useless_format)]
        let via_pre_lift = format!("Pushing {}:latest", registry);
        assert_eq!(via_primitive, via_pre_lift);
    }

    /// Post-lift shield (negative half): no source line under
    /// `cli/src/commands/` may still spell either pre-lift raw
    /// `format!("Pushing {}:{}", <registry>, <tag>)` shape or the
    /// `:latest` literal-tail variant inline. Every consumer reaches
    /// for [`pushing_progress_message`] on first grep, not by
    /// copy-pasting the raw `format!` from an existing sibling.
    #[test]
    fn no_module_still_spells_raw_pushing_progress_format() {
        use std::path::PathBuf;
        let src_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut offenders: Vec<(PathBuf, usize, String)> = Vec::new();
        // The two pre-lift shapes, spelled verbatim.
        let needles: &[&str] = &["format!(\"Pushing {}:{}\"", "format!(\"Pushing {}:latest\""];
        fn walk(dir: &std::path::Path, out: &mut Vec<PathBuf>) {
            for entry in std::fs::read_dir(dir).unwrap().flatten() {
                let p = entry.path();
                if p.is_dir() {
                    walk(&p, out);
                } else if p.extension().and_then(|e| e.to_str()) == Some("rs") {
                    out.push(p);
                }
            }
        }
        let mut files: Vec<PathBuf> = Vec::new();
        walk(&src_dir, &mut files);
        for path in files {
            // Skip this module — the shape strings live in its
            // shield needles and its docstring.
            if path.file_name().and_then(|n| n.to_str()) == Some("pushing_progress_message.rs") {
                continue;
            }
            // Skip `oci_manifest.rs` — its
            // `no_raw_registry_tag_format_survives_in_lifted_sites`
            // shield names the framed `format!("Pushing {}:{}", ...)`
            // shape as a legitimate framed peer example in its
            // docstring, and this shield's negative-half needle
            // would otherwise collide with that documentation.
            if path.file_name().and_then(|n| n.to_str()) == Some("oci_manifest.rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).unwrap();
            let mut in_block_comment = false;
            for (idx, line) in source.lines().enumerate() {
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") {
                    continue;
                }
                if trimmed.starts_with("/*") {
                    in_block_comment = true;
                }
                if in_block_comment {
                    if trimmed.contains("*/") {
                        in_block_comment = false;
                    }
                    continue;
                }
                for needle in needles {
                    if line.contains(needle) {
                        offenders.push((path.clone(), idx + 1, line.to_string()));
                    }
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `format!(\"Pushing {{}}:...\")` literal(s) survive on \
             a pushing-progress-message site — route each through \
             `crate::pushing_progress_message::pushing_progress_message\
             (registry, tag)` instead:\n{offenders:#?}"
        );
    }

    /// Post-lift shield (positive half): each of the two pre-lift
    /// modules that housed the composition MUST forward through
    /// [`pushing_progress_message`] at least once
    /// (`commands/github_runner_ci.rs` twice — the two-tag CI loop's
    /// `:latest` and `:<git-sha>` iterations), so a migration that
    /// dropped a call site outright leaves the negative "no raw
    /// inline shape" scan trivially satisfied by absence but the
    /// positive count still fails.
    #[test]
    fn every_prelift_module_forwards_through_pushing_progress_message() {
        use std::path::PathBuf;
        let src_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let expectations: &[(&[&str], usize)] = &[
            (&["commands", "push.rs"], 1),
            (&["commands", "github_runner_ci.rs"], 2),
        ];
        let needle = "pushing_progress_message(";
        for (segments, min_count) in expectations {
            let mut path = src_dir.clone();
            for s in *segments {
                path.push(s);
            }
            let source = std::fs::read_to_string(&path)
                .unwrap_or_else(|_| panic!("expected {} to exist", path.display()));
            let forwards = source.matches(needle).count();
            assert!(
                forwards >= *min_count,
                "{} must forward at least {min_count} pushing-progress \
                 -message composition(s) through `{needle}`; found \
                 {forwards}. A dropped call would leave the negative \
                 raw-shape scan satisfied by absence.",
                path.display(),
            );
        }
    }
}
