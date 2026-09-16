//! Registry `push <registry>:<tag>` operation-label composition
//! primitive — the pre-lift
//! `format!("push {}:{}", registry, tag)` shape three sibling
//! `push_with_retry` bodies each spelled inline as the
//! [`crate::retry::RetryPolicy`] operation label pushed at
//! [`crate::retry::retry_command_logged`].
//!
//! # Duplication being lifted
//!
//! Three pre-lift sibling sites each restated the same 2-slot
//! `format!("push {}:{}", …, …)` composition, diverging only on the
//! surrounding [`crate::retry::RetryPolicy`] variant and the caller's
//! image-file / doca-preflight discipline:
//!
//! 1. `infrastructure/registry.rs::RegistryError::push_with_retries`
//!    (~L259) — the substrate-side push implementation on the
//!    domain-typed [`crate::infrastructure::registry::RegistryError`]
//!    surface. `RetryPolicy::network_with_max_attempts(retries)`.
//! 2. `commands/github_runner_ci.rs::push_with_retry` (~L848) — the
//!    CI-runner push body wired ahead of a two-tag
//!    (`latest` + `<git-sha>`) progress-bar loop.
//!    `RetryPolicy::network_or_immediate(safe_mode)`.
//! 3. `commands/push.rs::push_with_retry` (~L552) — the public
//!    per-tag push body every `push_tags_with_progress` iteration
//!    reaches for, and the primitive the three
//!    `commands/{push,pangea,bootstrap}.rs::execute` release-line
//!    sites converged on. `RetryPolicy::network()`.
//!
//! Each of the three spellings renders the same byte shape: the
//! ASCII verb `push`, a single ASCII space, the registry slot, a
//! single ASCII `:` separator, and the tag slot. A drift in the verb
//! (`"pushed "` vs `"push "`), the separator (`:` → `/` or `::`), or
//! the slot order (`format!("push {}:{}", tag, registry)`) at any one
//! site pre-lift diverges silently from the other two — the log
//! prefix `retry_command_logged` emits keeps working, and only the
//! failure-diagnostic surface (which registry:tag failed) shifts
//! shape. Post-lift the composition lives at ONE typed body and
//! every consumer inherits the same shape from
//! [`push_op_label`].
//!
//! # Distinct from the sibling `<verb> <registry>:<tag>` compositions
//!
//! [`crate::oci_manifest::image_reference`] owns the bare
//! `<registry>:<tag>` composition. This primitive owns the framed
//! `push <ref>` op-label composition and delegates the bare tail
//! through `image_reference`, so a future refinement to the bare
//! shape (a separator swap, a Unicode-colon guard, an argv-order
//! check) lands at ONE site and reaches every framed peer through
//! that dependency edge rather than through a copy-paste. A future
//! sibling `inspect_op_label`, `pull_op_label`, or
//! `set_message_pushing_message` primitive walks through the same
//! `image_reference` tail identically.
//!
//! # THEORY grounding
//!
//! §V solve-once-at-the-primitive: the `push <ref>` op-label shape
//! lives at ONE construction surface — a future refinement (a
//! `"push "` → `"push image "` verb widening, a distinct retry-log
//! namespace for pushes vs. inspects, a structured
//! `RetryOperation` enum replacing the free-string label) lands in
//! one place rather than in every consumer.
//!
//! §VI.1 three-is-a-law: three sites today (`registry.rs`,
//! `github_runner_ci.rs`, `push.rs`), clearing the duplication
//! threshold at exactly the point THEORY calls a law.

use std::io;

use crate::oci_manifest::image_reference;

/// Compose the pre-lift `push <registry>:<tag>` operation label the
/// three sibling `push_with_retry` bodies pass to
/// [`crate::retry::retry_command_logged`] as its `operation`
/// argument.
///
/// # Element layout
///
/// - Verb — literal ASCII `push` followed by a single ASCII space
///   (byte `0x20`). NOT `pushed`, NOT `pushing`, NOT tab-separated.
/// - Registry slot — the composed registry base
///   (e.g. `"ghcr.io/pleme-io/service"`), passed through
///   [`crate::oci_manifest::image_reference`] as its
///   `repository` argument.
/// - Separator — a single ASCII `:` (byte `0x3A`) between the
///   registry and tag slots, owned by
///   [`crate::oci_manifest::image_reference`].
/// - Tag slot — the site-local tag (e.g. a git SHA, `"latest"`,
///   a `v<semver>` release tag).
///
/// # Returned type
///
/// A fresh owned [`String`] every call. The label is consumed by
/// [`crate::retry::retry_command_logged`]'s `operation:
/// impl Into<String>` parameter; returning an owned [`String`]
/// avoids a caller-side `.to_string()` and keeps every consumer
/// site symmetric with the pre-lift `format!` idiom.
///
/// # Invariants inherited from [`crate::oci_manifest::image_reference`]
///
/// - `registry` MUST be non-empty (debug-asserted).
/// - `tag` MUST be non-empty (debug-asserted).
/// - `registry` MUST NOT already carry a tag; a pre-tagged
///   registry would compose a double-tagged reference
///   (debug-asserted).
pub fn push_op_label(registry: &str, tag: &str) -> String {
    let mut buf: Vec<u8> = Vec::with_capacity("push ".len() + registry.len() + 1 + tag.len());
    // Cannot fail: `Vec<u8>` never returns an `io::Error` on write.
    write_push_op_label(&mut buf, registry, tag).expect("Vec<u8> write is infallible");
    // Cannot fail: both inputs are `&str` (already UTF-8) and the
    // verb / separator are ASCII.
    String::from_utf8(buf).expect("composition of ASCII verb + `&str` + `&str` is UTF-8")
}

/// Writer-taking sibling of [`push_op_label`]. Emits the same bytes
/// [`push_op_label`] returns, but through a [`io::Write`] sink — the
/// byte-oracle surface for tests that pin the emitted composition
/// against every drift class (a verb swap, a separator swap, an
/// argv-order swap) without allocating an intermediate [`String`].
///
/// # Byte contract
///
/// The written byte sequence is exactly `push` + ` ` + `<registry>`
/// + `:` + `<tag>`, no trailing newline, no framing punctuation.
pub fn write_push_op_label<W: io::Write>(w: &mut W, registry: &str, tag: &str) -> io::Result<()> {
    write!(w, "push {}", image_reference(registry, tag))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-oracle: [`push_op_label`] renders the pre-lift
    /// `push <registry>:<tag>` shape byte-for-byte — verb, single
    /// ASCII space, registry slot, single ASCII `:` separator, tag
    /// slot, and nothing else.
    #[test]
    fn push_op_label_emits_pre_lift_literal_byte_for_byte() {
        assert_eq!(
            push_op_label("ghcr.io/pleme-io/service", "abc1234"),
            "push ghcr.io/pleme-io/service:abc1234",
        );
    }

    /// Byte-oracle sibling: [`write_push_op_label`] emits the same
    /// bytes [`push_op_label`] returns, with no trailing newline and
    /// no framing punctuation.
    #[test]
    fn write_push_op_label_emits_pre_lift_literal_byte_for_byte() {
        let mut buf: Vec<u8> = Vec::new();
        write_push_op_label(&mut buf, "ghcr.io/pleme-io/service", "abc1234").unwrap();
        let out = String::from_utf8(buf).expect("writer emits valid UTF-8");
        assert_eq!(out, "push ghcr.io/pleme-io/service:abc1234");
        assert!(
            !out.ends_with('\n'),
            "writer must NOT emit a trailing `\\n` — the composed \
             label is consumed as `retry_command_logged`'s `operation` \
             argument, not as a stand-alone log line; got {out:?}"
        );
    }

    /// Verb pin: the leading ASCII bytes are exactly `push ` (four
    /// letters + one space). A refactor that pluralized the verb
    /// (`"pushes "`), progressive-formed it (`"pushing "`), or
    /// swapped in a tab (`"push\t"`) would shift the retry-log
    /// prefix `retry_command_logged` emits and break every dashboard
    /// or alert filter that groups on `push `.
    #[test]
    fn push_op_label_leads_with_ascii_push_verb_and_single_space() {
        let label = push_op_label("registry", "tag");
        assert!(
            label.starts_with("push "),
            "label must lead with `push ` (verb + single ASCII space); \
             got {label:?}"
        );
        let bytes = label.as_bytes();
        assert_eq!(bytes[0], b'p');
        assert_eq!(bytes[1], b'u');
        assert_eq!(bytes[2], b's');
        assert_eq!(bytes[3], b'h');
        assert_eq!(bytes[4], b' ', "byte 4 must be a single ASCII space (0x20)");
    }

    /// Separator pin: the byte between the registry slot and the
    /// tag slot is the ASCII `:` (`0x3A`), NOT `/`, NOT `::`, NOT
    /// the Unicode fullwidth colon `：` (`EF BC 9A`). The composition
    /// delegates to [`crate::oci_manifest::image_reference`] for the
    /// bare tail, so this test pins the delegation edge as much as
    /// the byte.
    #[test]
    fn push_op_label_delegates_separator_to_image_reference() {
        let label = push_op_label("registry", "tag");
        assert_eq!(label, "push registry:tag");
        assert!(
            !label.contains('/'),
            "label must NOT carry `/` in the composed tail (except \
             inside the caller-owned registry slot); got {label:?}"
        );
        assert!(
            !label.contains("::"),
            "label must carry ONE colon after the registry slot, not \
             a doubled `::` sigil; got {label:?}"
        );
        assert!(
            !label.contains('\u{FF1A}'),
            "label must not carry Unicode fullwidth colon `：` \
             (U+FF1A); got {label:?}"
        );
    }

    /// Slot-order pin: the registry slot lands BEFORE the `:`
    /// separator; the tag slot lands AFTER it. A refactor that
    /// swapped the argv order — rendering `push <tag>:<registry>` —
    /// would silently retarget every failure diagnostic to the
    /// tag-as-registry shape, a destructive-in-production drift a
    /// mere length check would not catch.
    #[test]
    fn push_op_label_places_registry_before_tag() {
        let label = push_op_label("registry-alpha", "tag-beta");
        assert_eq!(label, "push registry-alpha:tag-beta");
        let tail = label.strip_prefix("push ").expect("verb prefix present");
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

    /// Equivalence oracle: [`push_op_label(r, t)`] renders exactly
    /// the bytes the pre-lift `format!("push {}:{}", r, t)` idiom
    /// rendered. Pins the migration end-to-end: a drift in the
    /// primitive body against the pre-lift idiom fails HERE, not
    /// after a consumer has already been re-wired.
    #[test]
    fn push_op_label_matches_pre_lift_format_idiom() {
        let registry = "ghcr.io/pleme-io/svc";
        let tag = "v1.2.3";
        let via_primitive = push_op_label(registry, tag);
        #[allow(clippy::useless_format)]
        let via_pre_lift = format!("push {}:{}", registry, tag);
        assert_eq!(via_primitive, via_pre_lift);
    }

    /// Post-lift shield (negative half): no source line under
    /// `cli/src/commands/` or `cli/src/infrastructure/` may still
    /// spell the pre-lift raw `format!("push {}:{}", <registry>,
    /// <tag>)` shape inline. Every consumer reaches for
    /// [`push_op_label`] on first grep, not by copy-pasting the raw
    /// `format!` from an existing sibling.
    #[test]
    fn no_module_still_spells_raw_push_op_label_format() {
        use std::path::PathBuf;
        let src_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut offenders: Vec<(PathBuf, usize, String)> = Vec::new();
        // The one pre-lift shape, spelled verbatim.
        let needle = "format!(\"push {}:{}\", registry, tag)";
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
            // Skip this module — the shape string lives in its
            // shield needle and its docstring.
            if path.file_name().and_then(|n| n.to_str()) == Some("push_op_label.rs") {
                continue;
            }
            // Skip `oci_manifest.rs` — its `no_raw_registry_tag_format_survives_in_lifted_sites`
            // shield names the framed `format!("push {}:{}", ...)` shape as a
            // legitimate framed peer example in its docstring, and this
            // shield's negative-half needle would otherwise collide with that
            // documentation.
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
                if line.contains(needle) {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `{}` literal(s) survive on a push-op-label site — \
             route each through `crate::push_op_label::push_op_label\
             (registry, tag)` instead:\n{:#?}",
            needle,
            offenders
        );
    }

    /// Post-lift shield (positive half): the three pre-lift modules
    /// that housed the composition MUST each forward through
    /// [`push_op_label`] at least once, so a migration that dropped a
    /// call site outright leaves the negative "no raw inline shape"
    /// scan trivially satisfied by absence but the positive count
    /// still fails.
    #[test]
    fn every_prelift_module_forwards_through_push_op_label() {
        use std::path::PathBuf;
        let src_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let expectations: &[(&[&str], usize)] = &[
            (&["infrastructure", "registry.rs"], 1),
            (&["commands", "github_runner_ci.rs"], 1),
            (&["commands", "push.rs"], 1),
        ];
        let needle = "push_op_label(";
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
                "{} must forward at least {min_count} push-op-label \
                 composition(s) through `{needle}`; found {forwards}. \
                 A dropped call would leave the negative raw-shape \
                 scan satisfied by absence.",
                path.display(),
            );
        }
    }
}
