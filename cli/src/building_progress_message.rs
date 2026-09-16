//! Sequential-per-item `Building <name>` progress-bar message-
//! composition primitive — the pre-lift
//! `format!("Building {}", <name>)` shape two sibling
//! `pb.set_message(…)` per-iteration bodies each spelled inline ahead
//! of every per-component / per-binary build+push step.
//!
//! # Duplication being lifted
//!
//! Two pre-lift sibling sites each restated the same
//! `Building <name>` composition, diverging only on the label the
//! `name` slot bound (a Pangea component name vs. a bootstrap binary
//! name):
//!
//! 1. `commands/pangea.rs::push_all_sequential` (~L393) — the
//!    per-component `for component in PANGEA_COMPONENTS` progress-bar
//!    loop's per-iteration message inside the `push all` release
//!    driver.
//!    `pb.set_message(format!("Building {}", component.name))`.
//! 2. `commands/bootstrap.rs::push_all_sequential` (~L385) — the
//!    per-binary `for binary in BOOTSTRAP_BINARIES` progress-bar loop's
//!    per-iteration message inside the `bootstrap push all` release
//!    driver.
//!    `pb.set_message(format!("Building {}", binary.name))`.
//!
//! Each of the two spellings renders the same byte shape: the ASCII
//! gerund `Building`, a single ASCII space, and the item-name slot. A
//! drift in the verb (`"Built "` vs `"Building "`, `"building "` vs
//! `"Building "` — `indicatif` renders exactly what the caller emits,
//! no title-casing normalization runs downstream), the separator
//! (a tab, a two-space indent, an em-dash), or a stray trailing colon
//! at any one site pre-lift diverged silently from the other — the
//! progress bar kept ticking and only the per-iteration message
//! surface shifted shape. Post-lift the composition lives at ONE
//! typed body and every consumer inherits the same shape from
//! [`building_progress_message`].
//!
//! # Distinct from the sibling `Pushing <ref>` composition
//!
//! [`crate::pushing_progress_message::pushing_progress_message`] owns
//! the framed `Pushing <registry>:<tag>` progress-bar message
//! (per-tag `push_with_retry` iteration surface). This primitive owns
//! the earlier `Building <name>` per-item message the same sequential
//! driver renders one build step before the push step. Keeping the
//! two verbs at distinct primitives pins the surface each iteration
//! is in — `Building` for the compile / Nix-derivation phase,
//! `Pushing` for the registry-upload phase — at the byte level rather
//! than by convention.
//!
//! # THEORY grounding
//!
//! §V solve-once-at-the-primitive: the `Building <name>`
//! progress-bar message shape lives at ONE construction surface — a
//! future refinement (a `"Building "` → `"🔨 Building "` icon-prefix
//! widening, a distinct progress-bar namespace for builds vs. tests,
//! a structured `ProgressMessage` enum replacing the free-string
//! payload) lands in one place rather than in every consumer.

use std::io;

/// Compose the pre-lift `Building <name>` progress-bar message the
/// two sibling `pb.set_message(…)` bodies pass to the
/// `indicatif::ProgressBar` ahead of every per-item build step.
///
/// # Element layout
///
/// - Verb — literal ASCII `Building` (capital `B`) followed by a
///   single ASCII space (byte `0x20`). NOT `Built`, NOT `building`,
///   NOT tab-separated.
/// - Name slot — the site-local item name (a Pangea component name,
///   a bootstrap binary name), rendered verbatim.
///
/// # Returned type
///
/// A fresh owned [`String`] every call. The message is consumed by
/// `indicatif::ProgressBar::set_message`'s `impl Into<Cow<'static,
/// str>>` parameter; returning an owned [`String`] avoids a
/// caller-side `.to_string()` and keeps every consumer site
/// symmetric with the pre-lift `format!` idiom.
///
/// # Invariants
///
/// - `name` MUST be non-empty (debug-asserted). An empty name would
///   render as the bare verb + space, silently masking a caller-side
///   miswiring of the item label.
pub fn building_progress_message(name: &str) -> String {
    debug_assert!(
        !name.is_empty(),
        "building_progress_message: `name` must be non-empty"
    );
    let mut buf: Vec<u8> = Vec::with_capacity("Building ".len() + name.len());
    write_building_progress_message(&mut buf, name).expect("Vec<u8> write is infallible");
    String::from_utf8(buf).expect("composition of ASCII verb + `&str` is UTF-8")
}

/// Writer-taking sibling of [`building_progress_message`]. Emits the
/// same bytes [`building_progress_message`] returns, but through a
/// [`io::Write`] sink — the byte-oracle surface for tests that pin
/// the emitted composition against every drift class (a verb swap, a
/// separator swap, a trailing punctuation) without allocating an
/// intermediate [`String`].
///
/// # Byte contract
///
/// The written byte sequence is exactly `Building` + ` ` + `<name>`,
/// no trailing newline, no framing punctuation, no leading indent.
pub fn write_building_progress_message<W: io::Write>(w: &mut W, name: &str) -> io::Result<()> {
    write!(w, "Building {name}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-oracle: [`building_progress_message`] renders the
    /// pre-lift `Building <name>` shape byte-for-byte — verb, single
    /// ASCII space, name slot, and nothing else.
    #[test]
    fn building_progress_message_emits_pre_lift_literal_byte_for_byte() {
        assert_eq!(building_progress_message("operator"), "Building operator");
    }

    /// Byte-oracle sibling: [`write_building_progress_message`]
    /// emits the same bytes [`building_progress_message`] returns,
    /// with no trailing newline and no framing punctuation.
    #[test]
    fn write_building_progress_message_emits_pre_lift_literal_byte_for_byte() {
        let mut buf: Vec<u8> = Vec::new();
        write_building_progress_message(&mut buf, "postgres-bootstrap").unwrap();
        let out = String::from_utf8(buf).expect("writer emits valid UTF-8");
        assert_eq!(out, "Building postgres-bootstrap");
        assert!(
            !out.ends_with('\n'),
            "writer must NOT emit a trailing `\\n` — the composed \
             message is consumed as `pb.set_message`'s payload, not \
             as a stand-alone log line; got {out:?}"
        );
    }

    /// Verb pin: the leading ASCII bytes are exactly `Building ` —
    /// a capital `B`, seven lowercase letters, one ASCII space. A
    /// refactor that switched to the past tense (`"Built "`), to
    /// lowercase (`"building "`), or that swapped in a tab
    /// (`"Building\t"`) would shift the progress-bar surface every
    /// consumer of the bar reads mid-build, and would silently
    /// diverge from every sibling spinner line the bar template
    /// pins.
    #[test]
    fn building_progress_message_leads_with_ascii_capitalized_building_verb_and_single_space() {
        let msg = building_progress_message("x");
        assert!(
            msg.starts_with("Building "),
            "message must lead with `Building ` (verb + single ASCII \
             space); got {msg:?}"
        );
        let bytes = msg.as_bytes();
        assert_eq!(bytes[0], b'B', "byte 0 must be capital ASCII `B`");
        assert_eq!(bytes[1], b'u');
        assert_eq!(bytes[2], b'i');
        assert_eq!(bytes[3], b'l');
        assert_eq!(bytes[4], b'd');
        assert_eq!(bytes[5], b'i');
        assert_eq!(bytes[6], b'n');
        assert_eq!(bytes[7], b'g');
        assert_eq!(bytes[8], b' ', "byte 8 must be a single ASCII space (0x20)");
    }

    /// Separator pin: the byte between the verb and the name slot
    /// is ONE ASCII space (`0x20`), NOT a tab (`\t`), NOT two spaces,
    /// NOT an em-dash. A pre-lift drift here would ripple across
    /// every progress-bar frame and (on a narrow terminal) push the
    /// name slot off-screen.
    #[test]
    fn building_progress_message_separates_verb_from_name_with_single_ascii_space() {
        let msg = building_progress_message("compiler");
        assert_eq!(msg, "Building compiler");
        assert!(
            !msg.contains('\t'),
            "message must not carry a tab byte between verb and \
             name slot; got {msg:?}"
        );
        assert!(
            !msg.contains("  "),
            "message must not carry a double-space between verb and \
             name slot; got {msg:?}"
        );
    }

    /// Trailing-punctuation pin: the composed byte sequence ends at
    /// the last byte of the name slot — no trailing `:`, no
    /// trailing `…`, no trailing space. A future refactor that
    /// appended a suffix here would shift the progress-bar surface
    /// on every iteration.
    #[test]
    fn building_progress_message_ends_at_name_slot_with_no_trailing_punctuation() {
        let msg = building_progress_message("web");
        assert!(
            msg.ends_with('b'),
            "message must end with the name's last byte; got {msg:?}"
        );
        assert!(!msg.ends_with(':'), "no trailing `:`; got {msg:?}");
        assert!(!msg.ends_with(' '), "no trailing ASCII space; got {msg:?}");
        assert!(!msg.ends_with('\n'), "no trailing newline; got {msg:?}");
    }

    /// Equivalence oracle: [`building_progress_message(n)`] renders
    /// exactly the bytes the pre-lift `format!("Building {}", n)`
    /// idiom rendered. Pins the migration end-to-end: a drift in
    /// the primitive body against the pre-lift idiom fails HERE,
    /// not after a consumer has already been re-wired.
    #[test]
    fn building_progress_message_matches_pre_lift_format_idiom() {
        for name in ["operator", "cli", "web", "compiler", "postgres-bootstrap"] {
            let via_primitive = building_progress_message(name);
            #[allow(clippy::useless_format)]
            let via_pre_lift = format!("Building {}", name);
            assert_eq!(via_primitive, via_pre_lift);
        }
    }

    /// Debug-assert half of the non-empty-name invariant.
    #[test]
    #[should_panic(expected = "`name` must be non-empty")]
    #[cfg(debug_assertions)]
    fn building_progress_message_debug_asserts_non_empty_name() {
        let _ = building_progress_message("");
    }

    /// Post-lift shield (negative half): no source line under
    /// `cli/src/commands/` may still spell the pre-lift raw
    /// `format!("Building {}", …)` shape inline. Every consumer
    /// reaches for [`building_progress_message`] on first grep, not
    /// by copy-pasting the raw `format!` from an existing sibling.
    #[test]
    fn no_module_still_spells_raw_building_progress_format() {
        use std::path::PathBuf;
        let src_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut offenders: Vec<(PathBuf, usize, String)> = Vec::new();
        let needle = "format!(\"Building {}\"";
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
            // shield needle and its docstring.
            if path.file_name().and_then(|n| n.to_str()) == Some("building_progress_message.rs") {
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
            "raw `format!(\"Building {{}}\", …)` literal(s) survive on \
             a building-progress-message site — route each through \
             `crate::building_progress_message::building_progress_message\
             (name)` instead:\n{offenders:#?}"
        );
    }

    /// Post-lift shield (positive half): each of the two pre-lift
    /// modules that housed the composition MUST forward through
    /// [`building_progress_message`] at least once, so a migration
    /// that dropped a call site outright leaves the negative "no raw
    /// inline shape" scan trivially satisfied by absence but the
    /// positive count still fails.
    #[test]
    fn every_prelift_module_forwards_through_building_progress_message() {
        use std::path::PathBuf;
        let src_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let expectations: &[(&[&str], usize)] = &[
            (&["commands", "pangea.rs"], 1),
            (&["commands", "bootstrap.rs"], 1),
        ];
        let needle = "building_progress_message(";
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
                "{} must forward at least {min_count} building-progress \
                 -message composition(s) through `{needle}`; found \
                 {forwards}. A dropped call would leave the negative \
                 raw-shape scan satisfied by absence.",
                path.display(),
            );
        }
    }
}
