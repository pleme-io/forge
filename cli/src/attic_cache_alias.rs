//! Attic cache-alias composition primitive — the pre-lift
//! `format!("{}:{}", <server>, <cache_name>)` shape that composes the
//! `<server>:<cache_name>` alias every Attic client / CLI subcommand
//! consumes as a single positional argument.
//!
//! # Duplication being lifted
//!
//! Three pre-lift sibling sites each spelled the same 2-slot
//! `format!("{}:{}", …, …)` composition, diverging only on the
//! server-slot expression (a local `attic_server` binding, a
//! `deploy_config.cache_server()` accessor, a `&str` parameter) and on
//! the cache-slot expression (a local `cache_name` binding vs
//! `self.cache_name` on the [`crate::infrastructure::attic::AtticClient`]
//! receiver):
//!
//! 1. `commands/build.rs::execute` (~L230) — `let cache_ref =
//!    format!("{}:{}", attic_server, cache_name);` composed ahead of a
//!    `crate::infrastructure::attic::AtticClient::new(cache_ref.clone())
//!    .push_closure_via_stdin(...)` closure-push spawn.
//! 2. `commands/rust_service.rs::build_rust_service` (~L634) — `let
//!    cache_target = format!("{}:{}", deploy_config.cache_server(),
//!    cache_name);` composed ahead of the per-arch
//!    `push_arch_closure_to_attic` helper (AMD64 + optional ARM64).
//! 3. `infrastructure/attic.rs::AtticClient::use_cache` (~L763) — `let
//!    cache_ref = format!("{}:{}", server, self.cache_name);` composed
//!    ahead of an `attic use <cache_ref>` argv slice; and the sibling
//!    `info!("Selected active Attic cache: {}:{}", server,
//!    self.cache_name)` narration at L781 restates the same
//!    `<server>:<cache_name>` composition inline in the log line.
//!
//! All four spellings render the same byte shape: the server slot, a
//! single ASCII `:` separator, and the cache-name slot. A drift in
//! the separator — an accidental `"/"` or `"::"` from a copy-paste
//! typo, an argv-order swap that put the cache-name first, or a
//! silent Unicode-colon slip — pre-lift had to hit N sites in
//! lockstep or diverge; post-lift it hits ONE typed body and every
//! consumer inherits the shape from
//! `crate::attic_cache_alias::attic_cache_alias(server, cache_name)`.
//!
//! # Distinct from the sibling `<registry>:<tag>` image-reference shape
//!
//! [`crate::oci_manifest::image_reference`] owns the `<registry>:<tag>`
//! composition every OCI image-reference site reaches for — same
//! 2-slot `format!("{}:{}", …, …)` shape, distinct semantics: the
//! image-reference primitive composes a docker/OCI image reference
//! (server-scoped path + tag), whereas this primitive composes an
//! Attic cache alias (server + cache name). The two shapes cannot
//! collapse: `attic push <cache-alias>` and `docker push <image-ref>`
//! consume distinct argv shapes even though both share the leading
//! `<host-scoped-name>:<tail>` byte grammar, and a drift that fused
//! the two would silently retarget an Attic push to a docker registry
//! or vice versa. This primitive owns ONLY the Attic-cache shape;
//! image references keep their own home.
//!
//! # THEORY grounding
//!
//! §V solve-once-at-the-primitive: the `<server>:<cache_name>` shape
//! lives at ONE construction surface so a future refinement — the
//! separator swap (`:` → `/`), a v2 attic client accepting the two
//! slots as separate positionals, or a hyphen-normalization pass on
//! the cache name — lands in one place rather than in every
//! consumer.
//!
//! §VI.1 three-is-a-law: three sites today (build.rs, rust_service.rs,
//! attic.rs::use_cache — plus the sibling `info!` narration at
//! attic.rs::L781 that restates the composition inline), so the lift
//! clears the duplication threshold four times over.

use std::io;

/// Compose the pre-lift `<server>:<cache_name>` Attic cache alias
/// every Attic client / CLI subcommand consumes as a single positional
/// argument.
///
/// # Element layout
///
/// - Server slot (`<server>`) — the Attic server alias (e.g.
///   `"pleme-cache"`), typically resolved through
///   [`crate::infrastructure::attic::attic_server_alias`] or an
///   equivalent site-local accessor.
/// - Separator — a single ASCII `:` (byte `0x3A`). NOT `/`, NOT `::`,
///   NOT the Unicode fullwidth colon `：` (`EF BC 9A`).
/// - Cache-name slot (`<cache_name>`) — the site-local cache name
///   (e.g. `"pleme"`).
///
/// # Returned type
///
/// A fresh owned [`String`] every call. The alias is consumed by
/// argv-slice builders that require a `&str` slot bound to a
/// caller-owned buffer; returning an owned [`String`] lets the caller
/// choose its lifetime rather than borrowing from a temporary the
/// primitive would drop at the return point.
pub fn attic_cache_alias(server: &str, cache_name: &str) -> String {
    let mut buf: Vec<u8> = Vec::with_capacity(server.len() + 1 + cache_name.len());
    // Cannot fail: `Vec<u8>` never returns an `io::Error` on write.
    write_attic_cache_alias(&mut buf, server, cache_name).expect("Vec<u8> write is infallible");
    // Cannot fail: both inputs are `&str` (already UTF-8) and the
    // separator is ASCII `:`.
    String::from_utf8(buf).expect("composition of two &str + ASCII `:` is UTF-8")
}

/// Writer-taking sibling of [`attic_cache_alias`]. Emits the same
/// bytes [`attic_cache_alias`] returns, but through a [`io::Write`]
/// sink — the byte-oracle surface for tests that pin the emitted
/// composition against every drift class (a separator swap, an
/// argv-order swap, a Unicode-colon slip) without allocating an
/// intermediate [`String`].
///
/// # Byte contract
///
/// The written byte sequence is exactly `<server>` + `:` + `<cache_name>`,
/// no trailing newline, no framing punctuation. A drift that added a
/// framing prefix / suffix would fail the
/// `write_attic_cache_alias_emits_pre_lift_literal_byte_for_byte`
/// oracle below.
pub fn write_attic_cache_alias<W: io::Write>(
    w: &mut W,
    server: &str,
    cache_name: &str,
) -> io::Result<()> {
    write!(w, "{}:{}", server, cache_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-oracle: [`attic_cache_alias`] renders the pre-lift
    /// `<server>:<cache_name>` shape byte-for-byte — server slot,
    /// single ASCII `:` separator, cache-name slot, and nothing else.
    /// A drift that (a) swapped the separator to `/` or `::`,
    /// (b) added framing (e.g., `attic://<server>/<cache>`),
    /// (c) reordered the slots, or (d) upcased either half would fail
    /// this assertion.
    #[test]
    fn attic_cache_alias_emits_pre_lift_literal_byte_for_byte() {
        assert_eq!(
            attic_cache_alias("pleme-cache", "pleme"),
            "pleme-cache:pleme",
        );
    }

    /// Byte-oracle sibling: [`write_attic_cache_alias`] emits the same
    /// bytes [`attic_cache_alias`] returns, with no trailing newline
    /// and no framing punctuation. A refactor that promoted the
    /// writer to a `writeln!` (adding a `\n`) or that wrapped the
    /// alias in quotes / brackets would flip this assertion.
    #[test]
    fn write_attic_cache_alias_emits_pre_lift_literal_byte_for_byte() {
        let mut buf: Vec<u8> = Vec::new();
        write_attic_cache_alias(&mut buf, "pleme-cache", "pleme").unwrap();
        let out = String::from_utf8(buf).expect("writer emits valid UTF-8");
        assert_eq!(out, "pleme-cache:pleme");
        assert!(
            !out.ends_with('\n'),
            "writer must NOT emit a trailing `\\n` — the composed \
             alias is consumed as a single positional arg, not as a \
             stand-alone log line; got {out:?}"
        );
    }

    /// Separator pin: the single byte between the server slot and the
    /// cache-name slot is the ASCII `:` (`0x3A`), NOT `/`, NOT `::`,
    /// NOT the Unicode fullwidth colon `：` (`EF BC 9A`). Attic's CLI
    /// parses `<server>:<cache>` on the literal ASCII colon; a drift
    /// that silently swapped the separator would render every
    /// downstream `attic <sub> <alias>` invocation a mysterious
    /// unknown-cache failure with no structural link back to the
    /// composition.
    #[test]
    fn attic_cache_alias_uses_single_ascii_colon_separator() {
        let alias = attic_cache_alias("srv", "cache");
        let bytes = alias.as_bytes();
        assert_eq!(bytes.len(), 3 + 1 + 5, "shape must be `srv:cache`");
        assert_eq!(bytes[3], b':', "byte at index 3 must be ASCII `:` (0x3A)");
        assert!(
            !alias.contains('/'),
            "alias must not carry `/` — attic parses on `:`; got {alias:?}"
        );
        assert!(
            !alias.contains("::"),
            "alias must carry ONE colon, not a doubled `::` sigil; got {alias:?}"
        );
        assert!(
            !alias.contains('\u{FF1A}'),
            "alias must not carry Unicode fullwidth colon `：` (U+FF1A); \
             got {alias:?}"
        );
    }

    /// Slot-order pin: the server slot lands FIRST, before the
    /// separator; the cache-name slot lands SECOND, after it. A
    /// refactor that swapped the argv order — rendering
    /// `<cache_name>:<server>` — would silently retarget every Attic
    /// invocation to the cache-name-as-server alias, a
    /// destructive-in-production drift that a mere length check would
    /// not catch. Two distinct string arguments make the swap
    /// observable at the assertion level.
    #[test]
    fn attic_cache_alias_places_server_before_cache_name() {
        let alias = attic_cache_alias("server-alpha", "cache-beta");
        let (before, after) = alias.split_once(':').unwrap();
        assert_eq!(
            before, "server-alpha",
            "server slot must land before the `:` separator"
        );
        assert_eq!(
            after, "cache-beta",
            "cache-name slot must land after the `:` separator"
        );
    }

    /// Empty-slot discipline: the primitive owns COMPOSITION, not
    /// validation. Callers that hand an empty `server` or empty
    /// `cache_name` receive a syntactically-empty half of the alias
    /// (e.g. `":cache"` or `"server:"`), NOT a bail nor a default.
    /// Attic's CLI will reject the empty half downstream; validation
    /// belongs at the boundary that owns the empty-check invariant,
    /// not at this shape-only composition primitive. Pins the
    /// contract so a future refactor cannot silently insert a
    /// default-server fallback or a `.unwrap_or(...)` guard here.
    #[test]
    fn attic_cache_alias_composes_empty_slots_verbatim() {
        assert_eq!(attic_cache_alias("", "cache"), ":cache");
        assert_eq!(attic_cache_alias("server", ""), "server:");
        assert_eq!(attic_cache_alias("", ""), ":");
    }

    /// Post-lift shield (negative half): no source line under
    /// `cli/src/commands/` or `cli/src/infrastructure/` may still
    /// spell the pre-lift raw `format!("{}:{}", <server>,
    /// <cache_name>)` shape inline on an Attic-cache-alias site.
    /// Every consumer reaches for [`attic_cache_alias`] on first grep,
    /// not by copy-pasting the raw `format!` from an existing sibling.
    ///
    /// Anchored on the identifier names that populate the two slots
    /// at the three pre-lift sites (`attic_server` / `cache_server()`
    /// / `server` in the server slot; `cache_name` / `self.cache_name`
    /// in the cache-name slot) — a rename to unrelated slot names
    /// (e.g. `<registry>:<tag>`) does not trip the shield, keeping the
    /// sibling image-reference primitive at its own home.
    #[test]
    fn no_module_still_spells_raw_attic_cache_alias_format() {
        use std::path::PathBuf;
        let src_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut offenders: Vec<(PathBuf, usize, String)> = Vec::new();
        // The three pre-lift shapes, spelled verbatim, without any
        // `format!` variant that a future refactor might introduce.
        let attic_shapes: &[&str] = &[
            "format!(\"{}:{}\", attic_server, cache_name)",
            "format!(\"{}:{}\", server, self.cache_name)",
            "format!(\"{}:{}\", deploy_config.cache_server(), cache_name)",
        ];
        // Walk every `.rs` file under `cli/src/`.
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
            if path.file_name().and_then(|n| n.to_str()) == Some("attic_cache_alias.rs") {
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
                for shape in attic_shapes {
                    if line.contains(shape) {
                        offenders.push((path.clone(), idx + 1, line.to_string()));
                    }
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `format!(\"{{}}:{{}}\", <server>, <cache_name>)` \
             literal(s) survive on an Attic-cache-alias site — route \
             each through `crate::attic_cache_alias::attic_cache_alias\
             (server, cache_name)` instead:\n{:#?}",
            offenders
        );
    }

    /// Post-lift shield (positive half): the three pre-lift modules
    /// that housed the composition MUST each forward through
    /// [`attic_cache_alias`] at least once, so a migration that
    /// dropped a call site outright leaves the negative "no raw
    /// inline shape" scan trivially satisfied by absence but the
    /// positive count still fails. Mirrors the sibling
    /// `every_prelift_module_forwards_through_*` shields the crate
    /// carries against every other typed primitive.
    #[test]
    fn every_prelift_module_forwards_through_attic_cache_alias() {
        use std::path::PathBuf;
        let src_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let expectations: &[(&[&str], usize)] = &[
            (&["commands", "build.rs"], 1),
            (&["commands", "rust_service.rs"], 1),
            (&["infrastructure", "attic.rs"], 1),
        ];
        let needle = "attic_cache_alias(";
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
                "{} must forward at least {min_count} attic-cache-alias \
                 composition(s) through `{needle}`; found {forwards}. A \
                 dropped call would leave the negative raw-shape scan \
                 satisfied by absence.",
                path.display(),
            );
        }
    }
}
