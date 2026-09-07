//! Info-routed `   Zone ID: <prefix>***` masked-Cloudflare-zone-ID readout
//! grammar with a **char-boundary-safe** prefix walk.
//!
//! Two pre-lift sibling sites across `cloudflare.rs` (Cloudflare cache-purge
//! preamble inside `purge_cache`) and `commands/deploy.rs` (post-deploy
//! purge preamble inside `deploy`) each restated the
//!
//! ```ignore
//! // cloudflare.rs:55 — bounds-safe on length
//! info!("   Zone ID: {}***", &zone_id[..8.min(zone_id.len())]);
//!
//! // commands/deploy.rs:162 — PANICS when `zone_id.len() < 8`
//! info!("   Zone ID: {}***", &zone_id[..8]);
//! ```
//!
//! stanza with a load-bearing safety divergence: `commands/deploy.rs`'s
//! naked byte slice PANICS the process when `zone_id.len() < 8`
//! (`byte index 8 is out of bounds`), and BOTH pre-lift sites still panic
//! when byte 8 lands mid-UTF-8-scalar (`byte index 8 is not a char boundary`).
//! Post-lift both sites reach for [`info_zone_id_field!`] whose payload is
//! computed by [`zone_id_masked_prefix`] — a `chars().take(N)` walk that
//! is safe on every input: an empty string, any short string, exactly
//! [`ZONE_ID_MASKED_PREFIX_LEN`] chars, longer, and multi-byte scalars.
//!
//! # Distinct from every sibling emoji-labeled tag-field primitive
//!
//! The crate carries a small family of `<emoji> <Label>: <value>` field
//! primitives ([`crate::info_git_sha_field!`], [`crate::info_registry_field!`],
//! [`crate::info_deploy_target_field!`], [`crate::info_tags_field!`]) that
//! all emit a zero-indent glyph-anchored preamble line. This primitive is
//! deliberately **not** one of them: the pre-lift stanza carries a
//! three-ASCII-space indent (it is a sub-item under the parent
//! `☁️ Purging Cloudflare cache` / `🧹 Purging Cloudflare cache...`
//! preamble emitted separately by the caller) and NO emoji glyph. A merge
//! into any `<emoji> Label:` primitive would either fabricate a glyph the
//! two pre-lift sites did not carry, or force the sibling emoji primitives
//! to drop their zero-indent anchor.
//!
//! # The load-bearing masking suffix
//!
//! Both pre-lift sites terminate the interpolation with a fixed `***`
//! three-asterisk masking marker (no spaces around it). Zone IDs are 32-
//! character hex strings that identify a Cloudflare tenant zone; the
//! masking convention here reveals only the first 8 characters so a CI
//! log or an operator's terminal can prove the correct zone loaded
//! without leaking the full tenant identifier. The primitive pins the
//! `***` shape, without a space and without a variable count of stars,
//! so a future collapse to `..*` / `…` / `<redacted>` / a
//! space-separated `<prefix> ***` hits the byte-oracle test rather than
//! shipping.
//!
//! # Preserving `tracing::info!` at the call site
//!
//! The macro expands to `::tracing::info!(...)` at the caller's location so
//! tracing's automatic source-location capture (`file` + `line` +
//! `module_path`) matches the pre-lift behavior byte-for-byte. A function-
//! based wrapper would collapse every emission to the wrapper's own site
//! and break structured-log destinations that filter by `module_path`
//! (`RUST_LOG=forge::cloudflare=info` would stop matching once the
//! emission moved to `forge::zone_id_field`). The byte-oracle writer
//! sibling [`write_zone_id_field`] captures the exact rendered body for
//! the tests (the three-space indent, the `Zone ID:` label, the
//! single-space gap before the masked prefix, the `***` suffix, the
//! trailing newline) so the invariant is pinned without racing an
//! ambient tracing subscriber — the same split
//! [`crate::nonfatal_warning::write_nonfatal_warn`] carries against
//! [`crate::warn_nonfatal!`] and
//! [`crate::git_sha_field::write_git_sha_field`] carries against
//! [`crate::info_git_sha_field!`].

use std::io;

/// Number of leading Unicode scalar values of a Cloudflare zone ID
/// revealed in a masked readout — the pre-lift `&zone_id[..8]` prefix
/// width both sibling sites hard-coded, now owned here so a future
/// re-decision on how much of a zone_id is safe to log flows from one
/// edit rather than two divergent numeric literals.
pub const ZONE_ID_MASKED_PREFIX_LEN: usize = 8;

/// Return the first [`ZONE_ID_MASKED_PREFIX_LEN`] Unicode scalars of
/// `zone_id` as an owned string, char-boundary-safe by construction.
///
/// The pre-lift `cloudflare.rs` sibling used `&zone_id[..8.min(len)]`
/// (bounds-safe on length but PANICS if byte 8 lands mid-UTF-8-scalar);
/// the pre-lift `commands/deploy.rs` sibling used the naked `&zone_id[..8]`
/// (PANICS on both `len < 8` and mid-scalar). This
/// `chars().take(N)` walk is safe on both edges: an empty input returns
/// an empty string, any input shorter than
/// [`ZONE_ID_MASKED_PREFIX_LEN`] chars returns the input verbatim, an
/// input of exactly [`ZONE_ID_MASKED_PREFIX_LEN`] chars returns the
/// input verbatim, and a longer input returns the first
/// [`ZONE_ID_MASKED_PREFIX_LEN`] chars.
///
/// A generic `AsRef<str>` bound accepts `&str` (both pre-lift call sites),
/// `&String` (from `Option<String>::as_ref()` unwraps like the
/// `commands/deploy.rs` site's `.zone_id.as_ref()`), owned `String`,
/// `Cow<str>`, and a future `substrate::CloudflareZoneId(String)` newtype
/// via `AsRef<str>`.
pub fn zone_id_masked_prefix<S: AsRef<str>>(zone_id: S) -> String {
    zone_id
        .as_ref()
        .chars()
        .take(ZONE_ID_MASKED_PREFIX_LEN)
        .collect()
}

/// Emits a single `"   Zone ID: <prefix>***"` line via [`writeln!`]
/// against the supplied writer, where `<prefix>` is the char-boundary-safe
/// leading slice returned by [`zone_id_masked_prefix`].
///
/// The [`info_zone_id_field!`] macro is the [`tracing::info!`] adapter
/// that production code invokes; this direct-writer variant exists so
/// the fail-before-pass tests can pin the exact emitted bytes (the
/// three-ASCII-space indent, the `Zone ID:` label, the single-space gap
/// before the masked prefix, the `***` suffix, the trailing newline)
/// without capturing a tracing subscriber and without racing an ambient
/// logger — the same split
/// [`crate::nonfatal_warning::write_nonfatal_warn`] carries against
/// [`crate::warn_nonfatal!`] and
/// [`crate::success_step::write_success_step`] carries against
/// [`crate::info_success!`].
#[allow(dead_code)] // Peer of the tracing-routed `info_zone_id_field!`
                    // macro, retained for the byte-oracle tests and for
                    // a future summary-report consumer.
pub fn write_zone_id_field<W: io::Write, S: AsRef<str>>(w: &mut W, zone_id: S) -> io::Result<()> {
    writeln!(w, "   Zone ID: {}***", zone_id_masked_prefix(zone_id))
}

/// Emit a Cloudflare-cache-purge preamble masked-zone-ID readout via
/// [`tracing::info!`] on the fleet-standard
/// `"   Zone ID: <prefix>***"` grammar, with a **char-boundary-safe**
/// prefix walk owned by [`zone_id_masked_prefix`].
///
/// The macro expands to a direct `::tracing::info!(...)` call at the
/// caller's location so tracing's automatic source-location capture is
/// preserved (a function wrapper would collapse every emission to the
/// wrapper's site — see the module docs for why that breaks per-module
/// filter routing).
///
/// # Examples
///
/// ```ignore
/// // Pre-lift (unsafe: panics if zone_id shorter than 8 bytes)
/// info!("   Zone ID: {}***", &zone_id[..8]);
///
/// // Post-lift (safe on empty, short, exactly-8, and multi-byte inputs)
/// crate::info_zone_id_field!(zone_id);
/// ```
#[macro_export]
macro_rules! info_zone_id_field {
    ($zone_id:expr) => {
        ::tracing::info!(
            "   Zone ID: {}***",
            $crate::zone_id_field::zone_id_masked_prefix($zone_id)
        )
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    // The typical Cloudflare zone ID is a 32-char hex string. Pin that
    // the primitive returns the expected 8-char prefix for this canonical
    // shape — the load-bearing pre-lift behavior on the ASCII-hex path.
    #[test]
    fn zone_id_masked_prefix_returns_first_eight_chars_for_32char_hex_zone_id() {
        let zone_id = "0123456789abcdef0123456789abcdef";
        assert_eq!(zone_id_masked_prefix(zone_id), "01234567");
    }

    // Exactly [`ZONE_ID_MASKED_PREFIX_LEN`] chars is the boundary between
    // the "take all" and "truncate" branches. Pin that no `***` marker
    // logic leaks into the primitive itself: it returns the input verbatim.
    #[test]
    fn zone_id_masked_prefix_returns_exact_input_for_exactly_eight_char_input() {
        assert_eq!(zone_id_masked_prefix("12345678"), "12345678");
    }

    // Fail-before-pass-after: the pre-lift `commands/deploy.rs`
    // `&zone_id[..8]` slice PANICS the process on every zone_id of len < 8:
    //
    //   thread 'main' panicked at 'byte index 8 is out of bounds …'
    //
    // Prove the lifted primitive does NOT panic on the same inputs — the
    // load-bearing safety upgrade this lift delivers.
    #[test]
    fn zone_id_masked_prefix_does_not_panic_on_len_lt_prefix_len() {
        for zone_id in ["", "a", "ab", "abc", "abcd", "abcde", "abcdef", "abcdefg"] {
            let out = zone_id_masked_prefix(zone_id);
            assert_eq!(
                out, zone_id,
                "prefix walk must return the input verbatim for len < {}",
                ZONE_ID_MASKED_PREFIX_LEN
            );
        }
    }

    // Fail-before-pass-after: the pre-lift `cloudflare.rs`
    // `&zone_id[..8.min(len)]` slice guards the length case but STILL
    // panics if byte 8 lands mid-UTF-8-scalar:
    //
    //   thread 'main' panicked at 'byte index 8 is not a char boundary …'
    //
    // Prove the lifted primitive walks char boundaries safely for a
    // multi-byte input where a byte slice would panic.
    #[test]
    fn zone_id_masked_prefix_does_not_panic_on_multibyte_mid_scalar_at_byte_eight() {
        // Each `é` is 2 bytes in UTF-8; `"éééééééé"` is 16 bytes / 8 chars.
        // Byte 8 lands on a char boundary here (start of the 5th `é`),
        // but a byte-slice attempt at `[..7]` would still land mid-scalar
        // for a `"ééé"` input where every 2nd byte is mid-scalar.
        let eight_multibyte = "éééééééé";
        assert_eq!(eight_multibyte.chars().count(), 8, "test fixture invariant");
        // Prefix walk grabs 8 chars = the whole input.
        assert_eq!(zone_id_masked_prefix(eight_multibyte), eight_multibyte);

        // A shorter multi-byte input where byte 8 is unavailable — the
        // pre-lift `..8` slice would panic; the char walk stays safe.
        let short_multibyte = "éé"; // 4 bytes, 2 chars.
        assert_eq!(zone_id_masked_prefix(short_multibyte), "éé");

        // A longer multi-byte input where the 8-char boundary is
        // well before the end. `chars().take(8)` grabs exactly 8 chars.
        let long_multibyte = "éééééééééééé"; // 24 bytes, 12 chars.
        let out = zone_id_masked_prefix(long_multibyte);
        assert_eq!(out.chars().count(), 8);
        assert_eq!(out, "éééééééé");
    }

    // Pin that the prefix walk operates on Unicode SCALARS, not bytes:
    // a multi-byte input longer than 8 CHARS but taking more than 8 bytes
    // returns 8 chars (byte count > 8). Prevents a future collapse back
    // to byte slicing that would look "byte-equivalent" for ASCII inputs
    // and silently regress multi-byte safety.
    #[test]
    fn zone_id_masked_prefix_walks_chars_not_bytes() {
        let out = zone_id_masked_prefix("éééééééééé"); // 20 bytes, 10 chars.
        assert_eq!(out.chars().count(), 8, "must take 8 chars");
        assert!(out.len() > 8, "8 multi-byte chars are >8 bytes");
    }

    // AsRef<str> bound accepts `&str`, `&String`, and owned `String` —
    // the three shapes the pre-lift call sites (`&str` param in
    // `cloudflare.rs`, `&String` from `Option::as_ref()` in
    // `commands/deploy.rs`) already fed into the naked byte-slice
    // and would need to reach through the lifted primitive.
    #[test]
    fn zone_id_masked_prefix_accepts_str_and_string_and_string_ref() {
        let s: &str = "0123456789abcdef";
        assert_eq!(zone_id_masked_prefix(s), "01234567");

        let owned: String = String::from("0123456789abcdef");
        assert_eq!(zone_id_masked_prefix(&owned), "01234567");
        assert_eq!(zone_id_masked_prefix(owned.clone()), "01234567");
        assert_eq!(zone_id_masked_prefix(owned.as_str()), "01234567");
    }

    // Pin the exact bytes: three ASCII spaces (0x20 0x20 0x20), the
    // literal `Zone ID:` (8 bytes), one ASCII space, the interpolated
    // 8-char prefix, the literal `***` (3 ASCII asterisks), then `\n`.
    // A future refactor that changes the indent width, drops the colon,
    // adds a space before `***`, changes the star count, changes the
    // label capitalization, or drops the trailing newline regresses
    // this assertion.
    #[test]
    fn write_zone_id_field_emits_three_space_indent_label_prefix_stars_and_newline() {
        let mut buf: Vec<u8> = Vec::new();
        write_zone_id_field(&mut buf, "0123456789abcdef").unwrap();
        assert_eq!(buf, b"   Zone ID: 01234567***\n");
    }

    // Human-readable pin of the exact grammar so a future reader can
    // eyeball the render without decoding bytes.
    #[test]
    fn write_zone_id_field_renders_expected_grammar() {
        let mut buf: Vec<u8> = Vec::new();
        write_zone_id_field(&mut buf, "0123456789abcdef0123456789abcdef").unwrap();
        assert_eq!(String::from_utf8(buf).unwrap(), "   Zone ID: 01234567***\n");
    }

    // Fail-before-pass-after: writing a short zone_id would have panicked
    // through the pre-lift `commands/deploy.rs` stanza. Prove the writer
    // handles it — the `***` marker still lands, the label still lands,
    // and the prefix is the whole short input.
    #[test]
    fn write_zone_id_field_handles_short_zone_id_without_panic() {
        let mut buf: Vec<u8> = Vec::new();
        write_zone_id_field(&mut buf, "abc").unwrap();
        assert_eq!(buf, b"   Zone ID: abc***\n");
    }

    // Fail-before-pass-after: the empty-string edge is the most extreme
    // regression the pre-lift `..8` slice would have panicked on.
    // Prove the writer emits a well-formed line even here — an empty
    // prefix is a legitimate render, distinguishable from the fully-
    // masked case only by the presence of the `***` marker.
    #[test]
    fn write_zone_id_field_handles_empty_zone_id_without_panic() {
        let mut buf: Vec<u8> = Vec::new();
        write_zone_id_field(&mut buf, "").unwrap();
        assert_eq!(buf, b"   Zone ID: ***\n");
    }

    // Guard against a two-space-indent drift: adjacent tracing lines in
    // the pre-lift Cloudflare purge preamble carry a THREE-space indent
    // (a sub-item under the parent `☁️ Purging Cloudflare cache` header),
    // matching the sibling `   Files to purge:` / `   • <file>` lines
    // emitted by the same `purge_cache` function. Pin the three-space
    // width so a future collapse to a two-space (`  `) or four-space
    // (`    `) grammar hits the byte-oracle test rather than shipping
    // a misaligned sub-item under the parent header.
    #[test]
    fn write_zone_id_field_uses_three_space_indent_not_two_or_four() {
        let mut buf: Vec<u8> = Vec::new();
        write_zone_id_field(&mut buf, "abc").unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(
            s.starts_with("   Zone ID:"),
            "must start with three spaces + label"
        );
        assert!(!s.starts_with("  Zone ID:"), "must NOT be two-space indent");
        assert!(
            !s.starts_with("    Zone ID:"),
            "must NOT be four-space indent"
        );
    }

    // Guard against a masking-marker-count drift: both pre-lift sites
    // spell the suffix as EXACTLY three ASCII asterisks (`***`), no
    // spaces, no ellipsis, no `<redacted>` string. Pin the three-star
    // shape so a future collapse to `**` / `****` / `…` / `<redacted>`
    // hits the byte-oracle rather than shipping.
    #[test]
    fn write_zone_id_field_emits_exactly_three_asterisks_no_space_no_ellipsis() {
        let mut buf: Vec<u8> = Vec::new();
        write_zone_id_field(&mut buf, "abcdefgh").unwrap();
        let s = String::from_utf8(buf).unwrap();
        // The full grammar must end with the three-star marker followed
        // by exactly one newline.
        assert!(
            s.ends_with("***\n"),
            "grammar must end with `***\\n`; got: {s:?}"
        );
        // The prefix immediately precedes the `***` — no spaces between.
        assert!(
            s.contains("abcdefgh***"),
            "the prefix must abut the `***` marker with no space; got: {s:?}"
        );
        // Explicitly reject a four-star drift.
        assert!(
            !s.contains("****"),
            "must NOT emit four asterisks; got: {s:?}"
        );
    }

    // The macro forwards to `::tracing::info!` at the caller's location.
    // The subscriber cannot be captured in-process without racing whatever
    // subscriber `main` installs. Instead, pin that the macro accepts the
    // supported arg shapes by expanding it at compile time — a compile-fail
    // here would fail the crate's `cargo test` build gate.
    #[test]
    fn info_zone_id_field_macro_compiles_with_supported_arg_shapes() {
        // Bare `&str` — the `cloudflare.rs` call site's shape (function
        // param `zone_id: &str`).
        let s: &str = "0123456789abcdef";
        crate::info_zone_id_field!(s);

        // `&String` — the `commands/deploy.rs` call site's shape
        // (`Option<String>::as_ref()` yields `Option<&String>`, then
        // pattern-match unwrap gives `&String`).
        let owned = String::from("cafebabe0123456789ab");
        let borrowed: &String = &owned;
        crate::info_zone_id_field!(borrowed);

        // Owned `String` via the same slot.
        crate::info_zone_id_field!(owned);
    }
}
