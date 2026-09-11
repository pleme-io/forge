//! Cloudflare cache-purge success-acknowledgement primitive — the
//! single-owner sibling of [`crate::info_success!`] for the exact
//! `"Cloudflare cache purged successfully"` operator-facing terminator
//! the post-purge Ok-path emits.
//!
//! Two pre-lift sibling sites each restated
//!
//! ```ignore
//! crate::info_success!("Cloudflare cache purged successfully");
//! ```
//!
//! verbatim:
//!
//! - `cli/src/cloudflare.rs::purge_cache` at :122, the ack inside the
//!   self-narrating HTTP-purge primitive itself — emitted after the
//!   [`reqwest`] response deserialization succeeds and Cloudflare's
//!   `CloudflareResponse.success` returns `true`.
//! - `cli/src/commands/deploy.rs::execute` at :181, the ack inside the
//!   caller's `Ok(())` arm of the `match cloudflare::purge_cache(…).await`
//!   block — emitted immediately after the callee has ALREADY emitted the
//!   identical line.
//!
//! The two sites are literal duplicates: identical message body, identical
//! `crate::info_success!` routing, identical `✅` glyph rendering,
//! identical trailing newline. At runtime the operator saw the line
//! TWICE for every successful cache purge — once from the self-narrating
//! `cloudflare.rs` internals, once from the deploy.rs Ok-arm terminator.
//! Post-lift the message body lives at ONE typed constant
//! ([`CLOUDFLARE_PURGE_SUCCESS_MESSAGE`]), the emission responsibility
//! lives at ONE owner primitive ([`announce_cloudflare_purge_success`])
//! invoked solely by `cloudflare::purge_cache`, and the caller's
//! redundant re-emission is deleted. A negative caller shield forbids any
//! future consumer from re-spelling the literal inline.
//!
//! # Single-owner contract
//!
//! [`announce_cloudflare_purge_success`] is a plain function, not a
//! macro, so tracing's automatic source-location capture points at THIS
//! module rather than at each caller — a deliberate reversal of the
//! [`crate::info_bookmark_git_sha_field!`] / [`crate::info_success!`]
//! macro-expansion convention. The trade-off is intentional: this ack
//! belongs to ONE operation (Cloudflare API cache purge) and ONE owner
//! (the [`cloudflare::purge_cache`] primitive that performed the API
//! call). A future filter like `RUST_LOG=forge::cloudflare_purge_success_ack=off`
//! silences EXACTLY this ack across every consumer, which is what the
//! operator wants — the pre-lift split (a filter at `forge::cloudflare`
//! silenced the callee but left the deploy.rs echo untouched, and vice
//! versa) was itself a symptom of the load-bearing double-emission.
//!
//! # Sibling primitives already governing this flow
//!
//! The pre-purge preamble (`Zone ID: <masked>…`) already routes through
//! [`crate::info_zone_id_field!`] at BOTH pre-lift sites — the two
//! callers agreed on the masked-prefix grammar before this lift, and the
//! divergence was closed by the earlier `zone_id_field.rs` primitive.
//! This module closes the SUCCESS-ACK divergence the same way: one
//! constant, one emission owner, one shield.
//!
//! The pre-purge announcement (`🧹 Purging Cloudflare cache...` at the
//! caller vs. `☁️  Purging Cloudflare cache` at the callee) is a
//! distinct visual-grammar divergence outside this primitive's scope —
//! it is layered narration by design (the caller frames the step; the
//! callee narrates the operation), not a literal duplicate. A future
//! lift may unify that layer; this module deliberately does not.

use std::io;

/// The exact `Cloudflare cache purged successfully` message body every
/// pre-lift consumer spelled inline. Pinned as one named constant so a
/// future rewording (e.g. `"Cloudflare cache invalidated"` under a
/// domain-model rename, `"Cloudflare edge cache purged"` under a wire-
/// protocol clarification, appending the URL count under a richer
/// operator readout) happens at ONE typed boundary rather than at every
/// call site, and so the [byte-oracle test](write_cloudflare_purge_success_line)
/// pins the exact bytes the tracing subscriber will render.
///
/// The value is a plain ASCII `&'static str` deliberately: the `✅`
/// glyph prefix and the trailing newline are added by the
/// [`crate::info_success!`] macro / [`writeln!`] adapter respectively;
/// this constant carries ONLY the message body.
pub const CLOUDFLARE_PURGE_SUCCESS_MESSAGE: &str = "Cloudflare cache purged successfully";

/// Emit the fleet-standard `"✅ Cloudflare cache purged successfully"`
/// line via [`writeln!`] against the supplied writer.
///
/// The byte-oracle sibling of [`announce_cloudflare_purge_success`];
/// this direct-writer variant exists so the fail-before-pass tests can
/// pin the exact emitted bytes (the `✅` glyph, the one-ASCII-space
/// separator, the [`CLOUDFLARE_PURGE_SUCCESS_MESSAGE`] body, the
/// trailing newline) without capturing a tracing subscriber and without
/// racing an ambient logger — the same split
/// [`crate::success_step::write_success_step`] carries against
/// [`crate::info_success!`].
///
/// The rendered byte sequence is identical (by construction) to what
/// [`crate::info_success!("{}", CLOUDFLARE_PURGE_SUCCESS_MESSAGE)`]
/// would emit through a tracing subscriber with `with_ansi(false)`.
#[allow(dead_code)] // Peer of the tracing-routed
                    // `announce_cloudflare_purge_success` — kept for
                    // byte-oracle tests and any future consumer that
                    // wants the exact bytes without a tracing hop.
pub fn write_cloudflare_purge_success_line<W: io::Write>(w: &mut W) -> io::Result<()> {
    writeln!(w, "\u{2705} {}", CLOUDFLARE_PURGE_SUCCESS_MESSAGE)
}

/// Emit the operator-facing acknowledgement that a Cloudflare cache
/// purge finished successfully, via [`tracing::info!`] on the fleet-
/// standard `"✅ <message>"` grammar owned by [`crate::info_success!`].
///
/// **Single-owner primitive.** This function MUST be invoked exactly
/// once per successful [`crate::cloudflare::purge_cache`] call, and
/// ONLY by [`crate::cloudflare::purge_cache`] itself — the pre-lift
/// caller-side re-emission at `commands/deploy.rs` produced a duplicate
/// line at runtime and is deleted. The positive-delegation shield in
/// this module's tests pins that `cli/src/cloudflare.rs` forwards
/// through this function at least once; the negative-caller shield
/// forbids any file under `cli/src/commands/` from invoking it (no
/// consumer of `purge_cache` should re-emit the ack the callee already
/// owns).
///
/// See the [module docs](self) for the pre-lift sibling site census,
/// the single-owner contract, and the split against the layered
/// pre-purge narration (which is out of this primitive's scope).
pub fn announce_cloudflare_purge_success() {
    crate::info_success!("{}", CLOUDFLARE_PURGE_SUCCESS_MESSAGE);
}

#[cfg(test)]
mod tests {
    use super::*;

    // Pin the exact message body: a plain ASCII string, no leading or
    // trailing whitespace, no glyph, no newline. The `✅` glyph and the
    // trailing newline are added by the emission wrapper, not by the
    // constant. A future refactor that folded the glyph into the
    // constant would double-emit `✅ ✅ Cloudflare…` once wrapped again
    // by `info_success!`; pin the constant's shape explicitly so that
    // regression is caught before it ships.
    #[test]
    fn cloudflare_purge_success_message_is_plain_body_only() {
        assert_eq!(
            CLOUDFLARE_PURGE_SUCCESS_MESSAGE,
            "Cloudflare cache purged successfully"
        );
        assert!(
            !CLOUDFLARE_PURGE_SUCCESS_MESSAGE.contains('\u{2705}'),
            "message body must NOT carry the ✅ glyph — the glyph is \
             prepended by `crate::info_success!` at emission time; got: \
             {CLOUDFLARE_PURGE_SUCCESS_MESSAGE:?}",
        );
        assert!(
            !CLOUDFLARE_PURGE_SUCCESS_MESSAGE.ends_with('\n'),
            "message body must NOT carry a trailing newline — the \
             newline is appended by `writeln!` / `info!`; got: \
             {CLOUDFLARE_PURGE_SUCCESS_MESSAGE:?}",
        );
    }

    // Pin the exact rendered bytes: `✅` (U+2705, 3 bytes E2 9C 85, no
    // variation selector), one ASCII space, the 36-byte
    // `Cloudflare cache purged successfully` body, then `\n`. A future
    // refactor that adds a variation selector, widens the one-space gap
    // to two, reword the body, or drops the trailing newline regresses
    // this assertion.
    #[test]
    fn write_cloudflare_purge_success_line_emits_exact_bytes() {
        let mut buf: Vec<u8> = Vec::new();
        write_cloudflare_purge_success_line(&mut buf).unwrap();
        assert_eq!(buf, b"\xe2\x9c\x85 Cloudflare cache purged successfully\n");
    }

    // Human-readable pin of the exact grammar so a future reader can
    // eyeball the render without decoding bytes.
    #[test]
    fn write_cloudflare_purge_success_line_renders_expected_grammar() {
        let mut buf: Vec<u8> = Vec::new();
        write_cloudflare_purge_success_line(&mut buf).unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "\u{2705} Cloudflare cache purged successfully\n"
        );
    }

    // Guard against the two-space grammar drift (the `⚠️  ` / `⏭️  `
    // siblings both use two ASCII spaces because their emoji carry a
    // variation selector and are visually narrower without the extra
    // gap). `✅` is already fully-qualified, so a two-space gap would
    // widen the label off the neighboring one-space `crate::info_success!`
    // shape rather than align with it. Pin the negative shape here so a
    // future reader who reaches for the variation-selector-emoji
    // grammar hits this test.
    #[test]
    fn write_cloudflare_purge_success_line_does_not_use_two_space_grammar() {
        let mut buf: Vec<u8> = Vec::new();
        write_cloudflare_purge_success_line(&mut buf).unwrap();
        let rendered = String::from_utf8(buf).unwrap();
        assert!(
            !rendered.contains("\u{2705}  "),
            "render must use a one-space gap after ✅, not the two-space \
             gap the ⚠️/⏭️ siblings use; got: {rendered:?}",
        );
    }

    // Sanity: the callable emission wrapper compiles and executes
    // without panicking. A tracing subscriber is not installed in unit
    // tests, so the actual bytes are pinned by the byte-oracle above;
    // this test guards that a future refactor that changed the wrapper
    // shape (removed the function, converted to a macro that expects
    // args, etc.) is caught at build time.
    #[test]
    fn announce_cloudflare_purge_success_is_callable_without_args() {
        announce_cloudflare_purge_success();
    }

    // Negative shield: the literal message body must live at EXACTLY ONE
    // source file under `cli/src/` — this module. Any other file that
    // spells `"Cloudflare cache purged successfully"` inline (in an
    // `info!`, `println!`, `bail!`, `format!`, `error!`, or a raw
    // string constant) has bypassed the typed primitive.
    //
    // The needle deliberately excludes the caller shim in tests /
    // fixtures — no such shim exists today — and skips comment lines so
    // this shield's own prose describing the migration does not
    // self-hit.
    #[test]
    fn no_other_source_file_spells_the_literal_message_body() {
        use std::path::PathBuf;
        let src_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut offenders: Vec<(PathBuf, usize, String)> = Vec::new();
        walk_rs(&src_dir, &mut |path, source| {
            // The primitive's own module owns the sole definition of the
            // literal.
            if path.file_name().and_then(|n| n.to_str()) == Some("cloudflare_purge_success_ack.rs")
            {
                return;
            }
            for (idx, line) in source.lines().enumerate() {
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") || trimmed.starts_with("///") {
                    continue;
                }
                if line.contains("Cloudflare cache purged successfully") {
                    offenders.push((path.to_path_buf(), idx + 1, line.to_string()));
                }
            }
        });
        assert!(
            offenders.is_empty(),
            "the literal `Cloudflare cache purged successfully` survives \
             outside `cloudflare_purge_success_ack.rs` — route each \
             through `crate::cloudflare_purge_success_ack::CLOUDFLARE_PURGE_SUCCESS_MESSAGE` \
             (constant) or `announce_cloudflare_purge_success()` \
             (emission owner) instead:\n{offenders:#?}",
        );
    }

    // Positive shield (owner side): `cli/src/cloudflare.rs` MUST forward
    // through `announce_cloudflare_purge_success` at least once. The
    // owner is the sole emission site by design; a migration that
    // dropped the forward outright would leave the negative literal
    // shield trivially satisfied by absence but leave the operator
    // with no success ack at all.
    #[test]
    fn cloudflare_rs_forwards_through_announce_cloudflare_purge_success_once() {
        use std::path::PathBuf;
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("cloudflare.rs");
        let source = std::fs::read_to_string(&path).unwrap();
        let forwards = source.matches("announce_cloudflare_purge_success(").count();
        assert!(
            forwards >= 1,
            "cli/src/cloudflare.rs must forward at least 1 success-ack \
             site through `announce_cloudflare_purge_success(`; found \
             {forwards}. A dropped call would leave the negative literal \
             shield satisfied by absence but leave the operator with no \
             success ack at all.",
        );
    }

    // Negative shield (caller side): NO file under `cli/src/commands/`
    // may invoke `announce_cloudflare_purge_success` — the ack belongs
    // to the callee (`cloudflare::purge_cache`) alone. The pre-lift
    // `commands/deploy.rs` re-emission is deleted and the shield forbids
    // any future caller of `cloudflare::purge_cache` from re-adding it.
    #[test]
    fn no_command_module_invokes_announce_cloudflare_purge_success() {
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
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") || trimmed.starts_with("///") {
                    continue;
                }
                if line.contains("announce_cloudflare_purge_success(") {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "a command module invokes \
             `announce_cloudflare_purge_success` — the ack is owned by \
             `cloudflare::purge_cache` and must NOT be re-emitted by \
             its caller (the pre-lift `commands/deploy.rs` re-emission \
             produced a duplicate `✅ Cloudflare cache purged \
             successfully` line at runtime):\n{offenders:#?}",
        );
    }

    // Recursive `.rs` walker used by the negative literal shield. Kept
    // module-local because it is only useful here (every other shield
    // in this crate walks either `commands/` alone or a fixed set of
    // relative paths, so no crate-wide helper exists to reuse).
    fn walk_rs(dir: &std::path::Path, visit: &mut dyn FnMut(&std::path::Path, &str)) {
        for entry in std::fs::read_dir(dir).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk_rs(&path, visit);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).unwrap();
            visit(&path, &source);
        }
    }
}
