//! Info-routed `🎯 Target: <registry>:<tag>` labeled-registry-tag-field grammar.
//!
//! Two pre-lift sibling sites across `commands/{deploy (×1: post-`Nexus
//! Deploy - GitOps Workflow` `print_boxed_banner` preamble, above the
//! `📦 Namespace:` + `🚀 Deployment:` companion fields), github_runner_ci
//! (×1: post-`GitHub Runner CI Workflow` `print_boxed_banner` +
//! `info_git_sha_field!(git_sha)` preamble, immediately above the
//! Step-1 build call)}.rs` each restated the
//!
//! ```ignore
//! info!("🎯 Target: {}:{}", registry, tag);
//! ```
//!
//! stanza verbatim — a `🎯` glyph (U+1F3AF DIRECT HIT, standalone,
//! no variation selector, 4 bytes UTF-8), one ASCII space, the
//! six-character `Target:` label, one ASCII space, the interpolated
//! [`std::fmt::Display`]-formatted registry, an ASCII colon `:`, the
//! interpolated [`std::fmt::Display`]-formatted tag, and an
//! `info!`-routed emission via the tracing subscriber. Post-lift the
//! sites reach for [`info_deploy_target_field!`] and the emoji + label
//! + colon separator + tracing verbosity are decided once here.
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
//!   vs. a deploy-target registry+tag pair), distinct interpolation
//!   shape (single Display vs. colon-joined Display pair).
//! - [`crate::info_tags_field!`] narrates a `🏷️  Tags: <t1, t2, …>`
//!   pre-push tag-catalog readout via [`tracing::info!`] using the
//!   `🏷️` LABEL glyph (U+1F3F7 + U+FE0F, two-space grammar).
//!   Distinct semantic layer (a resolved multi-tag catalog vs. a
//!   single-tag deploy target), distinct separator grammar (comma-space
//!   join vs. colon).
//! - [`crate::ui::print_tag_field`] / [`crate::ui::write_tag_field`]
//!   emit a `🏷️  <label>: <value>` line via [`println!`] on stdout —
//!   a direct-to-stdout render targeted at the interactive operator's
//!   terminal, wearing the `🏷️` LABEL glyph. A merge with this
//!   primitive would either drop the tracing-subscriber routing this
//!   macro needs (breaking OTLP export of pre-deploy target readouts)
//!   or bolt colored terminal paint onto non-interactive log records
//!   that must stay ANSI-free (the crate's [`tracing_subscriber`]
//!   initialization in `main.rs` deliberately sets `with_ansi(false)`).
//! - [`info_deploy_target_field!`] (this macro) narrates a mid-preamble
//!   structured deploy-target readout via [`tracing::info!`] — the
//!   subscriber pipeline (structured logging, filter, OTLP export,
//!   per-module_path routing) processes the record with the exact call
//!   site's `module_path` / `file` / `line`, and the tracing layer
//!   emits an ANSI-free record suitable for CI-log ingestion.
//!
//! The sites carry different destinations and different value shapes
//! deliberately; a collapse of `info_deploy_target_field!` and
//! `print_tag_field` into one primitive would break the tracing-vs-
//! stdout split that separates pre-workflow preambles (structured logs,
//! CI-consumed) from post-workflow reports (colored terminal output for
//! the interactive operator).
//!
//! # The `🎯` DIRECT HIT glyph, not `📦` PACKAGE or `🏷️` LABEL
//!
//! The two pre-lift sites both spell the glyph as `🎯` (U+1F3AF DIRECT
//! HIT) — the fleet's mental anchor for "this is the target of the
//! forthcoming action": the registry+tag pair a build is about to be
//! pushed to, and the registry+tag pair a deploy is about to reconcile
//! toward. The `📦` PACKAGE glyph is reserved for build-input identity
//! readouts (`Git SHA:` / `Namespace:`) where the value identifies
//! *what* is being built, not *where* it lands. The `🏷️` LABEL glyph
//! is reserved for the multi-tag catalog a push resolves. A future
//! refactor that flipped this primitive's glyph to PACKAGE or LABEL
//! would silently merge the target-vs-input semantic split the three
//! glyphs deliberately establish across the crate.
//!
//! # The load-bearing single-space separator
//!
//! Both pre-lift sites spell `"🎯 Target: {}:{}"` with EXACTLY ONE
//! ASCII space between the glyph and the `Target` label. This is
//! deliberate and distinct from the fleet's [`crate::warn_nonfatal!`]
//! and [`crate::info_skipping!`] siblings, both of which use TWO ASCII
//! spaces after their (variation-selector-bearing) emoji. The `🎯`
//! glyph (U+1F3AF) has no variation selector — it is already a fully-
//! qualified emoji — so a second ASCII space would visually widen the
//! gap versus the two-space `⚠️  ` / `⏭️  ` shapes rather than align
//! with the one-space `📦 Git SHA:` sibling family. The primitive pins
//! the one-space grammar so a future collapse to the two-space form
//! (e.g. someone reading only `nonfatal_warning.rs` and extrapolating)
//! hits the byte-oracle test rather than shipping.
//!
//! # The load-bearing `:` colon separator between registry and tag
//!
//! Both pre-lift sites spell the interpolation as `"{}:{}"` — the
//! interpolated registry, an ASCII colon `:` (0x3A), the interpolated
//! tag. This matches the OCI image reference convention (`registry/
//! name:tag`) that the downstream Docker / Nix build sites hand to
//! `docker pull` / `docker push`. A future refactor that dropped to a
//! bare space or slash separator would misalign this readout against
//! the exact image-reference string the operator will shortly see in
//! the push-progress narrator; the byte-oracle pins the colon.
//!
//! # Preserving `tracing::info!` at the call site
//!
//! The macro expands to `::tracing::info!(...)` at the caller's
//! location, not to a function wrapper, so tracing's automatic source-
//! location capture (`file` + `line` + `module_path`) matches the
//! pre-lift behavior byte-for-byte. A function-based wrapper would
//! collapse every emission to the wrapper's own site and break
//! structured-log destinations that filter by module_path
//! (`RUST_LOG=forge::commands::deploy=info` would stop matching once
//! the emission moved to `forge::deploy_target_field`). The byte-oracle
//! writer sibling [`write_deploy_target_field`] captures the exact
//! rendered body for the tests (the `🎯` glyph, the one-space gap, the
//! `Target:` label, the second single-space gap before the registry,
//! the colon between registry and tag, the trailing newline) so the
//! invariant is pinned without racing an ambient tracing subscriber —
//! the same split
//! [`crate::nonfatal_warning::write_nonfatal_warn`] carries against
//! [`crate::warn_nonfatal!`] and
//! [`crate::git_sha_field::write_git_sha_field`] carries against
//! [`crate::info_git_sha_field!`].

use std::fmt;
use std::io;

/// Emits a single `"🎯 Target: <registry>:<tag>"` line via [`writeln!`]
/// against the supplied writer, wrapping the caller's registry and tag
/// with the pre-lift `🎯 ` + one-ASCII-space + `Target: ` label prefix
/// and the `:` colon separator that two sibling sites spelled inline.
///
/// The [`crate::info_deploy_target_field!`] macro is the
/// [`tracing::info!`] adapter that production code invokes; this
/// direct-writer variant exists so the fail-before-pass tests can pin
/// the exact emitted bytes (the single-space gap after the `🎯` glyph,
/// the `Target:` label literal, the second single-space gap before the
/// registry, the colon between registry and tag, the trailing newline)
/// without capturing a tracing subscriber and without racing an ambient
/// logger — the same split
/// [`crate::nonfatal_warning::write_nonfatal_warn`] carries against
/// [`crate::warn_nonfatal!`] and
/// [`crate::success_step::write_success_step`] carries against
/// [`crate::info_success!`].
///
/// The `registry` and `tag` parameters each accept any
/// [`fmt::Display`] rather than concrete `&str` so a bare `&str` (used
/// by every pre-lift call site today), a `String` / `Cow<str>`, and a
/// future registry / tag newtype (`substrate::OciRegistry(String)` /
/// `substrate::ImageTag(String)`) all flow through the same writer
/// without a per-caller `.to_string()` intermediate.
#[allow(dead_code)] // See doc comment: the writer is a test/byte-oracle
                    // peer of the tracing-routed
                    // `info_deploy_target_field!` macro, and a future
                    // `collect_deploy_preambles` summary sibling will
                    // consume it directly.
pub fn write_deploy_target_field<W: io::Write>(
    w: &mut W,
    registry: &dyn fmt::Display,
    tag: &dyn fmt::Display,
) -> io::Result<()> {
    writeln!(w, "\u{1F3AF} Target: {}:{}", registry, tag)
}

/// Emit a deploy-preamble target readout via [`tracing::info!`] on the
/// fleet-standard `"🎯 Target: <registry>:<tag>"` grammar.
///
/// The macro expands to a direct `::tracing::info!(...)` call at the
/// caller's location so tracing's automatic source-location capture is
/// preserved (a function wrapper would collapse every emission to the
/// wrapper's site — see the module docs for why that breaks per-module
/// filter routing). See the [module docs](self) for the sibling site
/// census, the split against [`crate::ui::print_tag_field`] (stdout,
/// colored, `🏷️` glyph) and [`crate::info_git_sha_field!`] (PACKAGE
/// glyph, single-Display value), and the compounding rationale for the
/// load-bearing single-space separator and colon-joined registry+tag
/// pair.
///
/// # Examples
///
/// ```ignore
/// // Pre-lift
/// info!("🎯 Target: {}:{}", registry, tag);
///
/// // Post-lift
/// crate::info_deploy_target_field!(registry, tag);
/// ```
#[macro_export]
macro_rules! info_deploy_target_field {
    ($registry:expr, $tag:expr) => {
        ::tracing::info!("\u{1F3AF} Target: {}:{}", $registry, $tag)
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    // Pin the exact prefix bytes: `🎯` (U+1F3AF, 4 bytes F0 9F 8E AF,
    // no variation selector), one ASCII space, the literal `Target:`
    // (7 bytes), one ASCII space, the interpolated registry Display,
    // an ASCII colon, the interpolated tag Display, then `\n`. A future
    // refactor that adds a variation selector, widens the one-space gap
    // to two, drops the colon, changes the label capitalization, drops
    // the colon between registry and tag, or drops the trailing newline
    // regresses this assertion.
    #[test]
    fn write_deploy_target_field_emits_prefix_label_registry_colon_tag_and_newline() {
        let mut buf: Vec<u8> = Vec::new();
        write_deploy_target_field(&mut buf, &"ghcr.io/pleme/svc", &"amd64-abc1234").unwrap();
        assert_eq!(
            buf,
            b"\xf0\x9f\x8e\xaf Target: ghcr.io/pleme/svc:amd64-abc1234\n"
        );
    }

    // Human-readable pin of the exact grammar so a future reader can
    // eyeball the render without decoding bytes.
    #[test]
    fn write_deploy_target_field_renders_expected_grammar() {
        let mut buf: Vec<u8> = Vec::new();
        write_deploy_target_field(&mut buf, &"ghcr.io/pleme/svc", &"amd64-abc1234").unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "\u{1F3AF} Target: ghcr.io/pleme/svc:amd64-abc1234\n"
        );
    }

    // Full-length SHA tag readout — the `github_runner_ci.rs`
    // consumer routes `git::get_short_sha()?` through here (7-char
    // short SHA by default); a future switch to a full 40-char SHA
    // must flow through the writer verbatim without truncation.
    #[test]
    fn write_deploy_target_field_forwards_full_sha_tag_verbatim() {
        let mut buf: Vec<u8> = Vec::new();
        let full_sha = "0123456789abcdef0123456789abcdef01234567";
        write_deploy_target_field(&mut buf, &"ghcr.io/pleme/runner", &full_sha).unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "\u{1F3AF} Target: ghcr.io/pleme/runner:0123456789abcdef0123456789abcdef01234567\n"
        );
    }

    // Guard against the two-space grammar drift: `⚠️  ` and `⏭️  `
    // siblings both use two ASCII spaces (their emoji carry variation
    // selectors and are visually narrower without the extra space).
    // `🎯` is already fully-qualified emoji, so a two-space gap would
    // visually widen the label off the neighboring one-space `📦 Git
    // SHA:` shape rather than align with it. Pin the negative shape
    // explicitly so a future reader who reaches for the sibling
    // grammar hits this test.
    #[test]
    fn write_deploy_target_field_does_not_use_two_space_grammar() {
        let mut buf: Vec<u8> = Vec::new();
        write_deploy_target_field(&mut buf, &"r", &"t").unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(
            !s.starts_with("\u{1F3AF}  "),
            "write_deploy_target_field must NOT emit two ASCII spaces \
             after the `🎯` glyph — the fleet-standard one-space \
             grammar for fully-qualified emoji is load-bearing. \
             Actual: {s:?}",
        );
    }

    // Guard against variation-selector drift: `🎯` (U+1F3AF) is
    // deliberately used as a bare 4-byte glyph. A future refactor
    // that appended U+FE0F would silently break byte-oracle downstream
    // comparators. Pin the exact 4-byte encoding.
    #[test]
    fn write_deploy_target_field_does_not_append_variation_selector() {
        let mut buf: Vec<u8> = Vec::new();
        write_deploy_target_field(&mut buf, &"r", &"t").unwrap();
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
    // deploy-target semantic anchor. Sibling glyphs `📦` PACKAGE
    // (U+1F4E6, F0 9F 93 A6 — Git-SHA / artifact identity) and `🏷`
    // LABEL (U+1F3F7, F0 9F 8F B7 — tag catalog) each carry different
    // semantic layers. A future refactor that flipped this primitive's
    // glyph to PACKAGE or LABEL would silently merge the target-vs-
    // input semantic split the three-glyph convention deliberately
    // establishes. Pin all four glyph bytes.
    #[test]
    fn write_deploy_target_field_emits_direct_hit_glyph_not_package_or_label() {
        let mut buf: Vec<u8> = Vec::new();
        write_deploy_target_field(&mut buf, &"r", &"t").unwrap();
        assert_eq!(
            &buf[0..4],
            &[0xf0, 0x9f, 0x8e, 0xaf],
            "write_deploy_target_field must emit U+1F3AF DIRECT HIT \
             (F0 9F 8E AF), NOT U+1F4E6 PACKAGE (F0 9F 93 A6) or \
             U+1F3F7 LABEL (F0 9F 8F B7) — the three glyphs anchor \
             different semantic layers across the crate. Bytes: {buf:?}",
        );
    }

    // Guard against the colon separator drifting to a bare space or
    // slash. The `{}:{}` interpolation produces `registry:tag`
    // matching the OCI image-reference convention (the `docker push`
    // / `docker pull` argument shape). A refactor to `{}/{}` would
    // emit `registry/tag` and misalign this readout against the exact
    // image-reference string the operator will shortly see in the
    // push-progress narrator.
    #[test]
    fn write_deploy_target_field_joins_registry_and_tag_with_colon_not_slash_or_space() {
        let mut buf: Vec<u8> = Vec::new();
        write_deploy_target_field(&mut buf, &"ghcr.io/pleme/svc", &"amd64-latest").unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(
            s.contains("ghcr.io/pleme/svc:amd64-latest"),
            "write_deploy_target_field must join registry and tag with \
             `:` (ASCII colon) — the OCI image-reference convention. \
             Actual render: {s:?}",
        );
        assert!(
            !s.contains("ghcr.io/pleme/svc/amd64-latest"),
            "write_deploy_target_field must NOT join registry and tag \
             with `/` (ASCII slash). Actual render: {s:?}",
        );
        assert!(
            !s.contains("ghcr.io/pleme/svc amd64-latest"),
            "write_deploy_target_field must NOT join registry and tag \
             with ` ` (ASCII space). Actual render: {s:?}",
        );
    }

    // No-ANSI guard: the crate's `tracing_subscriber` initialization
    // in `main.rs` deliberately sets `with_ansi(false)` so CI log
    // ingestion sees clean records. Pin that this primitive's render
    // carries no ANSI escape byte (0x1B) — a future refactor that
    // reached for `colored` on the label side would break the ANSI-
    // free contract the tracing-routed sites depend on.
    #[test]
    fn write_deploy_target_field_emits_no_ansi_escape() {
        let mut buf: Vec<u8> = Vec::new();
        write_deploy_target_field(&mut buf, &"r", &"t").unwrap();
        assert!(
            !buf.contains(&0x1b),
            "write_deploy_target_field must emit no ANSI escape (0x1B) \
             — the tracing subscriber is configured `with_ansi(false)`. \
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
    fn info_deploy_target_field_macro_compiles_with_supported_arg_shapes() {
        // Bare `&str` (every pre-lift call site today).
        let registry_str: &str = "ghcr.io/pleme/svc";
        let tag_str: &str = "amd64-abc1234";
        crate::info_deploy_target_field!(registry_str, tag_str);
        // Owned `String` via the same slots.
        let registry_owned = String::from("ghcr.io/pleme/svc");
        let tag_owned = String::from("amd64-abc1234");
        crate::info_deploy_target_field!(registry_owned, tag_owned);
        // Mixed reference and owned.
        let borrowed_reg = &String::from("ghcr.io/pleme/svc");
        crate::info_deploy_target_field!(borrowed_reg, "amd64-latest");
        // A future substrate::OciRegistry / substrate::ImageTag pair
        // would implement Display — simulate with a Display-wrapping
        // newtype to prove the slots take any Display.
        struct Wrap<'a>(&'a str);
        impl<'a> fmt::Display for Wrap<'a> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }
        crate::info_deploy_target_field!(Wrap("ghcr.io/pleme/svc"), Wrap("amd64-beefface"));
    }

    // Caller shield: no source line under `cli/src/commands/` may
    // spell the pre-lift raw `info!("🎯 Target: {}:{}", <reg>, <tag>);`
    // stanza inline any more. The two pre-lift sites migrated; any
    // future consumer that wants the same grammar reaches for
    // `crate::info_deploy_target_field!` on first grep, not by copy-
    // pasting the raw shape from an existing command module.
    #[test]
    fn no_command_module_still_spells_raw_info_deploy_target_field_stanza() {
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
                if line.contains("info!(\"\u{1F3AF} Target: {}:{}\"") {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `info!(\"\u{1F3AF} Target: {{}}:{{}}\", <reg>, <tag>);` \
             stanza(s) survive under `commands/` — route each through \
             `crate::info_deploy_target_field!(<reg>, <tag>)` \
             instead:\n{:#?}",
            offenders
        );
    }

    // Positive half of the shield: the two pre-lift files MUST each
    // forward through `crate::info_deploy_target_field!(` at least
    // once, so a migration that dropped a call site outright leaves
    // the negative "no raw inline shape" scan trivially satisfied by
    // absence but the positive count still fails.
    #[test]
    fn every_prelift_module_forwards_through_info_deploy_target_field_macro() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        // (module basename, minimum forward count from the pre-lift census)
        let expectations: &[(&str, usize)] = &[("deploy.rs", 1), ("github_runner_ci.rs", 1)];
        for (basename, min_count) in expectations {
            let path = commands_dir.join(basename);
            let source = std::fs::read_to_string(&path).unwrap();
            let forwards = source.matches("crate::info_deploy_target_field!(").count();
            assert!(
                forwards >= *min_count,
                "{basename} must forward at least {min_count} deploy-target \
                 preamble site(s) through \
                 `crate::info_deploy_target_field!(`; found {forwards}. A \
                 dropped call would leave the negative raw-shape scan \
                 satisfied by absence.",
            );
        }
    }
}
