//! Operator-facing advisory-warning grammar.
//!
//! Fourteen pre-lift sibling sites across
//! `commands/{deploy (×1: Cloudflare-enabled-but-missing-configuration
//! guard), github_runner_ci (×3: rollout-timeout + image-mismatch +
//! could-not-verify-deployed-image branches on the watch path),
//! comprehensive_release (×2: skipping-integration-tests +
//! no-compose-file-provided branches on the release orchestrator),
//! integration_tests (×3: continuing-despite-failures +
//! fail-fast-stopping + pre-deployment-tests-failed-on-warn-action
//! branches on the test orchestrator), web_build_verify (×5: env.js /
//! version.json not-referenced, no-JS/CSS-assets-found,
//! non-hashed-asset-name, assets-directory-not-found branches on the
//! bundle-consistency probe)}.rs` each restated the
//! `warn!("⚠️  <message>", <args?>)` stanza verbatim — a `⚠️` emoji
//! glyph followed by two ASCII spaces, then a caller-composed message
//! (which may or may not carry `format_args!`-style interpolation),
//! routed through [`tracing::warn!`]. Post-lift the 14 sites reach
//! for [`warn_advisory!`], and the prefix + glyph + spacing are
//! decided once here.
//!
//! # Distinct from the sibling warn primitives
//!
//! Four warn grammars now coexist in this crate, and each is the
//! sole home for its distinct semantic layer:
//!
//! - [`crate::warn_config!`] (`config/validation_warning.rs`)
//!   narrates a CONFIG-load advisory whose value the parser
//!   accepted-but-flagged. It writes directly to stderr via
//!   [`writeln!`] — bypassing the tracing subscriber deliberately
//!   because a `--json` or `--quiet` command run must surface config
//!   problems even when the tracing filter is set to suppress `warn`
//!   records.
//! - [`crate::ui::eprint_step_warn`] narrates a step-level surprise
//!   routed to stderr with `.yellow()` paint (a retry attempt
//!   failing, a log fetch that fell through). The colored prefix
//!   targets the interactive operator readout at the exact call site.
//! - [`crate::warn_nonfatal!`] (`nonfatal_warning.rs`) narrates a
//!   WORKFLOW-step whose failure the caller deliberately continues
//!   past, carrying the load-bearing `(non-fatal)` marker and a
//!   mandatory [`std::fmt::Display`] error tail — the enclosing
//!   surface (a build, a deploy) is shipping despite the sub-step's
//!   caught error, and the marker is the operator-facing signal that
//!   the step-orchestrator continued past.
//! - [`warn_advisory!`] (this macro) narrates an
//!   ORCHESTRATOR-decision advisory the operator should notice but
//!   the pipeline continues past by design — a rollout watch
//!   reaching its timeout, a probe finding an unexpected asset shape,
//!   a fail-fast decision terminating a test loop, a configuration
//!   guard skipping an optional sub-step. It expands to
//!   `::tracing::warn!(...)` so the subscriber pipeline (structured
//!   logging, filter, OTLP export, per-`module_path` routing)
//!   processes the record, and it carries NO `(non-fatal)` marker
//!   (the advisory narrates a caller-chosen control-flow decision,
//!   NOT a caught error the caller is continuing past).
//!
//! The four sites carry different destinations, different markers,
//! and different filter paths deliberately; a collapse into one
//! primitive would either drop the stderr-direct write
//! [`warn_config!`] needs (breaking `--quiet` config surfacing),
//! drop the tracing-subscriber routing [`warn_nonfatal!`] and
//! [`warn_advisory!`] need (breaking OTLP export of workflow
//! events), or wrongly extend the `(non-fatal)` marker to sites
//! that carry no error at all (breaking the marker's
//! operator-facing contract that a specific caught-error was
//! swallowed).
//!
//! # Distinct from [`crate::warn_nonfatal!`]
//!
//! Same emoji glyph, same two-space post-glyph gap, same tracing
//! routing — but the two macros have different arity and different
//! markers. [`crate::warn_nonfatal!`] carries a MANDATORY
//! `(<label>, <err>)` positional pair AND stamps the load-bearing
//! `(non-fatal)` marker inside the connective; consumer sites bind
//! `err` at the failure boundary of a caught operation. This macro
//! carries a VARIADIC `format_args!`-style body and stamps NO
//! marker; consumer sites narrate a control-flow decision the
//! orchestrator chose, with no caught-error object at hand.
//!
//! # `format_args!` rather than positional pair
//!
//! [`write_advisory_warning`] takes a [`std::fmt::Arguments<'_>`]
//! rather than `(label, args...)` — the pre-lift 14 sites' shapes
//! varied from zero interpolation slots (13 sites, e.g.
//! `warn!("⚠️  Rollout timeout after 5 minutes")`) to one
//! interpolation slot (1 site, `warn!("⚠️  Non-hashed asset: {} (will
//! use short cache)", filename)`), and forcing a positional
//! `(label, arg)` shape would either exclude the one variadic site
//! or force the 13 zero-arg sites to pass a placeholder. The
//! `format_args!` shape accepts both variants without a per-caller
//! adaptation layer, and forwards the format arguments to
//! `tracing::warn!` unchanged so tracing's default `fmt` subscriber
//! renders the message body byte-identically to the pre-lift
//! `warn!("⚠️  <fmt>", args...)` form.
//!
//! # Compounding
//!
//! Pre-lift, a future adjustment to how orchestrator-decision
//! advisories surface — routing them through
//! `tracing::warn!(target: "forge::advisory", ...)` for structured
//! observability so a downstream OTLP subscriber can count in-body
//! advisories per pipeline stage, promoting the `⚠️` glyph to
//! `.yellow()` under a palette-consistency grammar, prefixing the
//! rendered line with the caller's `module_path!()` under an
//! attribution grammar, elevating them to hard errors under a
//! `--strict-advisories` mode, or collecting them into a
//! release-completion summary panel — had to hit 14 sites in
//! lockstep or drift the surface (glyph, spacing, tracing level).
//! Post-lift the glyph, spacing, tracing level, and routing live
//! in ONE macro body; the sites carry only the per-advisory
//! message body.

use std::fmt;
use std::io;

/// Writer-taking byte-oracle sibling to [`warn_advisory!`]. Emits
/// the single `⚠️  <message>` line via [`writeln!`] against the
/// supplied writer.
///
/// The [`crate::warn_advisory!`] macro is the [`tracing::warn!`]
/// adapter production code invokes; this direct-writer variant
/// exists so the fail-before-pass tests can pin the exact emitted
/// bytes (the two-space gap after the `⚠️` glyph, the caller
/// message, the trailing newline) without capturing a tracing
/// subscriber and without racing an ambient logger — the same split
/// [`crate::nonfatal_warning::write_nonfatal_warn`] carries against
/// [`crate::warn_nonfatal!`], and [`crate::config::write_validation_warning`]
/// against [`crate::warn_config!`]. The writer is therefore the
/// byte-format oracle for the tests and the natural next-lift
/// consumer (a `collect_advisories()` summary sibling) rather than
/// the production emission path.
///
/// The `args` parameter takes [`fmt::Arguments<'_>`] rather than
/// `impl fmt::Display` (or `&str`) so the macro forwards
/// `format_args!(...)` without an intermediate `String` allocation
/// — the pre-lift `warn!("⚠️  <fmt>", ...)` spelling also passed
/// args through `format_args!` under the hood (that is what
/// `tracing::warn!`'s message-format arm expands into), so this
/// preserves the byte-for-byte behavior AND the zero-allocation
/// path.
#[allow(dead_code)] // See doc comment: the writer is a test/byte-oracle
                    // peer of the tracing-routed `warn_advisory!` macro,
                    // and the future `collect_advisories` sibling will
                    // consume it directly.
pub fn write_advisory_warning<W: io::Write>(w: &mut W, args: fmt::Arguments<'_>) -> io::Result<()> {
    writeln!(w, "⚠️  {}", args)
}

/// Emit an operator-facing orchestrator-decision advisory via
/// [`tracing::warn!`] on the fleet-standard `"⚠️  <message>"`
/// grammar.
///
/// The macro expands to a direct `::tracing::warn!(...)` call at
/// the caller's location so tracing's automatic source-location
/// capture is preserved (a function wrapper would collapse every
/// emission to the wrapper's site and break per-`module_path` filter
/// routing — the same reason [`crate::warn_nonfatal!`] is a macro
/// rather than a function). See the [module docs](self) for the
/// sibling site census, the split against the other three warn
/// primitives, and the compounding rationale for centralising the
/// glyph decision at one code point.
///
/// # Examples
///
/// ```ignore
/// // Pre-lift, zero-arg case (13 sites):
/// warn!("⚠️  Rollout timeout after 5 minutes");
/// // Post-lift:
/// crate::warn_advisory!("Rollout timeout after 5 minutes");
///
/// // Pre-lift, variadic case (1 site):
/// warn!("⚠️  Non-hashed asset: {} (will use short cache)", filename);
/// // Post-lift:
/// crate::warn_advisory!("Non-hashed asset: {} (will use short cache)", filename);
/// ```
#[macro_export]
macro_rules! warn_advisory {
    ($($arg:tt)*) => {
        ::tracing::warn!("⚠️  {}", ::std::format_args!($($arg)*))
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fail-before-pass envelope for [`write_advisory_warning`]. Pins
    /// the exact prefix bytes: `⚠️` (U+26A0 U+FE0F — warning-sign
    /// codepoint plus the emoji variation selector), two ASCII spaces,
    /// the caller message, then `\n`. A future refactor that drops
    /// the variation selector, collapses the two-space gap to one,
    /// swaps the glyph, or drops the trailing newline flips this
    /// assertion rather than silently diverging the 14 consumer
    /// sites' surface.
    #[test]
    fn write_advisory_warning_emits_prefix_message_and_newline() {
        let mut buf: Vec<u8> = Vec::new();
        write_advisory_warning(&mut buf, format_args!("Rollout timeout after 5 minutes")).unwrap();
        assert_eq!(
            buf, b"\xe2\x9a\xa0\xef\xb8\x8f  Rollout timeout after 5 minutes\n",
            "write_advisory_warning must emit the U+26A0 U+FE0F glyph, two-space gap, \
             message body, then `\\n`"
        );
    }

    /// Pins that the writer accepts a multi-argument `format_args!`
    /// spelling without an intermediate `String` allocation — the
    /// pre-lift `warn!("⚠️  <fmt>", <arg>)` variadic shape (used at
    /// exactly one site: `web_build_verify.rs`'s
    /// `warn!("⚠️  Non-hashed asset: {} (will use short cache)",
    /// filename)`) must forward through the same writer as the
    /// zero-arg sites without a per-caller `.to_string()` intermediate.
    #[test]
    fn write_advisory_warning_interpolates_multi_arg_format() {
        let mut buf: Vec<u8> = Vec::new();
        write_advisory_warning(
            &mut buf,
            format_args!("Non-hashed asset: {} (will use short cache)", "app.js"),
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "\u{26a0}\u{fe0f}  Non-hashed asset: app.js (will use short cache)\n"
        );
    }

    /// Pins that a message containing its own `:` and parenthetical
    /// aside survives verbatim through the writer — the pre-lift
    /// `warn!("⚠️  Pre-deployment tests failed but on_failure.action
    /// = 'warn', continuing...")` grammar embeds an equals sign,
    /// single quotes, and an ellipsis, and the writer MUST NOT re-
    /// quote or re-escape any of them.
    #[test]
    fn write_advisory_warning_preserves_literal_punctuation() {
        let mut buf: Vec<u8> = Vec::new();
        write_advisory_warning(
            &mut buf,
            format_args!(
                "Pre-deployment tests failed but on_failure.action = 'warn', continuing..."
            ),
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "\u{26a0}\u{fe0f}  Pre-deployment tests failed but on_failure.action = 'warn', \
             continuing...\n"
        );
    }

    /// The macro forwards to `::tracing::warn!` at the caller's
    /// location, but the tracing subscriber can't be captured in-
    /// process without racing whatever subscriber `main` installs.
    /// Instead, pin that the macro accepts the same argument shapes
    /// the writer accepts by expanding it at compile time — a
    /// compile-fail here would fail the crate's `cargo test` build
    /// gate.
    #[test]
    fn warn_advisory_macro_compiles_with_supported_arg_shapes() {
        // Bare literal (13 pre-lift sites).
        crate::warn_advisory!("bare message with no interpolation");
        // Single positional arg (1 pre-lift site).
        crate::warn_advisory!("value = {}", 42);
        // Multi-arg (no pre-lift site but supported for future callers).
        crate::warn_advisory!("value = {}, name = {}", 42, "svc");
        // Trailing comma is legal.
        crate::warn_advisory!("trailing comma is legal",);
    }

    /// Caller shield — asserts no source line under `cli/src/commands/`
    /// still spells the pre-lift shape `warn!("⚠️  ...")` inline. Every
    /// non-`(non-fatal)` advisory-warning emission that carries the
    /// `⚠️  ` glyph prefix must route through
    /// [`crate::warn_advisory!`], which expands to the canonical
    /// `tracing::warn!(...)` call at the caller's location.
    ///
    /// The shield scans EVERY `commands/*.rs` module rather than only
    /// the eight pre-lift files so a future orchestrator that
    /// surfaces a new advisory (a new sub-step in a new command
    /// module) reaches for `warn_advisory!` on first grep of `ui.rs`
    /// / this module, not by copy-pasting a raw `warn!("⚠️  ...", ...)`
    /// stanza from `github_runner_ci.rs`.
    ///
    /// The `.contains` needle is the pre-lift `warn!("⚠️  ` opener
    /// (the emoji-glyph prefix combined with the `warn!` macro-call
    /// opener). Lines carrying the ` (non-fatal): {}"` connective are
    /// explicitly excluded so the shield does not swallow the
    /// sibling [`crate::warn_nonfatal!`] pre-lift shape's caller-
    /// shield territory — a raw `warn!("⚠️  <label> (non-fatal): {}",
    /// <err>)` reintroduction correctly fails
    /// [`crate::nonfatal_warning`]'s shield, not this one. Comment
    /// lines are skipped so this module's own docstring reference to
    /// the pre-lift shape doesn't self-hit.
    #[test]
    fn no_command_module_still_spells_raw_advisory_warn() {
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
                // Match the raw pre-lift shape; exclude the
                // sibling non-fatal shape whose caller-shield lives
                // in `crate::nonfatal_warning`.
                if line.contains("warn!(\"\u{26a0}\u{fe0f}  ")
                    && !line.contains(" (non-fatal): {}\"")
                {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `warn!(\"\u{26a0}\u{fe0f}  ...\", <args?>)` advisory-warning \
             stanza(s) survive under `commands/` — route each through \
             `crate::warn_advisory!(<fmt>, <args?>)` instead (or through \
             `crate::warn_nonfatal!` when the advisory carries a caught error \
             with a `(non-fatal)` marker):\n{:#?}",
            offenders
        );
    }

    /// Positive half of the shield: the eight pre-lift files MUST
    /// each forward through `crate::warn_advisory!(` at least once,
    /// so a migration that dropped a call site outright leaves the
    /// negative "no raw inline shape" scan trivially satisfied by
    /// absence but the positive count still fails.
    #[test]
    fn every_prelift_module_forwards_through_warn_advisory_macro() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        // (module basename, minimum forward count from the pre-lift census)
        let expectations: &[(&str, usize)] = &[
            ("deploy.rs", 1),
            ("github_runner_ci.rs", 3),
            ("comprehensive_release.rs", 2),
            ("integration_tests.rs", 3),
            ("web_build_verify.rs", 5),
        ];
        for (basename, min_count) in expectations {
            let path = commands_dir.join(basename);
            let source = std::fs::read_to_string(&path).unwrap();
            let forwards = source.matches("crate::warn_advisory!(").count();
            assert!(
                forwards >= *min_count,
                "{basename} must forward at least {min_count} advisory-warning \
                 site(s) through `crate::warn_advisory!(`; found {forwards}. A dropped \
                 call would leave the negative raw-shape scan satisfied by absence.",
            );
        }
    }
}
