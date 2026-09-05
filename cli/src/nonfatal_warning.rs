//! Non-fatal workflow-step warning grammar.
//!
//! Six pre-lift sibling sites across `commands/{build (×2), deploy (×2),
//! github_runner_ci (×2)}.rs` each restated the
//! `warn!("⚠️  <label> (non-fatal): {}", <err>)` stanza verbatim — a
//! `⚠️` glyph followed by two ASCII spaces, a per-site step label, the
//! literal ` (non-fatal): ` marker, and an interpolated error [`Display`]
//! (`std::fmt::Display`). Post-lift the sites reach for [`warn_nonfatal!`]
//! and the prefix + marker + separator + tracing verbosity are decided once
//! here.
//!
//! # Distinct from the sibling warning primitives
//!
//! Three warning grammars coexist in this crate, and each is the sole home
//! for its distinct semantic layer:
//!
//! - [`crate::warn_config!`] (`config/validation_warning.rs`) narrates a
//!   CONFIG-load advisory whose value the parser accepted-but-flagged. It
//!   writes directly to stderr via [`writeln!`] — bypassing the tracing
//!   subscriber deliberately because a `--json` or `--quiet` command run
//!   must surface config problems even when the tracing filter is set to
//!   suppress `warn` records.
//! - [`crate::ui::eprint_step_warn`] narrates a step-level surprise routed
//!   to stderr with `.yellow()` paint (a retry attempt failing, a log fetch
//!   that fell through). The colored prefix targets the interactive
//!   operator readout at the exact call site.
//! - [`warn_nonfatal!`] (this macro) narrates a WORKFLOW-step whose failure
//!   the caller deliberately continues past — the enclosing surface (a
//!   build, a deploy, a GitHub-runner CI run) is shipping despite the
//!   sub-step's failure. It expands to `::tracing::warn!(...)` so the
//!   subscriber pipeline (structured logging, filter, OTLP export, per-
//!   module_path routing) processes the record.
//!
//! The three sites carry different destinations and different filter paths
//! deliberately; a collapse into one primitive would either drop the
//! stderr-direct write [`warn_config!`] needs (breaking `--quiet` config
//! surfacing) or drop the tracing-subscriber routing [`warn_nonfatal!`]
//! needs (breaking OTLP export of non-fatal step failures).
//!
//! # The load-bearing `(non-fatal)` marker
//!
//! The literal ` (non-fatal)` inside the message is not decoration. It is
//! the operator-facing signal that the enclosing step-orchestrator
//! deliberately continued past the failure — the same word the pre-lift
//! six sites all reached for. A future promotion to a `--strict` mode that
//! turns non-fatal warnings into hard errors, or a summary panel
//! collecting them after the run finishes, hits ONE code point (this
//! module) rather than N sibling `warn!` sites each spelling the marker
//! inline. Post-lift the invariant "every non-fatal step-failure emission
//! carries the `(non-fatal)` marker" is enforceable by a caller-shield
//! scan (a grep for the pre-lift `warn!("⚠️  ... (non-fatal)` shape MUST
//! return no hits under `commands/`), and the natural next lift's
//! consumer (a `collect_nonfatal_warnings()` sibling that pushes each
//! rendered line into a per-run summary vec) plugs into
//! [`write_nonfatal_warn`] rather than intercepting `tracing::warn`.
//!
//! # Preserving `tracing::warn!` at the call site
//!
//! The macro expands to `::tracing::warn!(...)` at the caller's location,
//! not to a function wrapper, so tracing's automatic source-location
//! capture (`file` + `line` + `module_path`) matches the pre-lift behavior
//! byte-for-byte. A function-based wrapper would collapse every emission
//! to the wrapper's own site and break structured-log destinations that
//! filter by module_path (`RUST_LOG=forge::commands::deploy=warn` would
//! stop matching once the emission moved to `forge::nonfatal_warning`).

use std::fmt;
use std::io;

/// Emits a single `"⚠️  <label> (non-fatal): <err>"` line via
/// [`writeln!`] against the supplied writer, wrapping the arguments with
/// the pre-lift prefix + marker + separator that six sibling sites
/// spelled inline.
///
/// The [`crate::warn_nonfatal!`] macro is the `tracing::warn!` adapter that
/// production code invokes; this direct-writer variant exists so the
/// fail-before-pass tests can pin the exact emitted bytes (the two-space
/// gap after the `⚠️` glyph, the literal ` (non-fatal): ` marker, the
/// trailing newline) without capturing a tracing subscriber and without
/// racing an ambient logger — the same split
/// [`crate::config::write_validation_warning`] carries against
/// [`crate::warn_config!`], except that peer's macro forwards through the
/// writer directly (an `eprintln!`-shaped destination) so the writer is
/// used at runtime, while this crate's `warn_nonfatal!` macro expands to
/// `::tracing::warn!(...)` at the caller's location (preserving tracing's
/// source-location capture) and never calls the writer at runtime. The
/// writer is therefore the byte-format oracle for the tests and the
/// future consumer (a `collect_nonfatal_warnings` summary sibling) rather
/// than the production emission path.
///
/// The `err` parameter accepts any [`fmt::Display`] rather than a
/// concrete error type so a bare `&str` (used by tests) and an
/// `anyhow::Error` / typed `NixBuildError` / boxed `dyn Error` (used by
/// production) both flow through the same writer without a per-caller
/// `.to_string()` intermediate.
#[allow(dead_code)] // See doc comment: the writer is a test/byte-oracle
                    // peer of the tracing-routed `warn_nonfatal!` macro,
                    // and the future `collect_nonfatal_warnings` sibling
                    // will consume it directly.
pub fn write_nonfatal_warn<W: io::Write>(
    w: &mut W,
    label: &str,
    err: &dyn fmt::Display,
) -> io::Result<()> {
    writeln!(w, "⚠️  {} (non-fatal): {}", label, err)
}

/// Emit a non-fatal workflow-step warning via [`tracing::warn!`] on the
/// fleet-standard `"⚠️  <label> (non-fatal): <err>"` grammar.
///
/// The macro expands to a direct `::tracing::warn!(...)` call at the
/// caller's location so tracing's automatic source-location capture is
/// preserved (a function wrapper would collapse every emission to the
/// wrapper's site — see the module docs for why that breaks per-module
/// filter routing). See the [module docs](self) for the sibling site
/// census, the split against [`crate::warn_config!`] and
/// [`crate::ui::eprint_step_warn`], and the compounding rationale for the
/// load-bearing `(non-fatal)` marker.
///
/// # Examples
///
/// ```ignore
/// // Pre-lift
/// warn!("⚠️  Failed to push closure to Attic (non-fatal): {}", e);
///
/// // Post-lift
/// crate::warn_nonfatal!("Failed to push closure to Attic", e);
/// ```
#[macro_export]
macro_rules! warn_nonfatal {
    ($label:expr, $err:expr $(,)?) => {
        ::tracing::warn!("⚠️  {} (non-fatal): {}", $label, $err)
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    // Pin the exact prefix bytes: `⚠️` (U+26A0 U+FE0F), two ASCII
    // spaces, the label, one ASCII space, `(non-fatal): `, then the
    // interpolated error Display, then `\n`. A future refactor that
    // drops the variation selector, collapses the two-space gap to one,
    // moves the parenthesized marker (` [non-fatal]`, ` -- non-fatal`),
    // swaps the ` : ` colon-space separator, or drops the trailing
    // newline regresses this assertion.
    #[test]
    fn write_nonfatal_warn_emits_prefix_label_marker_err_and_newline() {
        let mut buf: Vec<u8> = Vec::new();
        write_nonfatal_warn(&mut buf, "Failed to reconcile", &"timeout").unwrap();
        assert_eq!(
            buf,
            b"\xe2\x9a\xa0\xef\xb8\x8f  Failed to reconcile (non-fatal): timeout\n"
        );
    }

    // Pins the exact grammar as a human-readable UTF-8 assertion so a
    // future reader can eyeball the render without decoding the bytes.
    // Doubles as a Display-forwarding pin: the `&dyn Display` slot
    // receives an `anyhow::Error`-style error whose `Display` includes
    // a colon; the two-colon composition (`(non-fatal): timeout: I/O
    // error`) MUST survive verbatim without the writer re-quoting or
    // re-escaping the inner message.
    #[test]
    fn write_nonfatal_warn_forwards_multi_segment_error_display() {
        let mut buf: Vec<u8> = Vec::new();
        let err = "timeout: I/O error (broken pipe)";
        write_nonfatal_warn(&mut buf, "Cloudflare cache purge failed", &err).unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "\u{26a0}\u{fe0f}  Cloudflare cache purge failed \
             (non-fatal): timeout: I/O error (broken pipe)\n"
        );
    }

    // The macro forwards to `::tracing::warn!` at the caller's location,
    // but the tracing subscriber can't be captured in-process without
    // racing whatever subscriber `main` installs. Instead, pin that the
    // macro accepts the same `(label, err)` shapes the writer accepts by
    // expanding it at compile time — a compile-fail here would fail the
    // crate's `cargo test` build gate.
    #[test]
    fn warn_nonfatal_macro_compiles_with_supported_arg_shapes() {
        // Bare `&str` err (used by tests).
        crate::warn_nonfatal!("Bare-string err label", "timeout");
        // `String` err (owned Display).
        let owned_err = String::from("owned message");
        crate::warn_nonfatal!("Owned-string err label", owned_err);
        // Boxed `dyn std::error::Error`-shaped Display forwarding.
        let boxed: Box<dyn std::error::Error> = "boxed error".into();
        crate::warn_nonfatal!("Boxed err label", boxed);
        // Trailing comma is legal.
        crate::warn_nonfatal!("Trailing comma label", "err",);
    }

    // Caller shield: no source line under `cli/src/commands/` may spell
    // the pre-lift shape `warn!("⚠️  ... (non-fatal): {}", <expr>)`
    // inline any more. Every non-fatal step-failure emission must
    // route through `crate::warn_nonfatal!`, which expands to the
    // canonical `tracing::warn!(...)` call at the caller's location.
    //
    // The shield scans EVERY `commands/*.rs` module rather than only
    // the six pre-lift files so a future step-orchestrator that surfaces
    // a new non-fatal failure (a new sub-step in a new command module)
    // reaches for `warn_nonfatal!` on first grep of ui.rs / this module,
    // not by copy-pasting a raw `warn!("⚠️  ... (non-fatal): {}", ...)`
    // stanza from build.rs.
    //
    // The needle is anchored on the emoji + two-space gap + literal
    // ` (non-fatal): ` marker + `{}` slot so a future variant that
    // spells the marker differently (`--non-fatal`, `[non-fatal]`,
    // ` non-fatal:`) is out of scope; the needle catches only the exact
    // pre-lift shape, and the shield's positive half (the delegation-
    // count assertion below) forces future variants of the SAME shape
    // through the primitive too.
    #[test]
    fn no_command_module_still_spells_raw_nonfatal_warn() {
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
                if line.contains("warn!(\"\u{26a0}\u{fe0f}  ")
                    && line.contains(" (non-fatal): {}\"")
                {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `warn!(\"\u{26a0}\u{fe0f}  ... (non-fatal): {{}}\", <expr>)` \
             stanza(s) survive under `commands/` — route each through \
             `crate::warn_nonfatal!(<label>, <err>)` instead:\n{:#?}",
            offenders
        );
    }

    // Positive half of the shield: the six pre-lift files MUST each
    // forward through `crate::warn_nonfatal!(` at least once, so a
    // migration that dropped a call site outright leaves the negative
    // "no raw inline shape" scan trivially satisfied by absence but
    // the positive count still fails.
    #[test]
    fn every_prelift_module_forwards_through_warn_nonfatal_macro() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        // (module basename, minimum forward count from the pre-lift census)
        let expectations: &[(&str, usize)] = &[
            ("build.rs", 2),
            ("deploy.rs", 2),
            ("github_runner_ci.rs", 2),
        ];
        for (basename, min_count) in expectations {
            let path = commands_dir.join(basename);
            let source = std::fs::read_to_string(&path).unwrap();
            let forwards = source.matches("crate::warn_nonfatal!(").count();
            assert!(
                forwards >= *min_count,
                "{basename} must forward at least {min_count} non-fatal \
                 warning site(s) through `crate::warn_nonfatal!(`; found \
                 {forwards}. A dropped call would leave the negative \
                 raw-shape scan satisfied by absence.",
            );
        }
    }
}
