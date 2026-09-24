//! Fused `stderr.lines().take(10)` head-walk + keyword-any-match
//! predicate + diagnostic-line-writer dispatch grammar for the two
//! sibling prerelease cargo-gate failure diagnostic stanzas in
//! `commands/prerelease.rs`.
//!
//! # Pre-lift census — 2 sibling stanzas, one fused stderr-head shape
//!
//! Both `commands/prerelease.rs::run_cargo_check` (G1 failure arm,
//! ~L1231-1235) and `commands/prerelease.rs::run_cargo_clippy` (G2
//! failure arm, ~L1271-1275) each restated the same 5-line stanza
//! verbatim modulo a closed (keyword-set, diagnostic-line-style) tuple:
//!
//! ```ignore
//! // commands/prerelease.rs::run_cargo_check (G1 failure arm)
//! for line in stderr.lines().take(10) {
//!     if line.contains("error") {
//!         crate::ui::print_diagnostic_error_line(line);
//!     }
//! }
//!
//! // commands/prerelease.rs::run_cargo_clippy (G2 failure arm)
//! for line in stderr.lines().take(10) {
//!     if line.contains("warning:") || line.contains("error:") {
//!         crate::ui::print_diagnostic_line(line);
//!     }
//! }
//! ```
//!
//! # Two coupled axes, one closed variant per gate
//!
//! The two stanzas differ on exactly two axes, and those axes are
//! semantically coupled per gate:
//!
//! - **Keyword predicate.** G1 uses the bare substring `"error"` (no
//!   colon) — matches every `cargo check` compilation diagnostic line
//!   in the pre-lift dialect: `error:`, `error[E0432]`, the trailing
//!   `error: could not compile ...` summary. G2 uses the colon-anchored
//!   pair `"warning:"` / `"error:"` — the clippy diagnostic prefix, so
//!   narrative lines that mention "warning" or "error" as prose (e.g.,
//!   the trailing `warnings emitted` summary) do NOT surface.
//! - **Diagnostic-line style.** G1 paints matches `.red()` via
//!   [`crate::ui::print_diagnostic_error_line`] — a compilation error
//!   is a hard failure and gets the red highlight. G2 emits matches
//!   plain-verbatim via [`crate::ui::print_diagnostic_line`] — a
//!   clippy warning ships with its own inline color envelope from
//!   cargo's stderr and the plain-verbatim path preserves those bytes
//!   without a double-color layer.
//!
//! Both axes carry per-gate meaning — the keyword shape encodes the
//! filter's dialect and the sink style encodes the failure's severity
//! — so the two arms are pinned to one variant per gate via the
//! closed [`PrereleaseCargoGateStderrHeadVariant`] enum. A rename of
//! one gate's keyword predicate reaches its sink style in lockstep by
//! construction, and a new gate variant added forces both
//! [`PrereleaseCargoGateStderrHeadVariant::line_matches`] and
//! [`PrereleaseCargoGateStderrHeadVariant::write_matching_line`] to
//! extend at build time via the enum's exhaustiveness check —
//! diagnostic-shape drift is a compile error, not a review catch.
//!
//! # Cap pinned at ONE named const
//!
//! Both pre-lift stanzas hard-coded `.take(10)` inline. The primitive
//! lifts the cap to [`PRERELEASE_CARGO_GATE_STDERR_HEAD_LINE_CAP`], a
//! named const paired with a
//! [`PRERELEASE_CARGO_GATE_STDERR_HEAD_LINE_CAP_MATCHES_PRE_LIFT`]
//! oracle test — a future adjustment (a swap to 15 for a wider
//! diagnostic window, a config-derived cap) lands at ONE body, and
//! the pin test flags any drift from the pre-lift literal.
//!
//! # THEORY grounding
//!
//! THEORY.md §II Language — typed primitives own boundary
//! classification; the "cargo gate failure stderr-head keyword-filter
//! block" grammar is named at ONE typed primitive instead of restated
//! at each gate's failure arm. THEORY.md §V.4 Phase 1 attestation —
//! the closed [`PrereleaseCargoGateStderrHeadVariant`] enum forces
//! every consumer's exhaustive `match` to extend when a new gate joins
//! the diagnostic surface, so the (keyword, sink-style) pair stays
//! pinned at one body across the family. THEORY.md §VI.1 one-oracle
//! — the writer sibling and the [`byte-oracle`](tests) tests pin the
//! rendered byte-shape (the three-space indent, the trailing `'\n'`,
//! the ANSI red envelope on `CargoCheckErrors`, its absence on
//! `CargoClippyWarningsAndErrors`) so a future refinement of the
//! diagnostic block's rendering grammar surfaces here or NOWHERE.

use std::io;

use crate::ui::{write_diagnostic_error_line, write_diagnostic_line};

/// Line-count cap on the stderr head walked by the primitive. Pinned
/// to the pre-lift `.take(10)` literal both G1 and G2 sites spelled
/// inline. A change here rotates the byte-shape reachable at both
/// post-lift consumer sites.
pub const PRERELEASE_CARGO_GATE_STDERR_HEAD_LINE_CAP: usize = 10;

/// Closed set of prerelease cargo-gate failure surfaces whose
/// stderr-head diagnostic block routes through this primitive. Each
/// variant carries its own (keyword-predicate, diagnostic-line-style)
/// pair via the [`line_matches`](Self::line_matches) and
/// [`write_matching_line`](Self::write_matching_line) projections,
/// which read from the same discriminant so the two axes stay pinned
/// per gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrereleaseCargoGateStderrHeadVariant {
    /// G1 `cargo check --lib --bins` failure. Predicate:
    /// `line.contains("error")` (bare, no colon, matches `error:`,
    /// `error[E0432]`, and the trailing `error: could not compile`
    /// summary). Sink style: [`crate::ui::print_diagnostic_error_line`]
    /// (`.red()`-painted body).
    CargoCheckErrors,
    /// G2 `cargo clippy --lib --bins -- -D warnings` failure.
    /// Predicate: `line.contains("warning:") || line.contains("error:")`
    /// (colon-anchored, matches the clippy diagnostic prefix — not
    /// narrative lines like `"warnings emitted"`). Sink style:
    /// [`crate::ui::print_diagnostic_line`] (plain-verbatim body, no
    /// color layer added on top of clippy's inline stderr palette).
    CargoClippyWarningsAndErrors,
}

impl PrereleaseCargoGateStderrHeadVariant {
    /// Return `true` iff `line` matches this variant's keyword-any-of
    /// substring predicate. Pinned per variant so a rename of one
    /// gate's dialect does not touch the other.
    pub fn line_matches(self, line: &str) -> bool {
        match self {
            Self::CargoCheckErrors => line.contains("error"),
            Self::CargoClippyWarningsAndErrors => {
                line.contains("warning:") || line.contains("error:")
            }
        }
    }

    /// Emit one matching `line` via this variant's diagnostic-line
    /// writer sibling: red-painted for `CargoCheckErrors`,
    /// plain-verbatim for `CargoClippyWarningsAndErrors`. Both writers
    /// carry the same three-space indent and the same per-line trailing
    /// newline; only the ANSI palette envelope differs.
    pub fn write_matching_line<W: io::Write>(self, w: &mut W, line: &str) -> io::Result<()> {
        match self {
            Self::CargoCheckErrors => write_diagnostic_error_line(w, line),
            Self::CargoClippyWarningsAndErrors => write_diagnostic_line(w, line),
        }
    }
}

/// Writer-taking sibling of
/// [`print_prerelease_cargo_gate_stderr_head_filtered_lines`]: walk
/// the first [`PRERELEASE_CARGO_GATE_STDERR_HEAD_LINE_CAP`] lines of
/// `stderr`, and for each line that matches the variant's predicate,
/// dispatch it through the variant's diagnostic-line writer. Lines
/// within the head that fail the predicate are silently dropped —
/// matching the pre-lift `for line in stderr.lines().take(10) { if
/// ... { ... } }` short-circuit reading.
pub fn write_prerelease_cargo_gate_stderr_head_filtered_lines<W: io::Write>(
    w: &mut W,
    stderr: &str,
    variant: PrereleaseCargoGateStderrHeadVariant,
) -> io::Result<()> {
    for line in stderr
        .lines()
        .take(PRERELEASE_CARGO_GATE_STDERR_HEAD_LINE_CAP)
    {
        if variant.line_matches(line) {
            variant.write_matching_line(w, line)?;
        }
    }
    Ok(())
}

/// Stdout adapter for
/// [`write_prerelease_cargo_gate_stderr_head_filtered_lines`]. Both
/// underlying writers ([`crate::ui::write_diagnostic_error_line`] and
/// [`crate::ui::write_diagnostic_line`]) target stdout, so this
/// primitive locks stdout once for the whole diagnostic block.
///
/// # Examples
///
/// ```ignore
/// // Pre-lift (commands/prerelease.rs::run_cargo_check G1 failure arm)
/// let stderr = crate::repo::utf8_lossy_borrow(&output.stderr);
/// for line in stderr.lines().take(10) {
///     if line.contains("error") {
///         crate::ui::print_diagnostic_error_line(line);
///     }
/// }
///
/// // Post-lift
/// let stderr = crate::repo::utf8_lossy_borrow(&output.stderr);
/// crate::prerelease_cargo_gate_stderr_head_filter::
///     print_prerelease_cargo_gate_stderr_head_filtered_lines(
///         &stderr,
///         crate::prerelease_cargo_gate_stderr_head_filter::
///             PrereleaseCargoGateStderrHeadVariant::CargoCheckErrors,
///     );
/// ```
pub fn print_prerelease_cargo_gate_stderr_head_filtered_lines(
    stderr: &str,
    variant: PrereleaseCargoGateStderrHeadVariant,
) {
    let _ = write_prerelease_cargo_gate_stderr_head_filtered_lines(
        &mut io::stdout().lock(),
        stderr,
        variant,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The cap pinned to the pre-lift `.take(10)` literal. A change
    /// here rotates the byte-shape reachable at both post-lift
    /// consumer sites — the pin makes the drift a test failure, not a
    /// review catch.
    #[test]
    fn prerelease_cargo_gate_stderr_head_line_cap_matches_pre_lift_literal() {
        assert_eq!(PRERELEASE_CARGO_GATE_STDERR_HEAD_LINE_CAP, 10);
    }

    /// Byte-oracle: `CargoCheckErrors` projects the same bytes as the
    /// pre-lift inline stanza that walks `stderr.lines().take(10)`,
    /// filters on `line.contains("error")`, and dispatches surviving
    /// lines through [`crate::ui::write_diagnostic_error_line`]. Pins
    /// the G1 arm's byte-shape against the peer writer so the ANSI
    /// palette envelope, the three-space indent, and the per-line
    /// trailing newline stay pinned at one body without hard-coding
    /// ANSI escapes here (colored's auto-detection strips them on a
    /// non-tty test binary, so peer-comparison is the robust oracle).
    #[test]
    fn write_cargo_check_errors_variant_projects_error_line_bytes() {
        let stderr = "\
error: could not compile
compiling foo
error[E0432]: unresolved import
    finished
2 errors emitted
";
        let mut primitive: Vec<u8> = Vec::new();
        write_prerelease_cargo_gate_stderr_head_filtered_lines(
            &mut primitive,
            stderr,
            PrereleaseCargoGateStderrHeadVariant::CargoCheckErrors,
        )
        .expect("write against a Vec<u8> writer must succeed");

        let mut inline: Vec<u8> = Vec::new();
        for line in stderr.lines().take(10) {
            if line.contains("error") {
                write_diagnostic_error_line(&mut inline, line)
                    .expect("inline peer write must succeed");
            }
        }
        assert_eq!(
            primitive, inline,
            "CargoCheckErrors variant must project the same bytes as \
             the pre-lift inline `for line in stderr.lines().take(10) \
             {{ if line.contains(\"error\") {{ \
             write_diagnostic_error_line(w, line)?; }} }}` stanza"
        );
    }

    /// Byte-oracle: `CargoCheckErrors` drops lines whose bytes do NOT
    /// contain the bare substring `"error"`. Pins the negative arm of
    /// the G1 predicate — a regression that widened the predicate
    /// (e.g. adding a fallback `"warning"` OR) or narrowed it (e.g.
    /// requiring the colon anchor) would surface here.
    #[test]
    fn write_cargo_check_errors_variant_drops_non_matching_lines() {
        let stderr = "\
compiling foo v0.1.0
    finished dev [unoptimized + debuginfo] in 3.14s
warning: no explicit match
";
        let mut buf: Vec<u8> = Vec::new();
        write_prerelease_cargo_gate_stderr_head_filtered_lines(
            &mut buf,
            stderr,
            PrereleaseCargoGateStderrHeadVariant::CargoCheckErrors,
        )
        .expect("write must succeed");
        assert!(
            buf.is_empty(),
            "no line contains bare `error` — writer must emit zero \
             bytes; got: {:?}",
            String::from_utf8_lossy(&buf)
        );
    }

    /// Byte-oracle: `CargoClippyWarningsAndErrors` projects the same
    /// bytes as the pre-lift inline stanza that walks
    /// `stderr.lines().take(10)`, filters on
    /// `line.contains("warning:") || line.contains("error:")`, and
    /// dispatches surviving lines through
    /// [`crate::ui::write_diagnostic_line`]. Pins the G2 arm's
    /// byte-shape against the peer writer so the plain-verbatim body,
    /// the three-space indent, and the per-line trailing newline stay
    /// pinned at one body.
    #[test]
    fn write_cargo_clippy_variant_projects_plain_line_bytes() {
        let stderr = "\
warning: unused variable `x`
    finished
error: some critical rejection
info: consider adding `_` prefix
";
        let mut primitive: Vec<u8> = Vec::new();
        write_prerelease_cargo_gate_stderr_head_filtered_lines(
            &mut primitive,
            stderr,
            PrereleaseCargoGateStderrHeadVariant::CargoClippyWarningsAndErrors,
        )
        .expect("write must succeed");

        let mut inline: Vec<u8> = Vec::new();
        for line in stderr.lines().take(10) {
            if line.contains("warning:") || line.contains("error:") {
                write_diagnostic_line(&mut inline, line).expect("inline peer write must succeed");
            }
        }
        assert_eq!(
            primitive, inline,
            "CargoClippyWarningsAndErrors variant must project the same \
             bytes as the pre-lift inline `for line in \
             stderr.lines().take(10) {{ if line.contains(\"warning:\") \
             || line.contains(\"error:\") {{ \
             write_diagnostic_line(w, line)?; }} }}` stanza"
        );
    }

    /// Byte-oracle: `CargoClippyWarningsAndErrors` respects the colon
    /// anchor — a line containing bare `"warning"` (no colon) is
    /// dropped. Pins the "colon-anchored predicate" narrowing that
    /// distinguishes G2 from G1: a regression that dropped the colon
    /// would silently surface `"warnings emitted"` summary lines the
    /// pre-lift filter deliberately hid.
    #[test]
    fn write_cargo_clippy_variant_drops_colonless_warning_prose() {
        let stderr = "\
warnings emitted during compilation
1 error occurred while compiling
some unrelated line
";
        let mut buf: Vec<u8> = Vec::new();
        write_prerelease_cargo_gate_stderr_head_filtered_lines(
            &mut buf,
            stderr,
            PrereleaseCargoGateStderrHeadVariant::CargoClippyWarningsAndErrors,
        )
        .expect("write must succeed");
        assert!(
            buf.is_empty(),
            "no line carries the colon-anchored clippy diagnostic prefix; \
             writer must emit zero bytes; got: {:?}",
            String::from_utf8_lossy(&buf)
        );
    }

    /// Byte-oracle: the head cap holds — a stderr with 15 matching
    /// lines yields exactly 10 rendered rows. Pins the
    /// [`PRERELEASE_CARGO_GATE_STDERR_HEAD_LINE_CAP`] boundary against
    /// a drift where a future adjustment removed the `.take(N)`
    /// entirely and dumped the full stream.
    #[test]
    fn write_variant_caps_at_ten_matching_lines_even_when_more_available() {
        let mut stderr = String::new();
        for i in 0..15 {
            stderr.push_str(&format!("error at row {i}\n"));
        }
        let mut buf: Vec<u8> = Vec::new();
        write_prerelease_cargo_gate_stderr_head_filtered_lines(
            &mut buf,
            &stderr,
            PrereleaseCargoGateStderrHeadVariant::CargoCheckErrors,
        )
        .expect("write must succeed");
        let out = String::from_utf8(buf).unwrap();
        // The primitive emits one `\n` per rendered row.
        let row_count = out.matches('\n').count();
        assert_eq!(
            row_count, PRERELEASE_CARGO_GATE_STDERR_HEAD_LINE_CAP,
            "primitive must cap emitted rows at \
             PRERELEASE_CARGO_GATE_STDERR_HEAD_LINE_CAP (={PRERELEASE_CARGO_GATE_STDERR_HEAD_LINE_CAP}); \
             got {row_count} rendered rows (out: {out:?})"
        );
        // The eleventh row must not appear.
        assert!(
            !out.contains("error at row 10"),
            "eleventh row must be dropped by the head cap; got: {out:?}"
        );
    }

    /// Byte-oracle: an empty `stderr` writes nothing under either
    /// variant. Pins the no-panic-on-empty contract — the pre-lift
    /// `for line in "".lines().take(10) { ... }` empty-iterator
    /// behavior carries through unchanged.
    #[test]
    fn write_variant_on_empty_stderr_writes_nothing() {
        for variant in [
            PrereleaseCargoGateStderrHeadVariant::CargoCheckErrors,
            PrereleaseCargoGateStderrHeadVariant::CargoClippyWarningsAndErrors,
        ] {
            let mut buf: Vec<u8> = Vec::new();
            write_prerelease_cargo_gate_stderr_head_filtered_lines(&mut buf, "", variant)
                .expect("write must succeed");
            assert!(
                buf.is_empty(),
                "empty stderr must produce no output for {variant:?}; got: {:?}",
                buf
            );
        }
    }

    /// Byte-oracle: the primitive projects the same bytes as the
    /// pre-lift 5-line inline stanza expressed against the variant's
    /// `write_matching_line` dispatch. This is the invariant the
    /// migration MUST preserve — the two post-lift consumers see the
    /// same operator-facing output byte-for-byte as they did pre-lift.
    #[test]
    fn write_variant_projects_prelift_inline_stanza_byte_shape() {
        let stderr = "\
error: A
compiling foo
error: B
    finished
error: C
";

        // G1 (CargoCheckErrors) projection
        let mut primitive: Vec<u8> = Vec::new();
        write_prerelease_cargo_gate_stderr_head_filtered_lines(
            &mut primitive,
            stderr,
            PrereleaseCargoGateStderrHeadVariant::CargoCheckErrors,
        )
        .expect("primitive write must succeed");

        let mut inline: Vec<u8> = Vec::new();
        for line in stderr.lines().take(10) {
            if line.contains("error") {
                write_diagnostic_error_line(&mut inline, line)
                    .expect("inline peer write must succeed");
            }
        }
        assert_eq!(
            primitive, inline,
            "G1 primitive must project the same bytes as the pre-lift \
             `for line in stderr.lines().take(10) {{ if line.contains(\"error\") {{ \
             write_diagnostic_error_line(w, line)?; }} }}` stanza"
        );
    }

    /// Variant projection oracle: `line_matches` reads from the
    /// variant's discriminant. Pins the (predicate) half of the
    /// per-variant coupling — a rename that decoupled the enum arm
    /// from its predicate body would surface here.
    #[test]
    fn variant_line_matches_projection() {
        // CargoCheckErrors: bare "error" substring
        assert!(PrereleaseCargoGateStderrHeadVariant::CargoCheckErrors
            .line_matches("error: could not compile"));
        assert!(PrereleaseCargoGateStderrHeadVariant::CargoCheckErrors
            .line_matches("error[E0432]: unresolved import"));
        assert!(
            PrereleaseCargoGateStderrHeadVariant::CargoCheckErrors.line_matches("2 errors emitted")
        );
        assert!(!PrereleaseCargoGateStderrHeadVariant::CargoCheckErrors
            .line_matches("warning: unused variable"));
        assert!(!PrereleaseCargoGateStderrHeadVariant::CargoCheckErrors
            .line_matches("compiling foo v0.1.0"));

        // CargoClippyWarningsAndErrors: colon-anchored "warning:" | "error:"
        assert!(
            PrereleaseCargoGateStderrHeadVariant::CargoClippyWarningsAndErrors
                .line_matches("warning: unused variable")
        );
        assert!(
            PrereleaseCargoGateStderrHeadVariant::CargoClippyWarningsAndErrors
                .line_matches("error: some rejection")
        );
        assert!(
            !PrereleaseCargoGateStderrHeadVariant::CargoClippyWarningsAndErrors
                .line_matches("warnings emitted")
        );
        assert!(
            !PrereleaseCargoGateStderrHeadVariant::CargoClippyWarningsAndErrors
                .line_matches("1 error occurred")
        );
    }

    /// Negative caller shield: no source line under
    /// `cli/src/commands/` may spell the pre-lift `stderr.lines()
    /// .take(10)` head walk inline anymore — both G1 and G2 sites
    /// route through the primitive. The needle is anchored on the
    /// exact `stderr.lines().take(10)` substring — the fused walk's
    /// tell.
    ///
    /// A future prerelease-cargo-gate failure arm that reaches for
    /// the same shape and skips the primitive fails this shield; a
    /// legitimate unrelated `.take(10)` on a differently-named
    /// stream (`stdout.lines().take(10)`, `combined.lines().take(10)`)
    /// is NOT swept up here.
    #[test]
    fn no_command_module_still_spells_raw_stderr_lines_take_ten_head_walk() {
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
                if line.contains("stderr.lines().take(10)") {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `stderr.lines().take(10)` head walk survives under \
             `commands/` — route each fused walk + keyword-filter + \
             diagnostic-line-print through \
             `crate::prerelease_cargo_gate_stderr_head_filter::print_prerelease_cargo_gate_stderr_head_filtered_lines(<stderr>, <variant>)` \
             instead:\n{:#?}",
            offenders
        );
    }

    /// Positive delegation shield: `commands/prerelease.rs` MUST
    /// forward at least the pre-lift count of head-walk sites through
    /// the primitive, so a migration that dropped a call site outright
    /// leaves the negative "no raw inline shape" scan trivially
    /// satisfied by absence but the positive count still fails.
    #[test]
    fn prerelease_module_forwards_through_stderr_head_filter_primitive() {
        use std::path::PathBuf;
        let prerelease_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands")
            .join("prerelease.rs");
        let source = std::fs::read_to_string(&prerelease_path).unwrap();
        let forwards = source
            .matches(
                "crate::prerelease_cargo_gate_stderr_head_filter::\
                 print_prerelease_cargo_gate_stderr_head_filtered_lines(",
            )
            .count();
        assert!(
            forwards >= 2,
            "commands/prerelease.rs must forward at least 2 head-walk \
             site(s) through \
             `crate::prerelease_cargo_gate_stderr_head_filter::print_prerelease_cargo_gate_stderr_head_filtered_lines(`; \
             found {forwards}. A dropped call would leave the negative \
             raw-shape scan satisfied by absence.",
        );
    }
}
