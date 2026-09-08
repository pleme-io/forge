//! Test-suite-failure banner primitive.
//!
//! Three sibling failed-suite stanzas across
//! `commands/{comprehensive_release (×2: `println!(); "✗ Unit tests
//! failed".red().bold(); println!();` at :356–:358 under the
//! `run_inherited_status` unit-tests branch and `println!(); "✗
//! Integration tests failed".red().bold(); println!();` at :677–:679
//! under the `tests_failed` docker-compose integration branch),
//! rust_service (×1: `println!(); "✗ Integration tests failed"
//! .red().bold(); println!();` at :1660–:1664 under the `Err(e)`
//! branch of the awaited `run_integration_tests` call)}.rs` each
//! rendered the same three-line **blank + red-bold `✗ <Suite> tests
//! failed` + blank** banner immediately before returning the failure
//! back up the release-pipeline stack. The operator's eye lands on
//! the red-bold line between two blank lines to see *which* suite
//! collapsed the pipeline before scrolling up into the captured
//! output.
//!
//! Pre-lift all three sites spelled the entire stanza verbatim,
//! differing only in the suite label (`"Unit"` vs `"Integration"`)
//! baked into the `println!` template. A future palette adjustment
//! (a swap of `✗` for `❌` under a heavier per-suite sigil, dropping
//! `.bold()` off the message so it competes weakly against a
//! following spinner clear, dropping `.red()` off the message so a
//! `--no-color` CI log loses the failure-status semantic, hoisting
//! the coloring off the whole line onto a `format!` site, an OTLP
//! `test_suite_failure` observability event that emits alongside
//! the print, a lift of the two bracketing `println!()` blank lines
//! to a leaner one-line grammar) had to hit all three sites in
//! lockstep or the visual grammar the release-pipeline carries
//! between its two suite-runner wrappers would drift; post-lift it
//! hits ONE typed body.
//!
//! Sibling of `commands/subcommand_invocation.rs` — same enum-owned
//! per-variant-label + shared bracketing grammar pattern, applied to
//! the failure-close side of a test-suite run rather than the
//! pre-spawn echo side of a child-tool invocation. This primitive
//! owns the byte-for-byte spelling of the three-line banner; the
//! caller decides what to do with the failure (return an `Err`,
//! trigger a log dump, run cleanup) because the two axes are
//! orthogonal — a future refactor of the post-banner branch flow
//! moves independently of a future refactor of the banner grammar.

use std::io;

use colored::Colorize;

/// The test suite whose failure the release-pipeline announces on the
/// banner line between two blank lines. Each variant maps to a fixed
/// byte-string label the banner emits between the `✗ ` sigil and the
/// ` tests failed` suffix.
///
/// Pre-lift the label was baked into the format string at each of
/// the three consumer sites (`"✗ Unit tests failed"` at
/// `comprehensive_release.rs:357` and `"✗ Integration tests failed"`
/// at `comprehensive_release.rs:678` and `rust_service.rs:1662`);
/// post-lift the enum owns the byte-level spelling at exactly one
/// site. Adding a fourth suite (e.g. `E2E`, `Smoke`) is one new
/// variant plus one [`TestSuiteFailureKind::label`] arm — the
/// surrounding banner grammar stays fixed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TestSuiteFailureKind {
    /// The Rust workspace's `cargo test --lib --bins` unit-test
    /// suite — the `run_inherited_status` branch in
    /// `commands/comprehensive_release.rs`'s `run_unit_tests` phase.
    Unit,
    /// The docker-compose-brought-up integration-test suite — the
    /// `tests_failed` branch in
    /// `commands/comprehensive_release.rs`'s
    /// `run_integration_tests` phase, and the `Err(e)` branch of the
    /// awaited `run_integration_tests` call in
    /// `commands/rust_service.rs`'s `deploy_rust_service_with_tag`.
    Integration,
}

impl TestSuiteFailureKind {
    /// The fixed title-case suite label emitted between the `✗ `
    /// sigil and the ` tests failed` suffix on the banner line.
    ///
    /// Pre-lift the label was baked into the format string at each
    /// site; the byte-for-byte spelling is invariant across the
    /// three consumer sites and named as a `const fn` so a future
    /// addition of a fourth suite cannot drift the label
    /// formatting from what the operator has been trained to read.
    pub const fn label(self) -> &'static str {
        match self {
            TestSuiteFailureKind::Unit => "Unit",
            TestSuiteFailureKind::Integration => "Integration",
        }
    }
}

/// Prints the three-line **blank + `✗ <kind.label()> tests failed`
/// .red().bold() + blank** test-suite-failure banner stanza all
/// three pre-lift sites (`commands/comprehensive_release.rs` ×2 and
/// `commands/rust_service.rs` ×1) spelled verbatim.
///
/// Delegates to [`write_suite_failure_banner`] against
/// [`std::io::stdout`]; the writer split exists so the byte-oracle
/// sibling test can pin the three-line body, the two bracketing
/// blank lines, the `✗ ` sigil, the suite label, the ` tests
/// failed` suffix, and the trailing `\n` against an in-memory
/// [`Vec<u8>`] buffer without capturing stdout.
pub fn print_suite_failure_banner(kind: TestSuiteFailureKind) {
    let _ = write_suite_failure_banner(&mut std::io::stdout().lock(), kind);
}

/// Writer-taking sibling to [`print_suite_failure_banner`]. Emits
/// the three-line body (blank line, then `"✗ <kind.label()> tests
/// failed".red().bold()`, then blank line) via [`writeln!`] against
/// the supplied writer.
///
/// [`print_suite_failure_banner`] is the stdout adapter; this
/// variant exists so tests can pin the three-line body, the two
/// bracketing blank lines, the `✗ ` sigil, the suite label, the `
/// tests failed` suffix, and the trailing `\n` by inspecting emitted
/// bytes rather than shelling out and grepping stdout.
pub fn write_suite_failure_banner<W: io::Write>(
    w: &mut W,
    kind: TestSuiteFailureKind,
) -> io::Result<()> {
    writeln!(w)?;
    let msg = format!("✗ {} tests failed", kind.label());
    writeln!(w, "{}", msg.red().bold())?;
    writeln!(w)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Strip CSI `ESC [ … <letter>` sequences from `s`. The
    /// byte-oracle asserts against the plain-form output the
    /// operator reads regardless of whether [`colored`] emits ANSI
    /// escapes on this test binary's stdout (which depends on
    /// whether stdout is a TTY — cargo test's default parallel
    /// runner can be either). The `.red().bold()` coloring contract
    /// on the middle line is pinned separately by
    /// [`primitive_body_carries_red_bold_on_message`].
    fn strip_ansi(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        let mut chars = s.chars();
        while let Some(c) = chars.next() {
            if c == '\x1b' {
                if chars.next() != Some('[') {
                    continue;
                }
                for nc in chars.by_ref() {
                    if nc.is_ascii_alphabetic() {
                        break;
                    }
                }
                continue;
            }
            out.push(c);
        }
        out
    }

    /// Pin the [`TestSuiteFailureKind::Unit`] byte-form: three lines
    /// exactly — an empty line, then `✗ Unit tests failed`, then an
    /// empty line — each terminated by `\n`. A future refactor that
    /// dropped either bracketing blank line, swapped `✗` for `❌`,
    /// promoted the label to `UNIT`, or dropped the trailing
    /// newline regresses this assertion.
    #[test]
    fn write_unit_line_carries_blank_red_bold_message_blank() {
        let mut buf: Vec<u8> = Vec::new();
        write_suite_failure_banner(&mut buf, TestSuiteFailureKind::Unit).unwrap();
        let out = String::from_utf8(buf).unwrap();
        let plain = strip_ansi(&out);
        assert_eq!(plain, "\n✗ Unit tests failed\n\n");
    }

    /// Pin the [`TestSuiteFailureKind::Integration`] byte-form under
    /// the same three-line grammar, differing only in the suite
    /// label — the invariant the enum owns. A future refactor that
    /// flipped either label's spelling to the other's, or promoted
    /// a variant's label to lower-case, regresses one arm here
    /// without touching the other.
    #[test]
    fn write_integration_line_carries_blank_red_bold_message_blank() {
        let mut buf: Vec<u8> = Vec::new();
        write_suite_failure_banner(&mut buf, TestSuiteFailureKind::Integration).unwrap();
        let out = String::from_utf8(buf).unwrap();
        let plain = strip_ansi(&out);
        assert_eq!(plain, "\n✗ Integration tests failed\n\n");
    }

    /// Label-axis pin: [`TestSuiteFailureKind::Unit::label`] returns
    /// the verbatim `"Unit"` byte string and
    /// [`TestSuiteFailureKind::Integration::label`] returns the
    /// verbatim `"Integration"` byte string the pre-lift three
    /// sites each spelled inline as format-string literals. A
    /// future refactor that swapped either arm regresses this
    /// assertion.
    #[test]
    fn kind_label_maps_to_pre_lift_title_case_suite_name() {
        assert_eq!(TestSuiteFailureKind::Unit.label(), "Unit");
        assert_eq!(TestSuiteFailureKind::Integration.label(), "Integration");
    }

    /// Structural coloring shield: the primitive body must chain
    /// `.red().bold()` on the composed message. Pins the coloring
    /// contract that the byte-oracle above deliberately ignores
    /// (colored auto-drops ANSI on non-TTY writers, so a
    /// plain-bytes assertion cannot distinguish
    /// `"✗ Unit tests failed"` from `"✗ Unit tests failed".red().bold()`
    /// on a stdout-Vec-piped `cargo test` run). A "just print the
    /// message plain, colored is noisy in CI" cleanup that dropped
    /// `.red().bold()` off the middle line regresses this
    /// assertion before the failure-status semantic vanishes from
    /// the terminal.
    ///
    /// The needle scan is bounded to the module body before the
    /// first `#[cfg(test)]` block so this shield's own diagnostic
    /// prose does not false-match itself.
    #[test]
    fn primitive_body_carries_red_bold_on_message() {
        let source = include_str!("test_suite_failure_banner.rs");
        let body = crate::test_support::module_body_before_first_cfg_test(
            source,
            "test_suite_failure_banner.rs",
        );
        assert!(
            body.contains("writeln!"),
            "primitive body must carry a `writeln!` — every test-suite-failure \
             banner stanza this primitive owns is emitted via `writeln!` against \
             the caller's writer.",
        );
        assert!(
            body.contains(".red().bold()"),
            "primitive body must chain `.red().bold()` on the composed message — \
             a \"just print plain, colored is noisy in CI\" cleanup that dropped \
             `.red().bold()` here regresses the failure-status semantic every \
             pre-lift site carried.",
        );
        assert!(
            body.contains("\"✗ {} tests failed\""),
            "primitive body must carry the exact `\"✗ {{}} tests failed\"` \
             format string — the `✗ ` sigil, the label slot, and the ` tests \
             failed` suffix. A rewrite that swapped the sigil for `❌`, dropped \
             the space after `✗`, or reworded the suffix regresses this \
             assertion.",
        );
    }

    /// Caller shield: no source line under `cli/src/commands/` may
    /// spell the pre-lift `"✗ <Suite> tests failed".red().bold()`
    /// message construction inline any more. Every test-suite-
    /// failure banner stanza in a release-pipeline suite-runner
    /// wrapper must resolve through [`print_suite_failure_banner`]
    /// so a future palette adjustment on the sigil, the coloring,
    /// the label position, or the bracketing blank-line count
    /// flows to all three sites from one edit.
    ///
    /// The needle scans for the co-occurrence of `"✗ ` (with the
    /// trailing space that anchors the sigil-prefix grammar) and
    /// `tests failed"` (with the leading close-quote-space that
    /// anchors the suffix). The combination uniquely identifies
    /// the pre-lift test-suite-failure banner message; other `✗`
    /// diagnostics in-repo either lack the ` tests failed` suffix
    /// or are already lifted onto their own primitive.
    #[test]
    fn no_command_module_still_spells_raw_suite_failure_message() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let mut offenders: Vec<(PathBuf, Vec<String>)> = Vec::new();
        for entry in std::fs::read_dir(&commands_dir).unwrap().flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            if path.file_name().and_then(|n| n.to_str()) == Some("test_suite_failure_banner.rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).unwrap();
            let hits: Vec<String> = source
                .lines()
                .enumerate()
                .filter(|(_, l)| {
                    let t = l.trim_start();
                    !t.starts_with("//") && l.contains("\"✗ ") && l.contains(" tests failed\"")
                })
                .map(|(i, l)| format!("line {}: {}", i + 1, l.trim()))
                .collect();
            if !hits.is_empty() {
                offenders.push((path, hits));
            }
        }
        assert!(
            offenders.is_empty(),
            "pre-lift `\"✗ <Suite> tests failed\".red().bold()` banner \
             message(s) survive under `commands/` — route each through \
             `crate::commands::test_suite_failure_banner::print_suite_failure_banner(\
             <TestSuiteFailureKind>)` instead:\n{:#?}",
            offenders,
        );
    }

    /// Positive-delegation shield: every pre-lift consumer module
    /// (`commands/comprehensive_release.rs` and
    /// `commands/rust_service.rs`) must resolve at least one
    /// suite-failure banner through
    /// [`print_suite_failure_banner`]. Pairs with the negative
    /// caller shield above: the negative shield forbids the raw
    /// `"✗ <Suite> tests failed"` literal from surviving, and this
    /// shield forbids a "just delete the banner, the returned
    /// error suffices" cleanup that quietly drops the operator's
    /// visual anchor onto the failure without regressing the
    /// negative-shield assertion.
    #[test]
    fn each_pre_lift_module_delegates_through_primitive_at_least_once() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        for module in ["comprehensive_release.rs", "rust_service.rs"] {
            let path = commands_dir.join(module);
            let source = std::fs::read_to_string(&path).unwrap();
            let uses_primitive = source.contains("print_suite_failure_banner");
            assert!(
                uses_primitive,
                "pre-lift module `commands/{}` no longer resolves any \
                 suite-failure banner through \
                 `test_suite_failure_banner::print_suite_failure_banner` — a \
                 cleanup that dropped the delegation regresses the visual \
                 anchor onto the failure without tripping the negative \
                 caller shield.",
                module,
            );
        }
    }
}
