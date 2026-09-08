//! Web-tests-config disabled-suite skip-line primitive.
//!
//! The three sibling "suite disabled in `deploy.yaml`" branches of
//! `commands/test.rs::run_web_tests` — Unit at :323–:330, API
//! integration at :344–:351, and E2E at :357–:364 — each restated the
//!
//! ```ignore
//! println!(
//!     "  {} <Suite> tests: {} (disabled in deploy.yaml)",
//!     "⏭️ ".bright_yellow(),
//!     "skipped".dimmed(),
//! );
//! ```
//!
//! four-line stanza verbatim: a TWO-space indent, the U+23ED
//! `⏭` NEXT-TRACK glyph followed by U+FE0F emoji-variation selector
//! and ONE trailing ASCII space rendered under `.bright_yellow()`, a
//! per-site `<Suite>` label (`"Unit"` / `"API integration"` / `"E2E"`)
//! before the fixed `" tests: "` glue, the literal `"skipped"` under
//! `.dimmed()`, then the fixed `" (disabled in deploy.yaml)"` tail. The
//! only per-site axis is the `<Suite>` label; every other byte of the
//! stanza is invariant.
//!
//! Three identically-shaped bodies past THEORY §VI.1's three-is-a-law
//! threshold — the visual contract for the disabled-suite skip line
//! (indent width, skip-glyph choice, glyph palette, suite-label
//! position, `"skipped"` palette, `deploy.yaml` mention wording) now
//! attaches to a type at ONE code line. A future palette adjustment
//! (a swap of `⏭️` for `⊘` under a heavier "not applicable" sigil, a
//! drop of `.bright_yellow()` off the glyph so it visually merges with
//! surrounding narration, a promotion of `"skipped"` to a `.bold()`
//! chain so the disabled-status shouts louder than the suite label,
//! a swap of `"deploy.yaml"` for `"deploy.toml"` under a future config
//! rename, a widen of the indent to three spaces to match the sibling
//! resolved-artifact-enumeration grammar) had to hit all three sites in
//! lockstep or the visual grammar `run_web_tests` carries between its
//! three sibling suite-skip branches would drift; post-lift it hits ONE
//! typed body.
//!
//! # Distinct from the sibling skip primitives
//!
//! The crate carries a small family of skip-glyph primitives; each pins
//! ONE indent scope and one visual register:
//!
//! - [`crate::info_skipping!`] emits a `tracing::info!`-routed
//!   `"⏭️  Skipping <phase>"` line under the `info!` grammar the
//!   deployment-flow narrator drives (a `_skip` gate on an entire phase
//!   like `"build step"` / `"push step"` / `"integration tests"`).
//!   Distinct routing (`tracing::info!` vs. `println!` here), distinct
//!   register (whole-phase gate vs. per-suite disabled-in-config
//!   readout), distinct indent (0 vs. 2), distinct glyph palette
//!   (plain vs. bright_yellow).
//! - [`crate::ui::print_skipping_step`] emits a `println!`-routed
//!   `"   ⏭️  <step> (skipped)"` line under a three-space indent for a
//!   post-header per-step skip narration (see `commands/deploy.rs`'s
//!   `--skip-push` / `--skip-migrate` gates). Distinct indent (three-
//!   space vs. two-space here), distinct trailing-parenthetical wording
//!   (`"(skipped)"` vs. `"(disabled in deploy.yaml)"` here — the two
//!   name different reasons a step did not run, so preserving both
//!   spellings is load-bearing).
//! - [`print_web_test_suite_skipped`] (this primitive) emits the
//!   two-space-indent, `.bright_yellow()`-glyph, `.dimmed()`-`"skipped"`
//!   readout the three `run_web_tests` sibling branches spelled
//!   verbatim, naming which `deploy.yaml`-configured web-tests suite
//!   was disabled at config time.
//!
//! The three primitives carry different indent scopes and different
//! visual roles deliberately; a collapse of any two into one primitive
//! would silently merge sibling indent contracts and misalign the visual
//! hierarchy against every existing consumer.
//!
//! # The two-space indent is load-bearing
//!
//! All three pre-lift sites spell the indent as TWO ASCII spaces before
//! the `⏭️` glyph. This aligns with the sibling `run_web_tests`
//! preamble's `"  📋 Test Configuration (from deploy.yaml):"` header
//! and the three `"     • <suite>: <enabled|disabled>"` sub-item rows
//! that carry FIVE-space sub-indent under it, so the skip-row indent
//! sits at the same visual column as the header itself — one level
//! above the enabled/disabled sub-items. A narrow to zero-space (top-
//! level narration) would jump the skip row over the header it sits
//! under; a widen to three-space would collide with the sibling
//! `crate::ui::print_skipping_step` narrative marker. The byte-oracle
//! pins the two-space width so a silent drift hits the test rather
//! than shipping.
//!
//! # The `⏭️` codepoint is load-bearing
//!
//! All three pre-lift sites spell the skip glyph as U+23ED
//! (BLACK RIGHT-POINTING DOUBLE TRIANGLE WITH VERTICAL BAR — the
//! "next track" media-transport control) followed by U+FE0F (variation
//! selector 16, which requests emoji-style presentation on
//! font/renderer combinations that would otherwise render U+23ED as a
//! text symbol) and ONE trailing ASCII space, the whole sequence
//! wrapped in `.bright_yellow()`. The `⏭️` glyph carries the "this
//! stage was skipped by explicit configuration" meaning the operator
//! is trained to read across the fleet's skip-family surfaces; a swap
//! to U+2757 `❗` (would imply a warning), U+274C `❌` (would imply a
//! failure), or U+267E `♾` (would imply an infinite loop) each changes
//! the operator's read of the line entirely, and the byte-oracle pins
//! the codepoint so a silent glyph swap hits the test rather than
//! shipping.
//!
//! # The `"skipped"` label under `.dimmed()` is load-bearing
//!
//! All three pre-lift sites spell the second `{}` slot as the literal
//! `"skipped"` wrapped in `.dimmed()`. The dimmed palette says
//! "informational, no action needed"; a swap to `.red()` would flag
//! this as an error, a swap to `.green()` would flag this as a pass,
//! and dropping the coloring entirely would let the label compete
//! visually with the suite-name anchor the operator scans for. The
//! byte-oracle keeps the palette-free variant asserting the label
//! spelling; the ANSI-carrying variant of the shield asserts the
//! `.dimmed()` chain sits on the argument in the module body.
//!
//! # The `"deploy.yaml"` filename is load-bearing
//!
//! All three pre-lift sites spell the trailing parenthetical as
//! `"(disabled in deploy.yaml)"` — naming the specific config file the
//! operator opens to re-enable the suite. A future config-rename
//! (`deploy.toml`, `pipeline.yaml`, `service.yaml`) would need to flow
//! through this one primitive rather than three inline sites, so the
//! parenthetical's byte-for-byte spelling attaches to the typed body.

use std::io;

use colored::Colorize;

/// Which `deployment.tests` suite in `deploy.yaml` the disabled-suite
/// skip line names.
///
/// The three variants exactly enumerate the fields of the
/// [`crate::commands::test::WebTestsConfig`] struct that carry an
/// `enabled` bool in `deploy.yaml`'s `deployment.tests` section: `unit`
/// (vitest), `api_integration` (vitest against a running API), and
/// `e2e` (playwright).
///
/// Pre-lift the label was baked into each `println!` template's format
/// string (`"  {} Unit tests: ..."` at :325, `"  {} API integration
/// tests: ..."` at :346, `"  {} E2E tests: ..."` at :359); post-lift
/// the enum owns the byte-level spelling at exactly ONE site. Adding
/// a fourth web-tests suite (say, `visual_regression`) is one new
/// variant plus one [`WebTestSuiteKind::label`] arm — the surrounding
/// print grammar stays fixed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WebTestSuiteKind {
    /// The `unit` suite in `deploy.yaml`'s `deployment.tests` section
    /// (vitest). Label projection: `"Unit"`.
    Unit,
    /// The `api_integration` suite in `deploy.yaml`'s
    /// `deployment.tests` section (vitest against a running API).
    /// Label projection: `"API integration"`.
    ApiIntegration,
    /// The `e2e` suite in `deploy.yaml`'s `deployment.tests` section
    /// (Playwright). Label projection: `"E2E"`.
    E2E,
}

impl WebTestSuiteKind {
    /// The fixed suite-name label that occupies the `<Suite>` slot of
    /// `"<Suite> tests: skipped (disabled in deploy.yaml)"` in the
    /// skip-stanza's grammar.
    ///
    /// Pre-lift the label was baked into each `println!` template's
    /// format string; the byte-for-byte spelling is invariant across
    /// the three consumer sites and named as a `const fn` so a future
    /// addition of a fourth suite cannot drift the label formatting
    /// from what the operator has been trained to read.
    pub const fn label(self) -> &'static str {
        match self {
            WebTestSuiteKind::Unit => "Unit",
            WebTestSuiteKind::ApiIntegration => "API integration",
            WebTestSuiteKind::E2E => "E2E",
        }
    }
}

/// Prints the one-line `"  {} <kind.label()> tests: {} (disabled in
/// deploy.yaml)"` (two-space indent, bright-yellow `⏭️ ` glyph, suite
/// label, dimmed `"skipped"`, trailing parenthetical) disabled-suite
/// skip stanza all three pre-lift sites in `commands/test.rs` spelled
/// verbatim.
///
/// Delegates to [`write_web_test_suite_skipped`] against
/// [`std::io::stdout`]; the writer split exists so the byte-oracle
/// sibling tests can pin the two-space indent, the `⏭️` codepoint,
/// the suite-label projection, the `"skipped"` word, the trailing
/// parenthetical wording, and the trailing `\n` against an in-memory
/// [`Vec<u8>`] buffer without capturing stdout.
pub fn print_web_test_suite_skipped(kind: WebTestSuiteKind) {
    let _ = write_web_test_suite_skipped(&mut io::stdout().lock(), kind);
}

/// Writer-taking sibling to [`print_web_test_suite_skipped`]. Emits
/// the single `"  ⏭️  <suite> tests: skipped (disabled in
/// deploy.yaml)"` line via [`writeln!`] against the supplied writer.
///
/// [`print_web_test_suite_skipped`] is the stdout adapter; this
/// variant exists so tests can pin the one-line body's bytes by
/// inspecting emitted output rather than shelling out and grepping
/// stdout.
pub fn write_web_test_suite_skipped<W: io::Write>(
    w: &mut W,
    kind: WebTestSuiteKind,
) -> io::Result<()> {
    writeln!(
        w,
        "  {} {} tests: {} (disabled in deploy.yaml)",
        "\u{23ED}\u{FE0F} ".bright_yellow(),
        kind.label(),
        "skipped".dimmed(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Strip CSI `ESC [ … <letter>` sequences from `s`. The
    /// byte-oracle asserts against the plain-form output the operator
    /// reads regardless of whether [`colored`] emits ANSI escapes on
    /// this test binary's stdout (which depends on whether stdout is
    /// a TTY — cargo test's default parallel runner can be either).
    /// The coloring contract on the two colored spans is pinned
    /// separately by [`primitive_body_carries_bright_yellow_on_glyph_and_dimmed_on_skipped`].
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

    /// Pin the [`WebTestSuiteKind::Unit`] byte-form: exactly one line,
    /// two-space indent, `⏭️ ` glyph, one space, `Unit tests: skipped
    /// (disabled in deploy.yaml)`, trailing `\n`. A future refactor
    /// that promoted the label to `"Unit Tests"` (title-case), narrowed
    /// the indent to zero-space (top-level), or widened it to three-
    /// space (colliding with `ui::print_skipping_step`) regresses this
    /// assertion.
    #[test]
    fn write_unit_line_carries_indent_glyph_label_skipped_and_parenthetical() {
        let mut buf: Vec<u8> = Vec::new();
        write_web_test_suite_skipped(&mut buf, WebTestSuiteKind::Unit).unwrap();
        let out = String::from_utf8(buf).unwrap();
        let plain = strip_ansi(&out);
        assert_eq!(
            plain,
            "  \u{23ED}\u{FE0F}  Unit tests: skipped (disabled in deploy.yaml)\n"
        );
    }

    /// Pin the [`WebTestSuiteKind::ApiIntegration`] byte-form under the
    /// same grammar, differing only in the suite label — the invariant
    /// the enum owns. A future refactor that folded the two-word label
    /// into a single word (`"ApiIntegration"` / `"API-integration"`)
    /// regresses this arm without touching the other two.
    #[test]
    fn write_api_integration_line_carries_indent_glyph_label_skipped_and_parenthetical() {
        let mut buf: Vec<u8> = Vec::new();
        write_web_test_suite_skipped(&mut buf, WebTestSuiteKind::ApiIntegration).unwrap();
        let out = String::from_utf8(buf).unwrap();
        let plain = strip_ansi(&out);
        assert_eq!(
            plain,
            "  \u{23ED}\u{FE0F}  API integration tests: skipped (disabled in deploy.yaml)\n"
        );
    }

    /// Pin the [`WebTestSuiteKind::E2E`] byte-form under the same
    /// grammar, differing only in the suite label. A future refactor
    /// that lowercased the label (`"e2e"`) or expanded the acronym
    /// (`"End-to-end"`) regresses this arm.
    #[test]
    fn write_e2e_line_carries_indent_glyph_label_skipped_and_parenthetical() {
        let mut buf: Vec<u8> = Vec::new();
        write_web_test_suite_skipped(&mut buf, WebTestSuiteKind::E2E).unwrap();
        let out = String::from_utf8(buf).unwrap();
        let plain = strip_ansi(&out);
        assert_eq!(
            plain,
            "  \u{23ED}\u{FE0F}  E2E tests: skipped (disabled in deploy.yaml)\n"
        );
    }

    /// Label-axis pin: the three [`WebTestSuiteKind::label`] arms
    /// return the verbatim `"Unit"` / `"API integration"` / `"E2E"`
    /// byte strings the pre-lift three sites each spelled inline as
    /// format-string literals. A future refactor that swapped any arm
    /// regresses this assertion.
    #[test]
    fn suite_label_maps_to_pre_lift_yaml_section_name() {
        assert_eq!(WebTestSuiteKind::Unit.label(), "Unit");
        assert_eq!(WebTestSuiteKind::ApiIntegration.label(), "API integration");
        assert_eq!(WebTestSuiteKind::E2E.label(), "E2E");
    }

    /// Pin the U+23ED codepoint (three-byte UTF-8 `E2 8F AD`) followed
    /// by the U+FE0F emoji-variation selector (three-byte UTF-8
    /// `EF B8 8F`) — NOT U+2757 `❗` (would imply warning), NOT U+274C
    /// `❌` (would imply failure), NOT ASCII `>>` (would collide with
    /// the sibling `subcommand_invocation` digraph). A silent glyph
    /// swap changes the operator's read of the line entirely.
    #[test]
    fn write_web_test_suite_skipped_emits_u23ed_next_track_glyph() {
        let mut buf: Vec<u8> = Vec::new();
        write_web_test_suite_skipped(&mut buf, WebTestSuiteKind::Unit).unwrap();
        assert!(
            buf.windows(3).any(|w| w == [0xe2, 0x8f, 0xad]),
            "output must carry U+23ED `\u{23ED}` NEXT-TRACK glyph as \
             the three-byte UTF-8 sequence `E2 8F AD` — a swap to \
             U+2757 `\u{2757}` / U+274C `\u{274C}` silently changes the \
             operator's read of the line. Bytes: {buf:?}"
        );
        assert!(
            buf.windows(3).any(|w| w == [0xef, 0xb8, 0x8f]),
            "output must carry U+FE0F emoji-variation selector as the \
             three-byte UTF-8 sequence `EF B8 8F` immediately after the \
             glyph — dropping it makes renderers fall back to text-style \
             presentation of U+23ED which reads as a visually different \
             character. Bytes: {buf:?}"
        );
    }

    /// Structural coloring shield: the primitive body must chain
    /// `.bright_yellow()` on the `\u{23ED}\u{FE0F} ` glyph AND
    /// `.dimmed()` on the `"skipped"` label. Pins the coloring
    /// contract that the byte-oracle above deliberately ignores
    /// (colored auto-drops ANSI on non-TTY writers, so a plain-bytes
    /// assertion cannot distinguish `⏭️` from `⏭️`.bright_yellow() on
    /// a stdout-`Vec`-piped `cargo test` run). A "just print the glyph
    /// plain, it's shorter" cleanup that drops `.bright_yellow()` off
    /// the glyph, or a `.red()`/`.green()` swap on `"skipped"` that
    /// changes the informational register to warning or pass,
    /// regresses this assertion before the visual grammar drifts in
    /// the terminal.
    ///
    /// The needle scan is bounded to the module body before the first
    /// `#[cfg(test)]` block so this shield's own diagnostic prose does
    /// not false-match itself.
    #[test]
    fn primitive_body_carries_bright_yellow_on_glyph_and_dimmed_on_skipped() {
        let source = include_str!("web_test_suite_skipped.rs");
        let body = crate::test_support::module_body_before_first_cfg_test(
            source,
            "web_test_suite_skipped.rs",
        );
        assert!(
            body.contains("writeln!"),
            "primitive body must carry a `writeln!` — every disabled-suite \
             skip stanza this primitive owns is emitted via `writeln!` \
             against the caller's writer.",
        );
        assert!(
            body.contains("\"  {} {} tests: {} (disabled in deploy.yaml)\""),
            "primitive body must carry the exact `\"  {{}} {{}} tests: {{}} \
             (disabled in deploy.yaml)\"` four-column format string — \
             two-space indent, glyph slot, label slot, `\" tests: \"` \
             glue, `\"skipped\"` slot, `\" (disabled in deploy.yaml)\"` \
             tail. A rewrite that folded the columns, promoted the \
             indent, renamed the config file, or hoisted the columns \
             off `writeln!` regresses this assertion.",
        );
        assert!(
            body.contains(".bright_yellow()"),
            "primitive body must chain `.bright_yellow()` on the \
             `\u{23ED}\u{FE0F} ` skip glyph — a \"just print the glyph \
             plain, it's shorter\" cleanup that dropped \
             `.bright_yellow()` here regresses the visual grammar the \
             three pre-lift sites each carried.",
        );
        assert!(
            body.contains("\"skipped\".dimmed()"),
            "primitive body must chain `.dimmed()` on the literal \
             `\"skipped\"` label — a `.red()`/`.green()` swap or a \
             plain-`\"skipped\"` cleanup changes the informational \
             register of the line and regresses the pre-lift palette \
             contract.",
        );
    }

    /// Caller shield: no source line under `cli/src/commands/` may
    /// spell the pre-lift `println!("  {} <Suite> tests: {} (disabled
    /// in deploy.yaml)", "⏭️ ".bright_yellow(), "skipped".dimmed())`
    /// inline any more. Every disabled-web-suite skip stanza in
    /// `commands/test.rs::run_web_tests` must resolve through
    /// [`print_web_test_suite_skipped`] so a future palette or wording
    /// adjustment flows to all three sites from one edit.
    ///
    /// The needle rejects any line that co-occurs the
    /// `(disabled in deploy.yaml)` trailing parenthetical with a
    /// `println!` prefix — the composite uniquely identifies the
    /// pre-lift disabled-suite skip grammar (nothing else in the crate
    /// spells the exact tail `(disabled in deploy.yaml)`).
    #[test]
    fn no_command_module_still_spells_raw_web_test_suite_skipped_stanza() {
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
            if path.file_name().and_then(|n| n.to_str()) == Some("web_test_suite_skipped.rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).unwrap();
            let hits: Vec<String> = source
                .lines()
                .enumerate()
                .filter(|(_, l)| {
                    let t = l.trim_start();
                    !t.starts_with("//")
                        && l.contains("(disabled in deploy.yaml)")
                        && l.contains("\"skipped\".dimmed()")
                })
                .map(|(i, l)| format!("line {}: {}", i + 1, l.trim()))
                .collect();
            if !hits.is_empty() {
                offenders.push((path, hits));
            }
        }
        assert!(
            offenders.is_empty(),
            "pre-lift `println!(\"  {{}} <Suite> tests: {{}} (disabled in \
             deploy.yaml)\", \"⏭️ \".bright_yellow(), \"skipped\".dimmed())` \
             disabled-suite skip stanza(s) survive under `commands/` — \
             route each through \
             `crate::commands::web_test_suite_skipped::print_web_test_suite_skipped(\
             <WebTestSuiteKind>)` instead:\n{:#?}",
            offenders,
        );
    }

    /// Positive-delegation shield: `commands/test.rs`'s
    /// `run_web_tests` fn body MUST forward through
    /// [`print_web_test_suite_skipped`] at least THREE times so a
    /// migration that dropped a call site outright leaves the negative
    /// caller shield trivially satisfied by absence but the positive
    /// count still fails.
    #[test]
    fn run_web_tests_forwards_through_print_web_test_suite_skipped_three_times() {
        let source = include_str!("test.rs");
        let body = crate::test_support::fn_body_slice_between_markers(
            source,
            "commands/test.rs",
            "async fn run_web_tests(",
            "\n#[cfg(test)]",
        );
        let forwards = body
            .matches("crate::commands::web_test_suite_skipped::print_web_test_suite_skipped(")
            .count();
        assert!(
            forwards >= 3,
            "commands/test.rs::run_web_tests must forward at least THREE \
             disabled-suite skip sites (Unit / API integration / E2E) \
             through \
             `crate::commands::web_test_suite_skipped::print_web_test_suite_skipped(\
             <WebTestSuiteKind>)`; found {forwards}. A dropped call \
             would leave the negative caller-shield scan satisfied by \
             absence."
        );
    }
}
