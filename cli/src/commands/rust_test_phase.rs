//! Rust-test-phase stanza — the fused announce → spawn → summary-pass
//! ceremony `commands/test.rs::run_rust_tests` spelled verbatim once
//! per phase (`--lib --bins` unit tests, then `--test *` integration
//! tests).
//!
//! # Pre-lift census — two sibling 8-line stanzas
//!
//! Two consumer sites in `commands/test.rs::run_rust_tests` (one per
//! `if run_unit { … }` / `if run_integration { … }` arm) each spelled
//! the same 8-line block byte-for-byte, diverging only on the five
//! per-phase axes named below:
//!
//! ```ignore
//! println!(
//!     "  {} Running Rust <PHASE> tests for {}...",
//!     "<EMOJI>".bright_yellow(),
//!     service.bright_cyan()
//! );
//!
//! let mut cmd = Command::new(&cargo);
//! cmd.args([<ARGV...>]).current_dir(service_dir);
//! crate::retry::run_inherited_status(cmd, "<OP-LABEL>")
//!     .await
//!     .context("<CONTEXT>")?;
//!
//! crate::ui::print_summary_pass("Rust <PHASE> tests passed");
//! ```
//!
//! The five diverging axes are:
//!
//! | axis                 | Unit                       | Integration                     |
//! |----------------------|----------------------------|---------------------------------|
//! | announce glyph       | `🧪`                       | `🔗`                            |
//! | phase word           | `unit`                     | `integration`                   |
//! | `cargo` sub-argv     | `["test","--lib","--bins"]`| `["test","--test","*"]`         |
//! | op-label             | `cargo test --lib --bins`  | `cargo test --test *`           |
//! | `.context()` phrase  | `Failed to run cargo test` | `Failed to run cargo integration tests` |
//!
//! The announce line, the spawn, the ack-on-success, and the
//! per-phase-summary label all read from the same [`RustTestPhase`]
//! variant, so a drift in any single axis at either arm lands at
//! ONE variant match rather than the two inline literals a copy-paste
//! would carry.
//!
//! # Load-bearing invariants
//!
//! 1. **Announce-run-ack ordering.** The `println!` announce fires
//!    BEFORE the spawn (so the operator sees which phase is starting
//!    even if the spawn hangs); the [`crate::ui::print_summary_pass`]
//!    fires AFTER the `?` short-circuit (so a non-zero exit surfaces
//!    via the error path, never as a false-pass ack). The lifted
//!    body preserves that order byte-for-byte at both sites.
//! 2. **`current_dir(service_dir)` scoping.** Both pre-lift sites
//!    scoped the `cargo test` spawn to the service's crate root so
//!    the workspace resolution reads the service's `Cargo.toml`,
//!    never the forge CLI's. Dropping the scope would silently run
//!    forge's own tests at every `forge test rust <svc>` invocation.
//! 3. **Inherited stdio via [`crate::retry::run_inherited_status`].**
//!    Both pre-lift sites chose the inherited-stdio spawn variant
//!    (rather than `output().await` capture) so `cargo`'s progress
//!    streams live to the operator's terminal. Capturing would
//!    silence the phase's diagnostics.
//!
//! # Compounding
//!
//! A third `cargo test` phase (a `--doc` doctests run, a
//! `--all-targets` variant, an `--ignored` post-deployment slice)
//! forwards through the same primitive at one new
//! [`RustTestPhase`] variant plus one call rather than a third
//! 8-line stanza copy. A future refinement — a
//! `tracing::info!("phase={} elapsed={:?}", phase.phase_word(),
//! elapsed)` structured tick around the spawn, a per-phase JSON
//! artifact write, a metric emitted per phase — lands at ONE body
//! and reaches every consumer by construction.
//!
//! # Theory grounding
//!
//! - THEORY.md §V (typed primitives own their algebra): the phase
//!   axis lives as a closed enum with typed accessors rather than
//!   parallel `if unit { … } if integration { … }` scaffolding at
//!   the call site.
//! - THEORY.md §VI.1 (duplication is a bug — the three-times rule):
//!   two sibling occurrences hit the compounding-directive threshold,
//!   and the lift closes them both under one body before a third
//!   phase copies the stanza a third time.

use anyhow::{Context, Result};
use colored::Colorize;

/// The closed set of Rust `cargo test` phases the CLI's
/// `forge test rust` sub-command drives per service. Each variant
/// pins the five per-phase axes both pre-lift stanzas diverged on
/// (announce glyph, phase word, `cargo` sub-argv, op-label, context
/// phrase) as `const` accessors so a call site names the phase
/// once and reads every axis by construction.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RustTestPhase {
    /// `cargo test --lib --bins` — library + binary unit tests.
    Unit,
    /// `cargo test --test *` — integration tests under the service's
    /// `tests/` directory.
    Integration,
}

impl RustTestPhase {
    /// The lowercase phase word the announce line and the
    /// summary-pass label both embed (`"unit"` / `"integration"`).
    pub const fn phase_word(self) -> &'static str {
        match self {
            Self::Unit => "unit",
            Self::Integration => "integration",
        }
    }

    /// The announce-line leading emoji, rendered `.bright_yellow()`
    /// at the call site (`🧪` unit / `🔗` integration).
    pub const fn announce_glyph(self) -> &'static str {
        match self {
            Self::Unit => "🧪",
            Self::Integration => "🔗",
        }
    }

    /// The fixed `cargo` sub-argv the spawn passes to
    /// [`Command::args`].
    pub const fn cargo_argv(self) -> &'static [&'static str] {
        match self {
            Self::Unit => &["test", "--lib", "--bins"],
            Self::Integration => &["test", "--test", "*"],
        }
    }

    /// The `run_inherited_status` op-label — surfaces at the
    /// spawn-failure error path (`"Failed to run {op}"`).
    pub const fn op_label(self) -> &'static str {
        match self {
            Self::Unit => "cargo test --lib --bins",
            Self::Integration => "cargo test --test *",
        }
    }

    /// The [`anyhow::Context`] phrase attached on non-zero exit
    /// (`"Failed to run cargo test"` for unit,
    /// `"Failed to run cargo integration tests"` for integration).
    pub const fn context_msg(self) -> &'static str {
        match self {
            Self::Unit => "Failed to run cargo test",
            Self::Integration => "Failed to run cargo integration tests",
        }
    }

    /// The one-line [`crate::ui::print_summary_pass`] label emitted
    /// on the success path (`"Rust <phase> tests passed"`).
    pub fn summary_pass_label(self) -> String {
        format!("Rust {} tests passed", self.phase_word())
    }
}

/// Emit the phase announce line
/// `  <glyph> Running Rust <phase> tests for <service>...\n` against
/// the supplied writer. Split from the stdout-adapter helper so
/// fail-before-pass byte-oracle tests pin the exact rendered bytes
/// without capturing stdout.
pub fn write_rust_test_phase_announce_line<W: std::io::Write>(
    w: &mut W,
    phase: RustTestPhase,
    service: &str,
) -> std::io::Result<()> {
    writeln!(
        w,
        "  {} Running Rust {} tests for {}...",
        phase.announce_glyph().bright_yellow(),
        phase.phase_word(),
        service.bright_cyan()
    )
}

/// Stdout adapter for [`write_rust_test_phase_announce_line`].
fn print_rust_test_phase_announce_line(phase: RustTestPhase, service: &str) {
    let _ = write_rust_test_phase_announce_line(&mut std::io::stdout().lock(), phase, service);
}

/// The lifted 8-line fused stanza. Emits the phase announce line,
/// spawns `cargo test <argv>` under the service's crate root via the
/// `(bin, args, cwd, op)`-front async wrapper
/// [`crate::retry::run_bin_args_at_inherited_status`] (which composes
/// `Command::new(bin).args(args).current_dir(cwd)` and routes through
/// [`crate::retry::run_inherited_status`] with inherited stdio), and
/// on success emits [`crate::ui::print_summary_pass`] with the
/// per-phase label. A non-zero exit propagates as an
/// [`anyhow::Error`] under [`RustTestPhase::context_msg`], and the
/// success ack does not fire on the error path.
///
/// `cargo` is the resolved `CARGO` binary path (both pre-lift sites
/// read it through `crate::repo::get_tool_path("CARGO", "cargo")`);
/// `service` is the service-name display body threaded through the
/// announce line; `service_dir` is the working directory scoped onto
/// the spawn via the wrapper's `.current_dir(cwd)` fold.
pub async fn announce_and_run_rust_test_phase(
    cargo: &str,
    service: &str,
    service_dir: &str,
    phase: RustTestPhase,
) -> Result<()> {
    print_rust_test_phase_announce_line(phase, service);

    crate::retry::run_bin_args_at_inherited_status(
        cargo,
        phase.cargo_argv(),
        service_dir,
        phase.op_label(),
    )
    .await
    .context(phase.context_msg())?;

    crate::ui::print_summary_pass(&phase.summary_pass_label());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ============================================================
    // Per-axis const-anchor pins — one per pre-lift literal
    // ============================================================

    /// Pin: [`RustTestPhase::phase_word`] carries the exact
    /// lowercase phase word both pre-lift `println!` templates and
    /// summary-pass labels embedded (`"Rust unit tests for {}..."`
    /// / `"Rust unit tests passed"`).
    #[test]
    fn phase_word_carries_pre_lift_bytes_at_both_variants() {
        assert_eq!(RustTestPhase::Unit.phase_word(), "unit");
        assert_eq!(RustTestPhase::Integration.phase_word(), "integration");
    }

    /// Pin: [`RustTestPhase::announce_glyph`] carries the exact
    /// U+1F9EA TEST TUBE / U+1F517 LINK emoji both pre-lift
    /// announce templates spelled.
    #[test]
    fn announce_glyph_carries_pre_lift_bytes_at_both_variants() {
        assert_eq!(RustTestPhase::Unit.announce_glyph(), "🧪");
        assert_eq!(RustTestPhase::Integration.announce_glyph(), "🔗");
    }

    /// Pin: [`RustTestPhase::cargo_argv`] carries the exact
    /// `cargo` sub-argv both pre-lift `cmd.args(...)` chains
    /// spelled inline. Any drift (a wildcard swap, an added flag,
    /// a re-order) flips this test rather than silently diverging
    /// the two consumer arms.
    #[test]
    fn cargo_argv_carries_pre_lift_bytes_at_both_variants() {
        assert_eq!(
            RustTestPhase::Unit.cargo_argv(),
            &["test", "--lib", "--bins"]
        );
        assert_eq!(
            RustTestPhase::Integration.cargo_argv(),
            &["test", "--test", "*"]
        );
    }

    /// Pin: [`RustTestPhase::op_label`] carries the exact
    /// `run_inherited_status` op-label both pre-lift sites
    /// spelled — this surfaces in the `"Failed to run {op}"`
    /// spawn-failure narrative from
    /// [`crate::retry::classify_inherited_status`].
    #[test]
    fn op_label_carries_pre_lift_bytes_at_both_variants() {
        assert_eq!(RustTestPhase::Unit.op_label(), "cargo test --lib --bins");
        assert_eq!(RustTestPhase::Integration.op_label(), "cargo test --test *");
    }

    /// Pin: [`RustTestPhase::context_msg`] carries the exact
    /// `.context("...")` phrase both pre-lift sites wrapped the
    /// `run_inherited_status(...)` future with. The two phrases
    /// intentionally differ (`"Failed to run cargo test"` names
    /// the unit-tests failure narrative even though its op-label
    /// is fully-qualified, matching pre-lift bytes verbatim).
    #[test]
    fn context_msg_carries_pre_lift_bytes_at_both_variants() {
        assert_eq!(
            RustTestPhase::Unit.context_msg(),
            "Failed to run cargo test"
        );
        assert_eq!(
            RustTestPhase::Integration.context_msg(),
            "Failed to run cargo integration tests"
        );
    }

    /// Projection pin: [`RustTestPhase::summary_pass_label`]
    /// composes the `"Rust <phase> tests passed"` label from the
    /// single phase-word axis, reproducing both pre-lift
    /// [`crate::ui::print_summary_pass`] literals verbatim.
    #[test]
    fn summary_pass_label_covers_both_pre_lift_variants() {
        assert_eq!(
            RustTestPhase::Unit.summary_pass_label(),
            "Rust unit tests passed"
        );
        assert_eq!(
            RustTestPhase::Integration.summary_pass_label(),
            "Rust integration tests passed"
        );
    }

    // ============================================================
    // Byte-oracle pair — write_rust_test_phase_announce_line at
    // both variants against the same pre-lift service-name
    // ============================================================

    /// Unit-variant byte-oracle. `colored` collapses its ANSI
    /// envelope under a non-tty test writer, so the emitted line
    /// reads as the bare un-ANSI'd bytes — the correct downstream
    /// shape a piped `forge test rust` invocation would see. Pins
    /// the leading two-space indent, the `🧪` glyph, the
    /// `Running Rust unit tests for` phrase, the interpolated
    /// service name, the trailing `...`, and the terminating `\n`
    /// the pre-lift `println!` template emitted.
    #[test]
    fn write_announce_line_unit_variant_carries_pre_lift_bytes() {
        let mut buf: Vec<u8> = Vec::new();
        write_rust_test_phase_announce_line(&mut buf, RustTestPhase::Unit, "billing-api")
            .expect("write against a Vec<u8> sink must succeed");
        let out = String::from_utf8(buf)
            .expect("announce line must emit valid UTF-8 (the pre-lift println! did)");
        assert!(
            out.contains("  🧪 Running Rust unit tests for "),
            "unit-variant announce line must open with the two-space \
             indent + `🧪` glyph + `Running Rust unit tests for ` \
             phrase (pre-lift literal from `run_rust_tests`'s \
             `if run_unit` arm). Got {out:?}"
        );
        assert!(
            out.contains("billing-api"),
            "unit-variant announce line must interpolate the \
             `service` argument verbatim. Got {out:?}"
        );
        assert!(
            out.ends_with("...\n"),
            "unit-variant announce line must terminate with `...\\n` \
             — the pre-lift `println!` template's trailing ellipsis \
             plus the implicit newline. Got {out:?}"
        );
    }

    /// Integration-variant byte-oracle sibling to the unit-variant
    /// test above. Pins the `🔗` glyph swap and the `integration`
    /// phase-word swap, keeping the rest of the line shape
    /// (indent, `Running Rust ... tests for {}...\n`, service
    /// interpolation) invariant across both variants.
    #[test]
    fn write_announce_line_integration_variant_carries_pre_lift_bytes() {
        let mut buf: Vec<u8> = Vec::new();
        write_rust_test_phase_announce_line(&mut buf, RustTestPhase::Integration, "billing-api")
            .expect("write against a Vec<u8> sink must succeed");
        let out = String::from_utf8(buf)
            .expect("announce line must emit valid UTF-8 (the pre-lift println! did)");
        assert!(
            out.contains("  🔗 Running Rust integration tests for "),
            "integration-variant announce line must open with the \
             two-space indent + `🔗` glyph + `Running Rust integration \
             tests for ` phrase (pre-lift literal from \
             `run_rust_tests`'s `if run_integration` arm). Got {out:?}"
        );
        assert!(
            out.contains("billing-api"),
            "integration-variant announce line must interpolate the \
             `service` argument verbatim. Got {out:?}"
        );
        assert!(
            out.ends_with("...\n"),
            "integration-variant announce line must terminate with \
             `...\\n`. Got {out:?}"
        );
    }

    // ============================================================
    // Whole-module shields on `commands/test.rs`
    // ============================================================

    /// Positive delegation shield: `commands/test.rs` must forward
    /// through [`announce_and_run_rust_test_phase`] at exactly two
    /// sites (one per pre-lift consumer: the `if run_unit` arm and
    /// the `if run_integration` arm of `run_rust_tests`). A fusion
    /// that folded the two arms into one call or dropped one of
    /// the phases silently fails here — the negative shields below
    /// would still pass, but the positive count would fall below
    /// the pre-lift census.
    #[test]
    fn test_forwards_through_announce_and_run_rust_test_phase_twice() {
        const SOURCE: &str = include_str!("test.rs");
        let body =
            crate::test_support::module_body_before_first_cfg_test(SOURCE, "commands/test.rs");
        const FORWARD_NEEDLE: &str = "rust_test_phase::announce_and_run_rust_test_phase(";
        let forward_hits = body.matches(FORWARD_NEEDLE).count();
        assert_eq!(
            forward_hits, 2,
            "commands/test.rs body must forward to \
             `crate::commands::rust_test_phase::\
             announce_and_run_rust_test_phase(...)` at exactly 2 \
             sites — one per pre-lift consumer (`if run_unit` and \
             `if run_integration` arms of `run_rust_tests`). Found \
             {forward_hits} forwarding hits."
        );
    }

    /// Negative caller shield: no raw `"Running Rust <phase>
    /// tests for {}..."` announce-line literal may live in
    /// `commands/test.rs` outside a delegation to the primitive.
    /// A future re-inline of either pre-lift announce line trips
    /// this shield rather than silently diverging the two
    /// consumer arms' visual grammar.
    #[test]
    fn no_raw_running_rust_tests_announce_literal_survives_in_test_module() {
        const SOURCE: &str = include_str!("test.rs");
        let body =
            crate::test_support::module_body_before_first_cfg_test(SOURCE, "commands/test.rs");
        for pre_lift in [
            "\"  {} Running Rust unit tests for {}...\"",
            "\"  {} Running Rust integration tests for {}...\"",
        ] {
            let hits = crate::test_support::code_line_hits(body, pre_lift);
            assert!(
                hits.is_empty(),
                "commands/test.rs must route every Rust-test-phase \
                 announce line through \
                 `crate::commands::rust_test_phase::\
                 announce_and_run_rust_test_phase(...)` so a future \
                 regression that re-inlines the pre-lift template \
                 `{pre_lift}` fails here rather than silently \
                 splitting the announce grammar across the primitive \
                 and the re-fused site. Offending lines: {hits:?}"
            );
        }
    }

    /// Negative caller shield: no raw `"Rust <phase> tests passed"`
    /// summary-pass literal may live in `commands/test.rs` outside
    /// a delegation to the primitive. Pairs with the announce-line
    /// shield above so a re-inline that copied only the summary
    /// (dropping the announce, or vice versa) still trips a shield.
    #[test]
    fn no_raw_rust_tests_passed_summary_literal_survives_in_test_module() {
        const SOURCE: &str = include_str!("test.rs");
        let body =
            crate::test_support::module_body_before_first_cfg_test(SOURCE, "commands/test.rs");
        for pre_lift in [
            "\"Rust unit tests passed\"",
            "\"Rust integration tests passed\"",
        ] {
            let hits = crate::test_support::code_line_hits(body, pre_lift);
            assert!(
                hits.is_empty(),
                "commands/test.rs must route every Rust-test-phase \
                 summary-pass ack through \
                 `crate::commands::rust_test_phase::\
                 announce_and_run_rust_test_phase(...)` so a future \
                 regression that re-inlines the pre-lift literal \
                 `{pre_lift}` fails here rather than silently \
                 splitting the ack grammar across the primitive and \
                 the re-fused site. Offending lines: {hits:?}"
            );
        }
    }

    /// Negative caller shield: no raw pre-lift `cargo test` op-label
    /// may live in `commands/test.rs` outside a delegation to the
    /// primitive. Pins the third of the three per-phase literal
    /// axes (announce line + summary label + op-label) so a
    /// re-inline that copied only the spawn (dropping the announce
    /// and summary) still trips a shield.
    #[test]
    fn no_raw_cargo_test_op_label_survives_in_test_module() {
        const SOURCE: &str = include_str!("test.rs");
        let body =
            crate::test_support::module_body_before_first_cfg_test(SOURCE, "commands/test.rs");
        for pre_lift in ["\"cargo test --lib --bins\"", "\"cargo test --test *\""] {
            let hits = crate::test_support::code_line_hits(body, pre_lift);
            assert!(
                hits.is_empty(),
                "commands/test.rs must route every Rust-test-phase \
                 spawn through \
                 `crate::commands::rust_test_phase::\
                 announce_and_run_rust_test_phase(...)` so a future \
                 regression that re-inlines the pre-lift op-label \
                 `{pre_lift}` fails here rather than silently \
                 splitting the spawn grammar across the primitive \
                 and the re-fused site. Offending lines: {hits:?}"
            );
        }
    }
}
