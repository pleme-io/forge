// Terminal UI utilities
// This module can be expanded with custom widgets, tables, etc.

use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use std::borrow::Cow;
use std::time::Duration;

/// Steady-tick cadence every pre-lift spinner site spelled inline as
/// `std::time::Duration::from_millis(100)`. Pinned as one named
/// constant so a future adjustment (a slower tick under CI-log
/// pressure, a faster tick under interactive TTY) happens at one
/// typed boundary rather than eight literal-argument sites.
const SPINNER_TICK: Duration = Duration::from_millis(100);

/// Palette [`styled_spinner`] accepts. Each variant spliced into the
/// fixed `{spinner:.<color>} {msg}` template every pre-lift consumer
/// spelled hard-coded verbatim, closed to the exact three colors the
/// pre-lift 8-site sibling class carried and nothing more — a new
/// palette entry is a deliberate additive edit, not an open call-site
/// choice.
///
/// # Compounding
///
/// Pre-lift each of the 8 sibling `.set_style(...)` sites nailed the
/// color into a string literal at the call site; a rename that
/// misspells `.green` as `.grne` would compile and silently degrade the
/// spinner to the indicatif default palette. Post-lift the mapping
/// [`SpinnerStyle`] → template string lives in ONE match arm; the enum
/// is closed, so a future variant added without an arm fails the
/// exhaustiveness check at build time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpinnerStyle {
    /// Success-track spinner (`{spinner:.green} {msg}`). 5 pre-lift
    /// sites: `commands/{build, deploy, github_runner_ci (×2),
    /// comprehensive_release}.rs` — each wraps a long-running "happy
    /// path" spawn (nix build, git commit-and-push, cargo test).
    Green,
    /// Test-run spinner (`{spinner:.cyan} {msg}`). 2 pre-lift sites:
    /// `commands/{integration_tests, test}.rs` first-attempt suite
    /// executions.
    Cyan,
    /// Retry-attempt spinner (`{spinner:.yellow} {msg}`). 1 pre-lift
    /// site: `commands/integration_tests.rs` retry loop —
    /// re-execution of a suite whose first attempt failed.
    Yellow,
}

impl SpinnerStyle {
    /// Full [`indicatif`] template string spliced by
    /// [`ProgressStyle::default_spinner`] onto the returned spinner.
    ///
    /// Kept as a match on the closed enum (rather than
    /// `format!("{{spinner:.{}}} {{msg}}", self.color())`) so the
    /// returned `&'static str` needs no allocation and the template
    /// shape stays greppable — a fleet-wide sweep for
    /// `{spinner:.green} {msg}` finds this arm, not a `format!` call
    /// whose runtime output nobody can grep for.
    fn template(self) -> &'static str {
        match self {
            SpinnerStyle::Green => "{spinner:.green} {msg}",
            SpinnerStyle::Cyan => "{spinner:.cyan} {msg}",
            SpinnerStyle::Yellow => "{spinner:.yellow} {msg}",
        }
    }
}

/// Build a running spinner-flavored [`ProgressBar`] pre-loaded with the
/// canonical `{spinner:.<color>} {msg}` template, an initial `message`,
/// and the [`SPINNER_TICK`] steady-tick cadence every pre-lift
/// consumer spelled inline.
///
/// # Compounding
///
/// Pre-lift 8 sibling sites across
/// `commands/{build, deploy, github_runner_ci (×2), comprehensive_release,
/// integration_tests (×2), test}.rs` each spelled the same 4-step block:
///
/// ```text
/// let <name> = ProgressBar::new_spinner();
/// <name>.set_style(
///     ProgressStyle::default_spinner()
///         .template("{spinner:.<color>} {msg}")
///         .unwrap(),
/// );
/// <name>.set_message(<literal-or-format!>);
/// <name>.enable_steady_tick(std::time::Duration::from_millis(100));
/// ```
///
/// Post-lift each collapses to a single typed constructor call:
///
/// ```text
/// let <name> = ui::styled_spinner(ui::SpinnerStyle::Green, "Building with Nix...");
/// ```
///
/// The steady-tick cadence, the template shape, the `.unwrap()` on a
/// static template (which we upgrade to a labeled `.expect`), and the
/// [`SpinnerStyle`] → color-token mapping all canonicalize at ONE typed
/// boundary. A future adjustment (a `.dim`-suffixed spinner, a slower
/// tick under piped stdout, a bracketed template) happens in one place,
/// not eight.
///
/// # `impl Into<Cow<'static, str>>` message parameter
///
/// [`ProgressBar::set_message`] accepts `impl Into<Cow<'static, str>>`;
/// this primitive exposes the same accepting shape so both the 5
/// `&'static str` literal sites (`"Building with Nix..."`, `"Pushing to
/// main..."`, `"Running cargo test --lib --bins..."`) and the 3
/// `format!`-computed owned-`String` sites (`format!("Running {}",
/// suite.name)`, `format!("Running {} tests...", suite_name)`,
/// `format!("Running {} (attempt {}/{})", suite.name, attempts,
/// max_attempts)`) bind at the call site with no per-caller conversion.
pub fn styled_spinner(style: SpinnerStyle, message: impl Into<Cow<'static, str>>) -> ProgressBar {
    let bar = ProgressBar::new_spinner();
    bar.set_style(
        ProgressStyle::default_spinner()
            .template(style.template())
            .expect("SpinnerStyle::template returns a well-formed indicatif template"),
    );
    bar.set_message(message);
    bar.enable_steady_tick(SPINNER_TICK);
    bar
}

/// Template every pre-lift determinate `ProgressBar::new(<total>)` site
/// spelled inline verbatim. Pinned as one named constant so a future
/// visual adjustment (a wider `{bar:40}` track, a different color pair,
/// a `{eta}` slot) happens at ONE typed boundary rather than four
/// literal-argument sites.
const PROGRESS_BAR_TEMPLATE: &str = "{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} {msg}";

/// Fill / edge / empty glyph triple every pre-lift determinate site fed
/// to [`ProgressStyle::progress_chars`] verbatim. Same one-boundary
/// pinning as [`PROGRESS_BAR_TEMPLATE`].
const PROGRESS_BAR_CHARS: &str = "#>-";

/// Build a determinate [`ProgressBar`] with `total` steps, pre-loaded
/// with the canonical
/// `{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} {msg}` template
/// and `"#>-"` progress-char triple every pre-lift consumer spelled
/// inline. Sibling to [`styled_spinner`] — the spinner-flavored bar
/// with no length — pinning the length-carrying flavor at the same
/// `crate::ui` typed boundary.
///
/// # Compounding
///
/// Pre-lift 4 sibling sites across `commands/{pangea, bootstrap, push,
/// github_runner_ci}.rs` each spelled the same 3-step block (two of
/// them wrapped in a file-local `fn create_progress_bar(total: u64) ->
/// ProgressBar` helper that this primitive supersedes):
///
/// ```text
/// let <name> = ProgressBar::new(<total>);
/// <name>.set_style(
///     ProgressStyle::default_bar()
///         .template("{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} {msg}")
///         .unwrap()                          // push.rs, github_runner_ci.rs
///         .progress_chars("#>-"),
/// );
/// ```
///
/// or
///
/// ```text
///         .expect("Invalid progress bar template")   // pangea.rs, bootstrap.rs
/// ```
///
/// Post-lift each collapses to:
///
/// ```text
/// let <name> = ui::styled_progress_bar(<total>);
/// ```
///
/// The template shape, the color pair, the progress-char triple, and
/// the `.expect` label on a static template (which the 2 raw
/// `.unwrap()` sites also inherit) all canonicalize at ONE typed
/// boundary. A future adjustment (a `{eta}` slot, a widened `{bar:60}`
/// track, a different color pair) happens in one place, not four.
///
/// The primitive does NOT set a message — each pre-lift consumer sets
/// a per-iteration message via `pb.set_message(format!(...))` inside
/// its own loop body, and the finish message via
/// `pb.finish_with_message(...)`. Both of those bindings remain at the
/// call site.
pub fn styled_progress_bar(total: u64) -> ProgressBar {
    let bar = ProgressBar::new(total);
    bar.set_style(
        ProgressStyle::default_bar()
            .template(PROGRESS_BAR_TEMPLATE)
            .expect("PROGRESS_BAR_TEMPLATE is a well-formed indicatif template")
            .progress_chars(PROGRESS_BAR_CHARS),
    );
    bar
}

/// Prints the three-line success banner every pre-lift consumer
/// spelled inline as three sibling `println!` calls: a
/// `bright_green`-tinted `"━"`-rule of `width` glyphs, the `message` in
/// `green().bold()`, and a second identical rule. Marks a terminal-
/// success milestone at 7 sibling call sites across
/// `commands/{developer_tools, rust_service, web_service}.rs` — the
/// pre-lift `println!("{}", "━".repeat(<width>).bright_green());
/// println!("{}", <MSG>.green().bold()); println!("{}",
/// "━".repeat(<width>).bright_green());` stanza — so a future palette
/// shift (a swap of the rule character, a `bright_green`→dedicated
/// success color, a hoist of the width onto a `MilestoneKind` closed
/// enum) happens at ONE site rather than seven.
///
/// Delegates to [`write_success_banner`] against `std::io::stdout()`;
/// the writer split exists so the fail-before-pass test can pin the
/// three-line, message-order contract by inspecting emitted bytes
/// rather than shelling out and grepping stdout.
///
/// # Compounding
///
/// The three consumer sites share a visual grammar the CLI operator
/// has been trained to read (bar → highlighted headline → bar) — but
/// each pre-lift restatement is a fresh chance for that grammar to
/// drift: a swap of `.green()` for `.bright_green()` on the headline
/// silently loses the visual contrast against the rule, a swap of the
/// rule character in one site alone breaks operator scanning across
/// commands. The primitive collapses seven contract restatements onto
/// ONE typed function whose body a future palette swap has to hit
/// exactly once.
pub fn print_success_banner(width: usize, message: &str) {
    let _ = write_success_banner(&mut std::io::stdout().lock(), width, message);
}

/// Writer-taking sibling to [`print_success_banner`]. Emits the three
/// banner lines (`bright_green` rule, `green().bold()` message,
/// `bright_green` rule) via [`writeln!`] against the supplied writer.
/// [`print_success_banner`] is the stdout adapter; this variant exists
/// so tests can pin the line count and message-order contract without
/// capturing stdout.
pub fn write_success_banner<W: std::io::Write>(
    w: &mut W,
    width: usize,
    message: &str,
) -> std::io::Result<()> {
    let bar = "━".repeat(width);
    writeln!(w, "{}", bar.as_str().bright_green())?;
    writeln!(w, "{}", message.green().bold())?;
    writeln!(w, "{}", bar.as_str().bright_green())?;
    Ok(())
}

/// Rule-character glyph every pre-lift release-milestone site fed to
/// [`String::repeat`] verbatim. Pinned as one named constant so a
/// future swap of the release-milestone grammar's rule character (a
/// promotion to `━` to unify with [`write_success_banner`]'s heavy
/// rule, a demotion to `-` for a leaner readout) happens at ONE typed
/// boundary rather than three literal-argument sites.
const RELEASE_STAGE_BANNER_RULE_CHAR: &str = "=";

/// Rule width every pre-lift release-milestone site spelled inline as
/// the literal `60`. Same one-boundary pinning as
/// [`RELEASE_STAGE_BANNER_RULE_CHAR`]; the width is distinct from the
/// per-caller `width` parameter [`write_success_banner`] carries
/// because the release-milestone grammar is a fixed-shape terminal
/// banner (not a variable-width headline) — every consumer chose 60,
/// so 60 lives in the primitive rather than repeating at every call
/// site.
const RELEASE_STAGE_BANNER_WIDTH: usize = 60;

/// Prints the three-line release-milestone banner every pre-lift
/// consumer spelled inline as a `"=".repeat(60).bright_green()` rule,
/// a composite headline of the form `<STAGE> COMPLETE` in `green.bold`,
/// then `<product>` in `cyan.bold`, then `(<suffix>)` in `dimmed`, and
/// a second identical rule. Marks a terminal-milestone in the product
/// release pipeline at 3 sibling call sites across
/// `commands/{rollback, product_release (×2)}.rs` — the pre-lift
/// `println!("{}", "=".repeat(60).bright_green()); println!("{} {} {}",
/// "<STAGE> COMPLETE".green().bold(), product.cyan().bold(),
/// format!("(<...>)", ...).dimmed()); println!("{}",
/// "=".repeat(60).bright_green());` stanza — so a future palette shift
/// against rule-char, headline color, or parenthesization happens at
/// ONE site rather than three.
///
/// Delegates to [`write_release_stage_banner`] against
/// `std::io::stdout()`; the writer split exists so the fail-before-pass
/// test can pin the three-line, palette, and headline-composition
/// contract by inspecting emitted bytes rather than shelling out and
/// grepping stdout.
///
/// # Distinct from [`print_success_banner`]
///
/// [`print_success_banner`] carries a `━`-rule + single-message
/// headline grammar the 7 pre-lift consumer sites in
/// `commands/{developer_tools, rust_service, web_service}.rs` used to
/// mark a single-command terminal-success milestone. This primitive
/// carries a **distinct** `=`-rule + composite `<STAGE> + <product> +
/// (<suffix>)` headline grammar the 3 pre-lift consumer sites in
/// `commands/{rollback, product_release}.rs` used to mark a
/// product-release-lifecycle milestone — a shape where the stage name
/// varies (ROLLBACK / BUILD / RELEASE) and the product name and a
/// stage-specific suffix (target env, git sha, or both) are
/// visually separated by color. The two primitives coexist rather
/// than one subsuming the other because the visual grammars an
/// operator has been trained to read differ — a single-command
/// success is a `━` bar, a product-release milestone is an `=` bar.
///
/// # Compounding
///
/// Pre-lift each of the 3 consumer sites restated the entire
/// three-line stanza — a swap of the rule character in one site
/// alone (an `=` demoted to `-` in `rollback.rs` while
/// `product_release.rs` stayed on `=`) silently splits the
/// release-lifecycle visual grammar, a `.green().bold()` promoted
/// to `.bright_green().bold()` on the stage headline loses the
/// contrast against the rule, a `.dimmed()` dropped from the
/// suffix promotes non-load-bearing metadata onto operator eye
/// alongside the stage name. Post-lift the primitive collapses
/// all three restatements onto ONE typed function; a future
/// palette adjustment hits one body, not three.
pub fn print_release_stage_banner(stage: &str, product: &str, suffix: &str) {
    let _ = write_release_stage_banner(&mut std::io::stdout().lock(), stage, product, suffix);
}

/// Writer-taking sibling to [`print_release_stage_banner`]. Emits the
/// three release-milestone banner lines (`bright_green` `=` rule,
/// `<stage>.green().bold() + <product>.cyan().bold() +
/// format!("({})", <suffix>).dimmed()` headline, `bright_green` `=`
/// rule) via [`writeln!`] against the supplied writer.
/// [`print_release_stage_banner`] is the stdout adapter; this variant
/// exists so tests can pin the line count, palette, and
/// headline-composition contract without capturing stdout.
pub fn write_release_stage_banner<W: std::io::Write>(
    w: &mut W,
    stage: &str,
    product: &str,
    suffix: &str,
) -> std::io::Result<()> {
    let bar = RELEASE_STAGE_BANNER_RULE_CHAR.repeat(RELEASE_STAGE_BANNER_WIDTH);
    writeln!(w, "{}", bar.as_str().bright_green())?;
    writeln!(
        w,
        "{} {} {}",
        stage.green().bold(),
        product.cyan().bold(),
        format!("({})", suffix).dimmed()
    )?;
    writeln!(w, "{}", bar.as_str().bright_green())?;
    Ok(())
}

/// Rule glyph every pre-lift section-header site fed to the literal
/// `"════════════════════════════════════════════════"`. Pinned as
/// one named constant so a future swap of the section-header rule
/// character (a promotion to `━` to unify with
/// [`write_success_banner`], a demotion to `-` for a leaner readout)
/// happens at ONE typed boundary rather than 16 literal-argument
/// sites (two rules per stanza across 8 consumer sites).
const SECTION_HEADER_RULE: &str = "════════════════════════════════════════════════";

/// Two-space indent every pre-lift section-header site prepended to
/// the title via the literal `"  <TITLE>".bold()`. Pinned as one
/// named constant so a future swap of the indent width (a tab, four
/// spaces, no indent under a leaner section grammar) happens at ONE
/// typed boundary rather than eight literal-argument sites.
const SECTION_HEADER_TITLE_INDENT: &str = "  ";

/// Prints the seven-line section-header banner every pre-lift consumer
/// spelled inline as a blank line, a
/// `"════════════════════════════════════════════════".bold()` rule,
/// a `"  <TITLE>".bold()` indented title, a second identical rule,
/// and a trailing blank line. Marks the opening of a section in a
/// pipeline run at 8 sibling call sites across
/// `commands/{codegen, post_deploy_verification, prerelease (×2),
/// rebac_validation, sync (×3)}.rs` — the pre-lift 7-line stanza —
/// so a future palette shift against rule-char, rule-width, indent
/// glyph, or title emphasis happens at ONE site rather than eight.
///
/// Delegates to [`write_section_header`] against
/// `std::io::stdout()`; the writer split exists so the
/// fail-before-pass test can pin the five-line body, palette, and
/// title-indent contract by inspecting emitted bytes rather than
/// shelling out and grepping stdout.
///
/// # Distinct from [`print_header`], [`print_success_banner`], and [`print_release_stage_banner`]
///
/// [`print_header`] carries a `╔═…═╗` boxed grammar in `bright_blue`
/// used for top-level command titles.
///
/// [`print_success_banner`] carries a `━`-rule + single-message
/// terminal-success grammar in `bright_green` used to mark the end
/// of a build-tools regeneration.
///
/// [`print_release_stage_banner`] carries a `=`-rule + composite
/// `<STAGE> + <product> + (<suffix>)` headline grammar used to mark
/// a product-release-lifecycle milestone.
///
/// This primitive carries a **distinct** `═`-rule + bold-title
/// grammar used to mark the OPENING of a section within a pipeline
/// (e.g. `Schema Export + Codegen`, `Gate Summary`, `ReBAC
/// Validation`). The four primitives coexist rather than one
/// subsuming the other because the visual grammars an operator has
/// been trained to read differ — a top-level command title is a
/// boxed blue banner, a section opening within a pipeline is a
/// double-rule bold title, a terminal success is a heavy-rule green
/// banner, a release-lifecycle milestone is an equals-rule composite
/// headline.
///
/// # Compounding
///
/// Pre-lift each of the 8 consumer sites restated the entire
/// seven-line stanza (two `println!` blanks framing a rule +
/// `"  <TITLE>".bold()` + rule triple). A swap of the rule character
/// in one site alone (an `═` demoted to `-` in `sync.rs` while
/// `prerelease.rs` stayed on `═`) silently splits the section-opening
/// visual grammar across the pipeline. A `.bold()` dropped from the
/// title on one site alone loses the emphasis against the rule and
/// promotes body text over the section boundary. A width drift
/// between `.repeat(48)` and `.repeat(60)` in one site alone lines
/// two adjacent sections against visibly different rules. Post-lift
/// the primitive collapses all eight restatements onto ONE typed
/// function; a future palette adjustment hits one body, not eight.
pub fn print_section_header(title: &str) {
    println!();
    let _ = write_section_header(&mut std::io::stdout().lock(), title);
    println!();
}

/// Writer-taking sibling to [`print_section_header`]. Emits the
/// three section-header body lines (`bold` `═` rule,
/// `SECTION_HEADER_TITLE_INDENT + <title>` in `bold`, `bold` `═`
/// rule) via [`writeln!`] against the supplied writer.
/// [`print_section_header`] is the stdout adapter (and adds the
/// framing blank lines the pre-lift stanza carried); this variant
/// exists so tests can pin the body line count, palette, and
/// title-indent contract without capturing stdout.
pub fn write_section_header<W: std::io::Write>(w: &mut W, title: &str) -> std::io::Result<()> {
    writeln!(w, "{}", SECTION_HEADER_RULE.bold())?;
    writeln!(
        w,
        "{}",
        format!("{}{}", SECTION_HEADER_TITLE_INDENT, title).bold()
    )?;
    writeln!(w, "{}", SECTION_HEADER_RULE.bold())?;
    Ok(())
}

pub fn print_header(title: &str) {
    println!();
    println!(
        "{}",
        "╔════════════════════════════════════════════════════════════╗".bright_blue()
    );
    println!("{}", format!("║  {:<58}║", title).bright_blue());
    println!(
        "{}",
        "╚════════════════════════════════════════════════════════════╝".bright_blue()
    );
    println!();
}

pub fn print_success(message: &str) {
    println!("{}", format!("✅ {}", message).bright_green().bold());
}

pub fn print_error(message: &str) {
    eprintln!("{}", format!("❌ {}", message).bright_red().bold());
}

pub fn print_info(message: &str) {
    println!("{}", format!("ℹ️  {}", message).bright_cyan());
}

pub fn print_warning(message: &str) {
    println!("{}", format!("⚠️  {}", message).bright_yellow());
}

/// Prints the one-line bold step-heading grammar 44 pre-lift consumer sites
/// spelled inline as `println!("{}", "<TITLE>".bold());` across 12 command
/// modules (`commands/{developer_tools, codegen, product_release, bootstrap,
/// federation_tests, sync, migration_new, rollback, prerelease,
/// frontend_validation, codegen_validation, post_deploy_verification}.rs`).
/// Marks the start of a step, gate, phase, or list within a command's
/// in-body readout ("G1: cargo check", "Step 2: SeaORM Entity Generation",
/// "Phase 1: Push artifacts", "Rollback Plan:", "🏗️  Architecture:", …).
///
/// # Distinct from the other `ui::print_*` primitives
///
/// [`print_header`] is a `╔═╗` boxed top-level command title in
/// `bright_blue`. [`print_section_header`] is a `═`-rule + bold-title
/// triple around a section OPENING within a pipeline.
/// [`print_success_banner`] and [`print_release_stage_banner`] are `━` /
/// `=` rule + colored-message COMPLETION banners. This primitive carries
/// the LEANEST opening — a single bold label, no rule, no color, no
/// framing blank — every pre-lift consumer used inside a command as an
/// in-body milestone marker one step below a full section boundary.
///
/// # Compounding
///
/// Pre-lift 44 sibling sites each restated the `println!("{}", "<TITLE>".bold())`
/// grammar verbatim. A future palette adjustment (a green checkmark
/// prefix, a `[Gn/N]` step-numbering scheme, an OTLP `step_start`
/// observability event, a swap of `.bold()` for `.underline()` under
/// a leaner grammar) had to hit 44 sites in lockstep or drift the visual
/// grammar; post-lift it hits ONE typed body. Delegates to
/// [`write_step_heading`] against `std::io::stdout()`; the writer split
/// exists so the fail-before-pass test can pin the single-line body and
/// palette contract by inspecting emitted bytes rather than shelling out
/// and grepping stdout.
pub fn print_step_heading(title: &str) {
    let _ = write_step_heading(&mut std::io::stdout().lock(), title);
}

/// Writer-taking sibling to [`print_step_heading`]. Emits the single
/// `<title>.bold()` line via [`writeln!`] against the supplied writer.
/// [`print_step_heading`] is the stdout adapter; this variant exists so
/// tests can pin the one-line body and `\x1b[1m` bold sequence without
/// capturing stdout.
pub fn write_step_heading<W: std::io::Write>(w: &mut W, title: &str) -> std::io::Result<()> {
    writeln!(w, "{}", title.bold())
}

#[cfg(test)]
mod tests {
    use super::{styled_spinner, SpinnerStyle, SPINNER_TICK};
    use std::sync::Mutex;
    use std::time::Duration;

    /// Serializes the three banner tests that flip `colored`'s global
    /// override to force ANSI emission against a `Vec<u8>` writer. The
    /// override is process-global; without a shared guard, cargo's
    /// default parallel test runner can schedule one test's
    /// [`colored::control::unset_override`] between another's
    /// `set_override(true)` and its `writeln!`, leaving the writer's
    /// bytes stripped of the very ANSI sequences those tests then
    /// assert against. Every banner test that touches the override
    /// acquires this mutex for the entire set-write-unset window.
    static ANSI_OVERRIDE_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn spinner_style_template_pins_the_three_pre_lift_color_variants() {
        // Fail-before-pass envelope for the SpinnerStyle → template
        // mapping: pre-lift 8 sibling call sites each hard-coded the
        // color token verbatim, so a silent rename inside `template()`
        // (`.green` → `.grn`, `.cyan` dropped altogether) would compile
        // AND run — the indicatif parser accepts an unknown color
        // token by silently falling back to the default palette
        // rather than surfacing a template error. The pinning
        // assertions turn a silent color regression into a fail-loud
        // test failure. The closed enum's own exhaustiveness check
        // separately guards a new variant landed without an arm.
        assert_eq!(SpinnerStyle::Green.template(), "{spinner:.green} {msg}");
        assert_eq!(SpinnerStyle::Cyan.template(), "{spinner:.cyan} {msg}");
        assert_eq!(SpinnerStyle::Yellow.template(), "{spinner:.yellow} {msg}");
    }

    #[test]
    fn spinner_tick_carries_the_hundred_millisecond_pre_lift_cadence() {
        // Pre-lift every sibling site spelled
        // `enable_steady_tick(std::time::Duration::from_millis(100))`
        // verbatim; the fusion moves that literal into ONE named
        // constant. If the constant ever drifts (`from_millis(250)`,
        // `from_secs(1)`), the eight visual-cadence contracts drift
        // together silently, so pin the constant's value here.
        assert_eq!(SPINNER_TICK, Duration::from_millis(100));
    }

    #[test]
    fn styled_spinner_accepts_static_str_literal_message() {
        // Pre-lift 5 of the 8 consumer sites passed a `&'static str`
        // literal (`"Building with Nix..."`, `"Pushing to main..."`,
        // `"Running cargo test --lib --bins..."`). The primitive's
        // `impl Into<Cow<'static, str>>` bound must accept that shape
        // without a per-caller `.to_string()` bridge; this test
        // fails to compile if the bound narrows in a way that
        // rejects `&'static str`.
        let bar = styled_spinner(SpinnerStyle::Green, "Building with Nix...");
        bar.finish_and_clear();
    }

    #[test]
    fn styled_spinner_accepts_format_computed_owned_message() {
        // Pre-lift the remaining 3 of 8 consumer sites fed
        // `set_message` a `format!`-computed owned `String`
        // (`format!("Running {}", suite.name)`,
        // `format!("Running {} tests...", suite_name)`,
        // `format!("Running {} (attempt {}/{})", ...)`).  The
        // primitive's bound must accept the owned shape as freely as
        // the `&'static str` case; this test fails to compile if the
        // bound narrows to `&'static str` alone.
        let suite = "webhook";
        let owned: String = format!("Running {}", suite);
        let bar = styled_spinner(SpinnerStyle::Cyan, owned);
        bar.finish_and_clear();
    }

    #[test]
    fn progress_bar_template_pins_the_pre_lift_template_string_verbatim() {
        // Fail-before-pass envelope for the determinate-bar template.
        // Pre-lift 4 sibling sites (`commands/{pangea, bootstrap, push,
        // github_runner_ci}.rs`) each spelled this exact template
        // literal inline. If the constant ever silently drifts (an
        // extra space, `.cyan/blue` → `.blue/cyan`, a `{eta}` slot
        // slipped in), the four determinate-bar visual contracts drift
        // together, so pin the string here.
        assert_eq!(
            super::PROGRESS_BAR_TEMPLATE,
            "{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} {msg}"
        );
    }

    #[test]
    fn progress_bar_chars_pins_the_pre_lift_fill_edge_empty_triple_verbatim() {
        // Same fail-before-pass envelope for the `progress_chars` triple.
        // Every pre-lift site spelled `.progress_chars("#>-")` verbatim;
        // a silent rewrite to `"=>-"`, `"##-"`, or `"#-"` would compile
        // and render four progress bars that visually diverge from what
        // every consumer originally set — so pin the triple here.
        assert_eq!(super::PROGRESS_BAR_CHARS, "#>-");
    }

    #[test]
    fn styled_progress_bar_returns_a_determinate_bar_with_the_requested_length() {
        // Fail-before-pass envelope for the flavor-and-length contract:
        // a determinate bar returns `Some(<total>)` from `.length()`,
        // in contrast to `styled_spinner`'s spinner-flavored bar which
        // returns `None`. Pre-lift each of the 4 consumer sites
        // constructed via `ProgressBar::new(<total>)`, never
        // `new_spinner()`; a fusion that accidentally routed to
        // `new_spinner()` would render an animated glyph with no
        // fraction and no `{pos}/{len}` slot, silently degrading every
        // pre-lift consumer's push-progress readout. The specific
        // length round-trip also nails that `total` reaches
        // `ProgressBar::new` unwrapped.
        let bar = super::styled_progress_bar(7);
        assert_eq!(
            bar.length(),
            Some(7),
            "styled_progress_bar must return a determinate bar carrying \
             the requested `total` as its length, not a spinner-flavored bar"
        );
        bar.finish_and_clear();
    }

    /// Fail-before-pass envelope for [`super::write_success_banner`].
    /// Pins the three-line body order every pre-lift consumer spelled
    /// verbatim (`"━".repeat(width).bright_green()` rule,
    /// `<MSG>.green().bold()` message, `"━".repeat(width).bright_green()`
    /// rule). A silent contract drift a future rewrite might introduce —
    /// dropping one bar to two `println!`s, swapping the message and a
    /// bar, promoting the message color to `bright_green` and losing the
    /// visual-contrast contract against the rule, hoisting the rule
    /// character off `━` in one branch alone — flips this assertion
    /// rather than compiling and silently diverging the seven consumer
    /// sites' visual grammar.
    #[test]
    fn write_success_banner_emits_three_bar_message_bar_lines_in_order() {
        // Force ANSI emission so the palette contract survives a test
        // runner attached to a non-tty (colored auto-drops sequences).
        // Hold the shared [`ANSI_OVERRIDE_LOCK`] across the whole
        // set-write-unset window so a peer banner test's `unset` can
        // never strand this writer between colored's on/off flip.
        let _override_guard = ANSI_OVERRIDE_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        colored::control::set_override(true);

        let mut buf: Vec<u8> = Vec::new();
        super::write_success_banner(&mut buf, 80, "✅ REGENERATION COMPLETE")
            .expect("write_success_banner against a Vec<u8> writer must succeed");

        colored::control::unset_override();

        let out = String::from_utf8(buf)
            .expect("write_success_banner must emit valid UTF-8 (the pre-lift println!s did)");

        // Exactly three lines — the pre-lift stanza is three
        // `println!`s, not two, and not four. A refactor that drops or
        // adds a bar fails here.
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(
            lines.len(),
            3,
            "write_success_banner must emit exactly three lines \
             (rule, message, rule) — the pre-lift stanza is three \
             `println!`s; got {}:\n{}",
            lines.len(),
            out
        );

        // The bar glyph appears in the outer two lines but never in
        // the middle line; the message text appears in the middle line
        // but never in the outer lines. A swap of the middle line and
        // a bar (a fusion that reorders the `writeln!`s) fails here.
        assert!(
            lines[0].contains('━'),
            "line 0 must be a `━` rule; got {:?}",
            lines[0]
        );
        assert!(
            lines[2].contains('━'),
            "line 2 must be a `━` rule; got {:?}",
            lines[2]
        );
        assert!(
            !lines[1].contains('━'),
            "line 1 must NOT contain the rule glyph — it is the \
             message line; got {:?}",
            lines[1]
        );
        assert!(
            lines[1].contains("REGENERATION COMPLETE"),
            "line 1 must carry the message verbatim; got {:?}",
            lines[1]
        );

        // The rule width reaches `String::repeat` unwrapped — a fusion
        // that hoists the width off the parameter and pins it to a
        // constant fails here.
        let bar_glyph_count = lines[0].chars().filter(|c| *c == '━').count();
        assert_eq!(
            bar_glyph_count, 80,
            "line 0 must contain exactly `width` (80) `━` glyphs; got {}",
            bar_glyph_count
        );

        // The palette contract: the rule lines carry the
        // `bright_green` ANSI sequence and the message line carries
        // the `bold` sequence. A silent swap of `.bright_green()` for
        // `.green()` on the rule loses the contrast against the
        // message — pin the sequences here.
        assert!(
            lines[0].contains("\x1b[92m"),
            "line 0 must carry the `bright_green` ANSI sequence \
             (`\\x1b[92m`); got {:?}",
            lines[0]
        );
        assert!(
            lines[1].contains("\x1b[1;32m") || lines[1].contains("\x1b[32;1m"),
            "line 1 must carry the `green` + `bold` ANSI sequence; got {:?}",
            lines[1]
        );
    }

    /// Fail-before-pass envelope for [`super::write_release_stage_banner`].
    /// Pins the three-line body order every pre-lift consumer spelled
    /// verbatim (`"=".repeat(60).bright_green()` rule,
    /// `<STAGE>.green().bold() + <product>.cyan().bold() +
    /// format!("({})", <suffix>).dimmed()` composite headline,
    /// `"=".repeat(60).bright_green()` rule). A silent contract drift
    /// a future rewrite might introduce — dropping one bar to two
    /// `writeln!`s, swapping the message and a bar, promoting the
    /// stage color to `bright_green` and losing the visual-contrast
    /// contract against the rule, hoisting the rule character off `=`
    /// in one branch alone, dropping the parentheses around the
    /// suffix, dropping `.dimmed()` from the suffix so it competes
    /// with the stage for operator eye — flips this assertion rather
    /// than compiling and silently diverging the three consumer
    /// sites' visual grammar.
    #[test]
    fn write_release_stage_banner_emits_three_bar_headline_bar_lines_in_order() {
        // Force ANSI emission so the palette contract survives a test
        // runner attached to a non-tty (colored auto-drops sequences).
        // Hold the shared [`ANSI_OVERRIDE_LOCK`] across the whole
        // set-write-unset window so a peer banner test's `unset` can
        // never strand this writer between colored's on/off flip.
        let _override_guard = ANSI_OVERRIDE_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        colored::control::set_override(true);

        let mut buf: Vec<u8> = Vec::new();
        super::write_release_stage_banner(&mut buf, "RELEASE COMPLETE", "kenshi", "prod, abc123")
            .expect("write_release_stage_banner against a Vec<u8> writer must succeed");

        colored::control::unset_override();

        let out = String::from_utf8(buf).expect(
            "write_release_stage_banner must emit valid UTF-8 (the pre-lift println!s did)",
        );

        // Exactly three lines — the pre-lift stanza is three
        // `println!`s, not two, and not four. A refactor that drops
        // or adds a bar fails here.
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(
            lines.len(),
            3,
            "write_release_stage_banner must emit exactly three lines \
             (rule, headline, rule) — the pre-lift stanza is three \
             `println!`s; got {}:\n{}",
            lines.len(),
            out
        );

        // The `=` rule glyph appears in the outer two lines but never
        // in the middle line; every headline component appears in the
        // middle line but never in the outer lines. A swap of the
        // middle line and a bar (a fusion that reorders the
        // `writeln!`s) fails here.
        assert!(
            lines[0].contains('='),
            "line 0 must be an `=` rule; got {:?}",
            lines[0]
        );
        assert!(
            lines[2].contains('='),
            "line 2 must be an `=` rule; got {:?}",
            lines[2]
        );
        assert!(
            !lines[1].contains('='),
            "line 1 must NOT contain the rule glyph — it is the \
             composite headline line; got {:?}",
            lines[1]
        );
        assert!(
            lines[1].contains("RELEASE COMPLETE"),
            "line 1 must carry the stage headline verbatim; got {:?}",
            lines[1]
        );
        assert!(
            lines[1].contains("kenshi"),
            "line 1 must carry the product name verbatim; got {:?}",
            lines[1]
        );
        assert!(
            lines[1].contains("(prod, abc123)"),
            "line 1 must wrap the suffix in parentheses — the pre-lift \
             stanza wrapped it via `format!(\"({{}})\", <suffix>)`, so \
             a fusion that drops the parenthesization fails here; got {:?}",
            lines[1]
        );

        // The rule width is pinned inside the primitive at 60 (every
        // pre-lift consumer spelled `.repeat(60)` verbatim). A fusion
        // that hoists the width off the constant fails here.
        let rule_glyph_count = lines[0].chars().filter(|c| *c == '=').count();
        assert_eq!(
            rule_glyph_count, 60,
            "line 0 must contain exactly `RELEASE_STAGE_BANNER_WIDTH` \
             (60) `=` glyphs; got {}",
            rule_glyph_count
        );

        // The palette contract: the rule lines carry the `bright_green`
        // ANSI sequence; the stage carries `green` + `bold`; the
        // product carries `cyan` + `bold`; the parenthesized suffix
        // carries the `dimmed` (`\x1b[2m`) sequence. A silent swap of
        // any of these loses the visual grammar's meaning — the stage
        // and the product would no longer be visually separable, the
        // suffix would promote off the dimmed track onto operator eye
        // alongside the stage. Pin every sequence here.
        assert!(
            lines[0].contains("\x1b[92m"),
            "line 0 must carry the `bright_green` ANSI sequence \
             (`\\x1b[92m`); got {:?}",
            lines[0]
        );
        assert!(
            lines[1].contains("\x1b[1;32m") || lines[1].contains("\x1b[32;1m"),
            "line 1 stage must carry the `green` + `bold` ANSI sequence; \
             got {:?}",
            lines[1]
        );
        assert!(
            lines[1].contains("\x1b[1;36m") || lines[1].contains("\x1b[36;1m"),
            "line 1 product must carry the `cyan` + `bold` ANSI sequence; \
             got {:?}",
            lines[1]
        );
        assert!(
            lines[1].contains("\x1b[2m"),
            "line 1 suffix must carry the `dimmed` ANSI sequence \
             (`\\x1b[2m`); got {:?}",
            lines[1]
        );
    }

    /// Fail-before-pass envelope for [`super::write_section_header`].
    /// Pins the three-line body order every pre-lift consumer spelled
    /// verbatim (`"═".repeat(48).bold()` rule via the literal
    /// `"════════════════════════════════════════════════"`,
    /// `"  <title>".bold()` indented title, `"═".repeat(48).bold()`
    /// rule). A silent contract drift a future rewrite might
    /// introduce — dropping one bar to two `writeln!`s, swapping the
    /// title and a bar, hoisting the rule character off `═` in one
    /// branch alone, dropping `.bold()` from the title so it loses
    /// emphasis against the rule, dropping the two-space indent so
    /// the title crashes against the first column — flips this
    /// assertion rather than compiling and silently diverging the
    /// eight consumer sites' visual grammar.
    #[test]
    fn write_section_header_emits_three_bar_title_bar_lines_in_order() {
        // Force ANSI emission so the palette contract survives a test
        // runner attached to a non-tty (colored auto-drops sequences).
        // Hold the shared [`ANSI_OVERRIDE_LOCK`] across the whole
        // set-write-unset window so a peer banner test's `unset` can
        // never strand this writer between colored's on/off flip.
        let _override_guard = ANSI_OVERRIDE_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        colored::control::set_override(true);

        let mut buf: Vec<u8> = Vec::new();
        super::write_section_header(&mut buf, "Schema Export + Codegen")
            .expect("write_section_header against a Vec<u8> writer must succeed");

        colored::control::unset_override();

        let out = String::from_utf8(buf)
            .expect("write_section_header must emit valid UTF-8 (the pre-lift println!s did)");

        // Exactly three body lines — the pre-lift stanza's rule +
        // title + rule triple is three `println!`s, not two, and not
        // four. A refactor that drops or adds a bar fails here. The
        // framing blank lines the pre-lift stanza carried live on
        // `print_section_header`, not on the writer sibling.
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(
            lines.len(),
            3,
            "write_section_header must emit exactly three body lines \
             (rule, title, rule) — the pre-lift stanza's rule+title+rule \
             triple is three `println!`s; got {}:\n{}",
            lines.len(),
            out
        );

        // The `═` rule glyph appears in the outer two lines but never
        // in the middle line; the title text appears in the middle
        // line but never in the outer lines. A swap of the middle
        // line and a bar (a fusion that reorders the `writeln!`s)
        // fails here.
        assert!(
            lines[0].contains('═'),
            "line 0 must be an `═` rule; got {:?}",
            lines[0]
        );
        assert!(
            lines[2].contains('═'),
            "line 2 must be an `═` rule; got {:?}",
            lines[2]
        );
        assert!(
            !lines[1].contains('═'),
            "line 1 must NOT contain the rule glyph — it is the \
             indented title line; got {:?}",
            lines[1]
        );
        assert!(
            lines[1].contains("Schema Export + Codegen"),
            "line 1 must carry the title verbatim; got {:?}",
            lines[1]
        );

        // The two-space indent every pre-lift consumer prepended to
        // the title via the literal `"  <TITLE>"` must reach the
        // rendered line intact. A fusion that hoists the indent off
        // the constant and drops it fails here — every consumer's
        // pre-lift stanza carried the two-space visual gutter between
        // the rule's left edge and the first title glyph.
        assert!(
            lines[1].contains("  Schema Export + Codegen"),
            "line 1 must carry the two-space title indent verbatim — \
             the pre-lift stanza spelled `\"  <TITLE>\".bold()`; got {:?}",
            lines[1]
        );

        // The rule width every pre-lift consumer spelled inline is
        // 48 characters (the literal
        // `"════════════════════════════════════════════════"`). A
        // fusion that hoists the rule off the constant and lands on
        // a different width lines two adjacent section headers
        // against visibly different rules — pin the count here.
        let rule_glyph_count = lines[0].chars().filter(|c| *c == '═').count();
        assert_eq!(
            rule_glyph_count, 48,
            "line 0 must contain exactly `SECTION_HEADER_RULE`.len() (48) \
             `═` glyphs; got {}",
            rule_glyph_count
        );

        // The palette contract: every one of the three lines carries
        // the `bold` ANSI sequence. A silent drop of `.bold()` on
        // any line loses the section-boundary emphasis against the
        // surrounding body text — pin the sequence here.
        for (i, line) in lines.iter().enumerate() {
            assert!(
                line.contains("\x1b[1m"),
                "line {} must carry the `bold` ANSI sequence \
                 (`\\x1b[1m`) — the pre-lift stanza spelled `.bold()` \
                 on each of the three lines; got {:?}",
                i,
                line
            );
        }
    }

    #[test]
    fn styled_spinner_returns_spinner_flavored_bar_not_a_determinate_bar() {
        // A [`ProgressBar::new_spinner`]-flavored bar reports
        // `.length()` as `None`; a determinate
        // [`ProgressBar::new(<n>)`]-flavored bar reports `Some(n)`.
        // Pre-lift each of the 8 consumer sites constructed via
        // `new_spinner()`, never `new(<n>)`; the fusion must preserve
        // that flavor or the returned bar renders a determinate
        // progress track (a filled bar with a bogus 0-length
        // denominator) instead of an animated spinner glyph.
        let bar = styled_spinner(SpinnerStyle::Yellow, "");
        assert!(
            bar.length().is_none(),
            "styled_spinner must return a spinner-flavored bar (no length), \
             not a determinate progress bar"
        );
        bar.finish_and_clear();
    }

    /// Fail-before-pass envelope for [`super::write_step_heading`]. Pins
    /// the exact single-line body every pre-lift consumer spelled
    /// verbatim (`<title>.bold()` via `println!("{}", "<TITLE>".bold())`).
    /// A silent contract drift a future rewrite might introduce —
    /// dropping `.bold()` so the label loses emphasis, promoting the
    /// title to a color that competes with the surrounding body text,
    /// adding a framing blank the pre-lift stanza never carried,
    /// dropping the trailing `\n` — flips this assertion rather than
    /// compiling and silently diverging the 44 consumer sites' visual
    /// grammar.
    #[test]
    fn write_step_heading_emits_exactly_one_bold_title_line() {
        // Force ANSI emission so the palette contract survives a test
        // runner attached to a non-tty (colored auto-drops sequences).
        // Hold the shared [`ANSI_OVERRIDE_LOCK`] across the whole
        // set-write-unset window so a peer banner test's `unset` can
        // never strand this writer between colored's on/off flip.
        let _override_guard = ANSI_OVERRIDE_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        colored::control::set_override(true);

        let mut buf: Vec<u8> = Vec::new();
        super::write_step_heading(&mut buf, "G1: cargo check")
            .expect("write_step_heading against a Vec<u8> writer must succeed");

        colored::control::unset_override();

        let out = String::from_utf8(buf)
            .expect("write_step_heading must emit valid UTF-8 (the pre-lift println!s did)");

        // Exactly one line — the pre-lift stanza is one `println!`,
        // not two, and carries no framing blank. A refactor that
        // slips a leading or trailing blank into the primitive body
        // fails here.
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(
            lines.len(),
            1,
            "write_step_heading must emit exactly one line — the \
             pre-lift stanza is one `println!` carrying no framing \
             blank; got {}:\n{}",
            lines.len(),
            out
        );

        // The title text reaches the rendered line verbatim; a fusion
        // that hoists the title off the parameter and pins it to a
        // constant fails here.
        assert!(
            lines[0].contains("G1: cargo check"),
            "line 0 must carry the title verbatim; got {:?}",
            lines[0]
        );

        // The `bold` ANSI sequence reaches the rendered line; a fusion
        // that drops `.bold()` (a "just print the string, it's
        // shorter" cleanup) fails here.
        assert!(
            lines[0].contains("\x1b[1m"),
            "line 0 must carry the `bold` ANSI sequence (`\\x1b[1m`) \
             — every pre-lift consumer spelled `.bold()` on the \
             title; got {:?}",
            lines[0]
        );

        // The trailing `\n` reaches the writer — pre-lift stanza used
        // `println!` (not `print!`), so the newline is part of the
        // contract. A fusion that swapped `writeln!` for `write!`
        // fails here.
        assert!(
            out.ends_with('\n'),
            "write_step_heading must emit a trailing `\\n` (the \
             pre-lift `println!` did); got {:?}",
            out
        );
    }

    /// Post-lift the callers migrated onto [`super::print_step_heading`]
    /// no longer spell the `println!("{}", "<TITLE>".bold());` shape
    /// inline. Structural regression shield — without it, a future
    /// refactor could silently re-inline the one-liner (e.g. a "just
    /// call `println!` directly, it's shorter" cleanup) and reopen the
    /// 44-site duplication class this lift closed. Enforced at the
    /// module bodies before their `#[cfg(test)]` regions so a
    /// test-support mention of the raw shape does not defeat the
    /// shield. The exact-shape needle `println!("{}", "` co-occurring
    /// with `".bold());` on the SAME line uniquely identifies the
    /// pre-lift restatement — other bold-carrying `println!`s in
    /// these files (composite `format!` args, non-literal-arg shapes)
    /// stay unshielded because they are morally-adjacent shapes with
    /// their own lift targets, not this one.
    #[test]
    fn print_step_heading_callers_delegate_through_primitive() {
        const CALLERS: &[(&str, &str)] = &[
            (
                include_str!("commands/developer_tools.rs"),
                "commands/developer_tools.rs",
            ),
            (include_str!("commands/codegen.rs"), "commands/codegen.rs"),
            (
                include_str!("commands/product_release.rs"),
                "commands/product_release.rs",
            ),
            (
                include_str!("commands/bootstrap.rs"),
                "commands/bootstrap.rs",
            ),
            (
                include_str!("commands/federation_tests.rs"),
                "commands/federation_tests.rs",
            ),
            (include_str!("commands/sync.rs"), "commands/sync.rs"),
            (
                include_str!("commands/migration_new.rs"),
                "commands/migration_new.rs",
            ),
            (include_str!("commands/rollback.rs"), "commands/rollback.rs"),
            (
                include_str!("commands/prerelease.rs"),
                "commands/prerelease.rs",
            ),
            (
                include_str!("commands/frontend_validation.rs"),
                "commands/frontend_validation.rs",
            ),
            (
                include_str!("commands/codegen_validation.rs"),
                "commands/codegen_validation.rs",
            ),
            (
                include_str!("commands/post_deploy_verification.rs"),
                "commands/post_deploy_verification.rs",
            ),
        ];
        for (source, module_path) in CALLERS {
            let body = crate::test_support::module_body_before_first_cfg_test(source, module_path);
            for (i, line) in body.lines().enumerate() {
                assert!(
                    !(line.contains("println!(\"{}\", \"") && line.contains("\".bold());")),
                    "{module_path}:{lineno} spells the pre-lift inline \
                     `println!(\"{{}}\", \"<TITLE>\".bold());` step-heading \
                     stanza — that one-liner was lifted onto \
                     `crate::ui::print_step_heading`. A re-inline would \
                     silently reopen the 44-site duplication class this \
                     shield exists to close. Offending line: {line:?}",
                    lineno = i + 1
                );
            }
            assert!(
                body.contains("crate::ui::print_step_heading("),
                "{module_path} body must forward to \
                 `crate::ui::print_step_heading(\"<TITLE>\")` — the \
                 primitive body every one-line bold step-heading in the \
                 crate now delegates through."
            );
        }
    }
}
