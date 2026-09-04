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

/// Rule-character glyph every pre-lift ASCII-bar banner site fed to
/// [`String::repeat`] verbatim (`println!("=====...=====")`, a
/// 42-glyph ASCII `=` rule with NO color and NO emphasis — distinct
/// from every peer banner primitive in this module, all of which
/// carry either a Unicode rule glyph (`━`, `─`, `═`) or a color
/// wrapper). Pinned as one named constant so a future swap of the
/// helm-chart-action banner's rule character (a promotion to `━` to
/// unify with [`write_success_banner`]'s heavy Unicode rule, a
/// demotion to `-` for an even leaner readout) happens at ONE typed
/// boundary rather than six literal-argument sites (two rules per
/// stanza across three consumer sites).
const ASCII_BAR_BANNER_RULE_CHAR: &str = "=";

/// Rule width every pre-lift ASCII-bar banner site spelled inline as
/// the literal `"=========================================="`
/// (measured: 42 glyphs across every one of the three consumer
/// sites in `commands/helm.rs`). Same one-boundary pinning as
/// [`ASCII_BAR_BANNER_RULE_CHAR`]; the width is distinct from the
/// per-caller `width` parameter [`write_success_banner`] carries
/// because the ASCII-bar grammar is a fixed-shape helm-chart-action
/// banner (not a variable-width headline) — every consumer chose 42,
/// so 42 lives in the primitive rather than repeating at every call
/// site.
const ASCII_BAR_BANNER_WIDTH: usize = 42;

/// Title indent every pre-lift ASCII-bar banner site prepended to
/// the middle line via the literal `"  <title>"` two-space gap. Same
/// one-boundary pinning as [`ASCII_BAR_BANNER_RULE_CHAR`]; a future
/// swap (a tab, four spaces, no indent under a leaner grammar)
/// happens at ONE typed boundary rather than three literal-argument
/// sites.
const ASCII_BAR_BANNER_TITLE_INDENT: &str = "  ";

/// Prints the four-line ASCII-bar banner every pre-lift consumer in
/// `commands/helm.rs` spelled inline as `println!();
/// println!("=========================================="); println!(
/// "  <title>"); println!("==========================================");`.
/// Marks the OPENING of a per-chart action (releasing a library
/// chart, linting a chart, releasing a chart) inside the helm
/// pipeline at 3 sibling call sites (`commands/helm.rs:1753` —
/// `Releasing {lib_chart_name} {version} (library)`; `:2606` —
/// `Linting {chart_name}`; `:2698` — `Releasing {chart_name}`) — the
/// pre-lift 4-line stanza — so a future palette shift against
/// rule-char, rule-width, indent glyph, or title emphasis happens at
/// ONE site rather than three.
///
/// Delegates to [`write_ascii_bar_banner`] against
/// `std::io::stdout()` (and prepends the pre-lift leading blank
/// line); the writer split exists so the fail-before-pass test can
/// pin the three-line body, palette, and title-indent contract by
/// inspecting emitted bytes rather than shelling out and grepping
/// stdout.
///
/// # Distinct from every peer banner primitive
///
/// [`print_header`] carries a `╔═…═╗` boxed grammar in `bright_blue`
/// for top-level command titles.
///
/// [`print_success_banner`] carries a Unicode `━`-rule in
/// `bright_green` + single-message headline for terminal-success
/// milestones.
///
/// [`print_release_stage_banner`] carries a Unicode-repeated `=`-rule
/// in `bright_green` + composite `<STAGE> + <product> + (<suffix>)`
/// headline for product-release-lifecycle milestones.
///
/// [`print_section_header`] carries a Unicode `═`-rule in `bold` +
/// bold-title grammar for section openings within a pipeline.
///
/// [`print_ascii_title_underline`] carries a single `=`-rule + blank
/// LINE (not a banner) below a hand-authored `printh_header`-style
/// title in the command intro.
///
/// This primitive carries a **distinct** ASCII-only `=`-rule +
/// plain-text title grammar the 3 pre-lift consumer sites in the
/// helm pipeline use to mark a per-chart action boundary. All six
/// primitives coexist rather than one subsuming the other because
/// the visual grammars an operator has been trained to read differ
/// — the helm-pipeline's per-chart boundary is deliberately the
/// only ASCII-only, uncolored banner in the crate, so a
/// `--no-color` grep or a CI log post-processor that strips ANSI
/// still shows a clear per-chart section boundary.
///
/// # Compounding
///
/// Pre-lift each of the 3 consumer sites restated the entire
/// four-line stanza — a swap of the rule character in one site
/// alone (an `=` demoted to `-` in the library-releasing site while
/// the per-chart-releasing site stayed on `=`) silently splits the
/// helm-pipeline visual grammar, a width drift from 42 to a fresh
/// literal glyph count lines two adjacent chart sections against
/// visibly different rules, a promotion of the title to `.bold()`
/// on one site alone loses the ASCII-only grep-friendliness. Post-
/// lift the primitive collapses all three restatements onto ONE
/// typed function; a future palette adjustment hits one body, not
/// three.
pub fn print_ascii_bar_banner(title: &str) {
    println!();
    let _ = write_ascii_bar_banner(&mut std::io::stdout().lock(), title);
}

/// Writer-taking sibling to [`print_ascii_bar_banner`]. Emits the
/// three ASCII-bar banner body lines (`=`-rule of
/// [`ASCII_BAR_BANNER_WIDTH`] glyphs, `[`ASCII_BAR_BANNER_TITLE_INDENT`]
/// + <title>` plain-text title, matching `=`-rule) via [`writeln!`]
/// against the supplied writer. [`print_ascii_bar_banner`] is the
/// stdout adapter (and adds the framing leading blank line the pre-
/// lift stanza carried); this variant exists so tests can pin the
/// body line count, palette, and title-indent contract without
/// capturing stdout.
pub fn write_ascii_bar_banner<W: std::io::Write>(w: &mut W, title: &str) -> std::io::Result<()> {
    let bar = ASCII_BAR_BANNER_RULE_CHAR.repeat(ASCII_BAR_BANNER_WIDTH);
    writeln!(w, "{}", bar)?;
    writeln!(w, "{}{}", ASCII_BAR_BANNER_TITLE_INDENT, title)?;
    writeln!(w, "{}", bar)?;
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

/// Palette-selector enum for [`print_section_completion_banner`] /
/// [`write_section_completion_banner`]. Closed over the three status
/// roles the pre-lift consumer sites in `commands/{codegen, sync,
/// rebac_validation}.rs` selected between at their completion-banner
/// body line — a section that finished cleanly, one that finished with
/// warnings but no errors, one that finished with errors. Same
/// knowable-construction pattern as [`ReportSectionStyle`]: the color
/// choice lives in ONE closed enum whose `match` arms name the palette
/// per role, so a future variant added without an arm fails the
/// exhaustiveness check at build time rather than silently degrading
/// via a stringly-typed `&str` color name.
///
/// # Compounding
///
/// Pre-lift each consumer inlined the color into a method chain at the
/// body-line `println!` (`.green().bold()` for a clean run,
/// `.yellow().bold()` for a warnings-only run, `.red().bold()` for a
/// run with errors). A rename that misspells `.green` as `.grne` would
/// compile-fail, but a swap of `.yellow().bold()` for `.red().bold()`
/// in one branch alone would drift the visual grammar silently — the
/// three status roles lose their eye-navigation categorization
/// (success / warning / failure) without any compile failure. Post-lift
/// the mapping [`SectionCompletionStyle`] → [`colored::ColoredString`]
/// lives in ONE `match` arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionCompletionStyle {
    /// Success-track completion banner (`<title>.green().bold()`).
    /// Pre-lift sites: `codegen.rs` (always), `sync.rs` (errors empty
    /// branch), `rebac_validation.rs` (`all_passed && warnings == 0`
    /// branch).
    Success,
    /// Warning-track completion banner (`<title>.yellow().bold()`).
    /// Pre-lift sites: `rebac_validation.rs` (`all_passed` with
    /// non-zero warnings branch).
    Warning,
    /// Failure-track completion banner (`<title>.red().bold()`).
    /// Pre-lift sites: `sync.rs` (errors non-empty branch),
    /// `rebac_validation.rs` (validation-failed branch).
    Failure,
}

/// Prints the three-line section-completion banner every pre-lift
/// consumer spelled inline as a
/// `"════════════════════════════════════════════════".bold()` rule,
/// a `"  <TITLE>".<COLOR>().bold()` indented status-colored title, and
/// a second identical rule. Marks the CLOSING of a section in a
/// pipeline run at 3 sibling call sites across
/// `commands/{codegen, sync, rebac_validation}.rs` — the pre-lift
/// rule + status-colored-title + rule triple — so a future palette
/// shift against rule-char, rule-width, indent glyph, or the
/// success/warning/failure color mapping happens at ONE site rather
/// than three.
///
/// Delegates to [`write_section_completion_banner`] against
/// [`std::io::stdout()`]; the writer split exists so the
/// fail-before-pass test can pin the three-line body, the palette per
/// [`SectionCompletionStyle`], the two-space title indent, and the
/// `═`-rule + `\x1b[1m` bold ANSI palette contract by inspecting
/// emitted bytes rather than shelling out and grepping stdout.
///
/// # Distinct from [`print_section_header`]
///
/// [`print_section_header`] carries the OPENING of a section within a
/// pipeline — same 48-glyph `═`-rule + two-space title indent
/// grammar, but the title is always `.bold()` in the default
/// foreground and framed by leading + trailing blank lines the
/// primitive adds around its writer. This primitive is the CLOSING
/// mirror: the same rule sigil (a matched section boundary a
/// [`print_section_header`] opened is closed with the same visual
/// weight), but the title is colored per the completion status the
/// section finished under, and no framing blank lines are added (the
/// pre-lift consumer sites did not carry them at the closing banner).
///
/// # Compounding
///
/// Pre-lift each of the 3 consumer sites restated the entire
/// three-line stanza with the rule character (`═`), the rule width
/// (48), the two-space title indent, the color method
/// (`.green()` / `.yellow()` / `.red()`), and the `.bold()` chain all
/// spelled inline — six literal-argument rule prints across three
/// files, plus five status-colored body branches (codegen×1, sync×2,
/// rebac×3). A width drift between `.repeat(48)` and a fresh literal
/// glyph count in one site alone lines two adjacent section closings
/// against visibly different rules. A swap of `.green().bold()` for
/// `.bright_green().bold()` in one site alone loses the contrast
/// against the peer failure-track closing. Post-lift the primitive
/// collapses all three restatements onto ONE typed function; a future
/// palette adjustment hits one body, not three. The
/// [`SectionCompletionStyle`] enum being closed additionally guards
/// against a future consumer inventing a fourth palette (a
/// `.magenta().bold()` "partial" banner) without a deliberate enum
/// extension.
pub fn print_section_completion_banner(title: &str, style: SectionCompletionStyle) {
    let _ = write_section_completion_banner(&mut std::io::stdout().lock(), title, style);
}

/// Writer-taking sibling to [`print_section_completion_banner`]. Emits
/// the three section-completion body lines (`bold` `═` rule,
/// `SECTION_HEADER_TITLE_INDENT + <title>` in the color chosen per
/// [`SectionCompletionStyle`] + `.bold()`, `bold` `═` rule) via
/// [`writeln!`] against the supplied writer.
/// [`print_section_completion_banner`] is the stdout adapter; this
/// variant exists so tests can pin the three-line body, the palette
/// mapping, the two-space title indent, and the 48-glyph `═` rule
/// without capturing stdout.
pub fn write_section_completion_banner<W: std::io::Write>(
    w: &mut W,
    title: &str,
    style: SectionCompletionStyle,
) -> std::io::Result<()> {
    let indented = format!("{}{}", SECTION_HEADER_TITLE_INDENT, title);
    let colored_title = match style {
        SectionCompletionStyle::Success => indented.green().bold(),
        SectionCompletionStyle::Warning => indented.yellow().bold(),
        SectionCompletionStyle::Failure => indented.red().bold(),
    };
    writeln!(w, "{}", SECTION_HEADER_RULE.bold())?;
    writeln!(w, "{}", colored_title)?;
    writeln!(w, "{}", SECTION_HEADER_RULE.bold())?;
    Ok(())
}

/// Top-border glyph line of the [`print_header`] / [`write_header`] boxed
/// grammar — `╔` + `BOXED_HEADER_INNER_WIDTH` `═` glyphs + `╗`, 62 display
/// columns wide. Named so a future swap of the box corner-and-rule glyphs
/// (a downgrade to ASCII `+---+`, an upgrade to a heavier double-line
/// weight) happens at ONE typed boundary rather than in three inline
/// literals per consumer.
const BOXED_HEADER_TOP: &str = "╔════════════════════════════════════════════════════════════╗";

/// Bottom-border glyph line, sibling to [`BOXED_HEADER_TOP`] — `╚` +
/// `BOXED_HEADER_INNER_WIDTH` `═` glyphs + `╝`.
const BOXED_HEADER_BOTTOM: &str = "╚════════════════════════════════════════════════════════════╝";

/// Padded width of the title field inside the middle body line — the
/// `{:<N}` min-width the [`format!`] expression fills the title to so
/// the right-side `║` lines up with the top border's right-side `╗`.
///
/// # The off-by-one bug this constant closes
///
/// Two pre-lift consumers — `commands/pangea.rs::print_header` and
/// `commands/bootstrap.rs::print_header` — spelled the middle body
/// line as `format!("║  {:58} ║", title)`, i.e. a bare `{:58}` min-width
/// (which defaults to left-align for strings) followed by a **literal
/// space** before the closing `║`. That put the right-side `║` at
/// column 63, one glyph past the top border's `╗` at column 62 — a
/// visibly-tilted right edge on every boxed header those two modules
/// emitted. Threading both consumers through this constant closes the
/// off-by-one at ONE named boundary.
const BOXED_HEADER_TITLE_WIDTH: usize = 58;

/// Writer-taking sibling to [`print_header`]. Emits the three body
/// lines of the `╔═…═╗` boxed-header grammar — top border, indented
/// title middle line, bottom border — in `bright_blue` via
/// [`writeln!`] against the supplied writer. The leading and trailing
/// framing blank lines the pre-lift stanza carried live on
/// [`print_header`], not on this writer sibling — so a test that pins
/// the box's body-line count and border-vs-body width parity can
/// inspect emitted bytes rather than shelling out and grepping stdout.
///
/// # Distinct from other `write_*` box grammars
///
/// [`write_section_header`] carries a `═`-rule + bold-title readout
/// used to open a section inside a pipeline. [`write_success_banner`]
/// carries a `━`-rule + green-bold-message terminal-success readout.
/// This writer carries the `╔═╗` boxed top-of-command title in
/// `bright_blue`.
pub fn write_header<W: std::io::Write>(w: &mut W, title: &str) -> std::io::Result<()> {
    writeln!(w, "{}", BOXED_HEADER_TOP.bright_blue())?;
    writeln!(
        w,
        "{}",
        format!("║  {:<width$}║", title, width = BOXED_HEADER_TITLE_WIDTH).bright_blue()
    )?;
    writeln!(w, "{}", BOXED_HEADER_BOTTOM.bright_blue())?;
    Ok(())
}

pub fn print_header(title: &str) {
    println!();
    let mut out = std::io::stdout();
    let _ = write_header(&mut out, title);
    println!();
}

pub fn print_success(message: &str) {
    let _ = write_success(&mut std::io::stdout().lock(), message);
}

/// Writer-taking sibling to [`print_success`]. Emits the single
/// `✅ <message>.bright_green().bold()` milestone-level line via
/// [`writeln!`] against the supplied writer. [`print_success`] is the
/// stdout adapter; this variant exists so tests can pin the one-line
/// body, the `✅ ` prefix, the `bright_green` ANSI sequence
/// (`\x1b[92m`), and the `bold` ANSI sequence (`\x1b[1m`) without
/// capturing stdout — and so a caller that already owns a `Vec<u8>` or
/// a locked stderr handle need not double-buffer through `print_success`.
///
/// # Distinct from the peer [`write_step_success`]
///
/// [`write_step_success`] carries a lighter `green()` (never
/// `bright_green`) `✅ <msg>` line the in-body step-completion sites use
/// (∼30 pre-lift consumer sites — see `write_step_success`'s docstring).
/// This primitive carries the milestone-level `bright_green().bold()`
/// palette the top-of-command completion banners use — three pre-lift
/// consumer sites (`commands/{bootstrap,build,push}.rs`) each spelled
/// the expansion verbatim as
/// `println!("{}", "✅ <MSG>".bright_green().bold())`, hand-rolling
/// [`print_success`]'s exact one-line body inline. The palette lift
/// (`green` → `bright_green` + `bold`) is the visual grammar distinction
/// separating the two — a caller that promoted a step-completion onto
/// this writer would collapse the contrast the two-writer split exists
/// to preserve, and a caller that demoted a milestone completion onto
/// [`write_step_success`] would flatten it into the in-body noise floor.
///
/// # ANSI byte equivalence with the pre-lift stanzas
///
/// The three pre-lift stanzas spelled the `✅ ` prefix INSIDE the
/// coloring span (`"✅ <MSG>".bright_green().bold()`); this primitive
/// prepends the prefix OUTSIDE and colors the joined string
/// (`format!("✅ {}", <MSG>").bright_green().bold()`). The two shapes
/// wrap identical UTF-8 payloads with identical ANSI sequences and emit
/// byte-identical output — the writer-level test below pins that
/// contract against a `Vec<u8>` sink.
pub fn write_success<W: std::io::Write>(w: &mut W, message: &str) -> std::io::Result<()> {
    writeln!(w, "{}", format!("✅ {}", message).bright_green().bold())
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

/// Prints the one-line `Step <label>: <title>.bold()` labeled-step-heading
/// grammar 23 pre-lift consumer sites spelled inline as
/// `println!("Step <label>: {}", "<TITLE>".bold());` across
/// `commands/rust_service.rs` (two multi-step deployment pipelines —
/// `deploy_rust_service` steps 0/0.5/1/1.5/2/3/4/4.5/5/6/7 and
/// `release_rust_service` steps 0/8, 1/8, 2/9, 2.5/9, 3/9, 4/9, 5/9,
/// 6/9, 6.5/9, 7/9, 8/9, 9/9). Marks the start of one numbered step
/// inside a multi-step pipeline, the label carrying the step's ordinal
/// (`"1"`, `"1.5"`) or fraction (`"1/8"`, `"6.5/9"`) so the operator can
/// read progress at a glance ("we are at step 3 of 9").
///
/// # Distinct from the other `ui::print_*` primitives
///
/// [`print_step_heading`] is a bare `<title>.bold()` line with no
/// numeric context — its consumer sites are inside pipelines whose
/// steps are enumerated by their bodies alone ("G1: cargo check",
/// "Backend Gates"), not by a `Step <label>: ` prefix the operator
/// counts against a known total. [`print_phase_heading`] is the
/// two-line phase-level opening (`.bold().underline()` + framing
/// blank) one scope above a numbered step. [`print_section_header`] is
/// a `═`-rule + bold-title triple around a section opening. This
/// primitive carries the labeled-step grammar: an UNCOLORED `Step
/// <label>: ` prefix (so the label sits in the surrounding body
/// palette) followed by a `.bold()` title (so the eye jumps to the
/// title text rather than the ordinal). The two multi-step pipelines
/// in `commands/rust_service.rs` are the only pre-lift consumers of
/// this grammar in the crate — every other module's stepwise heading
/// either omits the numeric label ([`print_step_heading`]) or wraps
/// its `println!` in a multi-line `format!` because the title itself
/// composes runtime state.
///
/// # Compounding
///
/// Pre-lift 23 sibling sites each restated the `println!("Step
/// <label>: {}", "<TITLE>".bold())` grammar verbatim. A future
/// adjustment (a swap of `Step ` for a locale-neutral `[<label>] `
/// prefix, a promotion of the label to `.cyan()` for visual separation
/// from the title, an OTLP `step_start` span wired alongside the
/// print, a swap of `.bold()` for `.bold().underline()` under a
/// heavier step-vs-substep distinction, a `Step <label> of <total>: `
/// long-form spelled from a `(current, total)` typed pair rather than
/// the operator hand-formatting `"<n>/<total>"` into the label) had to
/// hit 23 sites in lockstep or drift the visual grammar; post-lift it
/// hits ONE typed body. Delegates to [`write_numbered_step_heading`]
/// against [`std::io::stdout()`]; the writer split exists so the
/// fail-before-pass test can pin the one-line body, the `Step
/// <label>: ` uncolored prefix, and the `\x1b[1m` bold sequence on the
/// title by inspecting emitted bytes rather than shelling out and
/// grepping stdout.
pub fn print_numbered_step_heading(label: &str, title: &str) {
    let _ = write_numbered_step_heading(&mut std::io::stdout().lock(), label, title);
}

/// Writer-taking sibling to [`print_numbered_step_heading`]. Emits the
/// single `Step <label>: <title>.bold()` line via [`writeln!`] against
/// the supplied writer. [`print_numbered_step_heading`] is the stdout
/// adapter; this variant exists so tests can pin the one-line body,
/// the uncolored `Step <label>: ` prefix, and the `\x1b[1m` bold
/// sequence on the title without capturing stdout.
pub fn write_numbered_step_heading<W: std::io::Write>(
    w: &mut W,
    label: &str,
    title: &str,
) -> std::io::Result<()> {
    writeln!(w, "Step {}: {}", label, title.bold())
}

/// Prints the one-line `Check <index>: <title>.blue()` numbered-check-heading
/// grammar 7 pre-lift consumer sites spelled inline as
/// `println!("{}", "Check <N>: <TITLE>".blue());` across
/// `commands/rebac_validation.rs` (Check 1: ReBAC Documentation,
/// Check 2: Permission Engine Source Files, Check 3: Object Type →
/// Entity Mapping, Check 4: Relation Hierarchy Consistency, Check 5:
/// Redis Key Pattern Validation, Check 6: Redis Connectivity, Check 7:
/// GraphQL Permission Operations). Marks the start of one numbered
/// quality check inside a multi-check validation pipeline, the
/// `<index>` carrying the check's 1-based ordinal so the operator can
/// read progress against a known total ("we are at check 3 of 7").
///
/// # Distinct from the other `ui::print_*` primitives
///
/// [`print_numbered_step_heading`] is the peer for a numbered-STEP
/// grammar (`Step <label>: <title>.bold()`, uncolored `Step ` prefix,
/// `.bold()` title, `&str` label because pipeline steps compose
/// fractional labels like `"2.5/9"`). This primitive is its numbered-
/// CHECK sibling: an ENTIRE-line `.blue()` palette (the pre-lift
/// `println!("{}", "Check <N>: <title>".blue())` wraps the whole
/// composed string, not just the title, per THEORY §V.1 knowable
/// construction — the check-heading is a distinct semantic scope
/// warranting its own palette), a `u32` index because a rebac
/// validation check is enumerated as a plain positive ordinal and a
/// typed `u32` locks that invariant in (a caller reaching for `"2.5"`
/// would fail to compile, per THEORY §V.1 unrepresentability), and a
/// literal `Check <index>: ` prefix baked into the format string so
/// the "Check" keyword is one edit away from a locale swap or a
/// grammar tightening. [`print_step_check`] is the `.green()` in-body
/// `   ✓ <message>` sub-check line that a check-body emits AFTER the
/// heading to record one passing sub-assertion — same "check" word,
/// different scope (a HEADING that opens a numbered check vs. an
/// in-body ROW that names one sub-assertion inside it).
/// [`print_step_heading`] is the bare `<title>.bold()` line with no
/// numeric context — its consumer sites open steps whose bodies alone
/// enumerate them, not against a known total.
///
/// # `.blue()` on the whole line
///
/// Pre-lift every consumer spelled the coloring as
/// `"Check <N>: <title>".blue()` on the FULL composed string, never
/// as `format!("Check {}: {}", n, title.blue())` on the title alone
/// or as `format!("{}: {}", "Check <N>".blue(), title)` on the prefix
/// alone. The primitive preserves that: the `\x1b[34m` blue ANSI
/// sequence wraps the entire `Check <index>: <title>` composed string,
/// so a terminal without color renders `Check <index>: <title>`
/// legibly and a terminal with color paints the whole heading in one
/// visual span that separates it from the surrounding uncolored body.
///
/// # Compounding
///
/// Pre-lift 7 sibling sites each restated the
/// `println!("{}", "Check <N>: <TITLE>".blue())` grammar verbatim, with
/// the `Check ` prefix, the numeric ordinal, the `: ` separator, the
/// title text, and the `.blue()` coloring on the composed line all
/// spelled inline. A future adjustment (a swap of `Check ` for a
/// locale-neutral `[<index>] ` prefix, a promotion to
/// `.blue().bold()` for heavier emphasis against the surrounding
/// pass/fail rows, an OTLP `rebac_check_start` observability event
/// wired alongside the print, a swap of `.blue()` for
/// `.bright_blue()` under a themed palette, a `Check <index> of
/// <total>: ` long-form spelled from a `(current, total)` typed pair)
/// had to hit 7 sites in lockstep or drift the visual grammar; post-
/// lift it hits ONE typed body. Delegates to
/// [`write_numbered_check_heading`] against [`std::io::stdout()`]; the
/// writer split exists so the fail-before-pass test can pin the one-
/// line body, the `Check <index>: <title>` composed layout, the
/// `\x1b[34m` blue ANSI palette contract on the whole line, and the
/// trailing `\n` by inspecting emitted bytes rather than shelling out
/// and grepping stdout.
pub fn print_numbered_check_heading(index: u32, title: &str) {
    let _ = write_numbered_check_heading(&mut std::io::stdout().lock(), index, title);
}

/// Writer-taking sibling to [`print_numbered_check_heading`]. Emits
/// the single `Check <index>: <title>` line, `.blue()`-wrapped in
/// full, via [`writeln!`] against the supplied writer.
/// [`print_numbered_check_heading`] is the stdout adapter; this
/// variant exists so tests can pin the one-line body, the
/// `Check <index>: <title>` composed layout, and the `\x1b[34m` blue
/// ANSI sequence wrapping the whole composed string without capturing
/// stdout.
pub fn write_numbered_check_heading<W: std::io::Write>(
    w: &mut W,
    index: u32,
    title: &str,
) -> std::io::Result<()> {
    writeln!(w, "{}", format!("Check {}: {}", index, title).blue())
}

/// Prints the two-line bold-underlined phase-heading grammar 6 pre-lift
/// consumer sites spelled inline as `println!("{}", "<TITLE>".bold().underline());`
/// immediately followed by `println!();` across `commands/prerelease.rs`
/// (Phase 0a / 0b / 0c openings + `Backend Gates` / `Migration Gates` /
/// `Frontend Gates` sub-phase openings). Marks the start of a top-level
/// phase or sub-phase of the prerelease pipeline whose scope brackets
/// several downstream [`print_step_heading`] step markers.
///
/// # Distinct from the other `ui::print_*` primitives
///
/// [`print_step_heading`] is the LEANEST opening — a single `.bold()`
/// line, no underline, no framing blank — the in-body step marker one
/// scope below a phase. This primitive carries the phase-level opening:
/// `.bold()` PLUS `.underline()` for the extra emphasis a phase deserves
/// over a step, PLUS a trailing framing blank the pre-lift stanza spelled
/// as a second `println!();`. [`print_section_header`] is a `═`-rule +
/// bold-title triple around a section opening in a non-prerelease
/// pipeline; the phase-heading grammar is prerelease's leaner, rule-less
/// peer. [`print_header`] is the `╔═╗` boxed top-level command title one
/// scope above a phase.
///
/// # Compounding
///
/// Pre-lift 6 sibling sites each restated the
/// `println!("{}", "<TITLE>".bold().underline()); println!();` two-line
/// grammar verbatim. A future palette adjustment (a swap of `.underline()`
/// for a `═`-rule under the heavier section-header grammar, a promotion
/// of the trailing framing blank to two blanks under a more spacious
/// phase-body, an OTLP `phase_start` observability event, a `[Pn/N]`
/// phase-numbering prefix, a swap of `.bold().underline()` for
/// `.bright_cyan().bold()` under a themed phase palette) had to hit 6
/// sites in lockstep or drift the visual grammar; post-lift it hits ONE
/// typed body. Delegates to [`write_phase_heading`] against
/// [`std::io::stdout()`]; the writer split exists so the fail-before-pass
/// test can pin the two-line body, the `\x1b[1m` bold and `\x1b[4m`
/// underline ANSI sequences, and the trailing framing blank by
/// inspecting emitted bytes rather than shelling out and grepping stdout.
pub fn print_phase_heading(title: &str) {
    let _ = write_phase_heading(&mut std::io::stdout().lock(), title);
}

/// Writer-taking sibling to [`print_phase_heading`]. Emits the two-line
/// body — the `<title>.bold().underline()` heading then a framing blank
/// — via [`writeln!`] against the supplied writer.
/// [`print_phase_heading`] is the stdout adapter; this variant exists so
/// tests can pin the two-line body, the `\x1b[1m` bold + `\x1b[4m`
/// underline ANSI sequences, and the trailing blank without capturing
/// stdout.
pub fn write_phase_heading<W: std::io::Write>(w: &mut W, title: &str) -> std::io::Result<()> {
    writeln!(w, "{}", title.bold().underline())?;
    writeln!(w)
}

/// Prints the one-line `✅ <message>.green()` in-body step-completion
/// grammar 9 pre-lift consumer sites spelled inline as
/// `println!("✅ {}", "<MSG>".green());` across 4 command modules
/// (`commands/{federation (×6), rust_service (×1), schema_validation
/// (×1), developer_tools (×1)}.rs`). Marks the successful completion
/// of an in-body step, gate, or phase within a command's readout
/// ("Schema extraction complete", "Pre-composition validation passed",
/// "Supergraph composed successfully", "Manifest updated and pushed",
/// "Cargo.nix updated!", …) — the natural closing counterpart to
/// [`print_step_heading`]'s opening step marker.
///
/// # Distinct from the other `ui::print_*` primitives
///
/// [`print_success`] is a `bright_green().bold()` `✅ <msg>` line the
/// `e2e.rs` runner uses as its milestone-level success sigil — the
/// heavier palette (`bright_green` rather than `green`, `.bold()`
/// added) marks it as a suite / phase / all-tests-complete milestone
/// visually louder than an in-body step. [`print_success_banner`] is
/// a three-line `━`-rule + `green().bold()` message + `━`-rule
/// terminal-completion banner. This primitive carries the LEANEST
/// closing — a single `✅ ` prefix + `green()` message, no bold, no
/// rule, no framing blank — every pre-lift consumer used inside a
/// command's pipeline as an in-body step-completion marker one step
/// below a milestone-level `print_success` call and two steps below a
/// terminal `print_success_banner`.
///
/// # Compounding
///
/// Pre-lift 9 sibling sites each restated the `println!("✅ {}",
/// "<MSG>".green())` grammar verbatim. A future palette adjustment (a
/// swap of `✅ ` for `✓ ` glyph, a promotion of `.green()` to
/// `.bright_green()` or `.green().bold()` under a leaner step-vs-
/// milestone distinction, an OTLP `step_complete` observability event
/// wired alongside the print, a swap of the leading emoji for a bare
/// checkmark under a CI-log-friendly palette) had to hit 9 sites in
/// lockstep or drift the visual grammar; post-lift it hits ONE typed
/// body. Delegates to [`write_step_success`] against
/// [`std::io::stdout()`]; the writer split exists so the
/// fail-before-pass test can pin the single-line body, the leading
/// `✅ ` prefix, and the `\x1b[32m` green palette contract by
/// inspecting emitted bytes rather than shelling out and grepping
/// stdout.
pub fn print_step_success(message: &str) {
    let _ = write_step_success(&mut std::io::stdout().lock(), message);
}

/// Writer-taking sibling to [`print_step_success`]. Emits the single
/// `✅ <message>.green()` line via [`writeln!`] against the supplied
/// writer. [`print_step_success`] is the stdout adapter; this variant
/// exists so tests can pin the one-line body, the `✅ ` prefix, and
/// the `\x1b[32m` green ANSI sequence without capturing stdout.
pub fn write_step_success<W: std::io::Write>(w: &mut W, message: &str) -> std::io::Result<()> {
    writeln!(w, "✅ {}", message.green())
}

/// Prints the one-line `"   {} <message>"` (three-space indent + red
/// `❌` glyph + plain message) in-body step-failure grammar 40 pre-lift
/// consumer sites spelled inline as `println!("   {} <fmt>",
/// "❌".red(), <args>)` (or its multi-line spread across five to seven
/// source lines when the message carries a `format!`-computed
/// argument list) across 7 command modules (`commands/{prerelease
/// (×17), post_deploy_verification (×10), frontend_validation (×6),
/// migration_validation (×3), sync (×2), codegen_validation (×1),
/// integration_tests (×1)}.rs`). Marks the failed completion of an
/// in-body step, gate, sub-check, or per-item probe within a command's
/// readout ("Docker not available: <err>", "Type check failed (12
/// errors, 3.4s)", "Health check failed: Status 502", "Schema drift
/// detected!", "GraphQL returned errors: <errors>", …) — the natural
/// failure counterpart to [`print_step_success`]'s
/// `✅ <msg>.green()` in-body step-completion marker.
///
/// # Distinct from the other `ui::print_*` primitives
///
/// [`print_error`] is a `bright_red().bold()` `❌ <msg>` line the
/// milestone-level command-failure sigil, emitted at the top-level of
/// the command (not indented inside a body) — the heavier palette
/// (`bright_red` rather than plain `.red()` on the glyph, `.bold()`
/// added, message-colored, no indent) marks it as a command-level
/// failure louder than an in-body step. [`print_step_success`] is the
/// success counterpart at this exact indent depth: `✅ ` glyph
/// (not indented) + `.green()` message. This primitive carries the
/// LEANEST indented failure — a three-space indent, a `.red()`-colored
/// `❌` glyph, and a plain (uncolored) message — every pre-lift
/// consumer used inside a command's pipeline as an in-body
/// step-failure marker one step below a milestone-level
/// [`print_error`] and two steps below a terminal
/// [`print_success_banner`]'s failure counterpart.
///
/// # `.red()` on the glyph, plain on the message
///
/// Pre-lift every consumer spelled the coloring as `"❌".red()` on the
/// GLYPH alone, never on the composed line (`format!("   ❌ {}",
/// msg).red()`). The primitive preserves that split: the `\x1b[31m`
/// red ANSI sequence wraps the glyph, the message reaches the writer
/// uncolored, and the three-space indent is emitted OUTSIDE both spans
/// — so a terminal without color renders `   ❌ <msg>` legibly. A
/// re-lift that hoisted the color onto the whole line would paint the
/// message text red at every site, changing the visual grammar
/// silently.
///
/// # Compounding
///
/// Pre-lift 40 sibling sites each restated the `println!("   {}
/// <fmt>", "❌".red(), <args>)` grammar verbatim, with the
/// three-space indent, the `❌` glyph, the `.red()` coloring on the
/// glyph, and the plain-message tail all spelled inline. A future
/// palette adjustment (a swap of `❌ ` for `✗ ` under a
/// CI-log-friendly grammar, a promotion of `.red()` to
/// `.bright_red()` under a leaner step-vs-milestone distinction, an
/// OTLP `step_failed` observability event wired alongside the print,
/// a shift of the three-space indent to two- or four-space under a
/// standardized body-indent, a swap to `eprintln!` so failure lines
/// route to stderr) had to hit 40 sites in lockstep or drift the
/// visual grammar; post-lift it hits ONE typed body. Delegates to
/// [`write_step_failure`] against [`std::io::stdout()`]; the writer
/// split exists so the fail-before-pass test can pin the one-line
/// body, the three-space indent, the `❌ ` glyph, and the `\x1b[31m`
/// red ANSI palette contract by inspecting emitted bytes rather than
/// shelling out and grepping stdout.
pub fn print_step_failure(message: &str) {
    let _ = write_step_failure(&mut std::io::stdout().lock(), message);
}

/// Writer-taking sibling to [`print_step_failure`]. Emits the single
/// `   <❌.red()> <message>` line via [`writeln!`] against the
/// supplied writer. [`print_step_failure`] is the stdout adapter;
/// this variant exists so tests can pin the one-line body, the
/// three-space indent, the `❌ ` glyph, and the `\x1b[31m` red ANSI
/// sequence around the glyph (never the message) without capturing
/// stdout.
pub fn write_step_failure<W: std::io::Write>(w: &mut W, message: &str) -> std::io::Result<()> {
    writeln!(w, "   {} {}", "❌".red(), message)
}

/// Prints the one-line `"   {} <message>"` (three-space indent + green
/// `✅` glyph + plain message) in-body step-pass grammar 62 pre-lift
/// consumer sites spelled inline as one of two shapes across 15 command
/// modules:
///
/// - **First lift (28 sites, 10 modules):** `println!("   {} <fmt>",
///   "✅".green(), <args>)` — the explicit-color spelling across
///   `commands/{prerelease (×6), migration_new (×4), frontend_validation
///   (×4), migration_validation (×3), post_deploy_verification (×3),
///   codegen_validation (×3), rust_service (×2), codegen (×1),
///   integration_tests (×1), migrations (×1)}.rs`.
/// - **Second lift (34 sites, 7 additional modules + 2 that grew):**
///   `println!("   ✅ <fmt>", <args>)` — the plain-emoji spelling
///   (single-line and multi-line-spread flavors) across
///   `commands/{rust_service (+×10), flux (×6), developer_tools (×6),
///   migrations (+×4), web_service (×4), federation_tests (×2),
///   schema_validation (×2)}.rs`. These sites relied on the terminal
///   to render `✅` in color; post-lift they carry the `.green()` ANSI
///   on the glyph like every sibling site, a colored-mode drift that
///   `colored`'s TTY auto-drop makes invisible in piped/log output.
///
/// Marks the successful completion of an in-body step, gate, sub-check,
/// or per-item probe within a command's readout ("All migrations valid",
/// "Type check passed (3.4s)", "Health check passed (12ms)", "Schema
/// exported to <path> (<n> bytes)", "Tests passed (<n> tests, <s>s)",
/// "Migrations completed for <env>", …) — the exact-shape success
/// counterpart to [`print_step_failure`]'s `   ❌.red() <msg>` in-body
/// step-failure marker.
///
/// # Distinct from the other `ui::print_*` primitives
///
/// [`print_step_success`] carries a different visual grammar entirely:
/// the `✅ ` glyph reaches the writer WITHOUT a three-space indent and
/// with the MESSAGE painted `.green()` (not the glyph). That primitive
/// lifts a distinct 9-site sibling class of milestone-closing "phase
/// complete" markers ("Schema extraction complete", "Supergraph
/// composed successfully", "Cargo.nix updated!", …), one step above the
/// in-body sub-check grammar this primitive carries. [`print_success`]
/// is a `bright_green().bold()` `✅ <msg>` milestone-level command
/// success sigil the `e2e.rs` runner uses. [`print_success_banner`] is
/// a three-line `━`-rule + `green().bold()` message + `━`-rule
/// terminal-completion banner. This primitive carries the LEANEST
/// indented pass — a three-space indent, a `.green()`-colored `✅`
/// glyph, and a plain (uncolored) message — every pre-lift consumer
/// used inside a command's pipeline as an in-body step-pass marker
/// exactly one indent depth below the milestone-level
/// [`print_step_success`].
///
/// # `.green()` on the glyph, plain on the message
///
/// Pre-lift every consumer spelled the coloring as `"✅".green()` on the
/// GLYPH alone, never on the composed line (`format!("   ✅ {}",
/// msg).green()`). The primitive preserves that split: the `\x1b[32m`
/// green ANSI sequence wraps the glyph, the message reaches the writer
/// uncolored, and the three-space indent is emitted OUTSIDE both spans
/// — so a terminal without color renders `   ✅ <msg>` legibly. A
/// re-lift that hoisted the color onto the whole line would paint the
/// message text green at every site (colliding with sibling sites that
/// already color a sub-field of the message via `.cyan()` /
/// `.bright_white()`), changing the visual grammar silently.
///
/// # Compounding
///
/// Pre-lift 28 sibling sites each restated the `println!("   {}
/// <fmt>", "✅".green(), <args>)` grammar verbatim, with the
/// three-space indent, the `✅` glyph, the `.green()` coloring on the
/// glyph, and the plain-message tail all spelled inline. A future
/// palette adjustment (a swap of `✅ ` for `✓ ` under a CI-log-friendly
/// grammar, a promotion of `.green()` to `.bright_green()` under a
/// leaner step-vs-milestone distinction, an OTLP `step_passed`
/// observability event wired alongside the print, a shift of the
/// three-space indent to two- or four-space under a standardized
/// body-indent) had to hit 28 sites in lockstep or drift the visual
/// grammar; post-lift it hits ONE typed body. Delegates to
/// [`write_step_pass`] against [`std::io::stdout()`]; the writer split
/// exists so the fail-before-pass test can pin the one-line body, the
/// three-space indent, the `✅ ` glyph, and the `\x1b[32m` green ANSI
/// palette contract by inspecting emitted bytes rather than shelling
/// out and grepping stdout.
pub fn print_step_pass(message: &str) {
    let _ = write_step_pass(&mut std::io::stdout().lock(), message);
}

/// Writer-taking sibling to [`print_step_pass`]. Emits the single
/// `   <✅.green()> <message>` line via [`writeln!`] against the
/// supplied writer. [`print_step_pass`] is the stdout adapter; this
/// variant exists so tests can pin the one-line body, the three-space
/// indent, the `✅ ` glyph, and the `\x1b[32m` green ANSI sequence
/// around the glyph (never the message) without capturing stdout.
pub fn write_step_pass<W: std::io::Write>(w: &mut W, message: &str) -> std::io::Result<()> {
    writeln!(w, "   {} {}", "✅".green(), message)
}

/// Prints the one-line `"   {} <message>"` (three-space indent + green
/// `✓` thin-checkmark glyph + plain message) in-body step-check grammar
/// 18 pre-lift consumer sites spelled inline as
/// `println!("   {} <fmt>", "✓".green(), <args>)` (or its multi-line
/// spread across four to six source lines when the message carries a
/// `format!`-computed argument list) across 6 command modules
/// (`commands/{codegen (×4), codegen_validation (×4), sync (×6),
/// frontend_validation (×1), prerelease (×1), rebac_validation
/// (×1)}.rs`). Marks a passing sub-check within a step's readout
/// ("Schema in sync", "Codegen in sync", "Entities generated",
/// "Schema exported (<n> bytes)", "src/gql/ (<n> TypeScript files)",
/// "Dependencies installed (<s>s)", …) — the exact-shape sub-item
/// sibling to [`print_step_pass`]'s heavier `✅.green()` step-result
/// marker.
///
/// # Distinct from [`print_step_pass`]
///
/// Both wear the `.green()` palette (same `\x1b[32m` ANSI sequence) on
/// a `.green()`-colored glyph under a shared three-space-indent body
/// grammar, but they carry different glyphs (`✓` vs `✅`) and different
/// semantic layers: a step-pass names the SUCCESSFUL completion of a
/// full step, gate, or per-item probe the operator has been watching
/// for ("Health check passed (12ms)", "All migrations valid", "Type
/// check passed (3.4s)"); a step-check names a SUB-ITEM within a step
/// — a finer-grained OK marker for one entry in a list the outer step
/// is iterating over ("Schema exported", "Codegen completed
/// successfully", "hooks.ts (<n> lines)", one gate name inside a
/// batch summary). The two primitives coexist rather than one
/// subsuming the other because the visual grammars an operator has
/// been trained to read differ — a heavy `✅` marks a milestone
/// operator progress checkpoint, a thin `✓` marks one item in a list
/// under it. Consumers in the same module (e.g. `sync.rs`,
/// `codegen_validation.rs`) mix both glyphs deliberately.
///
/// # Distinct from the other `ui::print_*` primitives
///
/// [`print_step_success`] carries `✅` at zero indent with the message
/// (not the glyph) painted `.green()` — a milestone-closing "phase
/// complete" marker one indent scope above the in-body step grammar.
/// [`print_success`] is a `bright_green().bold()` `✅ <msg>`
/// milestone-level command success sigil. [`print_success_banner`] is
/// a three-line `━`-rule + `green().bold()` message + `━`-rule
/// terminal-completion banner. This primitive carries the LEANEST
/// indented sub-item OK — a three-space indent, a `.green()`-colored
/// `✓` thin-checkmark glyph, and a plain (uncolored) message — every
/// pre-lift consumer used inside a command's pipeline as an in-body
/// sub-check marker one step below the milestone-level
/// [`print_step_pass`].
///
/// # `.green()` on the glyph, plain on the message
///
/// Pre-lift every consumer spelled the coloring as `"✓".green()` on
/// the GLYPH alone, never on the composed line (`format!("   ✓ {}",
/// msg).green()`). The primitive preserves that split: the
/// `\x1b[32m` green ANSI sequence wraps the glyph, the message
/// reaches the writer uncolored, and the three-space indent is
/// emitted OUTSIDE both spans — so a terminal without color renders
/// `   ✓ <msg>` legibly. A re-lift that hoisted the color onto the
/// whole line would paint the message text green at every site
/// (colliding with sibling sites that already color a sub-field of
/// the message via `.cyan()` / `.bright_white()`), changing the
/// visual grammar silently.
///
/// # Compounding
///
/// Pre-lift 18 sibling sites each restated the `println!("   {}
/// <fmt>", "✓".green(), <args>)` grammar verbatim, with the
/// three-space indent, the `✓` thin-checkmark glyph, the `.green()`
/// coloring on the glyph, and the plain-message tail all spelled
/// inline. A future palette adjustment (a swap of `✓ ` for `[OK] `
/// under a CI-log-friendly grammar, a promotion of `.green()` to
/// `.bright_green()` collapsing the sub-check vs step-pass distinction,
/// an OTLP `sub_check_passed` observability event wired alongside the
/// print, a shift of the three-space indent to two- or four-space
/// under a standardized body-indent) had to hit 18 sites in lockstep
/// or drift the visual grammar; post-lift it hits ONE typed body.
/// Delegates to [`write_step_check`] against [`std::io::stdout()`];
/// the writer split exists so the fail-before-pass test can pin the
/// one-line body, the three-space indent, the `✓` glyph, and the
/// `\x1b[32m` green ANSI palette contract by inspecting emitted bytes
/// rather than shelling out and grepping stdout.
pub fn print_step_check(message: &str) {
    let _ = write_step_check(&mut std::io::stdout().lock(), message);
}

/// Writer-taking sibling to [`print_step_check`]. Emits the single
/// `   <✓.green()> <message>` line via [`writeln!`] against the
/// supplied writer. [`print_step_check`] is the stdout adapter; this
/// variant exists so tests can pin the one-line body, the three-space
/// indent, the `✓` thin-checkmark glyph, and the `\x1b[32m` green
/// ANSI sequence around the glyph (never the message) without
/// capturing stdout.
pub fn write_step_check<W: std::io::Write>(w: &mut W, message: &str) -> std::io::Result<()> {
    writeln!(w, "   {} {}", "✓".green(), message)
}

/// Prints the one-line `"  {} <message>"` (two-space indent + green
/// `✓` thin-checkmark glyph + plain message) wider-body
/// summary-check grammar 7 pre-lift consumer sites spelled inline as
/// `println!("  {} <fmt>", "✓".green())` across 2 command modules
/// (`commands/{rust_service (×5), search_sync (×2)}.rs`). Marks a
/// summary-level completion tick inside a `📋 SUMMARY` /
/// `📊 DEPLOYMENT REPORT` report block, or the terminal "operation
/// completed successfully" line of a self-contained sync task — the
/// exact-shape wider-body sibling to [`print_step_check`]'s
/// three-space in-body sub-check grammar.
///
/// # Distinct from [`print_step_check`]
///
/// Both wear the `.green()` palette (same `\x1b[32m` ANSI sequence)
/// on a `.green()`-colored `✓` glyph followed by a plain message, but
/// they carry DIFFERENT indent widths (two-space vs three-space) and
/// different semantic layers: a step-check marks a sub-item inside a
/// step's readout (one entry in a per-file list, one row in a batch
/// summary) under the three-space in-body grammar every step-level
/// primitive in this module shares; a report-item marks a
/// summary-level completion tick one indent scope OUTSIDE the in-body
/// step grammar — the wider two-space indent puts it at the same
/// visual level as [`print_report_section_subheader`] rows. The two
/// primitives coexist rather than one subsuming the other because the
/// visual grammars an operator has been trained to read differ —
/// three-space `✓` marks one item in a list under an in-body step,
/// two-space `✓` marks one row in a report or summary block one scope
/// up. `commands/rust_service.rs::print_deployment_report` spells the
/// two-space `✓.green()` REPORT-ITEM grammar for four completed
/// milestones inside the same function that later spells other
/// in-body step primitives deliberately.
///
/// # Distinct from the `.bright_green()` sibling grammar
///
/// `commands/workspace_deps.rs` carries two `"✓".bright_green()` sites
/// under a THREE-space indent (`"   {} {} - dist/ up-to-date"` /
/// `"   {} {} built successfully"`) that this primitive deliberately
/// does NOT enroll: the `\x1b[92m` bright-green palette and the
/// three-space indent together form a distinct per-workspace-package
/// build-tick grammar, and folding those two sites into this
/// primitive's `\x1b[32m` two-space body would drift their visual
/// grammar. Those sites stay unlifted by design.
///
/// # `.green()` on the glyph, plain on the message
///
/// Pre-lift every consumer spelled the coloring as `"✓".green()` on
/// the GLYPH alone, never on the composed line (`format!("  ✓ {}",
/// msg).green()`). The primitive preserves that split: the
/// `\x1b[32m` green ANSI sequence wraps the glyph, the message
/// reaches the writer uncolored, and the two-space indent is emitted
/// OUTSIDE both spans — so a terminal without color renders
/// `  ✓ <msg>` legibly.
///
/// # Compounding
///
/// Pre-lift 7 sibling sites each restated the `println!("  {} <fmt>",
/// "✓".green())` grammar verbatim, with the two-space indent, the
/// `✓` thin-checkmark glyph, the `.green()` coloring on the glyph,
/// and the plain-message tail all spelled inline. A future palette
/// adjustment (a swap of `✓ ` for `[OK] ` under a CI-log-friendly
/// grammar, a promotion of `.green()` to `.bright_green()` collapsing
/// the report-item vs `workspace_deps.rs` sibling distinction, an
/// OTLP `report_item_completed` observability event wired alongside
/// the print, a shift of the two-space indent to zero or four spaces
/// under a standardized report-indent) had to hit 7 sites in lockstep
/// or drift the visual grammar; post-lift it hits ONE typed body.
/// Delegates to [`write_report_item`] against [`std::io::stdout()`];
/// the writer split exists so the fail-before-pass test can pin the
/// one-line body, the two-space indent, the `✓` glyph, and the
/// `\x1b[32m` green ANSI palette contract by inspecting emitted bytes
/// rather than shelling out and grepping stdout.
pub fn print_report_item(message: &str) {
    let _ = write_report_item(&mut std::io::stdout().lock(), message);
}

/// Writer-taking sibling to [`print_report_item`]. Emits the single
/// `  <✓.green()> <message>` line via [`writeln!`] against the
/// supplied writer. [`print_report_item`] is the stdout adapter; this
/// variant exists so tests can pin the one-line body, the two-space
/// indent, the `✓` thin-checkmark glyph, and the `\x1b[32m` green
/// ANSI sequence around the glyph (never the message) without
/// capturing stdout.
pub fn write_report_item<W: std::io::Write>(w: &mut W, message: &str) -> std::io::Result<()> {
    writeln!(w, "  {} {}", "✓".green(), message)
}

/// Prints the one-line `"  {} <message>"` (two-space indent + yellow
/// `⏳` hourglass glyph + plain message) wider-body pending-item
/// grammar every pre-lift consumer spelled inline as
/// `println!("  {} <literal>", "⏳".yellow())`. Marks a step that has
/// been launched but has not yet observably completed — a pod rollout
/// Flux is about to reconcile, a Hive Router restart the operator has
/// to wait 30-60s for — the exact-shape peer of
/// [`print_report_item`] on the two-space wider-body report-line
/// grammar, one indent scope up from the three-space in-body
/// [`print_step_pass`] / [`print_step_warn`] / [`print_step_failure`]
/// step primitives.
///
/// # Distinct from the other `ui::print_*` primitives
///
/// [`print_report_item`] carries the two-space `✓.green()` completed-
/// item row of a summary block — the peer this primitive lives beside
/// on the same wider-body grammar but marking the OPPOSITE status
/// (completed vs. still-pending). [`print_step_warn`] carries a
/// three-space `⚠️.yellow()` in-body irregularity warning — one indent
/// scope deeper AND a distinct glyph (warning triangle, not hourglass)
/// AND a distinct semantic role (something went sideways, not
/// something is still in flight). [`print_step_skip`] carries a
/// three-space `○.yellow()` in-body skip marker — the same yellow
/// palette but a distinct hollow-circle glyph, a distinct three-space
/// indent, and a distinct semantic role (step was elided by config,
/// not step is still in flight). Folding this primitive into any of
/// the three would collapse the pending-vs-passed, pending-vs-warned,
/// or pending-vs-skipped visual distinction at every site the
/// operator has been trained to read.
///
/// # `.yellow()` on the glyph, plain on the message
///
/// Pre-lift every consumer spelled the coloring as `"⏳".yellow()` on
/// the GLYPH alone, never on the composed line (`format!("  ⏳ {}",
/// msg).yellow()`). The primitive preserves that split: the
/// `\x1b[33m` yellow ANSI sequence wraps the glyph, the message
/// reaches the writer uncolored, and the two-space indent is emitted
/// OUTSIDE both spans — so a terminal without color renders
/// `  ⏳ <msg>` legibly.
///
/// # Compounding
///
/// Pre-lift 6 sibling sites across `commands/rust_service.rs` (the
/// `verify_deployment_status` waiting-block ×4 and the deployment-
/// summary "Flux will deploy… / Hive Router will update…" tail ×2)
/// each restated the `println!("  {} <literal>", "⏳".yellow())`
/// grammar verbatim, with the two-space indent, the `⏳` hourglass
/// glyph, and the `.yellow()` coloring on the glyph all spelled
/// inline. A future palette adjustment (a swap of `⏳ ` for `[..] `
/// under a CI-log-friendly grammar, a promotion of `.yellow()` to
/// `.bright_yellow()` under a leaner step-vs-milestone distinction,
/// an OTLP `step_pending` observability event wired alongside the
/// print, a shift of the two-space indent to zero or four spaces
/// under a standardized report-indent) had to hit 6 sites in
/// lockstep or drift the visual grammar; post-lift it hits ONE typed
/// body. Delegates to [`write_pending_item`] against
/// [`std::io::stdout()`]; the writer split exists so the
/// fail-before-pass test can pin the one-line body, the two-space
/// indent, the `⏳` glyph, and the `\x1b[33m` yellow ANSI palette
/// contract by inspecting emitted bytes rather than shelling out and
/// grepping stdout.
pub fn print_pending_item(message: &str) {
    let _ = write_pending_item(&mut std::io::stdout().lock(), message);
}

/// Writer-taking sibling to [`print_pending_item`]. Emits the single
/// `  <⏳.yellow()> <message>` line via [`writeln!`] against the
/// supplied writer. [`print_pending_item`] is the stdout adapter;
/// this variant exists so tests can pin the one-line body, the
/// two-space indent, the `⏳` hourglass glyph, and the `\x1b[33m`
/// yellow ANSI sequence around the glyph (never the message) without
/// capturing stdout.
pub fn write_pending_item<W: std::io::Write>(w: &mut W, message: &str) -> std::io::Result<()> {
    writeln!(w, "  {} {}", "⏳".yellow(), message)
}

/// Prints the one-line `"  {} <message>"` (two-space indent + cyan `→`
/// glyph + plain message) wider-body arrow-item grammar every pre-lift
/// consumer spelled inline as `println!("  {} <fmt>", "→".cyan(), <args>)`.
/// Marks a narrative anchor in the operator log — a command about to be
/// invoked, a subordinate step being narrated ("Using kubectl to run
/// sync inside search service pod"), a discovery reported back ("Found
/// pod: X"), an imperative next-step instruction to the operator
/// ("Monitor the rollout using the commands above") — the exact-shape
/// per-narration peer of [`print_report_item`]'s two-space `✓.green()`
/// completed-row grammar and [`print_pending_item`]'s two-space
/// `⏳.yellow()` still-pending grammar. Sibling on the same wider-body
/// report-line indent but marking a DIFFERENT semantic layer: neither
/// completion (green ✓) nor still-in-flight wait (yellow ⏳), but a
/// forward-pointing narrative marker (cyan →) for what the operator is
/// about to see or should do next.
///
/// # Distinct from the other `ui::print_*` primitives
///
/// [`print_report_item`] carries the two-space `✓.green()` completed
/// summary row — same indent width, DIFFERENT glyph (thin checkmark vs.
/// forward arrow), DIFFERENT palette (`\x1b[32m` green vs. `\x1b[36m`
/// cyan), and DIFFERENT semantic layer (something already succeeded vs.
/// something about to happen or being narrated). [`print_pending_item`]
/// carries the two-space `⏳.yellow()` still-pending row — same indent
/// width, DIFFERENT glyph (hourglass vs. arrow), DIFFERENT palette
/// (`\x1b[33m` yellow vs. `\x1b[36m` cyan), and DIFFERENT semantic layer
/// (a background rollout the operator has to wait for vs. an operator-
/// log narration entry). Folding this primitive into either would
/// collapse the narrative-vs-completion or narrative-vs-in-flight
/// distinction at every site the operator has been trained to read.
///
/// # Distinct from the `.yellow()` three-space sibling grammar
///
/// `commands/codegen_validation.rs` carries one `"→".yellow()` site
/// under a THREE-space indent (`"   {} Codegen changes detected,
/// auto-committing..."`) that this primitive deliberately does NOT
/// enroll: the `\x1b[33m` yellow palette AND the three-space in-body
/// indent AND the "irregularity/attention" semantic together form a
/// distinct grammar (closer to an in-body [`print_step_warn`] variant
/// with an arrow glyph) than this wider-body cyan narrative marker. That
/// site stays unlifted by design.
///
/// # `.cyan()` on the glyph, plain on the message
///
/// Pre-lift every consumer spelled the coloring as `"→".cyan()` on the
/// GLYPH alone, never on the composed line (`format!("  → {}",
/// msg).cyan()`). The primitive preserves that split: the `\x1b[36m`
/// cyan ANSI sequence wraps the glyph, the message reaches the writer
/// uncolored, and the two-space indent is emitted OUTSIDE both spans —
/// so a terminal without color renders `  → <msg>` legibly.
///
/// # Compounding
///
/// Pre-lift 5 sibling sites across `commands/{rust_service (×1),
/// search_sync (×4)}.rs` each restated the `println!("  {} <fmt>",
/// "→".cyan(), <args>)` grammar verbatim, with the two-space indent,
/// the `→` forward-arrow glyph, and the `.cyan()` coloring on the
/// glyph all spelled inline. A future palette adjustment (a swap of
/// `→ ` for `[>] ` under a CI-log-friendly grammar, a promotion of
/// `.cyan()` to `.bright_cyan()` under a leaner narrative-vs-milestone
/// distinction, an OTLP `narration_emitted` observability event wired
/// alongside the print, a shift of the two-space indent to zero or
/// four spaces under a standardized report-indent) had to hit 5 sites
/// in lockstep or drift the visual grammar; post-lift it hits ONE
/// typed body. Delegates to [`write_arrow_item`] against
/// [`std::io::stdout()`]; the writer split exists so the fail-before-
/// pass test can pin the one-line body, the two-space indent, the `→`
/// glyph, and the `\x1b[36m` cyan ANSI palette contract by inspecting
/// emitted bytes rather than shelling out and grepping stdout.
pub fn print_arrow_item(message: &str) {
    let _ = write_arrow_item(&mut std::io::stdout().lock(), message);
}

/// Writer-taking sibling to [`print_arrow_item`]. Emits the single
/// `  <→.cyan()> <message>` line via [`writeln!`] against the supplied
/// writer. [`print_arrow_item`] is the stdout adapter; this variant
/// exists so tests can pin the one-line body, the two-space indent,
/// the `→` forward-arrow glyph, and the `\x1b[36m` cyan ANSI sequence
/// around the glyph (never the message) without capturing stdout.
pub fn write_arrow_item<W: std::io::Write>(w: &mut W, message: &str) -> std::io::Result<()> {
    writeln!(w, "  {} {}", "→".cyan(), message)
}

/// Prints the one-line `"  {} <message>"` (two-space indent + dimmed
/// `□` hollow-square glyph + plain message) wider-body watch-item
/// grammar every pre-lift consumer spelled inline as
/// `println!("  {} <literal>", "□".dimmed())`. Marks an unchecked
/// checkbox in a "WATCH FOR THESE ISSUES" operator-troubleshooting
/// checklist — a failure mode the operator has NOT yet observed but
/// should mentally tick off if it appears (a pod that fails to start,
/// a CrashLoopBackOff, a Hive Router that fails after a schema push, a
/// GraphQL query that fails post-deploy) — the exact-shape peer of
/// [`print_report_item`] on the two-space wider-body report-line
/// grammar but carrying the opposite tense (a hypothetical failure yet
/// to be inspected vs. a completed pass) and the opposite palette
/// weight (`.dimmed()` deprioritized vs. `.green()` foregrounded).
///
/// # Distinct from the other `ui::print_*` primitives
///
/// [`print_report_item`] carries the two-space `✓.green()` completed-
/// summary row — same indent width, DIFFERENT glyph (thin checkmark
/// vs. hollow square), DIFFERENT palette (`\x1b[32m` green vs.
/// `\x1b[2m` dim), and DIFFERENT semantic role (something already
/// succeeded vs. something to keep an eye on).
/// [`print_pending_item`] carries the two-space `⏳.yellow()` still-
/// in-flight row — same indent width, DIFFERENT glyph (hourglass vs.
/// hollow square), DIFFERENT palette (`\x1b[33m` yellow vs. `\x1b[2m`
/// dim), and DIFFERENT semantic role (a background rollout the
/// operator has to wait for vs. a failure mode the operator should
/// watch for). [`print_arrow_item`] carries the two-space `→.cyan()`
/// narrative-marker row — same indent width, DIFFERENT glyph
/// (forward-arrow vs. hollow square), DIFFERENT palette (`\x1b[36m`
/// cyan vs. `\x1b[2m` dim), and DIFFERENT semantic role (a forward-
/// pointing "here is what happens next" narration vs. a passive
/// "here is a failure mode to look out for" checklist entry). Folding
/// this primitive into any of the three would collapse the watch-vs-
/// passed, watch-vs-pending, or watch-vs-narrative visual distinction
/// at every site the operator has been trained to read.
///
/// # `.dimmed()` on the glyph, plain on the message
///
/// Pre-lift every consumer spelled the coloring as `"□".dimmed()` on
/// the GLYPH alone, never on the composed line (`format!("  □ {}",
/// msg).dimmed()`). The primitive preserves that split: the `\x1b[2m`
/// dim ANSI sequence wraps the glyph, the message reaches the writer
/// uncolored, and the two-space indent is emitted OUTSIDE both spans
/// — so a terminal without color renders `  □ <msg>` legibly.
///
/// # Compounding
///
/// Pre-lift 4 sibling sites in `commands/rust_service.rs` (the
/// `verify_deployment_status` "WATCH FOR THESE ISSUES" checklist:
/// Pod-fails-to-start, Pod-is-CrashLoopBackOff, Hive-Router-fails-
/// after-update, GraphQL-queries-fail) each restated the
/// `println!("  {} <literal>", "□".dimmed())` grammar verbatim, with
/// the two-space indent, the `□` hollow-square glyph, and the
/// `.dimmed()` coloring on the glyph all spelled inline. A future
/// palette adjustment (a swap of `□ ` for `[ ] ` under a CI-log-
/// friendly grammar, a promotion of `.dimmed()` to `.bright_black()`
/// under a leaner deprioritization contrast, an OTLP
/// `watch_item_emitted` observability event wired alongside the
/// print, a shift of the two-space indent to zero or four spaces
/// under a standardized report-indent) had to hit 4 sites in
/// lockstep or drift the visual grammar; post-lift it hits ONE typed
/// body. Delegates to [`write_watch_item`] against
/// [`std::io::stdout()`]; the writer split exists so the fail-before-
/// pass test can pin the one-line body, the two-space indent, the `□`
/// glyph, and the `\x1b[2m` dim ANSI palette contract by inspecting
/// emitted bytes rather than shelling out and grepping stdout.
pub fn print_watch_item(message: &str) {
    let _ = write_watch_item(&mut std::io::stdout().lock(), message);
}

/// Writer-taking sibling to [`print_watch_item`]. Emits the single
/// `  <□.dimmed()> <message>` line via [`writeln!`] against the
/// supplied writer. [`print_watch_item`] is the stdout adapter; this
/// variant exists so tests can pin the one-line body, the two-space
/// indent, the `□` hollow-square glyph, and the `\x1b[2m` dim ANSI
/// sequence around the glyph (never the message) without capturing
/// stdout.
pub fn write_watch_item<W: std::io::Write>(w: &mut W, message: &str) -> std::io::Result<()> {
    writeln!(w, "  {} {}", "□".dimmed(), message)
}

/// Prints the one-line `"    → <message>"` (four-space indent + plain
/// `→` forward-arrow glyph + single space + plain uncolored message)
/// nested arrow-hint grammar every pre-lift consumer in
/// `commands/rust_service.rs` spelled inline as
/// `println!("    → <literal>")`. Marks a sub-hint dangling one indent
/// scope BELOW a preceding [`print_watch_item`] (`"  □ <watch-item>"`)
/// entry in the operator's "WATCH FOR THESE ISSUES" troubleshooting
/// checklist — a leaf suggestion the operator should try if the parent
/// failure mode appears (e.g. "Pod fails to start" watch-item followed
/// by "Check logs for startup errors" / "Verify database connection" /
/// "Check if migrations broke the schema" leaf hints). One indent scope
/// deeper than [`print_arrow_item`]'s two-space `.cyan()` narrative
/// marker, and carries NO color so the leaf hints recede visually
/// beneath the `□`.dimmed()` watch-item head without competing for eye
/// attention.
///
/// # Distinct from the other `ui::print_*` primitives
///
/// [`print_arrow_item`] carries the two-space `→.cyan()` narrative-
/// marker row — DIFFERENT indent width (two vs. four spaces),
/// DIFFERENT palette (`\x1b[36m` cyan on the glyph vs. plain
/// uncolored), and DIFFERENT semantic role (a top-level "here is what
/// happens next" narration vs. a leaf troubleshooting hint dangling
/// beneath a `□.dimmed()` watch-item head). Folding this primitive
/// into `print_arrow_item` would either widen the narrative marker's
/// indent (silently pushing every `search_sync` and `rust_service`
/// narration two spaces to the right) or narrow the leaf hint's
/// indent (silently pulling every WATCH-FOR-THESE-ISSUES sub-hint
/// two spaces to the left, collapsing the visual nesting under the
/// `□` head), and either painting the leaf hints cyan (competing with
/// the `□.dimmed()` head for weight) or stripping the narrative
/// marker's cyan (losing the cross-consumer narrative signal). All
/// four drifts change the visual grammar at every site the operator
/// has been trained to read.
///
/// # No coloring at all
///
/// Pre-lift every consumer spelled the hint as a plain
/// `println!("    → <literal>")` with no `.dimmed()` / `.cyan()` /
/// `.italic()` chain — the leaf hint reaches the terminal with the
/// default palette so it recedes beneath the sibling `□.dimmed()`
/// watch-item head without competing for eye attention. The primitive
/// preserves that: neither the four-space indent, nor the `→` glyph,
/// nor the space, nor the message reach the writer through any
/// [`colored`] chain, so no `\x1b[<..>m` ANSI sequence appears in the
/// rendered line. A future palette adjustment that wraps this
/// primitive in `.dimmed()` is a deliberate additive edit; the
/// pre-lift shape reaches ONE typed boundary rather than 12 literal
/// sites.
///
/// # Compounding
///
/// Pre-lift 12 sibling sites in `commands/rust_service.rs` (the
/// `verify_deployment_status` "WATCH FOR THESE ISSUES" checklist:
/// Pod-fails-to-start ×3, Pod-is-CrashLoopBackOff ×3,
/// Hive-Router-fails-after-update ×3, GraphQL-queries-fail ×3) each
/// restated the `println!("    → <literal>")` grammar verbatim, with
/// the four-space indent, the `→` forward-arrow glyph, and the plain
/// uncolored default palette all spelled inline. A future adjustment
/// (a swap of `→ ` for `- ` under a CI-log-friendly grammar, a
/// promotion of the whole line to `.dimmed()` under a leaner leaf-vs-
/// head contrast, an OTLP `troubleshoot_hint_emitted` observability
/// event wired alongside the print, a shift of the four-space indent
/// to two or six spaces under a standardized report-indent) had to
/// hit 12 sites in lockstep or drift the visual grammar; post-lift it
/// hits ONE typed body. Delegates to [`write_arrow_hint`] against
/// [`std::io::stdout()`]; the writer split exists so the fail-before-
/// pass test can pin the one-line body, the four-space indent, the
/// `→` glyph, and the absence of every `\x1b[<..>m` ANSI palette
/// sequence by inspecting emitted bytes rather than shelling out and
/// grepping stdout.
pub fn print_arrow_hint(message: &str) {
    let _ = write_arrow_hint(&mut std::io::stdout().lock(), message);
}

/// Writer-taking sibling to [`print_arrow_hint`]. Emits the single
/// `"    → <message>"` line via [`writeln!`] against the supplied
/// writer. [`print_arrow_hint`] is the stdout adapter; this variant
/// exists so tests can pin the one-line body, the four-space indent,
/// the `→` forward-arrow glyph, and the ABSENCE of every ANSI palette
/// sequence around glyph or message without capturing stdout.
pub fn write_arrow_hint<W: std::io::Write>(w: &mut W, message: &str) -> std::io::Result<()> {
    writeln!(w, "    → {}", message)
}

/// Prints the one-line `"  • <message>"` (two-space indent + U+2022 `•`
/// BULLET glyph + single space + plain uncolored message) wider-body
/// declarative-item grammar every pre-lift consumer spelled inline as
/// `println!("  • <literal>")` or `println!("  • <fmt>", <args>)`
/// across four command modules. Marks a leaf entry inside a
/// human-facing declarative list under a `println!("<HEADING>:")`
/// heading — the "Generated files:" / "Updated files:" bullet rows
/// under `commands/{developer_tools,web_service}.rs::regenerate_*` /
/// `update_*` closers, the "Monitor deployment:" bullet rows under
/// `commands/deploy.rs`, the "Summary:" bullet rows under
/// `commands/comprehensive_release.rs` — an inert catalog the
/// operator reads for orientation, distinct from every semantic-loaded
/// glyph in the surrounding wider-body item grammar.
///
/// # Distinct from the other `ui::print_*` primitives
///
/// [`print_report_item`] carries the two-space `✓.green()` completed-
/// summary row — same two-space indent width, DIFFERENT glyph (thin
/// checkmark vs. U+2022 bullet), DIFFERENT palette (`\x1b[32m` green
/// on the glyph vs. plain uncolored), and DIFFERENT semantic role (a
/// per-item check-mark tally of what already succeeded vs. an
/// undecorated entry in a declarative list). [`print_pending_item`]
/// carries the two-space `⏳.yellow()` still-pending row — same
/// two-space indent width, DIFFERENT glyph (hourglass vs. bullet),
/// DIFFERENT palette (`\x1b[33m` yellow vs. plain), and DIFFERENT
/// semantic role (a background rollout the operator waits for vs. an
/// inert catalog entry). [`print_arrow_item`] carries the two-space
/// `→.cyan()` narrative marker — same two-space indent width,
/// DIFFERENT glyph (forward arrow vs. bullet), DIFFERENT palette
/// (`\x1b[36m` cyan vs. plain), and DIFFERENT semantic role (a
/// forward-pointing narration of what happens next vs. a static list
/// entry). [`print_watch_item`] carries the two-space `□.dimmed()`
/// watch-for-these-issues row — same two-space indent width,
/// DIFFERENT glyph (hollow square vs. filled bullet), DIFFERENT
/// palette (`\x1b[2m` dim vs. plain), and DIFFERENT semantic role (a
/// troubleshooting-checklist head the operator scans for problems vs.
/// a declarative list entry). Folding this primitive into any of the
/// four would either paint every "Generated files: <path>" bullet
/// row green/yellow/cyan/dim (colliding with the summary-tally,
/// pending, narrative, or watch-checklist grammars operators are
/// trained to read) or swap the U+2022 `•` glyph for `✓ / ⏳ / → / □`
/// (misclassifying an inert catalog entry as a completed step, an
/// in-flight step, a narration, or a troubleshooting head), silently
/// changing the visual grammar at every site.
///
/// # No coloring at all
///
/// Pre-lift every consumer spelled the row as a plain
/// `println!("  • <literal>")` / `println!("  • <fmt>", <args>)` with
/// no `.dimmed()` / `.green()` / `.cyan()` chain — the declarative
/// list entry reaches the terminal with the default palette so the
/// bullet catalog reads as inert data, not as a status signal. The
/// primitive preserves that: neither the two-space indent, nor the
/// `•` glyph, nor the space, nor the message reach the writer through
/// any [`colored`] chain, so no `\x1b[<..>m` ANSI sequence appears in
/// the rendered line. A future palette adjustment that wraps this
/// primitive in `.dimmed()` is a deliberate additive edit; the
/// pre-lift shape reaches ONE typed boundary rather than 24 literal
/// sites.
///
/// # U+2022 `•` BULLET, not U+00B7 `·` middle-dot or ASCII `*`
///
/// Pre-lift every consumer spelled the glyph as the U+2022 `•` BULLET
/// codepoint (three UTF-8 bytes `e2 80 a2`), not U+00B7 `·` middle-dot
/// (two UTF-8 bytes `c2 b7`), not the ASCII `*` asterisk. The
/// primitive preserves that: the exact three-byte `• ` sequence reaches
/// the writer between the two-space indent and the message. A swap to
/// `·` would render as a nearly-invisible middle-dot on most fonts; a
/// swap to `*` would collide with markdown/README list grammars the
/// operator reads in a wholly different visual register. Both drifts
/// are captured by the fail-before-pass envelope's byte-level match.
///
/// # Compounding
///
/// Pre-lift 24 sibling sites across `commands/{developer_tools (×11),
/// comprehensive_release (×5), deploy (×4), web_service (×4)}.rs`
/// each restated the `println!("  • <literal>")` or
/// `println!("  • <fmt>", <args>)` grammar verbatim (some as
/// single-line `println!`s, some spread across a four-line
/// `println!(\n    "  • <fmt>",\n    <arg>\n);` when the tail is a
/// ternary/format-expression argument), with the two-space indent,
/// the U+2022 `•` glyph, the single trailing space, and the absence of
/// every ANSI palette sequence all spelled inline. A future palette
/// adjustment (a swap of `• ` for `- ` under a markdown-friendly
/// grammar, a promotion of the bullet catalog to `.dimmed()` so a
/// heading pulls forward against a receded catalog, an OTLP
/// `bullet_item_emitted` observability event wired alongside the
/// print, a shift of the two-space indent to zero or four spaces
/// under a standardized report-indent) had to hit 24 sites in
/// lockstep or drift the visual grammar; post-lift it hits ONE typed
/// body. Delegates to [`write_bullet_item`] against
/// [`std::io::stdout()`]; the writer split exists so the fail-before-
/// pass test can pin the one-line body, the two-space indent, the
/// `•` U+2022 glyph, and the ABSENCE of every `\x1b[<..>m` ANSI
/// palette sequence by inspecting emitted bytes rather than shelling
/// out and grepping stdout.
pub fn print_bullet_item(message: &str) {
    let _ = write_bullet_item(&mut std::io::stdout().lock(), message);
}

/// Writer-taking sibling to [`print_bullet_item`]. Emits the single
/// `"  • <message>"` line via [`writeln!`] against the supplied
/// writer. [`print_bullet_item`] is the stdout adapter; this variant
/// exists so tests can pin the one-line body, the two-space indent,
/// the U+2022 `•` BULLET glyph, and the ABSENCE of every ANSI palette
/// sequence around glyph or message without capturing stdout.
pub fn write_bullet_item<W: std::io::Write>(w: &mut W, message: &str) -> std::io::Result<()> {
    writeln!(w, "  • {}", message)
}

/// Prints the one-line `"  {} <message>"` (two-space indent +
/// `bright_green`-colored `✅` glyph + plain message) wider-body
/// summary-pass grammar every pre-lift consumer in `commands/test.rs`
/// spelled inline as `println!("  {} <fmt>", "✅".bright_green(),
/// <args>)`. Marks the passing outcome of a whole test suite or a
/// whole test run — "Rust unit tests passed", "N test suite(s)
/// passed", "All tests passed!" — the exact-shape peer of
/// [`print_report_item`] on the two-space wider-body summary-row
/// grammar but carrying the heavier `.bright_green() ✅` palette the
/// pre-lift `commands/test.rs` consumers deliberately reserved for a
/// suite-completing pass (distinct from the thin-`✓.green()` per-row
/// completed marker), and one indent scope up from the three-space
/// `.green() ✅` in-body [`print_step_pass`] step-pass primitive.
///
/// # Distinct from the other `ui::print_*` primitives
///
/// [`print_step_pass`] carries the three-space `✅.green()` in-body
/// per-step pass — same `✅` glyph, DIFFERENT indent width (three
/// spaces vs. two), DIFFERENT palette (`\x1b[32m` green vs.
/// `\x1b[92m` bright_green), DIFFERENT semantic role (a per-step
/// checkpoint inside a pipeline vs. the closing summary of a whole
/// test suite/run). [`print_report_item`] carries the two-space
/// `✓.green()` completed-summary row — same two-space indent width,
/// DIFFERENT glyph (thin checkmark vs. filled emoji), DIFFERENT
/// palette (`\x1b[32m` green vs. `\x1b[92m` bright_green), DIFFERENT
/// semantic role (a per-item row in a multi-row summary block vs.
/// the single closing summary line of a suite/run). [`print_success`]
/// carries the zero-indent `✅ <MSG>.bright_green().bold()` milestone-
/// level completion sigil — DIFFERENT indent (zero vs. two spaces),
/// DIFFERENT palette weight (message-colored + `.bold()` vs. glyph-
/// only bright_green), DIFFERENT semantic role (a top-level command
/// milestone vs. the closing summary of a test suite/run inside a
/// command's body). Folding this primitive into any of the three
/// would collapse the summary-vs-step, summary-vs-per-item-row, or
/// summary-vs-milestone visual distinction at every site the
/// operator has been trained to read.
///
/// # `.bright_green()` on the glyph, plain on the message
///
/// Pre-lift every consumer spelled the coloring as
/// `"✅".bright_green()` on the GLYPH alone, never on the composed
/// line (`format!("  ✅ {}", msg).bright_green()`). The primitive
/// preserves that split: the `\x1b[92m` bright_green ANSI sequence
/// wraps the glyph, the message reaches the writer uncolored, and
/// the two-space indent is emitted OUTSIDE both spans — so a
/// terminal without color renders `  ✅ <msg>` legibly. A re-lift
/// that hoisted the color onto the whole line would paint the
/// message text bright_green at every site (colliding with the
/// `commands/test.rs:381-390` sibling that already `.dimmed()`s a
/// `", N skipped"` sub-field of the message and passes it as an
/// interpolated argument).
///
/// # `.bright_green()`, not `.green()`
///
/// Pre-lift every consumer at `commands/test.rs` spelled the palette
/// as `.bright_green()` (`\x1b[92m`), not `.green()` (`\x1b[32m`).
/// The distinction is load-bearing: `.green()` is the palette
/// [`print_step_pass`] and [`print_report_item`] already carry on
/// per-step and per-row grammars, and painting a suite/run summary
/// line in the same shade collapses the visual hierarchy the
/// pre-lift consumers deliberately reserved bright_green to mark.
///
/// # Compounding
///
/// Pre-lift 5 sibling sites in `commands/test.rs`
/// (`run_rust_tests`'s unit-tests-passed and integration-tests-passed
/// closers, `run_web_tests`'s `N test suite(s) passed` closer,
/// `run_test_suite`'s per-suite `<suite> tests passed` closer, and
/// `print_success_summary`'s `All tests passed!` closer) each
/// restated the `println!("  {} <fmt>", "✅".bright_green(), <args>)`
/// grammar verbatim, with the two-space indent, the `✅` glyph, and
/// the `.bright_green()` coloring on the glyph all spelled inline. A
/// future palette adjustment (a swap of `✅` for `✓` under a
/// CI-log-friendly grammar, a demotion of `.bright_green()` to
/// `.green()` under a leaner step-vs-summary distinction, an OTLP
/// `test_summary_pass_emitted` observability event wired alongside
/// the print, a shift of the two-space indent to zero or four spaces
/// under a standardized summary-indent) had to hit 5 sites in
/// lockstep or drift the visual grammar; post-lift it hits ONE typed
/// body. Delegates to [`write_summary_pass`] against
/// [`std::io::stdout()`]; the writer split exists so the fail-before-
/// pass test can pin the one-line body, the two-space indent, the
/// `✅` glyph, and the `\x1b[92m` bright_green ANSI palette contract
/// by inspecting emitted bytes rather than shelling out and grepping
/// stdout.
pub fn print_summary_pass(message: &str) {
    let _ = write_summary_pass(&mut std::io::stdout().lock(), message);
}

/// Writer-taking sibling to [`print_summary_pass`]. Emits the single
/// `  <✅.bright_green()> <message>` line via [`writeln!`] against
/// the supplied writer. [`print_summary_pass`] is the stdout
/// adapter; this variant exists so tests can pin the one-line body,
/// the two-space indent, the `✅` filled-emoji glyph, and the
/// `\x1b[92m` bright_green ANSI sequence around the glyph (never the
/// message) without capturing stdout.
pub fn write_summary_pass<W: std::io::Write>(w: &mut W, message: &str) -> std::io::Result<()> {
    writeln!(w, "  {} {}", "✅".bright_green(), message)
}

/// Prints the one-line `"── <label> ──"` dashed-label section-marker
/// 4 pre-lift consumer sites in `commands/prerelease.rs` spelled inline
/// as `println!("{}", "── <label> ──".dimmed())` — a `── ` prefix, a
/// literal label, a ` ──` suffix, the whole span painted `.dimmed()`.
/// Marks a diagnostic-stream boundary: the leading edge of a raw
/// `cargo test stdout` / `cargo test stderr` / `cargo test output` /
/// `stderr (last 40 lines)` block dumped below a failed gate. Sits
/// beneath the [`print_step_failure`] `❌` line that reports the gate
/// verdict and above the raw `for line in stdout.lines() { println!("
///    {}", line); }` echo — a lightweight visual boundary between the
/// operator-facing verdict and the debug-facing subprocess corpus.
///
/// # Distinct from the other `ui::print_*` primitives
///
/// [`print_section_header`] and [`print_section_completion_banner`]
/// carry the HEAVY `═` U+2550 double-horizontal rule at the top-level
/// section grammar — a permanent milestone the operator scrolls back
/// to find. This primitive carries the LIGHT `─` U+2500
/// single-horizontal rule at a nested diagnostic-block grammar — a
/// throwaway marker around a subprocess dump that only exists under a
/// failure. Folding the two would let a subprocess-stream boundary
/// promote to the top-level section grammar (or collapse a section
/// header down to a dimmed label) and drift the visual hierarchy.
/// [`print_step_info`] / [`print_step_warn`] / [`print_step_pass`] all
/// carry a three-space in-body indent with a leading glyph and a
/// message — they mark a per-step outcome, not a stream boundary; the
/// `── ` / ` ──` dash-fence carries the boundary semantics and this
/// primitive preserves it.
///
/// # Distinct from the bold+red E2E diagnostics sibling
///
/// `commands/prerelease.rs:891` carries the visually related
/// `println!("{}", "── E2E Failure Diagnostics ──".bold().red())` —
/// the same `── <label> ──` dash-fence shape but with a `.bold().red()`
/// palette instead of `.dimmed()`. That site is NOT enrolled in this
/// primitive: the `.bold().red()` palette marks it as the top-level
/// diagnostic-block heading for the whole E2E post-mortem (Docker
/// containers, images, screenshots, troubleshooting steps), one shade
/// louder than the per-stream `── cargo test stdout ──` labels
/// underneath which are `.dimmed()`. A future
/// `print_bold_red_dashed_marker` peer can lift that site if a second
/// bold+red diagnostic-header sibling appears.
///
/// # Palette on the whole span, NOT the label alone
///
/// Pre-lift every consumer spelled the coloring as
/// `"── cargo test stdout ──".dimmed()` — the `.dimmed()` wraps the
/// FULL literal (leading dashes + label + trailing dashes), not the
/// label text alone. The primitive preserves that: the `\x1b[2m ...
/// \x1b[0m` dimmed span begins BEFORE the leading `── ` and closes
/// AFTER the trailing ` ──`. A re-lift that split the coloring
/// (`.dimmed()` on the dashes alone with a plain label between) would
/// invert the visual weight — the label would jump forward against
/// the dimmed frame instead of receding into it — and change the
/// visual grammar silently.
///
/// # Compounding
///
/// Pre-lift 4 sibling sites each restated the `println!("{}",
/// "── <label> ──".dimmed())` grammar verbatim, with the `── ` prefix,
/// the ` ──` suffix, and the whole-span `.dimmed()` coloring all
/// spelled inline. A future palette adjustment (a swap of `── / ──`
/// for `[ / ]` under a CI-log-friendly grammar, a promotion of
/// `.dimmed()` to `.dimmed().italic()` under a leaner diagnostic-vs-
/// operator distinction, an OTLP `diagnostic_block_opened`
/// observability event wired alongside the print, a shift of the
/// U+2500 `─` to U+2015 `―` or ASCII `-` under a terminal-compatibility
/// pass) had to hit 4 sites in lockstep or drift the visual grammar;
/// post-lift it hits ONE typed body. Delegates to
/// [`write_dimmed_dashed_marker`] against [`std::io::stdout()`]; the
/// writer split exists so the fail-before-pass test can pin the
/// one-line body, the `── <label> ──` dash-fence shape, and the
/// `\x1b[2m` dimmed ANSI palette contract by inspecting emitted bytes
/// rather than shelling out and grepping stdout.
pub fn print_dimmed_dashed_marker(label: &str) {
    let _ = write_dimmed_dashed_marker(&mut std::io::stdout().lock(), label);
}

/// Writer-taking sibling to [`print_dimmed_dashed_marker`]. Emits the
/// single `<── <label> ──.dimmed()>` line via [`writeln!`] against
/// the supplied writer. [`print_dimmed_dashed_marker`] is the stdout
/// adapter; this variant exists so tests can pin the one-line body,
/// the `── ` prefix, the ` ──` suffix, and the `\x1b[2m` dimmed ANSI
/// sequence around the WHOLE dash-fence (never split between dashes
/// and label) without capturing stdout.
pub fn write_dimmed_dashed_marker<W: std::io::Write>(
    w: &mut W,
    label: &str,
) -> std::io::Result<()> {
    writeln!(w, "{}", format!("── {} ──", label).dimmed())
}

/// Prints the one-line `"   {} <message>"` (three-space indent + yellow
/// `⚠️` glyph + plain message) in-body step-warning grammar 5 pre-lift
/// consumer sites spelled inline as `println!("   {} <fmt>",
/// "⚠️".yellow(), <args>)` (or its multi-line spread across four to six
/// source lines when the message carries a `format!`-computed argument
/// list) across 5 command modules (`commands/{post_deploy_verification
/// (×2), frontend_validation (×1), migration_validation (×1),
/// prerelease (×1)}.rs`). Marks a non-fatal irregularity mid-body — a
/// retry attempt about to fire, a missing optional artifact, a skipped
/// pre-cleanup step — the exact-shape between-pass-and-failure sibling
/// to [`print_step_pass`]'s `.green() ✅` in-body pass and
/// [`print_step_failure`]'s `.red() ❌` in-body failure.
///
/// # Distinct from the other `ui::print_*` primitives
///
/// [`print_warning`] is a `bright_yellow().bold()` `⚠️ <msg>` line the
/// milestone-level command-warning sigil, emitted at the top-level of
/// the command (not indented inside a body) — the heavier palette
/// (`bright_yellow` rather than plain `.yellow()` on the glyph,
/// `.bold()` added, message-colored, no indent) marks it as a
/// command-level warning louder than an in-body step. This primitive
/// carries the LEANEST indented warning — a three-space indent, a
/// `.yellow()`-colored `⚠️` glyph, and a plain (uncolored) message —
/// every pre-lift consumer used inside a command's pipeline as an
/// in-body step-warning marker one step below a milestone-level
/// [`print_warning`], one shade calmer than [`print_step_failure`], and
/// visually paired with [`print_step_pass`] under the same three-space
/// body-indent grammar.
///
/// # `.yellow()` on the glyph, plain on the message
///
/// Pre-lift every consumer spelled the coloring as `"⚠️".yellow()` on
/// the GLYPH alone, never on the composed line (`format!("   ⚠️ {}",
/// msg).yellow()`). The primitive preserves that split: the `\x1b[33m`
/// yellow ANSI sequence wraps the glyph, the message reaches the writer
/// uncolored, and the three-space indent is emitted OUTSIDE both spans
/// — so a terminal without color renders `   ⚠️ <msg>` legibly. A
/// re-lift that hoisted the color onto the whole line would paint the
/// message text yellow at every site, changing the visual grammar
/// silently.
///
/// # stdout, not stderr
///
/// One nearby sibling — `commands/rust_service.rs:1884`'s "Skipping
/// image verification (no registry credentials available)" — spells the
/// same `"   {} <fmt>", "⚠️".yellow(), ...` visual grammar but routes
/// through `eprintln!` (stderr), not `println!` (stdout). That stanza
/// is deliberately NOT enrolled in this primitive: the stdout/stderr
/// stream is an observable behavior contract (a downstream consumer
/// piping stdout while leaving stderr on the terminal, a log-shipper
/// tagging streams differently), and folding it into a stdout
/// primitive would silently shift its output stream. A future
/// [`eprint_step_warn`] peer can lift that stderr-routed sibling class
/// once it grows past one site.
///
/// # Compounding
///
/// Pre-lift 5 sibling sites each restated the `println!("   {} <fmt>",
/// "⚠️".yellow(), <args>)` grammar verbatim, with the three-space
/// indent, the `⚠️` glyph, the `.yellow()` coloring on the glyph, and
/// the plain-message tail all spelled inline. A future palette
/// adjustment (a swap of `⚠️ ` for `!` under a CI-log-friendly grammar,
/// a promotion of `.yellow()` to `.bright_yellow()` under a leaner
/// step-vs-milestone distinction, an OTLP `step_warned` observability
/// event wired alongside the print, a shift of the three-space indent
/// to two- or four-space under a standardized body-indent) had to hit
/// 5 sites in lockstep or drift the visual grammar; post-lift it hits
/// ONE typed body. Delegates to [`write_step_warn`] against
/// [`std::io::stdout()`]; the writer split exists so the
/// fail-before-pass test can pin the one-line body, the three-space
/// indent, the `⚠️ ` glyph, and the `\x1b[33m` yellow ANSI palette
/// contract by inspecting emitted bytes rather than shelling out and
/// grepping stdout.
pub fn print_step_warn(message: &str) {
    let _ = write_step_warn(&mut std::io::stdout().lock(), message);
}

/// Writer-taking sibling to [`print_step_warn`]. Emits the single
/// `   <⚠️.yellow()> <message>` line via [`writeln!`] against the
/// supplied writer. [`print_step_warn`] is the stdout adapter; this
/// variant exists so tests can pin the one-line body, the three-space
/// indent, the `⚠️ ` glyph, and the `\x1b[33m` yellow ANSI sequence
/// around the glyph (never the message) without capturing stdout.
pub fn write_step_warn<W: std::io::Write>(w: &mut W, message: &str) -> std::io::Result<()> {
    writeln!(w, "   {} {}", "⚠️".yellow(), message)
}

/// Prints the one-line `"   {} {} failed (non-fatal): {}"` (three-space
/// indent + `"WARN".yellow()` textual prefix + verb-phrase label +
/// literal ` failed (non-fatal): ` connective + [`std::fmt::Display`]
/// error tail) stderr-routed non-fatal-failure grammar 5 pre-lift
/// consumer sites spelled inline as `eprintln!("   {} <label> failed
/// (non-fatal): {}", "WARN".yellow(), <opt-args>, e)` across a single
/// command module (`commands/product_release.rs`), each marking a
/// non-fatal failure inside the release pipeline — a source /
/// build-per-service / image-per-service attestation computation, a
/// product certification composition, or a post-deploy verification
/// re-invocation — where the pipeline deliberately continues under a
/// degraded contract (attestation absent, certification skipped,
/// staging verification hollow) rather than abort the release.
///
/// # Distinct from every peer `ui::print_*` primitive
///
/// [`print_step_warn`] shares the three-space body indent and yellow
/// palette but wears the `.yellow()`-colored `⚠️` emoji glyph on an
/// UNCOLORED tail, routes through STDOUT (not stderr), and carries a
/// PLAIN message with no fixed structural template — its consumer sites
/// mark an in-body irregularity mid-pipeline that the operator wants
/// drawn to attention (a retry attempt firing, a missing optional
/// artifact, a pre-cleanup surprise), NOT a non-fatal failure with an
/// error tail. [`print_warning`] is the milestone-level
/// `bright_yellow().bold()` `⚠️ <msg>` command-warning sigil emitted at
/// the top-level of the command with NO indent, NO error tail, and a
/// heavier palette — one scope above an in-body pipeline step.
/// [`print_step_failure`] shares the three-space body indent but wears
/// the `.red()`-colored `❌` glyph and routes through STDOUT — its
/// consumer sites mark a FATAL failure inside a validation pipeline
/// (a gate that has decided the release must abort), NOT a non-fatal
/// one where the caller has chosen to continue.
///
/// This primitive carries the SEVEN distinguishing properties every
/// pre-lift consumer site spelled in lockstep — a three-space indent,
/// a `"WARN".yellow()` TEXTUAL prefix (not the `⚠️` emoji glyph the
/// [`print_step_warn`] sibling wears), an interpolated verb-phrase
/// label naming what failed, the literal connective ` failed
/// (non-fatal): `, an interpolated [`std::fmt::Display`] error tail,
/// STDERR (`eprintln!`) routing rather than stdout, and a mandatory
/// error tail (no error-less call site — every pre-lift consumer bound
/// its `e` at the failure boundary). All seven together give this
/// primitive a distinct visual and semantic identity from every peer
/// UI primitive in this module.
///
/// # `"WARN"` text label, not the `⚠️` emoji glyph
///
/// Pre-lift every consumer spelled the marker as `"WARN".yellow()` —
/// the ASCII word `WARN` in yellow — rather than the `⚠️` emoji glyph
/// [`print_step_warn`] wears. The primitive preserves that split: a
/// terminal without emoji-glyph support (a CI runner's plain text log,
/// a downstream `grep`-in-logs pipeline pattern-matching on `\bWARN\b`,
/// a variable-width-font renderer that squashes the `⚠️` combining
/// pair) renders `   WARN <label> failed (non-fatal): <err>` legibly
/// where it would fold `   ⚠️ <label> failed (non-fatal): <err>` into
/// an unreadable shape. A future palette adjustment (a promotion to
/// `.yellow().bold()` for lower-contrast terminals, a swap of `"WARN"`
/// for `"⚠️  WARN"` under a "log-scanner + human-readable" hybrid, a
/// shift to `\x1b[93m` bright-yellow) hits ONE typed body rather than
/// 5 sites.
///
/// # stderr, not stdout
///
/// Every pre-lift consumer routed through `eprintln!` (stderr), not
/// `println!` (stdout). The primitive preserves that routing: the
/// stdout/stderr stream is an observable behavior contract (a
/// downstream consumer piping stdout while leaving stderr on the
/// terminal, a log-shipper tagging streams differently, a
/// `--json`-mode consumer parsing structured stdout while allowing
/// free-text human warnings to stderr), and folding this class into a
/// stdout primitive would silently shift the release pipeline's
/// non-fatal warnings out of the stderr channel operators pipe
/// separately to alerts. Distinct from [`print_step_warn`]'s stdout
/// routing.
///
/// # Mandatory error tail
///
/// The signature takes `err: &dyn std::fmt::Display` rather than
/// folding it into `what` — every pre-lift consumer bound its `e` at
/// the failure boundary, and the primitive splits the label (the
/// caller's static verb-phrase describing what failed, e.g. `"Source
/// attestation"` or `"Post-deploy verification"`) from the runtime
/// error state so the `failed (non-fatal): ` connective lives ONCE in
/// the primitive body rather than being spelled by each caller.
/// `anyhow::Error` implements [`std::fmt::Display`], so every pre-lift
/// `e` binding forwards through unchanged; a caller with a
/// [`std::io::Error`] or a boxed dyn error can also forward directly
/// without adaptation.
///
/// # Compounding
///
/// Pre-lift 5 sibling sites each restated the `eprintln!("   {}
/// <label> failed (non-fatal): {}", "WARN".yellow(), ..., e)` grammar
/// verbatim, with the three-space indent, the `"WARN"` textual prefix,
/// the `.yellow()` coloring, the ` failed (non-fatal): ` connective,
/// the stderr routing, and the `Display`-formatted error tail all
/// spelled inline. A future adjustment — routing them through
/// `tracing::warn!(target: "forge::release", ...)` for structured
/// observability so a downstream OTLP subscriber can count non-fatal
/// failures per release stage, promoting them to hard errors under
/// `--strict-attestation` mode, collecting them into a
/// release-completion summary panel, standardizing the connective on a
/// locale-neutral `" — non-fatal: "`, promoting `.yellow()` to
/// `.yellow().bold()` under a lower-contrast-terminal grammar — had
/// to hit 5 sites in lockstep or drift the surface (label palette,
/// connective, destination stream, glyph vs text). Post-lift the
/// stream, prefix, connective, and coloring live in ONE writer body
/// and the sites carry only the (label, error) pair. Delegates to
/// [`write_nonfatal_warn`] against [`std::io::stderr`]; the writer
/// split exists so the fail-before-pass test can pin the one-line
/// body, the three-space indent, the `WARN` text (not `⚠️`), the
/// `\x1b[33m` yellow ANSI palette contract, the ` failed (non-fatal):
/// ` connective, and the trailing error interpolation by inspecting
/// emitted bytes rather than shelling out and grepping stderr.
pub fn print_nonfatal_warn(what: &str, err: &dyn std::fmt::Display) {
    let _ = write_nonfatal_warn(&mut std::io::stderr().lock(), what, err);
}

/// Writer-taking sibling to [`print_nonfatal_warn`]. Emits the single
/// `   <WARN.yellow()> <what> failed (non-fatal): <err>` line via
/// [`writeln!`] against the supplied writer. [`print_nonfatal_warn`]
/// is the stderr adapter; this variant exists so tests can pin the
/// one-line body, the three-space indent, the `WARN` text prefix, the
/// `\x1b[33m` yellow ANSI sequence around the prefix (never the label
/// or the error), the literal ` failed (non-fatal): ` connective, and
/// the error interpolation without capturing stderr.
pub fn write_nonfatal_warn<W: std::io::Write>(
    w: &mut W,
    what: &str,
    err: &dyn std::fmt::Display,
) -> std::io::Result<()> {
    writeln!(
        w,
        "   {} {} failed (non-fatal): {}",
        "WARN".yellow(),
        what,
        err
    )
}

/// Prints the single `   ⚠️  <msg>: <err>` (three-space indent + UNCOLORED
/// `⚠️` emoji glyph + two spaces + caller-supplied message + literal `: `
/// connective + [`std::fmt::Display`]-formatted error tail) stderr-routed
/// step-warn-with-error grammar 6 pre-lift consumer sites spelled inline
/// as `eprintln!("   ⚠️  <msg>: {}", <err>)` across
/// `commands/rust_service.rs` (×4 non-fatal Attic closure-push /
/// `path-info-recursive` branches inside the crate2nix build orchestrator
/// where a cache miss must NOT abort the release) and
/// `commands/federation_tests.rs` (×2 could-not-fetch-job-logs branches
/// on the Kubernetes-side diagnostic gather-up path).
///
/// # Distinct from every peer `ui::*` primitive
///
/// [`print_step_warn`] shares the three-space indent and the `⚠️` glyph
/// but wears a `.yellow()`-COLORED glyph, routes through STDOUT (not
/// stderr), carries a plain message with NO error tail and NO fixed `: `
/// connective — its consumer sites mark an in-body irregularity mid-
/// pipeline drawn to attention with a self-contained sentence, NOT a
/// non-fatal caught-error with an interpolated `Display` cause. This
/// primitive is the stderr sibling with a mandatory error tail.
///
/// [`print_nonfatal_warn`] shares the stderr routing and the mandatory
/// error tail but wears the `"WARN".yellow()` ASCII TEXT prefix
/// (specifically NOT the `⚠️` emoji glyph), enforces the fixed
/// `<label> failed (non-fatal): <err>` template with the ` failed
/// (non-fatal): ` connective spelled once inside the primitive, and
/// consumer sites carry only a static verb-phrase label — not a full
/// caller-composed sentence that may or may not carry a `(non-fatal)`
/// annotation of its own. This primitive is the emoji-glyph sibling
/// with a caller-composed message body: the ` failed (non-fatal): `
/// grammar is not part of its contract; when a caller wants that
/// connective it spells it inside the message.
///
/// # UNCOLORED `⚠️` glyph, not `.yellow()`
///
/// Pre-lift every consumer spelled the marker as the bare `⚠️` glyph
/// inside the format string literal, with NO `.yellow()` styling applied
/// — distinct from [`print_step_warn`]'s `.yellow()`-colored `⚠️`. A
/// terminal-log inspector, a downstream `grep`-in-logs pipeline, or a
/// CI-log renderer without `\x1b[33m` interpretation renders the pre-lift
/// bytes verbatim; the primitive preserves that byte contract. A future
/// palette adjustment (promoting to `.yellow()` for visual consistency
/// with the [`print_step_warn`] sibling, promoting to `.bright_yellow()`
/// under a milestone grammar, or switching to `"WARN".yellow()` to fold
/// into the [`print_nonfatal_warn`] template) hits ONE typed body rather
/// than 6 sites.
///
/// # stderr, not stdout
///
/// Every pre-lift consumer routed through `eprintln!` (stderr), not
/// `println!` (stdout). The primitive preserves that routing: the
/// stdout/stderr stream is an observable behavior contract (a downstream
/// consumer piping stdout while leaving stderr on the terminal, a
/// log-shipper tagging streams differently) and folding this class into
/// a stdout primitive would silently shift these in-body non-fatal
/// caught-error warnings out of the stderr channel operators pipe
/// separately to alerts.
///
/// # Mandatory error tail
///
/// The signature takes `err: &dyn std::fmt::Display` rather than folding
/// it into `msg` — every pre-lift consumer bound its `e` (an
/// [`anyhow::Error`] at the closure-push failure boundary) or a
/// [`std::borrow::Cow`] over the pod's stderr bytes (rendered through
/// [`crate::repo::utf8_lossy_borrow`]) at the failure boundary and
/// interpolated it after a literal `: ` connective. The primitive
/// splits the message (the caller's composed sentence, which may itself
/// carry a `(non-fatal)` parenthetical) from the runtime error state so
/// the `: ` connective lives ONCE in the primitive body rather than
/// being spelled by each caller.
///
/// # Compounding
///
/// Pre-lift 6 sibling sites each restated the `eprintln!("   ⚠️  <msg>:
/// {}", <err>)` grammar verbatim, with the three-space indent, the `⚠️`
/// emoji glyph, the two spaces after the glyph, the `: ` connective, the
/// stderr routing, and the `Display`-formatted error tail all spelled
/// inline. A future adjustment — routing them through
/// `tracing::warn!(target: "forge::pipeline", ...)` for structured
/// observability so a downstream OTLP subscriber can count in-body
/// non-fatal caught-errors per pipeline stage, promoting the glyph to
/// `.yellow()` under a palette-consistency grammar, shifting the `: `
/// connective to `" — "`, promoting to `.yellow().bold()` under a
/// lower-contrast-terminal grammar — had to hit 6 sites in lockstep or
/// drift the surface. Post-lift the glyph, connective, and destination
/// stream live in ONE writer body; the sites carry only the (msg, err)
/// pair. Delegates to [`write_eprint_step_warn`] against
/// [`std::io::stderr`]; the writer split exists so the fail-before-pass
/// test can pin the one-line body, the three-space indent, the `⚠️`
/// glyph (never `WARN` text — that grammar belongs to
/// [`write_nonfatal_warn`]), the two-space post-glyph gap, the `: `
/// connective, and the trailing error interpolation by inspecting
/// emitted bytes rather than shelling out and grepping stderr.
///
/// `#[allow(dead_code)]` mirrors the pre-existing baseline flags on
/// every consumer function that carries a call site — `build_rust_service`
/// (holds ×4 sites) and `wait_for_job_completion` /
/// `run_federation_tests` (hold ×2 sites) are all dead-code-flagged
/// under `cargo clippy --all-targets` on the main `forge` bin target
/// because clippy's cross-module reachability does not trace the CLI
/// dispatch table, so a primitive called ONLY from dead-flagged
/// consumers is itself flagged; the allowance closes that
/// baseline-inherited noise without hiding a real dead-code find.
#[allow(dead_code)]
pub fn eprint_step_warn(msg: &str, err: &dyn std::fmt::Display) {
    let _ = write_eprint_step_warn(&mut std::io::stderr().lock(), msg, err);
}

/// Writer-taking sibling to [`eprint_step_warn`]. Emits the single
/// `   ⚠️  <msg>: <err>` line via [`writeln!`] against the supplied
/// writer. [`eprint_step_warn`] is the stderr adapter; this variant
/// exists so tests can pin the one-line body, the three-space indent,
/// the UNCOLORED `⚠️` emoji glyph, the two-space post-glyph gap, the
/// `: ` connective, and the trailing error interpolation without
/// capturing stderr.
///
/// `#[allow(dead_code)]` mirrors the sibling on [`eprint_step_warn`]:
/// this writer's only production caller is the [`eprint_step_warn`]
/// stdout adapter, whose own dead-code-flagged consumers propagate the
/// flag transitively through the delegation chain.
#[allow(dead_code)]
pub fn write_eprint_step_warn<W: std::io::Write>(
    w: &mut W,
    msg: &str,
    err: &dyn std::fmt::Display,
) -> std::io::Result<()> {
    writeln!(w, "   ⚠️  {}: {}", msg, err)
}

/// Prints the single `   <○.yellow()> <message>` line 5 pre-lift
/// consumer sites spelled inline as `println!("   {} <fmt>",
/// "○".yellow(), <args>)`. Peer to [`print_step_pass`] (`✅.green()` /
/// `\x1b[32m`), [`print_step_failure`] (`❌.red()` / `\x1b[31m`), and
/// [`print_step_warn`] (`⚠️.yellow()` / `\x1b[33m` — same yellow shade,
/// different glyph and semantic layer): a gate/step that was
/// deliberately NOT executed under this run — skipped by a `--skip-*`
/// flag, a missing prerequisite, an "example type, no entity required"
/// classification — is neither a pass, a failure, nor a warning about
/// something that DID execute; it is a distinct outcome kind, and the
/// pre-lift call sites uniformly reached for the hollow-circle `○`
/// glyph in yellow to name it.
///
/// # Distinct from [`print_step_warn`]
///
/// Both wear the `.yellow()` palette (same `\x1b[33m` ANSI sequence)
/// under a shared three-space-indent body grammar, but they carry
/// different glyphs (`○` vs `⚠️`) and different semantic layers: a
/// step-warn narrates that something DID happen and the caller wants
/// to draw attention to it (a retry attempt failing, a missing
/// manifest the pipeline recovered from, a pre-cleanup surprise); a
/// step-skip narrates that something DID NOT happen because the
/// pipeline routed around it (`--skip-entities`, `DATABASE_URL not
/// set`, `example type, no entity required`, `ReBAC validation
/// skipped: {}`). A future palette adjustment (a shade shift on the
/// skip glyph to `.dimmed()` to visually deprioritize skips relative
/// to warns, a dedicated `\x1b[90m` gray palette for skips, a glyph
/// swap under a CI-log-friendly grammar) hits ONE typed body rather
/// than 5 sites.
///
/// # `.yellow()` on the glyph, plain on the message
///
/// Pre-lift every consumer spelled the coloring as `"○".yellow()` on
/// the GLYPH alone, never on the composed line (`format!("   ○ {}",
/// msg).yellow()`). The primitive preserves that split: the
/// `\x1b[33m` yellow ANSI sequence wraps the glyph, the message
/// reaches the writer uncolored, and the three-space indent is
/// emitted OUTSIDE both spans — so a terminal without color renders
/// `   ○ <msg>` legibly.
///
/// # Compounding
///
/// Pre-lift 5 sibling sites each restated the `println!("   {}
/// <fmt>", "○".yellow(), <args>)` grammar verbatim, with the
/// three-space indent, the `○` glyph, the `.yellow()` coloring on the
/// glyph, and the plain-message tail all spelled inline. A future
/// palette adjustment or an OTLP `step_skipped` observability event
/// wired alongside the print had to hit 5 sites in lockstep or drift
/// the visual grammar; post-lift it hits ONE typed body. Delegates
/// to [`write_step_skip`] against [`std::io::stdout()`]; the writer
/// split exists so the fail-before-pass test can pin the one-line
/// body, the three-space indent, the `○` glyph, and the `\x1b[33m`
/// yellow ANSI palette contract by inspecting emitted bytes.
pub fn print_step_skip(message: &str) {
    let _ = write_step_skip(&mut std::io::stdout().lock(), message);
}

/// Writer-taking sibling to [`print_step_skip`]. Emits the single
/// `   <○.yellow()> <message>` line via [`writeln!`] against the
/// supplied writer. [`print_step_skip`] is the stdout adapter; this
/// variant exists so tests can pin the one-line body, the three-space
/// indent, the `○` glyph, and the `\x1b[33m` yellow ANSI sequence
/// around the glyph (never the message) without capturing stdout.
pub fn write_step_skip<W: std::io::Write>(w: &mut W, message: &str) -> std::io::Result<()> {
    writeln!(w, "   {} {}", "○".yellow(), message)
}

/// Prints the one-line `"ℹ️  <message>"` (info glyph + two spaces +
/// plain message, uncolored, no indent) in-body step-info grammar 15
/// pre-lift consumer sites spelled inline as `println!("ℹ️  <fmt>",
/// <args>)` (or its multi-line spread across three to four source
/// lines when the message carries a `format!`-computed argument list)
/// across 8 command modules (`commands/{federation (×4),
/// rust_service (×6), migrations (×1), schema_validation (×1),
/// developer_tools (×2), search_sync (×1)}.rs`). Marks a non-executing
/// note within a command's readout — a "skip because <precondition>"
/// explanation, a follow-up hint after a milestone
/// ("Image pushed to <registry>:<tag>", "Flux will handle deployment
/// - use 'kubectl get pods -n <ns>' to monitor",
/// "Run `flux reconcile helmrelease <name>` to force immediate
/// reconciliation."), or a bare fact about the environment
/// ("No existing Cargo.lock found", "No migrations directory found",
/// "Search sync is disabled, skipping") — the exact-shape sibling to
/// [`print_step_pass`]'s `.green() ✅` in-body pass,
/// [`print_step_failure`]'s `.red() ❌` in-body failure,
/// [`print_step_warn`]'s `.yellow() ⚠️` in-body warn, and
/// [`print_step_skip`]'s `.yellow() ○` in-body skip.
///
/// # Distinct from the other `ui::print_*` primitives
///
/// [`print_info`] is a `bright_cyan()` `ℹ️  <msg>` milestone-level info
/// sigil the caller reaches for when the whole line should paint cyan
/// to lift it above the body text — a heavier palette than every
/// pre-lift consumer of this primitive used. This primitive carries
/// the LEANEST info line — no indent, no color, just the `ℹ️  ` glyph
/// + two spaces + plain message — every pre-lift consumer used inside
/// a command's body as a plain-note sigil that reads legibly on both
/// a color-capable TTY and a CI log with color stripped, without
/// competing visually with an adjacent `.green()` / `.red()` / `.yellow()`
/// step marker. The 3-space-indented sibling `println!("   ℹ️  ...")` in
/// `commands/migrations.rs` (three sites) carries a distinct
/// deeper-nested visual grammar and is NOT enrolled in this class.
///
/// # Uncolored — no palette to preserve
///
/// Pre-lift every consumer spelled the whole line plain — no `.color()`
/// chain on the glyph, no `format!(...).color()` wrap on the composed
/// line. The primitive preserves that: the writer receives `ℹ️  <msg>\n`
/// with no ANSI escape sequences anywhere, so a terminal without color
/// renders exactly what a color-capable one does. A future promotion to
/// `.bright_cyan()` on the whole line would collide with the sibling
/// milestone-level [`print_info`] grammar — pin the uncolored contract in
/// the test so a "just call `print_info` now, it's got a nicer palette"
/// cleanup fails loudly instead of silently changing the shape of every
/// site.
///
/// # Compounding
///
/// Pre-lift 15 sibling sites each restated the `println!("ℹ️  <fmt>",
/// <args>)` grammar verbatim, with the `ℹ️` glyph, the two-space gap
/// (the emoji renders with variable width across terminals — the second
/// space is a legibility hedge every pre-lift consumer carried), and
/// the plain-message tail all spelled inline. A future palette
/// adjustment (a swap of `ℹ️  ` for `[i] ` under a CI-log-friendly
/// grammar, a promotion to `.dimmed()` under a "notes are quieter than
/// steps" cleanup, an OTLP `step_noted` observability event wired
/// alongside the print, a shift to `writeln!` against `stderr` so notes
/// route out-of-band) had to hit 15 sites in lockstep or drift the
/// visual grammar; post-lift it hits ONE typed body. Delegates to
/// [`write_step_info`] against [`std::io::stdout()`]; the writer split
/// exists so the fail-before-pass test can pin the one-line body, the
/// `ℹ️  ` glyph + two-space gap, and the absence-of-any-ANSI-escape
/// contract by inspecting emitted bytes rather than shelling out and
/// grepping stdout.
pub fn print_step_info(message: &str) {
    let _ = write_step_info(&mut std::io::stdout().lock(), message);
}

/// Writer-taking sibling to [`print_step_info`]. Emits the single
/// `ℹ️  <message>` line via [`writeln!`] against the supplied writer.
/// [`print_step_info`] is the stdout adapter; this variant exists so
/// tests can pin the one-line body, the `ℹ️  ` glyph + two-space gap,
/// and the absence of any ANSI escape sequence without capturing
/// stdout.
pub fn write_step_info<W: std::io::Write>(w: &mut W, message: &str) -> std::io::Result<()> {
    writeln!(w, "ℹ️  {}", message)
}

/// Prints the two-line `"=".repeat(<width>)` ASCII rule + trailing
/// blank grammar 14 pre-lift consumer sites spelled inline as
/// `println!("{}", "=".repeat(<50|60>)); println!();` across 5
/// command modules (`commands/{rust_service (×6), developer_tools
/// (×4), web_service (×2), rollback (×1), product_release (×1)}.rs`).
/// Emitted directly beneath a multi-part styled command-intro title
/// (the caller's `println!("🔄 {} {} {}", ...)` /
/// `println!("🚀 {} {} {}", ...)` line), the rule underlines that
/// title and the blank line separates the intro banner from the body
/// that follows.
///
/// # Distinct from the other `ui::print_*` primitives
///
/// [`print_header`] is a `╔═╗` boxed top-level command title in
/// `bright_blue` — heavy Unicode box-drawing, a self-contained
/// framed title, no preceding caller `println!`. [`print_section_header`]
/// is a `═`-rule + bold-title + `═`-rule triple around a section
/// opening WITHIN a pipeline — heavy Unicode rule, palette-carrying,
/// title-CONTAINED. This primitive carries the LEANEST intro
/// separator — a single-byte `=` ASCII rule + a blank line, no color,
/// no title inside — every pre-lift consumer emitted it as an
/// UNDERLINE for a multi-part styled title the caller had just
/// printed on the preceding line, closing the command-intro banner
/// and opening the body.
///
/// # Compounding
///
/// Pre-lift 14 sibling sites each restated the two-line
/// `println!("{}", "=".repeat(<width>)); println!();` grammar
/// verbatim, with the rule character (`=`), the rule mechanism
/// (`"=".repeat(...)`), and the trailing framing blank
/// (`println!()`) all spelled inline. A future palette adjustment
/// (a swap of `=` for `─` or `━` under a leaner-vs-heavier rule
/// distinction, a promotion to a colored bar under a themed
/// palette, dropping the trailing blank in favor of tighter body
/// spacing, standardizing the two pre-lift widths (50 and 60) onto
/// a single canonical intro-banner width) had to hit 14 sites in
/// lockstep or drift the visual grammar; post-lift it hits ONE
/// typed body. Delegates to [`write_ascii_title_underline`] against
/// [`std::io::stdout()`]; the writer split exists so the
/// fail-before-pass test can pin the exact rule byte-count, the
/// trailing blank line, and the absence of coloring by inspecting
/// emitted bytes rather than shelling out and grepping stdout.
pub fn print_ascii_title_underline(width: usize) {
    let _ = write_ascii_title_underline(&mut std::io::stdout().lock(), width);
}

/// Writer-taking sibling to [`print_ascii_title_underline`]. Emits
/// the two-line body (`"=".repeat(width)` ASCII rule then a blank
/// line) via [`writeln!`] against the supplied writer.
/// [`print_ascii_title_underline`] is the stdout adapter; this
/// variant exists so tests can pin the rule byte-count, the trailing
/// blank, and the plain (uncolored) ASCII palette without capturing
/// stdout.
pub fn write_ascii_title_underline<W: std::io::Write>(
    w: &mut W,
    width: usize,
) -> std::io::Result<()> {
    writeln!(w, "{}", "=".repeat(width))?;
    writeln!(w)
}

/// Rule width every pre-lift report-section-subheader stanza in
/// `commands/rust_service.rs`'s `print_deployment_report` fed to
/// [`String::repeat`] verbatim (the literal `80`). Pinned as one
/// named constant so a future narrowing (e.g. to fit an 80-column
/// terminal that already carries a 2-space caller indent, so the
/// rule folds onto a second line) or widening (a shift to `120` to
/// match a wider report grammar) happens at ONE typed boundary
/// rather than five literal-argument sites.
const REPORT_SECTION_SUBHEADER_RULE_WIDTH: usize = 80;

/// Rule glyph every pre-lift report-section-subheader stanza fed to
/// [`String::repeat`] verbatim (a single-character `─`, U+2500 BOX
/// DRAWINGS LIGHT HORIZONTAL). Pinned as one named constant so a
/// future swap of the subheader grammar's rule character (a
/// promotion to `━` for a heavier boundary, a demotion to `-` for
/// an ASCII-only fallback under a color-stripped log) happens at
/// ONE typed boundary rather than five literal-argument sites.
///
/// The glyph is distinct from every peer's — [`write_success_banner`]
/// uses `━` in `bright_green` (a heavier + colored terminal-success
/// milestone), [`write_ascii_bar_banner`] uses `=` uncolored (an
/// ASCII-only per-chart-action boundary), [`write_section_header`]
/// uses `═` bold uncolored (a section opening triple), and
/// [`write_ascii_title_underline`] uses `=` uncolored (a
/// command-intro underline). This primitive carries the LIGHTEST +
/// DIMMED rule grammar the report-body subheaders wear beneath a
/// bold-colored title inside `print_deployment_report`.
const REPORT_SECTION_SUBHEADER_RULE_CHAR: &str = "─";

/// Palette [`print_report_section_subheader`] accepts. Each variant
/// spliced into the fixed `<title>.<COLOR>().bold()` styling every
/// pre-lift consumer spelled hard-coded verbatim, closed to the
/// exact three colors the pre-lift 5-site sibling class in
/// `commands/rust_service.rs`'s `print_deployment_report` carried
/// and nothing more — a new palette entry is a deliberate additive
/// edit, not an open call-site choice.
///
/// # Compounding
///
/// Pre-lift each of the 5 sibling `println!("{}", "<TITLE>".<COLOR>
/// ().bold()); println!("{}", "─".repeat(80).dimmed());` sites nailed
/// the color into a method chain at the call site; a rename that
/// misspells `.green` as `.grne` would compile-fail (unlike the
/// [`SpinnerStyle`] indicatif-template class, which silently
/// degrades on a typo), but a swap of `.yellow().bold()` for
/// `.red().bold()` in one site alone would drift the visual grammar
/// silently — the 5 subheaders lose their eye-navigation
/// categorization (success / pending / info) without any compile
/// failure. Post-lift the mapping [`ReportSectionStyle`] →
/// [`colored::ColoredString`] lives in ONE match arm; the enum is
/// closed, so a future variant added without an arm fails the
/// exhaustiveness check at build time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportSectionStyle {
    /// Success-track subheader (`<title>.green().bold()`). 2 pre-lift
    /// sites in `commands/rust_service.rs`'s
    /// `print_deployment_report` — the `✅ COMPLETED ACTIONS`
    /// subheader opening the completed-actions readout and the
    /// `✓ VERIFICATION COMMANDS` subheader opening the
    /// verification-commands readout.
    Success,
    /// Warning-track subheader (`<title>.yellow().bold()`). 2 pre-lift
    /// sites in `commands/rust_service.rs`'s
    /// `print_deployment_report` — the `⏳ PENDING ROLLOUTS`
    /// subheader opening the pending-rollouts readout and the
    /// `⚠️  WATCH FOR THESE ISSUES` subheader opening the
    /// watch-for-issues readout.
    Warning,
    /// Info-track subheader (`<title>.cyan().bold()`). 1 pre-lift
    /// site in `commands/rust_service.rs`'s
    /// `print_deployment_report` — the `🔍 MONITORING COMMANDS`
    /// subheader opening the monitoring-commands readout.
    Info,
}

/// Prints the two-line report-section-subheader grammar every
/// pre-lift consumer spelled inline as `println!("{}", "<TITLE>".
/// <COLOR>().bold()); println!("{}", "─".repeat(80).dimmed());`
/// across 5 sibling sites in `commands/rust_service.rs`'s
/// `print_deployment_report` — a `.bold()`-and-colored title line
/// followed by a dimmed 80-glyph `─` rule that visually opens one
/// subsection of the deployment-report body ("what happened",
/// "what will happen next", "how to check", "how to watch", "what
/// to watch for").
///
/// Delegates to [`write_report_section_subheader`] against
/// [`std::io::stdout()`]; the writer split exists so the
/// fail-before-pass test can pin the two-line body, the palette per
/// [`ReportSectionStyle`], the dimmed 80-glyph `─` rule, and the
/// `\x1b[2m` dim ANSI palette contract on the rule by inspecting
/// emitted bytes rather than shelling out and grepping stdout.
///
/// # Distinct from the other `ui::print_*` primitives
///
/// [`print_step_heading`] is a bare `<title>.bold()` line with no
/// trailing rule — its consumer sites open a numbered pipeline step
/// whose body follows immediately, not a report-body subsection
/// separated from its readout by a rule. [`print_section_header`]
/// is a `═`-rule + bold-title + `═`-rule triple around a section
/// opening WITHIN a pipeline — heavy Unicode `═` rule
/// (uncolored), title-CONTAINED between two rules, no color choice.
/// [`print_ascii_title_underline`] is a two-line `=`-rule + blank
/// separator emitted BENEATH a caller's multi-part styled
/// command-intro title, not carrying its own title or coloring.
/// [`print_success_banner`] and [`print_release_stage_banner`] are
/// three-line `━` / `=` colored rule + colored headline + rule
/// terminal-milestone banners. This primitive carries the report-body
/// subheader grammar: title line ABOVE a dimmed light-rule (the
/// only such shape in the crate), colored per the
/// [`ReportSectionStyle`]-signaled section role
/// (success / warning / info) so the eye can navigate the report
/// body by color band alone.
///
/// # Compounding
///
/// Pre-lift 5 sibling sites each restated the two-line stanza
/// verbatim, with the title text, the color method
/// (`.green()` / `.yellow()` / `.cyan()`), the `.bold()` chain, the
/// rule character (`─`), the rule width (80), and the `.dimmed()`
/// rule styling all spelled inline. A future adjustment (a swap of
/// `─` for `━` under a heavier boundary grammar, a shift to a
/// caller-computed width so the rule tracks the surrounding
/// deployment report's actual column count, a promotion of
/// `.dimmed()` to `.bright_black()` under a friendlier
/// low-contrast-terminal readout, an OTLP `report_section_opened`
/// span wired alongside the print) had to hit 5 sites in lockstep
/// or drift the visual grammar; post-lift it hits ONE typed body.
/// The [`ReportSectionStyle`] enum being closed additionally guards
/// against a future consumer inventing a fourth palette (a
/// `.magenta().bold()` "critical" subheader) without a deliberate
/// enum extension.
pub fn print_report_section_subheader(title: &str, style: ReportSectionStyle) {
    let _ = write_report_section_subheader(&mut std::io::stdout().lock(), title, style);
}

/// Writer-taking sibling to [`print_report_section_subheader`].
/// Emits the two report-subheader lines
/// (`<title>.<COLOR>().bold()` per [`ReportSectionStyle`], then
/// `"─".repeat(80).dimmed()` rule) via [`writeln!`] against the
/// supplied writer. [`print_report_section_subheader`] is the
/// stdout adapter; this variant exists so tests can pin the
/// two-line body, the palette mapping, the dimmed 80-glyph `─`
/// rule, and the `\x1b[2m` dim ANSI sequence on the rule without
/// capturing stdout.
pub fn write_report_section_subheader<W: std::io::Write>(
    w: &mut W,
    title: &str,
    style: ReportSectionStyle,
) -> std::io::Result<()> {
    let colored_title = match style {
        ReportSectionStyle::Success => title.green().bold(),
        ReportSectionStyle::Warning => title.yellow().bold(),
        ReportSectionStyle::Info => title.cyan().bold(),
    };
    writeln!(w, "{}", colored_title)?;
    writeln!(
        w,
        "{}",
        REPORT_SECTION_SUBHEADER_RULE_CHAR
            .repeat(REPORT_SECTION_SUBHEADER_RULE_WIDTH)
            .dimmed()
    )?;
    Ok(())
}

/// Literal heading text the [`print_next_steps_heading`] /
/// [`write_next_steps_heading`] pair emits — every pre-lift consumer
/// spelled this same eleven-byte string (`"Next steps:"`) verbatim as
/// the first argument to a `println!` above a numbered "what to do
/// next" instruction list. Pinned as a `pub const` so consumers that
/// want to assert against the heading text (a fleet-wide sweep, a
/// downstream log-shipper filtering on the label) read the same
/// constant the writer emits rather than re-typing the string literal.
pub const NEXT_STEPS_HEADING_TEXT: &str = "Next steps:";

/// Prints the one-line `"Next steps:"` plain-text uncolored,
/// unindented heading 5 pre-lift consumer sites spelled inline as
/// `println!("Next steps:")` across 3 command modules
/// (`commands/{web_service (×2), sync (×1), developer_tools (×2)}.rs`).
/// Marks the label above a numbered "what to do next" instruction list
/// the caller emits itself — each pre-lift site follows this heading
/// with two or three `println!("  N. <instruction>")` rows the
/// operator reads after the surrounding pipeline reports a completion
/// banner.
///
/// # Distinct from every peer `ui::print_*` primitive
///
/// [`print_step_heading`] carries the same plain-title shape but
/// paints its title `.bold()` and marks a step-level heading inside a
/// pipeline body (e.g. `"Building supergraph:"` above a build's own
/// sub-output). This primitive carries NO bold and marks a
/// post-completion instruction label the operator reads AFTER the
/// pipeline has finished emitting its own body — a distinct visual
/// grammar the pre-lift 5 sites deliberately kept as plain, uncolored
/// text so the numbered instruction rows beneath it carry the reader's
/// eye rather than the heading itself. [`print_phase_heading`] paints
/// its title `.bold().underline()` for a top-level phase marker, one
/// weight heavier still. [`print_section_header`] wears a `═`-rule
/// frame and marks a section boundary, a wholly different grammar.
///
/// # No coloring, no bold, no indent
///
/// Pre-lift every consumer spelled the heading as a plain
/// `println!("Next steps:")` with no `.dimmed()` / `.bold()` /
/// `.italic()` chain and no leading whitespace — the heading reaches
/// the terminal with the default palette so it recedes beneath the
/// numbered instruction rows that follow. The primitive preserves
/// that: neither the label nor its trailing colon reaches the writer
/// through any [`colored`] chain, so no `\x1b[<..>m` ANSI sequence
/// appears in the rendered line. A future palette adjustment that
/// wraps this primitive in `.bold()` or `.dimmed()` is a deliberate
/// additive edit; the pre-lift shape reaches ONE typed boundary
/// rather than 5 literal sites.
///
/// # Compounding
///
/// Pre-lift 5 sibling sites each restated the `println!("Next
/// steps:")` grammar verbatim, with the plain uncolored default
/// palette, the `"Next steps:"` label text, and the trailing colon
/// all spelled inline. A future adjustment (a swap of `"Next steps:"`
/// for `"To do next:"` under a friendlier grammar, a promotion to
/// `.bold()` under a leaner post-completion-instruction distinction,
/// an OTLP `next_steps_heading_emitted` observability event wired
/// alongside the print, a swap of the trailing colon for a middle
/// dot) had to hit 5 sites in lockstep or drift the visual grammar;
/// post-lift it hits ONE typed body. Delegates to
/// [`write_next_steps_heading`] against [`std::io::stdout()`]; the
/// writer split exists so the fail-before-pass test can pin the
/// one-line body, the exact `"Next steps:"` heading text, and the
/// absence of every `\x1b[<..>m` ANSI palette sequence by inspecting
/// emitted bytes rather than shelling out and grepping stdout.
pub fn print_next_steps_heading() {
    let _ = write_next_steps_heading(&mut std::io::stdout().lock());
}

/// Writer-taking sibling to [`print_next_steps_heading`]. Emits the
/// single `Next steps:` line via [`writeln!`] against the supplied
/// writer. [`print_next_steps_heading`] is the stdout adapter; this
/// variant exists so tests can pin the one-line body, the exact
/// heading text ([`NEXT_STEPS_HEADING_TEXT`]), and the absence of
/// every `\x1b[<..>m` ANSI palette sequence without capturing stdout.
pub fn write_next_steps_heading<W: std::io::Write>(w: &mut W) -> std::io::Result<()> {
    writeln!(w, "{}", NEXT_STEPS_HEADING_TEXT)
}

#[cfg(test)]
mod tests {
    use super::{styled_spinner, SpinnerStyle, SPINNER_TICK};
    use colored::Colorize;
    use std::sync::Mutex;
    use std::time::Duration;

    /// Serializes the banner tests that flip `colored`'s global
    /// override to force ANSI emission against a `Vec<u8>` writer. The
    /// override is process-global; without a shared guard, cargo's
    /// default parallel test runner can schedule one test's
    /// [`colored::control::unset_override`] between another's
    /// `set_override(true)` and its `writeln!`, leaving the writer's
    /// bytes stripped of the very ANSI sequences those tests then
    /// assert against. Every banner test that touches the override
    /// acquires this mutex for the entire set-write-unset window via
    /// the [`AnsiOverrideForTest`] guard.
    static ANSI_OVERRIDE_LOCK: Mutex<()> = Mutex::new(());

    /// RAII guard that closes the acquire-lock + set-override +
    /// matched-unset-override + poisoned-mutex-recovery stanza which
    /// the five pre-lift banner tests each carried verbatim.
    ///
    /// The pre-lift tests were:
    /// [`write_success_banner_emits_three_bar_message_bar_lines_in_order`],
    /// [`write_release_stage_banner_emits_three_bar_headline_bar_lines_in_order`],
    /// [`write_section_header_emits_three_bar_title_bar_lines_in_order`],
    /// [`write_step_heading_emits_exactly_one_bold_title_line`], and
    /// [`write_step_success_emits_exactly_one_check_prefixed_green_line`].
    ///
    /// Each pre-lift test opened with an acquire prologue at the test
    /// top — `let _override_guard = ANSI_OVERRIDE_LOCK.lock()`
    /// followed by `.unwrap_or_else(|poisoned| poisoned.into_inner())`
    /// followed by `colored::control::set_override(true)` — and its
    /// matched [`colored::control::unset_override`] call about 8
    /// lines later, paired but visually separated by the writer call
    /// and its [`expect`] between them.
    ///
    /// # Compounding
    ///
    /// Pre-lift the acquire + set + matched-unset had to appear in
    /// lockstep in every banner test — a future test author could
    /// (and, given how visually separated the pair sat in each test
    /// body, would eventually) omit the trailing
    /// [`colored::control::unset_override`], stranding subsequent
    /// tests with the global override still forced on and silently
    /// coloring their output against contracts that pinned the
    /// absence of coloring (e.g.
    /// [`write_ascii_title_underline_emits_rule_line_then_blank_line`]
    /// asserts NO ANSI escapes present). Similarly, a poisoned mutex
    /// recovered by one test author (via
    /// `unwrap_or_else(|poisoned| poisoned.into_inner())`) and
    /// forgotten by another meant a panic during one test's
    /// set-write-unset window would poison the mutex and hang every
    /// subsequent banner test on `.lock().unwrap()`. Post-lift the
    /// acquire + set + poisoned-recover + Drop-unset dance lives in
    /// ONE typed body; the pairing is a Rust invariant (Drop cannot
    /// be forgotten), the poisoned-mutex recovery is the guard's
    /// unconditional policy, and a new banner test picks up all
    /// three properties by naming the type. The `_lock` field is
    /// held for the guard's lifetime — dropping the guard drops the
    /// [`MutexGuard`] AFTER the [`unset_override`] call in [`Drop`],
    /// so the lock protects the entire set-write-unset window
    /// (colored on → writer runs → colored off) even under a
    /// re-entrant acquire from another test.
    struct AnsiOverrideForTest {
        /// The acquired [`ANSI_OVERRIDE_LOCK`] guard. `_`-prefixed
        /// because it exists only for its RAII lifetime — the mutex
        /// releases when [`AnsiOverrideForTest::drop`] returns, which
        /// happens AFTER the `unset_override` call.
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl AnsiOverrideForTest {
        /// Acquire the shared [`ANSI_OVERRIDE_LOCK`] with a
        /// poisoned-mutex recovery (a prior test's panic during its
        /// set-write-unset window taints the mutex but leaves the
        /// override state deterministic — the guard's own [`Drop`]
        /// will `unset_override` on scope exit, so recovering the
        /// inner `()` and continuing is the correct policy) and force
        /// [`colored`]'s global override on so the writer under test
        /// emits ANSI sequences to a `Vec<u8>` buffer instead of
        /// having them stripped by [`colored`]'s auto-detection when
        /// the test binary's stdout is not a TTY.
        fn acquire() -> Self {
            let lock = ANSI_OVERRIDE_LOCK
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            colored::control::set_override(true);
            Self { _lock: lock }
        }
    }

    impl Drop for AnsiOverrideForTest {
        /// Restore [`colored`]'s auto-detection by clearing the
        /// override. Runs BEFORE the wrapped [`MutexGuard`] releases,
        /// so the lock still protects the unset call — a peer test
        /// waiting on [`ANSI_OVERRIDE_LOCK`] cannot see the
        /// override-still-forced-on window between the writer
        /// finishing and the unset firing.
        fn drop(&mut self) {
            colored::control::unset_override();
        }
    }

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
        // Force ANSI emission (colored auto-drops sequences on a
        // non-tty stdout) and serialize against peer banner tests
        // via [`AnsiOverrideForTest`]; its Drop restores colored's
        // auto-detection on scope exit AFTER releasing the shared
        // [`ANSI_OVERRIDE_LOCK`], closing the set-write-unset window
        // without a manual [`colored::control::unset_override`] call
        // that a future test author could omit.
        let _override_guard = AnsiOverrideForTest::acquire();

        let mut buf: Vec<u8> = Vec::new();
        super::write_success_banner(&mut buf, 80, "✅ REGENERATION COMPLETE")
            .expect("write_success_banner against a Vec<u8> writer must succeed");

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
        // Force ANSI emission (colored auto-drops sequences on a
        // non-tty stdout) and serialize against peer banner tests
        // via [`AnsiOverrideForTest`]; its Drop restores colored's
        // auto-detection on scope exit AFTER releasing the shared
        // [`ANSI_OVERRIDE_LOCK`], closing the set-write-unset window
        // without a manual [`colored::control::unset_override`] call
        // that a future test author could omit.
        let _override_guard = AnsiOverrideForTest::acquire();

        let mut buf: Vec<u8> = Vec::new();
        super::write_release_stage_banner(&mut buf, "RELEASE COMPLETE", "kenshi", "prod, abc123")
            .expect("write_release_stage_banner against a Vec<u8> writer must succeed");

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

    /// Fail-before-pass envelope for [`super::write_ascii_bar_banner`].
    /// Pins the three-line body order every pre-lift consumer in
    /// `commands/helm.rs` spelled verbatim (`"=".repeat(42)` rule via
    /// the literal `"=========================================="`,
    /// `"  <title>"` plain-text two-space-indented title,
    /// `"=".repeat(42)` rule) AND the distinguishing ASCII-only
    /// contract: NO ANSI escape sequences on any line. A silent
    /// contract drift a future rewrite might introduce — dropping one
    /// bar to two `writeln!`s, swapping the title and a bar, hoisting
    /// the rule character off `=` in one branch alone, promoting the
    /// title to `.bold()` so it loses ASCII-only grep-friendliness,
    /// promoting the rule to `.bright_green()` so a `--no-color`
    /// consumer loses the per-chart-action boundary marker, dropping
    /// the two-space indent so the title crashes against the first
    /// column, drifting the width off 42 so two adjacent chart
    /// sections line against visibly different rules — flips this
    /// assertion rather than compiling and silently diverging the
    /// three consumer sites' visual grammar.
    #[test]
    fn write_ascii_bar_banner_emits_three_bar_title_bar_ascii_only_lines_in_order() {
        // Force ANSI emission (colored auto-drops sequences on a
        // non-tty stdout) and serialize against peer banner tests
        // via [`AnsiOverrideForTest`]. This primitive is
        // deliberately ASCII-only (no `.color()` calls in its
        // writer) so the guard's `set_override(true)` cannot inject
        // colors on its own — but the guard's Drop restoring
        // colored's auto-detection AND the [`ANSI_OVERRIDE_LOCK`]
        // serialization matter because a regression that promotes
        // the writer to `.color()` would light up under the
        // override, and that failure must not race with a peer
        // banner test that expects colors ON.
        let _override_guard = AnsiOverrideForTest::acquire();

        let mut buf: Vec<u8> = Vec::new();
        super::write_ascii_bar_banner(&mut buf, "Releasing example-chart 1.2.3 (library)")
            .expect("write_ascii_bar_banner against a Vec<u8> writer must succeed");

        let out = String::from_utf8(buf)
            .expect("write_ascii_bar_banner must emit valid UTF-8 (the pre-lift println!s did)");

        // Exactly three body lines — the pre-lift stanza's rule +
        // title + rule triple is three `println!`s, not two, and not
        // four. A refactor that drops or adds a bar fails here. The
        // framing leading blank line the pre-lift stanza carried
        // lives on `print_ascii_bar_banner`, not on the writer
        // sibling.
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(
            lines.len(),
            3,
            "write_ascii_bar_banner must emit exactly three body lines \
             (rule, title, rule) — the pre-lift stanza's rule+title+rule \
             triple is three `println!`s; got {}:\n{}",
            lines.len(),
            out
        );

        // The `=` rule glyph appears in the outer two lines but never
        // in the middle line; the title text appears in the middle
        // line but never in the outer lines. A swap of the middle
        // line and a bar (a fusion that reorders the `writeln!`s)
        // fails here.
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
             indented title line; got {:?}",
            lines[1]
        );
        assert!(
            lines[1].contains("Releasing example-chart 1.2.3 (library)"),
            "line 1 must carry the title verbatim; got {:?}",
            lines[1]
        );

        // The two-space indent every pre-lift consumer prepended to
        // the title via the literal `"  <title>"` must reach the
        // rendered line intact and, unlike `write_section_header`,
        // must land at the very START of the line (this primitive
        // adds no ANSI prologue that could push it right). A
        // fusion that hoists the indent off the constant and drops
        // it fails here — every consumer's pre-lift stanza carried
        // the two-space visual gutter between the rule's left edge
        // and the first title glyph.
        assert_eq!(
            lines[1], "  Releasing example-chart 1.2.3 (library)",
            "line 1 must be exactly `\"  <title>\"` — the pre-lift \
             stanza spelled `println!(\"  {{}}\", <title>)`; got {:?}",
            lines[1]
        );

        // The rule width every pre-lift consumer spelled inline is
        // 42 characters (the literal
        // `"=========================================="`, measured
        // with `echo -n | wc -c`). A fusion that hoists the rule off
        // the constant and lands on a different width lines two
        // adjacent chart-action banners against visibly different
        // rules — pin the count here.
        let rule_glyph_count = lines[0].chars().filter(|c| *c == '=').count();
        assert_eq!(
            rule_glyph_count, 42,
            "line 0 must contain exactly `ASCII_BAR_BANNER_WIDTH` (42) \
             `=` glyphs; got {}",
            rule_glyph_count
        );
        // Both outer bars must have the EXACT same shape — no other
        // content, no trailing whitespace, no prefix — so the two
        // rules read as an equal-width top and bottom to operator
        // eye. A fusion that colors one bar and leaves the other
        // uncolored (an obvious regression of the ASCII-only
        // contract asserted below) would also drift the two bars'
        // rendered widths and fails here.
        assert_eq!(
            lines[0], lines[2],
            "line 0 and line 2 must be byte-identical rules — the \
             pre-lift stanza wrote the same literal twice; got {:?} \
             vs {:?}",
            lines[0], lines[2]
        );

        // The DISTINGUISHING property of this primitive vs. every
        // peer banner in this module: NO ANSI escape sequences on
        // any line. This is the reason the primitive coexists with
        // `write_release_stage_banner` (whose rule wears
        // `bright_green`), `write_success_banner` (`bright_green`
        // + `green().bold()`), and `write_section_header` (`bold`
        // on all three lines) rather than folding into any of them
        // — the helm pipeline's per-chart-action boundary is
        // deliberately the only ASCII-only banner in the crate, so
        // a `--no-color` grep or a CI log post-processor that
        // strips ANSI still surfaces the boundary. A future silent
        // promotion of the primitive to `.color()` (e.g. a helpful
        // "let's brighten this" edit) would break that contract
        // silently across all three consumers; the ESC (`\x1b`)
        // absence assertion catches it before compile.
        for (i, line) in lines.iter().enumerate() {
            assert!(
                !line.contains('\x1b'),
                "line {} must NOT contain any ANSI escape sequence \
                 — the pre-lift stanza spelled `println!(\"...\")` \
                 with no `.color()` wrapper, and this primitive's \
                 distinguishing contract vs. every peer banner is \
                 that a `--no-color` consumer still sees a clean \
                 per-chart boundary; got {:?}",
                i,
                line
            );
        }
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
        // Force ANSI emission (colored auto-drops sequences on a
        // non-tty stdout) and serialize against peer banner tests
        // via [`AnsiOverrideForTest`]; its Drop restores colored's
        // auto-detection on scope exit AFTER releasing the shared
        // [`ANSI_OVERRIDE_LOCK`], closing the set-write-unset window
        // without a manual [`colored::control::unset_override`] call
        // that a future test author could omit.
        let _override_guard = AnsiOverrideForTest::acquire();

        let mut buf: Vec<u8> = Vec::new();
        super::write_section_header(&mut buf, "Schema Export + Codegen")
            .expect("write_section_header against a Vec<u8> writer must succeed");

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

    /// Fail-before-pass envelope for [`super::write_header`]. Pins the
    /// three-line boxed body (top border, indented title, bottom border)
    /// AND the border-vs-body width parity that the two pre-lift local
    /// helpers in `commands/pangea.rs::print_header` and
    /// `commands/bootstrap.rs::print_header` failed: both spelled the
    /// middle line as `format!("║  {:58} ║", title)` — an extra literal
    /// space before the closing `║` — which put the right-side `║` one
    /// glyph past the top border's `╗`, tilting the rendered box. The
    /// primitive threads both consumers onto a single format spec so
    /// the border and body align at one named boundary; this test
    /// pins that parity by measuring the rendered widths after
    /// stripping ANSI SGR sequences.
    #[test]
    fn write_header_emits_three_bar_title_bar_lines_with_border_body_width_parity() {
        let _override_guard = AnsiOverrideForTest::acquire();

        let mut buf: Vec<u8> = Vec::new();
        super::write_header(&mut buf, "Push Pangea: pangea-compiler")
            .expect("write_header against a Vec<u8> writer must succeed");

        let out = String::from_utf8(buf)
            .expect("write_header must emit valid UTF-8 (the pre-lift println!s did)");

        // Exactly three body lines — the box's top+middle+bottom triple
        // is three `writeln!`s, not two, and not four. The framing
        // blank lines the pre-lift stanza carried live on
        // [`super::print_header`], not on the writer sibling — so a
        // future test author cannot conflate the two contracts by
        // reading this line count.
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(
            lines.len(),
            3,
            "write_header must emit exactly three body lines \
             (top border, title, bottom border); got {}:\n{}",
            lines.len(),
            out
        );

        // Strip ANSI SGR sequences (`\x1b[<params>m`) from each line so
        // the char-count reflects rendered display columns (glyphs),
        // not the bright_blue color-code bytes `colored` prefixes and
        // suffixes. A hand-rolled minimal stripper stays inside the
        // test module (no new dep) and stops at `m` per the SGR spec;
        // it iterates over `chars`, not raw bytes, so the multi-byte
        // UTF-8 encodings of `╔ ═ ╗ ║ ╚ ╝` survive the pass intact
        // (each box-drawing glyph is a single char but 3 UTF-8 bytes).
        fn strip_ansi(s: &str) -> String {
            let mut out = String::with_capacity(s.len());
            let mut iter = s.chars().peekable();
            while let Some(c) = iter.next() {
                if c == '\x1b' && iter.peek() == Some(&'[') {
                    iter.next(); // consume '['
                    for inner in iter.by_ref() {
                        if inner == 'm' {
                            break;
                        }
                    }
                } else {
                    out.push(c);
                }
            }
            out
        }

        let visible: Vec<String> = lines.iter().map(|l| strip_ansi(l)).collect();

        // The top and bottom border widths (in glyph count, which for
        // this ASCII/box-drawing subset equals display columns) must
        // equal the middle body-line width. Pre-lift the pangea and
        // bootstrap local helpers rendered a 63-column middle line
        // against a 62-column border — this assertion catches that
        // exact off-by-one drift on either side.
        let top_width = visible[0].chars().count();
        let mid_width = visible[1].chars().count();
        let bot_width = visible[2].chars().count();
        assert_eq!(
            top_width, mid_width,
            "write_header border and middle body widths must match \
             (else the right-side `║` tilts off the top-right `╗`); \
             top={} chars, middle={} chars\ntop:    {:?}\nmiddle: {:?}",
            top_width, mid_width, visible[0], visible[1]
        );
        assert_eq!(
            top_width, bot_width,
            "write_header top and bottom border widths must match; \
             top={} chars, bottom={} chars",
            top_width, bot_width
        );

        // The border glyphs appear on lines 0 and 2 but never on line
        // 1; the title text appears on line 1 but never on the border
        // lines. A rewrite that reorders the `writeln!`s fails here.
        assert!(
            visible[0].starts_with('╔') && visible[0].ends_with('╗'),
            "line 0 must be the top border framed by `╔`…`╗`; got {:?}",
            visible[0]
        );
        assert!(
            visible[2].starts_with('╚') && visible[2].ends_with('╝'),
            "line 2 must be the bottom border framed by `╚`…`╝`; got {:?}",
            visible[2]
        );
        assert!(
            visible[1].starts_with('║') && visible[1].ends_with('║'),
            "line 1 must be the body framed by `║`…`║`; got {:?}",
            visible[1]
        );
        assert!(
            visible[1].contains("Push Pangea: pangea-compiler"),
            "line 1 must carry the title verbatim; got {:?}",
            visible[1]
        );

        // Each of the three lines must carry the `bright_blue` ANSI
        // sequence (`\x1b[94m`) — the pre-lift stanzas spelled
        // `.bright_blue()` on each line explicitly, and the primitive
        // must preserve that per-line color contract so a `.dimmed()`
        // downgrade of one line does not slip in silently.
        for (i, line) in lines.iter().enumerate() {
            assert!(
                line.contains("\x1b[94m"),
                "line {} must carry the bright_blue ANSI sequence \
                 (`\\x1b[94m`) — the pre-lift stanza spelled \
                 `.bright_blue()` on each of the three lines; got {:?}",
                i,
                line
            );
        }
    }

    /// Shield test — grep-based assertion that no command module still
    /// carries the boxed-header stanza inline as three sibling
    /// `println!("{}", "╔══…══╗"…)` + body + `╚══…══╝` lines. Pre-lift
    /// two consumers (`commands/pangea.rs`, `commands/bootstrap.rs`)
    /// each carried a byte-identical local `fn print_header(title)`
    /// helper; both now delegate to [`super::print_header`]. This
    /// shield fires if a future rewrite reintroduces the inline
    /// stanza in ANY command module rather than calling the
    /// primitive, keeping the boxed-header color and width contract
    /// at ONE typed boundary.
    #[test]
    fn print_header_callers_delegate_through_primitive() {
        let commands_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");

        // The pre-lift needle: the exact top-border literal in
        // `bright_blue()`. If a command module carries this literal
        // it means the boxed-header stanza was reintroduced inline
        // rather than routed through [`super::print_header`].
        let needle =
            "\"╔════════════════════════════════════════════════════════════╗\".bright_blue()";

        let mut offenders: Vec<String> = Vec::new();
        let entries = std::fs::read_dir(&commands_dir)
            .expect("commands/ dir must exist under CARGO_MANIFEST_DIR/src");
        for entry in entries {
            let entry = entry.expect("read_dir entry");
            let path = entry.path();
            if !crate::repo::path_has_extension(&path, "rs") {
                continue;
            }
            let content = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("read {}: {}", path.display(), e));
            if content.contains(needle) {
                offenders.push(path.display().to_string());
            }
        }

        assert!(
            offenders.is_empty(),
            "boxed-header stanza reintroduced inline in command \
             module(s); call `crate::ui::print_header(title)` instead:\n  {}",
            offenders.join("\n  ")
        );
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
        // Force ANSI emission (colored auto-drops sequences on a
        // non-tty stdout) and serialize against peer banner tests
        // via [`AnsiOverrideForTest`]; its Drop restores colored's
        // auto-detection on scope exit AFTER releasing the shared
        // [`ANSI_OVERRIDE_LOCK`], closing the set-write-unset window
        // without a manual [`colored::control::unset_override`] call
        // that a future test author could omit.
        let _override_guard = AnsiOverrideForTest::acquire();

        let mut buf: Vec<u8> = Vec::new();
        super::write_step_heading(&mut buf, "G1: cargo check")
            .expect("write_step_heading against a Vec<u8> writer must succeed");

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

    /// Fail-before-pass envelope for [`super::write_numbered_step_heading`].
    /// Pins the exact single-line body every pre-lift consumer spelled
    /// verbatim (`println!("Step <label>: {}", "<TITLE>".bold());`). A
    /// silent contract drift a future rewrite might introduce — dropping
    /// `.bold()` on the title so the label loses emphasis, swapping the
    /// literal `Step ` prefix for a locale-neutral `[<label>] ` shape
    /// without touching consumer sites' expectations, coloring the
    /// `Step <label>: ` prefix into a palette that competes with the
    /// surrounding body text, promoting the trailing `\n` off via
    /// `write!` instead of `writeln!` — flips this assertion rather than
    /// compiling and silently diverging the 23 consumer sites' visual
    /// grammar.
    #[test]
    fn write_numbered_step_heading_emits_step_prefix_then_bold_title_line() {
        // Force ANSI emission (colored auto-drops sequences on a
        // non-tty stdout) and serialize against peer banner tests
        // via [`AnsiOverrideForTest`]; its Drop restores colored's
        // auto-detection on scope exit AFTER releasing the shared
        // [`ANSI_OVERRIDE_LOCK`], closing the set-write-unset window
        // without a manual [`colored::control::unset_override`] call
        // that a future test author could omit.
        let _override_guard = AnsiOverrideForTest::acquire();

        let mut buf: Vec<u8> = Vec::new();
        super::write_numbered_step_heading(&mut buf, "2.5/9", "Verifying image in registry...")
            .expect("write_numbered_step_heading against a Vec<u8> writer must succeed");

        let out = String::from_utf8(buf).expect(
            "write_numbered_step_heading must emit valid UTF-8 (the pre-lift println!s did)",
        );

        // Exactly one line — the pre-lift stanza is one `println!`,
        // not two, and carries no framing blank. A refactor that
        // slips a leading or trailing blank into the primitive body
        // fails here.
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(
            lines.len(),
            1,
            "write_numbered_step_heading must emit exactly one line — \
             the pre-lift stanza is one `println!` carrying no framing \
             blank; got {}:\n{}",
            lines.len(),
            out
        );

        // The uncolored `Step <label>: ` prefix reaches the rendered
        // line verbatim in the surrounding body palette; a fusion that
        // colors the prefix (a "match the title's bold on the label
        // too" cleanup) inserts an ANSI escape between `Step ` and
        // the label and fails here.
        assert!(
            lines[0].starts_with("Step 2.5/9: "),
            "line must start with the uncolored `Step 2.5/9: ` prefix \
             — every pre-lift consumer spelled the literal `\"Step \
             <label>: {{}}\"` format string with no ANSI wrapping on \
             the prefix; got {:?}",
            lines[0]
        );

        // The title text reaches the rendered line verbatim; a fusion
        // that hoists the title off the parameter and pins it to a
        // constant fails here.
        assert!(
            lines[0].contains("Verifying image in registry..."),
            "line must carry the title verbatim; got {:?}",
            lines[0]
        );

        // The `bold` ANSI sequence reaches the rendered line on the
        // TITLE portion; a fusion that drops `.bold()` (a "just print
        // the string, it's shorter" cleanup) fails here.
        assert!(
            lines[0].contains("\x1b[1m"),
            "line must carry the `bold` ANSI sequence (`\\x1b[1m`) \
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
            "write_numbered_step_heading must emit a trailing `\\n` \
             (the pre-lift `println!` did); got {:?}",
            out
        );
    }

    /// Post-lift the caller sites in [`commands/rust_service.rs`] no
    /// longer spell the `println!("Step <label>: {}", "<TITLE>".bold());`
    /// shape inline. Structural regression shield — without it, a
    /// future refactor could silently re-inline the one-liner (e.g. a
    /// "just call `println!` directly, it's shorter" cleanup) and
    /// reopen the 23-site duplication class this lift closed. Enforced
    /// at the module body before its `#[cfg(test)]` region so a
    /// test-support mention of the raw shape does not defeat the
    /// shield. The exact-shape needle `println!("Step ` co-occurring
    /// with `".bold());` on the SAME line uniquely identifies the
    /// pre-lift restatement — the two multi-line
    /// `println!("Step <label>: {}", "…".dimmed())` `skip_flux_health_check`
    /// fall-through variants stay unshielded because they are morally-
    /// adjacent shapes with their own scope (bold vs. dimmed marks the
    /// active-vs-skipped step distinction), not this one.
    #[test]
    fn print_numbered_step_heading_callers_delegate_through_primitive() {
        const CALLERS: &[(&str, &str)] = &[(
            include_str!("commands/rust_service.rs"),
            "commands/rust_service.rs",
        )];
        for (source, module_path) in CALLERS {
            let body = crate::test_support::module_body_before_first_cfg_test(source, module_path);
            for (i, line) in body.lines().enumerate() {
                assert!(
                    !(line.contains("println!(\"Step ") && line.contains("\".bold());")),
                    "{module_path}:{lineno} spells the pre-lift inline \
                     `println!(\"Step <label>: {{}}\", \"<TITLE>\".bold());` \
                     labeled-step-heading stanza — that one-liner was \
                     lifted onto `crate::ui::print_numbered_step_heading`. \
                     A re-inline would silently reopen the 23-site \
                     duplication class this shield exists to close. \
                     Offending line: {line:?}",
                    lineno = i + 1
                );
            }
            assert!(
                body.contains("crate::ui::print_numbered_step_heading("),
                "{module_path} body must forward to \
                 `crate::ui::print_numbered_step_heading(\"<LABEL>\", \
                 \"<TITLE>\")` — the primitive body every one-line \
                 `Step <label>: <title>.bold()` labeled-step-heading in \
                 the crate now delegates through."
            );
        }
    }

    /// Fail-before-pass envelope for [`super::write_numbered_check_heading`].
    /// Pins the exact single-line body every pre-lift consumer spelled
    /// verbatim (`println!("{}", "Check <N>: <TITLE>".blue());`). A
    /// silent contract drift a future rewrite might introduce —
    /// dropping `.blue()` so the heading collapses onto the surrounding
    /// uncolored body palette and loses its scope marker, coloring only
    /// the title portion (a "match the sub-check green" cleanup) so the
    /// `Check <N>: ` prefix ends up in the plain body palette while
    /// the title carries the color, swapping `Check ` for a lowercase
    /// or otherwise-cased prefix, dropping the `: ` separator, promoting
    /// the trailing `\n` off via `write!` instead of `writeln!` — flips
    /// this assertion rather than compiling and silently diverging the 7
    /// consumer sites' visual grammar.
    #[test]
    fn write_numbered_check_heading_emits_blue_check_prefix_index_title_line() {
        // Force ANSI emission (colored auto-drops sequences on a
        // non-tty stdout) and serialize against peer banner tests
        // via [`AnsiOverrideForTest`]; its Drop restores colored's
        // auto-detection on scope exit AFTER releasing the shared
        // [`ANSI_OVERRIDE_LOCK`], closing the set-write-unset window
        // without a manual [`colored::control::unset_override`] call
        // that a future test author could omit.
        let _override_guard = AnsiOverrideForTest::acquire();

        let mut buf: Vec<u8> = Vec::new();
        super::write_numbered_check_heading(&mut buf, 3, "Object Type → Entity Mapping")
            .expect("write_numbered_check_heading against a Vec<u8> writer must succeed");

        let out = String::from_utf8(buf).expect(
            "write_numbered_check_heading must emit valid UTF-8 (the pre-lift println!s did)",
        );

        // Exactly one line — the pre-lift stanza is one `println!`,
        // not two, and carries no framing blank (the leading
        // `println!()` some sites spell BEFORE the heading is a
        // separator concern outside this primitive's scope). A
        // refactor that slips a leading or trailing blank into the
        // primitive body fails here.
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(
            lines.len(),
            1,
            "write_numbered_check_heading must emit exactly one line — \
             the pre-lift stanza is one `println!` carrying no framing \
             blank; got {}:\n{}",
            lines.len(),
            out
        );

        // The composed `Check <index>: <title>` layout reaches the
        // rendered line verbatim inside the blue span; a fusion that
        // reorders (`<title> (Check <index>)`) or drops the `: `
        // separator fails here.
        assert!(
            lines[0].contains("Check 3: Object Type → Entity Mapping"),
            "line must carry the composed `Check <index>: <title>` \
             layout verbatim; got {:?}",
            lines[0]
        );

        // The `blue` ANSI sequence wraps the WHOLE composed string; a
        // fusion that colors only the title portion (a "just tint the
        // title" cleanup) would emit the blue sequence AFTER `Check
        // 3: ` rather than before it, and this assertion fails.
        assert!(
            lines[0].starts_with("\x1b[34m"),
            "line must open with the `blue` ANSI sequence \
             (`\\x1b[34m`) — every pre-lift consumer spelled \
             `.blue()` on the FULL composed string, not just the \
             title; got {:?}",
            lines[0]
        );

        // The trailing `\n` reaches the writer — pre-lift stanza used
        // `println!` (not `print!`), so the newline is part of the
        // contract. A fusion that swapped `writeln!` for `write!`
        // fails here.
        assert!(
            out.ends_with('\n'),
            "write_numbered_check_heading must emit a trailing `\\n` \
             (the pre-lift `println!` did); got {:?}",
            out
        );
    }

    /// Post-lift the caller sites in [`commands/rebac_validation.rs`]
    /// no longer spell the `println!("{}", "Check <N>: <TITLE>".blue());`
    /// shape inline. Structural regression shield — without it, a
    /// future refactor could silently re-inline the one-liner (e.g. a
    /// "just call `println!` directly, it's shorter" cleanup) and
    /// reopen the 7-site duplication class this lift closed. Enforced
    /// at the module body before its `#[cfg(test)]` region so a
    /// test-support mention of the raw shape does not defeat the
    /// shield. The exact-shape needle `println!("{}", "Check ` co-
    /// occurring with `".blue());` on the SAME line uniquely
    /// identifies the pre-lift restatement — other blue-carrying
    /// `println!`s in the crate (composite `format!` args, non-
    /// `Check`-prefixed titles) stay unshielded because they are
    /// morally-adjacent shapes with their own lift targets, not this
    /// one.
    #[test]
    fn print_numbered_check_heading_callers_delegate_through_primitive() {
        const CALLERS: &[(&str, &str)] = &[(
            include_str!("commands/rebac_validation.rs"),
            "commands/rebac_validation.rs",
        )];
        for (source, module_path) in CALLERS {
            let body = crate::test_support::module_body_before_first_cfg_test(source, module_path);
            for (i, line) in body.lines().enumerate() {
                assert!(
                    !(line.contains("println!(\"{}\", \"Check ") && line.contains("\".blue());")),
                    "{module_path}:{lineno} spells the pre-lift inline \
                     `println!(\"{{}}\", \"Check <N>: <TITLE>\".blue());` \
                     numbered-check-heading stanza — that one-liner was \
                     lifted onto `crate::ui::print_numbered_check_heading`. \
                     A re-inline would silently reopen the 7-site \
                     duplication class this shield exists to close. \
                     Offending line: {line:?}",
                    lineno = i + 1
                );
            }
            assert!(
                body.contains("crate::ui::print_numbered_check_heading("),
                "{module_path} body must forward to \
                 `crate::ui::print_numbered_check_heading(<INDEX>, \
                 \"<TITLE>\")` — the primitive body every one-line \
                 `Check <index>: <title>.blue()` numbered-check-heading \
                 in the crate now delegates through."
            );
        }
    }

    /// Fail-before-pass envelope for [`super::write_phase_heading`]. Pins
    /// the exact two-line body every pre-lift consumer spelled verbatim
    /// (`println!("{}", "<TITLE>".bold().underline()); println!();`).
    /// A silent contract drift a future rewrite might introduce —
    /// dropping `.underline()` so the phase heading collapses onto the
    /// leaner [`super::print_step_heading`] grammar and loses its
    /// phase-vs-step scope distinction, dropping `.bold()`, promoting the
    /// title to a color that competes with the surrounding body text,
    /// dropping the trailing framing blank (a "tighter body spacing"
    /// cleanup) so downstream step headings crowd the phase title,
    /// promoting the blank to two blanks under a more spacious body,
    /// swapping `writeln!` for `write!` (losing the trailing `\n`) —
    /// flips this assertion rather than compiling and silently diverging
    /// the 6 consumer sites' visual grammar.
    #[test]
    fn write_phase_heading_emits_bold_underlined_title_then_blank_line() {
        // Force ANSI emission (colored auto-drops sequences on a
        // non-tty stdout) and serialize against peer banner tests
        // via [`AnsiOverrideForTest`]; its Drop restores colored's
        // auto-detection on scope exit AFTER releasing the shared
        // [`ANSI_OVERRIDE_LOCK`], closing the set-write-unset window
        // without a manual [`colored::control::unset_override`] call
        // that a future test author could omit.
        let _override_guard = AnsiOverrideForTest::acquire();

        let mut buf: Vec<u8> = Vec::new();
        super::write_phase_heading(&mut buf, "Phase 0a: Fast Gates (parallel)")
            .expect("write_phase_heading against a Vec<u8> writer must succeed");

        let out = String::from_utf8(buf)
            .expect("write_phase_heading must emit valid UTF-8 (the pre-lift println!s did)");

        // Exactly two lines — the pre-lift stanza was two `println!`
        // calls (the bold+underline title + one framing blank). A
        // refactor that drops the trailing blank (a "tighter body
        // spacing" cleanup) or promotes it to two blanks fails here.
        let lines: Vec<&str> = out.split_inclusive('\n').collect();
        assert_eq!(
            lines.len(),
            2,
            "write_phase_heading must emit exactly two lines — the \
             pre-lift stanza carried the bold+underlined title followed \
             by ONE framing blank via a second `println!()`; got {}:\n{:?}",
            lines.len(),
            out
        );

        // The title text reaches line 0 verbatim; a fusion that hoists
        // the title off the parameter and pins it to a constant fails
        // here.
        assert!(
            lines[0].contains("Phase 0a: Fast Gates (parallel)"),
            "line 0 must carry the title verbatim; got {:?}",
            lines[0]
        );

        // The `bold` SGR parameter (`1`) and `underline` SGR parameter
        // (`4`) both reach line 0 — every pre-lift consumer chained
        // `.bold().underline()`, and `colored` folds the pair into a
        // single compound `\x1b[1;4m` SGR sequence (the two-parameter
        // form of the CSI-`m` set-graphics-rendition escape). Assert
        // for either the compound form or the split forms so a future
        // colored release that changes the fold order (`\x1b[4;1m`) or
        // splits the pair into two `\x1b[1m`/`\x1b[4m` sequences still
        // passes — the contract is BOTH SGR parameters reach the wire,
        // not which byte-encoding colored picks.
        //
        // A fusion that drops `.bold()` (a "just underline it, that's
        // enough emphasis" cleanup) fails the bold check; one that
        // drops `.underline()` (collapsing the phase grammar onto the
        // leaner step-scope [`super::print_step_heading`]) fails the
        // underline check.
        let carries_bold = lines[0].contains("\x1b[1m")
            || lines[0].contains("\x1b[1;4m")
            || lines[0].contains("\x1b[4;1m");
        assert!(
            carries_bold,
            "line 0 must carry the `bold` SGR parameter (`1`) — every \
             pre-lift consumer chained `.bold().underline()` on the \
             title, and dropping `.bold()` erases the phase-heading \
             emphasis; got {:?}",
            lines[0]
        );
        let carries_underline = lines[0].contains("\x1b[4m")
            || lines[0].contains("\x1b[1;4m")
            || lines[0].contains("\x1b[4;1m");
        assert!(
            carries_underline,
            "line 0 must carry the `underline` SGR parameter (`4`) — \
             every pre-lift consumer chained `.underline()` alongside \
             `.bold()`, and dropping `.underline()` collapses the \
             phase grammar onto the leaner step-scope \
             `print_step_heading` and erases the visual distinction \
             between a phase opening and a step opening; got {:?}",
            lines[0]
        );

        // Line 1 is the trailing framing blank — exactly `\n`. A
        // refactor that promotes it to a blank-with-content (a stray
        // space) or drops it entirely fails here.
        assert_eq!(
            lines[1], "\n",
            "line 1 must be exactly `\\n` — every pre-lift trailing \
             `println!()` emits an empty line, and any content there \
             (a stray space, a promoted styled rule) is a visual \
             regression; got {:?}",
            lines[1]
        );

        // The trailing `\n` on the whole output reaches the writer —
        // pre-lift stanza used two `println!` calls (not `print!`), so
        // both newlines are part of the contract. A fusion that
        // swapped either `writeln!` for `write!` fails here.
        assert!(
            out.ends_with('\n'),
            "write_phase_heading must end with `\\n` — both pre-lift \
             `println!`s emit trailing newlines; got {:?}",
            out
        );
    }

    /// Post-lift the callers migrated onto [`super::print_phase_heading`]
    /// no longer spell the `println!("{}", "<TITLE>".bold().underline());`
    /// shape inline. Structural regression shield — without it, a future
    /// refactor could silently re-inline the two-liner (e.g. a "just
    /// call `println!` directly, it's shorter" cleanup) and reopen the
    /// 6-site duplication class this lift closed. Enforced at the
    /// module body before its `#[cfg(test)]` region so a test-support
    /// mention of the raw shape does not defeat the shield. The
    /// exact-shape needle `.bold().underline())` uniquely identifies the
    /// pre-lift restatement — no other in-repo `println!` chains
    /// `.bold().underline()` on its argument (the peer bold-only step
    /// heading uses `.bold()` alone, the section header uses a `═`-rule
    /// wrapper, the box header uses `.bright_blue()`), so this needle
    /// is unique to the pre-lift phase-heading stanza.
    #[test]
    fn print_phase_heading_callers_delegate_through_primitive() {
        const CALLERS: &[(&str, &str)] = &[(
            include_str!("commands/prerelease.rs"),
            "commands/prerelease.rs",
        )];
        for (source, module_path) in CALLERS {
            let body = crate::test_support::module_body_before_first_cfg_test(source, module_path);
            for (i, line) in body.lines().enumerate() {
                assert!(
                    !line.contains(".bold().underline())"),
                    "{module_path}:{lineno} spells the pre-lift inline \
                     `println!(\"{{}}\", \"<TITLE>\".bold().underline());` \
                     phase-heading stanza — that two-liner was lifted \
                     onto `crate::ui::print_phase_heading`. A re-inline \
                     would silently reopen the 6-site duplication class \
                     this shield exists to close. Offending line: {line:?}",
                    lineno = i + 1
                );
            }
            assert!(
                body.contains("crate::ui::print_phase_heading("),
                "{module_path} body must forward to \
                 `crate::ui::print_phase_heading(\"<TITLE>\")` — the \
                 primitive body every two-line bold+underlined phase \
                 heading in the crate now delegates through."
            );
        }
    }

    /// Fail-before-pass envelope for [`super::write_step_success`]. Pins
    /// the exact single-line body every pre-lift consumer spelled
    /// verbatim (`println!("✅ {}", "<MSG>".green())`). A silent
    /// contract drift a future rewrite might introduce — dropping the
    /// `✅ ` prefix so operators lose the visual anchor for a completed
    /// step, promoting the message color to `bright_green` or adding
    /// `.bold()` (which would collapse the visual distinction against
    /// the milestone-level [`super::print_success`]), adding a framing
    /// blank the pre-lift stanza never carried, hoisting the primitive
    /// off `println!` onto `print!` (losing the trailing `\n`) — flips
    /// this assertion rather than compiling and silently diverging the
    /// 9 consumer sites' visual grammar.
    #[test]
    fn write_step_success_emits_exactly_one_check_prefixed_green_line() {
        // Force ANSI emission (colored auto-drops sequences on a
        // non-tty stdout) and serialize against peer banner tests
        // via [`AnsiOverrideForTest`]; its Drop restores colored's
        // auto-detection on scope exit AFTER releasing the shared
        // [`ANSI_OVERRIDE_LOCK`], closing the set-write-unset window
        // without a manual [`colored::control::unset_override`] call
        // that a future test author could omit.
        let _override_guard = AnsiOverrideForTest::acquire();

        let mut buf: Vec<u8> = Vec::new();
        super::write_step_success(&mut buf, "Schema extraction complete")
            .expect("write_step_success against a Vec<u8> writer must succeed");

        let out = String::from_utf8(buf)
            .expect("write_step_success must emit valid UTF-8 (the pre-lift println!s did)");

        // Exactly one line — the pre-lift stanza is one `println!`,
        // not two, and carries no framing blank. A refactor that slips
        // a leading or trailing blank into the primitive body fails
        // here.
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(
            lines.len(),
            1,
            "write_step_success must emit exactly one line — the \
             pre-lift stanza is one `println!` carrying no framing \
             blank; got {}:\n{}",
            lines.len(),
            out
        );

        // The leading `✅ ` prefix reaches the rendered line before any
        // ANSI escape — a fusion that hoisted the checkmark inside the
        // colored span (`"✅ <msg>".green()`) or dropped it altogether
        // (`println!("{}", msg.green())`) fails here.
        assert!(
            lines[0].starts_with("✅ "),
            "line 0 must begin with the literal `✅ ` prefix — every \
             pre-lift consumer spelled it OUTSIDE the coloring span; \
             got {:?}",
            lines[0]
        );

        // The message text reaches the rendered line verbatim; a
        // fusion that hoists the message off the parameter and pins
        // it to a constant fails here.
        assert!(
            lines[0].contains("Schema extraction complete"),
            "line 0 must carry the message verbatim; got {:?}",
            lines[0]
        );

        // The `green` ANSI sequence (`\x1b[32m`) reaches the rendered
        // line; a fusion that dropped `.green()` (a "just print the
        // string, it's shorter" cleanup) or promoted the palette to
        // `.bright_green()` (`\x1b[92m` — the [`super::print_success`]
        // milestone palette) fails here. A promotion collapses the
        // visual distinction between step-completion and milestone
        // grammars this primitive exists to preserve.
        assert!(
            lines[0].contains("\x1b[32m"),
            "line 0 must carry the `green` ANSI sequence (`\\x1b[32m`) \
             — every pre-lift consumer spelled `.green()` (never \
             `.bright_green()` or `.green().bold()`) on the message; \
             got {:?}",
            lines[0]
        );
        assert!(
            !lines[0].contains("\x1b[92m"),
            "line 0 must NOT carry the `bright_green` ANSI sequence \
             (`\\x1b[92m`) — that palette belongs to the heavier \
             milestone-level `print_success`, not this in-body \
             step-completion primitive; got {:?}",
            lines[0]
        );
        assert!(
            !(lines[0].contains("\x1b[1;32m") || lines[0].contains("\x1b[32;1m")),
            "line 0 must NOT carry the `green` + `bold` compound ANSI \
             sequence — every pre-lift consumer spelled plain \
             `.green()` on the message, and `.green().bold()` belongs \
             to the two straggler milestone sites (`rust_service.rs` \
             lines 700 and 1975) deliberately excluded from this \
             lift's sibling class; got {:?}",
            lines[0]
        );

        // The trailing `\n` reaches the writer — pre-lift stanza used
        // `println!` (not `print!`), so the newline is part of the
        // contract. A fusion that swapped `writeln!` for `write!`
        // fails here.
        assert!(
            out.ends_with('\n'),
            "write_step_success must emit a trailing `\\n` (the \
             pre-lift `println!` did); got {:?}",
            out
        );
    }

    /// Post-lift the callers migrated onto [`super::print_step_success`]
    /// no longer spell the `println!("✅ {}", "<MSG>".green());` shape
    /// inline. Structural regression shield — without it, a future
    /// refactor could silently re-inline the one-liner (e.g. a "just
    /// call `println!` directly, it's shorter" cleanup) and reopen the
    /// 9-site duplication class this lift closed. Enforced at the
    /// module bodies before their `#[cfg(test)]` regions so a
    /// test-support mention of the raw shape does not defeat the
    /// shield. The exact-shape needle `println!("✅ {}", "` co-occurring
    /// with `".green());` on the SAME line uniquely identifies the
    /// pre-lift restatement — the two straggler `.green().bold()` sites
    /// (`rust_service.rs` lines 700 and 1975) carry a heavier
    /// milestone-level grammar deliberately excluded from this lift's
    /// sibling class, and their `".green().bold());` suffix does not
    /// match this shield's `".green());" needle, so they survive
    /// untouched.
    #[test]
    fn print_step_success_callers_delegate_through_primitive() {
        const CALLERS: &[(&str, &str)] = &[
            (
                include_str!("commands/federation.rs"),
                "commands/federation.rs",
            ),
            (
                include_str!("commands/rust_service.rs"),
                "commands/rust_service.rs",
            ),
            (
                include_str!("commands/schema_validation.rs"),
                "commands/schema_validation.rs",
            ),
            (
                include_str!("commands/developer_tools.rs"),
                "commands/developer_tools.rs",
            ),
        ];
        for (source, module_path) in CALLERS {
            let body = crate::test_support::module_body_before_first_cfg_test(source, module_path);
            for (i, line) in body.lines().enumerate() {
                assert!(
                    !(line.contains("println!(\"✅ {}\", \"") && line.contains("\".green());")),
                    "{module_path}:{lineno} spells the pre-lift inline \
                     `println!(\"✅ {{}}\", \"<MSG>\".green());` \
                     step-completion stanza — that one-liner was lifted \
                     onto `crate::ui::print_step_success`. A re-inline \
                     would silently reopen the 9-site duplication class \
                     this shield exists to close. Offending line: {line:?}",
                    lineno = i + 1
                );
            }
            assert!(
                body.contains("crate::ui::print_step_success("),
                "{module_path} body must forward to \
                 `crate::ui::print_step_success(\"<MSG>\")` — the \
                 primitive body every one-line `✅ ` + green() \
                 step-completion in the crate now delegates through."
            );
        }
    }

    /// Fail-before-pass envelope for [`super::write_success`]. Pins the
    /// one-line body every pre-lift consumer at
    /// `commands/{bootstrap.rs, build.rs, push.rs}` spelled verbatim
    /// (`println!("{}", "✅ <MSG>".bright_green().bold())`): the `✅ `
    /// prefix, the `bright_green` ANSI sequence (`\x1b[92m`), the
    /// `bold` ANSI sequence (`\x1b[1m`), and the trailing `\n`. A
    /// silent contract drift a future rewrite might introduce —
    /// dropping the `✅ ` glyph, demoting `.bright_green()` to
    /// `.green()` (`\x1b[32m` — the in-body
    /// [`super::write_step_success`] palette, which would collapse the
    /// milestone / step-completion contrast the two-writer split
    /// exists to preserve), dropping `.bold()`, swapping `writeln!`
    /// for `write!` (loses the trailing `\n`) — flips this assertion
    /// rather than compiling and silently diverging the three pre-lift
    /// consumer sites' visual grammar.
    #[test]
    fn write_success_emits_exactly_one_check_prefixed_bright_green_bold_line() {
        // Force ANSI emission (colored auto-drops sequences on a
        // non-tty stdout) and serialize against peer banner tests
        // via [`AnsiOverrideForTest`]; its Drop restores colored's
        // auto-detection on scope exit AFTER releasing the shared
        // [`ANSI_OVERRIDE_LOCK`], closing the set-write-unset window
        // without a manual [`colored::control::unset_override`] call
        // that a future test author could omit.
        let _override_guard = AnsiOverrideForTest::acquire();

        let mut buf: Vec<u8> = Vec::new();
        super::write_success(&mut buf, "Bootstrap release complete!")
            .expect("write_success against a Vec<u8> writer must succeed");

        let out = String::from_utf8(buf)
            .expect("write_success must emit valid UTF-8 (the pre-lift println!s did)");

        // Exactly one line — the pre-lift stanza is one `println!`,
        // not two, and carries no framing blank. A refactor that slips
        // a leading or trailing blank into the primitive body fails
        // here.
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(
            lines.len(),
            1,
            "write_success must emit exactly one line — the pre-lift \
             stanza is one `println!` carrying no framing blank; \
             got {}:\n{}",
            lines.len(),
            out
        );

        // The `✅ ` glyph reaches the rendered line — every pre-lift
        // consumer spelled it. A fusion that dropped the checkmark
        // (a "the color already signals success" cleanup) fails here.
        assert!(
            lines[0].contains("✅ "),
            "line 0 must carry the `✅ ` glyph — every pre-lift \
             consumer spelled it; got {:?}",
            lines[0]
        );

        // The message text reaches the rendered line verbatim; a
        // fusion that hoists the message off the parameter and pins
        // it to a constant fails here.
        assert!(
            lines[0].contains("Bootstrap release complete!"),
            "line 0 must carry the message verbatim; got {:?}",
            lines[0]
        );

        // The `bright_green` ANSI code (`92`) reaches the rendered
        // line — every pre-lift consumer spelled `.bright_green()` on
        // the message. `colored` fuses `.bright_green().bold()` into
        // one compound sequence (`\x1b[1;92m` on this toolchain, but a
        // future palette-writer refactor could split into two adjacent
        // `\x1b[92m` + `\x1b[1m` sequences), so the check accepts
        // either shape. A fusion that demoted the palette to `.green()`
        // (`\x1b[32m`, or compound `\x1b[1;32m` — the in-body
        // [`super::write_step_success`] palette) would collapse the
        // milestone / step-completion contrast this primitive exists
        // to preserve, and fails here.
        assert!(
            lines[0].contains("\x1b[92m")
                || lines[0].contains("\x1b[1;92m")
                || lines[0].contains("\x1b[92;1m"),
            "line 0 must carry the `bright_green` ANSI code (`92`) — \
             every pre-lift consumer spelled `.bright_green()` (never \
             `.green()`) on the message; got {:?}",
            lines[0]
        );
        assert!(
            !lines[0].contains("\x1b[32m")
                && !lines[0].contains("\x1b[1;32m")
                && !lines[0].contains("\x1b[32;1m"),
            "line 0 must NOT carry the `green` ANSI code (`32`) — \
             that palette belongs to the lighter in-body \
             [`super::write_step_success`] step-completion primitive, \
             not this milestone-level `write_success` body; got {:?}",
            lines[0]
        );

        // The `bold` ANSI code (`1`) reaches the rendered line — every
        // pre-lift consumer spelled `.bold()` after `.bright_green()`.
        // A fusion that dropped `.bold()` (a "brightness alone is
        // emphasis enough" cleanup) fails here. `colored` may emit the
        // compound as `\x1b[1;92m` / `\x1b[92;1m` or as two adjacent
        // sequences carrying the plain `\x1b[1m` alongside `\x1b[92m`.
        assert!(
            lines[0].contains("\x1b[1m")
                || lines[0].contains("\x1b[1;92m")
                || lines[0].contains("\x1b[92;1m"),
            "line 0 must carry the `bold` ANSI code (`1`) — every \
             pre-lift consumer spelled `.bold()` after \
             `.bright_green()`; got {:?}",
            lines[0]
        );

        // The trailing `\n` reaches the writer — pre-lift stanza used
        // `println!` (not `print!`), so the newline is part of the
        // contract. A fusion that swapped `writeln!` for `write!`
        // fails here.
        assert!(
            out.ends_with('\n'),
            "write_success must terminate with `\\n` — pre-lift \
             stanza used `println!`, not `print!`; got {:?}",
            out
        );
    }

    /// Callers-delegate shield for [`super::print_success`]. Every
    /// pre-lift `println!("{}", "✅ <MSG>".bright_green().bold());`
    /// straggler at `commands/{bootstrap.rs, build.rs, push.rs}` was
    /// the exact inline expansion of [`super::print_success`]'s one-line
    /// body — three sites hand-rolling the primitive that already
    /// existed. A future re-inline (a "one-liner, may as well spell it
    /// out" cleanup) would silently reopen the three-site duplication
    /// class this shield exists to close; this test scans each
    /// consumer module's body-before-first-`cfg(test)` for the pre-lift
    /// needle and asserts the migrated primitive call is present.
    #[test]
    fn print_success_callers_delegate_through_primitive() {
        const CALLERS: &[(&str, &str)] = &[
            (
                include_str!("commands/bootstrap.rs"),
                "commands/bootstrap.rs",
            ),
            (include_str!("commands/build.rs"), "commands/build.rs"),
            (include_str!("commands/push.rs"), "commands/push.rs"),
        ];
        for (source, module_path) in CALLERS {
            let body = crate::test_support::module_body_before_first_cfg_test(source, module_path);
            for (i, line) in body.lines().enumerate() {
                assert!(
                    !(line.contains("\"✅ ") && line.contains(".bright_green().bold()")),
                    "{module_path}:{lineno} spells the pre-lift inline \
                     `println!(\"{{}}\", \"✅ <MSG>\".bright_green().bold());` \
                     milestone-completion stanza — that one-liner was \
                     lifted onto `crate::ui::print_success`. A \
                     re-inline would silently reopen the three-site \
                     duplication class this shield exists to close. \
                     Offending line: {line:?}",
                    lineno = i + 1
                );
            }
            assert!(
                body.contains("crate::ui::print_success("),
                "{module_path} body must forward to \
                 `crate::ui::print_success(\"<MSG>\")` — the primitive \
                 body every one-line `✅ ` + bright_green().bold() \
                 milestone-completion straggler in the crate now \
                 delegates through."
            );
        }
    }

    /// Fail-before-pass envelope for [`super::write_step_failure`].
    /// Pins the one-line body every pre-lift consumer spelled verbatim
    /// (`println!("   {} <fmt>", "❌".red(), <args>)`): a three-space
    /// indent, a `.red()`-colored `❌` glyph, a single space, then the
    /// plain (uncolored) message. A silent contract drift a future
    /// rewrite might introduce — dropping the three-space indent (a
    /// "tighter body spacing" cleanup), promoting the whole line's
    /// coloring (`format!("   ❌ {}", msg).red()`) so the message text
    /// paints red at every site, swapping `❌ ` for `✗ ` under a
    /// CI-log-friendly grammar, promoting `.red()` to `.bright_red()`
    /// (`\x1b[91m` — the milestone-level [`super::print_error`]
    /// palette), slipping a trailing blank line into the primitive
    /// body — flips this assertion rather than compiling and silently
    /// diverging the 40 consumer sites' visual grammar.
    #[test]
    fn write_step_failure_emits_exactly_one_x_prefixed_indented_line() {
        // Force ANSI emission (colored auto-drops sequences on a
        // non-tty stdout) and serialize against peer banner tests
        // via [`AnsiOverrideForTest`]; its Drop restores colored's
        // auto-detection on scope exit AFTER releasing the shared
        // [`ANSI_OVERRIDE_LOCK`], closing the set-write-unset window
        // without a manual [`colored::control::unset_override`] call
        // that a future test author could omit.
        let _override_guard = AnsiOverrideForTest::acquire();

        let mut buf: Vec<u8> = Vec::new();
        super::write_step_failure(&mut buf, "Docker not available: connection refused")
            .expect("write_step_failure against a Vec<u8> writer must succeed");

        let out = String::from_utf8(buf)
            .expect("write_step_failure must emit valid UTF-8 (the pre-lift println!s did)");

        // Exactly one line — the pre-lift stanza is one `println!`,
        // not two, and carries no framing blank. A refactor that slips
        // a leading or trailing blank into the primitive body fails
        // here.
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(
            lines.len(),
            1,
            "write_step_failure must emit exactly one line — the \
             pre-lift stanza is one `println!` carrying no framing \
             blank; got {}:\n{}",
            lines.len(),
            out
        );

        // The three-space indent reaches the rendered line before any
        // ANSI escape — a fusion that hoisted the indent inside the
        // coloring span (`"   ❌".red()`) or dropped it altogether
        // (`println!("{} <msg>", "❌".red())`) fails here.
        assert!(
            lines[0].starts_with("   "),
            "line 0 must begin with a three-space indent — every \
             pre-lift consumer spelled `\"   {{}} <fmt>\"` verbatim, \
             so the indent must reach the writer OUTSIDE the coloring \
             span; got {:?}",
            lines[0]
        );

        // The `❌ ` glyph reaches the rendered line — a fusion that
        // swapped `❌ ` for `✗ ` under a "CI-log-friendly" cleanup or
        // dropped the glyph altogether fails here.
        assert!(
            lines[0].contains('❌'),
            "line 0 must contain the `❌` glyph — every pre-lift \
             consumer spelled `\"❌\".red()` on the marker; got {:?}",
            lines[0]
        );

        // The message text reaches the rendered line verbatim; a
        // fusion that hoists the message off the parameter and pins
        // it to a constant fails here.
        assert!(
            lines[0].contains("Docker not available: connection refused"),
            "line 0 must carry the message verbatim; got {:?}",
            lines[0]
        );

        // The `red` ANSI sequence (`\x1b[31m`) reaches the rendered
        // line; a fusion that dropped `.red()` (a "just print the
        // string, it's shorter" cleanup) or promoted the palette to
        // `.bright_red()` (`\x1b[91m` — the [`super::print_error`]
        // milestone palette) fails here. A promotion collapses the
        // visual distinction between step-failure and milestone
        // grammars this primitive exists to preserve.
        assert!(
            lines[0].contains("\x1b[31m"),
            "line 0 must carry the `red` ANSI sequence (`\\x1b[31m`) \
             — every pre-lift consumer spelled `.red()` (never \
             `.bright_red()` or `.red().bold()`) on the glyph; \
             got {:?}",
            lines[0]
        );
        assert!(
            !lines[0].contains("\x1b[91m"),
            "line 0 must NOT carry the `bright_red` ANSI sequence \
             (`\\x1b[91m`) — that palette belongs to the heavier \
             milestone-level `print_error`, not this in-body \
             step-failure primitive; got {:?}",
            lines[0]
        );

        // The `.red()` coloring wraps the GLYPH alone, never the
        // message text — a fusion that hoisted the color onto the
        // composed line (`format!("   ❌ {}", msg).red()`) would paint
        // the message red at every site. Pin that the message text is
        // NOT bracketed by a red-open + reset pair: the red span must
        // close (`\x1b[0m`) BEFORE the space that precedes the
        // message.
        let x_pos = lines[0].find('❌').expect("glyph must be present");
        let reset_pos = lines[0]
            .find("\x1b[0m")
            .expect("reset must be present after the glyph");
        let msg_pos = lines[0]
            .find("Docker not available")
            .expect("message must be present");
        assert!(
            x_pos < reset_pos && reset_pos < msg_pos,
            "the `\\x1b[0m` reset must close the red span BEFORE the \
             message begins — every pre-lift consumer spelled `.red()` \
             on the `❌` glyph alone, never on the message. Got \
             positions x={x_pos}, reset={reset_pos}, msg={msg_pos} in \
             line {:?}",
            lines[0]
        );

        // The trailing `\n` reaches the writer — pre-lift stanza used
        // `println!` (not `print!`), so the newline is part of the
        // contract. A fusion that swapped `writeln!` for `write!`
        // fails here.
        assert!(
            out.ends_with('\n'),
            "write_step_failure must emit a trailing `\\n` (the \
             pre-lift `println!` did); got {:?}",
            out
        );
    }

    /// Post-lift the callers migrated onto [`super::print_step_failure`]
    /// no longer spell the `println!("   {} <fmt>", "❌".red(), <args>)`
    /// shape inline. Structural regression shield — without it, a future
    /// refactor could silently re-inline the one-liner (e.g. a "just
    /// call `println!` directly, it's shorter" cleanup) and reopen the
    /// 40-site duplication class this lift closed. Enforced at the
    /// module bodies before their `#[cfg(test)]` regions so a
    /// test-support mention of the raw shape does not defeat the
    /// shield.
    ///
    /// The exact-shape needle is `"❌".red()` appearing anywhere in the
    /// module body, MINUS the two known non-step-failure sites that
    /// carry the same coloring under different grammars: the
    /// `prerelease.rs:198` `println!("{} Failed ({}):", "❌".red(), ...)`
    /// gate-summary label header (no three-space indent, plural item
    /// count in parens, colon suffix — a section-opening banner for a
    /// batch of failed gates, distinct from an in-body per-step
    /// failure) and the `release_service.rs:60`
    /// `info!("{} {} failed: {}", "❌".red(), step.name(), msg)`
    /// tracing-logger call (routed through `tracing::info!`, not
    /// `println!` — logger frontend, not terminal UI). Both survive
    /// untouched; the shield allowlists them by an anchoring substring
    /// unique to each.
    #[test]
    fn print_step_failure_callers_delegate_through_primitive() {
        const CALLERS: &[(&str, &str)] = &[
            (include_str!("commands/sync.rs"), "commands/sync.rs"),
            (
                include_str!("commands/migration_validation.rs"),
                "commands/migration_validation.rs",
            ),
            (
                include_str!("commands/prerelease.rs"),
                "commands/prerelease.rs",
            ),
            (
                include_str!("commands/codegen_validation.rs"),
                "commands/codegen_validation.rs",
            ),
            (
                include_str!("commands/post_deploy_verification.rs"),
                "commands/post_deploy_verification.rs",
            ),
            (
                include_str!("commands/integration_tests.rs"),
                "commands/integration_tests.rs",
            ),
            (
                include_str!("commands/frontend_validation.rs"),
                "commands/frontend_validation.rs",
            ),
        ];
        // Non-step-failure sites that carry `"❌".red()` under a
        // different grammar (a gate-summary label header, a tracing
        // logger call). Each is anchored by a substring unique to that
        // site so the shield allowlists it verbatim without needing
        // a line-number pin.
        const ALLOWLIST_SUBSTRINGS: &[&str] = &[
            // prerelease.rs:198 — gate-summary label header, no three-
            // space indent, plural item count in parens.
            "\"{} Failed ({}):\"",
        ];
        for (source, module_path) in CALLERS {
            let body = crate::test_support::module_body_before_first_cfg_test(source, module_path);
            for (i, line) in body.lines().enumerate() {
                if !line.contains("\"❌\".red()") {
                    continue;
                }
                if ALLOWLIST_SUBSTRINGS.iter().any(|s| line.contains(s)) {
                    continue;
                }
                panic!(
                    "{module_path}:{lineno} spells the pre-lift inline \
                     `\"❌\".red()` step-failure marker — that shape \
                     was lifted onto `crate::ui::print_step_failure`. \
                     A re-inline would silently reopen the 40-site \
                     duplication class this shield exists to close. \
                     Offending line: {line:?}",
                    lineno = i + 1
                );
            }
            assert!(
                body.contains("crate::ui::print_step_failure("),
                "{module_path} body must forward to \
                 `crate::ui::print_step_failure(\"<MSG>\")` — the \
                 primitive body every three-space-indented `❌.red()` \
                 in-body step-failure in the crate now delegates \
                 through."
            );
        }
    }

    /// Fail-before-pass envelope for [`super::write_step_pass`]. Pins
    /// the one-line body every pre-lift consumer spelled verbatim
    /// (`println!("   {} <fmt>", "✅".green(), <args>)`): a three-space
    /// indent, a `.green()`-colored `✅` glyph, a single space, then the
    /// plain (uncolored) message. A silent contract drift a future
    /// rewrite might introduce — dropping the three-space indent (a
    /// "tighter body spacing" cleanup), promoting the whole line's
    /// coloring (`format!("   ✅ {}", msg).green()`) so the message text
    /// paints green at every site (colliding with sibling sites that
    /// color a sub-field of the message via `.cyan()` /
    /// `.bright_white()`), swapping `✅ ` for `✓ ` under a
    /// CI-log-friendly grammar, promoting `.green()` to `.bright_green()`
    /// (`\x1b[92m` — the milestone-level [`super::print_success`]
    /// palette), slipping a trailing blank line into the primitive
    /// body — flips this assertion rather than compiling and silently
    /// diverging the 28 consumer sites' visual grammar.
    #[test]
    fn write_step_pass_emits_exactly_one_check_prefixed_indented_line() {
        // Force ANSI emission (colored auto-drops sequences on a
        // non-tty stdout) and serialize against peer banner tests
        // via [`AnsiOverrideForTest`]; its Drop restores colored's
        // auto-detection on scope exit AFTER releasing the shared
        // [`ANSI_OVERRIDE_LOCK`], closing the set-write-unset window
        // without a manual [`colored::control::unset_override`] call
        // that a future test author could omit.
        let _override_guard = AnsiOverrideForTest::acquire();

        let mut buf: Vec<u8> = Vec::new();
        super::write_step_pass(&mut buf, "Health check passed (12ms)")
            .expect("write_step_pass against a Vec<u8> writer must succeed");

        let out = String::from_utf8(buf)
            .expect("write_step_pass must emit valid UTF-8 (the pre-lift println!s did)");

        // Exactly one line — the pre-lift stanza is one `println!`,
        // not two, and carries no framing blank. A refactor that slips
        // a leading or trailing blank into the primitive body fails
        // here.
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(
            lines.len(),
            1,
            "write_step_pass must emit exactly one line — the \
             pre-lift stanza is one `println!` carrying no framing \
             blank; got {}:\n{}",
            lines.len(),
            out
        );

        // The three-space indent reaches the rendered line before any
        // ANSI escape — a fusion that hoisted the indent inside the
        // coloring span (`"   ✅".green()`) or dropped it altogether
        // (`println!("{} <msg>", "✅".green())`) fails here.
        assert!(
            lines[0].starts_with("   "),
            "line 0 must begin with a three-space indent — every \
             pre-lift consumer spelled `\"   {{}} <fmt>\"` verbatim, \
             so the indent must reach the writer OUTSIDE the coloring \
             span; got {:?}",
            lines[0]
        );

        // The `✅ ` glyph reaches the rendered line — a fusion that
        // swapped `✅ ` for `✓ ` under a "CI-log-friendly" cleanup or
        // dropped the glyph altogether fails here.
        assert!(
            lines[0].contains('✅'),
            "line 0 must contain the `✅` glyph — every pre-lift \
             consumer spelled `\"✅\".green()` on the marker; got {:?}",
            lines[0]
        );

        // The message text reaches the rendered line verbatim; a
        // fusion that hoists the message off the parameter and pins
        // it to a constant fails here.
        assert!(
            lines[0].contains("Health check passed (12ms)"),
            "line 0 must carry the message verbatim; got {:?}",
            lines[0]
        );

        // The `green` ANSI sequence (`\x1b[32m`) reaches the rendered
        // line; a fusion that dropped `.green()` (a "just print the
        // string, it's shorter" cleanup) or promoted the palette to
        // `.bright_green()` (`\x1b[92m` — the [`super::print_success`]
        // milestone palette) fails here. A promotion collapses the
        // visual distinction between step-pass and milestone
        // grammars this primitive exists to preserve.
        assert!(
            lines[0].contains("\x1b[32m"),
            "line 0 must carry the `green` ANSI sequence (`\\x1b[32m`) \
             — every pre-lift consumer spelled `.green()` (never \
             `.bright_green()` or `.green().bold()`) on the glyph; \
             got {:?}",
            lines[0]
        );
        assert!(
            !lines[0].contains("\x1b[92m"),
            "line 0 must NOT carry the `bright_green` ANSI sequence \
             (`\\x1b[92m`) — that palette belongs to the heavier \
             milestone-level `print_success`, not this in-body \
             step-pass primitive; got {:?}",
            lines[0]
        );

        // The `.green()` coloring wraps the GLYPH alone, never the
        // message text — a fusion that hoisted the color onto the
        // composed line (`format!("   ✅ {}", msg).green()`) would
        // paint the message green at every site (colliding with
        // sibling sites that already color a sub-field of the message
        // via `.cyan()` / `.bright_white()`). Pin that the message
        // text is NOT bracketed by a green-open + reset pair: the
        // green span must close (`\x1b[0m`) BEFORE the space that
        // precedes the message.
        let check_pos = lines[0].find('✅').expect("glyph must be present");
        let reset_pos = lines[0]
            .find("\x1b[0m")
            .expect("reset must be present after the glyph");
        let msg_pos = lines[0]
            .find("Health check passed")
            .expect("message must be present");
        assert!(
            check_pos < reset_pos && reset_pos < msg_pos,
            "the `\\x1b[0m` reset must close the green span BEFORE the \
             message begins — every pre-lift consumer spelled \
             `.green()` on the `✅` glyph alone, never on the message. \
             Got positions check={check_pos}, reset={reset_pos}, \
             msg={msg_pos} in line {:?}",
            lines[0]
        );

        // The trailing `\n` reaches the writer — pre-lift stanza used
        // `println!` (not `print!`), so the newline is part of the
        // contract. A fusion that swapped `writeln!` for `write!`
        // fails here.
        assert!(
            out.ends_with('\n'),
            "write_step_pass must emit a trailing `\\n` (the \
             pre-lift `println!` did); got {:?}",
            out
        );
    }

    /// Post-lift the callers migrated onto [`super::print_step_pass`]
    /// no longer spell EITHER of the two pre-lift shapes inline —
    /// neither the explicit-color `println!("   {} <fmt>", "✅".green(),
    /// <args>)` (28 pre-lift sites, first lift) NOR the plain-emoji
    /// `println!("   ✅ <fmt>", <args>)` (34 pre-lift sites across 7
    /// command modules — `commands/{rust_service (×10), flux (×6),
    /// developer_tools (×6), migrations (×4), web_service (×4),
    /// federation_tests (×2), schema_validation (×2)}.rs`, single-line
    /// and multi-line-spread flavors both — closed here in the
    /// follow-up lift). Two different pre-lift spellings collapsed onto
    /// the same primitive because both encode the same "in-body
    /// sub-step passed" semantics — the plain-emoji sites just relied
    /// on the terminal to render `✅` in color, and their post-lift
    /// bytes now carry the `.green()` ANSI on the glyph like every
    /// sibling site (a colored-mode drift that `colored`'s TTY auto-
    /// drop makes invisible in piped/log output).
    ///
    /// Structural regression shield — without it, a future refactor
    /// could silently re-inline either one-liner (e.g. a "just call
    /// `println!` directly, it's shorter" cleanup) and reopen the
    /// 62-site duplication class the two lifts closed. Enforced at
    /// the module bodies before their `#[cfg(test)]` regions so a
    /// test-support mention of the raw shape does not defeat the
    /// shield.
    ///
    /// The exact-shape needles are:
    ///
    /// - `"✅".green()` appearing anywhere in the module body, MINUS
    ///   one known non-step-pass site that carries the same coloring
    ///   under a different grammar: the `prerelease.rs:182`
    ///   `println!("{} Passed ({}):", "✅".green(), self.passed.len())`
    ///   gate-summary label header (no three-space indent, plural item
    ///   count in parens, colon suffix — a section-opening banner for
    ///   a batch of passed gates, distinct from an in-body per-step
    ///   pass). Survives untouched; the shield allowlists it by an
    ///   anchoring substring unique to that site.
    /// - `println!("   ✅ ` appearing anywhere in the module body —
    ///   the plain-emoji one-liner the second lift closes. No
    ///   allowlist exceptions: every pre-lift site was a genuine
    ///   in-body sub-pass and forwards through the primitive
    ///   post-lift.
    ///
    /// `release_service.rs`'s `info!("{} {} completed in {:.1}s",
    /// "✅".green(), ...)` and similar `info!("   ✅ …", …)` calls
    /// across `bootstrap.rs`, `comprehensive_release.rs`,
    /// `integration_tests.rs`, `kenshi.rs`, and peers are routed
    /// through `tracing::info!` (logger frontend, not terminal UI)
    /// and are not enrolled in the caller set below.
    #[test]
    fn print_step_pass_callers_delegate_through_primitive() {
        const CALLERS: &[(&str, &str)] = &[
            (
                include_str!("commands/migration_validation.rs"),
                "commands/migration_validation.rs",
            ),
            (
                include_str!("commands/migration_new.rs"),
                "commands/migration_new.rs",
            ),
            (
                include_str!("commands/codegen_validation.rs"),
                "commands/codegen_validation.rs",
            ),
            (include_str!("commands/codegen.rs"), "commands/codegen.rs"),
            (
                include_str!("commands/post_deploy_verification.rs"),
                "commands/post_deploy_verification.rs",
            ),
            (
                include_str!("commands/prerelease.rs"),
                "commands/prerelease.rs",
            ),
            (
                include_str!("commands/frontend_validation.rs"),
                "commands/frontend_validation.rs",
            ),
            (
                include_str!("commands/integration_tests.rs"),
                "commands/integration_tests.rs",
            ),
            (
                include_str!("commands/rust_service.rs"),
                "commands/rust_service.rs",
            ),
            (
                include_str!("commands/migrations.rs"),
                "commands/migrations.rs",
            ),
            (
                include_str!("commands/developer_tools.rs"),
                "commands/developer_tools.rs",
            ),
            (include_str!("commands/flux.rs"), "commands/flux.rs"),
            (
                include_str!("commands/schema_validation.rs"),
                "commands/schema_validation.rs",
            ),
            (
                include_str!("commands/web_service.rs"),
                "commands/web_service.rs",
            ),
            (
                include_str!("commands/federation_tests.rs"),
                "commands/federation_tests.rs",
            ),
        ];
        // Non-step-pass sites that carry `"✅".green()` under a
        // different grammar (a gate-summary label header). Each is
        // anchored by a substring unique to that site so the shield
        // allowlists it verbatim without needing a line-number pin.
        const ALLOWLIST_SUBSTRINGS: &[&str] = &[
            // prerelease.rs:182 — gate-summary label header, no three-
            // space indent, plural item count in parens.
            "\"{} Passed ({}):\"",
        ];
        for (source, module_path) in CALLERS {
            let body = crate::test_support::module_body_before_first_cfg_test(source, module_path);
            let lines: Vec<&str> = body.lines().collect();
            for (i, line) in lines.iter().enumerate() {
                let lineno = i + 1;
                // Shield 1 — explicit-color pre-lift needle
                // (`"✅".green()` inline).
                if line.contains("\"✅\".green()")
                    && !ALLOWLIST_SUBSTRINGS.iter().any(|s| line.contains(s))
                {
                    panic!(
                        "{module_path}:{lineno} spells the pre-lift inline \
                         `\"✅\".green()` step-pass marker — that shape \
                         was lifted onto `crate::ui::print_step_pass`. \
                         A re-inline would silently reopen the \
                         62-site duplication class this shield exists \
                         to close. Offending line: {line:?}"
                    );
                }
                // Shield 2 — plain-emoji pre-lift needle
                // (`println!("   ✅ …` inline, single-line form). The
                // `println!(` prefix on the same line rules out
                // `info!(…)` / `warn!(…)` tracing-logger sites that
                // reach `tracing`, not stdout, and are not enrolled in
                // this caller set.
                if line.contains("println!(\"   ✅ ") || line.contains("println!(\"   ✅\"") {
                    panic!(
                        "{module_path}:{lineno} spells the pre-lift inline \
                         `println!(\"   ✅ <fmt>\", …)` plain-emoji \
                         step-pass one-liner — that shape was lifted \
                         onto `crate::ui::print_step_pass`. A re-inline \
                         would silently reopen the 60-site duplication \
                         class this shield exists to close. Offending \
                         line: {line:?}"
                    );
                }
                // Shield 3 — plain-emoji multi-line spread: the
                // `println!(` opener sits on the PRECEDING line and
                // the `"   ✅ <fmt>",` literal on THIS one. We
                // require the immediately-preceding line to end with
                // an unclosed `println!(` (last-non-whitespace token
                // is `println!(`) so that `info!(` / `warn!(` /
                // `error!(` multi-line spreads with the same literal
                // stay unenrolled (they route through `tracing`, not
                // stdout — logger frontend, not terminal UI).
                let trimmed = line.trim_start();
                if trimmed.starts_with("\"   ✅ ") || trimmed.starts_with("\"   ✅\"") {
                    let prev_trimmed = if i > 0 { lines[i - 1].trim_end() } else { "" };
                    if prev_trimmed.ends_with("println!(") {
                        panic!(
                            "{module_path}:{lineno} spells the pre-lift \
                             multi-line `println!(` + `\"   ✅ <fmt>\",` \
                             plain-emoji step-pass literal — that shape \
                             was lifted onto `crate::ui::print_step_pass`. \
                             Offending line: {line:?}"
                        );
                    }
                }
            }
            assert!(
                body.contains("crate::ui::print_step_pass("),
                "{module_path} body must forward to \
                 `crate::ui::print_step_pass(\"<MSG>\")` — the \
                 primitive body every three-space-indented in-body \
                 step-pass in the crate (both `.green()`-explicit and \
                 plain-emoji pre-lift spellings) now delegates \
                 through."
            );
        }
    }

    /// Fail-before-pass envelope for [`super::write_step_check`]. Pins
    /// the one-line body every pre-lift consumer spelled verbatim
    /// (`println!("   {} <fmt>", "✓".green(), <args>)`): a three-space
    /// indent, a `.green()`-colored `✓` thin-checkmark glyph, a single
    /// space, then the plain (uncolored) message. A silent contract
    /// drift a future rewrite might introduce — dropping the
    /// three-space indent, promoting the whole line's coloring
    /// (`format!("   ✓ {}", msg).green()`) so the message text paints
    /// green at every site (colliding with sibling sites that color a
    /// sub-field of the message via `.cyan()` / `.bright_white()`),
    /// swapping `✓ ` for `[OK] ` under a CI-log-friendly grammar,
    /// promoting `.green()` to `.bright_green()` (`\x1b[92m` — the
    /// milestone-level [`super::print_success`] palette, or the
    /// `commands/workspace_deps.rs:102,289` `"✓".bright_green()`
    /// sibling grammar this primitive deliberately does NOT enroll),
    /// swapping `✓` for the heavier `✅` glyph (collapsing the
    /// distinction between this sub-check primitive and its sibling
    /// [`super::print_step_pass`]), slipping a trailing blank line
    /// into the primitive body — flips this assertion rather than
    /// compiling and silently diverging the 18 consumer sites' visual
    /// grammar.
    #[test]
    fn write_step_check_emits_exactly_one_check_prefixed_indented_line() {
        // Force ANSI emission (colored auto-drops sequences on a
        // non-tty stdout) and serialize against peer banner tests via
        // [`AnsiOverrideForTest`]; its Drop restores colored's
        // auto-detection on scope exit AFTER releasing the shared
        // [`ANSI_OVERRIDE_LOCK`], closing the set-write-unset window
        // without a manual [`colored::control::unset_override`] call
        // that a future test author could omit.
        let _override_guard = AnsiOverrideForTest::acquire();

        let mut buf: Vec<u8> = Vec::new();
        super::write_step_check(&mut buf, "Schema in sync")
            .expect("write_step_check against a Vec<u8> writer must succeed");

        let out = String::from_utf8(buf)
            .expect("write_step_check must emit valid UTF-8 (the pre-lift println!s did)");

        // Exactly one line — the pre-lift stanza is one `println!`,
        // not two, and carries no framing blank. A refactor that slips
        // a leading or trailing blank into the primitive body fails
        // here.
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(
            lines.len(),
            1,
            "write_step_check must emit exactly one line — the \
             pre-lift stanza is one `println!` carrying no framing \
             blank; got {}:\n{}",
            lines.len(),
            out
        );

        // The three-space indent reaches the rendered line before any
        // ANSI escape — a fusion that hoisted the indent inside the
        // coloring span (`"   ✓".green()`) or dropped it altogether
        // (`println!("{} <msg>", "✓".green())`) fails here.
        assert!(
            lines[0].starts_with("   "),
            "line 0 must begin with a three-space indent — every \
             pre-lift consumer spelled `\"   {{}} <fmt>\"` verbatim, \
             so the indent must reach the writer OUTSIDE the coloring \
             span; got {:?}",
            lines[0]
        );

        // The `✓` thin-checkmark glyph reaches the rendered line — a
        // fusion that swapped `✓` for the heavier `✅` (collapsing the
        // sub-check vs step-pass distinction) or for `[OK]` under a
        // "CI-log-friendly" cleanup fails here.
        assert!(
            lines[0].contains('✓'),
            "line 0 must contain the `✓` thin-checkmark glyph — every \
             pre-lift consumer spelled `\"✓\".green()` on the marker \
             (NEVER the heavier `\"✅\".green()` — that is the sibling \
             `print_step_pass` grammar for full step results); got {:?}",
            lines[0]
        );
        assert!(
            !lines[0].contains('✅'),
            "line 0 must NOT contain the heavier `✅` glyph — that \
             glyph belongs to the sibling `print_step_pass` primitive \
             for full step results, not this sub-check primitive; \
             got {:?}",
            lines[0]
        );

        // The message text reaches the rendered line verbatim; a
        // fusion that hoists the message off the parameter and pins
        // it to a constant fails here.
        assert!(
            lines[0].contains("Schema in sync"),
            "line 0 must carry the message verbatim; got {:?}",
            lines[0]
        );

        // The `green` ANSI sequence (`\x1b[32m`) reaches the rendered
        // line; a fusion that dropped `.green()` (a "just print the
        // string, it's shorter" cleanup) or promoted the palette to
        // `.bright_green()` (`\x1b[92m` — the milestone-level
        // [`super::print_success`] palette, or the
        // `commands/workspace_deps.rs` `"✓".bright_green()` sibling
        // grammar) fails here.
        assert!(
            lines[0].contains("\x1b[32m"),
            "line 0 must carry the `green` ANSI sequence (`\\x1b[32m`) \
             — every pre-lift consumer spelled `.green()` (never \
             `.bright_green()`) on the glyph; got {:?}",
            lines[0]
        );
        assert!(
            !lines[0].contains("\x1b[92m"),
            "line 0 must NOT carry the `bright_green` ANSI sequence \
             (`\\x1b[92m`) — that palette belongs to the heavier \
             milestone-level `print_success` and to the distinct \
             `\"✓\".bright_green()` sibling grammar in \
             `commands/workspace_deps.rs`, not this sub-check \
             primitive; got {:?}",
            lines[0]
        );

        // The `.green()` coloring wraps the GLYPH alone, never the
        // message text — a fusion that hoisted the color onto the
        // composed line (`format!("   ✓ {}", msg).green()`) would
        // paint the message green at every site. Pin that the message
        // text is NOT bracketed by a green-open + reset pair: the
        // green span must close (`\x1b[0m`) BEFORE the space that
        // precedes the message.
        let glyph_pos = lines[0].find('✓').expect("glyph must be present");
        let reset_pos = lines[0]
            .find("\x1b[0m")
            .expect("reset must be present after the glyph");
        let msg_pos = lines[0]
            .find("Schema in sync")
            .expect("message must be present");
        assert!(
            glyph_pos < reset_pos && reset_pos < msg_pos,
            "the `\\x1b[0m` reset must close the green span BEFORE the \
             message begins — every pre-lift consumer spelled \
             `.green()` on the `✓` glyph alone, never on the message. \
             Got positions glyph={glyph_pos}, reset={reset_pos}, \
             msg={msg_pos} in line {:?}",
            lines[0]
        );

        // The trailing `\n` reaches the writer — pre-lift stanza used
        // `println!` (not `print!`), so the newline is part of the
        // contract. A fusion that swapped `writeln!` for `write!`
        // fails here.
        assert!(
            out.ends_with('\n'),
            "write_step_check must emit a trailing `\\n` (the \
             pre-lift `println!` did); got {:?}",
            out
        );
    }

    /// Post-lift the callers migrated onto [`super::print_step_check`]
    /// no longer spell the `println!("   {} <fmt>", "✓".green(),
    /// <args>)` shape inline. Structural regression shield — without
    /// it, a future refactor could silently re-inline the one-liner
    /// (e.g. a "just call `println!` directly, it's shorter" cleanup)
    /// and reopen the 18-site duplication class this lift closed.
    /// Enforced at the module bodies before their `#[cfg(test)]`
    /// regions so a test-support mention of the raw shape does not
    /// defeat the shield.
    ///
    /// The exact-shape needle is `"✓".green()` appearing anywhere in
    /// the module body. Non-step-check `"✓".green()` sites that live
    /// under DIFFERENT grammars are left in place and NOT enrolled
    /// below (the needle would still match them, so the file is
    /// excluded from `CALLERS` rather than allowlisted): the two-space
    /// indent wider-body summary sites in `commands/rust_service.rs`
    /// and `commands/search_sync.rs` (`"  {}"` — a distinct
    /// wider-body summary grammar, not the three-space in-body
    /// sub-check this primitive lifts) now delegate through the
    /// sibling [`super::print_report_item`] primitive, and their own
    /// shield ([`print_report_item_callers_delegate_through_primitive`])
    /// pins that migration; the four-space bullet-decorated
    /// `commands/rust_service.rs` `"    • {} New image is already
    /// deployed!"` waiting-marker sibling wears its own grammar and
    /// is allowlisted inside the report-item shield. The
    /// `commands/workspace_deps.rs:102,289` `"✓".bright_green()` sites
    /// carry a different palette so the exact-shape needle does not
    /// match them at all — no exclusion needed for that file. This
    /// module `include_str!` list therefore covers only the six
    /// modules whose ALL `"✓".green()` sites carry the three-space
    /// in-body sub-check grammar this primitive owns.
    #[test]
    fn print_step_check_callers_delegate_through_primitive() {
        const CALLERS: &[(&str, &str)] = &[
            (
                include_str!("commands/codegen_validation.rs"),
                "commands/codegen_validation.rs",
            ),
            (include_str!("commands/codegen.rs"), "commands/codegen.rs"),
            (include_str!("commands/sync.rs"), "commands/sync.rs"),
            (
                include_str!("commands/frontend_validation.rs"),
                "commands/frontend_validation.rs",
            ),
            (
                include_str!("commands/prerelease.rs"),
                "commands/prerelease.rs",
            ),
            (
                include_str!("commands/rebac_validation.rs"),
                "commands/rebac_validation.rs",
            ),
        ];
        // No allowlisted `"✓".green()` sites inside the enrolled
        // modules — every `"✓".green()` occurrence in each of the six
        // caller files above carries the three-space in-body
        // sub-check grammar and is expected to have been migrated.
        // Non-enrolled modules (`commands/rust_service.rs`,
        // `commands/search_sync.rs`) hold two-space-indent siblings
        // under a distinct wider-body summary grammar and are left in
        // place unchanged.
        const ALLOWLIST_SUBSTRINGS: &[&str] = &[];
        for (source, module_path) in CALLERS {
            let body = crate::test_support::module_body_before_first_cfg_test(source, module_path);
            for (i, line) in body.lines().enumerate() {
                if !line.contains("\"✓\".green()") {
                    continue;
                }
                if ALLOWLIST_SUBSTRINGS.iter().any(|s| line.contains(s)) {
                    continue;
                }
                panic!(
                    "{module_path}:{lineno} spells the pre-lift inline \
                     `\"✓\".green()` step-check marker — that shape \
                     was lifted onto `crate::ui::print_step_check`. \
                     A re-inline would silently reopen the 18-site \
                     duplication class this shield exists to close. \
                     Offending line: {line:?}",
                    lineno = i + 1
                );
            }
            assert!(
                body.contains("crate::ui::print_step_check("),
                "{module_path} body must forward to \
                 `crate::ui::print_step_check(\"<MSG>\")` — the \
                 primitive body every three-space-indented `✓.green()` \
                 in-body step-check in the crate now delegates \
                 through."
            );
        }
    }

    /// Fail-before-pass envelope for [`super::write_report_item`].
    /// Pins the one-line body every pre-lift consumer spelled
    /// verbatim (`println!("  {} <fmt>", "✓".green())`): a two-space
    /// indent, a `.green()`-colored `✓` thin-checkmark glyph, a
    /// single space, then the plain (uncolored) message. A silent
    /// contract drift a future rewrite might introduce — widening
    /// the indent to three-space (collapsing the wider-body summary
    /// grammar into the sibling [`super::print_step_check`] in-body
    /// sub-check grammar), promoting the whole line's coloring
    /// (`format!("  ✓ {}", msg).green()`) so the message text paints
    /// green at every site, swapping `✓ ` for `[OK] ` under a
    /// CI-log-friendly grammar, promoting `.green()` to
    /// `.bright_green()` (`\x1b[92m` — colliding with the
    /// `commands/workspace_deps.rs` sibling grammar this primitive
    /// deliberately does NOT enroll), swapping `✓` for `✅`
    /// (collapsing this two-space report-item primitive into a
    /// wider-body variant of [`super::print_step_pass`]), slipping a
    /// trailing blank line into the primitive body — flips this
    /// assertion rather than compiling and silently diverging the 7
    /// consumer sites' visual grammar.
    #[test]
    fn write_report_item_emits_exactly_one_check_prefixed_two_indented_line() {
        let _override_guard = AnsiOverrideForTest::acquire();

        let mut buf: Vec<u8> = Vec::new();
        super::write_report_item(&mut buf, "Docker Image")
            .expect("write_report_item against a Vec<u8> writer must succeed");

        let out = String::from_utf8(buf)
            .expect("write_report_item must emit valid UTF-8 (the pre-lift println!s did)");

        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(
            lines.len(),
            1,
            "write_report_item must emit exactly one line — the \
             pre-lift stanza is one `println!` carrying no framing \
             blank; got {}:\n{}",
            lines.len(),
            out
        );

        // Two-space indent, NOT three-space (which is the sibling
        // `print_step_check` in-body sub-check grammar).
        assert!(
            lines[0].starts_with("  "),
            "line 0 must begin with a two-space indent — every \
             pre-lift consumer spelled `\"  {{}} <fmt>\"` verbatim, \
             so the indent must reach the writer OUTSIDE the coloring \
             span; got {:?}",
            lines[0]
        );
        assert!(
            !lines[0].starts_with("   "),
            "line 0 must NOT begin with a three-space indent — that \
             indent belongs to the sibling `print_step_check` in-body \
             sub-check grammar, not this wider-body report-item \
             grammar; got {:?}",
            lines[0]
        );

        // The `✓` thin-checkmark glyph reaches the rendered line —
        // NOT the heavier `✅` (which is the sibling
        // `print_step_pass` grammar for full step results).
        assert!(
            lines[0].contains('✓'),
            "line 0 must contain the `✓` thin-checkmark glyph; got {:?}",
            lines[0]
        );
        assert!(
            !lines[0].contains('✅'),
            "line 0 must NOT contain the heavier `✅` glyph — that \
             glyph belongs to the sibling `print_step_pass` \
             primitive for full step results, not this report-item \
             primitive; got {:?}",
            lines[0]
        );

        // The message text reaches the rendered line verbatim.
        assert!(
            lines[0].contains("Docker Image"),
            "line 0 must carry the message verbatim; got {:?}",
            lines[0]
        );

        // The `green` ANSI sequence — NOT `bright_green` (which is
        // the distinct `commands/workspace_deps.rs` sibling grammar).
        assert!(
            lines[0].contains("\x1b[32m"),
            "line 0 must carry the `green` ANSI sequence (`\\x1b[32m`); \
             got {:?}",
            lines[0]
        );
        assert!(
            !lines[0].contains("\x1b[92m"),
            "line 0 must NOT carry the `bright_green` ANSI sequence \
             (`\\x1b[92m`) — that palette belongs to the distinct \
             `commands/workspace_deps.rs` sibling grammar, not this \
             report-item primitive; got {:?}",
            lines[0]
        );

        // The `.green()` coloring wraps the GLYPH alone, never the
        // message text — the `\x1b[0m` reset must close the green
        // span BEFORE the message begins.
        let glyph_pos = lines[0].find('✓').expect("glyph must be present");
        let reset_pos = lines[0]
            .find("\x1b[0m")
            .expect("reset must be present after the glyph");
        let msg_pos = lines[0]
            .find("Docker Image")
            .expect("message must be present");
        assert!(
            glyph_pos < reset_pos && reset_pos < msg_pos,
            "the `\\x1b[0m` reset must close the green span BEFORE the \
             message begins — every pre-lift consumer spelled \
             `.green()` on the `✓` glyph alone, never on the message. \
             Got positions glyph={glyph_pos}, reset={reset_pos}, \
             msg={msg_pos} in line {:?}",
            lines[0]
        );

        // The trailing `\n` reaches the writer — pre-lift stanza
        // used `println!`, so the newline is part of the contract.
        assert!(
            out.ends_with('\n'),
            "write_report_item must emit a trailing `\\n` (the \
             pre-lift `println!` did); got {:?}",
            out
        );
    }

    /// Post-lift the callers migrated onto
    /// [`super::print_report_item`] no longer spell the
    /// `println!("  {} <fmt>", "✓".green())` shape inline. Structural
    /// regression shield — without it, a future refactor could
    /// silently re-inline the one-liner (e.g. a "just call `println!`
    /// directly, it's shorter" cleanup) and reopen the 7-site
    /// duplication class this lift closed. Enforced at the module
    /// bodies before their `#[cfg(test)]` regions so a test-support
    /// mention of the raw shape does not defeat the shield.
    ///
    /// The exact-shape needle is `"✓".green()` appearing anywhere in
    /// the module body. Non-report-item `"✓".green()` sites that live
    /// under DIFFERENT grammars are allowlisted below: the four-space
    /// bullet-decorated `commands/rust_service.rs` `"    • {} New
    /// image is already deployed!"` line wears a distinct
    /// waiting-marker grammar (four-space indent + bullet ornament +
    /// baked-in message), not the two-space report-item this
    /// primitive lifts. The `commands/workspace_deps.rs` two
    /// `"✓".bright_green()` sites carry a different palette so the
    /// exact-shape needle does not match them at all — no exclusion
    /// needed for that file, and it is NOT enrolled here.
    #[test]
    fn print_report_item_callers_delegate_through_primitive() {
        const CALLERS: &[(&str, &str)] = &[
            (
                include_str!("commands/rust_service.rs"),
                "commands/rust_service.rs",
            ),
            (
                include_str!("commands/search_sync.rs"),
                "commands/search_sync.rs",
            ),
        ];
        // Four-space bullet-decorated `"    • {} New image is
        // already deployed!"` in `commands/rust_service.rs` —
        // distinct waiting-marker grammar with a four-space indent
        // and a bullet ornament, not this primitive's two-space
        // report-item shape.
        const ALLOWLIST_SUBSTRINGS: &[&str] = &["• {} New image is already deployed!"];
        for (source, module_path) in CALLERS {
            let body = crate::test_support::module_body_before_first_cfg_test(source, module_path);
            for (i, line) in body.lines().enumerate() {
                if !line.contains("\"✓\".green()") {
                    continue;
                }
                if ALLOWLIST_SUBSTRINGS.iter().any(|s| line.contains(s)) {
                    continue;
                }
                panic!(
                    "{module_path}:{lineno} spells the pre-lift inline \
                     `\"✓\".green()` two-space report-item marker — \
                     that shape was lifted onto \
                     `crate::ui::print_report_item`. A re-inline \
                     would silently reopen the 7-site duplication \
                     class this shield exists to close. Offending \
                     line: {line:?}",
                    lineno = i + 1
                );
            }
            assert!(
                body.contains("crate::ui::print_report_item("),
                "{module_path} body must forward to \
                 `crate::ui::print_report_item(\"<MSG>\")` — the \
                 primitive body every two-space-indented `✓.green()` \
                 wider-body report-item in the crate now delegates \
                 through."
            );
        }
    }

    /// Fail-before-pass envelope for [`super::write_pending_item`].
    /// Pins the one-line body every pre-lift consumer spelled verbatim
    /// (`println!("  {} <literal>", "⏳".yellow())`): a two-space
    /// indent, a `.yellow()`-colored `⏳` glyph, a single space, then
    /// the plain (uncolored) message. A silent contract drift a future
    /// rewrite might introduce — dropping the two-space indent (a
    /// "tighter body spacing" cleanup), promoting the whole line's
    /// coloring (`format!("  ⏳ {}", msg).yellow()`) so the message
    /// text paints yellow at every site, swapping `⏳` for `[..]`
    /// under a CI-log-friendly grammar, swapping `⏳` for `○` under a
    /// collapse with the sibling [`super::print_step_skip`] grammar,
    /// promoting `.yellow()` to `.bright_yellow()` (`\x1b[93m` — the
    /// milestone-level [`super::print_warning`] palette), slipping a
    /// trailing blank line into the primitive body — flips this
    /// assertion rather than compiling and silently diverging the 6
    /// consumer sites' visual grammar.
    #[test]
    fn write_pending_item_emits_exactly_one_hourglass_prefixed_two_indented_line() {
        // Force ANSI emission (colored auto-drops sequences on a
        // non-tty stdout) and serialize against peer banner tests via
        // [`AnsiOverrideForTest`]; its Drop restores colored's
        // auto-detection on scope exit AFTER releasing the shared
        // [`ANSI_OVERRIDE_LOCK`], closing the set-write-unset window
        // without a manual [`colored::control::unset_override`] call a
        // future test author could omit.
        let _override_guard = AnsiOverrideForTest::acquire();

        let mut buf: Vec<u8> = Vec::new();
        super::write_pending_item(&mut buf, "Service Pod Rollout")
            .expect("write_pending_item against a Vec<u8> writer must succeed");

        let out = String::from_utf8(buf)
            .expect("write_pending_item must emit valid UTF-8 (the pre-lift println!s did)");

        // Exactly one line — the pre-lift stanza is one `println!`
        // carrying no framing blank.
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(
            lines.len(),
            1,
            "write_pending_item must emit exactly one line — the \
             pre-lift stanza is one `println!` carrying no framing \
             blank; got {}:\n{}",
            lines.len(),
            out
        );

        // Two-space indent, NOT three-space (which is the sibling
        // `print_step_skip` / `print_step_warn` in-body-step grammar).
        assert!(
            lines[0].starts_with("  "),
            "line 0 must begin with a two-space indent — every \
             pre-lift consumer spelled `\"  {{}} <literal>\"` \
             verbatim, so the indent must reach the writer OUTSIDE \
             the coloring span; got {:?}",
            lines[0]
        );
        assert!(
            !lines[0].starts_with("   "),
            "line 0 must NOT begin with a three-space indent — that \
             indent belongs to the sibling in-body `print_step_*` \
             grammar, not this wider-body pending-item grammar; \
             got {:?}",
            lines[0]
        );

        // The `⏳` hourglass glyph reaches the rendered line — NOT
        // `○` (the sibling `print_step_skip` grammar for elided
        // steps) and NOT `⚠️` (the sibling `print_step_warn` grammar
        // for non-fatal irregularities).
        assert!(
            lines[0].contains('⏳'),
            "line 0 must contain the `⏳` hourglass glyph; got {:?}",
            lines[0]
        );
        assert!(
            !lines[0].contains('○'),
            "line 0 must NOT contain the `○` glyph — that glyph \
             belongs to the sibling `print_step_skip` primitive for \
             elided steps, not this in-flight pending-item primitive; \
             got {:?}",
            lines[0]
        );

        // The message text reaches the rendered line verbatim.
        assert!(
            lines[0].contains("Service Pod Rollout"),
            "line 0 must carry the message verbatim; got {:?}",
            lines[0]
        );

        // The `yellow` ANSI sequence — NOT `bright_yellow` (which is
        // the distinct milestone-level `print_warning` palette).
        assert!(
            lines[0].contains("\x1b[33m"),
            "line 0 must carry the `yellow` ANSI sequence \
             (`\\x1b[33m`); got {:?}",
            lines[0]
        );
        assert!(
            !lines[0].contains("\x1b[93m"),
            "line 0 must NOT carry the `bright_yellow` ANSI sequence \
             (`\\x1b[93m`) — that palette belongs to the distinct \
             milestone-level `print_warning` grammar, not this \
             pending-item primitive; got {:?}",
            lines[0]
        );

        // The `.yellow()` coloring wraps the GLYPH alone, never the
        // message text — the `\x1b[0m` reset must close the yellow
        // span BEFORE the message begins.
        let glyph_pos = lines[0].find('⏳').expect("glyph must be present");
        let reset_pos = lines[0]
            .find("\x1b[0m")
            .expect("reset must be present after the glyph");
        let msg_pos = lines[0]
            .find("Service Pod Rollout")
            .expect("message must be present");
        assert!(
            glyph_pos < reset_pos && reset_pos < msg_pos,
            "the `\\x1b[0m` reset must close the yellow span BEFORE \
             the message begins — every pre-lift consumer spelled \
             `.yellow()` on the `⏳` glyph alone, never on the \
             message. Got positions glyph={glyph_pos}, \
             reset={reset_pos}, msg={msg_pos} in line {:?}",
            lines[0]
        );

        // The trailing `\n` reaches the writer — pre-lift stanza used
        // `println!`, so the newline is part of the contract.
        assert!(
            out.ends_with('\n'),
            "write_pending_item must emit a trailing `\\n` (the \
             pre-lift `println!` did); got {:?}",
            out
        );
    }

    /// Post-lift the callers migrated onto
    /// [`super::print_pending_item`] no longer spell the
    /// `println!("  {} <literal>", "⏳".yellow())` shape inline.
    /// Structural regression shield — without it a future refactor
    /// could silently re-inline the one-liner (e.g. a "just call
    /// `println!` directly, it's shorter" cleanup) and reopen the
    /// 6-site duplication class this lift closed. Enforced at the
    /// module body BEFORE its `#[cfg(test)]` region so a test-support
    /// mention of the raw shape does not defeat the shield.
    ///
    /// The exact-shape needle is `"⏳".yellow()` appearing anywhere in
    /// the module body — no allowlist is required because every
    /// pre-lift occurrence in the crate belonged to this class.
    #[test]
    fn print_pending_item_callers_delegate_through_primitive() {
        const CALLERS: &[(&str, &str)] = &[(
            include_str!("commands/rust_service.rs"),
            "commands/rust_service.rs",
        )];
        for (source, module_path) in CALLERS {
            let body = crate::test_support::module_body_before_first_cfg_test(source, module_path);
            for (i, line) in body.lines().enumerate() {
                if !line.contains("\"⏳\".yellow()") {
                    continue;
                }
                panic!(
                    "{module_path}:{lineno} spells the pre-lift inline \
                     `\"⏳\".yellow()` two-space pending-item marker — \
                     that shape was lifted onto \
                     `crate::ui::print_pending_item`. A re-inline \
                     would silently reopen the 6-site duplication \
                     class this shield exists to close. Offending \
                     line: {line:?}",
                    lineno = i + 1
                );
            }
            assert!(
                body.contains("crate::ui::print_pending_item("),
                "{module_path} body must forward to \
                 `crate::ui::print_pending_item(\"<MSG>\")` — the \
                 primitive body every two-space-indented `⏳.yellow()` \
                 pending-item in the crate now delegates through."
            );
        }
    }

    /// Fail-before-pass envelope for [`super::write_arrow_item`]. Pins
    /// the one-line body every pre-lift consumer spelled verbatim
    /// (`println!("  {} <fmt>", "→".cyan(), <args>)`): a two-space
    /// indent, a `.cyan()`-colored `→` forward-arrow glyph, a single
    /// space, then the plain (uncolored) message. A silent contract
    /// drift a future rewrite might introduce — widening the indent to
    /// three-space (collapsing the wider-body narrative grammar into
    /// the sibling in-body `print_step_*` grammar), promoting the whole
    /// line's coloring (`format!("  → {}", msg).cyan()`) so the message
    /// text paints cyan at every site, swapping `→ ` for `-> ` or `[>]
    /// ` under a CI-log-friendly grammar, swapping `→` for `✓` (would
    /// collide with the sibling [`super::print_report_item`] completed-
    /// row grammar) or `⏳` (would collide with the sibling
    /// [`super::print_pending_item`] still-pending grammar), promoting
    /// `.cyan()` to `.bright_cyan()` (`\x1b[96m`), slipping a trailing
    /// blank line into the primitive body — flips this assertion rather
    /// than compiling and silently diverging the 5 consumer sites'
    /// visual grammar.
    #[test]
    fn write_arrow_item_emits_exactly_one_arrow_prefixed_two_indented_line() {
        let _override_guard = AnsiOverrideForTest::acquire();

        let mut buf: Vec<u8> = Vec::new();
        super::write_arrow_item(&mut buf, "Found pod: search-0")
            .expect("write_arrow_item against a Vec<u8> writer must succeed");

        let out = String::from_utf8(buf)
            .expect("write_arrow_item must emit valid UTF-8 (the pre-lift println!s did)");

        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(
            lines.len(),
            1,
            "write_arrow_item must emit exactly one line — the pre-lift \
             stanza is one `println!` carrying no framing blank; got \
             {}:\n{}",
            lines.len(),
            out
        );

        // Two-space indent, NOT three-space (which is the sibling
        // in-body `print_step_*` grammar and the
        // `commands/codegen_validation.rs` `"→".yellow()` sibling).
        assert!(
            lines[0].starts_with("  "),
            "line 0 must begin with a two-space indent — every pre-lift \
             consumer spelled `\"  {{}} <fmt>\"` verbatim, so the \
             indent must reach the writer OUTSIDE the coloring span; \
             got {:?}",
            lines[0]
        );
        assert!(
            !lines[0].starts_with("   "),
            "line 0 must NOT begin with a three-space indent — that \
             indent belongs to the sibling in-body `print_step_*` \
             grammar and the `commands/codegen_validation.rs` \
             `\"→\".yellow()` sibling, not this wider-body arrow-item \
             grammar; got {:?}",
            lines[0]
        );

        // The `→` forward-arrow glyph reaches the rendered line — NOT
        // `✓` (the sibling `print_report_item` completed-row grammar)
        // and NOT `⏳` (the sibling `print_pending_item` still-pending
        // grammar).
        assert!(
            lines[0].contains('→'),
            "line 0 must contain the `→` forward-arrow glyph; got {:?}",
            lines[0]
        );
        assert!(
            !lines[0].contains('✓'),
            "line 0 must NOT contain the `✓` glyph — that glyph \
             belongs to the sibling `print_report_item` primitive for \
             completed rows, not this arrow-item narrative primitive; \
             got {:?}",
            lines[0]
        );
        assert!(
            !lines[0].contains('⏳'),
            "line 0 must NOT contain the `⏳` glyph — that glyph \
             belongs to the sibling `print_pending_item` primitive for \
             still-pending rows, not this arrow-item narrative \
             primitive; got {:?}",
            lines[0]
        );

        // The message text reaches the rendered line verbatim.
        assert!(
            lines[0].contains("Found pod: search-0"),
            "line 0 must carry the message verbatim; got {:?}",
            lines[0]
        );

        // The `cyan` ANSI sequence — NOT `bright_cyan` (`\x1b[96m`),
        // NOT `green` (`\x1b[32m`, the sibling `print_report_item`
        // palette), NOT `yellow` (`\x1b[33m`, the sibling
        // `print_pending_item` palette).
        assert!(
            lines[0].contains("\x1b[36m"),
            "line 0 must carry the `cyan` ANSI sequence (`\\x1b[36m`); \
             got {:?}",
            lines[0]
        );
        assert!(
            !lines[0].contains("\x1b[96m"),
            "line 0 must NOT carry the `bright_cyan` ANSI sequence \
             (`\\x1b[96m`); got {:?}",
            lines[0]
        );
        assert!(
            !lines[0].contains("\x1b[32m"),
            "line 0 must NOT carry the `green` ANSI sequence \
             (`\\x1b[32m`) — that palette belongs to the sibling \
             `print_report_item` completed-row grammar, not this \
             arrow-item narrative grammar; got {:?}",
            lines[0]
        );
        assert!(
            !lines[0].contains("\x1b[33m"),
            "line 0 must NOT carry the `yellow` ANSI sequence \
             (`\\x1b[33m`) — that palette belongs to the sibling \
             `print_pending_item` still-pending grammar, not this \
             arrow-item narrative grammar; got {:?}",
            lines[0]
        );

        // The `.cyan()` coloring wraps the GLYPH alone, never the
        // message text — the `\x1b[0m` reset must close the cyan span
        // BEFORE the message begins.
        let glyph_pos = lines[0].find('→').expect("glyph must be present");
        let reset_pos = lines[0]
            .find("\x1b[0m")
            .expect("reset must be present after the glyph");
        let msg_pos = lines[0]
            .find("Found pod: search-0")
            .expect("message must be present");
        assert!(
            glyph_pos < reset_pos && reset_pos < msg_pos,
            "the `\\x1b[0m` reset must close the cyan span BEFORE the \
             message begins — every pre-lift consumer spelled \
             `.cyan()` on the `→` glyph alone, never on the message. \
             Got positions glyph={glyph_pos}, reset={reset_pos}, \
             msg={msg_pos} in line {:?}",
            lines[0]
        );

        // The trailing `\n` reaches the writer — pre-lift stanza used
        // `println!`, so the newline is part of the contract.
        assert!(
            out.ends_with('\n'),
            "write_arrow_item must emit a trailing `\\n` (the pre-lift \
             `println!` did); got {:?}",
            out
        );
    }

    /// Post-lift the callers migrated onto
    /// [`super::print_arrow_item`] no longer spell the
    /// `println!("  {} <fmt>", "→".cyan(), <args>)` shape inline.
    /// Structural regression shield — without it a future refactor
    /// could silently re-inline the one-liner (e.g. a "just call
    /// `println!` directly, it's shorter" cleanup) and reopen the
    /// 5-site duplication class this lift closed. Enforced at the
    /// module bodies BEFORE their `#[cfg(test)]` regions so a
    /// test-support mention of the raw shape does not defeat the
    /// shield.
    ///
    /// The exact-shape needle is `"→".cyan()` appearing anywhere in the
    /// module body — no allowlist is required because every pre-lift
    /// occurrence in the crate belonged to this class. The
    /// `commands/codegen_validation.rs` `"→".yellow()` sibling (three-
    /// space in-body irregularity grammar) does NOT match the `.cyan()`
    /// needle, so it is not swept in and stays unlifted by design.
    #[test]
    fn print_arrow_item_callers_delegate_through_primitive() {
        const CALLERS: &[(&str, &str)] = &[
            (
                include_str!("commands/rust_service.rs"),
                "commands/rust_service.rs",
            ),
            (
                include_str!("commands/search_sync.rs"),
                "commands/search_sync.rs",
            ),
        ];
        for (source, module_path) in CALLERS {
            let body = crate::test_support::module_body_before_first_cfg_test(source, module_path);
            for (i, line) in body.lines().enumerate() {
                if !line.contains("\"→\".cyan()") {
                    continue;
                }
                panic!(
                    "{module_path}:{lineno} spells the pre-lift inline \
                     `\"→\".cyan()` two-space arrow-item marker — that \
                     shape was lifted onto \
                     `crate::ui::print_arrow_item`. A re-inline would \
                     silently reopen the 5-site duplication class this \
                     shield exists to close. Offending line: {line:?}",
                    lineno = i + 1
                );
            }
            assert!(
                body.contains("crate::ui::print_arrow_item("),
                "{module_path} body must forward to \
                 `crate::ui::print_arrow_item(\"<MSG>\")` — the \
                 primitive body every two-space-indented `→.cyan()` \
                 arrow-item narrative marker in the crate now \
                 delegates through."
            );
        }
    }

    /// Fail-before-pass envelope for [`super::write_watch_item`]. Pins
    /// the one-line body every pre-lift consumer spelled verbatim
    /// (`println!("  {} <literal>", "□".dimmed())`): a two-space
    /// indent, a `.dimmed()`-colored `□` glyph, a single space, then
    /// the plain (uncolored) message. A silent contract drift a future
    /// rewrite might introduce — dropping the two-space indent (a
    /// "tighter body spacing" cleanup), promoting the whole line's
    /// coloring (`format!("  □ {}", msg).dimmed()`) so the message
    /// text paints dim at every site, swapping `□` for `[ ]` under a
    /// CI-log-friendly grammar, swapping `□` for `○` (would collide
    /// with the sibling [`super::print_step_skip`] grammar), swapping
    /// `□` for `✓` (would collide with the sibling
    /// [`super::print_report_item`] completed-row grammar), promoting
    /// `.dimmed()` to `.bright_black()` (`\x1b[90m`), slipping a
    /// trailing blank line into the primitive body — flips this
    /// assertion rather than compiling and silently diverging the 4
    /// consumer sites' visual grammar.
    #[test]
    fn write_watch_item_emits_exactly_one_hollow_square_prefixed_two_indented_line() {
        // Force ANSI emission (colored auto-drops sequences on a
        // non-tty stdout) and serialize against peer banner tests via
        // [`AnsiOverrideForTest`]; its Drop restores colored's
        // auto-detection on scope exit AFTER releasing the shared
        // [`ANSI_OVERRIDE_LOCK`], closing the set-write-unset window
        // without a manual [`colored::control::unset_override`] call a
        // future test author could omit.
        let _override_guard = AnsiOverrideForTest::acquire();

        let mut buf: Vec<u8> = Vec::new();
        super::write_watch_item(&mut buf, "Pod fails to start")
            .expect("write_watch_item against a Vec<u8> writer must succeed");

        let out = String::from_utf8(buf)
            .expect("write_watch_item must emit valid UTF-8 (the pre-lift println!s did)");

        // Exactly one line — the pre-lift stanza is one `println!`
        // carrying no framing blank.
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(
            lines.len(),
            1,
            "write_watch_item must emit exactly one line — the \
             pre-lift stanza is one `println!` carrying no framing \
             blank; got {}:\n{}",
            lines.len(),
            out
        );

        // Two-space indent, NOT three-space (which is the sibling
        // in-body `print_step_*` grammar).
        assert!(
            lines[0].starts_with("  "),
            "line 0 must begin with a two-space indent — every \
             pre-lift consumer spelled `\"  {{}} <literal>\"` \
             verbatim, so the indent must reach the writer OUTSIDE \
             the coloring span; got {:?}",
            lines[0]
        );
        assert!(
            !lines[0].starts_with("   "),
            "line 0 must NOT begin with a three-space indent — that \
             indent belongs to the sibling in-body `print_step_*` \
             grammar, not this wider-body watch-item grammar; \
             got {:?}",
            lines[0]
        );

        // The `□` hollow-square glyph reaches the rendered line — NOT
        // `○` (the sibling `print_step_skip` grammar for elided
        // steps), NOT `✓` (the sibling `print_report_item` grammar
        // for completed rows), NOT `⏳` (the sibling
        // `print_pending_item` grammar for in-flight rows), NOT `→`
        // (the sibling `print_arrow_item` grammar for narration).
        assert!(
            lines[0].contains('□'),
            "line 0 must contain the `□` hollow-square glyph; got {:?}",
            lines[0]
        );
        assert!(
            !lines[0].contains('○'),
            "line 0 must NOT contain the `○` glyph — that glyph \
             belongs to the sibling `print_step_skip` primitive for \
             elided steps, not this watch-item primitive; got {:?}",
            lines[0]
        );
        assert!(
            !lines[0].contains('✓'),
            "line 0 must NOT contain the `✓` glyph — that glyph \
             belongs to the sibling `print_report_item` primitive for \
             completed rows, not this watch-item primitive; got {:?}",
            lines[0]
        );
        assert!(
            !lines[0].contains('⏳'),
            "line 0 must NOT contain the `⏳` glyph — that glyph \
             belongs to the sibling `print_pending_item` primitive \
             for in-flight rows, not this watch-item primitive; \
             got {:?}",
            lines[0]
        );
        assert!(
            !lines[0].contains('→'),
            "line 0 must NOT contain the `→` glyph — that glyph \
             belongs to the sibling `print_arrow_item` primitive for \
             narration markers, not this watch-item primitive; \
             got {:?}",
            lines[0]
        );

        // The message text reaches the rendered line verbatim.
        assert!(
            lines[0].contains("Pod fails to start"),
            "line 0 must carry the message verbatim; got {:?}",
            lines[0]
        );

        // The `dim` ANSI sequence — NOT `bright_black` (which is the
        // distinct `.bright_black()` palette a future refactor might
        // slip in as a "friendlier deprioritization" cleanup).
        assert!(
            lines[0].contains("\x1b[2m"),
            "line 0 must carry the `dim` ANSI sequence \
             (`\\x1b[2m`); got {:?}",
            lines[0]
        );
        assert!(
            !lines[0].contains("\x1b[90m"),
            "line 0 must NOT carry the `bright_black` ANSI sequence \
             (`\\x1b[90m`) — that palette is a distinct deprioritized \
             shade the pre-lift consumers deliberately did not use; \
             got {:?}",
            lines[0]
        );
        assert!(
            !lines[0].contains("\x1b[32m"),
            "line 0 must NOT carry the `green` ANSI sequence \
             (`\\x1b[32m`) — that palette belongs to the sibling \
             `print_report_item` completed-row grammar, not this \
             watch-item grammar; got {:?}",
            lines[0]
        );
        assert!(
            !lines[0].contains("\x1b[33m"),
            "line 0 must NOT carry the `yellow` ANSI sequence \
             (`\\x1b[33m`) — that palette belongs to the sibling \
             `print_pending_item` still-pending grammar, not this \
             watch-item grammar; got {:?}",
            lines[0]
        );
        assert!(
            !lines[0].contains("\x1b[36m"),
            "line 0 must NOT carry the `cyan` ANSI sequence \
             (`\\x1b[36m`) — that palette belongs to the sibling \
             `print_arrow_item` narrative grammar, not this \
             watch-item grammar; got {:?}",
            lines[0]
        );

        // The `.dimmed()` coloring wraps the GLYPH alone, never the
        // message text — the `\x1b[0m` reset must close the dim span
        // BEFORE the message begins.
        let glyph_pos = lines[0].find('□').expect("glyph must be present");
        let reset_pos = lines[0]
            .find("\x1b[0m")
            .expect("reset must be present after the glyph");
        let msg_pos = lines[0]
            .find("Pod fails to start")
            .expect("message must be present");
        assert!(
            glyph_pos < reset_pos && reset_pos < msg_pos,
            "the `\\x1b[0m` reset must close the dim span BEFORE the \
             message begins — every pre-lift consumer spelled \
             `.dimmed()` on the `□` glyph alone, never on the \
             message. Got positions glyph={glyph_pos}, \
             reset={reset_pos}, msg={msg_pos} in line {:?}",
            lines[0]
        );

        // The trailing `\n` reaches the writer — pre-lift stanza used
        // `println!`, so the newline is part of the contract.
        assert!(
            out.ends_with('\n'),
            "write_watch_item must emit a trailing `\\n` (the \
             pre-lift `println!` did); got {:?}",
            out
        );
    }

    /// Post-lift the callers migrated onto
    /// [`super::print_watch_item`] no longer spell the
    /// `println!("  {} <literal>", "□".dimmed())` shape inline.
    /// Structural regression shield — without it a future refactor
    /// could silently re-inline the one-liner (e.g. a "just call
    /// `println!` directly, it's shorter" cleanup) and reopen the
    /// 4-site duplication class this lift closed. Enforced at the
    /// module body BEFORE its `#[cfg(test)]` region so a test-support
    /// mention of the raw shape does not defeat the shield.
    ///
    /// The exact-shape needle is `"□".dimmed()` appearing anywhere in
    /// the module body — no allowlist is required because every
    /// pre-lift occurrence in the crate belonged to this class.
    #[test]
    fn print_watch_item_callers_delegate_through_primitive() {
        const CALLERS: &[(&str, &str)] = &[(
            include_str!("commands/rust_service.rs"),
            "commands/rust_service.rs",
        )];
        for (source, module_path) in CALLERS {
            let body = crate::test_support::module_body_before_first_cfg_test(source, module_path);
            for (i, line) in body.lines().enumerate() {
                if !line.contains("\"□\".dimmed()") {
                    continue;
                }
                panic!(
                    "{module_path}:{lineno} spells the pre-lift inline \
                     `\"□\".dimmed()` two-space watch-item marker — \
                     that shape was lifted onto \
                     `crate::ui::print_watch_item`. A re-inline \
                     would silently reopen the 4-site duplication \
                     class this shield exists to close. Offending \
                     line: {line:?}",
                    lineno = i + 1
                );
            }
            assert!(
                body.contains("crate::ui::print_watch_item("),
                "{module_path} body must forward to \
                 `crate::ui::print_watch_item(\"<MSG>\")` — the \
                 primitive body every two-space-indented `□.dimmed()` \
                 watch-item in the crate now delegates through."
            );
        }
    }

    /// Fail-before-pass envelope for [`super::write_arrow_hint`]. Pins
    /// the one-line body every pre-lift consumer spelled verbatim
    /// (`println!("    → <literal>")`): a four-space indent, a plain
    /// `→` forward-arrow glyph, a single space, then the plain
    /// (uncolored) message. A silent contract drift a future rewrite
    /// might introduce — narrowing the indent to two-space (collapsing
    /// this leaf hint grammar into the sibling
    /// [`super::print_arrow_item`] wider-body narrative grammar),
    /// widening the indent to six-space (drifting the visual nesting
    /// beneath the `□.dimmed()` watch-item head), swapping `→` for
    /// `-` or `>` under a CI-log-friendly grammar, swapping `→` for
    /// `✓` (would collide with [`super::print_report_item`] completed-
    /// row grammar) or `⏳` (would collide with
    /// [`super::print_pending_item`] still-pending grammar), wrapping
    /// the glyph or message in `.cyan()` (would collide with
    /// [`super::print_arrow_item`] narrative palette) or `.dimmed()`
    /// (would promote the leaf hint to the same weight as its
    /// `□.dimmed()` watch-item head), slipping a trailing blank line
    /// into the primitive body — flips this assertion rather than
    /// compiling and silently diverging the 12 consumer sites' visual
    /// grammar.
    #[test]
    fn write_arrow_hint_emits_exactly_one_four_indented_uncolored_arrow_leaf_hint_line() {
        // Force ANSI-emission serialization against peer banner tests
        // via [`AnsiOverrideForTest`] — even though this primitive
        // emits NO ANSI sequences, the guard's presence pins the
        // discipline: if a future refactor slips a `.dimmed()` /
        // `.cyan()` chain into the writer, the guard ensures the
        // sequence actually reaches the buffer for detection here
        // rather than being auto-stripped by [`colored`]'s non-tty
        // fallback. The guard's Drop restores colored's auto-detection
        // on scope exit AFTER releasing the shared
        // [`ANSI_OVERRIDE_LOCK`].
        let _override_guard = AnsiOverrideForTest::acquire();

        let mut buf: Vec<u8> = Vec::new();
        super::write_arrow_hint(&mut buf, "Check logs for startup errors")
            .expect("write_arrow_hint against a Vec<u8> writer must succeed");

        let out = String::from_utf8(buf)
            .expect("write_arrow_hint must emit valid UTF-8 (the pre-lift println!s did)");

        // Exactly one line — the pre-lift stanza is one `println!`
        // carrying no framing blank.
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(
            lines.len(),
            1,
            "write_arrow_hint must emit exactly one line — the \
             pre-lift stanza is one `println!` carrying no framing \
             blank; got {}:\n{}",
            lines.len(),
            out
        );

        // Exactly four spaces of indent — NOT two (the sibling
        // wider-body [`super::print_arrow_item`] narrative marker),
        // NOT three (the sibling in-body `print_step_*` grammar).
        // The needle uses a five-char prefix guard so a fusion that
        // widened the indent to five or more spaces also flips this.
        assert!(
            lines[0].starts_with("    → "),
            "line 0 must begin with a four-space indent followed by \
             `→ ` verbatim — every pre-lift consumer spelled \
             `\"    → <literal>\"` verbatim, so the four-space indent \
             AND the plain `→ ` prefix must reach the writer together; \
             got {:?}",
            lines[0]
        );
        assert!(
            !lines[0].starts_with("     "),
            "line 0 must NOT begin with a five-or-more-space indent — \
             a widened indent would drift the visual nesting beneath \
             the `□.dimmed()` watch-item head; got {:?}",
            lines[0]
        );
        assert!(
            !lines[0].starts_with("  → "),
            "line 0 must NOT begin with a two-space indent followed \
             by `→ ` — that two-space grammar belongs to the sibling \
             wider-body `print_arrow_item` narrative marker, not \
             this leaf hint primitive; got {:?}",
            lines[0]
        );

        // The `→` forward-arrow glyph reaches the rendered line — NOT
        // `✓` (the sibling `print_report_item` completed-row grammar),
        // NOT `⏳` (the sibling `print_pending_item` still-pending
        // grammar), NOT `□` (the sibling `print_watch_item` watch
        // head grammar).
        assert!(
            lines[0].contains('→'),
            "line 0 must contain the `→` forward-arrow glyph; got {:?}",
            lines[0]
        );
        assert!(
            !lines[0].contains('✓'),
            "line 0 must NOT contain the `✓` glyph — that glyph \
             belongs to the sibling `print_report_item` primitive for \
             completed rows, not this arrow-hint leaf primitive; \
             got {:?}",
            lines[0]
        );
        assert!(
            !lines[0].contains('⏳'),
            "line 0 must NOT contain the `⏳` glyph — that glyph \
             belongs to the sibling `print_pending_item` primitive \
             for still-pending rows, not this arrow-hint leaf \
             primitive; got {:?}",
            lines[0]
        );
        assert!(
            !lines[0].contains('□'),
            "line 0 must NOT contain the `□` glyph — that glyph \
             belongs to the sibling `print_watch_item` primitive for \
             watch-head rows, not this arrow-hint leaf primitive; \
             got {:?}",
            lines[0]
        );

        // The message text reaches the rendered line verbatim.
        assert!(
            lines[0].contains("Check logs for startup errors"),
            "line 0 must carry the message verbatim; got {:?}",
            lines[0]
        );

        // ABSENCE OF ALL PALETTE ANSI SEQUENCES — no coloring at all.
        // A silent promotion of the whole line to `.dimmed()` (which
        // would collide visually with the `□.dimmed()` watch head) or
        // to `.cyan()` (which would collide with `print_arrow_item`'s
        // narrative palette) reaches the buffer as one of these
        // sequences and flips the corresponding assertion.
        for (ansi_seq, palette_label, colliding_primitive) in [
            ("\x1b[2m", "dim", "print_watch_item (`.dimmed()`)"),
            ("\x1b[90m", "bright_black", "no current sibling"),
            ("\x1b[36m", "cyan", "print_arrow_item (`.cyan()` narrative)"),
            (
                "\x1b[96m",
                "bright_cyan",
                "no current sibling; would drift arrow-item palette",
            ),
            (
                "\x1b[32m",
                "green",
                "print_report_item (`.green()` completed)",
            ),
            (
                "\x1b[33m",
                "yellow",
                "print_pending_item (`.yellow()` still-pending)",
            ),
            (
                "\x1b[31m",
                "red",
                "print_step_failure (`.red()` step-failure)",
            ),
            ("\x1b[1m", "bold", "no current sibling"),
        ] {
            assert!(
                !lines[0].contains(ansi_seq),
                "line 0 must NOT carry the `{palette_label}` ANSI \
                 sequence ({ansi_seq:?}) — every pre-lift consumer \
                 spelled the hint as a plain `println!(\"    → \
                 <literal>\")` with NO coloring chain, so the leaf \
                 hint recedes beneath the sibling `□.dimmed()` \
                 watch-item head without competing for eye attention. \
                 A promotion to this palette would collide with \
                 {colliding_primitive}. Got {:?}",
                lines[0]
            );
        }
        // Sanity: no ANSI escape byte at all in the rendered line.
        assert!(
            !lines[0].contains('\x1b'),
            "line 0 must contain no ANSI escape byte (`\\x1b`) at all \
             — this leaf hint primitive emits no coloring; got {:?}",
            lines[0]
        );

        // The trailing `\n` reaches the writer — pre-lift stanza used
        // `println!`, so the newline is part of the contract.
        assert!(
            out.ends_with('\n'),
            "write_arrow_hint must emit a trailing `\\n` (the \
             pre-lift `println!` did); got {:?}",
            out
        );
    }

    /// Post-lift the callers in `commands/rust_service.rs` migrated
    /// onto [`super::print_arrow_hint`] no longer spell the
    /// `println!("    → <literal>")` shape inline. Structural
    /// regression shield — without it a future refactor could
    /// silently re-inline the one-liner (e.g. a "just call `println!`
    /// directly, it's shorter" cleanup) and reopen the 12-site
    /// duplication class this lift closed. Enforced at the module
    /// body BEFORE its first `#[cfg(test)]` region so a test-support
    /// mention of the raw shape does not defeat the shield.
    ///
    /// The exact-shape needle is the four-space `println!("    → `
    /// prefix, which is the pre-lift `println!("    → <literal>")`
    /// grammar in full (indent + macro + opening quote + four spaces
    /// + arrow + space). No allowlist is required because every
    /// pre-lift occurrence in the crate belonged to this class; a
    /// re-inline with any literal completing the shape flips the
    /// shield.
    ///
    /// The positive count is pinned at TWELVE — one per pre-lift
    /// consumer (Pod-fails-to-start ×3, Pod-is-CrashLoopBackOff ×3,
    /// Hive-Router-fails-after-update ×3, GraphQL-queries-fail ×3).
    /// A fusion that fused two consumer sites into one call (e.g. a
    /// join into a single `println!`) or dropped one of the hints
    /// silently fails here — the negative half above would still
    /// pass, but this positive count would fall to eleven.
    #[test]
    fn print_arrow_hint_callers_in_rust_service_delegate_through_primitive() {
        const SRC: &str = include_str!("commands/rust_service.rs");
        const MODULE_PATH: &str = "commands/rust_service.rs";
        let body = crate::test_support::module_body_before_first_cfg_test(SRC, MODULE_PATH);
        for (i, line) in body.lines().enumerate() {
            // Match the pre-lift `println!("    → ` prefix in full —
            // indent + macro + opening quote + four spaces + arrow +
            // space. A comment or docstring line whose payload text
            // happens to spell `    → ` never matches because the
            // needle demands the `println!("` prefix reach the byte
            // before the four-space indent.
            if !line.contains("println!(\"    → ") {
                continue;
            }
            panic!(
                "{MODULE_PATH}:{lineno} spells the pre-lift inline \
                 `println!(\"    → <literal>\")` four-space nested \
                 arrow-hint stanza — that shape was lifted onto \
                 `crate::ui::print_arrow_hint`. A re-inline would \
                 silently reopen the 12-site duplication class this \
                 shield exists to close. Offending line: {line:?}",
                lineno = i + 1
            );
        }
        let forward_hits = body.matches("crate::ui::print_arrow_hint(").count();
        assert_eq!(
            forward_hits, 12,
            "{MODULE_PATH} body must forward to \
             `crate::ui::print_arrow_hint(\"<MSG>\")` at exactly \
             TWELVE sites — one per pre-lift consumer (Pod-fails-to-\
             start ×3, Pod-is-CrashLoopBackOff ×3, Hive-Router-fails-\
             after-update ×3, GraphQL-queries-fail ×3). A fusion \
             that fused two consumer sites into one call or dropped \
             one of the hints silently fails here. Found \
             {forward_hits} forwarding hits."
        );
    }

    /// Fail-before-pass envelope for [`super::write_bullet_item`]. Pins
    /// the one-line body every pre-lift consumer spelled verbatim
    /// (`println!("  • <literal>")` or `println!("  • <fmt>", <args>)`):
    /// a two-space indent, a plain U+2022 `•` BULLET glyph, a single
    /// space, then the plain (uncolored) message. A silent contract drift
    /// a future rewrite might introduce — narrowing the indent to
    /// zero-space (colliding with `println!("Generated files:")` heading
    /// grammar sitting immediately above the bullet list), widening the
    /// indent to three-space (colliding with the in-body `print_step_*`
    /// grammar), swapping U+2022 `•` for U+00B7 `·` middle-dot (would
    /// render as a nearly-invisible dot on most fonts) or ASCII `*`
    /// (would collide with markdown/README list grammars), wrapping the
    /// glyph or message in `.green()` / `.yellow()` / `.cyan()` /
    /// `.dimmed()` (would collide with [`super::print_report_item`] /
    /// [`super::print_pending_item`] / [`super::print_arrow_item`] /
    /// [`super::print_watch_item`] semantic-loaded item grammars),
    /// slipping a trailing blank line into the primitive body — flips
    /// this assertion rather than compiling and silently diverging the
    /// 24 consumer sites' visual grammar.
    #[test]
    fn write_bullet_item_emits_exactly_one_two_indented_uncolored_bullet_list_entry_line() {
        // Force ANSI-emission serialization against peer banner tests
        // via [`AnsiOverrideForTest`] — even though this primitive
        // emits NO ANSI sequences, the guard's presence pins the
        // discipline: if a future refactor slips a `.dimmed()` /
        // `.green()` / `.cyan()` chain into the writer, the guard
        // ensures the sequence actually reaches the buffer for
        // detection here rather than being auto-stripped by
        // [`colored`]'s non-tty fallback. The guard's Drop restores
        // colored's auto-detection on scope exit AFTER releasing the
        // shared [`ANSI_OVERRIDE_LOCK`].
        let _override_guard = AnsiOverrideForTest::acquire();

        let mut buf: Vec<u8> = Vec::new();
        super::write_bullet_item(&mut buf, "FluxCD status: flux get kustomizations -A")
            .expect("write_bullet_item against a Vec<u8> writer must succeed");

        let out = String::from_utf8(buf)
            .expect("write_bullet_item must emit valid UTF-8 (the pre-lift println!s did)");

        // Exactly one line — the pre-lift stanza is one `println!`
        // carrying no framing blank.
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(
            lines.len(),
            1,
            "write_bullet_item must emit exactly one line — the \
             pre-lift stanza is one `println!` carrying no framing \
             blank; got {}:\n{}",
            lines.len(),
            out
        );

        // Exactly two spaces of indent followed by `• ` verbatim —
        // NOT zero-space (the sibling `println!("Generated files:")`
        // heading grammar sitting immediately above the bullet list),
        // NOT three-space (the sibling in-body `print_step_*`
        // grammar). The needle uses a four-char prefix guard so a
        // fusion that widened the indent to four or more spaces also
        // flips this.
        assert!(
            lines[0].starts_with("  • "),
            "line 0 must begin with a two-space indent followed by \
             `• ` verbatim — every pre-lift consumer spelled \
             `\"  • <literal>\"` or `\"  • <fmt>\"` verbatim, so the \
             indent + glyph + space triple must reach the writer \
             OUTSIDE any coloring span; got {:?}",
            lines[0]
        );
        assert!(
            !lines[0].starts_with("   "),
            "line 0 must NOT begin with a three-space indent — that \
             indent belongs to the sibling in-body `print_step_*` \
             grammar, not this wider-body bullet-item grammar; \
             got {:?}",
            lines[0]
        );

        // The U+2022 BULLET glyph reaches the rendered line as the
        // three-byte `e2 80 a2` UTF-8 sequence — NOT U+00B7 `·`
        // middle-dot (two bytes `c2 b7`), NOT ASCII `*` (one byte
        // `2a`). A silent codepoint drift renders the catalog nearly-
        // invisible or collides with markdown list grammar.
        assert!(
            lines[0]
                .as_bytes()
                .windows(3)
                .any(|w| w == [0xe2, 0x80, 0xa2]),
            "line 0 must carry the U+2022 `•` BULLET codepoint as the \
             three-byte UTF-8 sequence `e2 80 a2` — a swap to U+00B7 \
             `·` middle-dot or ASCII `*` silently changes the visual \
             grammar; got {:?}",
            lines[0]
        );
        assert!(
            !lines[0].contains('·'),
            "line 0 must NOT contain the U+00B7 `·` middle-dot glyph \
             — that codepoint renders nearly-invisibly on most fonts; \
             got {:?}",
            lines[0]
        );
        assert!(
            !lines[0].contains('*'),
            "line 0 must NOT contain the ASCII `*` asterisk — that \
             glyph collides with markdown/README list grammars the \
             operator reads in a wholly different visual register; \
             got {:?}",
            lines[0]
        );
        assert!(
            !lines[0].contains('✓'),
            "line 0 must NOT contain the `✓` glyph — that glyph \
             belongs to the sibling `print_report_item` primitive for \
             completed rows, not this bullet-item primitive; got {:?}",
            lines[0]
        );
        assert!(
            !lines[0].contains('⏳'),
            "line 0 must NOT contain the `⏳` glyph — that glyph \
             belongs to the sibling `print_pending_item` primitive \
             for in-flight rows, not this bullet-item primitive; \
             got {:?}",
            lines[0]
        );
        assert!(
            !lines[0].contains('→'),
            "line 0 must NOT contain the `→` glyph — that glyph \
             belongs to the sibling `print_arrow_item` primitive for \
             narration markers, not this bullet-item primitive; \
             got {:?}",
            lines[0]
        );
        assert!(
            !lines[0].contains('□'),
            "line 0 must NOT contain the `□` glyph — that glyph \
             belongs to the sibling `print_watch_item` primitive for \
             watch-for-these-issues rows, not this bullet-item \
             primitive; got {:?}",
            lines[0]
        );

        // The message text reaches the rendered line verbatim.
        assert!(
            lines[0].contains("FluxCD status: flux get kustomizations -A"),
            "line 0 must carry the message verbatim; got {:?}",
            lines[0]
        );

        // Absolutely no ANSI escape sequence reaches the writer — the
        // pre-lift consumers all spelled the bullet row plain
        // (no `.dimmed()` / `.green()` / `.cyan()` / `.yellow()` /
        // `.bright_black()` chain). A silent palette promotion would
        // paint the inert catalog with a status color, collapsing the
        // visual distinction against the sibling item-list primitives.
        assert!(
            !lines[0].contains("\x1b["),
            "line 0 must NOT contain any `\\x1b[` ANSI escape prefix \
             — every pre-lift consumer emitted the bullet row plain, \
             and a silent palette promotion would collide with the \
             sibling `print_report_item` / `print_pending_item` / \
             `print_arrow_item` / `print_watch_item` semantic-loaded \
             grammars; got {:?}",
            lines[0]
        );

        // The trailing `\n` reaches the writer — pre-lift stanza used
        // `println!`, so the newline is part of the contract.
        assert!(
            out.ends_with('\n'),
            "write_bullet_item must emit a trailing `\\n` (the \
             pre-lift `println!` did); got {:?}",
            out
        );
    }

    /// Post-lift the callers migrated onto
    /// [`super::print_bullet_item`] no longer spell the
    /// `println!("  • <literal>")` / `println!("  • <fmt>", <args>)`
    /// shape inline. Structural regression shield — without it a
    /// future refactor could silently re-inline the one-liner (e.g. a
    /// "just call `println!` directly, it's shorter" cleanup) and
    /// reopen the 24-site duplication class this lift closed.
    /// Enforced at the module body BEFORE its first `#[cfg(test)]`
    /// region so a test-support mention of the raw shape does not
    /// defeat the shield.
    ///
    /// The exact-shape needle is the `"  • ` prefix (opening quote +
    /// two spaces + U+2022 bullet + space), which is the pre-lift
    /// `println!("  • ...")` and multi-line
    /// `println!(\n    "  • ...",\n    <arg>\n);` grammar in full.
    /// No allowlist is required because every pre-lift occurrence in
    /// the crate belonged to this class; a re-inline with any literal
    /// completing the shape flips the shield.
    #[test]
    fn print_bullet_item_callers_delegate_through_primitive() {
        // `commands/deploy.rs` carries no `#[cfg(test)]` block so the
        // shared `module_body_before_first_cfg_test` helper panics on
        // its miss; the raw source is safe to scan whole because the
        // module's entire body is production code (no test bodies to
        // filter out) and this shield's own diagnostic prose lives in
        // `ui.rs`, never in the target modules the `include_str!`
        // above pulls in.
        const CALLERS: &[(&str, &str, bool, usize)] = &[
            (
                include_str!("commands/developer_tools.rs"),
                "commands/developer_tools.rs",
                true,
                11,
            ),
            (
                include_str!("commands/comprehensive_release.rs"),
                "commands/comprehensive_release.rs",
                true,
                5,
            ),
            (
                include_str!("commands/deploy.rs"),
                "commands/deploy.rs",
                false,
                4,
            ),
            (
                include_str!("commands/web_service.rs"),
                "commands/web_service.rs",
                true,
                4,
            ),
        ];
        for (source, module_path, has_cfg_test, expected_forwards) in CALLERS {
            let body: &str = if *has_cfg_test {
                crate::test_support::module_body_before_first_cfg_test(source, module_path)
            } else {
                source
            };
            for (i, line) in body.lines().enumerate() {
                if !line.contains("\"  • ") {
                    continue;
                }
                panic!(
                    "{module_path}:{lineno} spells the pre-lift inline \
                     `\"  • ` two-space bullet-list stanza — that \
                     shape was lifted onto \
                     `crate::ui::print_bullet_item`. A re-inline \
                     would silently reopen the 24-site duplication \
                     class this shield exists to close. Offending \
                     line: {line:?}",
                    lineno = i + 1
                );
            }
            let forward_hits = body.matches("crate::ui::print_bullet_item(").count();
            assert_eq!(
                forward_hits, *expected_forwards,
                "{module_path} body must forward to \
                 `crate::ui::print_bullet_item(\"<MSG>\")` at exactly \
                 {expected_forwards} site(s) — one per pre-lift \
                 consumer in this module. A fusion that folded two \
                 consumer sites into one call or dropped one of the \
                 bullet rows silently fails here. Found \
                 {forward_hits} forwarding hits."
            );
        }
    }

    /// Fail-before-pass envelope for [`super::write_step_warn`]. Pins
    /// the one-line body every pre-lift consumer spelled verbatim
    /// (`println!("   {} <fmt>", "⚠️".yellow(), <args>)`): a three-space
    /// indent, a `.yellow()`-colored `⚠️` glyph, a single space, then the
    /// plain (uncolored) message. A silent contract drift a future
    /// rewrite might introduce — dropping the three-space indent (a
    /// "tighter body spacing" cleanup), promoting the whole line's
    /// coloring (`format!("   ⚠️ {}", msg).yellow()`) so the message
    /// text paints yellow at every site, swapping `⚠️ ` for `!` under a
    /// CI-log-friendly grammar, promoting `.yellow()` to
    /// `.bright_yellow()` (`\x1b[93m` — the milestone-level
    /// [`super::print_warning`] palette), slipping a trailing blank
    /// line into the primitive body — flips this assertion rather than
    /// compiling and silently diverging the 5 consumer sites' visual
    /// grammar.
    #[test]
    fn write_step_warn_emits_exactly_one_warn_prefixed_indented_line() {
        // Force ANSI emission (colored auto-drops sequences on a
        // non-tty stdout) and serialize against peer banner tests
        // via [`AnsiOverrideForTest`]; its Drop restores colored's
        // auto-detection on scope exit AFTER releasing the shared
        // [`ANSI_OVERRIDE_LOCK`], closing the set-write-unset window
        // without a manual [`colored::control::unset_override`] call
        // that a future test author could omit.
        let _override_guard = AnsiOverrideForTest::acquire();

        let mut buf: Vec<u8> = Vec::new();
        super::write_step_warn(&mut buf, "Pre-cleanup warning: orphaned container")
            .expect("write_step_warn against a Vec<u8> writer must succeed");

        let out = String::from_utf8(buf)
            .expect("write_step_warn must emit valid UTF-8 (the pre-lift println!s did)");

        // Exactly one line — the pre-lift stanza is one `println!`,
        // not two, and carries no framing blank. A refactor that slips
        // a leading or trailing blank into the primitive body fails
        // here.
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(
            lines.len(),
            1,
            "write_step_warn must emit exactly one line — the \
             pre-lift stanza is one `println!` carrying no framing \
             blank; got {}:\n{}",
            lines.len(),
            out
        );

        // The three-space indent reaches the rendered line before any
        // ANSI escape — a fusion that hoisted the indent inside the
        // coloring span (`"   ⚠️".yellow()`) or dropped it altogether
        // (`println!("{} <msg>", "⚠️".yellow())`) fails here.
        assert!(
            lines[0].starts_with("   "),
            "line 0 must begin with a three-space indent — every \
             pre-lift consumer spelled `\"   {{}} <fmt>\"` verbatim, \
             so the indent must reach the writer OUTSIDE the coloring \
             span; got {:?}",
            lines[0]
        );

        // The `⚠️ ` glyph reaches the rendered line — a fusion that
        // swapped `⚠️ ` for `!` under a "CI-log-friendly" cleanup or
        // dropped the glyph altogether fails here.
        assert!(
            lines[0].contains('⚠'),
            "line 0 must contain the `⚠️` glyph — every pre-lift \
             consumer spelled `\"⚠️\".yellow()` on the marker; got {:?}",
            lines[0]
        );

        // The message text reaches the rendered line verbatim; a
        // fusion that hoists the message off the parameter and pins
        // it to a constant fails here.
        assert!(
            lines[0].contains("Pre-cleanup warning: orphaned container"),
            "line 0 must carry the message verbatim; got {:?}",
            lines[0]
        );

        // The `yellow` ANSI sequence (`\x1b[33m`) reaches the rendered
        // line; a fusion that dropped `.yellow()` (a "just print the
        // string, it's shorter" cleanup) or promoted the palette to
        // `.bright_yellow()` (`\x1b[93m` — the [`super::print_warning`]
        // milestone palette) fails here. A promotion collapses the
        // visual distinction between step-warn and milestone
        // grammars this primitive exists to preserve.
        assert!(
            lines[0].contains("\x1b[33m"),
            "line 0 must carry the `yellow` ANSI sequence (`\\x1b[33m`) \
             — every pre-lift consumer spelled `.yellow()` (never \
             `.bright_yellow()` or `.yellow().bold()`) on the glyph; \
             got {:?}",
            lines[0]
        );
        assert!(
            !lines[0].contains("\x1b[93m"),
            "line 0 must NOT carry the `bright_yellow` ANSI sequence \
             (`\\x1b[93m`) — that palette belongs to the heavier \
             milestone-level `print_warning`, not this in-body \
             step-warn primitive; got {:?}",
            lines[0]
        );

        // The `.yellow()` coloring wraps the GLYPH alone, never the
        // message text — a fusion that hoisted the color onto the
        // composed line (`format!("   ⚠️ {}", msg).yellow()`) would
        // paint the message yellow at every site. Pin that the
        // message text is NOT bracketed by a yellow-open + reset
        // pair: the yellow span must close (`\x1b[0m`) BEFORE the
        // space that precedes the message.
        let warn_pos = lines[0].find('⚠').expect("glyph must be present");
        let reset_pos = lines[0]
            .find("\x1b[0m")
            .expect("reset must be present after the glyph");
        let msg_pos = lines[0]
            .find("Pre-cleanup warning")
            .expect("message must be present");
        assert!(
            warn_pos < reset_pos && reset_pos < msg_pos,
            "the `\\x1b[0m` reset must close the yellow span BEFORE the \
             message begins — every pre-lift consumer spelled `.yellow()` \
             on the `⚠️` glyph alone, never on the message. Got \
             positions warn={warn_pos}, reset={reset_pos}, msg={msg_pos} \
             in line {:?}",
            lines[0]
        );

        // The trailing `\n` reaches the writer — pre-lift stanza used
        // `println!` (not `print!`), so the newline is part of the
        // contract. A fusion that swapped `writeln!` for `write!`
        // fails here.
        assert!(
            out.ends_with('\n'),
            "write_step_warn must emit a trailing `\\n` (the \
             pre-lift `println!` did); got {:?}",
            out
        );
    }

    /// Post-lift the callers migrated onto [`super::print_step_warn`]
    /// no longer spell the `println!("   {} <fmt>", "⚠️".yellow(),
    /// <args>)` shape inline. Structural regression shield — without
    /// it, a future refactor could silently re-inline the one-liner
    /// (e.g. a "just call `println!` directly, it's shorter" cleanup)
    /// and reopen the 5-site duplication class this lift closed.
    /// Enforced at the module bodies before their `#[cfg(test)]`
    /// regions so a test-support mention of the raw shape does not
    /// defeat the shield.
    ///
    /// The exact-shape needle is `"⚠️".yellow()` appearing anywhere in
    /// the module body, MINUS the one known non-step-warn site that
    /// carries the same coloring under a different grammar: the
    /// `rust_service.rs:1884` `eprintln!(...)` stderr-routed
    /// missing-credentials warning (same visual grammar, different
    /// output stream — see the `# stdout, not stderr` note on
    /// [`super::print_step_warn`]). Survives untouched; the shield
    /// allowlists it by an anchoring substring unique to that site.
    #[test]
    fn print_step_warn_callers_delegate_through_primitive() {
        const CALLERS: &[(&str, &str)] = &[
            (
                include_str!("commands/post_deploy_verification.rs"),
                "commands/post_deploy_verification.rs",
            ),
            (
                include_str!("commands/frontend_validation.rs"),
                "commands/frontend_validation.rs",
            ),
            (
                include_str!("commands/migration_validation.rs"),
                "commands/migration_validation.rs",
            ),
            (
                include_str!("commands/prerelease.rs"),
                "commands/prerelease.rs",
            ),
        ];
        // Non-step-warn sites that carry `"⚠️".yellow()` under a
        // different grammar (a stderr-routed `eprintln!` sibling
        // that shares the visual grammar but not the output stream).
        // Each is anchored by a substring unique to that site so the
        // shield allowlists it verbatim without needing a line-number
        // pin. Empty for the enrolled `CALLERS` above — the stderr
        // sibling lives in `commands/rust_service.rs`, which is NOT
        // enrolled below precisely because its one `"⚠️".yellow()`
        // occurrence is that allowlisted stderr stanza, not a
        // lift-eligible stdout site.
        const ALLOWLIST_SUBSTRINGS: &[&str] = &[];
        for (source, module_path) in CALLERS {
            let body = crate::test_support::module_body_before_first_cfg_test(source, module_path);
            for (i, line) in body.lines().enumerate() {
                if !line.contains("\"⚠\u{fe0f}\".yellow()") {
                    continue;
                }
                if ALLOWLIST_SUBSTRINGS.iter().any(|s| line.contains(s)) {
                    continue;
                }
                panic!(
                    "{module_path}:{lineno} spells the pre-lift inline \
                     `\"⚠️\".yellow()` step-warn marker — that shape \
                     was lifted onto `crate::ui::print_step_warn`. \
                     A re-inline would silently reopen the 5-site \
                     duplication class this shield exists to close. \
                     Offending line: {line:?}",
                    lineno = i + 1
                );
            }
            assert!(
                body.contains("crate::ui::print_step_warn("),
                "{module_path} body must forward to \
                 `crate::ui::print_step_warn(\"<MSG>\")` — the \
                 primitive body every three-space-indented `⚠️.yellow()` \
                 in-body step-warn in the crate now delegates \
                 through."
            );
        }
    }

    /// Fail-before-pass envelope for [`super::write_nonfatal_warn`].
    /// Pins the one-line body every pre-lift consumer spelled verbatim
    /// (`eprintln!("   {} <label> failed (non-fatal): {}",
    /// "WARN".yellow(), <opt-args>, e)`): a three-space indent, a
    /// `.yellow()`-colored `WARN` ASCII text prefix (NOT the `⚠️` emoji
    /// glyph the [`super::print_step_warn`] sibling wears), a single
    /// space, the verb-phrase label interpolated verbatim, the literal
    /// ` failed (non-fatal): ` connective, and the
    /// [`std::fmt::Display`]-formatted error tail. A silent contract
    /// drift a future rewrite might introduce — dropping the
    /// three-space indent (a "tighter body spacing" cleanup),
    /// promoting the whole line's coloring (`format!("   WARN {}
    /// failed (non-fatal): {}", label, err).yellow()`) so the label
    /// and error text paint yellow at every site, swapping the `WARN`
    /// text for the `⚠️` emoji glyph under a "match the step-warn
    /// visual grammar" cleanup (which would collapse the
    /// human-readable + log-scanner-`\bWARN\b`-friendly split the
    /// pre-lift consumers deliberately preserved), promoting
    /// `.yellow()` to `.bright_yellow()` (`\x1b[93m` — the milestone
    /// [`super::print_warning`] palette), reflowing the connective to
    /// omit the space after `(non-fatal):`, slipping a trailing blank
    /// line into the primitive body — flips this assertion rather
    /// than compiling and silently diverging the 5 consumer sites'
    /// visual grammar.
    #[test]
    fn write_nonfatal_warn_emits_exactly_one_warn_prefixed_indented_line_with_error_tail() {
        // Force ANSI emission (colored auto-drops sequences on a
        // non-tty stderr) and serialize against peer banner tests via
        // [`AnsiOverrideForTest`]; its Drop restores colored's
        // auto-detection on scope exit AFTER releasing the shared
        // [`ANSI_OVERRIDE_LOCK`], closing the set-write-unset window
        // without a manual [`colored::control::unset_override`] call
        // that a future test author could omit.
        let _override_guard = AnsiOverrideForTest::acquire();

        let mut buf: Vec<u8> = Vec::new();
        // Use a plain `&str` as the `&dyn Display` — `anyhow::Error`,
        // `std::io::Error`, and every other `Display` type reach the
        // writer through the same trait object at the pre-lift call
        // sites, so a `&str` witness pins the byte contract without
        // dragging an error-building preamble into the test body.
        super::write_nonfatal_warn(&mut buf, "Source attestation", &"connection refused")
            .expect("write_nonfatal_warn against a Vec<u8> writer must succeed");

        let out = String::from_utf8(buf)
            .expect("write_nonfatal_warn must emit valid UTF-8 (the pre-lift eprintln!s did)");

        // Exactly one line — the pre-lift stanza is one `eprintln!`,
        // not two, and carries no framing blank. A refactor that slips
        // a leading or trailing blank into the primitive body fails
        // here.
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(
            lines.len(),
            1,
            "write_nonfatal_warn must emit exactly one line — the \
             pre-lift stanza is one `eprintln!` carrying no framing \
             blank; got {}:\n{}",
            lines.len(),
            out
        );

        // The three-space indent reaches the rendered line before any
        // ANSI escape — a fusion that hoisted the indent inside the
        // coloring span (`"   WARN".yellow()`) or dropped it altogether
        // fails here.
        assert!(
            lines[0].starts_with("   "),
            "line 0 must begin with a three-space indent — every \
             pre-lift consumer spelled `\"   {{}} <label> failed \
             (non-fatal): {{}}\"` verbatim, so the indent must reach \
             the writer OUTSIDE the coloring span; got {:?}",
            lines[0]
        );

        // The `WARN` ASCII text reaches the rendered line — a fusion
        // that swapped `WARN` for the `⚠️` emoji glyph under a "match
        // the step-warn visual grammar" cleanup fails here. The
        // pre-lift consumers deliberately used the ASCII word so
        // log-scanners can pattern-match on `\bWARN\b` and terminals
        // without emoji-glyph support render legibly.
        assert!(
            lines[0].contains("WARN"),
            "line 0 must contain the `WARN` ASCII text prefix — every \
             pre-lift consumer spelled `\"WARN\".yellow()` on the \
             marker (NOT the `⚠️` emoji glyph the `print_step_warn` \
             sibling wears); got {:?}",
            lines[0]
        );
        assert!(
            !lines[0].contains('⚠'),
            "line 0 must NOT contain the `⚠️` emoji glyph — that glyph \
             belongs to the sibling `print_step_warn` primitive (stdout \
             + `⚠️.yellow()` glyph, in-body step-warn grammar); this \
             primitive deliberately wears the `WARN` ASCII text prefix \
             so a log-scanner can pattern-match on `\\bWARN\\b` and \
             terminals without emoji-glyph support render legibly; \
             got {:?}",
            lines[0]
        );

        // The verb-phrase label reaches the rendered line verbatim —
        // a fusion that hoists the label off the parameter and pins
        // it to a constant fails here.
        assert!(
            lines[0].contains("Source attestation"),
            "line 0 must carry the label verbatim; got {:?}",
            lines[0]
        );

        // The literal ` failed (non-fatal): ` connective reaches the
        // rendered line — a fusion that reflowed it to `" — non-fatal: "`,
        // dropped the parenthetical, or capitalized `non-fatal` fails
        // here. Every pre-lift consumer spelled it verbatim.
        assert!(
            lines[0].contains(" failed (non-fatal): "),
            "line 0 must carry the literal ` failed (non-fatal): ` \
             connective — every pre-lift consumer spelled it verbatim \
             between the label and the error tail; got {:?}",
            lines[0]
        );

        // The `Display`-formatted error tail reaches the rendered line.
        assert!(
            lines[0].contains("connection refused"),
            "line 0 must carry the `Display`-formatted error tail \
             verbatim; got {:?}",
            lines[0]
        );

        // The `yellow` ANSI sequence (`\x1b[33m`) reaches the rendered
        // line; a fusion that dropped `.yellow()` (a "just print the
        // string, it's shorter" cleanup) or promoted the palette to
        // `.bright_yellow()` (`\x1b[93m` — the milestone
        // [`super::print_warning`] palette) fails here. A promotion
        // collapses the visual distinction between the non-fatal warn
        // and the milestone warning grammars this primitive exists to
        // preserve.
        assert!(
            lines[0].contains("\x1b[33m"),
            "line 0 must carry the `yellow` ANSI sequence (`\\x1b[33m`) \
             — every pre-lift consumer spelled `.yellow()` (never \
             `.bright_yellow()` or `.yellow().bold()`) on the `WARN` \
             text; got {:?}",
            lines[0]
        );
        assert!(
            !lines[0].contains("\x1b[93m"),
            "line 0 must NOT carry the `bright_yellow` ANSI sequence \
             (`\\x1b[93m`) — that palette belongs to the heavier \
             milestone-level `print_warning`, not this in-pipeline \
             non-fatal-warn primitive; got {:?}",
            lines[0]
        );

        // The `.yellow()` coloring wraps the `WARN` PREFIX alone,
        // never the label or the error tail — a fusion that hoisted
        // the color onto the composed line (`format!("   WARN {}
        // failed (non-fatal): {}", label, err).yellow()`) would paint
        // the label and error yellow at every site. Pin that the
        // label text is NOT inside the yellow span: the yellow span
        // must close (`\x1b[0m`) BEFORE the space that precedes the
        // label.
        let warn_pos = lines[0].find("WARN").expect("WARN prefix must be present");
        let reset_pos = lines[0]
            .find("\x1b[0m")
            .expect("reset must be present after the WARN prefix");
        let label_pos = lines[0]
            .find("Source attestation")
            .expect("label must be present");
        assert!(
            warn_pos < reset_pos && reset_pos < label_pos,
            "the `\\x1b[0m` reset must close the yellow span BEFORE the \
             label begins — every pre-lift consumer spelled `.yellow()` \
             on the `WARN` text alone, never on the label or the error \
             tail. Got positions warn={warn_pos}, reset={reset_pos}, \
             label={label_pos} in line {:?}",
            lines[0]
        );

        // The trailing `\n` reaches the writer — pre-lift stanza used
        // `eprintln!` (not `eprint!`), so the newline is part of the
        // contract. A fusion that swapped `writeln!` for `write!`
        // fails here.
        assert!(
            out.ends_with('\n'),
            "write_nonfatal_warn must emit a trailing `\\n` (the \
             pre-lift `eprintln!` did); got {:?}",
            out
        );
    }

    /// Post-lift the callers migrated onto
    /// [`super::print_nonfatal_warn`] no longer spell the
    /// `eprintln!("   {} <label> failed (non-fatal): {}",
    /// "WARN".yellow(), <opt-args>, e)` shape inline. Structural
    /// regression shield — without it, a future refactor could
    /// silently re-inline the stanza (a "just call `eprintln!`
    /// directly, it's shorter" cleanup) and reopen the 5-site
    /// duplication class this lift closed. Enforced at the module
    /// body before its `#[cfg(test)]` region so a test-support mention
    /// of the raw shape does not defeat the shield.
    ///
    /// The exact-shape needle is `"WARN".yellow()` appearing anywhere
    /// in the module body. `commands/product_release.rs` is the only
    /// module in the crate whose pre-lift body carried this shape
    /// (source-wide grep before the lift returned 5 hits, all in
    /// `product_release.rs`); if a future adjustment routes a
    /// non-fatal release-pipeline warning through a NEW module, that
    /// module belongs on this shield.
    #[test]
    fn print_nonfatal_warn_callers_delegate_through_primitive() {
        const CALLERS: &[(&str, &str)] = &[(
            include_str!("commands/product_release.rs"),
            "commands/product_release.rs",
        )];
        // No known non-`print_nonfatal_warn` sites carry
        // `"WARN".yellow()` under a different grammar: the source-wide
        // grep before the lift returned 5 hits and every one migrated
        // onto the primitive. Kept as an allowlist for
        // future-proofing — a peer stderr-routed `"WARN".yellow()`
        // sibling on a distinct grammar (e.g. a `WARN` prefix with a
        // suggestion tail instead of `failed (non-fatal): ` connective)
        // would land here, be flagged by the shield, and either enroll
        // in a new peer primitive or add an anchoring substring to
        // this list.
        const ALLOWLIST_SUBSTRINGS: &[&str] = &[];
        for (source, module_path) in CALLERS {
            let body = crate::test_support::module_body_before_first_cfg_test(source, module_path);
            for (i, line) in body.lines().enumerate() {
                if !line.contains("\"WARN\".yellow()") {
                    continue;
                }
                if ALLOWLIST_SUBSTRINGS.iter().any(|s| line.contains(s)) {
                    continue;
                }
                panic!(
                    "{module_path}:{lineno} spells the pre-lift inline \
                     `\"WARN\".yellow()` non-fatal-warn marker — that \
                     shape was lifted onto \
                     `crate::ui::print_nonfatal_warn`. A re-inline \
                     would silently reopen the 5-site duplication \
                     class this shield exists to close. Offending \
                     line: {line:?}",
                    lineno = i + 1
                );
            }
            assert!(
                body.contains("crate::ui::print_nonfatal_warn("),
                "{module_path} body must forward to \
                 `crate::ui::print_nonfatal_warn(<label>, &<err>)` — \
                 the primitive body every three-space-indented \
                 `\"WARN\".yellow()` non-fatal-failure in the crate \
                 now delegates through."
            );
        }
    }

    /// Fail-before-pass envelope for [`super::write_step_skip`]. Pins
    /// the one-line body every pre-lift consumer spelled verbatim
    /// (`println!("   {} <fmt>", "○".yellow(), <args>)`): a
    /// three-space indent, a `.yellow()`-colored `○` hollow-circle
    /// glyph, a single space, then the plain (uncolored) message. A
    /// silent contract drift a future rewrite might introduce —
    /// dropping the three-space indent, promoting the whole line's
    /// coloring (`format!("   ○ {}", msg).yellow()`) so the message
    /// text paints yellow at every site, swapping `○` for `-` under a
    /// CI-log-friendly grammar, dimming the palette to `\x1b[90m`
    /// under a "skips are quieter than warns" cleanup, slipping a
    /// trailing blank line into the primitive body — flips this
    /// assertion rather than compiling and silently diverging the 5
    /// consumer sites' visual grammar.
    #[test]
    fn write_step_skip_emits_exactly_one_skip_prefixed_indented_line() {
        // Force ANSI emission and serialize against peer banner tests
        // via [`AnsiOverrideForTest`]; its Drop restores colored's
        // auto-detection on scope exit AFTER releasing the shared
        // [`ANSI_OVERRIDE_LOCK`].
        let _override_guard = AnsiOverrideForTest::acquire();

        let mut buf: Vec<u8> = Vec::new();
        super::write_step_skip(&mut buf, "Skipped via --skip-entities")
            .expect("write_step_skip against a Vec<u8> writer must succeed");

        let out = String::from_utf8(buf)
            .expect("write_step_skip must emit valid UTF-8 (the pre-lift println!s did)");

        // Exactly one line — the pre-lift stanza is one `println!`,
        // not two, and carries no framing blank.
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(
            lines.len(),
            1,
            "write_step_skip must emit exactly one line — the \
             pre-lift stanza is one `println!` carrying no framing \
             blank; got {}:\n{}",
            lines.len(),
            out
        );

        // The three-space indent reaches the rendered line before any
        // ANSI escape.
        assert!(
            lines[0].starts_with("   "),
            "line 0 must begin with a three-space indent — every \
             pre-lift consumer spelled `\"   {{}} <fmt>\"` verbatim, \
             so the indent must reach the writer OUTSIDE the coloring \
             span; got {:?}",
            lines[0]
        );

        // The `○` glyph reaches the rendered line — a fusion that
        // swapped `○` for `-` under a "CI-log-friendly" cleanup or
        // dropped the glyph altogether fails here.
        assert!(
            lines[0].contains('○'),
            "line 0 must contain the `○` hollow-circle glyph — every \
             pre-lift consumer spelled `\"○\".yellow()` on the marker; \
             got {:?}",
            lines[0]
        );

        // The message text reaches the rendered line verbatim.
        assert!(
            lines[0].contains("Skipped via --skip-entities"),
            "line 0 must carry the message verbatim; got {:?}",
            lines[0]
        );

        // The `yellow` ANSI sequence (`\x1b[33m`) reaches the rendered
        // line; a fusion that dropped `.yellow()` (a "just print the
        // string, it's shorter" cleanup) or dimmed the palette to
        // `\x1b[90m` (a "skips are quieter than warns" cleanup) fails
        // here.
        assert!(
            lines[0].contains("\x1b[33m"),
            "line 0 must carry the `yellow` ANSI sequence (`\\x1b[33m`) \
             — every pre-lift consumer spelled `.yellow()` (never \
             `.dimmed()` or `.bright_yellow()`) on the glyph; got {:?}",
            lines[0]
        );
        assert!(
            !lines[0].contains("\x1b[93m"),
            "line 0 must NOT carry the `bright_yellow` ANSI sequence \
             (`\\x1b[93m`) — that palette belongs to milestone-level \
             warnings, not this in-body skip primitive; got {:?}",
            lines[0]
        );
        assert!(
            !lines[0].contains("\x1b[90m"),
            "line 0 must NOT carry the `bright_black` / dim ANSI \
             sequence (`\\x1b[90m`) — every pre-lift consumer used \
             plain `.yellow()`, and a promotion to dimmed would \
             collapse the skip vs the sibling `\"○\".dimmed()` shade \
             (`commands/rust_service.rs:1150` — a distinct \"inactive \
             environment listing\" grammar this primitive does NOT \
             enroll); got {:?}",
            lines[0]
        );

        // The `.yellow()` coloring wraps the GLYPH alone, never the
        // message text.
        let glyph_pos = lines[0].find('○').expect("glyph must be present");
        let reset_pos = lines[0]
            .find("\x1b[0m")
            .expect("reset must be present after the glyph");
        let msg_pos = lines[0]
            .find("Skipped via --skip-entities")
            .expect("message must be present");
        assert!(
            glyph_pos < reset_pos && reset_pos < msg_pos,
            "the `\\x1b[0m` reset must close the yellow span BEFORE the \
             message begins — every pre-lift consumer spelled `.yellow()` \
             on the `○` glyph alone, never on the message. Got \
             positions glyph={glyph_pos}, reset={reset_pos}, msg={msg_pos} \
             in line {:?}",
            lines[0]
        );

        // The trailing `\n` reaches the writer — pre-lift stanza used
        // `println!` (not `print!`), so the newline is part of the
        // contract.
        assert!(
            out.ends_with('\n'),
            "write_step_skip must emit a trailing `\\n` (the \
             pre-lift `println!` did); got {:?}",
            out
        );
    }

    /// Post-lift the callers migrated onto [`super::print_step_skip`]
    /// no longer spell the `println!("   {} <fmt>", "○".yellow(),
    /// <args>)` shape inline. Structural regression shield — without
    /// it, a future refactor could silently re-inline the one-liner
    /// and reopen the 5-site duplication class this lift closed.
    /// Enforced at the module bodies before their `#[cfg(test)]`
    /// regions so a test-support mention of the raw shape does not
    /// defeat the shield.
    ///
    /// The exact-shape needle is `"○".yellow()` appearing anywhere in
    /// the module body. `commands/rust_service.rs:1150` is a nearby
    /// non-step-skip sibling site (`"○".dimmed()` — a
    /// dimmed-inactive-environment listing under a distinct visual
    /// grammar, NOT `.yellow()`); the pattern needle would not match
    /// it in any case, and `rust_service.rs` is deliberately NOT
    /// enrolled below because it carries no `"○".yellow()` stanza to
    /// migrate.
    #[test]
    fn print_step_skip_callers_delegate_through_primitive() {
        const CALLERS: &[(&str, &str)] = &[
            (
                include_str!("commands/prerelease.rs"),
                "commands/prerelease.rs",
            ),
            (
                include_str!("commands/rebac_validation.rs"),
                "commands/rebac_validation.rs",
            ),
            (include_str!("commands/sync.rs"), "commands/sync.rs"),
        ];
        // No known non-step-skip `"○".yellow()` sites: the one
        // dimmed-`○` sibling in `commands/rust_service.rs:1150`
        // spells `.dimmed()`, not `.yellow()`, so the needle does not
        // match it and no allowlist is required.
        const ALLOWLIST_SUBSTRINGS: &[&str] = &[];
        for (source, module_path) in CALLERS {
            let body = crate::test_support::module_body_before_first_cfg_test(source, module_path);
            for (i, line) in body.lines().enumerate() {
                if !line.contains("\"○\".yellow()") {
                    continue;
                }
                if ALLOWLIST_SUBSTRINGS.iter().any(|s| line.contains(s)) {
                    continue;
                }
                panic!(
                    "{module_path}:{lineno} spells the pre-lift inline \
                     `\"○\".yellow()` step-skip marker — that shape \
                     was lifted onto `crate::ui::print_step_skip`. \
                     A re-inline would silently reopen the 5-site \
                     duplication class this shield exists to close. \
                     Offending line: {line:?}",
                    lineno = i + 1
                );
            }
            assert!(
                body.contains("crate::ui::print_step_skip("),
                "{module_path} body must forward to \
                 `crate::ui::print_step_skip(\"<MSG>\")` — the \
                 primitive body every three-space-indented `○.yellow()` \
                 in-body step-skip in the crate now delegates \
                 through."
            );
        }
    }

    /// Fail-before-pass envelope for [`super::write_step_info`]. Pins
    /// the one-line body every pre-lift consumer spelled verbatim
    /// (`println!("ℹ️  <fmt>", <args>)`): the `ℹ️` info glyph, a two-
    /// space gap (a legibility hedge — the emoji renders with variable
    /// width across terminals, every pre-lift consumer carried the
    /// second space), then the plain (uncolored) message. A silent
    /// contract drift a future rewrite might introduce — collapsing
    /// the two-space gap to one, prepending an indent (a "let's align
    /// with `print_step_pass`'s three-space in-body indent" cleanup —
    /// distinct grammar; three sites in `commands/migrations.rs`
    /// carry the indented variant under a different visual layer),
    /// promoting to `.bright_cyan()` (`\x1b[96m` — the milestone-level
    /// [`super::print_info`] palette that this uncolored primitive
    /// deliberately does NOT wear), swapping `ℹ️  ` for `[i] ` under a
    /// CI-log-friendly grammar, slipping a trailing blank line into
    /// the primitive body — flips this assertion rather than compiling
    /// and silently diverging the 15 consumer sites' visual grammar.
    #[test]
    fn write_step_info_emits_exactly_one_info_prefixed_uncolored_line() {
        // No `AnsiOverrideForTest` needed — every pre-lift consumer
        // spelled the whole line plain (no `.color()` chain anywhere),
        // so this primitive's contract is the ABSENCE of ANSI
        // sequences. Forcing `colored`'s override on would defeat that
        // check by falsely-coloring nothing, so run against a bare
        // `Vec<u8>` writer.
        let mut buf: Vec<u8> = Vec::new();
        super::write_step_info(&mut buf, "Image pushed to registry.example.com:abc123")
            .expect("write_step_info against a Vec<u8> writer must succeed");

        let out = String::from_utf8(buf)
            .expect("write_step_info must emit valid UTF-8 (the pre-lift println!s did)");

        // Exactly one line — the pre-lift stanza is one `println!`,
        // not two, and carries no framing blank. A refactor that slips
        // a leading or trailing blank into the primitive body fails
        // here.
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(
            lines.len(),
            1,
            "write_step_info must emit exactly one line — the \
             pre-lift stanza is one `println!` carrying no framing \
             blank; got {}:\n{}",
            lines.len(),
            out
        );

        // The `ℹ️` glyph reaches the rendered line at the very start
        // — a fusion that prepended a three-space indent (a "let's
        // align with `print_step_pass`'s in-body indent" cleanup) or
        // dropped the glyph altogether fails here.
        assert!(
            lines[0].starts_with('ℹ'),
            "line 0 must begin with the `ℹ️` info glyph — every \
             pre-lift consumer spelled `\"ℹ️  <fmt>\"` verbatim with \
             NO leading indent (the indented `\"   ℹ️  \"` variant in \
             `commands/migrations.rs` is a distinct grammar); got {:?}",
            lines[0]
        );

        // The two-space gap between the glyph and the message reaches
        // the rendered line — every pre-lift consumer carried a
        // DOUBLE space after `ℹ️` (a legibility hedge against the
        // emoji's variable rendered width). A fusion that collapses
        // it to a single space fails here.
        assert!(
            lines[0].contains("ℹ\u{fe0f}  "),
            "line 0 must contain the `ℹ️` glyph followed by TWO \
             spaces — every pre-lift consumer spelled `\"ℹ️  \"` \
             (double space) verbatim as a legibility hedge against \
             the emoji's variable rendered width; got {:?}",
            lines[0]
        );

        // The message text reaches the rendered line verbatim; a
        // fusion that hoists the message off the parameter and pins
        // it to a constant fails here.
        assert!(
            lines[0].contains("Image pushed to registry.example.com:abc123"),
            "line 0 must carry the message verbatim; got {:?}",
            lines[0]
        );

        // NO ANSI escape sequence reaches the rendered line — every
        // pre-lift consumer spelled the whole line plain (no
        // `.color()` chain on the glyph, no `format!(...).color()`
        // wrap on the composed line). A fusion that promoted the line
        // to `.bright_cyan()` (`\x1b[96m` — the milestone-level
        // [`super::print_info`] palette) or added any color at all
        // fails here. This absence-of-color contract is the exact
        // shape that distinguishes this primitive from
        // [`super::print_info`].
        assert!(
            !out.contains('\x1b'),
            "write_step_info must emit ZERO ANSI escape sequences — \
             every pre-lift consumer spelled the whole line plain \
             (no `.color()` chain anywhere). A promotion to \
             `.bright_cyan()` (`\\x1b[96m` — the milestone-level \
             `print_info` palette) collapses the distinction between \
             this uncolored in-body primitive and the heavier \
             milestone-level info sigil. Got: {:?}",
            out
        );

        // The trailing `\n` reaches the writer — pre-lift stanza used
        // `println!` (not `print!`), so the newline is part of the
        // contract. A fusion that swapped `writeln!` for `write!`
        // fails here.
        assert!(
            out.ends_with('\n'),
            "write_step_info must emit a trailing `\\n` (the \
             pre-lift `println!` did); got {:?}",
            out
        );
    }

    /// Post-lift the callers migrated onto [`super::print_step_info`]
    /// no longer spell the `println!("ℹ️  <fmt>", <args>)` shape
    /// inline. Structural regression shield — without it, a future
    /// refactor could silently re-inline the one-liner (e.g. a "just
    /// call `println!` directly, it's shorter" cleanup) and reopen the
    /// 15-site duplication class this lift closed. Enforced at the
    /// module bodies before their `#[cfg(test)]` regions so a
    /// test-support mention of the raw shape does not defeat the
    /// shield.
    ///
    /// The exact-shape needle is `"ℹ️  ` (opening quote immediately
    /// followed by the info glyph and a DOUBLE space) appearing
    /// anywhere in the module body. The three
    /// `commands/migrations.rs` 3-space-indented siblings
    /// (`println!("   ℹ️  ...")`) start with `"   ℹ️` — quote-then-
    /// spaces — so the needle does not match them; they carry a
    /// distinct deeper-nested grammar and are NOT enrolled in this
    /// class. The `commands/status.rs:1592` `"ℹ️ ".bright_blue()`
    /// site spells a SINGLE space after the glyph and paints the whole
    /// span blue under a Kubernetes-event-type sigil grammar — a
    /// different visual layer entirely, and the double-space needle
    /// does not match its single-space form.
    #[test]
    fn print_step_info_callers_delegate_through_primitive() {
        const CALLERS: &[(&str, &str)] = &[
            (
                include_str!("commands/federation.rs"),
                "commands/federation.rs",
            ),
            (
                include_str!("commands/rust_service.rs"),
                "commands/rust_service.rs",
            ),
            (
                include_str!("commands/migrations.rs"),
                "commands/migrations.rs",
            ),
            (
                include_str!("commands/schema_validation.rs"),
                "commands/schema_validation.rs",
            ),
            (
                include_str!("commands/developer_tools.rs"),
                "commands/developer_tools.rs",
            ),
            (
                include_str!("commands/search_sync.rs"),
                "commands/search_sync.rs",
            ),
        ];
        // No known non-step-info `"ℹ️  ` (double-space) sites: the
        // 3-space-indented sibling in `commands/migrations.rs` (three
        // occurrences) starts with `"   ℹ️  ` — quote-then-spaces —
        // so the needle does not match, and `commands/status.rs`'s
        // `"ℹ️ ".bright_blue()` spells a SINGLE space so the
        // double-space needle does not match it either.
        const ALLOWLIST_SUBSTRINGS: &[&str] = &[];
        for (source, module_path) in CALLERS {
            let body = crate::test_support::module_body_before_first_cfg_test(source, module_path);
            for (i, line) in body.lines().enumerate() {
                if !line.contains("\"ℹ\u{fe0f}  ") {
                    continue;
                }
                if ALLOWLIST_SUBSTRINGS.iter().any(|s| line.contains(s)) {
                    continue;
                }
                panic!(
                    "{module_path}:{lineno} spells the pre-lift inline \
                     `\"ℹ️  <fmt>\"` step-info marker — that shape \
                     was lifted onto `crate::ui::print_step_info`. \
                     A re-inline would silently reopen the 15-site \
                     duplication class this shield exists to close. \
                     Offending line: {line:?}",
                    lineno = i + 1
                );
            }
            assert!(
                body.contains("crate::ui::print_step_info("),
                "{module_path} body must forward to \
                 `crate::ui::print_step_info(\"<MSG>\")` — the \
                 primitive body every uncolored `ℹ️  ` in-body \
                 step-info in the crate now delegates through."
            );
        }
    }

    /// Pins the exact bytes [`super::write_ascii_title_underline`]
    /// emits — a `"=".repeat(width)` rule line, then a blank line —
    /// the shape the 14 pre-lift consumer sites carried across five
    /// command modules. Fails BEFORE the lift so the sibling class
    /// closure is verifiable; guards against future palette drift
    /// (rule character, trailing blank, coloring).
    #[test]
    fn write_ascii_title_underline_emits_rule_line_then_blank_line() {
        // No `colored::control::set_override` shim needed — every
        // pre-lift stanza spelled the rule as a plain `"=".repeat(...)`
        // WITHOUT chaining a `.color()` / `.bold()` styling. Emit against
        // a `Vec<u8>` writer and assert on bytes verbatim.
        let mut buf: Vec<u8> = Vec::new();
        super::write_ascii_title_underline(&mut buf, 50)
            .expect("write_ascii_title_underline against a Vec<u8> writer must succeed");
        let out = String::from_utf8(buf).expect(
            "write_ascii_title_underline must emit valid UTF-8 (the pre-lift println!s did)",
        );

        // Exactly two lines — the pre-lift stanza was two `println!`
        // calls (the rule + one framing blank). A refactor that drops
        // the trailing blank (a "tighter body spacing" cleanup) or
        // that promotes it to two blanks fails here.
        let lines: Vec<&str> = out.split_inclusive('\n').collect();
        assert_eq!(
            lines.len(),
            2,
            "write_ascii_title_underline must emit exactly two lines — \
             the pre-lift stanza carried the `=`-rule followed by ONE \
             framing blank via a second `println!()`; got {}:\n{:?}",
            lines.len(),
            out
        );

        // Line 0 is the `=`-rule of exactly `width` `=` bytes plus a
        // trailing `\n`. A refactor that swaps `=` for `-` or `─` (a
        // heavier / lighter rule promotion) fails the byte-content
        // check; one that drifts the width fails the length check.
        assert_eq!(
            lines[0], "==================================================\n",
            "line 0 must be exactly `50` `=` bytes + `\\n` — every \
             pre-lift consumer spelled the rule as a plain \
             `\"=\".repeat(width)` ASCII bar with no chained styling \
             and no width drift; got {:?}",
            lines[0]
        );

        // Line 1 is the trailing blank — exactly `\n`. A refactor
        // that promotes it to a blank-with-content (e.g. spaces) or
        // drops it entirely fails here.
        assert_eq!(
            lines[1], "\n",
            "line 1 must be exactly `\\n` — the pre-lift trailing \
             `println!()` emits an empty line, and any content there \
             (a stray space, a promoted styled rule) is a visual \
             regression; got {:?}",
            lines[1]
        );

        // No ANSI coloring anywhere — every pre-lift consumer emitted
        // the rule as plain ASCII. A refactor that promotes the rule
        // to `.dimmed()` / `.bright_blue()` (borrowing the palette
        // from `print_section_header`'s bold-`═`-rule triple) fails
        // here.
        assert!(
            !out.contains('\x1b'),
            "write_ascii_title_underline must emit no ANSI escape \
             sequences — every pre-lift consumer spelled a plain \
             `\"=\".repeat(width)` ASCII bar with no chained \
             `.color()` / `.bold()`; got {:?}",
            out
        );
    }

    /// Post-lift the callers migrated onto
    /// [`super::print_ascii_title_underline`] no longer spell the
    /// `println!("{}", "=".repeat(<width>));` shape inline. Structural
    /// regression shield — without it, a future refactor could
    /// silently re-inline the two-liner (e.g. a "just call `println!`
    /// directly, it's shorter" cleanup) and reopen the 14-site
    /// duplication class this lift closed. Enforced at the module
    /// bodies before their `#[cfg(test)]` regions so a test-support
    /// mention of the raw shape does not defeat the shield. The
    /// exact-shape needle `println!("{}", "=".repeat(` uniquely
    /// identifies the pre-lift restatement — the `═`-heavy-rule
    /// consumers of `print_section_header` use a Unicode
    /// `SECTION_HEADER_RULE` constant (`═` bytes, never
    /// `"=".repeat(...)`), and the `=`-rule sites in
    /// `print_release_stage_banner` live inside `ui.rs` (outside
    /// this shield's `commands/*.rs` scope).
    #[test]
    fn print_ascii_title_underline_callers_delegate_through_primitive() {
        const CALLERS: &[(&str, &str)] = &[
            (
                include_str!("commands/rust_service.rs"),
                "commands/rust_service.rs",
            ),
            (
                include_str!("commands/developer_tools.rs"),
                "commands/developer_tools.rs",
            ),
            (
                include_str!("commands/web_service.rs"),
                "commands/web_service.rs",
            ),
            (include_str!("commands/rollback.rs"), "commands/rollback.rs"),
            (
                include_str!("commands/product_release.rs"),
                "commands/product_release.rs",
            ),
        ];
        for (source, module_path) in CALLERS {
            let body = crate::test_support::module_body_before_first_cfg_test(source, module_path);
            for (i, line) in body.lines().enumerate() {
                assert!(
                    !line.contains("println!(\"{}\", \"=\".repeat("),
                    "{module_path}:{lineno} spells the pre-lift inline \
                     `println!(\"{{}}\", \"=\".repeat(<width>));` \
                     ASCII title-underline rule — that two-liner was \
                     lifted onto `crate::ui::print_ascii_title_underline`. \
                     A re-inline would silently reopen the 14-site \
                     duplication class this shield exists to close. \
                     Offending line: {line:?}",
                    lineno = i + 1
                );
            }
            assert!(
                body.contains("crate::ui::print_ascii_title_underline("),
                "{module_path} body must forward to \
                 `crate::ui::print_ascii_title_underline(<width>)` — \
                 the primitive body every two-line `=`-rule + blank \
                 command-intro underline in the crate now delegates \
                 through."
            );
        }
    }

    /// Caller-migration shield for [`super::print_ascii_bar_banner`].
    /// Asserts (1) no
    /// `println!("==========================================")`
    /// re-inline of the pre-lift 42-glyph ASCII `=` rule remains
    /// anywhere in `commands/helm.rs`, and (2) the module forwards
    /// through `crate::ui::print_ascii_bar_banner(...)` at exactly
    /// three sites — one per pre-lift consumer. A re-inline (e.g. a
    /// "just print the equals bar inline, it's obvious" cleanup)
    /// would silently reopen the 3-site duplication class this lift
    /// closed and drift the helm-pipeline's per-chart-action visual
    /// grammar; this shield flips before compile.
    ///
    /// The shield does NOT bound its scan through
    /// [`crate::test_support::module_body_before_first_cfg_test`]
    /// because `commands/helm.rs`'s test blocks are interleaved
    /// with production functions (the first `#[cfg(test)]` marker
    /// sits well above the three call sites this shield covers).
    /// The negative needle is the exact 42-`=` full println!
    /// spelling, which the module's tests never construct, so a
    /// source-wide `.matches(...).count()` suffices to catch a
    /// re-inline without false-positives.
    ///
    /// The needle uses the exact 42-glyph rule the pre-lift stanza
    /// carried — a fusion that lands on a different width (e.g. 40
    /// or 50) would still flip the paired
    /// `write_ascii_bar_banner_emits_three_bar_title_bar_ascii_only_lines_in_order`
    /// envelope because the writer pins the width via
    /// [`super::ASCII_BAR_BANNER_WIDTH`]. The envelope pins the
    /// width; this shield pins the caller set.
    #[test]
    fn print_ascii_bar_banner_callers_delegate_through_primitive() {
        const HELM_SRC: &str = include_str!("commands/helm.rs");
        // Negative assertion — no pre-lift inline rule remains
        // anywhere in the module. The literal is a full println!
        // spelling, so tests (which never construct this raw
        // 42-`=` string) cannot false-positive it.
        let inline_hits = HELM_SRC
            .matches("println!(\"==========================================\")")
            .count();
        assert_eq!(
            inline_hits, 0,
            "commands/helm.rs must NOT spell the pre-lift inline \
             `println!(\"==========================================\
             \");` 42-glyph ASCII `=` rule — that four-line stanza \
             (leading blank + rule + `  <title>` + rule) was lifted \
             onto `crate::ui::print_ascii_bar_banner`. A re-inline \
             would silently reopen the 3-site duplication class \
             this shield exists to close. Found {inline_hits} \
             inline occurrences."
        );
        // Positive assertion — the module forwards through the
        // primitive at exactly three sites, one per pre-lift
        // consumer (`Releasing {lib_chart_name} {version} (library)`,
        // `Linting {chart_name}`, `Releasing {chart_name}`). A
        // fusion that folds one of the three consumer sites back
        // to inline `println!`s (silently splitting the visual
        // grammar across two chart actions) fails here — the
        // negative half above would still pass, but this positive
        // count would fall to two.
        let forward_hits = HELM_SRC
            .matches("crate::ui::print_ascii_bar_banner(")
            .count();
        assert_eq!(
            forward_hits, 3,
            "commands/helm.rs must forward through \
             `crate::ui::print_ascii_bar_banner(<title>)` at \
             exactly THREE sites — one per pre-lift consumer \
             (the library-releasing site, the per-chart linting \
             site, the per-chart releasing site). A fusion that \
             folds one back to inline `println!`s or that adds a \
             fourth caller without extending this shield's \
             expected count fails here. Found {forward_hits} \
             forwarding hits."
        );
    }

    /// Fail-before-pass envelope for [`AnsiOverrideForTest`]. Pins
    /// the two properties every pre-lift banner test carried
    /// implicitly and would silently regress a future omission of:
    /// (1) [`AnsiOverrideForTest::acquire`] forces [`colored`]'s
    /// global override ON so a subsequent `.green()` render reaches
    /// the buffer as the `\x1b[32m` ANSI sequence rather than being
    /// stripped by [`colored`]'s non-tty auto-detection, and (2)
    /// dropping the guard both releases the shared
    /// [`ANSI_OVERRIDE_LOCK`] and restores [`colored`]'s
    /// auto-detection — verified by re-acquiring the guard from the
    /// same test body (the second `.lock()` would deadlock if Drop
    /// hadn't released the mutex, and the second render reaches the
    /// buffer with the override still forcing colored on).
    #[test]
    fn ansi_override_for_test_forces_colored_on_and_releases_lock_on_drop() {
        // Scope 1 — acquire, render inside the guard's lifetime.
        let first_render = {
            let _guard = AnsiOverrideForTest::acquire();
            format!("{}", "x".green())
        }; // guard drops here — Drop runs unset_override, then MutexGuard releases.

        assert!(
            first_render.contains("\x1b[32m"),
            "AnsiOverrideForTest::acquire() must force colored ON \
             while alive — a `.green()` render inside the guard's \
             lifetime must reach the buffer as `\\x1b[32m` (the \
             pre-lift stanza's `colored::control::set_override(true)` \
             call carried this contract; the guard's `acquire()` \
             carries it now); got {:?}",
            first_render
        );

        // Scope 2 — the second acquire must not deadlock (Drop
        // released the MutexGuard) AND must re-force colored ON
        // (Drop's `unset_override` was cleared by the second
        // `set_override(true)` inside `acquire()`).
        let _second = AnsiOverrideForTest::acquire();
        let second_render = format!("{}", "y".green());
        assert!(
            second_render.contains("\x1b[32m"),
            "AnsiOverrideForTest::acquire() must be re-acquirable \
             after a prior guard drops — the first guard's Drop must \
             release the MutexGuard (else this call deadlocks) AND \
             the second acquire must re-force colored ON so a fresh \
             `.green()` render reaches the buffer as `\\x1b[32m`; \
             got {:?}",
            second_render
        );
    }

    /// Structural regression shield — the 5 pre-lift banner tests
    /// (`write_success_banner_...`, `write_release_stage_banner_...`,
    /// `write_section_header_...`, `write_step_heading_...`,
    /// `write_step_success_...`) each spelled the raw
    /// `let _override_guard = ANSI_OVERRIDE_LOCK.lock()
    /// .unwrap_or_else(|poisoned| poisoned.into_inner());
    /// colored::control::set_override(true);` acquire stanza and its
    /// matched trailing `colored::control::unset_override();` about
    /// 8 lines later. Post-lift both live only inside
    /// [`AnsiOverrideForTest`]'s [`AnsiOverrideForTest::acquire`]
    /// body and its [`Drop`] impl — one occurrence each in the
    /// executable source of `ui.rs`. A future re-inline (e.g. a
    /// "just call `set_override` directly, it's shorter" cleanup)
    /// would push the count above one for either side; this shield
    /// flips before compiling and prevents the 5-site duplication
    /// class this lift closed from reopening. The needle uses the
    /// exact 8-space test-body indent (`"        "`) so the guard's
    /// own 12-space-indented invocations (`AnsiOverrideForTest::
    /// acquire`'s body and the `Drop` impl) do NOT match.
    #[test]
    fn ansi_override_test_helpers_live_only_inside_the_guard_type() {
        const SRC: &str = include_str!("ui.rs");
        // Line-anchored needles — `\n<8 spaces>...<;>\n` matches a
        // full source line whose ONLY indent is 8 spaces (the
        // pre-lift test-body indent). Self-references in this
        // shield's own error messages sit under a 13-space indent +
        // backtick, so `\n<8 spaces>` never lines them up.
        let set_test_body_hits = SRC
            .matches(concat!(
                "\n        colored::control::set_override",
                "(true);\n"
            ))
            .count();
        assert_eq!(
            set_test_body_hits, 0,
            "ui.rs must NOT spell an 8-space-indented \
             set_override(true) as a full line — every pre-lift \
             banner test was migrated onto AnsiOverrideForTest::\
             acquire() which owns the sole (12-space-indented) call. \
             A re-inline reopens the 5-site duplication class. \
             Found {set_test_body_hits} test-body hits."
        );
        let unset_test_body_hits = SRC
            .matches(concat!(
                "\n        colored::control::unset_override",
                "();\n"
            ))
            .count();
        assert_eq!(
            unset_test_body_hits, 0,
            "ui.rs must NOT spell an 8-space-indented \
             unset_override() as a full line — every pre-lift \
             banner test was migrated onto AnsiOverrideForTest \
             whose Drop owns the sole (12-space-indented) call. \
             A re-inline reopens the 5-site duplication class. \
             Found {unset_test_body_hits} test-body hits."
        );
        let lock_test_body_hits = SRC
            .matches("\n        let _override_guard = ANSI_OVERRIDE_LOCK\n")
            .count();
        assert_eq!(
            lock_test_body_hits, 0,
            "ui.rs must NOT spell the pre-lift 8-space-indented \
             ANSI_OVERRIDE_LOCK acquire prologue as a full line — \
             every pre-lift banner test was migrated onto \
             AnsiOverrideForTest::acquire() which owns the sole \
             lock acquisition. A re-inline reopens the 5-site \
             duplication class. Found {lock_test_body_hits} hits."
        );
        // The guard-owned invocations DO reach the source once
        // each — a rename of the guard type that misses the type
        // definition (leaving the tests referring to a non-existent
        // AnsiOverrideForTest::acquire) fails at compile time; this
        // shield pins the reverse (the guard's own set/unset call
        // sites are unique). 12-space needle matches only within
        // acquire's fn body / Drop's fn body.
        let acquire_body_hits = SRC
            .matches(concat!(
                "\n            colored::control::set_override",
                "(true);\n"
            ))
            .count();
        assert_eq!(
            acquire_body_hits, 1,
            "ui.rs must spell a 12-space-indented set_override(true) \
             call exactly ONCE — inside AnsiOverrideForTest::acquire. \
             Found {acquire_body_hits} guard-body hits."
        );
        let drop_body_hits = SRC
            .matches(concat!(
                "\n            colored::control::unset_override",
                "();\n"
            ))
            .count();
        assert_eq!(
            drop_body_hits, 1,
            "ui.rs must spell a 12-space-indented unset_override() \
             call exactly ONCE — inside AnsiOverrideForTest's Drop. \
             Found {drop_body_hits} guard-body hits."
        );
    }

    /// Fail-before-pass envelope for
    /// [`super::write_report_section_subheader`]. Pins the two-line
    /// body every pre-lift consumer spelled verbatim
    /// (`<title>.<COLOR>().bold()` line, `"─".repeat(80).dimmed()`
    /// rule line) and the exact palette per
    /// [`super::ReportSectionStyle`] variant. A silent contract
    /// drift a future rewrite might introduce — dropping the rule
    /// line (a "the title is loud enough" cleanup), promoting the
    /// dimmed rule to a colored rule that competes with the title
    /// for eye attention, swapping the `─` glyph for `━` or `-` in
    /// one branch alone (silently splitting the visual grammar
    /// across the 5 consumer subheaders), narrowing the rule width
    /// off 80 in one branch alone, hoisting `.bold()` off the title
    /// so it disappears into surrounding body text, or swapping
    /// `.green()` for `.bright_green()` in the [`Success`] arm
    /// alone (losing the visual-contrast contract against the
    /// warning-track subheader) — flips this assertion rather than
    /// compiling and silently diverging the 5 consumer sites'
    /// visual grammar.
    ///
    /// [`Success`]: super::ReportSectionStyle::Success
    #[test]
    fn write_report_section_subheader_emits_bold_colored_title_then_dimmed_light_rule() {
        // Force ANSI emission (colored auto-drops sequences on a
        // non-tty stdout) and serialize against peer banner tests
        // via [`AnsiOverrideForTest`]; its Drop restores colored's
        // auto-detection on scope exit AFTER releasing the shared
        // [`ANSI_OVERRIDE_LOCK`], closing the set-write-unset window
        // without a manual [`colored::control::unset_override`] call
        // that a future test author could omit.
        let _override_guard = AnsiOverrideForTest::acquire();

        // Verify all three enum variants — the palette contract lives
        // in the primitive's `match` arms, so a silent rename of one
        // arm's color chain (`.yellow()` → `.red()` on Warning) would
        // pass the Success and Info assertions and still flip only
        // the Warning branch here.
        //
        // `colored` folds `.color().bold()` into a single composite
        // ANSI escape whose two attributes may appear in either
        // `\x1b[1;<c>m` or `\x1b[<c>;1m` order depending on the
        // attribute-application sequence; accept both spellings.
        for (style, bold_first_seq, color_first_seq, label) in [
            (
                super::ReportSectionStyle::Success,
                "\x1b[1;32m",
                "\x1b[32;1m",
                "green (Success)",
            ),
            (
                super::ReportSectionStyle::Warning,
                "\x1b[1;33m",
                "\x1b[33;1m",
                "yellow (Warning)",
            ),
            (
                super::ReportSectionStyle::Info,
                "\x1b[1;36m",
                "\x1b[36;1m",
                "cyan (Info)",
            ),
        ] {
            let mut buf: Vec<u8> = Vec::new();
            super::write_report_section_subheader(&mut buf, "TEST SUBHEADER", style)
                .expect("write_report_section_subheader against a Vec<u8> writer must succeed");
            let out = String::from_utf8(buf).expect(
                "write_report_section_subheader must emit valid UTF-8 (the pre-lift println!s did)",
            );

            // Exactly two lines — the pre-lift stanza is two
            // `println!`s (title + rule). A refactor that drops the
            // rule or fuses both onto one line fails here.
            let lines: Vec<&str> = out.lines().collect();
            assert_eq!(
                lines.len(),
                2,
                "{label}: write_report_section_subheader must emit \
                 exactly two lines (title, rule) — the pre-lift stanza \
                 is two `println!`s; got {}:\n{}",
                lines.len(),
                out
            );

            // Line 0 (title) carries the message verbatim and its
            // color's ANSI sequence + the `\x1b[1m` bold sequence.
            // The `colored` crate may serialize either as `\x1b[1;<c>m`
            // or `\x1b[<c>;1m` depending on the attribute order, so
            // accept either shape — the invariant is that BOTH the
            // color code and the bold code reach the buffer around
            // the title text.
            assert!(
                lines[0].contains("TEST SUBHEADER"),
                "{label}: line 0 must carry the title verbatim; got {:?}",
                lines[0]
            );
            assert!(
                lines[0].contains(bold_first_seq) || lines[0].contains(color_first_seq),
                "{label}: line 0 must carry the composite `bold` + \
                 `<color>` ANSI sequence {:?} or {:?} for the \
                 {label} palette — a silent rename of the color chain \
                 in the primitive's match arm (`.green()` → `.red()`) \
                 or a silent drop of `.bold()` would flip this; got \
                 {:?}",
                bold_first_seq,
                color_first_seq,
                lines[0]
            );

            // Line 1 (rule) is exactly 80 `─` glyphs styled with
            // `.dimmed()` (`\x1b[2m`). A refactor that narrows the
            // width, promotes `.dimmed()` off, or swaps `─` for `━`
            // fails here.
            let rule_glyph_count = lines[1].chars().filter(|c| *c == '─').count();
            assert_eq!(
                rule_glyph_count, 80,
                "{label}: line 1 must contain exactly 80 `─` glyphs — \
                 the pre-lift stanza spelled `\"─\".repeat(80)` \
                 verbatim; got {} in {:?}",
                rule_glyph_count, lines[1]
            );
            assert!(
                lines[1].contains("\x1b[2m"),
                "{label}: line 1 must carry the `dimmed` ANSI \
                 sequence (`\\x1b[2m`) — a silent drop of `.dimmed()` \
                 from the primitive would flip this; got {:?}",
                lines[1]
            );
            assert!(
                !lines[1].contains('━'),
                "{label}: line 1 must NOT contain the heavy `━` \
                 glyph — the light `─` (U+2500) is the intentional \
                 rule character distinguishing this primitive from \
                 the heavy-rule banner peers; got {:?}",
                lines[1]
            );
        }
    }

    /// Post-lift the callers in `commands/rust_service.rs`'s
    /// `print_deployment_report` migrated onto
    /// [`super::print_report_section_subheader`] no longer spell the
    /// two-line `println!("{}", "<TITLE>".<COLOR>().bold());
    /// println!("{}", "─".repeat(80).dimmed());` stanza inline.
    /// Structural regression shield — without it, a future refactor
    /// could silently re-inline the two-liner and reopen the 5-site
    /// duplication class this lift closed. The negative needle
    /// `"─".repeat(80)` uniquely identifies the pre-lift restatement:
    /// the rule character (`─`, U+2500) is not used elsewhere in the
    /// module (the peer `━`-rule and `═`-rule bars live inside
    /// distinct `ui::` primitives), and the width 80 is not repeated
    /// verbatim outside this class.
    ///
    /// The shield does NOT bound its scan through
    /// [`crate::test_support::module_body_before_first_cfg_test`]
    /// because `commands/rust_service.rs` has no `#[cfg(test)]`
    /// block interleaved with `print_deployment_report`, and the
    /// pre-lift needle `\"─\".repeat(80)` is not constructed
    /// anywhere in the module's tests. A source-wide scan therefore
    /// covers the 5 pre-lift sites without false positives.
    #[test]
    fn print_report_section_subheader_callers_delegate_through_primitive() {
        const SRC: &str = include_str!("commands/rust_service.rs");
        // Negative assertion — no pre-lift inline `"─".repeat(80)`
        // stanza remains anywhere in the module. The rule character
        // `─` (U+2500) is not shared by peer bars in the module.
        let inline_hits = SRC.matches("\"─\".repeat(80)").count();
        assert_eq!(
            inline_hits, 0,
            "commands/rust_service.rs must NOT spell the pre-lift \
             inline `\"─\".repeat(80).dimmed()` 80-glyph light rule — \
             that two-line stanza (a bold-colored title above a \
             dimmed light rule) was lifted onto \
             `crate::ui::print_report_section_subheader`. A re-inline \
             would silently reopen the 5-site duplication class this \
             shield exists to close. Found {inline_hits} inline \
             occurrences."
        );
        // Positive assertion — the module forwards through the
        // primitive at exactly five sites, one per pre-lift consumer
        // (`✅ COMPLETED ACTIONS`, `⏳ PENDING ROLLOUTS`,
        // `✓ VERIFICATION COMMANDS`, `🔍 MONITORING COMMANDS`,
        // `⚠️  WATCH FOR THESE ISSUES`). A fusion that folds one of
        // the 5 consumer sites back to inline `println!`s (silently
        // splitting the visual grammar across two subheaders) fails
        // here — the negative half above would still pass, but this
        // positive count would fall to four.
        let forward_hits = SRC
            .matches("crate::ui::print_report_section_subheader(")
            .count();
        assert_eq!(
            forward_hits, 5,
            "commands/rust_service.rs must forward through \
             `crate::ui::print_report_section_subheader(<title>, \
             <style>)` at exactly FIVE sites — one per pre-lift \
             consumer subheader inside `print_deployment_report`. A \
             fusion that folds one back to inline `println!`s or that \
             adds a sixth caller without extending this shield's \
             expected count fails here. Found {forward_hits} \
             forwarding hits."
        );
    }

    /// Fail-before-pass envelope for
    /// [`super::write_section_completion_banner`]. Pins the three-line
    /// body every pre-lift consumer spelled verbatim (a
    /// `"════════════════════════════════════════════════".bold()`
    /// rule, a `"  <title>".<COLOR>().bold()` indented status-colored
    /// title, and a second identical rule) and the exact palette per
    /// [`super::SectionCompletionStyle`] variant. A silent contract
    /// drift a future rewrite might introduce — dropping one rule to
    /// two `writeln!`s, swapping the middle line and a rule, hoisting
    /// the rule character off `═` in one branch alone, dropping
    /// `.bold()` from the title so it loses emphasis against the rule,
    /// dropping the two-space indent so the title crashes against the
    /// first column, promoting the `.green()` in the [`Success`] arm
    /// to `.bright_green()` (losing the visual-contrast contract
    /// against the failure-track closing), or swapping `.yellow()` in
    /// the [`Warning`] arm for `.red()` (collapsing the three status
    /// roles' eye-navigation categorization) — flips this assertion
    /// rather than compiling and silently diverging the 3 consumer
    /// sites' visual grammar.
    ///
    /// [`Success`]: super::SectionCompletionStyle::Success
    /// [`Warning`]: super::SectionCompletionStyle::Warning
    #[test]
    fn write_section_completion_banner_emits_three_bar_title_bar_lines_per_status_palette() {
        // Force ANSI emission (colored auto-drops sequences on a
        // non-tty stdout) and serialize against peer banner tests via
        // [`AnsiOverrideForTest`]; its Drop restores colored's
        // auto-detection on scope exit AFTER releasing the shared
        // [`ANSI_OVERRIDE_LOCK`], closing the set-write-unset window
        // without a manual [`colored::control::unset_override`] call
        // that a future test author could omit.
        let _override_guard = AnsiOverrideForTest::acquire();

        // Verify all three enum variants — the palette contract lives
        // in the primitive's `match` arms, so a silent rename of one
        // arm's color chain (`.yellow()` → `.red()` on Warning) would
        // pass the Success and Failure assertions and still flip only
        // the Warning branch here.
        //
        // `colored` folds `.color().bold()` into a single composite
        // ANSI escape whose two attributes may appear in either
        // `\x1b[1;<c>m` or `\x1b[<c>;1m` order depending on the
        // attribute-application sequence; accept both spellings.
        for (style, bold_first_seq, color_first_seq, label) in [
            (
                super::SectionCompletionStyle::Success,
                "\x1b[1;32m",
                "\x1b[32;1m",
                "green (Success)",
            ),
            (
                super::SectionCompletionStyle::Warning,
                "\x1b[1;33m",
                "\x1b[33;1m",
                "yellow (Warning)",
            ),
            (
                super::SectionCompletionStyle::Failure,
                "\x1b[1;31m",
                "\x1b[31;1m",
                "red (Failure)",
            ),
        ] {
            let mut buf: Vec<u8> = Vec::new();
            super::write_section_completion_banner(&mut buf, "TEST COMPLETION", style)
                .expect("write_section_completion_banner against a Vec<u8> writer must succeed");
            let out = String::from_utf8(buf).expect(
                "write_section_completion_banner must emit valid UTF-8 (the pre-lift println!s did)",
            );

            // Exactly three body lines — the pre-lift stanza's
            // rule+title+rule triple is three `println!`s, not two,
            // and not four. A refactor that drops or adds a rule
            // fails here.
            let lines: Vec<&str> = out.lines().collect();
            assert_eq!(
                lines.len(),
                3,
                "{label}: write_section_completion_banner must emit \
                 exactly three body lines (rule, title, rule) — the \
                 pre-lift stanza is three `println!`s; got {}:\n{}",
                lines.len(),
                out
            );

            // The `═` rule glyph appears in the outer two lines but
            // never in the middle line; the title text appears in the
            // middle line but never in the outer lines.
            assert!(
                lines[0].contains('═'),
                "{label}: line 0 must be an `═` rule; got {:?}",
                lines[0]
            );
            assert!(
                lines[2].contains('═'),
                "{label}: line 2 must be an `═` rule; got {:?}",
                lines[2]
            );
            assert!(
                !lines[1].contains('═'),
                "{label}: line 1 must NOT contain the rule glyph — it \
                 is the indented status-colored title line; got {:?}",
                lines[1]
            );
            assert!(
                lines[1].contains("TEST COMPLETION"),
                "{label}: line 1 must carry the title verbatim; got {:?}",
                lines[1]
            );
            assert!(
                lines[1].contains("  TEST COMPLETION"),
                "{label}: line 1 must carry the two-space title \
                 indent verbatim — the pre-lift stanza spelled \
                 `\"  <TITLE>\".<COLOR>().bold()`; got {:?}",
                lines[1]
            );

            // The rule width every pre-lift consumer spelled inline
            // is 48 characters — pin it here so a fusion that hoists
            // the rule off `SECTION_HEADER_RULE` onto a fresh width
            // fails the shield.
            let rule_glyph_count = lines[0].chars().filter(|c| *c == '═').count();
            assert_eq!(
                rule_glyph_count, 48,
                "{label}: line 0 must contain exactly 48 `═` glyphs \
                 (`SECTION_HEADER_RULE.len()`); got {} in {:?}",
                rule_glyph_count, lines[0]
            );

            // The two outer rule lines carry the `bold` ANSI sequence
            // (`\x1b[1m`) alone — a silent drop of `.bold()` on
            // either rule loses the section-boundary emphasis.
            for i in [0usize, 2] {
                assert!(
                    lines[i].contains("\x1b[1m"),
                    "{label}: line {i} must carry the `bold` ANSI \
                     sequence (`\\x1b[1m`) on the rule — the pre-lift \
                     stanza spelled `.bold()` on both rules; got {:?}",
                    lines[i]
                );
            }

            // Line 1 (title) carries the composite `bold` +
            // `<color>` ANSI sequence per the enum variant. The
            // `colored` crate may serialize either as `\x1b[1;<c>m`
            // or `\x1b[<c>;1m` depending on the attribute order, so
            // accept either shape — the invariant is that BOTH the
            // color code and the bold code reach the buffer around
            // the title text.
            assert!(
                lines[1].contains(bold_first_seq) || lines[1].contains(color_first_seq),
                "{label}: line 1 must carry the composite `bold` + \
                 `<color>` ANSI sequence {:?} or {:?} for the \
                 {label} palette — a silent rename of the color chain \
                 in the primitive's match arm (`.green()` → `.red()`) \
                 or a silent drop of `.bold()` would flip this; got \
                 {:?}",
                bold_first_seq,
                color_first_seq,
                lines[1]
            );
        }
    }

    /// Post-lift the callers in `commands/{codegen, sync,
    /// rebac_validation}.rs` migrated onto
    /// [`super::print_section_completion_banner`] no longer spell the
    /// three-line
    /// `println!("{}", "════════════════════════════════════════════════".bold());
    /// println!("{}", "  <TITLE>".<COLOR>().bold());
    /// println!("{}", "════════════════════════════════════════════════".bold());`
    /// stanza inline. Structural regression shield — without it, a
    /// future refactor could silently re-inline the three-liner and
    /// reopen the 6-site rule-print duplication class this lift
    /// closed. The negative needle
    /// `"════════════════════════════════════════════════"` uniquely
    /// identifies the pre-lift restatement: the 48-glyph `═` sigil is
    /// the module-private [`super::SECTION_HEADER_RULE`] constant and
    /// is not spelled as a literal anywhere else in the crate outside
    /// this shield and the peer [`super::print_section_header`]
    /// shield.
    #[test]
    fn print_section_completion_banner_callers_delegate_through_primitive() {
        const CALLERS: &[(&str, &str, usize)] = &[
            // (source, module_path, expected forward count)
            (
                include_str!("commands/codegen.rs"),
                "commands/codegen.rs",
                1, // one always-Success completion at end of `run_codegen`
            ),
            (
                include_str!("commands/sync.rs"),
                "commands/sync.rs",
                2, // one Success branch + one Failure branch at end of `run_sync`
            ),
            (
                include_str!("commands/rebac_validation.rs"),
                "commands/rebac_validation.rs",
                3, // one Success + one Warning + one Failure at end of `run_rebac_validation`
            ),
        ];
        for (source, module_path, expected_forwards) in CALLERS {
            // Negative assertion — no pre-lift inline
            // `"════════════════════════════════════════════════"`
            // stanza remains in the module body. The 48-glyph `═`
            // sigil uniquely identifies the pre-lift restatement.
            let inline_hits = source
                .matches("\"════════════════════════════════════════════════\"")
                .count();
            assert_eq!(
                inline_hits, 0,
                "{module_path} must NOT spell the pre-lift inline 48-glyph \
                 `\"════════════════════════════════════════════════\".bold()` \
                 rule — that three-line stanza was lifted onto \
                 `crate::ui::print_section_completion_banner`. A re-inline \
                 would silently reopen the 6-site duplication class this \
                 shield exists to close. Found {inline_hits} inline \
                 occurrences."
            );
            // Positive assertion — the module forwards through the
            // primitive at exactly the expected number of sites, one
            // per pre-lift branch. A fusion that folds one branch
            // back to inline `println!`s (silently splitting the
            // visual grammar across the pipeline) fails here.
            let forward_hits = source
                .matches("crate::ui::print_section_completion_banner(")
                .count();
            assert_eq!(
                forward_hits, *expected_forwards,
                "{module_path} must forward through \
                 `crate::ui::print_section_completion_banner(<title>, \
                 <style>)` at exactly {expected_forwards} sites — one \
                 per pre-lift status branch. A fusion that folds one \
                 back to inline `println!`s or that adds a caller \
                 without extending this shield's expected count fails \
                 here. Found {forward_hits} forwarding hits."
            );
        }
    }

    /// Fail-before-pass envelope for [`super::write_eprint_step_warn`].
    /// Pins the one-line body every pre-lift consumer spelled verbatim
    /// (`eprintln!("   ⚠️  <msg>: {}", <err>)`): a three-space indent,
    /// the UNCOLORED `⚠️` emoji glyph (NOT the `.yellow()`-colored
    /// variant the [`super::print_step_warn`] sibling wears, NOT the
    /// `WARN` ASCII text prefix the [`super::print_nonfatal_warn`]
    /// sibling wears), a two-space post-glyph gap, the caller's message
    /// interpolated verbatim, the literal `: ` connective, and the
    /// [`std::fmt::Display`]-formatted error tail. A silent contract
    /// drift a future rewrite might introduce — dropping the
    /// three-space indent, collapsing the two-space post-glyph gap to a
    /// single space (which crashes the glyph into the message on
    /// emoji-width-1 terminals), promoting the glyph to `.yellow()`
    /// (which slips `\x1b[33m` into the byte stream the pre-lift
    /// `eprintln!`s did not emit and collapses the visual distinction
    /// from the [`super::print_step_warn`] sibling), swapping the `⚠️`
    /// glyph for `WARN` (which collapses the visual distinction from
    /// the [`super::print_nonfatal_warn`] sibling), reflowing the `: `
    /// connective to `" - "` or `" — "`, slipping a trailing blank
    /// line into the primitive body — flips this assertion rather than
    /// compiling and silently diverging the 6 consumer sites' visual
    /// grammar.
    #[test]
    fn write_eprint_step_warn_emits_exactly_one_warn_glyph_prefixed_line_with_error_tail() {
        // Force ANSI emission (colored auto-drops sequences on a
        // non-tty writer) and serialize against peer banner tests via
        // [`AnsiOverrideForTest`]; its Drop restores colored's
        // auto-detection on scope exit AFTER releasing the shared
        // [`ANSI_OVERRIDE_LOCK`]. The override being ON is what pins
        // the "NO `\x1b[33m` present" assertion below as meaningful —
        // if coloring were applied to the glyph, colored WOULD emit
        // `\x1b[33m` under the override.
        let _override_guard = AnsiOverrideForTest::acquire();

        let mut buf: Vec<u8> = Vec::new();
        // A plain `&str` witnesses the `&dyn Display` — `anyhow::Error`,
        // [`std::borrow::Cow<str>`], and every other pre-lift
        // consumer's `Display` type reach the writer through the same
        // trait object.
        super::write_eprint_step_warn(&mut buf, "Could not fetch logs", &"connection refused")
            .expect("write_eprint_step_warn against a Vec<u8> writer must succeed");

        let out = String::from_utf8(buf)
            .expect("write_eprint_step_warn must emit valid UTF-8 (the pre-lift eprintln!s did)");

        // Exactly one line — the pre-lift stanza is one `eprintln!`,
        // not two, and carries no framing blank. A refactor that slips
        // a leading or trailing blank into the primitive body fails
        // here.
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(
            lines.len(),
            1,
            "write_eprint_step_warn must emit exactly one line — the \
             pre-lift stanza is one `eprintln!` carrying no framing \
             blank; got {}:\n{}",
            lines.len(),
            out
        );

        // The three-space indent reaches the rendered line before the
        // glyph — a fusion that dropped the indent (a "tighter body
        // spacing" cleanup) or shifted to four spaces (to match the
        // `commands/rust_service.rs` four-space bullet-decorated
        // sibling grammar) fails here.
        assert!(
            lines[0].starts_with("   \u{26a0}"),
            "line 0 must begin with a three-space indent followed by \
             the `⚠️` glyph (U+26A0) — every pre-lift consumer spelled \
             `\"   ⚠️  <msg>: {{}}\"` verbatim; got {:?}",
            lines[0]
        );

        // The `⚠️` grapheme is the base warning-sign codepoint U+26A0
        // FOLLOWED by the U+FE0F emoji variation selector — pre-lift
        // consumers spelled the full six-byte UTF-8 sequence
        // (`\xE2\x9A\xA0\xEF\xB8\x8F`) in the format string literal. A
        // fusion that dropped the variation selector (which some
        // terminals need to render the emoji form rather than the
        // text-presentation dingbat) fails here.
        assert!(
            lines[0].contains("\u{26a0}\u{fe0f}"),
            "line 0 must carry the `⚠️` grapheme with its U+FE0F emoji \
             variation selector — every pre-lift `eprintln!` literal \
             carried both codepoints; dropping the VS15/VS16 selector \
             flips the rendered grapheme from an emoji to a \
             text-presentation dingbat on emoji-capable terminals; got \
             {:?}",
            lines[0]
        );

        // The two-space post-glyph gap — pre-lift consumers spelled
        // `⚠️` + two literal spaces (the `⚠️` glyph is a wide
        // combining sequence on some terminals but narrow on others;
        // two spaces guarantees a visible gap in both). A fusion that
        // collapsed to one space fails here.
        assert!(
            lines[0].contains("\u{26a0}\u{fe0f}  Could not fetch logs"),
            "line 0 must carry the two-space post-glyph gap between \
             `⚠️` and the message — every pre-lift consumer spelled it \
             verbatim; got {:?}",
            lines[0]
        );

        // The `⚠️` emoji glyph is present and the `WARN` ASCII text is
        // NOT — a fusion that swapped the glyph for `WARN` (which
        // would collapse this primitive into the sibling
        // `write_nonfatal_warn`) fails here.
        assert!(
            !lines[0].contains("WARN"),
            "line 0 must NOT contain the `WARN` ASCII text prefix — \
             that prefix belongs to the sibling `write_nonfatal_warn` \
             primitive (stderr + `\"WARN\".yellow()` prefix + `<label> \
             failed (non-fatal): <err>` template); this primitive \
             wears the emoji-glyph grammar with a caller-composed \
             message body; got {:?}",
            lines[0]
        );

        // The literal `: ` connective reaches the rendered line — a
        // fusion that reflowed it to `" — "` or dropped the space
        // after the colon fails here.
        assert!(
            lines[0].contains("Could not fetch logs: connection refused"),
            "line 0 must carry the literal `: ` connective between the \
             message and the error tail — every pre-lift consumer \
             spelled it verbatim; got {:?}",
            lines[0]
        );

        // NO `\x1b[33m` yellow ANSI sequence — pre-lift consumers
        // spelled the `⚠️` glyph as a bare literal in the format
        // string, never `.yellow()`-wrapped. A fusion that promoted
        // the glyph to `.yellow()` (a "match the print_step_warn
        // sibling's palette" cleanup) fails here. The colored override
        // is forced ON for this test — colored coloring, when applied,
        // WOULD emit `\x1b[33m` under the override — so the absence of
        // that sequence pins the uncolored contract.
        assert!(
            !lines[0].contains("\x1b[33m"),
            "line 0 must NOT carry the `yellow` ANSI sequence \
             (`\\x1b[33m`) — every pre-lift consumer spelled the `⚠️` \
             glyph as a bare literal, never `.yellow()`-wrapped; a \
             promotion to `.yellow()` would collapse the visual \
             distinction from the sibling `print_step_warn` primitive \
             whose ONLY difference here is the coloring; got {:?}",
            lines[0]
        );

        // The trailing `\n` reaches the writer — pre-lift stanza used
        // `eprintln!` (not `eprint!`), so the newline is part of the
        // contract. A fusion that swapped `writeln!` for `write!`
        // fails here.
        assert!(
            out.ends_with('\n'),
            "write_eprint_step_warn must emit a trailing `\\n` (the \
             pre-lift `eprintln!` did); got {:?}",
            out
        );
    }

    /// Post-lift the callers migrated onto
    /// [`super::eprint_step_warn`] no longer spell the
    /// `eprintln!("   ⚠️  <msg>: {}", <err>)` shape inline. Structural
    /// regression shield — without it, a future refactor could
    /// silently re-inline the stanza (a "just call `eprintln!`
    /// directly, it's shorter" cleanup) and reopen the 6-site
    /// duplication class this lift closed. Enforced on the module body
    /// before its `#[cfg(test)]` region so a test-support mention of
    /// the raw shape does not defeat the shield.
    ///
    /// The exact-shape needle is the pre-lift prefix `eprintln!("   ⚠`
    /// (three-space-indented stderr `eprintln!` opening the format
    /// string with the `⚠` warning-sign codepoint). The
    /// `commands/rust_service.rs:1653` sibling that spells
    /// `eprintln!("⚠️  Failed to clean up temp k8s repo: {}", e)` with
    /// NO leading indent is a distinct visual grammar (top-level
    /// warning, not in-body pipeline step) and is not in scope for
    /// this lift; its zero-indent shape does not match the needle.
    #[test]
    fn eprint_step_warn_callers_delegate_through_primitive() {
        const CALLERS: &[(&str, &str)] = &[
            (
                include_str!("commands/rust_service.rs"),
                "commands/rust_service.rs",
            ),
            (
                include_str!("commands/federation_tests.rs"),
                "commands/federation_tests.rs",
            ),
        ];
        // No known non-`eprint_step_warn` sites carry the three-space-
        // indented `⚠️` stderr shape under a different grammar: the
        // source-wide grep before the lift returned exactly 6 hits (4
        // in rust_service.rs, 2 in federation_tests.rs) and every one
        // migrated onto the primitive. Kept as an allowlist for
        // future-proofing — a peer stderr-routed `⚠️`-prefixed sibling
        // on a distinct grammar (e.g. a diagnostic-block header with
        // no error tail) would land here, be flagged by the shield,
        // and either enroll in a new peer primitive or add an
        // anchoring substring to this list.
        const ALLOWLIST_SUBSTRINGS: &[&str] = &[];
        for (source, module_path) in CALLERS {
            let body = crate::test_support::module_body_before_first_cfg_test(source, module_path);
            for (i, line) in body.lines().enumerate() {
                if !line.contains("eprintln!(\"   \u{26a0}") {
                    continue;
                }
                if ALLOWLIST_SUBSTRINGS.iter().any(|s| line.contains(s)) {
                    continue;
                }
                panic!(
                    "{module_path}:{lineno} spells the pre-lift inline \
                     `eprintln!(\"   ⚠️  <msg>: {{}}\", <err>)` \
                     stderr-routed step-warn stanza — that shape was \
                     lifted onto `crate::ui::eprint_step_warn`. A \
                     re-inline would silently reopen the 6-site \
                     duplication class this shield exists to close. \
                     Offending line: {line:?}",
                    lineno = i + 1
                );
            }
            assert!(
                body.contains("crate::ui::eprint_step_warn("),
                "{module_path} body must forward to \
                 `crate::ui::eprint_step_warn(<msg>, &<err>)` — the \
                 primitive body every three-space-indented `⚠️` \
                 stderr-routed step-warn-with-error in the crate now \
                 delegates through."
            );
        }
    }

    /// Fail-before-pass envelope for [`super::write_summary_pass`].
    /// Pins the one-line body every pre-lift consumer in
    /// `commands/test.rs` spelled verbatim (`println!("  {} <fmt>",
    /// "✅".bright_green(), <args>)`): a two-space indent, a
    /// `.bright_green()`-colored `✅` glyph, a single space, then the
    /// plain (uncolored) message. A silent contract drift a future
    /// rewrite might introduce — dropping the two-space indent (a
    /// "tighter body spacing" cleanup), promoting to the three-space
    /// [`super::print_step_pass`] in-body per-step indent, demoting
    /// `.bright_green()` to `.green()` (`\x1b[32m` — the sibling
    /// [`super::print_step_pass`] / [`super::print_report_item`]
    /// per-step and per-row palette that collapses the visual
    /// hierarchy pre-lift consumers reserved bright_green to mark),
    /// promoting the whole line's coloring (`format!("  ✅ {}",
    /// msg).bright_green()`) so the message text paints bright_green
    /// at every site (colliding with the `commands/test.rs:381-390`
    /// sibling that already `.dimmed()`s a `", N skipped"` sub-field
    /// of the message), swapping `✅` for `✓` under a
    /// CI-log-friendly grammar (would collide with the sibling
    /// [`super::print_report_item`] per-row grammar), slipping a
    /// trailing blank line into the primitive body — flips this
    /// assertion rather than compiling and silently diverging the 5
    /// consumer sites' visual grammar.
    #[test]
    fn write_summary_pass_emits_exactly_one_bright_green_check_prefixed_two_indented_line() {
        // Force ANSI emission (colored auto-drops sequences on a
        // non-tty stdout) and serialize against peer banner tests
        // via [`AnsiOverrideForTest`]; its Drop restores colored's
        // auto-detection on scope exit AFTER releasing the shared
        // [`ANSI_OVERRIDE_LOCK`], closing the set-write-unset window
        // without a manual [`colored::control::unset_override`] call
        // a future test author could omit.
        let _override_guard = AnsiOverrideForTest::acquire();

        let mut buf: Vec<u8> = Vec::new();
        super::write_summary_pass(&mut buf, "All tests passed!")
            .expect("write_summary_pass against a Vec<u8> writer must succeed");

        let out = String::from_utf8(buf)
            .expect("write_summary_pass must emit valid UTF-8 (the pre-lift println!s did)");

        // Exactly one line — the pre-lift stanza is one `println!`
        // carrying no framing blank. A refactor that slips a leading
        // or trailing blank into the primitive body fails here.
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(
            lines.len(),
            1,
            "write_summary_pass must emit exactly one line — the \
             pre-lift stanza is one `println!` carrying no framing \
             blank; got {}:\n{}",
            lines.len(),
            out
        );

        // Two-space indent, NOT three-space (which is the sibling
        // in-body `print_step_pass` per-step grammar).
        assert!(
            lines[0].starts_with("  "),
            "line 0 must begin with a two-space indent — every \
             pre-lift consumer in `commands/test.rs` spelled \
             `\"  {{}} <fmt>\"` verbatim, so the indent must reach \
             the writer OUTSIDE the coloring span; got {:?}",
            lines[0]
        );
        assert!(
            !lines[0].starts_with("   "),
            "line 0 must NOT begin with a three-space indent — that \
             indent belongs to the sibling in-body \
             `print_step_pass` per-step grammar, not this wider-body \
             summary-pass grammar; got {:?}",
            lines[0]
        );

        // The `✅` glyph reaches the rendered line — NOT `✓` (the
        // sibling `print_report_item` per-row grammar).
        assert!(
            lines[0].contains('✅'),
            "line 0 must contain the `✅` glyph — every pre-lift \
             consumer spelled `\"✅\".bright_green()` on the \
             marker; got {:?}",
            lines[0]
        );
        assert!(
            !lines[0].contains('✓'),
            "line 0 must NOT contain the `✓` thin-checkmark glyph \
             — that glyph belongs to the sibling `print_report_item` \
             per-row grammar, not this summary-pass grammar; \
             got {:?}",
            lines[0]
        );

        // The message text reaches the rendered line verbatim; a
        // fusion that hoists the message off the parameter and pins
        // it to a constant fails here.
        assert!(
            lines[0].contains("All tests passed!"),
            "line 0 must carry the message verbatim; got {:?}",
            lines[0]
        );

        // The `bright_green` ANSI sequence (`\x1b[92m`) reaches the
        // rendered line; a fusion that demoted the palette to
        // `.green()` (`\x1b[32m` — the sibling
        // `print_step_pass` / `print_report_item` per-step and
        // per-row palette) collapses the visual hierarchy pre-lift
        // consumers reserved bright_green to mark and fails here.
        assert!(
            lines[0].contains("\x1b[92m"),
            "line 0 must carry the `bright_green` ANSI sequence \
             (`\\x1b[92m`) — every pre-lift consumer spelled \
             `.bright_green()` (never `.green()` or \
             `.bright_green().bold()`) on the glyph; got {:?}",
            lines[0]
        );
        assert!(
            !lines[0].contains("\x1b[32m"),
            "line 0 must NOT carry the `green` ANSI sequence \
             (`\\x1b[32m`) — that palette belongs to the sibling \
             `print_step_pass` per-step and `print_report_item` \
             per-row grammars, not this heavier summary-pass \
             grammar; got {:?}",
            lines[0]
        );

        // The `.bright_green()` coloring wraps the GLYPH alone,
        // never the message text — the `\x1b[0m` reset must close
        // the bright_green span BEFORE the message begins. Pre-lift
        // one caller (`commands/test.rs:381-390`) already
        // `.dimmed()`s a `", N skipped"` sub-field of the message
        // and passes it as an interpolated argument, so painting
        // the whole line bright_green would fight that per-caller
        // coloring at that site.
        let check_pos = lines[0].find('✅').expect("glyph must be present");
        let reset_pos = lines[0]
            .find("\x1b[0m")
            .expect("reset must be present after the glyph");
        let msg_pos = lines[0]
            .find("All tests passed!")
            .expect("message must be present");
        assert!(
            check_pos < reset_pos && reset_pos < msg_pos,
            "the `\\x1b[0m` reset must close the bright_green span \
             BEFORE the message begins — every pre-lift consumer \
             spelled `.bright_green()` on the `✅` glyph alone, \
             never on the message. Got positions check={check_pos}, \
             reset={reset_pos}, msg={msg_pos} in line {:?}",
            lines[0]
        );

        // The trailing `\n` reaches the writer — pre-lift stanza
        // used `println!` (not `print!`), so the newline is part of
        // the contract. A fusion that swapped `writeln!` for
        // `write!` fails here.
        assert!(
            out.ends_with('\n'),
            "write_summary_pass must emit a trailing `\\n` (the \
             pre-lift `println!` did); got {:?}",
            out
        );
    }

    /// Post-lift the callers migrated onto
    /// [`super::print_summary_pass`] no longer spell the
    /// `"✅".bright_green()` shape inline in
    /// `commands/test.rs`. Structural regression shield — without it
    /// a future refactor could silently re-inline the one-liner
    /// (e.g. a "just call `println!` directly, it's shorter"
    /// cleanup) and reopen the 5-site duplication class this lift
    /// closed. Enforced at the module body BEFORE its
    /// `#[cfg(test)]` region so a test-support mention of the raw
    /// shape does not defeat the shield.
    ///
    /// The exact-shape needle is `"✅".bright_green()` appearing
    /// anywhere in the module body — no allowlist is required
    /// because every pre-lift occurrence in `commands/test.rs`
    /// belonged to this summary-pass class (verified by grepping
    /// the pre-lift snapshot for the needle; the 5 hits at lines
    /// 262, 278, 383, 490, 534 all shared the two-space `"  {} <fmt>"`
    /// summary-pass grammar).
    #[test]
    fn print_summary_pass_callers_delegate_through_primitive() {
        const CALLERS: &[(&str, &str)] = &[(include_str!("commands/test.rs"), "commands/test.rs")];
        for (source, module_path) in CALLERS {
            let body = crate::test_support::module_body_before_first_cfg_test(source, module_path);
            for (i, line) in body.lines().enumerate() {
                if !line.contains("\"✅\".bright_green()") {
                    continue;
                }
                panic!(
                    "{module_path}:{lineno} spells the pre-lift inline \
                     `\"✅\".bright_green()` two-space summary-pass \
                     marker — that shape was lifted onto \
                     `crate::ui::print_summary_pass`. A re-inline \
                     would silently reopen the 5-site duplication \
                     class this shield exists to close. Offending \
                     line: {line:?}",
                    lineno = i + 1
                );
            }
            assert!(
                body.contains("crate::ui::print_summary_pass("),
                "{module_path} body must forward to \
                 `crate::ui::print_summary_pass(\"<MSG>\")` — the \
                 primitive body every two-space-indented \
                 `✅.bright_green()` summary-pass line in the crate \
                 now delegates through."
            );
        }
    }

    /// Fail-before-pass envelope for
    /// [`super::write_dimmed_dashed_marker`]. Pins the exact one-line
    /// body the 4 pre-lift sites in `commands/prerelease.rs` spelled
    /// verbatim — a `── ` prefix, the caller-supplied label, a ` ──`
    /// suffix, the whole span painted `.dimmed()` (`\x1b[2m`
    /// begin-span before the leading `── `, `\x1b[0m` end-span after
    /// the trailing ` ──`), and a trailing `\n`. Written to fail
    /// before the primitive body lands and pass once it does.
    #[test]
    fn write_dimmed_dashed_marker_emits_exactly_one_dimmed_dash_fenced_line() {
        let _override_guard = AnsiOverrideForTest::acquire();

        let mut buf: Vec<u8> = Vec::new();
        super::write_dimmed_dashed_marker(&mut buf, "cargo test stdout")
            .expect("write_dimmed_dashed_marker against a Vec<u8> writer must succeed");

        let out = String::from_utf8(buf).expect(
            "write_dimmed_dashed_marker must emit valid UTF-8 (the pre-lift println!s did)",
        );

        // Exactly one line — the pre-lift stanza is one `println!`
        // carrying no framing blank on either side. A refactor that
        // slips a leading blank (to visually separate the marker from
        // the failure verdict above) or a trailing blank (to lift the
        // subprocess corpus off the marker below) into the primitive
        // body would silently change the four callers' output at once.
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(
            lines.len(),
            1,
            "write_dimmed_dashed_marker must emit exactly one line — \
             the pre-lift stanza is one `println!` carrying no framing \
             blank; got {}:\n{}",
            lines.len(),
            out
        );

        // The `── ` prefix and ` ──` suffix reach the rendered line —
        // U+2500 BOX DRAWINGS LIGHT HORIZONTAL, NOT U+2015 HORIZONTAL
        // BAR, NOT U+2014 EM DASH, NOT ASCII `-`.
        assert!(
            lines[0].contains("── cargo test stdout ──"),
            "line 0 must carry the exact `── <label> ──` dash-fence \
             the pre-lift consumers spelled — U+2500 LIGHT HORIZONTAL \
             on both sides, one space between the dashes and the \
             label; got {:?}",
            lines[0]
        );
        assert!(
            !lines[0].contains("── cargo test stdout ──\n──"),
            "line 0 must be a single dash-fenced marker, not a \
             multi-line block; got {:?}",
            lines[0]
        );

        // The label reaches the rendered line verbatim; a fusion that
        // pins the label to a constant fails here.
        assert!(
            lines[0].contains("cargo test stdout"),
            "line 0 must carry the label verbatim; got {:?}",
            lines[0]
        );

        // The `dimmed` ANSI sequence (`\x1b[2m`) reaches the rendered
        // line — NOT `.bold()` (`\x1b[1m`), NOT `.italic()`
        // (`\x1b[3m`), NOT `.red()` (`\x1b[31m` — the sibling
        // `── E2E Failure Diagnostics ──` bold+red diagnostic-block
        // heading grammar). A silent palette promotion off `.dimmed()`
        // would erase the receding-vs-verdict visual weight that
        // separates the subprocess dump from the operator-facing
        // failure line.
        assert!(
            lines[0].contains("\x1b[2m"),
            "line 0 must carry the `dimmed` ANSI sequence \
             (`\\x1b[2m`); got {:?}",
            lines[0]
        );
        assert!(
            !lines[0].contains("\x1b[1m"),
            "line 0 must NOT carry the `bold` ANSI sequence \
             (`\\x1b[1m`) — that palette belongs to the sibling \
             bold+red diagnostic-block heading grammar \
             (`── E2E Failure Diagnostics ──`), not this dimmed \
             stream-boundary marker; got {:?}",
            lines[0]
        );
        assert!(
            !lines[0].contains("\x1b[31m"),
            "line 0 must NOT carry the `red` ANSI sequence \
             (`\\x1b[31m`) — that palette belongs to the sibling \
             bold+red diagnostic-block heading grammar, not this \
             dimmed stream-boundary marker; got {:?}",
            lines[0]
        );

        // The `.dimmed()` coloring wraps the WHOLE `── <label> ──`
        // dash-fence, not the label text alone — the `\x1b[2m` begin
        // must precede the leading `──` and the `\x1b[0m` reset must
        // follow the trailing `──`. A re-lift that split the coloring
        // (`.dimmed()` on the dashes with a plain label between)
        // would invert the visual weight and change the grammar
        // silently.
        let dim_pos = lines[0]
            .find("\x1b[2m")
            .expect("dimmed begin-span must be present");
        let leading_dash_pos = lines[0].find("──").expect("leading `──` must be present");
        let label_pos = lines[0]
            .find("cargo test stdout")
            .expect("label must be present");
        let reset_pos = lines[0]
            .find("\x1b[0m")
            .expect("reset must be present after the fence");
        assert!(
            dim_pos < leading_dash_pos,
            "the `\\x1b[2m` dimmed begin-span must precede the \
             leading `──` — every pre-lift consumer spelled \
             `.dimmed()` on the composed literal, not on the label \
             alone. Got positions dim={dim_pos}, dash={leading_dash_pos} \
             in line {:?}",
            lines[0]
        );
        assert!(
            label_pos < reset_pos,
            "the `\\x1b[0m` reset must follow the label — every \
             pre-lift consumer spelled `.dimmed()` on the composed \
             literal so the reset closes after the trailing `──`. \
             Got positions label={label_pos}, reset={reset_pos} in \
             line {:?}",
            lines[0]
        );

        // The trailing `\n` reaches the writer — pre-lift stanza
        // used `println!` (not `print!`), so the newline is part of
        // the contract. A fusion that swapped `writeln!` for
        // `write!` fails here.
        assert!(
            out.ends_with('\n'),
            "write_dimmed_dashed_marker must emit a trailing `\\n` \
             (the pre-lift `println!` did); got {:?}",
            out
        );
    }

    /// Post-lift the callers migrated onto
    /// [`super::print_dimmed_dashed_marker`] no longer spell the
    /// `"── <label> ──".dimmed()` shape inline in
    /// `commands/prerelease.rs`. Structural regression shield — a
    /// future refactor could silently re-inline the one-liner and
    /// reopen the 4-site duplication class this lift closed. The
    /// exact-shape needle is `── ` immediately followed on the same
    /// source line by `.dimmed()` — the bold+red sibling
    /// (`── E2E Failure Diagnostics ──.bold().red()`) at
    /// `commands/prerelease.rs:891` is allowlisted because its
    /// distinct palette places it in a different grammar (bold+red
    /// diagnostic-block heading, not dimmed stream boundary) and it
    /// is NOT enrolled in this lift.
    #[test]
    fn print_dimmed_dashed_marker_callers_delegate_through_primitive() {
        const CALLERS: &[(&str, &str)] = &[(
            include_str!("commands/prerelease.rs"),
            "commands/prerelease.rs",
        )];
        for (source, module_path) in CALLERS {
            let body = crate::test_support::module_body_before_first_cfg_test(source, module_path);
            for (i, line) in body.lines().enumerate() {
                if !line.contains("── ") || !line.contains(".dimmed()") {
                    continue;
                }
                if line.contains(".bold().red()") {
                    continue;
                }
                panic!(
                    "{module_path}:{lineno} spells the pre-lift inline \
                     `\"── <label> ──\".dimmed()` dash-fenced \
                     stream-boundary marker — that shape was lifted \
                     onto `crate::ui::print_dimmed_dashed_marker`. A \
                     re-inline would silently reopen the 4-site \
                     duplication class this shield exists to close. \
                     Offending line: {line:?}",
                    lineno = i + 1
                );
            }
            assert!(
                body.contains("crate::ui::print_dimmed_dashed_marker("),
                "{module_path} body must forward to \
                 `crate::ui::print_dimmed_dashed_marker(\"<LABEL>\")` \
                 — the primitive body every `── <label> ──.dimmed()` \
                 stream-boundary marker in the crate now delegates \
                 through."
            );
        }
    }

    /// Fail-before-pass envelope for [`super::write_next_steps_heading`].
    /// Pins the one-line body every pre-lift consumer spelled verbatim
    /// (`println!("Next steps:")`): the exact
    /// [`super::NEXT_STEPS_HEADING_TEXT`] eleven-byte heading text and
    /// NO indent, NO leading whitespace, NO trailing whitespace before
    /// the newline, NO coloring, NO bold. A silent contract drift a
    /// future rewrite might introduce — swapping the label text for a
    /// friendlier grammar (`"Next steps:"` → `"To do next:"`),
    /// promoting the whole line to `.bold()` (making it compete for
    /// weight with the numbered instruction rows beneath), promoting
    /// to `.dimmed()` (making it recede so far the reader misses the
    /// section boundary), slipping a leading indent (drifting the
    /// visual grammar off zero-indent), slipping a trailing space
    /// before the newline, or fusing a leading or trailing blank into
    /// the primitive body — flips this assertion rather than compiling
    /// and silently diverging the 5 consumer sites' visual grammar.
    #[test]
    fn write_next_steps_heading_emits_exactly_one_uncolored_plain_next_steps_label_line() {
        // Force ANSI-emission serialization against peer banner tests
        // via [`AnsiOverrideForTest`] — even though this primitive
        // emits NO ANSI sequences, the guard's presence pins the
        // discipline: if a future refactor slips a `.bold()` /
        // `.dimmed()` chain into the writer, the guard ensures the
        // sequence actually reaches the buffer for detection here
        // rather than being auto-stripped by [`colored`]'s non-tty
        // fallback. The guard's Drop restores colored's auto-detection
        // on scope exit AFTER releasing the shared
        // [`ANSI_OVERRIDE_LOCK`].
        let _override_guard = AnsiOverrideForTest::acquire();

        let mut buf: Vec<u8> = Vec::new();
        super::write_next_steps_heading(&mut buf)
            .expect("write_next_steps_heading against a Vec<u8> writer must succeed");

        let out = String::from_utf8(buf)
            .expect("write_next_steps_heading must emit valid UTF-8 (the pre-lift println!s did)");

        // Exactly one line — the pre-lift stanza is one `println!`
        // carrying no framing blank.
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(
            lines.len(),
            1,
            "write_next_steps_heading must emit exactly one line — \
             the pre-lift stanza is one `println!` carrying no framing \
             blank; got {}:\n{}",
            lines.len(),
            out
        );

        // The exact heading text reaches the rendered line verbatim.
        // Compare against the pub const so a silent divergence between
        // the constant and the writer's format string (a future edit
        // to one but not the other) flips this.
        assert_eq!(
            lines[0],
            super::NEXT_STEPS_HEADING_TEXT,
            "line 0 must equal `NEXT_STEPS_HEADING_TEXT` verbatim — \
             the pre-lift stanza was `println!(\"Next steps:\")` at \
             every site, so the primitive's single-line body must \
             carry the same eleven-byte label with no indent, no \
             coloring, and no trailing whitespace; got {:?}",
            lines[0]
        );

        // NO leading indent — pre-lift every consumer spelled the
        // heading at column zero (no `"  "`, `"    "`, or `"\t"`
        // prefix). A fusion that added an indent would push the label
        // away from the left margin and drift the visual grammar.
        assert!(
            !lines[0].starts_with(char::is_whitespace),
            "line 0 must NOT begin with any leading whitespace — every \
             pre-lift consumer spelled `println!(\"Next steps:\")` \
             starting at column zero, so no `\" \"`, `\"\\t\"`, or any \
             other whitespace may prefix the heading; got {:?}",
            lines[0]
        );

        // NO trailing whitespace before the newline — the label ends
        // at the colon, and the newline follows immediately.
        assert!(
            !lines[0].ends_with(char::is_whitespace),
            "line 0 must NOT end with any trailing whitespace before \
             the newline — the pre-lift `println!(\"Next steps:\")` \
             ended at the colon; got {:?}",
            lines[0]
        );

        // ABSENCE OF ALL PALETTE ANSI SEQUENCES — no coloring at all.
        // A silent promotion to `.bold()` (making the label compete
        // for weight with the numbered instruction rows), `.dimmed()`
        // (making it recede so far the reader misses the section
        // boundary), or any color chain reaches the buffer as one of
        // these sequences and flips the corresponding assertion.
        for (ansi_seq, palette_label, colliding_primitive) in [
            ("\x1b[1m", "bold", "print_step_heading (`.bold()`)"),
            (
                "\x1b[2m",
                "dim",
                "print_dimmed_dashed_marker (`.dimmed()` on the whole span)",
            ),
            (
                "\x1b[4m",
                "underline",
                "print_phase_heading (`.bold().underline()`)",
            ),
            (
                "\x1b[32m",
                "green",
                "print_step_success (`.green()` completion)",
            ),
            (
                "\x1b[33m",
                "yellow",
                "print_step_warn (`.yellow()` warning)",
            ),
            ("\x1b[31m", "red", "print_step_failure (`.red()` failure)"),
            ("\x1b[36m", "cyan", "print_arrow_item (`.cyan()` narrative)"),
            (
                "\x1b[34m",
                "blue",
                "print_numbered_check_heading (`.blue()` heading)",
            ),
        ] {
            assert!(
                !lines[0].contains(ansi_seq),
                "line 0 must NOT carry the `{palette_label}` ANSI \
                 sequence ({ansi_seq:?}) — every pre-lift consumer \
                 spelled the heading as a plain `println!(\"Next \
                 steps:\")` with NO coloring chain, so the label \
                 recedes beneath the numbered instruction rows that \
                 follow it. A promotion to this palette would collide \
                 with {colliding_primitive}. Got {:?}",
                lines[0]
            );
        }
        // Sanity: no ANSI escape byte at all in the rendered line.
        assert!(
            !lines[0].contains('\x1b'),
            "line 0 must contain no ANSI escape byte (`\\x1b`) at all \
             — this plain heading primitive emits no coloring; got {:?}",
            lines[0]
        );

        // The trailing `\n` reaches the writer — pre-lift stanza used
        // `println!` (not `print!`), so the newline is part of the
        // contract. A fusion that swapped `writeln!` for `write!`
        // fails here.
        assert!(
            out.ends_with('\n'),
            "write_next_steps_heading must emit a trailing `\\n` (the \
             pre-lift `println!` did); got {:?}",
            out
        );
    }

    /// Post-lift the callers migrated onto
    /// [`super::print_next_steps_heading`] no longer spell the
    /// `println!("Next steps:")` shape inline across
    /// `commands/{web_service.rs, sync.rs, developer_tools.rs}`.
    /// Structural regression shield — a future refactor could silently
    /// re-inline the one-liner (e.g. a "just call `println!` directly,
    /// it's shorter" cleanup) and reopen the 5-site duplication class
    /// this lift closed. Enforced against each module body BEFORE its
    /// first `#[cfg(test)]` region so a test-support mention of the
    /// raw shape does not defeat the shield.
    ///
    /// The exact-shape needle is `println!("Next steps:` — the macro
    /// invocation with the opening quote and the heading label prefix
    /// on the same source line. No allowlist is required because
    /// every pre-lift occurrence in the crate belonged to this class;
    /// a re-inline with any suffix completing the shape (e.g.
    /// `println!("Next steps:")` verbatim, or a hypothetical
    /// `println!("Next steps: {}", ...)` widening) flips the shield.
    ///
    /// The positive count is pinned per-module at the pre-lift site
    /// count (`web_service.rs` ×2, `sync.rs` ×1, `developer_tools.rs`
    /// ×2). A fusion that folded two consumer sites into one call or
    /// dropped one of the headings silently fails here — the negative
    /// half above would still pass, but the positive count would fall
    /// below the pre-lift census.
    #[test]
    fn print_next_steps_heading_callers_delegate_through_primitive() {
        const CALLERS: &[(&str, &str, usize)] = &[
            (
                include_str!("commands/web_service.rs"),
                "commands/web_service.rs",
                2,
            ),
            (include_str!("commands/sync.rs"), "commands/sync.rs", 1),
            (
                include_str!("commands/developer_tools.rs"),
                "commands/developer_tools.rs",
                2,
            ),
        ];
        for (source, module_path, expected_forwards) in CALLERS {
            let body = crate::test_support::module_body_before_first_cfg_test(source, module_path);
            for (i, line) in body.lines().enumerate() {
                if !line.contains("println!(\"Next steps:") {
                    continue;
                }
                panic!(
                    "{module_path}:{lineno} spells the pre-lift inline \
                     `println!(\"Next steps:\")` plain-text \
                     post-completion instruction heading — that shape \
                     was lifted onto \
                     `crate::ui::print_next_steps_heading`. A re-inline \
                     would silently reopen the 5-site duplication \
                     class this shield exists to close. Offending \
                     line: {line:?}",
                    lineno = i + 1
                );
            }
            let forward_hits = body.matches("crate::ui::print_next_steps_heading(").count();
            assert_eq!(
                forward_hits, *expected_forwards,
                "{module_path} body must forward to \
                 `crate::ui::print_next_steps_heading()` at exactly \
                 {expected_forwards} site(s) — one per pre-lift \
                 consumer in this module. A fusion that folded two \
                 consumer sites into one call or dropped one of the \
                 headings silently fails here. Found {forward_hits} \
                 forwarding hits."
            );
        }
    }
}
