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
/// `✅` glyph + plain message) in-body step-pass grammar 28 pre-lift
/// consumer sites spelled inline as `println!("   {} <fmt>",
/// "✅".green(), <args>)` (or its multi-line spread across five to
/// seven source lines when the message carries a `format!`-computed
/// argument list) across 10 command modules (`commands/{prerelease
/// (×6), migration_new (×4), frontend_validation (×4), migration_validation
/// (×3), post_deploy_verification (×3), codegen_validation (×3), rust_service
/// (×2), codegen (×1), integration_tests (×1), migrations (×1)}.rs`).
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
    /// no longer spell the `println!("   {} <fmt>", "✅".green(),
    /// <args>)` shape inline. Structural regression shield — without
    /// it, a future refactor could silently re-inline the one-liner
    /// (e.g. a "just call `println!` directly, it's shorter" cleanup)
    /// and reopen the 28-site duplication class this lift closed.
    /// Enforced at the module bodies before their `#[cfg(test)]`
    /// regions so a test-support mention of the raw shape does not
    /// defeat the shield.
    ///
    /// The exact-shape needle is `"✅".green()` appearing anywhere in
    /// the module body, MINUS one known non-step-pass site that
    /// carries the same coloring under a different grammar: the
    /// `prerelease.rs:182` `println!("{} Passed ({}):", "✅".green(),
    /// self.passed.len())` gate-summary label header (no three-space
    /// indent, plural item count in parens, colon suffix — a
    /// section-opening banner for a batch of passed gates, distinct
    /// from an in-body per-step pass). Survives untouched; the shield
    /// allowlists it by an anchoring substring unique to that site.
    /// `release_service.rs`'s `info!("{} {} completed in {:.1}s",
    /// "✅".green(), ...)` tracing-logger call is routed through
    /// `tracing::info!`, not `println!` — logger frontend, not
    /// terminal UI — and is not enrolled in the caller set below.
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
            for (i, line) in body.lines().enumerate() {
                if !line.contains("\"✅\".green()") {
                    continue;
                }
                if ALLOWLIST_SUBSTRINGS.iter().any(|s| line.contains(s)) {
                    continue;
                }
                panic!(
                    "{module_path}:{lineno} spells the pre-lift inline \
                     `\"✅\".green()` step-pass marker — that shape \
                     was lifted onto `crate::ui::print_step_pass`. \
                     A re-inline would silently reopen the 28-site \
                     duplication class this shield exists to close. \
                     Offending line: {line:?}",
                    lineno = i + 1
                );
            }
            assert!(
                body.contains("crate::ui::print_step_pass("),
                "{module_path} body must forward to \
                 `crate::ui::print_step_pass(\"<MSG>\")` — the \
                 primitive body every three-space-indented `✅.green()` \
                 in-body step-pass in the crate now delegates \
                 through."
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
}
