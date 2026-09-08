//! `<emoji> <verb-phrase> for <service.cyan()>...` phase-open banner
//! primitive.
//!
//! The six sibling `pub async fn rust_<phase>(service: String)` command
//! bodies at `commands/developer_tools.rs` —
//! [`rust_unit_test`] at :131, [`rust_lint`] at :142, [`rust_fmt`] at
//! :160, [`rust_fmt_check`] at :166, [`rust_extract_schema`] at :177,
//! and [`rust_update_cargo_nix`] at :207 — each opened with the
//! `println!("<emoji> <verb-phrase> for {}...", service.cyan())`
//! stanza. Six copies of the same three-token grammar (leading emoji
//! glyph, verb-phrase in ASCII, `.cyan()`-styled service name, fixed
//! trailing `...` ellipsis, `writeln!`-terminated) meant a palette
//! shift — swapping `.cyan()` for `.bright_cyan().bold()` under a
//! consistency pass with other command-family openers, dropping the
//! trailing `...` for parity with the `ui::print_bold_titled_phase_open`
//! grammar, promoting the emoji to a `Colorize`-styled glyph, hoisting
//! the `for` connector to `on` to distinguish per-service work from
//! per-cluster work, or emitting an OTLP `developer_tool.phase_open`
//! observability event alongside — had to be applied at six sites in
//! lockstep or the visual grammar of the developer-tool command
//! family drifts against itself. Post-lift the (emoji, verb-phrase)
//! pair lives inside the closed [`DeveloperToolPhase`] enum and the
//! grammar lives at ONE `writeln!` body in
//! [`write_developer_tool_phase_open`].
//!
//! Sibling of `commands/subcommand_invocation.rs` on the same
//! print-then-run axis: that primitive owns the pre-spawn echo line
//! for child-tool invocations by the product-release orchestrator;
//! this primitive owns the pre-work banner for the six per-service
//! developer-tool commands. Both close a small closed enum
//! (`SubcommandTool::{Forge,Nix}` there; [`DeveloperToolPhase`]'s
//! six variants here) over the axis that varies and hand the
//! byte-level `writeln!` grammar to a single fusion body.

use std::io;

use colored::Colorize;

/// The developer-tool phase whose open banner is being emitted.
///
/// Each variant maps to a fixed `(emoji, verb_phrase)` pair the
/// pre-lift `commands/developer_tools.rs` sites each spelled inline in
/// the format string. Adding a seventh developer-tool command
/// (e.g. `rust_bench`, `rust_audit`) is one new variant plus one arm
/// in each of [`DeveloperToolPhase::emoji`] and
/// [`DeveloperToolPhase::verb_phrase`] — the surrounding print grammar
/// stays fixed.
///
/// # Six-variant closed set
///
/// [`UnitTest`](Self::UnitTest) → `🧪 Running unit tests`;
/// [`Clippy`](Self::Clippy) → `🔍 Running clippy linter`;
/// [`Format`](Self::Format) → `✨ Formatting code`;
/// [`FormatCheck`](Self::FormatCheck) → `🔍 Checking code formatting`;
/// [`ExtractSchema`](Self::ExtractSchema) → `📄 Extracting GraphQL schema`;
/// [`UpdateCargoNix`](Self::UpdateCargoNix) → `🔄 Updating Cargo.nix`.
///
/// Two variants share the same `🔍` glyph but diverge on the
/// verb-phrase (`Running clippy linter` vs
/// `Checking code formatting`) — the enum captures the pre-lift
/// two-axis correlation the format-string literals encoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeveloperToolPhase {
    /// `🧪 Running unit tests` — the [`super::developer_tools::rust_unit_test`]
    /// opener that precedes `cargo test`.
    UnitTest,
    /// `🔍 Running clippy linter` — the
    /// [`super::developer_tools::rust_lint`] opener that precedes
    /// `cargo clippy --all-targets --all-features -- -D warnings`.
    Clippy,
    /// `✨ Formatting code` — the [`super::developer_tools::rust_fmt`]
    /// opener that precedes `cargo fmt --all`.
    Format,
    /// `🔍 Checking code formatting` — the
    /// [`super::developer_tools::rust_fmt_check`] opener that precedes
    /// `cargo fmt --all -- --check`.
    FormatCheck,
    /// `📄 Extracting GraphQL schema` — the
    /// [`super::developer_tools::rust_extract_schema`] opener that
    /// precedes a `cargo run --bin <extract-schema-binary>` spawn.
    ExtractSchema,
    /// `🔄 Updating Cargo.nix` — the
    /// [`super::developer_tools::rust_update_cargo_nix`] opener that
    /// precedes a `cargo update` + `crate2nix` regeneration pair.
    UpdateCargoNix,
}

impl DeveloperToolPhase {
    /// The fixed leading glyph (a single grapheme cluster) each
    /// pre-lift site baked into the format-string literal. Named as a
    /// `const fn` so a future variant addition cannot silently drift
    /// the grapheme (e.g. swap `📄` for the visually-similar `📃`
    /// U+1F4C3 SCROLL) — the enum owns the byte-for-byte spelling.
    pub const fn emoji(self) -> &'static str {
        match self {
            DeveloperToolPhase::UnitTest => "🧪",
            DeveloperToolPhase::Clippy => "🔍",
            DeveloperToolPhase::Format => "✨",
            DeveloperToolPhase::FormatCheck => "🔍",
            DeveloperToolPhase::ExtractSchema => "📄",
            DeveloperToolPhase::UpdateCargoNix => "🔄",
        }
    }

    /// The fixed ASCII verb-phrase between the emoji and
    /// `for <service>...`. Pins the pre-lift wording the operator
    /// scans (`Running unit tests`, not `Executing unit tests`;
    /// `Formatting code`, not `Reformatting code`) so a stylistic
    /// pass on any one site cannot drift a sibling's spelling.
    pub const fn verb_phrase(self) -> &'static str {
        match self {
            DeveloperToolPhase::UnitTest => "Running unit tests",
            DeveloperToolPhase::Clippy => "Running clippy linter",
            DeveloperToolPhase::Format => "Formatting code",
            DeveloperToolPhase::FormatCheck => "Checking code formatting",
            DeveloperToolPhase::ExtractSchema => "Extracting GraphQL schema",
            DeveloperToolPhase::UpdateCargoNix => "Updating Cargo.nix",
        }
    }
}

/// Prints the one-line `"<emoji> <verb-phrase> for {}...", service.cyan()`
/// phase-open banner stanza the six pre-lift `commands/developer_tools.rs`
/// sites each spelled verbatim.
///
/// Delegates to [`write_developer_tool_phase_open`] against
/// [`std::io::stdout`]; the writer split exists so the byte-oracle
/// sibling tests can pin each variant's exact byte-form against an
/// in-memory [`Vec<u8>`] buffer without capturing stdout.
pub fn print_developer_tool_phase_open(phase: DeveloperToolPhase, service: &str) {
    let _ = write_developer_tool_phase_open(&mut io::stdout().lock(), phase, service);
}

/// Writer-taking sibling of [`print_developer_tool_phase_open`]. Emits
/// the single `<emoji> <verb-phrase> for <service.cyan()>...` line via
/// [`writeln!`] against the supplied writer.
///
/// The [`Colorize::cyan`] call on `service` matches the pre-lift six
/// sites verbatim; a caller reaching for a different palette on the
/// service-name span reaches for a new primitive rather than a
/// parameter here, because the six pre-lift sites are the closed set
/// of consumers this primitive owns and none of them varied the
/// palette.
pub fn write_developer_tool_phase_open<W: io::Write>(
    w: &mut W,
    phase: DeveloperToolPhase,
    service: &str,
) -> io::Result<()> {
    writeln!(
        w,
        "{} {} for {}...",
        phase.emoji(),
        phase.verb_phrase(),
        service.cyan()
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
    /// The coloring contract on the `.cyan()` service-name span is
    /// pinned separately by
    /// [`primitive_body_carries_cyan_on_service_name`].
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

    /// Pin the [`DeveloperToolPhase::UnitTest`] byte-form: exactly one
    /// line, leading `🧪`, single space, `Running unit tests`, single
    /// space, `for`, single space, service name, trailing `...` and
    /// `\n`. A future refactor that hoisted the trailing `...` off the
    /// literal, dropped the space between `for` and the service name,
    /// or dropped the newline regresses this assertion.
    #[test]
    fn write_unit_test_line_carries_test_tube_running_unit_tests_grammar() {
        let mut buf: Vec<u8> = Vec::new();
        write_developer_tool_phase_open(&mut buf, DeveloperToolPhase::UnitTest, "backend").unwrap();
        let plain = strip_ansi(&String::from_utf8(buf).unwrap());
        assert_eq!(plain, "🧪 Running unit tests for backend...\n");
    }

    /// Pin the [`DeveloperToolPhase::Clippy`] byte-form, differing
    /// from [`DeveloperToolPhase::UnitTest`] on the emoji AND on the
    /// verb-phrase — the two-axis correlation the enum owns.
    #[test]
    fn write_clippy_line_carries_magnifier_running_clippy_linter_grammar() {
        let mut buf: Vec<u8> = Vec::new();
        write_developer_tool_phase_open(&mut buf, DeveloperToolPhase::Clippy, "web").unwrap();
        let plain = strip_ansi(&String::from_utf8(buf).unwrap());
        assert_eq!(plain, "🔍 Running clippy linter for web...\n");
    }

    /// Pin the [`DeveloperToolPhase::Format`] byte-form: leading `✨`
    /// SPARKLES, verb-phrase `Formatting code`. Diverges from
    /// [`DeveloperToolPhase::FormatCheck`] on both the emoji and the
    /// verb-phrase (`✨` vs `🔍`, `Formatting code` vs
    /// `Checking code formatting`) despite being adjacent in the
    /// pre-lift source order — the enum captures that divergence.
    #[test]
    fn write_format_line_carries_sparkles_formatting_code_grammar() {
        let mut buf: Vec<u8> = Vec::new();
        write_developer_tool_phase_open(&mut buf, DeveloperToolPhase::Format, "backend").unwrap();
        let plain = strip_ansi(&String::from_utf8(buf).unwrap());
        assert_eq!(plain, "✨ Formatting code for backend...\n");
    }

    /// Pin the [`DeveloperToolPhase::FormatCheck`] byte-form: shares
    /// the `🔍` glyph with [`DeveloperToolPhase::Clippy`] but diverges
    /// on the verb-phrase (`Checking code formatting` vs
    /// `Running clippy linter`). Two variants sharing an emoji is a
    /// pre-lift invariant this test pins so a "just deduplicate the
    /// emoji" refactor cannot collapse them into a single arm.
    #[test]
    fn write_format_check_line_carries_magnifier_checking_code_formatting_grammar() {
        let mut buf: Vec<u8> = Vec::new();
        write_developer_tool_phase_open(&mut buf, DeveloperToolPhase::FormatCheck, "web").unwrap();
        let plain = strip_ansi(&String::from_utf8(buf).unwrap());
        assert_eq!(plain, "🔍 Checking code formatting for web...\n");
    }

    /// Pin the [`DeveloperToolPhase::ExtractSchema`] byte-form:
    /// leading `📄` PAGE FACING UP, verb-phrase
    /// `Extracting GraphQL schema`. A future refactor that swapped
    /// `📄` for the visually-similar `📃` U+1F4C3 SCROLL regresses
    /// this assertion at the byte level (the two codepoints share no
    /// bytes in their UTF-8 encoding).
    #[test]
    fn write_extract_schema_line_carries_page_extracting_graphql_schema_grammar() {
        let mut buf: Vec<u8> = Vec::new();
        write_developer_tool_phase_open(&mut buf, DeveloperToolPhase::ExtractSchema, "backend")
            .unwrap();
        let plain = strip_ansi(&String::from_utf8(buf).unwrap());
        assert_eq!(plain, "📄 Extracting GraphQL schema for backend...\n");
    }

    /// Pin the [`DeveloperToolPhase::UpdateCargoNix`] byte-form:
    /// leading `🔄` COUNTERCLOCKWISE ARROWS BUTTON, verb-phrase
    /// `Updating Cargo.nix`. Diverges from every other variant on
    /// both axes.
    #[test]
    fn write_update_cargo_nix_line_carries_arrows_updating_cargo_nix_grammar() {
        let mut buf: Vec<u8> = Vec::new();
        write_developer_tool_phase_open(&mut buf, DeveloperToolPhase::UpdateCargoNix, "backend")
            .unwrap();
        let plain = strip_ansi(&String::from_utf8(buf).unwrap());
        assert_eq!(plain, "🔄 Updating Cargo.nix for backend...\n");
    }

    /// Coloring shield: the primitive body must chain [`Colorize::cyan`]
    /// on the `service` argument. Pins the coloring contract that the
    /// plain-bytes oracles above deliberately ignore (colored auto-drops
    /// ANSI on non-TTY writers, so a plain-bytes assertion cannot
    /// distinguish `service` from `service.cyan()` on a stdout-Vec-piped
    /// `cargo test` run). A "just print the service plain, it's shorter"
    /// cleanup that dropped `.cyan()` here regresses the visual grammar
    /// the six pre-lift sites each carried.
    ///
    /// The needle scan is bounded to the module body before the first
    /// `#[cfg(test)]` block so this shield's own diagnostic prose does
    /// not false-match itself.
    #[test]
    fn primitive_body_carries_cyan_on_service_name() {
        let source = include_str!("developer_tool_phase_open.rs");
        let body = crate::test_support::module_body_before_first_cfg_test(
            source,
            "developer_tool_phase_open.rs",
        );
        assert!(
            body.contains("writeln!"),
            "primitive body must carry a `writeln!` — every phase-open banner \
             this primitive owns is emitted via `writeln!` against the caller's \
             writer.",
        );
        assert!(
            body.contains("service.cyan()"),
            "primitive body must chain `.cyan()` on the `service` argument — a \
             cleanup that dropped `.cyan()` here regresses the visual grammar \
             the six pre-lift sites each carried.",
        );
        assert!(
            body.contains("\"{} {} for {}...\""),
            "primitive body must carry the exact `\"{{}} {{}} for {{}}...\"` \
             format string — emoji slot, verb-phrase slot, `for` connector, \
             service-name slot, fixed trailing `...` ellipsis. A rewrite that \
             swapped the `for` connector, dropped the ellipsis, or hoisted the \
             connector into the verb-phrase regresses this assertion.",
        );
    }

    /// Caller shield: no source line under `cli/src/commands/` may
    /// spell the pre-lift `println!("<emoji> <verb-phrase> for {}...", ...cyan())`
    /// inline any more. Every developer-tool phase-open banner in
    /// `commands/developer_tools.rs`'s `rust_*` command bodies must
    /// resolve through [`print_developer_tool_phase_open`] so a future
    /// palette adjustment on the `.cyan()` service span, the trailing
    /// `...` ellipsis, or the `for` connector flows to every site from
    /// one edit.
    ///
    /// The needle rejects any non-comment line that co-occurs
    /// `println!(` with the ` for {}...", ` fragment ending in
    /// `.cyan()` — the composite uniquely identifies the pre-lift
    /// developer-tool phase-open grammar.
    #[test]
    fn no_command_module_still_spells_raw_developer_tool_phase_open() {
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
            if path.file_name().and_then(|n| n.to_str()) == Some("developer_tool_phase_open.rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).unwrap();
            let hits: Vec<String> = source
                .lines()
                .enumerate()
                .filter(|(_, l)| {
                    let t = l.trim_start();
                    !t.starts_with("//")
                        && t.starts_with("println!(")
                        && l.contains(" for {}...\", ")
                        && l.contains(".cyan()")
                })
                .map(|(i, l)| format!("line {}: {}", i + 1, l.trim()))
                .collect();
            if !hits.is_empty() {
                offenders.push((path, hits));
            }
        }
        assert!(
            offenders.is_empty(),
            "pre-lift `println!(\"<emoji> <verb-phrase> for {{}}...\", <service>.cyan())` \
             stanza(s) survive under `commands/` — route each through \
             `crate::commands::developer_tool_phase_open::print_developer_tool_phase_open(\
             <DeveloperToolPhase>, &<service>)` instead:\n{:#?}",
            offenders,
        );
    }

    /// Positive-delegation shield: `commands/developer_tools.rs` MUST
    /// forward through [`print_developer_tool_phase_open`] at least
    /// six times — one per pre-lift `rust_*` command body the census
    /// identified. Pins that a dropped call site cannot leave the
    /// negative caller shield trivially satisfied by absence.
    #[test]
    fn developer_tools_module_forwards_through_phase_open_primitive_at_least_six_times() {
        use std::path::PathBuf;
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands")
            .join("developer_tools.rs");
        let source = std::fs::read_to_string(&path).unwrap();
        let forwards = source.matches("print_developer_tool_phase_open(").count();
        assert!(
            forwards >= 6,
            "developer_tools.rs must forward at least six pre-lift phase-open \
             banner site(s) through \
             `crate::commands::developer_tool_phase_open::print_developer_tool_phase_open(`; \
             found {forwards}. A dropped call would leave the negative \
             raw-`println!` scan satisfied by absence.",
        );
    }
}
