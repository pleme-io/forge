//! Subcommand-invocation announce-line primitive.
//!
//! The two sibling `run_<tool>_subcommand`-family helpers in
//! `commands/product_release.rs` — `run_forge_subcommand` at :30 and
//! `run_nix_release_app` at :55 — each echoed the child-tool command
//! about to be spawned via the same
//! `println!("   {} <TOOL> {}", ">>".dimmed(), args.join(" ").dimmed())`
//! three-space-indent, `.dimmed()` `>>` digraph, tool label,
//! space-joined `.dimmed()` argv grammar. The operator scans this line
//! to see which child tool the product-release orchestrator delegated
//! to on the next spawn.
//!
//! Pre-lift both sites spelled the entire stanza verbatim, differing
//! only in the tool label (`"forge"` vs `"nix"`) baked into the
//! `println!` template. A future palette adjustment (a swap of `>>`
//! for `▶` under a heavier per-tool sigil, dropping `.dimmed()` off
//! the digraph so it competes with the argv for the operator's eye,
//! dropping `.dimmed()` off the argv so a wall of argv text shouts
//! louder than the tool-name anchor, hoisting the coloring off the
//! two spans onto the whole line at a `format!` site, an OTLP
//! `subcommand_invocation` observability event that emits alongside
//! the print, a lift of the three-space indent to a two-space indent
//! under a leaner grammar) had to hit both sites in lockstep or the
//! visual grammar the orchestrator carries between its two child-tool
//! spawn wrappers would drift; post-lift it hits ONE typed body.
//!
//! Sibling of `commands/manifest_push.rs` — same
//! `tracing`/`println!`-routed announcement-with-args grammar the
//! wider deployment-flow surface follows, applied to the pre-spawn
//! echo-line stage of a child-tool invocation. This primitive owns
//! the byte-for-byte spelling of the pre-spawn echo line; the child
//! process's exit routing stays with the caller (via
//! `crate::retry::run_inherited_status`) because the two axes are
//! orthogonal — a future refactor of the exit-routing wrapper flows
//! independently of a future refactor of the echo grammar.

use std::io;

use colored::Colorize;

/// The child tool the product-release orchestrator delegates to on
/// the next spawn. Each variant maps to a fixed byte-string label the
/// announce line emits between the dimmed `>>` digraph and the dimmed
/// space-joined argv.
///
/// Pre-lift the label was baked into the format string at each of
/// the two `product_release.rs` sites (`"   {} forge {}"` at :30 and
/// `"   {} nix {}"` at :55); post-lift the enum owns the byte-level
/// spelling at exactly one site. Adding a third child tool
/// (e.g. `kubectl`, `helm`) is one new variant plus one
/// [`SubcommandTool::label`] arm — the surrounding print grammar
/// stays fixed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubcommandTool {
    /// The `forge` binary — re-invoked via `run_forge_subcommand` to
    /// route a product-release phase through the same CLI the operator
    /// launched.
    Forge,
    /// The `nix` binary — invoked via `run_nix_release_app` to spawn a
    /// per-service `.#release:<service>` (standalone) or
    /// `.#release:<product>:<service>` (monorepo) app.
    Nix,
}

impl SubcommandTool {
    /// The fixed lowercase tool label emitted between the `>>`
    /// digraph and the space-joined argv on the announce line.
    ///
    /// Pre-lift the label was baked into the format string at each
    /// site; the byte-for-byte spelling is invariant across the two
    /// consumer sites and named as a `const fn` so a future addition
    /// of a third tool cannot drift the label formatting from what
    /// the operator has been trained to read.
    pub const fn label(self) -> &'static str {
        match self {
            SubcommandTool::Forge => "forge",
            SubcommandTool::Nix => "nix",
        }
    }
}

/// Prints the one-line `"   {} <tool.label()> {}"` (three-space
/// indent, dimmed `>>` digraph, tool label, dimmed space-joined
/// argv) subcommand-invocation announce stanza both pre-lift sites
/// in `commands/product_release.rs` spelled verbatim.
///
/// Delegates to [`write_subcommand_invocation`] against
/// [`std::io::stdout`]; the writer split exists so the byte-oracle
/// sibling test can pin the three-space indent, the `>>` digraph,
/// the tool label, the space-joined argv, and the trailing `\n`
/// against an in-memory [`Vec<u8>`] buffer without capturing stdout.
pub fn print_subcommand_invocation(tool: SubcommandTool, args: &[&str]) {
    let _ = write_subcommand_invocation(&mut std::io::stdout().lock(), tool, args);
}

/// Writer-taking sibling to [`print_subcommand_invocation`]. Emits
/// the single `   <>>.dimmed()> <tool.label()> <args.join(" ").dimmed()>`
/// line via [`writeln!`] against the supplied writer.
///
/// [`print_subcommand_invocation`] is the stdout adapter; this
/// variant exists so tests can pin the one-line body, the three-space
/// indent, the `>>` digraph, the tool label, the space-joined argv,
/// and the trailing `\n` by inspecting emitted bytes rather than
/// shelling out and grepping stdout.
pub fn write_subcommand_invocation<W: io::Write>(
    w: &mut W,
    tool: SubcommandTool,
    args: &[&str],
) -> io::Result<()> {
    let joined = args.join(" ");
    writeln!(
        w,
        "   {} {} {}",
        ">>".dimmed(),
        tool.label(),
        joined.dimmed()
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
    /// The coloring contract on the two `.dimmed()` spans is pinned
    /// separately by [`primitive_body_carries_dimmed_on_digraph_and_argv`].
    fn strip_ansi(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        let mut chars = s.chars();
        while let Some(c) = chars.next() {
            if c == '\x1b' {
                // Consume `[` … `<final byte>` — CSI runs terminate at
                // an ASCII letter in the 0x40–0x7e range; anything not
                // recognized is dropped through to preserve
                // best-effort readability.
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

    /// Pin the [`SubcommandTool::Forge`] byte-form: exactly one line,
    /// three-space indent, `>> forge` prefix (a space between the
    /// digraph and the label), then a single space and the
    /// space-joined argv, then a trailing `\n`. A future refactor
    /// that hoisted the indent inside the coloring span, swapped `>>`
    /// for `→` (collapsing this per-tool announce into a variant of
    /// the sibling `ui::print_arrow_item` narrative-marker), promoted
    /// the label to `Forge`/`FORGE`, or dropped the newline regresses
    /// this assertion.
    #[test]
    fn write_forge_line_carries_indent_digraph_forge_label_and_joined_argv() {
        let mut buf: Vec<u8> = Vec::new();
        write_subcommand_invocation(&mut buf, SubcommandTool::Forge, &["push", "--all"]).unwrap();
        let out = String::from_utf8(buf).unwrap();
        let plain = strip_ansi(&out);
        assert_eq!(plain, "   >> forge push --all\n");
    }

    /// Pin the [`SubcommandTool::Nix`] byte-form under the same
    /// grammar, differing only in the tool label — the invariant the
    /// enum owns. A future refactor that flipped either label's
    /// spelling to the other's or promoted a variant's label to
    /// title-case regresses one arm here without touching the other.
    #[test]
    fn write_nix_line_carries_indent_digraph_nix_label_and_joined_argv() {
        let mut buf: Vec<u8> = Vec::new();
        write_subcommand_invocation(
            &mut buf,
            SubcommandTool::Nix,
            &["run", ".#release:foo", "--", "--push-only"],
        )
        .unwrap();
        let out = String::from_utf8(buf).unwrap();
        let plain = strip_ansi(&out);
        assert_eq!(plain, "   >> nix run .#release:foo -- --push-only\n");
    }

    /// Empty-argv edge: [`args.join(" ")`] on `&[]` yields `""`, so
    /// the pre-lift `println!("   {} <tool> {}", ...)` layout emits a
    /// trailing space between the tool label and the argv slot. Pin
    /// that shape so a future refactor that trims the trailing space
    /// on empty argv (or trims one anywhere) is caught before it
    /// diverges the two sibling sites' pre-lift trailing-space
    /// behavior. Neither pre-lift site was called with empty argv in
    /// practice, but the primitive's contract stays defined at every
    /// slice.
    #[test]
    fn write_forge_line_on_empty_argv_keeps_pre_lift_trailing_space() {
        let mut buf: Vec<u8> = Vec::new();
        write_subcommand_invocation(&mut buf, SubcommandTool::Forge, &[]).unwrap();
        let out = String::from_utf8(buf).unwrap();
        let plain = strip_ansi(&out);
        assert_eq!(plain, "   >> forge \n");
    }

    /// Label-axis pin: [`SubcommandTool::Forge::label`] returns the
    /// verbatim `"forge"` byte string and
    /// [`SubcommandTool::Nix::label`] returns the verbatim `"nix"`
    /// byte string the pre-lift two sites each spelled inline as
    /// format-string literals. A future refactor that swapped either
    /// arm regresses this assertion.
    #[test]
    fn tool_label_maps_to_pre_lift_lowercase_binary_name() {
        assert_eq!(SubcommandTool::Forge.label(), "forge");
        assert_eq!(SubcommandTool::Nix.label(), "nix");
    }

    /// Structural coloring shield: the primitive body must chain
    /// `.dimmed()` on BOTH the `>>` digraph AND the `joined` argv
    /// expression. Pins the coloring contract that the byte-oracle
    /// above deliberately ignores (colored auto-drops ANSI on
    /// non-TTY writers, so a plain-bytes assertion cannot distinguish
    /// `>>` from `">>".dimmed()` on a stdout-Vec-piped `cargo test`
    /// run). A "just print the digraph plain, it's shorter" cleanup
    /// that drops `.dimmed()` off either span regresses this
    /// assertion before the visual grammar drifts in the terminal.
    ///
    /// The needle scan is bounded to the module body before the
    /// first `#[cfg(test)]` block so this shield's own diagnostic
    /// prose does not false-match itself. The scan is whole-body (not
    /// per-line) because `cargo fmt` may split the `writeln!` across
    /// multiple lines under a wide-arg-list rewrap.
    #[test]
    fn primitive_body_carries_dimmed_on_digraph_and_argv() {
        let source = include_str!("subcommand_invocation.rs");
        let body = crate::test_support::module_body_before_first_cfg_test(
            source,
            "subcommand_invocation.rs",
        );
        assert!(
            body.contains("writeln!"),
            "primitive body must carry a `writeln!` — every subcommand-invocation \
             announce stanza this primitive owns is emitted via `writeln!` against \
             the caller's writer.",
        );
        assert!(
            body.contains("\"   {} {} {}\""),
            "primitive body must carry the exact `\"   {{}} {{}} {{}}\"` three-column \
             format string — three-space indent, digraph slot, label slot, argv slot. \
             A rewrite that folded the columns into two, promoted the indent to four \
             spaces, or hoisted the columns off `writeln!` regresses this assertion.",
        );
        assert!(
            body.contains("\">>\".dimmed()"),
            "primitive body must chain `.dimmed()` on the `>>` digraph — a \
             \"just print the digraph plain, it's shorter\" cleanup that dropped \
             `.dimmed()` here regresses the visual grammar the two pre-lift sites \
             each carried.",
        );
        assert!(
            body.contains("joined.dimmed()"),
            "primitive body must chain `.dimmed()` on the space-joined argv — a \
             cleanup that dropped `.dimmed()` here makes the argv shout louder than \
             the tool-label anchor the operator scans for.",
        );
    }

    /// Caller shield: no source line under `cli/src/commands/` may
    /// spell the pre-lift `println!("   {} <tool> {}", ">>".dimmed(), …)`
    /// inline any more. Every subcommand-invocation announce stanza
    /// in a `run_<tool>_subcommand`-family helper must resolve
    /// through [`print_subcommand_invocation`] so a future palette
    /// adjustment on the digraph, the coloring on either span, the
    /// indent width, or the label position flows to both sites from
    /// one edit.
    ///
    /// The needle rejects any line that co-occurs `">>".dimmed()`
    /// with `.join(" ").dimmed()` — the composite uniquely
    /// identifies the pre-lift subcommand-invocation announce
    /// grammar (the other in-repo `>>`.dimmed() sites in
    /// `product_release.rs` at `run_health_check` and the Phase-1
    /// per-service echo lines carry `.cyan()` or plain `.dimmed()`
    /// on the second span, never a `.join(" ").dimmed()` argv, and
    /// the per-env scope-open stanza lifted onto
    /// `ui::print_env_scope_open` carries `.cyan().bold()` on the
    /// second span).
    #[test]
    fn no_command_module_still_spells_raw_subcommand_invocation_announce() {
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
            if path.file_name().and_then(|n| n.to_str()) == Some("subcommand_invocation.rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).unwrap();
            let hits: Vec<String> = source
                .lines()
                .enumerate()
                .filter(|(_, l)| {
                    let t = l.trim_start();
                    !t.starts_with("//")
                        && l.contains("\">>\".dimmed()")
                        && l.contains(".join(\" \").dimmed()")
                })
                .map(|(i, l)| format!("line {}: {}", i + 1, l.trim()))
                .collect();
            if !hits.is_empty() {
                offenders.push((path, hits));
            }
        }
        assert!(
            offenders.is_empty(),
            "pre-lift `println!(\"   {{}} <tool> {{}}\", \">>\".dimmed(), \
             <argv>.join(\" \").dimmed())` announce stanza(s) survive under \
             `commands/` — route each through \
             `crate::commands::subcommand_invocation::print_subcommand_invocation(\
             <SubcommandTool>, <argv>)` instead:\n{:#?}",
            offenders,
        );
    }
}
