//! `probe_stdout_capture_sync` → `(none)`-or-dump ternary fusion for the
//! docker-diagnostics stanzas.
//!
//! # Pre-lift census — 4 sibling stanzas across e2e.rs and prerelease.rs
//!
//! Both `commands/e2e.rs::print_e2e_failure_diagnostics` (stderr sink,
//! `"  "` indent) and `commands/prerelease.rs::print_e2e_diagnostics_on_failure`
//! (stdout sink, `"     "` indent) each restated the same 6-line stanza
//! twice — once for the "running" `docker ps` probe and once for the
//! "recently exited" `docker ps -a --filter status=exited --since 15m`
//! probe:
//!
//! ```ignore
//! if let Some(stdout) = crate::retry::probe_stdout_capture_sync(
//!     &docker_bin(),
//!     &[…],
//! ) {
//!     if stdout.trim().is_empty() {
//!         eprintln!("  (none)");         // or println!("     (none)");
//!     } else {
//!         eprint!("{}", stdout);         // or print!("{}", stdout);
//!     }
//! }
//! ```
//!
//! The four sites differ in three axes:
//!
//! 1. **Argv** — the exact `docker` sub-command and its `--format`
//!    template.
//! 2. **Sink** — `eprintln!`/`eprint!` (stderr, e2e.rs) vs
//!    `println!`/`print!` (stdout, prerelease.rs). Correlated: the
//!    diagnostics block owns its stream discipline.
//! 3. **Indent** — `"  "` (2 ASCII spaces) or `"     "` (5 ASCII spaces).
//!    Correlated with the docker `--format` template, which embeds the
//!    same indent as its literal leading whitespace.
//!
//! The probe → capture → ternary loop is byte-identical modulo those axes.
//! This module closes the sink under [`DiagSink`] and folds the ternary
//! into the byte-oracle [`write_captured_or_none`], letting each of the
//! four sites collapse to a single call to
//! [`probe_and_dump_or_none_sync`].
//!
//! # The two primitives this module owns
//!
//! - [`write_captured_or_none`] — the pure ternary body writer. Testable
//!   against a `Vec<u8>` sink without spawning `docker`.
//! - [`probe_and_dump_or_none_sync`] — the sync fusion primitive that
//!   spawns the binary via [`crate::retry::probe_stdout_capture_sync`],
//!   silently swallows a probe failure (matching the pre-lift `if let
//!   Some(stdout) = …` convention), and dispatches to the writer against
//!   the sink chosen by [`DiagSink`].

use std::io::{self, Write};

/// Where a diagnostic dump lands.
///
/// The two variants pin the correlated `(println!/eprintln!, print!/
/// eprint!)` pair the pre-lift sibling stanzas carried. A caller does not
/// mix — the diagnostics block chose its stream at the top and the four
/// child stanzas honored that choice; the closed enum makes that choice
/// exhaustive at compile time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagSink {
    /// Process stdout — `println!`/`print!`. Pre-lift site:
    /// `commands/prerelease.rs::print_e2e_diagnostics_on_failure`.
    Stdout,
    /// Process stderr — `eprintln!`/`eprint!`. Pre-lift site:
    /// `commands/e2e.rs::print_e2e_failure_diagnostics`.
    Stderr,
}

/// Write the "(none)"-or-dump ternary body to `w`.
///
/// The pre-lift shape is:
///
/// ```ignore
/// if captured.trim().is_empty() {
///     writeln!(w, "{}(none)", indent)?;
/// } else {
///     write!(w, "{}", captured)?;
/// }
/// ```
///
/// The `.trim().is_empty()` guard matches the pre-lift discipline
/// verbatim: a probe that returned a payload of only ASCII whitespace
/// (`""`, `"\n"`, `"   \n"`) reads as "(none)". The non-empty branch
/// dumps the raw captured bytes with no added newline — the docker
/// `--format` template already includes trailing newlines per row and
/// the pre-lift sites deliberately used `eprint!`/`print!` (no
/// terminator) rather than `eprintln!`/`println!` to avoid doubling
/// the final line break.
///
/// Byte-oracle: the emitted bytes are exactly `{indent}(none)\n` on the
/// empty branch and exactly `{captured}` (verbatim, byte-for-byte) on
/// the non-empty branch, so a future indent, verb, or newline-discipline
/// drift hits the assertion rather than shipping.
pub fn write_captured_or_none<W: Write>(w: &mut W, captured: &str, indent: &str) -> io::Result<()> {
    if captured.trim().is_empty() {
        writeln!(w, "{}(none)", indent)
    } else {
        write!(w, "{}", captured)
    }
}

/// Dispatch [`write_captured_or_none`] against the process's stdout or
/// stderr per `sink`. Silently ignores the write result — matching the
/// pre-lift `println!`/`eprintln!` discipline where a broken pipe on the
/// diagnostics stream is not a fatal condition on the surrounding
/// caller (E2E test failure).
pub fn dump_captured_or_none(captured: &str, sink: DiagSink, indent: &str) {
    match sink {
        DiagSink::Stdout => {
            let _ = write_captured_or_none(&mut io::stdout().lock(), captured, indent);
        }
        DiagSink::Stderr => {
            let _ = write_captured_or_none(&mut io::stderr().lock(), captured, indent);
        }
    }
}

/// Run `bin` with `args` via [`crate::retry::probe_stdout_capture_sync`],
/// then dump the captured stdout to `sink` — printing `"{indent}(none)"`
/// when the capture is whitespace-only. A probe failure (spawn error,
/// non-existent binary) is silently skipped, matching the pre-lift
/// `if let Some(stdout) = …` convention where an unreachable `docker`
/// binary produces no diagnostics rather than a hard error inside the
/// enclosing failure handler.
///
/// The 4 pre-lift sibling stanzas each collapse to a single call to this
/// primitive; a future re-decision on the probe surface (say, retry
/// semantics, a timeout, or a stderr merge) lands in one place.
pub fn probe_and_dump_or_none_sync(bin: &str, args: &[&str], sink: DiagSink, indent: &str) {
    let Some(captured) = crate::retry::probe_stdout_capture_sync(bin, args) else {
        return;
    };
    dump_captured_or_none(&captured, sink, indent);
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── write_captured_or_none — byte-oracle over the ternary ────────

    /// Byte-oracle: an empty capture emits exactly `{indent}(none)\n`.
    /// A future drift to `"(none)\n"` (dropped indent), `"none"`
    /// (dropped parentheses), or `"(none)"` (missing newline) regresses
    /// this.
    #[test]
    fn write_captured_or_none_empty_emits_indent_none_newline() {
        let mut buf = Vec::new();
        write_captured_or_none(&mut buf, "", "  ").expect("write to Vec is infallible");
        assert_eq!(buf, b"  (none)\n");
    }

    /// Byte-oracle: an all-whitespace capture (spaces, newlines, tabs)
    /// still reads as "(none)". `.trim().is_empty()` is the pre-lift
    /// discipline; a future swap to `.is_empty()` would emit the
    /// whitespace verbatim and regress this test.
    #[test]
    fn write_captured_or_none_whitespace_only_emits_none() {
        let mut buf = Vec::new();
        write_captured_or_none(&mut buf, "  \n\t\n", "     ").expect("write to Vec is infallible");
        assert_eq!(buf, b"     (none)\n");
    }

    /// Byte-oracle: a non-empty capture is dumped verbatim, with NO
    /// added leading indent and NO added trailing newline — the docker
    /// `--format` template embeds both. A future drift to `writeln!`
    /// on the non-empty branch would double the trailing newline; this
    /// pins the `write!` discipline.
    #[test]
    fn write_captured_or_none_nonempty_emits_captured_verbatim() {
        let mut buf = Vec::new();
        let captured = "  container-a\trunning\t80/tcp\n  container-b\trunning\t443/tcp\n";
        write_captured_or_none(&mut buf, captured, "  ").expect("write to Vec is infallible");
        assert_eq!(buf.as_slice(), captured.as_bytes());
    }

    /// Byte-oracle: the 5-space indent variant carries the same
    /// discipline as the 2-space one. Pre-lift `prerelease.rs` used
    /// 5 spaces to align under a `"\n   Docker containers (running):"`
    /// header; a future indent change should land through this
    /// parameter rather than a per-caller string constant.
    #[test]
    fn write_captured_or_none_five_space_indent_variant() {
        let mut buf = Vec::new();
        write_captured_or_none(&mut buf, "", "     ").expect("write to Vec is infallible");
        assert_eq!(buf, b"     (none)\n");
    }

    // ── DiagSink shield ──────────────────────────────────────────────

    /// Shield: [`DiagSink`] stays a closed 2-variant enum. A future
    /// third variant (a `Tee` that duplicates the write to both
    /// streams, or a `Buffer` variant for the summary-report frontier)
    /// is a deliberate design decision — this shield forces it through
    /// review rather than sliding in via a defaulted match arm.
    #[test]
    fn diag_sink_stays_closed_two_variants() {
        // Exhaustive match — a new variant regresses compilation here.
        for sink in [DiagSink::Stdout, DiagSink::Stderr] {
            match sink {
                DiagSink::Stdout => (),
                DiagSink::Stderr => (),
            }
        }
    }

    // ── Caller shields ───────────────────────────────────────────────

    /// Caller shield: no source line under `cli/src/commands/` may
    /// spell the pre-lift raw `if stdout.trim().is_empty() { …
    /// "(none)" … } else { … "{}", stdout … }` ternary inline any
    /// more. The four pre-lift sites (`commands/e2e.rs` × 2,
    /// `commands/prerelease.rs` × 2) migrated; any future consumer
    /// that wants the same grammar reaches for
    /// [`probe_and_dump_or_none_sync`] on first grep, not by
    /// copy-pasting the raw ternary from an existing command module.
    #[test]
    fn no_command_module_still_spells_raw_probe_dump_or_none_ternary() {
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
                // Skip comment lines so this shield's own reference
                // to the pre-lift shape in prose does not self-hit.
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") || trimmed.starts_with("///") {
                    continue;
                }
                // The narrow needle: the "(none)" fallback literal is
                // the distinctive marker of the pre-lift ternary — the
                // negated `if !stdout.trim().is_empty() { … }` shape
                // (a different pattern that skips work when empty)
                // lives on unaffected in `commands/flux.rs` and
                // `commands/prerelease.rs`'s stdout-forwarding sites,
                // and this shield deliberately does not fire on it.
                // Every legitimate consumer post-lift routes through
                // [`write_captured_or_none`], where the "(none)"
                // literal lives; a new inline occurrence of the pair
                // (trim predicate AND the "(none)" fallback) on the
                // same line signals a copy-paste regression.
                if line.contains("stdout.trim().is_empty()") && line.contains("(none)") {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
                // The empty branch spelled as a separate `(none)`
                // println/eprintln line (as the pre-lift stanzas
                // wrote it — `eprintln!("  (none)");` on its own line
                // above the `else`) is caught by scanning for the
                // literal in a line whose next non-blank sibling is
                // an `else` — approximated here by matching the
                // `"(none)"` literal in a `println!`/`eprintln!`
                // context on a bare line.
                let literal_forms = [
                    "println!(\"  (none)\")",
                    "println!(\"     (none)\")",
                    "eprintln!(\"  (none)\")",
                    "eprintln!(\"     (none)\")",
                ];
                if literal_forms.iter().any(|needle| line.contains(needle)) {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `stdout.trim().is_empty()` ternary stanza(s) survive \
             under `commands/` — route each through \
             `crate::probe_dump::probe_and_dump_or_none_sync(…)` instead:\n{:#?}",
            offenders
        );
    }

    /// Positive half of the shield: the two pre-lift files MUST each
    /// forward through `crate::probe_dump::probe_and_dump_or_none_sync(`
    /// at least twice, so a migration that dropped a call site outright
    /// leaves the negative "no raw ternary" scan trivially satisfied by
    /// absence but the positive count still fails.
    #[test]
    fn every_prelift_module_forwards_through_probe_and_dump_primitive() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        // (module basename, minimum forward count from the pre-lift
        // census — 2 stanzas per file).
        let expectations: &[(&str, usize)] = &[("e2e.rs", 2), ("prerelease.rs", 2)];
        for (basename, min_count) in expectations {
            let path = commands_dir.join(basename);
            let source = std::fs::read_to_string(&path).unwrap();
            let forwards = source
                .matches("crate::probe_dump::probe_and_dump_or_none_sync(")
                .count();
            assert!(
                forwards >= *min_count,
                "{basename} must forward at least {min_count} probe-dump-or-none \
                 site(s) through `crate::probe_dump::probe_and_dump_or_none_sync(`; \
                 found {forwards}. A dropped call would leave the negative \
                 raw-ternary scan satisfied by absence.",
            );
        }
    }
}
