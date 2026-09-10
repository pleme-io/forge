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

/// Build the docker `--format` template every pre-lift diagnostic
/// caller passed inline: `{indent}{{.Names}}\t{{.Status}}\t{{.<col>}}`.
///
/// Both diagnostic sub-commands ([`probe_and_dump_docker_ps_running`]
/// with `col = "Ports"`, [`probe_and_dump_docker_ps_exited_since_15m`]
/// with `col = "Image"`) share the leading `{{.Names}}\t{{.Status}}\t`
/// prefix and diverge only on the third column — a single template
/// builder pins that shared prefix at ONE body, so a future drift to
/// a different separator (`|`, `;`) or a fourth column
/// (`{{.CreatedAt}}`) reaches both sub-commands from one edit.
///
/// The leading `indent` matches the surrounding section indent every
/// pre-lift caller passed as its own `indent` argument to
/// [`probe_and_dump_or_none_sync`] — docker echoes the template
/// verbatim per row, so aligning the two indents keeps the dumped
/// rows under the section heading.
fn docker_ps_diag_format(indent: &str, third_column: &str) -> String {
    format!("{indent}{{{{.Names}}}}\t{{{{.Status}}}}\t{{{{.{third_column}}}}}")
}

/// Build the docker `images --format` template every pre-lift diagnostic
/// caller spelled inline:
/// `{indent}{{.Repository}}:{{.Tag}}\t{{.Size}}\t{{.<col>}}`.
///
/// Sibling of [`docker_ps_diag_format`]. Three pre-lift consumer sites
/// (`commands/e2e.rs::print_image_info` — 2-space indent × `CreatedSince`
/// third column, `commands/e2e.rs::print_failure_diagnostics` — 2-space
/// indent × `ID`, `commands/prerelease.rs::print_e2e_diagnostics` —
/// 5-space indent × `ID`) each restated the same `docker images --format`
/// template inline with the leading indent, the fixed
/// `{{.Repository}}:{{.Tag}}\t{{.Size}}\t` prefix, and a divergent third
/// column baked into a heredoc-shaped multi-line argv literal.
///
/// The three consumer bodies differ in their command-invocation shape
/// (one uses `Command::new(...).args(...).output()`; the two others use
/// [`crate::retry::probe_stdout_capture_sync`]), in their sink
/// (stdout / stderr / stdout), and in their post-capture filter
/// (`.contains("backend") || .contains("web")` at 2-space sites vs
/// `.contains("-backend") || .contains("-web")` at the 5-space site),
/// so no full fusion primitive fits all three today. The shared
/// `--format` template body IS common across the three, so this
/// builder captures the template alone and each consumer builds
/// its argv around it.
///
/// A future re-decision on the template (a fourth column, a different
/// separator, or a per-column format directive) lands at ONE body here
/// rather than at three sites. `docker` echoes the template verbatim
/// per row, so aligning the `indent` argument with the surrounding
/// section heading keeps the dumped rows visually nested under it —
/// the same discipline [`docker_ps_diag_format`] carries.
///
/// The `third_column` parameter accepts the docker `--format` field
/// name unadorned (`"ID"`, `"CreatedSince"`, `"Size"`, ...); the
/// builder prepends the `{{.` delimiters and appends `}}`. A caller
/// that spelled `"{{.ID}}"` inline would double-wrap the delimiters
/// and produce an invalid template — the byte-oracles below reject
/// exactly that regression class.
pub(crate) fn docker_images_diag_format(indent: &str, third_column: &str) -> String {
    format!("{indent}{{{{.Repository}}}}:{{{{.Tag}}}}\t{{{{.Size}}}}\t{{{{.{third_column}}}}}")
}

/// Diagnostic probe: run `docker ps --format` with the fixed
/// (Names, Status, Ports) three-column table indented by `indent`,
/// dump the captured stdout to `sink`, or emit `"{indent}(none)"`
/// when docker returned no rows. A probe failure (spawn error,
/// non-existent `docker` binary) is silently skipped — same contract
/// as [`probe_and_dump_or_none_sync`].
///
/// # Pre-lift census
///
/// Both `commands/e2e.rs::print_failure_diagnostics` (`DiagSink::Stderr`,
/// `"  "` indent) and `commands/prerelease.rs::print_e2e_diagnostics`
/// (`DiagSink::Stdout`, `"     "` indent) restated the same 6-line
/// [`probe_and_dump_or_none_sync`] stanza with a copy-pasted
/// `"{indent}{{.Names}}\t{{.Status}}\t{{.Ports}}"` `--format` template
/// — two sites past THEORY §VI.1's recurring-shape threshold when
/// paired with the sibling [`probe_and_dump_docker_ps_exited_since_15m`]
/// (four docker-ps diagnostic stanzas total sharing the same
/// three-column template family). Post-lift each site collapses to a
/// single call to one of the two typed fusion primitives, and the
/// `--format` template lives at ONE body inside [`docker_ps_diag_format`].
pub fn probe_and_dump_docker_ps_running(docker_bin: &str, sink: DiagSink, indent: &str) {
    let template = docker_ps_diag_format(indent, "Ports");
    probe_and_dump_or_none_sync(docker_bin, &["ps", "--format", &template], sink, indent);
}

/// Diagnostic probe: run `docker ps -a --filter status=exited
/// --since 15m --format` with the fixed (Names, Status, Image)
/// three-column table indented by `indent`, dump the captured
/// stdout to `sink`, or emit `"{indent}(none)"` when docker returned
/// no rows. Sibling of [`probe_and_dump_docker_ps_running`], same
/// contract on spawn-failure (silent skip) and same
/// (Names, Status, `<3rd>`) template family.
///
/// The `--since 15m` window matches the pre-lift discipline both
/// diagnostic callers spelled inline; a future adjustment to the
/// retention horizon (`5m` for a faster CI hop, `1h` for slower
/// e2e stacks) lands at this one body rather than at two sites.
pub fn probe_and_dump_docker_ps_exited_since_15m(docker_bin: &str, sink: DiagSink, indent: &str) {
    let template = docker_ps_diag_format(indent, "Image");
    probe_and_dump_or_none_sync(
        docker_bin,
        &[
            "ps",
            "-a",
            "--filter",
            "status=exited",
            "--since",
            "15m",
            "--format",
            &template,
        ],
        sink,
        indent,
    );
}

/// Section header preceding an E2E-failure-diagnostic probe dump.
///
/// # Pre-lift census — 6 sibling stanzas across e2e.rs and prerelease.rs
///
/// Both `commands/e2e.rs::print_failure_diagnostics` (stderr sink,
/// `""` indent) and `commands/prerelease.rs::print_e2e_diagnostics`
/// (stdout sink, `"   "` indent) each restated the same three
/// `<println|eprintln>!("\n<indent><label>:")` header lines above the
/// docker-ps-running / docker-ps-exited / docker-images probe dumps —
/// three labels × two files = 6 stanzas diverging only on
/// (sink, indent, label).
///
/// The three labels each precede a fixed probe pair the wider
/// diagnostics block owns:
///
/// | variant                          | precedes                                                   |
/// | -------------------------------- | ---------------------------------------------------------- |
/// | `DockerContainersRunning`        | [`probe_and_dump_docker_ps_running`]                       |
/// | `DockerContainersRecentlyExited` | [`probe_and_dump_docker_ps_exited_since_15m`]              |
/// | `E2eDockerImages`                | inline `docker images --format` capture-and-filter loop    |
///
/// The closed 3-variant enum makes the label choice exhaustive at
/// compile time; a caller cannot spell a fourth section title without
/// adding a variant. Sibling of [`DiagSink`] in intent — both close a
/// small discrete axis of the diagnostics block's shape at the type
/// level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagSectionHeader {
    /// `"Docker containers (running)"` — the label above the running
    /// `docker ps` probe. Pre-lift sites:
    /// `commands/e2e.rs::print_failure_diagnostics` (`""` indent,
    /// stderr) and `commands/prerelease.rs::print_e2e_diagnostics`
    /// (`"   "` indent, stdout).
    DockerContainersRunning,
    /// `"Docker containers (recently exited)"` — the label above the
    /// `docker ps -a --filter status=exited --since 15m` probe. Pre-lift
    /// sites: same two files as the sibling variant above.
    DockerContainersRecentlyExited,
    /// `"E2E Docker images"` — the label above the `docker images
    /// --format` capture-and-filter loop. Pre-lift sites: same two
    /// files as the sibling variants above.
    E2eDockerImages,
}

impl DiagSectionHeader {
    /// The literal English label rendered inside the section header.
    ///
    /// Correlated-adjective projection: each variant maps to exactly
    /// one `&'static str`, byte-oracle-pinned by the tests below.
    /// A future re-word (say, `"Docker containers (still running)"`)
    /// lands at this one match rather than at six caller sites.
    pub fn label(self) -> &'static str {
        match self {
            Self::DockerContainersRunning => "Docker containers (running)",
            Self::DockerContainersRecentlyExited => "Docker containers (recently exited)",
            Self::E2eDockerImages => "E2E Docker images",
        }
    }
}

/// Write the section-header stanza to `w`.
///
/// The pre-lift shape at both `println!`/`eprintln!` variants is:
///
/// ```ignore
/// println!("\n{indent}{label}:");   // or eprintln!, per sink
/// ```
///
/// The `println!`/`eprintln!` macro appends a trailing newline, so the
/// on-the-wire bytes are exactly `\n{indent}{label}:\n` — a leading
/// blank line (visual separator from the preceding block), the caller's
/// `indent`, the label, a trailing colon, then the terminator. This
/// byte-oracle pins that entire form.
///
/// Testable against a `Vec<u8>` sink without touching stdout/stderr.
pub fn write_diag_section_header<W: Write>(
    w: &mut W,
    indent: &str,
    header: DiagSectionHeader,
) -> io::Result<()> {
    writeln!(w, "\n{}{}:", indent, header.label())
}

/// Dispatch [`write_diag_section_header`] against the process's stdout
/// or stderr per `sink`. Silently ignores the write result — matching
/// the pre-lift `println!`/`eprintln!` discipline where a broken pipe
/// on the diagnostics stream is not a fatal condition on the
/// surrounding caller (E2E test failure). Sibling of
/// [`dump_captured_or_none`] in intent.
pub fn print_diag_section_header(sink: DiagSink, indent: &str, header: DiagSectionHeader) {
    match sink {
        DiagSink::Stdout => {
            let _ = write_diag_section_header(&mut io::stdout().lock(), indent, header);
        }
        DiagSink::Stderr => {
            let _ = write_diag_section_header(&mut io::stderr().lock(), indent, header);
        }
    }
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
    /// forward through the shared probe-dump primitive family
    /// (`probe_and_dump_or_none_sync` OR one of the specialized
    /// docker-ps wrappers below) at least twice, so a migration that
    /// dropped a call site outright leaves the negative "no raw
    /// ternary" scan trivially satisfied by absence but the positive
    /// count still fails.
    ///
    /// Both new specialized wrappers ([`probe_and_dump_docker_ps_running`],
    /// [`probe_and_dump_docker_ps_exited_since_15m`]) delegate through
    /// [`probe_and_dump_or_none_sync`] internally, so a caller that
    /// spells the specialized name still routes through the shared
    /// `(none)`-or-dump ternary at the byte level — the count floor
    /// accepts either shape as a valid delegation.
    #[test]
    fn every_prelift_module_forwards_through_probe_and_dump_primitive() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        // (module basename, minimum forward count from the pre-lift
        // census — 2 stanzas per file).
        let expectations: &[(&str, usize)] = &[("e2e.rs", 2), ("prerelease.rs", 2)];
        let needles: &[&str] = &[
            "crate::probe_dump::probe_and_dump_or_none_sync(",
            "crate::probe_dump::probe_and_dump_docker_ps_running(",
            "crate::probe_dump::probe_and_dump_docker_ps_exited_since_15m(",
        ];
        for (basename, min_count) in expectations {
            let path = commands_dir.join(basename);
            let source = std::fs::read_to_string(&path).unwrap();
            let forwards: usize = needles.iter().map(|n| source.matches(n).count()).sum();
            assert!(
                forwards >= *min_count,
                "{basename} must forward at least {min_count} probe-dump-or-none \
                 site(s) through one of \
                 `crate::probe_dump::probe_and_dump_or_none_sync(` or its \
                 specialized docker-ps wrappers \
                 (`probe_and_dump_docker_ps_running`, \
                 `probe_and_dump_docker_ps_exited_since_15m`); \
                 found {forwards}. A dropped call would leave the negative \
                 raw-ternary scan satisfied by absence.",
            );
        }
    }

    // ── docker_ps_diag_format — byte-oracle over the shared template ──

    /// Byte-oracle: [`docker_ps_diag_format`] with the pre-lift
    /// 2-space indent and `"Ports"` third column emits the byte-form
    /// `commands/e2e.rs::print_failure_diagnostics` spelled inline
    /// pre-lift, verbatim. A drift that changed the separator from
    /// TAB to any other byte, or that reordered the columns, regresses
    /// this assertion — both hidden failure modes at the docker-ps
    /// consumer where the column ordering is a load-bearing contract
    /// downstream parsers rely on.
    #[test]
    fn docker_ps_diag_format_two_space_indent_ports_matches_pre_lift() {
        let template = docker_ps_diag_format("  ", "Ports");
        assert_eq!(template, "  {{.Names}}\t{{.Status}}\t{{.Ports}}");
    }

    /// Byte-oracle: [`docker_ps_diag_format`] with the pre-lift
    /// 5-space indent and `"Image"` third column emits the byte-form
    /// `commands/prerelease.rs::print_e2e_diagnostics` spelled inline
    /// pre-lift for the `docker ps -a --filter status=exited --since
    /// 15m --format` sub-command, verbatim.
    #[test]
    fn docker_ps_diag_format_five_space_indent_image_matches_pre_lift() {
        let template = docker_ps_diag_format("     ", "Image");
        assert_eq!(template, "     {{.Names}}\t{{.Status}}\t{{.Image}}");
    }

    /// Byte-oracle: [`docker_ps_diag_format`] with an empty indent
    /// still emits the fixed three-column template — pins that the
    /// indent parameter is a leading prefix rather than a required
    /// non-empty token, so a future caller aligning against a
    /// zero-indent section heading (a top-level failure report) does
    /// not have to pre-slice or workaround.
    #[test]
    fn docker_ps_diag_format_empty_indent_emits_bare_template() {
        assert_eq!(
            docker_ps_diag_format("", "Ports"),
            "{{.Names}}\t{{.Status}}\t{{.Ports}}"
        );
    }

    /// Caller shield: no source line under `cli/src/commands/` may
    /// spell either of the two pre-lift docker-ps `--format` template
    /// literals inline any more. The four pre-lift sites
    /// (`commands/e2e.rs` × 2, `commands/prerelease.rs` × 2) migrated;
    /// any future consumer that wants the same three-column diagnostic
    /// template reaches for one of the specialized docker-ps wrappers
    /// (which route through [`docker_ps_diag_format`] internally) on
    /// first grep, not by copy-pasting the raw literal from an
    /// existing command module. Mirrors the negative half of the
    /// sibling `no_command_module_still_spells_raw_probe_dump_or_none_ternary`
    /// shield above.
    #[test]
    fn no_command_module_still_spells_raw_docker_ps_diag_format_literal() {
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
                // Anchor on the fixed `{{.Names}}\t{{.Status}}\t` head
                // that both pre-lift template shapes share, plus one
                // of the two third-column variants — a stanza that
                // spelled the pre-lift template verbatim always carried
                // this exact sequence, and no post-lift consumer will
                // (the typed primitives own the template inside their
                // bodies, generated at runtime via `format!`).
                if line.contains("{{.Names}}\\t{{.Status}}\\t{{.Ports}}")
                    || line.contains("{{.Names}}\\t{{.Status}}\\t{{.Image}}")
                {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw docker-ps `--format` template literal(s) survive \
             under `commands/` — route each through \
             `crate::probe_dump::probe_and_dump_docker_ps_running(...)` \
             or `crate::probe_dump::probe_and_dump_docker_ps_exited_since_15m(...)` \
             instead:\n{:#?}",
            offenders
        );
    }

    // ── docker_images_diag_format — byte-oracle over the shared template ─

    /// Byte-oracle: [`docker_images_diag_format`] with the pre-lift
    /// 2-space indent and `"CreatedSince"` third column emits the byte-form
    /// `commands/e2e.rs::print_image_info` spelled inline pre-lift,
    /// verbatim. Regressions caught: a swap from TAB to another
    /// separator, a reorder of the `Repository:Tag` / `Size` / `<3rd>`
    /// column triple, or a change in the `Repository:Tag` colon
    /// separator that hides the repository+tag pair from the downstream
    /// filter.
    #[test]
    fn docker_images_diag_format_two_space_indent_created_since_matches_pre_lift() {
        let template = docker_images_diag_format("  ", "CreatedSince");
        assert_eq!(
            template,
            "  {{.Repository}}:{{.Tag}}\t{{.Size}}\t{{.CreatedSince}}"
        );
    }

    /// Byte-oracle: [`docker_images_diag_format`] with the pre-lift
    /// 2-space indent and `"ID"` third column matches the byte-form
    /// `commands/e2e.rs::print_failure_diagnostics` spelled inline
    /// pre-lift. Distinct sibling case to
    /// [`docker_images_diag_format_two_space_indent_created_since_matches_pre_lift`]:
    /// the two together pin that the `third_column` axis is honored
    /// (a builder that hard-coded `ID` and ignored the parameter would
    /// pass the ID sibling but fail this test's `CreatedSince` peer).
    #[test]
    fn docker_images_diag_format_two_space_indent_id_matches_pre_lift() {
        let template = docker_images_diag_format("  ", "ID");
        assert_eq!(template, "  {{.Repository}}:{{.Tag}}\t{{.Size}}\t{{.ID}}");
    }

    /// Byte-oracle: [`docker_images_diag_format`] with the pre-lift
    /// 5-space indent and `"ID"` third column matches the byte-form
    /// `commands/prerelease.rs::print_e2e_diagnostics` spelled inline
    /// pre-lift. Sibling to the two-space case above; the two together
    /// pin the `indent` axis is honored independently of the
    /// `third_column` axis.
    #[test]
    fn docker_images_diag_format_five_space_indent_id_matches_pre_lift() {
        let template = docker_images_diag_format("     ", "ID");
        assert_eq!(
            template,
            "     {{.Repository}}:{{.Tag}}\t{{.Size}}\t{{.ID}}"
        );
    }

    /// Byte-oracle: [`docker_images_diag_format`] with an empty indent
    /// still emits the fixed three-column template — pins that the
    /// indent parameter is a leading prefix rather than a required
    /// non-empty token, mirroring the empty-indent case for the
    /// docker-ps sibling above. A future consumer aligning against a
    /// zero-indent section heading (a top-level failure report) does
    /// not have to pre-slice or workaround.
    #[test]
    fn docker_images_diag_format_empty_indent_emits_bare_template() {
        assert_eq!(
            docker_images_diag_format("", "ID"),
            "{{.Repository}}:{{.Tag}}\t{{.Size}}\t{{.ID}}"
        );
    }

    /// Caller shield: no source line under `cli/src/commands/` may
    /// spell any of the three pre-lift `docker images --format`
    /// template literals inline any more. The three pre-lift sites
    /// (`commands/e2e.rs::print_image_info`,
    /// `commands/e2e.rs::print_failure_diagnostics`,
    /// `commands/prerelease.rs::print_e2e_diagnostics`) migrated onto
    /// [`docker_images_diag_format`]; any future consumer that wants
    /// the same three-column diagnostic template reaches for that
    /// builder on first grep, not by copy-pasting the raw literal from
    /// an existing command module. Mirrors the negative half of the
    /// sibling `no_command_module_still_spells_raw_docker_ps_diag_format_literal`
    /// shield above.
    #[test]
    fn no_command_module_still_spells_raw_docker_images_diag_format_literal() {
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
                // Anchor on the fixed `{{.Repository}}:{{.Tag}}\t{{.Size}}\t`
                // head that all three pre-lift template shapes share,
                // plus one of the two third-column variants observed in
                // the pre-lift census — a stanza that spelled the
                // pre-lift template verbatim always carried this exact
                // sequence, and no post-lift consumer will (the typed
                // primitive owns the template inside its body, generated
                // at runtime via `format!`).
                if line.contains("{{.Repository}}:{{.Tag}}\\t{{.Size}}\\t{{.ID}}")
                    || line.contains("{{.Repository}}:{{.Tag}}\\t{{.Size}}\\t{{.CreatedSince}}")
                {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `docker images --format` template literal(s) survive \
             under `commands/` — route each through \
             `crate::probe_dump::docker_images_diag_format(indent, third_column)` \
             instead:\n{:#?}",
            offenders
        );
    }

    /// Positive delegation shield: the two pre-lift files MUST forward
    /// through [`docker_images_diag_format`] at least as many times as
    /// the pre-lift census demanded (`e2e.rs` × 2 sites,
    /// `prerelease.rs` × 1 site). A migration that dropped a call site
    /// outright — leaving the negative "no raw template" scan trivially
    /// satisfied by absence — regresses this floor. Mirrors the sibling
    /// `every_prelift_module_forwards_through_probe_and_dump_primitive`
    /// positive-half discipline.
    #[test]
    fn every_prelift_module_forwards_through_docker_images_diag_format() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let expectations: &[(&str, usize)] = &[("e2e.rs", 2), ("prerelease.rs", 1)];
        let needle = "crate::probe_dump::docker_images_diag_format(";
        for (basename, min_count) in expectations {
            let path = commands_dir.join(basename);
            let source = std::fs::read_to_string(&path).unwrap();
            let forwards = source.matches(needle).count();
            assert!(
                forwards >= *min_count,
                "{basename} must forward at least {min_count} \
                 `docker images --format` template site(s) through \
                 `crate::probe_dump::docker_images_diag_format(...)`; found \
                 {forwards}. A dropped call would leave the negative \
                 raw-template scan satisfied by absence.",
            );
        }
    }

    // ── DiagSectionHeader — byte-oracle over label projections ────────

    /// Byte-oracle: `DockerContainersRunning.label()` renders exactly
    /// the pre-lift English label `commands/e2e.rs::print_failure_diagnostics`
    /// and `commands/prerelease.rs::print_e2e_diagnostics` both spelled
    /// inline pre-lift. A future re-word (a dropped parenthetical, a
    /// swap to `still running`, a colon inside the label) regresses
    /// this assertion.
    #[test]
    fn diag_section_header_docker_containers_running_label_matches_pre_lift() {
        assert_eq!(
            DiagSectionHeader::DockerContainersRunning.label(),
            "Docker containers (running)"
        );
    }

    /// Byte-oracle: `DockerContainersRecentlyExited.label()` renders
    /// exactly the pre-lift English label for the `docker ps -a --filter
    /// status=exited --since 15m` diagnostic section. Sibling of the
    /// `DockerContainersRunning` byte-oracle above; the two together
    /// pin that the label axis is honored per-variant (a projection
    /// that hard-coded one label and ignored the discriminant would
    /// pass one and fail the other).
    #[test]
    fn diag_section_header_docker_containers_recently_exited_label_matches_pre_lift() {
        assert_eq!(
            DiagSectionHeader::DockerContainersRecentlyExited.label(),
            "Docker containers (recently exited)"
        );
    }

    /// Byte-oracle: `E2eDockerImages.label()` renders exactly the
    /// pre-lift English label for the `docker images --format`
    /// diagnostic section. Third sibling to the two docker-containers
    /// byte-oracles above; the three together fix the closed-enum's
    /// full label surface at the byte level.
    #[test]
    fn diag_section_header_e2e_docker_images_label_matches_pre_lift() {
        assert_eq!(
            DiagSectionHeader::E2eDockerImages.label(),
            "E2E Docker images"
        );
    }

    /// Shield: the three [`DiagSectionHeader`] variants each render a
    /// distinct label. A future addition that accidentally aliased two
    /// discriminants onto the same string (a copy-paste that dropped
    /// the discriminating adjective) would collapse two visually
    /// distinct diagnostic sections in the failure report — this shield
    /// makes the collapse a hard test failure. Complements the three
    /// per-variant byte-oracles above.
    #[test]
    fn diag_section_header_labels_are_pairwise_distinct() {
        use std::collections::HashSet;
        let labels: HashSet<&'static str> = [
            DiagSectionHeader::DockerContainersRunning.label(),
            DiagSectionHeader::DockerContainersRecentlyExited.label(),
            DiagSectionHeader::E2eDockerImages.label(),
        ]
        .into_iter()
        .collect();
        assert_eq!(
            labels.len(),
            3,
            "DiagSectionHeader variants must render pairwise-distinct labels; found: {:?}",
            labels,
        );
    }

    /// Shield: [`DiagSectionHeader`] stays a closed 3-variant enum.
    /// A future fourth section (`"Node pod events"`, `"Flux
    /// reconciliation status"`, `"E2E screenshots"`) is a deliberate
    /// design decision — this shield forces it through review rather
    /// than sliding in via a defaulted match arm. Mirrors the sibling
    /// `diag_sink_stays_closed_two_variants` shield above.
    #[test]
    fn diag_section_header_stays_closed_three_variants() {
        for header in [
            DiagSectionHeader::DockerContainersRunning,
            DiagSectionHeader::DockerContainersRecentlyExited,
            DiagSectionHeader::E2eDockerImages,
        ] {
            match header {
                DiagSectionHeader::DockerContainersRunning => (),
                DiagSectionHeader::DockerContainersRecentlyExited => (),
                DiagSectionHeader::E2eDockerImages => (),
            }
        }
    }

    // ── write_diag_section_header — byte-oracle over the emitted stanza ─

    /// Byte-oracle: `write_diag_section_header` with the pre-lift
    /// `"   "` (3-space) indent and `DockerContainersRunning` variant
    /// emits exactly `"\n   Docker containers (running):\n"` — the
    /// byte form `commands/prerelease.rs::print_e2e_diagnostics`
    /// spelled inline pre-lift as `println!("\n   Docker containers
    /// (running):")`. A future drift that dropped the leading `\n`
    /// (removing the visual separator), the trailing `\n` (missing
    /// terminator), or the trailing `:` (unlabeled section) regresses
    /// this test.
    #[test]
    fn write_diag_section_header_three_space_indent_running_matches_pre_lift() {
        let mut buf = Vec::new();
        write_diag_section_header(&mut buf, "   ", DiagSectionHeader::DockerContainersRunning)
            .expect("write to Vec is infallible");
        assert_eq!(buf, b"\n   Docker containers (running):\n");
    }

    /// Byte-oracle: `write_diag_section_header` with an empty indent
    /// and `DockerContainersRecentlyExited` variant emits exactly
    /// `"\nDocker containers (recently exited):\n"` — the byte form
    /// `commands/e2e.rs::print_failure_diagnostics` spelled inline
    /// pre-lift as `eprintln!("\nDocker containers (recently exited):")`.
    /// Distinct sibling case to the three-space-indent + running one
    /// above: the two together pin that both the `indent` and the
    /// `header` axes are honored independently (a writer that
    /// hard-coded either axis would pass one and fail the other).
    #[test]
    fn write_diag_section_header_empty_indent_recently_exited_matches_pre_lift() {
        let mut buf = Vec::new();
        write_diag_section_header(
            &mut buf,
            "",
            DiagSectionHeader::DockerContainersRecentlyExited,
        )
        .expect("write to Vec is infallible");
        assert_eq!(buf, b"\nDocker containers (recently exited):\n");
    }

    /// Byte-oracle: `write_diag_section_header` with the `"   "` indent
    /// and `E2eDockerImages` variant emits exactly `"\n   E2E Docker
    /// images:\n"` — the byte form `commands/prerelease.rs::print_e2e_diagnostics`
    /// spelled inline pre-lift as `println!("\n   E2E Docker images:")`.
    /// Third-axis-crossing byte-oracle: pairs the 3-space indent with
    /// the third variant, so the three per-variant byte-oracles and
    /// the two-indent axis together cover both dimensions.
    #[test]
    fn write_diag_section_header_three_space_indent_e2e_images_matches_pre_lift() {
        let mut buf = Vec::new();
        write_diag_section_header(&mut buf, "   ", DiagSectionHeader::E2eDockerImages)
            .expect("write to Vec is infallible");
        assert_eq!(buf, b"\n   E2E Docker images:\n");
    }

    /// Byte-oracle: `write_diag_section_header` with an empty indent
    /// and `E2eDockerImages` variant emits exactly `"\nE2E Docker
    /// images:\n"` — the byte form `commands/e2e.rs::print_failure_diagnostics`
    /// spelled inline pre-lift as `eprintln!("\nE2E Docker images:")`.
    /// Sibling of the three-space + E2eDockerImages case above; the
    /// two together pin the empty-vs-nonempty indent branch at the
    /// same variant.
    #[test]
    fn write_diag_section_header_empty_indent_e2e_images_matches_pre_lift() {
        let mut buf = Vec::new();
        write_diag_section_header(&mut buf, "", DiagSectionHeader::E2eDockerImages)
            .expect("write to Vec is infallible");
        assert_eq!(buf, b"\nE2E Docker images:\n");
    }

    /// Byte-oracle: `write_diag_section_header` with an empty indent
    /// and `DockerContainersRunning` variant emits exactly
    /// `"\nDocker containers (running):\n"` — the byte form
    /// `commands/e2e.rs::print_failure_diagnostics` spelled inline
    /// pre-lift as `eprintln!("\nDocker containers (running):")`.
    /// Ties off the (indent × header) matrix at the empty-indent /
    /// running pair, so all four (indent × header) combinations the
    /// pre-lift census carries are byte-oracle-pinned.
    #[test]
    fn write_diag_section_header_empty_indent_running_matches_pre_lift() {
        let mut buf = Vec::new();
        write_diag_section_header(&mut buf, "", DiagSectionHeader::DockerContainersRunning)
            .expect("write to Vec is infallible");
        assert_eq!(buf, b"\nDocker containers (running):\n");
    }

    /// Byte-oracle: `write_diag_section_header` with the `"   "` indent
    /// and `DockerContainersRecentlyExited` variant emits exactly
    /// `"\n   Docker containers (recently exited):\n"` — the byte form
    /// `commands/prerelease.rs::print_e2e_diagnostics` spelled inline
    /// pre-lift as `println!("\n   Docker containers (recently exited):")`.
    /// Ties off the (indent × header) matrix at the three-space-indent /
    /// recently-exited pair, so all four (indent × header) combinations
    /// the pre-lift census carries are byte-oracle-pinned.
    #[test]
    fn write_diag_section_header_three_space_indent_recently_exited_matches_pre_lift() {
        let mut buf = Vec::new();
        write_diag_section_header(
            &mut buf,
            "   ",
            DiagSectionHeader::DockerContainersRecentlyExited,
        )
        .expect("write to Vec is infallible");
        assert_eq!(buf, b"\n   Docker containers (recently exited):\n");
    }

    // ── Caller shields — negative + positive ─────────────────────────

    /// Caller shield: no source line under `cli/src/commands/` may
    /// spell any of the six pre-lift `<println|eprintln>!("\n<indent>
    /// <label>:")` diagnostic-section-header literals inline any more.
    /// The six pre-lift sites (`commands/e2e.rs` × 3,
    /// `commands/prerelease.rs` × 3) migrated onto
    /// [`print_diag_section_header`]; any future consumer that wants
    /// the same section-header stanza reaches for the typed primitive
    /// on first grep, not by copy-pasting a raw literal from an
    /// existing command module. Mirrors the negative-half discipline
    /// of the sibling `no_command_module_still_spells_raw_docker_ps_diag_format_literal`
    /// and `no_command_module_still_spells_raw_probe_dump_or_none_ternary`
    /// shields above.
    #[test]
    fn no_command_module_still_spells_raw_diag_section_header_literal() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        // The six pre-lift needles — three labels × two indent/sink
        // combinations. Anchoring on the full literal (leading `\n`,
        // indent, label, trailing `:` inside the string, and the
        // closing `")` triple) pins the pre-lift shape exactly; a
        // post-lift caller either forwards through
        // `print_diag_section_header(...)` or spells a different label
        // (which is a new-variant decision, gated by the closed-enum
        // shield above).
        let literal_forms = [
            r#"println!("\n   Docker containers (running):")"#,
            r#"println!("\n   Docker containers (recently exited):")"#,
            r#"println!("\n   E2E Docker images:")"#,
            r#"eprintln!("\nDocker containers (running):")"#,
            r#"eprintln!("\nDocker containers (recently exited):")"#,
            r#"eprintln!("\nE2E Docker images:")"#,
        ];
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
                if literal_forms.iter().any(|needle| line.contains(needle)) {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `<println|eprintln>!(\"\\n<indent><label>:\")` diagnostic-\
             section-header literal(s) survive under `commands/` — route \
             each through `crate::probe_dump::print_diag_section_header(\
             <sink>, <indent>, crate::probe_dump::DiagSectionHeader::<variant>)` \
             instead:\n{:#?}",
            offenders
        );
    }

    /// Positive delegation shield: the two pre-lift files MUST forward
    /// through [`print_diag_section_header`] at least as many times as
    /// the pre-lift census demanded (`e2e.rs` × 3 sites,
    /// `prerelease.rs` × 3 sites). A migration that dropped a call
    /// site outright — leaving the negative "no raw header literal"
    /// scan trivially satisfied by absence — regresses this floor.
    /// Mirrors the sibling
    /// `every_prelift_module_forwards_through_probe_and_dump_primitive`
    /// positive-half discipline.
    #[test]
    fn every_prelift_module_forwards_through_print_diag_section_header() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let expectations: &[(&str, usize)] = &[("e2e.rs", 3), ("prerelease.rs", 3)];
        let needle = "crate::probe_dump::print_diag_section_header(";
        for (basename, min_count) in expectations {
            let path = commands_dir.join(basename);
            let source = std::fs::read_to_string(&path).unwrap();
            let forwards = source.matches(needle).count();
            assert!(
                forwards >= *min_count,
                "{basename} must forward at least {min_count} diagnostic-\
                 section-header site(s) through \
                 `crate::probe_dump::print_diag_section_header(...)`; \
                 found {forwards}. A dropped call would leave the negative \
                 raw-header-literal scan satisfied by absence.",
            );
        }
    }
}
