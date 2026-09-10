//! `Screenshots captured:` diagnostic-block section — skip-if-empty
//! header + indented PNG-path list stanza fusion.
//!
//! # Pre-lift census — 2 sibling stanzas across e2e.rs and prerelease.rs
//!
//! Both `commands/e2e.rs::print_failure_diagnostics` (stderr sink,
//! zero-space header indent, 2-space path indent, relative
//! `Path::new("target/screenshots")` dir) and
//! `commands/prerelease.rs::print_e2e_diagnostics` (stdout sink, 3-space
//! header indent, 5-space path indent, `backend_dir.join("target/screenshots")`
//! dir) restated the same 7-line stanza:
//!
//! ```ignore
//! let screenshot_dir = <path expr>;
//! let screenshots = crate::repo::read_dir_files_with_extension(<dir>, "png");
//! if !screenshots.is_empty() {
//!     <println!/eprintln!>("\n<header_indent>Screenshots captured:");
//!     for entry in &screenshots {
//!         <println!/eprintln!>("<path_indent>{}", entry.path().display());
//!     }
//! }
//! ```
//!
//! The two sites differ on three axes:
//!
//! 1. **Sink** — `eprintln!` (stderr, e2e.rs) vs `println!` (stdout,
//!    prerelease.rs). Closed under [`crate::probe_dump::DiagSink`], reused
//!    verbatim from the sibling docker-diagnostic probe family.
//! 2. **Header indent** — `""` (zero, e2e.rs, a top-level failure report)
//!    vs `"   "` (three spaces, prerelease.rs, nested under a
//!    `── E2E Failure Diagnostics ──` block heading). The pre-lift `\n`
//!    prefix lives inside the header line's format literal at both sites
//!    (leading blank-line separator before the section header).
//! 3. **Path indent** — `"  "` (2 spaces, e2e.rs) vs `"     "` (5 spaces,
//!    prerelease.rs). Two more than the header indent at both sites — the
//!    diagnostic-block convention the sibling
//!    [`crate::probe_dump::probe_and_dump_docker_ps_running`] family also
//!    honors — but kept as an explicit parameter here so a future consumer
//!    that wants the same block-section grammar with a different indent
//!    delta is not forced through a rewrite.
//!
//! The skip-if-empty guard, the leading-blank + header + path-list body,
//! and the trailing newline discipline are byte-identical modulo those
//! three axes. This module owns the writer under [`write_screenshots_captured_section`]
//! (testable against a `Vec<u8>` sink) and the read-dir + sink-dispatch
//! fusion under [`probe_and_dump_screenshots_captured_section`], letting
//! each pre-lift site collapse to a single call.

use crate::probe_dump::DiagSink;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// Write the `Screenshots captured:` section body to `w`.
///
/// # Behavior
///
/// - When `paths` is empty, emit **nothing** (no header, no blank line, no
///   trailing newline). This matches the pre-lift `if !screenshots.is_empty()`
///   guard at both sibling sites verbatim: the diagnostic block owns its own
///   blank-line separators between sections, and a section that would print
///   only a bare header with no rows would break the operator's visual
///   scan for populated sections.
/// - When `paths` is non-empty, emit exactly
///   `\n{header_indent}Screenshots captured:\n{path_indent}{p0}\n{path_indent}{p1}\n...`.
///
/// The `header_indent` and `path_indent` parameters accept any leading
/// prefix — the empty string, ASCII spaces (both pre-lift shapes), or a
/// future non-space prefix (`"│  "` for a box-drawing frame) — the writer
/// composes the indent as a leading substring rather than a repeated
/// character, so a mixed-glyph indent flows through without special-casing.
///
/// # Byte oracle
///
/// The emitted bytes are exactly:
///
/// - `b""` on the empty-paths branch,
/// - `b"\n{header_indent}Screenshots captured:\n{path_indent}{p0.display()}\n..."`
///   on the non-empty branch.
///
/// A future drift that dropped the leading blank line, dropped the trailing
/// newline on a path row, or added a glyph before `Screenshots` regresses
/// the tests below.
pub fn write_screenshots_captured_section<W: Write>(
    w: &mut W,
    paths: &[PathBuf],
    header_indent: &str,
    path_indent: &str,
) -> io::Result<()> {
    if paths.is_empty() {
        return Ok(());
    }
    writeln!(w)?;
    writeln!(w, "{header_indent}Screenshots captured:")?;
    for p in paths {
        writeln!(w, "{path_indent}{}", p.display())?;
    }
    Ok(())
}

/// Read every `*.png` entry under `screenshot_dir`, then dispatch
/// [`write_screenshots_captured_section`] against the process's stdout or
/// stderr per `sink`.
///
/// The read step forwards to [`crate::repo::read_dir_files_with_extension`],
/// which returns an empty `Vec` on a missing directory — matching the
/// pre-lift discipline where a nonexistent `target/screenshots` (E2E did
/// not reach the browser-driver step) produces no diagnostic-block noise,
/// not a hard error inside the enclosing failure handler.
///
/// The write result is silently ignored — matching the pre-lift
/// `println!`/`eprintln!` discipline where a broken pipe on the diagnostic
/// stream is not a fatal condition on the surrounding E2E test failure
/// report. Mirrors the sibling
/// [`crate::probe_dump::dump_captured_or_none`] discipline.
pub fn probe_and_dump_screenshots_captured_section(
    screenshot_dir: &Path,
    sink: DiagSink,
    header_indent: &str,
    path_indent: &str,
) {
    let entries = crate::repo::read_dir_files_with_extension(screenshot_dir, "png");
    let paths: Vec<PathBuf> = entries.iter().map(|e| e.path()).collect();
    match sink {
        DiagSink::Stdout => {
            let _ = write_screenshots_captured_section(
                &mut io::stdout().lock(),
                &paths,
                header_indent,
                path_indent,
            );
        }
        DiagSink::Stderr => {
            let _ = write_screenshots_captured_section(
                &mut io::stderr().lock(),
                &paths,
                header_indent,
                path_indent,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── write_screenshots_captured_section — byte oracles ────────────

    /// Byte-oracle: an empty paths slice emits ZERO bytes. Pins the
    /// `if paths.is_empty() { return Ok(()); }` skip guard — a future
    /// drift that emitted just the header line with no paths (or a bare
    /// blank line) would leak a mis-aligned section into the operator's
    /// diagnostic scan and hits this assertion first.
    #[test]
    fn write_screenshots_captured_section_empty_paths_emits_no_bytes() {
        let mut buf: Vec<u8> = Vec::new();
        write_screenshots_captured_section(&mut buf, &[], "", "  ").unwrap();
        assert_eq!(buf, b"", "empty paths must emit zero bytes");
    }

    /// Byte-oracle: matches the pre-lift `commands/e2e.rs::print_failure_diagnostics`
    /// stanza byte-for-byte when `paths` carries two screenshots. Zero
    /// header indent + 2-space path indent = the top-level failure-report
    /// section shape.
    #[test]
    fn write_screenshots_captured_section_e2e_top_level_shape_matches_pre_lift() {
        let mut buf: Vec<u8> = Vec::new();
        let paths = vec![
            PathBuf::from("target/screenshots/test_login.png"),
            PathBuf::from("target/screenshots/test_dashboard.png"),
        ];
        write_screenshots_captured_section(&mut buf, &paths, "", "  ").unwrap();
        assert_eq!(
            buf.as_slice(),
            b"\nScreenshots captured:\n  target/screenshots/test_login.png\n  target/screenshots/test_dashboard.png\n"
        );
    }

    /// Byte-oracle: matches the pre-lift `commands/prerelease.rs::print_e2e_diagnostics`
    /// stanza byte-for-byte when `paths` carries two screenshots. 3-space
    /// header indent + 5-space path indent = the nested-under-block-heading
    /// diagnostic-report section shape.
    #[test]
    fn write_screenshots_captured_section_prerelease_nested_shape_matches_pre_lift() {
        let mut buf: Vec<u8> = Vec::new();
        let paths = vec![
            PathBuf::from("/repo/backend/target/screenshots/checkout_flow.png"),
            PathBuf::from("/repo/backend/target/screenshots/error_modal.png"),
        ];
        write_screenshots_captured_section(&mut buf, &paths, "   ", "     ").unwrap();
        assert_eq!(
            buf.as_slice(),
            b"\n   Screenshots captured:\n     /repo/backend/target/screenshots/checkout_flow.png\n     /repo/backend/target/screenshots/error_modal.png\n"
        );
    }

    /// Byte-oracle: a single path still triggers the header + blank line
    /// prefix. Pins that the guard is `is_empty()`, not `len() < 2`.
    #[test]
    fn write_screenshots_captured_section_single_path_still_emits_header() {
        let mut buf: Vec<u8> = Vec::new();
        let paths = vec![PathBuf::from("target/screenshots/single.png")];
        write_screenshots_captured_section(&mut buf, &paths, "", "  ").unwrap();
        assert_eq!(
            buf.as_slice(),
            b"\nScreenshots captured:\n  target/screenshots/single.png\n"
        );
    }

    /// Byte-oracle: honors `Path::display()` verbatim per row — no
    /// truncation, no quoting, no basename projection. A future refactor
    /// that reached for `entry.file_name()` at the primitive layer
    /// (dropping the parent directory) would regress the operator's
    /// ability to grep the report for the full screenshot path.
    #[test]
    fn write_screenshots_captured_section_forwards_full_path_display_verbatim() {
        let mut buf: Vec<u8> = Vec::new();
        let path = PathBuf::from("/tmp/deep/nested/target/screenshots/scene_42.png");
        let paths = vec![path.clone()];
        write_screenshots_captured_section(&mut buf, &paths, "", "  ").unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(
            out.contains(&format!("{}", path.display())),
            "must contain the full path.display() bytes; got: {out:?}"
        );
    }

    /// Byte-oracle: emits NO ANSI escape (0x1B). The crate's
    /// `tracing_subscriber` init in `main.rs` sets `with_ansi(false)`, and
    /// the diagnostic-block sinks (stdout / stderr) inherit that discipline
    /// — a future refactor that reached for `colored` on the header line
    /// would break the ANSI-free contract downstream CI log ingestion
    /// depends on. Mirrors the sibling
    /// [`crate::using_pod_field::write_using_pod_field`] shield.
    #[test]
    fn write_screenshots_captured_section_emits_no_ansi_escape() {
        let mut buf: Vec<u8> = Vec::new();
        let paths = vec![PathBuf::from("target/screenshots/scene_a.png")];
        write_screenshots_captured_section(&mut buf, &paths, "   ", "     ").unwrap();
        assert!(
            !buf.contains(&0x1b),
            "must emit no ANSI escape (0x1B); got: {buf:?}"
        );
    }

    /// Byte-oracle: an empty header_indent and empty path_indent still
    /// produce a valid section body. Pins that the two indent parameters
    /// are leading prefixes rather than required non-empty tokens — a
    /// future consumer aligning against a zero-indent section (a plain
    /// summary report) does not have to pre-slice or workaround.
    #[test]
    fn write_screenshots_captured_section_empty_indents_emit_bare_body() {
        let mut buf: Vec<u8> = Vec::new();
        let paths = vec![PathBuf::from("a.png"), PathBuf::from("b.png")];
        write_screenshots_captured_section(&mut buf, &paths, "", "").unwrap();
        assert_eq!(buf.as_slice(), b"\nScreenshots captured:\na.png\nb.png\n");
    }

    // ── Caller shields ───────────────────────────────────────────────

    /// Caller shield: no source line under `cli/src/commands/` may spell
    /// the pre-lift raw `Screenshots captured:` header literal inline any
    /// more. The two pre-lift sites (`commands/e2e.rs::print_failure_diagnostics`,
    /// `commands/prerelease.rs::print_e2e_diagnostics`) migrated; any
    /// future consumer that wants the same block section reaches for
    /// [`probe_and_dump_screenshots_captured_section`] on first grep, not
    /// by copy-pasting the raw header + for-loop stanza from an existing
    /// command module.
    #[test]
    fn no_command_module_still_spells_raw_screenshots_captured_header_literal() {
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
                // Skip comment lines so this shield's own reference to
                // the pre-lift shape in prose does not self-hit.
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") || trimmed.starts_with("///") {
                    continue;
                }
                // The narrow needle: the `Screenshots captured:` header
                // literal inside a `println!`/`eprintln!` context.
                // Post-lift the header lives at ONE body inside
                // [`write_screenshots_captured_section`] and no command
                // module carries the literal any more.
                if (line.contains("println!") || line.contains("eprintln!"))
                    && line.contains("Screenshots captured:")
                {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `Screenshots captured:` header stanza(s) survive under \
             `commands/` — route each through \
             `crate::screenshot_diag::probe_and_dump_screenshots_captured_section(...)` \
             instead:\n{:#?}",
            offenders
        );
    }

    /// Positive delegation shield: the two pre-lift files MUST each
    /// forward through [`probe_and_dump_screenshots_captured_section`] at
    /// least once, so a migration that dropped a call site outright leaves
    /// the negative "no raw header" scan trivially satisfied by absence
    /// but the positive count still fails. Mirrors the sibling
    /// [`crate::probe_dump`] positive-half discipline.
    #[test]
    fn every_prelift_module_forwards_through_probe_and_dump_screenshots_captured_section() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let expectations: &[(&str, usize)] = &[("e2e.rs", 1), ("prerelease.rs", 1)];
        let needle = "crate::screenshot_diag::probe_and_dump_screenshots_captured_section(";
        for (basename, min_count) in expectations {
            let path = commands_dir.join(basename);
            let source = std::fs::read_to_string(&path).unwrap();
            let forwards = source.matches(needle).count();
            assert!(
                forwards >= *min_count,
                "{basename} must forward at least {min_count} \
                 `Screenshots captured:` section site(s) through \
                 `crate::screenshot_diag::probe_and_dump_screenshots_captured_section(`; \
                 found {forwards}. A dropped call would leave the negative \
                 raw-header scan satisfied by absence.",
            );
        }
    }
}
