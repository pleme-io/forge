//! `docker images` stdout → `"backend" | "web"` substring-filter →
//! sink-dispatched line-print grammar for the two E2E docker-images
//! diagnostic surfaces in `commands/e2e.rs`.
//!
//! # Pre-lift census — 2 sibling stanzas, one substring-filter grammar
//!
//! Both `commands/e2e.rs::print_image_info` (Loaded-images list, `stdout`
//! sink) and `commands/e2e.rs::print_failure_diagnostics` (E2E docker-
//! images failure-diagnostics section, `stderr` sink) each restated the
//! same 5-line stanza verbatim modulo the sink macro:
//!
//! ```ignore
//! // commands/e2e.rs::print_image_info (~L1076-1080), stdout sink
//! for line in stdout.lines() {
//!     if line.contains("backend") || line.contains("web") {
//!         println!("{}", line);
//!     }
//! }
//!
//! // commands/e2e.rs::print_failure_diagnostics (~L1126-1130), stderr sink
//! for line in stdout.lines() {
//!     if line.contains("backend") || line.contains("web") {
//!         eprintln!("{}", line);
//!     }
//! }
//! ```
//!
//! The two sites differ in exactly one axis — the sink macro
//! (`println!`/`eprintln!`) — and both consume the docker-images stdout
//! payload produced by the sibling `crate::probe_dump::
//! docker_images_diag_format(...)` template that the surrounding
//! diagnostic block spawns.
//!
//! The filter itself is a byte-for-byte-identical predicate: a line
//! survives iff its raw bytes contain either the ASCII substring
//! `"backend"` OR the ASCII substring `"web"`. That predicate is the
//! load-bearing shape both call sites named at the "E2E-relevant image
//! rows only" boundary — the wider docker-images table (postgres,
//! kenshi, otel, everything else in the local registry) is filtered out
//! of the diagnostic stream at exactly this substring pair.
//!
//! Post-lift both sites collapse to a single call to
//! [`print_e2e_docker_images_backend_or_web_lines`], parameterized by
//! the sink chosen via the pre-existing closed [`crate::probe_dump::
//! DiagSink`] enum — the same enum every other `commands/e2e.rs::
//! print_failure_diagnostics` sub-section threads through the sibling
//! `probe_dump` primitives (`probe_and_dump_docker_ps_running`,
//! `probe_and_dump_docker_ps_exited_since_15m`,
//! `probe_and_dump_screenshots_captured_section`), so the two lifted
//! sites join the same sink-dispatch discipline the surrounding
//! diagnostic block already reads from.
//!
//! # Why a substring match, not a word-boundary anchor
//!
//! The pre-lift sites deliberately used a substring match: the `docker
//! images` `--format` template feeds the primitive rows whose
//! `Repository` column can carry a namespace prefix (`kenshi-web`,
//! `pleme-web`, `<registry>/backend-image`) and the E2E diagnostic
//! wants each of those rows to surface. A word-boundary anchor would
//! silently drop namespaced or hyphenated image names the pre-lift
//! diagnostic did surface — a behavioral drift, not an improvement.
//! The primitive keeps the substring semantics by construction.
//!
//! # THEORY grounding
//!
//! THEORY.md §II Language — typed primitives own boundary
//! classification; the "E2E-relevant docker-image row" filter is named
//! at ONE typed primitive site instead of restated at each diagnostic
//! sub-section that emits filtered rows. THEORY.md §VI.1 one-oracle —
//! a future refinement of the filter grammar (a third substring, a
//! configurable predicate list, a swap to a compiled regex) lands at
//! this one primitive rather than at each `commands/e2e.rs` call site
//! independently. THEORY.md §V.4 Phase 1 attestation — the sink
//! dispatch is the same closed [`crate::probe_dump::DiagSink`] enum
//! the surrounding docker-diagnostic sub-sections read, so a future
//! record-shape addition (e.g. a `DiagSink::Buffered(Vec<u8>)` variant
//! for structured attestation capture) forces every consumer's
//! exhaustive `match` — this primitive included — to extend by
//! construction rather than drift silently.

use std::io::{self, Write};

use crate::probe_dump::DiagSink;

/// Byte-oracle sibling of [`print_e2e_docker_images_backend_or_web_lines`]:
/// write each newline-separated line of `stdout` whose bytes contain
/// either the substring `"backend"` OR the substring `"web"` to `w`,
/// each rendered `"{line}\n"` verbatim.
///
/// The pre-lift `println!("{}", line)` and `eprintln!("{}", line)`
/// stanzas both emit `line + '\n'` per surviving row — the byte-oracle
/// preserves that record shape (one line per row, terminated by `'\n'`,
/// no leading indent injected here since the surrounding docker-images
/// `--format` template already embeds any leading whitespace as
/// literal-in-row content).
///
/// A line whose UTF-8-lossy view produces neither substring is skipped
/// silently — the pre-lift filter's short-circuit reading.
///
/// # Empty-input semantics
///
/// An input `stdout` that contains no newline-terminated line matching
/// the filter yields NO writes to `w`. This matches the pre-lift
/// discipline: both call sites' surrounding diagnostic block silently
/// omits the sub-section rather than emitting a "(none)" placeholder,
/// because the filter is applied inside an already-scoped diagnostic
/// heading (`print_diag_section_header(..., E2eDockerImages)`) that
/// carries the "these are the E2E images" context on its own line.
#[allow(dead_code)] // Writer sibling exercised by the byte-oracle tests.
pub fn write_e2e_docker_images_backend_or_web_lines<W>(w: &mut W, stdout: &str) -> io::Result<()>
where
    W: Write,
{
    for line in stdout.lines() {
        if line.contains("backend") || line.contains("web") {
            writeln!(w, "{}", line)?;
        }
    }
    Ok(())
}

/// Filter `stdout` down to lines mentioning `"backend"` or `"web"` and
/// dispatch each surviving line to `sink` (stdout or stderr) as one
/// `'\n'`-terminated record.
///
/// The pre-lift sibling stanzas in `commands/e2e.rs::print_image_info`
/// (stdout sink) and `commands/e2e.rs::print_failure_diagnostics`
/// (stderr sink) each restated the 5-line filter+print body verbatim
/// modulo the sink macro; both now route through this primitive with
/// the sink threaded via the closed [`DiagSink`] enum.
///
/// A write failure on the sink is silently ignored — matching the
/// pre-lift `println!`/`eprintln!` discipline, where a broken pipe on
/// the diagnostic stream is not a fatal condition on the surrounding
/// caller (the E2E images-info dump or the E2E failure diagnostics
/// section).
///
/// # Examples
///
/// ```ignore
/// // Pre-lift (commands/e2e.rs::print_image_info)
/// let stdout = crate::repo::utf8_lossy_borrow(&output.stdout);
/// for line in stdout.lines() {
///     if line.contains("backend") || line.contains("web") {
///         println!("{}", line);
///     }
/// }
///
/// // Post-lift
/// let stdout = crate::repo::utf8_lossy_borrow(&output.stdout);
/// crate::e2e_docker_images_backend_or_web_line_filter::
///     print_e2e_docker_images_backend_or_web_lines(
///         &stdout,
///         crate::probe_dump::DiagSink::Stdout,
///     );
/// ```
pub fn print_e2e_docker_images_backend_or_web_lines(stdout: &str, sink: DiagSink) {
    match sink {
        DiagSink::Stdout => {
            let _ = write_e2e_docker_images_backend_or_web_lines(&mut io::stdout().lock(), stdout);
        }
        DiagSink::Stderr => {
            let _ = write_e2e_docker_images_backend_or_web_lines(&mut io::stderr().lock(), stdout);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Pin the exact rendered bytes for the pass-through case: every
    // input line matches the filter, so the writer must emit each line
    // verbatim followed by `'\n'`. A future regression that swapped
    // `writeln!` for `write!` or dropped the `'\n'` would break the
    // pre-lift `println!("{}", line)` record boundary.
    #[test]
    fn write_filter_emits_every_matching_line_terminated_by_newline() {
        let mut buf: Vec<u8> = Vec::new();
        let stdout = "img/backend:v1\nimg/web:v1\nimg/backend:v2\n";
        write_e2e_docker_images_backend_or_web_lines(&mut buf, stdout).unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "img/backend:v1\nimg/web:v1\nimg/backend:v2\n"
        );
    }

    // Pin the filter's negative predicate: a line whose bytes contain
    // NEITHER `"backend"` NOR `"web"` must be dropped silently. A
    // regression that widened the predicate (e.g. added a third
    // substring) would surface here, and a regression that narrowed it
    // (e.g. requiring both substrings) would surface at the positive
    // pin above.
    #[test]
    fn write_filter_drops_lines_matching_neither_substring() {
        let mut buf: Vec<u8> = Vec::new();
        let stdout = "img/postgres:v1\nimg/kenshi:v1\nimg/otel-collector:v1\n";
        write_e2e_docker_images_backend_or_web_lines(&mut buf, stdout).unwrap();
        assert!(
            buf.is_empty(),
            "no line contains `backend` or `web` — writer must \
             emit zero bytes; got: {:?}",
            String::from_utf8_lossy(&buf)
        );
    }

    // Pin the mixed case: only rows carrying either substring survive,
    // in their original input order, one per output line.
    #[test]
    fn write_filter_keeps_only_matching_rows_in_input_order() {
        let mut buf: Vec<u8> = Vec::new();
        let stdout = "img/postgres:v1\nimg/backend:v1\nimg/kenshi:v1\nimg/web:v1\nimg/otel:v1\n";
        write_e2e_docker_images_backend_or_web_lines(&mut buf, stdout).unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "img/backend:v1\nimg/web:v1\n"
        );
    }

    // Substring semantics — `kenshi-web` and `pleme-web` and
    // `<registry>/backend-image` must all survive because the pre-lift
    // filter is a raw `.contains(...)` check, NOT a word-boundary
    // anchor. A regression that tightened the filter to a word-
    // boundary regex would silently drop namespaced image rows the
    // pre-lift diagnostic surfaced.
    #[test]
    fn write_filter_matches_substring_including_hyphenated_namespaces() {
        let mut buf: Vec<u8> = Vec::new();
        let stdout = "kenshi-web:v1\npleme-web:v1\nghcr.io/pleme/backend-image:v1\n";
        write_e2e_docker_images_backend_or_web_lines(&mut buf, stdout).unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "kenshi-web:v1\npleme-web:v1\nghcr.io/pleme/backend-image:v1\n"
        );
    }

    // Empty-input invariant: an input with no lines yields no writes.
    // Matches the pre-lift `for line in "".lines() { ... }` zero-iter
    // behavior.
    #[test]
    fn write_filter_on_empty_input_writes_nothing() {
        let mut buf: Vec<u8> = Vec::new();
        write_e2e_docker_images_backend_or_web_lines(&mut buf, "").unwrap();
        assert!(buf.is_empty());
    }

    // Caller shield: no source line under `cli/src/commands/` may spell
    // the pre-lift filter+print body inline anymore. Both
    // `commands/e2e.rs` sub-sections must route through the primitive.
    //
    // The needle is anchored on the exact `line.contains("backend")
    // || line.contains("web")` predicate — the fused filter's tell —
    // so the shield catches only the pre-lift dialect; sibling
    // `commands/prerelease.rs::print_e2e_diagnostics_on_failure`'s
    // separate `"-backend"`/`"-web"` hyphen-prefixed filter (a
    // deliberately narrower grammar the surrounding sub-section reads)
    // is NOT swept up here.
    #[test]
    fn no_command_module_still_spells_raw_backend_or_web_line_filter() {
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
                // the pre-lift shape in prose doesn't self-hit.
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") || trimmed.starts_with("///") {
                    continue;
                }
                if line.contains("line.contains(\"backend\") || line.contains(\"web\")") {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `line.contains(\"backend\") || line.contains(\"web\")` \
             filter predicate survives under `commands/` — route each \
             fused filter+print through \
             `crate::e2e_docker_images_backend_or_web_line_filter::print_e2e_docker_images_backend_or_web_lines(<stdout>, <sink>)` \
             instead:\n{:#?}",
            offenders
        );
    }

    // Positive half of the shield: `commands/e2e.rs` MUST forward at
    // least the pre-lift count of filter sites through the primitive,
    // so a migration that dropped a call site outright leaves the
    // negative "no raw inline shape" scan trivially satisfied by
    // absence but the positive count still fails.
    #[test]
    fn e2e_module_forwards_through_backend_or_web_line_filter_primitive() {
        use std::path::PathBuf;
        let e2e_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands")
            .join("e2e.rs");
        let source = std::fs::read_to_string(&e2e_path).unwrap();
        let forwards = source
            .matches(
                "crate::e2e_docker_images_backend_or_web_line_filter::\
                 print_e2e_docker_images_backend_or_web_lines(",
            )
            .count();
        assert!(
            forwards >= 2,
            "commands/e2e.rs must forward at least 2 filter+print \
             site(s) through \
             `crate::e2e_docker_images_backend_or_web_line_filter::print_e2e_docker_images_backend_or_web_lines(`; \
             found {forwards}. A dropped call would leave the negative \
             raw-shape scan satisfied by absence.",
        );
    }
}
