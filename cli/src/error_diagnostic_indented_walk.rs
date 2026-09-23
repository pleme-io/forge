//! Two-space-indented `tracing::error!`-routed diagnostic header + walk
//! grammar.
//!
//! Two pre-lift sibling sites across `commands/rollout.rs::execute`
//! (SAFE-mode `problems_detected` reporting body ~L307-320 for the
//! `Recent Events:` sub-section, ~L322-335 for the `Recent Logs (last 30
//! lines):` sub-section) each restated the fused
//!
//! ```text
//! if !<items>.is_empty() {
//!     error!("<Header>");
//!     for <line> in <items>.<walk> {
//!         error!("  {}", <line>);
//!     }
//! }
//! ```
//!
//! stanza verbatim — a header line rendered on the `tracing::error!`
//! channel, then each `<items>` element re-rendered on the same channel
//! prefixed with the two-ASCII-space indent and no trailing newline
//! (tracing supplies the record boundary). Post-lift the two sites reach
//! for [`error_diagnostic_indented_walk`] and the header emission, the
//! indent width, and the tracing verbosity are decided once here.
//!
//! # Distinct from [`crate::repo::push_indented_lines_4sp`]
//!
//! [`crate::repo::push_indented_lines_4sp`] serves the FOUR-space
//! diagnostic-buffer dialect — the six sibling sites under
//! `commands/flux.rs::gather_deployment_diagnostics` that push into an
//! [`anyhow::Error`] Display chain via `String::push_str`. That primitive
//! is *buffer*-routed and *four*-space-indented; this primitive is
//! *tracing*-routed and *two*-space-indented. The two coexist rather
//! than fusing because a runtime indent-width parameter would let a
//! caller accidentally shift a tracing-channel diagnostic to the buffer
//! dialect's column, and a runtime output-target parameter would collapse
//! two subscribers' record boundaries (the buffered String has one
//! newline per line, the tracing channel has one record per line — the
//! record boundary is not a newline in the same sense).
//!
//! # Empty-input semantics — the header is NOT a standalone line
//!
//! The pre-lift `if !<items>.is_empty() { error!("<Header>"); … }` gate
//! bracketed the header emission together with the walk: if the fetch
//! returned an empty collection, neither the header nor any walk line
//! was written. The iterator-driven post-lift shape reproduces that
//! invariant by delaying the header emission until the first walk line
//! actually lands — an empty iterator produces no header. The two are
//! byte-equivalent for every non-empty input the pre-lift call sites
//! observe (fresh `Vec<String>` returned by [`crate::k8s::get_pod_events`]
//! and a non-empty [`String`] returned by [`crate::k8s::get_pod_logs`])
//! and stay byte-equivalent for the empty case they also observe (the
//! pod has produced no events yet, or its container has emitted no
//! stdout/stderr yet).
//!
//! # Two writer surfaces — `tracing` for production, `io::Write` for pins
//!
//! [`error_diagnostic_indented_walk`] routes through [`tracing::error!`]
//! at the primitive's own module path — production code emits via the
//! tracing subscriber `main` installs and the subscriber sees each line
//! as a distinct record on the `ERROR` level. The subscriber cannot be
//! captured in-process without racing an ambient tracing setup, so the
//! byte-oracle sibling [`write_error_diagnostic_indented_walk`] emits
//! the same header + indented-line shape to a supplied [`io::Write`]
//! target with an explicit `'\n'` line terminator, so a fail-before-
//! pass-after test can pin the exact rendered bytes (the header, the
//! two-space indent, one line per input element, no trailing extra
//! newline) without depending on the tracing runtime.

use std::fmt;
use std::io;

/// Emit `header` followed by each `line` of `lines` prefixed with the
/// pre-lift two-ASCII-space indent to the supplied writer as one
/// `'\n'`-terminated record per line.
///
/// When `lines` is empty the writer receives NOTHING — the header is
/// bracketed with the walk exactly as the pre-lift `if !X.is_empty()`
/// gate did. See the module docs for why the empty-input case must
/// suppress the header rather than emit it as a standalone line.
///
/// The [`error_diagnostic_indented_walk`] tracing-channel adapter is
/// what production code invokes; this direct-writer variant exists so
/// the fail-before-pass tests can pin the exact emitted bytes (the
/// header line, the two-space indent, one line per walk element, the
/// trailing newline on each record) without capturing a tracing
/// subscriber and without racing an ambient logger — the same split
/// [`crate::indented_success_step::write_indented_success_step`] carries
/// against [`crate::info_indented_success!`].
///
/// The `line` items accept any [`fmt::Display`] rather than a concrete
/// `&str` so `Vec<String>::iter().rev().take(10)` (yielding `&String`),
/// `String::lines().take(30)` (yielding `&str`), and a future
/// diagnostic-item type carrying structured fields all flow through the
/// same writer without a per-caller `.to_string()` intermediate.
#[allow(dead_code)] // See doc comment: the writer is a test/byte-oracle
                    // peer of the tracing-routed
                    // `error_diagnostic_indented_walk` function.
pub fn write_error_diagnostic_indented_walk<W, I, S>(
    w: &mut W,
    header: &str,
    lines: I,
) -> io::Result<()>
where
    W: io::Write,
    I: IntoIterator<Item = S>,
    S: fmt::Display,
{
    let mut printed_header = false;
    for line in lines {
        if !printed_header {
            writeln!(w, "{}", header)?;
            printed_header = true;
        }
        writeln!(w, "  {}", line)?;
    }
    Ok(())
}

/// Emit `header` and each `line` of `lines` prefixed with the pre-lift
/// two-ASCII-space indent via [`tracing::error!`] — one record per line,
/// header first, then the walk.
///
/// When `lines` is empty the tracing channel receives NOTHING — the
/// header emission is gated by the presence of at least one walk item,
/// mirroring the pre-lift `if !X.is_empty()` bracket on both
/// `commands/rollout.rs::execute` call sites (Recent Events / Recent
/// Logs). See the module docs for the byte-equivalence argument against
/// the pre-lift shape.
///
/// # Examples
///
/// ```ignore
/// // Pre-lift (commands/rollout.rs::execute Recent Events branch)
/// match k8s::get_pod_events(&client, &namespace, &pod.name).await {
///     Ok(events) => {
///         if !events.is_empty() {
///             error!("Recent Events:");
///             for event in events.iter().rev().take(10) {
///                 error!("  {}", event);
///             }
///         }
///     }
///     Err(e) => warn!("Failed to get events: {}", e),
/// }
///
/// // Post-lift
/// match k8s::get_pod_events(&client, &namespace, &pod.name).await {
///     Ok(events) => crate::error_diagnostic_indented_walk::
///         error_diagnostic_indented_walk(
///             "Recent Events:",
///             events.iter().rev().take(10),
///         ),
///     Err(e) => warn!("Failed to get events: {}", e),
/// }
/// ```
pub fn error_diagnostic_indented_walk<I, S>(header: &str, lines: I)
where
    I: IntoIterator<Item = S>,
    S: fmt::Display,
{
    let mut printed_header = false;
    for line in lines {
        if !printed_header {
            tracing::error!("{}", header);
            printed_header = true;
        }
        tracing::error!("  {}", line);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Pin the exact rendered bytes for the Recent Events shape: a
    // header line, then each walk item prefixed with `"  "` (two ASCII
    // spaces) and terminated by `'\n'`. A future refactor that drops
    // the indent, widens it to four spaces (the buffer dialect), or
    // omits the trailing newline regresses this assertion.
    #[test]
    fn write_error_diagnostic_indented_walk_emits_header_then_two_space_indented_lines() {
        let mut buf: Vec<u8> = Vec::new();
        let events: [String; 3] = [
            String::from("Pulling image"),
            String::from("Successfully pulled image"),
            String::from("Created container"),
        ];
        write_error_diagnostic_indented_walk(
            &mut buf,
            "Recent Events:",
            events.iter().rev().take(10),
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "Recent Events:\n  Created container\n  Successfully pulled image\n  Pulling image\n"
        );
    }

    // Pin the Recent Logs shape byte-for-byte: the same primitive
    // absorbs `String::lines()` (which yields `&str`, not `&String`),
    // and each line survives verbatim through the two-space indent.
    #[test]
    fn write_error_diagnostic_indented_walk_absorbs_string_lines_iter() {
        let mut buf: Vec<u8> = Vec::new();
        let logs = String::from("line 1\nline 2\nline 3\n");
        write_error_diagnostic_indented_walk(
            &mut buf,
            "Recent Logs (last 30 lines):",
            logs.lines().take(30),
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "Recent Logs (last 30 lines):\n  line 1\n  line 2\n  line 3\n"
        );
    }

    // Empty-input invariant: the header must NOT be emitted as a
    // standalone line when the walk iterator produces zero items. A
    // future refactor that emits the header unconditionally regresses
    // this — the pre-lift `if !<items>.is_empty()` gate specifically
    // bracketed the header with the walk, and a lone header on the
    // ERROR channel would surface as a mystery diagnostic during the
    // rollout success path.
    #[test]
    fn write_error_diagnostic_indented_walk_suppresses_header_on_empty_input() {
        let mut buf: Vec<u8> = Vec::new();
        let empty: Vec<String> = Vec::new();
        write_error_diagnostic_indented_walk(&mut buf, "Recent Events:", empty.iter()).unwrap();
        assert!(
            buf.is_empty(),
            "empty walk must suppress the header — a lone header on the \
             ERROR channel breaks the pre-lift `if !X.is_empty()` bracket \
             semantics; got: {:?}",
            String::from_utf8_lossy(&buf)
        );
    }

    // Explicit indent-width pin: two ASCII spaces (0x20 0x20), not one,
    // not three, not a tab. The four-space sibling
    // `crate::repo::push_indented_lines_4sp` targets the diagnostic
    // BUFFER dialect and its indent is fixed at four spaces to line up
    // with the buffer's outer heading column. This primitive targets
    // the TRACING channel and its indent is fixed at two spaces to
    // line up under the tracing subscriber's own leading level tag
    // (`ERROR forge::commands::rollout: ` on the standard formatter).
    // A drift between the two dialects breaks the operator's visual
    // scan of a rollout-failure diagnostic block.
    #[test]
    fn write_error_diagnostic_indented_walk_uses_exactly_two_space_indent() {
        let mut buf: Vec<u8> = Vec::new();
        write_error_diagnostic_indented_walk(&mut buf, "Header:", std::iter::once("body")).unwrap();
        let rendered = String::from_utf8(buf).unwrap();
        assert!(
            rendered.contains("\n  body\n"),
            "walk line must be indented with exactly two ASCII spaces — \
             the four-space dialect belongs to `push_indented_lines_4sp`; \
             got: {:?}",
            rendered
        );
        assert!(
            !rendered.contains("\n    body\n"),
            "walk line must NOT be indented with four spaces — that is \
             the buffer dialect's grammar; got: {:?}",
            rendered
        );
        assert!(
            !rendered.contains("\n\tbody\n"),
            "walk line must NOT be indented with a tab; got: {:?}",
            rendered
        );
    }

    // Compile-time pin: the tracing-routed adapter must accept both
    // the pre-lift iterator shapes without a caller-side projection
    // (`.map(|s| s.as_str())` etc.). A regression that narrowed
    // `S: fmt::Display` to `S: AsRef<str>` or to a concrete `&str`
    // would break the `events.iter().rev().take(10)` call site
    // (`&String` items) without breaking the `logs.lines().take(30)`
    // one (`&str` items), and the shape catch would be delayed to a
    // full `cargo build` on the caller file.
    #[test]
    fn error_diagnostic_indented_walk_accepts_prelift_iterator_shapes() {
        // `Vec<String>::iter().rev().take(N)` yields `&String`.
        let events: Vec<String> = vec![String::from("ev1"), String::from("ev2")];
        error_diagnostic_indented_walk("Recent Events:", events.iter().rev().take(10));
        // `String::lines().take(N)` yields `&str`.
        let logs = String::from("l1\nl2\n");
        error_diagnostic_indented_walk("Recent Logs (last 30 lines):", logs.lines().take(30));
        // Empty iterator compiles and is a no-op.
        error_diagnostic_indented_walk("Header:", std::iter::empty::<&str>());
    }

    // Caller shield: no source line under `cli/src/commands/` may spell
    // the pre-lift fused shape `error!("<Header>"); for … { error!("  {}",
    // …); }` inline any more. Both `commands/rollout.rs::execute`
    // Recent Events / Recent Logs sub-sections must route through
    // `crate::error_diagnostic_indented_walk::error_diagnostic_indented_walk`.
    //
    // The needle is anchored on the two-space-indent `error!("  {}", `
    // walk-body shape — the fused stanza's tell — so the shield catches
    // only the pre-lift dialect, and the positive delegation shield
    // below forces future variants of the SAME shape through the
    // primitive.
    #[test]
    fn no_command_module_still_spells_raw_two_space_error_indent_walk() {
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
                if line.contains("error!(\"  {}\", ") {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `error!(\"  {{}}\", …)` two-space-indent walk-body \
             stanza(s) survive under `commands/` — route each fused \
             header+walk through \
             `crate::error_diagnostic_indented_walk::error_diagnostic_indented_walk(<header>, <iter>)` \
             instead:\n{:#?}",
            offenders
        );
    }

    // Positive half of the shield: `commands/rollout.rs` MUST forward
    // at least the pre-lift count of walk sites through the primitive,
    // so a migration that dropped a call site outright leaves the
    // negative "no raw inline shape" scan trivially satisfied by
    // absence but the positive count still fails.
    #[test]
    fn rollout_module_forwards_through_error_diagnostic_indented_walk() {
        use std::path::PathBuf;
        let rollout_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands")
            .join("rollout.rs");
        let source = std::fs::read_to_string(&rollout_path).unwrap();
        let forwards = source
            .matches("crate::error_diagnostic_indented_walk::error_diagnostic_indented_walk(")
            .count();
        assert!(
            forwards >= 2,
            "commands/rollout.rs must forward at least 2 fused header+walk \
             site(s) through \
             `crate::error_diagnostic_indented_walk::error_diagnostic_indented_walk(`; \
             found {forwards}. A dropped call would leave the negative \
             raw-shape scan satisfied by absence.",
        );
    }
}
