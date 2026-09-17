//! Backend + Frontend directory preamble primitive — the two-line
//! `println!("Backend: {}", <backend>.display()); println!("Frontend:
//! {}", <web>.display())` stanza the two schema/codegen-adjacent
//! command entry points (`commands/codegen.rs::execute` and
//! `commands/prerelease.rs::run`) emit immediately after their
//! `crate::ui::print_section_header` heading.
//!
//! # Pre-lift census — two sibling stanzas, byte-identical
//!
//! Two pre-lift command modules each restated
//!
//! ```ignore
//! println!("Backend: {}", <backend_dir>.display());
//! println!("Frontend: {}", <web_dir>.display());
//! ```
//!
//! verbatim under the section-header preamble at their top-of-command
//! entry:
//!
//! 1. `commands/codegen.rs::execute` (~L72-73) — the schema-export +
//!    codegen surface's opener, directly under
//!    `crate::ui::print_section_header("Schema Export + Codegen")`
//!    and before the `println!()` framing blank that separates the
//!    preamble from Step 1.
//! 2. `commands/prerelease.rs::run` (~L389-390) — the pre-release-gates
//!    surface's opener, directly under
//!    `crate::ui::print_section_header("Pre-Release Gates")` and
//!    threaded between the caller-specific `Working directory:` header
//!    row and the `Fail on error:` config-echo row.
//!
//! Both stanzas name the same two BFF (Backend-for-Frontend) surfaces
//! forge orchestrates against: the backend crate's source directory
//! and the web frontend's source directory. A drift in the header
//! wording — a capitalization swap (`backend:` vs `Backend:`), a
//! label swap (`API:` / `Server:` / `Rust:` for the first line;
//! `Web:` / `UI:` / `Frontend:` for the second), an argv-order swap
//! (frontend before backend), a colon-space vs colon-tab connective,
//! or a `.display()` swap to `.to_string_lossy()` — pre-lift had to
//! hit two sites in lockstep or diverge; post-lift it hits ONE typed
//! body and every consumer inherits the change from
//! [`print_backend_frontend_dirs_preamble`].
//!
//! # Distinct from the sibling `print_path_label` grammar
//!
//! [`crate::ui::print_path_label`] emits a single
//! `📂 <LABEL>: <path.display()>` line — a leading `📂 ` FILE FOLDER
//! glyph anchor and a caller-supplied label. This primitive emits a
//! TWO-line pair with FIXED labels (`Backend:` and `Frontend:`, both
//! at column 0) and NO leading glyph — every pre-lift consumer spelled
//! the plain-text opener directly under a section-header banner, not
//! the `📂 `-anchored path-label grammar the mid-body path echoes use.
//! Folding this primitive into `print_path_label` would (a) prepend
//! the `📂 ` glyph to both header rows (silently changing the visual
//! grammar the operator reads at every codegen/prerelease start) and
//! (b) force each of the two sites to spell the `"Backend"` /
//! `"Frontend"` label at the call site again (defeating the
//! solve-once purpose — a rename of either label would still hit two
//! sites in lockstep).
//!
//! # THEORY grounding
//!
//! §V solve-once-at-the-primitive: the `Backend:` / `Frontend:`
//! preamble grammar lives at ONE construction surface so a future
//! refinement (a colored label palette matching the section header,
//! a `.display()` -> `.to_string_lossy()` swap for non-UTF-8 path
//! resilience, an added `Migrations:` line for the third orchestration
//! surface `commands/sync.rs` also carries) lands in one place rather
//! than at every consumer.
//!
//! # Composition
//!
//! [`print_backend_frontend_dirs_preamble`] emits the two-line stanza
//! against [`std::io::stdout()`];
//! [`write_backend_frontend_dirs_preamble`] is the writer-taking
//! sibling that pins the exact emitted bytes for the
//! fail-before-pass byte-oracle tests.

use std::io;
use std::path::Path;

/// Print the two-line `Backend: <backend>` / `Frontend: <web>`
/// preamble stanza — the two-line header pair the two pre-lift
/// sites in `commands/codegen.rs::execute` and
/// `commands/prerelease.rs::run` emit immediately under their
/// `crate::ui::print_section_header` heading — to
/// [`std::io::stdout()`].
///
/// Delegates to [`write_backend_frontend_dirs_preamble`] against a
/// locked stdout handle; the writer split exists so the
/// fail-before-pass tests can pin the emitted bytes without
/// capturing stdout.
pub fn print_backend_frontend_dirs_preamble(backend_dir: &Path, web_dir: &Path) {
    let _ =
        write_backend_frontend_dirs_preamble(&mut std::io::stdout().lock(), backend_dir, web_dir);
}

/// Writer-taking sibling of [`print_backend_frontend_dirs_preamble`].
/// Emits the TWO-line `Backend: <backend>` / `Frontend: <web>`
/// preamble stanza — both label rows anchored at column 0, colon +
/// single-space connective, `Path::display()`-projected value — via
/// [`writeln!`] against the supplied writer.
///
/// # Byte contract
///
/// The rendered byte sequence is:
///
/// - `Backend: ` (9 ASCII bytes: the literal label, a colon, one
///   ASCII space).
/// - The `backend_dir.display()` projection verbatim.
/// - `\n` (line terminator from the first `writeln!`).
/// - `Frontend: ` (10 ASCII bytes).
/// - The `web_dir.display()` projection verbatim.
/// - `\n` (line terminator).
///
/// No ANSI escape appears in the emitted bytes — every pre-lift
/// consumer spelled `println!("Backend: {}", ...)` / `println!(
/// "Frontend: {}", ...)` with no `.bold()` / `.dimmed()` /
/// `.cyan()` wrapping on either label or value.
pub fn write_backend_frontend_dirs_preamble<W: io::Write>(
    w: &mut W,
    backend_dir: &Path,
    web_dir: &Path,
) -> io::Result<()> {
    writeln!(w, "Backend: {}", backend_dir.display())?;
    writeln!(w, "Frontend: {}", web_dir.display())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Byte-oracle: the writer emits exactly TWO lines — the
    /// `Backend:` row and the `Frontend:` row, in that order. A
    /// refactor that (a) added a third `Migrations:` row without
    /// re-parameterizing the primitive, (b) collapsed the two rows
    /// into one, or (c) reordered `Frontend:` above `Backend:` would
    /// flip this assertion.
    #[test]
    fn write_backend_frontend_dirs_preamble_emits_two_lines_in_order() {
        let mut buf: Vec<u8> = Vec::new();
        write_backend_frontend_dirs_preamble(
            &mut buf,
            Path::new("/repo/backend"),
            Path::new("/repo/web"),
        )
        .unwrap();
        let out = String::from_utf8(buf).expect("writer emits valid UTF-8");
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(
            lines.len(),
            2,
            "write_backend_frontend_dirs_preamble must emit exactly \
             two lines (Backend + Frontend); got {} lines:\n{:?}",
            lines.len(),
            out
        );
        assert_eq!(lines[0], "Backend: /repo/backend");
        assert_eq!(lines[1], "Frontend: /repo/web");
    }

    /// Byte-oracle: each row opens with the pre-lift literal label
    /// (`Backend:` / `Frontend:`) at column 0 followed by a single
    /// ASCII space. A drift that added a leading `📂 ` FILE FOLDER
    /// glyph (a fusion with [`crate::ui::print_path_label`]), a
    /// caller-supplied indent (a shift-into-mid-body cleanup), or a
    /// colon-tab connective would flip this assertion.
    #[test]
    fn write_backend_frontend_dirs_preamble_labels_anchored_at_column_zero() {
        let mut buf: Vec<u8> = Vec::new();
        write_backend_frontend_dirs_preamble(&mut buf, Path::new("/b"), Path::new("/w")).unwrap();
        let out = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert!(
            lines[0].starts_with("Backend: "),
            "row 0 must open with the literal `Backend: ` (label + \
             colon + single ASCII space) at column 0; got {:?}",
            lines[0]
        );
        assert!(
            lines[1].starts_with("Frontend: "),
            "row 1 must open with the literal `Frontend: ` (label + \
             colon + single ASCII space) at column 0; got {:?}",
            lines[1]
        );
    }

    /// Byte-oracle: no ANSI escape byte (`\x1b`) appears anywhere in
    /// the emitted bytes. Every pre-lift consumer spelled the plain
    /// `println!("Backend: {}", ...)` / `println!("Frontend: {}",
    /// ...)` form without a `.bold()` / `.dimmed()` / `.cyan()`
    /// wrapping. A promotion to a colored palette (matching the
    /// `.cyan()` env label in `commands/rust_service.rs::.migrations`
    /// prints) would introduce `\x1b[` bytes and fail this scan.
    #[test]
    fn write_backend_frontend_dirs_preamble_emits_no_ansi_escape() {
        let mut buf: Vec<u8> = Vec::new();
        write_backend_frontend_dirs_preamble(&mut buf, Path::new("/x"), Path::new("/y")).unwrap();
        assert!(
            !buf.contains(&0x1b),
            "no ANSI escape byte may appear in the plain-text preamble; \
             got {:?}",
            String::from_utf8_lossy(&buf)
        );
    }

    /// Byte-oracle: the caller-supplied paths reach the writer via
    /// `Path::display()` verbatim. A future signature that swapped
    /// `.display()` for `.to_string_lossy()` would still pass here for
    /// UTF-8-safe paths (both projections agree on UTF-8 inputs) —
    /// this test pins the pre-lift consumer intent (a plain UTF-8
    /// display) without over-constraining the projection.
    #[test]
    fn write_backend_frontend_dirs_preamble_paths_reach_writer_verbatim() {
        let backend = PathBuf::from("/absolute/backend/dir");
        let web = PathBuf::from("relative/web/dir");
        let mut buf: Vec<u8> = Vec::new();
        write_backend_frontend_dirs_preamble(&mut buf, &backend, &web).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(
            out.contains("/absolute/backend/dir"),
            "backend path must reach writer verbatim; got {out:?}"
        );
        assert!(
            out.contains("relative/web/dir"),
            "web path must reach writer verbatim; got {out:?}"
        );
    }

    /// Post-lift shield (negative): no source line under
    /// `cli/src/commands/` may still spell the pre-lift raw
    /// `println!("Backend: {}", <_>.display())` or `println!(
    /// "Frontend: {}", <_>.display())` shape inline. Every consumer
    /// reaches for [`print_backend_frontend_dirs_preamble`] on first
    /// grep, not by copy-pasting the raw stanza. Scoped to
    /// non-comment lines so a docstring mention of the raw shape
    /// does not defeat the shield.
    #[test]
    fn no_command_module_still_spells_raw_backend_frontend_preamble() {
        use std::path::PathBuf as StdPathBuf;
        let commands_dir = StdPathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let mut offenders: Vec<(StdPathBuf, usize, String)> = Vec::new();
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
                let is_raw_backend =
                    line.contains("println!(\"Backend: {}\",") && line.contains(".display()");
                let is_raw_frontend =
                    line.contains("println!(\"Frontend: {}\",") && line.contains(".display()");
                if is_raw_backend || is_raw_frontend {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `println!(\"Backend: {{}}\", <_>.display())` / \
             `println!(\"Frontend: {{}}\", <_>.display())` stanza(s) \
             survive under `commands/` — route each through \
             `crate::backend_frontend_dirs_preamble::\
             print_backend_frontend_dirs_preamble(<backend>, <web>)` \
             instead:\n{:#?}",
            offenders
        );
    }

    /// Post-lift shield (positive): the two pre-lift modules MUST
    /// forward through [`print_backend_frontend_dirs_preamble`] at
    /// least once each. A migration that dropped a call site outright
    /// leaves the negative "no raw inline shape" scan trivially
    /// satisfied by absence but the positive count still fails.
    #[test]
    fn every_prelift_module_forwards_through_backend_frontend_dirs_preamble() {
        use std::path::PathBuf as StdPathBuf;
        let commands_dir = StdPathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let expectations: &[(&str, usize)] = &[("codegen.rs", 1), ("prerelease.rs", 1)];
        let needle = "print_backend_frontend_dirs_preamble(";
        for (basename, min_count) in expectations {
            let path = commands_dir.join(basename);
            let source = std::fs::read_to_string(&path)
                .unwrap_or_else(|_| panic!("expected {} to exist", path.display()));
            let forwards = source.matches(needle).count();
            assert!(
                forwards >= *min_count,
                "{basename} must forward at least {min_count} \
                 backend+frontend preamble site(s) through `{needle}`; \
                 found {forwards}. A dropped call would leave the \
                 negative raw-shape scan satisfied by absence.",
            );
        }
    }
}
