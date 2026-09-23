//! Two-bullet manifest-files catalog + trailing blank-line separator
//! primitive — the closer stanza every `crate2nix`-driven regenerate /
//! update workflow reaches for immediately after
//! [`crate::cargo_nix_ceremony_banner::print_cargo_nix_ceremony_banner`]
//! to list the produced-or-updated manifest pair (`Cargo.lock` +
//! `Cargo.nix`) and separate them from the following
//! [`crate::ui::print_next_steps_heading`] section.
//!
//! # Pre-lift census — three sibling three-line stanzas
//!
//! Three pre-lift sibling three-line stanzas — one in
//! `commands/web_service.rs` (`web_cargo_update` at :266-268) and two
//! in `commands/developer_tools.rs` (`rust_regenerate` at :383-385;
//! `rust_cargo_update` at :429-431) each restated
//!
//! ```ignore
//! crate::ui::print_bullet_path(&<dir>.join("Cargo.lock"));
//! crate::ui::print_bullet_path(&<dir>.join("Cargo.nix"));
//! println!();
//! ```
//!
//! byte-for-byte, differing only in the caller-provided `<dir>` prefix
//! threaded through both `.join(...)` compositions:
//!
//! 1. `commands/web_service.rs::web_cargo_update` (:266-268) — Hanabi
//!    workspace closer, `<dir>` = `hanabi_dir` (from
//!    [`crate::hanabi_dir::hanabi_dir`]).
//! 2. `commands/developer_tools.rs::rust_regenerate` (:383-385) —
//!    generic rust-service workspace closer under the
//!    `Regeneration` ceremony variant, `<dir>` = `workspace_root`
//!    (from `read_service_env_and_chdir_to_workspace`); the `Cargo.lock`
//!    bullet spells `&cargo_lock` at the call site but `cargo_lock`
//!    aliases `workspace_root.join("Cargo.lock")` from the file-existence
//!    probe seven lines above.
//! 3. `commands/developer_tools.rs::rust_cargo_update` (:429-431) —
//!    the same generic rust-service workspace closer under the
//!    `Update` ceremony variant.
//!
//! Three sibling occurrences clear THEORY.md §VI.1's "two is a
//! coincidence, three is a law" threshold. Post-lift the three stanzas
//! route through [`print_cargo_lock_and_cargo_nix_bullets_with_blank`];
//! a drift in the manifest-file catalog (a swap of `Cargo.lock` for
//! `Cargo.toml`, a rename of `Cargo.nix` to `cargo.nix`, an inversion of
//! the two-line bullet order, a widening of the trailing blank to
//! two blank lines) lands at ONE typed body and reaches all three
//! consumers by construction.
//!
//! # Coupling being pinned
//!
//! The two file names and their emission order are not independent: the
//! ceremony-close catalog is a two-element enumeration of the
//! `crate2nix generate` output pair (input `Cargo.lock` first, output
//! `Cargo.nix` second, matching the file's role in the
//! `cargo update` → `crate2nix generate` pipeline). Pre-lift each site
//! nailed the two file names into two independent inline
//! `.join(...)` string literals; a copy-paste that spelled `Cargo.lock`
//! twice, dropped the `Cargo.nix` line, or reversed the order compiled
//! clean and silently mismatched the operator's read. Post-lift the two
//! file names live at [`CARGO_LOCK_BASENAME`] / [`CARGO_NIX_BASENAME`]
//! and the emission order lives at one function body, so the copy-paste
//! hazard is foreclosed at the type level.
//!
//! # Distinct from the sibling `print_bullet_path` frontier
//!
//! [`crate::ui::print_bullet_path`] owns the ONE `  • <path>\n`
//! single-bullet rendering used across the fleet's various
//! file-catalog surfaces. This primitive is one dedicated fusion
//! specialization for the (`Cargo.lock`, `Cargo.nix`, blank) triple —
//! the same architectural split
//! [`crate::cargo_nix_ceremony_banner`] carries against
//! [`crate::ui::print_success_banner`], and [`crate::generate_cargo_nix_step`]
//! carries against [`crate::nix::run_nix_wrapped_crate2nix`]. The
//! primitive stays a grammar-and-ordering owner (bullet → bullet →
//! blank), not a bullet-render-behavior owner, so a future re-shaping
//! of the underlying `  • ` indent + `•` glyph + trailing-newline
//! grammar lands at [`crate::ui::write_bullet_item`] and this
//! primitive inherits by composition.
//!
//! # THEORY grounding
//!
//! - THEORY.md §V.1 (Construction guarantees; Types → Invariants →
//!   Proofs → Render Anywhere): the paired byte-oracle sibling
//!   [`write_cargo_lock_and_cargo_nix_bullets_with_blank`] is the
//!   Render Anywhere half — pinning the exact three-line rendered
//!   bytes as a `cargo test`-verifiable invariant so a fusion that
//!   swapped the file-name order, dropped the trailing blank, or
//!   inserted a variation selector into the bullet glyph fails at
//!   `cargo test` time rather than at operator readout.
//! - THEORY.md §VI.1 (three-times rule): three sibling occurrences at
//!   the "two is a coincidence; three is a law" threshold, so the
//!   three-line stanza lifts onto ONE typed body.

use std::io;
use std::path::Path;

/// The `Cargo.lock` manifest-file basename every pre-lift site spelled
/// inline as `.join("Cargo.lock")` on the first of the two
/// [`crate::ui::print_bullet_path`] calls. Named as a `const` so a
/// future rename (`Cargo.lock` → `cargo.lock`, or a fleet-wide swap
/// onto a `Cargo.lock.toml`-shaped alternate) lands at ONE edit rather
/// than at three inline literals.
pub const CARGO_LOCK_BASENAME: &str = "Cargo.lock";

/// The `Cargo.nix` manifest-file basename every pre-lift site spelled
/// inline as `.join("Cargo.nix")` on the second
/// [`crate::ui::print_bullet_path`] call. Sibling of
/// [`CARGO_LOCK_BASENAME`].
pub const CARGO_NIX_BASENAME: &str = "Cargo.nix";

/// Print the three-line
/// `  • <dir>/Cargo.lock\n  • <dir>/Cargo.nix\n\n` closer to stdout —
/// the fusion primitive three pre-lift sibling sites in
/// `commands/{web_service.rs, developer_tools.rs}` each spelled
/// inline via two independent [`crate::ui::print_bullet_path`] calls
/// and a trailing bare `println!()`.
///
/// `dir` is the directory both manifest files live under — pre-lift
/// sites pass `&hanabi_dir` (from
/// [`crate::hanabi_dir::hanabi_dir`]) or `&workspace_root` (from
/// `commands/developer_tools.rs::read_service_env_and_chdir_to_workspace`);
/// the primitive owns the `.join("Cargo.lock")` /
/// `.join("Cargo.nix")` composition on top of that directory.
///
/// Delegates through [`crate::ui::print_bullet_path`] so the shared
/// `  • <path.display()>\n` bullet-row grammar has ONE landing point —
/// a future re-shaping of the two-space indent, the U+2022 `•` BULLET
/// glyph, or the trailing-newline convention rides through this
/// primitive by construction.
pub fn print_cargo_lock_and_cargo_nix_bullets_with_blank(dir: &Path) {
    crate::ui::print_bullet_path(&dir.join(CARGO_LOCK_BASENAME));
    crate::ui::print_bullet_path(&dir.join(CARGO_NIX_BASENAME));
    println!();
}

/// Byte-oracle sibling of
/// [`print_cargo_lock_and_cargo_nix_bullets_with_blank`] — writes the
/// same three lines to any [`std::io::Write`] so a `#[test]` can
/// capture and compare them.
///
/// Delegates to [`crate::ui::write_bullet_path`] so the primitive
/// keeps a single source of truth for the outer `  • {path}` byte
/// template; the trailing blank line is a bare `writeln!(w)` matching
/// the pre-lift `println!()` semantics.
///
/// # `#[allow(dead_code)]` intent
///
/// The production entry point
/// [`print_cargo_lock_and_cargo_nix_bullets_with_blank`] delegates to
/// the stdout-adapter form ([`crate::ui::print_bullet_path`]) rather
/// than this writer sibling, so a non-test build sees no caller. The
/// writer split exists so byte-oracle tests can pin the exact three-
/// line rendered bytes without capturing stdout; the same pattern
/// [`crate::generate_cargo_nix_step::write_generate_cargo_nix_announce`]
/// carries against its colored sibling.
#[allow(dead_code)]
pub fn write_cargo_lock_and_cargo_nix_bullets_with_blank<W: io::Write>(
    w: &mut W,
    dir: &Path,
) -> io::Result<()> {
    crate::ui::write_bullet_path(w, &dir.join(CARGO_LOCK_BASENAME))?;
    crate::ui::write_bullet_path(w, &dir.join(CARGO_NIX_BASENAME))?;
    writeln!(w)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Const-anchor pin: the canonical `"Cargo.lock"` basename all
    /// three pre-lift sites spelled verbatim.
    #[test]
    fn cargo_lock_basename_carries_pre_lift_bytes() {
        assert_eq!(CARGO_LOCK_BASENAME, "Cargo.lock");
    }

    /// Const-anchor pin: the canonical `"Cargo.nix"` basename all
    /// three pre-lift sites spelled verbatim.
    #[test]
    fn cargo_nix_basename_carries_pre_lift_bytes() {
        assert_eq!(CARGO_NIX_BASENAME, "Cargo.nix");
    }

    /// Byte-oracle: the closer emits exactly three lines — a
    /// `Cargo.lock` bullet, a `Cargo.nix` bullet, then a bare blank —
    /// each with the two-space indent + U+2022 `•` BULLET glyph +
    /// `<path.display()>` + trailing `\n`. A future refactor that
    /// swapped the file order, dropped the trailing blank, widened
    /// the two-space indent, or appended a U+FE0F variation selector
    /// to the bullet glyph regresses this assertion.
    #[test]
    fn write_bullets_emits_exact_three_line_shape() {
        let mut buf: Vec<u8> = Vec::new();
        write_cargo_lock_and_cargo_nix_bullets_with_blank(&mut buf, Path::new("/repo")).unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "  \u{2022} /repo/Cargo.lock\n  \u{2022} /repo/Cargo.nix\n\n"
        );
    }

    /// Order pin: the `Cargo.lock` bullet MUST precede the
    /// `Cargo.nix` bullet — matching the file's role in the
    /// `cargo update` → `crate2nix generate` pipeline (input first,
    /// output second). A future refactor that inverted the two
    /// bullets would break the operator's mental model of the closer.
    #[test]
    fn write_bullets_emits_cargo_lock_before_cargo_nix() {
        let mut buf: Vec<u8> = Vec::new();
        write_cargo_lock_and_cargo_nix_bullets_with_blank(&mut buf, Path::new("/x")).unwrap();
        let rendered = String::from_utf8(buf).unwrap();
        let lock_pos = rendered.find("Cargo.lock").expect("lock present");
        let nix_pos = rendered.find("Cargo.nix").expect("nix present");
        assert!(
            lock_pos < nix_pos,
            "Cargo.lock must appear before Cargo.nix — got lock at {lock_pos}, nix at {nix_pos}",
        );
    }

    /// Line-count pin: exactly three trailing `\n` bytes (two
    /// bullets + one blank). A future refactor that widened the
    /// blank separator to two lines or dropped it would flip this
    /// assertion.
    #[test]
    fn write_bullets_emits_exactly_three_newlines() {
        let mut buf: Vec<u8> = Vec::new();
        write_cargo_lock_and_cargo_nix_bullets_with_blank(&mut buf, Path::new("/x")).unwrap();
        let newlines = buf.iter().filter(|&&b| b == b'\n').count();
        assert_eq!(
            newlines, 3,
            "expected exactly three `\\n` bytes (two bullet lines + \
             one blank separator); got {newlines}. Bytes: {buf:?}",
        );
    }

    /// Relative-root pin: a caller-provided relative `dir` composes
    /// relative bullet paths — the primitive does NOT silently
    /// absolutize. Matches the pre-lift `.join(...)` behavior.
    #[test]
    fn write_bullets_preserves_relative_dir() {
        let mut buf: Vec<u8> = Vec::new();
        write_cargo_lock_and_cargo_nix_bullets_with_blank(&mut buf, Path::new("workspace"))
            .unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "  \u{2022} workspace/Cargo.lock\n  \u{2022} workspace/Cargo.nix\n\n"
        );
    }

    /// No-ANSI guard: the byte-oracle writer's payload carries no
    /// ANSI escape byte (0x1B). Matches the pre-lift `print_bullet_path`
    /// convention that the bullet family carries no palette on the
    /// glyph or the message body.
    #[test]
    fn write_bullets_emits_no_ansi_escape() {
        let mut buf: Vec<u8> = Vec::new();
        write_cargo_lock_and_cargo_nix_bullets_with_blank(&mut buf, Path::new("/x")).unwrap();
        assert!(
            !buf.contains(&0x1b),
            "closer must emit no ANSI escape (0x1B) — the bullet \
             family carries no palette on either the glyph or the \
             path body. Bytes: {buf:?}",
        );
    }

    /// Caller shield (negative half): no source line under
    /// `cli/src/commands/` may spell the pre-lift raw two-bullet +
    /// blank triple inline any more. The three pre-lift sites
    /// migrated; any future consumer that wants the same closer
    /// reaches for
    /// [`print_cargo_lock_and_cargo_nix_bullets_with_blank`] on
    /// first grep, not by copy-pasting the three-line shape from an
    /// existing site. The scan looks for a `Cargo.lock` bullet line
    /// immediately followed by a `Cargo.nix` bullet line — the exact
    /// pre-lift fingerprint — so unrelated inline `print_bullet_path`
    /// calls elsewhere in the file are not caught.
    #[test]
    fn no_command_module_still_spells_raw_cargo_lock_cargo_nix_bullet_pair() {
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
            let lines: Vec<&str> = source.lines().collect();
            for i in 0..lines.len().saturating_sub(1) {
                let a = lines[i];
                let b = lines[i + 1];
                let a_trim = a.trim_start();
                let b_trim = b.trim_start();
                if a_trim.starts_with("//") || b_trim.starts_with("//") {
                    continue;
                }
                if a.contains("print_bullet_path(")
                    && a.contains("\"Cargo.lock\"")
                    && b.contains("print_bullet_path(")
                    && b.contains("\"Cargo.nix\"")
                {
                    offenders.push((path.clone(), i + 1, format!("{}\n{}", a, b)));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `print_bullet_path(&<dir>.join(\"Cargo.lock\")) + \
             print_bullet_path(&<dir>.join(\"Cargo.nix\"))` bullet \
             pair(s) survive under `commands/` — route each through \
             `crate::cargo_lock_and_cargo_nix_bullets::\
             print_cargo_lock_and_cargo_nix_bullets_with_blank(<dir>)` \
             instead:\n{:#?}",
            offenders
        );
    }

    /// Caller shield (positive half): the pre-lift modules that
    /// housed the three sites MUST forward through
    /// [`print_cargo_lock_and_cargo_nix_bullets_with_blank`] — either
    /// DIRECTLY or INDIRECTLY via
    /// [`crate::cargo_nix_ceremony_summary_opener::print_cargo_nix_ceremony_summary_opener`],
    /// which delegates through this primitive — at least the pre-lift
    /// count of times, so a migration that dropped a call site
    /// outright leaves the negative "no raw inline shape" scan
    /// trivially satisfied by absence but the positive count still
    /// fails. Mirrors the sibling
    /// `every_prelift_module_forwards_through_bootstrap_dir` shield in
    /// [`crate::bootstrap_dir`].
    #[test]
    fn every_prelift_module_forwards_through_cargo_lock_and_cargo_nix_bullets() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let expectations: &[(&str, usize)] = &[("web_service.rs", 1), ("developer_tools.rs", 2)];
        let direct_needle = "print_cargo_lock_and_cargo_nix_bullets_with_blank(";
        // Reconstruct the indirect needle via `format!` so this
        // shield's own source text does not false-match itself.
        let indirect_needle = format!("{}(", "print_cargo_nix_ceremony_summary_opener");
        for (basename, min_count) in expectations {
            let path = commands_dir.join(basename);
            let source = std::fs::read_to_string(&path)
                .unwrap_or_else(|_| panic!("expected {} to exist", path.display()));
            let direct = source.matches(direct_needle).count();
            let indirect = source.matches(indirect_needle.as_str()).count();
            let forwards = direct + indirect;
            assert!(
                forwards >= *min_count,
                "{basename} must forward at least {min_count} \
                 (Cargo.lock, Cargo.nix, blank) closer stanza(s) \
                 through `{direct_needle}` (direct) or \
                 `crate::cargo_nix_ceremony_summary_opener::print_cargo_nix_ceremony_summary_opener(` \
                 (indirect via the summary opener); found \
                 {direct} direct + {indirect} indirect = {forwards}. \
                 A dropped call would leave the negative raw-shape scan \
                 satisfied by absence.",
            );
        }
    }
}
