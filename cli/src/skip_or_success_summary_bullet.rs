//! Typed primitive: emit a comprehensive-release summary bullet whose
//! terminal token is the canonical `SKIPPED` marker or a per-phase
//! success status.
//!
//! # Compounding
//!
//! Pre-lift FIVE sibling stanzas at the SUMMARY section of
//! `commands/comprehensive_release.rs::execute` (~L810-836) each carried
//! the same shape verbatim:
//!
//! ```ignore
//! crate::ui::print_bullet_item(&format!(
//!     "<label>: {}",
//!     if <skip_predicate> { "SKIPPED" } else { <success_status> },
//! ));
//! ```
//!
//! - `Unit tests` / `skip_unit_tests` / `"PASSED"`
//! - `Integration tests` / `skip_integration_tests || compose_file.is_none()` / `"PASSED"`
//! - `Docker build` / `skip_build` / `"SUCCESS"`
//! - `Registry push` / `skip_push` / `format!("SUCCESS (tag: {git_sha})")`
//! - `Kubernetes deploy` / `skip_deploy` / `"SUCCESS"`
//!
//! Every stanza carried the same three variation axes — a `&str` label
//! (`Unit tests` / `Integration tests` / …), a `bool` skip predicate
//! (`skip_unit_tests` / `skip_integration_tests || …` / …), and a
//! per-phase success status (`PASSED` / `SUCCESS` / `SUCCESS (tag: …)`).
//! The `"SKIPPED"` sentinel was restated five times inline; a drift on
//! one site to `"Skipped"` or `"SKIP"` would silently emit an
//! inconsistent operator-facing summary. Post-lift the `SKIPPED`
//! sentinel lives at ONE line ([`SKIP_SUMMARY_STATUS`]) and each caller
//! delegates through [`print_skip_or_success_summary_bullet`], so a new
//! summary line (a `commands/<new-phase>.rs` postamble bullet) picks up
//! the same skip sentinel and the same `"  • <label>: <status>\n"`
//! rendering by construction.
//!
//! # Theory grounding
//!
//! - THEORY.md §V.1 (Construction guarantees; Types → Invariants →
//!   Proofs → Render Anywhere): the paired byte-oracle sibling
//!   [`write_skip_or_success_summary_bullet`] is the Render Anywhere
//!   half — pinning the exact rendered bytes (two-space indent, U+2022
//!   `•` glyph, `<label>: <status>` body, trailing newline, ABSENCE of
//!   ANSI palette sequences) as a `cargo test`-verifiable invariant.
//! - THEORY.md §VI.1 (three-times rule; two-is-a-coincidence
//!   threshold): FIVE sibling occurrences past the tripping-point tier,
//!   so lifting onto ONE construction surface pre-empts the next-phase
//!   drift THEORY §VI.1 warns against.

use std::io;

/// The canonical skip sentinel emitted at the terminal token of a
/// summary bullet whose phase was gated off by an operator flag
/// (`--skip-<phase>`) or by a structural precondition failure (an
/// integration-test phase with no `compose_file`). Every summary bullet
/// this module renders emits this exact byte sequence when its
/// `skipped` argument is `true`.
///
/// Solve-once: the pre-lift SKIPPED literal was restated five times
/// inline across the SUMMARY section; a drift at one site to
/// `"Skipped"`, `"SKIP"`, or `"SKIPPED (see log)"` would silently split
/// the operator-facing summary grammar. Post-lift the literal lives at
/// exactly one line.
pub const SKIP_SUMMARY_STATUS: &str = "SKIPPED";

/// Emit a summary bullet whose terminal token is either the canonical
/// [`SKIP_SUMMARY_STATUS`] marker (when `skipped`) or the caller's
/// per-phase `success_status`.
///
/// Rendered shape: `"  • <label>: <status>\n"` — same as the pre-lift
/// `crate::ui::print_bullet_item(&format!("<label>: {}", …))` stanza's
/// byte output, so the operator-facing summary readout is preserved
/// verbatim.
///
/// Delegates to [`write_skip_or_success_summary_bullet`] against
/// [`std::io::stdout()`]; the writer split exists so the paired
/// byte-oracle test can pin the rendered bytes without shelling out
/// and capturing stdout.
pub fn print_skip_or_success_summary_bullet(label: &str, skipped: bool, success_status: &str) {
    let _ = write_skip_or_success_summary_bullet(
        &mut io::stdout().lock(),
        label,
        skipped,
        success_status,
    );
}

/// Writer-taking sibling to [`print_skip_or_success_summary_bullet`].
/// Emits `"  • <label>: <status>\n"` — routing through
/// [`crate::ui::write_bullet_item`] so the `"  • "` prefix, the U+2022
/// `•` glyph, and the trailing newline stay owned by the canonical
/// bullet-writer primitive rather than being restated here.
pub fn write_skip_or_success_summary_bullet<W: io::Write>(
    w: &mut W,
    label: &str,
    skipped: bool,
    success_status: &str,
) -> io::Result<()> {
    let status = if skipped {
        SKIP_SUMMARY_STATUS
    } else {
        success_status
    };
    crate::ui::write_bullet_item(w, &format!("{}: {}", label, status))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The skip sentinel is the exact all-caps `SKIPPED` string the
    /// pre-lift `if <skip> { "SKIPPED" } else { … }` ternary emitted at
    /// each of the five call sites.
    #[test]
    fn skip_summary_status_is_the_canonical_all_caps_skipped_marker() {
        assert_eq!(SKIP_SUMMARY_STATUS, "SKIPPED");
    }

    /// Byte-oracle: `skipped=true` renders the two-space + `•` + label
    /// + `: SKIPPED\n` shape verbatim, matching the pre-lift `format!`
    /// output on the skip arm.
    #[test]
    fn skip_arm_renders_two_space_bullet_label_colon_skipped_newline() {
        let mut buf = Vec::new();
        write_skip_or_success_summary_bullet(&mut buf, "Unit tests", true, "PASSED")
            .expect("Vec write is infallible");
        let got = String::from_utf8(buf).expect("bullet is UTF-8");
        assert_eq!(got, "  • Unit tests: SKIPPED\n");
    }

    /// Byte-oracle: `skipped=false` renders the per-phase success token
    /// (`PASSED` for test phases) verbatim, matching the pre-lift
    /// `else` arm of the `format!` output.
    #[test]
    fn success_arm_renders_two_space_bullet_label_colon_passed_newline() {
        let mut buf = Vec::new();
        write_skip_or_success_summary_bullet(&mut buf, "Unit tests", false, "PASSED")
            .expect("Vec write is infallible");
        let got = String::from_utf8(buf).expect("bullet is UTF-8");
        assert_eq!(got, "  • Unit tests: PASSED\n");
    }

    /// Byte-oracle: `skipped=false` with a `SUCCESS`-family per-phase
    /// success status renders that status verbatim — pins the
    /// `Docker build` / `Kubernetes deploy` sites' shape.
    #[test]
    fn success_arm_renders_docker_build_success_shape_verbatim() {
        let mut buf = Vec::new();
        write_skip_or_success_summary_bullet(&mut buf, "Docker build", false, "SUCCESS")
            .expect("Vec write is infallible");
        let got = String::from_utf8(buf).expect("bullet is UTF-8");
        assert_eq!(got, "  • Docker build: SUCCESS\n");
    }

    /// Byte-oracle: `skipped=false` with a `format!`-composed success
    /// status embedding a git-sha suffix renders the composed body
    /// verbatim — pins the `Registry push` site's `SUCCESS (tag:
    /// <sha>)` shape without the primitive needing to know about
    /// git-sha embedding.
    #[test]
    fn success_arm_carries_registry_push_tagged_success_status_verbatim() {
        let mut buf = Vec::new();
        let composed = format!("SUCCESS (tag: {})", "abc1234");
        write_skip_or_success_summary_bullet(&mut buf, "Registry push", false, &composed)
            .expect("Vec write is infallible");
        let got = String::from_utf8(buf).expect("bullet is UTF-8");
        assert_eq!(got, "  • Registry push: SUCCESS (tag: abc1234)\n");
    }

    /// Peer-comparison: the post-lift byte-oracle output matches the
    /// pre-lift `crate::ui::write_bullet_item(w, &format!("<label>: {}",
    /// if skipped { "SKIPPED" } else { success }))` shape byte-for-byte
    /// on every `(label, skipped, success)` triple the SUMMARY section
    /// pre-lift emitted. THEORY §V.1 Render Anywhere pin — a future
    /// regression that added an ANSI palette, dropped the newline, or
    /// swapped the two-space indent would fail this test at `cargo
    /// test` time rather than at operator readout.
    #[test]
    fn post_lift_matches_pre_lift_write_bullet_item_shape_on_every_pre_lift_triple() {
        let cases: &[(&str, bool, &str)] = &[
            ("Unit tests", true, "PASSED"),
            ("Unit tests", false, "PASSED"),
            ("Integration tests", true, "PASSED"),
            ("Integration tests", false, "PASSED"),
            ("Docker build", true, "SUCCESS"),
            ("Docker build", false, "SUCCESS"),
            ("Registry push", true, "SUCCESS (tag: abc1234)"),
            ("Registry push", false, "SUCCESS (tag: abc1234)"),
            ("Kubernetes deploy", true, "SUCCESS"),
            ("Kubernetes deploy", false, "SUCCESS"),
        ];
        for (label, skipped, success_status) in cases {
            let mut post_lift = Vec::new();
            write_skip_or_success_summary_bullet(&mut post_lift, label, *skipped, success_status)
                .expect("Vec write is infallible");

            let mut pre_lift = Vec::new();
            let status = if *skipped { "SKIPPED" } else { *success_status };
            crate::ui::write_bullet_item(&mut pre_lift, &format!("{}: {}", label, status))
                .expect("Vec write is infallible");

            assert_eq!(
                post_lift, pre_lift,
                "post-lift bytes must match pre-lift `write_bullet_item + \
                 format!` shape on triple ({:?}, {}, {:?})",
                label, skipped, success_status,
            );
        }
    }

    /// Solve-once shield: the pre-lift `if <skip> { "SKIPPED" } else {
    /// … }` ternary carrying the all-caps `SKIPPED` string token is
    /// removed from every command module. A future caller that
    /// re-inlined the ternary would silently emit an inconsistent skip
    /// sentinel (or drift the label formatting) — this shield refuses
    /// the re-inline anchored on the distinctive `{ "SKIPPED" } else`
    /// byte sequence.
    #[test]
    fn no_command_module_still_carries_pre_lift_skipped_ternary() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let sentinel = "{ \"SKIPPED\" } else";
        let mut offenders: Vec<PathBuf> = Vec::new();
        for entry in std::fs::read_dir(&commands_dir).unwrap().flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let content = std::fs::read_to_string(&path)
                .unwrap_or_else(|_| panic!("read {}", path.display()));
            if content.contains(sentinel) {
                offenders.push(path);
            }
        }
        assert!(
            offenders.is_empty(),
            "no re-inline shield: pre-lift `{{ \"SKIPPED\" }} else` \
             ternary must be lifted onto \
             `crate::skip_or_success_summary_bullet::print_skip_or_success_summary_bullet`; \
             offenders: {:?}",
            offenders,
        );
    }

    /// Positive delegation shield: the `commands/comprehensive_release.rs`
    /// SUMMARY section must route through
    /// [`print_skip_or_success_summary_bullet`] at exactly the
    /// five pre-lift sites. A lift that removed one caller's pre-lift
    /// stanza without wiring the primitive would silently drop that
    /// bullet from the operator-facing summary.
    #[test]
    fn comprehensive_release_delegates_to_summary_bullet_primitive_five_times() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands")
            .join("comprehensive_release.rs");
        let content =
            std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("read {}", path.display()));
        let hits = content
            .matches("crate::skip_or_success_summary_bullet::print_skip_or_success_summary_bullet(")
            .count();
        assert_eq!(
            hits, 5,
            "positive delegation shield: `commands/comprehensive_release.rs` \
             must delegate through `crate::skip_or_success_summary_bullet::\
             print_skip_or_success_summary_bullet` at exactly FIVE sites \
             (Unit tests / Integration tests / Docker build / Registry push \
             / Kubernetes deploy); found {}",
            hits,
        );
    }
}
