//! Three-line success-summary opener stanza for every `crate2nix`-driven
//! regenerate / update workflow that closes on the `Cargo.lock` +
//! `Cargo.nix` manifest pair — the fused pairing of the
//! [`crate::cargo_nix_ceremony_banner::print_cargo_nix_ceremony_banner`]
//! headline banner, the
//! [`crate::cargo_lock_and_cargo_nix_bullets::print_cargo_lock_and_cargo_nix_bullets_with_blank`]
//! two-bullet manifest catalog, and the
//! [`crate::next_steps_review_the_changes_opener::print_next_steps_heading_then_review_the_changes`]
//! `Next steps:` + `1. Review the changes: git diff` opener.
//!
//! # Pre-lift census — three sibling three-call stanzas
//!
//! Three pre-lift sibling three-call stanzas — one in
//! `commands/web_service.rs` (`web_cargo_update` at :262-268) and two
//! in `commands/developer_tools.rs` (`rust_regenerate` at :362-368;
//! `rust_cargo_update` at :407-413) each restated
//!
//! ```ignore
//! crate::cargo_nix_ceremony_banner::print_cargo_nix_ceremony_banner(
//!     crate::cargo_nix_ceremony_banner::CargoNixCeremony::<X>,
//! );
//! crate::cargo_lock_and_cargo_nix_bullets::print_cargo_lock_and_cargo_nix_bullets_with_blank(
//!     &<workspace_dir>,
//! );
//! crate::next_steps_review_the_changes_opener::print_next_steps_heading_then_review_the_changes();
//! ```
//!
//! byte-for-byte, differing only in the [`CargoNixCeremony`] variant
//! and the caller-provided workspace directory:
//!
//! 1. `commands/web_service.rs::web_cargo_update` (:262-268) — Hanabi
//!    `cargo update` closer, `<X>` = `Update`, `<workspace_dir>` =
//!    `hanabi_dir` (from [`crate::hanabi_dir::hanabi_dir`]).
//! 2. `commands/developer_tools.rs::rust_regenerate` (:362-368) —
//!    generic rust-service regenerate closer, `<X>` = `Regeneration`,
//!    `<workspace_dir>` = `workspace_root` (from
//!    `read_service_env_and_chdir_to_workspace`).
//! 3. `commands/developer_tools.rs::rust_cargo_update` (:407-413) —
//!    generic rust-service update closer, `<X>` = `Update`,
//!    `<workspace_dir>` = `workspace_root`.
//!
//! Three sibling occurrences clear THEORY.md §VI.1's "two is a
//! coincidence, three is a law" threshold. Post-lift the three stanzas
//! route through [`print_cargo_nix_ceremony_summary_opener`]; a drift
//! in the (banner → bullets → next-steps) ordering, an inversion of
//! the bullets and the heading, or a duplication of any of the three
//! calls lands at ONE typed body and reaches all three consumers by
//! construction.
//!
//! # Coupling being pinned
//!
//! The three calls are not independent: they compose one narrative
//! payload — the ceremony's headline, the manifest catalog it produced
//! or updated, and the imperative next-step opener that invites the
//! operator to inspect the working-tree delta before proceeding to
//! the ceremony-specific `print_next_step(2, ...)` tail. Pre-lift each
//! site nailed the three calls into three independent inline
//! invocations; a copy-paste that dropped the bullets line, called
//! the next-steps opener before the banner, or double-printed the
//! banner compiled clean and silently mismatched the operator's read.
//! Post-lift the ordering lives at one function body and the
//! copy-paste hazard is foreclosed at the type level.
//!
//! # Distinct from the individual siblings
//!
//! [`crate::cargo_nix_ceremony_banner::print_cargo_nix_ceremony_banner`]
//! owns the ONE `━`-rule + green-bold-label + `━`-rule banner render
//! plus the following files-heading. [`crate::cargo_lock_and_cargo_nix_bullets::print_cargo_lock_and_cargo_nix_bullets_with_blank`]
//! owns the ONE `  • <dir>/Cargo.lock\n  • <dir>/Cargo.nix\n\n`
//! two-bullet catalog. [`crate::next_steps_review_the_changes_opener::print_next_steps_heading_then_review_the_changes`]
//! owns the ONE `Next steps:\n  1. Review the changes: git diff\n`
//! opener. This primitive is one dedicated fusion specialization for
//! the (banner, bullets, next-steps-opener) triple — the same
//! architectural split that
//! [`crate::next_steps_review_the_changes_opener`] carries against
//! [`crate::ui::print_next_steps_heading`] +
//! [`crate::ui::print_next_step`], and that
//! [`crate::cargo_lock_and_cargo_nix_bullets`] carries against
//! [`crate::ui::print_bullet_path`]. The primitive stays a
//! grammar-and-ordering owner (banner → bullets → next-steps), not a
//! render-behavior owner, so a future re-shaping of any of the three
//! underlying primitives rides through this specialization by
//! construction.
//!
//! # Distinct from the sibling `web_regenerate` closer
//!
//! `commands/web_service.rs::regenerate_hanabi` (:179-185) also emits
//! a [`CargoNixCeremony::Regeneration`] banner followed by a
//! [`crate::next_steps_review_the_changes_opener::print_next_steps_heading_then_review_the_changes`]
//! opener, but between them it emits an ad-hoc two-bullet catalog
//! naming `deps.nix` + `Cargo.nix` (via two direct
//! [`crate::ui::print_bullet_path`] calls with a bare trailing
//! `println!()`), NOT the shared
//! `Cargo.lock` + `Cargo.nix` pair this primitive owns. That fourth
//! site is deliberately out of scope for this primitive: its
//! two-bullet payload is distinct, and a collapse would either force
//! this primitive to grow a bullets-variant axis its three-site
//! sibling family does not exercise, or would silently rewrite the
//! `deps.nix` bullet into a `Cargo.lock` bullet at the operator's
//! readout.
//!
//! # Ordering invariant
//!
//! The three calls MUST fire in the (banner → bullets → next-steps)
//! order — the pre-lift three sites exhibit this shape, and a
//! runtime that ran the next-steps opener before the banner would
//! print `Next steps:` above `✅ <X> COMPLETE`, an inversion of the
//! headline-first grammar every ceremony closer across forge follows.
//! The primitive preserves the invariant by construction.
//!
//! # THEORY grounding
//!
//! - THEORY.md §V.1 (Construction guarantees; Types → Invariants →
//!   Proofs → Render Anywhere): the closed [`CargoNixCeremony`] enum
//!   sits at the primitive's boundary so the caller cannot pass an
//!   ill-typed ceremony tag, and the delegation covariance the
//!   sibling
//!   [`crate::cargo_nix_ceremony_banner::CargoNixCeremony::write_files_heading`]
//!   pins rides through this primitive by construction.
//! - THEORY.md §VI.1 (three-times rule): three sibling occurrences at
//!   the "two is a coincidence; three is a law" threshold, so the
//!   three-call stanza lifts onto ONE typed body.

use std::path::Path;

use crate::cargo_nix_ceremony_banner::CargoNixCeremony;

/// Print the three-line success-summary opener to stdout — the
/// fusion primitive three pre-lift sibling sites in
/// `commands/{web_service.rs, developer_tools.rs}` each spelled
/// inline via three independent calls to
/// [`crate::cargo_nix_ceremony_banner::print_cargo_nix_ceremony_banner`],
/// [`crate::cargo_lock_and_cargo_nix_bullets::print_cargo_lock_and_cargo_nix_bullets_with_blank`],
/// and
/// [`crate::next_steps_review_the_changes_opener::print_next_steps_heading_then_review_the_changes`].
///
/// `ceremony` selects the headline banner variant (`Regeneration` /
/// `Update`) and, in lockstep, the follow-on files-heading via the
/// closed [`CargoNixCeremony`] enum. `workspace_dir` is the directory
/// both manifest files live under — pre-lift sites pass `&hanabi_dir`
/// (from [`crate::hanabi_dir::hanabi_dir`]) or `&workspace_root` (from
/// `commands/developer_tools.rs::read_service_env_and_chdir_to_workspace`).
///
/// Delegates through the three underlying primitives so their
/// respective grammars keep single sources of truth — a future
/// re-shaping of the banner width, the bullet glyph, or the
/// `Next steps:` heading label rides through this primitive by
/// construction.
pub fn print_cargo_nix_ceremony_summary_opener(ceremony: CargoNixCeremony, workspace_dir: &Path) {
    crate::cargo_nix_ceremony_banner::print_cargo_nix_ceremony_banner(ceremony);
    crate::cargo_lock_and_cargo_nix_bullets::print_cargo_lock_and_cargo_nix_bullets_with_blank(
        workspace_dir,
    );
    crate::next_steps_review_the_changes_opener::print_next_steps_heading_then_review_the_changes();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Signature pin: the primitive accepts one `CargoNixCeremony`
    /// value and one `&Path`, and returns `()`. A future edit that
    /// widened the signature (say to take a `&str` next-steps
    /// override, or to return an `io::Result<()>`) would ripple to
    /// every caller and trip the type-check.
    #[test]
    fn primitive_accepts_ceremony_and_workspace_dir() {
        // Compile-time pin only — the fn pointer coerces iff the
        // signature matches. No stdout capture: the delegation
        // covariance below is what the three underlying byte-oracles
        // ([`cargo_nix_ceremony_banner`],
        // [`cargo_lock_and_cargo_nix_bullets`],
        // [`next_steps_review_the_changes_opener`]) already pin.
        let _: fn(CargoNixCeremony, &Path) = print_cargo_nix_ceremony_summary_opener;
    }

    /// Slice the module's own source to the production body — i.e.
    /// everything above the first `#[cfg(test)]` attribute — so the
    /// tests below can count the three delegation call sites in the
    /// production body without matching against needle-mentions inside
    /// their own `assert!` diagnostic messages.
    fn production_body() -> String {
        let source = include_str!("cargo_nix_ceremony_summary_opener.rs");
        let cutoff = source
            .find("#[cfg(test)]")
            .expect("production body ends at the test cfg attr");
        source[..cutoff].to_string()
    }

    /// Delegation pin: the primitive body MUST call each of the three
    /// underlying primitives exactly once. A future edit that dropped
    /// one call, duplicated one, or inserted a fourth (unlifted)
    /// primitive into the fused stanza flips this assertion. The scan
    /// runs against [`production_body`] (the slice above the first
    /// `#[cfg(test)]` attr) and filters through
    /// [`crate::test_support::code_line_hits`] so neither this
    /// docstring's own prose nor the test module's own needle-mentions
    /// inside `assert!` diagnostics false-match themselves.
    #[test]
    fn primitive_body_calls_each_underlying_primitive_exactly_once() {
        let body = production_body();
        let banner_hits =
            crate::test_support::code_line_hits(&body, "print_cargo_nix_ceremony_banner(");
        let bullets_hits = crate::test_support::code_line_hits(
            &body,
            "print_cargo_lock_and_cargo_nix_bullets_with_blank(",
        );
        let opener_hits = crate::test_support::code_line_hits(
            &body,
            "print_next_steps_heading_then_review_the_changes(",
        );
        assert_eq!(
            banner_hits.len(),
            1,
            "primitive body must call `print_cargo_nix_ceremony_banner(` \
             exactly once; found {}: {:#?}",
            banner_hits.len(),
            banner_hits
        );
        assert_eq!(
            bullets_hits.len(),
            1,
            "primitive body must call \
             `print_cargo_lock_and_cargo_nix_bullets_with_blank(` \
             exactly once; found {}: {:#?}",
            bullets_hits.len(),
            bullets_hits
        );
        assert_eq!(
            opener_hits.len(),
            1,
            "primitive body must call \
             `print_next_steps_heading_then_review_the_changes(` \
             exactly once; found {}: {:#?}",
            opener_hits.len(),
            opener_hits
        );
    }

    /// Ordering invariant: the banner MUST fire before the bullets,
    /// and the bullets MUST fire before the next-steps opener. A
    /// future edit that flipped the (banner → bullets → next-steps)
    /// ordering — say by hoisting the next-steps opener above the
    /// banner — would print `Next steps:` before `✅ <X> COMPLETE`,
    /// an inversion of the headline-first grammar every ceremony
    /// closer follows. The scan reads the production body and pins
    /// the three call sites' positions; the `//!` module doc, `///`
    /// fn doc, and the test module below are all skipped by
    /// [`production_body`] slicing at `#[cfg(test)]`, then by the
    /// `///`/`//!` filter below.
    #[test]
    fn primitive_body_emits_banner_before_bullets_before_next_steps() {
        let executable: String = production_body()
            .lines()
            .filter(|l| {
                let t = l.trim_start();
                !t.starts_with("//!") && !t.starts_with("///")
            })
            .collect::<Vec<_>>()
            .join("\n");
        let banner_pos = executable
            .find("print_cargo_nix_ceremony_banner(")
            .expect("banner call present in fn body");
        let bullets_pos = executable
            .find("print_cargo_lock_and_cargo_nix_bullets_with_blank(")
            .expect("bullets call present in fn body");
        let opener_pos = executable
            .find("print_next_steps_heading_then_review_the_changes(")
            .expect("next-steps opener call present in fn body");
        assert!(
            banner_pos < bullets_pos,
            "banner ({banner_pos}) must fire before bullets ({bullets_pos})",
        );
        assert!(
            bullets_pos < opener_pos,
            "bullets ({bullets_pos}) must fire before next-steps opener ({opener_pos})",
        );
    }

    /// Positive delegation shield: each pre-lift command module MUST
    /// forward through [`print_cargo_nix_ceremony_summary_opener`] at
    /// least the migrated count, so a migration that dropped a call
    /// site outright leaves the negative "no raw three-line stanza"
    /// scan (below) trivially satisfied by absence but the positive
    /// count still fails.
    ///
    /// Web-service.rs (×1: `web_cargo_update` update closer at
    /// :262-268). Developer-tools.rs (×2: `rust_regenerate`
    /// regeneration closer at :362-368, `rust_cargo_update` update
    /// closer at :407-413).
    #[test]
    fn every_prelift_module_forwards_through_summary_opener_primitive() {
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let expectations: &[(&str, usize)] = &[("web_service.rs", 1), ("developer_tools.rs", 2)];
        // Reconstruct the call-site needle via `format!` so this
        // shield's own source text does not false-match itself.
        let needle = format!("{}(", "print_cargo_nix_ceremony_summary_opener");
        for (basename, min_count) in expectations {
            let path = commands_dir.join(basename);
            let source = std::fs::read_to_string(&path).unwrap();
            let forwards = crate::test_support::code_line_hits(&source, &needle).len();
            assert!(
                forwards >= *min_count,
                "{basename} must forward at least {min_count} \
                 cargo-nix-ceremony summary-opener stanza(s) through \
                 `crate::cargo_nix_ceremony_summary_opener::\
                 print_cargo_nix_ceremony_summary_opener(`; \
                 found {forwards}. A dropped call would leave the \
                 negative raw-stanza scan satisfied by absence.",
            );
        }
    }

    /// Caller shield (negative half): no source line under
    /// `cli/src/commands/` may spell the pre-lift raw three-call
    /// stanza — a
    /// `print_cargo_nix_ceremony_banner(...);` call immediately
    /// followed (within four intervening code lines) by both a
    /// `print_cargo_lock_and_cargo_nix_bullets_with_blank(...);` call
    /// and a
    /// `print_next_steps_heading_then_review_the_changes();` call —
    /// inline any more. The three pre-lift sites migrated; any future
    /// consumer that wants the same closer reaches for
    /// [`print_cargo_nix_ceremony_summary_opener`] on first grep, not
    /// by copy-pasting the three-line shape from an existing site.
    ///
    /// The window is capped at four intervening lines so unrelated
    /// consumers that reach for one of the three underlying primitives
    /// in isolation (e.g. `regenerate_hanabi`, which uses the banner
    /// and the next-steps opener but interposes an ad-hoc
    /// `deps.nix` + `Cargo.nix` two-bullet catalog rather than the
    /// shared `Cargo.lock` + `Cargo.nix` bullets) are not caught.
    #[test]
    fn no_command_module_still_spells_raw_three_call_stanza() {
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let mut offenders: Vec<(PathBuf, usize)> = Vec::new();
        for entry in std::fs::read_dir(&commands_dir).unwrap().flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).unwrap();
            let executable_lines: Vec<(usize, String)> = source
                .lines()
                .enumerate()
                .filter(|(_, l)| {
                    let t = l.trim_start();
                    !t.starts_with("//!") && !t.starts_with("///") && !t.starts_with("//")
                })
                .map(|(i, l)| (i, l.to_string()))
                .collect();
            for i in 0..executable_lines.len() {
                let (idx0, first) = &executable_lines[i];
                if !first.contains("print_cargo_nix_ceremony_banner(") {
                    continue;
                }
                // Look for the sibling calls within a
                // four-executable-line window so unrelated banners
                // paired with different follow-ons are not caught.
                let window = &executable_lines[i + 1..(i + 6).min(executable_lines.len())];
                let has_bullets = window
                    .iter()
                    .any(|(_, l)| l.contains("print_cargo_lock_and_cargo_nix_bullets_with_blank("));
                let has_opener = window
                    .iter()
                    .any(|(_, l)| l.contains("print_next_steps_heading_then_review_the_changes("));
                if has_bullets && has_opener {
                    offenders.push((path.clone(), idx0 + 1));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw three-call `print_cargo_nix_ceremony_banner(...) + \
             print_cargo_lock_and_cargo_nix_bullets_with_blank(...) + \
             print_next_steps_heading_then_review_the_changes()` stanza(s) \
             survive under `commands/` — route each stanza through \
             `crate::cargo_nix_ceremony_summary_opener::\
             print_cargo_nix_ceremony_summary_opener(<ceremony>, <workspace_dir>)` \
             instead:\n{offenders:#?}"
        );
    }
}
