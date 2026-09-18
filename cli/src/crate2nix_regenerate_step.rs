//! Announce-run-ack fusion primitive for the `crate2nix generate`
//! regeneration ceremony that operates on a caller-scoped working
//! directory — the `run_crate2nix_in` sibling of
//! [`crate::generate_cargo_nix_step`] (which owns the
//! `nix run nixpkgs#crate2nix -- generate <argv>` wrapped-generate
//! frontier).
//!
//! # Pre-lift census — two sibling five-line stanzas
//!
//! Two pre-lift `commands/web_service.rs` sites each restated the
//!
//! ```ignore
//! crate::rust_toolchain_phase_announce::print_rust_toolchain_phase_announce(
//!     "Regenerating <target>",
//!     "(crate2nix generate)",
//! );
//! crate::nix::run_crate2nix_in(&crate2nix, &hanabi_dir)
//!     .await
//!     .context("Failed to regenerate Hanabi Cargo.nix")?;
//! crate::ui::print_step_pass("<target> regenerated");
//! println!();
//! ```
//!
//! stanza byte-for-byte, differing only in the `<target>` display
//! body threaded through both the `Regenerating <target>` announce
//! label and the `<target> regenerated` step-pass ack:
//!
//! 1. `commands/web_service.rs::web_regenerate` (:171-180) — Step 2
//!    Hanabi Cargo.nix regeneration, `<target>` = `"Hanabi Cargo.nix"`.
//! 2. `commands/web_service.rs::web_cargo_update` (:258-267) — Step 2
//!    Cargo.nix regeneration, `<target>` = `"Cargo.nix"`.
//!
//! Both stanzas thread the same `crate::nix::run_crate2nix_in(&crate2nix,
//! &hanabi_dir)` delegate (both sites operate on the Hanabi platform
//! directory — see [`crate::hanabi_dir::hanabi_dir`]), the same
//! `"(crate2nix generate)"` dimmed detail body, and the same
//! `"Failed to regenerate Hanabi Cargo.nix"` outer-`.context` narrative
//! wrapping the inner `run_crate2nix_in` context. Post-lift the two
//! stanzas route through [`announce_and_run_crate2nix_regenerate`]; a
//! drift in the announce grammar, the delegate contract, the ack
//! shape, or the trailing blank-separator ordering lands at ONE
//! typed body and reaches both consumers by construction.
//!
//! # Distinct from the sibling `generate_cargo_nix_step` frontier
//!
//! [`crate::generate_cargo_nix_step::announce_and_generate_cargo_nix`]
//! owns the analogous announce+run+ack fusion for the
//! `nix run nixpkgs#crate2nix -- generate <argv>` wrapped-generate
//! shape (via [`crate::nix::run_nix_wrapped_crate2nix`]), with a `📦`
//! U+1F4E6 PACKAGE glyph on the announce, a fixed `["-f", "Cargo.toml",
//! "-o", "Cargo.nix"]` argv tail, and a `"Cargo.nix generated"` ack
//! body. This primitive owns the direct-binary
//! `crate2nix generate` shape scoped to a caller-provided working
//! directory (via [`crate::nix::run_crate2nix_in`]), with a `🦀`
//! U+1F980 CRAB glyph on the announce, no argv tail beyond `generate`,
//! and a caller-provided `<target>` display body threaded through
//! both the announce label and the ack. The two frontiers share the
//! same closer grammar (`print_step_pass` + trailing blank
//! separator) but diverge on delegate, glyph, and argv shape, so a
//! collapse would either lose the announce-glyph split (build-
//! input `📦` vs Rust-toolchain-phase `🦀`) or force one of the two
//! delegates to grow a shape its consumer sites have no reason to
//! accept.
//!
//! # Ordering invariant
//!
//! The step-pass ack and the trailing blank separator MUST NOT fire
//! when [`crate::nix::run_crate2nix_in`] fails — the `?` propagation
//! short-circuits before the ack, so a failed regenerate does not
//! print `✅ <target> regenerated`. The pre-lift two sites exhibited
//! this shape (the `.await?` sat above the `print_step_pass` +
//! `println!()` pair), and the primitive preserves the invariant by
//! construction.

use std::path::Path;

use anyhow::{Context, Result};

/// The dimmed-rendered parenthesized detail body two pre-lift sites
/// spelled inline as `"(crate2nix generate)".dimmed()` on the
/// [`crate::rust_toolchain_phase_announce::print_rust_toolchain_phase_announce`]
/// call. Named as a `const` so a future re-branding of the detail
/// body lands at one edit rather than through two inline literal
/// edits, and any future byte-oracle writer sibling can pin the exact
/// rendered payload without duplicating the literal.
pub const CRATE2NIX_REGENERATE_ANNOUNCE_DETAIL: &str = "(crate2nix generate)";

/// The outer-`.context` narrative both pre-lift sites wrapped the
/// [`crate::nix::run_crate2nix_in`] call with:
/// `"Failed to regenerate Hanabi Cargo.nix"`. Both consumer sites
/// operate on the Hanabi platform directory (see
/// [`crate::hanabi_dir::hanabi_dir`]) so the context body names the
/// Hanabi component regardless of the `target_name` display body —
/// preserving the pre-lift bytes at both sites, including the
/// `web_cargo_update` site whose display ack abbreviates to
/// `"Cargo.nix"` but whose failure narrative still spells
/// `"Hanabi Cargo.nix"`.
pub const CRATE2NIX_REGENERATE_CONTEXT: &str = "Failed to regenerate Hanabi Cargo.nix";

/// Compose the `"Regenerating <target>"` announce label body two
/// pre-lift sites spelled inline (`"Regenerating Hanabi Cargo.nix"`
/// / `"Regenerating Cargo.nix"`). The single-parameter shape shields
/// the announce grammar from a drift in one caller.
fn format_regenerate_announce_label(target_name: &str) -> String {
    format!("Regenerating {}", target_name)
}

/// Compose the `"<target> regenerated"` step-pass ack body two
/// pre-lift sites spelled inline (`"Hanabi Cargo.nix regenerated"` /
/// `"Cargo.nix regenerated"`). Sibling of
/// [`format_regenerate_announce_label`].
fn format_regenerated_step_pass(target_name: &str) -> String {
    format!("{} regenerated", target_name)
}

/// Fuse the `🦀 Regenerating <target> (crate2nix generate)` colored
/// announce, the [`crate::nix::run_crate2nix_in`] delegate against
/// the caller-scoped `dir`, the `✅ <target> regenerated` step-pass
/// ack, and the trailing blank separator into ONE typed primitive.
///
/// `crate2nix_path` is the resolved `CRATE2NIX` binary path
/// (typically read through the caller's `crate2nix_bin()` sigil);
/// `dir` is the working directory the `crate2nix generate` spawn
/// runs inside (both pre-lift sites pass
/// [`crate::hanabi_dir::hanabi_dir`]); `target_name` is the display
/// body threaded through both the `Regenerating <target>` announce
/// label and the `<target> regenerated` ack body.
///
/// # Errors
///
/// Returns an error if [`crate::nix::run_crate2nix_in`] fails — the
/// outer [`CRATE2NIX_REGENERATE_CONTEXT`] wrap carries the
/// caller-narrative into the anyhow chain alongside the canonical
/// `(op, exit_code)` structural record from
/// [`crate::retry::run_inherited_status`]. On failure the `?`
/// propagation short-circuits before the success ack, so a failed
/// regenerate does not print `✅ <target> regenerated`.
pub async fn announce_and_run_crate2nix_regenerate(
    crate2nix_path: &str,
    dir: &Path,
    target_name: &str,
) -> Result<()> {
    crate::rust_toolchain_phase_announce::print_rust_toolchain_phase_announce(
        &format_regenerate_announce_label(target_name),
        CRATE2NIX_REGENERATE_ANNOUNCE_DETAIL,
    );
    crate::nix::run_crate2nix_in(crate2nix_path, dir)
        .await
        .context(CRATE2NIX_REGENERATE_CONTEXT)?;
    crate::ui::print_step_pass(&format_regenerated_step_pass(target_name));
    println!();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Const-anchor pin: the canonical `"(crate2nix generate)"` dimmed
    // detail body carries its exact pre-lift byte sequence.
    #[test]
    fn crate2nix_regenerate_announce_detail_carries_pre_lift_bytes() {
        assert_eq!(CRATE2NIX_REGENERATE_ANNOUNCE_DETAIL, "(crate2nix generate)");
    }

    // Const-anchor pin: the canonical
    // `"Failed to regenerate Hanabi Cargo.nix"` outer-`.context`
    // narrative both pre-lift sites spelled verbatim.
    #[test]
    fn crate2nix_regenerate_context_carries_pre_lift_bytes() {
        assert_eq!(
            CRATE2NIX_REGENERATE_CONTEXT,
            "Failed to regenerate Hanabi Cargo.nix"
        );
    }

    // Projection pin: `Regenerating <target>` label composition. The
    // `web_regenerate` site pre-lift spelled `"Regenerating Hanabi
    // Cargo.nix"` and the `web_cargo_update` site spelled
    // `"Regenerating Cargo.nix"` — both fall out of this single
    // formatter under the target-name axis.
    #[test]
    fn regenerate_announce_label_covers_both_pre_lift_variants() {
        assert_eq!(
            format_regenerate_announce_label("Hanabi Cargo.nix"),
            "Regenerating Hanabi Cargo.nix"
        );
        assert_eq!(
            format_regenerate_announce_label("Cargo.nix"),
            "Regenerating Cargo.nix"
        );
    }

    // Projection pin: `<target> regenerated` ack composition. Same
    // two pre-lift variants (`"Hanabi Cargo.nix regenerated"` /
    // `"Cargo.nix regenerated"`) fall out of the formatter under the
    // target-name axis, so the announce-and-ack pair stay
    // parameterized by the same single `target_name` argument at
    // both consumer sites.
    #[test]
    fn regenerated_step_pass_covers_both_pre_lift_variants() {
        assert_eq!(
            format_regenerated_step_pass("Hanabi Cargo.nix"),
            "Hanabi Cargo.nix regenerated"
        );
        assert_eq!(
            format_regenerated_step_pass("Cargo.nix"),
            "Cargo.nix regenerated"
        );
    }

    // Byte-oracle: exercise the announce-line writer sibling of the
    // production `print_rust_toolchain_phase_announce` printer this
    // primitive delegates through, threading the primitive's own
    // `format_regenerate_announce_label` projection and detail
    // constant. Pins the exact rendered bytes for the `web_regenerate`
    // variant: `🦀` (U+1F980, 4 bytes F0 9F A6 80, no variation
    // selector), one ASCII space, the projected label body, one
    // ASCII space, the detail body, then `\n`.
    #[test]
    fn write_regenerate_announce_matches_hanabi_variant_bytes() {
        let mut buf: Vec<u8> = Vec::new();
        crate::rust_toolchain_phase_announce::write_rust_toolchain_phase_announce(
            &mut buf,
            &format_regenerate_announce_label("Hanabi Cargo.nix"),
            CRATE2NIX_REGENERATE_ANNOUNCE_DETAIL,
        )
        .unwrap();
        assert_eq!(
            buf,
            b"\xf0\x9f\xa6\x80 Regenerating Hanabi Cargo.nix (crate2nix generate)\n"
        );
    }

    // Byte-oracle: the `web_cargo_update` variant.
    #[test]
    fn write_regenerate_announce_matches_cargo_nix_variant_bytes() {
        let mut buf: Vec<u8> = Vec::new();
        crate::rust_toolchain_phase_announce::write_rust_toolchain_phase_announce(
            &mut buf,
            &format_regenerate_announce_label("Cargo.nix"),
            CRATE2NIX_REGENERATE_ANNOUNCE_DETAIL,
        )
        .unwrap();
        assert_eq!(
            buf,
            b"\xf0\x9f\xa6\x80 Regenerating Cargo.nix (crate2nix generate)\n"
        );
    }

    // Caller shield (negative half): no source line under
    // `cli/src/commands/` may spell the pre-lift raw
    // `"Regenerating Hanabi Cargo.nix"` or `"Regenerating Cargo.nix"`
    // announce label inline any more. The two pre-lift sites in
    // `commands/web_service.rs` migrated; any future consumer that
    // wants the same announce reaches for
    // [`announce_and_run_crate2nix_regenerate`] on first grep, not by
    // copy-pasting the raw literal.
    #[test]
    fn no_command_module_still_spells_raw_regenerate_announce_label() {
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
                if line.contains("\"Regenerating Hanabi Cargo.nix\"")
                    || line.contains("\"Regenerating Cargo.nix\"")
                {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `\"Regenerating (Hanabi )?Cargo.nix\"` announce label \
             literal(s) survive under `commands/` — route each through \
             `crate::crate2nix_regenerate_step::announce_and_run_crate2nix_regenerate` \
             instead:\n{:#?}",
            offenders
        );
    }

    // Caller shield (negative half): no source line under
    // `cli/src/commands/` may spell the pre-lift raw
    // `print_step_pass("Hanabi Cargo.nix regenerated")` or
    // `print_step_pass("Cargo.nix regenerated")` step-pass ack
    // inline any more. Narrowed to the `print_step_pass` frontier so
    // the unrelated `info!("Cargo.nix regenerated")` tracing line in
    // `commands/tool.rs::bump` (a distinct surface — log-only, no
    // announce/ack ceremony — see the "Distinct from the sibling
    // `run_crate2nix_in_sync` third site" carve-out in the module
    // doc) stays out of scope. Symmetric with the announce-label
    // shield above.
    #[test]
    fn no_command_module_still_spells_raw_regenerated_step_pass_ack() {
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
                if line.contains("print_step_pass(\"Hanabi Cargo.nix regenerated\")")
                    || line.contains("print_step_pass(\"Cargo.nix regenerated\")")
                {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `print_step_pass(\"(Hanabi )?Cargo.nix regenerated\")` \
             step-pass ack literal(s) survive under `commands/` — route \
             each through `crate::crate2nix_regenerate_step::\
             announce_and_run_crate2nix_regenerate` instead:\n{:#?}",
            offenders
        );
    }

    // Positive half of the shield: the pre-lift file MUST forward
    // through
    // `crate::crate2nix_regenerate_step::announce_and_run_crate2nix_regenerate(`
    // at least twice, so a migration that dropped a call site
    // outright leaves the negative "no raw inline shape" scans
    // trivially satisfied by absence but the positive count still
    // fails.
    #[test]
    fn every_prelift_module_forwards_through_announce_and_run_crate2nix_regenerate() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let expectations: &[(&str, usize)] = &[("web_service.rs", 2)];
        let needle = "crate2nix_regenerate_step::announce_and_run_crate2nix_regenerate(";
        for (basename, min_count) in expectations {
            let path = commands_dir.join(basename);
            let source = std::fs::read_to_string(&path)
                .unwrap_or_else(|_| panic!("expected {} to exist", path.display()));
            let forwards = source.matches(needle).count();
            assert!(
                forwards >= *min_count,
                "{basename} must forward at least {min_count} \
                 announce+crate2nix-regenerate stanza(s) through \
                 `{needle}`; found {forwards}. A dropped call would \
                 leave the negative raw-shape scans satisfied by absence.",
            );
        }
    }
}
