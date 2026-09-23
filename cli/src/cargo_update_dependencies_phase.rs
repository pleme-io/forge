//! Announce-run-ack fusion primitive for the `cargo update` dependency
//! refresh phase — the closer sibling of
//! [`crate::crate2nix_regenerate_step`] (which owns the analogous
//! announce+run+ack fusion for the `crate2nix generate` regeneration
//! phase). Both frontiers appear in adjacent `Step 1` / `Step 2` pairs
//! on the two workspace-scoped `cargo-update-*` ceremonies the lift
//! consolidates.
//!
//! # Pre-lift census — two sibling four-line stanzas
//!
//! Two pre-lift `commands/` sites each restated the
//!
//! ```ignore
//! crate::package_phase_announce::print_package_phase_announce(
//!     "Updating dependencies",
//!     "(cargo update)",
//! );
//! <cargo update body — differs in cwd axis and error-context narrative>
//! crate::ui::print_step_pass("Dependencies updated");
//! println!();
//! ```
//!
//! frame byte-for-byte around a differing `cargo update` body:
//!
//! 1. `commands/web_service.rs::web_cargo_update` (~L233-245) —
//!    `<cargo update body>` = `let mut cmd = Command::new(&cargo);
//!    cmd.arg("update").current_dir(&hanabi_dir);
//!    crate::retry::run_inherited_status(cmd, "cargo update").await
//!    .context("Failed to update Hanabi dependencies")?;`.
//! 2. `commands/developer_tools.rs::rust_cargo_update` (~L391-398) —
//!    `<cargo update body>` = `crate::nix::run_cargo_update(&cargo_bin())
//!    .await?;` (which internally routes through
//!    `crate::retry::run_bin_args_inherited_status(cargo_path, &["update"],
//!    "cargo update")` with the `"Failed to update Cargo.lock"` context).
//!
//! Both sibling bodies differ only along two axes:
//!
//! - **Working directory.** Site 1 passes `.current_dir(&hanabi_dir)`
//!   explicitly; site 2 relies on process cwd (already chdir'd to
//!   `workspace_root` by
//!   `read_service_env_and_chdir_to_workspace`). Post-lift both callers
//!   pass their workspace path through the `dir` axis of
//!   [`announce_and_run_cargo_update_in`] and the primitive threads it
//!   into [`crate::nix::run_cargo_update_in`]'s `.current_dir(dir)`
//!   Command builder — for site 2 the cwd axis is a no-op since process
//!   cwd already equals the passed directory.
//! - **Outer error-context narrative.** Site 1 wraps
//!   `"Failed to update Hanabi dependencies"`; site 2 inherits the
//!   canonical `"Failed to update Cargo.lock"` narrative from
//!   [`crate::nix::run_cargo_update`]. Post-lift the outer primitive
//!   accepts an `Option<&str>` `error_context` — `Some(...)` wraps the
//!   inner canonical `"Failed to update Cargo.lock"` context with the
//!   caller's caller-narrative, `None` propagates the canonical inner
//!   context unchanged.
//!
//! Post-lift the two stanzas route through
//! [`announce_and_run_cargo_update_in`]; a drift in the announce
//! grammar, the delegate contract, the ack shape, or the trailing
//! blank-separator ordering lands at ONE typed body and reaches both
//! consumers by construction.
//!
//! # Distinct from the sibling `crate2nix_regenerate_step` frontier
//!
//! [`crate::crate2nix_regenerate_step::announce_and_run_crate2nix_regenerate`]
//! owns the analogous announce+run+ack fusion for the
//! `crate2nix generate` regeneration phase (Step 2 of the same
//! `web_cargo_update` / `rust_cargo_update` ceremonies), with a `🦀`
//! U+1F980 CRAB glyph on the announce (via
//! `print_rust_toolchain_phase_announce`), a
//! `"Regenerating <target>"` announce label, and a
//! `"<target> regenerated"` ack. This primitive owns the Step 1
//! dependency-refresh phase, with a `📦` U+1F4E6 PACKAGE glyph on the
//! announce (via `print_package_phase_announce`), a
//! `"Updating dependencies"` announce label, and a
//! `"Dependencies updated"` ack. The two frontiers share the same
//! closer grammar (`print_step_pass` + trailing blank separator) but
//! diverge on delegate, glyph, announce label, ack label, and phase
//! ordinal, so a collapse would either lose the announce-glyph split
//! (build-input `📦` vs Rust-toolchain-phase `🦀`) or force one of the
//! two delegates to grow a shape its consumer sites have no reason to
//! accept.
//!
//! # Ordering invariant
//!
//! The step-pass ack and the trailing blank separator MUST NOT fire
//! when [`crate::nix::run_cargo_update_in`] fails — the `?`
//! propagation short-circuits before the ack, so a failed update does
//! not print `✅ Dependencies updated`. The pre-lift two sites
//! exhibited this shape (the `.await?` sat above the paired
//! `print_step_pass` and `println!()` calls), and the primitive
//! preserves the invariant by construction.

use std::path::Path;

use anyhow::{Context, Result};

/// The `"Updating dependencies"` announce label body both pre-lift
/// sites spelled inline on the
/// [`crate::package_phase_announce::print_package_phase_announce`]
/// call. Named as a `const` so a future re-branding of the label body
/// lands at one edit rather than through two inline literal edits.
pub const CARGO_UPDATE_ANNOUNCE_LABEL: &str = "Updating dependencies";

/// The dimmed-rendered `"(cargo update)"` detail body both pre-lift
/// sites spelled inline on the
/// [`crate::package_phase_announce::print_package_phase_announce`]
/// call. Names the operator-facing cargo verb the announce refers to.
pub const CARGO_UPDATE_ANNOUNCE_DETAIL: &str = "(cargo update)";

/// The `"Dependencies updated"` step-pass ack body both pre-lift
/// sites spelled inline on the
/// [`crate::ui::print_step_pass`] call after the `cargo update` body
/// returned `Ok(())`. Sibling of [`CARGO_UPDATE_ANNOUNCE_LABEL`].
pub const CARGO_UPDATE_ACK: &str = "Dependencies updated";

/// Fuse the `📦 Updating dependencies (cargo update)` colored
/// announce, the [`crate::nix::run_cargo_update_in`] delegate against
/// the caller-scoped `dir`, the `✅ Dependencies updated` step-pass
/// ack, and the trailing blank separator into ONE typed primitive.
///
/// `cargo_path` is the resolved `CARGO` binary path (typically read
/// through the caller's `cargo_bin()` sigil); `dir` is the working
/// directory the `cargo update` spawn runs inside (both pre-lift sites
/// pass their respective workspace directory —
/// [`crate::hanabi_dir::hanabi_dir`] for the Hanabi shared-BFF
/// consumer, `workspace_root` from
/// `read_service_env_and_chdir_to_workspace` for the Rust-workspace
/// consumer); `error_context`, when `Some`, wraps the inner canonical
/// `"Failed to update Cargo.lock"` context from
/// [`crate::nix::run_cargo_update_in`] with a caller-narrative bail
/// wrapper (site 1: `"Failed to update Hanabi dependencies"`), and
/// when `None` propagates the canonical inner context unchanged
/// (site 2, matching the pre-lift `nix::run_cargo_update` return
/// shape).
///
/// # Errors
///
/// Returns an error if [`crate::nix::run_cargo_update_in`] fails —
/// the canonical `(op, exit_code)` structural record from
/// [`crate::retry::run_inherited_status`] and the inner
/// `"Failed to update Cargo.lock"` narrative flow into the anyhow
/// chain by construction, with the optional
/// caller-narrative wrap layered on top. On failure the `?`
/// propagation short-circuits before the success ack, so a failed
/// update does not print `✅ Dependencies updated`.
pub async fn announce_and_run_cargo_update_in(
    cargo_path: &str,
    dir: impl AsRef<Path>,
    error_context: Option<&str>,
) -> Result<()> {
    crate::package_phase_announce::print_package_phase_announce(
        CARGO_UPDATE_ANNOUNCE_LABEL,
        CARGO_UPDATE_ANNOUNCE_DETAIL,
    );
    let result = crate::nix::run_cargo_update_in(cargo_path, dir).await;
    match error_context {
        Some(ctx) => result.context(ctx.to_string())?,
        None => result?,
    };
    crate::ui::print_step_pass(CARGO_UPDATE_ACK);
    println!();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Const-anchor pin: the canonical `"Updating dependencies"`
    // announce label body carries its exact pre-lift byte sequence.
    #[test]
    fn cargo_update_announce_label_carries_pre_lift_bytes() {
        assert_eq!(CARGO_UPDATE_ANNOUNCE_LABEL, "Updating dependencies");
    }

    // Const-anchor pin: the canonical `"(cargo update)"` dimmed
    // detail body carries its exact pre-lift byte sequence.
    #[test]
    fn cargo_update_announce_detail_carries_pre_lift_bytes() {
        assert_eq!(CARGO_UPDATE_ANNOUNCE_DETAIL, "(cargo update)");
    }

    // Const-anchor pin: the canonical `"Dependencies updated"`
    // step-pass ack body carries its exact pre-lift byte sequence.
    #[test]
    fn cargo_update_ack_carries_pre_lift_bytes() {
        assert_eq!(CARGO_UPDATE_ACK, "Dependencies updated");
    }

    // Byte-oracle: exercise the announce-line writer sibling of the
    // production `print_package_phase_announce` printer this primitive
    // delegates through, threading the primitive's own const label /
    // detail pair. Pins the exact rendered bytes: `📦` (U+1F4E6,
    // 4 bytes F0 9F 93 A6, no variation selector), one ASCII space,
    // the label body, one ASCII space, the detail body, then `\n`.
    #[test]
    fn write_cargo_update_announce_emits_exact_pre_lift_bytes() {
        let mut buf: Vec<u8> = Vec::new();
        crate::package_phase_announce::write_package_phase_announce(
            &mut buf,
            CARGO_UPDATE_ANNOUNCE_LABEL,
            CARGO_UPDATE_ANNOUNCE_DETAIL,
        )
        .unwrap();
        assert_eq!(
            buf,
            b"\xf0\x9f\x93\xa6 Updating dependencies (cargo update)\n"
        );
    }

    // Byte-oracle: exercise the ack-line writer sibling of the
    // production `print_step_pass` printer this primitive delegates
    // through, threading the primitive's own const ack body. Pins the
    // exact rendered bytes: three ASCII spaces of indent, the green
    // `\x1b[32m✅\x1b[0m` U+2705 WHITE HEAVY CHECK MARK glyph, one
    // ASCII space, the ack body, then `\n`.
    #[test]
    fn write_cargo_update_ack_emits_expected_shape() {
        let mut buf: Vec<u8> = Vec::new();
        crate::ui::write_step_pass(&mut buf, CARGO_UPDATE_ACK).unwrap();
        let rendered = String::from_utf8(buf).unwrap();
        assert!(
            rendered.contains("Dependencies updated"),
            "step-pass ack body must carry the pre-lift `Dependencies \
             updated` phrase; got: {:?}",
            rendered
        );
        assert!(
            rendered.starts_with("   "),
            "step-pass ack body must open with the three-space \
             indent grammar; got: {:?}",
            rendered
        );
        assert!(
            rendered.ends_with('\n'),
            "step-pass ack body must terminate with a trailing \
             newline; got: {:?}",
            rendered
        );
    }

    // Caller shield (negative half): no source line under
    // `cli/src/commands/` may spell the pre-lift raw
    // `"Updating dependencies"` announce label paired with the
    // `"(cargo update)"` detail inline on a
    // `print_package_phase_announce` call any more. Post-lift both
    // consumer sites route through
    // [`announce_and_run_cargo_update_in`]; any future consumer that
    // wants the same announce reaches for the primitive on first
    // grep, not by copy-pasting the raw literal.
    //
    // Narrowed to the exact `"Updating dependencies"` / `"(cargo
    // update)"` two-literal pair on the same or adjacent line so the
    // unrelated `commands/developer_tools.rs::rust_cargo_update`
    // command-intro banner (line ~380-385, `"Updating dependencies"`
    // paired with `"and regenerating Cargo.nix"` on the
    // `print_command_intro_banner` call — a different frontier) stays
    // out of scope.
    #[test]
    fn no_command_module_still_spells_raw_cargo_update_announce_pair() {
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
            for (idx, line) in lines.iter().enumerate() {
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") || trimmed.starts_with("///") {
                    continue;
                }
                if line.contains("\"(cargo update)\"") {
                    let window_start = idx.saturating_sub(2);
                    let window: String = lines[window_start..=idx].join("\n");
                    if window.contains("\"Updating dependencies\"")
                        && window.contains("print_package_phase_announce")
                    {
                        offenders.push((path.clone(), idx + 1, line.to_string()));
                    }
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `print_package_phase_announce(\"Updating dependencies\", \
             \"(cargo update)\")` announce stanza survives under \
             `commands/` — route it through \
             `crate::cargo_update_dependencies_phase::\
             announce_and_run_cargo_update_in` instead:\n{:#?}",
            offenders
        );
    }

    // Caller shield (negative half): no source line under
    // `cli/src/commands/` may spell the pre-lift raw
    // `print_step_pass("Dependencies updated")` step-pass ack inline
    // any more. Symmetric with the announce-pair shield above.
    #[test]
    fn no_command_module_still_spells_raw_cargo_update_ack() {
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
                if line.contains("print_step_pass(\"Dependencies updated\")") {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `print_step_pass(\"Dependencies updated\")` step-pass \
             ack literal survives under `commands/` — route it through \
             `crate::cargo_update_dependencies_phase::\
             announce_and_run_cargo_update_in` instead:\n{:#?}",
            offenders
        );
    }

    // Positive half of the shield: the two pre-lift command modules
    // MUST forward through
    // `crate::cargo_update_dependencies_phase::\
    // announce_and_run_cargo_update_in(` at least once each, so a
    // migration that dropped a call site outright leaves the negative
    // "no raw inline shape" scans trivially satisfied by absence but
    // the positive count still fails.
    #[test]
    fn both_prelift_modules_forward_through_announce_and_run_cargo_update_in() {
        use std::path::PathBuf;
        let cli_src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let canonical = "crate::cargo_update_dependencies_phase::\
                         announce_and_run_cargo_update_in(";
        for relative in &["commands/web_service.rs", "commands/developer_tools.rs"] {
            let source = std::fs::read_to_string(cli_src.join(relative)).unwrap();
            let hits = source
                .lines()
                .filter(|line| {
                    let trimmed = line.trim_start();
                    !trimmed.starts_with("//")
                        && !trimmed.starts_with("///")
                        && line.contains(canonical)
                })
                .count();
            assert!(
                hits >= 1,
                "{relative} must forward through `{canonical}` at \
                 least once (post-lift consumer of the Step-1 cargo \
                 update announce+run+ack frame). Found {hits} hit(s).",
            );
        }
    }
}
