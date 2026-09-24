//! Announce-and-reconcile-`flux-system` step primitive with the
//! visible `println!("   🔄 Reconciling <target>...")` announce +
//! [`crate::ui::print_step_pass`] ack grammar.
//!
//! Two pre-lift sibling stanzas — one at
//! `commands/flux.rs::reconcile_source` (dispatches through
//! [`crate::flux_reconcile::reconcile_source_git`], announce target
//! `"git source"`, ack `"Git source reconciled"`, context envelope
//! `"Failed to reconcile FluxCD git source"`) and one at
//! `commands/flux.rs::reconcile_kustomization` (dispatches through
//! [`crate::flux_reconcile::reconcile_kustomization`] with
//! `with_source=false`, announce target `"kustomization"`, ack
//! `"Kustomization reconciled"`, context envelope `"Failed to
//! reconcile root FluxCD kustomization"`) — each spelled the same
//! shape verbatim:
//!
//! ```ignore
//! println!("   🔄 Reconciling <target>...");
//! crate::flux_reconcile::<primitive>("flux-system", "flux-system"[, false])
//!     .await
//!     .context("Failed to reconcile <context-detail>")?;
//! crate::ui::print_step_pass("<Ack-label>");
//! ```
//!
//! Both callers reconcile the same `("flux-system", "flux-system")`
//! target/namespace pair (the root FluxCD kustomization); both emit
//! the announcement via the three-space-indented `println!("   🔄
//! Reconciling …")` grammar (distinct from the `tracing::info!`
//! grammar the sibling `flux_system_reconcile` fusion primitive
//! owns); both close with a
//! [`crate::ui::print_step_pass`] completion signal.
//!
//! # Semantic split from [`crate::commands::flux_system_reconcile`]
//!
//! The sibling `commands/flux_system_reconcile.rs` primitive owns
//! the `tracing::info!("🔄 Triggering FluxCD reconciliation...") +
//! info_success!/warn_nonfatal!` grammar that
//! `commands/{deploy,github_runner_ci}.rs` share. THIS primitive
//! owns the DIFFERENT visible grammar that `commands/flux.rs`
//! shares. Splitting them into two typed primitives — rather than
//! forcing one enum to carry both grammars — keeps each caller's
//! narrative contract at exactly one construction surface, so a
//! future re-branding of one grammar (e.g. moving the `flux.rs`
//! sites onto `tracing::info!`) is a caller-level migration, not
//! an in-place edit to a bundled primitive shared across two
//! independent visual contracts.
//!
//! # Correlated axis
//!
//! The per-site axes — which underlying reconcile primitive to
//! invoke, the announce noun, the ack sentence, the context
//! envelope — are NOT independent: they correlate under a single
//! [`FluxReconcileAnnounceStep`] enum discriminant. A future caller
//! cannot silently drift the announce noun off the underlying
//! primitive because the enum owns the whole correlated tuple.

use anyhow::{Context, Result};

use crate::flux_reconcile;

/// The canonical `("flux-system", "flux-system")` `(name, namespace)`
/// pair the two sibling flows each spliced verbatim into the flux
/// argv. Named as a `const` so a future re-branding of the root
/// FluxCD kustomization (`flux-system` → `flux-root`) flows through
/// one edit.
const FLUX_SYSTEM_NAME: &str = "flux-system";

/// The canonical `flux-system` namespace argument the two sibling
/// flows each passed as the second positional slot. Named as a
/// `const` alongside [`FLUX_SYSTEM_NAME`] so the pair the primitive
/// owns stays visibly coupled at one site.
const FLUX_SYSTEM_NAMESPACE: &str = "flux-system";

/// The two typed variants of the announce-and-reconcile-`flux-system`
/// stepwise stanza the fusion primitive supports.
///
/// The pre-lift two sites each picked their underlying reconcile
/// primitive, their announce noun, their ack sentence, and their
/// context envelope INDEPENDENTLY, at inline literal call sites — a
/// silent drift that swapped the `reconcile_source_git` dispatch in
/// against a `"kustomization"` announce (or vice versa) would have
/// shipped with no test surface catching it. Encoding the correlated
/// tuple as a discriminant with [`Self::announce_target`],
/// [`Self::ack_label`], and [`Self::context_message`] projections
/// makes the pairing structurally impossible to break: a future
/// re-tuning of any single axis touches this enum, and every caller
/// inherits the invariant by construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FluxReconcileAnnounceStep {
    /// Reconcile the FluxCD `flux-system` git source via
    /// [`flux_reconcile::reconcile_source_git`]. Consumed by the
    /// pre-lift `commands/flux.rs::reconcile_source` site.
    GitSource,
    /// Reconcile the root FluxCD `flux-system` kustomization via
    /// [`flux_reconcile::reconcile_kustomization`] with
    /// `with_source=false`. Consumed by the pre-lift
    /// `commands/flux.rs::reconcile_kustomization` site.
    RootKustomization,
}

impl FluxReconcileAnnounceStep {
    /// The noun spliced into the `"   🔄 Reconciling <target>..."`
    /// announce line for this step.
    #[inline]
    #[must_use]
    pub const fn announce_target(self) -> &'static str {
        match self {
            Self::GitSource => "git source",
            Self::RootKustomization => "kustomization",
        }
    }

    /// The sentence handed to [`crate::ui::print_step_pass`] on the
    /// success arm for this step.
    #[inline]
    #[must_use]
    pub const fn ack_label(self) -> &'static str {
        match self {
            Self::GitSource => "Git source reconciled",
            Self::RootKustomization => "Kustomization reconciled",
        }
    }

    /// The anyhow context envelope wrapped around the specialized
    /// [`flux_reconcile`] error type on the failure arm.
    #[inline]
    #[must_use]
    pub const fn context_message(self) -> &'static str {
        match self {
            Self::GitSource => "Failed to reconcile FluxCD git source",
            Self::RootKustomization => "Failed to reconcile root FluxCD kustomization",
        }
    }
}

/// Byte-oracle sibling of [`run_flux_reconcile_announce_step`]: write
/// the canonical `"   🔄 Reconciling <target>...\n"` announce line
/// for `step` to `w`, byte-for-byte identical to the visual grammar
/// the two sibling flows in `commands/flux.rs` present to an
/// operator watching the terminal. A drift here — the leading
/// three-space indent, the `🔄` glyph, the trailing `...`, the
/// terminating newline — surfaces as a localized test failure at one
/// site, not as silent grammar-drift across two flows.
///
/// Same writer/print split every prior sibling-writer refactor
/// honors (see `flux_system_reconcile.rs`,
/// `pod_probe_pending_wait_line.rs`, `nonfatal_warning.rs` for the
/// canonical rationale).
#[allow(dead_code)] // See doc comment: the writer is a test/byte-oracle
                    // peer of the stdout-routed
                    // `run_flux_reconcile_announce_step`, and a future
                    // `collect_flux_reconcile_narratives` audit sibling
                    // will consume it directly.
pub fn write_flux_reconcile_announce_line<W: std::io::Write>(
    w: &mut W,
    step: FluxReconcileAnnounceStep,
) -> std::io::Result<()> {
    writeln!(w, "   \u{1f504} Reconciling {}...", step.announce_target())
}

/// Emit the canonical `"   🔄 Reconciling <target>..."` announce
/// line, dispatch to the correlated [`flux_reconcile`] primitive
/// against the `("flux-system", "flux-system")` target/namespace
/// pair, wrap any specialized error in the correlated anyhow
/// context envelope, and — on success — close with the correlated
/// [`crate::ui::print_step_pass`] ack sentence.
///
/// Fusion primitive over the two sibling stanzas the FluxCD-force-
/// reconcile flow in `commands/flux.rs` spelled inline (see the
/// [module docs](self) for the pre-lift shape). The pre-lift
/// callers picked the underlying reconcile primitive, the announce
/// noun, the ack sentence, and the context envelope at independent
/// inline literal sites; post-lift all four axes correlate under
/// [`FluxReconcileAnnounceStep`] and the primitive itself owns the
/// three-space-indented announce grammar, the argv contract on the
/// reconcile, the anyhow-context envelope, and the
/// [`crate::ui::print_step_pass`] ack.
///
/// # Grammar pinned by the byte-oracle sibling
///
/// The announce-line bytes are pinned by
/// [`write_flux_reconcile_announce_line`] under `#[cfg(test)]`; a
/// drift on either variant's announce noun surfaces as a localized
/// test failure.
pub async fn run_flux_reconcile_announce_step(step: FluxReconcileAnnounceStep) -> Result<()> {
    println!("   \u{1f504} Reconciling {}...", step.announce_target());
    match step {
        FluxReconcileAnnounceStep::GitSource => {
            flux_reconcile::reconcile_source_git(FLUX_SYSTEM_NAME, FLUX_SYSTEM_NAMESPACE)
                .await
                .context(step.context_message())?;
        }
        FluxReconcileAnnounceStep::RootKustomization => {
            flux_reconcile::reconcile_kustomization(FLUX_SYSTEM_NAME, FLUX_SYSTEM_NAMESPACE, false)
                .await
                .context(step.context_message())?;
        }
    }
    crate::ui::print_step_pass(step.ack_label());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pin the announce-target axis on the [`GitSource`] variant.
    #[test]
    fn git_source_announce_target_reads_git_source() {
        assert_eq!(
            FluxReconcileAnnounceStep::GitSource.announce_target(),
            "git source",
        );
    }

    /// Pin the announce-target axis on the [`RootKustomization`]
    /// variant.
    #[test]
    fn root_kustomization_announce_target_reads_kustomization() {
        assert_eq!(
            FluxReconcileAnnounceStep::RootKustomization.announce_target(),
            "kustomization",
        );
    }

    /// Pin the ack-label axis on the [`GitSource`] variant. The
    /// pre-lift caller spelled `"Git source reconciled"` verbatim
    /// at `commands/flux.rs::reconcile_source`.
    #[test]
    fn git_source_ack_label_reads_git_source_reconciled() {
        assert_eq!(
            FluxReconcileAnnounceStep::GitSource.ack_label(),
            "Git source reconciled",
        );
    }

    /// Pin the ack-label axis on the [`RootKustomization`] variant.
    /// The pre-lift caller spelled `"Kustomization reconciled"`
    /// verbatim at `commands/flux.rs::reconcile_kustomization`.
    #[test]
    fn root_kustomization_ack_label_reads_kustomization_reconciled() {
        assert_eq!(
            FluxReconcileAnnounceStep::RootKustomization.ack_label(),
            "Kustomization reconciled",
        );
    }

    /// Pin the context-envelope axis on the [`GitSource`] variant.
    /// The pre-lift caller wrapped the specialized
    /// `FluxSourceGitReconcileError` in this anyhow context.
    #[test]
    fn git_source_context_message_reads_git_source_envelope() {
        assert_eq!(
            FluxReconcileAnnounceStep::GitSource.context_message(),
            "Failed to reconcile FluxCD git source",
        );
    }

    /// Pin the context-envelope axis on the [`RootKustomization`]
    /// variant. The pre-lift caller wrapped the specialized
    /// `FluxReconcileError` in this anyhow context.
    #[test]
    fn root_kustomization_context_message_reads_root_envelope() {
        assert_eq!(
            FluxReconcileAnnounceStep::RootKustomization.context_message(),
            "Failed to reconcile root FluxCD kustomization",
        );
    }

    /// Pin the exact announce-line bytes for the [`GitSource`]
    /// variant: `"   🔄 Reconciling git source...\n"` — three-space
    /// indent, the `🔄` glyph, the sibling-shared `"Reconciling "`
    /// verb-phrase, the `announce_target()` noun, the trailing
    /// `"..."`, and the terminating newline.
    #[test]
    fn write_announce_line_emits_git_source_bytes() {
        let mut buf: Vec<u8> = Vec::new();
        write_flux_reconcile_announce_line(&mut buf, FluxReconcileAnnounceStep::GitSource)
            .expect("write to Vec<u8> is infallible");
        assert_eq!(
            String::from_utf8(buf).expect("ASCII+UTF-8 output"),
            "   \u{1f504} Reconciling git source...\n",
        );
    }

    /// Pin the exact announce-line bytes for the [`RootKustomization`]
    /// variant: `"   🔄 Reconciling kustomization...\n"` — same
    /// three-space indent + `🔄` glyph + `"Reconciling "` verb-phrase
    /// as the [`GitSource`] sibling, differing only in the noun.
    #[test]
    fn write_announce_line_emits_root_kustomization_bytes() {
        let mut buf: Vec<u8> = Vec::new();
        write_flux_reconcile_announce_line(&mut buf, FluxReconcileAnnounceStep::RootKustomization)
            .expect("write to Vec<u8> is infallible");
        assert_eq!(
            String::from_utf8(buf).expect("ASCII+UTF-8 output"),
            "   \u{1f504} Reconciling kustomization...\n",
        );
    }

    /// Positive delegation shield: `commands/flux.rs` must forward
    /// through [`run_flux_reconcile_announce_step`] from at least two
    /// code lines (the two pre-lift caller sites in
    /// `reconcile_source` + `reconcile_kustomization`). A future
    /// re-inlining of either stanza that dropped the fusion primitive
    /// regresses this count and fails the shield.
    #[test]
    fn flux_rs_forwards_through_announce_step_at_least_twice() {
        let src =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/commands/flux.rs",))
                .expect("commands/flux.rs must be readable at test time");
        let hits = code_line_hits(&src, "run_flux_reconcile_announce_step(");
        assert!(
            hits >= 2,
            "commands/flux.rs must delegate to \
             `run_flux_reconcile_announce_step(` from at least two \
             code lines (the two pre-lift caller sites) — the fusion \
             primitive is the sole home for the three-space-indented \
             `println!(\"   🔄 Reconciling <target>...\")` announce + \
             `print_step_pass(\"<Label> reconciled\")` ack grammar. \
             Saw {hits} code-line hit(s)."
        );
    }

    /// Negative caller shield: `commands/flux.rs` must NOT carry a
    /// raw `println!("   🔄 Reconciling <target>...")` announce
    /// literal at a caller site — the fusion primitive owns that
    /// grammar. The one exception is the sibling
    /// `reconcile_product_chain` stanza (`"   🔄 Reconciling product
    /// chain for {} …"`) which lives under the separate
    /// [`crate::commands::flux_product_chain_phase`] primitive and
    /// carries a different noun-clause + trailing-space grammar. This
    /// shield forbids the two-word `"Reconciling git source..."` /
    /// `"Reconciling kustomization..."` verbatim literals only.
    #[test]
    fn flux_rs_forbids_raw_reconcile_announce_literals() {
        let src =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/commands/flux.rs",))
                .expect("commands/flux.rs must be readable at test time");
        for literal in [
            "\"   \u{1f504} Reconciling git source...\"",
            "\"   \u{1f504} Reconciling kustomization...\"",
        ] {
            let hits = code_line_hits(&src, literal);
            assert_eq!(
                hits, 0,
                "commands/flux.rs must not carry a raw {literal} \
                 announce literal at a caller site — the fusion \
                 primitive `run_flux_reconcile_announce_step` owns \
                 that grammar. Saw {hits} code-line hit(s)."
            );
        }
    }

    /// Count code-line hits of `needle` in `src`, skipping lines
    /// whose FIRST non-whitespace bytes are the Rust line-comment
    /// prefix `//` (which covers `//`, `///`, `//!`). Doc- and
    /// prose-comment lines that mention the needle to explain the
    /// primitive don't count against a shield that pins call-site
    /// discipline in EXECUTABLE code.
    fn code_line_hits(src: &str, needle: &str) -> usize {
        src.lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .filter(|line| line.contains(needle))
            .count()
    }
}
