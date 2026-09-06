//! Announce-and-reconcile-`flux-system` fusion primitive.
//!
//! Two pre-lift sibling six-line stanzas — one at
//! `commands/deploy.rs::execute` (post-manifest-push, `with_source=false`,
//! success phrase `"triggered"`) and one at
//! `commands/github_runner_ci.rs::execute` (post-manifest-push,
//! `with_source=true`, success phrase `"complete"`) — each spelled the
//! same shape verbatim, differing only in the two axes above:
//!
//! ```ignore
//! info!("🔄 Triggering FluxCD reconciliation...");
//! match flux_reconcile::reconcile_kustomization("flux-system", "flux-system", <bool>).await {
//!     Ok(()) => {
//!         crate::info_success!("FluxCD reconciliation <triggered|complete>");
//!     }
//!     Err(e) => {
//!         crate::warn_nonfatal!("FluxCD reconcile failed", e);
//!     }
//! }
//! ```
//!
//! Both callers reconcile the same `("flux-system", "flux-system")`
//! kustomization/namespace pair (the root FluxCD kustomization); both
//! route the failure through the fleet-standard non-fatal marker via
//! [`crate::warn_nonfatal!`]; both emit the announcement via
//! [`tracing::info!`] and the success acknowledgement via
//! [`crate::info_success!`]. The ONLY per-caller axes are the
//! `with_source` boolean passed to
//! [`crate::flux_reconcile::reconcile_kustomization`] and the
//! adjective spliced into the success phrase — and those two axes are
//! not independent: `with_source=false` corresponds to the
//! kick-off-only ("triggered") variant, `with_source=true` corresponds
//! to the wait-for-readiness ("complete") variant.
//!
//! Encoding that correlated pair as [`FluxSystemReconcileMode`] closes
//! two drift risks at ONE typed boundary. First, a caller cannot
//! silently pass `with_source=true` but keep the "triggered" phrase
//! (or vice versa), because the mode-enum owns both mappings. Second,
//! a future re-branding of the announcement, the success phrase, the
//! failure label, or the reconciliation target lands at exactly one
//! module rather than through two inline literal edits.
//!
//! The bare
//! [`crate::flux_reconcile::reconcile_kustomization`] primitive stays
//! the sole home for the flux argv contract and the typed error
//! surface — this fusion sits above it and is the sole home for the
//! `announcement + Ok(())=>info_success! + Err(e)=>warn_nonfatal!`
//! grammar. The third caller of `reconcile_kustomization` at
//! `commands/flux.rs::reconcile_kustomization` (line 467) uses a
//! DIFFERENT announcement grammar (a three-space-indented
//! `println!("   🔄 Reconciling kustomization...")` + a
//! `crate::ui::print_step_pass("Kustomization reconciled")` completion
//! signal) and stays outside this primitive's scope by design.
//!
//! Sibling of
//! `commands/manifest_push.rs::commit_and_push_manifest_with_progress`
//! — same visual-grammar-fusion pattern (a `tracing`-routed
//! announcement + a subordinate operation + a canonical completion
//! signal) applied to the sibling stage of the single-manifest
//! deployment flow. The two primitives partition the
//! post-manifest-push landing surface — `manifest_push` owns the
//! git-commit-and-push step, `flux_system_reconcile` owns the
//! FluxCD-reconcile step — so a future consumer that reaches for the
//! wrong stage fails at the type boundary rather than by silent
//! log-drift.

use std::fmt;
use std::io;

use tracing::info;

use crate::flux_reconcile;

/// The canonical `🔄 Triggering FluxCD reconciliation...` announcement
/// line the two sibling post-manifest-push deployment flows in
/// `commands/{deploy,github_runner_ci}.rs` each emitted immediately
/// before invoking [`flux_reconcile::reconcile_kustomization`]. Named
/// as a `const` so a future re-branding of the verb (`🔄 Triggering`
/// → `🔄 Kicking off`, `🔄 Requesting`) flows to both flows from one
/// edit rather than through two inline literal edits.
const TRIGGERING_FLUX_ANNOUNCEMENT: &str = "🔄 Triggering FluxCD reconciliation...";

/// The canonical non-fatal-warning label the two sibling flows each
/// passed to [`crate::warn_nonfatal!`] on the `Err` arm of the
/// `flux reconcile` call. Named as a `const` so a future
/// re-branding of the failure label (`FluxCD reconcile failed` →
/// `FluxCD reconciliation failed`) flows through one edit.
const FLUX_RECONCILE_FAILED_LABEL: &str = "FluxCD reconcile failed";

/// The canonical success phrase spliced into the post-reconcile
/// [`crate::info_success!`] line when the caller kicks off the
/// reconciliation without waiting for source/kustomization readiness
/// ([`FluxSystemReconcileMode::Triggered`]). Named as a `const` so a
/// future re-phrasing (e.g. `"triggered"` → `"kicked off"`) lands at
/// one site with its sibling completion phrase.
const SUCCESS_PHRASE_TRIGGERED: &str = "triggered";

/// The canonical success phrase spliced into the post-reconcile
/// [`crate::info_success!`] line when the caller waits for
/// source/kustomization readiness
/// ([`FluxSystemReconcileMode::Completed`]). Named as a `const`
/// sibling of [`SUCCESS_PHRASE_TRIGGERED`] so a re-phrasing of one
/// half flows to its neighbor from one edit.
const SUCCESS_PHRASE_COMPLETED: &str = "complete";

/// The canonical `reconcile_kustomization` name argument the two
/// sibling flows each passed as the first positional slot. Named as
/// a `const` so a future re-branding of the root FluxCD kustomization
/// (`flux-system` → `flux-root`) flows through one edit.
const FLUX_SYSTEM_KUSTOMIZATION: &str = "flux-system";

/// The canonical `reconcile_kustomization` namespace argument the two
/// sibling flows each passed as the second positional slot. Named as
/// a `const` alongside [`FLUX_SYSTEM_KUSTOMIZATION`] so the
/// `(kustomization, namespace)` pair the primitive owns stays visibly
/// coupled at one site.
const FLUX_SYSTEM_NAMESPACE: &str = "flux-system";

/// The two typed variants of the announce-and-reconcile-`flux-system`
/// stanza the fusion primitive supports.
///
/// The pre-lift two sites each picked their `with_source` boolean and
/// their success-phrase adjective INDEPENDENTLY, at inline literal
/// call sites — a silent drift that swapped `with_source=true` in
/// against the "triggered" phrase (or vice versa) would have shipped
/// with no test surface catching it. Encoding the correlated pair as
/// a mode enum with `with_source()` and `success_phrase()` inverses
/// makes the pairing structurally impossible to break: a future
/// re-tuning of either axis touches this enum, and every caller
/// inherits the invariant by construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FluxSystemReconcileMode {
    /// Kick off the reconciliation and return immediately without
    /// waiting for source/kustomization readiness. Emits the success
    /// acknowledgement `"FluxCD reconciliation triggered"` on the
    /// `Ok` arm. Consumed by the pre-lift
    /// `commands/deploy.rs::execute` site
    /// (`with_source=false`).
    Triggered,
    /// Wait for the source + kustomization readiness before returning.
    /// Emits the success acknowledgement
    /// `"FluxCD reconciliation complete"` on the `Ok` arm. Consumed
    /// by the pre-lift `commands/github_runner_ci.rs::execute` site
    /// (`with_source=true`).
    Completed,
}

impl FluxSystemReconcileMode {
    /// The `with_source` boolean passed to
    /// [`flux_reconcile::reconcile_kustomization`] for this mode.
    /// Inverse of [`Self::success_phrase`] under the correlated
    /// pairing the primitive owns.
    #[inline]
    #[must_use]
    pub const fn with_source(self) -> bool {
        matches!(self, FluxSystemReconcileMode::Completed)
    }

    /// The success phrase spliced into the post-reconcile
    /// [`crate::info_success!`] line for this mode. Inverse of
    /// [`Self::with_source`] under the correlated pairing.
    #[inline]
    #[must_use]
    pub const fn success_phrase(self) -> &'static str {
        match self {
            FluxSystemReconcileMode::Triggered => SUCCESS_PHRASE_TRIGGERED,
            FluxSystemReconcileMode::Completed => SUCCESS_PHRASE_COMPLETED,
        }
    }
}

/// Emit the canonical two-line announce-and-outcome narrative to `w`
/// as newline-terminated lines, byte-for-byte identical to the visual
/// grammar the two sibling post-manifest-push deployment flows in
/// `commands/{deploy,github_runner_ci}.rs` present to an operator
/// watching the terminal.
///
/// Line 1 is always the announcement
/// [`TRIGGERING_FLUX_ANNOUNCEMENT`]. Line 2 branches on `outcome`:
/// on `Ok(())` it emits `"✅ FluxCD reconciliation <phrase>"` (byte-
/// identical to [`crate::success_step::write_success_step`] applied
/// to the composed message); on `Err(err)` it emits
/// `"⚠️  FluxCD reconcile failed (non-fatal): <err>"` (byte-identical
/// to [`crate::nonfatal_warning::write_nonfatal_warn`] applied to
/// [`FLUX_RECONCILE_FAILED_LABEL`] and the error's [`fmt::Display`]).
///
/// The writer split exists because the production fusion primitive
/// [`announce_and_reconcile_flux_system`] emits the announcement
/// through `tracing::info!` and the outcome through
/// `crate::info_success!` / `crate::warn_nonfatal!` (both
/// `tracing`-routed via the global `tracing_subscriber` fmt layer),
/// neither of which is byte-oracle-testable in a hermetic
/// `#[cfg(test)]` block without capturing an ambient subscriber. The
/// direct writer emits the two strings in narrative order into a
/// `Vec<u8>` so the fail-before-pass test can pin the grammar via
/// `String::from_utf8` — a rename of the announcement, a swap of the
/// success phrase, a drift on the failure label, or a re-shaping of
/// the `(non-fatal)` marker flips the assertion at ONE site rather
/// than silently forking the grammar across two consumers.
///
/// Same writer/print split every prior sibling-writer refactor
/// honors (see `nonfatal_warning.rs`, `success_step.rs`,
/// `manifest_push.rs`, `step_header.rs` for the canonical split
/// rationale).
#[allow(dead_code)] // See doc comment: the writer is a test/byte-oracle
                    // peer of the tracing-routed
                    // `announce_and_reconcile_flux_system`, and a future
                    // `collect_reconcile_narratives` audit sibling will
                    // consume it directly.
pub fn write_flux_system_reconcile_stanza<W: io::Write>(
    w: &mut W,
    mode: FluxSystemReconcileMode,
    outcome: Result<(), &dyn fmt::Display>,
) -> io::Result<()> {
    writeln!(w, "{}", TRIGGERING_FLUX_ANNOUNCEMENT)?;
    match outcome {
        Ok(()) => writeln!(
            w,
            "\u{2705} FluxCD reconciliation {}",
            mode.success_phrase()
        ),
        Err(err) => writeln!(
            w,
            "\u{26a0}\u{fe0f}  {} (non-fatal): {}",
            FLUX_RECONCILE_FAILED_LABEL, err
        ),
    }
}

/// Emit the canonical `🔄 Triggering FluxCD reconciliation...`
/// announcement, invoke
/// [`flux_reconcile::reconcile_kustomization`] against the
/// `("flux-system", "flux-system", <mode.with_source()>)` triple, and
/// route the outcome through the fleet-standard
/// [`crate::info_success!`] (`Ok`) or [`crate::warn_nonfatal!`]
/// (`Err`) primitives.
///
/// Fusion primitive over the two sibling six-line stanzas the
/// single-manifest deployment flows in
/// `commands/{deploy,github_runner_ci}.rs` each spelled inline (see
/// the [module docs](self) for the pre-lift shape). The pre-lift
/// callers passed the `with_source` boolean and the success-phrase
/// adjective at independent inline literal sites; post-lift both
/// axes are owned by [`FluxSystemReconcileMode`] and the primitive
/// itself owns the announcement, the argv contract on the reconcile,
/// the success/error grammar, and the non-fatal routing.
///
/// # Grammar pinned by the byte-oracle sibling
///
/// The narrative bytes (announcement + Ok-arm success phrase +
/// Err-arm non-fatal marker) are pinned by
/// [`write_flux_system_reconcile_stanza`] under `#[cfg(test)]`; a
/// drift here surfaces as a localized test failure at one site, not
/// as silent grammar-drift across two deployment flows.
///
/// # Non-fatal by design
///
/// The reconcile itself never fails the enclosing workflow — a
/// failure surfaces through [`crate::warn_nonfatal!`] so the caller
/// does not need its own `Err` arm and the enclosing deployment
/// keeps running. The pre-lift two sites both exhibited this shape.
pub async fn announce_and_reconcile_flux_system(mode: FluxSystemReconcileMode) {
    info!("{}", TRIGGERING_FLUX_ANNOUNCEMENT);
    match flux_reconcile::reconcile_kustomization(
        FLUX_SYSTEM_KUSTOMIZATION,
        FLUX_SYSTEM_NAMESPACE,
        mode.with_source(),
    )
    .await
    {
        Ok(()) => {
            crate::info_success!("FluxCD reconciliation {}", mode.success_phrase());
        }
        Err(e) => {
            crate::warn_nonfatal!(FLUX_RECONCILE_FAILED_LABEL, e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pin the exact two-line narrative bytes emitted by
    /// [`write_flux_system_reconcile_stanza`] on the
    /// [`FluxSystemReconcileMode::Triggered`] Ok arm: the
    /// `🔄 Triggering FluxCD reconciliation...` announcement +
    /// newline, then the `✅ FluxCD reconciliation triggered`
    /// success line + newline. A future refactor that swapped the
    /// `🔄` glyph, re-phrased the announcement, dropped the
    /// checkmark, or drifted the success phrase off `"triggered"`
    /// regresses this assertion.
    #[test]
    fn write_stanza_emits_triggered_ok_bytes() {
        let mut buf: Vec<u8> = Vec::new();
        write_flux_system_reconcile_stanza(&mut buf, FluxSystemReconcileMode::Triggered, Ok(()))
            .unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "\u{1f504} Triggering FluxCD reconciliation...\n\
             \u{2705} FluxCD reconciliation triggered\n"
        );
    }

    /// Pin the [`FluxSystemReconcileMode::Completed`] Ok arm bytes:
    /// same announcement, then the `✅ FluxCD reconciliation complete`
    /// success line. A future refactor that collapsed the two-mode
    /// success grammar into a single phrase (or drifted the completed
    /// phrase off `"complete"`) regresses this assertion.
    #[test]
    fn write_stanza_emits_completed_ok_bytes() {
        let mut buf: Vec<u8> = Vec::new();
        write_flux_system_reconcile_stanza(&mut buf, FluxSystemReconcileMode::Completed, Ok(()))
            .unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "\u{1f504} Triggering FluxCD reconciliation...\n\
             \u{2705} FluxCD reconciliation complete\n"
        );
    }

    /// Pin the Err arm bytes: the same announcement, then the
    /// `⚠️  FluxCD reconcile failed (non-fatal): <err>` line
    /// (byte-identical to the fleet-standard
    /// [`crate::warn_nonfatal!`] shape). A future refactor that
    /// dropped the variation selector on `⚠️`, collapsed the
    /// two-space gap, moved the `(non-fatal)` marker, or drifted the
    /// failure label off `"FluxCD reconcile failed"` regresses this
    /// assertion.
    #[test]
    fn write_stanza_emits_err_bytes() {
        let mut buf: Vec<u8> = Vec::new();
        write_flux_system_reconcile_stanza(
            &mut buf,
            FluxSystemReconcileMode::Triggered,
            Err(&"flux exited 1"),
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "\u{1f504} Triggering FluxCD reconciliation...\n\
             \u{26a0}\u{fe0f}  FluxCD reconcile failed (non-fatal): \
             flux exited 1\n"
        );
    }

    /// Mode-axis pin: [`FluxSystemReconcileMode::with_source`] maps
    /// `Triggered` → `false` and `Completed` → `true`. This is the
    /// invariant the mode-enum owns — a caller cannot silently
    /// combine `with_source=true` with the `"triggered"` phrase (or
    /// vice versa) because both axes derive from the same mode. A
    /// future refactor that swapped either arm regresses this
    /// assertion and every downstream flow inheriting the mode's
    /// axis pair fails at compile-time or the byte-oracle above.
    #[test]
    fn mode_with_source_maps_to_pre_lift_boolean() {
        assert!(!FluxSystemReconcileMode::Triggered.with_source());
        assert!(FluxSystemReconcileMode::Completed.with_source());
    }

    /// Success-phrase axis pin: `Triggered` splices `"triggered"` and
    /// `Completed` splices `"complete"` — the two verbatim adjectives
    /// the pre-lift two sites each spelled inline. Sibling of
    /// [`mode_with_source_maps_to_pre_lift_boolean`] under the
    /// correlated pairing the primitive owns.
    #[test]
    fn mode_success_phrase_maps_to_pre_lift_wording() {
        assert_eq!(
            FluxSystemReconcileMode::Triggered.success_phrase(),
            "triggered"
        );
        assert_eq!(
            FluxSystemReconcileMode::Completed.success_phrase(),
            "complete"
        );
    }

    /// Const-anchor pin: the five canonical strings the primitive
    /// owns each carry their exact pre-lift byte sequence. A future
    /// edit that touched one const without updating the mirrored
    /// inline literal in the caller-shield below cannot silently
    /// proceed.
    #[test]
    fn canonical_constants_carry_pre_lift_byte_sequences() {
        assert_eq!(
            TRIGGERING_FLUX_ANNOUNCEMENT,
            "\u{1f504} Triggering FluxCD reconciliation..."
        );
        assert_eq!(FLUX_RECONCILE_FAILED_LABEL, "FluxCD reconcile failed");
        assert_eq!(SUCCESS_PHRASE_TRIGGERED, "triggered");
        assert_eq!(SUCCESS_PHRASE_COMPLETED, "complete");
        assert_eq!(FLUX_SYSTEM_KUSTOMIZATION, "flux-system");
        assert_eq!(FLUX_SYSTEM_NAMESPACE, "flux-system");
    }

    /// Caller shield: no source line under `cli/src/commands/` may
    /// spell the pre-lift announcement literal
    /// `info!("🔄 Triggering FluxCD reconciliation...")` inline any
    /// more. Every announce-and-reconcile-`flux-system` narrative in
    /// a deployment flow must resolve through
    /// [`announce_and_reconcile_flux_system`] so a future drift on the
    /// announcement (a new verb, a re-branded target) flows to both
    /// flows from one edit.
    ///
    /// The forbidden shape is reconstructed at test time via
    /// `format!` from the bare string `"Triggering FluxCD"` so this
    /// shield's own source text does not false-match itself. Every
    /// hit routes through [`crate::test_support::code_line_hits`]
    /// for anti-comment-line-self-match discipline.
    #[test]
    fn no_command_module_still_spells_raw_flux_reconcile_announcement() {
        use std::path::PathBuf;
        let forbidden = format!(
            "info!(\"{}{}",
            "\u{1f504} ", "Triggering FluxCD reconciliation..."
        );
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let mut offenders: Vec<(PathBuf, Vec<String>)> = Vec::new();
        for entry in std::fs::read_dir(&commands_dir).unwrap().flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            // Skip THIS module — its own prose and byte-oracle test
            // strings mention the pre-lift shape verbatim by design.
            if path.file_name().and_then(|n| n.to_str()) == Some("flux_system_reconcile.rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).unwrap();
            let hits = crate::test_support::code_line_hits(&source, &forbidden);
            if !hits.is_empty() {
                offenders.push((path, hits));
            }
        }
        assert!(
            offenders.is_empty(),
            "pre-lift `info!(\"{}\")` announcement stanza(s) survive \
             under `commands/` — route each through \
             `crate::commands::flux_system_reconcile::\
             announce_and_reconcile_flux_system(<mode>)` instead:\n{:#?}",
            forbidden,
            offenders,
        );
    }

    /// Caller shield: no source line under `cli/src/commands/` may
    /// spell the pre-lift `reconcile_kustomization("flux-system",
    /// "flux-system", ...)` triple inline any more, EXCEPT for
    /// `commands/flux.rs` — that module hosts a distinct
    /// three-space-indented `println!` announcement grammar
    /// (`"   🔄 Reconciling kustomization..."`) plus a
    /// `crate::ui::print_step_pass("Kustomization reconciled")`
    /// completion signal, and that stanza is outside this primitive's
    /// scope by design.
    ///
    /// The forbidden shape is reconstructed at test time via
    /// `format!` from the bare pair `"flux-system"`, `"flux-system"`
    /// so this shield's own source text does not false-match itself.
    #[test]
    fn no_deployment_module_still_spells_raw_reconcile_kustomization_triple() {
        use std::path::PathBuf;
        let forbidden = format!(
            "reconcile_kustomization(\"{}\", \"{}\"",
            "flux-system", "flux-system"
        );
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let mut offenders: Vec<(PathBuf, Vec<String>)> = Vec::new();
        for entry in std::fs::read_dir(&commands_dir).unwrap().flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let name = path.file_name().and_then(|n| n.to_str());
            // Skip THIS module (owns the primitive) and
            // `commands/flux.rs` (distinct-grammar site by design).
            if name == Some("flux_system_reconcile.rs") || name == Some("flux.rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).unwrap();
            let hits = crate::test_support::code_line_hits(&source, &forbidden);
            if !hits.is_empty() {
                offenders.push((path, hits));
            }
        }
        assert!(
            offenders.is_empty(),
            "pre-lift `{}...)` reconcile call(s) survive under \
             `commands/` outside of `commands/flux.rs` — route each \
             through `crate::commands::flux_system_reconcile::\
             announce_and_reconcile_flux_system(<mode>)` \
             instead:\n{:#?}",
            forbidden,
            offenders,
        );
    }

    /// Positive-half delegation shield: the two consumer modules
    /// MUST each carry exactly one call to
    /// [`announce_and_reconcile_flux_system`]. Guards against a
    /// silent removal of the reconciliation step from a consumer
    /// (a refactor that accidentally dropped the fusion call while
    /// migrating a step, a merge that lost the call in a conflict
    /// resolution). The reconcile is load-bearing for the deployment
    /// actually landing on the cluster, so its presence at exactly
    /// one site per flow is a structural invariant.
    #[test]
    fn every_flux_system_reconcile_consumer_delegates_through_fusion() {
        // Match the CALL-syntax `(` suffix so a leading `use` import
        // line carrying the identifier without a call does not
        // double-count against the per-consumer invocation invariant.
        let needle = "announce_and_reconcile_flux_system(";
        for (path, source) in [
            ("commands/deploy.rs", include_str!("deploy.rs")),
            (
                "commands/github_runner_ci.rs",
                include_str!("github_runner_ci.rs"),
            ),
        ] {
            let count = source.matches(needle).count();
            assert_eq!(
                count, 1,
                "`{path}` must invoke `crate::commands::\
                 flux_system_reconcile::{needle}` exactly once for its \
                 post-manifest-push FluxCD reconciliation step; found \
                 {count}. A flow that runs to completion without \
                 emitting the reconcile breaks the deployment landing \
                 on the cluster."
            );
        }
    }
}
