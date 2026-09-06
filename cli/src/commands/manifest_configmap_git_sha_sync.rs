//! Sync-manifest-tag-and-configmap-GIT_SHA fusion primitive.
//!
//! Two pre-lift sibling four-line stanzas — one at
//! `commands/deploy.rs::execute` (post-kustomization-preamble, applied
//! against the caller's `kustomization_path` + `tag`) and one at
//! `commands/github_runner_ci.rs::execute` (post-manifest-preamble,
//! applied against the caller's `manifest_path` + `git_sha`) — each
//! spelled the same shape verbatim, differing only in the two
//! per-caller local-variable names:
//!
//! ```ignore
//! git::update_manifest(<path>, &<old>, &<new>).await?;
//!
//! // Update ConfigMap with GIT_SHA
//! info!("📝 Updating ConfigMap with GIT_SHA...");
//! git::update_configmap_git_sha(<path>, &<new>).await?;
//! ```
//!
//! The pre-lift two sites each read the "new" value into a local
//! (`tag` in `deploy.rs`, `git_sha` in `github_runner_ci.rs`) and
//! threaded it INDEPENDENTLY through two consecutive calls: the first
//! writes `images[].newTag` (via [`git::update_manifest`]), the second
//! writes the sibling ConfigMap's `data.GIT_SHA` (via
//! [`git::update_configmap_git_sha`]) on the same manifest directory.
//! The load-bearing invariant is that the SAME value lands in BOTH
//! YAML fields — the Kustomize image tag and the ConfigMap GIT_SHA —
//! so downstream pods see one coherent (`newTag`, `GIT_SHA`) pair.
//!
//! Pre-lift, that invariant was carried by "two identifiers happen to
//! spell the same local variable" — a shape a future refactor could
//! silently break (a caller might route a stale local to one of the
//! two calls, or splice in a suffix-only variant for one field but
//! not the other). Post-lift, the primitive takes ONE `new_tag`
//! parameter and threads it through both writes, making the drift
//! structurally impossible: the two YAML fields are updated to the
//! same string by construction, and a future caller cannot pass a
//! divergent pair without adding a distinct parameter.
//!
//! The pre-lift between-writes narrative `info!("📝 Updating ConfigMap
//! with GIT_SHA...")` line likewise lands at ONE typed boundary; a
//! future re-branding of the announcement (a new verb, a new emoji,
//! a re-shaped label) flows to both flows from one edit rather than
//! through two inline literal edits.
//!
//! Sibling of
//! `commands/manifest_push.rs::commit_and_push_manifest_with_progress`
//! and
//! `commands/flux_system_reconcile.rs::announce_and_reconcile_flux_system`
//! — same visual-grammar-fusion pattern applied to the third stage
//! of the single-manifest deployment flow. The three primitives now
//! partition the post-preamble landing surface of a Kustomize-based
//! deploy: this module owns the `(manifest write + configmap write)`
//! pair, `manifest_push` owns the git-commit-and-push step,
//! `flux_system_reconcile` owns the FluxCD-reconcile step. A future
//! consumer that reaches for the wrong stage fails at the type
//! boundary rather than by silent log-drift.

use anyhow::Result;
use std::io::{self, Write};
use std::path::Path;

use tracing::info;

use crate::git;

/// The canonical `📝 Updating ConfigMap with GIT_SHA...` announcement
/// line the two sibling deployment flows in
/// `commands/{deploy,github_runner_ci}.rs` each emitted immediately
/// before invoking [`git::update_configmap_git_sha`]. Named as a
/// `const` so a future re-branding of the verb (`📝 Updating` →
/// `📝 Publishing`, `📝 Writing`) or the field name (`GIT_SHA` →
/// `DEPLOY_SHA`) flows to both flows from one edit rather than
/// through two inline literal edits.
const CONFIGMAP_GIT_SHA_ANNOUNCEMENT: &str = "📝 Updating ConfigMap with GIT_SHA...";

/// Fused typed writer: update the Kustomize `images[].newTag` to
/// `new_tag` via [`git::update_manifest`], then emit the canonical
/// `📝 Updating ConfigMap with GIT_SHA...` announcement, then update
/// the sibling ConfigMap's `data.GIT_SHA` to the same `new_tag` via
/// [`git::update_configmap_git_sha`].
///
/// Fusion primitive over the two sibling four-line stanzas the
/// single-manifest deployment flows in
/// `commands/{deploy,github_runner_ci}.rs` each spelled inline (see
/// the [module docs](self) for the pre-lift shape). Both writes
/// consume the SAME `new_tag` value by construction: a future caller
/// cannot pass a divergent `(newTag, GIT_SHA)` pair without adding a
/// distinct parameter, so the load-bearing "one coherent
/// (`newTag`, `GIT_SHA`) pair lands in the manifest" invariant is
/// owned by the primitive rather than by a pair-of-locals convention
/// at each call site.
///
/// # Grammar pinned by the byte-oracle sibling
///
/// The between-writes narrative bytes (the `📝 Updating ConfigMap
/// with GIT_SHA...` line) are pinned by
/// [`write_configmap_git_sha_announcement`] under `#[cfg(test)]`; a
/// drift here surfaces as a localized test failure at one site, not
/// as silent grammar-drift across two deployment flows.
///
/// # Argument `old_tag`
///
/// Threaded through to [`git::update_manifest`] as its second
/// positional argument. Currently ignored by that primitive (the
/// underscore-prefixed `_old_tag` parameter documents the
/// intent-to-preserve-but-not-consume shape); the primitive accepts
/// it verbatim so a future re-widening of [`git::update_manifest`]
/// that DOES consume `old_tag` (e.g. an idempotency guard that skips
/// the write when the pre-image already carries `new_tag`) lands
/// without a signature change here.
pub async fn sync_manifest_tag_and_configmap_git_sha(
    manifest_path: &Path,
    old_tag: &str,
    new_tag: &str,
) -> Result<()> {
    git::update_manifest(manifest_path, old_tag, new_tag).await?;
    info!("{}", CONFIGMAP_GIT_SHA_ANNOUNCEMENT);
    git::update_configmap_git_sha(manifest_path, new_tag).await?;
    Ok(())
}

/// Emit the canonical between-writes announcement line to `w` as a
/// newline-terminated string, byte-for-byte identical to the visual
/// grammar the two sibling deployment flows in
/// `commands/{deploy,github_runner_ci}.rs` present to an operator
/// watching the terminal between the two YAML writes.
///
/// The writer split exists because the production fusion primitive
/// [`sync_manifest_tag_and_configmap_git_sha`] emits the announcement
/// through `tracing::info!`, which is not byte-oracle-testable in a
/// hermetic `#[cfg(test)]` block without capturing an ambient
/// subscriber. The direct writer emits the announcement string into a
/// `Vec<u8>` so the fail-before-pass test can pin the grammar via
/// `String::from_utf8` — a rename of the announcement verb, a swap of
/// the emoji, or a drift on the field name flips the assertion at
/// ONE site rather than silently forking the grammar across two
/// consumers.
///
/// Same writer/print split every prior sibling-writer refactor
/// honors (see `nonfatal_warning.rs`, `success_step.rs`,
/// `manifest_push.rs`, `flux_system_reconcile.rs` for the canonical
/// split rationale).
#[allow(dead_code)] // See doc comment: the writer is a test/byte-oracle
                    // peer of the tracing-routed
                    // `sync_manifest_tag_and_configmap_git_sha`, and a
                    // future `collect_configmap_narratives` audit sibling
                    // will consume it directly.
pub fn write_configmap_git_sha_announcement<W: Write>(w: &mut W) -> io::Result<()> {
    writeln!(w, "{}", CONFIGMAP_GIT_SHA_ANNOUNCEMENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pin the exact one-line between-writes narrative bytes emitted
    /// by [`write_configmap_git_sha_announcement`]: the
    /// `📝 Updating ConfigMap with GIT_SHA...` line + newline. A
    /// future refactor that swapped the `📝` glyph, re-phrased the
    /// verb (`Updating` → `Publishing`), or drifted the field name
    /// off `GIT_SHA` regresses this assertion.
    #[test]
    fn write_announcement_emits_pre_lift_bytes() {
        let mut buf: Vec<u8> = Vec::new();
        write_configmap_git_sha_announcement(&mut buf).unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "\u{1f4dd} Updating ConfigMap with GIT_SHA...\n"
        );
    }

    /// Const-anchor pin: the single canonical string the primitive
    /// owns carries its exact pre-lift byte sequence. A future edit
    /// that touched the const without updating the mirrored inline
    /// literal in the caller-shield below cannot silently proceed.
    #[test]
    fn canonical_constant_carries_pre_lift_byte_sequence() {
        assert_eq!(
            CONFIGMAP_GIT_SHA_ANNOUNCEMENT,
            "\u{1f4dd} Updating ConfigMap with GIT_SHA..."
        );
    }

    /// Caller shield: no source line under `cli/src/commands/` may
    /// spell the pre-lift announcement literal
    /// `info!("📝 Updating ConfigMap with GIT_SHA...")` inline any
    /// more. Every sync-manifest-tag-and-configmap-GIT_SHA narrative
    /// in a deployment flow must resolve through
    /// [`sync_manifest_tag_and_configmap_git_sha`] so a future drift
    /// on the announcement (a new verb, a re-branded field) flows to
    /// both flows from one edit.
    ///
    /// The forbidden shape is reconstructed at test time via
    /// `format!` from the bare string
    /// `"Updating ConfigMap with GIT_SHA"` so this shield's own
    /// source text does not false-match itself. Every hit routes
    /// through [`crate::test_support::code_line_hits`] for
    /// anti-comment-line-self-match discipline.
    #[test]
    fn no_command_module_still_spells_raw_configmap_git_sha_announcement() {
        use std::path::PathBuf;
        let forbidden = format!(
            "info!(\"{}{}",
            "\u{1f4dd} ", "Updating ConfigMap with GIT_SHA..."
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
            if path.file_name().and_then(|n| n.to_str())
                == Some("manifest_configmap_git_sha_sync.rs")
            {
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
             `crate::commands::manifest_configmap_git_sha_sync::\
             sync_manifest_tag_and_configmap_git_sha(path, old, new)` \
             instead:\n{:#?}",
            forbidden,
            offenders,
        );
    }

    /// Caller shield: no source line under `cli/src/commands/` may
    /// spell a bare inline `git::update_configmap_git_sha(` call any
    /// more. Every ConfigMap-GIT_SHA write must resolve through
    /// [`sync_manifest_tag_and_configmap_git_sha`] so the load-bearing
    /// `(images[].newTag, data.GIT_SHA)` sync invariant — the SAME
    /// value lands in BOTH YAML fields — stays owned by the primitive
    /// rather than by a pair-of-locals convention at each call site.
    ///
    /// The forbidden shape is reconstructed at test time via
    /// `format!` from the bare token `"update_configmap_git_sha"`
    /// with the `(` suffix so a leading `use` import line carrying
    /// the identifier without a call does not false-match. Hits
    /// route through [`crate::test_support::code_line_hits`] for
    /// anti-comment-line-self-match discipline.
    #[test]
    fn no_command_module_still_spells_raw_update_configmap_git_sha_call() {
        use std::path::PathBuf;
        let forbidden = format!("git::{}(", "update_configmap_git_sha");
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let mut offenders: Vec<(PathBuf, Vec<String>)> = Vec::new();
        for entry in std::fs::read_dir(&commands_dir).unwrap().flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            // Skip THIS module — the fusion primitive itself is the
            // sole permitted caller of `git::update_configmap_git_sha`.
            if path.file_name().and_then(|n| n.to_str())
                == Some("manifest_configmap_git_sha_sync.rs")
            {
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
            "pre-lift `{}...)` call(s) survive under `commands/` — \
             route each through `crate::commands::\
             manifest_configmap_git_sha_sync::\
             sync_manifest_tag_and_configmap_git_sha(path, old, new)` \
             instead:\n{:#?}",
            forbidden,
            offenders,
        );
    }

    /// Positive-half delegation shield: the two consumer modules
    /// MUST each carry exactly one call to
    /// [`sync_manifest_tag_and_configmap_git_sha`]. Guards against a
    /// silent removal of the ConfigMap-GIT_SHA write from a consumer
    /// (a refactor that accidentally dropped the fusion call while
    /// migrating a step, a merge that lost the call in a conflict
    /// resolution). Pods keyed to `GIT_SHA` for their env-carried
    /// deploy identity would silently observe a stale value if the
    /// call were dropped, so its presence at exactly one site per
    /// flow is a structural invariant.
    #[test]
    fn every_manifest_configmap_sync_consumer_delegates_through_fusion() {
        // Match the CALL-syntax `(` suffix so a leading `use` import
        // line carrying the identifier without a call does not
        // double-count against the per-consumer invocation invariant.
        let needle = "sync_manifest_tag_and_configmap_git_sha(";
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
                 manifest_configmap_git_sha_sync::{needle}` exactly \
                 once for its manifest+ConfigMap-GIT_SHA sync step; \
                 found {count}. A flow that runs to completion \
                 without emitting the ConfigMap write leaves pods \
                 observing a stale `GIT_SHA` env value."
            );
        }
    }
}
