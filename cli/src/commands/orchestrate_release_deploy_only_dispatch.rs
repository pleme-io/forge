//! Fused deploy-only single-environment `forge orchestrate-release`
//! self-re-invocation dispatch.
//!
//! # Pre-lift census — two sibling three-step stanzas
//!
//! Two consumer sites — `commands/rollback.rs::execute`'s
//! Deploy-previous-tags loop (~L227-244 pre-lift) and
//! `commands/product_release.rs::execute`'s Phase-2 deploy loop
//! (~L705-722 pre-lift) — each spelled the same three-step composition
//! immediately after resolving the per-service registry / image-tag
//! pair:
//!
//! ```ignore
//! let service_dir = crate::product_service_dir_string::product_service_dir_string(
//!     &repo_root,
//!     &product,
//!     &<entry|svc>.path,
//! );
//!
//! run_forge_subcommand(
//!     &crate::commands::orchestrate_release_deploy_only_argv::orchestrate_release_deploy_only_single_env_argv(
//!         &<entry|svc>.name,
//!         &service_dir,
//!         &repo_root,
//!         &<registry_url_expr>,
//!         &<image_tag_expr>,
//!         env_name,
//!     ),
//! )
//! .await?;
//! ```
//!
//! Both stanzas bind an intermediate `service_dir: String` used at
//! exactly one place (the `&service_dir` slot in the argv builder) and
//! then dropped. Post-lift the intermediate disappears at both callers,
//! and the `service_dir` synthesis + argv build + spawn-await pipeline
//! lives at ONE typed body.
//!
//! # Why fuse the spawn here (peer to `run_forge_subcommand_in_product_dir`)
//!
//! The sibling `commands/product_release.rs::run_forge_subcommand_in_product_dir`
//! (~L73-85) already demonstrates the same discipline for the
//! product-scoped self-re-invoke: it fuses `resolve_product_dir` +
//! `path_to_string_lossy` + `product_working_dir_forge_argv` +
//! `run_forge_subcommand` at one body. This module is the peer
//! adapter for the deploy-only, single-environment self-re-invoke
//! shape — the `orchestrate_release_deploy_only_single_env_argv` argv
//! module explicitly deferred the spawn half (`//! Why an array
//! builder, not an argv-plus-spawn fuser`), so the spawn adapter lives
//! HERE, above the argv builder, where its two consumers meet.
//!
//! # THEORY grounding
//!
//! - THEORY.md §V.1 (Construction guarantees; Types → Invariants →
//!   Proofs → Render Anywhere): the returned `Result<()>` composes the
//!   three underlying primitives (`product_service_dir_string`,
//!   `orchestrate_release_deploy_only_single_env_argv`,
//!   `run_forge_subcommand`) into one typed pipeline — a caller cannot
//!   skip a step (say, forget the `service_dir` synthesis and pass
//!   `""`) and still compile.
//! - THEORY.md §VI.1 (three-times rule; "two occurrences is a
//!   coincidence, three is a law"): two sibling occurrences at the
//!   threshold — this lift closes the class before a third caller
//!   re-inlines the fused stanza.

use anyhow::Result;

/// Re-invoke `forge orchestrate-release --deploy-only
/// --single-environment` for one service targeting one environment.
///
/// Fuses the three pre-lift steps both `commands/rollback.rs::execute`
/// (Deploy-previous-tags loop) and
/// `commands/product_release.rs::execute` (Phase-2 deploy loop)
/// spelled inline: (1) resolve the service directory via
/// [`crate::product_service_dir_string::product_service_dir_string`],
/// (2) build the canonical 15-slot argv via
/// [`crate::commands::orchestrate_release_deploy_only_argv::orchestrate_release_deploy_only_single_env_argv`],
/// (3) spawn the self-re-invocation via
/// [`crate::commands::product_release::run_forge_subcommand`].
///
/// The intermediate `service_dir: String` is bound and dropped
/// inside this primitive — a post-lift caller passes the
/// `(product, service_path)` split directly instead of pre-composing
/// the filesystem-string local.
pub async fn dispatch_orchestrate_release_deploy_only_single_env(
    service: &str,
    product: &str,
    service_path: &str,
    repo_root: &str,
    registry: &str,
    image_tag: &str,
    env_name: &str,
) -> Result<()> {
    let service_dir = crate::product_service_dir_string::product_service_dir_string(
        repo_root,
        product,
        service_path,
    );
    let argv = crate::commands::orchestrate_release_deploy_only_argv::orchestrate_release_deploy_only_single_env_argv(
        service,
        &service_dir,
        repo_root,
        registry,
        image_tag,
        env_name,
    );
    crate::commands::product_release::run_forge_subcommand(&argv).await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Signature pin: the primitive accepts seven `&str` slots (in the
    /// pre-lift argument order, with the pre-lift `service_dir` slot
    /// expanded in place into the `(product, service_path)` pair that
    /// composes it) and returns a `Result<()>` async future. A future
    /// edit that widened the signature (e.g. reordered the args, took
    /// an owned `String` for the service name, or returned something
    /// other than `Result<()>`) ripples to every caller and trips this
    /// pin at compile time.
    ///
    /// The `async` async-fn's return-position `impl Trait` cannot be
    /// bound to a generic `Fut: Future` (its opaque type is fresh at
    /// every HRTB instantiation), so instead the pin drives the
    /// primitive through an `async` block that borrows seven distinct
    /// `&str` slots and `.await`s the returned future. A drift in
    /// arity, argument type, or return type flips this compile.
    #[test]
    fn signature_is_seven_slot_str_in_result_out() {
        let _ = async {
            let r: Result<()> = dispatch_orchestrate_release_deploy_only_single_env(
                "service",
                "product",
                "service_path",
                "repo_root",
                "registry",
                "image_tag",
                "env_name",
            )
            .await;
            r
        };
    }

    /// Positive delegation shield: each pre-lift command module MUST
    /// forward through
    /// [`dispatch_orchestrate_release_deploy_only_single_env`] at
    /// least once, so a migration that dropped a call site outright
    /// leaves the negative "no raw three-step stanza" scan (below)
    /// trivially satisfied by absence but the positive count still
    /// fails.
    ///
    /// Rollback.rs (×1: deploy-previous-tags loop in `execute`).
    /// Product-release.rs (×1: Phase-2 deploy loop in `execute`).
    #[test]
    fn every_prelift_module_forwards_through_dispatch() {
        // Reconstruct the delegation needle via `format!` so this
        // shield's own source text does not false-match itself.
        let needle = format!("{}(", "dispatch_orchestrate_release_deploy_only_single_env");
        let expectations: &[(&str, &str, usize)] = &[
            (include_str!("rollback.rs"), "commands/rollback.rs", 1),
            (
                include_str!("product_release.rs"),
                "commands/product_release.rs",
                1,
            ),
        ];
        for (source, module_path, min_count) in expectations {
            let hits = crate::test_support::code_line_hits(source, &needle);
            assert!(
                hits.len() >= *min_count,
                "{module_path} must forward at least {min_count} \
                 deploy-only single-environment `orchestrate-release` \
                 self-re-invoke stanza(s) through \
                 `crate::commands::orchestrate_release_deploy_only_dispatch::\
                 dispatch_orchestrate_release_deploy_only_single_env(`; \
                 found {} hit(s). A dropped call would leave the \
                 negative raw-stanza scan satisfied by absence.",
                hits.len(),
            );
        }
    }

    /// Negative caller shield: neither pre-lift command module may
    /// spell the raw three-step
    /// `product_service_dir_string(...) + orchestrate_release_deploy_only_single_env_argv(...) + run_forge_subcommand(...)`
    /// composition inline any more. The scan looks for a source line
    /// spelling `orchestrate_release_deploy_only_single_env_argv(` in
    /// each caller — post-lift only the dispatch module itself owns
    /// that call.
    ///
    /// Reconstruct the needle via `format!` so this shield's own
    /// source text does not false-match itself.
    #[test]
    fn no_prelift_caller_still_spells_raw_argv_builder_call() {
        let needle = format!("{}(", "orchestrate_release_deploy_only_single_env_argv");
        let callers: &[(&str, &str)] = &[
            (include_str!("rollback.rs"), "commands/rollback.rs"),
            (
                include_str!("product_release.rs"),
                "commands/product_release.rs",
            ),
        ];
        for (source, module_path) in callers {
            let hits = crate::test_support::code_line_hits(source, &needle);
            assert!(
                hits.is_empty(),
                "{module_path} must NOT spell the raw \
                 `orchestrate_release_deploy_only_single_env_argv(` \
                 call inline any more — route the deploy-only \
                 self-re-invoke through \
                 `crate::commands::orchestrate_release_deploy_only_dispatch::\
                 dispatch_orchestrate_release_deploy_only_single_env(...)` \
                 instead. Offending line(s): {hits:#?}"
            );
        }
    }
}
