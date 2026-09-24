//! Kenshi operator release operations
//!
//! Release the kenshi operator image with updates to all cluster manifests.
//! Handles both primary and secondary clusters in a single release.

use anyhow::Result;

use crate::commands::release_commit::announce_and_commit_cluster_overlay_release_step;

/// Release kenshi operator: push image and update K8s manifests for all clusters
///
/// This handles the complete release workflow:
/// 1. Push image to GHCR with auto-tags (amd64-{sha}, amd64-latest)
/// 2. Update primary cluster kustomization.yaml images[] overlay
/// 3. Update secondary cluster kustomization.yaml images[] overlay
/// 4. Commit and push to git
pub async fn release(
    image_path: String,
    registry: String,
    primary_kustomization: String,
    secondary_kustomization: String,
    retries: u32,
    token: Option<String>,
) -> Result<()> {
    // Step 1: Emit release preamble + resolve git SHA into the canonical
    // `amd64-<sha>` tag via the shared cluster-overlay release primitive.
    let new_tag =
        crate::commands::cluster_overlay_release_preamble::announce_release_start_and_compute_tag(
            "kenshi operator",
            &image_path,
            &registry,
        )
        .await?;

    // Step 2: Announce the `Step 1/4: Push Image` header and perform
    // the auto-tag amd64 image push in one fused primitive at
    // `commands::cluster_overlay_release_push_step::announce_and_push_release_image_step`,
    // shared with the sibling `commands/{kenshi_agent,nix_builder}.rs`
    // consumers. The primitive owns the canonical `Push Image` step
    // title (via the private `PUSH_IMAGE_STEP_TITLE` const in that
    // module), the step-1 anchor, and the six load-bearing push
    // defaults (explicit-tags empty, arch=amd64, push_attic=false,
    // attic_cache="", update_kustomization_path=None,
    // commit_kustomization=false), so a future signature change on
    // `push::execute` (a new positional slot, a bool-flag swap) or a
    // re-titling of the step (`Publish Image`) flows to all three
    // flows from one edit rather than through three silently
    // misalignable positional call sites + three inline literal
    // edits.
    crate::commands::cluster_overlay_release_push_step::announce_and_push_release_image_step(
        4,
        image_path,
        registry.clone(),
        retries,
        token,
    )
    .await?;

    // Step 3: Update primary cluster kustomization.yaml images[] overlay
    crate::step_header::announce_step_header(2, 4, "Update primary cluster kustomization");
    update_kustomization_image(&primary_kustomization, &new_tag).await?;
    println!();

    // Step 4: Update secondary cluster kustomization.yaml images[] overlay
    crate::step_header::announce_step_header(3, 4, "Update secondary cluster kustomization");
    update_kustomization_image(&secondary_kustomization, &new_tag).await?;
    println!();

    // Step 5: Commit and push
    announce_and_commit_cluster_overlay_release_step(
        4,
        "kenshi operator",
        &new_tag,
        &[&primary_kustomization, &secondary_kustomization],
    )
    .await?;

    crate::commands::cluster_overlay_release_postamble::announce_release_complete(
        "kenshi operator",
        &registry,
        &new_tag,
    );

    Ok(())
}

/// Update kustomization.yaml images[] overlay for kenshi
///
/// Finds the kenshi image entry and updates the newTag. The walk +
/// enter/exit + splice + emit + bail + finalize sequence rides the
/// fused `commands::kustomization_edit::splice_first_images_new_tag`
/// primitive — sibling of the `commands/nix_builder.rs::
/// update_kustomization_image` flow and of the pure-transform
/// `splice_first_images_new_tag_content` half the
/// `commands/kenshi_agent.rs::update_kustomization_image` interleaved
/// flow shares. The per-site predicate below rejects the adjacent
/// `kenshi-agent` overlay by construction; the primitive threads it
/// through both the enter and exit arms so a `- name: ghcr.io/…/kenshi-
/// agent` line coherently exits the target block rather than being
/// held inside by a registry-substring exit predicate that the pre-lift
/// stanza carried latently.
async fn update_kustomization_image(kustomization_path: &str, new_tag: &str) -> Result<()> {
    crate::commands::kustomization_edit::splice_first_images_new_tag(
        kustomization_path,
        |line| line.contains("kenshi") && !line.contains("kenshi-agent"),
        new_tag,
        "images[] newTag",
        "kenshi",
    )
    .await
}
