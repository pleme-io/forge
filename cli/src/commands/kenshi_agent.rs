//! Kenshi Agent release operations
//!
//! Release the kenshi-agent sidecar image with updates to all cluster manifests.
//! Handles both primary and secondary clusters in a single release.

use anyhow::Result;

use crate::commands::release_commit::announce_and_commit_cluster_overlay_release_step;

/// Release kenshi-agent: push image and update K8s manifests for all clusters
///
/// This handles the complete release workflow:
/// 1. Push image to GHCR with auto-tags (amd64-{sha}, amd64-latest)
/// 2. Update primary cluster kustomization.yaml images[] overlay
/// 3. Update secondary cluster kustomization.yaml images[] overlay
/// 4. Update primary cluster builder-pool agentImage field
/// 5. Update secondary cluster builder-pool agentImage field
/// 6. Commit and push to git
pub async fn release(
    image_path: String,
    registry: String,
    primary_kustomization: String,
    secondary_kustomization: String,
    primary_builder_pool: String,
    secondary_builder_pool: String,
    retries: u32,
    token: Option<String>,
) -> Result<()> {
    // Step 1: Emit release preamble + resolve git SHA into the canonical
    // `amd64-<sha>` tag via the shared cluster-overlay release primitive.
    let new_tag =
        crate::commands::cluster_overlay_release_preamble::announce_release_start_and_compute_tag(
            "kenshi-agent",
            &image_path,
            &registry,
        )
        .await?;

    // Step 2: Announce the `Step 1/6: Push Image` header and perform
    // the auto-tag amd64 image push in one fused primitive at
    // `commands::cluster_overlay_release_push_step::announce_and_push_release_image_step`,
    // shared with the sibling `commands/{kenshi,nix_builder}.rs`
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
        6,
        image_path,
        registry.clone(),
        retries,
        token,
    )
    .await?;

    // Step 3: Update primary cluster kustomization.yaml images[] overlay
    crate::step_header::announce_step_header(2, 6, "Update primary cluster kustomization");
    update_kustomization_image(&primary_kustomization, &registry, &new_tag).await?;
    println!();

    // Step 4: Update secondary cluster kustomization.yaml images[] overlay
    crate::step_header::announce_step_header(3, 6, "Update secondary cluster kustomization");
    update_kustomization_image(&secondary_kustomization, &registry, &new_tag).await?;
    println!();

    // Step 5: Update primary cluster builder-pool agentImage — the
    // `require_existing_labeled("Builder pool file")` +
    // `info!("📝 Updating: {}", ...)` + `read_text_async` +
    // `image_reference` + indent-preserving `.trim().starts_with(<field>:)`
    // splice + `write_text_async` + `info_indented_success!` fusion now
    // lives at ONE typed boundary at
    // `commands::builder_pool_edit::update_builder_pool_field`, shared
    // with the sibling `commands/nix_builder.rs::update_builder_pool_field
    // (BuilderPoolField::BuilderImage, ...)` consumer so a future
    // refinement of the builder-pool CRD schema, the miss envelope, or
    // the announcement grammar flows to both builder-pool release flows
    // from one edit. `BuilderPoolField::AgentImage` selects the
    // `agentImage:` YAML field the kenshi-agent builder pool references.
    crate::step_header::announce_step_header(4, 6, "Update primary cluster builder-pool");
    crate::commands::builder_pool_edit::update_builder_pool_field(
        &primary_builder_pool,
        crate::commands::builder_pool_edit::BuilderPoolField::AgentImage,
        &registry,
        &new_tag,
    )
    .await?;
    println!();

    // Step 6: Update secondary cluster builder-pool agentImage — same
    // fusion primitive as the primary-cluster call above; a future edit
    // to the builder-pool edit shape reaches both sibling calls from
    // one boundary.
    crate::step_header::announce_step_header(5, 6, "Update secondary cluster builder-pool");
    crate::commands::builder_pool_edit::update_builder_pool_field(
        &secondary_builder_pool,
        crate::commands::builder_pool_edit::BuilderPoolField::AgentImage,
        &registry,
        &new_tag,
    )
    .await?;
    println!();

    // Step 7: Commit and push
    announce_and_commit_cluster_overlay_release_step(
        6,
        "kenshi-agent",
        &new_tag,
        &[
            &primary_kustomization,
            &secondary_kustomization,
            &primary_builder_pool,
            &secondary_builder_pool,
        ],
    )
    .await?;

    crate::commands::cluster_overlay_release_postamble::announce_release_complete(
        "kenshi-agent",
        &registry,
        &new_tag,
    );

    Ok(())
}

/// Update kustomization.yaml images[] overlay for kenshi-agent
///
/// Finds the kenshi-agent image entry and updates the newTag.
/// Also updates AGENT_IMAGE env var if present in patches.
async fn update_kustomization_image(
    kustomization_path: &str,
    registry: &str,
    new_tag: &str,
) -> Result<()> {
    let (path, content) =
        crate::commands::kustomization_edit::open_for_update(kustomization_path).await?;

    let new_image = crate::oci_manifest::image_reference(registry, new_tag);
    let mut updated_images = false;
    let mut updated_env = false;
    let mut new_content = String::new();
    let mut in_kenshi_agent_image = false;

    for line in content.lines() {
        // Track if we're in the kenshi-agent image block
        if line.contains("name:") && line.contains("kenshi-agent") {
            in_kenshi_agent_image = true;
        }
        // Exit the image block when we hit another image entry
        if in_kenshi_agent_image
            && line.trim().starts_with("- name:")
            && !line.contains("kenshi-agent")
        {
            in_kenshi_agent_image = false;
        }

        // Update newTag within the kenshi-agent image block. The
        // indent-preserving `{indent}newTag: {new_tag}\n` splice rides
        // the shared `crate::repo::indent_preserving_kv_line` primitive
        // — sibling of the kenshi and nix-builder images[] splices and
        // of the builder-pool field splice — so the byte shape stays
        // pinned at one body across the four sibling flows.
        if in_kenshi_agent_image && line.contains("newTag:") {
            new_content.push_str(&crate::repo::indent_preserving_kv_line(
                line, "newTag", new_tag,
            ));
            updated_images = true;
            crate::info_updated_field!("images[] newTag", new_tag);
        }
        // Update AGENT_IMAGE env var reference if present. The
        // registry-anchored `{prefix}{new_image}{suffix}\n` splice
        // (`line.find(registry)` → `find(|c| c == '"' || c == '\'' ||
        // c == ' ' || c == '\n')` → three-piece format) now rides the
        // pure `crate::repo::splice_registry_anchored_image_ref`
        // primitive — sibling of the `nix_builder.rs::
        // update_kenshi_builder_image` BUILDER_IMAGE arm — so the
        // delimiter alphabet, the trailing-newline shape, and the miss
        // envelope stay pinned at ONE body across both flows. The
        // pre-lift `unwrap_or(0) + if start_idx > 0` conservative guard
        // becomes the `if let Some { .. } else { push verbatim }` shape
        // below: byte-identical because the outer `line.contains(
        // "AGENT_IMAGE") && line.contains("kenshi-agent:")` predicate
        // makes an unindented AGENT_IMAGE line unreachable in practice.
        else if line.contains("AGENT_IMAGE") && line.contains("kenshi-agent:") {
            if let Some(rewritten) =
                crate::repo::splice_registry_anchored_image_ref(line, registry, &new_image)
            {
                new_content.push_str(&rewritten);
                updated_env = true;
                crate::info_updated_field!("AGENT_IMAGE env", new_image);
            } else {
                new_content.push_str(line);
                new_content.push('\n');
            }
        } else {
            new_content.push_str(line);
            new_content.push('\n');
        }
    }

    if !updated_images && !updated_env {
        anyhow::bail!(
            "No kenshi-agent entry found in images[] or AGENT_IMAGE in {}",
            kustomization_path
        );
    }

    crate::commands::kustomization_edit::finalize_and_announce(
        path,
        &new_content,
        "Kustomization updated",
    )
    .await
}
