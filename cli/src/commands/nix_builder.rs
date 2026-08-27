//! Nix builder remote build service operations
//!
//! Verify, test, and release the nix-builder remote AMD64 build service.
//! Used for Mac (ARM) to Linux (AMD64) cross-compilation.

use anyhow::{Context, Result};
use std::path::Path;
use std::process::Command;
use tracing::{info, warn};

use crate::commands::push;
use crate::commands::release_commit::commit_cluster_overlay_release;
use crate::repo::get_tool_path;

/// Resolve the `nc` binary path via the canonical two-argument
/// [`crate::repo::get_tool_path`] `("NC_BIN", "nc")` call — the
/// module-scoped sigil every `nc` network-probe spawn in this module
/// routes through.
///
/// Pre-lift two consumer sites in this module (`verify_k8s_service` at
/// the in-cluster reachability probe and `verify_external` at the
/// external L4 reachability probe) each spelled
/// `get_tool_path("NC_BIN", "nc")` verbatim, silently bypassing any
/// single-point-of-truth for `nc` resolution: a future edit to the
/// resolve contract at either site (a substrate-path validation step,
/// a per-spawn env-injection hook, a telemetry sigil on the resolved
/// path) would have left the other stranded at the pre-edit form.
/// Post-lift each consumer routes through this sigil, the deriving
/// pre-lift respells are gone from the module body, and the two-arg
/// resolve appears at ONE code line.
///
/// Sibling of the `<tool>_bin()` sigils landed on the CARGO surface
/// across `commands/{test_ci,prerelease,developer_tools,tool,e2e,
/// comprehensive_release}.rs`, the NIX_BIN surface across
/// `commands/{build,developer_tools,rust_service,nix_builder,e2e,
/// tool}.rs`, the DOCKER_BIN / BUN_BIN / CRATE2NIX / ATTIC_BIN
/// surfaces, the `commands/helm.rs::helm_bin()` sigil, and the
/// `flux_reconcile.rs::flux_bin()` / `flux_get.rs::flux_bin()` /
/// `infrastructure/attic.rs::attic_bin()` / `nix.rs::nix_bin()`
/// sibling sigils — the same per-module single-point-of-truth
/// discipline applied to the NC_BIN surface here. THEORY §I.5
/// (Generation over composition, duplication budget zero) and §VI.1
/// (three-times rule).
fn nc_bin() -> String {
    get_tool_path("NC_BIN", "nc")
}

/// Verify nix-builder service is accessible
pub async fn verify(
    hostname: String,
    port: u16,
    k8s_service: Option<String>,
    namespace: Option<String>,
) -> Result<()> {
    info!("🔍 Verifying nix-builder at {}:{}", hostname, port);

    // If k8s_service is provided, we're running in-cluster
    if let Some(svc) = k8s_service {
        let ns = namespace.ok_or_else(|| {
            anyhow::anyhow!(
                "--namespace is required when using --k8s-service for in-cluster verification"
            )
        })?;
        info!("Running in-cluster verification for service: {}", svc);
        verify_k8s_service(&svc, &ns, port).await?;
    } else {
        // External verification (from Mac/developer machine)
        verify_external(&hostname, port).await?;
    }

    info!("✅ nix-builder verification complete!");
    Ok(())
}

/// Test remote build by building a simple package
pub async fn test(hostname: String, port: u16, ssh_key: String, package: String) -> Result<()> {
    info!("🧪 Testing remote build with package: {}", package);
    info!("Builder: {}:{}", hostname, port);
    info!("SSH key: {}", ssh_key);

    // Verify SSH key exists
    if !std::path::Path::new(&ssh_key).exists() {
        anyhow::bail!(
            "SSH key not found at {}. Run `./bin/darwin-rebuild` to copy it.",
            ssh_key
        );
    }

    info!("Testing SSH connection...");
    // Owns the sync captured-output spawn + classify ritual at the
    // canonical `crate::retry::run_capture_anyhow_sync` primitive.
    // Post-lift the `"ssh probe failed (exit {code}): {stderr}"` /
    // `"Failed to spawn ssh probe: {io_error}"` envelopes emerge by
    // construction at `retry::classify_capture_anyhow` — same shape
    // every migrated captured-output site in forge emits.
    let mut ssh_cmd = Command::new(get_tool_path("SSH_BIN", "ssh"));
    ssh_cmd.args(&[
        "-i",
        &ssh_key,
        "-p",
        &port.to_string(),
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "ConnectTimeout=10",
        &format!("root@{}", hostname),
        "echo 'SSH connection successful'",
    ]);
    crate::retry::run_capture_anyhow_sync(ssh_cmd, "ssh probe")?;

    info!("✅ SSH connection successful!");

    // Test a simple remote build
    info!("Testing remote build of nixpkgs#{}", package);
    info!(
        "This will offload the build to the remote builder at {}:{}",
        hostname, port
    );

    // Sibling of the SSH probe: same primitive, retains the returned
    // `Output` so the subsequent `info!` line can read
    // `nix_build.stdout` to log the remote store path.
    let mut nix_cmd = Command::new(get_tool_path("NIX_BIN", "nix"));
    nix_cmd
        .args(&[
            "build",
            &format!("nixpkgs#{}", package),
            "--system",
            "x86_64-linux",
            "--no-link",
            "--print-out-paths",
        ])
        .env("NIX_SSHOPTS", format!("-p {}", port));
    let nix_build = crate::retry::run_capture_anyhow_sync(nix_cmd, "nix cross-build")?;

    let output = String::from_utf8_lossy(&nix_build.stdout);
    info!("✅ Remote build successful!");
    info!("Build output: {}", output.trim());

    info!("");
    info!("🎉 nix-builder is working correctly!");
    info!("");
    info!("You can now use it for your builds:");
    info!("  nix build .#dockerImage --system x86_64-linux");
    info!("");

    Ok(())
}

/// Verify K8s service is accessible (in-cluster)
async fn verify_k8s_service(service: &str, namespace: &str, port: u16) -> Result<()> {
    info!(
        "Checking if service {}.{} is accessible on port {}",
        service, namespace, port
    );

    // Use netcat to check if port is accessible
    let nc_check = Command::new(nc_bin())
        .args(&[
            "-zv",
            &format!("{}.{}.svc.cluster.local", service, namespace),
            &port.to_string(),
        ])
        .output()
        .context("Failed to execute netcat check")?;

    if !nc_check.status.success() {
        let stderr = String::from_utf8_lossy(&nc_check.stderr);
        anyhow::bail!("Service not accessible: {}. Stderr: {}", service, stderr);
    }

    info!("✅ Service {} is accessible on port {}", service, port);
    Ok(())
}

/// Verify external access to nix-builder (from Mac/developer machine)
async fn verify_external(hostname: &str, port: u16) -> Result<()> {
    info!("Checking external access to {}:{}", hostname, port);

    // Check DNS resolution
    info!("Resolving DNS for {}", hostname);
    let dig_output = Command::new(get_tool_path("DIG_BIN", "dig"))
        .args(&["+short", hostname])
        .output()
        .context("Failed to resolve DNS")?;

    if !dig_output.status.success() || dig_output.stdout.is_empty() {
        warn!("DNS resolution failed or returned no results");
        warn!("Make sure to run ./bin/darwin-rebuild to update DNS");
    } else {
        let ip = String::from_utf8_lossy(&dig_output.stdout);
        info!("✅ DNS resolved to: {}", ip.trim());
    }

    // Check TCP connectivity with timeout
    info!("Checking TCP connectivity to {}:{}", hostname, port);
    let nc_check = Command::new(nc_bin())
        .args(&["-zv", "-G", "5", hostname, &port.to_string()])
        .output()
        .context("Failed to execute netcat check")?;

    if !nc_check.status.success() {
        let stderr = String::from_utf8_lossy(&nc_check.stderr);
        anyhow::bail!(
            "Cannot connect to {}:{}. Stderr: {}",
            hostname,
            port,
            stderr
        );
    }

    info!("✅ TCP connection to {}:{} successful", hostname, port);
    Ok(())
}

/// Release nix-builder: push image and update K8s manifests for all clusters
///
/// This handles the complete release workflow:
/// 1. Push image to GHCR with auto-tags (amd64-{sha}, amd64-latest)
/// 2. Update primary cluster nix-builder kustomization.yaml images[] overlay (if exists)
/// 3. Update primary cluster kenshi kustomization.yaml BUILDER_IMAGE env var
/// 4. Update primary cluster builder-pool builderImage field
/// 5. Update secondary cluster kenshi kustomization.yaml BUILDER_IMAGE env var
/// 6. Update secondary cluster builder-pool builderImage field
/// 7. Commit and push to git
pub async fn release(
    image_path: String,
    registry: String,
    primary_nix_builder_kustomization: Option<String>,
    primary_kenshi_kustomization: String,
    primary_builder_pool: String,
    secondary_kenshi_kustomization: String,
    secondary_builder_pool: String,
    retries: u32,
    token: Option<String>,
) -> Result<()> {
    info!("🚀 Starting nix-builder release");
    info!("   Image: {}", image_path);
    info!("   Registry: {}", registry);
    println!();

    // Step 1: Get git SHA for tagging
    let git_sha = push::get_git_sha().await?;
    let new_tag = format!("amd64-{}", git_sha);
    info!("📋 Release tag: {}", new_tag);
    println!();

    // Step 2: Push image to GHCR
    info!("━━━ Step 1/7: Push Image ━━━");
    push::execute(
        image_path,
        registry.clone(),
        vec![], // tags - will be generated by auto_tags
        true,   // auto_tags
        "amd64".to_string(),
        retries,
        token,
        false,         // push_attic
        String::new(), // attic_cache
        None,          // update_kustomization_path
        false,         // commit_kustomization
    )
    .await?;
    println!();

    // Collect all modified files for git commit
    let mut modified_files: Vec<String> = Vec::new();

    // Step 3: Update primary cluster nix-builder kustomization.yaml images[] overlay (if exists)
    if let Some(ref primary_kust) = primary_nix_builder_kustomization {
        info!("━━━ Step 2/7: Update primary cluster nix-builder kustomization ━━━");
        update_kustomization_image(primary_kust, &registry, &new_tag).await?;
        modified_files.push(primary_kust.clone());
        println!();
    } else {
        info!("━━━ Step 2/7: Skip primary cluster nix-builder kustomization (not provided) ━━━");
        println!();
    }

    // Step 4: Update primary cluster kenshi kustomization.yaml BUILDER_IMAGE
    info!("━━━ Step 3/7: Update primary cluster kenshi BUILDER_IMAGE ━━━");
    update_kenshi_builder_image(&primary_kenshi_kustomization, &registry, &new_tag).await?;
    modified_files.push(primary_kenshi_kustomization.clone());
    println!();

    // Step 5: Update primary cluster builder-pool builderImage
    info!("━━━ Step 4/7: Update primary cluster builder-pool ━━━");
    update_builder_pool_builder_image(&primary_builder_pool, &registry, &new_tag).await?;
    modified_files.push(primary_builder_pool.clone());
    println!();

    // Step 6: Update secondary cluster kenshi kustomization.yaml BUILDER_IMAGE
    info!("━━━ Step 5/7: Update secondary cluster kenshi BUILDER_IMAGE ━━━");
    update_kenshi_builder_image(&secondary_kenshi_kustomization, &registry, &new_tag).await?;
    modified_files.push(secondary_kenshi_kustomization.clone());
    println!();

    // Step 7: Update secondary cluster builder-pool builderImage
    info!("━━━ Step 6/7: Update secondary cluster builder-pool ━━━");
    update_builder_pool_builder_image(&secondary_builder_pool, &registry, &new_tag).await?;
    modified_files.push(secondary_builder_pool.clone());
    println!();

    // Step 8: Commit and push
    info!("━━━ Step 7/7: Commit and Push ━━━");
    info!("📤 Committing release changes...");
    let file_refs: Vec<&str> = modified_files.iter().map(String::as_str).collect();
    commit_cluster_overlay_release(None, "nix-builder", &new_tag, &file_refs).await?;

    println!();
    info!("╔════════════════════════════════════════════════════════════╗");
    info!("║  ✅ nix-builder release complete!                          ║");
    info!("╚════════════════════════════════════════════════════════════╝");
    println!();
    info!("Image: {}:{}", registry, new_tag);
    info!("Updated all clusters");
    info!("FluxCD will reconcile the changes automatically.");
    println!();

    Ok(())
}

/// Update kustomization.yaml images[] overlay
///
/// Finds `images:` section and updates the `newTag` for the matching image name.
/// Standard kustomization pattern: default image in deployment is :latest,
/// kustomization overlay specifies specific tag.
async fn update_kustomization_image(
    kustomization_path: &str,
    registry: &str,
    new_tag: &str,
) -> Result<()> {
    let path = Path::new(kustomization_path);
    if !path.exists() {
        anyhow::bail!("Kustomization file not found: {}", kustomization_path);
    }

    info!("📝 Updating: {}", kustomization_path);

    // Read content
    let content = crate::repo::read_text_async(path).await?;

    // Find and replace newTag in images[] section
    // Pattern:
    //   images:
    //     - name: ghcr.io/org/nix-builder
    //       newName: ghcr.io/org/nix-builder
    //       newTag: amd64-xxxxxxxx
    let mut updated = false;
    let mut new_content = String::new();
    let mut in_target_image = false;

    for line in content.lines() {
        // Check if we're entering the target image block
        if line.contains("name:") && line.contains(registry) {
            in_target_image = true;
        }
        // Check if we're leaving the image block (next image or end of images section)
        if in_target_image && (line.trim().starts_with("- name:") && !line.contains(registry)) {
            in_target_image = false;
        }

        // Update newTag within the target image block
        if in_target_image && line.contains("newTag:") {
            let indent = line.len() - line.trim_start().len();
            let indent_str: String = line.chars().take(indent).collect();
            new_content.push_str(&format!("{}newTag: {}\n", indent_str, new_tag));
            updated = true;
            info!("   Updated newTag to: {}", new_tag);
        } else {
            new_content.push_str(line);
            new_content.push('\n');
        }
    }

    if !updated {
        anyhow::bail!(
            "No images[] entry found for {} in {}",
            registry,
            kustomization_path
        );
    }

    // Write back (remove trailing newline from loop)
    let final_content = new_content.trim_end().to_string() + "\n";
    tokio::fs::write(path, &final_content)
        .await
        .context("Failed to write kustomization.yaml")?;

    info!("   ✅ Kustomization updated");
    Ok(())
}

/// Update kenshi kustomization.yaml BUILDER_IMAGE configMap literal
///
/// Finds the configMapGenerator literal `BUILDER_IMAGE={registry}:xxx`
/// and updates the tag.
async fn update_kenshi_builder_image(
    kustomization_path: &str,
    registry: &str,
    new_tag: &str,
) -> Result<()> {
    let path = Path::new(kustomization_path);
    if !path.exists() {
        anyhow::bail!("Kustomization file not found: {}", kustomization_path);
    }

    info!("📝 Updating: {}", kustomization_path);

    // Read content
    let content = crate::repo::read_text_async(path).await?;

    // Find and replace BUILDER_IMAGE reference
    // Pattern: - BUILDER_IMAGE={registry}:amd64-xxx
    // Or: {registry}:amd64-xxx (anywhere in literals)
    let new_image = crate::oci_manifest::image_reference(registry, new_tag);

    let mut updated = false;
    let mut new_content = String::new();

    for line in content.lines() {
        if line.contains(registry)
            && (line.contains("BUILDER_IMAGE") || line.contains("nix-builder:"))
        {
            // Replace the image reference in this line
            // Use regex-like replacement: find registry:tag pattern and replace
            let start_idx = line.find(registry).unwrap();
            let prefix = &line[..start_idx];

            // Find the end of the tag (newline, quote, or end of string)
            let after_registry = &line[start_idx..];
            let tag_end = after_registry
                .find(|c: char| c == '"' || c == '\'' || c == ' ' || c == '\n')
                .unwrap_or(after_registry.len());

            let suffix = &after_registry[tag_end..];
            new_content.push_str(&format!("{}{}{}\n", prefix, new_image, suffix));
            updated = true;
            info!("   Updated BUILDER_IMAGE to: {}", new_image);
        } else {
            new_content.push_str(line);
            new_content.push('\n');
        }
    }

    if !updated {
        anyhow::bail!(
            "No BUILDER_IMAGE reference found for {} in {}",
            registry,
            kustomization_path
        );
    }

    // Write back
    let final_content = new_content.trim_end().to_string() + "\n";
    tokio::fs::write(path, &final_content)
        .await
        .context("Failed to write kustomization.yaml")?;

    info!("   ✅ Kenshi kustomization updated");
    Ok(())
}

/// Update builder-pool YAML builderImage field
///
/// Finds the builderImage field and updates it to the new tag.
async fn update_builder_pool_builder_image(
    builder_pool_path: &str,
    registry: &str,
    new_tag: &str,
) -> Result<()> {
    let path = Path::new(builder_pool_path);
    if !path.exists() {
        anyhow::bail!("Builder pool file not found: {}", builder_pool_path);
    }

    info!("📝 Updating: {}", builder_pool_path);

    // Read content
    let content = crate::repo::read_text_async(path).await?;

    let new_image = crate::oci_manifest::image_reference(registry, new_tag);
    let mut updated = false;
    let mut new_content = String::new();

    for line in content.lines() {
        // Update builderImage field (not agentImage - that's for kenshi-agent)
        if line.trim().starts_with("builderImage:") {
            let indent = line.len() - line.trim_start().len();
            let indent_str: String = line.chars().take(indent).collect();
            new_content.push_str(&format!("{}builderImage: {}\n", indent_str, new_image));
            updated = true;
            info!("   Updated builderImage to: {}", new_image);
        } else {
            new_content.push_str(line);
            new_content.push('\n');
        }
    }

    if !updated {
        anyhow::bail!("No builderImage field found in {}", builder_pool_path);
    }

    // Write back
    let final_content = new_content.trim_end().to_string() + "\n";
    tokio::fs::write(path, &final_content)
        .await
        .context("Failed to write builder-pool.yaml")?;

    info!("   ✅ Builder pool updated");
    Ok(())
}

#[cfg(test)]
mod nix_bin_routing_tests {
    /// Whole-module shield: no raw `Command::new(get_tool_path("NIX_BIN", "nix"))` may live in
    /// `commands/nix_builder.rs`'s non-test body. Every `nix` spawn in
    /// this module must first resolve `NIX_BIN` via
    /// [`crate::repo::get_tool_path`] — the canonical env-var override
    /// every other nix-invocation site in forge honors
    /// (`commands/build.rs::execute` d8ef0d5,
    /// `commands/tool.rs::build_lock_target`,
    /// `commands/developer_tools.rs::rust_update_cargo_nix` and
    /// siblings 4dfb2b3, `commands/rust_service.rs`'s three
    /// nix spawn sites 7c34e57,
    /// `commands/product_release.rs::run_nix_release_app` d0cd622,
    /// `nix.rs::build_flake_attr_in` / `build_docker_image_from_dir`
    /// / `path_info_recursive`, and
    /// `nix_hooks.rs::NixHooks::build_and_get_path`).
    ///
    /// Pre-lift this module carried one real `nix` spawn site:
    /// `test`'s remote-build probe at line 88
    /// (`nix build nixpkgs#<pkg> --system x86_64-linux
    /// --no-link --print-out-paths` under `NIX_SSHOPTS`, the
    /// `forge nix-builder test` command whose exit-code decides
    /// whether the remote AMD64 builder is declared healthy for
    /// Mac→Linux cross-compilation). The spawn spelled
    /// `Command::new(get_tool_path("NIX_BIN", "nix"))` verbatim, ignoring `NIX_BIN` at
    /// exactly the moment hermetic-runner consistency matters most —
    /// the test that decides whether the remote builder is trusted
    /// to build the very same forge CLI. A Nix-hermetic runner with
    /// a store-path `nix` binary silently fell through to whatever
    /// `nix` was first on `PATH` at this site, diverging from every
    /// other nix-invocation surface in forge and from the sibling
    /// KUBECTL_BIN / GIT_BIN / CARGO frontier's uniform discipline.
    ///
    /// The scan bounds on the whole-module boundary (from the file
    /// start to the first `\n#[cfg(test)]\n` marker, which delimits
    /// this shield) so shield docstring mentions of
    /// `Command::new(get_tool_path("NIX_BIN", "nix"))` stay out of scope AND every current or
    /// future nix-spawning helper landing anywhere in the top-level
    /// module body cannot silently ride along without going through
    /// `NIX_BIN`. Mirrors the sibling whole-module shields on
    /// `commands/build.rs::test_execute_routes_nix_through_nix_bin_not_raw_command`
    /// (d8ef0d5),
    /// `commands/developer_tools.rs::test_developer_tools_routes_nix_through_nix_bin_not_raw_command`
    /// (4dfb2b3), and
    /// `commands/rust_service.rs::test_rust_service_routes_nix_through_nix_bin_not_raw_command`
    /// (7c34e57) — the whole-module-boundary scan discipline
    /// pioneered on `commands/supergraph_verification.rs` (65283fb).
    #[test]
    fn test_nix_builder_routes_nix_through_nix_bin_not_raw_command() {
        const SOURCE: &str = include_str!("nix_builder.rs");
        let body = crate::test_support::module_body_before_first_cfg_test(
            SOURCE,
            "commands/nix_builder.rs",
        );
        assert!(
            !body.contains("Command::new(\"nix\")"),
            "commands/nix_builder.rs must not spawn `nix` via the bare \
             literal — every `nix` spawn must resolve `NIX_BIN` via \
             `crate::repo::get_tool_path(\"NIX_BIN\", \"nix\")` first. \
             A raw `Command::new(\"nix\")` bypasses the hermetic-runner \
             contract substrate's mkRuntimeToolsEnv exports."
        );
        assert!(
            body.contains("get_tool_path(\"NIX_BIN\", \"nix\")"),
            "commands/nix_builder.rs must resolve the nix binary via \
             `get_tool_path(\"NIX_BIN\", \"nix\")` — the canonical \
             lookup was not found in the module body."
        );
    }

    /// Whole-module shield: no raw `Command::new("ssh")`, `Command::new("nc")`,
    /// or `Command::new("dig")` may live in `commands/nix_builder.rs`'s
    /// non-test body. Every network-probe spawn in this module must first
    /// resolve `{SSH_BIN, NC_BIN, DIG_BIN}` via
    /// [`crate::repo::get_tool_path`] — the same `{TOOL}_BIN` env-var
    /// override convention every other `Command::new(get_tool_path(...))`
    /// call site in forge honors (`commands/build.rs` NIX_BIN d8ef0d5,
    /// `commands/comprehensive_release.rs` DOCKER_BIN 7236cd6,
    /// `commands/rebac_validation.rs` REDIS_CLI_BIN 9aed883, etc.).
    ///
    /// Pre-lift this module carried four raw network-probe spawn sites:
    /// `test`'s `ssh -i <key> ... root@<host> 'echo ...'` reachability
    /// probe (line 57 — decides whether the remote AMD64 builder is
    /// reachable at all before the nix cross-build test even runs);
    /// `verify_k8s_service`'s `nc -zv <svc>.<ns>.svc.cluster.local <port>`
    /// probe (line 129 — the sole in-cluster reachability signal for
    /// `forge nix-builder verify --k8s-service`); `verify_external`'s
    /// `dig +short <hostname>` DNS resolution probe (line 153 — the
    /// external-verification path's DNS-health signal); and
    /// `verify_external`'s `nc -zv -G 5 <hostname> <port>` TCP probe
    /// (line 168 — the external-verification path's L4 reachability
    /// signal). Each spawn spelled `Command::new("<probe>")` verbatim,
    /// ignoring `SSH_BIN` / `NC_BIN` / `DIG_BIN` on a Nix-hermetic
    /// runner whose derivation exports those exact paths. On a
    /// minimal Nix container that omits `ssh` / `nc` / `dig` from
    /// PATH entirely — but wires the corresponding `*_BIN` env vars
    /// from the substrate — every probe silently fails-to-exec and
    /// the verify/test commands falsely report the remote builder
    /// unreachable. Post-lift the four probes ride the same
    /// `{TOOL}_BIN` frontier the sibling nix invocation above (line
    /// 89) already rides.
    ///
    /// The scan bounds on the whole-module boundary (from the file
    /// start to the first `\n#[cfg(test)]\n` marker, which delimits
    /// the sibling NIX_BIN shield's `mod nix_bin_routing_tests`
    /// block above) so shield docstring mentions of the forbidden
    /// `Command::new("<probe>")` shapes stay out of scope AND every
    /// current or future probe helper landing anywhere in the
    /// top-level module body cannot silently ride along without
    /// going through the `{TOOL}_BIN` env var. Mirrors the sibling
    /// whole-module shields on `commands/rebac_validation.rs`
    /// (REDIS_CLI_BIN, 9aed883) and `commands/comprehensive_release.rs`
    /// (DOCKER_BIN, 7236cd6) — the whole-module-boundary scan
    /// discipline pioneered on
    /// `commands/supergraph_verification.rs` (65283fb).
    ///
    /// The forbidden `Command::new("<probe>")` shapes are
    /// reconstructed at test time via `format!` so the shield's
    /// own source text does not false-match itself; every
    /// docstring mention of the forbidden shape uses probe-name
    /// paraphrase for the same reason.
    #[test]
    fn test_nix_builder_probes_route_through_ssh_nc_dig_bin_not_raw_command() {
        const SOURCE: &str = include_str!("nix_builder.rs");
        let body = crate::test_support::module_body_before_first_cfg_test(
            SOURCE,
            "commands/nix_builder.rs",
        );
        for probe in ["ssh", "nc", "dig"] {
            let forbidden = format!("Command::new(\"{}\")", probe);
            assert!(
                !body.contains(&forbidden),
                "commands/nix_builder.rs must not spawn `{probe}` via the \
                 bare literal — every `{probe}` spawn must resolve the \
                 corresponding `{{TOOL}}_BIN` env var via \
                 `crate::repo::get_tool_path` first. A raw \
                 `Command::new(<probe>)` bypasses the hermetic-runner \
                 contract substrate's mkRuntimeToolsEnv exports.",
                probe = probe
            );
        }
        for env_var in ["SSH_BIN", "NC_BIN", "DIG_BIN"] {
            let canonical = format!(
                "get_tool_path(\"{}\", \"{}\")",
                env_var,
                env_var.trim_end_matches("_BIN").to_lowercase()
            );
            assert!(
                body.contains(&canonical),
                "commands/nix_builder.rs must resolve the {env_var} probe via \
                 `{canonical}` — the canonical lookup was not found in the \
                 module body.",
                env_var = env_var,
                canonical = canonical
            );
        }
    }

    /// Whole-module shield: `fn nc_bin()` — the module-scoped sigil
    /// that resolves the `nc` binary via the canonical two-argument
    /// [`crate::repo::get_tool_path`] `("NC_BIN", "nc")` call — MUST
    /// be defined at a code line in this module, AND the two-arg
    /// resolve MUST appear at exactly ONE code line in the module
    /// body (only in the sigil definition).
    ///
    /// Pre-lift the module carried two respells of the canonical
    /// two-arg form — one per `nc` network-probe entry point
    /// (`verify_k8s_service`'s in-cluster reachability probe and
    /// `verify_external`'s external L4 reachability probe) — silently
    /// bypassing any single-point-of-truth for `nc` tool resolution: a
    /// future edit to the resolve contract at either entry point
    /// would have left the other stranded at the pre-edit form. Post-
    /// lift each consumer routes through `nc_bin()` and the two-arg
    /// resolve appears in exactly ONE place (the sigil body). The
    /// `resolve_count == 1` assertion fails-before at 2 (the two
    /// pre-lift respells) and passes-after at 1 — canonical
    /// fail-before-pass-after arc matching the sibling `<tool>_bin()`
    /// shield discipline landed on `flux_reconcile.rs::flux_bin`
    /// (ba3e615), `flux_get.rs::flux_bin` (5ad341e),
    /// `infrastructure/attic.rs::attic_bin` (559adae),
    /// `commands/comprehensive_release.rs::cargo_bin` (fceeecc),
    /// `cli/src/nix.rs::nix_bin` (6b2ea15), and the broader
    /// `<tool>_bin()` sigil family.
    ///
    /// The scan bounds on the whole-module boundary (from the file
    /// start to the first `\n#[cfg(test)]\n` marker — the sibling
    /// NIX_BIN shield's `mod nix_bin_routing_tests` block opener) so
    /// this shield's own docstring mentions of the canonical form —
    /// living inside the `#[cfg(test)]` block below that marker —
    /// stay out of scope AND every current or future nc-spawning
    /// helper landing anywhere in the top-level module body cannot
    /// silently ride along without going through `nc_bin()`.
    ///
    /// Both needles are reconstructed via `format!` inside
    /// [`crate::test_support::sigil_bin_fn_definition_needle`] and
    /// [`crate::test_support::get_tool_path_two_arg_call_needle`], so
    /// this shield's own source never contains a concrete
    /// `get_tool_path("NC_BIN", "nc")` or `fn nc_bin()` literal and
    /// cannot false-match itself on any assertion. Both assertions
    /// route through [`crate::test_support::code_line_hits`] to
    /// preserve the anti-docstring-self-match discipline — existing
    /// `///` and `//!` prose in the module that legitimately quotes
    /// the pre-lift or canonical shape for narrative purposes does
    /// not count against the sigil-body or resolve assertions.
    #[test]
    fn test_nix_builder_routes_nc_through_nc_bin_sigil_not_raw_resolve() {
        const SOURCE: &str = include_str!("nix_builder.rs");
        let body = crate::test_support::module_body_before_first_cfg_test(
            SOURCE,
            "commands/nix_builder.rs",
        );

        let sigil_needle = crate::test_support::sigil_bin_fn_definition_needle("nc_bin");
        let sigil_hits = crate::test_support::code_line_hits(body, &sigil_needle);
        assert!(
            !sigil_hits.is_empty(),
            "commands/nix_builder.rs must define `nc_bin()` at a code line \
             in the module body — the sigil function that resolves the \
             `NC_BIN` override for every `nc` network-probe spawn at the \
             two consumer sites (`verify_k8s_service`, `verify_external`). \
             Mirrors the sibling `<tool>_bin()` sigils across the CARGO / \
             NIX_BIN / DOCKER_BIN / BUN_BIN / CRATE2NIX / ATTIC_BIN / \
             FLUX_BIN surfaces."
        );

        let two_arg_needle = crate::test_support::get_tool_path_two_arg_call_needle("NC_BIN", "nc");
        let resolve_hits = crate::test_support::code_line_hits(body, &two_arg_needle);
        assert_eq!(
            resolve_hits.len(),
            1,
            "the canonical two-argument resolve `{two_arg_needle}` must \
             appear at exactly ONE code line in the module body (only in \
             the `nc_bin()` sigil), not {} — every consumer must route \
             through `nc_bin()`, not re-copy the resolve inline. A future \
             edit to the resolve contract (a substrate-path validation \
             step, a per-spawn env-injection hook, a telemetry sigil on \
             the resolved path) must land at the sigil body once, not at \
             each drifted call site. Found {} code-line hit(s): \
             {resolve_hits:#?}",
            resolve_hits.len(),
            resolve_hits.len()
        );
    }

    /// Regression-shield: `test` MUST route the SSH-probe spawn AND
    /// the nix-cross-build spawn through the canonical
    /// `crate::retry::run_capture_anyhow_sync` primitive rather than
    /// re-spell the pre-lift per-site
    /// `Command::new(bin).args(...)[.env(...)].output().context(
    /// "Failed to execute <op>")? + if !X.status.success() { let stderr
    /// = ...; bail!("<Op> failed: {}", stderr); }` six-line stanza that
    /// each site carried verbatim modulo the per-site bin / args /
    /// spawn-context / bail-message.
    ///
    /// Pre-lift each site's operator log line dropped the exit code:
    /// someone seeing `"SSH connection failed:"` on a Nix-hermetic
    /// runner had no way to tell whether ssh exited 255 (a real
    /// connection refusal), 127 (SSH_BIN wiring bug), or was killed by
    /// a signal (an OOM); someone seeing `"Remote build failed:"` on
    /// the sibling cross-build probe had no way to tell whether nix
    /// exited 1 (a real build error), 100 (nix-daemon evaluation
    /// failure), or 127 (NIX_BIN wiring bug). Post-lift the canonical
    /// `"ssh probe failed (exit {code}): {stderr}"` /
    /// `"nix cross-build failed (exit {code}): {stderr}"` envelope
    /// emerges by construction at
    /// `retry::classify_capture_anyhow` — same
    /// `(op, exit_code, stderr)` shape the sibling migrated sites
    /// (`commands/dashboards.rs`, `commands/sync.rs`,
    /// `commands/federation_tests.rs`, `commands/codegen.rs`) emit,
    /// so a future Phase 1 attestation-record consumer (THEORY §V.4)
    /// reading the terminating shape pattern-matches on ONE envelope
    /// across every captured-output bail in forge.
    ///
    /// # Scan bounds
    ///
    /// Bounded to the `test` function body — from
    /// `pub async fn test(` to the next top-level `async fn` marker
    /// (`async fn verify_k8s_service(`) — so:
    ///
    /// - The sibling `nc_check` bail paths at
    ///   `verify_k8s_service` (line 173-176 post-migration) and
    ///   `verify_external` (line 208-215 post-migration) — which
    ///   legitimately keep their custom
    ///   `"Service not accessible: {service}. Stderr: {stderr}"` /
    ///   `"Cannot connect to {hostname}:{port}. Stderr: {stderr}"`
    ///   shapes carrying per-call service/host/port context that
    ///   does NOT fit the primitive's
    ///   `(op, exit_code, stderr)`-only envelope — stay out of scope.
    /// - The migration-inline commentary above each migrated site
    ///   (which quotes the pre-lift bail literal for narrative
    ///   purposes) rides INSIDE the fn body, so the shield's
    ///   forbidden-literal check uses `code_line_hits` to filter
    ///   out `//` comment lines automatically — the same
    ///   anti-docstring-self-match discipline the sibling
    ///   `nc_bin` / `nix_bin` sigil shields above enforce.
    ///
    /// # What the shield pins
    ///
    /// - `bail!("SSH connection failed:` MUST NOT appear at a code
    ///   line in the `test` fn body.
    /// - `bail!("Remote build failed:` MUST NOT appear at a code line
    ///   in the `test` fn body.
    /// - `run_capture_anyhow_sync(` MUST appear at ≥2 code lines in
    ///   the `test` fn body (one per migrated site — SSH probe and
    ///   nix cross-build probe). A regression that dropped either
    ///   delegation would leave the forbidden-literal side satisfied
    ///   by absence; pinning a positive floor guards against that
    ///   regression class.
    #[test]
    fn test_test_fn_routes_ssh_and_nix_probes_through_run_capture_anyhow_sync_not_inline_bail() {
        const SOURCE: &str = include_str!("nix_builder.rs");
        let body = crate::test_support::fn_body_slice_between_markers(
            SOURCE,
            "commands/nix_builder.rs::test",
            "pub async fn test(",
            "\nasync fn verify_k8s_service(",
        );

        for forbidden in [
            "bail!(\"SSH connection failed:",
            "bail!(\"Remote build failed:",
        ] {
            let inline_hits = crate::test_support::code_line_hits(body, forbidden);
            assert!(
                inline_hits.is_empty(),
                "commands/nix_builder.rs::test must not carry an inline \
                 `{forbidden}...\")` terminator — the corresponding \
                 captured-output spawn must route through \
                 `crate::retry::run_capture_anyhow_sync`, which emits the \
                 canonical `\"{{op}} failed (exit {{code}}): {{stderr}}\"` \
                 envelope with the exit code carried. Found: \
                 {inline_hits:?}"
            );
        }

        let delegation = "run_capture_anyhow_sync(";
        let delegation_hits = crate::test_support::code_line_hits(body, delegation);
        assert!(
            delegation_hits.len() >= 2,
            "commands/nix_builder.rs::test must delegate BOTH the SSH \
             probe AND the nix cross-build probe through \
             `crate::retry::run_capture_anyhow_sync` — expected ≥2 \
             delegations at code lines in the fn body, found {}. A \
             regression that dropped one delegation AND accidentally \
             left the forbidden-literal shield satisfied (e.g. by \
             rewriting the bail into a `bail!(\"failed\")` shape \
             without the pre-lift colon suffix) fails here. Hits: \
             {delegation_hits:#?}",
            delegation_hits.len()
        );
    }
}
