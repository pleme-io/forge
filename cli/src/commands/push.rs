use anyhow::{anyhow, Context, Result};
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use std::path::Path;
use std::process::Stdio;
use tokio::process::Command;
use tracing::{info, warn};

use crate::infrastructure::registry::RegistryRef;
use crate::repo::get_tool_path;
use crate::retry::{log_retry_attempt, retry_command, RetryPolicy};

/// Get git SHA for tagging - Single source of truth
///
/// Priority:
/// 1. RELEASE_GIT_SHA env var (set by Nix wrapper at release start)
/// 2. GIT_SHA env var (alternative)
/// 3. git rev-parse --short HEAD (fallback for direct CLI usage)
pub async fn get_git_sha() -> Result<String> {
    // Check for RELEASE_GIT_SHA environment variable first
    if let Ok(sha) = std::env::var("RELEASE_GIT_SHA") {
        if !sha.is_empty() {
            return Ok(sha);
        }
    }

    // Check for GIT_SHA environment variable
    if let Ok(sha) = std::env::var("GIT_SHA") {
        if !sha.is_empty() {
            return Ok(sha);
        }
    }

    // Fallback to git rev-parse for direct CLI usage — routed through
    // the canonical async sibling of `git::get_short_sha`. Spawn-vs-op
    // dispatch flows through the typed `GitError` producer; the
    // structural `(op, exit_code, stderr)` failure tuple is preserved
    // for the anyhow boundary while the user-facing advisory ("ensure
    // you're in a git repository with committed changes") stays in the
    // wrapping `.context(...)` envelope.
    let hash = crate::git::get_short_sha_async().await.context(
        "Failed to get git SHA for image tagging. \
         Ensure you're in a git repository with committed changes.",
    )?;
    if hash.is_empty() {
        anyhow::bail!("Git returned empty SHA - repository may be corrupted");
    }
    Ok(hash)
}

/// Generate architecture-prefixed tags
///
/// Returns tags like ["amd64-abc1234", "amd64-latest"] for the given architecture
pub async fn generate_auto_tags(arch: &str) -> Result<Vec<String>> {
    let sha = get_git_sha().await?;
    Ok(vec![
        format!("{}-{}", arch, sha),
        format!("{}-latest", arch),
    ])
}

/// Discover GHCR token from various sources
///
/// Delegates to the canonical RegistryCredentials::discover_token().
/// Priority: provided token → GHCR_TOKEN → GITHUB_TOKEN → gh CLI → kubectl secret
pub fn discover_ghcr_token(token: Option<String>) -> Result<String> {
    crate::infrastructure::registry::RegistryCredentials::discover_token(token)
        .map_err(|e| anyhow::anyhow!("{}", e))
}

/// Update kustomization.yaml with new image tag
///
/// Finds the image entry matching the registry and updates its newTag field.
/// Optionally commits and pushes the change to git.
pub async fn update_kustomization(
    kustomization_path: &str,
    registry: &str,
    new_tag: &str,
    commit: bool,
) -> Result<()> {
    let path = Path::new(kustomization_path);
    if !path.exists() {
        anyhow::bail!("Kustomization file not found: {}", kustomization_path);
    }

    info!("📝 Updating kustomization: {}", kustomization_path);

    // Read current content
    let content = tokio::fs::read_to_string(path)
        .await
        .context("Failed to read kustomization.yaml")?;

    // Extract service name from registry for matching (last path component).
    // Falls back to the raw input only when the registry string has no
    // recognizable structure — RegistryRef rejects malformed input.
    let parsed_registry = RegistryRef::parse(registry).ok();
    let service_match = parsed_registry
        .as_ref()
        .map_or(registry, RegistryRef::image_name);

    // Use targeted text replacement instead of serde_yaml round-trip.
    // Round-tripping through serde_yaml destroys comments, reformats
    // multi-line strings (patch: | blocks), and can corrupt the file.
    let lines: Vec<&str> = content.lines().collect();
    let mut result = Vec::with_capacity(lines.len());
    let mut updated = false;
    let mut matched_name = false;

    for line in &lines {
        if matched_name {
            let trimmed = line.trim();
            if trimmed.starts_with("newTag:") {
                let old_tag = trimmed.trim_start_matches("newTag:").trim();
                info!(
                    "   Updating {} from {} to {}",
                    service_match, old_tag, new_tag
                );
                let indent = &line[..line.len() - line.trim_start().len()];
                result.push(format!("{}newTag: {}", indent, new_tag));
                updated = true;
                matched_name = false;
                continue;
            }
            if !trimmed.is_empty() && !trimmed.starts_with('#') {
                matched_name = false;
            }
        }

        let trimmed = line.trim();
        if trimmed.starts_with("- name:") {
            let name_value = trimmed.trim_start_matches("- name:").trim();
            if registry.contains(name_value) || name_value.contains(service_match) {
                matched_name = true;
            }
        }

        result.push(line.to_string());
    }

    if !updated {
        anyhow::bail!(
            "No matching image found in kustomization.yaml for registry: {}",
            registry
        );
    }

    let mut updated_content = result.join("\n");
    if content.ends_with('\n') {
        updated_content.push('\n');
    }
    tokio::fs::write(path, &updated_content)
        .await
        .context("Failed to write kustomization.yaml")?;

    info!("   ✅ Kustomization updated");

    // Commit and push if requested
    if commit {
        info!("📤 Committing and pushing kustomization changes...");

        // Git add — route through `retry::run_inherited_status` so non-zero
        // exits bail with the structural `(op, exit_code)` record. The bail
        // closes the chain at the staging boundary so a failed `git add`
        // cannot silently proceed to the `git commit` + `git push` steps
        // downstream against an unstaged kustomization.yaml.
        let mut add_cmd = Command::new("git");
        add_cmd.args(["add", kustomization_path]);
        crate::retry::run_inherited_status(add_cmd, "git add")
            .await
            .context("Failed to stage kustomization.yaml")?;

        // Extract service name from path for commit message
        let service_name = path
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");

        // Git commit. Intentionally retains the bare `.status()` + warn-on-
        // non-zero shape: `git commit` with nothing to commit returns
        // non-zero, and the kustomization-update path treats that as a
        // benign no-op (re-run against an already-updated file). Migrating
        // this site to `run_inherited_status` would change semantics — it
        // would bail, breaking idempotent re-runs.
        let commit_msg = format!("deploy: update {} to {}", service_name, new_tag);
        let commit_status = Command::new("git")
            .args(&["commit", "-m", &commit_msg])
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .await
            .context("Failed to commit kustomization.yaml")?;

        if !commit_status.success() {
            warn!("Git commit returned non-zero (may be no changes)");
        }

        // Git push — route through `retry::run_inherited_status` so a
        // denied push (auth, branch protection, conflict) bails loudly with
        // the structural record rather than silently returning Ok and
        // letting the caller proceed to "Kustomization committed and
        // pushed" against an unpushed branch.
        let mut push_cmd = Command::new("git");
        push_cmd.args(["push", "origin", "main"]);
        crate::retry::run_inherited_status(push_cmd, "git push")
            .await
            .context("Failed to push kustomization changes to git")?;

        info!("   ✅ Kustomization committed and pushed");
    }

    Ok(())
}

pub async fn execute(
    image_path: String,
    registry: String,
    mut tags: Vec<String>,
    auto_tags: bool,
    arch: String,
    retries: u32,
    token: Option<String>,
    push_attic: bool,
    attic_cache: String,
    update_kustomization_path: Option<String>,
    commit_kustomization: bool,
) -> Result<()> {
    println!();
    println!(
        "{}",
        "╔════════════════════════════════════════════════════════════╗".bright_blue()
    );
    println!(
        "{}",
        "║  Push to Container Registry                                ║".bright_blue()
    );
    println!(
        "{}",
        "╚════════════════════════════════════════════════════════════╝".bright_blue()
    );
    println!();

    // Check if build result exists
    if !tokio::fs::try_exists(&image_path).await.unwrap_or(false) {
        anyhow::bail!(
            "Build result not found at '{}'. Run 'forge build' first.",
            image_path
        );
    }

    // If auto_tags is enabled, generate architecture-prefixed tags
    if auto_tags {
        let generated_tags = generate_auto_tags(&arch).await?;
        info!("🔧 Auto-generating tags for {}: {:?}", arch, generated_tags);
        tags.extend(generated_tags);
    }

    // Get GHCR token
    let ghcr_token = discover_ghcr_token(token)?;

    if tags.is_empty() {
        anyhow::bail!("At least one tag must be specified with --tag or use --auto-tags");
    }

    info!("🎯 Target: {}", registry);
    info!("📦 Image path: {}", image_path);
    info!("🏷️  Tags: {}", tags.join(", "));
    println!();

    // Push to Attic cache first (if requested). Routes through
    // [`crate::infrastructure::attic::AtticClient::push_optional`] so
    // three load-bearing properties this site previously bypassed land
    // at ONE call:
    //   1. `ATTIC_BIN` env override — the pre-migration raw-spawn body
    //      here ignored the env var every other attic-push site in the
    //      workspace honors via `get_tool_path("ATTIC_BIN", "attic")`
    //      (`infrastructure/attic.rs::resolve_attic_bin`).
    //   2. Retry-policy semantics — a transient network failure (HTTP
    //      5xx from the attic backend, mid-stream EOF, connection
    //      refused) dropped straight into the `warn!` non-fatal arm on
    //      attempt 1; the typed primitive drives the canonical
    //      `RetryPolicy::network` schedule (250ms × factor=2 capped at
    //      30s) via `retry_command` so transient failures retry before
    //      being classified non-fatal.
    //   3. Typed-error dispatch — a spawn failure vs. a non-zero exit
    //      landed as an untyped `Result<ExitStatus>` here; the primitive
    //      routes through `classify_attic_push_failure` to the
    //      `AtticError::ExecFailed` / `AtticError::PushFailed` split.
    // The `warn!` on failure lives inside `push_optional` itself, so
    // the non-fatal-on-failure contract this site had is preserved by
    // construction. Sibling of the `commands/build.rs::execute` and
    // `commands/rust_service.rs::push_rust_service` migrations that
    // already routed their attic-push bodies through the primitive.
    // The regression-shield
    // `tests::test_execute_routes_attic_push_through_attic_client_not_raw_command`
    // pins the delegation structurally against a future re-fusion.
    if push_attic {
        info!("📤 Pushing to Attic cache...");
        let _ok = crate::infrastructure::attic::AtticClient::discover(attic_cache.clone())
            .push_optional(&image_path)
            .await;
        println!();
    }

    // Push with skopeo (with retries)
    info!("📤 Pushing to container registry with skopeo...");
    info!("   Retries: {} attempts per tag", retries);
    println!();

    let pb = ProgressBar::new(tags.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} {msg}")
            .unwrap()
            .progress_chars("#>-"),
    );

    // Push all tags
    for tag in &tags {
        pb.set_message(format!("Pushing {}:{}", registry, tag));

        push_with_retry(&image_path, &registry, tag, &ghcr_token, retries).await?;

        pb.inc(1);
    }

    pb.finish_with_message("Push complete");

    println!();
    println!("{}", "✅ Images pushed successfully!".bright_green().bold());
    for tag in &tags {
        println!("   • {}:{}", registry, tag);
    }
    println!();

    // Update kustomization.yaml if requested
    if let Some(kustomization_path) = update_kustomization_path {
        // Use the first tag (typically the git SHA tag) for kustomization
        let tag_for_kustomization = tags
            .first()
            .ok_or_else(|| anyhow!("No tags available for kustomization update"))?;

        update_kustomization(
            &kustomization_path,
            &registry,
            tag_for_kustomization,
            commit_kustomization,
        )
        .await?;
    }

    Ok(())
}

/// Push a single image to GHCR with retries using skopeo.
///
/// Drives [`crate::retry::retry_command`] with a network-shaped policy
/// (5 attempts × 250ms × factor=2 capped at 30s) — the canonical
/// frontier shape — which composes the canonical
/// `is_transient_network_stderr` classifier with the canonical
/// `CommandAttemptFailure::from_capture` mapping in one primitive.
/// Pre-migration this site (and two siblings in
/// `commands/github_runner_ci.rs`) carried the
/// `run_with_policy + classifier + from_capture` triple verbatim —
/// three identically-shaped bodies past the three-times threshold
/// (THEORY §VI.1). The `retries` parameter is preserved as skopeo's
/// internal `--retry-times` (per-blob retry inside skopeo); the OUTER
/// loop is bounded by the typed policy.
#[cfg(test)]
mod tests {
    /// Regression-shield: `commands/push.rs::execute` must route its
    /// Attic-cache push through
    /// [`crate::infrastructure::attic::AtticClient`] rather than spawning
    /// `attic` directly. Pre-migration a raw
    /// `Command::new("attic").args(["push", cache, path]).status()` body
    /// lived at this call site and bypassed three load-bearing properties
    /// the typed primitive carries: the `ATTIC_BIN` env override every
    /// other attic-invocation site honors via
    /// `get_tool_path("ATTIC_BIN", "attic")`, the
    /// [`crate::retry::RetryPolicy::network`] retry schedule (250ms ×
    /// factor=2 capped at 30s) that turns a transient HTTP 5xx from the
    /// attic backend into a retry instead of an immediate non-fatal
    /// warn, and the typed [`crate::error::AtticError`] dispatch
    /// (`ExecFailed` vs `PushFailed`) the untyped `Result<ExitStatus>`
    /// collapsed away.
    ///
    /// This test reads this module's own source via [`include_str!`] and
    /// asserts the raw `Command::new("attic")` string does not reappear
    /// while the delegation to `AtticClient` does. A future regression
    /// that re-fuses the raw-spawn body fails here, not silently in
    /// production where a bypassed `ATTIC_BIN` override or dropped
    /// retry-policy wrapping would surface only as a mysterious "attic
    /// not found" or "cache push failed on the first try" report from
    /// the field.
    ///
    /// The check is deliberately structural (substring on the source
    /// text) rather than behavioral — a behavioral test would require
    /// wiring up the full `execute` flow with mocked registry / attic /
    /// filesystem surfaces, which is disproportionate to the invariant
    /// being pinned. The regression-shield discipline mirrors the
    /// `#![deny(unused_mut)]` and `#![deny(clippy::field_reassign_with_default)]`
    /// crate-root lints main.rs installs to turn "achievement reached
    /// fleet-wide" invariants into hard failures.
    #[test]
    fn test_execute_routes_attic_push_through_attic_client_not_raw_command() {
        const SOURCE: &str = include_str!("push.rs");

        // Locate the `execute` function body. The regression-shield only
        // cares about code inside `execute`, not about the docstring/test
        // module which legitimately references the pre-migration string
        // for context.
        let execute_marker = "pub async fn execute(";
        let start = SOURCE
            .find(execute_marker)
            .expect("push.rs must contain `pub async fn execute(` — module invariant");
        let after_execute = &SOURCE[start..];
        // Bound the search at the tests module marker so the docstring
        // in THIS test — which legitimately spells the pre-migration
        // `Command::new("attic")` string for context — is excluded from
        // the scan. Every real code site sits strictly between the
        // `execute(` marker and the `#[cfg(test)]` marker in this file.
        let end_relative = after_execute
            .find("\n#[cfg(test)]")
            .expect("push.rs must contain `#[cfg(test)]` tests module — this module's own marker");
        let execute_body = &after_execute[..end_relative];

        assert!(
            !execute_body.contains("Command::new(\"attic\")"),
            "execute() must NOT spawn `attic` directly — route through \
             `crate::infrastructure::attic::AtticClient::discover(...)\
             .push_optional(...)` so `ATTIC_BIN` overrides, the network \
             retry policy, and the typed `AtticError` dispatch all land \
             at the shared primitive. Found the pre-migration spawn body \
             in execute()."
        );
        assert!(
            execute_body.contains("AtticClient::discover"),
            "execute() must delegate the attic push to \
             `AtticClient::discover(...).push_optional(...)` — the \
             delegation string was not found in execute()."
        );
        assert!(
            execute_body.contains("push_optional"),
            "execute() must call `push_optional(...)` to preserve the \
             non-fatal-on-failure contract while inheriting the retry \
             policy, env resolution, and typed error dispatch — the \
             call string was not found in execute()."
        );
    }
}

pub async fn push_with_retry(
    image_path: &str,
    registry: &str,
    tag: &str,
    token: &str,
    retries: u32,
) -> Result<()> {
    let organization = RegistryRef::parse(registry)
        .with_context(|| format!("Invalid registry URL: {registry}"))?
        .organization()
        .to_string();

    let policy = RetryPolicy::network();
    let op = format!("push {}:{}", registry, tag);

    let result = retry_command(&policy, &op, |attempt| {
        let organization = organization.clone();
        let op = op.clone();
        let policy = policy.clone();
        async move {
            let skopeo = get_tool_path("SKOPEO_BIN", "skopeo");
            let outcome = Command::new(&skopeo)
                .args([
                    "copy",
                    "--insecure-policy",
                    &format!("--retry-times={}", retries),
                    &format!("--dest-creds={}:{}", organization, token),
                    &format!("docker-archive:{}", image_path),
                    &format!("docker://{}:{}", registry, tag),
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .output()
                .await;
            log_retry_attempt(outcome, &op, attempt, &policy)
        }
    })
    .await;

    result.map(|_| ()).map_err(|e| anyhow::anyhow!("{}", e))
}
