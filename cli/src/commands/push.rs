use anyhow::{anyhow, Context, Result};
use std::process::Stdio;
use tokio::process::Command;
use tracing::info;

use crate::infrastructure::registry::{split_composed_registry_base, RegistryRef};
use crate::repo::get_tool_path;
use crate::retry::{retry_command_logged, RetryPolicy};
use crate::ui::styled_progress_bar;

/// Get git SHA for tagging - Single source of truth
///
/// Priority:
/// 1. RELEASE_GIT_SHA env var (set by Nix wrapper at release start)
/// 2. GIT_SHA env var (alternative)
/// 3. git rev-parse --short HEAD (fallback for direct CLI usage)
pub async fn get_git_sha() -> Result<String> {
    // Check for RELEASE_GIT_SHA environment variable first — routed
    // through the crate-scoped `crate::git::release_git_sha_from_env`
    // sigil so the empty-string-is-miss semantic (the Nix release
    // wrapper exports the var unconditionally with an empty value on
    // non-release invocations) lives at one point across the crate.
    // Sibling consumers: `commands/rust_service.rs::get_tag_suffix`
    // and `commands/product_release.rs::execute` (both route through
    // the same sigil).
    if let Some(sha) = crate::git::release_git_sha_from_env() {
        return Ok(sha);
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
    let path = crate::repo::require_existing_labeled(kustomization_path, "Kustomization file")?;

    info!("📝 Updating kustomization: {}", kustomization_path);

    // Read current content
    let content = crate::repo::read_text_async(path).await?;

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
    crate::repo::write_text_async(path, &updated_content).await?;

    info!("   ✅ Kustomization updated");

    // Commit and push if requested
    if commit {
        info!("📤 Committing and pushing kustomization changes...");

        // Git add — route through `retry::run_inherited_status` so non-zero
        // exits bail with the structural `(op, exit_code)` record. The bail
        // closes the chain at the staging boundary so a failed `git add`
        // cannot silently proceed to the `git commit` + `git push` steps
        // downstream against an unstaged kustomization.yaml.
        //
        // Binary resolution rides `crate::git::git_command_async()` so a
        // Nix-hermetic runner's `GIT_BIN` override wins over ambient `PATH`
        // — same discipline the sibling `commands/federation.rs` /
        // `commands/codegen_validation.rs` git-mutation sites honor and
        // the same class of bug the free-function-`git` / `GitClient`
        // migrations at 818ed9a / badcdf4 / 8653403 redeemed.
        crate::git::git_run_inherited_status(["add", kustomization_path], "git add")
            .await
            .context("Failed to stage kustomization.yaml")?;

        // Extract service name from path for commit message
        let service_name = path
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");

        // Git commit — routes through the idempotent-no-op peer of
        // `crate::git::git_run_inherited_status`: `git commit` with
        // nothing to commit returns non-zero, and the kustomization-
        // update path treats that as a benign no-op (re-run against an
        // already-updated file). The primitive body at
        // `crate::git::git_commit_idempotent` owns the spawn +
        // stdio-inherit + warn-on-non-zero shape at ONE code line
        // across the crate, so this consumer observes the same
        // warning envelope as the sibling
        // `commands/rollback.rs::execute` idempotent-commit call by
        // construction rather than by convention.
        let commit_msg = format!("deploy: update {} to {}", service_name, new_tag);
        crate::git::git_commit_idempotent(&commit_msg, "Failed to commit kustomization.yaml")
            .await?;

        // Git push — route through `retry::run_inherited_status` so a
        // denied push (auth, branch protection, conflict) bails loudly with
        // the structural record rather than silently returning Ok and
        // letting the caller proceed to "Kustomization committed and
        // pushed" against an unpushed branch.
        crate::git::git_run_inherited_status(["push", "origin", "main"], "git push")
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
    crate::ui::print_header("Push to Container Registry");

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

    push_tags_with_progress(&image_path, &registry, &tags, &ghcr_token, retries).await?;

    println!();
    crate::ui::print_success("Images pushed successfully!");
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

    /// Regression-shield: every `git`-spawning site in
    /// `commands/push.rs::update_kustomization` MUST resolve the binary
    /// through [`crate::git::git_command_async`] rather than the pre-lift
    /// `Command::new("git")` literal. Pre-migration three sites (add /
    /// commit / push at lines 166 / 186 / 203) bypassed the `GIT_BIN`
    /// env override the `tools::get_tool_path(tools::GIT)` idiom
    /// (cli/src/tools.rs:102-105) resolves — the same class of bug the
    /// sibling `flux` / `cargo` / `doca` / free-function-`git` /
    /// `GitClient` / `commands/federation.rs` migrations redeemed at
    /// 621f827 / f0dfa12 / d3dd199 / 685642f / d6f6bc7 / dd5a212 /
    /// 673e4be / b02d4eb / 54a9985 / 139b37a / 818ed9a / badcdf4 /
    /// 8653403.
    ///
    /// This test reads this module's own source via [`include_str!`] and
    /// asserts the raw `Command::new("git")` string does not reappear in
    /// `update_kustomization` while the delegation to `git_command_async`
    /// does. A future regression that re-fuses the raw-spawn body fails
    /// here, not silently in production where a Nix-hermetic runner's
    /// `GIT_BIN`-provided `git` would lose to whatever `git` is first on
    /// `PATH` at deploy time.
    ///
    /// The check is deliberately structural (substring on the source
    /// text) rather than behavioral — the end-to-end `GIT_BIN`-routing
    /// invariant is already pinned by
    /// [`crate::git::tests::test_git_command_async_routes_through_git_bin_env_var`]
    /// on the primitive itself; this shield only certifies that every
    /// `update_kustomization` git spawn reads through that primitive.
    /// Mirrors the sibling attic-scan shield above.
    #[test]
    fn test_update_kustomization_routes_git_through_git_command_async_not_raw_command() {
        const SOURCE: &str = include_str!("push.rs");

        // Bound the scan to `update_kustomization` — the three git spawn
        // sites all live inside it. The wrapping `execute(` and the tests
        // module below reference the pre-migration string legitimately;
        // the docstring on this test itself does too.
        // Bound the fn body between `update_kustomization`'s header and
        // the next top-level `pub async fn` (`execute`), so docstrings
        // and the tests module below reference the pre-migration string
        // legitimately outside this scope.
        let fn_body = crate::test_support::fn_body_slice_between_markers(
            SOURCE,
            "push.rs",
            "pub async fn update_kustomization(",
            "\npub async fn execute(",
        );

        assert!(
            !fn_body.contains("Command::new(\"git\")"),
            "update_kustomization() must NOT spawn `git` directly — route \
             through `crate::git::git_run_inherited_status(&[...], \
             \"git …\")` (the async bail-on-non-zero fusion primitive), \
             `crate::git::git_commit_idempotent(&msg, ctx)` (the async \
             warn-on-non-zero idempotent-`git commit` peer), or \
             `crate::git::git_command_async()` so `GIT_BIN` overrides land \
             at the shared primitive. Found the pre-migration spawn body \
             in update_kustomization()."
        );
        assert!(
            fn_body.contains("crate::git::git_run_inherited_status(")
                || fn_body.contains("crate::git::git_commit_idempotent(")
                || fn_body.contains("crate::git::git_command_async()"),
            "update_kustomization() must delegate every git spawn to \
             `crate::git::git_run_inherited_status(&[...], \"git …\")` \
             (the async bail-on-non-zero fusion primitive, which \
             internally routes through `git_command_async()` + \
             `run_inherited_status`), to `crate::git::git_commit_idempotent(\
             &msg, ctx)` (the async warn-on-non-zero peer for the \
             documented idempotent-no-op `git commit` carve-out, which \
             also routes through `git_command_async()`), OR to \
             `crate::git::git_command_async()` directly for any other \
             specialized shape — no delegation string was found in \
             update_kustomization()."
        );
    }

    /// Regression shield: `commands/push.rs::get_git_sha` must resolve
    /// the `RELEASE_GIT_SHA` env-var branch via
    /// [`crate::git::release_git_sha_from_env`] rather than by
    /// hand-spelling `env::var("RELEASE_GIT_SHA")` + the
    /// `!sha.is_empty()` empty-check inline. Pre-lift this file and
    /// `commands/rust_service.rs::get_tag_suffix` and
    /// `commands/product_release.rs::execute` each carried a
    /// byte-equivalent inline stanza; three consumers past THEORY
    /// §VI.1's three-is-a-law threshold — the trio had to agree on
    /// both the env-var spelling AND the empty-string-is-miss
    /// semantic for the pushed image tag, the deployed image tag,
    /// and the product-release-driven downstream tags to all resolve
    /// to the SAME code-commit SHA. A drift at one site (a typo
    /// `RELEASE_SHA`, or the empty-check accidentally deleted so
    /// `Ok("")` — the shape the Nix release wrapper exports on
    /// non-release invocations — leaks through as a valid SHA) would
    /// silently render `amd64-` image tags (bare arch suffix, no
    /// SHA) at this one consumer only, clobbering the `amd64-latest`
    /// moving tag on every direct-CLI push while the other two
    /// consumers stayed on the pre-lift shape.
    ///
    /// Structural, not behavioral — the end-to-end env-var read
    /// semantics are pinned by
    /// [`crate::git::tests::test_release_git_sha_from_env_none_when_unset`]
    /// / `_none_when_empty` / `_some_when_set` on the sigil itself;
    /// this shield only certifies that `get_git_sha()` reads through
    /// the sigil, not through a re-copied inline stanza.
    #[test]
    fn test_get_git_sha_routes_release_git_sha_through_sigil_not_inline_env_var() {
        const SOURCE: &str = include_str!("push.rs");

        let fn_body = crate::test_support::fn_body_slice_between_markers(
            SOURCE,
            "commands/push.rs",
            "pub async fn get_git_sha(",
            "\npub async fn generate_auto_tags(",
        );

        assert!(
            !fn_body.contains("env::var(\"RELEASE_GIT_SHA\")"),
            "get_git_sha() must NOT read `RELEASE_GIT_SHA` inline — \
             route through `crate::git::release_git_sha_from_env()` \
             so the env-var-spelling AND the empty-string-is-miss \
             contract are honored at exactly ONE code line across \
             the crate. Found the pre-lift inline \
             `env::var(\"RELEASE_GIT_SHA\")` read in get_git_sha()."
        );
        assert!(
            fn_body.contains("crate::git::release_git_sha_from_env()"),
            "get_git_sha() must resolve the release SHA via \
             `crate::git::release_git_sha_from_env()` — the sigil \
             call was not found in get_git_sha()."
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

    // doca wants --registry/--image separately where skopeo took one composed
    // reference. `split_composed_registry_base` names the doca-side first-'/'
    // cut at ONE code line across the crate — a base with none is REFUSED
    // rather than guessed at (a wrong split pushes to a different repository
    // than intended, and the push then silently reports success).
    let (host, image) = split_composed_registry_base(registry)?;
    let host = host.to_string();
    let image = image.to_string();

    let result = retry_command_logged(&policy, &op, |_attempt| {
        let organization = organization.clone();
        let host = host.clone();
        let image = image.clone();
        async move {
            let doca = get_tool_path("DOCA_BIN", "oci-push");
            // ── CREDENTIALS BY ENV, NEVER ARGV. ─────────────────────────────
            // `--dest-creds=<org>:<token>` put the token in /proc/<pid>/cmdline,
            // world-readable on a shared runner for the life of the push.
            //
            // `--retry-times` dropped deliberately: it was a second retry loop
            // nested inside retry_command above, and doca's push_with_retry
            // already backs off exponentially while telling transient failures
            // apart from permanent ones (a 401 does not burn the budget).
            Command::new(&doca)
                .args([
                    "push",
                    "--tarball",
                    image_path,
                    "--registry",
                    &host,
                    "--image",
                    &image,
                    "--tag",
                    tag,
                ])
                .env("INPUT_DEST_USER", &organization)
                .env("INPUT_DEST_PASS", token)
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .output()
                .await
        }
    })
    .await;

    result.map(|_| ()).map_err(|e| anyhow::anyhow!("{}", e))
}

/// Push every tag of an image to a registry, streaming per-tag progress
/// on a determinate [`styled_progress_bar`].
///
/// Three sibling call sites — `commands/push.rs::execute`,
/// `commands/pangea.rs::push_single`, `commands/bootstrap.rs::push_image`
/// — carried this loop-shape verbatim: build the bar, `set_message` a
/// per-tag `"Pushing {registry}:{tag}"` label, invoke
/// [`push_with_retry`], increment the bar, then close with a
/// `"Push complete"` `finish_with_message`. Three identically-shaped
/// bodies past THEORY §VI.1's three-is-a-law threshold — the visual
/// contract for the tag-push loop (label spelling, completion phrasing,
/// bar-increment vs. failure interleave) now attaches to a type at ONE
/// code line. A future consumer that pushes a `&[String]` of tags to a
/// registry through [`push_with_retry`] imports this primitive rather
/// than re-copying the four-line block; a change to the per-tag label
/// or the completion message touches one line, not three.
///
/// Sibling to [`crate::ui::styled_progress_bar`] (the determinate-bar
/// primitive itself, lifted at 859c009) — this fuses the bar with the
/// per-tag body it wraps every real consumer of the bar drove verbatim.
pub async fn push_tags_with_progress(
    image_path: &str,
    registry: &str,
    tags: &[String],
    ghcr_token: &str,
    retries: u32,
) -> Result<()> {
    let pb = styled_progress_bar(tags.len() as u64);
    for tag in tags {
        pb.set_message(format!("Pushing {}:{}", registry, tag));
        push_with_retry(image_path, registry, tag, ghcr_token, retries).await?;
        pb.inc(1);
    }
    pb.finish_with_message("Push complete");
    Ok(())
}

#[cfg(test)]
mod push_tags_with_progress_tests {
    use super::push_tags_with_progress;

    /// `push_tags_with_progress` on an empty tag slice returns `Ok(())`
    /// without spawning `doca` — the loop body is skipped, so the
    /// primitive's structural invariants (bar construction, completion
    /// message dispatch) are exercised in isolation from the network-
    /// spawning inner body. Fail-before-pass semantics: if the
    /// primitive returns `Err(_)` on an empty slice (e.g. a future edit
    /// pushes a `assert!(!tags.is_empty())` inside the body), this test
    /// catches the regression before any consumer wire.
    #[tokio::test]
    async fn empty_tags_returns_ok_without_spawning() {
        let out = push_tags_with_progress("nowhere", "example.invalid/img", &[], "token", 0).await;
        assert!(
            out.is_ok(),
            "push_tags_with_progress must return Ok(()) on an empty \
             tag slice (loop body skipped, no `doca` spawn) — got {out:?}"
        );
    }

    /// Regression shield: each of the three pre-lift sibling call sites
    /// (`commands/{push,pangea,bootstrap}.rs`) must route the tag-push
    /// loop through `push_tags_with_progress` rather than re-inline the
    /// four-line `styled_progress_bar + for tag + set_message +
    /// push_with_retry + inc + finish_with_message` block. The check is
    /// structural (substring on the source text via `include_str!`,
    /// bounded to each consumer fn via
    /// [`crate::test_support::fn_body_slice_between_markers`] so the
    /// primitive-definition body and unrelated fn bodies do not mask a
    /// regression) — a future regression that re-fuses one of the
    /// inline bodies fails here, not silently in production where a
    /// drift on the per-tag label spelling or the completion message
    /// would leak through at one site while the other two stayed on
    /// the primitive.
    #[test]
    fn every_pre_lift_sibling_call_site_routes_through_push_tags_with_progress() {
        for (module_path, source, open_marker, end_marker) in [
            (
                "commands/push.rs",
                include_str!("push.rs"),
                "pub async fn execute(",
                "\n#[cfg(test)]",
            ),
            (
                "commands/pangea.rs",
                include_str!("pangea.rs"),
                "pub async fn push_single(",
                "\npub async fn push_all(",
            ),
            (
                "commands/bootstrap.rs",
                include_str!("bootstrap.rs"),
                "pub async fn push_single(",
                "\npub async fn push_all(",
            ),
        ] {
            let fn_body = crate::test_support::fn_body_slice_between_markers(
                source,
                module_path,
                open_marker,
                end_marker,
            );
            assert!(
                fn_body.contains("push_tags_with_progress(&image_path,"),
                "{module_path}::{open_marker} must delegate its tag-push \
                 loop to `push_tags_with_progress(&image_path, &registry, \
                 &tags, &ghcr_token, retries)` — the call string was \
                 not found in the fn body."
            );
            assert!(
                !fn_body.contains("pb.set_message(format!(\"Pushing "),
                "{module_path}::{open_marker} must NOT re-inline the \
                 pre-lift `pb.set_message(format!(\"Pushing …\", …))` \
                 tag-push loop body — route through \
                 `push_tags_with_progress(...)` so the visual contract \
                 lives at ONE code line. Found the pre-lift inline body \
                 in the fn."
            );
        }
    }
}
