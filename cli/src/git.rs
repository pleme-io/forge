use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::error::GitError;
use crate::retry::classify_capture;
use crate::tools::{get_tool_path, tools};

/// Run `git <args>` (resolved against `workdir` if any) and return its
/// captured stdout, or a typed `GitError`. Production entrypoint —
/// resolves the `git` binary once through
/// [`crate::tools::get_tool_path`] so every consumer honors the
/// `GIT_BIN` env override the tools-registry idiom names as the
/// hermetic-runner contract for [`tools::GIT`], then delegates the
/// spawn-plus-classify to [`git_capture_with_bin`]. Same production /
/// test split as `flux_reconcile::reconcile_kustomization` +
/// `reconcile_kustomization_with_bin`,
/// `graphql_schema::extract_graphql_schema` +
/// `extract_graphql_schema_with_bin`, and `nix::run_nix_build_typed` +
/// `run_nix_build_typed_with_bin` — production reads through
/// `get_tool_path`, tests point at an absolute-path shim without
/// racing on the process-wide env var.
///
/// # `GIT_BIN` env override
///
/// The `git` binary resolves via `tools::get_tool_path(tools::GIT)` —
/// same discipline every Nix-derivation-provided tool in forge honors.
/// Pre-this-lift every production call site here spelled the literal
/// `"git"` as the first argument to `git_capture`, ignoring the env
/// var the `tools::get_tool_path("git")` idiom (§tools.rs) resolves. A
/// Nix-hermetic runner with a store-path `git` would fall through to
/// whatever `git` was first on `PATH` — the exact class of bug the
/// `CARGO`-bypass at the pre-lift extract-schema sites carried
/// (redeemed at 673e4be / b02d4eb / 54a9985), the `FLUX`-bypass at
/// the pre-lift `flux reconcile` sites carried (redeemed at
/// f0dfa12 / 621f827 / d3dd199), and the `FLUX`-bypass at the
/// pre-lift `flux get` sites carried (redeemed at 685642f / d6f6bc7 /
/// dd5a212).
fn git_capture(args: &[&str], workdir: Option<&Path>, op: &str) -> Result<Vec<u8>, GitError> {
    git_capture_with_bin(&get_tool_path(tools::GIT), args, workdir, op)
}

/// Test-injection sibling of [`git_capture`]: accepts the resolved
/// `bin` as an explicit argument so unit tests can point at a
/// hermetic shim without mutating the process-wide `GIT_BIN` env var
/// — same discipline as `flux_reconcile::reconcile_kustomization_with_bin`,
/// `graphql_schema::extract_graphql_schema_with_bin`, and
/// `AtticClient::with_attic_bin`. Splitting the resolution from the
/// execution keeps the test surface hermetic AND parallel-safe:
/// `#[test]` on this module can run concurrent tests without racing on
/// env-var writes.
///
/// `op` is the human-readable label attached to any returned error and
/// is what discriminates "git couldn't spawn" (`GitError::ExecFailed`)
/// from "git ran but exited non-zero" (`GitError::OpFailed`).
///
/// Spawn-vs-op dispatch flows through the canonical
/// [`GitError::from_capture`] primitive: spawn failures
/// (`Err(io::Error)` — git not on PATH) route to `GitError::ExecFailed`;
/// non-zero exits route to `GitError::OpFailed` carrying the structural
/// `(exit_code, stderr)` tuple [`crate::retry::CapturedFailure`]
/// extracts. The mapper-pair this site previously inlined now lives
/// once on `GitError::from_capture` alongside the async predicate
/// sites (`infrastructure/git.rs::GitClient::is_clean`,
/// `GitClient::has_staged_changes`) that carried the verbatim same
/// shape.
fn git_capture_with_bin(
    bin: &str,
    args: &[&str],
    workdir: Option<&Path>,
    op: &str,
) -> Result<Vec<u8>, GitError> {
    let mut cmd = Command::new(bin);
    cmd.args(args);
    if let Some(w) = workdir {
        cmd.current_dir(w);
    }
    let output = GitError::from_capture(cmd.output(), op)?;
    Ok(output.stdout)
}

/// Run a git operation against a specific (remote, branch) endpoint —
/// `git push origin <branch>`, `git pull origin <branch>` — and surface
/// failures as `GitError::RemoteOpFailed` so callers can recover the
/// exact endpoint from the typed record without parsing the bail!
/// string. Mirror of [`git_capture`] for the network half of the
/// surface: production entrypoint that resolves the `git` binary
/// through [`crate::tools::get_tool_path`] once so every network op
/// honors the `GIT_BIN` env override, then delegates to
/// [`git_capture_remote_with_bin`].
fn git_capture_remote(
    args: &[&str],
    workdir: Option<&Path>,
    op: &str,
    remote: &str,
    branch: &str,
) -> Result<Vec<u8>, GitError> {
    git_capture_remote_with_bin(
        &get_tool_path(tools::GIT),
        args,
        workdir,
        op,
        remote,
        branch,
    )
}

/// Test-injection sibling of [`git_capture_remote`]: accepts the
/// resolved `bin` as an explicit argument for the same reasons
/// [`git_capture_with_bin`] does.
///
/// Spawn-vs-op dispatch flows through the canonical
/// [`crate::retry::classify_capture`] primitive — same shape as
/// [`git_capture_with_bin`], with the op-failure arm producing
/// `GitError::RemoteOpFailed` (carrying `(remote, branch, exit_code,
/// stderr)`) instead of `GitError::OpFailed`.
fn git_capture_remote_with_bin(
    bin: &str,
    args: &[&str],
    workdir: Option<&Path>,
    op: &str,
    remote: &str,
    branch: &str,
) -> Result<Vec<u8>, GitError> {
    let mut cmd = Command::new(bin);
    cmd.args(args);
    if let Some(w) = workdir {
        cmd.current_dir(w);
    }
    let output = classify_capture(
        cmd.output(),
        |e| GitError::ExecFailed {
            op: op.to_string(),
            message: e.to_string(),
        },
        |cf| GitError::RemoteOpFailed {
            op: op.to_string(),
            remote: remote.to_string(),
            branch: branch.to_string(),
            exit_code: cf.exit_code,
            stderr: cf.stderr,
        },
    )?;
    Ok(output.stdout)
}

fn stdout_string(bytes: Vec<u8>) -> Result<String> {
    Ok(String::from_utf8(bytes)
        .context("Git output is not valid UTF-8")?
        .trim()
        .to_string())
}

/// Get the root directory of the git repository
///
/// Root flake pattern (ONLY supported pattern):
/// Tries REPO_ROOT environment variable first (set by CLI --repo-root parameter),
/// then falls back to calling `git rev-parse --show-toplevel`.
///
/// This consolidated logic prevents duplicate implementations across commands.
pub fn get_repo_root() -> Result<PathBuf> {
    // Try environment variable first (for CLI --repo-root parameter)
    if let Ok(repo_root) = std::env::var("REPO_ROOT") {
        return Ok(PathBuf::from(repo_root));
    }

    // Fall back to git command
    let stdout = git_capture(&["rev-parse", "--show-toplevel"], None, "rev-parse")?;
    Ok(PathBuf::from(stdout_string(stdout)?))
}

/// Get full git SHA (40 characters)
pub fn get_full_sha() -> Result<String> {
    let stdout = git_capture(&["rev-parse", "HEAD"], None, "rev-parse")?;
    stdout_string(stdout)
}

/// Get short git SHA (7 characters)
pub fn get_short_sha() -> Result<String> {
    let stdout = git_capture(&["rev-parse", "--short=7", "HEAD"], None, "rev-parse")?;
    stdout_string(stdout)
}

/// Async sibling of [`git_capture`] — same `(args, workdir, op)`
/// shape, but spawns through [`tokio::process::Command`] so it composes
/// with `async fn` callers without a `block_on` bridge. Production
/// entrypoint that resolves the `git` binary through
/// [`crate::tools::get_tool_path`] once so every async caller honors
/// the `GIT_BIN` env override, then delegates to
/// [`git_capture_async_with_bin`].
async fn git_capture_async(
    args: &[&str],
    workdir: Option<&Path>,
    op: &str,
) -> Result<Vec<u8>, GitError> {
    git_capture_async_with_bin(&get_tool_path(tools::GIT), args, workdir, op).await
}

/// Test-injection sibling of [`git_capture_async`]: accepts the
/// resolved `bin` as an explicit argument for the same reasons
/// [`git_capture_with_bin`] does. Routes through the same
/// [`GitError::from_capture`] typed-error producer the sync sibling
/// uses, so spawn-vs-op dispatch and the
/// `(op, exit_code, stderr)` failure tuple
/// [`crate::retry::CapturedFailure`] extracts at the sync surface are
/// preserved by construction on the async surface.
async fn git_capture_async_with_bin(
    bin: &str,
    args: &[&str],
    workdir: Option<&Path>,
    op: &str,
) -> Result<Vec<u8>, GitError> {
    let mut cmd = tokio::process::Command::new(bin);
    cmd.args(args);
    if let Some(w) = workdir {
        cmd.current_dir(w);
    }
    let output = GitError::from_capture(cmd.output().await, op)?;
    Ok(output.stdout)
}

/// Async sibling of [`get_short_sha`] — `git rev-parse --short=7 HEAD`
/// captured via [`tokio::process::Command`]. Same 7-character contract:
/// `--short=7` is explicit, not `core.abbrev`-dependent, so callers
/// that consume the SHA for image tags inherit deterministic
/// `{arch}-<7-char-sha>` rendering across hosts whose
/// `git config core.abbrev` differs from the default.
pub async fn get_short_sha_async() -> Result<String> {
    let stdout = git_capture_async(&["rev-parse", "--short=7", "HEAD"], None, "rev-parse").await?;
    stdout_string(stdout)
}

/// `workdir`-scoped sibling of [`get_short_sha_async`]. Resolves the
/// short SHA against a specific git working tree (e.g. a frontend
/// sub-repo whose codegen commit is owned by a different working
/// directory than the current process's CWD).
pub async fn get_short_sha_async_in(workdir: &Path) -> Result<String> {
    let stdout = git_capture_async(
        &["rev-parse", "--short=7", "HEAD"],
        Some(workdir),
        "rev-parse",
    )
    .await?;
    stdout_string(stdout)
}

/// Update kustomization.yaml with new image tag
/// This function updates the `images[].newTag` field in a Kustomize file
pub async fn update_manifest(manifest_path: &Path, _old_tag: &str, new_tag: &str) -> Result<()> {
    let content = tokio::fs::read_to_string(manifest_path)
        .await
        .context("Failed to read kustomization.yaml")?;

    // Parse YAML
    let mut yaml: serde_yaml::Value =
        serde_yaml::from_str(&content).context("Failed to parse kustomization.yaml as YAML")?;

    // Update images[].newTag field
    if let Some(images) = yaml.get_mut("images").and_then(|v| v.as_sequence_mut()) {
        for image in images {
            if let Some(new_tag_field) = image.get_mut("newTag") {
                // Replace the newTag value
                *new_tag_field = serde_yaml::Value::String(new_tag.to_string());
            }
        }
    } else {
        anyhow::bail!("No 'images' section found in kustomization.yaml");
    }

    // Serialize back to YAML with proper formatting
    let updated = serde_yaml::to_string(&yaml).context("Failed to serialize YAML")?;

    tokio::fs::write(manifest_path, updated)
        .await
        .context("Failed to write kustomization.yaml")?;

    Ok(())
}

/// Update service ConfigMap with GIT_SHA
/// This function updates the `data.GIT_SHA` field in a service's ConfigMap
/// For web service, it also replaces GIT_SHA_PLACEHOLDER in env.js
///
/// # Arguments
/// * `manifest_path` - Path to the kustomization.yaml file
/// * `git_sha` - Git SHA to set in the ConfigMap
///
/// # Returns
/// Returns Ok(()) if successful, or an error if the ConfigMap file is not found or cannot be updated
pub async fn update_configmap_git_sha(manifest_path: &Path, git_sha: &str) -> Result<()> {
    // Extract service name from manifest path (e.g., .../services/email/kustomization.yaml -> email)
    let service_name = manifest_path
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|s| s.to_str())
        .ok_or_else(|| anyhow::anyhow!("Could not extract service name from manifest path"))?;

    // Construct ConfigMap file path (e.g., email-config.yaml or web-config.yaml)
    let config_map_path = manifest_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Could not get parent directory"))?
        .join(format!("{}-config.yaml", service_name));

    // Check if ConfigMap exists
    if !config_map_path.exists() {
        // Not an error - some services may not have a ConfigMap
        return Ok(());
    }

    let content = tokio::fs::read_to_string(&config_map_path)
        .await
        .context("Failed to read ConfigMap file")?;

    // Parse YAML
    let mut yaml: serde_yaml::Value =
        serde_yaml::from_str(&content).context("Failed to parse ConfigMap as YAML")?;

    // Update data.GIT_SHA field
    if let Some(data) = yaml.get_mut("data").and_then(|v| v.as_mapping_mut()) {
        data.insert(
            serde_yaml::Value::String("GIT_SHA".to_string()),
            serde_yaml::Value::String(git_sha.to_string()),
        );

        // For web service, also replace GIT_SHA_PLACEHOLDER in env.js
        if service_name == "web" {
            if let Some(env_js) = data.get_mut(&serde_yaml::Value::String("env.js".to_string())) {
                if let Some(env_js_str) = env_js.as_str() {
                    let updated_env_js = env_js_str.replace("GIT_SHA_PLACEHOLDER", git_sha);
                    *env_js = serde_yaml::Value::String(updated_env_js);
                }
            }
        }
    } else {
        anyhow::bail!("No 'data' section found in ConfigMap");
    }

    // Serialize back to YAML with proper formatting
    let updated = serde_yaml::to_string(&yaml).context("Failed to serialize YAML")?;

    tokio::fs::write(&config_map_path, updated)
        .await
        .context("Failed to write ConfigMap")?;

    Ok(())
}

/// Commit and push changes in an explicit working directory.
///
/// Used for multi-repo deployments (e.g., k8s manifests in a separate repo).
pub fn commit_and_push_in(
    workdir: &Path,
    files: &[&Path],
    message: &str,
    branch: &str,
) -> Result<()> {
    // Pull from origin first to avoid conflicts
    git_capture_remote(
        &["pull", "origin", branch],
        Some(workdir),
        "pull",
        "origin",
        branch,
    )?;

    // Add each file
    for file in files {
        let relative_path = file.strip_prefix(workdir).unwrap_or(file);
        let rel = relative_path.to_str().unwrap();
        git_capture(&["add", rel], Some(workdir), "add")?;
    }

    // Create commit
    git_capture(&["commit", "-m", message], Some(workdir), "commit")?;

    // Push
    git_capture_remote(
        &["push", "origin", branch],
        Some(workdir),
        "push",
        "origin",
        branch,
    )?;

    Ok(())
}

/// Check if the git working tree is clean (no uncommitted changes).
pub fn is_working_tree_clean() -> Result<bool> {
    let stdout = git_capture(&["status", "--porcelain"], None, "status")?;
    let s = String::from_utf8_lossy(&stdout);
    Ok(s.trim().is_empty())
}

/// Check if a git tag exists locally.
pub fn tag_exists(tag: &str) -> Result<bool> {
    let stdout = git_capture(&["tag", "--list", tag], None, "tag --list")?;
    let s = String::from_utf8_lossy(&stdout);
    Ok(!s.trim().is_empty())
}

/// Check if a git tag exists, scoped to `workdir`.
///
/// Dir-scoped sibling of [`tag_exists`]. A bump runs against a caller-supplied
/// `--working-dir`, and answering "does this tag exist" from the PROCESS's cwd
/// instead would silently consult the wrong repository — returning false for a
/// tag that exists, which is exactly how a release collides with its own tag.
pub fn tag_exists_in(tag: &str, workdir: Option<&Path>) -> Result<bool> {
    let stdout = git_capture(&["tag", "--list", tag], workdir, "tag --list")?;
    let s = String::from_utf8_lossy(&stdout);
    Ok(!s.trim().is_empty())
}

/// The highest already-released version, read from `<prefix>X.Y.Z` tags.
/// Returns `""` when the repo has no such tag — a distinct answer from "0.0.0",
/// because "nothing released yet" and "released 0.0.0" seed differently.
///
/// Compares NUMERICALLY via `parse_semver`, never lexicographically: `v0.10.0`
/// outranks `v0.9.0`, and a string sort gets that backwards. Tags that do not
/// parse as exact `X.Y.Z` (release candidates, dated tags, `v1.2`) are SKIPPED
/// rather than failing the read — a repo is entitled to carry other tags, and
/// refusing to bump because of one would be a false gate.
pub fn max_released_version(prefix: &str, workdir: Option<&Path>) -> Result<String> {
    let pattern = format!("{}*", prefix);
    let stdout = git_capture(&["tag", "--list", &pattern], workdir, "tag --list")?;
    let listing = String::from_utf8_lossy(&stdout);

    let mut best: Option<(u64, u64, u64)> = None;
    let mut best_str = String::new();
    for line in listing.lines() {
        let tag = line.trim();
        let Some(candidate) = tag.strip_prefix(prefix) else {
            continue;
        };
        let Ok(parsed) = crate::version::parse_semver(candidate) else {
            continue;
        };
        if best.is_none_or(|b| parsed > b) {
            best = Some(parsed);
            best_str = candidate.to_string();
        }
    }
    Ok(best_str)
}

/// Create an annotated git tag.
pub fn create_tag(tag: &str, message: &str) -> Result<()> {
    git_capture(&["tag", "-a", tag, "-m", message], None, "tag -a")?;
    Ok(())
}

/// Push a git tag to the remote.
pub fn push_tag(tag: &str) -> Result<()> {
    git_capture_remote(&["push", "origin", tag], None, "push", "origin", tag)?;
    Ok(())
}

/// Commit and push a single-repo deployment commit: the kustomization
/// manifest, the sibling `<service>-config.yaml` ConfigMap if present,
/// and the canonical "Deploy `<service>` image tag `<new_tag>`" release
/// message — routed through the [`commit_and_push_in`] primitive
/// every release-commit path in forge shares.
///
/// Single-repo shape-adapter over [`commit_and_push_in`]: resolves
/// `workdir` via [`get_repo_root`], extracts the service name from the
/// manifest's parent directory, computes the optional sibling
/// `<service>-config.yaml` path, builds the canonical release-commit
/// message, and delegates to `commit_and_push_in` against branch
/// `"main"`. The pull/add/commit/push spawn sequence itself — the
/// shape both single-repo deploys and multi-repo deploys share — now
/// lives once at `commit_and_push_in` and is driven by both callers
/// through a single typed-error producer site per spawn.
pub fn commit_and_push(manifest_path: &Path, old_tag: &str, new_tag: &str) -> Result<()> {
    let workdir = get_repo_root()?;

    let manifest_parent = manifest_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Could not get parent directory"))?;

    let service_name = manifest_parent
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("service");

    let config_map_path = manifest_parent.join(format!("{}-config.yaml", service_name));

    let mut files: Vec<&Path> = vec![manifest_path];
    if config_map_path.exists() {
        files.push(&config_map_path);
    }

    let message = format!(
        "Deploy {} image tag {}\n\nUpdated image tag: {} → {}\nUpdated ConfigMap GIT_SHA: {}\n\nGenerated by forge",
        service_name, new_tag, old_tag, new_tag, new_tag
    );

    commit_and_push_in(&workdir, &files, &message, "main")
}

/// Async `git` spawn constructor honoring `GIT_BIN`. Resolves the
/// `git` binary through [`crate::tools::get_tool_path`] on the
/// canonical `tools::GIT` name once and returns a
/// [`tokio::process::Command`] ready for `.args(...)` +
/// [`crate::retry::run_inherited_status`] (inherited-stdio,
/// status-only semantics — no stdout capture).
///
/// Companion to [`git_capture_async`] on the same free-function
/// surface. `git_capture_async` targets consumers that want the
/// stdout-capturing typed-error dispatch (`GitError::OpFailed` /
/// `ExecFailed`); `git_command_async` targets consumers that want to
/// inherit git's stdout/stderr and dispatch only on the exit code —
/// the shape every `commands/federation.rs` / `commands/push.rs` /
/// `commands/codegen_validation.rs` / `commands/rollback.rs` /
/// `commands/rust_service.rs::deploy_rust_service_with_tag`
/// git-mutation site drives via `Command::new("git").args([...])` +
/// `run_inherited_status`.
///
/// Names the "spawn `git` via `GIT_BIN`" discipline once at the
/// constructor so every consumer honors the env override the
/// tools-registry idiom resolves. Pre-lift each consumer spelled the
/// bare literal `Command::new("git")` — the exact class of bug the
/// `flux` / `cargo` / `doca` / free-function-`git`-capture / `GitClient`
/// migrations redeemed at 621f827 / f0dfa12 / d3dd199 / 685642f /
/// d6f6bc7 / dd5a212 / 673e4be / b02d4eb / 54a9985 / 139b37a /
/// 818ed9a / badcdf4. This constructor closes the last remaining
/// free-function `Command::new("git")`-plus-`run_inherited_status`
/// surface a Nix-hermetic runner could bypass through PATH.
pub fn git_command_async() -> tokio::process::Command {
    tokio::process::Command::new(get_tool_path(tools::GIT))
}

/// Sync sibling of [`git_command_async`]: returns a
/// [`std::process::Command`] whose program is the `GIT_BIN`-resolved
/// path to `git`, ready for `.args(...)` + `.status()` /
/// `.output()` on blocking (non-tokio) code paths.
///
/// Companion to `git_command_async` for the sync half of the
/// free-function surface. Async consumers (`commands/push.rs` /
/// `commands/rollback.rs` / `commands/codegen_validation.rs` /
/// `commands/federation.rs`) route through `git_command_async`;
/// blocking consumers such as `commands/helm.rs::deploy` — invoked
/// from `main.rs` outside any tokio runtime — route through this
/// sibling so both halves honor the `GIT_BIN` env override the
/// tools-registry idiom names as the hermetic-runner contract for
/// [`tools::GIT`].
///
/// Names the discipline once so future blocking-git sites (e.g. the
/// remaining `Command::new("git")` sites in
/// `commands/product_release.rs::commit_artifact_tags` and
/// `commands/release_commit.rs`'s test-side spawn sites) lift
/// through the same constructor rather than each re-spelling the
/// literal `"git"` — the exact class of bug the async
/// `git_command_async` migration redeemed for the async half of the
/// surface at 818ed9a / badcdf4 / 8653403 / f6be190 / 81d7486 /
/// 8a1958e (plus `rust_service::deploy_rust_service_with_tag`'s
/// three-site single-repo branch that misnamed itself
/// `commit_and_push_in` in the prior primitive docstring and lifts
/// through `git_command_async` since its consumers `.await` through
/// `retry::run_inherited_status`), and the sync
/// `config/mod::resolve_k8s_repo_root` +
/// `commands/e2e.rs::resolve_repo_root` + `commands/helm.rs::bump`
/// migrations redeemed on the second, third, and fourth sync
/// consumers.
pub fn git_command_sync() -> Command {
    Command::new(get_tool_path(tools::GIT))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::GitError;

    use crate::test_support::{make_executable_shim, GitBinScope, GIT_BIN_ENV_LOCK};

    /// Write an executable shim that pretends to be `git`. Delegates to
    /// the shared `crate::test_support::make_executable_shim` so the
    /// shim discipline (absolute-path invocation, 0o755 chmod, tempdir
    /// lifetime) lives in one place — same primitive as
    /// `nix.rs`'s `make_nix_shim` and `attic.rs`'s `make_attic_shim`.
    fn make_git_shim(body: &str) -> (tempfile::TempDir, String) {
        make_executable_shim("git", body)
    }

    /// When the resolved git binary cannot be spawned,
    /// `git_capture_with_bin` must surface `ExecFailed` carrying the
    /// offending op label — never a stringly anyhow
    /// `Failed to execute git`. Pins the typed split so telemetry can
    /// distinguish "git missing" from "git said no".
    #[test]
    fn test_git_capture_exec_failed_carries_op() {
        let result = git_capture_with_bin(
            "/nonexistent/path/to/git-binary-that-does-not-exist",
            &["rev-parse", "HEAD"],
            None,
            "rev-parse",
        );
        let err = result.expect_err("missing git binary must fail");
        match err {
            GitError::ExecFailed { op, .. } => {
                assert_eq!(op, "rev-parse");
            }
            other => panic!("expected ExecFailed, got: {other:?}"),
        }
    }

    /// Non-zero exits must produce `OpFailed` carrying the op label, the
    /// exit code, and the captured stderr — never a fused stringly bag.
    /// Uses an absolute-path shim so the test is hermetic and
    /// parallel-safe.
    #[test]
    fn test_git_capture_op_failed_carries_structured_fields() {
        let (_dir, shim) = make_git_shim("#!/bin/sh\necho 'fatal: bad object' 1>&2\nexit 128\n");
        let result = git_capture_with_bin(&shim, &["rev-parse", "HEAD"], None, "rev-parse");
        let err = result.expect_err("nonzero exit must fail");
        match err {
            GitError::OpFailed {
                op,
                exit_code,
                stderr,
            } => {
                assert_eq!(op, "rev-parse");
                assert_eq!(exit_code, Some(128));
                assert!(
                    stderr.contains("bad object"),
                    "stderr field must capture the git stderr verbatim, got: {stderr:?}"
                );
            }
            other => panic!("expected OpFailed, got: {other:?}"),
        }
    }

    /// Success path: `git_capture_with_bin` returns the trimmed stdout
    /// verbatim.
    #[test]
    fn test_git_capture_success_returns_stdout() {
        let (_dir, shim) = make_git_shim("#!/bin/sh\necho 'deadbeef'\nexit 0\n");
        let stdout = git_capture_with_bin(&shim, &["rev-parse", "HEAD"], None, "rev-parse")
            .expect("must succeed");
        assert_eq!(String::from_utf8_lossy(&stdout).trim(), "deadbeef");
    }

    /// Network-side ops must surface `RemoteOpFailed` carrying the
    /// (op, remote, branch) tuple they targeted so attestation records
    /// and retry schedulers recover the exact endpoint from the typed
    /// record without parsing the bail! string (THEORY §V.4).
    #[test]
    fn test_git_capture_remote_failed_carries_endpoint() {
        let (_dir, shim) = make_git_shim("#!/bin/sh\necho 'remote: rejected' 1>&2\nexit 1\n");
        let result = git_capture_remote_with_bin(
            &shim,
            &["push", "origin", "main"],
            None,
            "push",
            "origin",
            "main",
        );
        let err = result.expect_err("nonzero exit must fail");
        match err {
            GitError::RemoteOpFailed {
                op,
                remote,
                branch,
                exit_code,
                stderr,
            } => {
                assert_eq!(op, "push");
                assert_eq!(remote, "origin");
                assert_eq!(branch, "main");
                assert_eq!(exit_code, Some(1));
                assert!(stderr.contains("rejected"));
            }
            other => panic!("expected RemoteOpFailed, got: {other:?}"),
        }
    }

    /// `git_capture_remote_with_bin` must surface an exec-time failure
    /// as `ExecFailed`, not as `RemoteOpFailed` — the typed split
    /// keeps "couldn't spawn git" structurally distinct from "git
    /// rejected the network operation."
    #[test]
    fn test_git_capture_remote_exec_failed_is_distinct() {
        let result = git_capture_remote_with_bin(
            "/nonexistent/path/to/git",
            &["push", "origin", "main"],
            None,
            "push",
            "origin",
            "main",
        );
        let err = result.expect_err("missing binary must fail");
        match err {
            GitError::ExecFailed { op, .. } => assert_eq!(op, "push"),
            other => panic!("expected ExecFailed, got: {other:?}"),
        }
    }

    /// Success path on the network side: `git_capture_remote_with_bin`
    /// returns the trimmed stdout verbatim.
    #[test]
    fn test_git_capture_remote_success_returns_stdout() {
        let (_dir, shim) = make_git_shim("#!/bin/sh\necho 'Everything up-to-date'\nexit 0\n");
        let stdout = git_capture_remote_with_bin(
            &shim,
            &["push", "origin", "main"],
            None,
            "push",
            "origin",
            "main",
        )
        .expect("must succeed");
        assert!(String::from_utf8_lossy(&stdout).contains("up-to-date"));
    }

    #[test]
    fn test_git_client_sha() {
        // Guard against races with tests that mutate `GIT_BIN`
        // ([`test_no_bin_entry_points_route_through_git_bin_env_var`]):
        // this test invokes `get_short_sha` → `git_capture` (no-bin) →
        // resolves through `get_tool_path(tools::GIT)`, so a concurrent
        // env-var write could redirect the spawn to a shim and blow up
        // the length invariant.
        let _guard = GIT_BIN_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        // This test only works in a git repo
        if let Ok(sha) = get_short_sha() {
            assert!(!sha.is_empty());
            assert!(sha.len() >= 7); // Short SHA is at least 7 chars
        }
    }

    // ---------------------------------------------------------------
    // async sibling — git_capture_async / get_short_sha_async{,_in}
    // ---------------------------------------------------------------

    /// Async `git_capture_async`: a missing binary surfaces
    /// `GitError::ExecFailed` carrying the op label — same typed-error
    /// producer dispatch the sync `git_capture` sibling drives, now
    /// covered on the async surface so a future regression that, e.g.,
    /// fused the spawn-vs-op classifier into a stringly anyhow path
    /// fails this test rather than silently degrade the four async
    /// callsites (`commands/push.rs::get_git_sha`,
    /// `commands/rust_service.rs::get_tag_suffix`,
    /// `commands/codegen_validation.rs`, `commands/federation.rs`)
    /// that pre-this-commit each hand-rolled the
    /// `Command::new("git").args([...]).output().await.context(...)?`
    /// envelope verbatim.
    #[tokio::test]
    async fn test_git_capture_async_exec_failed_carries_op() {
        let result = git_capture_async_with_bin(
            "/nonexistent/path/to/git-binary-that-does-not-exist",
            &["rev-parse", "HEAD"],
            None,
            "rev-parse",
        )
        .await;
        let err = result.expect_err("missing git binary must fail");
        match err {
            GitError::ExecFailed { op, .. } => {
                assert_eq!(op, "rev-parse");
            }
            other => panic!("expected ExecFailed, got: {other:?}"),
        }
    }

    /// Async `git_capture_async`: non-zero exit produces `OpFailed`
    /// carrying the op label, the exit code, and the captured stderr —
    /// the structural `(op, exit_code, stderr)` tuple Phase 1
    /// attestation records (THEORY §V.4) pattern-match on. Hermetic
    /// against the host git via an absolute-path shim.
    #[tokio::test]
    async fn test_git_capture_async_op_failed_carries_structured_fields() {
        let (_dir, shim) = make_git_shim("#!/bin/sh\necho 'fatal: bad object' 1>&2\nexit 128\n");
        let result =
            git_capture_async_with_bin(&shim, &["rev-parse", "HEAD"], None, "rev-parse").await;
        let err = result.expect_err("nonzero exit must fail");
        match err {
            GitError::OpFailed {
                op,
                exit_code,
                stderr,
            } => {
                assert_eq!(op, "rev-parse");
                assert_eq!(exit_code, Some(128));
                assert!(
                    stderr.contains("bad object"),
                    "stderr field must capture the git stderr verbatim, got: {stderr:?}"
                );
            }
            other => panic!("expected OpFailed, got: {other:?}"),
        }
    }

    /// Async happy path: `git_capture_async_with_bin` returns the
    /// trimmed stdout verbatim.
    #[tokio::test]
    async fn test_git_capture_async_success_returns_stdout() {
        let (_dir, shim) = make_git_shim("#!/bin/sh\necho 'deadbeef'\nexit 0\n");
        let stdout = git_capture_async_with_bin(&shim, &["rev-parse", "HEAD"], None, "rev-parse")
            .await
            .expect("must succeed");
        assert_eq!(String::from_utf8_lossy(&stdout).trim(), "deadbeef");
    }

    /// `git_capture_async` resolves the requested args inside the
    /// supplied `workdir` — pinned via a shim that writes its CWD to a
    /// side-channel file. Closes the only behavioral asymmetry between
    /// `get_short_sha_async` (no workdir) and `get_short_sha_async_in`
    /// (workdir): a regression that silently dropped the
    /// `cmd.current_dir(w)` arm would resolve the SHA against the
    /// process CWD instead of the supplied sub-repo and is structurally
    /// invisible without this pin.
    #[tokio::test]
    async fn test_git_capture_async_honors_workdir() {
        let dir = tempfile::tempdir().expect("tempdir");
        let probe = dir.path().join("cwd.log");
        let body = format!(
            "#!/bin/sh\npwd > {}\necho 'deadbeef'\nexit 0\n",
            probe.display()
        );
        let (_shim_dir, shim) = make_git_shim(&body);

        let stdout = git_capture_async_with_bin(
            &shim,
            &["rev-parse", "HEAD"],
            Some(dir.path()),
            "rev-parse",
        )
        .await
        .expect("must succeed");

        assert_eq!(String::from_utf8_lossy(&stdout).trim(), "deadbeef");
        let recorded = std::fs::read_to_string(&probe).expect("read cwd.log");
        // macOS may canonicalize /var → /private/var; match by suffix.
        let recorded_trim = recorded.trim();
        let workdir_str = dir.path().to_string_lossy();
        assert!(
            recorded_trim.ends_with(workdir_str.as_ref()),
            "git child must run inside the supplied workdir; \
             recorded cwd = {recorded_trim:?}, expected suffix = {workdir_str:?}"
        );
    }

    /// `get_short_sha_async` end-to-end against the real `git` binary
    /// inside a hermetic `tempfile::tempdir()` repo with a known seed
    /// commit. Pins that the async primitive returns a 7-character
    /// short SHA equal to the same repo's `git rev-parse --short=7
    /// HEAD` answer — the contract the four lifted callsites
    /// (`get_git_sha`, `get_tag_suffix`, codegen-validation,
    /// federation) all consume.
    #[tokio::test]
    async fn test_get_short_sha_async_in_returns_seven_char_sha() {
        // See [`test_git_client_sha`] rationale — this test invokes the
        // async no-bin production entry point and would blow up if a
        // concurrent env-var-mutating test redirected the spawn to a
        // shim mid-flight.
        let _guard = GIT_BIN_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let (_parent, _bare, work) = make_bare_origin_with_work();
        let sha = get_short_sha_async_in(&work)
            .await
            .expect("get_short_sha_async_in must succeed in a seeded repo");
        assert_eq!(
            sha.len(),
            7,
            "--short=7 must yield a 7-character SHA, got: {sha:?}"
        );
        assert!(
            sha.chars().all(|c| c.is_ascii_hexdigit()),
            "SHA must be hex, got: {sha:?}"
        );
    }

    /// Stand up a bare "origin" repo and a work-tree clone of it on
    /// `main` with an initial seed commit already pushed. Returns the
    /// owning `TempDir` plus the (bare, work) path pair. Shared
    /// scaffolding for the `commit_and_push_in` round-trip tests so
    /// the bare/work setup discipline lives in one place — same
    /// rationale as `test_support::make_executable_shim`.
    fn make_bare_origin_with_work() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let parent = tempfile::tempdir().expect("tempdir");
        let bare = parent.path().join("origin.git");
        let work = parent.path().join("work");
        std::fs::create_dir(&bare).expect("mkdir bare");
        std::fs::create_dir(&work).expect("mkdir work");

        let run = |args: &[&str], cwd: &Path| {
            let status = git_command_sync()
                .args(args)
                .current_dir(cwd)
                .status()
                .expect("spawn git");
            assert!(status.success(), "git {args:?} in {cwd:?} failed");
        };

        run(&["init", "--bare", "--initial-branch=main"], &bare);
        run(&["init", "--initial-branch=main"], &work);
        run(&["config", "user.email", "test@forge.local"], &work);
        run(&["config", "user.name", "Forge Test"], &work);
        // Disable commit signing locally so the test is hermetic
        // against the host's global `commit.gpgsign = true` (e.g. the
        // managed remote-execution environment forge runs in). Without
        // this the seed commit hits the host signer and fails the
        // setup before the function under test ever runs.
        run(&["config", "commit.gpgsign", "false"], &work);
        run(
            &[
                "remote",
                "add",
                "origin",
                bare.to_str().expect("bare path utf-8"),
            ],
            &work,
        );
        std::fs::write(work.join("seed.txt"), "initial\n").expect("write seed");
        run(&["add", "seed.txt"], &work);
        run(&["commit", "-m", "seed"], &work);
        run(&["push", "-u", "origin", "main"], &work);

        (parent, bare, work)
    }

    /// `commit_and_push_in` end-to-end: against a real bare-repo
    /// "origin" and a work-tree clone, pull → add → commit → push
    /// lands the configured commit subject on origin. Pins the
    /// surviving primitive every release-commit path in forge routes
    /// through (multi-repo via `rust_service::commit_and_push_in`,
    /// single-repo via `commit_and_push` post the lift that retired
    /// the inline pull/add/commit/push stanza on the single-repo
    /// path). Hermetic against the real `git` binary and a
    /// `tempfile::tempdir()` bare-repo pair so the test exercises the
    /// actual production spawn sequence rather than a shim.
    #[test]
    fn test_commit_and_push_in_lands_commit_on_origin() {
        // `commit_and_push_in` invokes `git_capture` / `git_capture_remote`
        // — the no-bin production entry points that resolve through
        // `GIT_BIN`. Serialize against the env-mutating test.
        let _guard = GIT_BIN_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let (parent, bare, work) = make_bare_origin_with_work();

        let manifest = work.join("kustomization.yaml");
        std::fs::write(&manifest, "images: []\n").expect("write manifest");

        commit_and_push_in(&work, &[&manifest], "Deploy round-trip pin", "main")
            .expect("commit_and_push_in must succeed");

        let probe = parent.path().join("probe");
        let status = git_command_sync()
            .args([
                "clone",
                bare.to_str().expect("bare utf-8"),
                probe.to_str().expect("probe utf-8"),
            ])
            .status()
            .expect("spawn git clone");
        assert!(status.success(), "clone probe failed");
        let subject_out = git_command_sync()
            .args(["log", "-1", "--pretty=%s"])
            .current_dir(&probe)
            .output()
            .expect("spawn git log");
        let subject = String::from_utf8_lossy(&subject_out.stdout)
            .trim()
            .to_string();
        assert_eq!(subject, "Deploy round-trip pin");
    }

    /// `commit_and_push_in` lands every file in the supplied slice
    /// inside one commit. Pins the multi-file primitive contract the
    /// post-lift `commit_and_push` consumes for "manifest + sibling
    /// configmap" (two files in the slice) and the rust_service
    /// multi-repo deploy consumes for its manifest-only flow (one
    /// file in the slice). A drift to "stages only the first file"
    /// would silently lose the ConfigMap-GIT_SHA update on the
    /// single-repo deploy path; this pin catches it.
    #[test]
    fn test_commit_and_push_in_stages_every_file_in_slice() {
        // Same env-var race guard as the single-file sibling above.
        let _guard = GIT_BIN_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let (parent, bare, work) = make_bare_origin_with_work();

        let manifest = work.join("kustomization.yaml");
        let config_map = work.join("svc-config.yaml");
        std::fs::write(&manifest, "images: []\n").expect("write manifest");
        std::fs::write(&config_map, "data:\n  GIT_SHA: abc\n").expect("write configmap");

        commit_and_push_in(
            &work,
            &[&manifest, &config_map],
            "Deploy multi-file pin",
            "main",
        )
        .expect("commit_and_push_in must succeed");

        let probe = parent.path().join("probe");
        let status = git_command_sync()
            .args([
                "clone",
                bare.to_str().expect("bare utf-8"),
                probe.to_str().expect("probe utf-8"),
            ])
            .status()
            .expect("spawn git clone");
        assert!(status.success(), "clone probe failed");
        let files_out = git_command_sync()
            .args(["show", "--name-only", "--pretty=", "HEAD"])
            .current_dir(&probe)
            .output()
            .expect("spawn git show");
        let files = String::from_utf8_lossy(&files_out.stdout);
        assert!(
            files.contains("kustomization.yaml"),
            "manifest must appear in HEAD commit, got: {files:?}"
        );
        assert!(
            files.contains("svc-config.yaml"),
            "configmap must appear in HEAD commit, got: {files:?}"
        );
    }

    /// The three no-bin production entry points ([`git_capture`],
    /// [`git_capture_async`], [`git_capture_remote`]) MUST resolve the
    /// `git` binary through [`crate::tools::get_tool_path`] on the
    /// canonical `tools::GIT` name — i.e. every one honors the
    /// `GIT_BIN` env override the tools-registry idiom names as the
    /// hermetic-runner contract, and none silently hardcodes the
    /// literal `"git"` on the spawn path.
    ///
    /// A regression that "tidies" any of the three production
    /// entrypoints back to `Command::new("git")` (the pre-lift shape,
    /// the exact class of bug the `flux`/`cargo`/`DOCA` bypasses
    /// carried at f0dfa12 / 621f827 / d3dd199 / 685642f / d6f6bc7 /
    /// dd5a212 / 673e4be / b02d4eb / 54a9985 / 139b37a) fails this
    /// test rather than silently degrade to whatever `git` is first on
    /// `PATH` at a Nix-hermetic runner.
    ///
    /// The pin is exercised via `GIT_BIN` set to a hermetic shim whose
    /// stderr carries a distinctive sigil. The typed `GitError::OpFailed`
    /// variant surfaces the shim's stderr verbatim, so seeing the sigil
    /// on every one of the three entry points is proof the resolution
    /// went through the shim, not through PATH.
    ///
    /// Runs under [`GIT_BIN_ENV_LOCK`] to serialize against every other
    /// test that either mutates `GIT_BIN` or invokes a no-bin
    /// production entry point that reads it.
    #[tokio::test]
    async fn test_no_bin_entry_points_route_through_git_bin_env_var() {
        let _guard = GIT_BIN_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());

        let sigil = "SIGIL_ROUTED_VIA_GIT_BIN_5f3a1c";
        let (_shim_dir, shim) = make_git_shim(&format!(
            "#!/bin/sh\necho '{sigil}' 1>&2\nexit 42\n",
            sigil = sigil,
        ));
        let _scope = GitBinScope::set(&shim);

        // Sync: git_capture(args, workdir, op) must delegate to
        // git_capture_with_bin(get_tool_path(tools::GIT), ...). With
        // GIT_BIN=shim, that resolves to `shim` and its stderr carries
        // the sigil.
        let sync_err =
            git_capture(&["rev-parse", "HEAD"], None, "rev-parse").expect_err("shim exits 42");
        match sync_err {
            GitError::OpFailed {
                op,
                exit_code,
                stderr,
            } => {
                assert_eq!(op, "rev-parse");
                assert_eq!(exit_code, Some(42), "shim's exit code must ride through");
                assert!(
                    stderr.contains(sigil),
                    "git_capture stderr must carry the shim's sigil — proves the \
                     no-bin entry point routed through GIT_BIN, not a hardcoded \"git\". \
                     Got stderr={stderr:?}"
                );
            }
            other => panic!("expected OpFailed from shim exit 42, got: {other:?}"),
        }

        // Async: git_capture_async(args, workdir, op) must delegate to
        // git_capture_async_with_bin(get_tool_path(tools::GIT), ...).
        let async_err = git_capture_async(&["rev-parse", "HEAD"], None, "rev-parse")
            .await
            .expect_err("shim exits 42");
        match async_err {
            GitError::OpFailed {
                op,
                exit_code,
                stderr,
            } => {
                assert_eq!(op, "rev-parse");
                assert_eq!(exit_code, Some(42));
                assert!(
                    stderr.contains(sigil),
                    "git_capture_async stderr must carry the shim's sigil — proves the \
                     async no-bin entry point routed through GIT_BIN. Got stderr={stderr:?}"
                );
            }
            other => panic!("expected OpFailed from shim exit 42, got: {other:?}"),
        }

        // Remote: git_capture_remote(args, workdir, op, remote, branch)
        // must delegate to git_capture_remote_with_bin(
        //   get_tool_path(tools::GIT), ...). Same shim; RemoteOpFailed
        // instead of OpFailed on the network-side arm.
        let remote_err =
            git_capture_remote(&["push", "origin", "main"], None, "push", "origin", "main")
                .expect_err("shim exits 42");
        match remote_err {
            GitError::RemoteOpFailed {
                op,
                remote,
                branch,
                exit_code,
                stderr,
            } => {
                assert_eq!(op, "push");
                assert_eq!(remote, "origin");
                assert_eq!(branch, "main");
                assert_eq!(exit_code, Some(42));
                assert!(
                    stderr.contains(sigil),
                    "git_capture_remote stderr must carry the shim's sigil — proves the \
                     remote no-bin entry point routed through GIT_BIN. Got stderr={stderr:?}"
                );
            }
            other => panic!("expected RemoteOpFailed from shim exit 42, got: {other:?}"),
        }
    }

    /// [`GitBinScope`] MUST restore the pre-scope state on drop — the
    /// exact discipline that keeps [`test_no_bin_entry_points_route_through_git_bin_env_var`]
    /// from leaking `GIT_BIN=<shim>` to any test that runs after it,
    /// which would otherwise redirect every subsequent git spawn under
    /// the same lock to the (dropped-tempdir) shim. Pins the restore
    /// contract on both directions: originally-unset stays unset,
    /// originally-set restores the original value verbatim.
    #[test]
    fn test_git_bin_scope_restores_pre_scope_state_on_drop() {
        let _guard = GIT_BIN_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());

        // Direction 1: originally-unset must stay unset after drop.
        std::env::remove_var("GIT_BIN");
        {
            let _scope = GitBinScope::set("/tmp/does-not-exist-shim");
            assert_eq!(
                std::env::var("GIT_BIN").ok().as_deref(),
                Some("/tmp/does-not-exist-shim"),
                "in-scope value must be visible"
            );
        }
        assert!(
            std::env::var("GIT_BIN").is_err(),
            "originally-unset GIT_BIN must be unset again after drop"
        );

        // Direction 2: originally-set must restore the original value.
        std::env::set_var("GIT_BIN", "/original/value/pre/scope");
        {
            let _scope = GitBinScope::set("/tmp/mid-scope-override");
            assert_eq!(
                std::env::var("GIT_BIN").ok().as_deref(),
                Some("/tmp/mid-scope-override"),
                "in-scope value must override"
            );
        }
        assert_eq!(
            std::env::var("GIT_BIN").ok().as_deref(),
            Some("/original/value/pre/scope"),
            "originally-set GIT_BIN must be restored verbatim after drop"
        );
        std::env::remove_var("GIT_BIN");
    }

    /// [`git_command_async`] MUST resolve the `git` binary through
    /// [`crate::tools::get_tool_path`] on the canonical `tools::GIT`
    /// name — i.e. it honors the `GIT_BIN` env override the
    /// tools-registry idiom names as the hermetic-runner contract,
    /// and never hardcodes the literal `"git"` on the spawn path.
    ///
    /// Two-arm pin. The static arm reads the returned Command's
    /// program directly (`Command::as_std().get_program()`) and
    /// asserts it equals the resolved shim path verbatim — proves the
    /// constructor resolves through `get_tool_path(tools::GIT)`
    /// without ever spawning. The end-to-end arm spawns the same
    /// Command through the exact `retry::run_inherited_status` shape
    /// every consumer (`commands/federation.rs` / `commands/push.rs` /
    /// `commands/codegen_validation.rs`) drives and asserts the
    /// shim's exit code rides through the returned anyhow chain —
    /// proves the resolution isn't just stringly-equal but actually
    /// spawns the shim end-to-end. A regression that "tidies"
    /// `git_command_async` back to `Command::new("git")` fails the
    /// program-name assertion; a regression that ignores the
    /// resolved bin at the retry layer fails the exit-code
    /// assertion.
    ///
    /// Runs under [`GIT_BIN_ENV_LOCK`] to serialize against every
    /// other test that either mutates `GIT_BIN` or invokes a no-bin
    /// production entry point that reads it.
    #[tokio::test]
    async fn test_git_command_async_routes_through_git_bin_env_var() {
        let _guard = GIT_BIN_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());

        let (_shim_dir, shim) = make_git_shim(
            "#!/bin/sh\necho 'SIGIL_ROUTED_VIA_GIT_COMMAND_ASYNC_9d2b7f' 1>&2\nexit 77\n",
        );
        let _scope = GitBinScope::set(&shim);

        // Static arm: the returned Command's program is the
        // GIT_BIN-resolved path, not the literal "git".
        let cmd = git_command_async();
        assert_eq!(
            cmd.as_std().get_program(),
            std::ffi::OsStr::new(&shim),
            "git_command_async() must resolve through GIT_BIN, not hardcode \"git\""
        );

        // End-to-end arm: spawning through the consumer shape
        // (retry::run_inherited_status) surfaces the shim's exit
        // code via the returned anyhow chain.
        let mut cmd = git_command_async();
        cmd.args(["diff", "--staged", "--quiet"]);
        let err = crate::retry::run_inherited_status(cmd, "git diff")
            .await
            .expect_err("shim exits 77");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("exit 77"),
            "run_inherited_status must surface the shim's exit code via \
             the anyhow message; got: {msg:?}"
        );
        assert!(
            msg.contains("git diff"),
            "run_inherited_status must surface the op label via the \
             anyhow message; got: {msg:?}"
        );
    }

    /// [`git_command_sync`] MUST resolve the `git` binary through
    /// [`crate::tools::get_tool_path`] on the canonical `tools::GIT`
    /// name — i.e. it honors the `GIT_BIN` env override the
    /// tools-registry idiom names as the hermetic-runner contract,
    /// and never hardcodes the literal `"git"` on the spawn path.
    ///
    /// Two-arm pin, mirroring the sibling
    /// [`test_git_command_async_routes_through_git_bin_env_var`].
    /// The static arm reads the returned Command's program directly
    /// (`Command::get_program()`) and asserts it equals the resolved
    /// shim path verbatim — proves the constructor resolves through
    /// `get_tool_path(tools::GIT)` without ever spawning. The
    /// end-to-end arm spawns the same Command through the blocking
    /// `.status()` shape every sync consumer (`commands/helm.rs::deploy`,
    /// `config/mod::resolve_k8s_repo_root`, `commands/e2e.rs::resolve_repo_root`,
    /// `commands/helm.rs::bump`, and future
    /// `commands/rust_service.rs::commit_and_push_in` /
    /// `commands/product_release.rs::commit_artifact_tags` migrations) drives
    /// and asserts the shim's exit code rides through verbatim — proves
    /// the resolution isn't just stringly-equal but actually spawns
    /// the shim end-to-end. A regression that "tidies"
    /// `git_command_sync` back to `Command::new("git")` fails the
    /// program-name assertion.
    ///
    /// Runs under [`GIT_BIN_ENV_LOCK`] to serialize against every
    /// other test that either mutates `GIT_BIN` or invokes a no-bin
    /// production entry point that reads it.
    #[test]
    fn test_git_command_sync_routes_through_git_bin_env_var() {
        let _guard = GIT_BIN_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());

        let (_shim_dir, shim) = make_git_shim(
            "#!/bin/sh\necho 'SIGIL_ROUTED_VIA_GIT_COMMAND_SYNC_4a1c8e' 1>&2\nexit 63\n",
        );
        let _scope = GitBinScope::set(&shim);

        // Static arm: the returned Command's program is the
        // GIT_BIN-resolved path, not the literal "git".
        let cmd = git_command_sync();
        assert_eq!(
            cmd.get_program(),
            std::ffi::OsStr::new(&shim),
            "git_command_sync() must resolve through GIT_BIN, not hardcode \"git\""
        );

        // End-to-end arm: spawning through the blocking `.status()`
        // shape (the consumer surface for helm::deploy) surfaces the
        // shim's exit code verbatim.
        let status = git_command_sync()
            .args(["diff", "--staged", "--quiet"])
            .status()
            .expect("shim must spawn");
        assert_eq!(
            status.code(),
            Some(63),
            "git_command_sync().status() must surface the shim's exit code \
             verbatim — proves the sync constructor spawns the GIT_BIN \
             shim end-to-end, not a PATH-resolved `git`"
        );
    }

    /// Whole-module shield: no raw bare-literal `git` spawn may live on
    /// an executable code line in `cli/src/git.rs`. Every git spawn —
    /// the two `pub fn` production entry points ([`git_capture`],
    /// [`git_capture_async`], [`git_capture_remote`], the
    /// `git_command_{sync,async}` free-function constructors, plus every
    /// sibling `#[cfg(test)]` fixture and probe (the `run` closure inside
    /// [`tests::make_bare_origin_with_work`] and the four
    /// `git clone` / `git log` / `git show` probes in
    /// [`tests::test_commit_and_push_in_lands_commit_on_origin`] and
    /// [`tests::test_commit_and_push_in_stages_every_file_in_slice`]) —
    /// must resolve `GIT_BIN` via the canonical
    /// [`git_command_sync`] / [`git_command_async`] constructors (or one
    /// of the higher-level `git_capture{,_async,_remote}` primitives
    /// that already delegate through `get_tool_path(tools::GIT)`). A
    /// Nix-hermetic runner invocation with a substrate-derivation-pinned
    /// `git` must land at that same store path, not at whichever `git`
    /// sits first on `PATH`.
    ///
    /// This module is the substrate for every git spawn in forge: the
    /// production primitives here delegate through
    /// `get_tool_path(tools::GIT)`, and the test-side fixture
    /// `make_bare_origin_with_work` seeds the bare+work pair every
    /// `commit_and_push_in` round-trip test in this module consumes. A
    /// raw literal at any test-side site would silently fall through
    /// to the PATH-resolved `git` and observe a state the substrate-
    /// pinned `git` (the one every production consumer routes through)
    /// did not produce — the same class of foreign-`git`-observing-
    /// substrate-`git` inversion the sibling
    /// `commands/release_commit.rs` (8f27812) /
    /// `commands/product_release.rs` (0ea75ba) /
    /// `commands/attestation.rs` (1c90949) /
    /// `cli/src/test_support.rs` (3036a55) shields close on their
    /// modules.
    ///
    /// The three forbidden shapes (`std::process::Command::new("git")`,
    /// bare `Command::new("git")`, `tokio::process::Command::new("git")`)
    /// are reconstructed via `format!` from the bare string `"git"` so
    /// this shield's own source text does not false-match itself. The
    /// per-line filter drops `///` / `//!` / `//` comment lines so the
    /// pre-existing docstrings on `git_command_{sync,async}` and the
    /// three `git_capture` primitives — which narrate the historical
    /// `Command::new("git")` anti-pattern by literal quotation — do not
    /// register as violations. Every one of the remaining occurrences
    /// (before this shield) at lines 471 / 477 / 482 / 504 / 700 / 983 /
    /// 1146 / 1214 lives inside a `///` docstring; the shield fires only
    /// on executable code.
    ///
    /// The production body of this module (`git_capture_with_bin`,
    /// `git_capture_async_with_bin`, `git_capture_remote_with_bin`)
    /// spawns via `Command::new(bin)` where `bin` is the resolved
    /// argument threaded from `get_tool_path(tools::GIT)` — a variable,
    /// not the bare literal this shield forbids, so it does not match.
    /// Similarly `git_command_sync` / `git_command_async` construct via
    /// `Command::new(get_tool_path(tools::GIT))` — again a variable.
    ///
    /// The end-to-end `GIT_BIN`-routing invariant of the underlying
    /// primitives is pinned separately by
    /// [`test_git_command_sync_routes_through_git_bin_env_var`] and
    /// [`test_git_command_async_routes_through_git_bin_env_var`]; this
    /// shield only certifies that every git-spawning site in this
    /// module reads through one of them.
    #[test]
    fn test_git_spawn_routes_through_git_command_sync_not_raw_literal() {
        const SOURCE: &str = include_str!("git.rs");

        crate::test_support::assert_source_forbids_bare_spawn_shapes_code_line(
            SOURCE,
            "cli/src/git.rs",
            "git",
            "resolve `GIT_BIN` via `git_command_sync()` / \
             `git_command_async()` (or one of the \
             `git_capture{,_async,_remote}` primitives that delegate \
             through them)",
        );

        assert!(
            SOURCE.contains("pub fn git_command_sync"),
            "cli/src/git.rs must expose the canonical `git_command_sync()` \
             constructor — the required form was not found in the module. \
             A regression that removed it would silently downgrade every \
             sync test-side spawn to the PATH fallback."
        );
        assert!(
            SOURCE.contains("pub fn git_command_async"),
            "cli/src/git.rs must expose the canonical `git_command_async()` \
             constructor — the required form was not found in the module. \
             A regression that removed it would silently downgrade every \
             async consumer to the PATH fallback."
        );
    }
}

/// Tests for the released-version reader added alongside `--seed-from-tags`.
///
/// These were owed: when `max_released_version` landed it was covered only by an
/// end-to-end run against a throwaway repo, which is real evidence but does not
/// pin the ORDERING rule or the skip rule against regression. A git shim pins
/// both without needing a repository.
#[cfg(test)]
mod max_released_version_tests {
    use super::*;
    use crate::test_support::{make_executable_shim, GitBinScope, GIT_BIN_ENV_LOCK};

    /// A fake `git` whose `tag --list` prints `listing` verbatim.
    fn git_listing_shim(listing: &str) -> (tempfile::TempDir, String) {
        make_executable_shim("git", &format!("#!/bin/sh\nprintf '{}'\n", listing))
    }

    #[test]
    fn orders_numerically_not_lexicographically() {
        let _guard = GIT_BIN_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        // THE rule. Lexicographically "0.3.1" > "0.10.0", so a string sort picks
        // the wrong tag and the next release lands behind a published one.
        let (_d, shim) = git_listing_shim("v0.3.0\\nv0.3.1\\nv0.10.0\\n");
        let _scope = GitBinScope::set(&shim);
        assert_eq!(max_released_version("v", None).unwrap(), "0.10.0");
    }

    #[test]
    fn skips_tags_that_are_not_exact_semver_rather_than_failing() {
        let _guard = GIT_BIN_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        // A repo is entitled to carry rc / dated / two-part tags. Refusing to
        // bump because of one would be a false gate, so they are skipped.
        let (_d, shim) = git_listing_shim("v1.2\\nv2.0.0-rc1\\nvNOPE\\nv0.1.0\\nv0.1.0.1\\n");
        let _scope = GitBinScope::set(&shim);
        assert_eq!(
            max_released_version("v", None).unwrap(),
            "0.1.0",
            "only the exact X.Y.Z tag counts"
        );
    }

    #[test]
    fn no_matching_tag_is_empty_not_zero() {
        let _guard = GIT_BIN_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        // "" and "0.0.0" seed DIFFERENTLY: empty means the manifest wins
        // outright, whereas 0.0.0 would be compared against it.
        let (_d, shim) = git_listing_shim("");
        let _scope = GitBinScope::set(&shim);
        assert_eq!(max_released_version("v", None).unwrap(), "");

        let (_d2, shim2) = git_listing_shim("nightly\\nlatest\\n");
        let _scope2 = GitBinScope::set(&shim2);
        assert_eq!(
            max_released_version("v", None).unwrap(),
            "",
            "tags that do not even carry the prefix yield empty"
        );
    }

    #[test]
    fn strips_the_prefix_and_honours_a_non_v_prefix() {
        let _guard = GIT_BIN_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let (_d, shim) = git_listing_shim("release-1.4.0\\nrelease-1.10.0\\n");
        let _scope = GitBinScope::set(&shim);
        assert_eq!(
            max_released_version("release-", None).unwrap(),
            "1.10.0",
            "the returned value is the bare version, prefix removed"
        );
    }

    #[test]
    fn tolerates_surrounding_whitespace_in_the_listing() {
        let _guard = GIT_BIN_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let (_d, shim) = git_listing_shim("  v0.2.0  \\n\\nv0.5.0\\n  \\n");
        let _scope = GitBinScope::set(&shim);
        assert_eq!(max_released_version("v", None).unwrap(), "0.5.0");
    }
}
