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
    if let Some(repo_root) = crate::repo::path_from_env_optional("REPO_ROOT") {
        return Ok(repo_root);
    }

    // Fall back to git command
    read_repo_root_via_rev_parse()
}

/// Run `git rev-parse --show-toplevel` (routed through
/// [`get_tool_path`]/[`tools::GIT`] so `GIT_BIN` overrides land at the
/// shared spawn primitive) and return the trimmed working-tree root.
///
/// Sole holder of the `&["rev-parse", "--show-toplevel"]` argv literal
/// AND the stdout-decode `stdout_string` composition — pre-this-lift
/// the pair was spelled verbatim at three sites ([`get_repo_root`],
/// `commands/e2e.rs::resolve_repo_root`, `commands/helm.rs::bump`). Both
/// [`get_repo_root`] and [`try_repo_root_via_rev_parse`] delegate here
/// so a future refinement to the discovery shape (adding a
/// `--absolute-git-dir` fallback, a canonicalization step, a per-attempt
/// telemetry emit) lands at ONE body instead of at three inline copies
/// diverging by accretion.
fn read_repo_root_via_rev_parse() -> Result<PathBuf> {
    let stdout = git_capture(&["rev-parse", "--show-toplevel"], None, "rev-parse")?;
    Ok(PathBuf::from(stdout_string(stdout)?))
}

/// Read the enclosing git working-tree root via
/// `git rev-parse --show-toplevel`, swallowing every failure mode.
/// Returns `Some(root)` when the git spawn succeeded with a zero exit
/// and valid UTF-8 output; returns `None` on spawn failure (missing
/// binary), non-zero exit (not a git repository, corrupt HEAD,
/// permission denied), or a UTF-8 decode error.
///
/// Sibling of [`get_repo_root`], which layers the `REPO_ROOT` env-var
/// shortcut on top and surfaces failures as `Result`. This primitive
/// is the raw git-side read for callers with their own fallback path:
/// `commands/e2e.rs::resolve_repo_root` falls back to the current
/// working directory when git can't answer; `commands/helm.rs::bump`
/// wraps the `None` in a caller-supplied `anyhow!` context.
///
/// # Why this primitive
///
/// Pre-lift the raw `git rev-parse --show-toplevel` invocation was
/// authored verbatim at THREE sites — [`get_repo_root`] (typed-error
/// propagation via [`git_capture`]), `commands/e2e.rs::resolve_repo_root`
/// (inline `git_command_sync().args(...).output()` with cwd fallback),
/// and `commands/helm.rs::bump` (inline `git_command_sync().args(...)
/// .output()` with `context()`-wrapped bail). Three occurrences of
/// the `["rev-parse", "--show-toplevel"]` argv literal is exactly
/// THEORY.md §VI.1's three-times-is-a-law threshold ("two occurrences
/// is a coincidence; three is a law"). Post-lift the argv slice, the
/// stdout-string decode, and the `PathBuf::from` conversion all live
/// at one body ([`read_repo_root_via_rev_parse`]); each consumer
/// composes only its own failure-handling shape.
///
/// # What this catches at construction
///
/// The pre-lift `commands/helm.rs::bump` site had a latent silent-empty
/// bug: `.output().context("Failed to run git rev-parse")?` returned
/// `Ok(_)` on any git spawn that succeeded — including a git that
/// exited non-zero with empty stdout (the "not a git repository" case
/// on exit 128 with `fatal: not a git repository` on stderr), so
/// `String::from_utf8(repo_root.stdout)?.trim().to_string()` yielded
/// `""` and every subsequent `git add`/`commit`/`tag` in `bump` ran
/// with `current_dir("")` instead of surfacing the error. Post-lift
/// this primitive returns `None` on any non-zero exit, and the
/// `helm::bump` caller's `.context("Failed to run git rev-parse")?`
/// converts the `None` into a loud error before any downstream spawn.
pub fn try_repo_root_via_rev_parse() -> Option<PathBuf> {
    read_repo_root_via_rev_parse().ok()
}

/// Which form of the HEAD commit's SHA a `git rev-parse HEAD` read
/// resolves to — the typed sum owning the `rev-parse` argv slice AND
/// the expected hex length of the rendered SHA.
///
/// Pre-this-lift each of `get_full_sha` / `get_short_sha` /
/// `get_short_sha_async` / `get_short_sha_async_in` spelled the
/// `rev-parse` argv literal by hand — three of the four also spelled
/// the load-bearing `"--short=7"` string verbatim, a §VI.1
/// three-times-is-a-law violation for a load-bearing invariant the
/// module's own docstring names: `--short=7` is explicit, not
/// `core.abbrev`-dependent, so callers that consume the SHA for image
/// tags inherit deterministic `{arch}-<7-char-sha>` rendering across
/// hosts whose `git config core.abbrev` differs from the default. A
/// fourth consumer that added a hand-rolled `--short=7 HEAD` site
/// would silently drift if a future host-abbrev migration ever wanted
/// to widen the form. Post-lift the argv slice AND the expected-length
/// oracle live once at [`HeadShaForm::args`] /
/// [`HeadShaForm::expected_len`]; every consumer routes through the
/// typed variant instead of respelling the argv.
///
/// # Consumers
///
/// * [`get_full_sha`] resolves the 40-character SHA at the process CWD.
/// * [`get_short_sha`] / [`get_short_sha_async`] resolve the
///   7-character SHA at the process CWD.
/// * [`get_short_sha_async_in`] resolves the 7-character SHA against
///   a supplied `workdir` (sub-repo whose codegen commit is owned by a
///   different working directory than the current process's CWD).
///
/// # THEORY grounding
///
/// THEORY.md §II Language — typed primitives own boundary
/// classification; the `--short=7` argv literal is a typed variant of
/// [`HeadShaForm`] rather than a bare `&str` respelled at every
/// consumer. THEORY.md §VI.1 one-oracle discipline — the `rev-parse`
/// argv slice AND the expected SHA hex length live at ONE surface
/// (this enum's `args` / `expected_len` methods); a future third form
/// (e.g., `Short12` for a 12-character SHA) extends the enum at one
/// site instead of re-derived at every downstream consumer's inline
/// literal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum HeadShaForm {
    /// The 7-character short hex SHA — `git rev-parse --short=7 HEAD`.
    /// `--short=7` is explicit, not `core.abbrev`-dependent, so
    /// deployment-tag consumers inherit deterministic
    /// `{arch}-<7-char-sha>` rendering across hosts.
    ///
    /// # Source order is load-bearing
    ///
    /// [`Short7`] is declared BEFORE [`Full`] so the source-order
    /// [`PartialOrd`] / [`Ord`] derivation puts `Short7 < Full` —
    /// the "hex-length" ladder pinned by
    /// [`tests::test_head_sha_form_ord_short7_below_full`]. A future
    /// consumer that reads "the wider form outranks the narrower
    /// form" gets it from a single `>=` comparison instead of a
    /// three-arm disjunction against the [`Full`] variant. A future
    /// third variant (e.g., `Short12` for a 12-character SHA) would
    /// insert between the two here to extend the ladder without a
    /// variant-order flip at the two present consumers.
    Short7,
    /// The full 40-character hex SHA — `git rev-parse HEAD`.
    Full,
}

impl HeadShaForm {
    /// The `git rev-parse` argv slice this form spawns with. The two
    /// variants encode the exact literals every pre-lift call site
    /// respelled by hand.
    const fn args(self) -> &'static [&'static str] {
        match self {
            Self::Full => &["rev-parse", "HEAD"],
            Self::Short7 => &["rev-parse", "--short=7", "HEAD"],
        }
    }

    /// The expected hex length of the rendered SHA — 40 for
    /// [`Self::Full`], 7 for [`Self::Short7`]. Downstream length
    /// invariants (test assertions, deployment-tag renderers that
    /// slice by `expected_len()`) read this oracle instead of
    /// respelling the literal at every consumer. `#[allow(dead_code)]`
    /// on this crate is the same posture the sibling typed sums
    /// ([`crate::retry::PerAttemptRegion`]) take: `pub const fn`
    /// visibility carries the surface for future consumers (structured
    /// telemetry emitters, deployment-tag renderers) while the
    /// present-day consumers live in `#[cfg(test)]` — the
    /// `test_head_sha_form_expected_len_pins_hex_length_per_variant`
    /// / `test_git_client_sha` /
    /// `test_get_short_sha_async_in_returns_seven_char_sha` /
    /// `test_read_head_sha_async_full_variant_returns_forty_char_hex`
    /// pins read through this method rather than the `40` / `7`
    /// literals.
    #[allow(dead_code)]
    pub const fn expected_len(self) -> usize {
        match self {
            Self::Full => 40,
            Self::Short7 => 7,
        }
    }
}

/// Read the HEAD commit's SHA at `form` through `git_capture`,
/// optionally scoped to `workdir`. The composed primitive every
/// `get_{full,short}_sha[_async][_in]` public entry point delegates
/// to — the argv slice, the `"rev-parse"` op label, and the
/// stdout-string trim are named ONCE here.
fn read_head_sha(form: HeadShaForm, workdir: Option<&Path>) -> Result<String> {
    let stdout = git_capture(form.args(), workdir, "rev-parse")?;
    stdout_string(stdout)
}

/// Async sibling of [`read_head_sha`] — same argv/op/trim composition
/// through [`git_capture_async`] so the tokio consumers
/// ([`get_short_sha_async`], [`get_short_sha_async_in`]) share the
/// primitive rather than each hand-rolling the argv slice.
async fn read_head_sha_async(form: HeadShaForm, workdir: Option<&Path>) -> Result<String> {
    let stdout = git_capture_async(form.args(), workdir, "rev-parse").await?;
    stdout_string(stdout)
}

/// Get full git SHA (40 characters)
pub fn get_full_sha() -> Result<String> {
    read_head_sha(HeadShaForm::Full, None)
}

/// Get short git SHA (7 characters)
pub fn get_short_sha() -> Result<String> {
    read_head_sha(HeadShaForm::Short7, None)
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
    read_head_sha_async(HeadShaForm::Short7, None).await
}

/// Crate-scoped sigil: resolve the `RELEASE_GIT_SHA` env var with
/// empty-string-is-miss semantics. Every production site that needs
/// the release-time SHA the Nix release wrapper captures at the START
/// of the release — before any deploy commits shift HEAD — routes
/// through this ONE body, so the env-var-spelling AND the
/// empty-string-is-miss contract are honored at exactly one code line
/// across the crate.
///
/// Pre-lift three byte-equivalent stanzas —
/// `if let Ok(sha) = env::var("RELEASE_GIT_SHA") { if !sha.is_empty()
/// { return Ok(sha); } }` at `commands/push.rs::get_git_sha` and
/// `commands/rust_service.rs::get_tag_suffix`, plus the
/// `env::var("RELEASE_GIT_SHA").unwrap_or_default(); if
/// git_sha.is_empty() { bail!(...) }` at
/// `commands/product_release.rs::execute` — lived across the crate.
/// Three consumers past THEORY §VI.1's three-is-a-law threshold: the
/// trio had to agree on both the env-var spelling AND the
/// empty-string-is-miss semantic (the Nix wrapper exports the var
/// unconditionally with an empty value on non-release invocations, so
/// treating `Ok("")` as "set" would mis-route every direct-CLI call
/// into the release-tagged branch). A drift at one site (e.g., a
/// typo `RELEASE_SHA`, or the empty-check accidentally deleted)
/// would silently mis-tag one consumer's image push relative to the
/// others — and the mismatch would only surface as a deploy-time
/// tag-lookup miss with no structural link back to the SHA-resolve
/// drift.
///
/// # Empty-string-is-miss semantic
///
/// `std::env::var` returns `Ok("")` when the var is set to the empty
/// string — as the Nix release wrapper does on non-release
/// invocations. This sigil folds `Ok("")` into `None` via `.filter(|s|
/// !s.is_empty())` so the caller can `if let Some(sha) = ...` without
/// re-spelling the empty-check.
///
/// Sibling of [`crate::repo::get_environment`] on the `FORGE_ENV`
/// surface and [`crate::infrastructure::attic::attic_server_alias`]
/// on the `ATTIC_SERVER_NAME` surface — same
/// env-var-with-substrate-contract shape lifted to one body per env
/// var. THEORY §V (solve-once-at-the-primitive); §VI.1
/// (recurring-shape-to-helper).
pub fn release_git_sha_from_env() -> Option<String> {
    std::env::var("RELEASE_GIT_SHA")
        .ok()
        .filter(|s| !s.is_empty())
}

/// `workdir`-scoped sibling of [`get_short_sha_async`]. Resolves the
/// short SHA against a specific git working tree (e.g. a frontend
/// sub-repo whose codegen commit is owned by a different working
/// directory than the current process's CWD).
pub async fn get_short_sha_async_in(workdir: &Path) -> Result<String> {
    read_head_sha_async(HeadShaForm::Short7, Some(workdir)).await
}

/// The async YAML read-modify-write shell.
///
/// Reads `path` as UTF-8, parses it as a [`serde_yaml::Value`], hands
/// `mutator` a `&mut` reference so the caller can splice into the parsed
/// document in place, then serializes the (possibly-mutated) value and
/// writes it back to `path`. Every error carries `path.display()` in its
/// [`anyhow::Context`] so a Nix-hermetic runner sees the exact file that
/// failed instead of a per-consumer semantic-role label that decouples
/// from the offending path.
///
/// # Why this primitive
///
/// Pre-lift two byte-similar consumer sites in this module — [`update_manifest`]
/// (kustomization.yaml `images[].newTag` splice) and
/// [`update_configmap_git_sha`] (ConfigMap `data.GIT_SHA` splice, plus a
/// web-specific `env.js` `GIT_SHA_PLACEHOLDER` sub-replace) — each hand-
/// rolled the same five-line
/// `tokio::fs::read_to_string + .context(?) + serde_yaml::from_str +
/// .context(?) + mutate + serde_yaml::to_string + .context(?) +
/// tokio::fs::write + .context(?)` shell around their per-site mutation.
/// The two shells carried the load-bearing per-consumer envelope drift
/// this primitive redeems: the read-context strings were
/// `"Failed to read kustomization.yaml"` vs `"Failed to read ConfigMap file"`,
/// the parse-context strings were
/// `"Failed to parse kustomization.yaml as YAML"` vs
/// `"Failed to parse ConfigMap as YAML"`, the write-context strings were
/// `"Failed to write kustomization.yaml"` vs `"Failed to write ConfigMap"`
/// — a fleet-wide grep for the offending YAML site's diagnostic returned
/// six different needles, and the pre-lift per-consumer role labels
/// (`kustomization.yaml`, `ConfigMap file`, `ConfigMap`) were decoupled
/// from the actual path a Nix-hermetic runner failed on. The primitive's
/// canonical `"Failed to <op> {}", path.display()` envelope surfaces the
/// exact file on every branch by construction.
///
/// # THEORY grounding
///
/// - THEORY.md §V (solve-once-at-the-primitive): the async YAML read-
///   modify-write shell (including its canonical
///   read/parse/serialize/write envelope) now lives at exactly one code
///   line across the crate (`yaml_read_modify_write_async` at
///   `git.rs`), so every consumer observes the same envelope by
///   construction rather than by convention.
/// - THEORY.md §VI.1 (recurring-shape-to-helper): two byte-similar
///   five-line stanzas across two consumer sites in the same module,
///   each spelling the same async-fs + serde_yaml round-trip.
///
/// # Sibling primitive
///
/// Sync sibling on the version-writer frontier:
/// [`crate::version::apply_version_write`], which drives an arbitrary
/// content transformer (`FnOnce(&str, &str) -> Result<String>`) on
/// `std::fs::read_to_string` + `std::fs::write`. This primitive lifts
/// the async half of the surface and specializes on parsed-YAML in-
/// place mutation (`FnOnce(&mut serde_yaml::Value) -> Result<()>`) —
/// the shape both consumer sites already had.
async fn yaml_read_modify_write_async<F>(path: &Path, mutator: F) -> Result<()>
where
    F: FnOnce(&mut serde_yaml::Value) -> Result<()>,
{
    let content = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("Failed to read {}", path.display()))?;
    let mut yaml: serde_yaml::Value = serde_yaml::from_str(&content)
        .with_context(|| format!("Failed to parse {} as YAML", path.display()))?;
    mutator(&mut yaml).with_context(|| format!("Failed to mutate {}", path.display()))?;
    let updated = serde_yaml::to_string(&yaml)
        .with_context(|| format!("Failed to serialize {} as YAML", path.display()))?;
    crate::repo::write_text_async(path, updated).await?;
    Ok(())
}

/// Update kustomization.yaml with new image tag
/// This function updates the `images[].newTag` field in a Kustomize file
pub async fn update_manifest(manifest_path: &Path, _old_tag: &str, new_tag: &str) -> Result<()> {
    let new_tag = new_tag.to_string();
    yaml_read_modify_write_async(manifest_path, move |yaml| {
        if let Some(images) = yaml.get_mut("images").and_then(|v| v.as_sequence_mut()) {
            for image in images {
                if let Some(new_tag_field) = image.get_mut("newTag") {
                    *new_tag_field = serde_yaml::Value::String(new_tag.clone());
                }
            }
        } else {
            anyhow::bail!("No 'images' section found in kustomization.yaml");
        }
        Ok(())
    })
    .await
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

    let is_web = service_name == "web";
    let git_sha = git_sha.to_string();
    yaml_read_modify_write_async(&config_map_path, move |yaml| {
        if let Some(data) = yaml.get_mut("data").and_then(|v| v.as_mapping_mut()) {
            data.insert(
                serde_yaml::Value::String("GIT_SHA".to_string()),
                serde_yaml::Value::String(git_sha.clone()),
            );

            // For web service, also replace GIT_SHA_PLACEHOLDER in env.js
            if is_web {
                if let Some(env_js) = data.get_mut(&serde_yaml::Value::String("env.js".to_string()))
                {
                    if let Some(env_js_str) = env_js.as_str() {
                        let updated_env_js = env_js_str.replace("GIT_SHA_PLACEHOLDER", &git_sha);
                        *env_js = serde_yaml::Value::String(updated_env_js);
                    }
                }
            }
        } else {
            anyhow::bail!("No 'data' section found in ConfigMap");
        }
        Ok(())
    })
    .await
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
///
/// Retained as the per-tag boundary projection at the git-tag surface for a
/// future consumer that already holds a rendered `<prefix>X.Y.Z` string and
/// asks a ONE-tag existence question (an FFI boundary reading a specific tag
/// off a JSON payload, a probe of "does the exact tag `v1.4.0` exist yet"
/// against a fixed literal, an admin CLI that verifies a caller-supplied tag).
/// Post the joint typed peer [`released_semver_tags_typed`] landing, the sole
/// production caller (`commands/gem.rs::bump`'s `seed_from_tags` arm) reads
/// tag membership off the joint scan's `BTreeSet<SemverTriple>` directly —
/// pure, allocation-free, and TOTAL — so this per-tag primitive is currently
/// unreferenced inside the crate: hence `#[allow(dead_code)]` to name the
/// retention as intentional under the `pub`-fn dead-code lint the `bin`-crate
/// build applies, same discipline the sibling stringly `max_released_version`,
/// `next_free_version`, and `next_free_version_typed` boundary projections
/// already carry.
#[allow(dead_code)]
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
///
/// Retains the stringly return signature for the existing production caller
/// (`commands/gem.rs` reads the value as a `&str` and pipes it into the
/// stringly [`crate::version::next_free_version`] entry point), and delegates
/// through [`max_released_version_typed`] at the entry point. The
/// prefix-strip, per-tag parse, and `>` fold all live at ONE body — the
/// typed peer below — and the stringly return here is the boundary
/// projection: `.map(|t| t.to_string()).unwrap_or_default()`, so `None`
/// (no matching tag) becomes the empty-string sentinel every existing
/// caller already handles. Same THEORY.md §V.4 typed-primitive discipline
/// the version.rs surface established across
/// `parse_semver` / `parse_semver_typed`,
/// `bump_semver` / `bump_semver_typed`,
/// `bump_seed` / `bump_seed_typed`, and
/// `next_free_version` / `next_free_version_typed` — here applied to the
/// git-tag-scan primitive that feeds them.
///
/// Retained as the stringly boundary projection at the git-tag-scan
/// surface for a future consumer that already speaks `&str` (an FFI
/// boundary that reads the highest tag off a JSON payload, a
/// telemetry emitter that logs the winner as a string, a
/// `HashMap<String, ...>` keyed by rendered tag). Post the
/// b3527d3 lift, the sole production caller
/// (`commands/gem.rs::bump`'s `seed_from_tags` arm) routes through
/// [`max_released_version_typed`] directly, so this wrapper is
/// currently unreferenced inside the crate — hence
/// `#[allow(dead_code)]` to name the retention as intentional under
/// the `pub`-fn dead-code lint the `bin`-crate build applies.
#[allow(dead_code)]
pub fn max_released_version(prefix: &str, workdir: Option<&Path>) -> Result<String> {
    Ok(max_released_version_typed(prefix, workdir)?
        .map(|t| t.to_string())
        .unwrap_or_default())
}

/// The typed-primitive peer of [`max_released_version`]: the same
/// `<prefix>X.Y.Z`-tag scan, but returns `Option<SemverTriple>` at the
/// boundary rather than re-projecting the winner to a `String` and letting
/// the caller re-parse it.
///
/// # Why the typed peer
///
/// The stringly [`max_released_version`] tracked the running best as an
/// `Option<SemverTriple>` internally (for the derived-`Ord` discipline
/// the fold needs), then re-projected the winner to a `String` at the
/// return, discarding the typed triple the fold had just produced. Every
/// downstream consumer that reasoned over the return either compared it
/// against the empty-string sentinel (`if !max_released.is_empty()`) or
/// re-parsed it back to a typed triple inside
/// [`crate::version::next_free_version_typed`], redeeming a
/// [`SemverTriple`] the primitive had already computed. The typed peer
/// exposes the typed winner at the boundary so:
/// - the "no released tag yet" state is a `None` at the type level, not
///   a `""` sentinel string a future consumer might forget to check for;
/// - a downstream caller that already holds a typed [`SemverTriple`]
///   pipes it straight into
///   [`crate::version::bump_seed_typed`] /
///   [`crate::version::next_free_version_typed`] without a
///   `to_string()` → parse round-trip;
/// - the derived-`Ord` semver-lex discipline named at
///   [`SemverTriple`]'s field declaration order flows through the
///   boundary rather than being redeemed at every consumer.
///
/// The stringly [`max_released_version`] retains its `String` return for
/// the existing production caller (`commands/gem.rs`), and delegates
/// through this typed peer, so the prefix-strip, per-tag parse, and
/// `parsed > b` fold live at ONE body — this one — and both entry points
/// route through it. Same THEORY.md §VI.1 one-oracle discipline the
/// sibling `parse_semver_typed`, `bump_semver_typed`, `bump_seed_typed`,
/// and `next_free_version_typed` typed peers already established across
/// the version.rs release-arithmetic surface, here applied to the
/// git-tag-scan primitive at the source of the seed decision.
pub fn max_released_version_typed(
    prefix: &str,
    workdir: Option<&Path>,
) -> Result<Option<crate::version::SemverTriple>> {
    // Delegate through [`released_semver_tags_typed`] — the fully-typed
    // scanner that carries the ONE `git tag --list <prefix>*` fetch and
    // the parse/fold over its listing. `BTreeSet<SemverTriple>` is
    // sorted by [`crate::version::SemverTriple`]'s derived `Ord`
    // (semver-lex over the field declaration order `major, minor,
    // patch`), so `.iter().next_back().copied()` reads the highest
    // element in O(log n) and preserves the numeric-ordering discipline
    // this primitive was added to close — the pre-delegation
    // `parsed > b` fold and the delegated set's `next_back()` name the
    // same ordering rule at exactly ONE site (`SemverTriple`'s field
    // declaration order).
    Ok(released_semver_tags_typed(prefix, workdir)?
        .iter()
        .next_back()
        .copied())
}

/// The fully-typed scan of `<prefix>X.Y.Z` git tags: ONE
/// `git tag --list <prefix>*` fetch, ONE
/// [`crate::version::parse_semver_typed`] parse per listing line, and
/// the parseable winners collected into a [`BTreeSet`] whose derived
/// ordering matches [`crate::version::SemverTriple`]'s field-declared
/// `Ord` (semver-lex over `major, minor, patch`).
///
/// # Why the joint peer
///
/// Every consumer that seeds a bump from released tags used to fire
/// TWO git spawns per invocation on the fast path and up to
/// `1 + 1024` on the pathological path: one
/// `git tag --list <prefix>*` at [`max_released_version_typed`] to
/// pick the seed's high-water mark, then one
/// `git tag --list <prefix><candidate>` per collision-loop iteration
/// at [`crate::version::next_free_version_all_typed`]'s
/// `tag_exists` predicate — with the per-iteration lookup rebuilding
/// the tag string via `format!("<prefix>{t}")` and swallowing the
/// git-capture error via `.unwrap_or(false)` (so a git-binary failure
/// silently promoted a real published tag to "does not exist" and
/// let the loop bump straight into a collision, which is exactly how
/// `commands/gem.rs::bump`'s `seed_from_tags` arm used to consume the
/// scan).
///
/// The joint peer collapses both derived values (the numeric max, the
/// exhaustive membership set) onto ONE `git tag --list` fetch and
/// carries them through a pure, allocation-free predicate the
/// collision loop consumes without a fallible boundary. The
/// consumer's tag-exists closure becomes
/// `|t: SemverTriple| set.contains(&t)`: pure, total, and O(log n)
/// per iteration on the [`BTreeSet`], with the git-capture error
/// propagated at the ONE fetch site rather than silently redeemed at
/// every loop iteration.
///
/// # Boundary discipline
///
/// [`max_released_version_typed`] retains its `Option<SemverTriple>`
/// return signature and delegates through this joint peer (a
/// `.iter().next_back().copied()` projection at the boundary), so the
/// tag-scan lives at ONE body — this one — and both entry points
/// route through it. Same THEORY.md §VI.1 one-oracle discipline the
/// sibling `parse_semver_typed`, `bump_semver_typed`, `bump_seed_typed`,
/// `next_free_version_all_typed`, and `max_released_version_typed`
/// typed peers already established across the release-arithmetic
/// surface, here applied to the git-tag-scan primitive at the source
/// of the seed AND collision decisions in ONE fetch.
///
/// THEORY.md §V.4 typed primitives: the git-tag-scan surface now
/// carries a fully typed peer (typed prefix, typed set of triples out)
/// — not a `(&str, Option<&Path>) -> Result<String>` shape that a
/// future consumer would re-scan for both the max AND the membership
/// set at two separate spawns.
pub fn released_semver_tags_typed(
    prefix: &str,
    workdir: Option<&Path>,
) -> Result<std::collections::BTreeSet<crate::version::SemverTriple>> {
    let pattern = format!("{}*", prefix);
    let stdout = git_capture(&["tag", "--list", &pattern], workdir, "tag --list")?;
    let listing = String::from_utf8_lossy(&stdout);

    // Collect into a `BTreeSet` rather than a `HashSet`: the derived
    // `Ord` on `SemverTriple` (semver-lex over field declaration
    // order) is exactly the ordering the `max_released_version_typed`
    // delegator reads at `.iter().next_back()`, so the ONE scan
    // yields both derived values (numeric max, membership set) from
    // the SAME sorted structure — no separate fold over the listing,
    // no per-element `.max()` on the boundary. Tags that do not
    // parse as exact `X.Y.Z` (release candidates, dated tags, `v1.2`)
    // are SKIPPED rather than failing the read — same rule the
    // pre-delegation `parse_semver_typed`-in-fold applied, retained
    // here so a repo that carries other tag shapes still reads.
    let mut set = std::collections::BTreeSet::new();
    for line in listing.lines() {
        let tag = line.trim();
        let Some(candidate) = tag.strip_prefix(prefix) else {
            continue;
        };
        let Ok(parsed) = crate::version::parse_semver_typed(candidate) else {
            continue;
        };
        set.insert(parsed);
    }
    Ok(set)
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

/// Best-effort discard-status sibling of [`git_command_sync`]: build a
/// `git <args>` spawn rooted at `current_dir`, wait for the child via
/// `.status()`, then DISCARD the
/// `std::io::Result<std::process::ExitStatus>` entirely — swallow every
/// failure (spawn `io::Error`, non-zero exit, signal termination),
/// return `()`. The unit return type is load-bearing: a caller cannot
/// silently promote it into a control-flow position because the
/// primitive has no envelope to inspect, closing the misuse surface a
/// docstring-only carve-out would leave open.
///
/// Names the "advisory git spawn honoring `GIT_BIN`" shape once so the
/// four pre-lift `let _ = crate::git::git_command_sync().args(…)
/// .current_dir(…).status();` stanzas on `commands/helm.rs::deploy`
/// (three consecutive `git add` / `git commit` / `git push` advisory
/// spawns invoked under `--commit`) and `commands/helm.rs::bump` (one
/// `git add -A <charts_dir>` fallback spawn) collapse onto ONE
/// definition. Every consumer inherits both disciplines by
/// construction: `GIT_BIN`-routing via the delegated
/// [`git_command_sync`] and best-effort-discard via the discarded
/// `.status()` — pre-lift the shape was hand-rolled and any future
/// consumer that copied a sibling was free to independently drift the
/// `GIT_BIN`-routing off (`Command::new("git")` — the exact class of
/// bug the flake-follow of pre-lift consumer sites redeemed at
/// 818ed9a / badcdf4 / 8653403 / f6be190 / 81d7486 / 8a1958e / etc.)
/// or the best-effort-discard off (a bare `.status()?` that bubbled a
/// spawn-only error out of an advisory spawn the operator can already
/// see failing on inherited stderr).
///
/// # Stdio — inherits both streams into the parent's terminal
///
/// Spawns via `.status()` rather than `.output()` — `.status()`-based
/// spawns leave stdout+stderr unset, so the child inherits both
/// streams from the parent, and the operator watching a `forge helm
/// deploy --commit` invocation SEES the git output that names why the
/// advisory `git add`/`commit`/`push` failed (dirty tree, hook
/// refusal, non-fast-forward push). Mirrors the sibling
/// [`crate::retry::run_status_discard_in_async`] stdio contract on the
/// async half of the discard-status fleet.
///
/// # When to reach for this vs the sibling primitives
///
/// This primitive is DELIBERATELY narrower than its inherited-status
/// and captured-output siblings: it does not surface stdout, exit
/// status, or the spawn envelope. It is the right choice ONLY when
/// the caller wants a silent-at-the-caller / loud-on-the-terminal
/// git invocation whose success or failure has no bearing on the
/// enclosing operation. Do NOT reach for this when:
///
/// - The caller wants the git failure surfaced into the operator's
///   error chain → route the `Command` returned by [`git_command_sync`]
///   through [`crate::retry::run_inherited_status_sync`], which raises
///   the canonical `(op, exit_code)` failure envelope through
///   [`crate::retry::classify_inherited_status`].
/// - The caller decides what to do next based on the exit code or the
///   child's stdout → use [`git_capture`]-family primitives above (or
///   the raw `.output()` shape rooted through [`git_command_sync`]).
pub fn git_status_discard_sync_in<I, S>(current_dir: impl AsRef<Path>, args: I)
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    let _ = git_command_sync()
        .args(args)
        .current_dir(current_dir.as_ref())
        .status();
}

/// `(args, op)`-front async fusion primitive over [`git_command_async`] +
/// [`crate::retry::run_inherited_status` ]for the twelve production consumers
/// that hand-fuse the three-line stanza
///
/// ```text
/// let mut <name>_cmd = crate::git::git_command_async();
/// <name>_cmd.args([...]);
/// crate::retry::run_inherited_status(<name>_cmd, "git <op>")
///     .await
///     .context("...")?;
/// ```
///
/// at the async git-mutation surface. The pre-lift sites — the `git add`
/// / `git commit` / `git push` bail-on-non-zero triples on
/// `commands/rollback.rs::execute` (2 sites: add + push; commit retains a
/// bare `.status()` per its documented "commit with nothing to commit
/// returns non-zero" idempotent-no-op carve-out),
/// `commands/push.rs::update_kustomization` (2 sites: add + push; commit
/// retains the same carve-out), `commands/rust_service.rs::
/// deploy_rust_service_with_tag` (3 sites: add + commit + push), and
/// `commands/federation.rs::deploy_federation` (5 sites: three
/// `git add` + one commit + one push, all bail-on-non-zero) — collapse
/// onto a single delegation
/// `crate::git::git_run_inherited_status(&[...], "git <op>").await?` at
/// every consumer, and every consumer inherits both disciplines by
/// construction: `GIT_BIN`-routing via the delegated
/// [`git_command_async`] and the canonical `(op, exit_code)` failure
/// envelope via the delegated [`crate::retry::run_inherited_status`].
/// Pre-lift each was hand-fused per-site; each such stanza is one place
/// a future consumer can drift the `GIT_BIN`-routing off
/// (`tokio::process::Command::new("git")` — the exact class of bug the
/// original `git_command_async` migration redeemed at 818ed9a / badcdf4
/// / 8653403 / f6be190 / 81d7486 / 8a1958e) or drift the envelope off
/// (a bare `.status().await?` that silently accepts a denied push).
///
/// # Semantics — inherited stdio, structural failure envelope
///
/// - Both stdout and stderr inherit into the parent's terminal via the
///   delegated [`crate::retry::run_inherited_status`], so the operator
///   watching a `forge push` / `forge rollback` / `forge deploy` /
///   `forge federation` invocation sees git's own output that names
///   why the mutation failed (dirty tree, hook refusal, non-fast-
///   forward push, auth denial).
/// - Spawn failure raises the canonical `"Failed to run {op}"` chain
///   (with the underlying `io::Error` as the `context` source) via
///   [`crate::retry::classify_inherited_status`]; non-zero exit raises
///   the canonical `"{op} failed (exit {code})"` chain; signal
///   termination raises the canonical `"{op} failed (killed by signal)"`
///   chain. Callers attach per-site context with
///   `.with_context(|| ...)?` on the outer chain.
///
/// # When to reach for this vs the sibling primitives
///
/// This primitive is the async status-only sibling of
/// [`crate::infrastructure::kubectl::kubectl_capture_anyhow`] (async
/// captured-output on the kubectl frontier) and of
/// [`git_status_discard_sync_in`] (sync best-effort-discard on the git
/// frontier). Do NOT reach for this when:
///
/// - The caller wants the stdout back → use one of the
///   [`git_capture`]-family primitives above.
/// - The caller is on a sync (non-tokio) code path → build the
///   `std::process::Command` through [`git_command_sync`] and dispatch
///   through [`crate::retry::run_inherited_status_sync`].
/// - The caller must configure `.current_dir(...)`, `.env(...)`, or a
///   builder-driven argv (e.g. `cmd.arg(...); if flag { cmd.arg(...); }`)
///   → keep the direct [`git_command_async`] +
///   [`crate::retry::run_inherited_status`] surface. This helper only
///   wraps the fixed-argv shape.
/// - The caller documents an idempotent "non-zero is a benign no-op"
///   carve-out (e.g. `git commit` re-run against an already-committed
///   tree) → route through the peer primitive
///   [`git_commit_idempotent`] instead, which owns the
///   spawn-then-warn-on-non-zero shape at ONE body across the crate.
pub async fn git_run_inherited_status<I, S>(args: I, op: &str) -> anyhow::Result<()>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    let mut cmd = git_command_async();
    cmd.args(args);
    crate::retry::run_inherited_status(cmd, op).await
}

/// `git commit -m <commit_msg>` that treats a non-zero exit as a benign
/// no-op — the canonical "commit with nothing to commit returns non-zero"
/// idempotency carve-out the sibling [`git_run_inherited_status`]
/// docstring explicitly names as the one case the bail-on-non-zero
/// fusion primitive is NOT for.
///
/// # Peer of [`git_run_inherited_status`] on the "warn vs bail" axis
///
/// Same [`git_command_async`] opener, same `[commit, -m, msg]` argv,
/// same inherited stdio contract as the sibling. Where
/// [`git_run_inherited_status`] delegates through
/// [`crate::retry::run_inherited_status`] and bails on non-zero via
/// [`crate::retry::classify_inherited_status`]'s
/// `(op, exit_code)` envelope, THIS primitive emits ONE canonical
/// [`tracing::warn!`] diagnostic (carrying the exit code as a
/// structured field) and returns `Ok(())`. Every consumer of the
/// idempotent-no-op carve-out now observes the SAME warning envelope
/// by construction rather than by convention — pre-lift
/// [`commands/push.rs::update_kustomization`](../commands/push.rs)
/// used `warn!(...)` on a plain string; pre-lift
/// [`commands/rollback.rs::execute`](../commands/rollback.rs) used
/// `eprintln!("{}", "...".yellow())`. Same intent, drifting shape;
/// the primitive fuses both onto ONE code line.
///
/// # `GIT_BIN` env override
///
/// The `git` binary resolves through [`git_command_async`] so a
/// Nix-hermetic runner's `GIT_BIN` override wins over ambient `PATH`
/// — same discipline every git-mutation site in forge honors.
///
/// # `stdout` / `stderr`
///
/// Both are pinned to [`std::process::Stdio::inherit`] so `git`'s own
/// commit-summary diagnostic (or the `nothing to commit, working tree
/// clean` message on the idempotent no-op path) reaches the operator
/// terminal verbatim.
///
/// # Return
///
/// Returns `Ok(())` on any exit status (success OR non-zero). Spawn
/// failures (e.g. `GIT_BIN` resolves to an absent path) bail via `?`
/// with `spawn_context` attached — a Nix-hermetic runner precondition
/// still surfaces as an operator-actionable error rather than a
/// silent-success downstream.
///
/// # When NOT to reach for this
///
/// If the caller wants a non-zero commit exit to bail (a commit that
/// MUST land — no idempotency), reach for [`git_run_inherited_status`]
/// with `["commit", "-m", msg]` instead. The two primitives sit on the
/// same async-git-mutation surface; only the failure-dispatch axis
/// separates them.
pub async fn git_commit_idempotent(commit_msg: &str, spawn_context: &str) -> anyhow::Result<()> {
    let status = git_command_async()
        .args(["commit", "-m", commit_msg])
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status()
        .await
        .with_context(|| spawn_context.to_string())?;
    if !status.success() {
        tracing::warn!(
            exit_code = ?status.code(),
            "git commit returned non-zero (may be no changes to commit)"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::GitError;

    use crate::test_support::{
        make_executable_shim, make_seeded_work_and_bare_origin, GitBinScope, GIT_BIN_ENV_LOCK,
    };

    /// Write an executable shim that pretends to be `git`. Delegates to
    /// the shared `crate::test_support::make_executable_shim` so the
    /// shim discipline (absolute-path invocation, 0o755 chmod, tempdir
    /// lifetime) lives in one place — same primitive as
    /// `nix.rs`'s `make_nix_shim` and `attic.rs`'s `make_attic_shim`.
    fn make_git_shim(body: &str) -> (tempfile::TempDir, String) {
        make_executable_shim("git", body)
    }

    /// [`yaml_read_modify_write_async`] delegates the mutation callback
    /// on a well-formed YAML round-trip: read succeeds, parse succeeds,
    /// mutator observes the parsed [`serde_yaml::Value`] tree, and the
    /// mutated form lands on disk. Pins the primitive's contract that a
    /// mutator's edits are what appears in the post-write bytes — a
    /// regression that dropped the mutator call (or serialized the pre-
    /// mutation value) would fail this test.
    #[tokio::test]
    async fn test_yaml_read_modify_write_async_delegates_mutation_and_writes_result() {
        let dir = tempfile::tempdir().expect("scratch tempdir");
        let path = dir.path().join("doc.yaml");
        std::fs::write(&path, "images:\n- name: web\n  newTag: v1.0.0\n").expect("seed");

        yaml_read_modify_write_async(&path, |yaml| {
            let images = yaml
                .get_mut("images")
                .and_then(|v| v.as_sequence_mut())
                .expect("images sequence");
            for image in images {
                if let Some(new_tag) = image.get_mut("newTag") {
                    *new_tag = serde_yaml::Value::String("v2.0.0".to_string());
                }
            }
            Ok(())
        })
        .await
        .expect("read-modify-write must succeed on a valid document");

        let written = std::fs::read_to_string(&path).expect("post-write read");
        assert!(
            written.contains("v2.0.0"),
            "mutator's splice must appear in the post-write bytes: {written:?}"
        );
        assert!(
            !written.contains("v1.0.0"),
            "pre-mutation value must not appear in the post-write bytes: {written:?}"
        );
    }

    /// [`yaml_read_modify_write_async`]'s read arm must surface a read
    /// failure with `path.display()` in the anyhow context. Pins that a
    /// Nix-hermetic runner observing the failure can grep the failing
    /// path directly out of the anyhow chain rather than needing to
    /// correlate a per-consumer semantic-role label with the offending
    /// file.
    #[tokio::test]
    async fn test_yaml_read_modify_write_async_missing_file_errors_carry_path() {
        let dir = tempfile::tempdir().expect("scratch tempdir");
        let path = dir.path().join("does-not-exist.yaml");

        let err = yaml_read_modify_write_async(&path, |_| Ok(()))
            .await
            .expect_err("missing file must fail");
        let msg = format!("{err:#}");
        assert!(
            msg.contains(&path.display().to_string()),
            "read failure must carry the offending path in the anyhow \
             chain (not a per-consumer semantic-role label decoupled \
             from the actual file): {msg:?}"
        );
        assert!(
            msg.contains("Failed to read"),
            "read failure must classify as a read failure so an operator's \
             next step is `ls` on the path, not `yamllint`: {msg:?}"
        );
    }

    /// [`yaml_read_modify_write_async`]'s parse arm must surface a
    /// parse failure with `path.display()` and a `Failed to parse ... as
    /// YAML` classifier — proves the primitive distinguishes a
    /// syntactic-YAML failure from a read failure so an operator's next
    /// step is `yamllint` on the path, not `ls` or `cat`.
    #[tokio::test]
    async fn test_yaml_read_modify_write_async_invalid_yaml_errors_carry_path() {
        let dir = tempfile::tempdir().expect("scratch tempdir");
        let path = dir.path().join("broken.yaml");
        // Unclosed flow mapping — parses as an error rather than a
        // structural warning.
        std::fs::write(&path, "{a: 1, b: 2\n").expect("seed broken YAML");

        let err = yaml_read_modify_write_async(&path, |_| Ok(()))
            .await
            .expect_err("invalid YAML must fail");
        let msg = format!("{err:#}");
        assert!(
            msg.contains(&path.display().to_string()),
            "parse failure must carry the offending path in the anyhow \
             chain: {msg:?}"
        );
        assert!(
            msg.contains("Failed to parse") && msg.contains("as YAML"),
            "parse failure must classify as a YAML parse failure so an \
             operator's next step is `yamllint` on the path, not `ls` or \
             a re-write: {msg:?}"
        );
    }

    /// A mutator that returns `Err` must bubble the error verbatim
    /// through `yaml_read_modify_write_async`'s `.context()` envelope,
    /// and no write must land on disk. Pins the primitive's contract
    /// that a mutator-refused mutation is a HARD failure — never
    /// silently discarded — and that the pre-mutation bytes remain
    /// authoritative until a successful serialize+write. A regression
    /// that swapped the `?` propagation for a `let _ = mutator(...)`
    /// would fail this test.
    #[tokio::test]
    async fn test_yaml_read_modify_write_async_mutator_error_bubbles_and_leaves_file_untouched() {
        let dir = tempfile::tempdir().expect("scratch tempdir");
        let path = dir.path().join("doc.yaml");
        let seed = "key: value\n";
        std::fs::write(&path, seed).expect("seed");

        let err =
            yaml_read_modify_write_async(&path, |_| anyhow::bail!("mutator refuses to write"))
                .await
                .expect_err("mutator error must bubble");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("mutator refuses to write"),
            "mutator error must be preserved verbatim in the anyhow \
             chain: {msg:?}"
        );
        assert!(
            msg.contains(&path.display().to_string()),
            "mutator failure must carry the offending path in the \
             anyhow chain: {msg:?}"
        );

        let on_disk = std::fs::read_to_string(&path).expect("read post-fail");
        assert_eq!(
            on_disk, seed,
            "mutator failure must leave the file byte-identical to its \
             pre-call content — a partial write on the mutator-Err path \
             would corrupt state on a re-run"
        );
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
            // Length invariant reads through the typed oracle — a
            // future third form (Short12) that extended `HeadShaForm`
            // would update `expected_len()` and this assertion at
            // the same site rather than at every hand-rolled `>= 7`
            // literal.
            assert!(sha.len() >= HeadShaForm::Short7.expected_len());
        }
    }

    // -----------------------------------------------------------------
    // try_repo_root_via_rev_parse — Option-returning sibling of
    // get_repo_root. Owns the git-side read composed of the
    // `["rev-parse", "--show-toplevel"]` argv literal, the
    // `GIT_BIN`-routed spawn (via `git_capture`), and the
    // trimmed-stdout decode. Consumed by
    // `commands/e2e.rs::resolve_repo_root` (with a cwd fallback) and
    // `commands/helm.rs::bump` (wrapping the `None` in a
    // caller-supplied `anyhow!` context).
    // -----------------------------------------------------------------

    /// Happy path: a `git` shim that prints an absolute path to stdout
    /// and exits 0 must produce a `Some(PathBuf)` equal to that path
    /// (trimmed). Uses `GIT_BIN` to route the spawn through the shim
    /// so the test is hermetic against the host `git` and does NOT
    /// depend on the process cwd being inside a git repository.
    #[test]
    fn test_try_repo_root_via_rev_parse_returns_some_on_shim_zero_exit() {
        let _guard = GIT_BIN_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let (_shim_dir, shim) =
            make_git_shim("#!/bin/sh\necho '/tmp/hermetic-fake-repo-root'\nexit 0\n");
        let _scope = GitBinScope::set(&shim);

        let root =
            try_repo_root_via_rev_parse().expect("shim exit 0 with stdout must produce Some");
        assert_eq!(root, PathBuf::from("/tmp/hermetic-fake-repo-root"));
    }

    /// Non-zero exit path: a `git` shim that exits 128 with empty
    /// stdout (the "not a git repository" shape) must collapse to
    /// `None` — the primitive's raison d'être. Pre-lift the
    /// `commands/helm.rs::bump` production site inline-spelled
    /// `.output().context("Failed to run git rev-parse")?` without
    /// checking `status.success()`, then did
    /// `String::from_utf8(stdout)?.trim().to_string()` — yielding `""`
    /// on this shape and running every downstream `git
    /// add`/`commit`/`tag` with `current_dir("")` instead of
    /// surfacing the error. Post-lift the `None` here converts at the
    /// caller's `.context(...)?` into a loud error before any
    /// downstream spawn.
    #[test]
    fn test_try_repo_root_via_rev_parse_returns_none_on_shim_non_zero_exit() {
        let _guard = GIT_BIN_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let (_shim_dir, shim) =
            make_git_shim("#!/bin/sh\necho 'fatal: not a git repository' 1>&2\nexit 128\n");
        let _scope = GitBinScope::set(&shim);

        assert_eq!(
            try_repo_root_via_rev_parse(),
            None,
            "non-zero exit with empty stdout must collapse to None"
        );
    }

    /// Spawn-failure path: pointing `GIT_BIN` at a nonexistent binary
    /// must collapse to `None` — same Option semantic as the non-zero
    /// exit path, so both classes of git failure surface identically
    /// to callers. Sibling of
    /// [`test_git_capture_exec_failed_carries_op`] on the upstream
    /// `git_capture` surface (typed `GitError::ExecFailed` there,
    /// swallowed to `None` here).
    #[test]
    fn test_try_repo_root_via_rev_parse_returns_none_on_spawn_failure() {
        let _guard = GIT_BIN_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _scope = GitBinScope::set("/nonexistent/path/to/git-binary-that-does-not-exist");

        assert_eq!(
            try_repo_root_via_rev_parse(),
            None,
            "missing git binary must collapse to None"
        );
    }

    /// UTF-8 decode failure: a `git` shim that writes an invalid
    /// UTF-8 byte to stdout and exits 0 must collapse to `None` —
    /// pins the third failure arm the primitive's `Option` semantic
    /// swallows. Same `stdout_string` discipline the internal
    /// [`read_repo_root_via_rev_parse`] helper owns; a future
    /// refactor that switched to `String::from_utf8_lossy` would
    /// silently drop this arm and reach the consumer sites with a
    /// path containing replacement characters instead of the
    /// caller's fallback.
    #[test]
    fn test_try_repo_root_via_rev_parse_returns_none_on_invalid_utf8_stdout() {
        let _guard = GIT_BIN_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        // `printf '\377'` emits the single byte 0xFF — invalid UTF-8
        // (a leading byte of a 4-byte sequence with no continuation).
        let (_shim_dir, shim) = make_git_shim("#!/bin/sh\nprintf '\\377'\nexit 0\n");
        let _scope = GitBinScope::set(&shim);

        assert_eq!(
            try_repo_root_via_rev_parse(),
            None,
            "invalid UTF-8 stdout must collapse to None"
        );
    }

    /// One-oracle invariant: [`read_repo_root_via_rev_parse`] and
    /// [`try_repo_root_via_rev_parse`] must return the SAME
    /// `PathBuf` on any input where both succeed. Pins the
    /// sibling contract that [`get_repo_root`]'s git-fallback branch
    /// and [`try_repo_root_via_rev_parse`] both delegate through
    /// ONE body — so a future refinement (e.g. an
    /// `--absolute-git-dir` fallback, a canonicalization pass, a
    /// per-attempt telemetry emit) lands at one site and reaches
    /// every consumer by construction. Pre-lift the composed
    /// `git rev-parse --show-toplevel` + trim + `PathBuf::from`
    /// shape was authored verbatim at THREE sites (`get_repo_root`,
    /// `commands/e2e.rs::resolve_repo_root`,
    /// `commands/helm.rs::bump`) — THEORY.md §VI.1's
    /// three-times-is-a-law threshold.
    #[test]
    fn test_read_repo_root_via_rev_parse_agrees_with_try_variant() {
        let _guard = GIT_BIN_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let (_shim_dir, shim) =
            make_git_shim("#!/bin/sh\necho '/tmp/hermetic-agreement-fake'\nexit 0\n");
        let _scope = GitBinScope::set(&shim);

        let via_result = read_repo_root_via_rev_parse()
            .expect("shim exit 0 must produce Ok on the Result-returning helper");
        let via_option = try_repo_root_via_rev_parse()
            .expect("shim exit 0 must produce Some on the Option-returning primitive");
        assert_eq!(
            via_result, via_option,
            "the Result-returning helper and its Option-swallowing sibling \
             MUST resolve the SAME PathBuf — they share one body"
        );
    }

    /// [`HeadShaForm::args`] returns the exact argv slice every
    /// pre-lift call site respelled by hand — pinned per variant so a
    /// future rewrite that dropped `"--short=7"` (silently widening
    /// the SHA to a host-abbrev-dependent length) fails this test
    /// rather than degrade every deployment-tag renderer downstream.
    #[test]
    fn test_head_sha_form_args_owns_rev_parse_literal_per_variant() {
        assert_eq!(HeadShaForm::Full.args(), &["rev-parse", "HEAD"]);
        assert_eq!(
            HeadShaForm::Short7.args(),
            &["rev-parse", "--short=7", "HEAD"],
        );
    }

    /// [`HeadShaForm::expected_len`] pins the hex-length oracle every
    /// consumer reads instead of respelling the `40` / `7` literals
    /// inline. A regression that flipped the two arms would fail this
    /// test before it reached the deployment-tag length invariant.
    #[test]
    fn test_head_sha_form_expected_len_pins_hex_length_per_variant() {
        assert_eq!(HeadShaForm::Full.expected_len(), 40);
        assert_eq!(HeadShaForm::Short7.expected_len(), 7);
    }

    /// The typed sum carries `PartialOrd` / `Ord` via source-order
    /// derivation so a future consumer that reads "the full form is
    /// wider than the short form" gets it from `Short7 < Full`
    /// directly. Pins the source-order invariant so a variant
    /// reordering that flipped the ladder fails this test.
    #[test]
    fn test_head_sha_form_ord_short7_below_full() {
        assert!(HeadShaForm::Short7 < HeadShaForm::Full);
        assert!(HeadShaForm::Full > HeadShaForm::Short7);
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
        // Fixture setup releases `GIT_BIN_ENV_LOCK` internally between
        // its composed spawns; we acquire it AFTER the primitive
        // returns so the async production entry point below reads a
        // stable `GIT_BIN` even under a concurrent env-var-mutating
        // test. Same caller-holds-lock-after-setup discipline every
        // `test_support::make_seeded_work_and_bare_origin` consumer
        // follows.
        let (_parent, _bare, work) = make_seeded_work_and_bare_origin();
        let _guard = GIT_BIN_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let sha = get_short_sha_async_in(&work)
            .await
            .expect("get_short_sha_async_in must succeed in a seeded repo");
        // Length invariant reads through the typed oracle
        // ([`HeadShaForm::Short7::expected_len`]) rather than the
        // literal `7` — a future variant addition that widened the
        // form would update `expected_len` and this assertion at one
        // site.
        assert_eq!(
            sha.len(),
            HeadShaForm::Short7.expected_len(),
            "--short=7 must yield a 7-character SHA, got: {sha:?}"
        );
        assert!(
            sha.chars().all(|c| c.is_ascii_hexdigit()),
            "SHA must be hex, got: {sha:?}"
        );
    }

    /// [`read_head_sha_async`] end-to-end against the real `git`
    /// binary inside a hermetic bare-work pair, exercising the
    /// [`HeadShaForm::Full`] variant. The four public entry points
    /// pre-this-commit only exposed the `Short7` variant on the async
    /// surface (`get_short_sha_async`, `get_short_sha_async_in`); the
    /// `Full` variant reached async consumers only indirectly through
    /// this primitive. Pins that the `Full` variant returns a
    /// 40-character hex SHA and that the same repo's `Short7` answer
    /// is its 7-character prefix — the reader-side agreement the
    /// typed-primitive contract encodes at
    /// [`HeadShaForm::expected_len`].
    ///
    /// `clippy::await_holding_lock` allowed: this test holds
    /// `GIT_BIN_ENV_LOCK` across the async production entry point
    /// exactly as the sibling
    /// [`test_get_short_sha_async_in_returns_seven_char_sha`] test
    /// does — the guard exists to serialize against the
    /// env-var-mutating async test
    /// (`test_no_bin_entry_points_route_through_git_bin_env_var`) so
    /// a concurrent write does not redirect the spawn to a shim
    /// mid-flight. Same rationale, same posture.
    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn test_read_head_sha_async_full_variant_returns_forty_char_hex() {
        let (_parent, _bare, work) = make_seeded_work_and_bare_origin();
        let _guard = GIT_BIN_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());

        let full = read_head_sha_async(HeadShaForm::Full, Some(&work))
            .await
            .expect("read_head_sha_async(Full) must succeed in a seeded repo");
        assert_eq!(
            full.len(),
            HeadShaForm::Full.expected_len(),
            "Full variant must yield a 40-character SHA, got: {full:?}"
        );
        assert!(
            full.chars().all(|c| c.is_ascii_hexdigit()),
            "Full SHA must be hex, got: {full:?}"
        );

        let short = read_head_sha_async(HeadShaForm::Short7, Some(&work))
            .await
            .expect("read_head_sha_async(Short7) must succeed in a seeded repo");
        assert_eq!(
            short.len(),
            HeadShaForm::Short7.expected_len(),
            "Short7 variant must yield a 7-character SHA, got: {short:?}"
        );
        assert!(
            full.starts_with(&short),
            "Short7 must be the 7-character prefix of Full at the same HEAD; \
             full = {full:?}, short = {short:?}"
        );
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
        let (parent, bare, work) = make_seeded_work_and_bare_origin();

        // `commit_and_push_in` invokes `git_capture` / `git_capture_remote`
        // — the no-bin production entry points that resolve through
        // `GIT_BIN`. Serialize against the env-mutating test. Fixture
        // setup above released its internal guard between spawns; we
        // hold the lock across the seed push and the tested primitive
        // so a concurrent env-var flip cannot redirect either.
        let _guard = GIT_BIN_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        // `commit_and_push_in` opens with `git pull origin main`, which
        // requires the bare to already carry a `main` branch — so pre-push
        // the seed commit onto origin before invoking the tested primitive.
        let seed_push = git_command_sync()
            .args(["push", "-u", "origin", "main"])
            .current_dir(&work)
            .status()
            .expect("seed push spawn");
        assert!(seed_push.success(), "seed push to bare origin must succeed");

        let manifest = work.join("kustomization.yaml");
        std::fs::write(&manifest, "images: []\n").expect("write manifest");

        commit_and_push_in(&work, &[&manifest], "Deploy round-trip pin", "main")
            .expect("commit_and_push_in must succeed");

        let probe = parent.path().join("probe");
        let subject = crate::test_support::clone_bare_and_read_head_subject(&bare, &probe);
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
        let (parent, bare, work) = make_seeded_work_and_bare_origin();

        // Same env-var race guard as the single-file sibling above:
        // hold the lock across the seed push and the tested primitive
        // so a concurrent env-var flip cannot redirect either.
        let _guard = GIT_BIN_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        // Same pre-push discipline as the single-file sibling above —
        // `commit_and_push_in`'s opening `git pull origin main` needs
        // a `main` branch on origin to fast-forward against.
        let seed_push = git_command_sync()
            .args(["push", "-u", "origin", "main"])
            .current_dir(&work)
            .status()
            .expect("seed push spawn");
        assert!(seed_push.success(), "seed push to bare origin must succeed");

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

    /// [`git_run_inherited_status`] MUST spawn its child through the
    /// canonical [`git_command_async`] constructor — i.e. it inherits
    /// the `GIT_BIN` env override the tools-registry idiom names as the
    /// hermetic-runner contract for [`tools::GIT`], and never hardcodes
    /// the literal `"git"` on the spawn path. The end-to-end shape
    /// (shim exits N, primitive surfaces exit code + op label via the
    /// anyhow chain) also pins the delegation to
    /// [`crate::retry::run_inherited_status`] — a regression that
    /// swapped the classifier for a bare `.status().await?` would drop
    /// the exit-code branch of the envelope.
    ///
    /// Runs under [`GIT_BIN_ENV_LOCK`] to serialize against every
    /// other test that either mutates `GIT_BIN` or invokes a no-bin
    /// production entry point that reads it.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_git_run_inherited_status_routes_through_git_bin_env_var() {
        let _guard = GIT_BIN_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());

        let (_shim_dir, shim) = make_git_shim(
            "#!/bin/sh\necho 'SIGIL_ROUTED_VIA_GIT_RUN_INHERITED_STATUS_b7c3a1' 1>&2\nexit 42\n",
        );
        let _scope = GitBinScope::set(&shim);

        let err = git_run_inherited_status(["push", "origin", "main"], "git push")
            .await
            .expect_err("shim exits 42");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("exit 42"),
            "git_run_inherited_status must surface the shim's exit \
             code via the anyhow message — proves the primitive \
             delegates through `retry::run_inherited_status`'s \
             `classify_inherited_status` envelope, not a bare \
             `.status().await?` that silently drops the exit code; \
             got: {msg:?}"
        );
        assert!(
            msg.contains("git push"),
            "git_run_inherited_status must surface the op label via \
             the anyhow message — proves the `(args, op)`-front \
             surface forwards `op` verbatim to \
             `retry::run_inherited_status`; got: {msg:?}"
        );
    }

    /// [`git_run_inherited_status`] MUST forward its argv slice
    /// verbatim to the spawned child. Pins the contract every consumer
    /// site depends on — pre-lift each hand-fused the argv slice via
    /// `<name>_cmd.args([...])`, so a regression that dropped,
    /// reordered, or truncated the forwarded argv would silently
    /// redirect the git mutation every deploy-frontier consumer
    /// (`commands/rollback.rs::execute`,
    /// `commands/push.rs::update_kustomization`,
    /// `commands/rust_service.rs::deploy_rust_service_with_tag`,
    /// `commands/federation.rs::deploy_federation`) depends on for
    /// control flow.
    ///
    /// The shim body prints nothing but appends every positional arg on
    /// its own line to the hermetic [`crate::test_support::ArgvLog`],
    /// then exits 0 — so the primitive's `Ok(())` return path is
    /// exercised alongside the argv round-trip. Uses `git add
    /// <deep/path/with/slash>` to prove the primitive doesn't
    /// re-tokenize its input on whitespace or path separators.
    ///
    /// Runs under [`GIT_BIN_ENV_LOCK`] to serialize against every
    /// other test that either mutates `GIT_BIN` or invokes a no-bin
    /// production entry point that reads it.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_git_run_inherited_status_forwards_args_and_returns_ok_on_zero_exit() {
        let _guard = GIT_BIN_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());

        let argv_log = crate::test_support::ArgvLog::reserve();
        let (_shim_dir, shim) = make_git_shim(&argv_log.shim_body(""));
        let _scope = GitBinScope::set(&shim);

        git_run_inherited_status(["add", "deploy/service.artifact.json"], "git add")
            .await
            .expect("zero-exit shim must surface as Ok(())");

        let logged = argv_log.read_argv_log();
        let lines: Vec<&str> = logged.lines().collect();
        assert_eq!(
            lines,
            vec!["add", "deploy/service.artifact.json"],
            "git_run_inherited_status must forward every argv slice \
             element verbatim to the spawned git — proves the \
             `(args, op)`-front surface routes `args` through the \
             delegated `git_command_async().args(args)` at exactly one \
             body, not re-tokenized on whitespace or path separators"
        );
    }

    /// A spawn `Err` (`GIT_BIN` resolves to a nonexistent path) MUST
    /// bail with the canonical `"Failed to spawn {op}: {io_error}"`
    /// envelope — the SPAWN arm of
    /// [`crate::retry::classify_inherited_status`]. Pins the shape
    /// every consumer site depends on for the "developer has no `git`
    /// on PATH / GIT_BIN points at an absent Nix derivation"
    /// precondition to surface as an operator-actionable error rather
    /// than a downstream silent-success against an unstaged /
    /// uncommitted / unpushed tree.
    ///
    /// Runs under [`GIT_BIN_ENV_LOCK`] to serialize against every
    /// other test that either mutates `GIT_BIN` or invokes a no-bin
    /// production entry point that reads it.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_git_run_inherited_status_spawn_error_carries_op() {
        let _guard = GIT_BIN_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _scope = GitBinScope::set(
            "/nonexistent/dir/absolutely-not-a-git-binary-forge-run-inherited-status-shim",
        );

        let err = git_run_inherited_status(["push", "origin", "main"], "git push")
            .await
            .expect_err("unresolvable GIT_BIN must produce Err");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("Failed to run git push"),
            "canonical spawn-failure envelope `\"Failed to run \
             {{op}}\"` from `retry::classify_inherited_status` must \
             carry the op label, got: {msg}"
        );
    }

    /// [`git_commit_idempotent`] MUST spawn its child through the
    /// canonical [`git_command_async`] constructor — i.e. it inherits
    /// the `GIT_BIN` env override the tools-registry idiom names as
    /// the hermetic-runner contract for [`tools::GIT`], and never
    /// hardcodes the literal `"git"` on the spawn path. The end-to-end
    /// shape (shim exits 0, primitive returns `Ok(())`) also pins the
    /// argv fixed-shape (`["commit", "-m", <msg>]`) and the
    /// stdio-inherit contract to the sibling
    /// [`test_git_run_inherited_status_forwards_args_and_returns_ok_on_zero_exit`].
    ///
    /// Runs under [`GIT_BIN_ENV_LOCK`] to serialize against every
    /// other test that either mutates `GIT_BIN` or invokes a no-bin
    /// production entry point that reads it.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_git_commit_idempotent_routes_through_git_bin_and_forwards_argv() {
        let _guard = GIT_BIN_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());

        let argv_log = crate::test_support::ArgvLog::reserve();
        let (_shim_dir, shim) = make_git_shim(&argv_log.shim_body(""));
        let _scope = GitBinScope::set(&shim);

        git_commit_idempotent(
            "chore: forge test commit message",
            "spawn ctx (unused on zero exit)",
        )
        .await
        .expect("zero-exit shim must surface as Ok(())");

        let logged = argv_log.read_argv_log();
        let lines: Vec<&str> = logged.lines().collect();
        assert_eq!(
            lines,
            vec!["commit", "-m", "chore: forge test commit message"],
            "git_commit_idempotent must forward the fixed \
             `[\"commit\", \"-m\", <msg>]` argv verbatim to the \
             GIT_BIN-resolved shim — proves the primitive routes \
             through `git_command_async().args([...])` at exactly one \
             body and does not re-tokenize the message on whitespace"
        );
    }

    /// [`git_commit_idempotent`] MUST surface a non-zero exit as
    /// `Ok(())` (the idempotent-no-op carve-out). Pins the
    /// carve-out's whole contract: a shim exiting non-zero — the
    /// exact "nothing to commit" scenario the sibling
    /// [`git_run_inherited_status`] docstring names as the case NOT
    /// to reach for that primitive — must NOT bail here. A regression
    /// that swapped the body's `if !status.success()` warn arm for a
    /// `bail!` or an `?` on the status would fail this test with the
    /// `expect_err`-shaped assertion inverted.
    ///
    /// Runs under [`GIT_BIN_ENV_LOCK`] to serialize against every
    /// other test that either mutates `GIT_BIN` or invokes a no-bin
    /// production entry point that reads it.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_git_commit_idempotent_non_zero_exit_is_ok() {
        let _guard = GIT_BIN_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());

        // Shim exits 1 to mimic `git commit` on a clean tree
        // ("nothing to commit, working tree clean" → exit 1).
        let (_shim_dir, shim) = make_git_shim("#!/bin/sh\nexit 1\n");
        let _scope = GitBinScope::set(&shim);

        git_commit_idempotent(
            "chore: forge idempotent no-op",
            "spawn ctx (unused on non-zero)",
        )
        .await
        .expect(
            "git_commit_idempotent must surface a non-zero exit as \
                 `Ok(())` — the idempotent-no-op carve-out; a regression \
                 that bailed would fail here",
        );
    }

    /// [`git_commit_idempotent`] MUST bail on a spawn failure
    /// (`GIT_BIN` resolves to an absent path) with the caller's
    /// `spawn_context` attached to the anyhow chain. Pins the
    /// carve-out's OTHER contract: the child never runs because the
    /// binary can't spawn at all — a Nix-hermetic-runner precondition
    /// must surface as an operator-actionable error rather than a
    /// silent-success downstream against an unmutated tree.
    ///
    /// Runs under [`GIT_BIN_ENV_LOCK`] to serialize against every
    /// other test that either mutates `GIT_BIN` or invokes a no-bin
    /// production entry point that reads it.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_git_commit_idempotent_spawn_error_carries_context() {
        let _guard = GIT_BIN_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _scope = GitBinScope::set(
            "/nonexistent/dir/absolutely-not-a-git-binary-forge-commit-idempotent-shim",
        );

        let err = git_commit_idempotent(
            "chore: forge unresolvable-bin probe",
            "Failed to commit forge-idempotent-spawn-probe canary",
        )
        .await
        .expect_err("unresolvable GIT_BIN must produce Err");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("Failed to commit forge-idempotent-spawn-probe canary"),
            "git_commit_idempotent must attach the caller's `spawn_context` \
             to the anyhow chain on spawn failure — proves the primitive \
             routes through `.with_context(|| ...)` on the `.status().await` \
             `Err` branch, so a Nix-hermetic runner precondition surfaces \
             as an operator-actionable error rather than a silent success \
             downstream against an uncommitted tree. got: {msg:?}"
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

    /// [`git_status_discard_sync_in`] MUST spawn its child through the
    /// canonical [`git_command_sync`] constructor — i.e. it inherits
    /// the `GIT_BIN` env override the tools-registry idiom names as
    /// the hermetic-runner contract for [`tools::GIT`], and never
    /// hardcodes the literal `"git"` on the spawn path.
    ///
    /// End-to-end arm: sets `GIT_BIN` to a shim that appends its
    /// positional args to an [`crate::test_support::ArgvLog`]-owned
    /// hermetic `argv.log`, then invokes
    /// `git_status_discard_sync_in` with a fixed argv slice; asserts
    /// the log content is the exact argv slice, line-per-arg. The
    /// spawn is DELIBERATELY end-to-end (not just a static
    /// `Command::get_program()` check) so a regression that "tidied"
    /// the primitive back to `Command::new("git")` would fail the
    /// argv round-trip against the shim — the PATH-resolved `git`
    /// would either refuse the `not-a-real-subcommand` argv or the
    /// unresolvable working directory below, and the shim's write to
    /// the hermetic log would not appear.
    ///
    /// Runs under [`GIT_BIN_ENV_LOCK`] to serialize against every
    /// other test that either mutates `GIT_BIN` or invokes a no-bin
    /// production entry point that reads it.
    #[cfg(unix)]
    #[test]
    fn test_git_status_discard_sync_in_routes_through_git_bin_env_var() {
        let _guard = GIT_BIN_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());

        let argv_log = crate::test_support::ArgvLog::reserve();
        let (_shim_dir, shim) = make_git_shim(&argv_log.shim_body(""));
        let _scope = GitBinScope::set(&shim);

        let cwd = tempfile::tempdir().expect("cwd tempdir");
        git_status_discard_sync_in(cwd.path(), ["add", "kustomization.yaml"]);

        let logged = argv_log.read_argv_log();
        let lines: Vec<&str> = logged.lines().collect();
        assert_eq!(
            lines,
            vec!["add", "kustomization.yaml"],
            "argv.log must round-trip the caller's argv slice verbatim, \
             one line per positional arg — proves the primitive spawns \
             the GIT_BIN-resolved shim and forwards args unchanged"
        );
    }

    /// [`git_status_discard_sync_in`] MUST invoke its child with the
    /// supplied `current_dir` set as the child's working directory.
    ///
    /// A shim body appends `PWD:$PWD` as the first log line so the
    /// test can distinguish the working directory the child observed
    /// from the process-wide cwd. `current_dir` is the tempdir's
    /// canonical path (canonicalize resolves `/tmp` symlinks on
    /// darwin/linux); the shim's `$PWD` is compared against the same
    /// canonicalization on both sides.
    ///
    /// Runs under [`GIT_BIN_ENV_LOCK`] to serialize against every
    /// other test that either mutates `GIT_BIN` or invokes a no-bin
    /// production entry point that reads it.
    #[cfg(unix)]
    #[test]
    fn test_git_status_discard_sync_in_uses_supplied_current_dir() {
        let _guard = GIT_BIN_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());

        let log_dir = tempfile::tempdir().expect("log tempdir");
        let log_path = log_dir.path().join("pwd.log");
        let (_shim_dir, shim) = make_git_shim(&format!(
            "#!/bin/sh\nprintf '%s\\n' \"PWD:$PWD\" >> '{}'\nexit 0\n",
            log_path.display()
        ));
        let _scope = GitBinScope::set(&shim);

        let cwd_dir = tempfile::tempdir().expect("cwd tempdir");
        let cwd = std::fs::canonicalize(cwd_dir.path()).expect("canonicalize cwd tempdir");
        git_status_discard_sync_in(&cwd, ["status", "--short"]);

        let logged = std::fs::read_to_string(&log_path).expect("read pwd log");
        let trimmed = logged.trim_end_matches('\n');
        assert_eq!(
            trimmed,
            format!("PWD:{}", cwd.display()),
            "child's $PWD must equal the caller's supplied current_dir \
             (canonicalized), not the process-wide cwd — proves the \
             primitive threads `current_dir` through to the spawn"
        );
    }

    /// [`git_status_discard_sync_in`] MUST discard a non-zero exit
    /// status without panicking or bailing. The pre-lift call sites
    /// invoked the sync spawn with `let _ = …status();` so a
    /// non-zero exit from `git add`/`commit`/`push` under the
    /// advisory `--commit` flag never bubbled up as an error; the
    /// primitive must preserve that best-effort semantics by
    /// construction.
    ///
    /// Uses a shim exiting 77 (arbitrary non-zero, not a common
    /// git failure code, so a false-match against an accidental
    /// PATH-resolved `git` is easy to spot). The primitive's `()`
    /// return type gives the assertion its shape: if the body ever
    /// grew a `.expect(…)` or `.unwrap()` on the discarded
    /// `.status()` result, this test would panic instead of
    /// returning cleanly.
    ///
    /// Runs under [`GIT_BIN_ENV_LOCK`] to serialize against every
    /// other test that either mutates `GIT_BIN` or invokes a no-bin
    /// production entry point that reads it.
    #[cfg(unix)]
    #[test]
    fn test_git_status_discard_sync_in_discards_non_zero_exit() {
        let _guard = GIT_BIN_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());

        let (_shim_dir, shim) = make_git_shim("#!/bin/sh\nexit 77\n");
        let _scope = GitBinScope::set(&shim);

        let cwd = tempfile::tempdir().expect("cwd tempdir");
        // No `.expect(…)`, no `?` — the returned `()` is the whole
        // contract. A regression that bailed on non-zero would
        // panic here (the primitive returns `()`, not
        // `anyhow::Result<()>`).
        git_status_discard_sync_in(cwd.path(), ["push"]);
    }

    /// [`git_status_discard_sync_in`] MUST discard a spawn failure
    /// (`fork+exec` failed — `GIT_BIN` resolves to a path that
    /// doesn't exist) without panicking or bailing. Same best-effort
    /// discipline as [`test_git_status_discard_sync_in_discards_non_zero_exit`],
    /// but exercises the OTHER failure branch: the child never runs
    /// because the binary can't spawn at all.
    ///
    /// The `GitBinScope::set("/nonexistent/git-binary-that-does-not-exist")`
    /// forces the `Command::new(get_tool_path(tools::GIT))` resolution
    /// to a path guaranteed absent; the `.status()` call then returns
    /// `Err(io::Error)`. The primitive's `let _ = …` binding must
    /// swallow it silently — a `.expect(…)` would panic here.
    ///
    /// Runs under [`GIT_BIN_ENV_LOCK`] to serialize against every
    /// other test that either mutates `GIT_BIN` or invokes a no-bin
    /// production entry point that reads it.
    #[test]
    fn test_git_status_discard_sync_in_discards_spawn_failure() {
        let _guard = GIT_BIN_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());

        let _scope = GitBinScope::set("/nonexistent/git-binary-that-does-not-exist-9a4c2f");

        let cwd = tempfile::tempdir().expect("cwd tempdir");
        // No `.expect(…)`, no `?` — a regression that bailed on
        // spawn failure would panic here (the primitive returns
        // `()`, not `anyhow::Result<()>`).
        git_status_discard_sync_in(cwd.path(), ["push"]);
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

    /// Serial-safe guard for tests that mutate the `RELEASE_GIT_SHA`
    /// process env var. [`release_git_sha_from_env`] reads it once
    /// per call; concurrent tests that set / remove it would race the
    /// resolved value observed by any test asserting on the
    /// primitive's return. Same `unwrap_or_else(|p| p.into_inner())`
    /// recovery shape as [`crate::test_support::GIT_BIN_ENV_LOCK`]
    /// and [`crate::test_support::ROOT_FLAKE_ENV_LOCK`] so a prior
    /// panicking test that poisoned the mutex does not chain-fail
    /// every subsequent test sharing the lock.
    static RELEASE_GIT_SHA_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// [`release_git_sha_from_env`] returns `None` when the
    /// `RELEASE_GIT_SHA` env var is unset. Pins the "unset is a
    /// miss" contract — every pre-lift consumer
    /// (`commands/push.rs::get_git_sha`,
    /// `commands/rust_service.rs::get_tag_suffix`,
    /// `commands/product_release.rs::execute`) skipped the
    /// release-tag branch when the var was unset, so a drift here
    /// (e.g., a Some("") shim, or a panic-on-VarError) would
    /// mis-route every direct-CLI call into the release-tagged
    /// branch and silently mis-tag its image push.
    #[test]
    fn test_release_git_sha_from_env_none_when_unset() {
        let _guard = RELEASE_GIT_SHA_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let _snapshot = crate::test_support::EnvVarSnapshot::capture("RELEASE_GIT_SHA");
        std::env::remove_var("RELEASE_GIT_SHA");
        assert_eq!(release_git_sha_from_env(), None);
    }

    /// [`release_git_sha_from_env`] returns `None` when the
    /// `RELEASE_GIT_SHA` env var is set to the empty string — the
    /// exact shape the Nix release wrapper exports on non-release
    /// invocations. Pins the empty-string-is-miss contract that
    /// every pre-lift consumer spelled inline via `if !sha.is_empty()
    /// { return Ok(sha); }` or `if git_sha.is_empty() { bail!(...) }`.
    /// A drift here (deleting the `.filter(|s| !s.is_empty())`
    /// clause) would let a wrapper-exported empty value through as
    /// `Some("")`, and downstream image tags would render with a
    /// bare `amd64-` suffix rather than a real SHA — silently
    /// clobbering the `amd64-latest` moving tag on every direct-CLI
    /// call.
    #[test]
    fn test_release_git_sha_from_env_none_when_empty() {
        let _guard = RELEASE_GIT_SHA_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let _snapshot = crate::test_support::EnvVarSnapshot::capture("RELEASE_GIT_SHA");
        std::env::set_var("RELEASE_GIT_SHA", "");
        assert_eq!(release_git_sha_from_env(), None);
    }

    /// [`release_git_sha_from_env`] returns `Some(value)` verbatim
    /// when `RELEASE_GIT_SHA` is set to a non-empty value. Pins the
    /// no-canonicalization read path — a future refactor (e.g., a
    /// lowercase hook, a `--short=7` truncator, a "known length only"
    /// filter) is caught here rather than at the consumer's
    /// downstream image-tag composition — where a silently-rewritten
    /// SHA would surface only as a deploy-time tag-lookup miss.
    #[test]
    fn test_release_git_sha_from_env_some_when_set() {
        let _guard = RELEASE_GIT_SHA_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let _snapshot = crate::test_support::EnvVarSnapshot::capture("RELEASE_GIT_SHA");
        std::env::set_var("RELEASE_GIT_SHA", "abc1234");
        assert_eq!(release_git_sha_from_env(), Some("abc1234".to_string()));
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

    /// Every listing that yields a non-empty `String` from the stringly
    /// entry point must yield the byte-equal typed triple through
    /// `Display` from the typed peer, and every listing that yields the
    /// empty-string sentinel from the stringly entry point must yield
    /// `None` from the typed peer. Pins that the delegation
    /// `max_released_version → max_released_version_typed
    /// .map(|t| t.to_string()).unwrap_or_default()` never drifts —
    /// specifically that no representative shape crosses the None ↔
    /// non-empty boundary asymmetrically.
    #[test]
    fn typed_and_stringly_max_released_version_agree_at_every_representative_shape() {
        let _guard = GIT_BIN_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        for (label, listing, prefix) in [
            ("numeric-lex ordering", "v0.3.0\\nv0.3.1\\nv0.10.0\\n", "v"),
            (
                "non-exact tags skipped",
                "v1.2\\nv2.0.0-rc1\\nvNOPE\\nv0.1.0\\nv0.1.0.1\\n",
                "v",
            ),
            ("empty listing → empty / None", "", "v"),
            ("prefix mismatch → empty / None", "nightly\\nlatest\\n", "v"),
            (
                "non-v prefix",
                "release-1.4.0\\nrelease-1.10.0\\n",
                "release-",
            ),
            (
                "surrounding whitespace tolerated",
                "  v0.2.0  \\n\\nv0.5.0\\n  \\n",
                "v",
            ),
        ] {
            let (_d, shim) = git_listing_shim(listing);
            let _scope = GitBinScope::set(&shim);
            let by_str = max_released_version(prefix, None).unwrap();
            let by_typed = max_released_version_typed(prefix, None).unwrap();
            let projected = by_typed.map(|t| t.to_string()).unwrap_or_default();
            assert_eq!(
                by_str, projected,
                "{label}: stringly return must byte-equal Display of typed peer"
            );
            assert_eq!(
                by_str.is_empty(),
                by_typed.is_none(),
                "{label}: empty-string sentinel must correspond to None"
            );
        }
    }

    /// The typed peer returns the actual [`crate::version::SemverTriple`]
    /// value, not just the `Display`-equivalent string. Pins that a
    /// downstream caller destructuring `Some(SemverTriple { major,
    /// minor, patch })` reads the field values the tag decoded to,
    /// rather than needing to re-parse the projected string.
    #[test]
    fn typed_max_released_version_returns_semver_triple_fields_not_just_display() {
        let _guard = GIT_BIN_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let (_d, shim) = git_listing_shim("v0.3.0\\nv0.3.1\\nv0.10.0\\n");
        let _scope = GitBinScope::set(&shim);
        let winner = max_released_version_typed("v", None)
            .unwrap()
            .expect("v0.10.0 is the numeric max, not None");
        assert_eq!(winner.major, 0);
        assert_eq!(winner.minor, 10);
        assert_eq!(winner.patch, 0);
    }

    /// The empty-listing case is `None` at the type level, so a
    /// downstream typed caller distinguishes "no released tag" from
    /// "released 0.0.0" without the empty-string convention every
    /// caller had to remember. Pins the primary reason the typed peer
    /// exists — the sentinel-as-type lift.
    #[test]
    fn typed_max_released_version_yields_none_not_zero_when_no_matching_tag() {
        let _guard = GIT_BIN_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let (_d, shim) = git_listing_shim("");
        let _scope = GitBinScope::set(&shim);
        assert!(
            max_released_version_typed("v", None).unwrap().is_none(),
            "no matching tag is None, distinct from Some(0.0.0)"
        );

        let (_d2, shim2) = git_listing_shim("v0.0.0\\n");
        let _scope2 = GitBinScope::set(&shim2);
        assert_eq!(
            max_released_version_typed("v", None).unwrap(),
            Some(crate::version::SemverTriple::new(0, 0, 0)),
            "an explicit v0.0.0 tag reads as Some(0.0.0), distinct from None"
        );
    }

    /// The `parsed > b` fold on the typed peer is a semver-lex
    /// comparison via `SemverTriple`'s derived `Ord`, not a
    /// lexicographic comparison on the stringly projection. Pins the
    /// numeric-ordering rule (the ORIGINAL bug the primitive was
    /// added to close) is honored by the typed peer directly, not
    /// merely by the stringly delegator.
    #[test]
    fn typed_max_released_version_folds_via_semver_lex_ord_not_string_lex() {
        let _guard = GIT_BIN_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        // Lexicographically "0.3.1" > "0.10.0", so a string-lex fold
        // would pick 0.3.1 and the released-version reader would seed
        // the next bump BEHIND a published tag.
        let (_d, shim) = git_listing_shim("v0.3.0\\nv0.3.1\\nv0.10.0\\n");
        let _scope = GitBinScope::set(&shim);
        let winner = max_released_version_typed("v", None)
            .unwrap()
            .expect("0.10.0 exists in the listing");
        assert_eq!(
            winner,
            crate::version::SemverTriple::new(0, 10, 0),
            "typed fold must pick 0.10.0 over 0.3.1 via derived Ord"
        );
    }

    /// Every representative listing must yield the same numeric max
    /// through the joint typed peer's `.iter().next_back().copied()`
    /// projection as through the direct fold [`max_released_version_typed`]
    /// used to carry — pins that the delegation
    /// `max_released_version_typed → released_semver_tags_typed`
    /// preserves the seeding decision at every representative shape,
    /// so a future refactor that quietly forked one of the two
    /// max-selection bodies cannot land silently.
    ///
    /// Same shape catalogue the `typed_and_stringly_max_released_version_agree`
    /// shield already runs (numeric-lex, non-exact skip, empty, prefix
    /// mismatch, non-`v` prefix, whitespace) — reused here to pin the
    /// joint peer's projection is byte-equivalent to the pre-delegation
    /// fold at every fleet-observed shape.
    #[test]
    fn joint_scan_projection_equals_direct_fold_at_every_representative_shape() {
        let _guard = GIT_BIN_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        for (label, listing, prefix) in [
            ("numeric-lex ordering", "v0.3.0\\nv0.3.1\\nv0.10.0\\n", "v"),
            (
                "non-exact tags skipped",
                "v1.2\\nv2.0.0-rc1\\nvNOPE\\nv0.1.0\\nv0.1.0.1\\n",
                "v",
            ),
            ("empty listing", "", "v"),
            ("prefix mismatch", "nightly\\nlatest\\n", "v"),
            (
                "non-v prefix",
                "release-1.4.0\\nrelease-1.10.0\\n",
                "release-",
            ),
            (
                "surrounding whitespace tolerated",
                "  v0.2.0  \\n\\nv0.5.0\\n  \\n",
                "v",
            ),
        ] {
            let (_d, shim) = git_listing_shim(listing);
            let _scope = GitBinScope::set(&shim);
            let by_joint = released_semver_tags_typed(prefix, None)
                .unwrap()
                .iter()
                .next_back()
                .copied();
            let by_direct = max_released_version_typed(prefix, None).unwrap();
            assert_eq!(
                by_joint, by_direct,
                "{label}: joint-scan max must byte-equal the direct fold — \
                 the delegation `max_released_version_typed → \
                 released_semver_tags_typed` preserves the seed at every \
                 representative shape"
            );
        }
    }

    /// The joint scan carries EVERY parseable `<prefix>X.Y.Z` triple
    /// through to its `BTreeSet` return, not just the max — this is
    /// what the collision predicate consumes. Pins the primary reason
    /// the joint peer exists over the max-only fold: a downstream
    /// consumer that needs `contains` for the collision loop reads
    /// the full set off ONE fetch rather than firing one
    /// `tag_exists_in` git spawn per iteration.
    #[test]
    fn joint_scan_carries_every_parseable_triple_not_just_the_max() {
        let _guard = GIT_BIN_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let (_d, shim) = git_listing_shim("v0.1.0\\nv0.2.0\\nv0.5.0\\nv1.0.0\\n");
        let _scope = GitBinScope::set(&shim);
        let set = released_semver_tags_typed("v", None).unwrap();
        assert_eq!(
            set.len(),
            4,
            "every parseable X.Y.Z tag must appear in the scan set — \
             the collision predicate reads membership off this set, \
             not off the max"
        );
        for triple in [
            crate::version::SemverTriple::new(0, 1, 0),
            crate::version::SemverTriple::new(0, 2, 0),
            crate::version::SemverTriple::new(0, 5, 0),
            crate::version::SemverTriple::new(1, 0, 0),
        ] {
            assert!(
                set.contains(&triple),
                "collision predicate would miss {triple} — the joint scan \
                 must carry every parseable triple through, not just the max"
            );
        }
    }

    /// Non-exact tags (release candidates, dated tags, two-part `v1.2`)
    /// are SKIPPED from the joint scan's set, matching the
    /// `max_released_version_typed` fold's rule — a repo carrying
    /// mixed tag shapes must not have those shapes appear as
    /// `SemverTriple` members of the collision predicate. Pins the
    /// skip discipline the joint peer inherits from the delegated fold.
    #[test]
    fn joint_scan_skips_non_exact_tags_matching_the_fold_rule() {
        let _guard = GIT_BIN_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let (_d, shim) = git_listing_shim("v1.2\\nv2.0.0-rc1\\nvNOPE\\nv0.1.0\\nv0.1.0.1\\n");
        let _scope = GitBinScope::set(&shim);
        let set = released_semver_tags_typed("v", None).unwrap();
        assert_eq!(
            set.len(),
            1,
            "only the exact `X.Y.Z` shape counts — {set:?}"
        );
        assert!(
            set.contains(&crate::version::SemverTriple::new(0, 1, 0)),
            "the sole exact tag `v0.1.0` must be present in {set:?}"
        );
    }

    /// The empty listing yields an empty set, matching the
    /// `max_released_version_typed → None` boundary. Pins that a
    /// downstream `set.iter().next_back().copied()` reads `None` and
    /// `set.contains(&t)` reads `false` for every triple — the
    /// "nothing released yet" state at the type level, without the
    /// empty-string sentinel the pre-typed stringly wrapper carried.
    #[test]
    fn joint_scan_on_empty_listing_yields_empty_set_matching_none_max() {
        let _guard = GIT_BIN_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let (_d, shim) = git_listing_shim("");
        let _scope = GitBinScope::set(&shim);
        let set = released_semver_tags_typed("v", None).unwrap();
        assert!(
            set.is_empty(),
            "empty listing must yield empty set (nothing released yet) — {set:?}"
        );
        assert!(
            set.iter().next_back().is_none(),
            "empty set yields None at the max boundary"
        );
        assert!(
            !set.contains(&crate::version::SemverTriple::new(0, 0, 0)),
            "empty set contains nothing, including 0.0.0 — the collision \
             predicate returns false for every triple"
        );
    }
}
