//! Repository utilities for forge
//!
//! Provides common repository-related functions like finding the repo root,
//! detecting environment, and working with paths.

use anyhow::{Context, Result};
use serde::de::DeserializeOwned;
use std::path::{Path, PathBuf};
use tracing::debug;

/// Read a YAML file at `path` and deserialize it into `T`.
///
/// The sync sibling of
/// [`crate::git::yaml_read_modify_write_async`] on the read-only arm.
/// Where the async primitive owns the read/parse/mutate/serialize/write
/// round-trip on the async-fs surface, `read_yaml_sync` owns the
/// read/parse prefix on the sync-fs surface: the shape every consumer
/// that loads a typed config off disk (a `ProductConfig`, a
/// `ReleaseConfig`, a `serde_yaml::Value` for `.get(...)` navigation)
/// spelled inline pre-lift.
///
/// # Envelope
///
/// Each failure branch surfaces the offending `path.display()` via
/// [`anyhow::Context`] on the operator's next-step classifier:
///
/// - Read failure: `"Failed to read {path}"` — operator's next step is
///   `ls` on the exact path.
/// - Parse failure: `"Failed to parse {path} as YAML"` — operator's
///   next step is `yamllint` on the exact path, not `ls`.
///
/// Pre-lift six sibling consumer sites in `cli/src/config/mod.rs` each
/// carried its own per-consumer "role" label (`"product config"`,
/// `"service config"`) inside the context string, decoupling the
/// diagnostic wording from the offending path. Post-lift the primitive's
/// canonical `path.display()` envelope reaches every consumer by
/// construction; the role a config plays in the loader is preserved by
/// the caller's function name in the anyhow backtrace, not by a redundant
/// label inside the failure classifier.
///
/// # Type parameter
///
/// `T: DeserializeOwned` — accepts both closed-shape structs
/// (`ProductConfig`, `ServiceConfig`, `GlobalConfig`) and the open
/// [`serde_yaml::Value`] target (for a caller that navigates the
/// document tree via `.get(...)` chains rather than deserializing into
/// a struct). One primitive body serves both shapes.
///
/// # Errors
///
/// Returns `Err` if the file cannot be read (missing, unreadable, EIO)
/// or cannot be parsed as YAML into `T` (invalid YAML syntax, schema
/// mismatch). On the read-Err path no parse is attempted; on the
/// parse-Err path the read has already succeeded, so the offending file
/// is present on disk and the operator can inspect it directly.
pub fn read_yaml_sync<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;
    serde_yaml::from_str(&content)
        .with_context(|| format!("Failed to parse {} as YAML", path.display()))
}

/// Find repository root by looking for flake.nix
///
/// Search order:
/// 1. Current directory
/// 2. Parent directories (up to 10 levels)
/// 3. REPO_ROOT environment variable
///
/// # Errors
///
/// Returns an error if no flake.nix is found in any searched location.
///
/// # Examples
///
/// ```rust,ignore
/// let repo_root = find_repo_root()?;
/// println!("Repository root: {}", repo_root.display());
/// ```
pub fn find_repo_root() -> Result<PathBuf> {
    let current = std::env::current_dir().context("Failed to get current directory")?;

    debug!("Searching for repo root from: {}", current.display());

    // Check current directory
    if current.join("flake.nix").exists() {
        debug!("Found flake.nix in current directory");
        return Ok(current);
    }

    // Check parent directories (up to 10 levels)
    let mut dir = current.as_path();
    for level in 1..=10 {
        if let Some(parent) = dir.parent() {
            if parent.join("flake.nix").exists() {
                debug!(
                    "Found flake.nix {} level(s) up at: {}",
                    level,
                    parent.display()
                );
                return Ok(parent.to_path_buf());
            }
            dir = parent;
        } else {
            break;
        }
    }

    // Check REPO_ROOT env var
    if let Some(path) = path_from_env_optional("REPO_ROOT") {
        if path.join("flake.nix").exists() {
            debug!("Found flake.nix via REPO_ROOT env var: {}", path.display());
            return Ok(path);
        }
        debug!(
            "REPO_ROOT set to {} but no flake.nix found there",
            path.display()
        );
    }

    anyhow::bail!(
        "Cannot find repository root (flake.nix not found).\n\n  \
         Searched:\n  \
         - Current directory: {}\n  \
         - Parent directories (up to 10 levels)\n  \
         - REPO_ROOT environment variable\n\n  \
         Solutions:\n  \
         - Run this command from the repository root directory\n  \
         - Set REPO_ROOT environment variable to the repository root",
        current.display()
    )
}

/// Get a tool binary path from environment or fallback to PATH
///
/// Two-arg env-var-with-`String`-fallback sigil on the tool-name
/// surface: where [`env_var_or_default`] takes an arbitrary
/// substrate-supplied string as the fallback (an environment alias,
/// a registry URL, a server name, a cluster name),
/// [`get_tool_path`] takes a *command name* as the fallback (a
/// shell-name used as a PATH lookup by the caller). Post-lift the
/// body is `env_var_or_default(env_var, fallback)` — the
/// `env::var → String` shape lives at the ONE primitive body so a
/// future refinement of the shape (logging every resolve,
/// canonicalizing the value against a closed enum, a telemetry
/// sigil separating explicit-value from default-fallback paths, or
/// a swap to a typed `substrate::EnvVar(String)` newtype) lands at
/// [`env_var_or_default`] and reaches every sigil by construction
/// (THEORY §V — solve-once-at-the-primitive; §VI.1 —
/// recurring-shape-to-helper).
///
/// # Arguments
///
/// * `env_var` - Environment variable name to check first
/// * `fallback` - Command name to use if env var not set
///
/// # Examples
///
/// ```rust,ignore
/// let cargo = get_tool_path("CARGO", "cargo");
/// let crate2nix = get_tool_path("CRATE2NIX", "crate2nix");
/// ```
pub fn get_tool_path(env_var: &str, fallback: &str) -> String {
    env_var_or_default(env_var, fallback)
}

/// Resolve a substrate-declared directory-path env var into a
/// [`PathBuf`], surfacing `miss_context` via [`anyhow::Context`] on the
/// unset case.
///
/// Result<PathBuf> peer to [`get_tool_path`] — where `get_tool_path`
/// takes an env var and a PATH-lookup fallback (infallible, `String`),
/// `path_from_env` takes an env var and a caller-supplied
/// operator-facing miss wording (fallible, `PathBuf`). Every consumer
/// that resolves a substrate-declared directory path from an env var
/// (`SERVICE_DIR`, `REPO_ROOT`, etc.) routes through this one body so
/// the `env::var` read and the `PathBuf::from` projection live at
/// EXACTLY one point. A future refinement of the substrate-path
/// contract — a canonicalize hook, a must-exist check, a swap to a
/// typed `substrate::ServiceDir(PathBuf)` newtype, a telemetry sigil
/// on the resolved path — lands here and reaches every caller by
/// construction (THEORY §VI.1 — every recurring shape becomes a helper
/// before it becomes duplicated code).
///
/// # Arguments
///
/// * `env_var` - Environment variable name to read
/// * `miss_context` - Operator-facing wording forwarded to
///   [`anyhow::Context`] on the miss. Each caller keeps its own
///   domain-specific wording (`"SERVICE_DIR not set - this should be
///   called via substrate wrapper"`, `"SERVICE_DIR environment variable
///   not set"`, `"SERVICE_DIR not set - required for deploy.yaml
///   lookup"`) so the consumer's downstream diagnostic prose stays
///   grep-visible verbatim.
pub fn path_from_env(env_var: &str, miss_context: &'static str) -> Result<PathBuf> {
    let raw = std::env::var(env_var).context(miss_context)?;
    Ok(PathBuf::from(raw))
}

/// Resolve a substrate-declared directory-path env var into a
/// [`PathBuf`], folding the unset case into `None`.
///
/// `Option<PathBuf>` peer to [`path_from_env`] (Result<PathBuf>) and
/// [`env_var_optional`] (Option<String>) on the env-var-projection
/// algebra. Where [`path_from_env`] carries a caller-supplied
/// operator-facing miss wording and surfaces the unset case as a
/// [`Result::Err`] via [`anyhow::Context`] (the "the env var MUST be
/// set" contract used by callers that bail immediately), and
/// [`env_var_optional`] carries the raw `String` value forward
/// (leaving downstream projection to the caller), `path_from_env_optional`
/// closes the "env var MAY be set; if it is, treat it as a path"
/// contract at one body — the shape every `if let Ok(v) =
/// env::var(NAME) { PathBuf::from(v) }` inline stanza in the crate
/// spelled verbatim.
///
/// Composed on top of [`env_var_optional`] so the empty-string-is-a-
/// VALUE semantic is inherited by construction: an operator's
/// explicit-empty export (`REPO_ROOT=""`, `NIX_HOOKS_PATH=""`) lands
/// on `Some(PathBuf::new())`, not `None`. Parity with every pre-lift
/// consumer's inline `if let Ok(v) = env::var(NAME)` shape, where
/// `Ok(String::new())` matched the arm and flowed into
/// `PathBuf::from("")`. A future primitive refinement that swapped
/// `env_var_optional` for `release_git_sha_from_env`-style
/// `.filter(|s| !s.is_empty())` semantics would silently reroute
/// every `<NAME>=""` export from `Some(PathBuf::new())` to `None` and
/// misroute every consumer's `if let Some(_) = ...` dispatch.
///
/// # Pre-lift stanzas fused into ONE body
///
/// Six byte-similar inline `if let Ok(v) = std::env::var(NAME) {
/// PathBuf::from(v) }` stanzas spelled the shape across six CLI-facing
/// modules before this lift:
///
/// - [`find_repo_root`] (`REPO_ROOT`) — flake.nix-validated fallback
///   arm after the current-directory / parent-walk searches fail.
/// - `crate::git::get_repo_root` (`REPO_ROOT`) — env-var-first
///   shortcut before falling back to `git rev-parse --show-toplevel`.
/// - `crate::path_builder::PathBuilder::new` (`REPO_ROOT`) —
///   env-var-first shortcut before falling back to
///   `DeployConfig::find_repo_root(&current_dir)`.
/// - `commands/bootstrap.rs::get_bootstrap_dir` (`SERVICE_DIR`) —
///   env-var-first shortcut before falling back to `find_repo_root()
///   .join("pkgs/platform/bootstrap")`.
/// - `commands/pangea.rs::find_external_repo` (`<NAME>_DIR`, dynamic)
///   — env-var-first shortcut before searching standard `$HOME/code`
///   / `$HOME/.local/src` locations.
/// - `nix_hooks.rs::NixHooksPackage::discover` (`NIX_HOOKS_PATH`) —
///   env-var-first shortcut before building `.#nix-hooks` via `nix
///   build`.
///
/// # Post-lift refinement surface
///
/// Post-lift a future refinement of the shape — canonicalizing the
/// path via `std::fs::canonicalize`, absolutizing against the current
/// working directory, a telemetry sigil separating explicit-value from
/// unset paths, a must-exist check via `.filter(|p| p.exists())`, or
/// a swap to a typed `substrate::SubstratePath(PathBuf)` newtype —
/// lands at this body and reaches every consumer by construction. The
/// same solve-once-at-the-primitive discipline [`env_var_or_default`]
/// closes on the `String`-fallback surface, [`path_from_env`] closes
/// on the `Result<PathBuf>` surface, [`env_var_optional`] closes on
/// the `Option<String>` surface, and [`safe_mode_from_env`] /
/// [`truthy_flag_from_env`] close on the `bool` surface (THEORY §V —
/// solve-once-at-the-primitive; §VI.1 — recurring-shape-to-helper).
pub fn path_from_env_optional(env_var: &str) -> Option<PathBuf> {
    env_var_optional(env_var).map(PathBuf::from)
}

/// Verify a directory exists and contains expected files
///
/// # Arguments
///
/// * `dir` - Directory path to check
/// * `required_files` - List of files that must exist in the directory
///
/// # Errors
///
/// Returns an error if the directory doesn't exist or is missing required files.
pub fn verify_directory(dir: &Path, required_files: &[&str]) -> Result<()> {
    if !dir.exists() {
        anyhow::bail!(
            "Directory not found: {}\n\n  \
             If this is a new setup, you may need to create the directory.\n  \
             If on a different machine, try: git pull origin main",
            dir.display()
        );
    }

    if !dir.is_dir() {
        anyhow::bail!("Path exists but is not a directory: {}", dir.display());
    }

    for file in required_files {
        let file_path = dir.join(file);
        if !file_path.exists() {
            anyhow::bail!(
                "Required file not found: {}\n  \
                 Expected in: {}",
                file,
                dir.display()
            );
        }
    }

    Ok(())
}

/// Resolve a substrate-declared env var into a `String`, falling back
/// to `default` on the unset case.
///
/// Peer to [`get_tool_path`] on the env-var-with-`String`-fallback
/// surface — where `get_tool_path` is documented as "env var or PATH
/// lookup" and takes a *command name* as the fallback (a shell-name),
/// `env_var_or_default` takes an *arbitrary substrate-supplied
/// string* as the fallback (an environment alias, a registry URL, a
/// server name, a cluster name). Every crate site that resolved a
/// substrate-declared env var into a `String` with a hard-coded
/// literal fallback — the shape
///
/// ```text
/// std::env::var(<NAME>).unwrap_or_else(|_| <DEFAULT>.to_string())
/// ```
///
/// — routes through this one body so the `env::var` read and the
/// `String::from(default)` projection live at EXACTLY one point.
///
/// Pre-lift five per-module sigils spelled the pattern verbatim:
///
/// - [`get_environment`] (`FORGE_ENV` / `"staging"`)
/// - [`crate::infrastructure::attic::attic_server_alias`]
///   (`ATTIC_SERVER_NAME` / `"default"`)
/// - [`crate::config::default_cluster`] (`FORGE_CLUSTER` /
///   `"default"`)
/// - `crate::domain::service::get_registry_base`
///   (`SERVICE_REGISTRY_BASE` / `"ghcr.io/org/project"`)
/// - `crate::commands::pangea::get_registry_base` (`PANGEA_REGISTRY`
///   / `"ghcr.io/org/project"`)
///
/// Each per-module sigil kept its identity — the `(env_var, default)`
/// pair is baked into the sigil's body, so the caller-facing type is
/// still `fn() -> String` with no env-var name to typo at the call
/// site. Post-lift a future refinement of the shape — logging every
/// resolve, canonicalizing the value against a closed enum, a
/// telemetry sigil separating explicit-value from default-fallback
/// paths, or a swap to a typed `substrate::EnvVar(String)` newtype —
/// lands here and reaches every sigil by construction (THEORY §V —
/// solve-once-at-the-primitive; §VI.1 — recurring-shape-to-helper).
///
/// # Arguments
///
/// * `env_var` - Environment variable name to read
/// * `default` - Literal fallback returned when the env var is unset
///   or unreadable. Cloned into a `String` on the fallback path,
///   consumed as `String::from(default)`.
pub fn env_var_or_default(env_var: &str, default: &str) -> String {
    std::env::var(env_var).unwrap_or_else(|_| default.to_string())
}

/// Resolve an env-var read onto `Option<String>` with empty-string-is-a-value
/// parity — the shape every `std::env::var(NAME).ok()` inline stanza in the
/// crate spelled verbatim.
///
/// # The mirror-of-[`crate::git::release_git_sha_from_env`] contract
///
/// Peer to [`crate::git::release_git_sha_from_env`] on the `Option<String>`
/// surface, split by empty-string semantics: where `release_git_sha_from_env`
/// closes the empty-string-is-MISS shape (an unset env var and a
/// `RELEASE_GIT_SHA=""` export both fold to `None`), `env_var_optional`
/// closes the empty-string-is-a-VALUE shape (an unset env var folds to
/// `None`, a `DATABASE_URL=""` / `PUSHGATEWAY_URL=""` / `HOSTNAME=""`
/// export folds to `Some(String::new())`). The two primitives split the
/// crate's `env::var → Option<String>` surface exhaustively so a fresh
/// consumer picks its primitive by asking "does an explicit-empty export
/// count as a value or as a miss?" — the closed choice a per-module inline
/// `env::var(NAME).ok()` stanza does not present.
///
/// # Pre-lift stanzas fused into ONE body
///
/// Six byte-similar inline `std::env::var(NAME).ok()` stanzas spelled the
/// shape across three CLI-facing modules before this lift:
///
/// - `commands/sync.rs::generate_entities` (`DATABASE_URL`) — gate on the
///   env var before invoking `sea-orm-cli generate entity`.
/// - `observability.rs::EventMetadata::new` (`HOSTNAME`) — enrich every
///   structured event with the host emitting it.
/// - `observability.rs::EventMetadata::new` (`CI_JOB_ID` fallback of the
///   `GITHUB_RUN_ID` primary) — the `.or_else(|| env::var("CI_JOB_ID").ok())`
///   chain arm on the CI-job-id enrichment surface.
/// - `observability.rs::metrics::pushgateway_url` (`PUSHGATEWAY_URL`) —
///   gate on the env var before pushing Prometheus metrics.
/// - `infrastructure/registry.rs::RegistryCredentials::discover_token`
///   (`GHCR_TOKEN`) — first env-var arm of the GHCR-token discovery chain.
/// - `infrastructure/registry.rs::RegistryCredentials::discover_token`
///   (`GITHUB_TOKEN`) — second env-var arm of the same chain.
///
/// # Post-lift refinement surface
///
/// Post-lift a future refinement of the shape — logging every resolve, a
/// telemetry sigil separating explicit-value from unset paths, a swap to a
/// typed `substrate::EnvVar(Option<String>)` newtype, or canonicalizing the
/// value against a closed enum — lands at this body and reaches every
/// consumer by construction. The same solve-once-at-the-primitive
/// discipline [`env_var_or_default`] closes on the `String`-fallback
/// surface, [`path_from_env`] closes on the `Result<PathBuf>` surface,
/// [`safe_mode_from_env`] / [`truthy_flag_from_env`] close on the `bool`
/// surface, and [`crate::git::release_git_sha_from_env`] closes on the
/// empty-string-is-miss `Option<String>` mirror (THEORY §V —
/// solve-once-at-the-primitive; §VI.1 — recurring-shape-to-helper).
///
/// # The empty-string case
///
/// `Some(String::new())` on the empty-string set path — an operator's
/// explicit-empty export (`PUSHGATEWAY_URL=""`) lands on `Some(_)`, not
/// `None`. Parity with every pre-lift consumer's inline `.ok()`
/// behaviour: `env::var(NAME).ok()` on an `Ok(String::new())` is
/// `Some(String::new())`, not `None`. A future primitive refinement that
/// swapped `.ok()` for `.ok().filter(|s| !s.is_empty())` would silently
/// re-route every `<NAME>=""` export from `Some("")` to `None` and reopen
/// the class the peer split closes — that is the exact projection
/// [`crate::git::release_git_sha_from_env`] closes for the empty-is-miss
/// half, and a callers-facing merge would defeat the split.
pub fn env_var_optional(env_var: &str) -> Option<String> {
    std::env::var(env_var).ok()
}

/// Get the current environment (staging, production, etc.)
///
/// Reads from `FORGE_ENV` environment variable, defaults to `"staging"`.
///
/// This is the ONE body across the crate that reads `FORGE_ENV` into a
/// `String` with the `"staging"` default — the shape
/// `commands/status.rs` spelled inline as `std::env::var("FORGE_ENV")
/// .unwrap_or_else(|_| "staging".to_string())` before lifting through
/// here. Routes through the crate-scoped [`env_var_or_default`]
/// primitive so the `env::var`-read-with-`String`-fallback projection
/// lives at ONE body across the crate — a future refinement of the
/// shape (logging the resolved environment, canonicalizing it against
/// a closed enum of known environments, a telemetry sigil on the
/// value, or a swap to a typed `substrate::Environment(String)`
/// newtype) lands at the primitive and reaches every consumer by
/// construction (THEORY §V — solve-once-at-the-primitive; §VI.1 —
/// recurring-shape-to-helper).
///
/// The `"staging"` default matches the `#[arg(long, env = "FORGE_ENV",
/// default_value = "staging")]` clap attribute at `cli.rs:397` so the
/// CLI-flag path and the env-read path agree on the fallback.
pub fn get_environment() -> String {
    env_var_or_default("FORGE_ENV", "staging")
}

/// Resolve SAFE mode from the environment.
///
/// Reads the `SAFE` environment variable and folds it to a `bool` with
/// the "default TRUE — disable with `false` or `0` (case-insensitive)"
/// contract. Unset → `true`; `SAFE=false` / `SAFE=FALSE` / `SAFE=False`
/// / `SAFE=0` → `false`; anything else (including `SAFE=""`, `SAFE=no`,
/// `SAFE=off`, `SAFE=maybe`) → `true`.
///
/// This is the ONE body across the crate that reads `SAFE` into a
/// `bool` with the disable-with-`false`-or-`0` semantic. Pre-lift two
/// byte-equivalent inline stanzas spelled the shape:
///
/// ```text
/// std::env::var("SAFE")
///     .map(|v| {
///         let val = v.to_lowercase();
///         val != "false" && val != "0"
///     })
///     .unwrap_or(true)
/// ```
///
/// at `main.rs::main` (the `Commands::Rollout` arm's `safe_mode` local)
/// and `commands/github_runner_ci.rs::is_safe_mode`. Both consumers
/// govern retry semantics on the same operator-facing toggle: the
/// rollout dispatch's `RetryPolicy::network_or_immediate(safe_mode)`
/// arm and the github-runner-CI Attic-login/push retry-budget
/// partition. A drift at one site — a typo `SAFE_MODE`, a lost
/// `to_lowercase()` making `SAFE=FALSE` silently truthy, a swap to
/// `!= "0"` alone dropping the `"false"` half, an accidental default
/// flip to `false` — would silently misroute the operator's `SAFE`
/// toggle at one dispatch surface only, and the mismatch would surface
/// as a rollout that retries where the operator asked it not to (or
/// vice versa) on one CLI entry point while the other honors the
/// override.
///
/// Post-lift a future refinement of the shape (logging every resolve,
/// widening the disable set to `{no, off}`, a telemetry sigil
/// separating explicit-value from default-fallback paths, or a swap to
/// a typed `substrate::SafeMode(bool)` newtype) lands at this body and
/// reaches every consumer by construction — the same
/// solve-once-at-the-primitive discipline
/// [`env_var_or_default`] closes on the `String`-fallback surface,
/// [`path_from_env`] closes on the `Result<PathBuf>` surface, and
/// [`crate::git::release_git_sha_from_env`] closes on the
/// empty-string-is-miss `Option<String>` surface
/// (THEORY §V — solve-once-at-the-primitive; §VI.1 —
/// recurring-shape-to-helper).
///
/// The empty-string parity (`SAFE=""` → `true`) is deliberate: a
/// `to_lowercase()`d empty string satisfies both `!= "false"` and
/// `!= "0"`, so an operator's explicit-empty export lands on the
/// default-true branch alongside an unset env var. A future primitive
/// refinement that swapped the shape for `.ok().filter(|s|
/// !s.is_empty()).map(...).unwrap_or(true)` would preserve this
/// empty-is-truthy semantic; a swap to
/// `.ok().is_some_and(...)`-style dispatch would flip it and misroute
/// every `SAFE=""` export.
pub fn safe_mode_from_env() -> bool {
    std::env::var("SAFE")
        .map(|v| {
            let val = v.to_lowercase();
            val != "false" && val != "0"
        })
        .unwrap_or(true)
}

/// Resolve a "default FALSE — enable on `1` / `true` (case-insensitive)"
/// env-var flag onto a `bool`.
///
/// Reads `env_var` and returns `true` iff its value is `"1"` or the letters
/// `t-r-u-e` in any case (`true`, `TRUE`, `True`, `tRuE`, `TrUe`, …).
/// Unset → `false`; every other value (`""`, `"0"`, `"false"`, `"yes"`,
/// `"on"`, `"maybe"`, `"2"`) → `false`.
///
/// # The mirror-of-[`safe_mode_from_env`] contract
///
/// Peer to [`safe_mode_from_env`] on the flag-parsing surface: where
/// `safe_mode_from_env` folds the DEFAULT-TRUE / disable-with-`false`-or-`0`
/// operator toggle onto ONE body, `truthy_flag_from_env` folds the DEFAULT-
/// FALSE / enable-with-`1`-or-`true` mirror toggle onto ONE body. The two
/// primitives split the crate's opt-out (`SAFE`) versus opt-in
/// (`FORGE_HELM_REPUBLISH`, `SKIP_INTEGRATION`, `SKIP_E2E`) env-var-to-bool
/// surface exhaustively so a fresh consumer picks its primitive by asking
/// "is the default TRUE (safety-on) or FALSE (opt-in-only)?" — the closed
/// choice a per-module inline stanza does not present.
///
/// # Pre-lift stanzas fused into ONE body
///
/// Three byte-similar inline stanzas spelled the shape across three CLI
/// entry points:
///
/// - `commands/helm.rs::republish_enabled` (`FORGE_HELM_REPUBLISH`) —
///   `std::env::var("FORGE_HELM_REPUBLISH").is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))`.
///   Governs whether an already-published `(name, version)` Helm chart is
///   force-re-uploaded to `oci://ghcr.io/pleme-io/charts` (immutable by
///   default; enabling the flag is a "repair a corrupt upload"
///   escape hatch).
/// - `commands/prerelease.rs` `SKIP_INTEGRATION` — pre-lift
///   `.map(|v| v == "true" || v == "1").unwrap_or(false)`. Governs whether
///   the G13 gate (Postgres + Redis + NATS testcontainers) is skipped.
/// - `commands/prerelease.rs` `SKIP_E2E` — same pre-lift shape. Governs
///   whether the G14 gate (chromiumoxide + full stack) is skipped.
///
/// The two prerelease sites drifted from `helm.rs` on case-sensitivity: an
/// operator's `SKIP_INTEGRATION=TRUE` / `SKIP_E2E=TRUE` (uppercase) was
/// silently ignored — the `v == "true"` clause matches lowercase only —
/// while `FORGE_HELM_REPUBLISH=TRUE` fired via `.eq_ignore_ascii_case`.
/// Post-lift both consumers route through the case-insensitive body, so a
/// mixed-case `TRUE` / `True` / `TrUe` export from any of the three
/// operator-facing entry points behaves identically. That parity is a
/// load-bearing behavioral improvement, not a shuffle: a CI operator's
/// `SKIP_E2E=TRUE` now actually skips G14 instead of silently running it.
///
/// # Post-lift refinement surface
///
/// A future refinement of the shape (widening the enable set to include
/// `yes` / `on`, adding a telemetry sigil separating explicit-value from
/// default-fallback paths, a swap to a typed `substrate::FeatureFlag(bool)`
/// newtype, canonicalizing the accepted values against a closed enum, or
/// logging every resolve) lands at this body and reaches every consumer by
/// construction — the same solve-once-at-the-primitive discipline
/// [`safe_mode_from_env`] closes on the DEFAULT-TRUE mirror,
/// [`env_var_or_default`] closes on the `String`-fallback surface,
/// [`path_from_env`] closes on the `Result<PathBuf>` surface, and
/// [`crate::git::release_git_sha_from_env`] closes on the
/// empty-string-is-miss `Option<String>` surface (THEORY §V — solve-once-
/// at-the-primitive; §VI.1 — recurring-shape-to-helper).
///
/// # The empty-string case
///
/// `""` → `false`: an operator's explicit-empty export (`SKIP_E2E=""`)
/// does NOT enable the flag — `v == "1"` is false, and the empty string
/// matched against `eq_ignore_ascii_case("true")` is false (lengths
/// differ). Parity with every pre-lift consumer's inline behaviour.
pub fn truthy_flag_from_env(env_var: &str) -> bool {
    std::env::var(env_var).is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
}

/// Which product-directory layouts [`find_product_dir`] accepts as terminal.
///
/// The monorepo layout is universal — every consumer honors it. The
/// standalone layout is additive and consumed only by the rust-service
/// entry point, where a product may live as its own repository rather
/// than a `pkgs/products/{product}` subtree of a larger monorepo. The
/// named-standalone variant is additive on top of that: it also parses
/// the standalone `deploy.yaml` and requires a top-level string `name:`
/// field to be present, matching the `config::DeployConfig` loader's
/// pre-lift acceptance rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProductDirLayout {
    /// Monorepo pattern only: an ancestor whose parent is named `products`
    /// and whose grandparent is named `pkgs` — i.e. `.../pkgs/products/{product}`.
    Monorepo,
    /// Monorepo pattern OR standalone: additionally accept any ancestor
    /// directory that carries both `deploy.yaml` and `.git`, i.e. a
    /// product repository whose root IS the product directory.
    MonorepoOrStandalone,
    /// Monorepo pattern OR named standalone: additionally accept any
    /// ancestor directory that carries `deploy.yaml` and `.git` AND whose
    /// `deploy.yaml` parses as YAML with a top-level string `name:` field.
    /// The parse-and-verify step distinguishes a genuine product-repo root
    /// from any other `.git` directory that happens to carry an unrelated
    /// `deploy.yaml` (a deploy-manifest fragment for something else, a
    /// stray file). Matches the pre-lift
    /// `config::DeployConfig::find_product_directory` acceptance rule; a
    /// `.git`+`deploy.yaml` node without a valid `name:` string CONTINUES
    /// the climb rather than terminating, so an inner match at a deeper
    /// ancestor still resolves.
    MonorepoOrNamedStandalone,
}

/// Does `dir/deploy.yaml` parse as YAML and expose a top-level string
/// `name:` field? Extracted verbatim from the pre-lift
/// `config::DeployConfig::find_product_directory` inline check so the
/// named-standalone layout terminal preserves the same
/// tolerate-parse-failures shape: an unreadable file, an unparseable
/// YAML document, a document without a top-level `name`, or a `name`
/// whose value is not a string all return `false` (i.e. the walker
/// CONTINUES the climb) rather than propagating a parse error.
fn standalone_deploy_yaml_has_name(dir: &Path) -> bool {
    let deploy_yaml = dir.join("deploy.yaml");
    let Ok(content) = std::fs::read_to_string(&deploy_yaml) else {
        return false;
    };
    let Ok(yaml) = serde_yaml::from_str::<serde_yaml::Value>(&content) else {
        return false;
    };
    yaml.get("name").and_then(|n| n.as_str()).is_some()
}

/// Walk up from `start` toward the filesystem root, returning the first
/// ancestor (including `start` itself) that satisfies `layout`.
///
/// Fuses five sibling walkers that spelled the same parent-climb loop
/// verbatim across the crate:
///
/// - `commands/integration_tests.rs::find_product_dir_from_service`
///   ([`ProductDirLayout::Monorepo`])
/// - `commands/status.rs::find_product_dir_from_service`
///   ([`ProductDirLayout::Monorepo`])
/// - `commands/test.rs::find_product_dir_from_path`
///   ([`ProductDirLayout::Monorepo`])
/// - `commands/rust_service.rs::find_product_dir_from_path`
///   ([`ProductDirLayout::MonorepoOrStandalone`])
/// - `config::DeployConfig::find_product_directory`
///   ([`ProductDirLayout::MonorepoOrNamedStandalone`])
///
/// Three of the five sites carried a byte-identical monorepo-only
/// walker; the fourth extended it with a per-iteration standalone
/// check; the fifth extended THAT with a `deploy.yaml`-parse-plus-`name:`
/// verification. Post-lift the walk lives at ONE place with the layout
/// choice encoded in the closed enum — a future refinement (a fourth
/// layout, a per-layer audit hook, a symlink-cycle guard) lands
/// atomically across every consumer rather than at whichever copy the
/// author notices.
///
/// Walker mechanics — matches the pre-lift shape at every consumer
/// site:
///
/// 1. The monorepo terminal is checked at every iteration against the
///    CURRENT node: `current.parent()` must be named `products` and
///    `current.parent().parent()` must be named `pkgs`. The `current`
///    node itself (the `{product}` component) is what is returned.
/// 2. The standalone terminal (only under
///    [`ProductDirLayout::MonorepoOrStandalone`]) is checked at every
///    iteration against the CURRENT node: `current/deploy.yaml` and
///    `current/.git` must both exist. Order matches the pre-lift
///    `commands/rust_service.rs::find_product_dir_from_path` layout —
///    monorepo terminal first, standalone terminal second — so a path
///    that satisfies both (a `pkgs/products/{product}` node that
///    additionally carries a nested `.git`) returns via the monorepo
///    branch, preserving the pre-lift precedence.
/// 3. The named-standalone terminal (only under
///    [`ProductDirLayout::MonorepoOrNamedStandalone`]) is checked at
///    every iteration against the CURRENT node: `current/.git` and
///    `current/deploy.yaml` must both exist AND `current/deploy.yaml`
///    must parse as YAML exposing a top-level string `name:` field —
///    see [`standalone_deploy_yaml_has_name`]. A parse failure or a
///    missing / non-string `name:` field CONTINUES the climb rather
///    than terminating, so a deeper ancestor whose `deploy.yaml` DOES
///    carry a valid `name:` still resolves.
/// 4. On no match, climb by `current.parent()` and repeat. Terminate
///    with `None` when there is no parent (i.e. the filesystem root
///    was reached without hitting either terminal).
pub fn find_product_dir(start: &Path, layout: ProductDirLayout) -> Option<PathBuf> {
    let mut current = start.to_path_buf();
    loop {
        if let Some(parent) = current.parent() {
            if let Some(grandparent) = parent.parent() {
                if parent.file_name().and_then(|n| n.to_str()) == Some("products")
                    && grandparent.file_name().and_then(|n| n.to_str()) == Some("pkgs")
                {
                    return Some(current);
                }
            }
        }
        match layout {
            ProductDirLayout::Monorepo => {}
            ProductDirLayout::MonorepoOrStandalone => {
                if current.join("deploy.yaml").exists() && current.join(".git").exists() {
                    return Some(current);
                }
            }
            ProductDirLayout::MonorepoOrNamedStandalone => {
                if current.join(".git").exists()
                    && current.join("deploy.yaml").exists()
                    && standalone_deploy_yaml_has_name(&current)
                {
                    return Some(current);
                }
            }
        }
        if let Some(parent) = current.parent() {
            current = parent.to_path_buf();
        } else {
            return None;
        }
    }
}

/// Activate the root-flake pattern: publish `REPO_ROOT` + `SERVICE_DIR`
/// to the process environment and change the working directory to
/// `repo_root`.
///
/// Fuses three sibling call sites that each hand-spelled the same
/// three-line stanza verbatim:
///
/// - `main.rs::setup_service_directory` (the top-level CLI entry point;
///   pre-lift `set_var("REPO_ROOT", &root); set_var("SERVICE_DIR",
///   &dir); set_current_dir(&root)?`)
/// - `commands/status.rs::execute` (pre-lift `set_var("REPO_ROOT",
///   repo_root); set_var("SERVICE_DIR", service_dir);
///   set_current_dir(repo_root)?`)
/// - `commands/integration_tests.rs::execute_manual` (pre-lift
///   `set_var("REPO_ROOT", repo_root); set_var("SERVICE_DIR",
///   service_dir); set_current_dir(repo_root)?`)
///
/// The invariant every consumer honors — and that a fresh consumer
/// would forget by omission — is composed at ONE surface here:
///
/// 1. `REPO_ROOT` is set FIRST, so every downstream reader
///    (`repo::find_repo_root`, `git::get_repo_root`,
///    `PathBuilder::new`, `DeployConfig::load_for_service`) sees the
///    caller-supplied root regardless of whether the chdir succeeds.
/// 2. `SERVICE_DIR` is set SECOND, so `DeployConfig::load_for_service`
///    and every `commands/*::execute` that reads `SERVICE_DIR` sees the
///    caller-supplied service directory. Omitting this line at any of
///    the three pre-lift sites would have silently misrouted service
///    discovery to whatever `SERVICE_DIR` the calling shell inherited
///    from — a class of bug that structurally cannot occur post-lift.
/// 3. The chdir targets `repo_root`, NOT `service_dir` — the root
///    flake pattern (documented at `main.rs::setup_service_directory`)
///    is "run `nix build` from the repo root; the SERVICE_DIR env var
///    identifies the service to operate on." A caller that chdir'd to
///    `service_dir` instead would break every `nix flake` invocation
///    that follows.
///
/// The env vars are set BEFORE the chdir so a chdir failure still
/// leaves them populated — every pre-lift site had this property by
/// accident of source-order (the two `set_var` lines preceded the `?`
/// on `set_current_dir`); the primitive preserves it by construction.
///
/// # Errors
///
/// Returns an error if `set_current_dir(repo_root)` fails (e.g. the
/// path does not exist, the process lacks permission to enter it, or
/// the path is not a directory).
pub fn activate_root_flake<R, S>(repo_root: R, service_dir: S) -> Result<()>
where
    R: AsRef<Path>,
    S: AsRef<Path>,
{
    let repo_root = repo_root.as_ref();
    let service_dir = service_dir.as_ref();
    std::env::set_var("REPO_ROOT", repo_root);
    std::env::set_var("SERVICE_DIR", service_dir);
    std::env::set_current_dir(repo_root).with_context(|| {
        format!(
            "Failed to change working directory to repo root: {}",
            repo_root.display()
        )
    })
}

/// Run a command in a specific directory, restoring the original directory afterward
///
/// # Arguments
///
/// * `dir` - Directory to run the command in
/// * `f` - Async function to execute
///
/// # Errors
///
/// Returns an error if changing directories fails or if the function returns an error.
pub async fn in_directory<F, Fut, T>(dir: &Path, f: F) -> Result<T>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    let original_dir = std::env::current_dir().context("Failed to get current directory")?;

    std::env::set_current_dir(dir)
        .with_context(|| format!("Failed to change to directory: {}", dir.display()))?;

    // Use scopeguard to ensure we restore the directory even on panic
    let _guard = scopeguard::guard((), |_| {
        let _ = std::env::set_current_dir(&original_dir);
    });

    f().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_tool_path_with_env() {
        std::env::set_var("TEST_TOOL_PATH", "/custom/path/to/tool");
        assert_eq!(
            get_tool_path("TEST_TOOL_PATH", "default"),
            "/custom/path/to/tool"
        );
        std::env::remove_var("TEST_TOOL_PATH");
    }

    #[test]
    fn test_get_tool_path_fallback() {
        std::env::remove_var("NONEXISTENT_TOOL");
        assert_eq!(
            get_tool_path("NONEXISTENT_TOOL", "fallback-tool"),
            "fallback-tool"
        );
    }

    /// [`path_from_env`] surfaces `miss_context` verbatim through the
    /// `.context(...)` chain on a `env_var`-unset environment. Pins the
    /// contract every per-module `service_path_from_env()` sigil
    /// (`commands/developer_tools.rs`, `commands/schema_validation.rs`)
    /// delegates through: a future refactor that reshapes the primitive
    /// (a swap from `.context()` to a `bail!` with drifted wording, a
    /// lift to a typed error variant, a canonicalize prefix landed in
    /// front of the context) cannot silently drift the operator-facing
    /// wording every consumer's caller has been coached to grep for.
    #[test]
    fn test_path_from_env_surfaces_miss_context_when_unset() {
        let env_var = "TEST_PATH_FROM_ENV_UNSET_SIGIL_SHIELD";
        std::env::remove_var(env_var);
        let err = path_from_env(env_var, "sentinel miss wording for shield").unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("sentinel miss wording for shield"),
            "path_from_env() must forward `miss_context` verbatim on \
             the unset case — that is the contract every per-module \
             `service_path_from_env()` sigil delegates through. \
             Got: {msg}"
        );
    }

    /// [`path_from_env`] returns `PathBuf::from(env_var_value)` when the
    /// env var is set. Pins the `env::var → PathBuf` projection at ONE
    /// body so a future refinement (canonicalize hook, must-exist check,
    /// typed newtype) is caught here rather than at each consumer's
    /// downstream `.join(...)` / `.display()` call.
    #[test]
    fn test_path_from_env_returns_path_of_set_env_var() {
        let env_var = "TEST_PATH_FROM_ENV_SET_SIGIL_SHIELD";
        let sentinel = "/tmp/forge-path-from-env-sigil-shield";
        std::env::set_var(env_var, sentinel);
        let result = path_from_env(env_var, "unused-context-since-var-is-set");
        std::env::remove_var(env_var);
        let path = result.expect("path_from_env must succeed when env var is set");
        assert_eq!(
            path,
            PathBuf::from(sentinel),
            "path_from_env() must return `PathBuf::from(<env_var_value>)` \
             verbatim — the projection every pre-lift per-module \
             `service_path_from_env()` sigil spelled inline via \
             `Path::new(&service_dir)` / `PathBuf::from(service_dir)`."
        );
    }

    #[test]
    fn test_get_environment_default() {
        std::env::remove_var("FORGE_ENV");
        assert_eq!(get_environment(), "staging");
    }

    #[test]
    fn test_get_environment_custom() {
        std::env::set_var("FORGE_ENV", "production");
        assert_eq!(get_environment(), "production");
        std::env::remove_var("FORGE_ENV");
    }

    /// [`env_var_or_default`] returns the caller-supplied `default`
    /// verbatim when the env var is unset. Pins the shape every
    /// per-module sigil delegates through — [`get_environment`]
    /// (`FORGE_ENV`/`"staging"`), the `attic_server_alias` sigil
    /// (`ATTIC_SERVER_NAME`/`"default"`), the `default_cluster` sigil
    /// (`FORGE_CLUSTER`/`"default"`), the `SERVICE_REGISTRY_BASE`
    /// sigil, the `PANGEA_REGISTRY` sigil — depends on. A future
    /// refactor that reshaped the primitive (a swap from
    /// `unwrap_or_else(|_| _.to_string())` to a bail, a lift to a
    /// closed-enum of known values, a canonicalize prefix landed in
    /// front of the fallback) cannot silently drift the fallback
    /// wording every consumer's docstring pins verbatim.
    #[test]
    fn env_var_or_default_returns_default_when_env_var_unset() {
        let env_var = "TEST_ENV_VAR_OR_DEFAULT_UNSET_SIGIL_SHIELD";
        std::env::remove_var(env_var);
        assert_eq!(
            env_var_or_default(env_var, "sentinel-fallback"),
            "sentinel-fallback",
            "env_var_or_default() must return `default.to_string()` \
             verbatim on the unset case — that is the contract every \
             per-module env-var-with-`String`-fallback sigil (get_environment, \
             attic_server_alias, default_cluster, get_registry_base) \
             delegates through."
        );
    }

    /// [`env_var_or_default`] returns the env var's value verbatim
    /// when it IS set — the primitive's set-path projection. Pins the
    /// `env::var → String` shape at ONE body so a future refinement
    /// (canonicalize hook, must-not-be-empty check, typed newtype) is
    /// caught here rather than at each consumer's downstream `format!`
    /// call. Sibling shield to
    /// [`env_var_or_default_returns_default_when_env_var_unset`] on
    /// the set path.
    #[test]
    fn env_var_or_default_returns_env_var_value_when_set() {
        let env_var = "TEST_ENV_VAR_OR_DEFAULT_SET_SIGIL_SHIELD";
        let sentinel = "explicit-value-not-the-fallback";
        std::env::set_var(env_var, sentinel);
        let result = env_var_or_default(env_var, "unused-fallback-should-not-appear");
        std::env::remove_var(env_var);
        assert_eq!(
            result, sentinel,
            "env_var_or_default() must return `env::var(env_var)` \
             verbatim when set — the projection every pre-lift \
             per-module `env::var(NAME).unwrap_or_else(|_| \
             DEFAULT.to_string())` sigil spelled inline. A silent \
             precedence flip that returned the fallback even when the \
             env var was set would misroute every downstream `format!` \
             at the sigils' consumers to the wrong registry / cluster \
             / server alias / environment."
        );
    }

    /// [`get_tool_path`] treats an explicit empty-string `env::var`
    /// value as a set env var and returns it verbatim — NOT the
    /// fallback. Pins the delegation onto [`env_var_or_default`]:
    /// post-lift the sigil's body is a single-line forward to the
    /// primitive, so the `.unwrap_or_else(|_| ...)` empty-string-parity
    /// semantics come from the primitive by construction. A future
    /// refactor of the primitive that swapped `.unwrap_or_else` for
    /// `.ok().filter(|s| !s.is_empty())` would silently reroute a
    /// shell-exported `CARGO_BIN=""` / `CRATE2NIX_BIN=""` from
    /// empty-string to the caller-supplied tool-name fallback, and
    /// every consumer's downstream spawn would then invoke a bare
    /// `cargo` / `crate2nix` off `PATH` where pre-lift the operator's
    /// explicit empty override told it not to. Sibling shield to
    /// [`env_var_or_default_returns_empty_string_when_env_var_set_empty`]
    /// on the tool-name surface.
    #[test]
    fn get_tool_path_returns_empty_string_when_env_var_set_empty() {
        let env_var = "TEST_GET_TOOL_PATH_EMPTY_SIGIL_SHIELD";
        std::env::set_var(env_var, "");
        let result = get_tool_path(env_var, "the-fallback-must-not-fire");
        std::env::remove_var(env_var);
        assert_eq!(
            result, "",
            "get_tool_path() must return the empty string verbatim \
             when the env var is set to \"\" — matches the primitive \
             [`env_var_or_default`]'s `.unwrap_or_else(|_| ...)` \
             semantics, which the sigil delegates through post-lift."
        );
    }

    /// The post-lift body of [`get_tool_path`] is a single-line forward
    /// to [`env_var_or_default`] — the sigil no longer spells
    /// `env::var(...)` inline. Structural regression shield: without
    /// it, a future refactor could silently re-inline the shape (e.g.
    /// a helpful "just call `std::env::var` directly, it's shorter"
    /// cleanup) and reopen the duplication class this lift closed.
    /// Pre-lift the sigil's body carried the inline
    /// `std::env::var(env_var).unwrap_or_else(|_| fallback.to_string())`
    /// spelling; post-lift the body must contain the
    /// `env_var_or_default(env_var, fallback)` call site AND NOT the
    /// inline `env::var(env_var)` needle.
    #[test]
    fn get_tool_path_body_delegates_to_env_var_or_default_sigil() {
        const SOURCE: &str = include_str!("repo.rs");
        let body = crate::test_support::fn_body_slice_between_markers(
            SOURCE,
            "repo.rs",
            "pub fn get_tool_path(env_var: &str, fallback: &str) -> String {",
            "\n}",
        );
        assert!(
            body.contains("env_var_or_default(env_var, fallback)"),
            "get_tool_path() body must forward to \
             `env_var_or_default(env_var, fallback)` — the primitive \
             body every env-var-with-`String`-fallback sigil in the \
             crate now delegates through. Post-lift body: {body}"
        );
        assert!(
            !body.contains("std::env::var(env_var)") && !body.contains("env::var(env_var)"),
            "get_tool_path() body must NOT spell the inline \
             `env::var(env_var).unwrap_or_else(|_| \
             fallback.to_string())` shape — that duplication was lifted \
             onto [`env_var_or_default`]. A re-inline would silently \
             reopen the class this shield exists to close. \
             Post-lift body: {body}"
        );
    }

    /// [`env_var_or_default`] treats an explicit empty-string
    /// `env::var` value as a set env var and returns it verbatim —
    /// NOT the fallback. Pins the shape's parity with the pre-lift
    /// per-module sigils, each of which used `.unwrap_or_else(|_|
    /// ...)` (fallback fires only on the `Err` case, not on
    /// `Ok(String::new())`). A future refactor that swapped
    /// `.unwrap_or_else` for `.ok().filter(|s| !s.is_empty())` +
    /// fallback would silently reroute a shell-exported
    /// `FORGE_ENV=""` / `ATTIC_SERVER_NAME=""` /
    /// `SERVICE_REGISTRY_BASE=""` from empty-string to the
    /// caller-supplied default, and every consumer's downstream
    /// `format!("{}/...", ...)` would then compose against the
    /// default host name where pre-lift it composed against the empty
    /// leading segment. Explicit non-parity so the invariant survives
    /// a future primitive refinement.
    #[test]
    fn env_var_or_default_returns_empty_string_when_env_var_set_empty() {
        let env_var = "TEST_ENV_VAR_OR_DEFAULT_EMPTY_SIGIL_SHIELD";
        std::env::set_var(env_var, "");
        let result = env_var_or_default(env_var, "the-fallback-must-not-fire");
        std::env::remove_var(env_var);
        assert_eq!(
            result, "",
            "env_var_or_default() must return the empty string \
             verbatim when the env var is set to \"\" — matches every \
             pre-lift sigil's `.unwrap_or_else(|_| ...)` semantics, \
             where the fallback fires only on the `Err` case."
        );
    }

    /// Serial-safe guard for tests that mutate the `SAFE` process env
    /// var. [`safe_mode_from_env`] reads it once per call; concurrent
    /// tests that set / remove it would race the resolved value observed
    /// by any test asserting on the primitive's return. Same
    /// `unwrap_or_else(|p| p.into_inner())` recovery shape as the
    /// sibling [`crate::git::tests::RELEASE_GIT_SHA_ENV_LOCK`] and
    /// [`crate::test_support::GIT_BIN_ENV_LOCK`] so a prior panicking
    /// test that poisoned the mutex does not chain-fail every subsequent
    /// test sharing the lock.
    static SAFE_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// [`safe_mode_from_env`] returns `true` when the `SAFE` env var
    /// is unset. Pins the default-TRUE half of the contract every
    /// pre-lift consumer (`main.rs::main`'s `Commands::Rollout` arm,
    /// `commands/github_runner_ci.rs::is_safe_mode`) spelled inline
    /// as `.unwrap_or(true)` — an accidental default flip to `false`
    /// would silently disable rollout retries and Attic-login/push
    /// retries on every direct-CLI call where the operator did not
    /// explicitly export `SAFE`, the exact scenario the wrapper
    /// entrypoints treat as "retries on".
    #[test]
    fn safe_mode_from_env_defaults_to_true_when_unset() {
        let _guard = SAFE_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _snapshot = crate::test_support::EnvVarSnapshot::capture("SAFE");
        std::env::remove_var("SAFE");
        assert!(
            safe_mode_from_env(),
            "safe_mode_from_env() must default to `true` when `SAFE` \
             is unset — matches every pre-lift consumer's \
             `.unwrap_or(true)` on the `Err` case."
        );
    }

    /// [`safe_mode_from_env`] returns `false` when `SAFE=false`.
    /// Pins the disable-with-`false` half; a drop of the `!= \"false\"`
    /// clause would silently keep retries on even when the operator
    /// explicitly disabled them.
    #[test]
    fn safe_mode_from_env_is_false_for_literal_false() {
        let _guard = SAFE_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _snapshot = crate::test_support::EnvVarSnapshot::capture("SAFE");
        std::env::set_var("SAFE", "false");
        assert!(
            !safe_mode_from_env(),
            "safe_mode_from_env() must return `false` for `SAFE=false` \
             — the disable-with-`false` half of the contract every \
             pre-lift consumer spelled inline as `val != \"false\"`."
        );
    }

    /// [`safe_mode_from_env`] returns `false` when `SAFE=0`. Pins the
    /// disable-with-`0` half; a drop of the `!= \"0\"` clause would
    /// silently keep retries on for operators who spell the disable as
    /// the numeric zero.
    #[test]
    fn safe_mode_from_env_is_false_for_literal_zero() {
        let _guard = SAFE_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _snapshot = crate::test_support::EnvVarSnapshot::capture("SAFE");
        std::env::set_var("SAFE", "0");
        assert!(
            !safe_mode_from_env(),
            "safe_mode_from_env() must return `false` for `SAFE=0` \
             — the disable-with-`0` half of the contract every \
             pre-lift consumer spelled inline as `val != \"0\"`."
        );
    }

    /// [`safe_mode_from_env`] returns `false` for `SAFE=FALSE`,
    /// `SAFE=False`, and every other mixed-case spelling of `false`.
    /// Pins the `to_lowercase()` normalization step every pre-lift
    /// consumer spelled inline as `let val = v.to_lowercase();` — a
    /// drop of the normalizer would silently keep retries on for
    /// operators who capitalize the disable value.
    #[test]
    fn safe_mode_from_env_is_false_case_insensitive() {
        let _guard = SAFE_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _snapshot = crate::test_support::EnvVarSnapshot::capture("SAFE");
        for spelling in ["FALSE", "False", "fAlSe", "FALSe"] {
            std::env::set_var("SAFE", spelling);
            assert!(
                !safe_mode_from_env(),
                "safe_mode_from_env() must return `false` for \
                 `SAFE={spelling}` — the `to_lowercase()` normalization \
                 step every pre-lift consumer spelled inline via `let \
                 val = v.to_lowercase();`.",
            );
        }
    }

    /// [`safe_mode_from_env`] returns `true` when `SAFE=""` (an
    /// operator's explicit-empty export). Pins the empty-is-truthy
    /// parity: `"".to_lowercase()` is `""`, which satisfies both `!=
    /// "false"` and `!= "0"`, so the empty-string case lands on the
    /// default-true branch alongside an unset env var. A future
    /// primitive refinement that swapped the shape for a
    /// `.ok().filter(|s| !s.is_empty()).map(...).unwrap_or(true)`
    /// preserves this semantic; a swap to
    /// `.ok().is_some_and(...)`-style dispatch would flip it and
    /// silently misroute every `SAFE=""` export.
    #[test]
    fn safe_mode_from_env_is_true_for_empty_string() {
        let _guard = SAFE_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _snapshot = crate::test_support::EnvVarSnapshot::capture("SAFE");
        std::env::set_var("SAFE", "");
        assert!(
            safe_mode_from_env(),
            "safe_mode_from_env() must return `true` for `SAFE=\"\"` \
             — an empty string is neither `\"false\"` nor `\"0\"`, so \
             the empty-string case must land on the default-true branch."
        );
    }

    /// [`safe_mode_from_env`] returns `true` for any value that is
    /// neither `false` (any case) nor `0`. Pins the closed-set
    /// disable contract: only the two literal disable values flip
    /// retries off, and every other value (including plausible
    /// alternate spellings like `no`, `off`, `disable`, or a raw `1`)
    /// leaves retries ON. A future widening of the disable set to
    /// include e.g. `no` / `off` must land at the primitive body and
    /// break this shield, forcing an explicit contract update — not
    /// drift silently at one consumer only.
    #[test]
    fn safe_mode_from_env_is_true_for_unknown_value() {
        let _guard = SAFE_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _snapshot = crate::test_support::EnvVarSnapshot::capture("SAFE");
        for spelling in ["no", "off", "disable", "1", "true", "yes"] {
            std::env::set_var("SAFE", spelling);
            assert!(
                safe_mode_from_env(),
                "safe_mode_from_env() must return `true` for \
                 `SAFE={spelling}` — only literal `false` (any case) \
                 and literal `0` flip retries off; every other value \
                 leaves the default-true branch selected.",
            );
        }
    }

    /// [`truthy_flag_from_env`] returns `false` when the env var is unset.
    /// Pins the DEFAULT-FALSE half of the contract every pre-lift consumer
    /// (`commands/helm.rs::republish_enabled`,
    /// `commands/prerelease.rs::SKIP_INTEGRATION`,
    /// `commands/prerelease.rs::SKIP_E2E`) spelled inline as
    /// `.is_ok_and(...)` / `.unwrap_or(false)` on the `Err` case. An
    /// accidental default flip to `true` would silently re-enable Helm
    /// republish (destroying the immutability invariant of the shared
    /// `oci://ghcr.io/pleme-io/charts` registry) and silently skip G13 /
    /// G14 on every direct-CLI call where the operator did not
    /// explicitly opt in.
    #[test]
    fn truthy_flag_from_env_defaults_to_false_when_unset() {
        let env_var = "TEST_TRUTHY_FLAG_UNSET_SIGIL_SHIELD";
        std::env::remove_var(env_var);
        assert!(
            !truthy_flag_from_env(env_var),
            "truthy_flag_from_env() must default to `false` when the env \
             var is unset — matches every pre-lift consumer's \
             `.is_ok_and(...)` / `.unwrap_or(false)` on the `Err` case."
        );
    }

    /// [`truthy_flag_from_env`] returns `true` for the literal `"1"` —
    /// the enable-with-`1` half of the contract every pre-lift consumer
    /// spelled inline as `v == "1"`. A drop of the `"1"` clause would
    /// silently disable the `FORGE_HELM_REPUBLISH=1` shape documented in
    /// `helm.rs::republish_enabled`.
    #[test]
    fn truthy_flag_from_env_is_true_for_literal_one() {
        let env_var = "TEST_TRUTHY_FLAG_ONE_SIGIL_SHIELD";
        std::env::set_var(env_var, "1");
        let result = truthy_flag_from_env(env_var);
        std::env::remove_var(env_var);
        assert!(
            result,
            "truthy_flag_from_env() must return `true` for value `\"1\"` \
             — the enable-with-`1` half of the contract."
        );
    }

    /// [`truthy_flag_from_env`] returns `true` for the literal lowercase
    /// `"true"` — the enable-with-`true` half of the contract every
    /// pre-lift consumer spelled inline (case-sensitively in the two
    /// `prerelease.rs` sites, case-insensitively in `helm.rs`). Pins the
    /// primary spelling the operator-facing docs `commands/prerelease.rs`
    /// carry (`Skip with SKIP_INTEGRATION=true`,
    /// `Skip with SKIP_E2E=true`).
    #[test]
    fn truthy_flag_from_env_is_true_for_literal_lowercase_true() {
        let env_var = "TEST_TRUTHY_FLAG_TRUE_SIGIL_SHIELD";
        std::env::set_var(env_var, "true");
        let result = truthy_flag_from_env(env_var);
        std::env::remove_var(env_var);
        assert!(
            result,
            "truthy_flag_from_env() must return `true` for value \
             `\"true\"` — the enable-with-`true` half of the contract."
        );
    }

    /// [`truthy_flag_from_env`] is case-insensitive on `"true"` — every
    /// mixed-case spelling (`TRUE`, `True`, `TrUe`, `tRuE`) enables the
    /// flag. Load-bearing: pre-lift the two `commands/prerelease.rs`
    /// consumers used case-sensitive `v == "true"` and silently ignored
    /// `SKIP_INTEGRATION=TRUE` / `SKIP_E2E=TRUE` from operators who
    /// capitalized the value; `commands/helm.rs::republish_enabled` used
    /// `.eq_ignore_ascii_case("true")` and fired for the same input.
    /// Post-lift the primitive fires for both, closing that inter-file
    /// drift — a shield that fails if a future refactor of the primitive
    /// reverts to case-sensitive comparison.
    #[test]
    fn truthy_flag_from_env_is_true_case_insensitive_on_true() {
        let env_var = "TEST_TRUTHY_FLAG_CASE_SIGIL_SHIELD";
        for spelling in ["TRUE", "True", "TrUe", "tRuE", "TRUe"] {
            std::env::set_var(env_var, spelling);
            let result = truthy_flag_from_env(env_var);
            assert!(
                result,
                "truthy_flag_from_env() must return `true` for \
                 `env_var={spelling}` — `.eq_ignore_ascii_case(\"true\")` \
                 accepts every mixed-case spelling of the letters t-r-u-e."
            );
        }
        std::env::remove_var(env_var);
    }

    /// [`truthy_flag_from_env`] returns `false` when the env var is set
    /// to the empty string. Pins the empty-is-falsy parity: `"" == "1"`
    /// is false, and `"".eq_ignore_ascii_case("true")` is false (lengths
    /// differ), so an operator's explicit-empty export lands on the
    /// default-false branch alongside an unset env var. Sibling to
    /// [`safe_mode_from_env_is_true_for_empty_string`] on the opt-in
    /// mirror — a swap to `.ok().filter(|s| !s.is_empty())`-style
    /// dispatch would preserve this semantic; a hypothetical widen to
    /// "empty means enable" would flip it.
    #[test]
    fn truthy_flag_from_env_is_false_for_empty_string() {
        let env_var = "TEST_TRUTHY_FLAG_EMPTY_SIGIL_SHIELD";
        std::env::set_var(env_var, "");
        let result = truthy_flag_from_env(env_var);
        std::env::remove_var(env_var);
        assert!(
            !result,
            "truthy_flag_from_env() must return `false` for value `\"\"` \
             — neither `\"1\"` nor `eq_ignore_ascii_case(\"true\")` \
             accepts the empty string."
        );
    }

    /// [`truthy_flag_from_env`] returns `false` for every value outside
    /// the closed `{1, true (any case)}` enable set. Pins the closed-set
    /// enable contract: only the two literal enable values flip the flag
    /// on, and every other value (`"0"`, `"false"`, `"yes"`, `"on"`,
    /// `"disable"`, `"2"`, a plausible `"y"`) leaves it OFF. A future
    /// widening of the enable set to include `yes` / `on` must land at
    /// the primitive body and break this shield, forcing an explicit
    /// contract update — not drift silently at one consumer only.
    #[test]
    fn truthy_flag_from_env_is_false_for_non_enable_values() {
        let env_var = "TEST_TRUTHY_FLAG_NON_ENABLE_SIGIL_SHIELD";
        for spelling in [
            "0", "false", "FALSE", "no", "off", "yes", "on", "disable", "2", "y",
        ] {
            std::env::set_var(env_var, spelling);
            let result = truthy_flag_from_env(env_var);
            assert!(
                !result,
                "truthy_flag_from_env() must return `false` for \
                 `env_var={spelling}` — only literal `\"1\"` and \
                 `\"true\"` (case-insensitive) flip the flag on; every \
                 other value leaves the default-false branch selected."
            );
        }
        std::env::remove_var(env_var);
    }

    /// The monorepo terminal fires at the `{product}` node when its parent
    /// is `products` and its grandparent is `pkgs`. Pins the returned path
    /// to the `{product}` component itself — i.e. `.../pkgs/products/foo`
    /// walked up from a nested `services/bar` child, NOT the `services`
    /// sub-node or the `pkgs` root. Same shape every pre-lift consumer
    /// spelled: the walk-up returns the FIRST ancestor whose parent is
    /// `products` and grandparent is `pkgs`, so a deep service subtree
    /// resolves to its owning product directory.
    #[test]
    fn find_product_dir_monorepo_returns_product_dir_from_nested_service() {
        let root = tempfile::tempdir().expect("root tempdir");
        let product = root.path().join("pkgs").join("products").join("foo");
        let service = product.join("services").join("bar");
        std::fs::create_dir_all(&service).expect("create nested service dir");

        assert_eq!(
            find_product_dir(&service, ProductDirLayout::Monorepo),
            Some(product)
        );
    }

    /// A path with no `pkgs/products/{product}` ancestor and no
    /// `deploy.yaml`+`.git` marker under [`ProductDirLayout::Monorepo`]
    /// returns `None` at the filesystem-root terminal. Guards the walker's
    /// termination shape — the pre-lift `loop {}` returned `None` only
    /// when `current.parent()` was `None` at the outermost climb, and this
    /// post-lift shape must match. A silent `Some(root)` return here
    /// (e.g. a mis-refactored "any path counts" acceptance rule) would
    /// silently reroute every consumer's `deploy.yaml` lookup to the
    /// filesystem root.
    #[test]
    fn find_product_dir_monorepo_returns_none_when_no_pkgs_products_ancestor() {
        let root = tempfile::tempdir().expect("root tempdir");
        let unrelated = root.path().join("some").join("other").join("place");
        std::fs::create_dir_all(&unrelated).expect("create unrelated dir");

        assert!(find_product_dir(&unrelated, ProductDirLayout::Monorepo).is_none());
    }

    /// Under [`ProductDirLayout::MonorepoOrStandalone`], a directory
    /// carrying BOTH `deploy.yaml` and `.git` at the current node terminates
    /// the walk at that node — the pre-lift
    /// `commands/rust_service.rs::find_product_dir_from_path` shape. The
    /// walk starts from a nested subdirectory to prove the standalone
    /// terminal is checked at every level of the parent climb, not only at
    /// `start`.
    #[test]
    fn find_product_dir_standalone_terminal_matches_deploy_yaml_and_git() {
        let root = tempfile::tempdir().expect("root tempdir");
        let repo_root = root.path().join("standalone-product");
        std::fs::create_dir_all(&repo_root).expect("create repo root");
        std::fs::write(repo_root.join("deploy.yaml"), "kind: deploy\n").expect("write deploy.yaml");
        std::fs::create_dir_all(repo_root.join(".git")).expect("create .git");
        let nested = repo_root.join("crates").join("worker");
        std::fs::create_dir_all(&nested).expect("create nested crate dir");

        assert_eq!(
            find_product_dir(&nested, ProductDirLayout::MonorepoOrStandalone),
            Some(repo_root)
        );
    }

    /// Under [`ProductDirLayout::Monorepo`], the standalone terminal is
    /// NOT checked — a `deploy.yaml`+`.git` directory outside a
    /// `pkgs/products/{product}` layout returns `None`. Pins the layout
    /// enum's semantics at the terminal boundary: a caller passing
    /// [`ProductDirLayout::Monorepo`] gets exactly the pre-lift
    /// monorepo-only shape, not a superset. Without this a future
    /// refactor could silently widen the `Monorepo` variant to also fire
    /// the standalone check and misroute `commands/status.rs` /
    /// `commands/integration_tests.rs` / `commands/test.rs`.
    #[test]
    fn find_product_dir_monorepo_ignores_standalone_marker() {
        let root = tempfile::tempdir().expect("root tempdir");
        let repo_root = root.path().join("standalone-product");
        std::fs::create_dir_all(&repo_root).expect("create repo root");
        std::fs::write(repo_root.join("deploy.yaml"), "kind: deploy\n").expect("write deploy.yaml");
        std::fs::create_dir_all(repo_root.join(".git")).expect("create .git");

        assert!(find_product_dir(&repo_root, ProductDirLayout::Monorepo).is_none());
    }

    /// A `deploy.yaml` alone (no `.git`) does NOT satisfy the standalone
    /// terminal — the pre-lift
    /// `commands/rust_service.rs::find_product_dir_from_path` shape
    /// required BOTH markers via `&&`. Prevents a bare-`deploy.yaml`
    /// intermediary directory in the walk (e.g. a `deploy/` folder holding
    /// per-service YAMLs) from being misidentified as a product root.
    #[test]
    fn find_product_dir_standalone_requires_both_deploy_yaml_and_git() {
        let root = tempfile::tempdir().expect("root tempdir");
        let repo_root = root.path().join("half-standalone");
        std::fs::create_dir_all(&repo_root).expect("create repo root");
        std::fs::write(repo_root.join("deploy.yaml"), "kind: deploy\n").expect("write deploy.yaml");

        assert!(find_product_dir(&repo_root, ProductDirLayout::MonorepoOrStandalone).is_none());
    }

    /// Monorepo terminal wins over standalone terminal when both fire at
    /// the same node. A `pkgs/products/{product}` directory that also
    /// carries `deploy.yaml`+`.git` returns via the monorepo branch, not
    /// the standalone one — preserves the pre-lift
    /// `commands/rust_service.rs::find_product_dir_from_path` precedence
    /// (monorepo check first, standalone check second, per iteration).
    /// Load-bearing because the return value shape is identical either way
    /// (`Some(current)`), so the branch that fires isn't observable at
    /// the return, only at the walker's internal ordering — and a
    /// reordering that silently checked standalone first would still
    /// return `Some(current)` at this test's node but would diverge at a
    /// hypothetical layout that terminated on a lower-precedence rule
    /// first.
    #[test]
    fn find_product_dir_monorepo_terminal_wins_when_both_fire() {
        let root = tempfile::tempdir().expect("root tempdir");
        let product = root.path().join("pkgs").join("products").join("foo");
        std::fs::create_dir_all(&product).expect("create product dir");
        std::fs::write(product.join("deploy.yaml"), "kind: deploy\n").expect("write deploy.yaml");
        std::fs::create_dir_all(product.join(".git")).expect("create .git");

        assert_eq!(
            find_product_dir(&product, ProductDirLayout::MonorepoOrStandalone),
            Some(product)
        );
    }

    /// Under [`ProductDirLayout::MonorepoOrNamedStandalone`], a directory
    /// carrying `.git` + `deploy.yaml` whose YAML exposes a top-level
    /// string `name:` field terminates the walk at that node. Mirrors the
    /// pre-lift `config::DeployConfig::find_product_directory` shape: the
    /// walk starts from a nested subdirectory to prove the named-standalone
    /// terminal is checked at every level of the parent climb, not only at
    /// `start`.
    #[test]
    fn find_product_dir_named_standalone_terminal_matches_name_field() {
        let root = tempfile::tempdir().expect("root tempdir");
        let repo_root = root.path().join("named-standalone");
        std::fs::create_dir_all(&repo_root).expect("create repo root");
        std::fs::write(repo_root.join("deploy.yaml"), "name: my-product\n")
            .expect("write deploy.yaml with name");
        std::fs::create_dir_all(repo_root.join(".git")).expect("create .git");
        let nested = repo_root.join("crates").join("worker");
        std::fs::create_dir_all(&nested).expect("create nested crate dir");

        assert_eq!(
            find_product_dir(&nested, ProductDirLayout::MonorepoOrNamedStandalone),
            Some(repo_root)
        );
    }

    /// Under [`ProductDirLayout::MonorepoOrNamedStandalone`], a
    /// `.git`+`deploy.yaml` node whose YAML lacks a top-level `name:`
    /// field CONTINUES the climb rather than terminating. Load-bearing:
    /// the pre-lift `config::DeployConfig::find_product_directory` used
    /// this to distinguish a genuine product-repo root (carries a
    /// product `name:`) from any other repo whose `deploy.yaml` fragment
    /// happens to describe something else (e.g. only environment
    /// settings, or a top-level manifest for a non-product artifact).
    /// Without this rule the loader would silently mis-terminate at the
    /// wrong `.git` and resolve a wrong product name.
    #[test]
    fn find_product_dir_named_standalone_ignores_yaml_without_name_field() {
        let root = tempfile::tempdir().expect("root tempdir");
        let repo_root = root.path().join("nameless");
        std::fs::create_dir_all(&repo_root).expect("create repo root");
        std::fs::write(repo_root.join("deploy.yaml"), "kind: deploy\n")
            .expect("write deploy.yaml without name");
        std::fs::create_dir_all(repo_root.join(".git")).expect("create .git");

        assert!(
            find_product_dir(&repo_root, ProductDirLayout::MonorepoOrNamedStandalone).is_none()
        );
    }

    /// Under [`ProductDirLayout::MonorepoOrNamedStandalone`], a
    /// `.git`+`deploy.yaml` whose CONTENT is unparseable YAML CONTINUES
    /// the climb, matching the pre-lift
    /// `config::DeployConfig::find_product_directory` tolerate-parse-
    /// failures shape (`if let Ok(yaml) = serde_yaml::from_str::<...>(...)`).
    /// A parse error propagating out of the walker would be a hard
    /// regression: today a stray malformed `deploy.yaml` at a wrong
    /// ancestor still lets the walker reach a valid deeper product root;
    /// after the port that must remain true.
    #[test]
    fn find_product_dir_named_standalone_tolerates_unparseable_yaml() {
        let root = tempfile::tempdir().expect("root tempdir");
        let repo_root = root.path().join("broken");
        std::fs::create_dir_all(&repo_root).expect("create repo root");
        // Intentionally malformed YAML: unbalanced braces + tab where a
        // key is expected.
        std::fs::write(repo_root.join("deploy.yaml"), "\t{{\n")
            .expect("write malformed deploy.yaml");
        std::fs::create_dir_all(repo_root.join(".git")).expect("create .git");

        assert!(
            find_product_dir(&repo_root, ProductDirLayout::MonorepoOrNamedStandalone).is_none()
        );
    }

    /// Under [`ProductDirLayout::MonorepoOrNamedStandalone`], the
    /// monorepo terminal STILL fires (and takes precedence) at a
    /// `pkgs/products/{product}` node even when that node ALSO carries a
    /// named standalone `.git`+`deploy.yaml`. Pins the precedence rule
    /// per (4) of `find_product_dir`'s doc: the closed enum adds only an
    /// alternative terminal, never redirects the monorepo one. Without
    /// this a well-formed monorepo product that additionally happens to
    /// carry a nested `.git` (e.g. a submodule root, a dev-only
    /// scratch git init) would silently return via the named-standalone
    /// branch instead of the monorepo branch — the pre-lift consumers'
    /// documented shape.
    #[test]
    fn find_product_dir_named_standalone_monorepo_terminal_still_wins() {
        let root = tempfile::tempdir().expect("root tempdir");
        let product = root.path().join("pkgs").join("products").join("foo");
        std::fs::create_dir_all(&product).expect("create product dir");
        std::fs::write(product.join("deploy.yaml"), "name: foo\n")
            .expect("write deploy.yaml with name");
        std::fs::create_dir_all(product.join(".git")).expect("create .git");

        assert_eq!(
            find_product_dir(&product, ProductDirLayout::MonorepoOrNamedStandalone),
            Some(product)
        );
    }

    /// The `Monorepo` variant IGNORES the named-standalone marker (a
    /// `.git`+`deploy.yaml` whose YAML carries `name:`) — sibling of the
    /// existing `find_product_dir_monorepo_ignores_standalone_marker`
    /// test for the plain standalone marker. Guards the closed enum
    /// against a future refactor that silently widens `Monorepo` to also
    /// fire either standalone check.
    #[test]
    fn find_product_dir_monorepo_ignores_named_standalone_marker() {
        let root = tempfile::tempdir().expect("root tempdir");
        let repo_root = root.path().join("named-standalone");
        std::fs::create_dir_all(&repo_root).expect("create repo root");
        std::fs::write(repo_root.join("deploy.yaml"), "name: my-product\n")
            .expect("write deploy.yaml with name");
        std::fs::create_dir_all(repo_root.join(".git")).expect("create .git");

        assert!(find_product_dir(&repo_root, ProductDirLayout::Monorepo).is_none());
    }

    /// [`activate_root_flake`] publishes `REPO_ROOT` to the process
    /// environment as its FIRST side-effect, matching the pre-lift
    /// ordering at all three consumers (`main::setup_service_directory`,
    /// `commands/status::execute`, `commands/integration_tests::execute_manual`).
    /// A downstream `repo::find_repo_root` / `git::get_repo_root` /
    /// `PathBuilder::new` reading `REPO_ROOT` after the call sees the
    /// caller-supplied path, regardless of the chdir outcome.
    #[test]
    fn activate_root_flake_publishes_repo_root_env_var() {
        let _guard = crate::test_support::ROOT_FLAKE_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let _env = crate::test_support::RootFlakeEnvSnapshot::capture();
        let dir = tempfile::tempdir().expect("tempdir");
        let repo_root = dir.path().join("repo");
        let service_dir = dir.path().join("repo").join("services").join("api");
        std::fs::create_dir_all(&service_dir).expect("create service dir");

        activate_root_flake(&repo_root, &service_dir).expect("activate");
        assert_eq!(
            std::env::var("REPO_ROOT")
                .ok()
                .map(PathBuf::from)
                .as_deref(),
            Some(repo_root.as_path())
        );
    }

    /// [`activate_root_flake`] publishes `SERVICE_DIR` to the process
    /// environment. Load-bearing: `DeployConfig::load_for_service`,
    /// `commands/developer_tools`, `commands/schema_validation`,
    /// `commands/bootstrap`, and `commands/rust_service` all read
    /// `SERVICE_DIR` — a caller that set `REPO_ROOT` but forgot
    /// `SERVICE_DIR` would silently misroute service discovery to
    /// whatever `SERVICE_DIR` the calling shell inherited. Pins the
    /// invariant that the primitive's contract makes the omission
    /// structurally impossible.
    #[test]
    fn activate_root_flake_publishes_service_dir_env_var() {
        let _guard = crate::test_support::ROOT_FLAKE_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let _env = crate::test_support::RootFlakeEnvSnapshot::capture();
        let dir = tempfile::tempdir().expect("tempdir");
        let repo_root = dir.path().join("repo");
        let service_dir = dir.path().join("repo").join("services").join("worker");
        std::fs::create_dir_all(&service_dir).expect("create service dir");

        activate_root_flake(&repo_root, &service_dir).expect("activate");
        assert_eq!(
            std::env::var("SERVICE_DIR")
                .ok()
                .map(PathBuf::from)
                .as_deref(),
            Some(service_dir.as_path())
        );
    }

    /// [`activate_root_flake`] changes the process working directory to
    /// `repo_root` — NOT `service_dir`. Load-bearing: the root-flake
    /// pattern (documented at `main::setup_service_directory`) runs
    /// `nix build` from the repo root, and every subsequent
    /// path-relative read in the CLI presupposes that root is the cwd.
    /// A migration that silently reversed the chdir target to
    /// `service_dir` would break every `nix flake` invocation
    /// downstream, so the test asserts the equality against `repo_root`
    /// canonicalized to match `set_current_dir`'s canonicalization.
    #[test]
    fn activate_root_flake_chdirs_to_repo_root_not_service_dir() {
        let _guard = crate::test_support::ROOT_FLAKE_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let _env = crate::test_support::RootFlakeEnvSnapshot::capture();
        let dir = tempfile::tempdir().expect("tempdir");
        let repo_root = dir.path().join("repo");
        let service_dir = repo_root.join("services").join("api");
        std::fs::create_dir_all(&service_dir).expect("create service dir");

        activate_root_flake(&repo_root, &service_dir).expect("activate");
        let observed = std::env::current_dir().expect("cwd after activate");
        // Both sides go through canonicalize so a `/private/var/...` vs
        // `/var/...` symlink prefix at the tempdir root does not flake
        // the equality reading.
        let expected = repo_root.canonicalize().expect("canonicalize repo_root");
        let observed = observed.canonicalize().expect("canonicalize observed");
        assert_eq!(observed, expected);
    }

    /// [`activate_root_flake`] sets both env vars BEFORE attempting the
    /// chdir. Load-bearing: if the chdir fails (a caller passing a
    /// nonexistent path, a permission drop mid-pipeline), the env vars
    /// remain populated so a downstream `?`-propagated error handler
    /// can still read `REPO_ROOT` for its own diagnostics. Every
    /// pre-lift consumer had this property by accident of source-order
    /// (the two `set_var` lines preceded the `?` on `set_current_dir`);
    /// the primitive preserves it by construction, and this test pins
    /// it so a future rewrite that reordered the primitive's body
    /// cannot silently regress the invariant.
    #[test]
    fn activate_root_flake_publishes_env_vars_even_when_chdir_fails() {
        let _guard = crate::test_support::ROOT_FLAKE_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let _env = crate::test_support::RootFlakeEnvSnapshot::capture();
        let dir = tempfile::tempdir().expect("tempdir");
        // Point repo_root at a path that DOES NOT exist so
        // set_current_dir fails; service_dir can still be any path.
        let nonexistent_repo_root = dir.path().join("does-not-exist");
        let service_dir = dir.path().join("service");
        assert!(!nonexistent_repo_root.exists());

        let result = activate_root_flake(&nonexistent_repo_root, &service_dir);
        assert!(result.is_err(), "chdir to nonexistent path should fail");
        // Env vars remain published despite the chdir failure.
        assert_eq!(
            std::env::var("REPO_ROOT")
                .ok()
                .map(PathBuf::from)
                .as_deref(),
            Some(nonexistent_repo_root.as_path())
        );
        assert_eq!(
            std::env::var("SERVICE_DIR")
                .ok()
                .map(PathBuf::from)
                .as_deref(),
            Some(service_dir.as_path())
        );
    }

    /// The chdir-failure error surfaces `repo_root`'s path in its
    /// context, so a `?`-propagated error the CLI prints to the
    /// operator names the exact directory that could not be entered.
    /// Pre-lift each consumer got a bare `std::io::Error` from
    /// `set_current_dir` with no path context; post-lift the primitive
    /// attaches `with_context` naming the offending path — a small
    /// diagnostic upgrade at every consumer by construction.
    #[test]
    fn activate_root_flake_error_context_names_the_repo_root_path() {
        let _guard = crate::test_support::ROOT_FLAKE_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let _env = crate::test_support::RootFlakeEnvSnapshot::capture();
        let dir = tempfile::tempdir().expect("tempdir");
        let nonexistent_repo_root = dir.path().join("nope");
        let service_dir = dir.path().join("service");

        let err = activate_root_flake(&nonexistent_repo_root, &service_dir).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains(&nonexistent_repo_root.display().to_string()),
            "error should name the repo_root path; got: {msg}"
        );
    }

    /// The primitive accepts the caller's argument shape verbatim
    /// (`&str`, `String`, `&Path`, `PathBuf`) via `AsRef<Path>` bounds
    /// on both parameters. Load-bearing: the three pre-lift consumers
    /// each spelled the arguments differently (`main` passed
    /// `&String` from an `Option<String>` binding, `status` and
    /// `integration_tests` passed `&str` from their `&str`
    /// parameters). A single-type signature (e.g. `&str`-only) would
    /// have forced boilerplate at the `main` site; the `AsRef<Path>`
    /// bound makes every caller-shape pass by construction.
    #[test]
    fn activate_root_flake_accepts_str_and_string_and_path_args() {
        let _guard = crate::test_support::ROOT_FLAKE_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let _env = crate::test_support::RootFlakeEnvSnapshot::capture();
        let dir = tempfile::tempdir().expect("tempdir");
        let repo_root = dir.path().join("repo");
        let service_dir = repo_root.join("s");
        std::fs::create_dir_all(&service_dir).expect("mkdir");
        let repo_root_str: &str = repo_root.to_str().unwrap();
        let service_dir_string: String = service_dir.display().to_string();

        // &str for repo_root, String for service_dir.
        activate_root_flake(repo_root_str, service_dir_string).expect("&str + String");
        // &Path for repo_root, PathBuf for service_dir.
        activate_root_flake(repo_root.as_path(), repo_root.join("s")).expect("&Path + PathBuf");
        // &String for repo_root (matches the pre-lift main.rs shape),
        // &str for service_dir (matches the pre-lift status.rs shape).
        let repo_root_owned: String = repo_root.display().to_string();
        activate_root_flake(&repo_root_owned, "").ok();
    }

    /// The `MonorepoOrStandalone` variant does NOT verify the `name:`
    /// field — a `.git`+`deploy.yaml` node without `name:` terminates
    /// there under `MonorepoOrStandalone` (per the existing
    /// `find_product_dir_standalone_terminal_matches_deploy_yaml_and_git`
    /// test) but CONTINUES under `MonorepoOrNamedStandalone`. Pins the
    /// two standalone variants as independent branches: a shift of one
    /// variant's terminal condition must not silently reroute the other.
    #[test]
    fn find_product_dir_standalone_and_named_standalone_diverge_at_missing_name() {
        let root = tempfile::tempdir().expect("root tempdir");
        let repo_root = root.path().join("nameless");
        std::fs::create_dir_all(&repo_root).expect("create repo root");
        std::fs::write(repo_root.join("deploy.yaml"), "kind: deploy\n")
            .expect("write deploy.yaml without name");
        std::fs::create_dir_all(repo_root.join(".git")).expect("create .git");

        assert_eq!(
            find_product_dir(&repo_root, ProductDirLayout::MonorepoOrStandalone),
            Some(repo_root.clone())
        );
        assert!(
            find_product_dir(&repo_root, ProductDirLayout::MonorepoOrNamedStandalone).is_none()
        );
    }

    /// [`env_var_optional`] returns `None` when the env var is unset.
    /// Pins the `Err → None` half every pre-lift `env::var(NAME).ok()`
    /// stanza depended on — the six `Option<String>` gate / enrichment
    /// sites in `commands/sync.rs`, `observability.rs`, and
    /// `infrastructure/registry.rs` all treated the unset case as
    /// "absent" (return `Ok(false)` early, omit the field from the
    /// event, fall through to the next `.or_else` arm). A silent flip
    /// to `Some(String::new())` on the unset case would misroute every
    /// consumer's `.is_none()` / `.or_else` dispatch.
    #[test]
    fn env_var_optional_returns_none_when_env_var_unset() {
        let env_var = "TEST_ENV_VAR_OPTIONAL_UNSET_SIGIL_SHIELD";
        std::env::remove_var(env_var);
        assert_eq!(
            env_var_optional(env_var),
            None,
            "env_var_optional() must return `None` on the unset case — \
             matches every pre-lift `env::var(NAME).ok()` sigil's \
             `Err → None` projection, the projection consumers gate on."
        );
    }

    /// [`env_var_optional`] returns the env var's value inside `Some`
    /// verbatim when it IS set. Pins the `Ok(v) → Some(v)` set-path
    /// projection so a future refinement (a canonicalize prefix, a
    /// closed-enum canonicalization, a `.map(str::trim)` fold) is
    /// caught here rather than at each consumer's downstream unwrap.
    #[test]
    fn env_var_optional_returns_some_value_when_env_var_set() {
        let env_var = "TEST_ENV_VAR_OPTIONAL_SET_SIGIL_SHIELD";
        let sentinel = "explicit-value-not-none";
        std::env::set_var(env_var, sentinel);
        let result = env_var_optional(env_var);
        std::env::remove_var(env_var);
        assert_eq!(
            result,
            Some(sentinel.to_string()),
            "env_var_optional() must return `Some(env::var(env_var))` \
             verbatim when set — the projection every pre-lift \
             `env::var(NAME).ok()` sigil spelled inline."
        );
    }

    /// [`env_var_optional`] returns `Some(String::new())` — NOT `None`
    /// — when the env var is set to `""`. Pins the empty-string-is-a-
    /// VALUE half of the split against
    /// [`crate::git::release_git_sha_from_env`]'s empty-string-is-MISS
    /// mirror. A future primitive refactor that swapped `.ok()` for
    /// `.ok().filter(|s| !s.is_empty())` would silently reroute a
    /// shell-exported `PUSHGATEWAY_URL=""` / `HOSTNAME=""` /
    /// `DATABASE_URL=""` from `Some("")` to `None`, collapsing the two
    /// peers onto one body and defeating the split the two sibling
    /// primitives close on. Sibling shield to
    /// [`crate::git::tests`]'s empty-string-is-miss assertions on the
    /// mirror.
    #[test]
    fn env_var_optional_returns_some_empty_string_when_env_var_set_empty() {
        let env_var = "TEST_ENV_VAR_OPTIONAL_EMPTY_SIGIL_SHIELD";
        std::env::set_var(env_var, "");
        let result = env_var_optional(env_var);
        std::env::remove_var(env_var);
        assert_eq!(
            result,
            Some(String::new()),
            "env_var_optional() must return `Some(String::new())` \
             verbatim when the env var is set to \"\" — matches every \
             pre-lift `env::var(NAME).ok()` sigil's semantics, where \
             `Ok(String::new())` folds to `Some(String::new())`, NOT \
             `None`. That parity is what splits this primitive from \
             the sibling empty-is-miss `release_git_sha_from_env`."
        );
    }

    /// Post-lift the callers migrated onto [`env_var_optional`] no
    /// longer spell the `std::env::var(<NAME>).ok()` shape inline.
    /// Structural regression shield — without it, a future refactor
    /// could silently re-inline the shape (e.g. a helpful "just call
    /// `std::env::var` directly, it's shorter" cleanup) and reopen the
    /// duplication class this lift closed. Enforced at the module
    /// bodies before their `#[cfg(test)]` regions so a test-support
    /// mention of the raw shape does not defeat the shield.
    #[test]
    fn env_var_optional_callers_delegate_through_primitive() {
        const CALLERS: &[(&str, &str, &[&str])] = &[
            (
                include_str!("commands/sync.rs"),
                "commands/sync.rs",
                &["DATABASE_URL"],
            ),
            (
                include_str!("observability.rs"),
                "observability.rs",
                &["HOSTNAME", "GITHUB_RUN_ID", "CI_JOB_ID", "PUSHGATEWAY_URL"],
            ),
            (
                include_str!("infrastructure/registry.rs"),
                "infrastructure/registry.rs",
                &["GHCR_TOKEN", "GITHUB_TOKEN"],
            ),
        ];
        for (source, module_path, names) in CALLERS {
            let body = crate::test_support::module_body_before_tests(source, module_path);
            for name in *names {
                let raw = format!("std::env::var(\"{name}\").ok()");
                let short = format!("env::var(\"{name}\").ok()");
                assert!(
                    !body.contains(&raw) && !body.contains(&short),
                    "{module_path} body must NOT spell the inline \
                     `env::var(\"{name}\").ok()` shape — that \
                     `Option<String>` duplication was lifted onto \
                     `crate::repo::env_var_optional`. A re-inline would \
                     silently reopen the class this shield exists to \
                     close."
                );
                let call = format!("env_var_optional(\"{name}\")");
                assert!(
                    body.contains(&call),
                    "{module_path} body must forward to \
                     `crate::repo::env_var_optional(\"{name}\")` — the \
                     primitive body every `Option<String>` env-var \
                     sigil in the crate now delegates through."
                );
            }
        }
    }

    /// [`path_from_env_optional`] returns `None` when the env var is
    /// unset. Pins the `Err → None` half every pre-lift
    /// `if let Ok(v) = env::var(NAME) { PathBuf::from(v) }` inline
    /// stanza depended on — the six `Option<PathBuf>` env-var-first
    /// shortcut sites in `find_repo_root`, `git::get_repo_root`,
    /// `path_builder::PathBuilder::new`, `commands/bootstrap.rs`,
    /// `commands/pangea.rs`, and `nix_hooks.rs` all treated the
    /// unset case as "absent" (skip the arm and fall through to the
    /// non-env fallback: walk parents, `git rev-parse`, `find_repo_root`,
    /// standard `$HOME/code` locations, `nix build .#nix-hooks`). A
    /// silent flip to `Some(PathBuf::new())` on the unset case would
    /// misroute every consumer's fall-through arm into treating the
    /// current working directory as the substrate root.
    #[test]
    fn path_from_env_optional_returns_none_when_env_var_unset() {
        let env_var = "TEST_PATH_FROM_ENV_OPTIONAL_UNSET_SIGIL_SHIELD";
        std::env::remove_var(env_var);
        assert_eq!(
            path_from_env_optional(env_var),
            None,
            "path_from_env_optional() must return `None` on the unset \
             case — matches every pre-lift `if let Ok(v) = \
             env::var(NAME) {{ PathBuf::from(v) }}` stanza's `Err → \
             None` projection, the projection consumers gate on."
        );
    }

    /// [`path_from_env_optional`] returns the env var's value inside
    /// `Some(PathBuf::from(v))` verbatim when it IS set. Pins the
    /// `Ok(v) → Some(PathBuf::from(v))` set-path projection so a
    /// future refinement (canonicalize via `std::fs::canonicalize`, a
    /// must-exist filter, an absolutize hook against CWD) is caught
    /// here rather than at each consumer's downstream `.join(...)`
    /// / `.exists()` composition.
    #[test]
    fn path_from_env_optional_returns_some_path_when_env_var_set() {
        let env_var = "TEST_PATH_FROM_ENV_OPTIONAL_SET_SIGIL_SHIELD";
        let sentinel = "/tmp/explicit-path-not-none";
        std::env::set_var(env_var, sentinel);
        let result = path_from_env_optional(env_var);
        std::env::remove_var(env_var);
        assert_eq!(
            result,
            Some(PathBuf::from(sentinel)),
            "path_from_env_optional() must return \
             `Some(PathBuf::from(env::var(env_var)))` verbatim when \
             set — the projection every pre-lift `if let Ok(v) = \
             env::var(NAME) {{ PathBuf::from(v) }}` stanza spelled \
             inline."
        );
    }

    /// [`path_from_env_optional`] returns `Some(PathBuf::new())` —
    /// NOT `None` — when the env var is set to `""`. Pins the
    /// empty-string-is-a-VALUE half inherited from
    /// [`env_var_optional`] (which itself splits against
    /// [`crate::git::release_git_sha_from_env`]'s empty-string-is-MISS
    /// mirror). A future primitive refactor that composed on
    /// `release_git_sha_from_env`-style
    /// `.ok().filter(|s| !s.is_empty())` semantics instead of
    /// [`env_var_optional`] would silently reroute a shell-exported
    /// `REPO_ROOT=""` / `SERVICE_DIR=""` / `NIX_HOOKS_PATH=""` from
    /// `Some(PathBuf::new())` to `None` and collapse the split the two
    /// sibling primitives close on. Parity with the pre-lift
    /// `if let Ok(v) = env::var(NAME)` shape, where `Ok(String::new())`
    /// matched the arm and flowed into `PathBuf::from("")`.
    #[test]
    fn path_from_env_optional_returns_some_empty_path_when_env_var_set_empty() {
        let env_var = "TEST_PATH_FROM_ENV_OPTIONAL_EMPTY_SIGIL_SHIELD";
        std::env::set_var(env_var, "");
        let result = path_from_env_optional(env_var);
        std::env::remove_var(env_var);
        assert_eq!(
            result,
            Some(PathBuf::new()),
            "path_from_env_optional() must return `Some(PathBuf::new())` \
             verbatim when the env var is set to \"\" — matches every \
             pre-lift `if let Ok(v) = env::var(NAME) {{ PathBuf::from(v) \
             }}` stanza's semantics, where `Ok(String::new())` matched \
             the arm and flowed into `PathBuf::from(\"\")`. That parity \
             is what inherits the split from the sibling \
             `env_var_optional` primitive against the empty-is-miss \
             `release_git_sha_from_env`."
        );
    }

    /// Post-lift the callers migrated onto [`path_from_env_optional`]
    /// no longer spell the `if let Ok(v) = env::var(NAME) { ...
    /// PathBuf::from(v) ... }` shape inline. Structural regression
    /// shield — without it, a future refactor could silently re-inline
    /// the two-line stanza (e.g. a "just call `env::var` directly,
    /// then `PathBuf::from`, it's shorter" cleanup) and reopen the
    /// duplication class this lift closed. Enforced at the module
    /// bodies before their `#[cfg(test)]` regions so a test-support
    /// mention of the raw shape does not defeat the shield. The
    /// two-line adjacency (line N `env::var(NAME)`, line N+1
    /// `PathBuf::from(v)`) uniquely identifies the pre-lift shape;
    /// bare `if let Ok(_) = env::var(NAME)` reads whose next line does
    /// NOT hand the value to `PathBuf::from` (e.g. the
    /// `env_var_optional`-shaped `.ok()` sigils, the truthy-flag
    /// consumers, the boolean gates) stay unshielded — morally-
    /// adjacent shapes with their own lift target, not this one.
    #[test]
    fn path_from_env_optional_callers_delegate_through_primitive() {
        const CALLERS: &[(&str, &str, &[&str])] = &[
            (include_str!("git.rs"), "git.rs", &["REPO_ROOT"]),
            (
                include_str!("path_builder.rs"),
                "path_builder.rs",
                &["REPO_ROOT"],
            ),
            (
                include_str!("commands/bootstrap.rs"),
                "commands/bootstrap.rs",
                &["SERVICE_DIR"],
            ),
            (
                include_str!("nix_hooks.rs"),
                "nix_hooks.rs",
                &["NIX_HOOKS_PATH"],
            ),
        ];
        for (source, module_path, names) in CALLERS {
            let body = crate::test_support::module_body_before_tests(source, module_path);
            for name in *names {
                let raw = format!("std::env::var(\"{name}\")");
                let short = format!("env::var(\"{name}\")");
                assert!(
                    !body.contains(&raw) && !body.contains(&short),
                    "{module_path} body must NOT spell the inline \
                     `env::var(\"{name}\")` read — that \
                     `Option<PathBuf>` env-var-first shortcut was \
                     lifted onto `crate::repo::path_from_env_optional`. \
                     A re-inline would silently reopen the class this \
                     shield exists to close."
                );
                let call = format!("path_from_env_optional(\"{name}\")");
                assert!(
                    body.contains(&call),
                    "{module_path} body must forward to \
                     `crate::repo::path_from_env_optional(\"{name}\")` \
                     — the primitive body every `Option<PathBuf>` \
                     env-var-first shortcut in the crate now delegates \
                     through."
                );
            }
        }
        // `commands/pangea.rs::find_external_repo` composes the env-var
        // name dynamically as `format!("{}_DIR", name.to_uppercase())`
        // rather than hand-spelling a literal — its delegation is
        // shielded by needle-matching the primitive call site
        // instead of a per-name literal, so a re-inline that dropped
        // the dynamic-name arg would still fail the shield loudly.
        let pangea_body = crate::test_support::module_body_before_tests(
            include_str!("commands/pangea.rs"),
            "commands/pangea.rs",
        );
        assert!(
            pangea_body.contains("path_from_env_optional(&env_var)"),
            "commands/pangea.rs body must forward to \
             `crate::repo::path_from_env_optional(&env_var)` for the \
             dynamic `<NAME>_DIR` env-var arm — the primitive body \
             every `Option<PathBuf>` env-var-first shortcut in the \
             crate now delegates through."
        );
    }

    /// [`read_yaml_sync`] deserializes a well-formed YAML file at the
    /// caller's target type. Pins the round-trip: a regression that
    /// swapped the `serde_yaml::from_str` call for `serde_json::from_str`
    /// (or that returned the raw content string instead of the parsed
    /// value) fails here.
    #[test]
    fn read_yaml_sync_deserializes_well_formed_yaml_into_typed_target() {
        #[derive(serde::Deserialize, Debug, PartialEq)]
        struct Fixture {
            name: String,
            count: u32,
        }
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("fixture.yaml");
        std::fs::write(&path, "name: hive-router\ncount: 42\n").expect("seed write");

        let value: Fixture = read_yaml_sync(&path).expect("well-formed YAML must parse");

        assert_eq!(
            value,
            Fixture {
                name: "hive-router".to_string(),
                count: 42,
            }
        );
    }

    /// [`read_yaml_sync`]'s read arm must surface the offending
    /// `path.display()` alongside a `"Failed to read"` classifier so the
    /// operator's next step is `ls` on the exact path. Pins the
    /// canonical envelope every consumer inherits: the pre-lift
    /// per-consumer role labels (`"product config"`, `"service config"`)
    /// decoupled the diagnostic wording from the offending path, and
    /// this envelope closes that drift by construction.
    #[test]
    fn read_yaml_sync_missing_file_errors_carry_path_and_read_classifier() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("does-not-exist.yaml");

        let err = read_yaml_sync::<serde_yaml::Value>(&path).unwrap_err();
        let msg = format!("{err:#}");

        assert!(
            msg.contains(&path.display().to_string()),
            "read arm's envelope must carry `path.display()` so the \
             operator can `ls` the offending path directly. Got: {msg}"
        );
        assert!(
            msg.contains("Failed to read"),
            "read arm's envelope must carry the `Failed to read` \
             classifier so the operator's next step is `ls`, not \
             `yamllint`. Got: {msg}"
        );
    }

    /// [`read_yaml_sync`]'s parse arm must surface the offending
    /// `path.display()` alongside a `"Failed to parse ... as YAML"`
    /// classifier so the operator's next step is `yamllint` on the exact
    /// path, not `ls` (which would find a syntactically-broken file, a
    /// dead end). Pins the parse-failure envelope every consumer
    /// inherits.
    #[test]
    fn read_yaml_sync_invalid_yaml_errors_carry_path_and_parse_classifier() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("broken.yaml");
        std::fs::write(&path, "key: [unterminated\n").expect("seed write");

        let err = read_yaml_sync::<serde_yaml::Value>(&path).unwrap_err();
        let msg = format!("{err:#}");

        assert!(
            msg.contains(&path.display().to_string()),
            "parse arm's envelope must carry `path.display()` so the \
             operator can `yamllint` the offending path directly. \
             Got: {msg}"
        );
        assert!(
            msg.contains("Failed to parse") && msg.contains("as YAML"),
            "parse arm's envelope must carry `Failed to parse ... as \
             YAML` so the operator's next step is `yamllint`, not `ls` \
             (which would find a syntactically-broken file, a dead \
             end). Got: {msg}"
        );
    }

    /// [`read_yaml_sync`] parses at the OPEN [`serde_yaml::Value`]
    /// target when the caller navigates via `.get(...)` chains rather
    /// than deserializing into a closed struct. Pins that ONE primitive
    /// body serves both the typed-struct target (e.g. `ProductConfig`
    /// at `config::mod::load_product_config_from_dir`) and the
    /// open-value target (e.g. `serde_yaml::Value` at
    /// `config::mod::load_service_namespace`) — a regression that
    /// specialized the primitive to a closed T would silently break the
    /// four open-value consumer sites.
    #[test]
    fn read_yaml_sync_parses_at_open_serde_yaml_value_for_get_chain_consumers() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("nested.yaml");
        std::fs::write(
            &path,
            "environments:\n  production:\n    namespace: hive-prod\n",
        )
        .expect("seed write");

        let value: serde_yaml::Value = read_yaml_sync(&path).expect("open-value target must parse");

        let namespace = value
            .get("environments")
            .and_then(|e| e.get("production"))
            .and_then(|p| p.get("namespace"))
            .and_then(|n| n.as_str());
        assert_eq!(namespace, Some("hive-prod"));
    }
}
