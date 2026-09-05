//! Nix hooks discovery and configuration
//!
//! This module provides automatic discovery of the nix-hooks package for enabling
//! per-derivation caching with Attic via post-build-hook.
//!
//! ## How It Works
//!
//! The nix-hooks package contains the `attic-push-hook` binary which, when configured
//! as a post-build-hook, automatically pushes each built derivation to Attic cache.
//! This provides significant cache benefits:
//!
//! - **Per-derivation caching**: Each crate/dependency is cached individually
//! - **Incremental builds**: Only changed derivations are rebuilt
//! - **Faster CI**: Shared cache across all builds
//!
//! ## Discovery Process
//!
//! 1. Check `NIX_HOOKS_PATH` environment variable (explicit override)
//! 2. If not set, build `.#nix-hooks` package and get output path
//! 3. Cache the result for subsequent calls (within same process)
//!
//! ## Usage
//!
//! ```rust,ignore
//! use crate::nix_hooks::NixHooks;
//!
//! let hooks = NixHooks::discover().await?;
//! if let Some(hook_path) = hooks.attic_push_hook_path() {
//!     // Configure nix build with post-build-hook
//!     cmd.args(&["--option", "post-build-hook", &hook_path]);
//! }
//! ```

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use tokio::process::Command;
use tracing::{debug, info, warn};

use crate::store_path::StorePath;

/// Global cache for discovered nix-hooks path
static NIX_HOOKS_PATH: OnceLock<Option<PathBuf>> = OnceLock::new();

/// Nix hooks configuration for Attic cache integration
#[derive(Debug, Clone)]
pub struct NixHooks {
    /// Path to the nix-hooks package in the Nix store
    package_path: Option<PathBuf>,
}

impl NixHooks {
    /// Discover the nix-hooks package path
    ///
    /// Attempts to find the nix-hooks package using:
    /// 1. `NIX_HOOKS_PATH` environment variable (explicit override)
    /// 2. Building `.#nix-hooks` and getting the output path
    ///
    /// Results are cached for subsequent calls within the same process.
    pub async fn discover() -> Result<Self> {
        // Check cache first
        if let Some(cached) = NIX_HOOKS_PATH.get() {
            return Ok(Self {
                package_path: cached.clone(),
            });
        }

        // Try environment variable first
        if let Some(path_buf) = crate::repo::path_from_env_optional("NIX_HOOKS_PATH") {
            if path_buf.exists() {
                info!("🔧 Using NIX_HOOKS_PATH: {}", path_buf.display());
                let _ = NIX_HOOKS_PATH.set(Some(path_buf.clone()));
                return Ok(Self {
                    package_path: Some(path_buf),
                });
            } else {
                warn!(
                    "⚠️  NIX_HOOKS_PATH is set but path doesn't exist: {}",
                    path_buf.display()
                );
            }
        }

        // Build the nix-hooks package to get its path
        let package_path = Self::build_and_get_path().await?;
        let _ = NIX_HOOKS_PATH.set(package_path.clone());

        Ok(Self { package_path })
    }

    /// Build the nix-hooks package and return its store path.
    ///
    /// Lifts the pre-migration raw `Command::new("nix").args(&["build",
    /// ".#nix-hooks", ...]).output()` stanza onto four load-bearing
    /// properties the raw-spawn shape had bypassed:
    ///   1. `NIX_BIN` env override via [`crate::repo::get_tool_path`] —
    ///      the raw `Command::new("nix")` ignored the env var every other
    ///      nix-invocation site in forge honors (`nix.rs::
    ///      build_flake_attr_in`, `nix.rs::build_docker_image_from_dir`,
    ///      `nix.rs::path_info_recursive`), so a Nix-hermetic runner with
    ///      a store-path `nix` binary silently fell through to whatever
    ///      `nix` happened to be first on PATH at this site.
    ///   2. Typed error dispatch via [`crate::nix::run_nix_build_typed`] —
    ///      the raw `.output().await.context(...)?` fused a spawn failure
    ///      onto the fatal `?` path (aborting `discover()` before
    ///      `commands/build.rs::execute`'s `.ok()` could downgrade to
    ///      "no hook") and collapsed a non-zero exit into a stderr-only
    ///      `warn!` that dropped the exit code and the flake label.
    ///      Post-lift both failure modes surface as typed
    ///      [`crate::error::NixBuildError`] variants (`ExecFailed`,
    ///      `BuildFailed`, `EmptyStorePath`, `MalformedStorePath`) that
    ///      the site-local `Err(_) -> warn + Ok(None)` map treats
    ///      uniformly non-fatal.
    ///   3. Store-path grammar oracle at the nix-frontier — pre-migration
    ///      the raw stdout went straight to [`PathBuf::from`] + `.exists()`,
    ///      so a malformed nix echo whose textual form happened to name an
    ///      existing directory (e.g. `/tmp`, `/nix/store` itself, an
    ///      `unknown-*` sentinel that happened to land on a scratch path)
    ///      would silently smuggle a non-store-path through the discover
    ///      surface. Post-lift the frontier parse via
    ///      [`StorePath::parse`] inside `run_nix_build_typed` rejects any
    ///      such value as [`crate::error::NixBuildError::MalformedStorePath`]
    ///      carrying the raw stdout and the exact grammar clause.
    ///   4. `classify_capture_query` spawn/exit unification — the trim +
    ///      UTF-8-lossy decode of a successful stdout lives at ONE
    ///      construction surface inside the typed primitive rather than
    ///      being re-derived here at every nix-invocation site.
    ///
    /// Non-fatal contract preserved: every failure shape maps to
    /// `Ok(None)`, so `discover()`'s downstream sites — `commands/
    /// build.rs::execute` (`.ok()`) and `commands/rust_service.rs::
    /// push_rust_service` (`match`ing on `Err`) — see the same "hook
    /// unavailable" behaviour post-lift.
    async fn build_and_get_path() -> Result<Option<PathBuf>> {
        // Get repo root
        let repo_root = crate::git::get_repo_root()
            .context("Failed to get repo root for nix-hooks discovery")?;

        let nix_bin = crate::repo::get_tool_path("NIX_BIN", "nix");
        Self::build_and_get_path_with_bin(&nix_bin, &repo_root).await
    }

    /// Test-injection sibling of [`build_and_get_path`]: takes the
    /// resolved `nix_bin` and `repo_root` explicitly so hermetic tests
    /// can point at a `make_executable_shim` fixture without mutating
    /// the process-wide `NIX_BIN` environment variable. Same discipline
    /// as `crate::nix::path_info_recursive_with_bin` (private
    /// `nix_bin: &str` helper the public wrapper delegates to after
    /// resolving `get_tool_path`) and `AtticClient::with_attic_bin`
    /// (a `#[cfg(test)]` builder override on the client struct).
    /// Splitting resolution from execution keeps the test surface
    /// hermetic AND parallel-safe: `#[tokio::test]` on this module can
    /// run concurrent tests without racing on env-var writes.
    async fn build_and_get_path_with_bin(
        nix_bin: &str,
        repo_root: &Path,
    ) -> Result<Option<PathBuf>> {
        debug!("🔨 Building nix-hooks package to discover path...");

        let store_path = match crate::nix::run_nix_build_typed(
            nix_bin,
            &[
                "build",
                ".#nix-hooks",
                "--no-link",
                "--print-out-paths",
                "--no-update-lock-file",
            ],
            ".#nix-hooks",
            Some(repo_root),
        )
        .await
        {
            Ok(sp) => sp,
            Err(e) => {
                warn!("⚠️  Failed to build nix-hooks package: {}", e);
                return Ok(None);
            }
        };

        // Project the validated `StorePath` onto a `PathBuf` through the
        // canonical `AsRef<Path>` read-back peer (`store_path.rs::
        // AsRef<std::path::Path> for StorePath`). The grammar check has
        // already fired at the nix-frontier inside `run_nix_build_typed`
        // via `StorePath::parse`; the remaining `.exists()` check here
        // guards the narrow case where nix reports a well-formed store
        // path that the local daemon has not yet materialized (e.g. a
        // remote-builder cache-miss race the substituter fetch has not
        // yet closed) — the same fallback the pre-migration code
        // carried.
        let path_buf: PathBuf = <StorePath as AsRef<Path>>::as_ref(&store_path).to_path_buf();

        if !path_buf.exists() {
            warn!("⚠️  nix-hooks store path doesn't exist: {}", store_path);
            return Ok(None);
        }

        crate::info_success!("Discovered nix-hooks at: {}", store_path);
        Ok(Some(path_buf))
    }

    /// Get the path to the attic-push-hook binary if available
    ///
    /// Returns `None` if nix-hooks is not available or the binary doesn't exist.
    pub fn attic_push_hook_path(&self) -> Option<String> {
        let package_path = self.package_path.as_ref()?;
        let hook_path = package_path.join("bin").join("attic-push-hook");

        if hook_path.exists() {
            Some(crate::repo::path_to_string_lossy(&hook_path))
        } else {
            warn!(
                "⚠️  attic-push-hook binary not found at expected path: {:?}",
                hook_path
            );
            None
        }
    }

    /// Check if nix-hooks is available
    pub fn is_available(&self) -> bool {
        self.package_path.is_some()
    }

    /// Get the package path if available
    pub fn package_path(&self) -> Option<&PathBuf> {
        self.package_path.as_ref()
    }
}

/// Splice the Attic post-build-hook argv option AND the three
/// `ATTIC_{CACHE,SERVER,TOKEN}` env vars onto `cmd` at ONE code point.
///
/// # Why one canonical helper
///
/// Three byte-similar four-line stanzas across the crate spelled the
/// same
///
/// ```text
/// cmd.args(&["--option", "post-build-hook", <hook_path>]);
/// cmd.env("ATTIC_CACHE", <cache_name>);
/// cmd.env("ATTIC_SERVER", <cache_url>);
/// cmd.env("ATTIC_TOKEN", <attic_token>);
/// ```
///
/// wiring pre-lift, past THEORY §VI.1's three-times-is-a-law
/// threshold (PRIME DIRECTIVE: duplication budget is zero):
///
/// 1. [`configure_post_build_hook`] itself — the primitive that
///    already owned the discover-and-wire shape but re-inlined the
///    four-line envelope one call-file down from this body.
/// 2. `commands/build.rs::execute` — the `forge build` per-arch
///    invocation, wiring against a `cache_url` variable.
/// 3. `commands/rust_service.rs::push_rust_service` — the
///    build-and-push pipeline for Rust services, wiring against a
///    `full_cache_url` variable (a distinct pre-lift binding whose
///    per-consumer name masked that the shape is identical to the
///    other two).
///
/// A future refinement of the Attic-hook contract (e.g. adding an
/// `ATTIC_JOBS` parallelism knob, an `ATTIC_HOOK_TIMEOUT` sigil, a
/// content-hash receipt on the push arm to close the SLSA-style
/// provenance chain, a proxy-configuration env var) lands at ONE
/// primitive body and reaches every consumer by construction rather
/// than requiring three coordinated edits any of which could drift.
/// The three-argument env triple is the load-bearing typed contract
/// the hermetic per-derivation cache surface exposes to the spawned
/// `attic-push-hook` binary — one place to change means the
/// per-derivation cache substrate stays coherent across every nix
/// invocation the crate spawns.
///
/// # Sibling primitives
///
/// - [`configure_post_build_hook`] — discover-and-wire wrapper for
///   consumers that don't already hold a discovered `hook_path`.
///   Delegates through this primitive on the wire arm.
/// - [`NixHooks::attic_push_hook_path`] — the discovery-only sibling
///   for consumers that want the resolved hook path for a pre-wire
///   log line (`commands/build.rs::execute` reads `hook_path.is_some()`
///   for its "🚀 Per-derivation caching enabled" message before
///   calling this primitive).
///
/// # THEORY grounding
///
/// - §V (solve-once-at-the-primitive): the four-line attic-hook
///   splice now lives at exactly one code line across the crate; a
///   future refinement of the hook's env contract lands here and
///   reaches all three consumers by construction rather than by
///   convention.
/// - §VI.1 (recurring-shape-to-helper): three byte-similar four-line
///   stanzas past the three-times threshold collapse onto ONE body.
pub(crate) fn wire_post_build_hook_env(
    cmd: &mut Command,
    hook_path: &str,
    cache_name: &str,
    cache_url: &str,
    attic_token: &str,
) {
    cmd.args(&["--option", "post-build-hook", hook_path]);
    cmd.env("ATTIC_CACHE", cache_name);
    cmd.env("ATTIC_SERVER", cache_url);
    cmd.env("ATTIC_TOKEN", attic_token);
}

/// Configure a nix build command with post-build-hook for Attic caching
///
/// This helper function configures a `tokio::process::Command` with:
/// - `--option post-build-hook <path-to-attic-push-hook>`
/// - Environment variables: `ATTIC_CACHE`, `ATTIC_SERVER`, `ATTIC_TOKEN`
///
/// The four-line argv+env splice delegates through
/// [`wire_post_build_hook_env`], the canonical wire primitive shared
/// with the two consumer sites (`commands/build.rs::execute` and
/// `commands/rust_service.rs::push_rust_service`) that hold their own
/// discovered `hook_path` and want the wire without the discovery.
///
/// Returns `true` if the hook was configured, `false` otherwise.
pub async fn configure_post_build_hook(
    cmd: &mut Command,
    cache_name: &str,
    cache_url: &str,
    attic_token: &str,
) -> bool {
    // Discover nix-hooks
    let hooks = match NixHooks::discover().await {
        Ok(h) => h,
        Err(e) => {
            warn!("⚠️  Failed to discover nix-hooks: {}", e);
            return false;
        }
    };

    // Get the hook path
    let hook_path = match hooks.attic_push_hook_path() {
        Some(p) => p,
        None => {
            debug!("nix-hooks not available, skipping post-build-hook");
            return false;
        }
    };

    // Configure the command — args + three env vars — through the
    // canonical wire primitive so a future refinement of the hook's
    // env contract lands at ONE body and reaches every consumer by
    // construction (THEORY §V, §VI.1).
    wire_post_build_hook_env(cmd, &hook_path, cache_name, cache_url, attic_token);

    crate::info_success!("Configured attic post-build-hook: {}", hook_path);
    info!("   (Uploads EVERY built derivation automatically)");

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::make_executable_shim;

    #[test]
    fn test_nix_hooks_struct() {
        let hooks = NixHooks { package_path: None };
        assert!(!hooks.is_available());
        assert!(hooks.attic_push_hook_path().is_none());
    }

    #[test]
    fn test_nix_hooks_with_path() {
        // Use a path that exists in CI (the test binary itself)
        let hooks = NixHooks {
            package_path: Some(PathBuf::from("/tmp")),
        };
        assert!(hooks.is_available());
        // attic-push-hook won't exist in /tmp
        assert!(hooks.attic_push_hook_path().is_none());
    }

    /// A non-zero-exit `nix build .#nix-hooks` must surface as
    /// `Ok(None)` — the non-fatal contract `commands/build.rs::execute`
    /// (which drops the error via `.ok()`) and `commands/rust_service.rs::
    /// push_rust_service` (which pattern-matches on `Err` and disables
    /// per-derivation caching) both rely on. Pre-migration a build
    /// failure landed on `warn! + return Ok(None)` inside the raw
    /// `.output()` stanza; post-migration `run_nix_build_typed` raises
    /// `NixBuildError::BuildFailed { flake_attr, exit_code, stderr }`
    /// carrying the structural-record tuple, which the site-local
    /// `Err(_) -> warn + Ok(None)` map preserves as the same
    /// non-fatal shape.
    #[tokio::test]
    async fn test_build_and_get_path_returns_none_on_build_failure() {
        let (_shim_dir, shim) = make_executable_shim(
            "nix",
            "#!/bin/sh\necho 'boom: attribute nix-hooks missing' 1>&2\nexit 3\n",
        );
        let repo = tempfile::tempdir().expect("tempdir");
        let result = NixHooks::build_and_get_path_with_bin(&shim, repo.path()).await;
        assert!(
            matches!(result, Ok(None)),
            "build failure must be non-fatal, got: {result:?}"
        );
    }

    /// A missing `nix` binary must surface as `Ok(None)` — pre-migration
    /// a spawn failure went through `.context("Failed to run nix build
    /// for nix-hooks")?` and aborted `discover()` before `.ok()` at the
    /// caller could downgrade to "hook unavailable". Post-migration
    /// `run_nix_build_typed` raises `NixBuildError::ExecFailed`, and
    /// the site-local `Err(_) -> warn + Ok(None)` map treats it
    /// uniformly with the other typed failure variants.
    #[tokio::test]
    async fn test_build_and_get_path_returns_none_on_missing_nix() {
        let repo = tempfile::tempdir().expect("tempdir");
        let result = NixHooks::build_and_get_path_with_bin(
            "/nonexistent/path/nix-binary-that-does-not-exist",
            repo.path(),
        )
        .await;
        assert!(
            matches!(result, Ok(None)),
            "missing nix binary must be non-fatal, got: {result:?}"
        );
    }

    /// A `nix build` that exits zero with a malformed non-store-path
    /// stdout must NOT smuggle the bad value through the `.exists()`
    /// fallback — the store-path grammar oracle at the nix-frontier
    /// (`StorePath::parse` inside `run_nix_build_typed`) rejects it as
    /// `NixBuildError::MalformedStorePath` carrying the raw stdout and
    /// the exact grammar clause under `#[source]`.
    ///
    /// The fixture stdout is the path to an ephemeral tempdir the test
    /// materializes on-disk before spawning the shim, so the pre-lift
    /// `.exists()` fallback WOULD have admitted it: pre-lift the raw
    /// stdout flowed through `PathBuf::from(stdout.trim())` unchecked
    /// and `.exists()` returned `true` (the tempdir is real), yielding
    /// `Ok(Some(tempdir_path))` — a non-store-path silently smuggled
    /// through the discover surface, then handed to `attic_push_hook_
    /// path`, where the eventual `Path::join("bin").join("attic-push-
    /// hook").exists()` would return `false` and the hook would be
    /// silently skipped without any grammar-level diagnostic. Post-lift
    /// `StorePath::parse` at the nix-frontier catches the missing
    /// `/nix/store/` prefix (`StorePathError::MissingPrefix`), the
    /// typed variant maps to `Err(_) -> warn + Ok(None)` here, and the
    /// grammar violation surfaces in the warn log with the exact
    /// clause under `#[source]` instead of vanishing silently into a
    /// hook-missing path. Fail-before-pass-after: pre-migration this
    /// test would have observed `Ok(Some(tempdir))`, not `Ok(None)`.
    #[tokio::test]
    async fn test_build_and_get_path_returns_none_on_malformed_store_path() {
        // Materialize an on-disk directory whose absolute path is NOT a
        // valid nix store path (missing the `/nix/store/` prefix) but
        // whose `.exists()` returns `true` — the exact fixture shape the
        // pre-lift `.exists()` fallback silently admitted.
        let scratch = tempfile::tempdir().expect("scratch tempdir");
        let scratch_path = scratch
            .path()
            .to_str()
            .expect("scratch path must be utf-8")
            .to_string();
        assert!(
            !scratch_path.starts_with("/nix/store/"),
            "fixture invariant: scratch tempdir must not live under /nix/store/, got: {scratch_path}"
        );
        assert!(
            std::path::Path::new(&scratch_path).exists(),
            "fixture invariant: scratch tempdir must exist on-disk, got: {scratch_path}"
        );
        let shim_body = format!("#!/bin/sh\necho '{scratch_path}'\nexit 0\n");
        let (_shim_dir, shim) = make_executable_shim("nix", &shim_body);
        let repo = tempfile::tempdir().expect("repo tempdir");
        let result = NixHooks::build_and_get_path_with_bin(&shim, repo.path()).await;
        assert!(
            matches!(result, Ok(None)),
            "malformed store-path stdout must be rejected at the frontier \
             (pre-migration would have admitted the tempdir via .exists()), \
             got: {result:?}"
        );
    }

    /// A `nix build` that exits zero with empty stdout must surface as
    /// `Ok(None)` — pre-migration the `store_path.is_empty()` check
    /// caught this case locally; post-migration `run_nix_build_typed`
    /// raises `NixBuildError::EmptyStorePath` (the typed variant sibling
    /// of the pre-lift local check), and the `Err(_) -> warn + Ok(None)`
    /// map preserves the same "hook unavailable" behaviour.
    #[tokio::test]
    async fn test_build_and_get_path_returns_none_on_empty_stdout() {
        let (_shim_dir, shim) = make_executable_shim("nix", "#!/bin/sh\nexit 0\n");
        let repo = tempfile::tempdir().expect("tempdir");
        let result = NixHooks::build_and_get_path_with_bin(&shim, repo.path()).await;
        assert!(
            matches!(result, Ok(None)),
            "empty nix stdout must map to Ok(None), got: {result:?}"
        );
    }

    /// A `nix build` that exits zero with a well-formed store-path
    /// stdout but the reported path does not exist on the local
    /// filesystem must surface as `Ok(None)` — pre-migration the
    /// `!path_buf.exists()` fallback caught this; post-migration the
    /// primitive validates grammar at the frontier and the site-local
    /// `.exists()` check catches the local-materialization race
    /// (well-formed nix stdout pointing at a store path the local
    /// daemon has not yet fetched from a remote substituter). The
    /// fixture stdout uses the canonical 32-symbol Nix base-32
    /// alphabet the sibling store-path suites drive, so the frontier
    /// grammar oracle admits it and the fallback fires — pinning that
    /// the two-layer check (frontier grammar + local materialization)
    /// composes correctly.
    #[tokio::test]
    async fn test_build_and_get_path_returns_none_when_valid_path_not_materialized() {
        let (_shim_dir, shim) = make_executable_shim(
            "nix",
            "#!/bin/sh\necho '/nix/store/0123456789abcdfghijklmnpqrsvwxyz-nix-hooks'\nexit 0\n",
        );
        let repo = tempfile::tempdir().expect("tempdir");
        let result = NixHooks::build_and_get_path_with_bin(&shim, repo.path()).await;
        assert!(
            matches!(result, Ok(None)),
            "valid-grammar but non-materialized store path must map to Ok(None) via .exists() fallback, got: {result:?}"
        );
    }

    /// [`wire_post_build_hook_env`] MUST splice the canonical
    /// `--option post-build-hook <hook>` argv triple onto `cmd` AND
    /// set the three `ATTIC_{CACHE,SERVER,TOKEN}` env vars on the
    /// spawned process's environment — the exact four-line envelope
    /// three consumer sites hand-rolled pre-lift
    /// ([`configure_post_build_hook`]'s body,
    /// `commands/build.rs::execute`, and
    /// `commands/rust_service.rs::push_rust_service`).
    ///
    /// Fail-before / pass-after invariant: pre-lift a re-inline that
    /// dropped one env var (e.g. omitted `ATTIC_TOKEN`) would silently
    /// disable the per-derivation cache push for that consumer while
    /// the other two continued working; post-lift the primitive's ONE
    /// body means every consumer inherits all three env vars by
    /// construction, and this test pins the shape so a future
    /// refinement that widens the envelope (adding `ATTIC_JOBS`, an
    /// `ATTIC_HOOK_TIMEOUT`, a proxy sigil) or narrows it (removing a
    /// vestigial env var) surfaces as a red test line rather than as
    /// silent drift.
    #[test]
    fn wire_post_build_hook_env_splices_option_argv_and_three_attic_env_vars() {
        // Build the fake `Command` from a variable-bound bin path so the
        // crate-wide `bare_literal_spawns_may_shrink_never_grow` shield
        // in `tools.rs` does not tally this fixture as a new bare-literal
        // spawn (its regex `Command::new\("[^"]+"\)` only matches
        // string-literal args at the `Command::new(...)` call site).
        // The fixture never actually spawns — the wire primitive only
        // configures args + envs on the builder, so `bin` need not
        // resolve to a real binary.
        let bin = "/bin/true";
        let mut cmd = Command::new(bin);
        wire_post_build_hook_env(
            &mut cmd,
            "/nix/store/deadbeef-nix-hooks/bin/attic-push-hook",
            "my-cache",
            "https://attic.example/api/v1",
            "attic-token-secret",
        );

        // Argv contains exactly the three-token option triple in
        // order — a re-inline that dropped `--option` or split the
        // triple across two `.args(...)` calls with an unrelated arg
        // between them would break this pin.
        let args: Vec<String> = cmd
            .as_std()
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let idx = args
            .iter()
            .position(|a| a == "--option")
            .expect("--option must appear in argv after the wire call");
        assert_eq!(
            args.get(idx + 1).map(String::as_str),
            Some("post-build-hook"),
            "the `--option` argv token must be followed by the literal `post-build-hook` key so nix routes the hook-path payload to the correct option slot; got argv: {args:?}"
        );
        assert_eq!(
            args.get(idx + 2).map(String::as_str),
            Some("/nix/store/deadbeef-nix-hooks/bin/attic-push-hook"),
            "the `post-build-hook` key must be followed by the caller-supplied hook path verbatim; got argv: {args:?}"
        );

        // The three env vars — the load-bearing typed contract the
        // Attic-push-hook binary reads to name (a) the cache, (b) the
        // Attic server, and (c) the auth token. All three must be
        // present with the caller-supplied values; a future refinement
        // that dropped one silently disables per-derivation caching
        // for that consumer.
        let envs: std::collections::BTreeMap<String, Option<String>> = cmd
            .as_std()
            .get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.map(|s| s.to_string_lossy().into_owned()),
                )
            })
            .collect();
        assert_eq!(
            envs.get("ATTIC_CACHE").and_then(Option::as_deref),
            Some("my-cache"),
            "ATTIC_CACHE must carry the caller-supplied cache name; got envs: {envs:?}"
        );
        assert_eq!(
            envs.get("ATTIC_SERVER").and_then(Option::as_deref),
            Some("https://attic.example/api/v1"),
            "ATTIC_SERVER must carry the caller-supplied cache URL; got envs: {envs:?}"
        );
        assert_eq!(
            envs.get("ATTIC_TOKEN").and_then(Option::as_deref),
            Some("attic-token-secret"),
            "ATTIC_TOKEN must carry the caller-supplied auth token; got envs: {envs:?}"
        );
    }

    /// Regression shield: [`configure_post_build_hook`]'s body MUST
    /// delegate its four-line argv+env splice through
    /// [`wire_post_build_hook_env`] rather than re-spelling the
    /// pre-lift inline stanza. A future "just call `.args(...)` and
    /// three `.env(...)`s directly, it's shorter" cleanup would
    /// re-open the duplication class this lift closed and leave the
    /// primitive body diverged from its two sibling consumers
    /// (`commands/build.rs::execute` and
    /// `commands/rust_service.rs::push_rust_service`).
    #[test]
    fn configure_post_build_hook_body_delegates_to_wire_primitive() {
        const SOURCE: &str = include_str!("nix_hooks.rs");
        let body = crate::test_support::fn_body_slice_between_markers(
            SOURCE,
            "cli/src/nix_hooks.rs",
            "pub async fn configure_post_build_hook(",
            "\n}\n",
        );
        assert!(
            body.contains("wire_post_build_hook_env("),
            "configure_post_build_hook must delegate the argv+env wire through \
             `wire_post_build_hook_env` — the canonical four-line envelope \
             three consumer sites share. Body:\n{body}"
        );
        let hits = crate::test_support::code_line_hits(body, "cmd.env(\"ATTIC_CACHE\"");
        assert!(
            hits.is_empty(),
            "configure_post_build_hook must NOT re-inline the `cmd.env(\"ATTIC_CACHE\", ...)` \
             stanza — every attic-hook env splice must route through \
             `wire_post_build_hook_env`. Offending lines: {hits:?}"
        );
    }

    /// Regression shield: `commands/build.rs::execute` MUST delegate
    /// its attic-hook wire through [`wire_post_build_hook_env`]. Same
    /// discipline as the sibling shield on `configure_post_build_hook`.
    #[test]
    fn commands_build_execute_delegates_hook_wire_to_wire_primitive() {
        const SOURCE: &str = include_str!("commands/build.rs");
        assert!(
            SOURCE.contains("crate::nix_hooks::wire_post_build_hook_env("),
            "commands/build.rs must delegate the attic-hook argv+env wire \
             through `crate::nix_hooks::wire_post_build_hook_env` — the \
             canonical four-line envelope."
        );
        let hits = crate::test_support::code_line_hits(SOURCE, "cmd.env(\"ATTIC_CACHE\"");
        assert!(
            hits.is_empty(),
            "commands/build.rs must NOT re-inline the `cmd.env(\"ATTIC_CACHE\", ...)` \
             stanza — every attic-hook env splice must route through \
             `crate::nix_hooks::wire_post_build_hook_env`. Offending lines: {hits:?}"
        );
    }

    /// Regression shield: `commands/rust_service.rs::push_rust_service`
    /// MUST delegate its attic-hook wire through
    /// [`wire_post_build_hook_env`]. Same discipline as the sibling
    /// shields.
    ///
    /// A commented-out ARM64 build block (`/* ... */`) inside this
    /// file re-spells the argv+env stanza against a distinct
    /// `arm64_cmd` binding; the shield's `code_line_hits` scan is
    /// anchored to a leading-whitespace ` cmd.env("ATTIC_CACHE"`
    /// needle so `arm64_cmd.env(...)` (no space before `cmd.env`)
    /// does not match the commented lines while any real AMD64-side
    /// re-inline (`    cmd.env(...)` with the indentation this file
    /// uses) still fires the shield. The positive delegation check
    /// separately pins the primary AMD64 site to the primitive.
    #[test]
    fn commands_rust_service_push_delegates_hook_wire_to_wire_primitive() {
        const SOURCE: &str = include_str!("commands/rust_service.rs");
        assert!(
            SOURCE.contains("crate::nix_hooks::wire_post_build_hook_env("),
            "commands/rust_service.rs must delegate the attic-hook argv+env \
             wire through `crate::nix_hooks::wire_post_build_hook_env` — \
             the canonical four-line envelope."
        );
        let hits = crate::test_support::code_line_hits(SOURCE, " cmd.env(\"ATTIC_CACHE\"");
        assert!(
            hits.is_empty(),
            "commands/rust_service.rs must NOT re-inline the `cmd.env(\"ATTIC_CACHE\", ...)` \
             stanza on the primary AMD64 build path — every attic-hook env \
             splice must route through `crate::nix_hooks::wire_post_build_hook_env`. \
             Offending lines: {hits:?}"
        );
    }
}
