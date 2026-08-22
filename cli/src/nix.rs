//! Nix build utilities for forge
//!
//! Provides common Nix build operations like building images,
//! running crate2nix, and flake operations.

use anyhow::{Context, Result};
use std::path::Path;
use std::process::Stdio;
use tokio::process::Command;
use tracing::{debug, info};

use crate::error::NixBuildError;
use crate::repo::get_tool_path;
use crate::retry::{classify_capture, classify_capture_query};
use crate::store_path::StorePath;

/// Resolve the `nix` binary via the `NIX_BIN` env override, falling
/// back to `nix` on `PATH`. Wired through [`crate::repo::get_tool_path`]
/// — the canonical env-var-or-PATH lookup every other nix-invocation
/// site in the workspace honors (`commands/build.rs::execute`,
/// `commands/tool.rs::build_lock_target`,
/// `commands/rust_service.rs::nix_bin` 63d4fe7,
/// `nix_hooks.rs::NixHooks::build_and_get_path`,
/// `commands/developer_tools.rs::nix_bin` a12c172, and the sibling
/// `<tool>_bin()` sigil discipline the CARGO / BUN_BIN / NIX_BIN /
/// CRATE2NIX surfaces across forge already carry). Every `nix` spawn
/// this module drives reads through this sigil so the resolve happens
/// in exactly one place.
///
/// Seventh landing of the `<tool>_bin()` sigil pattern on the NIX_BIN
/// surface after `commands/rust_service.rs::nix_bin` (63d4fe7),
/// `commands/developer_tools.rs::nix_bin` (a12c172), and the sibling
/// `commands/comprehensive_release.rs::nix_bin` — first landing on the
/// core `cli/src/nix.rs` module, the highest-traffic nix-invocation
/// surface in forge and the primitive layer every command-module nix
/// build ultimately routes through (`build_flake_attr` / `build_flake_attr_in`
/// / `build_docker_image` / `build_docker_image_from_dir` /
/// `path_info_recursive`). Pre-lift the three consumer sites —
/// [`build_flake_attr_in`]'s primary `nix build` invocation,
/// [`build_docker_image_from_dir`]'s sub-flake `nix build`, and
/// [`path_info_recursive`]'s `nix path-info --recursive` closure probe
/// — each spelled the two-argument resolve verbatim, so a future
/// widening of the resolve (a per-spawn env-injection hook, a
/// substrate-path validation step, or a telemetry sigil on the
/// resolved path) had three sites to edit and could silently drift out
/// of sync at any of them. Post-lift each site collapses to `let
/// nix_bin = nix_bin();` and the resolve appears in exactly one place
/// — the sigil body.
///
/// A Nix-hermetic runner whose derivation exports
/// `NIX_BIN=/nix/store/…-nix/bin/nix` but omits `nix` from PATH
/// silently fell through to whatever `nix` was first on PATH at each
/// pre-lift site — every root-flake build / sub-flake build / closure-
/// enumeration verdict flowing through this module was attributed to
/// whichever `nix` PATH resolved first, not to the substrate-pinned
/// nix derivation the flake declared. This is especially load-bearing
/// on this module because `nix.rs` is what `commands/local.rs::up`,
/// `commands/bootstrap.rs::push_bootstrap_binary`,
/// `commands/image_release.rs::build_nix_image`,
/// `commands/pangea.rs::build_component_image`, and
/// `commands/tool.rs::release` all reach into for their build
/// primitive — a wrong-nix here compromises the store-path grammar
/// oracle at [`StorePath::parse`], the SLSA provenance gate at
/// `commands/attestation.rs::build_slsa_level`, and every downstream
/// Attic push / GHCR push / kubernetes deploy reads back through.
///
/// [`run_nix_build_typed`] and [`path_info_recursive_with_bin`] keep
/// their `nix_bin: &str` parameter unchanged — the resolution split
/// stays intact so `#[tokio::test]` on this module can point at a
/// hermetic shim without mutating the process-wide `NIX_BIN`
/// environment variable and run concurrent tests without racing on
/// env-var writes (the discipline documented at
/// [`path_info_recursive_with_bin`]'s docstring). The sigil owns the
/// public-caller side of the split; the primitive owns the test-
/// injection side.
fn nix_bin() -> String {
    get_tool_path("NIX_BIN", "nix")
}

/// Result of a Nix build operation.
///
/// `store_path` is a validated [`StorePath`] — the parse discipline
/// [`run_nix_build_typed`] applies at the nix-frontier survives through the
/// result, so every downstream consumer (`commands/local.rs::up` handing to
/// `docker load`, `commands/bootstrap.rs::push_bootstrap_binary` handing to
/// `push_with_retry`, `commands/image_release.rs::build_nix_image` returning
/// a `Result<String>`, `commands/pangea.rs::build_component_image` returning
/// a `Result<String>`, `commands/tool.rs::release` handing to
/// [`std::path::Path::new`]) holds the validated primitive by construction
/// and reaches its downstream boundary through the canonical projection
/// ([`StorePath::as_str`] for `&str`, [`StorePath::into_string`] for
/// `String`, [`AsRef<std::path::Path>`] for `&Path`), never a raw
/// unvalidated buffer that could silently smuggle a malformed nix-frontier
/// echo — a `/nix/store/…` with a subpath, an `unknown-*` sentinel, an
/// empty stdout — past the boundary the parse just proved.
///
/// THEORY.md §V.1 (Types → Invariants → Proofs): the store-path invariant
/// is proved at the frontier ([`run_nix_build_typed`]) and carried by the
/// return type, not re-derived per consumer. THEORY.md §VI.1 (one-oracle):
/// the canonical view is named at [`StorePath::as_str`] and every
/// downstream projection (borrow, owned-buffer move, `Path`-slot,
/// `OsStr`-slot, byte-slot) reads through it.
#[derive(Debug, Clone)]
pub struct NixBuildResult {
    /// The built artifact's validated store-object path.
    pub store_path: StorePath,
    /// The flake attribute that was built
    #[allow(dead_code)]
    pub flake_attr: String,
}

/// Run `nix build` with the given args and return the resulting store path.
///
/// `label` is the human-readable identifier (flake attribute or full
/// flake reference) attached to any returned `NixBuildError` so failure
/// records carry the offending input by construction.
///
/// `working_dir` is the directory the nix process is spawned in. `None`
/// keeps the parent process's CWD — the canonical shape for root-flake
/// builds. `Some(dir)` is the canonical shape for sub-flake builds where
/// the flake reference is a bare `.#attr` resolved relative to a
/// non-default directory (e.g. a tool-release flake under a sub-repo).
///
/// Returns typed errors:
/// - [`NixBuildError::ExecFailed`] when `nix` cannot be spawned.
/// - [`NixBuildError::BuildFailed`] when nix exits non-zero. `exit_code`
///   and `stderr` are kept as separate fields rather than fused into a
///   single message so downstream telemetry / retry / Phase 1
///   attestation can pattern-match on the failure shape.
/// - [`NixBuildError::EmptyStorePath`] when nix exits zero but prints no
///   store path — a contract violation that callers must distinguish
///   from a real build failure.
/// - [`NixBuildError::MalformedStorePath`] when nix exits zero and prints
///   a non-empty stdout that does not parse through the canonical
///   [`crate::store_path::StorePath`] grammar. Fires *before* the bad
///   value can silently propagate to `attic push`, the SLSA provenance
///   gate at `commands/attestation.rs::build_slsa_level`, or a
///   closure-scan pipeline. Preserves the raw stdout in `raw` and the
///   exact `StorePathError` grammar clause under `#[source]`.
pub(crate) async fn run_nix_build_typed(
    nix_bin: &str,
    args: &[&str],
    label: &str,
    working_dir: Option<&Path>,
) -> Result<StorePath, NixBuildError> {
    debug!("{} {}", nix_bin, args.join(" "));

    let mut cmd = Command::new(nix_bin);
    cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());
    if let Some(dir) = working_dir {
        cmd.current_dir(dir);
    }
    let captured = cmd.output().await;

    // Spawn-vs-op dispatch flows through the canonical
    // [`classify_capture_query`] primitive — query-shape sibling of
    // `classify_capture` (the op-shape primitive `git.rs::git_capture`
    // and `infrastructure/registry.rs::create_manifest_index` drive).
    // Spawn failures (`Err(io::Error)` — nix not on PATH) route to
    // `NixBuildError::ExecFailed`; non-zero exits route to
    // `NixBuildError::BuildFailed` carrying the structural
    // `(exit_code, stderr)` tuple `CapturedFailure` extracts. The
    // canonical UTF-8-lossy-trim of the success-stdout is performed
    // by the primitive — no per-site re-derivation.
    let store_path = classify_capture_query(
        captured,
        |e| NixBuildError::ExecFailed {
            flake_attr: label.to_string(),
            message: e.to_string(),
        },
        |cf| NixBuildError::BuildFailed {
            flake_attr: label.to_string(),
            exit_code: cf.exit_code,
            stderr: cf.stderr,
        },
    )?;

    if store_path.is_empty() {
        return Err(NixBuildError::EmptyStorePath {
            flake_attr: label.to_string(),
        });
    }

    // Route the trimmed stdout through the canonical StorePath grammar
    // oracle at the nix-frontier. `nix build --print-out-paths` promises
    // a well-formed store object path on the success path — a value that
    // does not parse is a nix contract violation, and every downstream
    // consumer (attic push, SLSA provenance gate, closure-scan pipeline)
    // has been reading the raw string unchecked. Surfacing the failure
    // here — typed, with the raw stdout preserved and the exact grammar
    // clause under `#[source]` — turns "cryptic remote attic push error"
    // and "attestation silently dropped via .unwrap_or(false)" into
    // one legible failure at the boundary. THEORY §V.1 (Types →
    // Invariants → Proofs): the validated identity is proved at the
    // frontier, not re-derived per downstream consumer. THEORY §VI.1
    // (one-oracle / three-times rule): the store-path grammar stays
    // defined at `StorePath::parse`; this call is the second consumer
    // (attestation is the first at `commands/attestation.rs::
    // build_slsa_level`), so a future grammar change lands at one site.
    let parsed =
        StorePath::parse(&store_path).map_err(|source| NixBuildError::MalformedStorePath {
            flake_attr: label.to_string(),
            raw: store_path.clone(),
            source,
        })?;

    // Hand the validated primitive itself to the caller — no `.as_str()
    // .to_string()` unparse-then-re-own round trip that would allocate a
    // fresh copy of bytes the [`StorePath`] already owns and drop the
    // structural witness of the parse in the same call. Every
    // [`NixBuildResult`] consumer downstream (docker-load, push-with-retry,
    // path-based tool extraction, image-release return) now holds the
    // validated primitive by construction and reaches its own boundary
    // through the canonical projection ([`StorePath::as_str`],
    // [`StorePath::into_string`], [`AsRef<std::path::Path>`]), never a raw
    // unvalidated buffer.
    Ok(parsed)
}

/// Build a Nix flake attribute and return the store path.
///
/// # Arguments
///
/// * `flake_attr` - The flake attribute to build (e.g., ".#postgres-bootstrap-image")
///
/// # Errors
///
/// Returns an error if the nix build command fails. The underlying
/// [`NixBuildError`] is preserved across the anyhow boundary and can be
/// recovered with `err.downcast_ref::<NixBuildError>()`.
///
/// # Examples
///
/// ```rust,ignore
/// let result = build_flake_attr(".#my-package").await?;
/// println!("Built at: {}", result.store_path);
/// ```
pub async fn build_flake_attr(flake_attr: &str) -> Result<NixBuildResult> {
    build_flake_attr_in(flake_attr, None).await
}

/// Build a Nix flake attribute, optionally relative to a working directory,
/// and return the store path.
///
/// Lifts the verbatim 13-line pattern
/// ```text
/// let output = tokio::process::Command::new(<bare-nix-literal>)
///     .args(["build", &flake_attr, "--no-link", "--print-out-paths", "--impure"])
///     .current_dir(dir)              // optional
///     .output().await
///     .with_context(|| format!("Failed to build {}", flake_attr))?;
/// if !output.status.success() {
///     let stderr = String::from_utf8_lossy(&output.stderr);
///     bail!("nix build {} failed: {}", flake_attr, stderr.trim());
/// }
/// let store_path = String::from_utf8_lossy(&output.stdout).trim().to_string();
/// if store_path.is_empty() {
///     bail!("nix build returned empty path for {}", flake_attr);
/// }
/// ```
/// that three command-module sites in forge carry verbatim modulo per-site
/// working_dir: `commands/local.rs::up` (no working_dir),
/// `commands/image_release.rs::build_nix_image` (working_dir = `&str` arg),
/// `commands/tool.rs::release` (working_dir = `&Path` arg). Three
/// identically-shaped bodies past the three-times threshold (THEORY §VI.1)
/// — this function is the law-redeeming consolidation for the "build a
/// flake attribute, return the store path, fail typed on every failure
/// shape" surface in forge.
///
/// `working_dir` is the directory the nix process is spawned in. `None`
/// keeps the parent process's CWD (the canonical shape for root-flake
/// builds — `commands/local.rs::up` and the existing
/// [`build_flake_attr`] callers). `Some(dir)` is the canonical shape for
/// builds against a sub-repo's flake — `commands/image_release.rs` and
/// `commands/tool.rs` both pass an explicit working directory.
///
/// # Errors
///
/// Returns an error if the nix build command fails. The underlying
/// [`NixBuildError`] is preserved across the anyhow boundary and can be
/// recovered with `err.downcast_ref::<NixBuildError>()` — the typed
/// `(BuildFailed | EmptyStorePath | ExecFailed | FlakeNotFound |
/// CargoNixMissing)` discrimination is structural to the typed-error
/// family and survives the anyhow envelope. Pre-migration the three
/// inline call sites fused stderr into a free-form `bail!` string, so a
/// downstream attestation / telemetry consumer that wanted the
/// `(exit_code, stderr)` tuple had to re-parse the message; post-
/// migration the tuple is recoverable by construction.
pub async fn build_flake_attr_in(
    flake_attr: &str,
    working_dir: Option<&Path>,
) -> Result<NixBuildResult> {
    debug!("Building Nix flake attribute: {}", flake_attr);

    // --impure required for path inputs like substrate in the root flake
    // and the sub-flake builds the migrated sites drive.
    let nix_bin = nix_bin();
    let store_path = run_nix_build_typed(
        &nix_bin,
        &[
            "build",
            flake_attr,
            "--no-link",
            "--print-out-paths",
            "--impure",
        ],
        flake_attr,
        working_dir,
    )
    .await?;

    debug!("Built {} at: {}", flake_attr, store_path);

    Ok(NixBuildResult {
        store_path,
        flake_attr: flake_attr.to_string(),
    })
}

/// Build a Docker image using Nix
///
/// This is a convenience wrapper around `build_flake_attr` for image builds.
///
/// # Arguments
///
/// * `image_name` - The name of the image (e.g., "postgres-bootstrap")
/// * `suffix` - Optional suffix (e.g., "-image", defaults to "-image")
///
/// # Examples
///
/// ```rust,ignore
/// let result = build_docker_image("postgres-bootstrap", None).await?;
/// // Builds .#postgres-bootstrap-image
/// ```
pub async fn build_docker_image(image_name: &str, suffix: Option<&str>) -> Result<NixBuildResult> {
    let suffix = suffix.unwrap_or("-image");
    let flake_attr = format!(".#{}{}", image_name, suffix);

    info!("📦 Building {} with Nix...", image_name);

    let result = build_flake_attr(&flake_attr).await?;

    info!("   ✅ Built: {}", result.store_path);

    Ok(result)
}

/// Build a Docker image from a specific flake directory
///
/// This is used for sub-flakes that are not exposed in the root flake.
///
/// # Arguments
///
/// * `flake_dir` - Path to the flake directory
/// * `image_name` - The name of the image (e.g., "postgres-bootstrap")
/// * `suffix` - Optional suffix (e.g., "-image", defaults to "-image")
///
/// # Examples
///
/// ```rust,ignore
/// let result = build_docker_image_from_dir("/path/to/bootstrap", "postgres-bootstrap", None).await?;
/// ```
pub async fn build_docker_image_from_dir(
    flake_dir: &std::path::Path,
    image_name: &str,
    suffix: Option<&str>,
) -> Result<NixBuildResult> {
    let suffix = suffix.unwrap_or("-image");
    let flake_ref = format!("{}#{}{}", flake_dir.display(), image_name, suffix);

    info!(
        "📦 Building {} from {} with Nix...",
        image_name,
        flake_dir.display()
    );
    debug!("Flake reference: {}", flake_ref);

    let nix_bin = nix_bin();
    let store_path = run_nix_build_typed(
        &nix_bin,
        &["build", &flake_ref, "--no-link", "--print-out-paths"],
        &flake_ref,
        None,
    )
    .await?;

    info!("   ✅ Built: {}", store_path);

    Ok(NixBuildResult {
        store_path,
        flake_attr: flake_ref,
    })
}

/// Run crate2nix to regenerate Cargo.nix
///
/// # Arguments
///
/// * `crate2nix_path` - Path to crate2nix binary (or just "crate2nix" if in PATH)
///
/// # Errors
///
/// Returns an error if crate2nix is not found or fails to generate. Routes
/// the bail-on-non-zero-exit shape through `retry::run_inherited_status`
/// so the (op, exit_code) tuple is carried into the anyhow chain by
/// construction — pre-migration the bail dropped the exit code into the
/// `Option<i32>::fmt(Debug)` rendering (`"with exit code: Some(N)"`),
/// indistinguishable from "killed by signal" (`"with exit code: None"`)
/// at the operator log surface.
pub async fn run_crate2nix(crate2nix_path: &str) -> Result<()> {
    info!("🔄 Running crate2nix generate...");

    crate::retry::run_bin_args_inherited_status(
        crate2nix_path,
        &["generate"],
        "crate2nix generate",
    )
    .await
    .context("Failed to regenerate Cargo.nix")?;

    Ok(())
}

/// Run `nix run nixpkgs#crate2nix -- generate [extra_generate_args…]` — the
/// nix-wrapped sibling of [`run_crate2nix`] the flake-registry consumer surface
/// uses when a direct `crate2nix` binary is not on PATH but a `nix` binary is
/// (the substrate-declared runtime the `nix run <registry>#<attr>` idiom
/// resolves against).
///
/// `nix_path` is the resolved `NIX_BIN` path (typically read through the
/// caller's `nix_bin()` sigil); `extra_generate_args` is the tail passed after
/// `--` to `crate2nix generate` — an empty slice for the plain-generate case,
/// `["-f", "Cargo.toml", "-o", "Cargo.nix"]` for the explicit-in/out case the
/// two `regenerate` command sites drive.
///
/// # Errors
///
/// Returns an error if `nix` is not found, if `nix run nixpkgs#crate2nix`
/// cannot resolve the flake attribute, or if the wrapped `crate2nix generate`
/// fails. Routes the bail-on-non-zero-exit shape through
/// `retry::run_inherited_status` so the (op, exit_code) tuple is carried into
/// the anyhow chain by construction — same canonical record-shape every other
/// migrated status-only inherited-stdio site in forge consumes.
pub async fn run_nix_wrapped_crate2nix(nix_path: &str, extra_generate_args: &[&str]) -> Result<()> {
    info!("🔄 Running `nix run nixpkgs#crate2nix -- generate`...");

    let mut argv: Vec<&str> = vec!["run", "nixpkgs#crate2nix", "--", "generate"];
    argv.extend_from_slice(extra_generate_args);
    crate::retry::run_bin_args_inherited_status(nix_path, &argv, "crate2nix generate")
        .await
        .context("Failed to generate Cargo.nix")?;

    Ok(())
}

/// Run cargo update to refresh Cargo.lock
///
/// # Arguments
///
/// * `cargo_path` - Path to cargo binary (or just "cargo" if in PATH)
///
/// # Errors
///
/// Returns an error if cargo is not found or update fails. Routes the
/// bail-on-non-zero-exit shape through `retry::run_inherited_status` so
/// the (op, exit_code) tuple is carried into the anyhow chain by
/// construction — same canonical record-shape every other migrated
/// status-only inherited-stdio site in forge consumes.
pub async fn run_cargo_update(cargo_path: &str) -> Result<()> {
    info!("📦 Updating Cargo.lock...");

    crate::retry::run_bin_args_inherited_status(cargo_path, &["update"], "cargo update")
        .await
        .context("Failed to update Cargo.lock")?;

    Ok(())
}

/// Recursive-closure enumeration for a built Nix output link — the
/// canonical typed primitive that pairs with
/// [`crate::infrastructure::attic::AtticClient::push_closure_via_stdin`]
/// on the "push every derivation in a build closure to Attic" surface.
///
/// `stdout` is the raw one-store-path-per-line output of `nix path-info
/// --recursive <output_link>`, retained verbatim as `Vec<u8>` so a
/// downstream `AtticClient::push_closure_via_stdin` call can feed it to
/// `attic push --stdin` byte-for-byte without a UTF-8 round-trip.
/// `closure_size` is the count of non-empty newline-delimited lines in
/// `stdout` — the same size the three pre-lift call sites derived via
/// `String::from_utf8_lossy(&stdout).lines().count()`, computed here
/// once at the primitive rather than three times at the callers.
#[derive(Debug)]
pub struct NixClosureInfo {
    pub stdout: Vec<u8>,
    pub closure_size: usize,
}

/// Enumerate the recursive closure of a built Nix output link via
/// `nix path-info --recursive <output_link>`, returning the raw
/// one-store-path-per-line stdout AND the derived closure size in one
/// typed record.
///
/// Lifts the verbatim ~18-line stanza
/// ```text
/// let path_info_output = Command::new(<bare-nix-literal>)
///     .args(&["path-info", "--recursive", <output_link>])
///     .output().await
///     .context("Failed to run nix path-info")?;
/// if !path_info_output.status.success() {
///     // warn — non-fatal
/// } else {
///     let paths = String::from_utf8_lossy(&path_info_output.stdout);
///     let closure_size = paths.lines().count();
///     // log size + push_closure_via_stdin(...stdout)
/// }
/// ```
/// that three command-module sites in forge carry verbatim modulo per-
/// site output-link literal and per-site log messaging:
/// - `commands/build.rs::execute` (single closure push after image build)
/// - `commands/rust_service.rs::push_rust_service` (AMD64 arm)
/// - `commands/rust_service.rs::push_rust_service` (ARM64 arm)
///
/// Three identically-shaped bodies past THEORY §VI.1's three-times
/// threshold (PRIME DIRECTIVE: duplication budget is zero) consolidate
/// onto this typed primitive. Three load-bearing properties this
/// primitive owns that the pre-lift raw-spawn stanzas dropped:
/// 1. **`NIX_BIN` env override.** Pre-lift each site spawned the
///    bare `nix` literal, ignoring the env var every other nix-
///    invocation site in the workspace honors via the [`nix_bin`]
///    sigil — so a Nix-hermetic runner with a store-path `nix` binary
///    would fall through to whatever `nix` was first on PATH at these
///    three sites specifically.
/// 2. **Typed error dispatch.** Pre-lift a spawn failure landed on the
///    fatal `?` path via anyhow context; a nonzero exit collapsed into
///    a bare `warn!("⚠️ Failed to get closure info (non-fatal)")` that
///    dropped the exit code, the stderr, AND the offending output-link
///    entirely. Post-lift both surface as typed
///    [`NixBuildError::ExecFailed`] / [`NixBuildError::PathInfoFailed`]
///    carrying the structural-record tuple THEORY §V.4 Phase 1
///    attestation records pattern-match on.
/// 3. **`closure_size` derivation.** Pre-lift each site re-derived the
///    line count via `String::from_utf8_lossy(&stdout).lines().count()`;
///    post-lift the derivation lives at ONE construction surface so a
///    future refinement (e.g. filter out `.drv` closures, exclude
///    fixed-output derivations) lands in one place.
///
/// # Contract
///
/// - `output_link` is the built-artifact identifier `nix path-info
///   --recursive` reads — a `result*` symlink path (the three call
///   sites' shape: `"result"`, `"result-amd64"`, `"result-arm64"`, or a
///   `format!("{}/{}", working_dir, output)` absolute path). Passed
///   verbatim to `nix path-info --recursive`; no grammar check is
///   performed here (Nix's own resolver handles the "no such symlink"
///   case, surfaced through [`NixBuildError::PathInfoFailed`]).
/// - Returns [`NixBuildError::ExecFailed`] with `flake_attr =
///   output_link.to_string()` when the resolved `nix` binary cannot be
///   spawned. Reuses the `flake_attr` field name for cross-call-site
///   uniformity with [`run_nix_build_typed`]; a future field-rename
///   (`flake_attr` -> `label`) lands in one place.
/// - Returns [`NixBuildError::PathInfoFailed`] carrying `(output_link,
///   exit_code, stderr)` when `nix path-info --recursive` exits
///   non-zero — the same structural-record tuple THEORY §V.4 Phase 1
///   attestation records consume, distinct from `BuildFailed` at the
///   type level so telemetry can tell build-step failures from
///   closure-enumeration failures without parsing the message.
///
/// # Non-fatal composition
///
/// The primitive returns a typed `Result`; the three lifted call sites
/// treat `nix path-info` failure as non-fatal by pattern-matching on
/// the returned `Result` (each site keeps its site-specific warn
/// messaging, since the pre-lift text differs per site — "closure
/// info" vs "AMD64 closure info" vs "ARM64 closure info"). A future
/// caller that wants the fatal contract composes `?`; a caller that
/// wants the non-fatal contract composes `.ok()` and its own log.
pub async fn path_info_recursive(output_link: &str) -> Result<NixClosureInfo, NixBuildError> {
    let nix_bin = nix_bin();
    path_info_recursive_with_bin(&nix_bin, output_link).await
}

/// Test-injection sibling of [`path_info_recursive`]: accepts the
/// resolved `nix_bin` as an explicit argument so unit tests can point
/// at a hermetic shim without mutating the process-wide `NIX_BIN`
/// environment variable — same discipline as `run_nix_build_typed` in
/// this module (a private `nix_bin: &str` helper the public wrapper
/// delegates to after resolving `get_tool_path`) and
/// `AtticClient::with_attic_bin` in `infrastructure/attic.rs` (a
/// `#[cfg(test)]` builder override on the client struct). Splitting
/// the resolution from the execution keeps the test surface hermetic
/// AND parallel-safe: `#[tokio::test]` on this module can run
/// concurrent tests without racing on env-var writes.
async fn path_info_recursive_with_bin(
    nix_bin: &str,
    output_link: &str,
) -> Result<NixClosureInfo, NixBuildError> {
    let mut cmd = Command::new(nix_bin);
    cmd.args(["path-info", "--recursive", output_link])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    // Spawn-vs-op dispatch flows through the canonical
    // [`classify_capture`] primitive — same shape as
    // `run_nix_build_typed`, but returns the raw `Output` (rather than
    // the trimmed-UTF-8 stdout of `classify_capture_query`) because the
    // downstream consumer — `push_closure_via_stdin` — needs the raw
    // bytes verbatim. Spawn failure -> `ExecFailed` carrying the
    // output-link as the `flake_attr` label (uniform with the
    // build-step primitive's field name). Non-zero exit -> the new
    // `PathInfoFailed` variant carrying (output_link, exit_code,
    // stderr) — the structural-record tuple THEORY §V.4 Phase 1
    // attestation records consume.
    let output = classify_capture(
        cmd.output().await,
        |e| NixBuildError::ExecFailed {
            flake_attr: output_link.to_string(),
            message: e.to_string(),
        },
        |cf| NixBuildError::PathInfoFailed {
            output_link: output_link.to_string(),
            exit_code: cf.exit_code,
            stderr: cf.stderr,
        },
    )?;

    // Line count via `str::lines()` on the UTF-8-lossy view — same
    // derivation the three pre-lift call sites drove verbatim. `lines()`
    // excludes a trailing empty line if stdout ends with `\n` (the
    // canonical shape `nix path-info` produces), so an N-store-path
    // closure yields `closure_size == N` — the count the pre-lift
    // sites' `info!/println!("Found {} derivations in closure", ...)`
    // log lines reported.
    let closure_size = String::from_utf8_lossy(&output.stdout).lines().count();
    Ok(NixClosureInfo {
        stdout: output.stdout,
        closure_size,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_build_flake_attr_invalid() {
        // This should fail because the attribute doesn't exist
        let result = build_flake_attr(".#nonexistent-package-xyz").await;
        assert!(result.is_err());
    }

    use crate::test_support::make_executable_shim;

    /// Write an executable shim script that pretends to be `nix`.
    /// Delegates to the shared
    /// `crate::test_support::make_executable_shim` so the shim
    /// discipline (absolute-path invocation, 0o755 chmod, tempdir
    /// lifetime) lives in one place — same primitive as
    /// `git.rs`'s `make_git_shim` and `attic.rs`'s `make_attic_shim`.
    fn make_nix_shim(body: &str) -> (tempfile::TempDir, String) {
        make_executable_shim("nix", body)
    }

    /// When the resolved nix binary cannot be spawned, `run_nix_build_typed`
    /// must surface `ExecFailed` carrying the offending label (not a stringly
    /// anyhow `Failed to execute nix build command`). Pins the typed split
    /// so telemetry can distinguish "nix missing" from "nix said no".
    #[tokio::test]
    async fn test_run_nix_build_typed_exec_failed_carries_label() {
        // Absolute path that does not exist — Command::spawn fails
        // deterministically without touching global PATH state.
        let result = run_nix_build_typed(
            "/nonexistent/path/to/nix-binary-that-does-not-exist",
            &["build", ".#x"],
            ".#x",
            None,
        )
        .await;
        let err = result.expect_err("missing nix binary must fail");
        match err {
            NixBuildError::ExecFailed { flake_attr, .. } => {
                assert_eq!(flake_attr, ".#x");
            }
            other => panic!("expected ExecFailed, got: {other:?}"),
        }
    }

    /// Build failures must produce `BuildFailed` carrying the flake
    /// attribute, an exit code, and the captured stderr — never a fused
    /// stringly bag. Uses a shim invoked by absolute path so the test is
    /// hermetic and parallel-safe.
    #[tokio::test]
    async fn test_run_nix_build_typed_build_failed_carries_structured_fields() {
        let (_dir, shim) = make_nix_shim("#!/bin/sh\necho 'attribute foo missing' 1>&2\nexit 7\n");
        let result = run_nix_build_typed(&shim, &["build", ".#thing"], ".#thing", None).await;
        let err = result.expect_err("nonzero exit must fail");
        match err {
            NixBuildError::BuildFailed {
                flake_attr,
                exit_code,
                stderr,
            } => {
                assert_eq!(flake_attr, ".#thing");
                assert_eq!(exit_code, Some(7));
                assert!(
                    stderr.contains("attribute foo missing"),
                    "stderr field must capture the nix stderr verbatim, got: {stderr:?}"
                );
            }
            other => panic!("expected BuildFailed, got: {other:?}"),
        }
    }

    /// A nix invocation that exits zero with empty stdout must produce
    /// `EmptyStorePath` — distinct from a real build failure — so callers
    /// can treat "contract violation" differently from "nix said no".
    #[tokio::test]
    async fn test_run_nix_build_typed_empty_store_path() {
        let (_dir, shim) = make_nix_shim("#!/bin/sh\nexit 0\n");
        let result = run_nix_build_typed(&shim, &["build", ".#empty"], ".#empty", None).await;
        let err = result.expect_err("empty stdout must fail");
        match err {
            NixBuildError::EmptyStorePath { flake_attr } => {
                assert_eq!(flake_attr, ".#empty");
            }
            other => panic!("expected EmptyStorePath, got: {other:?}"),
        }
    }

    /// On the success path, `run_nix_build_typed` must return the trimmed
    /// stdout verbatim as the store path — routed through the canonical
    /// [`StorePath::parse`] grammar oracle at the nix-frontier, so a
    /// well-formed value survives the round-trip unchanged. The fixture
    /// is the same canonical valid store path the sibling attestation and
    /// store-path grammar suites use (`0123…xyz` = the full 32-symbol Nix
    /// base-32 alphabet), so the grammar-oracle wiring is exercised end-
    /// to-end here rather than only in the store-path unit tests.
    #[tokio::test]
    async fn test_run_nix_build_typed_success_returns_store_path() {
        let (_dir, shim) = make_nix_shim(
            "#!/bin/sh\necho '/nix/store/0123456789abcdfghijklmnpqrsvwxyz-mysvc'\nexit 0\n",
        );
        let store_path = run_nix_build_typed(&shim, &["build", ".#ok"], ".#ok", None)
            .await
            .expect("success path");
        assert_eq!(
            store_path,
            "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-mysvc"
        );
    }

    /// `nix build --print-out-paths` that exits zero and prints a non-empty
    /// stdout that does not parse as a store object path must surface
    /// `MalformedStorePath` at the nix-frontier — the failure record must
    /// carry the flake label, the exact raw stdout, and the exact
    /// [`crate::store_path::StorePathError`] grammar clause under the
    /// `#[source]` chain. Pre-migration the raw stdout propagated
    /// unchecked to `attic push` (cryptic remote error) and the SLSA
    /// provenance gate (`.unwrap_or(false)` silently drops the
    /// attestation); the fixture here — `/nix/store/not-a-real-store-path`
    /// — is short enough to fire `StorePathError::TooShort`, the exact
    /// clause the frontier check catches.
    #[tokio::test]
    async fn test_run_nix_build_typed_malformed_store_path_carries_typed_variant() {
        use crate::store_path::StorePathError;
        use std::error::Error as _;
        let (_dir, shim) =
            make_nix_shim("#!/bin/sh\necho '/nix/store/not-a-real-store-path'\nexit 0\n");
        let result = run_nix_build_typed(&shim, &["build", ".#garbled"], ".#garbled", None).await;
        let err = result.expect_err("malformed nix stdout must fail typed");
        match &err {
            NixBuildError::MalformedStorePath {
                flake_attr,
                raw,
                source,
            } => {
                assert_eq!(flake_attr, ".#garbled");
                assert_eq!(raw, "/nix/store/not-a-real-store-path");
                assert!(
                    matches!(source, StorePathError::TooShort { .. }),
                    "expected TooShort grammar clause, got: {source:?}"
                );
            }
            other => panic!("expected MalformedStorePath, got: {other:?}"),
        }
        // The `#[source]` chain must expose the exact grammar clause so a
        // downstream telemetry consumer walking `Error::source` reaches
        // the rejection site without parsing the display string.
        let src = err.source().expect("must carry a source");
        let downcast = src
            .downcast_ref::<StorePathError>()
            .expect("source must downcast to StorePathError");
        assert!(matches!(downcast, StorePathError::TooShort { .. }));
    }

    /// `working_dir = Some(dir)` must spawn the nix process inside `dir`.
    /// Pinned with a shim that records its current working directory to a
    /// side-channel marker file (`pwd > .observed-cwd`) and prints a
    /// canonical valid store path on stdout — the stdout must satisfy the
    /// nix-frontier `StorePath::parse` gate the primitive now enforces,
    /// while the marker file is what proves `current_dir` was honored.
    /// Pre-migration, the three command-module sites that need a working
    /// directory drove `current_dir` on `tokio::process::Command` directly
    /// inline; post-migration the canonical primitive owns the wiring. A
    /// future regression that silently dropped the `current_dir` setter
    /// (e.g. via a refactor that moved the builder chain) would leave
    /// sub-flake builds resolving the wrong `flake.nix` — the canonical
    /// "wrong-tree" silent failure shape this test pins out.
    #[tokio::test]
    async fn test_run_nix_build_typed_honors_working_dir() {
        let (dir, shim) = make_nix_shim(
            "#!/bin/sh\npwd > .observed-cwd\n\
             echo '/nix/store/0123456789abcdfghijklmnpqrsvwxyz-marker'\nexit 0\n",
        );
        let work = tempfile::tempdir().expect("temp dir");
        let work_canonical = std::fs::canonicalize(work.path()).expect("canonicalize work");
        let store_path = run_nix_build_typed(&shim, &["build", ".#ok"], ".#ok", Some(work.path()))
            .await
            .expect("success path");
        assert_eq!(
            store_path, "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-marker",
            "stdout must pass through the nix-frontier grammar oracle unchanged"
        );
        let observed_raw = std::fs::read_to_string(work.path().join(".observed-cwd"))
            .expect("shim must have written .observed-cwd inside the working_dir");
        let observed = std::fs::canonicalize(observed_raw.trim()).expect("canonicalize observed");
        assert_eq!(
            observed, work_canonical,
            "shim's observed CWD must equal the working_dir passed to run_nix_build_typed"
        );
        drop(dir);
    }

    /// `working_dir = Some(missing_dir)` must surface a spawn-failure
    /// (`NixBuildError::ExecFailed`) with the offending label intact —
    /// the same typed contract `working_dir = None` provides. Pinned so a
    /// future regression that silently logged-and-swallowed the
    /// `current_dir` error (e.g. via a `.unwrap_or_default()` on the path)
    /// would surface here, not as a confusing "nix succeeded with empty
    /// stdout" downstream.
    #[tokio::test]
    async fn test_run_crate2nix_nonzero_exit_carries_structural_record() {
        // Shim under the basename `crate2nix` so the producer's
        // `Command::new(crate2nix_path)` sees a binary that exits with
        // a deterministic non-zero code. The migration routes the
        // bail-on-non-zero-exit shape through `retry::run_inherited_
        // status`, which emits `"{op} failed (exit N)"` as the
        // canonical structural record. Pre-migration the bail string
        // was `"crate2nix generate failed with exit code: Some(N)"`
        // (the `Option<i32>::fmt(Debug)` rendering), so the post-
        // migration canonical-record assertion fails-before-passes-
        // after by construction.
        let (_dir, shim) = make_executable_shim("crate2nix", "#!/bin/sh\nexit 9\n");
        let err = run_crate2nix(&shim)
            .await
            .expect_err("nonzero exit must fail");
        let chain = format!("{:?}", err);
        assert!(
            chain.contains("crate2nix generate failed (exit 9)"),
            "must carry canonical (op, exit_code) record; got: {chain}"
        );
        assert!(
            chain.contains("Failed to regenerate Cargo.nix"),
            "must carry outer caller-narrative; got: {chain}"
        );
    }

    #[tokio::test]
    async fn test_run_nix_wrapped_crate2nix_nonzero_exit_carries_structural_record() {
        // Symmetric pin for `run_nix_wrapped_crate2nix` — the `nix run
        // nixpkgs#crate2nix -- generate` sibling of `run_crate2nix`.
        // Shim under the basename `nix` so the producer's
        // `Command::new(nix_path)` sees a binary that exits with a
        // deterministic non-zero code. The migration routes the
        // bail-on-non-zero-exit shape through `retry::run_inherited_
        // status`, which emits `"{op} failed (exit N)"` as the
        // canonical structural record. Pre-migration each of the three
        // developer_tools sites hand-rolled the spawn WITHOUT the
        // outer `context("Failed to generate Cargo.nix")` wrap
        // reaching the operator log surface consistently, and two
        // spelled the bail-context prefix differently (`"Failed to
        // run crate2nix generate"` vs `"Failed to generate Cargo.
        // nix"`); post-migration every consumer inherits ONE canonical
        // context wrap and ONE canonical record shape from the
        // primitive.
        let (_dir, shim) = make_executable_shim("nix", "#!/bin/sh\nexit 11\n");
        let err = run_nix_wrapped_crate2nix(&shim, &[])
            .await
            .expect_err("nonzero exit must fail");
        let chain = format!("{:?}", err);
        assert!(
            chain.contains("crate2nix generate failed (exit 11)"),
            "must carry canonical (op, exit_code) record; got: {chain}"
        );
        assert!(
            chain.contains("Failed to generate Cargo.nix"),
            "must carry outer caller-narrative; got: {chain}"
        );
    }

    #[tokio::test]
    async fn test_run_nix_wrapped_crate2nix_forwards_extra_generate_args_verbatim() {
        // The primitive's `extra_generate_args: &[&str]` tail must
        // land on the wrapped `crate2nix generate` argv verbatim, in
        // order, AFTER the fixed prefix `["run", "nixpkgs#crate2nix",
        // "--", "generate"]`. Pre-lift the two `regenerate` sites each
        // spelled the eight-element argv literal
        // (`["run", "nixpkgs#crate2nix", "--", "generate", "-f",
        // "Cargo.toml", "-o", "Cargo.nix"]`) verbatim; a primitive that
        // silently reordered or dropped the tail would break both.
        // This shim captures its argv to `.observed-argv` and the
        // assertion is byte-exact against the joined form the
        // `regenerate` sites pass, so a reorder or a dropped element
        // fails-before-passes-after.
        let work = tempfile::tempdir().expect("temp dir");
        let observed = work.path().join(".observed-argv");
        let (_dir, shim) = make_executable_shim(
            "nix",
            &format!(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" > {}\nexit 0\n",
                observed.display()
            ),
        );
        run_nix_wrapped_crate2nix(&shim, &["-f", "Cargo.toml", "-o", "Cargo.nix"])
            .await
            .expect("success path");
        let captured = std::fs::read_to_string(&observed)
            .expect("shim must have written the observed argv line");
        let expected = "run\nnixpkgs#crate2nix\n--\ngenerate\n-f\nCargo.toml\n-o\nCargo.nix\n";
        assert_eq!(
            captured, expected,
            "the wrapped-generate argv must land at the shim verbatim: \
             fixed prefix `run nixpkgs#crate2nix -- generate` followed \
             by the caller's `extra_generate_args` tail in order, one \
             element per line. A drift (reorder, dropped element, \
             extra element) breaks both `regenerate` sites at once."
        );
    }

    #[tokio::test]
    async fn test_run_cargo_update_nonzero_exit_carries_structural_record() {
        // Symmetric pin for `run_cargo_update` — same migration shape,
        // same canonical record-format, same fails-before-passes-after
        // discipline. Pre-migration the bail was
        // `"cargo update failed with exit code: Some(N)"`; post-
        // migration the canonical `"cargo update failed (exit N)"`
        // record carries the exit code into the chain.
        let (_dir, shim) = make_executable_shim("cargo", "#!/bin/sh\nexit 13\n");
        let err = run_cargo_update(&shim)
            .await
            .expect_err("nonzero exit must fail");
        let chain = format!("{:?}", err);
        assert!(
            chain.contains("cargo update failed (exit 13)"),
            "must carry canonical (op, exit_code) record; got: {chain}"
        );
        assert!(
            chain.contains("Failed to update Cargo.lock"),
            "must carry outer caller-narrative; got: {chain}"
        );
    }

    #[tokio::test]
    async fn test_run_nix_build_typed_missing_working_dir_routes_to_exec_failed() {
        let (_dir, shim) = make_nix_shim("#!/bin/sh\necho '/nix/store/x'\nexit 0\n");
        let missing = std::path::Path::new(
            "/this/dir/does/not/exist-deliberately-for-the-nix-build-typed-test",
        );
        let result = run_nix_build_typed(&shim, &["build", ".#x"], ".#x", Some(missing)).await;
        let err = result.expect_err("missing working_dir must fail");
        match err {
            NixBuildError::ExecFailed { flake_attr, .. } => {
                assert_eq!(flake_attr, ".#x");
            }
            other => panic!("expected ExecFailed, got: {other:?}"),
        }
    }

    /// `path_info_recursive_with_bin` on the success path must return
    /// the raw stdout bytes verbatim AND the derived
    /// `closure_size = <non-empty newline-delimited line count>`. Pins
    /// the two load-bearing properties the three pre-lift call sites
    /// relied on together: `push_closure_via_stdin` needs the raw
    /// bytes verbatim (no UTF-8 round-trip), and the
    /// `info!/println!("Found {} derivations in closure", ...)` log
    /// line needs the same `str::lines().count()` value each site
    /// re-derived pre-lift.
    #[tokio::test]
    async fn test_path_info_recursive_with_bin_success_returns_bytes_and_size() {
        let (_dir, shim) = make_nix_shim(
            "#!/bin/sh\necho '/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-a'\n\
             echo '/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-b'\nexit 0\n",
        );
        let info = path_info_recursive_with_bin(&shim, "result-x")
            .await
            .expect("success path");
        assert_eq!(
            info.closure_size, 2,
            "two non-empty newline-delimited lines"
        );
        assert_eq!(
            info.stdout,
            b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-a\n\
              /nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-b\n"
                .to_vec(),
            "raw stdout bytes must flow through unchanged for push_closure_via_stdin"
        );
    }

    /// `path_info_recursive_with_bin` on the spawn-failure path (nix
    /// binary missing) must surface [`NixBuildError::ExecFailed`]
    /// carrying the output-link as the `flake_attr` label — sibling of
    /// [`test_run_nix_build_typed_exec_failed_carries_label`] on the
    /// closure-enumeration surface. Pins the spawn-vs-op split at the
    /// type level so telemetry can distinguish "nix missing" from "nix
    /// path-info said no" without parsing strings. Uses an absolute
    /// path that does not exist, injected directly into the
    /// `_with_bin` helper, so the test is hermetic and parallel-safe
    /// (no env-var mutation).
    #[tokio::test]
    async fn test_path_info_recursive_with_bin_exec_failed_carries_output_link() {
        let err = path_info_recursive_with_bin(
            "/nonexistent/path/to/nix-binary-does-not-exist-for-path-info-test",
            "result-missing-bin",
        )
        .await
        .expect_err("missing nix binary must fail");
        match err {
            NixBuildError::ExecFailed { flake_attr, .. } => {
                assert_eq!(flake_attr, "result-missing-bin");
            }
            other => panic!("expected ExecFailed, got: {other:?}"),
        }
    }

    /// `path_info_recursive_with_bin` failures must produce
    /// [`NixBuildError::PathInfoFailed`] carrying the output-link, exit
    /// code, and captured stderr — never a fused stringly bag and never
    /// the pre-lift `warn!("⚠️ Failed to get closure info (non-fatal)")`
    /// line that dropped all three fields. The `PathInfoFailed` shape
    /// is distinct from `BuildFailed` at the type level so a downstream
    /// telemetry / Phase 1 attestation record (THEORY §V.4) can tell a
    /// build-step failure from a closure-enumeration failure without
    /// parsing the message.
    #[tokio::test]
    async fn test_path_info_recursive_with_bin_path_info_failed_carries_structured_fields() {
        let (_dir, shim) = make_nix_shim(
            "#!/bin/sh\necho 'error: getting status of ./result-gone: No such file or directory' 1>&2\nexit 1\n",
        );
        let err = path_info_recursive_with_bin(&shim, "result-gone")
            .await
            .expect_err("nonzero exit must fail");
        match err {
            NixBuildError::PathInfoFailed {
                output_link,
                exit_code,
                stderr,
            } => {
                assert_eq!(output_link, "result-gone");
                assert_eq!(exit_code, Some(1));
                assert!(
                    stderr.contains("No such file"),
                    "stderr must carry the nix stderr verbatim, got: {stderr:?}"
                );
            }
            other => panic!("expected PathInfoFailed, got: {other:?}"),
        }
    }

    /// Empty stdout on the success path must produce `closure_size = 0`
    /// — pins that the line-count derivation matches `str::lines()`
    /// semantics on an empty input (the three pre-lift call sites all
    /// used `String::from_utf8_lossy(&stdout).lines().count()`, which
    /// is `0` on an empty stdout). Distinct from
    /// [`NixBuildError::PathInfoFailed`] at the type level: a nix
    /// invocation that succeeds and prints nothing is a valid (though
    /// degenerate) closure-enumeration result, not a failure.
    #[tokio::test]
    async fn test_path_info_recursive_with_bin_empty_stdout_yields_zero_closure_size() {
        let (_dir, shim) = make_nix_shim("#!/bin/sh\nexit 0\n");
        let info = path_info_recursive_with_bin(&shim, "result-empty")
            .await
            .expect("empty-but-successful path");
        assert_eq!(
            info.closure_size, 0,
            "empty stdout must yield closure_size 0"
        );
        assert!(info.stdout.is_empty(), "stdout must be empty bytes");
    }
}

#[cfg(test)]
mod nix_bin_routing_tests {
    /// Whole-module shield: no raw `Command::new("nix")` may live in
    /// `cli/src/nix.rs`'s non-test body, `fn nix_bin()` must be
    /// defined, and the two-argument NIX_BIN resolve must appear
    /// exactly ONCE in the module body (only in the sigil body).
    ///
    /// Pre-lift the three public-caller sites — [`super::build_flake_attr_in`]'s
    /// primary `nix build` invocation, [`super::build_docker_image_from_dir`]'s
    /// sub-flake `nix build`, and [`super::path_info_recursive`]'s
    /// `nix path-info --recursive` closure probe — each spelled the
    /// two-argument NIX_BIN resolve verbatim at each consumer.
    /// Post-lift each site collapses to `let nix_bin = nix_bin();` and
    /// the resolve appears in exactly ONE place (the sigil body). The
    /// `resolve_count == 1` assertion fails-before at 3, passes-after
    /// at 1 — the canonical fail-before-pass-after arc matching the
    /// sibling `<tool>_bin()` shield discipline landed on
    /// `commands/rust_service.rs::nix_bin` (63d4fe7),
    /// `commands/developer_tools.rs::nix_bin` (a12c172),
    /// `commands/frontend_validation.rs::bun_bin` (9986f11), and the
    /// broader CARGO / BUN_BIN / CRATE2NIX sigil family.
    ///
    /// The scan bounds on the whole-module boundary (from the file
    /// start to the FIRST `\n#[cfg(test)]\n` marker in source order,
    /// which lands at the sibling `mod tests` block above) so this
    /// shield's own docstring mentions of the forbidden literal —
    /// living in a `#[cfg(test)]` block below that first marker — stay
    /// out of scope AND every current or future nix-spawning helper
    /// landing anywhere in the top-level module body cannot silently
    /// ride along without going through `nix_bin()`.
    ///
    /// The two-argument-resolve needle is reconstructed via `format!`
    /// inside [`crate::test_support::get_tool_path_two_arg_call_needle`],
    /// so this shield's own source never contains the literal
    /// two-argument NIX_BIN resolve string and cannot false-match
    /// itself on the count-eq-1 assertion. The [`super::path_info_recursive`]
    /// primitive-docstring paragraph that pre-lift quoted the resolve
    /// verbatim (`nix.rs:432-437`) is paraphrased to reference the
    /// [`super::nix_bin`] sigil instead, so no docstring literal
    /// contributes to the count either.
    ///
    /// The `run_nix_build_typed(nix_bin: &str, ...)` and
    /// `path_info_recursive_with_bin(nix_bin: &str, ...)` primitives
    /// keep their `nix_bin: &str` parameter unchanged — the
    /// resolution split stays intact so `#[tokio::test]` on this
    /// module can point at a hermetic shim without mutating the
    /// process-wide env variable. The sigil owns the public-caller
    /// side of the split; the primitives own the test-injection side.
    #[test]
    fn test_nix_routes_nix_through_nix_bin_sigil_not_raw_command() {
        const SOURCE: &str = include_str!("nix.rs");
        let body = crate::test_support::module_body_before_first_cfg_test(SOURCE, "cli/src/nix.rs");
        assert!(
            !body.contains("Command::new(\"nix\")"),
            "cli/src/nix.rs must not spawn `nix` via the bare \
             literal — every `nix` spawn must resolve `NIX_BIN` via \
             `nix_bin()` first. A raw `Command::new(\"nix\")` bypasses \
             the hermetic-runner contract substrate's mkRuntimeToolsEnv \
             exports."
        );
        assert!(
            body.contains("fn nix_bin()"),
            "cli/src/nix.rs must define `nix_bin()` — the sigil \
             function that resolves the tools-registry `NIX_BIN` \
             override for every nix spawn. Mirrors the sibling \
             `nix_bin()` sigils at `commands/rust_service.rs` \
             (63d4fe7), `commands/developer_tools.rs` (a12c172), \
             `commands/comprehensive_release.rs:59`, and the broader \
             `<tool>_bin()` sigil discipline across the fleet."
        );
        let two_arg_needle =
            crate::test_support::get_tool_path_two_arg_call_needle("NIX_BIN", "nix");
        let resolve_count = body.matches(two_arg_needle.as_str()).count();
        assert_eq!(
            resolve_count, 1,
            "the two-argument resolve `{two_arg_needle}` must appear \
             exactly ONCE in the module body (only in the `nix_bin()` \
             sigil), not {resolve_count} times — every consumer must \
             route through `nix_bin()`, not re-copy the resolve inline"
        );
    }
}
