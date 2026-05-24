//! Docker daemon `docker` shell-out helpers.
//!
//! Houses the typed primitives forge uses to query the local Docker
//! daemon from command-module surfaces — distinct from
//! `cli/src/infrastructure/registry.rs`, which drives the remote
//! image-registry surface (skopeo / regctl against GHCR), and from
//! `cli/src/commands/rust_service.rs::push_docker_images`, which
//! drives the multi-arch push pipeline through that registry surface.
//!
//! Current surface:
//!
//! - [`find_first_image_id_by_name`] (sync) +
//!   [`find_first_image_id_by_name_async`] (async) — the canonical
//!   "look up a local Docker image's ID by name reference via
//!   `docker images -q <name>`" primitive. Three pre-lift sites
//!   carried verbatim copies of this shape
//!   (`commands/e2e.rs::check_image_exists`,
//!   `commands/product_release.rs::check_local_image_exists`,
//!   `commands/product_release.rs::push_prebuilt_image`'s inline
//!   image-id fetch) past THEORY §VI.1's three-is-a-law threshold.
//!   Sync + async siblings are both provided because the call sites
//!   are split across a sync entry point (`e2e.rs`) and an async
//!   one (`product_release.rs`) — mirrors the
//!   `fetch_secret_value` (sync) / `find_first_pod_name_async`
//!   (async) split this module's `kubectl.rs` sibling already
//!   carries.

use crate::tools::get_tool_path;

/// Canonical docker argv that fetches the IDs of local images matching
/// a name reference: `docker images -q <name>`. Centralized so the
/// sync ([`find_first_image_id_by_name`]) + async
/// ([`find_first_image_id_by_name_async`]) primitives and their
/// `_with_bin` test siblings all build the same argv from one
/// definition. A regression that, e.g., dropped the `-q` flag
/// (silently broadening output to the human-readable table format
/// that no caller knows how to parse) is a one-site fix here.
fn first_image_id_args(name: &str) -> [&str; 3] {
    ["images", "-q", name]
}

/// Classify a `docker images -q <name>` captured output into
/// `Option<String>`.
///
/// Returns `None` on non-zero exit, non-UTF8 stdout, or empty /
/// whitespace-only first line (no image matched the name reference);
/// `Some(<trimmed first line>)` otherwise.
///
/// The "first line" semantic matches every pre-lift call site:
/// `docker images -q <name>` emits one ID per matching image
/// separated by newlines, and the canonical post-lift behavior is
/// "give me the ID of the image" (singular). The
/// `check_local_image_exists` / `check_image_exists` siblings only
/// inspected non-emptiness; the `push_prebuilt_image` site
/// additionally took `.lines().next()` to pick the first ID.
/// Centralizing first-line + trim at the primitive collapses the
/// two read-shapes onto one classifier.
fn classify_first_image_id(output: &std::process::Output) -> Option<String> {
    if !output.status.success() {
        return None;
    }
    let raw = std::str::from_utf8(&output.stdout).ok()?;
    let first = raw.lines().next()?.trim();
    if first.is_empty() {
        None
    } else {
        Some(first.to_string())
    }
}

/// Find the ID of the first local Docker image matching a name
/// reference via `docker images -q <name>`. Sync sibling of
/// [`find_first_image_id_by_name_async`].
///
/// Returns `None` on any failure — docker not spawnable (daemon
/// down / binary missing), non-zero exit, non-UTF8 stdout, or
/// empty stdout (no image matched). The "best-effort, fall back
/// to None" shape matches the
/// [`crate::infrastructure::kubectl::fetch_secret_value`] and
/// [`crate::infrastructure::kubectl::find_first_pod_name_async`]
/// discipline: every pre-lift caller either bailed-or-degraded on
/// the missing-image case via a hand-rolled
/// `from_utf8_lossy(...).trim().is_empty()` chain.
/// Consolidating onto one Option-typed
/// primitive keeps the per-caller decision (bail with a
/// caller-specific message, fall through, build the image fresh)
/// at the caller while the discovery shape lives once at the
/// typed surface.
///
/// # Example
///
/// ```rust,ignore
/// // "does this prebuilt image exist locally?"
/// let exists = find_first_image_id_by_name("my-product-backend").is_some();
///
/// // "give me the image ID so I can re-tag it"
/// let image_id = find_first_image_id_by_name("my-product-backend")
///     .ok_or_else(|| anyhow::anyhow!("no local image for my-product-backend"))?;
/// ```
///
/// # Why Option, not Result
///
/// All three pre-lift call sites swallowed the spawn-failure case
/// at the immediate-caller layer (`unwrap_or(false)` at four
/// `e2e.rs` sites, `unwrap_or(false)` at the `product_release.rs`
/// caller) — the spawn-error-as-`Err` shape was structurally
/// redundant. Collapsing all failures to `None` at the typed
/// primitive matches the [`crate::infrastructure::kubectl::find_first_pod_name_async`]
/// discipline established in prior commits and is the lower-
/// machinery path versus introducing a dedicated `DockerError`
/// type for one primitive with no consumer that wants to
/// destructure the spawn-failure variant.
///
/// # Binary resolution
///
/// `docker` is resolved via [`crate::tools::get_tool_path`] — the
/// canonical `DOCKER_BIN`-or-PATH lookup forge uses for every
/// shell-out binary. Tests drive the underlying
/// [`find_first_image_id_by_name_with_bin`] directly with an
/// absolute shim path to avoid global-env mutation under
/// `cargo test`'s parallel runner.
pub fn find_first_image_id_by_name(name: &str) -> Option<String> {
    let bin = get_tool_path("docker");
    find_first_image_id_by_name_with_bin(&bin, name)
}

/// Test-facing sibling of [`find_first_image_id_by_name`] that
/// takes the docker binary path as an explicit parameter, so
/// hermetic shim tests can spawn the primitive against a
/// `make_executable_shim`-produced absolute path without mutating
/// the process-global `PATH` / `DOCKER_BIN` env var (the
/// parallel-runner race trap the centralized
/// `make_executable_shim` discipline pins everywhere else in
/// forge).
pub(crate) fn find_first_image_id_by_name_with_bin(bin: &str, name: &str) -> Option<String> {
    let output = std::process::Command::new(bin)
        .args(first_image_id_args(name))
        .output()
        .ok()?;
    classify_first_image_id(&output)
}

/// Async sibling of [`find_first_image_id_by_name`]. Same contract:
/// returns the trimmed first-line image ID on success, `None` on any
/// failure shape (spawn / non-zero exit / non-UTF8 / empty stdout).
/// Use this from `async fn` call sites; use the sync
/// [`find_first_image_id_by_name`] otherwise.
///
/// # Why both surfaces
///
/// Pre-lift the three sites split across a sync entry point
/// (`commands/e2e.rs::check_image_exists` —
/// `std::process::Command`) and an async one
/// (`commands/product_release.rs::check_local_image_exists` and
/// `push_prebuilt_image` — `tokio::process::Command`). Forcing
/// either to switch surface would require a structural caller
/// refactor (sync → async demands a `block_on` / runtime entry,
/// async → sync defeats the surrounding async pipeline). The two
/// primitives share `first_image_id_args` and
/// `classify_first_image_id` so a regression on either shape is
/// still a one-site fix.
pub async fn find_first_image_id_by_name_async(name: &str) -> Option<String> {
    let bin = get_tool_path("docker");
    find_first_image_id_by_name_async_with_bin(&bin, name).await
}

/// Test-facing sibling of [`find_first_image_id_by_name_async`]
/// that takes the docker binary path as an explicit parameter.
/// See [`find_first_image_id_by_name_with_bin`] for the discipline
/// rationale.
pub(crate) async fn find_first_image_id_by_name_async_with_bin(
    bin: &str,
    name: &str,
) -> Option<String> {
    let output = tokio::process::Command::new(bin)
        .args(first_image_id_args(name))
        .output()
        .await
        .ok()?;
    classify_first_image_id(&output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::make_executable_shim;

    // ---------------------------------------------------------------
    // sync primitive — find_first_image_id_by_name
    // ---------------------------------------------------------------

    /// On a successful docker invocation, `find_first_image_id_by_name_with_bin`
    /// returns the trimmed first-line image ID. Pins the canonical
    /// happy path the three pre-lift sites all asserted by
    /// construction (no explicit test existed at any of them; the
    /// shape was a hand-rolled `from_utf8_lossy(...).trim()` chain
    /// three times over).
    #[cfg(unix)]
    #[test]
    fn test_find_first_image_id_by_name_with_bin_success_returns_trimmed_id() {
        let (_dir, shim) =
            make_executable_shim("docker", "#!/bin/sh\nprintf '%s' 'sha256:abc123'\n");
        let got = find_first_image_id_by_name_with_bin(&shim, "my-backend");
        assert_eq!(got, Some("sha256:abc123".to_string()));
    }

    /// `find_first_image_id_by_name_with_bin` strips trailing
    /// whitespace from the first line. `docker images -q` typically
    /// emits one ID followed by a newline; without the trim arm a
    /// downstream caller would see `"abc123\n"` and the equality
    /// checks at the call site (e.g. `image_id ==
    /// expected_sha_prefix`) would silently mismatch.
    #[cfg(unix)]
    #[test]
    fn test_find_first_image_id_by_name_with_bin_strips_trailing_whitespace() {
        let (_dir, shim) = make_executable_shim("docker", "#!/bin/sh\necho '  abc123  '\n");
        let got = find_first_image_id_by_name_with_bin(&shim, "my-backend");
        assert_eq!(got, Some("abc123".to_string()));
    }

    /// `find_first_image_id_by_name_with_bin` takes the FIRST line
    /// when multiple image IDs match. Pre-lift the
    /// `push_prebuilt_image` site spelled `image_id.lines().next()
    /// .unwrap_or(&image_id)` after trimming the whole stdout, with
    /// the explicit comment "Use the first image ID if multiple
    /// exist." Centralizing the first-line discipline at the
    /// classifier collapses the read-shape onto one site.
    #[cfg(unix)]
    #[test]
    fn test_find_first_image_id_by_name_with_bin_multiline_returns_first() {
        let (_dir, shim) = make_executable_shim(
            "docker",
            "#!/bin/sh\nprintf '%s\\n%s\\n' 'first-id' 'second-id'\n",
        );
        let got = find_first_image_id_by_name_with_bin(&shim, "my-backend");
        assert_eq!(got, Some("first-id".to_string()));
    }

    /// `find_first_image_id_by_name_with_bin` returns `None` on a
    /// non-zero docker exit — daemon connection refused / docker
    /// not running. Pre-lift the three sites collapsed this case
    /// into the !is_empty() arm (which would also return false /
    /// None because non-zero exits typically print to stderr, not
    /// stdout); pinning it explicitly at the typed surface keeps
    /// "docker is broken" from sneaking through as a true-y
    /// "image exists" answer if a future docker version starts
    /// emitting fragments to stdout on error.
    #[cfg(unix)]
    #[test]
    fn test_find_first_image_id_by_name_with_bin_op_failure_returns_none() {
        let (_dir, shim) = make_executable_shim(
            "docker",
            "#!/bin/sh\necho 'Cannot connect to the Docker daemon' 1>&2\nexit 1\n",
        );
        let got = find_first_image_id_by_name_with_bin(&shim, "my-backend");
        assert!(got.is_none(), "non-zero docker exit must collapse to None");
    }

    /// `find_first_image_id_by_name_with_bin` returns `None` when
    /// docker succeeds but stdout is empty — the canonical "no
    /// image matched the name reference" shape. `docker images -q
    /// missing-name` exits 0 with empty stdout; the canonical
    /// "does it exist?" caller (`check_image_exists` /
    /// `check_local_image_exists`) inverts this to `false`, and the
    /// "give me the ID" caller (`push_prebuilt_image`) bails with
    /// a caller-specific message.
    #[cfg(unix)]
    #[test]
    fn test_find_first_image_id_by_name_with_bin_empty_stdout_returns_none() {
        let (_dir, shim) = make_executable_shim("docker", "#!/bin/sh\nexit 0\n");
        let got = find_first_image_id_by_name_with_bin(&shim, "nothing-here");
        assert!(
            got.is_none(),
            "empty stdout (no matching image) must collapse to None even on exit 0"
        );
    }

    /// `find_first_image_id_by_name_with_bin` returns `None` when
    /// docker is not spawnable (binary not on PATH / nonexistent
    /// absolute path). Pre-lift each site used `Command::new("docker")
    /// .output().context(...)?` which propagated spawn failure as
    /// `Err`; every immediate caller that consumed the boolean
    /// path then collapsed Err to `false` via `unwrap_or(false)`.
    /// Centralizing the spawn-failure collapse at the primitive
    /// matches every observed caller intent and brings the docker
    /// primitive in line with the [`find_first_pod_name_async`]
    /// discipline.
    ///
    /// [`find_first_pod_name_async`]: crate::infrastructure::kubectl::find_first_pod_name_async
    #[test]
    fn test_find_first_image_id_by_name_with_bin_spawn_failure_returns_none() {
        let missing = "/nonexistent/forge-test-shim-must-not-exist-docker";
        let got = find_first_image_id_by_name_with_bin(missing, "any-name");
        assert!(got.is_none(), "spawn against nonexistent path must be None");
    }

    /// `find_first_image_id_by_name_with_bin` passes the canonical
    /// `["images", "-q", <name>]` argv to docker. Pre-lift each of
    /// the three sites spelled this argv verbatim; pinning it here
    /// makes a future regression that, e.g., dropped the `-q` flag
    /// (silently broadening output to the human-readable
    /// REPOSITORY / TAG / IMAGE ID / CREATED / SIZE table that no
    /// caller knows how to parse) fail this test rather than
    /// degrade into a confusing "expected SHA, got 'REPOSITORY'"
    /// downstream.
    ///
    /// The shim writes its argv to a side-channel file in its
    /// tempdir so the test can inspect it post-spawn, then returns
    /// a canonical image ID so the rest of the primitive's pipeline
    /// completes successfully (otherwise we couldn't distinguish
    /// "args were wrong" from "args were right but the rest of the
    /// chain failed"). `printf '%s\n'` instead of `echo` so a
    /// future name argument that begins with `-n` isn't swallowed
    /// as echo's POSIX "no-trailing-newline" flag — the same
    /// portability trap the kubectl argv tests pin.
    #[cfg(unix)]
    #[test]
    fn test_find_first_image_id_by_name_with_bin_passes_canonical_docker_args() {
        let log_dir = tempfile::tempdir().expect("log tempdir");
        let log_path = log_dir.path().join("argv.log");
        let log_str = log_path.display().to_string();

        let body = format!(
            "#!/bin/sh\n\
             for a in \"$@\"; do printf '%s\\n' \"$a\" >> '{}'; done\n\
             printf '%s' 'sha256:ok'\n",
            log_str
        );
        let (_dir, shim) = make_executable_shim("docker", &body);

        let got = find_first_image_id_by_name_with_bin(&shim, "my-image");
        assert_eq!(got, Some("sha256:ok".to_string()));

        let logged = std::fs::read_to_string(&log_path).expect("read argv log");
        let lines: Vec<&str> = logged.lines().collect();
        assert_eq!(
            lines,
            vec!["images", "-q", "my-image"],
            "docker argv must match the canonical first-image-id shape"
        );
    }

    // ---------------------------------------------------------------
    // async primitive — find_first_image_id_by_name_async
    // ---------------------------------------------------------------

    /// On a successful docker invocation, the async primitive
    /// returns the trimmed first-line image ID — sibling of the
    /// sync `..._success_returns_trimmed_id` test. Pinned
    /// separately because the async surface spawns through
    /// `tokio::process::Command` instead of `std::process::Command`
    /// and a future drift on the async classifier wouldn't be
    /// caught by the sync test alone.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_find_first_image_id_by_name_async_with_bin_success_returns_trimmed_id() {
        let (_dir, shim) =
            make_executable_shim("docker", "#!/bin/sh\nprintf '%s' 'sha256:async-abc'\n");
        let got = find_first_image_id_by_name_async_with_bin(&shim, "my-backend").await;
        assert_eq!(got, Some("sha256:async-abc".to_string()));
    }

    /// The async sibling collapses non-zero docker exit to `None`
    /// — sibling of the sync `..._op_failure_returns_none` test.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_find_first_image_id_by_name_async_with_bin_op_failure_returns_none() {
        let (_dir, shim) = make_executable_shim(
            "docker",
            "#!/bin/sh\necho 'Cannot connect to the Docker daemon' 1>&2\nexit 1\n",
        );
        let got = find_first_image_id_by_name_async_with_bin(&shim, "my-backend").await;
        assert!(got.is_none(), "non-zero docker exit must collapse to None");
    }

    /// The async sibling collapses empty stdout (no matching
    /// image) to `None` even on exit 0 — sibling of the sync
    /// `..._empty_stdout_returns_none` test.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_find_first_image_id_by_name_async_with_bin_empty_stdout_returns_none() {
        let (_dir, shim) = make_executable_shim("docker", "#!/bin/sh\nexit 0\n");
        let got = find_first_image_id_by_name_async_with_bin(&shim, "nothing-here").await;
        assert!(
            got.is_none(),
            "empty stdout (no matching image) must collapse to None even on exit 0"
        );
    }

    /// The async sibling collapses spawn failure to `None` —
    /// sibling of the sync `..._spawn_failure_returns_none` test.
    #[tokio::test]
    async fn test_find_first_image_id_by_name_async_with_bin_spawn_failure_returns_none() {
        let missing = "/nonexistent/forge-test-shim-must-not-exist-docker-async";
        let got = find_first_image_id_by_name_async_with_bin(missing, "any-name").await;
        assert!(got.is_none(), "spawn against nonexistent path must be None");
    }
}
