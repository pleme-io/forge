//! Kubernetes `kubectl` shell-out helpers.
//!
//! Houses the typed primitives forge uses to drive `kubectl` from
//! command-module surfaces — distinct from `cli/src/k8s.rs`, which
//! wraps the typed `kube-rs` API client.
//!
//! Current surface:
//!
//! - [`fetch_secret_value`] — the canonical "fetch a base64-encoded
//!   data field from a Kubernetes Secret" primitive. Four pre-lift
//!   sites carried verbatim copies of this shape
//!   (`commands/build.rs::execute`,
//!   `commands/github_runner_ci.rs` AMD64 + fallback-namespace pair,
//!   `infrastructure/registry.rs::RegistryCredentials::try_kubectl_secret`)
//!   past THEORY §VI.1's three-is-a-law threshold.
//! - [`find_first_pod_name_async`] — the canonical "fetch the name
//!   of the first pod matching a label selector" primitive. Three
//!   pre-lift async sites carried verbatim copies of this shape
//!   (`commands/search_sync.rs::run_novasearch_sync`,
//!   `commands/migrations.rs` job-name pod lookup,
//!   `commands/supergraph_verification.rs::verify_hive_router_*`)
//!   past THEORY §VI.1's three-is-a-law threshold.
//!   `commands/seed.rs::find_primary_pod` carries the same shape
//!   on a sync spawn surface but already routes through the
//!   structural-error-tuple-preserving
//!   `classify_capture_query_anyhow` primitive (see commit 9637380);
//!   harmonizing the two surfaces is a future-commit concern.

use crate::tools::get_tool_path;

/// Fetch a base64-encoded value from a Kubernetes Secret via
/// `kubectl get secret -o jsonpath={.data.<key>}` and decode it to
/// UTF-8.
///
/// Returns `None` on any failure — kubectl not spawnable, secret
/// not found / non-zero exit, malformed base64, or decoded bytes
/// that aren't valid UTF-8. The "best-effort, fall back to None"
/// shape preserves the discipline every pre-lift caller relied on:
/// secret-fetch is a fallback path behind environment-variable
/// resolution, and a benign failure (e.g., kubectl not configured
/// in the developer's shell) must not error out the caller.
///
/// # Example
///
/// ```rust,ignore
/// let token = std::env::var("ATTIC_TOKEN")
///     .ok()
///     .or_else(|| fetch_secret_value("attic-secrets", "infrastructure", "server-token"))
///     .ok_or_else(|| anyhow::anyhow!("ATTIC_TOKEN not found"))?;
/// ```
///
/// # Why the result is `Option<String>`, not `Result<String, E>`
///
/// All four pre-lift call sites swallowed every failure shape into
/// `None`. Preserving that surface keeps semantics identical and
/// keeps the lift hermetic. A future consumer that wants structural
/// failure fidelity (which secret, which namespace, which exit
/// code, which stderr) can add a sibling [`fetch_secret_value_result`]
/// primitive at this module — but no current consumer does, so the
/// scope of this commit stays one primitive, four sites.
///
/// # Binary resolution
///
/// `kubectl` is resolved via [`crate::tools::get_tool_path`] — the
/// canonical `KUBECTL_BIN`-or-PATH lookup forge uses for every
/// shell-out binary. Tests drive the underlying
/// [`fetch_secret_value_with_bin`] directly with an absolute shim
/// path to avoid global-env mutation under cargo test's parallel
/// runner (the same discipline the `make_executable_shim` helper
/// enforces).
pub fn fetch_secret_value(secret_name: &str, namespace: &str, data_key: &str) -> Option<String> {
    let bin = get_tool_path("kubectl");
    fetch_secret_value_with_bin(&bin, secret_name, namespace, data_key)
}

/// Test-facing sibling of [`fetch_secret_value`] that takes the
/// kubectl binary path as an explicit parameter, so hermetic shim
/// tests can spawn the primitive against a `make_executable_shim`-
/// produced absolute path without mutating the process-global
/// `PATH` or `KUBECTL_BIN` env var (which races under cargo test's
/// parallel runner — N test threads racing on `std::env::set_var`
/// produce flakes that look like "binary not found" but are really
/// "another thread overwrote the env between our spawn and the OS
/// lookup").
///
/// The production [`fetch_secret_value`] wrapper resolves `bin` via
/// [`crate::tools::get_tool_path`] and delegates here, so both
/// surfaces share identical post-spawn classification by
/// construction.
pub(crate) fn fetch_secret_value_with_bin(
    bin: &str,
    secret_name: &str,
    namespace: &str,
    data_key: &str,
) -> Option<String> {
    let jsonpath = format!("jsonpath={{.data.{}}}", data_key);
    let output = std::process::Command::new(bin)
        .args([
            "get",
            "secret",
            secret_name,
            "-n",
            namespace,
            "-o",
            &jsonpath,
        ])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    use base64::{engine::general_purpose, Engine as _};
    let raw = String::from_utf8(output.stdout).ok()?;
    let decoded = general_purpose::STANDARD.decode(raw.trim()).ok()?;
    String::from_utf8(decoded).ok()
}

/// Canonical kubectl argv that fetches the first pod's name from a
/// label-selector query: `kubectl get pods -n <ns> -l <selector>
/// -o jsonpath={.items[0].metadata.name}`. Centralized so the
/// async primitive ([`find_first_pod_name_async`]) and its
/// `_with_bin` test sibling both build the same argv from one
/// definition. A regression that, e.g., dropped the `-n <ns>`
/// pair (silently broadening the search to the current-context
/// namespace) is a one-site fix here.
fn first_pod_name_args<'a>(namespace: &'a str, label_selector: &'a str) -> [&'a str; 8] {
    [
        "get",
        "pods",
        "-n",
        namespace,
        "-l",
        label_selector,
        "-o",
        "jsonpath={.items[0].metadata.name}",
    ]
}

/// Classify a `kubectl get pods … -o jsonpath={.items[0].metadata.name}`
/// captured output into `Option<String>`. Returns `None` on non-zero
/// exit, non-UTF8 stdout, or empty trimmed stdout (no pod matched the
/// selector); `Some(<trimmed pod name>)` otherwise.
fn classify_first_pod_name(output: &std::process::Output) -> Option<String> {
    if !output.status.success() {
        return None;
    }
    let name = std::str::from_utf8(&output.stdout).ok()?.trim();
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

/// Find the name of the first pod matching a label selector in the
/// given namespace via `kubectl get pods -n <ns> -l <selector>
/// -o jsonpath={.items[0].metadata.name}`.
///
/// Returns `None` on any failure — kubectl not spawnable, non-zero
/// exit (namespace missing / RBAC denied), non-UTF8 stdout, or
/// empty stdout (no pod matched the selector). The "best-effort,
/// fall back to None" shape matches the [`fetch_secret_value`]
/// discipline: every pre-lift caller bailed-or-degraded on missing
/// pod via a hand-rolled `String::from_utf8_lossy(...).trim()` +
/// `is_empty()` chain, and consolidating onto one Option-typed
/// primitive keeps the per-caller decision (bail, log, skip) at
/// the caller while the discovery shape lives once at the typed
/// surface.
///
/// # Example
///
/// ```rust,ignore
/// let pod = find_first_pod_name_async(&namespace, "app=hive-router")
///     .await
///     .ok_or_else(|| anyhow::anyhow!("no hive-router pod in {namespace}"))?;
/// ```
///
/// # Why async-only
///
/// All three pre-lift sites this primitive consolidates
/// (`commands/search_sync.rs`, `commands/migrations.rs`,
/// `commands/supergraph_verification.rs`) already spawn kubectl
/// on `tokio::process::Command`. A sync sibling would push
/// `block_on` into one of two unhappy positions — either a tokio
/// runtime entered from a sync context (panic on re-entry), or a
/// `spawn_blocking` indirection that defeats tokio's async-I/O
/// surface for a kubectl call that's already correctly async.
/// `commands/seed.rs::find_primary_pod` carries the same shape
/// on a sync spawn surface but already routes through the
/// structural-error-preserving `classify_capture_query_anyhow`
/// primitive (commit 9637380) and is deliberately left out of
/// this lift to preserve that prior structural fidelity.
///
/// # Binary resolution
///
/// `kubectl` is resolved via [`crate::tools::get_tool_path`] —
/// the canonical `KUBECTL_BIN`-or-PATH lookup forge uses for
/// every shell-out binary. Tests drive the underlying
/// [`find_first_pod_name_async_with_bin`] directly with an
/// absolute shim path to avoid global-env mutation under cargo
/// test's parallel runner.
pub async fn find_first_pod_name_async(namespace: &str, label_selector: &str) -> Option<String> {
    let bin = get_tool_path("kubectl");
    find_first_pod_name_async_with_bin(&bin, namespace, label_selector).await
}

/// Test-facing sibling of [`find_first_pod_name_async`] that takes
/// the kubectl binary path as an explicit parameter, so hermetic
/// shim tests can spawn the primitive against a
/// `make_executable_shim`-produced absolute path without mutating
/// the process-global `PATH` / `KUBECTL_BIN` env var (the
/// parallel-runner race trap the centralized
/// `make_executable_shim` discipline pins everywhere else in
/// forge).
pub(crate) async fn find_first_pod_name_async_with_bin(
    bin: &str,
    namespace: &str,
    label_selector: &str,
) -> Option<String> {
    let output = tokio::process::Command::new(bin)
        .args(first_pod_name_args(namespace, label_selector))
        .output()
        .await
        .ok()?;
    classify_first_pod_name(&output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::make_executable_shim;
    use base64::{engine::general_purpose, Engine as _};

    /// On a successful kubectl invocation, `fetch_secret_value_with_bin`
    /// returns the base64-decoded UTF-8 value of the secret's data
    /// field. Pins the canonical happy path the four pre-lift sites
    /// all asserted by construction (no explicit test existed at any
    /// of them; the shape was a hand-rolled `.output().ok().and_then`
    /// chain four times over).
    #[cfg(unix)]
    #[test]
    fn test_fetch_secret_value_with_bin_success_returns_decoded_utf8() {
        let encoded = general_purpose::STANDARD.encode(b"hunter2-token");
        let body = format!("#!/bin/sh\nprintf '%s' '{}'\n", encoded);
        let (_dir, shim) = make_executable_shim("kubectl", &body);

        let got =
            fetch_secret_value_with_bin(&shim, "attic-secrets", "infrastructure", "server-token");
        assert_eq!(got, Some("hunter2-token".to_string()));
    }

    /// `fetch_secret_value_with_bin` returns `None` on a non-zero
    /// kubectl exit — the "secret not found" / "namespace doesn't
    /// exist" / "RBAC denied" precondition. Pre-lift the four sites
    /// all collapsed this case into `None` via the
    /// `if o.status.success() { ... } else { None }` arm; pinning it
    /// here makes a future regression that re-fused success-vs-failure
    /// surface immediately as a test failure rather than a "downstream
    /// caller silently got a corrupt token" runtime bug.
    #[cfg(unix)]
    #[test]
    fn test_fetch_secret_value_with_bin_op_failure_returns_none() {
        let (_dir, shim) = make_executable_shim(
            "kubectl",
            "#!/bin/sh\necho 'Error from server (NotFound)' 1>&2\nexit 1\n",
        );
        let got =
            fetch_secret_value_with_bin(&shim, "missing-secret", "ghost-namespace", "any-key");
        assert!(got.is_none(), "non-zero exit must collapse to None");
    }

    /// `fetch_secret_value_with_bin` returns `None` when kubectl is
    /// not spawnable (binary not on PATH / nonexistent absolute path).
    /// Pre-lift the four sites used `.output().ok()` to swallow the
    /// spawn-failure `io::Error` into `None`; pinning the shape here
    /// keeps "developer has no kubectl on PATH" from erroring out a
    /// caller whose primary source is the env var.
    #[test]
    fn test_fetch_secret_value_with_bin_spawn_failure_returns_none() {
        let missing = "/nonexistent/forge-test-shim-must-not-exist-kubectl";
        let got = fetch_secret_value_with_bin(missing, "name", "ns", "key");
        assert!(got.is_none(), "spawn against nonexistent path must be None");
    }

    /// `fetch_secret_value_with_bin` returns `None` when the
    /// captured stdout is not valid base64 (e.g., a kubectl version
    /// that emitted plain text on a misconfigured jsonpath, or a
    /// caller's typo in the data key surfacing as a literal `<no
    /// value>` echo). The decode-then-classify arm is what protects
    /// downstream callers from treating "kubectl printed something"
    /// as "secret value present."
    #[cfg(unix)]
    #[test]
    fn test_fetch_secret_value_with_bin_invalid_base64_returns_none() {
        let (_dir, shim) =
            make_executable_shim("kubectl", "#!/bin/sh\necho '!!! not base64 !!!'\n");
        let got = fetch_secret_value_with_bin(&shim, "name", "ns", "key");
        assert!(got.is_none(), "invalid base64 must collapse to None");
    }

    /// `fetch_secret_value_with_bin` returns `None` when the
    /// base64-decoded bytes are not valid UTF-8 (the secret happens
    /// to be a binary blob — TLS cert, signing key, kubeconfig
    /// fragment). The pre-lift `String::from_utf8(b).ok()` arm
    /// at all four sites established this discriminator; pinning it
    /// here keeps a future drift onto `String::from_utf8_lossy` from
    /// silently corrupting a binary secret into mojibake.
    #[cfg(unix)]
    #[test]
    fn test_fetch_secret_value_with_bin_decoded_non_utf8_returns_none() {
        // 0xff 0xfe 0xfd is not a valid UTF-8 sequence.
        let encoded = general_purpose::STANDARD.encode([0xffu8, 0xfe, 0xfd]);
        let body = format!("#!/bin/sh\nprintf '%s' '{}'\n", encoded);
        let (_dir, shim) = make_executable_shim("kubectl", &body);

        let got = fetch_secret_value_with_bin(&shim, "name", "ns", "key");
        assert!(
            got.is_none(),
            "non-UTF8 decoded bytes must collapse to None"
        );
    }

    /// `fetch_secret_value_with_bin` strips trailing whitespace
    /// (newlines from `echo`, jsonpath formatter quirks) before
    /// base64-decoding. The pre-lift `s.trim()` call at all four
    /// sites was load-bearing: kubectl's jsonpath output is fed
    /// through `printf '%s'` semantics in production but real
    /// shells often inject a trailing newline depending on the
    /// terminal/locale — without the trim, base64-decode rejects the
    /// otherwise-valid encoded blob.
    #[cfg(unix)]
    #[test]
    fn test_fetch_secret_value_with_bin_strips_trailing_whitespace_before_decode() {
        let encoded = general_purpose::STANDARD.encode(b"value-with-trailing-nl");
        // echo appends a trailing newline; the trim arm must absorb it.
        let body = format!("#!/bin/sh\necho '{}'\n", encoded);
        let (_dir, shim) = make_executable_shim("kubectl", &body);

        let got = fetch_secret_value_with_bin(&shim, "name", "ns", "key");
        assert_eq!(got, Some("value-with-trailing-nl".to_string()));
    }

    /// `fetch_secret_value_with_bin` passes the canonical
    /// `["get", "secret", <name>, "-n", <ns>, "-o",
    /// "jsonpath={.data.<key>}"]` argv to kubectl. Pre-lift the four
    /// sites each spelled this argv verbatim; pinning it here makes
    /// a future regression that, e.g., dropped the `-n <ns>` pair
    /// (silently broadening the search to the current-context
    /// namespace) fail this test rather than degrade into a
    /// confusing "wrong secret returned" bug downstream.
    ///
    /// The shim writes its argv to a side-channel file in its
    /// tempdir so the test can inspect it post-spawn, then returns
    /// a valid base64 blob so the rest of the primitive's pipeline
    /// completes successfully (otherwise we couldn't distinguish
    /// "args were wrong" from "args were right but the rest of the
    /// chain failed").
    #[cfg(unix)]
    #[test]
    fn test_fetch_secret_value_with_bin_passes_canonical_kubectl_args() {
        let encoded = general_purpose::STANDARD.encode(b"ok");
        let log_dir = tempfile::tempdir().expect("log tempdir");
        let log_path = log_dir.path().join("argv.log");
        let log_str = log_path.display().to_string();

        // The shim writes each positional arg on its own line to argv.log,
        // then prints the canonical base64 blob to stdout and exits 0.
        // `printf '%s\n'` instead of `echo` so a `-n` argument isn't
        // swallowed as echo's "no trailing newline" flag (POSIX sh
        // portability trap: `echo -n` writes nothing on most shells).
        let body = format!(
            "#!/bin/sh\n\
             for a in \"$@\"; do printf '%s\\n' \"$a\" >> '{}'; done\n\
             printf '%s' '{}'\n",
            log_str, encoded
        );
        let (_dir, shim) = make_executable_shim("kubectl", &body);

        let got = fetch_secret_value_with_bin(&shim, "my-secret", "my-ns", "MY_KEY");
        assert_eq!(got, Some("ok".to_string()));

        let logged = std::fs::read_to_string(&log_path).expect("read argv log");
        let lines: Vec<&str> = logged.lines().collect();
        assert_eq!(
            lines,
            vec![
                "get",
                "secret",
                "my-secret",
                "-n",
                "my-ns",
                "-o",
                "jsonpath={.data.MY_KEY}",
            ],
            "kubectl argv must match the canonical secret-fetch shape"
        );
    }

    // ---------------------------------------------------------------
    // find_first_pod_name_async — the canonical pod-name discovery
    // primitive. The hermetic-shim tests pin the contract every
    // pre-lift site relied on: success → trimmed pod name, non-zero
    // exit → None, empty stdout (no matching pod) → None, spawn-
    // failure → None, and the canonical argv shape.
    // ---------------------------------------------------------------

    /// On a successful kubectl invocation,
    /// `find_first_pod_name_async_with_bin` returns the trimmed
    /// UTF-8 pod name from stdout. Pins the happy path the three
    /// pre-lift sites hand-rolled via
    /// `String::from_utf8_lossy(...).trim().to_string()`.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_find_first_pod_name_async_with_bin_success_returns_trimmed_name() {
        let (_dir, shim) = make_executable_shim(
            "kubectl",
            "#!/bin/sh\nprintf '%s' 'hive-router-7f9c8b6d-x2k4l'\n",
        );
        let got = find_first_pod_name_async_with_bin(&shim, "platform", "app=hive-router").await;
        assert_eq!(got, Some("hive-router-7f9c8b6d-x2k4l".to_string()));
    }

    /// `find_first_pod_name_async_with_bin` strips surrounding
    /// whitespace before returning. kubectl jsonpath output often
    /// carries a trailing newline depending on shell/locale; pre-
    /// lift each of the three sites had a `.trim()` call, and
    /// centralizing it at the primitive keeps the discipline at one
    /// site.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_find_first_pod_name_async_with_bin_strips_trailing_whitespace() {
        let (_dir, shim) = make_executable_shim("kubectl", "#!/bin/sh\necho '  novasearch-0  '\n");
        let got = find_first_pod_name_async_with_bin(&shim, "search", "app=novasearch").await;
        assert_eq!(got, Some("novasearch-0".to_string()));
    }

    /// `find_first_pod_name_async_with_bin` returns `None` on a
    /// non-zero kubectl exit — namespace missing / RBAC denied.
    /// Pre-lift each site checked `output.status.success()` and
    /// either bailed (search_sync, supergraph_verification) or fell
    /// through to a degraded path (migrations). Collapsing all
    /// op-failure shapes to `None` at the typed primitive keeps the
    /// caller's per-site recovery decision explicit at the call
    /// site.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_find_first_pod_name_async_with_bin_op_failure_returns_none() {
        let (_dir, shim) = make_executable_shim(
            "kubectl",
            "#!/bin/sh\necho 'Error from server (Forbidden)' 1>&2\nexit 1\n",
        );
        let got = find_first_pod_name_async_with_bin(&shim, "ghost-ns", "app=missing").await;
        assert!(got.is_none(), "non-zero kubectl exit must collapse to None");
    }

    /// `find_first_pod_name_async_with_bin` returns `None` when
    /// kubectl succeeds but stdout is empty — the canonical "no pod
    /// matched the label selector" shape. kubectl's
    /// `jsonpath={.items[0]...}` emits empty stdout (exit 0) when
    /// `.items` is empty, so the `success()` check alone is
    /// insufficient. Pinning empty-stdout → `None` here closes a
    /// gap that pre-lift sites handled inconsistently:
    /// search_sync.rs's `pod_name.is_empty()` arm bailed;
    /// supergraph_verification.rs had no empty check at all (so a
    /// missing pod silently fell through into a downstream
    /// `kubectl exec` against an empty pod name, surfacing as a
    /// confusing "resource name may not be empty" diagnostic).
    #[cfg(unix)]
    #[tokio::test]
    async fn test_find_first_pod_name_async_with_bin_empty_stdout_returns_none() {
        let (_dir, shim) = make_executable_shim("kubectl", "#!/bin/sh\nexit 0\n");
        let got = find_first_pod_name_async_with_bin(&shim, "platform", "app=nothing-here").await;
        assert!(
            got.is_none(),
            "empty stdout (no matching pod) must collapse to None even on exit 0"
        );
    }

    /// `find_first_pod_name_async_with_bin` returns `None` when
    /// kubectl is not spawnable — binary not on PATH / nonexistent
    /// absolute path. Mirrors the spawn-failure discipline of
    /// [`fetch_secret_value`].
    #[tokio::test]
    async fn test_find_first_pod_name_async_with_bin_spawn_failure_returns_none() {
        let missing = "/nonexistent/forge-test-shim-must-not-exist-kubectl-pod";
        let got = find_first_pod_name_async_with_bin(missing, "ns", "app=x").await;
        assert!(got.is_none(), "spawn against nonexistent path must be None");
    }

    /// `find_first_pod_name_async_with_bin` passes the canonical
    /// `["get", "pods", "-n", <ns>, "-l", <selector>, "-o",
    /// "jsonpath={.items[0].metadata.name}"]` argv to kubectl.
    /// Pre-lift each site spelled this argv verbatim; pinning it
    /// here makes a future regression that, e.g., dropped the
    /// `-n <ns>` pair (silently broadening the search to the
    /// current-context namespace) or that singularized `pods` →
    /// `pod` inconsistently (kubectl accepts both but the canonical
    /// idiom across forge uses `pods` at every pre-lift site of
    /// this shape) fail this test rather than silently change
    /// cluster-query semantics.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_find_first_pod_name_async_with_bin_passes_canonical_kubectl_args() {
        let log_dir = tempfile::tempdir().expect("log tempdir");
        let log_path = log_dir.path().join("argv.log");
        let log_str = log_path.display().to_string();

        // The shim writes each positional arg on its own line to argv.log,
        // then prints the canonical pod name. `printf '%s\n'` instead of
        // `echo` so a `-n` argument isn't swallowed as echo's
        // "no trailing newline" flag (POSIX sh portability trap).
        let body = format!(
            "#!/bin/sh\n\
             for a in \"$@\"; do printf '%s\\n' \"$a\" >> '{}'; done\n\
             printf '%s' 'job-runner-abc'\n",
            log_str
        );
        let (_dir, shim) = make_executable_shim("kubectl", &body);

        let got = find_first_pod_name_async_with_bin(&shim, "my-ns", "job-name=my-job").await;
        assert_eq!(got, Some("job-runner-abc".to_string()));

        let logged = std::fs::read_to_string(&log_path).expect("read argv log");
        let lines: Vec<&str> = logged.lines().collect();
        assert_eq!(
            lines,
            vec![
                "get",
                "pods",
                "-n",
                "my-ns",
                "-l",
                "job-name=my-job",
                "-o",
                "jsonpath={.items[0].metadata.name}",
            ],
            "kubectl argv must match the canonical first-pod-name shape"
        );
    }
}
