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

use crate::tools::{get_tool_path, tools};

/// Async `kubectl` spawn constructor honoring `KUBECTL_BIN`. Resolves
/// the `kubectl` binary through [`crate::tools::get_tool_path`] on the
/// canonical `tools::KUBECTL` name once and returns a
/// [`tokio::process::Command`] ready for `.args(...)` +
/// `.status()` / `.output()`.
///
/// Companion to [`find_first_pod_name_async`] on the same
/// `infrastructure::kubectl` surface: `find_first_pod_name_async` is a
/// domain-shaped primitive (canonical argv + Option-typed classifier)
/// for the discovery shape three sites share; `kubectl_command_async`
/// is the free-form constructor for one-off argvs whose shape has no
/// three-times-rule reuse yet. Names the "spawn `kubectl` via
/// `KUBECTL_BIN`" discipline once at the constructor so every consumer
/// honors the env override the tools-registry idiom
/// (`crate::tools::get_tool_path("kubectl")`, cli/src/tools.rs:102-105)
/// resolves.
///
/// Landed consumers (per commit at which each site migrated):
/// - `commands/product_release.rs::run_health_check` — two sites
///   (rollout-status + pod-phase probe), migrated at 5bb7cff.
/// - `commands/github_runner_ci.rs::execute` — three sites (rollout
///   pod-status probe, per-pod crash-log fetch, deployed-image
///   verification), migrated at 5566415.
/// - `services/migration_service.rs::MigrationService` — five
///   sites (delete-existing-job, apply-job manifest via stdin,
///   wait-for-job Complete probe, wait-for-job Failed probe,
///   get-job-logs), migrated at 5986a10. First non-`commands/*`
///   consumer of the primitive; the shield sits in
///   `impl MigrationService`'s sibling `#[cfg(test)]` block and
///   bounds the include_str! scan to the primary impl block by
///   the `\n}\n\nimpl Default for MigrationService` marker.
/// - `commands/supergraph_verification.rs` — three sites
///   (`verify_router_schema`'s router-pod `exec` health probe,
///   `annotate_configmap_with_hash`'s ConfigMap `annotate
///   --overwrite`, `verify_configmap_hash`'s ConfigMap `get -o
///   jsonpath=...` annotation read-back), migrated at 65283fb.
///   First multi-function consumer whose shield bounds the
///   include_str! scan to the top-level module body (file start to
///   the `\n#[cfg(test)]\nmod tests {` marker) rather than a
///   single function or a single impl block — so every current or
///   future kubectl-spawning helper landing anywhere in the module
///   body (across the three migrated entry points or any as-yet
///   unadded sibling) is covered by the same shield without a
///   per-function narrowing.
/// - `commands/status.rs` — ten sites across the ten async
///   fetch helpers (`fetch_deployment`, `fetch_pods`,
///   `fetch_statefulset`, `fetch_redis`, `fetch_redis_statefulset`,
///   `fetch_configmap`, `fetch_secrets`, `fetch_k8s_services`,
///   `fetch_migrations`, `fetch_events`), migrated at c2760df.
///   Largest single-module consumer through that commit — ten
///   free-function `.output().await` sites all sharing the same
///   argv shape past the primitive's constructor call — covered
///   by a single whole-module include_str! shield that follows
///   the `commands/supergraph_verification.rs` (65283fb)
///   discipline.
/// - `commands/flux.rs` — eight sites across the two async
///   diagnostic helpers (`get_pod_status_full`'s pod-image /
///   phase / readiness / waiting-reason probe, and
///   `gather_deployment_diagnostics`'s seven deployment /
///   pod / container / event probes: replicas jsonpath,
///   conditions jsonpath, `-o wide` pod listing, container-state
///   jsonpath, waiting/terminated-reason jsonpath, deployment-
///   scoped events, namespace-wide pod events), migrated at
///   f8da719. First lift onto a module that had no prior
///   `#[cfg(test)]` block; the shield adds the block itself
///   and bounds the include_str! scan by the same
///   `\n#[cfg(test)]\nmod tests {` marker discipline the
///   status.rs (c2760df) and supergraph_verification.rs
///   (65283fb) shields hold.
/// - `commands/rollout.rs::execute` — one site, the
///   `kubectl rollout undo deployment/<name> -n <ns>` step on
///   the `--rollback` branch of `forge rollout`, migrated at
///   this commit. Single-spawn module; the shield is a
///   whole-module include_str! scan (no marker narrowing
///   needed — the module has no sibling kubectl-spawning
///   helpers to bound around).
///
/// Pre-lift each of these sites spelled the bare literal
/// `Command::new("kubectl")` — the exact class of bug the `flux` /
/// `cargo` / `doca` / `git` free-function migrations redeemed at
/// 621f827 / f0dfa12 / d3dd199 / 685642f / d6f6bc7 / dd5a212 /
/// 673e4be / b02d4eb / 54a9985 / 139b37a / 818ed9a / badcdf4 /
/// 8653403 / 81d7486 / f6be190 / 8a1958e / 0d922f6 / 0a36ba0 /
/// 447cad1 / 82376e1 / 34661e3. A Nix-hermetic runner whose
/// `KUBECTL_BIN` points at a specific store-path `kubectl`
/// (substrate's `mkRuntimeToolsEnv`) would lose to whatever
/// `kubectl` is first on `PATH` at every pre-lift site. Remaining
/// pending consumers on the `KUBECTL_BIN`-routing frontier: the
/// various `commands/*.rs` sites the grep in the shield tests'
/// docstrings enumerates (`migrations.rs`,
/// `federation_tests.rs`, `integration_tests.rs`, `rollout.rs`,
/// `search_sync.rs`, `rust_service.rs`, `attestation.rs`,
/// `seed.rs`) plus the raw `Command::new("kubectl")` sites still
/// living in pin-only production paths (`pod_health.rs`,
/// `pod_listing.rs`, `network_policy_admission.rs`,
/// `flux_source_verification.rs`, `helm_release_signature.rs`).
/// The `rollout.rs::execute` entry above closes the last raw
/// `Command::new("kubectl")` on the `commands/rollout.rs`
/// surface.
pub fn kubectl_command_async() -> tokio::process::Command {
    tokio::process::Command::new(get_tool_path(tools::KUBECTL))
}

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
    let bin = get_tool_path(tools::KUBECTL);
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
    let bin = get_tool_path(tools::KUBECTL);
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

/// Best-effort captured-stdout `kubectl` probe: spawn `kubectl` via
/// [`kubectl_command_async`] with `args`, and return the UTF-8-lossy
/// stdout on `Ok(output)` — regardless of `output.status` — or `None`
/// on spawn `Err`. Deliberately swallows every failure (spawn
/// `io::Error`, non-zero exit, signal termination) because this
/// primitive exists for the diagnostic-print surface where the caller's
/// intent is "print whatever the probe produced, and stay silent if
/// the probe cannot be run."
///
/// Async twin of [`crate::retry::probe_stdout_capture_sync`] at the
/// `kubectl_command_async()` frontier: the sync twin is `(bin, args)`-
/// fronted so it lives on `retry.rs` alongside its
/// `run_bin_args_inherited_status_sync` / `run_inherited_status_sync`
/// siblings; this primitive is `(args)`-fronted because its `bin` is
/// pinned to whatever `kubectl_command_async()` resolves (the
/// canonical [`crate::tools::get_tool_path`]`(`[`crate::tools::tools::KUBECTL`]`)`
/// lookup honoring `KUBECTL_BIN`) — so it belongs on the
/// `infrastructure::kubectl` surface with its `kubectl_command_async`
/// / `fetch_secret_value` / `find_first_pod_name_async` siblings and
/// not on the free-form `retry.rs` spawn frontier.
///
/// Lifts the seven-occurrence async four-line stanza
///
/// ```text
/// if let Ok(output) = kubectl_command_async().args([...]).output().await {
///     let stdout = String::from_utf8_lossy(&output.stdout);
///     // ... use stdout ...
/// }
/// ```
///
/// that seven pod / event / condition diagnostic sites in
/// [`crate::commands::flux::gather_deployment_diagnostics`] carry
/// verbatim modulo the per-site argv and the trailing `use stdout`
/// block (replicas jsonpath, conditions jsonpath, `-o wide` pod
/// listing, container-state jsonpath, waiting/terminated-reason
/// jsonpath, deployment-scoped events, namespace-wide pod events).
/// Seven identically-shaped bodies past THEORY §VI.1's three-is-a-law
/// threshold (PRIME DIRECTIVE: duplication budget is zero); this
/// primitive is the law-redeeming consolidation for the async
/// best-effort-captured-stdout surface on the `kubectl_command_async()`
/// frontier — the missing counterpart to
/// [`crate::retry::run_capture_anyhow`] (async, raises the failing
/// envelope, used by [`crate::commands::flux::get_pod_status_full`]'s
/// control-flow-carrying pod-JSON capture in the same module).
///
/// # Semantics — deliberately infallible at the caller
///
/// - Spawn `Err` (`fork+exec` failed, e.g., `KUBECTL_BIN` points at
///   a store path that no longer exists on a Nix-hermetic runner
///   whose sigil has drifted): swallow, return `None`. Every pre-lift
///   site already discarded this branch by the `if let Ok(...)`
///   binding.
/// - Spawn `Ok(output)`: return `Some(String::from_utf8_lossy(
///   &output.stdout).into_owned())`, IGNORING `output.status`.
///   Diagnostic probes must not fail the caller, so a non-zero exit
///   is treated as "no data" from the probe's perspective — matches
///   pre-lift behavior at all seven sites (none consulted
///   `output.status.success()`). A caller that wants "empty means
///   no rows" can still `.map(|s| s.trim().is_empty())` on the
///   returned `Option<String>` — six of the seven pre-lift sites do
///   exactly this to skip the diagnostic header when the probe
///   returned no data.
///
/// # When to reach for this vs [`crate::retry::run_capture_anyhow`]
///
/// This primitive is DELIBERATELY narrower than its control-flow-
/// carrying sibling: it is the right choice ONLY for diagnostic
/// surfaces where the alternative is silently dropping the failure
/// envelope. Do NOT use it for control-flow-carrying captures — a
/// caller that decides what to do next based on the probe's output
/// MUST surface both the spawn envelope AND the exit-status envelope
/// through [`crate::retry::run_capture_anyhow`] (anyhow, exposes
/// stdout+stderr on success as an intact [`std::process::Output`]).
/// The pattern in [`crate::commands::flux`] is exactly this carve-out
/// today: [`crate::commands::flux::get_pod_status_full`]'s pod-JSON
/// capture is control-flow-carrying (drives the deploy-health state
/// machine) and rides on `run_capture_anyhow`, while
/// [`crate::commands::flux::gather_deployment_diagnostics`]'s seven
/// probes are best-effort-diagnostic (each `if let Ok(...) { print
/// section }`) and ride on this primitive.
pub async fn kubectl_probe_stdout_capture(args: &[&str]) -> Option<String> {
    let output = kubectl_command_async().args(args).output().await.ok()?;
    Some(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Control-flow-carrying async captured-output `kubectl` spawn:
/// compose [`kubectl_command_async`] with `args`, drive the
/// spawn-plus-classify ritual at the canonical
/// [`crate::retry::run_capture_anyhow`] primitive, and surface the raw
/// [`std::process::Output`] on the success arm — bytes-verbatim so a
/// caller consuming `output.stdout` as JSON (`serde_json::from_slice`),
/// base64 (`base64::decode`), or lossy UTF-8 (`String::from_utf8_lossy`)
/// picks the parse discipline itself.
///
/// # Fusion of two existing primitives
///
/// This primitive folds the three-line stanza
///
/// ```text
/// let mut cmd = kubectl_command_async();
/// cmd.args([...]);
/// let output = crate::retry::run_capture_anyhow(cmd, "<op>").await?;
/// ```
///
/// into one delegation. The `(args)`-front surface is `(args, op)`, and
/// composes with `.with_context(|| ...)?` on the outer chain — same
/// shape [`crate::commands::integration_tests::fetch_secret`] uses to
/// attach the secret-name/key hint to the anyhow trace after the
/// canonical primitive's `"(exit {code}): {stderr}"` envelope has
/// already surfaced.
///
/// Lifts the two-occurrence three-line stanza that two control-flow-
/// carrying `kubectl_command_async()` + `run_capture_anyhow`
/// composition sites carry verbatim modulo the per-site argv, op label,
/// and the trailing consumer block:
/// [`crate::commands::flux::get_pod_status_full`] (pod-JSON pull that
/// drives the deploy-health state machine — the load-bearing capture
/// [`kubectl_probe_stdout_capture`]'s docstring names as the
/// carve-out this primitive redeems) and
/// [`crate::commands::integration_tests::fetch_secret`] (secret-data
/// base64 pull that resolves an environment variable before the
/// integration-test suite runs). Two occurrences already past
/// THEORY §VI.1's three-times threshold in intent — a duplicate would
/// drift the `(op, exit_code, stderr)` envelope discipline silently
/// between the two production consumers; this lift is the
/// law-anticipating consolidation on the `kubectl_command_async()`
/// frontier.
///
/// # When to reach for this vs [`kubectl_probe_stdout_capture`]
///
/// This primitive is the CONTROL-FLOW-CARRYING sibling of
/// [`kubectl_probe_stdout_capture`]. Reach for this when the caller
/// decides what to do next based on the output (JSON body drives a
/// state machine, base64 blob decodes to a required credential) — a
/// spawn `Err` or non-zero exit MUST bail with the canonical
/// `(op, exit_code, stderr)` envelope. Reach for the probe primitive
/// instead when the caller renders the stdout into a best-effort
/// diagnostic surface where a failure has no bearing on control flow.
///
/// # Envelope shape by construction
///
/// The success arm returns `Ok(Output)` byte-verbatim; the failure
/// arms both bail through [`crate::retry::classify_capture_anyhow`]:
///
/// - spawn `Err` (e.g., `KUBECTL_BIN` resolves to an absent path on a
///   Nix-hermetic runner) → `"Failed to spawn {op}: {io_error}"`;
/// - non-zero exit → `"{op} failed (exit {code}): {stderr}"` (or
///   `"killed by signal"` on signal termination).
pub async fn kubectl_capture_anyhow(
    args: &[&str],
    op: &str,
) -> anyhow::Result<std::process::Output> {
    let mut cmd = kubectl_command_async();
    cmd.args(args);
    crate::retry::run_capture_anyhow(cmd, op).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{make_executable_shim, printf_only_shim, ArgvLog};
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
        let (_dir, shim) = printf_only_shim("kubectl", &encoded);

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
        let (_dir, shim) = printf_only_shim("kubectl", &encoded);

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
        let argv_log = ArgvLog::reserve();
        let (_dir, shim) = make_executable_shim("kubectl", &argv_log.shim_body(&encoded));

        let got = fetch_secret_value_with_bin(&shim, "my-secret", "my-ns", "MY_KEY");
        assert_eq!(got, Some("ok".to_string()));

        let logged = argv_log.read_argv_log();
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
        let (_dir, shim) = printf_only_shim("kubectl", "hive-router-7f9c8b6d-x2k4l");
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
        let argv_log = ArgvLog::reserve();
        let (_dir, shim) = make_executable_shim("kubectl", &argv_log.shim_body("job-runner-abc"));

        let got = find_first_pod_name_async_with_bin(&shim, "my-ns", "job-name=my-job").await;
        assert_eq!(got, Some("job-runner-abc".to_string()));

        let logged = argv_log.read_argv_log();
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

    // ---------------------------------------------------------------
    // kubectl_command_async — the free-form kubectl spawn constructor.
    // The pin below asserts the returned Command's program is the
    // KUBECTL_BIN-resolved path, never the literal "kubectl".
    // ---------------------------------------------------------------

    /// RAII scope-guard that sets `KUBECTL_BIN=value` on construction
    /// and restores the pre-scope state (either the original value or
    /// unset) on drop — panic-safe by construction. Mirrors the
    /// discipline of [`crate::test_support::GitBinScope`] without
    /// pulling that scope into `test_support.rs` while there is only
    /// one kubectl-env-touching test in the fleet; a second test
    /// would trigger the lift to `test_support.rs`, same rule as
    /// [`crate::test_support::make_executable_shim`] applied at the
    /// three-times threshold.
    struct KubectlBinScope {
        prior: std::result::Result<String, std::env::VarError>,
    }

    impl KubectlBinScope {
        fn set(value: &str) -> Self {
            let prior = std::env::var("KUBECTL_BIN");
            std::env::set_var("KUBECTL_BIN", value);
            Self { prior }
        }
    }

    impl Drop for KubectlBinScope {
        fn drop(&mut self) {
            match &self.prior {
                Ok(v) => std::env::set_var("KUBECTL_BIN", v),
                Err(_) => std::env::remove_var("KUBECTL_BIN"),
            }
        }
    }

    /// Serial-safe guard for tests that mutate `KUBECTL_BIN` or read
    /// a production entry point that resolves `kubectl` through
    /// `tools::get_tool_path(tools::KUBECTL)`. Same rationale as
    /// [`crate::test_support::GIT_BIN_ENV_LOCK`]: env-var writes are
    /// process-global; without a serial guard a concurrent
    /// production-path test could pick up the wrong shim from a
    /// mid-flight env-var mutation. `unwrap_or_else(|p|
    /// p.into_inner())` keeps a panicking prior test from chain-
    /// failing every subsequent test that shares the lock.
    static KUBECTL_BIN_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// [`kubectl_command_async`] MUST resolve the `kubectl` binary
    /// through [`crate::tools::get_tool_path`] on the canonical
    /// `tools::KUBECTL` name — i.e. it honors the `KUBECTL_BIN` env
    /// override the tools-registry idiom names as the hermetic-runner
    /// contract, and never hardcodes the literal `"kubectl"` on the
    /// spawn path.
    ///
    /// Two-arm pin, mirroring the sibling
    /// [`crate::git::tests::test_git_command_async_routes_through_git_bin_env_var`].
    /// The static arm reads the returned Command's program directly
    /// (`Command::as_std().get_program()`) and asserts it equals the
    /// resolved shim path verbatim — proves the constructor resolves
    /// through `get_tool_path(tools::KUBECTL)` without ever spawning.
    /// The end-to-end arm spawns the same Command through the exact
    /// `.output().await` shape every consumer
    /// (`commands/product_release.rs::run_health_check` — the first
    /// consumer this migration lifts) drives and asserts the shim's
    /// exit code rides through verbatim. A regression that "tidies"
    /// `kubectl_command_async` back to `Command::new("kubectl")`
    /// fails the program-name assertion.
    #[tokio::test]
    async fn test_kubectl_command_async_routes_through_kubectl_bin_env_var() {
        let _guard = KUBECTL_BIN_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());

        let (_shim_dir, shim) = make_executable_shim(
            "kubectl",
            "#!/bin/sh\necho 'SIGIL_ROUTED_VIA_KUBECTL_COMMAND_ASYNC_7c4e2a' 1>&2\nexit 91\n",
        );
        let _scope = KubectlBinScope::set(&shim);

        // Static arm: the returned Command's program is the
        // KUBECTL_BIN-resolved path, not the literal "kubectl".
        let cmd = kubectl_command_async();
        assert_eq!(
            cmd.as_std().get_program(),
            std::ffi::OsStr::new(&shim),
            "kubectl_command_async() must resolve through KUBECTL_BIN, not hardcode \"kubectl\""
        );

        // End-to-end arm: spawning through the consumer shape
        // (`.output().await`) surfaces the shim's exit code verbatim.
        let out = kubectl_command_async()
            .args(["rollout", "status", "deployment/x", "-n", "ns"])
            .output()
            .await
            .expect("shim must spawn");
        assert_eq!(
            out.status.code(),
            Some(91),
            "kubectl_command_async().output() must surface the shim's exit \
             code verbatim — proves the async constructor spawns the \
             KUBECTL_BIN shim end-to-end, not a PATH-resolved `kubectl`"
        );
    }

    // ---------------------------------------------------------------
    // kubectl_probe_stdout_capture — the async best-effort captured-
    // stdout diagnostic probe. Contract mirrors the sync twin
    // `retry::probe_stdout_capture_sync` at the
    // `kubectl_command_async()` frontier: on `Ok(output)`, return the
    // UTF-8-lossy stdout regardless of `output.status`; on spawn
    // `Err`, return `None`.
    // ---------------------------------------------------------------

    /// The primitive's canonical happy path: a shim that exits zero
    /// and prints an owned stdout sigil round-trips the stdout to the
    /// caller as UTF-8-lossy [`Option<String>`]. Pins the operator-
    /// visible surface every pre-lift call site relied on for the
    /// `let stdout = String::from_utf8_lossy(&output.stdout);` line
    /// they carried verbatim.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_kubectl_probe_stdout_capture_zero_exit_returns_lossy_stdout() {
        let _guard = KUBECTL_BIN_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let (_dir, shim) = printf_only_shim("kubectl", "ns/deploy/pod-abc Ready");
        let _scope = KubectlBinScope::set(&shim);

        let out = kubectl_probe_stdout_capture(&["get", "pods", "-n", "ns"]).await;
        assert_eq!(out, Some("ns/deploy/pod-abc Ready".to_string()));
    }

    /// The load-bearing carve-out: a non-zero exit STILL surfaces the
    /// stdout the shim produced. Pre-lift the seven diagnostic sites
    /// in `commands/flux.rs::gather_deployment_diagnostics` all
    /// discarded `output.status`, so a `kubectl get pods` that partial-
    /// listed pods and then exited 1 (e.g., one namespace's RBAC
    /// denied a jsonpath field but the deployment-scoped rows landed)
    /// still had its stdout render into the diagnostic surface. A
    /// naive re-implementation that gated on `output.status.success()`
    /// would blank the diagnostic surface at the precise operator-
    /// triage moment the primitive exists to preserve — that's the
    /// anti-pattern the primitive's docstring pins against.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_kubectl_probe_stdout_capture_nonzero_exit_still_returns_stdout() {
        let _guard = KUBECTL_BIN_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let (_dir, shim) = make_executable_shim(
            "kubectl",
            "#!/bin/sh\nprintf '%s' 'partial-listing before error'\nexit 1\n",
        );
        let _scope = KubectlBinScope::set(&shim);

        let out = kubectl_probe_stdout_capture(&["get", "pods", "-n", "ns"]).await;
        assert_eq!(
            out,
            Some("partial-listing before error".to_string()),
            "a non-zero kubectl exit must still surface the stdout \
             the shim produced — a naive gate on `output.status.success()` \
             would blank the diagnostic surface at the operator-triage \
             moment the primitive exists to preserve"
        );
    }

    /// The `(args)`-front surface routes the argv slice verbatim to
    /// the spawned kubectl. Pins the contract seven pre-lift sites
    /// relied on for their heterogeneous 8- and 10-element argv
    /// slices — a regression that dropped, reordered, or truncated
    /// the forwarded argv would break every diagnostic probe by
    /// construction. Shim logs each argument to a temp file, one per
    /// line; the primitive must forward every arg untouched.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_kubectl_probe_stdout_capture_forwards_args() {
        let _guard = KUBECTL_BIN_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let argv_log = ArgvLog::reserve();
        let (_dir, shim) = make_executable_shim("kubectl", &argv_log.shim_body("ok"));
        let _scope = KubectlBinScope::set(&shim);

        let out = kubectl_probe_stdout_capture(&[
            "get",
            "events",
            "-n",
            "my-ns",
            "--sort-by=.lastTimestamp",
            "-o",
            "custom-columns=TIME:.lastTimestamp",
        ])
        .await;
        assert_eq!(out.as_deref(), Some("ok"));

        let logged = argv_log.read_argv_log();
        let lines: Vec<&str> = logged.lines().collect();
        assert_eq!(
            lines,
            vec![
                "get",
                "events",
                "-n",
                "my-ns",
                "--sort-by=.lastTimestamp",
                "-o",
                "custom-columns=TIME:.lastTimestamp",
            ],
            "kubectl_probe_stdout_capture must forward every argv \
             slice element verbatim to the spawned kubectl"
        );
    }

    /// A spawn `Err` (the shim path is unresolvable) folds to `None`
    /// at the primitive's boundary. Pre-lift the seven diagnostic
    /// sites all discarded this branch by the `if let Ok(output) =
    /// ...` binding; a regression that surfaced the `io::Error`
    /// would `?`-propagate out of the diagnostic helper and abort
    /// the whole operator-facing failure-triage flow at exactly the
    /// moment the operator needs the diagnostic prints.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_kubectl_probe_stdout_capture_spawn_error_returns_none() {
        let _guard = KUBECTL_BIN_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let _scope =
            KubectlBinScope::set("/nonexistent/dir/absolutely-not-a-kubectl-binary-forge-shim");

        let out = kubectl_probe_stdout_capture(&["get", "pods"]).await;
        assert!(
            out.is_none(),
            "an unresolvable KUBECTL_BIN path must fold to None — the \
             seven pre-lift `if let Ok(output) = ...` sites discarded \
             this branch, and the primitive's contract preserves that \
             swallow-every-spawn-error semantic so a diagnostic helper \
             never aborts on spawn Err"
        );
    }

    // ---------------------------------------------------------------
    // kubectl_capture_anyhow — the async control-flow-carrying
    // captured-output composition. Fuses `kubectl_command_async()` +
    // `.args()` + `crate::retry::run_capture_anyhow(cmd, op)` — same
    // canonical `(op, exit_code, stderr)` envelope
    // `classify_capture_anyhow` produces on the retry.rs frontier,
    // now available at the `(args, op)`-front on the
    // `infrastructure::kubectl` surface every consumer already imports.
    // ---------------------------------------------------------------

    /// The primitive's canonical happy path: a shim that exits zero
    /// prints a stdout payload AND a stderr hint, and the primitive
    /// surfaces both byte-verbatim on the intact
    /// [`std::process::Output`]. Pins the shape both consumer sites
    /// depend on — `commands/flux::get_pod_status_full` parses the
    /// stdout as JSON via `serde_json::from_str(&stdout)` and
    /// `commands/integration_tests::fetch_secret` consumes it as
    /// `String::from_utf8(output.stdout)?` before base64-decode — so a
    /// regression that switched the return type to
    /// `String::from_utf8_lossy` would silently corrupt either
    /// consumer's parse path.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_kubectl_capture_anyhow_success_returns_output_intact() {
        let _guard = KUBECTL_BIN_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let (_dir, shim) = make_executable_shim(
            "kubectl",
            "#!/bin/sh\nprintf '{\"items\":[]}'\nprintf 'stderr-hint' 1>&2\nexit 0\n",
        );
        let _scope = KubectlBinScope::set(&shim);

        let output = kubectl_capture_anyhow(&["get", "pods", "-o", "json"], "kubectl get pods")
            .await
            .expect("zero-exit shim must surface as Ok(Output)");
        assert!(output.status.success());
        assert_eq!(
            output.stdout, b"{\"items\":[]}",
            "stdout bytes must flow through unchanged for downstream \
             byte-level parsing (`serde_json::from_slice`, base64 \
             decode) rather than a UTF-8-lossy round trip"
        );
        assert_eq!(
            output.stderr, b"stderr-hint",
            "stderr bytes must survive on the success path — a caller \
             that wants to log a successful-but-noisy kubectl's stderr \
             still can"
        );
    }

    /// A non-zero kubectl exit surfaces the canonical
    /// `"{op} failed (exit {code}): {stderr}"` envelope from the shared
    /// [`crate::retry::classify_capture_anyhow`] body — the exit code
    /// and the stderr both survive to the operator log line. Pre-lift
    /// the two consumer sites had this envelope by construction of
    /// their delegation to `run_capture_anyhow`; this primitive
    /// preserves that envelope by delegating to the same body.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_kubectl_capture_anyhow_nonzero_exit_carries_op_exit_and_stderr() {
        let _guard = KUBECTL_BIN_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let (_dir, shim) = make_executable_shim(
            "kubectl",
            "#!/bin/sh\nprintf 'Error from server (NotFound): pods not found' 1>&2\nexit 1\n",
        );
        let _scope = KubectlBinScope::set(&shim);

        let err = kubectl_capture_anyhow(&["get", "pods", "-n", "missing"], "kubectl get pods")
            .await
            .expect_err("nonzero exit must produce Err");
        let msg = format!("{err}");
        assert!(
            msg.contains("kubectl get pods failed (exit 1)"),
            "canonical envelope `\"{{op}} failed (exit {{code}})\"` must \
             carry both the op label AND the exit code, got: {msg}"
        );
        assert!(
            msg.contains("Error from server (NotFound): pods not found"),
            "stderr must survive into the op-failure envelope, got: {msg}"
        );
    }

    /// The `(args)`-front surface routes the argv slice verbatim to
    /// the spawned kubectl. Pins the contract both consumer sites
    /// rely on for their heterogeneous 8-element (`get pods -n <ns>
    /// -l app=<name> -o json`) and 5-element (`get secret <name> -o
    /// jsonpath={.data.<key>}`) argv slices — a regression that
    /// dropped, reordered, or truncated the forwarded argv would
    /// silently redirect the kubectl invocation both callers depend
    /// on for control flow.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_kubectl_capture_anyhow_forwards_args() {
        let _guard = KUBECTL_BIN_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let argv_log = ArgvLog::reserve();
        let (_dir, shim) = make_executable_shim("kubectl", &argv_log.shim_body("ok"));
        let _scope = KubectlBinScope::set(&shim);

        let output = kubectl_capture_anyhow(
            &[
                "get",
                "secret",
                "attic-secrets",
                "-o",
                "jsonpath={.data.token}",
            ],
            "kubectl get secret",
        )
        .await
        .expect("shim must succeed");
        assert_eq!(output.stdout, b"ok");

        let logged = argv_log.read_argv_log();
        let lines: Vec<&str> = logged.lines().collect();
        assert_eq!(
            lines,
            vec![
                "get",
                "secret",
                "attic-secrets",
                "-o",
                "jsonpath={.data.token}",
            ],
            "kubectl_capture_anyhow must forward every argv slice \
             element verbatim to the spawned kubectl"
        );
    }

    /// A spawn `Err` (`KUBECTL_BIN` resolves to a nonexistent path)
    /// bails with the canonical
    /// `"Failed to spawn {op}: {io_error}"` envelope — the SPAWN arm
    /// of [`crate::retry::classify_capture_anyhow`]. Pins the shape
    /// both consumer sites depend on for the "developer has no
    /// kubectl on PATH / KUBECTL_BIN points at an absent Nix
    /// derivation" precondition to surface as an operator-actionable
    /// error rather than a downstream parse-of-empty-output crash.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_kubectl_capture_anyhow_spawn_error_carries_op_and_io_error() {
        let _guard = KUBECTL_BIN_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let _scope = KubectlBinScope::set(
            "/nonexistent/dir/absolutely-not-a-kubectl-binary-forge-capture-anyhow-shim",
        );

        let err = kubectl_capture_anyhow(&["get", "pods"], "kubectl get pods")
            .await
            .expect_err("unresolvable KUBECTL_BIN must produce Err");
        let msg = format!("{err}");
        assert!(
            msg.contains("Failed to spawn kubectl get pods"),
            "canonical spawn-failure envelope `\"Failed to spawn \
             {{op}}\"` must carry the op label, got: {msg}"
        );
    }

    /// Whole-module shield: no bare
    /// `crate::tools::get_tool_path("kubectl")` literal form may live
    /// on any *code* line of `infrastructure/kubectl.rs`'s non-test
    /// body. Both sync-and-async resolver entry points on this module
    /// — [`fetch_secret_value`] (delegates to
    /// [`fetch_secret_value_with_bin`]) and
    /// [`find_first_pod_name_async`] (delegates to
    /// [`find_first_pod_name_async_with_bin`]) — MUST route through
    /// the canonical constant-form
    /// [`crate::tools::get_tool_path`]`(`[`crate::tools::tools::KUBECTL`]`)`
    /// lookup that the sibling [`kubectl_command_async`] constructor
    /// (kubectl.rs:130-132) already uses. Pre-lift the two `_with_bin`
    /// wrappers spelled `get_tool_path("kubectl")` verbatim — the
    /// deriving one-arg literal-string form re-derives `KUBECTL_BIN`
    /// at every call site from the bare `"kubectl"` basename, so a
    /// fleet-wide grep on `tools::KUBECTL` (the load-bearing constant
    /// this module's founding [`kubectl_command_async`] delegation
    /// resolves through) misses the two sites entirely. Routing
    /// through the `tools::KUBECTL` constant instead pins both
    /// consumer wrappers to the same canonical name every other
    /// `KUBECTL_BIN` consumer across forge
    /// (`commands/sessions.rs`, `commands/seed.rs`, this module's own
    /// [`kubectl_command_async`]) already routes through, so a rename
    /// of `tools::KUBECTL` surfaces at every kubectl-resolving site
    /// as a compile-time error and not silently at a subset of the
    /// call sites the literal form hides from the audit.
    ///
    /// This test reads this module's own source via [`include_str!`]
    /// and asserts:
    ///
    /// - The forbidden literal-string form `get_tool_path("kubectl")`
    ///   does NOT appear on any *code* line of the non-test body —
    ///   delegating the docstring filter to
    ///   [`crate::test_support::code_line_hits`] so the pre-existing
    ///   docstring at kubectl.rs:45 that narrates the anti-pattern
    ///   verbatim stays legal.
    /// - The canonical constant form `get_tool_path(tools::KUBECTL)`
    ///   DOES appear on at least one *code* line of the non-test
    ///   body — so a regression that deletes the tools::KUBECTL
    ///   delegation while keeping the shield trivially satisfied by
    ///   absence of the forbidden literal still fails.
    ///
    /// The forbidden needle is reconstructed via [`format!`] so this
    /// shield's own body (a runtime string literal, not a docstring)
    /// does not false-match itself. The scan is bounded strictly to
    /// the module body — from the file start to the
    /// `#[cfg(test)]\nmod tests {` marker — so this shield's own
    /// docstrings AND every current or future kubectl-spawning helper
    /// landing anywhere in the top-level module body (across the
    /// three migrated entry points or any as-yet unadded sibling) is
    /// covered by the same shield without a per-function narrowing.
    /// Mirrors the whole-module boundary discipline the sibling
    /// `commands/sessions.rs::tests::test_kubectl_spawns_resolve_
    /// through_tools_kubectl_not_bare_literal` (commit 8643721) and
    /// `commands/seed.rs`'s eponymous shield hold on their own
    /// surfaces.
    ///
    /// The end-to-end `KUBECTL_BIN`-routing invariant of the
    /// [`kubectl_command_async`] constructor is pinned separately by
    /// [`test_kubectl_command_async_routes_through_kubectl_bin_env_var`]
    /// above; this shield only certifies that the two sync-and-async
    /// `_with_bin`-delegating entry points pre-resolve through the
    /// same canonical constant name.
    #[test]
    fn test_kubectl_resolvers_route_through_tools_kubectl_not_bare_literal() {
        let module_body = crate::test_support::module_body_before_tests(
            include_str!("kubectl.rs"),
            "infrastructure/kubectl.rs",
        );

        let bare = "kubectl";
        let forbidden_literal = format!("get_tool_path(\"{}\")", bare);
        let canonical_constant = "get_tool_path(tools::KUBECTL)";

        let hits = crate::test_support::code_line_hits(module_body, &forbidden_literal);
        assert!(
            hits.is_empty(),
            "infrastructure/kubectl.rs must NOT resolve `kubectl` via \
             the deriving one-arg literal-string form \
             `get_tool_path(\"kubectl\")` at any *code* line — the bare \
             `\"kubectl\"` basename is hidden from a fleet-wide \
             `tools::KUBECTL` audit at every such site, so a rename of \
             the `tools::KUBECTL` constant would not surface as a build \
             error at these call sites. Route through the canonical \
             `get_tool_path(tools::KUBECTL)` constant form the sibling \
             `kubectl_command_async` (kubectl.rs:130-132) already uses. \
             Code-line hits: {hits:#?}"
        );

        let canonical_hits = crate::test_support::code_line_hits(module_body, canonical_constant);
        assert!(
            !canonical_hits.is_empty(),
            "infrastructure/kubectl.rs must resolve the `kubectl` binary \
             via the canonical `get_tool_path(tools::KUBECTL)` constant \
             form on at least one *code* line — the required form was \
             not found in the module body, so a future regression that \
             drops the delegation would silently satisfy the negative \
             scan by absence."
        );
    }
}
