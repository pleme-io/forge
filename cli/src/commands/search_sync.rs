//! Search service GitOps sync command
//!
//! Runs `novasearchctl sync` to apply index and lifecycle policy configurations
//! to the search service after K8s deployment rollout completes.
//!
//! This is a special case post-deploy hook for the search service that manages
//! its own GitOps reconciliation for search resources (indexes, policies).

use anyhow::{bail, Context, Result};
use std::env;
use std::path::Path;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;

use crate::config::{DeployConfig, NovaSearchConfig};
use crate::infrastructure::kubectl::kubectl_command_async;
use crate::repo::get_tool_path;

/// Run search service GitOps sync using novasearchctl
///
/// This function is called after K8s deployment rollout to sync index/policy
/// configurations to the running search service instance.
pub async fn run_novasearch_sync(
    service_dir: &Path,
    namespace: &str,
    deploy_config: &DeployConfig,
) -> Result<()> {
    let novasearch_config = &deploy_config.service.novasearch;

    if !novasearch_config.enabled {
        crate::ui::print_step_info("Search sync is disabled, skipping");
        return Ok(());
    }

    println!("🔄 Running search service GitOps sync...");

    // Build config path
    let config_path = service_dir.join(&novasearch_config.config_path);
    if !config_path.exists() {
        bail!(
            "Search config directory not found: {}\n\
             Expected to find kustomization.yaml and index/policy YAML files.",
            config_path.display()
        );
    }

    // Check for novasearchctl availability
    // First try nix run, then fall back to direct binary
    let novasearchctl_available = check_novasearchctl_available().await;

    if !novasearchctl_available {
        crate::ui::print_plain_advisory_warn(
            "novasearchctl not found in PATH, using kubectl exec fallback",
        );
        return run_sync_via_kubectl(&config_path, namespace, novasearch_config).await;
    }

    // Run novasearchctl sync directly
    run_sync_direct(&config_path, novasearch_config).await
}

/// Check if novasearchctl is available
///
/// Fast path: if `NOVASEARCHCTL_BIN` is exported (typically by a nix-hermetic
/// runner's `mkRuntimeToolsEnv`), the substrate has already resolved and
/// pinned the binary — trust that and skip the PATH probe. Falling through
/// to a PATH probe in that world would falsely report "not available"
/// whenever bare `novasearchctl` isn't on PATH (the norm for nix-shell
/// derivations, which only export the specific tool paths a derivation
/// declares), silently downgrading the local-spawn path to the kubectl-exec
/// fallback and losing the substrate-derived binary.
///
/// Fallback: probe PATH via the `which` crate for the mixed / non-Nix
/// development environment where `NOVASEARCHCTL_BIN` is unset. Uses
/// `which::which(...)` — the same crate-backed idiom the sibling probes in
/// `commands/test_ci.rs` (`cargo-nextest`, `cargo-tarpaulin`),
/// `commands/rust_service.rs` (`qemu-aarch64-static`), and
/// `commands/tool.rs` (`crate2nix`) already ride on — rather than a
/// subprocess spawn on the `which` binary, so there is no ambient
/// dependency on a `which` binary existing on PATH itself. This matters on
/// minimal Nix containers whose derivation only exports the specific tool
/// paths declared, where a `which` subprocess spawn would fail-to-exec
/// entirely and the probe would silently report `false` for that reason
/// alone.
async fn check_novasearchctl_available() -> bool {
    if env::var("NOVASEARCHCTL_BIN").is_ok() {
        return true;
    }
    which::which("novasearchctl").is_ok()
}

/// Run sync using novasearchctl directly
///
/// Resolves the binary via the canonical two-argument tools-registry idiom
/// `crate::repo::get_tool_path("NOVASEARCHCTL_BIN", "novasearchctl")` — the
/// same shape the sibling `commands/typescript.rs::regenerate` (5d87339)
/// and `commands/web_service.rs::web_regenerate` (2396779) already ride on.
/// A Nix-hermetic runner's substrate-derived `NOVASEARCHCTL_BIN` path is
/// honored; the bare-`"novasearchctl"` fallback preserves non-Nix behavior.
async fn run_sync_direct(config_path: &Path, config: &NovaSearchConfig) -> Result<()> {
    let novasearchctl = get_tool_path("NOVASEARCHCTL_BIN", "novasearchctl");
    let mut cmd = Command::new(&novasearchctl);
    cmd.arg("--server").arg(&config.api_url);
    cmd.arg("sync");
    cmd.arg("--source").arg(config_path);

    if config.dry_run {
        cmd.arg("--dry-run");
    }

    if config.prune {
        cmd.arg("--prune");
    }

    crate::ui::print_arrow_item(&format!(
        "novasearchctl --server {} sync --source {}{}{}",
        config.api_url,
        config_path.display(),
        if config.dry_run { " --dry-run" } else { "" },
        if config.prune { " --prune" } else { "" },
    ));

    let timeout_duration = Duration::from_secs(config.timeout_secs);

    let result = timeout(
        timeout_duration,
        crate::retry::run_inherited_status(cmd, "novasearchctl sync"),
    )
    .await;

    finalize_search_sync_await_result(result, config.timeout_secs)
}

/// Run sync via kubectl exec (fallback when novasearchctl not available locally)
///
/// This copies the config to a pod and runs novasearchctl inside the search service pod.
async fn run_sync_via_kubectl(
    config_path: &Path,
    namespace: &str,
    config: &NovaSearchConfig,
) -> Result<()> {
    crate::ui::print_arrow_item("Using kubectl to run sync inside search service pod");

    // Find the search service pod
    let pod_name =
        crate::infrastructure::kubectl::find_first_pod_name_async(namespace, "app=novasearch")
            .await
            .with_context(|| {
                format!(
                    "Failed to find search service pod in namespace {}",
                    namespace
                )
            })?;

    crate::ui::print_arrow_item(&format!("Found pod: {}", pod_name));

    // Copy config files to the pod. Routed through
    // `crate::retry::run_inherited_status` so a non-zero exit bails
    // with the structural `"{op} failed (exit {code})"` envelope
    // that `classify_inherited_status` (retry.rs) emits by
    // construction, rather than the pre-lift ad-hoc bail that named
    // the step but dropped the exit code the child process
    // returned. Folds the target namespace/pod/path into the `op`
    // label so the operator log line carries the same per-copy
    // anchor the pre-lift bail message had, with the exit code the
    // pre-lift stanza dropped now preserved at the operator surface.
    // Sibling of the ten async-frontier lifts already on this
    // primitive (`commands/{build, github_runner_ci, image_release,
    // pangea, product_release, rust_service, e2e, local, pangea_infra,
    // typescript}.rs`) and the intra-module `kubectl exec
    // novasearchctl sync` lift already riding this same primitive
    // below.
    let remote_config_path = "/tmp/search-sync-config";

    let mut cp_cmd = kubectl_command_async();
    cp_cmd.args([
        "cp",
        &config_path.to_string_lossy(),
        &format!("{}/{}:{}", namespace, pod_name, remote_config_path),
    ]);
    let cp_op = format!(
        "kubectl cp for {}/{}:{}",
        namespace, pod_name, remote_config_path
    );
    crate::retry::run_inherited_status(cp_cmd, &cp_op).await?;

    // Run novasearchctl sync inside the pod
    let mut exec_args: Vec<&str> =
        crate::kubectl_exec_pod_argv::kubectl_exec_pod_argv_prefix(namespace, &pod_name).to_vec();
    exec_args.extend([
        "novasearchctl",
        "--server",
        "http://localhost:8081",
        "sync",
        "--source",
        remote_config_path,
    ]);

    if config.dry_run {
        exec_args.push("--dry-run");
    }

    if config.prune {
        exec_args.push("--prune");
    }

    crate::ui::print_arrow_item(&format!(
        "kubectl exec -n {} {} -- novasearchctl sync --source {}",
        namespace, pod_name, remote_config_path,
    ));

    let timeout_duration = Duration::from_secs(config.timeout_secs);

    let mut exec_cmd = kubectl_command_async();
    exec_cmd.args(&exec_args);

    let result = timeout(
        timeout_duration,
        crate::retry::run_inherited_status(exec_cmd, "kubectl exec novasearchctl sync"),
    )
    .await;

    // Clean up: remove config from pod
    let mut cleanup_args: Vec<&str> =
        crate::kubectl_exec_pod_argv::kubectl_exec_pod_argv_prefix(namespace, &pod_name).to_vec();
    cleanup_args.extend(["rm", "-rf", remote_config_path]);
    let _ = kubectl_command_async().args(&cleanup_args).status().await;

    finalize_search_sync_await_result(result, config.timeout_secs)
}

/// Success message emitted on the `Ok(Ok(()))` arm of the primitive.
///
/// Held out as a `const` so the printed-line invariant is a single string
/// literal that the byte-oracle test below pins verbatim — a drift on
/// either the success ack or the error envelope would fail the test
/// before it could ship.
const SEARCH_SYNC_SUCCESS_ACK: &str = "Search sync completed successfully";

/// Timeout-envelope template. The `{}` placeholder is populated with the
/// caller's `timeout_secs`, matching the pre-lift `format!` shape at both
/// sites verbatim. Held out (with `#[allow(dead_code)]` because it exists
/// for the byte-oracle test to pin the canonical shape, not for the
/// primitive's own render path) so a drift on the template alone would
/// fail the byte-oracle test before it could ship.
#[allow(dead_code)]
const SEARCH_SYNC_TIMEOUT_ENVELOPE_TEMPLATE: &str = "Search sync timed out after {} seconds";

/// Format the timeout envelope. Held out for byte-oracle parity with the
/// pre-lift `format!` at either call site.
fn format_search_sync_timeout_message(timeout_secs: u64) -> String {
    format!("Search sync timed out after {} seconds", timeout_secs)
}

/// Fused terminator for the two `timeout(<duration>, <sync-op>).await`
/// stanzas in this module.
///
/// Pre-lift `run_sync_direct` (direct novasearchctl invocation) and
/// `run_sync_via_kubectl` (pod-side kubectl-exec fallback) each spelled
/// the same 12-line `match result { Ok(Ok(())) => ok / Ok(Err(e)) =>
/// forward / Err(_) => bail-with-timeout }` body verbatim. A drift on
/// either the success ack or the timeout envelope on ONE arm was silently
/// permissible — nothing pinned the two arms to spell the same operator
/// contract.
///
/// Post-lift the ONE body carries both the success ack literal
/// ([`SEARCH_SYNC_SUCCESS_ACK`]) and the timeout envelope template
/// ([`SEARCH_SYNC_TIMEOUT_ENVELOPE_TEMPLATE`], rendered via
/// [`format_search_sync_timeout_message`]), so a future call-site adder
/// gets the same shape by construction.
fn finalize_search_sync_await_result(
    result: std::result::Result<Result<()>, tokio::time::error::Elapsed>,
    timeout_secs: u64,
) -> Result<()> {
    match result {
        Ok(Ok(())) => {
            crate::ui::print_report_item(SEARCH_SYNC_SUCCESS_ACK);
            Ok(())
        }
        Ok(Err(e)) => Err(e),
        Err(_) => {
            bail!(format_search_sync_timeout_message(timeout_secs));
        }
    }
}

/// Check if search sync should run based on deploy config
pub fn should_run_novasearch_sync(deploy_config: &DeployConfig) -> bool {
    deploy_config.service.novasearch.enabled
}

#[cfg(test)]
mod tests {
    /// Whole-module shield: no raw `Command::new`-with-bare-`kubectl`-
    /// literal may live in `commands/search_sync.rs`. Every `kubectl`
    /// spawn on this module's `run_sync_via_kubectl` fallback path
    /// (the `kubectl cp` config-copy, the `kubectl exec … --
    /// novasearchctl sync` invocation, and the `kubectl exec … --
    /// rm -rf` cleanup) must resolve through
    /// [`crate::infrastructure::kubectl::kubectl_command_async`] —
    /// the async constructor that reads the `KUBECTL_BIN` env
    /// override via [`crate::tools::get_tool_path`] on the canonical
    /// `tools::KUBECTL` name.
    ///
    /// Pre-lift each of the three `kubectl` spawn sites spelled the
    /// bare `"kubectl"` literal verbatim, ignoring `KUBECTL_BIN` at
    /// the site. A Nix-hermetic runner's substrate-derived `kubectl`
    /// path was lost to whatever `kubectl` sat first on PATH — the
    /// same silent-PATH-fallback bug class the sibling consumer
    /// sites in forge already avoid (`commands/rollout.rs::execute`
    /// at c5fcf83, `commands/migrations.rs` at 946e573,
    /// `commands/status.rs` at c2760df, `commands/flux.rs` at
    /// f8da719, `commands/federation_tests.rs` at 9a409e8,
    /// `commands/supergraph_verification.rs` at 65283fb,
    /// `services/migration_service.rs` at 5986a10,
    /// `commands/github_runner_ci.rs` at 5566415,
    /// `commands/product_release.rs::run_health_check` at 5bb7cff).
    ///
    /// This shield scans the module's own source via [`include_str!`]
    /// and forbids the fused literal shape. The forbidden shape is
    /// reconstructed via [`format!`] so this shield's own source text
    /// does not false-match itself — the whole-module scan therefore
    /// covers both the top-of-file production body AND every sibling
    /// `#[cfg(test)]` block (any of which could otherwise silently
    /// re-introduce a raw literal). The end-to-end
    /// `KUBECTL_BIN`-routing invariant of the underlying primitive
    /// is pinned separately by
    /// [`crate::infrastructure::kubectl::tests::test_kubectl_command_async_routes_through_kubectl_bin_env_var`];
    /// this shield only certifies that every `kubectl`-spawning site
    /// in this module resolves through the constructor first.
    #[test]
    fn test_kubectl_spawn_routes_through_kubectl_command_async_not_raw_literal() {
        const SOURCE: &str = include_str!("search_sync.rs");

        crate::test_support::assert_source_forbids_bare_spawn_shapes(
            SOURCE,
            "commands/search_sync.rs",
            "kubectl",
            "resolve the substrate-exported `KUBECTL_BIN` env override via `kubectl_command_async`",
        );

        crate::test_support::assert_source_delegates_via_constructor_call_code_line(
            SOURCE,
            "commands/search_sync.rs",
            "kubectl",
            "kubectl_command_async",
        );
    }

    /// Whole-module shield: no raw `Command::new`-with-bare-`novasearchctl`-
    /// literal may live in `commands/search_sync.rs`. The sole `novasearchctl`
    /// spawn on the direct-invocation path (`run_sync_direct`) must resolve
    /// through the canonical two-argument tools-registry idiom
    /// [`crate::repo::get_tool_path`] against `NOVASEARCHCTL_BIN` first —
    /// the same shape the sibling `commands/typescript.rs::regenerate`
    /// (5d87339) and `commands/web_service.rs::web_regenerate` (2396779)
    /// already ride on.
    ///
    /// Pre-lift the single spawn site (`run_sync_direct`'s
    /// `Command::new(<bare>)`) spelled the bare literal verbatim,
    /// ignoring `NOVASEARCHCTL_BIN` at the site. A Nix-hermetic runner's
    /// substrate-derived novasearchctl path was lost to whatever
    /// `novasearchctl` sat first on PATH — and, worse, the `which`-based
    /// availability probe (`check_novasearchctl_available`) would report
    /// "not available" in a nix-hermetic env where bare `novasearchctl`
    /// isn't on PATH even though `NOVASEARCHCTL_BIN` was exported,
    /// silently downgrading every direct-invocation call to the
    /// `kubectl exec` pod-side fallback. This shield pins the direct-path
    /// spawn onto the substrate-exported env var; the sibling probe was
    /// rewritten in the same lift to short-circuit on `NOVASEARCHCTL_BIN`
    /// before falling through to the PATH probe, so the two halves stay
    /// aligned.
    ///
    /// The `novasearchctl` string literal still appears in this module as
    /// (a) the `which` probe's argument name at the fallback path
    /// (`check_novasearchctl_available`, PATH-probe body only), (b) the
    /// pod-side kubectl-exec arg list at `run_sync_via_kubectl`, and (c)
    /// the diagnostic `println!` labels — none of which are local spawns
    /// of the binary. The shield forbids only the fused
    /// `Command::new(<bare>)` shape, reconstructed via
    /// [`format!`] so the shield's own source text does not false-match
    /// itself; the whole-module scan therefore covers both the top-of-file
    /// production body AND every sibling `#[cfg(test)]` block. Also
    /// asserts the canonical `get_tool_path("NOVASEARCHCTL_BIN",
    /// "novasearchctl")` lookup form is present in the module, so the
    /// sigil-body itself cannot silently drift away from the substrate-
    /// exported env-var contract.
    #[test]
    fn test_novasearchctl_spawn_routes_through_novasearchctl_bin_not_raw_literal() {
        const SOURCE: &str = include_str!("search_sync.rs");

        crate::test_support::assert_source_forbids_bare_spawn_shapes(
            SOURCE,
            "commands/search_sync.rs",
            "novasearchctl",
            "resolve the substrate-exported `NOVASEARCHCTL_BIN` env override \
             via `crate::repo::get_tool_path(\"NOVASEARCHCTL_BIN\", \"novasearchctl\")`",
        );

        crate::test_support::assert_source_has_get_tool_path_two_arg_call_code_line(
            SOURCE,
            "commands/search_sync.rs",
            "NOVASEARCHCTL_BIN",
            "novasearchctl",
        );
    }

    /// Whole-module shield: no bare `which`-binary spawn (a raw
    /// `Command::new` on the bare tool-name literal) may live in
    /// `commands/search_sync.rs`. The PATH-probe fallback in
    /// `check_novasearchctl_available` must resolve through the
    /// `which::which(...)` crate idiom, the same shape the sibling probes
    /// in `commands/test_ci.rs` (`cargo-nextest`, `cargo-tarpaulin`),
    /// `commands/rust_service.rs` (`qemu-aarch64-static`), and
    /// `commands/tool.rs` (`crate2nix`) already ride on.
    ///
    /// Pre-lift the probe spawned a `which` subprocess via the bare
    /// tool-name literal — a fork+exec that added an ambient dependency
    /// on a `which` binary existing on PATH itself. On a minimal Nix
    /// container whose derivation only exports the specific tool paths
    /// declared, the `which` binary is absent and the spawn
    /// fails-to-exec entirely, so the probe silently reports `false`
    /// for that reason alone — the exact same silent-false failure mode
    /// the sibling `NOVASEARCHCTL_BIN` fast-path was written to bypass,
    /// only one layer of ambient dependency deeper. Post-lift the probe
    /// resolves PATH in-process via the `which` crate; no fork+exec, no
    /// ambient binary, no silent false.
    ///
    /// The forbidden shape is reconstructed at test time via [`format!`]
    /// so this shield's own source text does not false-match itself,
    /// and the docstring above uses `which`-binary paraphrase rather
    /// than the literal shape for the same reason; the whole-module
    /// scan therefore covers both the top-of-file production body AND
    /// every sibling `#[cfg(test)]` block. Also asserts the canonical
    /// `which::which(...)` crate idiom is present in the module, so
    /// the sigil-body itself cannot silently drift back to a
    /// subprocess spawn.
    #[test]
    fn test_which_probe_routes_through_which_crate_not_command_spawn() {
        const SOURCE: &str = include_str!("search_sync.rs");

        crate::test_support::assert_source_forbids_bare_spawn_shapes(
            SOURCE,
            "commands/search_sync.rs",
            "which",
            "resolve through the in-process `which::which(...)` crate idiom",
        );
        crate::test_support::assert_source_probes_via_which_which_code_line(
            SOURCE,
            "commands/search_sync.rs",
            "novasearchctl",
        );
    }

    /// Function-scoped shield: `run_sync_via_kubectl`'s body must route
    /// its `kubectl cp` config-copy spawn through
    /// [`crate::retry::run_inherited_status`], never a hand-rolled
    /// `.status().await` + `.context(…)?` + `if !status.success() {
    /// bail!(…) }` stanza that drops the exit code from the operator
    /// log line.
    ///
    /// Pre-lift the `cp` site spelled the seven-line stanza with a
    /// pair of ad-hoc failure messages that named the step but
    /// dropped the exit code the child process returned. Post-lift
    /// the canonical `"kubectl cp for <ns>/<pod>:<path> failed
    /// (exit {code})"` envelope emerges by construction at the
    /// primitive's ONE body — the sibling of the ten async-frontier
    /// lifts already on this primitive (`commands/{build,
    /// github_runner_ci, image_release, pangea, product_release,
    /// rust_service}.rs`) — and the intra-module `kubectl exec
    /// novasearchctl sync` spawn already routed through the same
    /// primitive.
    ///
    /// Scope is `run_sync_via_kubectl`'s function body (from the fn
    /// signature to the following `should_run_novasearch_sync`
    /// docstring marker) because the sibling shields in this module
    /// bound to the whole module and this one must exclude the
    /// intentional `let _ = …status().await;` best-effort cleanup at
    /// the tail of the same function — a fn-scoped slice via
    /// [`crate::test_support::fn_body_slice_between_markers`] keeps
    /// the negative-side scan tight against the pre-lift stanza and
    /// leaves the cleanup-discard shape (which is semantically
    /// distinct from a fatal-bail spawn) alone. The scan targets
    /// the pre-lift `.context(…)?` needle spelled at test time via
    /// [`format!`] so the shield's own docstring above (which names
    /// the pre-lift shape only in prose) does not false-match.
    /// Positive side pins that `crate::retry::run_inherited_status(`
    /// appears in the fn body at ≥1 line, so a regression that
    /// dropped the delegation cannot leave the negative scan
    /// trivially satisfied by absence.
    #[test]
    fn test_run_sync_via_kubectl_cp_spawn_routes_through_run_inherited_status() {
        const SOURCE: &str = include_str!("search_sync.rs");

        let fn_body = crate::test_support::fn_body_slice_between_markers(
            SOURCE,
            "commands/search_sync.rs",
            "async fn run_sync_via_kubectl(",
            "\n/// Check if search sync should run",
        );

        let pre_lift_context = format!(".context({}Failed to copy config to pod{})", '"', '"');
        assert!(
            !fn_body.contains(&pre_lift_context),
            "run_sync_via_kubectl must not re-inline the pre-lift \
             `.context(…)?` stanza on the `kubectl cp` spawn — every \
             kubectl cp spawn must route through \
             `crate::retry::run_inherited_status`, which carries the \
             exit code into the failure envelope."
        );

        let pre_lift_bail = format!(
            "bail!({}Failed to copy config directory to pod{})",
            '"', '"'
        );
        assert!(
            !fn_body.contains(&pre_lift_bail),
            "run_sync_via_kubectl must not re-inline the pre-lift \
             `bail!(…)` on the `kubectl cp` spawn — the ad-hoc \
             message dropped the exit code the child process \
             returned. `run_inherited_status`'s canonical \
             `\"{{op}} failed (exit {{code}})\"` envelope preserves it."
        );

        assert!(
            fn_body.contains("crate::retry::run_inherited_status("),
            "run_sync_via_kubectl must dispatch its `kubectl cp` \
             spawn through `crate::retry::run_inherited_status` — \
             the delegation string was not found in \
             run_sync_via_kubectl."
        );
    }

    /// The success arm of the primitive returns `Ok(())` verbatim and
    /// does not touch the `Err` path. The `print_report_item` ack is
    /// pinned separately in the byte-oracle below; here we only
    /// certify the control-flow shape.
    #[tokio::test]
    async fn test_finalize_search_sync_await_result_success_arm_returns_ok() {
        let result: std::result::Result<anyhow::Result<()>, tokio::time::error::Elapsed> =
            Ok(Ok(()));

        let out = super::finalize_search_sync_await_result(result, 30);

        assert!(
            out.is_ok(),
            "Ok(Ok(())) arm must return Ok(()) — got Err instead"
        );
    }

    /// The forward-error arm carries the inner `anyhow::Error` through
    /// unchanged. A future refactor that re-wraps the inner error
    /// would silently rot every operator's failure-message contract
    /// on this path; this shield fails first.
    #[tokio::test]
    async fn test_finalize_search_sync_await_result_forward_error_arm_preserves_inner_message() {
        let inner_msg = "novasearchctl child exited with code 7";
        let result: std::result::Result<anyhow::Result<()>, tokio::time::error::Elapsed> =
            Ok(Err(anyhow::anyhow!(inner_msg)));

        let out = super::finalize_search_sync_await_result(result, 30);

        let err = out.expect_err("Ok(Err(_)) arm must forward the inner error");
        assert_eq!(
            format!("{}", err),
            inner_msg,
            "Ok(Err(e)) arm must forward the inner error unchanged — \
             a wrapper on the message would rot the operator's \
             failure-envelope contract."
        );
    }

    /// The timeout arm bails with the canonical
    /// [`super::SEARCH_SYNC_TIMEOUT_ENVELOPE_TEMPLATE`] shape, rendering
    /// the caller's `timeout_secs` into the `{}` slot. A drift on the
    /// envelope wording is a semver-visible change to operator logs.
    #[tokio::test]
    async fn test_finalize_search_sync_await_result_timeout_arm_bails_with_canonical_envelope() {
        let elapsed = tokio::time::timeout(
            std::time::Duration::from_nanos(1),
            std::future::pending::<()>(),
        )
        .await
        .expect_err("pending future must trip the 1ns timeout");

        let result: std::result::Result<anyhow::Result<()>, tokio::time::error::Elapsed> =
            Err(elapsed);

        let out = super::finalize_search_sync_await_result(result, 42);
        let err = out.expect_err("Err(Elapsed) arm must bail");

        assert_eq!(
            format!("{}", err),
            "Search sync timed out after 42 seconds",
            "Err(Elapsed) arm must render the canonical envelope with \
             the caller's timeout_secs — a drift is a semver-visible \
             change to operator logs."
        );
    }

    /// Byte-oracle: the success-ack literal spelled by the primitive's
    /// `Ok(Ok(()))` arm and the `SEARCH_SYNC_SUCCESS_ACK` const must
    /// stay in lockstep. A drift on either side would let one arm
    /// spell a stale message while the const still reads the canonical
    /// one — the exact class of measured-claim rot theory calls out
    /// in `THEORY.md § V` (measured claims rot downward; a copy carries
    /// the number without the method).
    #[test]
    fn test_search_sync_success_ack_const_matches_pre_lift_literal() {
        assert_eq!(
            super::SEARCH_SYNC_SUCCESS_ACK,
            "Search sync completed successfully",
            "SEARCH_SYNC_SUCCESS_ACK must spell the pre-lift ack \
             verbatim — a drift here rots both call-site logs."
        );
    }

    /// Byte-oracle: the timeout-envelope template and its renderer
    /// stay in lockstep. Written as a `format!` composition so a
    /// drift on either the template or the renderer's `format!` call
    /// would fail the equality assertion before the message could
    /// ship.
    #[test]
    fn test_format_search_sync_timeout_message_renders_canonical_envelope() {
        assert_eq!(
            super::SEARCH_SYNC_TIMEOUT_ENVELOPE_TEMPLATE,
            "Search sync timed out after {} seconds",
        );
        assert_eq!(
            super::format_search_sync_timeout_message(300),
            "Search sync timed out after 300 seconds",
        );
        assert_eq!(
            super::format_search_sync_timeout_message(0),
            "Search sync timed out after 0 seconds",
        );
    }

    /// Positive-delegation shield: both `run_sync_direct` and
    /// `run_sync_via_kubectl` must call
    /// `finalize_search_sync_await_result(` on the tail of their
    /// `timeout(...).await` stanza. A re-inline of the 12-line
    /// `match result { Ok(Ok(())) => … / Ok(Err(e)) => … / Err(_) =>
    /// bail!(…) }` body at either site would silently permit a drift
    /// on either the success ack or the timeout envelope — the very
    /// duplication this lift was written to close.
    ///
    /// The forbidden pre-lift `match result { Ok(Ok(())) =>` opener
    /// is reconstructed via [`format!`] so this shield's own source
    /// text does not false-match itself; the whole-module scan
    /// therefore covers both fn bodies AND every sibling
    /// `#[cfg(test)]` block. The positive side pins that
    /// `finalize_search_sync_await_result(` appears at ≥2 code-line
    /// hits (both call sites), so a regression that dropped ONE
    /// delegation cannot leave the negative scan trivially satisfied
    /// by absence at the other.
    #[test]
    fn test_search_sync_timeout_terminators_delegate_through_finalize_primitive() {
        const SOURCE: &str = include_str!("search_sync.rs");

        let pre_lift_opener = format!("match result {{{}", "\n        Ok(Ok(())) =>");
        let pre_lift_hits = SOURCE.matches(&pre_lift_opener).count();
        assert_eq!(
            pre_lift_hits, 1,
            "commands/search_sync.rs must spell the pre-lift \
             `match result {{ Ok(Ok(())) => … / Ok(Err(e)) => … / \
             Err(_) => bail!(…) }}` body at EXACTLY ONE site — the \
             `finalize_search_sync_await_result` primitive body. \
             A second hit is a re-inlined call-site stanza; every \
             `timeout(<duration>, <sync-op>).await` stanza must \
             instead route its result through \
             `finalize_search_sync_await_result` so the success ack \
             and the timeout envelope stay pinned to ONE body. \
             Saw {} hits.",
            pre_lift_hits
        );

        let call_line_hits = SOURCE
            .lines()
            .filter(|line| line.contains("finalize_search_sync_await_result("))
            .count();

        assert!(
            call_line_hits >= 3,
            "commands/search_sync.rs must reference \
             `finalize_search_sync_await_result(` at ≥3 code lines \
             (both call sites and the fn definition) — a regression \
             that dropped a delegation would leave the negative \
             pre-lift-opener scan trivially satisfied by absence. \
             Saw {} code-line hits.",
            call_line_hits
        );
    }
}
