//! Typed primitives for reconciling FluxCD kustomizations and sources.
//!
//! This module owns two sibling shapes of the `flux reconcile ...` frontier:
//!
//! - [`reconcile_kustomization`] — `flux reconcile kustomization <ks> -n
//!   <ns> [--with-source]`, driven by four command-module sites (see below).
//! - [`reconcile_source_git`] — `flux reconcile source git <name> -n <ns>`,
//!   driven by `commands/flux.rs::reconcile_source` (the sole pre-lift raw-
//!   spawn `flux reconcile source git` site in forge). The typed
//!   [`FluxSourceGitReconcileError`] carries the same
//!   `(source_name, namespace, exit_code, stderr)` structural record
//!   [`FluxReconcileError`] does — Phase 1 attestation records (THEORY §V.4)
//!   pattern-match on both without re-parsing the display string.
//!
//! Four command-module sites in forge drive the same invocation shape
//! against `flux reconcile kustomization <name> -n <namespace>`:
//! ```text
//! Command::new("flux")
//!     .args(["reconcile", "kustomization", <kustomization>, "-n", <namespace>])
//!     .output().await;
//! // ...then a per-site `match` on Ok/Err + status.success()`.
//! ```
//! carried verbatim modulo per-site failure envelope (best-effort `warn!`
//! at two sites, fatal `bail!` at a third) and per-site `--with-source`
//! flag selection. Four identically-shaped bodies past THEORY §VI.1's
//! three-times threshold (PRIME DIRECTIVE: duplication budget is zero):
//!
//! - `commands/deploy.rs::execute` (best-effort, no `--with-source`)
//! - `commands/github_runner_ci.rs::execute` (best-effort, `--with-source`)
//! - `commands/flux.rs::reconcile_kustomization` (fatal, no `--with-source`)
//! - `commands/flux.rs::reconcile_product_chain` (per-app, no `--with-source`)
//!
//! Two load-bearing properties this primitive owns that the pre-lift
//! raw-spawn stanzas dropped:
//!
//! 1. **`FLUX_BIN` env override.** Pre-lift each site spelled
//!    `Command::new("flux")`, ignoring the env var the
//!    `tools::get_tool_path("flux")` idiom (§tools.rs) resolves.
//!    A Nix-hermetic runner with a store-path `flux` would fall
//!    through to whatever `flux` was first on `PATH` at every one
//!    of those sites — the exact class of bug the `CARGO`-bypass at
//!    the pre-lift extract-schema sites carried (redeemed at
//!    673e4be / b02d4eb / 54a9985).
//! 2. **Typed error dispatch.** Pre-lift, spawn failure fused with
//!    op failure into either a `warn!("... {}", stderr)` bag that
//!    dropped the exit code, or (at the fatal site) an anyhow
//!    `.context(...)` that lost the offending kustomization/namespace
//!    tuple. Post-lift both surface as typed
//!    [`FluxReconcileError`] variants carrying the structural
//!    `(kustomization, namespace, with_source, exit_code, stderr)`
//!    tuple THEORY §V.4 Phase 1 attestation records pattern-match on.
//!
//! THEORY.md §V.1 (Types → Invariants → Proofs): the "flux reconcile
//! ran and returned success" invariant is proved at the reconcile
//! frontier and carried by the return type `Result<(),
//! FluxReconcileError>`, not re-derived at four consumer sites.
//! THEORY.md §VI.1 (one-oracle): the reconcile invocation shape is
//! named here and every consumer reads through it.

use thiserror::Error;
use tokio::process::Command;

use crate::retry::classify_capture;

/// Module-scoped sigil: resolve the `flux` binary via the canonical
/// two-argument [`crate::repo::get_tool_path`] `("FLUX_BIN", "flux")`
/// call. Both production entry points in `flux_reconcile.rs` that need
/// the resolved binary path — the two `_with_bin`-fronting entry points
/// [`reconcile_kustomization`] and [`reconcile_source_git`] — route
/// through this sigil, so the substrate-exported `FLUX_BIN` env-var
/// contract is honored at exactly ONE code line in the module regardless
/// of which entry point the caller drives.
///
/// Pre-lift the module carried two respells of the deriving-one-arg
/// [`crate::tools::get_tool_path`] `("flux")` shape — one per entry
/// point — that a fleet-wide `FLUX_BIN`-literal audit could not see
/// (a regression that dropped the env var at either of the two sites
/// would silently fall through to whatever `flux` was first on PATH
/// on a Nix-hermetic runner). Post-lift both consumers route through
/// this sigil, the deriving one-arg form is absent from the module,
/// and a future widening of the resolve contract (a substrate-path
/// validation step, a per-spawn env-injection hook, a telemetry sigil
/// on the resolved path) lands at ONE body.
///
/// Sibling of the `<tool>_bin()` sigils landed on the CARGO surface
/// across `commands/{test_ci,prerelease,developer_tools,tool,e2e,
/// comprehensive_release}.rs`, the NIX_BIN surface across
/// `commands/{build,developer_tools,rust_service,nix_builder,e2e,
/// tool}.rs`, the DOCKER_BIN / BUN_BIN / CRATE2NIX / ATTIC_BIN
/// surfaces, the `commands/helm.rs::helm_bin()` sigil, and the sibling
/// `flux_get.rs::flux_bin()` sigil (5ad341e) — the same per-module
/// single-point-of-truth discipline applied to the FLUX-reconcile
/// surface here. THEORY §I.5 (Generation over composition, duplication
/// budget zero) and §VI.1 (three-times rule).
fn flux_bin() -> String {
    crate::repo::get_tool_path("FLUX_BIN", "flux")
}

/// Why a `flux reconcile kustomization <kustomization> -n <namespace>`
/// invocation failed to drive the reconcile to success. Carries the
/// offending `kustomization` AND `namespace` AND the boolean
/// `with_source` axis on every variant so a caller can attach all three
/// to a failure record — a Phase 1 attestation, a telemetry event, a
/// structured log line — without re-parsing the display string.
#[derive(Error, Debug)]
pub enum FluxReconcileError {
    /// The `flux` binary could not be spawned. Fires when the resolved
    /// tool path (from `get_tool_path("flux")`) is missing / non-
    /// executable — distinct by construction from `Failed`, which
    /// represents a spawn that succeeded but the child exited non-zero.
    #[error(
        "Failed to spawn flux for reconcile kustomization {kustomization} -n {namespace} \
         (with_source={with_source}): {message}"
    )]
    SpawnFailed {
        kustomization: String,
        namespace: String,
        with_source: bool,
        message: String,
    },

    /// `flux reconcile kustomization <kustomization> -n <namespace>`
    /// exited non-zero. Carries the exit code and the captured stderr
    /// as separate fields — same structural-record shape as
    /// `SchemaExtractionError::Failed` / `NixBuildError::BuildFailed`
    /// / `RegistryError::PushFailed` — so downstream telemetry can
    /// pattern-match on the failure shape without re-parsing the
    /// message.
    #[error(
        "flux reconcile kustomization {kustomization} -n {namespace} \
         (with_source={with_source}) failed (exit {exit_code:?}): {stderr}"
    )]
    Failed {
        kustomization: String,
        namespace: String,
        with_source: bool,
        exit_code: Option<i32>,
        stderr: String,
    },
}

/// Reconcile a FluxCD kustomization by running
/// `flux reconcile kustomization <kustomization> -n <namespace>
/// [--with-source]` and returning `Ok(())` on success.
///
/// # `FLUX_BIN` env override
///
/// The `flux` binary resolves via `tools::get_tool_path("flux")` —
/// same discipline every Nix-derivation-provided tool in forge honors.
/// Pre-lift the four consumer sites spelled `Command::new("flux")`
/// bypassing the override, so a Nix-hermetic runner with a store-path
/// `flux` would fall through to whatever `flux` was first on `PATH`.
///
/// # `with_source`
///
/// When `true`, appends `--with-source` to argv — telling flux to also
/// reconcile the underlying GitRepository / OCIRepository source
/// before reconciling the Kustomization. Only the
/// `github_runner_ci.rs` call site pre-lift wanted this flavor; the
/// `deploy.rs` site did not (its deploy flow relies on a
/// caller-driven `git commit` + `git push` racing ahead of the
/// reconcile). Encoding the axis as a boolean parameter keeps the
/// argv contract explicit at the call site rather than folded into
/// a per-caller command builder.
///
/// # Errors
///
/// - [`FluxReconcileError::SpawnFailed`] — the resolved flux binary
///   could not be spawned. Carries `kustomization`, `namespace`,
///   `with_source`, and the underlying io error message.
/// - [`FluxReconcileError::Failed`] — flux exited non-zero. Carries
///   `kustomization`, `namespace`, `with_source`, `exit_code`, and
///   the trimmed UTF-8-lossy stderr.
pub async fn reconcile_kustomization(
    kustomization: &str,
    namespace: &str,
    with_source: bool,
) -> Result<(), FluxReconcileError> {
    let flux = flux_bin();
    reconcile_kustomization_with_bin(&flux, kustomization, namespace, with_source).await
}

/// Test-injection sibling of [`reconcile_kustomization`]: accepts the
/// resolved `flux_bin` as an explicit argument so unit tests can point
/// at a hermetic shim without mutating the process-wide `FLUX_BIN`
/// environment variable — same discipline as
/// `graphql_schema::extract_graphql_schema_with_bin`,
/// `nix::path_info_recursive_with_bin`, and
/// `AtticClient::with_attic_bin`. Splitting the resolution from the
/// execution keeps the test surface hermetic AND parallel-safe:
/// `#[tokio::test]` on this module can run concurrent tests without
/// racing on env-var writes.
///
/// `kustomization` and `namespace` are spliced verbatim into flux's
/// argv (no escaping / no shell interpretation — `Command::args`
/// owns argv-vector delivery so a user-controlled name cannot inject
/// additional flux args).
async fn reconcile_kustomization_with_bin(
    flux_bin: &str,
    kustomization: &str,
    namespace: &str,
    with_source: bool,
) -> Result<(), FluxReconcileError> {
    let mut args: Vec<&str> = vec!["reconcile", "kustomization", kustomization, "-n", namespace];
    if with_source {
        args.push("--with-source");
    }
    let captured = Command::new(flux_bin).args(&args).output().await;

    // Spawn-vs-op dispatch flows through the canonical
    // [`classify_capture`] primitive — same shape as
    // `extract_graphql_schema_with_bin` / `run_nix_build_typed`.
    classify_capture(
        captured,
        |e| FluxReconcileError::SpawnFailed {
            kustomization: kustomization.to_string(),
            namespace: namespace.to_string(),
            with_source,
            message: e.to_string(),
        },
        |cf| FluxReconcileError::Failed {
            kustomization: kustomization.to_string(),
            namespace: namespace.to_string(),
            with_source,
            exit_code: cf.exit_code,
            stderr: cf.stderr,
        },
    )?;
    Ok(())
}

/// Why a `flux reconcile source git <source_name> -n <namespace>`
/// invocation failed to drive the source reconcile to success. Carries
/// the offending `source_name` AND `namespace` on every variant so a
/// caller can attach both to a failure record — a Phase 1 attestation, a
/// telemetry event, a structured log line — without re-parsing the
/// display string. Sibling of [`FluxReconcileError`] for the source-git
/// shape (no `--with-source` axis: reconciling a source directly is the
/// operation, not an axis on it).
#[derive(Error, Debug)]
pub enum FluxSourceGitReconcileError {
    /// The `flux` binary could not be spawned. Fires when the resolved
    /// tool path (from `get_tool_path("flux")`) is missing / non-
    /// executable — distinct by construction from `Failed`, which
    /// represents a spawn that succeeded but the child exited non-zero.
    #[error(
        "Failed to spawn flux for reconcile source git {source_name} -n {namespace}: {message}"
    )]
    SpawnFailed {
        source_name: String,
        namespace: String,
        message: String,
    },

    /// `flux reconcile source git <source_name> -n <namespace>` exited
    /// non-zero. Carries the exit code and the captured stderr as
    /// separate fields — same structural-record shape as
    /// `FluxReconcileError::Failed` — so downstream telemetry can
    /// pattern-match on the failure shape without re-parsing the
    /// message.
    #[error(
        "flux reconcile source git {source_name} -n {namespace} failed (exit {exit_code:?}): {stderr}"
    )]
    Failed {
        source_name: String,
        namespace: String,
        exit_code: Option<i32>,
        stderr: String,
    },
}

/// Reconcile a FluxCD `GitRepository` source by running
/// `flux reconcile source git <source_name> -n <namespace>` and
/// returning `Ok(())` on success.
///
/// # `FLUX_BIN` env override
///
/// The `flux` binary resolves via `tools::get_tool_path("flux")` —
/// same discipline every Nix-derivation-provided tool in forge honors.
/// Pre-lift the sole consumer site (`commands/flux.rs::reconcile_source`)
/// spelled `Command::new("flux")` bypassing the override, so a Nix-
/// hermetic runner with a store-path `flux` would fall through to
/// whatever `flux` was first on `PATH`.
///
/// # Errors
///
/// - [`FluxSourceGitReconcileError::SpawnFailed`] — the resolved flux
///   binary could not be spawned. Carries `source_name`, `namespace`,
///   and the underlying io error message.
/// - [`FluxSourceGitReconcileError::Failed`] — flux exited non-zero.
///   Carries `source_name`, `namespace`, `exit_code`, and the trimmed
///   UTF-8-lossy stderr.
pub async fn reconcile_source_git(
    source_name: &str,
    namespace: &str,
) -> Result<(), FluxSourceGitReconcileError> {
    let flux = flux_bin();
    reconcile_source_git_with_bin(&flux, source_name, namespace).await
}

/// Test-injection sibling of [`reconcile_source_git`]: accepts the
/// resolved `flux_bin` as an explicit argument so unit tests can point
/// at a hermetic shim without mutating the process-wide `FLUX_BIN`
/// environment variable — same discipline as
/// [`reconcile_kustomization_with_bin`],
/// `graphql_schema::extract_graphql_schema_with_bin`, and
/// `AtticClient::with_attic_bin`.
///
/// `source_name` and `namespace` are spliced verbatim into flux's argv
/// (no escaping / no shell interpretation — `Command::args` owns
/// argv-vector delivery so a user-controlled name cannot inject
/// additional flux args).
async fn reconcile_source_git_with_bin(
    flux_bin: &str,
    source_name: &str,
    namespace: &str,
) -> Result<(), FluxSourceGitReconcileError> {
    let captured = Command::new(flux_bin)
        .args(["reconcile", "source", "git", source_name, "-n", namespace])
        .output()
        .await;

    classify_capture(
        captured,
        |e| FluxSourceGitReconcileError::SpawnFailed {
            source_name: source_name.to_string(),
            namespace: namespace.to_string(),
            message: e.to_string(),
        },
        |cf| FluxSourceGitReconcileError::Failed {
            source_name: source_name.to_string(),
            namespace: namespace.to_string(),
            exit_code: cf.exit_code,
            stderr: cf.stderr,
        },
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::make_executable_shim;

    /// When the resolved flux binary cannot be spawned,
    /// `reconcile_kustomization_with_bin` must surface `SpawnFailed`
    /// carrying the offending kustomization, namespace, AND the
    /// `with_source` axis — never a fused warn-string bag. Pins the
    /// typed split so telemetry can distinguish "flux missing" from
    /// "flux said no" AND partition failures by kustomization /
    /// namespace / with-source axis. Uses an absolute path that does
    /// not exist so Command::spawn fails deterministically without
    /// touching global PATH state.
    #[tokio::test]
    async fn spawn_failed_carries_kustomization_namespace_and_with_source() {
        let result = reconcile_kustomization_with_bin(
            "/nonexistent/path/to/flux-binary-that-does-not-exist",
            "svc-alpha",
            "team-beta",
            true,
        )
        .await;
        let err = result.expect_err("missing flux binary must fail");
        match err {
            FluxReconcileError::SpawnFailed {
                kustomization,
                namespace,
                with_source,
                message,
            } => {
                assert_eq!(kustomization, "svc-alpha");
                assert_eq!(namespace, "team-beta");
                assert!(with_source, "with_source axis must ride through spawn err");
                assert!(
                    !message.is_empty(),
                    "spawn-failure message must not be empty"
                );
            }
            other => panic!("expected SpawnFailed, got: {other:?}"),
        }
    }

    /// A flux invocation that exits non-zero must produce `Failed`
    /// carrying the kustomization, namespace, `with_source`, exit code,
    /// and captured stderr — never a fused stringly bag. Uses a shim
    /// invoked by absolute path so the test is hermetic and parallel-
    /// safe against PATH.
    #[tokio::test]
    async fn failed_carries_structured_fields() {
        let (_shim_dir, shim) = make_executable_shim(
            "flux",
            "#!/bin/sh\necho 'kustomization not found' 1>&2\nexit 1\n",
        );
        let result =
            reconcile_kustomization_with_bin(&shim, "flux-system", "flux-system", false).await;
        let err = result.expect_err("nonzero exit must fail");
        match err {
            FluxReconcileError::Failed {
                kustomization,
                namespace,
                with_source,
                exit_code,
                stderr,
            } => {
                assert_eq!(kustomization, "flux-system");
                assert_eq!(namespace, "flux-system");
                assert!(!with_source, "with_source axis must ride through op err");
                assert_eq!(exit_code, Some(1));
                assert!(
                    stderr.contains("kustomization not found"),
                    "stderr field must capture the flux stderr verbatim, got: {stderr:?}"
                );
            }
            other => panic!("expected Failed, got: {other:?}"),
        }
    }

    /// On the success path, `reconcile_kustomization_with_bin` must
    /// return `Ok(())` — no residual output leaked into the result. A
    /// caller that consumes this via a `Result` `match` discriminates
    /// success from failure structurally without decoding stdout at
    /// the primitive surface.
    #[tokio::test]
    async fn succeeds_when_flux_exits_zero() {
        let (_shim_dir, shim) = make_executable_shim("flux", "#!/bin/sh\nexit 0\n");
        let outcome =
            reconcile_kustomization_with_bin(&shim, "flux-system", "flux-system", false).await;
        assert!(
            outcome.is_ok(),
            "success path must return Ok(()), got: {outcome:?}"
        );
    }

    /// `reconcile_kustomization_with_bin` must splice the caller-
    /// supplied `kustomization` and `namespace` into flux's argv
    /// verbatim, unshelled, unquoted, in the canonical
    /// `["reconcile", "kustomization", <ks>, "-n", <ns>]` order.
    /// Pinned with a shim that copies its full argv to a marker file
    /// so the test can prove the argv-vector reached flux exactly as
    /// expected. A future regression that silently reordered args
    /// (or spliced through a shell interpolation that changed an arg
    /// boundary) would surface here rather than as a Flux "unknown
    /// argument" or "reconciled the wrong resource" downstream.
    ///
    /// The shim uses `printf '%s\n'` (not `echo "$a"`) because POSIX
    /// `sh`'s `echo` treats a leading `-n` argument as a
    /// suppress-trailing-newline flag rather than as the literal
    /// two-character argument — a shim that used `echo` would
    /// silently drop the `-n` from the observed argv and mask an
    /// argv-shape regression.
    #[tokio::test]
    async fn honors_kustomization_and_namespace_in_argv() {
        let observed = tempfile::tempdir().expect("observed tempdir");
        let observed_path = observed.path().join("observed-argv");
        let shim_body = format!(
            "#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\" >> {}; done\nexit 0\n",
            observed_path.display()
        );
        let (_shim_dir, shim) = make_executable_shim("flux", &shim_body);
        reconcile_kustomization_with_bin(&shim, "svc-omega", "team-omega", false)
            .await
            .expect("success path");
        let raw = std::fs::read_to_string(&observed_path).expect("shim must have written argv");
        let args: Vec<&str> = raw.lines().collect();
        assert_eq!(
            args,
            vec![
                "reconcile",
                "kustomization",
                "svc-omega",
                "-n",
                "team-omega"
            ],
            "flux argv must be exactly [reconcile, kustomization, <ks>, -n, <ns>]"
        );
    }

    /// `with_source: true` must append `--with-source` as the final
    /// argv element; `with_source: false` must NOT include it. Pins
    /// the boolean-axis contract the `github_runner_ci.rs` and
    /// `deploy.rs` sites depend on distinctly (former passes `true`,
    /// latter passes `false`). A regression that appended the flag
    /// unconditionally would silently change deploy.rs's reconcile
    /// semantics; a regression that dropped it unconditionally
    /// would silently degrade github_runner_ci.rs's source-reconcile
    /// coverage.
    #[tokio::test]
    async fn with_source_axis_toggles_flag_in_argv() {
        // with_source=true: --with-source appended as the tail element.
        let observed_true = tempfile::tempdir().expect("observed tempdir");
        let observed_true_path = observed_true.path().join("observed-argv");
        let shim_true_body = format!(
            "#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\" >> {}; done\nexit 0\n",
            observed_true_path.display()
        );
        let (_shim_true_dir, shim_true) = make_executable_shim("flux", &shim_true_body);
        reconcile_kustomization_with_bin(&shim_true, "flux-system", "flux-system", true)
            .await
            .expect("success path");
        let raw_true =
            std::fs::read_to_string(&observed_true_path).expect("shim must have written argv");
        let args_true: Vec<&str> = raw_true.lines().collect();
        assert_eq!(
            args_true,
            vec![
                "reconcile",
                "kustomization",
                "flux-system",
                "-n",
                "flux-system",
                "--with-source",
            ],
            "with_source=true must append --with-source as the tail element"
        );

        // with_source=false: --with-source omitted entirely.
        let observed_false = tempfile::tempdir().expect("observed tempdir");
        let observed_false_path = observed_false.path().join("observed-argv");
        let shim_false_body = format!(
            "#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\" >> {}; done\nexit 0\n",
            observed_false_path.display()
        );
        let (_shim_false_dir, shim_false) = make_executable_shim("flux", &shim_false_body);
        reconcile_kustomization_with_bin(&shim_false, "flux-system", "flux-system", false)
            .await
            .expect("success path");
        let raw_false =
            std::fs::read_to_string(&observed_false_path).expect("shim must have written argv");
        let args_false: Vec<&str> = raw_false.lines().collect();
        assert_eq!(
            args_false,
            vec![
                "reconcile",
                "kustomization",
                "flux-system",
                "-n",
                "flux-system",
            ],
            "with_source=false must NOT append --with-source"
        );
        assert!(
            !args_false.contains(&"--with-source"),
            "with_source=false must NOT append --with-source anywhere in argv, got: {args_false:?}"
        );
    }

    /// Every failure variant's `Display` must render both
    /// `kustomization` AND `namespace` verbatim so a caller that
    /// collapses the typed error into a stringly-downstream
    /// `warn!("{}", err)` (both current best-effort call sites do this)
    /// surfaces the offending kustomization/namespace tuple to the
    /// operator as-is. A regression that dropped either field from
    /// the `#[error(...)]` attribute would silently degrade the
    /// operator prose at every stringly-downstream site.
    #[test]
    fn display_carries_kustomization_and_namespace_on_every_variant() {
        let kustomization = String::from("svc-omega-blue");
        let namespace = String::from("team-omega");
        let variants = [
            FluxReconcileError::SpawnFailed {
                kustomization: kustomization.clone(),
                namespace: namespace.clone(),
                with_source: true,
                message: "No such file or directory (os error 2)".to_string(),
            },
            FluxReconcileError::Failed {
                kustomization: kustomization.clone(),
                namespace: namespace.clone(),
                with_source: false,
                exit_code: Some(1),
                stderr: "Error: no Kustomization found".to_string(),
            },
        ];
        for v in &variants {
            let rendered = v.to_string();
            assert!(
                rendered.contains(&kustomization),
                "variant {v:?} must render kustomization verbatim; got: {rendered}"
            );
            assert!(
                rendered.contains(&namespace),
                "variant {v:?} must render namespace verbatim; got: {rendered}"
            );
        }
    }

    /// `FluxReconcileError::Failed`'s `Display` must render BOTH the
    /// numeric `exit_code` AND the captured `stderr` verbatim. The
    /// migrated `commands/flux.rs::reconcile_product_chain` best-effort
    /// site collapses the stderr field explicitly in a `println!`, but
    /// the fatal `commands/flux.rs::reconcile_kustomization` site (and
    /// any future call site that folds the typed error into an
    /// `anyhow::Context` chain via `?`) relies on `Display` to surface
    /// both fields at the operator log — a regression that dropped
    /// either from the `#[error(...)]` attribute would silently degrade
    /// the operator prose at every stringly-downstream site AND leave
    /// operators without the exit-code / stderr signal Phase 1
    /// attestation records depend on (THEORY §V.4).
    #[test]
    fn failed_display_carries_exit_code_and_stderr() {
        let err = FluxReconcileError::Failed {
            kustomization: "svc-alpha".to_string(),
            namespace: "team-beta".to_string(),
            with_source: false,
            exit_code: Some(42),
            stderr: "Error: no Kustomization found in \"team-beta\" namespace".to_string(),
        };
        let rendered = err.to_string();
        assert!(
            rendered.contains("42"),
            "Failed display must render exit_code verbatim; got: {rendered}"
        );
        assert!(
            rendered.contains("Error: no Kustomization found in \"team-beta\" namespace"),
            "Failed display must render stderr verbatim; got: {rendered}"
        );

        // The signal-terminated shape (`exit_code: None`) must ALSO carry
        // stderr so a killed-flux failure still surfaces its exit output.
        let killed = FluxReconcileError::Failed {
            kustomization: "svc-alpha".to_string(),
            namespace: "team-beta".to_string(),
            with_source: false,
            exit_code: None,
            stderr: "signal 9 while reconciling".to_string(),
        };
        let rendered_killed = killed.to_string();
        assert!(
            rendered_killed.contains("signal 9 while reconciling"),
            "signal-killed Failed display must render stderr verbatim; got: {rendered_killed}"
        );
    }

    /// A caller that wraps `FluxReconcileError` via `anyhow::Error::new(e)`
    /// (both migrated `commands/flux.rs` sites do this on the fatal arm)
    /// must be able to recover the typed variant across the anyhow
    /// boundary via `downcast_ref::<FluxReconcileError>()`. Pins the
    /// programmatic-recovery promise the previous commit body claimed —
    /// "recoverable via err.downcast_ref::<FluxReconcileError>() across
    /// the anyhow boundary" — WITHOUT which downstream telemetry would
    /// be forced to regex-parse the display string to partition failures
    /// by kustomization/namespace/exit_code. A regression that swapped
    /// the typed error for a `String` (or dropped the `#[derive(Error,
    /// Debug)]`) would break every consumer that expects to
    /// pattern-match on the structural tuple; that break would surface
    /// here rather than as a silent downgrade to stringly-typed telemetry.
    #[test]
    fn anyhow_boundary_preserves_typed_downcast() {
        let typed = FluxReconcileError::Failed {
            kustomization: "svc-alpha".to_string(),
            namespace: "team-beta".to_string(),
            with_source: true,
            exit_code: Some(7),
            stderr: "context deadline exceeded".to_string(),
        };
        let wrapped: anyhow::Error =
            anyhow::Error::new(typed).context("Failed to reconcile kustomization svc-alpha");
        let recovered = wrapped
            .downcast_ref::<FluxReconcileError>()
            .expect("typed FluxReconcileError must survive anyhow wrapping");
        match recovered {
            FluxReconcileError::Failed {
                kustomization,
                namespace,
                with_source,
                exit_code,
                stderr,
            } => {
                assert_eq!(kustomization, "svc-alpha");
                assert_eq!(namespace, "team-beta");
                assert!(*with_source, "with_source axis must survive anyhow wrap");
                assert_eq!(*exit_code, Some(7));
                assert_eq!(stderr, "context deadline exceeded");
            }
            other => panic!("expected Failed, got: {other:?}"),
        }

        // The SpawnFailed arm — the shape both migrated `commands/flux.rs`
        // sites re-anyhow on the fatal path — must survive the same
        // boundary. Without this the `Err(e).context(...)?` re-anyhow in
        // `reconcile_product_chain` would silently opaque the missing-flux
        // signal to a stringly-typed operator log.
        let spawn_typed = FluxReconcileError::SpawnFailed {
            kustomization: "svc-alpha".to_string(),
            namespace: "team-beta".to_string(),
            with_source: false,
            message: "No such file or directory (os error 2)".to_string(),
        };
        let spawn_wrapped: anyhow::Error =
            anyhow::Error::new(spawn_typed).context("Failed to reconcile kustomization svc-alpha");
        let spawn_recovered = spawn_wrapped
            .downcast_ref::<FluxReconcileError>()
            .expect("typed SpawnFailed must survive anyhow wrapping");
        assert!(
            matches!(spawn_recovered, FluxReconcileError::SpawnFailed { .. }),
            "recovered variant must be SpawnFailed, got: {spawn_recovered:?}"
        );
    }

    // ------------------------------------------------------------------
    // source-git sibling: mirrors the kustomization invariants against
    // the `flux reconcile source git <name> -n <ns>` shape.
    // ------------------------------------------------------------------

    /// When the resolved flux binary cannot be spawned,
    /// `reconcile_source_git_with_bin` must surface `SpawnFailed`
    /// carrying the offending `source_name` AND `namespace` — never a
    /// fused warn-string bag. Pins the typed split so telemetry can
    /// distinguish "flux missing" from "flux said no" AND partition
    /// source-git failures by source_name / namespace axis. Uses an
    /// absolute path that does not exist so Command::spawn fails
    /// deterministically without touching global PATH state.
    #[tokio::test]
    async fn source_git_spawn_failed_carries_source_name_and_namespace() {
        let result = reconcile_source_git_with_bin(
            "/nonexistent/path/to/flux-binary-that-does-not-exist",
            "flux-system",
            "flux-system",
        )
        .await;
        let err = result.expect_err("missing flux binary must fail");
        match err {
            FluxSourceGitReconcileError::SpawnFailed {
                source_name,
                namespace,
                message,
            } => {
                assert_eq!(source_name, "flux-system");
                assert_eq!(namespace, "flux-system");
                assert!(
                    !message.is_empty(),
                    "spawn-failure message must not be empty"
                );
            }
            other => panic!("expected SpawnFailed, got: {other:?}"),
        }
    }

    /// A `flux reconcile source git` invocation that exits non-zero must
    /// produce `Failed` carrying the source_name, namespace, exit code,
    /// and captured stderr — never a fused stringly bag. Uses a shim
    /// invoked by absolute path so the test is hermetic and parallel-
    /// safe against PATH.
    #[tokio::test]
    async fn source_git_failed_carries_structured_fields() {
        let (_shim_dir, shim) = make_executable_shim(
            "flux",
            "#!/bin/sh\necho 'GitRepository not found' 1>&2\nexit 1\n",
        );
        let result = reconcile_source_git_with_bin(&shim, "flux-system", "flux-system").await;
        let err = result.expect_err("nonzero exit must fail");
        match err {
            FluxSourceGitReconcileError::Failed {
                source_name,
                namespace,
                exit_code,
                stderr,
            } => {
                assert_eq!(source_name, "flux-system");
                assert_eq!(namespace, "flux-system");
                assert_eq!(exit_code, Some(1));
                assert!(
                    stderr.contains("GitRepository not found"),
                    "stderr field must capture the flux stderr verbatim, got: {stderr:?}"
                );
            }
            other => panic!("expected Failed, got: {other:?}"),
        }
    }

    /// On the success path, `reconcile_source_git_with_bin` must return
    /// `Ok(())` — no residual output leaked into the result.
    #[tokio::test]
    async fn source_git_succeeds_when_flux_exits_zero() {
        let (_shim_dir, shim) = make_executable_shim("flux", "#!/bin/sh\nexit 0\n");
        let outcome = reconcile_source_git_with_bin(&shim, "flux-system", "flux-system").await;
        assert!(
            outcome.is_ok(),
            "success path must return Ok(()), got: {outcome:?}"
        );
    }

    /// `reconcile_source_git_with_bin` must splice the caller-supplied
    /// `source_name` and `namespace` into flux's argv verbatim,
    /// unshelled, unquoted, in the canonical
    /// `["reconcile", "source", "git", <name>, "-n", <ns>]` order.
    /// Pinned with a shim that copies its full argv to a marker file so
    /// the test can prove the argv-vector reached flux exactly as
    /// expected. A future regression that silently reordered args
    /// (or spliced through a shell interpolation that changed an arg
    /// boundary) would surface here rather than as a Flux "unknown
    /// argument" or "reconciled the wrong source" downstream.
    ///
    /// The shim uses `printf '%s\n'` (not `echo "$a"`) because POSIX
    /// `sh`'s `echo` treats a leading `-n` argument as a
    /// suppress-trailing-newline flag rather than as the literal
    /// two-character argument — a shim that used `echo` would silently
    /// drop the `-n` from the observed argv and mask an argv-shape
    /// regression.
    #[tokio::test]
    async fn source_git_honors_source_name_and_namespace_in_argv() {
        let observed = tempfile::tempdir().expect("observed tempdir");
        let observed_path = observed.path().join("observed-argv");
        let shim_body = format!(
            "#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\" >> {}; done\nexit 0\n",
            observed_path.display()
        );
        let (_shim_dir, shim) = make_executable_shim("flux", &shim_body);
        reconcile_source_git_with_bin(&shim, "svc-omega-source", "team-omega")
            .await
            .expect("success path");
        let raw = std::fs::read_to_string(&observed_path).expect("shim must have written argv");
        let args: Vec<&str> = raw.lines().collect();
        assert_eq!(
            args,
            vec![
                "reconcile",
                "source",
                "git",
                "svc-omega-source",
                "-n",
                "team-omega",
            ],
            "flux argv must be exactly [reconcile, source, git, <name>, -n, <ns>]"
        );
    }

    /// Every `FluxSourceGitReconcileError` variant's `Display` must
    /// render both `source_name` AND `namespace` verbatim so a caller
    /// that collapses the typed error into a stringly-downstream
    /// `warn!("{}", err)` or `anyhow::Context` chain surfaces the
    /// offending tuple to the operator as-is. A regression that dropped
    /// either field from the `#[error(...)]` attribute would silently
    /// degrade the operator prose at every stringly-downstream site.
    /// `Failed`'s `Display` must ALSO render `exit_code` and `stderr`
    /// verbatim — the migrated `commands/flux.rs::reconcile_source` site
    /// folds the typed error into an `anyhow::Context` chain via `?`,
    /// and any Phase 1 attestation record (THEORY §V.4) reading through
    /// the display string relies on those fields.
    #[test]
    fn source_git_display_carries_every_field() {
        let source_name = String::from("svc-omega-source");
        let namespace = String::from("team-omega");
        let spawn = FluxSourceGitReconcileError::SpawnFailed {
            source_name: source_name.clone(),
            namespace: namespace.clone(),
            message: "No such file or directory (os error 2)".to_string(),
        };
        let failed = FluxSourceGitReconcileError::Failed {
            source_name: source_name.clone(),
            namespace: namespace.clone(),
            exit_code: Some(42),
            stderr: "Error: no GitRepository found in \"team-omega\" namespace".to_string(),
        };
        for v in [&spawn, &failed] {
            let rendered = v.to_string();
            assert!(
                rendered.contains(&source_name),
                "variant {v:?} must render source_name verbatim; got: {rendered}"
            );
            assert!(
                rendered.contains(&namespace),
                "variant {v:?} must render namespace verbatim; got: {rendered}"
            );
        }
        let rendered_failed = failed.to_string();
        assert!(
            rendered_failed.contains("42"),
            "Failed display must render exit_code verbatim; got: {rendered_failed}"
        );
        assert!(
            rendered_failed.contains("Error: no GitRepository found in \"team-omega\" namespace"),
            "Failed display must render stderr verbatim; got: {rendered_failed}"
        );

        // The signal-terminated shape (`exit_code: None`) must ALSO
        // carry stderr so a killed-flux failure still surfaces its exit
        // output.
        let killed = FluxSourceGitReconcileError::Failed {
            source_name: source_name.clone(),
            namespace,
            exit_code: None,
            stderr: "signal 9 while reconciling source".to_string(),
        };
        let rendered_killed = killed.to_string();
        assert!(
            rendered_killed.contains("signal 9 while reconciling source"),
            "signal-killed Failed display must render stderr verbatim; got: {rendered_killed}"
        );
    }

    /// A caller that wraps `FluxSourceGitReconcileError` via
    /// `anyhow::Error::new(e).context(...)` (the migrated
    /// `commands/flux.rs::reconcile_source` site does exactly this on
    /// the fatal arm) must be able to recover the typed variant across
    /// the anyhow boundary via
    /// `downcast_ref::<FluxSourceGitReconcileError>()`. Pins the
    /// programmatic-recovery promise — WITHOUT which downstream
    /// telemetry would be forced to regex-parse the display string to
    /// partition failures by source_name / namespace / exit_code. A
    /// regression that swapped the typed error for a `String` (or
    /// dropped the `#[derive(Error, Debug)]`) would break every
    /// consumer that expects to pattern-match on the structural tuple;
    /// that break would surface here rather than as a silent downgrade
    /// to stringly-typed telemetry.
    #[test]
    fn source_git_anyhow_boundary_preserves_typed_downcast() {
        let typed = FluxSourceGitReconcileError::Failed {
            source_name: "flux-system".to_string(),
            namespace: "flux-system".to_string(),
            exit_code: Some(7),
            stderr: "context deadline exceeded".to_string(),
        };
        let wrapped: anyhow::Error =
            anyhow::Error::new(typed).context("Failed to reconcile FluxCD git source");
        let recovered = wrapped
            .downcast_ref::<FluxSourceGitReconcileError>()
            .expect("typed FluxSourceGitReconcileError must survive anyhow wrapping");
        match recovered {
            FluxSourceGitReconcileError::Failed {
                source_name,
                namespace,
                exit_code,
                stderr,
            } => {
                assert_eq!(source_name, "flux-system");
                assert_eq!(namespace, "flux-system");
                assert_eq!(*exit_code, Some(7));
                assert_eq!(stderr, "context deadline exceeded");
            }
            other => panic!("expected Failed, got: {other:?}"),
        }

        let spawn_typed = FluxSourceGitReconcileError::SpawnFailed {
            source_name: "flux-system".to_string(),
            namespace: "flux-system".to_string(),
            message: "No such file or directory (os error 2)".to_string(),
        };
        let spawn_wrapped: anyhow::Error =
            anyhow::Error::new(spawn_typed).context("Failed to reconcile FluxCD git source");
        let spawn_recovered = spawn_wrapped
            .downcast_ref::<FluxSourceGitReconcileError>()
            .expect("typed SpawnFailed must survive anyhow wrapping");
        assert!(
            matches!(
                spawn_recovered,
                FluxSourceGitReconcileError::SpawnFailed { .. }
            ),
            "recovered variant must be SpawnFailed, got: {spawn_recovered:?}"
        );
    }

    /// Whole-module shield: `fn flux_bin()` — the module-scoped sigil
    /// that resolves the `flux` binary via the canonical two-argument
    /// [`crate::repo::get_tool_path`] `("FLUX_BIN", "flux")` call —
    /// MUST be defined at a code line in this module, AND the two-arg
    /// resolve MUST appear at exactly ONE code line in the module
    /// body (only in the sigil definition), AND the pre-lift deriving-
    /// one-arg [`crate::tools::get_tool_path`] `("flux")` shape MUST
    /// NOT appear at any code line.
    ///
    /// Pre-lift the module carried two respells of the deriving
    /// one-arg form — one per public entry point
    /// ([`reconcile_kustomization`], [`reconcile_source_git`]) —
    /// silently bypassing the module's own single-point-of-truth for
    /// tool resolution: a future edit to the resolve contract at
    /// either entry point would have left the other stranded at the
    /// pre-edit form, AND the deriving-one-arg shape hid the
    /// `FLUX_BIN` env-var literal from a fleet-wide audit. Post-lift
    /// each consumer routes through `flux_bin()` and the two-arg
    /// resolve appears in exactly ONE place (the sigil body). The
    /// `resolve_count == 1` assertion fails-before at 0 (the canonical
    /// two-arg form did not exist in the module pre-lift) and passes-
    /// after at 1 — canonical fail-before-pass-after arc matching the
    /// sibling `<tool>_bin()` shield discipline landed on
    /// `flux_get.rs::flux_bin` (5ad341e),
    /// `infrastructure/attic.rs::attic_bin` (559adae),
    /// `commands/comprehensive_release.rs::cargo_bin` (fceeecc),
    /// `cli/src/nix.rs::nix_bin` (6b2ea15), and the broader
    /// `<tool>_bin()` sigil family. The deriving-one-arg negative
    /// shield closes the audit-visibility loophole: a regression that
    /// reintroduces `crate::tools::get_tool_path("flux")` at any code
    /// line panics with a code-line hits diagnostic rather than
    /// silently passing.
    ///
    /// The scan bounds on the whole-module boundary (from the file
    /// start to the FIRST `\n#[cfg(test)]\nmod tests {` marker in
    /// source order — the outer test module's opener) so this
    /// shield's own docstring mentions of the pre-lift and canonical
    /// forms — living inside the `#[cfg(test)]` block below that
    /// marker — stay out of scope AND every current or future
    /// flux-spawning helper landing anywhere in the top-level module
    /// body cannot silently ride along without going through
    /// `flux_bin()`.
    ///
    /// All three needles are reconstructed via `format!` inside
    /// [`crate::test_support::sigil_bin_fn_definition_needle`],
    /// [`crate::test_support::canonical_two_arg_sigil_needle`], and
    /// [`crate::test_support::deriving_one_arg_sigil_needle_literal`],
    /// so this shield's own source never contains a concrete
    /// `crate::repo::get_tool_path("FLUX_BIN", "flux")`,
    /// `crate::tools::get_tool_path("flux")`, or `fn flux_bin()`
    /// literal and cannot false-match itself on any assertion. All
    /// three assertions route through
    /// [`crate::test_support::code_line_hits`] to preserve the
    /// anti-docstring-self-match discipline — the existing `///` and
    /// `//!` prose in the module that legitimately quotes the
    /// pre-lift shape for narrative purposes does not count against
    /// the sigil-body or deriving-form assertions.
    #[test]
    fn test_flux_reconcile_routes_flux_bin_through_flux_bin_sigil_not_raw_resolve() {
        let body = crate::test_support::module_body_before_tests(
            include_str!("flux_reconcile.rs"),
            "flux_reconcile.rs",
        );

        let sigil_needle = crate::test_support::sigil_bin_fn_definition_needle("flux_bin");
        let sigil_hits = crate::test_support::code_line_hits(body, &sigil_needle);
        assert!(
            !sigil_hits.is_empty(),
            "flux_reconcile.rs must define `flux_bin()` at a code line in \
             the module body — the sigil function that resolves the \
             tools-registry `FLUX_BIN` override for every `flux` binary \
             lookup at the two `_with_bin`-fronting entry points \
             (`reconcile_kustomization`, `reconcile_source_git`). \
             Mirrors the sibling `<tool>_bin()` sigils across the CARGO / \
             NIX_BIN / DOCKER_BIN / BUN_BIN / CRATE2NIX / ATTIC_BIN / \
             FLUX surfaces."
        );

        let two_arg_needle =
            crate::test_support::canonical_two_arg_sigil_needle("FLUX_BIN", "flux");
        let resolve_hits = crate::test_support::code_line_hits(body, &two_arg_needle);
        assert_eq!(
            resolve_hits.len(),
            1,
            "the canonical two-argument resolve `{two_arg_needle}` \
             must appear at exactly ONE code line in the module body \
             (only in the `flux_bin()` sigil), not {} — every consumer \
             must route through `flux_bin()`, not re-copy the resolve \
             inline. A future edit to the resolve contract (a \
             substrate-path validation step, a per-spawn env-injection \
             hook, a telemetry sigil on the resolved path) must land \
             at the sigil body once, not at each drifted call site. \
             Found {} code-line hit(s): {resolve_hits:#?}",
            resolve_hits.len(),
            resolve_hits.len()
        );

        let deriving_needle = crate::test_support::deriving_one_arg_sigil_needle_literal("flux");
        let deriving_hits = crate::test_support::code_line_hits(body, &deriving_needle);
        assert!(
            deriving_hits.is_empty(),
            "flux_reconcile.rs must not resolve `flux` via the pre-lift \
             deriving one-arg literal-string form `{deriving_needle}` \
             at any code line — a `FLUX_BIN`-literal audit would \
             miss the site. Every `flux` binary lookup must route \
             through the `flux_bin()` sigil which delegates to the \
             canonical two-arg `crate::repo::get_tool_path(\"FLUX_BIN\", \"flux\")` \
             form the sibling sigils honor. Code-line hits: {deriving_hits:#?}"
        );
    }
}
