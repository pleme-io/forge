//! Helm chart lifecycle commands
//!
//! Provides lint, package, push, deploy, release, template, and bump operations
//! for pleme-io Helm charts distributed via OCI registries.

use crate::repo::get_tool_path;
use crate::retry::RetryPolicy;
use crate::version;
use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread::sleep;
use std::time::{Duration, Instant};
use tracing::{info, warn};

/// Per-attempt wall-clock cap on `helm dependency update`. pleme-io wrapper
/// charts pull third-party subcharts (victoria-metrics-k8s-stack, cert-manager,
/// authentik, …) from upstream `*.github.io` repos at release time — those
/// downloads are not vendored in git (`.gitignore` excludes `charts/*/*.tgz`),
/// so a slow or unreachable upstream would otherwise block `helm dependency
/// update` indefinitely and wedge the entire monorepo auto-release. The cap
/// converts a hang into a typed per-chart failure that `release_all` collects
/// and continues past.
const DEP_TIMEOUT_SECS: u64 = 240;
/// Extra attempts after the first (so `DEP_RETRIES + 1` total) — absorbs
/// transient upstream slowness / index flakiness with exponential-with-cap
/// backoff (see [`HELM_DEP_UPDATE_RETRY_BACKOFF`]).
const DEP_RETRIES: u32 = 1;

/// The typed exponential-backoff policy for [`helm_dependency_update`]'s
/// between-retry sleeps — `initial_backoff` 5s × `factor` 2 capped at
/// `max_backoff` 30s. Consumes the pre-existing typed primitive at
/// [`crate::retry::RetryPolicy`] so the per-attempt delay lands at
/// [`RetryPolicy::compute_delay`], whose docstring names its raison
/// d'être: "the pre-existing fixed `sleep(2s)` schedule ... is the
/// worst of both worlds ... Exponential backoff (Bazel-style: 250ms ×
/// factor=2 capped at 30s) covers both regimes by construction."
///
/// Pre-lift the between-retry sleep spelled
/// `sleep(Duration::from_secs(5 * u64::from(attempt)))` — a linear
/// 5s × attempt schedule — inline at [`helm_dependency_update`]'s
/// backoff site. That shape carried three structural defects the typed-
/// primitive body forecloses:
///
/// 1. **Linear (unbounded-growth) schedule.** `5s * attempt` grows
///    without a ceiling: at `attempt == 10` the pre-lift schedule
///    sleeps 50s; at `attempt == 100` (a pathological but structurally
///    reachable `DEP_RETRIES` budget), 500s of wall-clock evaporate on
///    ONE inter-attempt gap. Post-lift, the exponential schedule
///    doubles until the shared `max_backoff` cap and then plateaus —
///    the same bounded-tail discipline every sibling `RetryPolicy`-
///    consumer (`TEST_RETRY_BACKOFF` at `commands/test.rs`,
///    `FLUX_POLL_BACKOFF` at `commands/flux.rs`) already reads.
/// 2. **Bespoke arithmetic at the sleep site.** The pre-lift
///    `5 * u64::from(attempt)` bakes the (seed, growth-shape) tuple
///    into the sleep call itself — no named surface a shield or a
///    future factor edit could pin. The lifted
///    `HELM_DEP_UPDATE_RETRY_BACKOFF` const names the (seed, factor,
///    cap) triple at one load-bearing structural surface.
/// 3. **Divergence from every sibling forge retry surface.** The five
///    sibling between-attempt-sleep surfaces already lifted (health-
///    endpoint b5db3b6, Shinka reconcile-poll b962db5, flux polling
///    65de62f, web-test-suite 9fd38d3, integration-test-suite e22b0a2)
///    consume `RetryPolicy::compute_delay` — a schedule discipline
///    edit (e.g. changing the cap, or the saturating-math semantics)
///    that landed at the typed primitive did not reach this one
///    bypasser. Post-lift, every hand-rolled between-attempt-sleep
///    site in the forge tree reads through the same primitive.
///
/// The `factor: 2` climb reproduces the pre-lift 5s → 10s schedule
/// verbatim at the currently-reachable attempts (`compute_delay(2) =
/// 5s * 2^0 = 5s` matches `5 * 1 = 5`; `compute_delay(3) = 5s * 2^1 =
/// 10s` matches `5 * 2 = 10`), then diverges strictly under the cap
/// discipline at every deeper retry.
///
/// `max_attempts: 1` is a placeholder — the retry loop drives its own
/// attempt budget through the top-of-module [`DEP_RETRIES`] constant
/// and consumes only [`RetryPolicy::compute_delay`] from this policy,
/// not [`RetryPolicy::max_attempts`]. The `max_attempts` field is
/// unconsulted at this consumption site. Sibling shape of the
/// placeholder-`max_attempts` idiom `TEST_RETRY_BACKOFF` (9fd38d3),
/// `INTEGRATION_TEST_RETRY_BACKOFF` (e22b0a2), `FLUX_POLL_BACKOFF`
/// (65de62f), `SHINKA_MIGRATION_POLL_BACKOFF` (b962db5), and
/// `HEALTH_ENDPOINT_BACKOFF` (b5db3b6) all use for the same reason.
const HELM_DEP_UPDATE_RETRY_BACKOFF: RetryPolicy = RetryPolicy {
    max_attempts: 1,
    initial_backoff: Duration::from_secs(5),
    factor: 2,
    max_backoff: Duration::from_secs(30),
};

/// Backoff between `helm dependency update` retries, given the 1-indexed
/// local `attempt` counter of the attempt that just failed (the
/// `for attempt in 1..=(DEP_RETRIES + 1)` shape
/// [`helm_dependency_update`] drives).
///
/// Maps the local 1-indexed counter to the 1-indexed
/// [`RetryPolicy::compute_delay`] attempt axis via `saturating_add(1)`:
/// local `attempt == 1` (the pre-retry sleep after the first failed
/// call) reads as `compute_delay(2) = initial_backoff * factor^0 =
/// initial_backoff = 5s`, matching the pre-lift `5 * 1 = 5s` seed
/// verbatim; local `attempt == 2` reads as `compute_delay(3) =
/// initial_backoff * factor^1 = 10s`, matching the pre-lift `5 * 2 =
/// 10s` verbatim; and every deeper retry diverges strictly under the
/// exponential-with-cap discipline. The `saturating_add` clamp
/// forecloses the `u32` overflow class at the bridge — an
/// unlikely-but-possible `attempt == u32::MAX` from a pathological
/// `DEP_RETRIES` budget reads as `compute_delay(u32::MAX)`, which
/// itself saturates to [`HELM_DEP_UPDATE_RETRY_BACKOFF::max_backoff`]
/// via the `checked_pow`-then-cap body inside
/// [`RetryPolicy::compute_delay`] without panic.
fn helm_dep_update_retry_delay(attempt: u32) -> Duration {
    HELM_DEP_UPDATE_RETRY_BACKOFF.compute_delay(attempt.saturating_add(1))
}

/// A digest-pinned placeholder image tag for lint/template validation. Charts
/// under a fedramp-high (or stricter) compliance baseline `fail()` rendering
/// unless the image is digest-pinned (CM-2, SI-7); a bare repository left the
/// tag at the chart default (e.g. `v1.18.0`) and made every such workload chart
/// unlintable. The value is the sha256 of the empty string — a recognizable
/// placeholder that satisfies the digest check; non-compliance charts ignore it.
/// Applied to BOTH `helm lint` and `helm template` so the fail() can't fire in
/// either pass.
const LINT_IMAGE_TAG: &str =
    "image.tag=sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const LINT_IMAGE_REPO: &str = "image.repository=test";

/// Run `program <args>` with a hard wall-clock timeout, inheriting stdio so
/// output still streams to CI. Returns `Ok(true)` on success, `Ok(false)` on a
/// clean non-zero exit, and `Err` if the process had to be killed at the
/// timeout. Generic over the program so the timeout machinery is unit-testable
/// without a real `helm` on PATH.
fn run_program_timed(program: &str, args: &[&str], timeout: Duration) -> Result<bool> {
    let mut child = Command::new(program)
        .args(args)
        .spawn()
        .with_context(|| format!("failed to spawn {} {}", program, args.join(" ")))?;
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status.success());
        }
        if start.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            bail!(
                "{} {} timed out after {}s",
                program,
                args.join(" "),
                timeout.as_secs()
            );
        }
        sleep(Duration::from_millis(50));
    }
}

/// Resolve the `helm` binary path via `HELM_BIN`, falling back to `helm`
/// on `PATH`. Wired through the canonical two-argument
/// [`crate::repo::get_tool_path`]`("HELM_BIN", "helm")` call — the
/// audit-visible env-var-or-fallback lookup every sibling
/// `<tool>_bin()` sigil across forge routes through (`docker_bin` at
/// `infrastructure/docker.rs` 9b1924d, `attic_bin` at
/// `infrastructure/attic.rs` 559adae, `doca_bin` at
/// `infrastructure/registry.rs` 868b2ad, `nix_bin` at `cli/src/nix.rs`
/// 6b2ea15, `cargo_bin` at `commands/comprehensive_release.rs`
/// fceeecc, `nc_bin` at `commands/nix_builder.rs` b5e632a, and the
/// broader `<tool>_bin()` sigil family across the CARGO / NIX_BIN /
/// DOCKER_BIN / BUN_BIN / CRATE2NIX / DOCA_BIN / FLUX_BIN /
/// DOCKER_COMPOSE_BIN surfaces). Mirrors the sibling
/// `git_command_sync` / `kubectl_command_async` / `flux_bin` /
/// `nix_bin` / `attic_bin` primitives — the one bridge between the
/// forge helm surface and the substrate-`mkRuntimeToolsEnv`-exported
/// binary path.
///
/// Pre-lift the sigil body itself spelled the ONE-argument deriving
/// [`crate::tools::get_tool_path`]`(crate::tools::tools::HELM)` form
/// — the constant-driven variant of the same shape pinned as the
/// silent-PATH-fallback bug at
/// [`crate::tools::tests::doca_resolves_from_doca_bin_and_the_deriving_lookup_does_not`].
/// The deriving form maps the constant `tools::HELM` (value `"helm"`)
/// to the env var `HELM_BIN` by uppercase+underscore rule, so for
/// this tool the deriving form happens to resolve the SAME env var
/// as the canonical two-argument form — but the abstraction that
/// decides which env var to read is one hop removed from the
/// audit-visible env-var literal. A fleet-wide `HELM_BIN` grep audit
/// misses this site under the deriving form; a substrate rename of
/// `HELM_BIN` cannot be found mechanically because the string never
/// appears in the source. Migrating the sigil body onto the two-arg
/// form pins the audit-visible literal once at this body and lets
/// the module join the fleet-wide `<tool>_bin()` sigil convention.
/// The pre-lift shape at every call site spelled `"helm"` bare
/// (5 `Command::new` spawns + 4 `run_program_timed` spawns +
/// `run_helm_timed`'s own body); each bypassed the env override, so
/// a Nix-hermetic runner's `HELM_BIN` lost to whatever `helm` was
/// first on PATH.
fn helm_bin() -> String {
    get_tool_path("HELM_BIN", "helm")
}

/// Run `helm <args>` with a hard wall-clock timeout (see [`run_program_timed`]).
/// Resolves the binary via [`helm_bin`] so `HELM_BIN` overrides land.
fn run_helm_timed(args: &[&str], timeout: Duration) -> Result<bool> {
    run_program_timed(&helm_bin(), args, timeout)
}

/// Print a captured [`std::process::Command::output`] result to this
/// process's own stdout/stderr, matching what `.status()` (inherited stdio)
/// would have streamed live. Callers that switch to `.output()` to capture a
/// failure reason must not silently swallow the CI log the operator would
/// otherwise have seen.
fn print_captured_output(stdout: &[u8], stderr: &[u8]) {
    if !stdout.is_empty() {
        print!("{}", String::from_utf8_lossy(stdout));
    }
    if !stderr.is_empty() {
        eprint!("{}", String::from_utf8_lossy(stderr));
    }
}

/// The last non-empty line of a failed command's captured output — stderr
/// first (where helm/OCI errors land, e.g. `403: denied: permission_denied:
/// write_package`), falling back to stdout. Gives a typed error a short,
/// SPECIFIC reason instead of a bare "helm X failed for Y", so a multi-chart
/// batch's final summary can name *why* a chart failed without forcing a
/// reader back into tens of thousands of interleaved CI log lines to find
/// the one relevant to that chart.
fn last_reason_line(stdout: &[u8], stderr: &[u8]) -> String {
    let stderr = String::from_utf8_lossy(stderr);
    let stdout = String::from_utf8_lossy(stdout);
    stderr
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .or_else(|| stdout.lines().rev().find(|l| !l.trim().is_empty()))
        .unwrap_or("(no output captured)")
        .trim()
        .to_string()
}

/// Render a batch's per-chart failures as one bullet each —
/// `  - <chart>: <stage>: <reason>` — so a multi-chart lint/release run's
/// final summary answers "which chart, and why" directly instead of just
/// listing names (the gap that made a real 24/28-chart GHCR-permission
/// failure look like one opaque batch error rather than a clear report).
fn format_failure_summary(failed: &[(String, String)]) -> String {
    failed
        .iter()
        .map(|(name, reason)| format!("  - {name}: {reason}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Boundary-classify a captured `helm` (or peer) [`std::process::Output`]
/// as a typed `Ok(())` / [`bail!`] result: return `Ok(())` when the
/// exit status is a success, or bail with the SPECIFIC per-chart reason
/// `"<context>: <last_reason_line(stdout, stderr)>"` when it is not.
///
/// This is the shared typed primitive the four `if !x_output.status.
/// success() { bail!("{}: {}", <context>, last_reason_line(&x_output.
/// stdout, &x_output.stderr)); }` sites at [`lint`] (both the `helm
/// lint` post-check and the `helm template` post-check), [`package`],
/// and [`push`] collapse onto — four consumers past the ≥3
/// three-times-rule threshold ([THEORY §VI.1](): "two occurrences is
/// a coincidence; three is a law"), so the shape is a law-redeeming
/// consolidation rather than a coincidence.
///
/// Two structural properties the primitive owns at ONE body instead of
/// at four sibling literal positions:
///
/// 1. **Diagnostic prose authorship.** The exact `"<context>: <reason>"`
///    format string lives here (ONE `bail!` body); a future edit that
///    reshapes the separator (`" | "` instead of `": "`) or introduces
///    named args (`{context}` / `{reason}`) lands at one call site and
///    reaches every consumer without drift. Pre-lift, the same three-arg
///    `bail!("{}: {}", <context>, last_reason_line(&x_output.stdout,
///    &x_output.stderr))` shape was authored at four independent literal
///    positions that a factor-out edit or a reason-line refactor would
///    silently diverge across.
/// 2. **Reason-line composition.** Every consumer routes the same
///    `(stdout, stderr)` byte-slice pair through the same
///    [`last_reason_line`] reader — pre-lift, one site's `.stderr`
///    typo (swapping `&x_output.stderr` for `&x_output.stdout`, or
///    losing the trailing `&x_output.stderr` argument to
///    `last_reason_line`) would silently degrade that site's failure
///    diagnostic to the wrong stream without any of the other three
///    sibling sites noticing. Post-lift the composition is authored
///    once at this body and impossible to typo at the consumer side.
///
/// Sibling primitive to [`last_reason_line`] (the reason-line composer)
/// and [`format_failure_summary`] (the batch-summary composer) at the
/// same "helm output → diagnostic prose" surface — this primitive
/// closes the "exit-status → typed Result" boundary at the same surface,
/// so the three helpers together own the whole "helm output → typed
/// per-chart Result" pipeline the four consumer sites drive.
fn ensure_helm_success(output: &std::process::Output, context: &str) -> Result<()> {
    if !output.status.success() {
        bail!(
            "{}: {}",
            context,
            last_reason_line(&output.stdout, &output.stderr)
        );
    }
    Ok(())
}

#[cfg(test)]
mod capture_tests {
    use super::{ensure_helm_success, format_failure_summary, last_reason_line};

    // Build a synthetic `std::process::Output` with the given exit
    // status and captured streams. Used by the `ensure_helm_success`
    // shields; centralized here so the four shields share one builder
    // and a future reshape of the shape (adding a captured signal,
    // widening to `ExitStatusExt`) lands at one place.
    fn make_output(success: bool, stdout: &[u8], stderr: &[u8]) -> std::process::Output {
        use std::os::unix::process::ExitStatusExt;
        std::process::Output {
            status: std::process::ExitStatus::from_raw(if success { 0 } else { 1 << 8 }),
            stdout: stdout.to_vec(),
            stderr: stderr.to_vec(),
        }
    }

    #[test]
    fn last_reason_line_prefers_final_nonblank_stderr_line() {
        let stderr = b"Pushing chart...\nError: failed to perform \"Push\" on destination: 403: denied: permission_denied: write_package\n";
        assert_eq!(
            last_reason_line(b"", stderr),
            "Error: failed to perform \"Push\" on destination: 403: denied: permission_denied: write_package"
        );
    }

    #[test]
    fn last_reason_line_falls_back_to_stdout_when_stderr_empty() {
        assert_eq!(
            last_reason_line(b"final stdout line\n", b""),
            "final stdout line"
        );
    }

    #[test]
    fn last_reason_line_handles_no_output() {
        assert_eq!(last_reason_line(b"", b""), "(no output captured)");
    }

    #[test]
    fn last_reason_line_skips_trailing_blank_lines() {
        let stderr = b"Error: real reason\n\n\n";
        assert_eq!(last_reason_line(b"", stderr), "Error: real reason");
    }

    #[test]
    fn format_failure_summary_renders_one_bullet_per_chart() {
        let failed = vec![
            (
                "pitr-forge".to_string(),
                "push: 403 permission_denied: write_package".to_string(),
            ),
            (
                "lareira-camelot".to_string(),
                "lint: pleme-lib:0.36.0 not found".to_string(),
            ),
        ];
        let out = format_failure_summary(&failed);
        assert_eq!(
            out,
            "  - pitr-forge: push: 403 permission_denied: write_package\n  - lareira-camelot: lint: pleme-lib:0.36.0 not found"
        );
    }

    /// `Ok(())` on a success-status output — the four consumer sites
    /// (`lint`'s `helm lint` post-check, `lint`'s `helm template`
    /// post-check, `package`'s `helm package` post-check, `push`'s
    /// `helm push` post-check) must all pass through unchanged when the
    /// captured process succeeded, regardless of what non-empty stdout
    /// or stderr the process happened to emit.
    #[test]
    fn ensure_helm_success_returns_ok_on_success_status_regardless_of_output_streams() {
        // Empty streams.
        assert!(ensure_helm_success(&make_output(true, b"", b""), "ctx").is_ok());
        // Non-empty stdout only (helm often prints "Manifest generated" on stdout even on success).
        assert!(ensure_helm_success(
            &make_output(true, b"Manifest generated\n", b""),
            "chart-dir"
        )
        .is_ok());
        // Non-empty stderr only (helm dep update chatter often lands on stderr even on success).
        assert!(ensure_helm_success(
            &make_output(
                true,
                b"",
                b"Getting updates for unmanaged Helm repositories...\n"
            ),
            "chart-dir"
        )
        .is_ok());
        // Both streams non-empty (the typical successful case).
        assert!(ensure_helm_success(
            &make_output(
                true,
                b"Successfully packaged chart\n",
                b"Saving 2 charts\nDeleting outdated charts\n"
            ),
            "chart-dir (helm package)"
        )
        .is_ok());
    }

    /// The exact bail-string preservation shield: a failed output must
    /// bail with the SAME prose the pre-lift `bail!("{}: {}", <context>,
    /// last_reason_line(&x_output.stdout, &x_output.stderr))` shape
    /// emitted at each of the four consumer sites, so downstream
    /// operator-facing greps, log-based alert regexes, and typed-error
    /// prose-matching stay stable across the lift. Fail-before-pass-
    /// after: any drift in the format string (a swapped separator, a
    /// reordered `{context}`/`{reason}` position, a stray colon) trips
    /// this shield.
    #[test]
    fn ensure_helm_success_bails_with_exact_pre_lift_prose_on_failure() {
        let out = make_output(
            false,
            b"",
            b"Error: failed to perform \"Push\" on destination: 403: denied: permission_denied: write_package\n",
        );
        let err =
            ensure_helm_success(&out, "my-chart").expect_err("a non-success output must bail");
        assert_eq!(
            err.to_string(),
            "my-chart: Error: failed to perform \"Push\" on destination: 403: denied: permission_denied: write_package",
        );
    }

    /// The reason-line composition shield: the primitive routes
    /// `(stdout, stderr)` through [`last_reason_line`] verbatim
    /// (stderr-first, stdout-fallback), so a `stderr`-empty output
    /// falls back to stdout at exactly the same discipline the sibling
    /// [`last_reason_line`] shields pin. Closes the "wrong-stream typo"
    /// class of defect the pre-lift 4× duplication would have silently
    /// admitted.
    #[test]
    fn ensure_helm_success_reason_line_composition_matches_last_reason_line_discipline() {
        // stderr-empty → stdout fallback.
        let stdout_only = make_output(false, b"final stdout diagnostic\n", b"");
        let err =
            ensure_helm_success(&stdout_only, "ctx-a").expect_err("a non-success output must bail");
        assert_eq!(err.to_string(), "ctx-a: final stdout diagnostic");

        // both empty → "(no output captured)" sentinel.
        let both_empty = make_output(false, b"", b"");
        let err =
            ensure_helm_success(&both_empty, "ctx-b").expect_err("a non-success output must bail");
        assert_eq!(err.to_string(), "ctx-b: (no output captured)");

        // both non-empty → stderr wins.
        let both = make_output(false, b"stdout line\n", b"stderr line\n");
        let err = ensure_helm_success(&both, "ctx-c").expect_err("a non-success output must bail");
        assert_eq!(err.to_string(), "ctx-c: stderr line");
    }

    /// Whole-module production-slice re-fusion shield: post-lift, the
    /// production slice of this module must not contain any bare
    /// `if !x.status.success() { bail!("{}: {}", ..., last_reason_line
    /// (...)) }` shape — every helm-output success/bail check must
    /// consume [`ensure_helm_success`] instead. Slices `SOURCE` at the
    /// `\n#[cfg(test)]\n` marker so this shield's own literal-string
    /// needles (living in `#[cfg(test)]` code below the marker) do not
    /// self-match, and filters `///`/`//!` doc-comment lines that
    /// legitimately name the pre-lift shape as prose so the
    /// `ensure_helm_success` docstring above does not false-fire.
    #[test]
    fn ensure_helm_success_is_the_only_consumer_of_last_reason_line_at_the_bail_site() {
        const SOURCE: &str = include_str!("helm.rs");
        let production = SOURCE
            .split_once("\n#[cfg(test)]\n")
            .map(|(prod, _)| prod)
            .unwrap_or(SOURCE);
        let hits: Vec<(usize, &str)> = production
            .lines()
            .enumerate()
            .filter(|(_, line)| {
                let trimmed = line.trim_start();
                !trimmed.starts_with("///") && !trimmed.starts_with("//!")
            })
            // Match call sites (`last_reason_line(&<expr>.stdout, ...)`),
            // not the definition (`fn last_reason_line(stdout: &[u8],
            // ...) -> ...`): consumer call sites always start with `&`.
            .filter(|(_, line)| line.contains("last_reason_line(&"))
            .collect();
        assert_eq!(
            hits.len(),
            1,
            "post-lift, `last_reason_line(..)` must be called exactly \
             once in the production slice of helm.rs (inside \
             `ensure_helm_success`). Found {} hit(s): {hits:#?}",
            hits.len(),
        );
    }
}

/// `helm dependency update` for a chart, bounded by [`DEP_TIMEOUT_SECS`] and
/// retried [`DEP_RETRIES`] times with exponential-with-cap backoff (see
/// [`HELM_DEP_UPDATE_RETRY_BACKOFF`] + [`helm_dep_update_retry_delay`]). A
/// genuinely unreachable dependency surfaces as a typed error (so the chart
/// is marked failed rather than shipped against unresolved deps); the caller
/// (`release_all`/`lint_all`) records the failure and proceeds to the next
/// chart. file://-only charts resolve offline and exit 0 even when an
/// unrelated repo index is unreachable.
fn helm_dependency_update(chart_dir: &str) -> Result<()> {
    let timeout = Duration::from_secs(DEP_TIMEOUT_SECS);
    let mut last = String::new();
    for attempt in 1..=(DEP_RETRIES + 1) {
        match run_helm_timed(&["dependency", "update", chart_dir], timeout) {
            Ok(true) => return Ok(()),
            Ok(false) => last = "helm dependency update exited non-zero".to_string(),
            Err(e) => last = e.to_string(),
        }
        if attempt <= DEP_RETRIES {
            warn!(
                "helm dependency update attempt {}/{} failed for {} ({}); retrying",
                attempt,
                DEP_RETRIES + 1,
                chart_dir,
                last
            );
            sleep(helm_dep_update_retry_delay(attempt));
        }
    }
    bail!(
        "helm dependency update failed after {} attempts for {}: {}",
        DEP_RETRIES + 1,
        chart_dir,
        last
    )
}

/// Run `helm lint` + `helm template` validation on a chart directory.
///
/// Library charts (type: library) skip `helm template` since they are not
/// directly installable.
pub fn lint(chart_dir: &str) -> Result<()> {
    let chart_path = Path::new(chart_dir);
    if !chart_path.exists() {
        bail!("Chart directory not found: {}", chart_dir);
    }

    info!("Linting chart: {}", chart_dir);

    // Detect library charts — they cannot be templated
    let is_library = {
        let chart_yaml = chart_path.join("Chart.yaml");
        chart_yaml.exists()
            && std::fs::read_to_string(&chart_yaml)
                .unwrap_or_default()
                .lines()
                .any(|line| line.trim() == "type: library")
    };

    // helm dependency update (resolves file:// references + fetches remote
    // subcharts) — bounded + retried so a slow/unreachable upstream fails this
    // chart cleanly instead of hanging the whole release.
    helm_dependency_update(chart_dir)?;

    // Common value arguments for lint + template. The digest-pinned placeholder
    // image (see LINT_IMAGE_TAG) keeps a fedramp-high chart's compliance fail()
    // from firing; an optional `ci/lint-values.yaml` (helm chart-testing
    // convention) supplies any values the chart `required`s to render (e.g.
    // pleme-discord-bot's botName), so a chart can keep its deploy-time guard AND
    // still lint generically.
    let mut value_args: Vec<String> = vec![
        "--set".into(),
        LINT_IMAGE_REPO.into(),
        "--set".into(),
        LINT_IMAGE_TAG.into(),
    ];
    let ci_values = chart_path.join("ci").join("lint-values.yaml");
    if ci_values.exists() {
        value_args.push("-f".into());
        value_args.push(ci_values.to_string_lossy().into_owned());
    }

    // helm lint
    let mut lint_args: Vec<String> = vec!["lint".into(), chart_dir.into()];
    lint_args.extend(value_args.iter().cloned());
    let lint_output = Command::new(helm_bin())
        .args(&lint_args)
        .output()
        .context("Failed to run helm lint")?;
    print_captured_output(&lint_output.stdout, &lint_output.stderr);

    ensure_helm_success(&lint_output, chart_dir)?;

    // helm template (validation) — skip for library charts. Discard rendered
    // stdout (keep stderr for errors): this is an exit-code validation, not a
    // render, and a wrapper chart like lareira-vm-stack emits MEGABYTES of
    // rendered manifests (victoria-metrics-k8s-stack + Grafana dashboards) that
    // otherwise blow past GitHub's per-step log limit, truncating the log and
    // hiding any later chart's real failure.
    if is_library {
        info!("Skipping helm template for library chart");
    } else {
        let mut tmpl_args: Vec<String> = vec!["template".into(), "test".into(), chart_dir.into()];
        tmpl_args.extend(value_args.iter().cloned());
        // stdout stays null'd (never captured, never printed) — a wrapper
        // chart like lareira-vm-stack renders MEGABYTES of manifests that
        // would otherwise sit in memory for no reason. stderr is piped so a
        // failure still gets a real, specific reason attached to the typed
        // error instead of forcing a reader back into the full CI log.
        let template_output = Command::new(helm_bin())
            .args(&tmpl_args)
            .stdout(std::process::Stdio::null())
            .output()
            .context("Failed to run helm template")?;
        print_captured_output(&[], &template_output.stderr);

        ensure_helm_success(&template_output, &format!("{} (helm template)", chart_dir))?;
    }

    info!("Lint passed: {}", chart_dir);
    Ok(())
}

/// Lint with optional library chart workspace isolation.
///
/// If `lib_chart_dir` is provided, creates a temp workspace with the chart
/// and its library dependency for file:// resolution.
pub fn lint_with_lib(
    chart_dir: &str,
    lib_chart_dir: Option<&str>,
    lib_chart_name: &str,
) -> Result<()> {
    match lib_chart_dir {
        Some(lib_dir) => {
            let chart_path = Path::new(chart_dir);
            let chart_name = chart_path
                .file_name()
                .and_then(|n| n.to_str())
                .context("Invalid chart directory name")?;

            let parent_dir = chart_path
                .parent()
                .and_then(|p| p.to_str())
                .context("Invalid chart parent directory")?;

            let (_tmpdir, tmp_chart_path) =
                prepare_chart_workspace(chart_name, parent_dir, Some(lib_dir), lib_chart_name)?;

            lint(&tmp_chart_path)
        }
        None => lint(chart_dir),
    }
}

/// Release with optional library chart workspace isolation.
pub fn release_with_lib(
    chart_dir: &str,
    registry: &str,
    version: Option<&str>,
    lib_chart_dir: Option<&str>,
    lib_chart_name: &str,
) -> Result<()> {
    match lib_chart_dir {
        Some(lib_dir) => {
            let chart_path = Path::new(chart_dir);
            let chart_name = chart_path
                .file_name()
                .and_then(|n| n.to_str())
                .context("Invalid chart directory name")?;

            let parent_dir = chart_path
                .parent()
                .and_then(|p| p.to_str())
                .context("Invalid chart parent directory")?;

            let (_tmpdir, tmp_chart_path) =
                prepare_chart_workspace(chart_name, parent_dir, Some(lib_dir), lib_chart_name)?;

            release(&tmp_chart_path, registry, version)
        }
        None => release(chart_dir, registry, version),
    }
}

/// Package a chart directory into a .tgz tarball.
pub fn package(chart_dir: &str, output: &str, version: Option<&str>) -> Result<String> {
    let chart_path = Path::new(chart_dir);
    if !chart_path.exists() {
        bail!("Chart directory not found: {}", chart_dir);
    }

    std::fs::create_dir_all(output)?;

    info!("Packaging chart: {} → {}", chart_dir, output);

    // Resolve dependencies — but skip the (network) re-fetch when `charts/` is
    // already populated by a prior `lint` pass on this same workspace (the
    // release_all path lints then packages the same temp dir). Avoids a second
    // upstream download per chart and the hang risk that comes with it.
    let charts_sub = chart_path.join("charts");
    let already_resolved = std::fs::read_dir(&charts_sub)
        .map(|mut d| d.next().is_some())
        .unwrap_or(false);
    if !already_resolved {
        helm_dependency_update(chart_dir)?;
    }

    // helm package
    let mut args = vec!["package", chart_dir, "--destination", output];
    let version_str;
    if let Some(v) = version {
        version_str = format!("--version={}", v);
        args.push(&version_str);
    }

    let pkg_output = Command::new(helm_bin())
        .args(&args)
        .output()
        .context("Failed to run helm package")?;
    print_captured_output(&pkg_output.stdout, &pkg_output.stderr);

    ensure_helm_success(&pkg_output, chart_dir)?;

    // Find the generated tarball — use name from Chart.yaml, not the directory
    // basename (which may contain a Nix store hash prefix).
    let chart_yaml = chart_path.join("Chart.yaml");
    let chart_name = if chart_yaml.exists() {
        let content = std::fs::read_to_string(&chart_yaml).unwrap_or_default();
        extract_yaml_field(&content, "name").unwrap_or_else(|_| "chart".to_string())
    } else {
        chart_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("chart")
            .to_string()
    };

    let tgz_path = find_latest_tgz(output, &chart_name)?;
    info!("Packaged: {}", tgz_path);
    Ok(tgz_path)
}

/// Push a chart tarball to an OCI registry.
pub fn push(chart: &str, registry: &str) -> Result<()> {
    if !Path::new(chart).exists() {
        bail!("Chart tarball not found: {}", chart);
    }

    info!("Pushing {} → {}", chart, registry);

    let output = Command::new(helm_bin())
        .args(["push", chart, registry])
        .output()
        .context("Failed to run helm push")?;
    print_captured_output(&output.stdout, &output.stderr);

    ensure_helm_success(&output, chart)?;

    info!("Push succeeded");
    Ok(())
}

/// A parsed chart dependency (name + version + repository).
struct ChartDep {
    name: String,
    version: String,
    repository: String,
}

/// Parse a Chart.yaml's `dependencies:` into name/version/repository triples.
/// Handles both block and flow YAML styles (serde_yaml).
fn parse_deps(chart_yaml_content: &str) -> Vec<ChartDep> {
    #[derive(serde::Deserialize)]
    struct ChartYaml {
        #[serde(default)]
        dependencies: Vec<Dep>,
    }
    #[derive(serde::Deserialize)]
    struct Dep {
        #[serde(default)]
        name: String,
        #[serde(default)]
        version: String,
        #[serde(default)]
        repository: String,
    }
    serde_yaml::from_str::<ChartYaml>(chart_yaml_content)
        .map(|c| {
            c.dependencies
                .into_iter()
                .map(|d| ChartDep {
                    name: d.name,
                    version: d.version,
                    repository: d.repository,
                })
                .collect()
        })
        .unwrap_or_default()
}

/// The canonical pleme-io OCI registry. Third-party Helm subchart deps are
/// transparently routed through this mirror at release time (see
/// [`redirect_remote_deps_to_mirror`]) — the hermetic supply-chain law.
pub const PLEME_OCI_REGISTRY: &str = "oci://ghcr.io/pleme-io/charts";

/// `true` for a third-party (non-pleme-io-OCI) Helm repository — an `http(s)://`
/// repo or an `oci://` repo that is NOT already the pleme-io mirror. These are
/// the deps the mirror copies and the redirect reroutes.
fn is_third_party_repo(repo: &str, registry: &str) -> bool {
    let remote =
        repo.starts_with("http://") || repo.starts_with("https://") || repo.starts_with("oci://");
    remote
        && !repo
            .trim_end_matches('/')
            .starts_with(registry.trim_end_matches('/'))
}

/// Mirror every third-party Helm subchart a wrapper chart depends on into the
/// pleme-io OCI registry, so the auto-release never fetches from a third-party
/// repo at release time (the hermetic supply-chain law).
///
/// Everything is derived from the wrapper charts' own `Chart.yaml` dependencies
/// under `charts_dir` — the operator declares the real upstream + version once,
/// in the dependency, and the substrate mirrors it. There is NO separate catalog
/// to drift. For each `{name, upstreamRepo, version}` dependency whose repository
/// is third-party, the chart is pulled from its upstream and pushed to
/// `registry`. Idempotent: a `(name, version)` already in `registry` is skipped,
/// so only a NEW upstream version ever touches the third-party repo. A repo with
/// no third-party deps is a clean no-op (so the action is safe to run anywhere).
/// Every helm call is bounded by [`DEP_TIMEOUT_SECS`].
pub fn mirror(charts_dir: &str, registry: &str) -> Result<()> {
    // Derive (name, upstream, version) from the wrapper deps themselves.
    let mut wanted: std::collections::BTreeMap<(String, String), String> =
        std::collections::BTreeMap::new();
    for entry in std::fs::read_dir(charts_dir)?.filter_map(std::result::Result::ok) {
        let cy = entry.path().join("Chart.yaml");
        if !cy.exists() {
            continue;
        }
        let content = std::fs::read_to_string(&cy).unwrap_or_default();
        for d in parse_deps(&content) {
            if !d.version.is_empty() && is_third_party_repo(&d.repository, registry) {
                wanted.insert((d.name, d.version), d.repository);
            }
        }
    }
    if wanted.is_empty() {
        info!("Mirror: no third-party subchart deps under {charts_dir} — nothing to mirror");
        return Ok(());
    }

    let timeout = Duration::from_secs(DEP_TIMEOUT_SECS);
    let reg = registry.trim_end_matches('/');
    let mut mirrored = 0u32;
    let mut skipped = 0u32;
    let mut failed: Vec<String> = Vec::new();

    // Per-dependency resilience (matching lint_all/release_all): a single
    // upstream mirror failure — e.g. a brand-new GHCR package name hitting a
    // one-time `403 write_package` permission gap that only closes once a
    // human grants package-creation once — must NOT stop the remaining
    // dependencies from mirroring, and must NOT abort the caller's release
    // pass that runs after this one. Collect failures and continue; bail
    // only once, at the end, with the full list.
    for ((name, version), upstream) in &wanted {
        match mirror_one(name, version, upstream, reg, registry, timeout) {
            Ok(true) => mirrored += 1,
            Ok(false) => skipped += 1,
            Err(e) => {
                warn!("Mirror: {name}:{version} from {upstream} FAILED — {e}; continuing with remaining deps");
                failed.push(format!("{name}:{version} ({e})"));
            }
        }
    }

    info!(
        "Mirror complete: {mirrored} pushed, {skipped} already present, {} failed ({} total)",
        failed.len(),
        wanted.len()
    );

    if !failed.is_empty() {
        bail!(
            "{} upstream subchart(s) failed to mirror (all others above were pushed; if this is a \
             brand-new package name, the GHCR package-creation permission is a one-time manual grant, \
             not a code fix): {}",
            failed.len(),
            failed.join(", ")
        );
    }

    Ok(())
}

/// Mirror a single third-party subchart dependency into `registry`. Returns
/// `Ok(true)` if newly pushed, `Ok(false)` if it was already present (skip).
/// Isolated into its own `Result`-returning function so [`mirror`]'s loop can
/// catch one dependency's failure without aborting the rest.
fn mirror_one(
    name: &str,
    version: &str,
    upstream: &str,
    reg: &str,
    registry: &str,
    timeout: Duration,
) -> Result<bool> {
    // Already mirrored? Shares ONE definition of "already published" with the
    // release path — see `chart_published`.
    if chart_published(reg, name, version, timeout) {
        info!("Mirror: {name}:{version} already in {reg} — skip");
        return Ok(false);
    }

    let tmp = tempfile::tempdir().context("mirror tempdir")?;
    let tmps = tmp.path().to_string_lossy().to_string();

    // Pull from upstream — OCI repos take the chart name in the path, HTTP
    // repos take it via --repo.
    let pulled = if upstream.starts_with("oci://") {
        let r = format!("{}/{}", upstream.trim_end_matches('/'), name);
        run_helm_timed(&["pull", &r, "--version", version, "-d", &tmps], timeout)?
    } else {
        run_helm_timed(
            &[
                "pull",
                name,
                "--repo",
                upstream,
                "--version",
                version,
                "-d",
                &tmps,
            ],
            timeout,
        )?
    };
    if !pulled {
        bail!("helm pull failed for {name} {version} from {upstream}");
    }

    // The pulled tarball name may carry a `v` prefix or differ from
    // {name}-{version}; find the .tgz rather than assume.
    let tgz = std::fs::read_dir(tmp.path())?
        .filter_map(std::result::Result::ok)
        .map(|e| e.path())
        .find(|p| p.extension().is_some_and(|x| x == "tgz"))
        .with_context(|| format!("no .tgz pulled for {name} {version}"))?;

    if !run_helm_timed(&["push", &tgz.to_string_lossy(), registry], timeout)? {
        bail!("helm push failed for {name} {version} → {registry}");
    }
    info!("Mirrored {name}:{version} ({upstream}) → {registry}");
    Ok(true)
}

/// Rewrite a chart's third-party Helm subchart dependency repositories to the
/// pleme-io OCI mirror, in place. Called on the temp workspace copy before
/// `helm dependency update` so the release fetches every subchart from ghcr (which
/// we control) instead of a third-party `*.github.io` repo — the release half of
/// the hermetic supply-chain law. The committed Chart.yaml is left untouched
/// (it honestly declares the real upstream); only the per-release temp copy is
/// rerouted. A no-op when there are no third-party deps. Requires the subchart to
/// have been mirrored first (the `mirror` step / `helm-mirror` action runs ahead
/// of the release).
fn redirect_remote_deps_to_mirror(chart_dir: &Path, registry: &str) -> Result<()> {
    let chart_yaml = chart_dir.join("Chart.yaml");
    if !chart_yaml.exists() {
        return Ok(());
    }
    let original = std::fs::read_to_string(&chart_yaml)?;
    let mut doc: serde_yaml::Value = match serde_yaml::from_str(&original) {
        Ok(v) => v,
        Err(_) => return Ok(()), // leave unparseable Chart.yaml to helm to surface
    };
    let Some(deps) = doc
        .get_mut("dependencies")
        .and_then(|d| d.as_sequence_mut())
    else {
        return Ok(());
    };
    let mut changed = false;
    for dep in deps.iter_mut() {
        let Some(map) = dep.as_mapping_mut() else {
            continue;
        };
        let repo = map
            .get(serde_yaml::Value::from("repository"))
            .and_then(|r| r.as_str())
            .unwrap_or("")
            .to_string();
        if is_third_party_repo(&repo, registry) {
            map.insert(
                serde_yaml::Value::from("repository"),
                serde_yaml::Value::from(registry),
            );
            changed = true;
        }
    }
    if changed {
        let rendered = serde_yaml::to_string(&doc).context("re-serialize redirected Chart.yaml")?;
        std::fs::write(&chart_yaml, rendered).context("write redirected Chart.yaml")?;
        // A stale Chart.lock would now disagree with the rerouted deps; drop it so
        // `helm dependency update` regenerates it against the mirror.
        let lock = chart_dir.join("Chart.lock");
        if lock.exists() {
            let _ = std::fs::remove_file(lock);
        }
    }
    Ok(())
}

/// Deploy a service by updating the HelmRelease image tag in the k8s repo.
pub fn deploy(
    service: &str,
    image_tag: &str,
    k8s_repo: &str,
    environment: &str,
    commit: bool,
    _watch: bool,
) -> Result<()> {
    let k8s_path = Path::new(k8s_repo);
    if !k8s_path.exists() {
        bail!("K8s repo not found: {}", k8s_repo);
    }

    // Find the HelmRelease file for this service
    // Convention: clusters/{cluster}/{category}/{service}/kustomization.yaml patches the HelmRelease
    info!(
        "Deploying {} with tag {} in {} environment",
        service, image_tag, environment
    );

    // Look for kustomization.yaml that patches the HelmRelease
    let cluster = match environment {
        "staging" => "plo",
        "production" => "plo",
        _ => environment,
    };

    // Search for the service's kustomization.yaml in the cluster overlay
    let kustomization_paths = [
        format!(
            "{}/clusters/{}/infrastructure/{}/kustomization.yaml",
            k8s_repo, cluster, service
        ),
        format!(
            "{}/clusters/{}/products/{}/kustomization.yaml",
            k8s_repo, cluster, service
        ),
    ];

    let kustomization_path = kustomization_paths
        .iter()
        .find(|p| Path::new(p).exists())
        .context(format!(
            "No kustomization.yaml found for service '{}' in cluster '{}'",
            service, cluster
        ))?;

    info!("Updating image tag in: {}", kustomization_path);

    // Read the kustomization.yaml
    let content = std::fs::read_to_string(kustomization_path)?;

    // Update the HelmRelease image tag via JSON patch
    // Look for: value: amd64-<hash> and replace with the new tag
    let updated = update_helmrelease_image_tag(&content, image_tag)?;

    std::fs::write(kustomization_path, &updated)?;

    if commit {
        info!("Committing changes...");
        // Binary resolution rides `crate::git::git_command_sync()` so a
        // Nix-hermetic runner's `GIT_BIN` override wins over ambient `PATH`
        // — same discipline the sibling async `commands/push.rs` /
        // `commands/rollback.rs` / `commands/codegen_validation.rs` /
        // `commands/federation.rs` git-mutation sites honor and the same
        // class of bug the free-function-`git` / `GitClient` migrations
        // at 818ed9a / badcdf4 / 8653403 / f6be190 / 81d7486 / 8a1958e
        // redeemed on the async half. Retains the pre-migration `let _ =
        // ….status()` best-effort shape — the deploy path's commit +
        // push are advisory (invoked with `--commit`), and the operator
        // sees the failure via inherited stderr; changing that shape
        // belongs in a separate lift, not in this GIT_BIN-routing pass.
        let _ = crate::git::git_command_sync()
            .args(["add", kustomization_path])
            .current_dir(k8s_repo)
            .status();

        let commit_msg = format!("deploy: update {} to {}", service, image_tag);
        let _ = crate::git::git_command_sync()
            .args(["commit", "-m", &commit_msg])
            .current_dir(k8s_repo)
            .status();

        let _ = crate::git::git_command_sync()
            .args(["push"])
            .current_dir(k8s_repo)
            .status();

        info!("Changes committed and pushed");
    }

    Ok(())
}

/// Full chart lifecycle: lint → package → push.
pub fn release(chart_dir: &str, registry: &str, version: Option<&str>) -> Result<()> {
    info!("=== Lint ===");
    lint(chart_dir)?;

    info!("=== Package ===");
    let tgz = package(chart_dir, "dist", version)?;

    info!("=== Push ===");
    push(&tgz, registry)?;

    info!("=== Release complete ===");
    Ok(())
}

/// Render chart templates for debugging.
pub fn template(chart_dir: &str, values: Option<&str>, set_values: &[String]) -> Result<()> {
    let chart_path = Path::new(chart_dir);
    if !chart_path.exists() {
        bail!("Chart directory not found: {}", chart_dir);
    }

    // helm dependency update (bounded + retried)
    helm_dependency_update(chart_dir)?;

    let mut args = vec![
        "template".to_string(),
        "test".to_string(),
        chart_dir.to_string(),
    ];

    if let Some(v) = values {
        args.push("-f".to_string());
        args.push(v.to_string());
    }

    for sv in set_values {
        args.push("--set".to_string());
        args.push(sv.clone());
    }

    if values.is_none() && set_values.is_empty() {
        args.push("--set".to_string());
        args.push("image.repository=test".to_string());
    }

    let status = Command::new(helm_bin())
        .args(&args.iter().map(|s| s.as_str()).collect::<Vec<_>>())
        .status()
        .context("Failed to run helm template")?;

    if !status.success() {
        bail!("helm template failed for {}", chart_dir);
    }

    Ok(())
}

/// Bump a library chart version and update all dependent Chart.yaml files.
///
/// Workflow:
///   1. Read current version from lib_chart_name/Chart.yaml
///   2. Compute new semver version (patch/minor/major)
///   3. Update library Chart.yaml
///   4. Update all dependent Chart.yaml files that reference the library
///   5. Git commit + tag (unless --no-commit)
///
/// Returns (old_version, new_version).
pub fn bump(
    charts_dir: &str,
    lib_chart_name: &str,
    level: &str,
    commit: bool,
) -> Result<(String, String)> {
    let charts_path = Path::new(charts_dir);
    if !charts_path.exists() {
        bail!("Charts directory not found: {}", charts_dir);
    }

    let lib_chart_yaml = charts_path.join(lib_chart_name).join("Chart.yaml");
    if !lib_chart_yaml.exists() {
        bail!("Library chart not found: {}", lib_chart_yaml.display());
    }

    // Read current version
    let content = std::fs::read_to_string(&lib_chart_yaml)
        .with_context(|| format!("Failed to read {}", lib_chart_yaml.display()))?;

    let old_version = extract_yaml_field(&content, "version")
        .context("Failed to read version from Chart.yaml")?;

    info!("Current version: {}", old_version);

    // Parse and bump through the canonical typed primitive in `crate::version`.
    // Matches the routing `gem::bump` (commands/gem.rs) and `tool::bump`
    // (commands/tool.rs) already perform, closing this site's drift onto the
    // typed `BumpLevel` grammar named at one site (`BumpLevel::from_str`).
    let new_version = version::bump_semver(&old_version, level)?;

    info!("New version:     {}", new_version);

    // Update library chart
    info!("Updating {}/Chart.yaml", lib_chart_name);
    // Ported off the `format!`-rebuilt-needle + `content.replace` shape onto
    // `version::write_chart_version` — the splice-over-matched-byte-span
    // Chart.yaml writer landed at 3bc0885, whose contract is the CSE
    // trap-3 rule in this crate's CLAUDE.md (§ "Version bumping"): never
    // rebuild the needle with `format!` and pass it to `content.replace`,
    // because the reader tolerates whitespace and quotes the reconstruction
    // does not, so the write silently no-ops AND reports success.
    //
    // The specific pre-port trap this site carried: `format!("version: {}",
    // old_version)` hardcodes ONE space between `version:` and the value
    // and drops any surrounding quotes, so a Chart.yaml authored as
    // `version: "0.4.2"` (fleet-observed on the openshift-helmchart
    // vendored family — 93c3818's population) or `version:  0.4.2`
    // (aligned) reads fine through `extract_yaml_field` (which
    // `.trim_matches('"').trim()`s on the way in) and then silently
    // no-ops on write while returning `Ok`. The typed writer splices
    // only the value bytes at the matched span and carries a
    // verified-mutation seal, so the mutation cannot report success
    // without changing the file. The two `bump_routing_tests` regression
    // seals below pin both fleet-observed shapes.
    version::write_chart_version(&lib_chart_yaml, &new_version)
        .with_context(|| format!("Failed to write version to {}", lib_chart_yaml.display()))?;

    // Update all dependent charts
    let mut updated_count = 0u32;
    for entry in std::fs::read_dir(charts_path)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }

        let dir_name = entry.file_name();
        let dir_name_str = dir_name.to_string_lossy();
        if dir_name_str == lib_chart_name {
            continue;
        }

        let dep_chart_yaml = entry.path().join("Chart.yaml");
        if !dep_chart_yaml.exists() {
            continue;
        }

        // Route the dependency-pin update through the typed writer — same
        // trap-3 shape closed at 3bc0885 / eb10657 for the chart's OWN
        // version, now closed for the nested pin. The pre-port form was:
        //
        //     let old_dep = format!("version: \"{}\"", old_version);
        //     let new_dep = format!("version: \"{}\"", new_version);
        //     if dep_content.contains(&old_dep)
        //         && dep_content.contains(&format!("name: {}", lib_chart_name))
        //     { let updated = dep_content.replace(&old_dep, &new_dep); ... }
        //
        // That `format!`-rebuilt needle hardcoded a double-quoted single-space
        // shape, so `version: 0.4.2` (unquoted, the majority form),
        // `version: '0.4.2'` (single-quoted), and `version:  "0.4.2"` (aligned)
        // silently no-op'd on write while `bump` returned `Ok`. Worse than the
        // top-level trap: the pre-`contains` guard suppressed the write
        // ENTIRELY rather than merely no-op'ing after a false-hit, so a
        // dependent chart's `updated_count += 1` never fired and the caller
        // was told the dep was NOT PRESENT rather than that the write failed —
        // silent-skip instead of silent-no-op-with-success. The typed writer
        // parses the `dependencies:` list via serde_yaml (enforcing uniqueness
        // of the name across entries) and splices the value bytes at the
        // matched entry's version-line span, so every fleet-observed form
        // routes through the same discipline and the verified-mutation seal
        // proves the delta before returning. `Ok(false)` from the writer
        // means "this chart has no dependency named `lib_chart_name`", which
        // is the legitimate no-op the pre-port guard was trying to express;
        // any structural error (malformed YAML, two entries share the name,
        // the entry lacks a version field) becomes a hard error rather than
        // a silent skip.
        let written =
            version::write_chart_dependency_version(&dep_chart_yaml, lib_chart_name, &new_version)
                .with_context(|| {
                    format!(
                        "Failed to update dependency pin in {}",
                        dep_chart_yaml.display()
                    )
                })?;
        if written {
            info!("Updating {}/Chart.yaml", dir_name_str);
            updated_count += 1;
        }
    }

    info!(
        "Updated {} + {} dependent charts",
        lib_chart_name, updated_count
    );

    if commit {
        info!("Committing changes...");
        // Binary resolution rides `crate::git::git_command_sync()` so a
        // Nix-hermetic runner's `GIT_BIN` override wins over ambient
        // `PATH` — same discipline the sibling sync
        // `commands/helm.rs::deploy` / `config/mod::resolve_k8s_repo_root`
        // / `commands/e2e.rs::resolve_repo_root` sites honor and the
        // same class of bug the async free-function-`git` / `GitClient`
        // / `commands/federation.rs` / `commands/push.rs` /
        // `commands/codegen_validation.rs` / `commands/rollback.rs`
        // migrations at 818ed9a / badcdf4 / 8653403 / f6be190 /
        // 81d7486 / 8a1958e redeemed on the async half. Retains the
        // pre-migration `.status()` / `bail!`-on-failure shape verbatim.
        // Find repo root
        let repo_root = crate::git::git_command_sync()
            .args(["rev-parse", "--show-toplevel"])
            .output()
            .context("Failed to run git rev-parse")?;

        let repo_root = String::from_utf8(repo_root.stdout)?.trim().to_string();

        let status = crate::git::git_command_sync()
            .args(["add", &format!("{}/*/Chart.yaml", charts_dir)])
            .current_dir(&repo_root)
            .status()
            .context("Failed to git add")?;

        if !status.success() {
            // Fallback: add individual files
            let _ = crate::git::git_command_sync()
                .args(["add", "-A", charts_dir])
                .current_dir(&repo_root)
                .status();
        }

        let commit_msg = format!("release: {} v{}", lib_chart_name, new_version);
        let status = crate::git::git_command_sync()
            .args(["commit", "-m", &commit_msg])
            .current_dir(&repo_root)
            .status()
            .context("Failed to git commit")?;

        if !status.success() {
            bail!("git commit failed");
        }

        let tag = format!("v{}", new_version);
        let status = crate::git::git_command_sync()
            .args(["tag", &tag])
            .current_dir(&repo_root)
            .status()
            .context("Failed to git tag")?;

        if !status.success() {
            warn!("git tag failed (tag may already exist)");
        }

        info!("Tagged {}", tag);
        info!("Next: git push && git push --tags");
    }

    Ok((old_version, new_version))
}

/// Read `version:` from a chart directory's `Chart.yaml`.
fn chart_version_at(chart_dir: &str) -> Result<String> {
    let content = std::fs::read_to_string(Path::new(chart_dir).join("Chart.yaml"))
        .with_context(|| format!("read Chart.yaml in {chart_dir}"))?;
    extract_yaml_field(&content, "version")
}

/// Package + push the library chart itself.
///
/// `Ok(Some(version))` = published, `Ok(None)` = already present (skipped).
///
/// A `type: library` chart has no templates of its own to render, so it is
/// NOT linted here — `helm lint` on a library chart reports no-templates as
/// a failure, which is exactly the kind of false red that would tempt the
/// next person to exclude it again. It is packaged and pushed directly.
fn release_lib_chart(
    charts_dir: &str,
    lib_chart_dir: Option<&str>,
    lib_chart_name: &str,
    registry: &str,
    output_dir: &str,
) -> Result<Option<String>> {
    let lib_path = match lib_chart_dir {
        Some(d) => PathBuf::from(d),
        None => Path::new(charts_dir).join(lib_chart_name),
    };
    if !lib_path.join("Chart.yaml").exists() {
        bail!("library chart not found at {}", lib_path.display());
    }
    // Per-chart opt-out applies to the LIBRARY chart too.
    //
    // Without this, publishing the lib (added in the same change that made
    // release_all publish it at all) would push ANY chart that happens to sit
    // at `<charts>/<lib_chart_name>` — including a private VENDORED FORK. That
    // is not hypothetical: helmworks-akeyless carries a tracked
    // `charts/pleme-lib` fork at 0.16.0, and a release there would have
    // injected a bogus `pleme-lib 0.16.0` into the SHARED
    // oci://ghcr.io/pleme-io/charts, where published versions are immutable and
    // therefore not cleanly removable.
    //
    // A repo whose lib chart is a fork declares
    // `annotations: { pleme.io/oci-auto-release: "false" }` and is skipped —
    // the same escape hatch dependents already had.
    if chart_oci_auto_release_disabled(&lib_path) {
        info!(
            "Skipping {} (pleme.io/oci-auto-release: \"false\") — library chart not published",
            lib_chart_name
        );
        return Ok(None);
    }

    let lib_str = lib_path.to_string_lossy().to_string();
    let version = chart_version_at(&lib_str)?;

    println!();
    println!("==========================================");
    println!("  Releasing {lib_chart_name} {version} (library)");
    println!("==========================================");

    if !republish_enabled()
        && chart_published(
            registry,
            lib_chart_name,
            &version,
            Duration::from_secs(DEP_TIMEOUT_SECS),
        )
    {
        println!("SKIP: {lib_chart_name} {version} already published (immutable)");
        return Ok(None);
    }

    let tgz = package(&lib_str, output_dir, None)?;
    push(&tgz, registry)?;
    println!("DONE: {lib_chart_name} {version}");
    Ok(Some(version))
}

/// Is `(name, version)` already published to `reg`?
///
/// `helm show chart <ref> --version <v>` succeeds iff the ref exists, so a
/// failure is read as "absent". Deliberately fail-OPEN (absent on error): a
/// registry hiccup must produce a redundant push, never a silent skip that
/// looks like a successful release.
///
/// This is the probe `release_all` was missing. Both the helmworks and the
/// substrate `helm-monorepo-auto-release.yml` headers already CLAIM the
/// release path "404-probes each (name, version) and SKIPS anything already
/// published" — it never did; only `mirror` probed. Extracted here so the
/// two paths share ONE definition of "already published" rather than the
/// docs describing a second, imaginary one.
fn chart_published(reg: &str, name: &str, version: &str, timeout: Duration) -> bool {
    let oci_ref = format!("{reg}/{name}");
    run_helm_timed(&["show", "chart", &oci_ref, "--version", version], timeout).unwrap_or(false)
}

/// Should an already-published `(name, version)` be pushed over?
///
/// Off by default — a published chart version is immutable, which is what
/// makes `version:` in a HelmRelease mean anything. `FORGE_HELM_REPUBLISH=1`
/// re-enables the old overwrite-always behaviour for the rare case of
/// repairing a corrupt upload (configure-off, not delete).
fn republish_enabled() -> bool {
    std::env::var("FORGE_HELM_REPUBLISH").is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
}

/// Discover chart directories inside a parent directory.
///
/// Returns chart names that have a Chart.yaml, excluding `exclude_name`.
fn discover_charts(charts_dir: &str, exclude_name: &str) -> Result<Vec<String>> {
    let dir = Path::new(charts_dir);
    if !dir.exists() {
        bail!("Charts directory not found: {}", charts_dir);
    }

    let mut charts: Vec<String> = Vec::new();
    for entry in std::fs::read_dir(dir)?.filter_map(std::result::Result::ok) {
        if !entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        if name == exclude_name || !entry.path().join("Chart.yaml").exists() {
            continue;
        }
        // Per-chart opt-out: a digest-substituted / GitOps-local chart (not a
        // generic OCI library chart — e.g. it pins an all-zero placeholder image
        // digest a separate flow substitutes at release) declares
        // `annotations: { pleme.io/oci-auto-release: "false" }` and is skipped.
        // Logged, never silently dropped (no-silent-caps).
        if chart_oci_auto_release_disabled(&entry.path()) {
            info!("Skipping {} (pleme.io/oci-auto-release: \"false\")", name);
            continue;
        }
        charts.push(name);
    }

    charts.sort();
    Ok(charts)
}

/// Whether a chart opts OUT of OCI auto-release via
/// `annotations["pleme.io/oci-auto-release"] == "false"` in its Chart.yaml.
fn chart_oci_auto_release_disabled(chart_dir: &Path) -> bool {
    #[derive(serde::Deserialize)]
    struct ChartYaml {
        #[serde(default)]
        annotations: std::collections::BTreeMap<String, String>,
    }
    std::fs::read_to_string(chart_dir.join("Chart.yaml"))
        .ok()
        .and_then(|c| serde_yaml::from_str::<ChartYaml>(&c).ok())
        .and_then(|c| c.annotations.get("pleme.io/oci-auto-release").cloned())
        .map(|v| v == "false")
        .unwrap_or(false)
}

/// Prepare a temp directory with a chart and its library dependency.
///
/// Copies the chart and (optionally) the library chart into a temp dir
/// so `helm dependency update` can resolve `file://` references.
/// Returns (temp_dir_path, chart_path_inside_temp).
fn prepare_chart_workspace(
    chart_name: &str,
    charts_dir: &str,
    lib_chart_dir: Option<&str>,
    lib_chart_name: &str,
) -> Result<(tempfile::TempDir, String)> {
    let tmpdir = tempfile::tempdir().context("Failed to create temp directory")?;
    let tmp_path = tmpdir.path();

    // Copy chart
    let src_chart = Path::new(charts_dir).join(chart_name);
    let dst_chart = tmp_path.join(chart_name);
    copy_dir_recursive(&src_chart, &dst_chart)
        .with_context(|| format!("Failed to copy chart {}", chart_name))?;

    // Copy library chart (either from external dir or from charts_dir)
    let lib_src = match lib_chart_dir {
        Some(ext) => Path::new(ext).to_path_buf(),
        None => Path::new(charts_dir).join(lib_chart_name),
    };

    if lib_src.exists() {
        let dst_lib = tmp_path.join(lib_chart_name);
        copy_dir_recursive(&lib_src, &dst_lib)
            .with_context(|| format!("Failed to copy library chart from {}", lib_src.display()))?;
    }

    // Stage the chart's file:// SIBLING chart deps (anything beyond the lib
    // chart) as flat siblings in the temp dir, recursively — so a wrapper chart
    // (e.g. lareira-jellyfin → file://../pleme-lareira → file://../pleme-microservice)
    // resolves every `file://../X` to tmp/X under helm dependency update. Without
    // this the tmp-copy isolates the chart away from its siblings and lint fails
    // with "directory .../pleme-lareira not found". The lib chart + the chart
    // itself are already staged, so seed `copied` with them to avoid re-copy / loops.
    let mut copied: std::collections::HashSet<String> =
        [chart_name.to_string(), lib_chart_name.to_string()]
            .into_iter()
            .collect();
    stage_file_sibling_deps(&src_chart, tmp_path, &mut copied)?;

    // Hermetic supply-chain law: reroute any third-party subchart deps in the
    // TEMP copy to the pleme-io OCI mirror, so lint/package/release fetch from
    // ghcr (which we control), never from a third-party repo. The committed
    // Chart.yaml keeps declaring the real upstream; only this per-release copy is
    // redirected. Requires the subchart to have been mirrored first.
    redirect_remote_deps_to_mirror(&dst_chart, PLEME_OCI_REGISTRY)?;

    let chart_path = dst_chart.to_string_lossy().to_string();
    Ok((tmpdir, chart_path))
}

/// The `file://` repository paths declared in a Chart.yaml's `dependencies`.
/// Parsed with serde_yaml so BOTH block style (`repository: file://…` on its own
/// line) AND flow style (`- {name: …, repository: "file://…"}` inline) are
/// caught — a line-scan misses the flow form and was leaving siblings unstaged.
fn file_dep_paths(chart_yaml_content: &str) -> Vec<String> {
    #[derive(serde::Deserialize)]
    struct ChartYaml {
        #[serde(default)]
        dependencies: Vec<Dep>,
    }
    #[derive(serde::Deserialize)]
    struct Dep {
        #[serde(default)]
        repository: String,
    }
    serde_yaml::from_str::<ChartYaml>(chart_yaml_content)
        .map(|c| {
            c.dependencies
                .into_iter()
                .map(|d| d.repository)
                .filter(|r| r.starts_with("file://"))
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod file_dep_tests {
    use super::file_dep_paths;

    #[test]
    fn parses_block_and_flow_dependency_styles() {
        let block =
            "dependencies:\n  - name: pleme-lareira\n    repository: \"file://../pleme-lareira\"\n";
        assert_eq!(file_dep_paths(block), vec!["file://../pleme-lareira"]);

        let flow = "dependencies:\n  - {name: pleme-lareira, version: \"~0.1.0\", repository: \"file://../pleme-lareira\"}\n";
        assert_eq!(file_dep_paths(flow), vec!["file://../pleme-lareira"]);

        // OCI/HTTP repos are not file:// and must be ignored; no deps → empty.
        let oci = "dependencies:\n  - name: pleme-lib\n    repository: \"oci://ghcr.io/pleme-io/charts\"\n";
        assert!(file_dep_paths(oci).is_empty());
        assert!(file_dep_paths("name: x\nversion: 0.1.0\n").is_empty());
    }
}

#[cfg(test)]
mod release_publish_tests {
    use super::{
        chart_oci_auto_release_disabled, chart_version_at, discover_charts, republish_enabled,
    };

    #[test]
    fn chart_version_at_reads_the_chart_yaml() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("Chart.yaml"),
            "apiVersion: v2\nname: pleme-lib\ntype: library\nversion: 0.42.0\n",
        )
        .unwrap();
        assert_eq!(
            chart_version_at(&dir.path().to_string_lossy()).unwrap(),
            "0.42.0"
        );
    }

    #[test]
    fn chart_version_at_errors_when_there_is_no_chart_yaml() {
        let dir = tempfile::tempdir().unwrap();
        assert!(chart_version_at(&dir.path().to_string_lossy()).is_err());
    }

    /// Immutability is the DEFAULT. If this ever flips, `version:` in a
    /// HelmRelease silently stops pinning bytes — which is the exact defect
    /// this pair of changes exists to close.
    #[test]
    fn republish_is_off_unless_explicitly_enabled() {
        // SAFETY: single-threaded scope; restored before returning.
        let prev = std::env::var("FORGE_HELM_REPUBLISH").ok();
        unsafe { std::env::remove_var("FORGE_HELM_REPUBLISH") };
        assert!(!republish_enabled(), "republish must default to OFF");

        unsafe { std::env::set_var("FORGE_HELM_REPUBLISH", "1") };
        assert!(republish_enabled(), "=1 must enable");
        unsafe { std::env::set_var("FORGE_HELM_REPUBLISH", "true") };
        assert!(republish_enabled(), "=true must enable");
        unsafe { std::env::set_var("FORGE_HELM_REPUBLISH", "0") };
        assert!(!republish_enabled(), "=0 must NOT enable");
        unsafe { std::env::set_var("FORGE_HELM_REPUBLISH", "yes") };
        assert!(
            !republish_enabled(),
            "an unrecognised value must NOT enable"
        );

        match prev {
            Some(v) => unsafe { std::env::set_var("FORGE_HELM_REPUBLISH", v) },
            None => unsafe { std::env::remove_var("FORGE_HELM_REPUBLISH") },
        }
    }

    /// `discover_charts` still excludes the library chart from the DEPENDENT
    /// list — that part was always correct. What was missing is that nothing
    /// released it separately; `release_all` now does, before the dependents.
    /// A forked library chart must NOT be publishable to the shared registry.
    /// Guards the hazard that publishing the lib at all introduced: a repo
    /// carrying its own `charts/pleme-lib` fork would otherwise inject a bogus
    /// version into oci://ghcr.io/pleme-io/charts, where versions are
    /// immutable and cannot be cleanly withdrawn.
    #[test]
    fn a_lib_chart_can_opt_out_of_publishing() {
        let dir = tempfile::tempdir().unwrap();
        let lib = dir.path().join("pleme-lib");
        std::fs::create_dir_all(&lib).unwrap();
        std::fs::write(
            lib.join("Chart.yaml"),
            "apiVersion: v2\nname: pleme-lib\ntype: library\nversion: 0.16.0\n\
             annotations:\n  pleme.io/oci-auto-release: \"false\"\n",
        )
        .unwrap();
        assert!(
            chart_oci_auto_release_disabled(&lib),
            "an opted-out library chart must be detected as such"
        );

        // And the default (no annotation) must still publish.
        let lib2 = dir.path().join("pleme-lib2");
        std::fs::create_dir_all(&lib2).unwrap();
        std::fs::write(
            lib2.join("Chart.yaml"),
            "apiVersion: v2\nname: pleme-lib\ntype: library\nversion: 0.42.0\n",
        )
        .unwrap();
        assert!(
            !chart_oci_auto_release_disabled(&lib2),
            "default must publish"
        );
    }

    #[test]
    fn discover_still_excludes_the_lib_from_dependents() {
        let dir = tempfile::tempdir().unwrap();
        for c in ["pleme-lib", "pleme-nats", "pleme-vector"] {
            let d = dir.path().join(c);
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join("Chart.yaml"), format!("name: {c}\nversion: 0.1.0\n")).unwrap();
        }
        let found = discover_charts(&dir.path().to_string_lossy(), "pleme-lib").unwrap();
        assert!(
            !found.contains(&"pleme-lib".to_string()),
            "lib must not be a dependent"
        );
        assert_eq!(found.len(), 2);
    }
}

#[cfg(test)]
mod parse_deps_tests {
    use super::parse_deps;

    #[test]
    fn extracts_name_version_repository_for_mirror() {
        // A wrapper chart with a remote subchart + a file:// lib — the mirror only
        // cares about (name, version); repository is carried for the http/oci split.
        let cy = "\
apiVersion: v2
name: lareira-vm-stack
version: 0.1.0
dependencies:
  - name: pleme-lib
    version: \">=0.18.1 <0.19.0\"
    repository: \"file://../pleme-lib\"
  - name: victoria-metrics-k8s-stack
    version: \"0.39.0\"
    repository: \"https://victoriametrics.github.io/helm-charts/\"
";
        let deps = parse_deps(cy);
        assert_eq!(deps.len(), 2);
        let vm = deps
            .iter()
            .find(|d| d.name == "victoria-metrics-k8s-stack")
            .unwrap();
        assert_eq!(vm.version, "0.39.0");
        assert_eq!(
            vm.repository,
            "https://victoriametrics.github.io/helm-charts/"
        );
        // flow style + a v-prefixed version (cert-manager shape) parses too.
        let flow = "dependencies:\n  - {name: cert-manager, version: \"v1.17.1\", repository: \"https://charts.jetstack.io\"}\n";
        let d = parse_deps(flow);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].name, "cert-manager");
        assert_eq!(d[0].version, "v1.17.1");
        // no deps → empty, never panics.
        assert!(parse_deps("name: x\n").is_empty());
    }
}

#[cfg(test)]
mod hermetic_mirror_tests {
    use super::{is_third_party_repo, redirect_remote_deps_to_mirror, PLEME_OCI_REGISTRY};

    #[test]
    fn classifies_third_party_repos() {
        let reg = PLEME_OCI_REGISTRY;
        // third-party: any http(s) repo, or an oci repo that is NOT the mirror.
        assert!(is_third_party_repo("https://charts.jetstack.io", reg));
        assert!(is_third_party_repo("http://example.com/charts", reg));
        assert!(is_third_party_repo(
            "oci://ghcr.io/actions/actions-runner-controller-charts",
            reg
        ));
        // NOT third-party: file:// siblings, and the mirror itself (with/without slash).
        assert!(!is_third_party_repo("file://../pleme-lib", reg));
        assert!(!is_third_party_repo("oci://ghcr.io/pleme-io/charts", reg));
        assert!(!is_third_party_repo("oci://ghcr.io/pleme-io/charts/", reg));
        assert!(!is_third_party_repo("", reg));
    }

    #[test]
    fn redirect_reroutes_third_party_keeps_file_and_drops_lock() {
        let dir = tempfile::tempdir().unwrap();
        let chart = dir.path();
        std::fs::write(
            chart.join("Chart.yaml"),
            "apiVersion: v2\nname: w\nversion: 0.1.0\ndependencies:\n  - name: pleme-lib\n    version: \">=0.18.1 <0.19.0\"\n    repository: \"file://../pleme-lib\"\n  - name: victoria-metrics-k8s-stack\n    version: \"0.39.0\"\n    repository: \"https://victoriametrics.github.io/helm-charts/\"\n",
        )
        .unwrap();
        std::fs::write(chart.join("Chart.lock"), "stale\n").unwrap();

        redirect_remote_deps_to_mirror(chart, PLEME_OCI_REGISTRY).unwrap();

        let out = std::fs::read_to_string(chart.join("Chart.yaml")).unwrap();
        let deps = super::parse_deps(&out);
        let lib = deps.iter().find(|d| d.name == "pleme-lib").unwrap();
        let vm = deps
            .iter()
            .find(|d| d.name == "victoria-metrics-k8s-stack")
            .unwrap();
        // file:// dep is left untouched; the third-party dep is rerouted to the mirror.
        assert_eq!(lib.repository, "file://../pleme-lib");
        assert_eq!(vm.repository, PLEME_OCI_REGISTRY);
        // the now-stale lock is removed so helm regenerates against the mirror.
        assert!(!chart.join("Chart.lock").exists());
    }

    #[test]
    fn redirect_is_noop_without_third_party_deps() {
        let dir = tempfile::tempdir().unwrap();
        let chart = dir.path();
        std::fs::write(
            chart.join("Chart.yaml"),
            "apiVersion: v2\nname: w\nversion: 0.1.0\ndependencies:\n  - name: pleme-lib\n    version: \">=0.18.1 <0.19.0\"\n    repository: \"file://../pleme-lib\"\n",
        )
        .unwrap();
        std::fs::write(chart.join("Chart.lock"), "keep\n").unwrap();
        redirect_remote_deps_to_mirror(chart, PLEME_OCI_REGISTRY).unwrap();
        // nothing rerouted ⇒ the lock is preserved.
        assert_eq!(
            std::fs::read_to_string(chart.join("Chart.lock")).unwrap(),
            "keep\n"
        );
    }
}

#[cfg(test)]
mod timeout_tests {
    use super::run_program_timed;
    use std::time::Duration;

    #[test]
    fn fast_success_returns_ok_true() {
        // `true` exits 0 immediately, well within the timeout.
        assert!(run_program_timed("true", &[], Duration::from_secs(5)).unwrap());
    }

    #[test]
    fn clean_nonzero_returns_ok_false() {
        // `false` exits 1 — a clean non-zero, not a timeout-kill.
        assert!(!run_program_timed("false", &[], Duration::from_secs(5)).unwrap());
    }

    #[test]
    fn slow_process_is_killed_at_timeout() {
        // `sleep 5` cannot finish within a 1s cap — the process is killed and a
        // typed timeout error is returned (the property that stops a hung
        // upstream from wedging the release).
        let err = run_program_timed("sleep", &["5"], Duration::from_secs(1)).unwrap_err();
        assert!(err.to_string().contains("timed out"), "got: {err}");
    }
}

/// Recursively copy a chart's `file://` sibling chart dependencies into `tmp_path`
/// as flat siblings (matching helm's `file://../X` resolution from the copied
/// chart). `copied` tracks already-staged chart dir names so a dep shared by many
/// wrappers (pleme-lareira, pleme-microservice, …) is copied once and cycles
/// terminate. `chart_src` is the dep's ORIGINAL on-disk dir, so nested file://
/// deps resolve against the real charts directory.
fn stage_file_sibling_deps(
    chart_src: &Path,
    tmp_path: &Path,
    copied: &mut std::collections::HashSet<String>,
) -> Result<()> {
    let chart_yaml = chart_src.join("Chart.yaml");
    if !chart_yaml.exists() {
        return Ok(());
    }
    let content = std::fs::read_to_string(&chart_yaml)
        .with_context(|| format!("Failed to read {}", chart_yaml.display()))?;

    for rel in file_dep_paths(&content) {
        let rel_path = rel.strip_prefix("file://").unwrap_or(&rel);
        let dep_src = match chart_src.join(rel_path).canonicalize() {
            Ok(p) => p,
            Err(_) => continue, // unresolved file:// dep — let helm surface it
        };
        let Some(dep_name) = dep_src.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if copied.contains(dep_name) || !dep_src.is_dir() {
            continue;
        }
        copy_dir_recursive(&dep_src, &tmp_path.join(dep_name))
            .with_context(|| format!("Failed to copy sibling chart dep {}", dep_name))?;
        copied.insert(dep_name.to_string());
        // Recurse against the dep's ORIGINAL dir so ITS file:// siblings resolve.
        stage_file_sibling_deps(&dep_src, tmp_path, copied)?;
    }
    Ok(())
}

/// Recursively copy a directory.
fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let dst_path = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_dir_recursive(&entry.path(), &dst_path)?;
        } else {
            std::fs::copy(entry.path(), dst_path)?;
        }
    }
    Ok(())
}

/// Lint all charts in a directory.
///
/// Discovers charts, sets up temp workspaces with library dependencies,
/// and runs lint on each. Returns error if any chart fails.
pub fn lint_all(charts_dir: &str, lib_chart_dir: Option<&str>, lib_chart_name: &str) -> Result<()> {
    let charts = discover_charts(charts_dir, lib_chart_name)?;
    if charts.is_empty() {
        bail!("No charts found in {}", charts_dir);
    }

    info!("Discovered {} charts: {}", charts.len(), charts.join(", "));

    let mut failed: Vec<(String, String)> = Vec::new();

    for chart_name in &charts {
        println!();
        println!("==========================================");
        println!("  Linting {}", chart_name);
        println!("==========================================");

        // Workspace prep is isolated too — a single chart's copy/stage/
        // redirect failure must not `?`-abort the remaining charts, same as
        // the lint step below.
        let (_tmpdir, chart_path) =
            match prepare_chart_workspace(chart_name, charts_dir, lib_chart_dir, lib_chart_name) {
                Ok(v) => v,
                Err(e) => {
                    println!("FAIL: {} workspace prep — {}", chart_name, e);
                    failed.push((chart_name.clone(), format!("workspace prep: {e}")));
                    continue;
                }
            };

        match lint(&chart_path) {
            Ok(()) => println!("PASS: {}", chart_name),
            Err(e) => {
                println!("FAIL: {} — {}", chart_name, e);
                failed.push((chart_name.clone(), format!("lint: {e}")));
            }
        }
    }

    println!();
    if failed.is_empty() {
        info!("All {} charts passed lint", charts.len());
        Ok(())
    } else {
        bail!(
            "{}/{} chart(s) failed lint — every chart was still linted independently:\n{}",
            failed.len(),
            charts.len(),
            format_failure_summary(&failed)
        )
    }
}

/// Release all charts: lint → package → push to OCI registry.
///
/// Discovers charts, sets up temp workspaces, and runs the full
/// release lifecycle for each chart.
pub fn release_all(
    charts_dir: &str,
    lib_chart_dir: Option<&str>,
    lib_chart_name: &str,
    registry: &str,
) -> Result<()> {
    let charts = discover_charts(charts_dir, lib_chart_name)?;
    if charts.is_empty() {
        bail!("No charts found in {}", charts_dir);
    }

    info!("Discovered {} charts: {}", charts.len(), charts.join(", "));

    let output_dir = "dist";
    std::fs::create_dir_all(output_dir)?;

    let mut failed: Vec<(String, String)> = Vec::new();
    let mut released = Vec::new();
    let mut skipped: Vec<String> = Vec::new();

    // ── The library chart ships FIRST, and it ships at all ──────────────
    // `discover_charts` excludes it by name (correct — dependents get it
    // copied into their workspace, so it must not be released as one of
    // them). But nothing released it SEPARATELY either, so the baseline
    // library was never published: GHCR sat at 0.40.1 while git reached
    // 0.42.0, and any consumer OUTSIDE this monorepo — which resolves it
    // over OCI rather than `file://../pleme-lib` — was capped there with no
    // path forward. That is what drove helmworks-akeyless to vendor a
    // 0.16.0 fork.
    //
    // It goes first because dependents resolve against it.
    match release_lib_chart(
        charts_dir,
        lib_chart_dir,
        lib_chart_name,
        registry,
        output_dir,
    ) {
        Ok(Some(v)) => released.push(format!("{lib_chart_name} (library) {v}")),
        Ok(None) => skipped.push(format!("{lib_chart_name} (library, already published)")),
        Err(e) => {
            println!("FAIL: {lib_chart_name} (library) — {e}");
            failed.push((lib_chart_name.to_string(), format!("library chart: {e}")));
        }
    }

    for chart_name in &charts {
        println!();
        println!("==========================================");
        println!("  Releasing {}", chart_name);
        println!("==========================================");

        // Every chart is independent from here down: a failure at ANY stage
        // (workspace prep / lint / package / push) records the chart + a
        // specific reason and `continue`s to the next chart. Nothing in this
        // loop is allowed to `?`-propagate and abort the batch — one chart's
        // GHCR permission gap or bad dependency version must never prevent
        // an unrelated, already-clean chart later in the list from
        // publishing (task pleme-io/helmworks-akeyless#143).
        let (_tmpdir, chart_path) =
            match prepare_chart_workspace(chart_name, charts_dir, lib_chart_dir, lib_chart_name) {
                Ok(v) => v,
                Err(e) => {
                    println!("FAIL: {} workspace prep — {}", chart_name, e);
                    failed.push((chart_name.clone(), format!("workspace prep: {e}")));
                    continue;
                }
            };

        // Lint
        println!("--- Lint ---");
        if let Err(e) = lint(&chart_path) {
            println!("FAIL: {} lint — {}", chart_name, e);
            failed.push((chart_name.clone(), format!("lint: {e}")));
            continue;
        }

        // Package
        println!("--- Package ---");
        let tgz = match package(&chart_path, output_dir, None) {
            Ok(t) => t,
            Err(e) => {
                println!("FAIL: {} package — {}", chart_name, e);
                failed.push((chart_name.clone(), format!("package: {e}")));
                continue;
            }
        };

        // Push — but only if this exact (name, version) is not already up.
        //
        // Without this probe `release_all` re-pushed EVERY chart on EVERY
        // merge, so an unchanged version number silently received new bytes
        // and `version:` in a HelmRelease pinned nothing. Both workflow
        // headers already claimed this skip existed; now it does.
        println!("--- Push ---");
        let version = chart_version_at(&chart_path).unwrap_or_default();
        if !version.is_empty()
            && !republish_enabled()
            && chart_published(
                registry,
                chart_name,
                &version,
                Duration::from_secs(DEP_TIMEOUT_SECS),
            )
        {
            println!("SKIP: {chart_name} {version} already published (immutable)");
            skipped.push(format!("{chart_name} {version}"));
            continue;
        }
        if let Err(e) = push(&tgz, registry) {
            println!("FAIL: {} push — {}", chart_name, e);
            failed.push((chart_name.clone(), format!("push: {e}")));
            continue;
        }

        println!("DONE: {}", chart_name);
        released.push(chart_name.clone());
    }

    println!();
    info!(
        "Released {} chart(s); skipped {} already-published",
        released.len(),
        skipped.len()
    );
    // No silent caps: every skip is named, so "nothing shipped" is never
    // indistinguishable from "everything was already current".
    if !skipped.is_empty() {
        info!("Skipped (already published): {}", skipped.join(", "));
    }

    if !failed.is_empty() {
        bail!(
            "{}/{} chart(s) failed — every chart was attempted independently ({} \
             succeeded and published above; one chart's failure never blocks another):\n{}",
            failed.len(),
            charts.len(),
            released.len(),
            format_failure_summary(&failed)
        )
    }

    Ok(())
}

// --- Helpers ---

/// Extract a top-level YAML field value (simple key: value parsing).
/// Read a TOP-LEVEL scalar field out of a Chart.yaml.
///
/// All three callers want a chart's own `name` / `version`, which in Chart.yaml
/// are always at column 0 — so the line must be UNINDENTED. The previous
/// version trimmed each line before testing the prefix, which made it
/// indentation-blind and therefore able to return a nested value from a
/// `dependencies:` entry, whose `version:` is a RANGE (`~1.2.3`, `>=1.0.0`)
/// rather than a version.
///
/// Measured 2026-08-17 before changing it, because the mechanism being wrong
/// and the fleet being affected are different claims: over all 564 Chart.yaml
/// in the fleet, exactly 2 would have been misread — both vendored Red Hat
/// charts under openshift-helmchart, where an indented `version: "0.0.1"` sits
/// at line 3 above the chart's own. The fleet's 533 dependency ranges never
/// precede the top-level key, which is why this never presented as a bug.
///
/// So this is closing a LATENT trap, not an outage: any authored chart that
/// listed `dependencies:` before `version:` would silently bump a dependency
/// range instead of the chart. Indentation is now part of the contract.
fn extract_yaml_field(content: &str, field: &str) -> Result<String> {
    let prefix = format!("{}: ", field);
    for line in content.lines() {
        // Column 0 only: a leading space means this key belongs to a nested
        // mapping (a dependency, an annotation), not to the chart.
        if line.starts_with(&prefix) {
            return Ok(line[prefix.len()..].trim().trim_matches('"').to_string());
        }
    }
    bail!(
        "Top-level field '{}' not found (a nested `{}:` under dependencies is \
         deliberately NOT accepted — it is a version RANGE, not a version)",
        field,
        field
    )
}

#[cfg(test)]
mod extract_yaml_field_tests {
    use super::extract_yaml_field;

    /// The real shape of a fleet Chart.yaml that carries dependencies.
    const CHART_WITH_DEPS: &str = "apiVersion: v2\nname: lareira-akeyless\nversion: 0.4.2\nappVersion: \"1.9.0\"\ndependencies:\n  - name: common\n    version: ~1.2.3\n";

    /// The vendored shape that WOULD have been misread: an indented version
    /// above the chart's own (openshift-helmchart redhat-mysql-persistent).
    const CHART_DEP_FIRST: &str = "apiVersion: v2\ndependencies:\n  - name: mysql\n    version: \"0.0.1\"\nname: redhat-mysql-persistent\nversion: 0.0.3\n";

    #[test]
    fn reads_the_charts_own_version_not_a_dependency_range() {
        assert_eq!(
            extract_yaml_field(CHART_WITH_DEPS, "version").unwrap(),
            "0.4.2"
        );
        assert_eq!(
            extract_yaml_field(CHART_WITH_DEPS, "name").unwrap(),
            "lareira-akeyless"
        );
        // appVersion must not be confused with version, in either direction.
        assert_eq!(
            extract_yaml_field(CHART_WITH_DEPS, "appVersion").unwrap(),
            "1.9.0"
        );
    }

    #[test]
    fn an_indented_version_ABOVE_the_real_one_is_skipped() {
        // The regression this fix exists for. Trim-based first-hit returned
        // "0.0.1" — a dependency pin — as the chart's version.
        assert_eq!(
            extract_yaml_field(CHART_DEP_FIRST, "version").unwrap(),
            "0.0.3",
            "must skip the indented dependency version and find the chart's own"
        );
    }

    #[test]
    fn a_nested_only_field_is_refused_rather_than_returned() {
        // If the ONLY occurrence is nested, that is not the chart's field. A
        // range silently returned as a version is worse than a loud failure.
        let nested_only =
            "apiVersion: v2\nname: x\ndependencies:\n  - name: c\n    version: \">=1.0.0\"\n";
        let err = extract_yaml_field(nested_only, "version").unwrap_err();
        assert!(
            err.to_string().contains("Top-level field"),
            "error must say the TOP-LEVEL field is missing, got: {err}"
        );
    }
}

fn find_latest_tgz(dir: &str, prefix: &str) -> Result<String> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_name()
                .to_str()
                .map(|n| n.starts_with(prefix) && n.ends_with(".tgz"))
                .unwrap_or(false)
        })
        .collect();

    entries.sort_by(|a, b| {
        b.metadata()
            .and_then(|m| m.modified())
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
            .cmp(
                &a.metadata()
                    .and_then(|m| m.modified())
                    .unwrap_or(std::time::SystemTime::UNIX_EPOCH),
            )
    });

    entries
        .first()
        .map(|e| e.path().to_string_lossy().to_string())
        .context(format!("No .tgz found for {} in {}", prefix, dir))
}

fn update_helmrelease_image_tag(content: &str, new_tag: &str) -> Result<String> {
    // Look for image tag patterns in kustomize patches:
    // value: amd64-<hash>
    let re = regex::Regex::new(r"(value:\s*)(amd64-[a-f0-9]+|latest)")
        .context("Failed to compile regex")?;

    if re.is_match(content) {
        Ok(re
            .replace_all(content, format!("${{1}}{}", new_tag).as_str())
            .to_string())
    } else {
        // Also try images[].newTag pattern (kustomize style)
        let re2 = regex::Regex::new(r"(newTag:\s*)(amd64-[a-f0-9]+|latest)")
            .context("Failed to compile regex")?;

        if re2.is_match(content) {
            Ok(re2
                .replace_all(content, format!("${{1}}{}", new_tag).as_str())
                .to_string())
        } else {
            bail!(
                "Could not find image tag pattern (value: amd64-* or newTag: amd64-*) in content"
            );
        }
    }
}

#[cfg(test)]
mod bump_routing_tests {
    use super::bump;
    use crate::version::{bump_semver_typed, BumpLevel};

    /// Build a minimal `<charts_dir>/<lib_chart_name>/Chart.yaml` carrying the
    /// given version under the single-line `version: X.Y.Z` shape
    /// [`super::extract_yaml_field`] recognizes, and return the temp charts dir.
    fn build_solo_lib_chart(version: &str) -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        let lib_name = "pleme-lib";
        let chart_dir = dir.path().join(lib_name);
        std::fs::create_dir(&chart_dir).unwrap();
        let chart_yaml = format!("apiVersion: v2\nname: {}\nversion: {}\n", lib_name, version);
        std::fs::write(chart_dir.join("Chart.yaml"), chart_yaml).unwrap();
        (dir, lib_name.to_string())
    }

    /// `helm::bump` routes every accepted level through
    /// [`crate::version::bump_semver_typed`] at every [`BumpLevel`] variant —
    /// the structural-routing seal that the typed-primitive grammar
    /// ([`crate::version::BumpLevel::from_str`]) IS the helm-bump level
    /// grammar. Lifts the prior verbatim-duplicate `parse_semver` + inline
    /// `match level { "patch" | "minor" | "major" | _ => bail!(...) }` cascade
    /// at this site onto the canonical primitive, matching the routing
    /// `commands/gem.rs::bump` and `commands/tool.rs::bump` already use.
    #[test]
    fn helm_bump_routes_through_bump_semver_typed_at_every_variant() {
        for &level in BumpLevel::ALL.iter() {
            let starting = "1.2.3";
            let (dir, lib_name) = build_solo_lib_chart(starting);
            let level_str = level.to_string();
            let (old, new) =
                bump(dir.path().to_str().unwrap(), &lib_name, &level_str, false).unwrap();
            assert_eq!(old, starting);
            assert_eq!(new, bump_semver_typed(starting, level).unwrap());
        }
    }

    /// `helm::bump` rejects an unrecognized level string with the byte-
    /// identical wording [`crate::version::BumpLevel::from_str`] emits — the
    /// one-oracle seal that the helm-bump level grammar is named at one site
    /// (`BumpLevel::from_str`), not retyped at every `bump()` consumer.
    #[test]
    fn helm_bump_rejects_unknown_level_with_canonical_wording() {
        let (dir, lib_name) = build_solo_lib_chart("1.2.3");
        let err = bump(dir.path().to_str().unwrap(), &lib_name, "xyz", false).unwrap_err();
        assert!(
            err.to_string()
                .contains("Invalid bump level 'xyz' — use patch, minor, or major"),
            "got: {err}"
        );
    }

    /// Build a `<charts_dir>/<lib_chart_name>/Chart.yaml` with a caller-
    /// authored `version:` line, so the writer can be exercised over the
    /// same fleet-observed shapes the port at 3bc0885's next-commit body
    /// names — quoted, aligned, single-quoted — that the pre-port
    /// `format!`-rebuilt-needle + `content.replace` sequence silently
    /// no-op'd on while still reporting `Ok(("...", "..."))`.
    fn build_solo_lib_chart_with_version_line(version_line: &str) -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        let lib_name = "pleme-lib";
        let chart_dir = dir.path().join(lib_name);
        std::fs::create_dir(&chart_dir).unwrap();
        let chart_yaml = format!("apiVersion: v2\nname: {}\n{}\n", lib_name, version_line);
        std::fs::write(chart_dir.join("Chart.yaml"), chart_yaml).unwrap();
        (dir, lib_name.to_string())
    }

    /// Regression seal for the port off `content.replace(&format!("version:
    /// {}", old), &format!("version: {}", new))` onto
    /// [`crate::version::write_chart_version`]. The pre-port needle
    /// hardcoded a single space and no quotes, so a Chart.yaml authored
    /// as `version: "0.4.2"` — the vendored openshift-helmchart family's
    /// shape, the population 93c3818 measured against — read fine through
    /// [`super::extract_yaml_field`] (which `.trim_matches('"').trim()`s on
    /// the way in) and then silently no-op'd on write while `bump`
    /// returned `Ok(("0.4.2", "0.4.3"))`. The typed writer splices the
    /// value bytes at the matched span and carries a verified-mutation
    /// seal, so both the file and the return value now agree.
    #[test]
    fn helm_bump_writes_through_a_double_quoted_lib_version_and_preserves_the_quotes() {
        let (dir, lib_name) = build_solo_lib_chart_with_version_line("version: \"0.4.2\"");
        let (old, new) = bump(dir.path().to_str().unwrap(), &lib_name, "patch", false).unwrap();
        assert_eq!((old.as_str(), new.as_str()), ("0.4.2", "0.4.3"));
        let after = std::fs::read_to_string(dir.path().join(&lib_name).join("Chart.yaml")).unwrap();
        assert!(
            after.contains("version: \"0.4.3\""),
            "pre-port trap-3: content.replace over a `format!`-rebuilt \
             `version: 0.4.2` needle silently no-op'd on the quoted form \
             AND reported success — file now reads: {after:?}"
        );
        assert!(
            !after.contains("version: \"0.4.2\""),
            "the old version bytes must not survive; file now reads: {after:?}"
        );
    }

    /// Regression seal for the aligned form: `version:  0.4.2` (two
    /// spaces after the colon), which the pre-port needle
    /// `format!("version: {}", old)` (one space) failed to locate — a
    /// second flavor of trap-3 that the splice-over-matched-span writer
    /// closes structurally. Reading through [`super::extract_yaml_field`]
    /// still works because `.trim()` on the value tolerates the extra
    /// leading space; the trap was write-side only.
    #[test]
    fn helm_bump_writes_through_an_aligned_padded_lib_version_and_preserves_the_padding() {
        let (dir, lib_name) = build_solo_lib_chart_with_version_line("version:  0.4.2");
        let (old, new) = bump(dir.path().to_str().unwrap(), &lib_name, "major", false).unwrap();
        assert_eq!((old.as_str(), new.as_str()), ("0.4.2", "1.0.0"));
        let after = std::fs::read_to_string(dir.path().join(&lib_name).join("Chart.yaml")).unwrap();
        assert!(
            after.contains("version:  1.0.0"),
            "padding between `version:` and the value must survive the \
             mutation; file now reads: {after:?}"
        );
        assert!(
            !after.contains("0.4.2"),
            "the old version bytes must not survive anywhere; file now reads: {after:?}"
        );
    }

    /// Build a temp charts dir carrying (a) a library chart at the given
    /// version and (b) a dependent chart whose `dependencies:` list pins
    /// the library at the same version via the caller-authored line.
    /// Returns `(charts_dir, lib_name, dep_name)`.
    ///
    /// The `dep_version_line` argument is spliced verbatim so the port
    /// can be exercised over every fleet-observed shape the pre-port
    /// `format!("version: \"{}\"", old)` needle handled or silently
    /// skipped: unquoted, single-quoted, aligned. The double-quoted
    /// shape was the ONLY one the pre-port form matched — it is
    /// covered by [`helm_bump_updates_double_quoted_dependent_chart_pin`]
    /// as a no-regression seal.
    fn build_lib_and_dependent_chart(
        lib_version: &str,
        dep_version_line: &str,
    ) -> (tempfile::TempDir, String, String) {
        let dir = tempfile::tempdir().unwrap();
        let lib_name = "pleme-lib";
        let dep_name = "app-wrapper";

        let lib_dir = dir.path().join(lib_name);
        std::fs::create_dir(&lib_dir).unwrap();
        let lib_chart = format!(
            "apiVersion: v2\nname: {}\nversion: {}\ntype: library\n",
            lib_name, lib_version
        );
        std::fs::write(lib_dir.join("Chart.yaml"), lib_chart).unwrap();

        let dep_dir = dir.path().join(dep_name);
        std::fs::create_dir(&dep_dir).unwrap();
        let dep_chart = format!(
            "apiVersion: v2\nname: {}\nversion: 0.1.0\ndependencies:\n  - name: {}\n    {}\n    repository: file://../{}\n",
            dep_name, lib_name, dep_version_line, lib_name
        );
        std::fs::write(dep_dir.join("Chart.yaml"), dep_chart).unwrap();

        (dir, lib_name.to_string(), dep_name.to_string())
    }

    /// Regression seal for the DOUBLE-QUOTED dep-pin form
    /// (`version: "0.4.2"`) — the only shape the pre-port
    /// `format!("version: \"{}\"", old)` needle happened to match. The
    /// port through `version::write_chart_dependency_version` must
    /// continue to update this shape.
    #[test]
    fn helm_bump_updates_double_quoted_dependent_chart_pin() {
        let (dir, lib_name, dep_name) =
            build_lib_and_dependent_chart("0.4.2", "version: \"0.4.2\"");
        let (old, new) = bump(dir.path().to_str().unwrap(), &lib_name, "patch", false).unwrap();
        assert_eq!((old.as_str(), new.as_str()), ("0.4.2", "0.4.3"));
        let after = std::fs::read_to_string(dir.path().join(&dep_name).join("Chart.yaml")).unwrap();
        assert!(
            after.contains("version: \"0.4.3\""),
            "the double-quoted dep pin must move to the new version and \
             KEEP its quotes; file now reads: {after:?}"
        );
        assert!(
            !after.contains("version: \"0.4.2\""),
            "old dep pin bytes must not survive: {after:?}"
        );
    }

    /// Regression seal for the UNQUOTED dep-pin form
    /// (`version: 0.4.2`) — the majority shape in the fleet. The pre-port
    /// `content.replace` over a `format!("version: \"{}\"", old)` needle
    /// hardcoded double quotes and one space, so the SKIP was worse than
    /// a silent no-op: the pre-`contains` guard suppressed the write
    /// entirely and `bump` reported the dep as NOT PRESENT rather than as
    /// failed. The port must now update this form.
    #[test]
    fn helm_bump_updates_unquoted_dependent_chart_pin() {
        let (dir, lib_name, dep_name) = build_lib_and_dependent_chart("0.4.2", "version: 0.4.2");
        let (old, new) = bump(dir.path().to_str().unwrap(), &lib_name, "patch", false).unwrap();
        assert_eq!((old.as_str(), new.as_str()), ("0.4.2", "0.4.3"));
        let after = std::fs::read_to_string(dir.path().join(&dep_name).join("Chart.yaml")).unwrap();
        assert!(
            after.contains("version: 0.4.3"),
            "the unquoted dep pin must move to the new version; the \
             pre-port `format!(\"version: \\\"{{}}\\\"\", ...)` needle \
             silently skipped this fleet-majority shape entirely — file \
             now reads: {after:?}"
        );
        assert!(
            !after.contains("version: 0.4.2"),
            "old dep pin bytes must not survive: {after:?}"
        );
    }

    /// Regression seal for the SINGLE-QUOTED dep-pin form
    /// (`version: '0.4.2'`) — legal YAML that the pre-port needle's
    /// hardcoded double quotes silently skipped on write. The port must
    /// splice the value bytes and keep the surrounding single quotes.
    #[test]
    fn helm_bump_updates_single_quoted_dependent_chart_pin() {
        let (dir, lib_name, dep_name) = build_lib_and_dependent_chart("0.4.2", "version: '0.4.2'");
        let (old, new) = bump(dir.path().to_str().unwrap(), &lib_name, "patch", false).unwrap();
        assert_eq!((old.as_str(), new.as_str()), ("0.4.2", "0.4.3"));
        let after = std::fs::read_to_string(dir.path().join(&dep_name).join("Chart.yaml")).unwrap();
        assert!(
            after.contains("version: '0.4.3'"),
            "the single-quoted dep pin must move to the new version and \
             KEEP its single quotes; file now reads: {after:?}"
        );
        assert!(
            !after.contains("version: '0.4.2'"),
            "old dep pin bytes must not survive: {after:?}"
        );
    }

    /// Regression seal for the ALIGNED dep-pin form
    /// (`version:  "0.4.2"`, two spaces after the colon) — the pre-port
    /// needle hardcoded ONE space, so this form silently skipped on
    /// write. The port must preserve the alignment byte-for-byte.
    #[test]
    fn helm_bump_updates_aligned_dependent_chart_pin_and_keeps_the_padding() {
        let (dir, lib_name, dep_name) =
            build_lib_and_dependent_chart("0.4.2", "version:  \"0.4.2\"");
        let (old, new) = bump(dir.path().to_str().unwrap(), &lib_name, "patch", false).unwrap();
        assert_eq!((old.as_str(), new.as_str()), ("0.4.2", "0.4.3"));
        let after = std::fs::read_to_string(dir.path().join(&dep_name).join("Chart.yaml")).unwrap();
        assert!(
            after.contains("version:  \"0.4.3\""),
            "the double-space alignment between `version:` and the value \
             must survive the mutation; file now reads: {after:?}"
        );
    }

    /// A dependent chart that does NOT depend on the library must be
    /// left untouched, and `bump` must still succeed. Mirrors the
    /// pre-port skip behavior — that was the ONE thing the pre-port
    /// `contains(name: ...)` guard got right.
    #[test]
    fn helm_bump_leaves_unrelated_dependent_chart_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let lib_name = "pleme-lib";
        let lib_dir = dir.path().join(lib_name);
        std::fs::create_dir(&lib_dir).unwrap();
        std::fs::write(
            lib_dir.join("Chart.yaml"),
            "apiVersion: v2\nname: pleme-lib\nversion: 0.4.2\ntype: library\n",
        )
        .unwrap();

        let unrelated_dir = dir.path().join("solo");
        std::fs::create_dir(&unrelated_dir).unwrap();
        let unrelated_content = "apiVersion: v2\nname: solo\nversion: 1.0.0\n";
        std::fs::write(unrelated_dir.join("Chart.yaml"), unrelated_content).unwrap();

        let (old, new) = bump(dir.path().to_str().unwrap(), lib_name, "patch", false).unwrap();
        assert_eq!((old.as_str(), new.as_str()), ("0.4.2", "0.4.3"));

        let after = std::fs::read_to_string(unrelated_dir.join("Chart.yaml")).unwrap();
        assert_eq!(
            after, unrelated_content,
            "a chart that does not depend on the library must be left \
             byte-for-byte untouched"
        );
    }
}

#[cfg(test)]
mod deploy_git_bin_routing_tests {
    /// Regression-shield: every `git`-spawning site in
    /// `commands/helm.rs::deploy` MUST resolve the binary through
    /// [`crate::git::git_command_sync`] rather than the pre-lift
    /// `Command::new("git")` literal. Pre-migration three sites
    /// (add / commit / push at lines 728 / 734 / 739) bypassed the
    /// `GIT_BIN` env override the `tools::get_tool_path(tools::GIT)`
    /// idiom (cli/src/tools.rs:102-105) resolves — the same class
    /// of bug the sibling async `flux` / `cargo` / `doca` /
    /// free-function-`git` / `GitClient` / `commands/federation.rs` /
    /// `commands/push.rs` / `commands/codegen_validation.rs` /
    /// `commands/rollback.rs` migrations redeemed at 621f827 /
    /// f0dfa12 / d3dd199 / 685642f / d6f6bc7 / dd5a212 / 673e4be /
    /// b02d4eb / 54a9985 / 139b37a / 818ed9a / badcdf4 / 8653403 /
    /// f6be190 / 81d7486 / 8a1958e. Sync half of the same routing
    /// discipline — the async migrations closed every
    /// `git_command_async` surface, this shield closes the first sync
    /// consumer (`helm::deploy`, invoked outside any tokio runtime
    /// from `main.rs:952`).
    ///
    /// This test reads this module's own source via [`include_str!`]
    /// and asserts the raw `Command::new("git")` string does not
    /// reappear in `deploy` while the delegation to
    /// `git_command_sync` does. A future regression that re-fuses the
    /// raw-spawn body fails here, not silently in production where a
    /// Nix-hermetic runner's `GIT_BIN`-provided `git` would lose to
    /// whatever `git` is first on `PATH` at deploy-commit-and-push
    /// time.
    ///
    /// The check is deliberately structural (substring on the source
    /// text) rather than behavioral — the end-to-end
    /// `GIT_BIN`-routing invariant is already pinned by
    /// [`crate::git::tests::test_git_command_sync_routes_through_git_bin_env_var`]
    /// on the primitive itself; this shield only certifies that every
    /// `helm::deploy` git spawn reads through that primitive. Mirrors
    /// the sibling shields on `commands/rollback.rs` /
    /// `commands/push.rs` / `commands/codegen_validation.rs` for the
    /// async half of the surface.
    #[test]
    fn test_deploy_routes_git_through_git_command_sync_not_raw_command() {
        const SOURCE: &str = include_str!("helm.rs");

        // Bound the scan to `deploy` — the three git spawn sites all
        // live inside it. Post-`bump` migration, only the sibling
        // `bump_git_bin_routing_tests` shield's own literal spellings
        // of `Command::new("git")` remain in this file, and those are
        // out of scope of this bound.
        let fn_marker = "pub fn deploy(";
        let start = SOURCE
            .find(fn_marker)
            .expect("helm.rs must contain `pub fn deploy(` — module invariant");
        let after_fn = &SOURCE[start..];
        // Bound at the next top-level `pub fn` in source order
        // (`release`), which follows `deploy`.
        let end_relative = after_fn
            .find("\npub fn release(")
            .expect("helm.rs must contain `pub fn release(` after `deploy`");
        let fn_body = &after_fn[..end_relative];

        assert!(
            !fn_body.contains("Command::new(\"git\")"),
            "deploy() must NOT spawn `git` directly — route through \
             `crate::git::git_command_sync()` so `GIT_BIN` overrides \
             land at the shared primitive. Found the pre-migration \
             spawn body in deploy()."
        );
        assert!(
            fn_body.contains("crate::git::git_command_sync()"),
            "deploy() must delegate every git spawn to \
             `crate::git::git_command_sync()` — the delegation string \
             was not found in deploy()."
        );
    }
}

#[cfg(test)]
mod bump_git_bin_routing_tests {
    /// Regression-shield: every `git`-spawning site in
    /// `commands/helm.rs::bump` MUST resolve the binary through
    /// [`crate::git::git_command_sync`] rather than the pre-lift
    /// `Command::new("git")` literal. Pre-migration five sites
    /// (`rev-parse --show-toplevel` / `add <charts>/*/Chart.yaml` /
    /// fallback `add -A <charts>` / `commit -m` / `tag <v>`) bypassed
    /// the `GIT_BIN` env override the
    /// `tools::get_tool_path(tools::GIT)` idiom (cli/src/tools.rs:102-105)
    /// resolves — the same class of bug the sibling sync
    /// `commands/helm.rs::deploy` (0d922f6),
    /// `config/mod::resolve_k8s_repo_root` (0a36ba0), and
    /// `commands/e2e.rs::resolve_repo_root` (447cad1) migrations
    /// redeemed on the first three sync consumers, and the async
    /// `flux` / `cargo` / `doca` / free-function-`git` / `GitClient` /
    /// `commands/federation.rs` / `commands/push.rs` /
    /// `commands/codegen_validation.rs` / `commands/rollback.rs`
    /// migrations redeemed at 621f827 / f0dfa12 / d3dd199 / 685642f /
    /// d6f6bc7 / dd5a212 / 673e4be / b02d4eb / 54a9985 / 139b37a /
    /// 818ed9a / badcdf4 / 8653403 / f6be190 / 81d7486 / 8a1958e.
    /// Fourth sync consumer on the same routing discipline.
    ///
    /// This test reads this module's own source via [`include_str!`]
    /// and asserts the raw `Command::new("git")` string does not
    /// reappear in `bump` while the delegation to
    /// `git_command_sync` does. A future regression that re-fuses
    /// the raw-spawn body fails here, not silently in production
    /// where a Nix-hermetic runner's `GIT_BIN`-provided `git` would
    /// lose to whatever `git` is first on `PATH` at
    /// `helm bump --commit` time (`forge helm bump` is invoked
    /// outside any tokio runtime from `main.rs`, same blocking
    /// entrypoint as the sibling `deploy` sync consumer at 0d922f6).
    ///
    /// The check is deliberately structural (substring on the source
    /// text) rather than behavioral — the end-to-end
    /// `GIT_BIN`-routing invariant is already pinned by
    /// [`crate::git::tests::test_git_command_sync_routes_through_git_bin_env_var`]
    /// on the primitive itself; this shield only certifies that
    /// every `helm::bump` git spawn reads through that primitive.
    /// Mirrors the sibling shields on `commands/helm.rs::deploy` /
    /// `config/mod::resolve_k8s_repo_root` /
    /// `commands/e2e.rs::resolve_repo_root` for the sync half of the
    /// surface.
    #[test]
    fn test_bump_routes_git_through_git_command_sync_not_raw_command() {
        const SOURCE: &str = include_str!("helm.rs");

        // Bound the scan to `bump` — the five git spawn sites all
        // live inside it. Bounds at the next top-level `fn` in source
        // order (`chart_version_at`) which follows `bump`.
        let fn_marker = "pub fn bump(";
        let start = SOURCE
            .find(fn_marker)
            .expect("helm.rs must contain `pub fn bump(` — module invariant");
        let after_fn = &SOURCE[start..];
        let end_relative = after_fn
            .find("\nfn chart_version_at(")
            .expect("helm.rs must contain `fn chart_version_at(` after `bump`");
        let fn_body = &after_fn[..end_relative];

        assert!(
            !fn_body.contains("Command::new(\"git\")"),
            "bump() must NOT spawn `git` directly — route through \
             `crate::git::git_command_sync()` so `GIT_BIN` overrides \
             land at the shared primitive. Found the pre-migration \
             spawn body in bump()."
        );
        assert!(
            fn_body.contains("crate::git::git_command_sync()"),
            "bump() must delegate every git spawn to \
             `crate::git::git_command_sync()` — the delegation \
             string was not found in bump()."
        );
    }
}

#[cfg(test)]
mod helm_bin_routing_tests {
    /// Regression-shield: every `helm`-spawning site in this module
    /// MUST resolve the binary through [`super::helm_bin`] rather
    /// than a bare `"helm"` literal. Pre-migration nine sites — five
    /// `.output()`/`.status()` spawns in `lint` / `package` / `push` /
    /// `template` plus four bounded spawns in `mirror_one` / the
    /// `chart_published` probe plus `run_helm_timed`'s own body —
    /// bypassed the `HELM_BIN` env override the tools-registry idiom
    /// (`crate::tools::get_tool_path(tools::HELM)`, cli/src/tools.rs:
    /// 102-105) resolves — the same class of bug the sibling
    /// `flux` / `cargo` / `doca` / free-function-`git` / `GitClient` /
    /// `commands/federation.rs` / `commands/push.rs` /
    /// `commands/codegen_validation.rs` / `commands/rollback.rs` /
    /// `commands/helm.rs::deploy` / `commands/helm.rs::bump` /
    /// `commands/product_release.rs::run_health_check` /
    /// `commands/github_runner_ci.rs::execute` /
    /// `services/migration_service.rs` /
    /// `commands/supergraph_verification.rs` /
    /// `commands/developer_tools.rs` / `commands/status.rs` /
    /// `commands/flux.rs` / `commands/build.rs` /
    /// `commands/rust_service.rs` migrations redeemed at 621f827 /
    /// f0dfa12 / d3dd199 / 685642f / d6f6bc7 / dd5a212 / 673e4be /
    /// b02d4eb / 54a9985 / 139b37a / 818ed9a / badcdf4 / 8653403 /
    /// f6be190 / 81d7486 / 8a1958e / 0d922f6 / 82376e1 / 5bb7cff /
    /// 5566415 / 5986a10 / 65283fb / 4dfb2b3 / 8687093 / c2760df /
    /// f8da719 / d8ef0d5 / 7c34e57.
    ///
    /// This test reads this module's own source via [`include_str!`]
    /// and asserts the raw `"helm"` bare literal does not reappear
    /// at either spawn shape (the direct `Command::new(<literal>)`
    /// form or the bounded `run_program_timed(<literal>, …)` form)
    /// while the `helm_bin()` sigil is defined and delegates to
    /// `get_tool_path(tools::HELM)`. A future regression that
    /// re-fuses either raw-spawn body fails here, not silently in
    /// production where a Nix-hermetic runner's `HELM_BIN`-provided
    /// `helm` would lose to whatever `helm` is first on `PATH` at
    /// chart-lint / chart-push / chart-mirror / release-idempotence
    /// time.
    ///
    /// The forbidden literals are constructed at test time via
    /// [`format!`] so this shield's own source text does not
    /// false-match itself — the whole-module scan therefore covers
    /// both the top-of-file production body AND every sibling
    /// `#[cfg(test)]` block (any of which could otherwise silently
    /// re-introduce a raw literal). The end-to-end `HELM_BIN`-routing
    /// invariant of the underlying primitive is pinned separately by
    /// [`crate::tools::tests::test_get_tool_path_from_env`] and
    /// [`crate::tools::tests::test_uppercase_conversion`]; this
    /// shield only certifies that every helm-spawning site in this
    /// module reads through `helm_bin()`.
    ///
    /// Beyond the spawn-shape invariants, this shield also pins the
    /// SIGIL BODY's own resolve shape onto the canonical two-argument
    /// [`crate::repo::get_tool_path`]`("HELM_BIN", "helm")` form — the
    /// audit-visible env-var-or-fallback lookup every sibling
    /// `<tool>_bin()` sigil across forge routes through
    /// (`infrastructure/docker.rs::docker_bin` 9b1924d,
    /// `infrastructure/attic.rs::attic_bin` 559adae,
    /// `infrastructure/registry.rs::doca_bin` 868b2ad,
    /// `commands/comprehensive_release.rs::cargo_bin` fceeecc,
    /// `cli/src/nix.rs::nix_bin` 6b2ea15,
    /// `commands/nix_builder.rs::nc_bin` b5e632a). Pre-lift the sigil
    /// body itself spelled the ONE-argument constant-driven deriving
    /// form (`crate::tools::get_tool_path(crate::tools::tools::HELM)`)
    /// — the exact abstraction pinned as the silent-PATH-fallback bug
    /// at
    /// [`crate::tools::tests::doca_resolves_from_doca_bin_and_the_deriving_lookup_does_not`]:
    /// the tool-name constant's VALUE derived the env var by
    /// uppercase+underscore rule, so a fleet-wide `HELM_BIN` grep
    /// audit missed the site and a substrate rename could not be found
    /// mechanically because the string never appeared in source.
    /// Post-lift the sigil body reads
    /// `crate::repo::get_tool_path("HELM_BIN", "helm")`, the two-arg
    /// needle appears at EXACTLY ONE code line in the whole file
    /// (only the sigil body), and neither pre-lift deriving form
    /// (constant-driven nor literal-string) may reappear at any
    /// code line — so a future "tidy" back to either deriving shape
    /// fails the shield rather than silently re-hiding the `HELM_BIN`
    /// literal from audits and re-opening the silent-PATH-fallback
    /// class. All positive/negative needles are reconstructed via
    /// [`format!`] through the `test_support` needle constructors
    /// ([`crate::test_support::get_tool_path_two_arg_call_needle`],
    /// [`crate::test_support::deriving_one_arg_sigil_needle_constant`],
    /// [`crate::test_support::deriving_one_arg_sigil_needle_literal`],
    /// [`crate::test_support::sigil_bin_fn_definition_needle`]) so
    /// this shield's own source text cannot false-match itself on any
    /// concrete substitution, and every hit routes through
    /// [`crate::test_support::code_line_hits`] for
    /// anti-docstring-self-match discipline. Mirrors the sibling
    /// `<tool>_bin()` sigil-shield family landed across
    /// `infrastructure/{docker,attic,registry}.rs` and
    /// `commands/{comprehensive_release,nix_builder}.rs`.
    #[test]
    fn test_helm_spawns_route_through_helm_bin_not_raw_literal() {
        const SOURCE: &str = include_str!("helm.rs");

        // Reconstruct the two forbidden shapes at test time — the
        // format string here contains the shape frame (`{}("{}"...)`)
        // but never the fused literal, so this file's source text
        // does not match itself when this shield scans below.
        let bare = "helm";
        let raw_bounded = format!("run_program_timed(\"{}\",", bare);

        crate::test_support::assert_source_forbids_bare_spawn_shapes(
            SOURCE,
            "commands/helm.rs",
            "helm",
            "resolve the substrate-exported `HELM_BIN` env override via `helm_bin()`",
        );
        assert!(
            !SOURCE.contains(&raw_bounded),
            "commands/helm.rs must not spawn `helm` via the bare \
             literal — every bounded helm spawn must route through \
             `run_helm_timed()` (which resolves via `helm_bin()`). A \
             raw literal at `run_program_timed` bypasses \
             `HELM_BIN`."
        );
        crate::test_support::assert_source_defines_sigil_bin_fn_code_line(
            SOURCE,
            "commands/helm.rs",
            "helm_bin",
            "HELM_BIN",
            "helm",
        );

        // Sigil-body invariants: two-arg resolve appears at exactly
        // ONE code line (only the sigil body), neither deriving form
        // reappears at any code line. All needles reconstructed via
        // `format!` through `test_support` — no concrete literal of
        // any forbidden shape appears in this shield's source.
        let two_arg_needle =
            crate::test_support::get_tool_path_two_arg_call_needle("HELM_BIN", "helm");
        let resolve_hits = crate::test_support::code_line_hits(SOURCE, &two_arg_needle);
        assert_eq!(
            resolve_hits.len(),
            1,
            "the two-argument resolve `{two_arg_needle}` must appear \
             at exactly ONE code line in `commands/helm.rs` (only in \
             the `helm_bin()` sigil), not {} — every consumer must \
             route through `helm_bin()`, not re-copy the resolve \
             inline. A future edit to the resolve contract (a \
             substrate-path validation step, a per-spawn env-injection \
             hook, a telemetry sigil on the resolved path) must land \
             at the sigil body once, not at each drifted call site. \
             Found {} code-line hit(s): {resolve_hits:#?}",
            resolve_hits.len(),
            resolve_hits.len()
        );
        crate::test_support::assert_source_forbids_deriving_one_arg_sigil_constant_form(
            SOURCE,
            "commands/helm.rs",
            "HELM_BIN",
            "helm",
            "HELM",
        );
        crate::test_support::assert_source_forbids_deriving_one_arg_sigil_literal_form(
            SOURCE,
            "commands/helm.rs",
            "HELM_BIN",
            "helm",
        );
    }
}

// ============================================================================
// helm_dependency_update retry backoff — HELM_DEP_UPDATE_RETRY_BACKOFF + helper
// ============================================================================
//
// These pin the `RetryPolicy`-consuming replacement of the pre-lift
// bespoke `sleep(Duration::from_secs(5 * u64::from(attempt)))` linear
// backoff at `helm_dependency_update`'s between-retry sleep site.
// Sibling of the `TEST_RETRY_BACKOFF` shields at `commands/test.rs`
// (commit 9fd38d3), the `INTEGRATION_TEST_RETRY_BACKOFF` shields at
// `commands/integration_tests.rs` (commit e22b0a2), the
// `FLUX_POLL_BACKOFF` shields at `commands/flux.rs` (commit 65de62f),
// the `SHINKA_MIGRATION_POLL_BACKOFF` shields at
// `commands/migrations.rs` (commit b962db5), and the
// `HEALTH_ENDPOINT_BACKOFF` shields at
// `commands/post_deploy_verification.rs` (commit b5db3b6) — same const-
// plus-delegation-helper shape, same four-test pattern (policy-shape /
// in-cap-schedule / past-cap-cap / saturating-no-panic), same
// whole-module boundary shield that forbids re-fusing the pre-lift
// bespoke-arithmetic linear-backoff shape.
#[cfg(test)]
mod dep_update_retry_backoff_tests {
    use super::{helm_dep_update_retry_delay, HELM_DEP_UPDATE_RETRY_BACKOFF};
    use std::time::Duration;

    /// The `HELM_DEP_UPDATE_RETRY_BACKOFF` const's `(initial_backoff,
    /// factor, max_backoff)` triple is the load-bearing invariant every
    /// consumption site shares. Pinned here so a future edit at the
    /// const's site is caught at a named test rather than silently at
    /// the consumption site and the delegation helper.
    #[test]
    fn test_helm_dep_update_retry_backoff_policy_shape() {
        assert_eq!(
            HELM_DEP_UPDATE_RETRY_BACKOFF.initial_backoff,
            Duration::from_secs(5),
            "HELM_DEP_UPDATE_RETRY_BACKOFF.initial_backoff must be 5s \
             — preserves the pre-lift `5 * 1 = 5s` first-retry seed \
             verbatim.",
        );
        assert_eq!(
            HELM_DEP_UPDATE_RETRY_BACKOFF.factor, 2,
            "HELM_DEP_UPDATE_RETRY_BACKOFF.factor must be 2 \
             — Bazel-style doubling climb between retries.",
        );
        assert_eq!(
            HELM_DEP_UPDATE_RETRY_BACKOFF.max_backoff,
            Duration::from_secs(30),
            "HELM_DEP_UPDATE_RETRY_BACKOFF.max_backoff must be 30s \
             — the shared cap every sibling RetryPolicy-consumer \
             (TEST_RETRY_BACKOFF, INTEGRATION_TEST_RETRY_BACKOFF, \
             FLUX_POLL_BACKOFF, SHINKA_MIGRATION_POLL_BACKOFF, \
             HEALTH_ENDPOINT_BACKOFF) also names.",
        );
    }

    /// Pre-lift the between-retry sleep emitted `5 * u64::from(attempt)`
    /// seconds verbatim; the lift's 1-indexed `attempt` counter must
    /// reproduce that at `attempt == 1` (5s) AND `attempt == 2` (10s),
    /// preserving the currently-reachable pre-lift schedule at the
    /// currently-configured `DEP_RETRIES = 1` budget and any 2-retry
    /// bump. Subsequent within-cap attempts (3/4) must emit the
    /// Bazel-style doubling climb (20s/30s-cap), strictly stronger
    /// than the pre-lift 15s/20s linear at every retry past the
    /// second.
    #[test]
    fn test_helm_dep_update_retry_delay_matches_pre_lift_seed_and_climbs_at_in_cap_attempts() {
        assert_eq!(
            helm_dep_update_retry_delay(1),
            Duration::from_secs(5),
            "attempt=1 must sleep 5s — matches pre-lift `5 * 1 = 5s` \
             seed verbatim.",
        );
        assert_eq!(
            helm_dep_update_retry_delay(2),
            Duration::from_secs(10),
            "attempt=2 must sleep 10s — matches pre-lift `5 * 2 = 10s` \
             at the second retry AND coincides with the Bazel-style \
             `5s * 2 = 10s` doubling.",
        );
        assert_eq!(
            helm_dep_update_retry_delay(3),
            Duration::from_secs(20),
            "attempt=3 must sleep 20s — Bazel-style `10s * 2 = 20s`, \
             strictly stronger than the pre-lift `5 * 3 = 15s` linear.",
        );
    }

    /// Attempts past the cap must all emit `max_backoff = 30s` —
    /// `(20s * 2).min(30s) = 30s` at attempt=4 and `(30s * 2).min(30s)
    /// = 30s` at every subsequent attempt. `DEP_RETRIES` is a
    /// top-of-module const with no upper bound on the type, so a
    /// future edit that raises the retry budget must not stretch a
    /// single inter-attempt sleep past the ceiling — the pre-lift
    /// linear `5 * attempt` schedule reached 500s at attempt=100; the
    /// post-lift schedule plateaus at 30s.
    #[test]
    fn test_helm_dep_update_retry_delay_caps_at_max_backoff_past_the_cap() {
        assert_eq!(
            helm_dep_update_retry_delay(4),
            Duration::from_secs(30),
            "attempt=4 must sleep 30s (cap) — `(20s * 2).min(30s) = 30s`.",
        );
        assert_eq!(
            helm_dep_update_retry_delay(5),
            Duration::from_secs(30),
            "attempt=5 must sleep 30s (cap).",
        );
        assert_eq!(
            helm_dep_update_retry_delay(100),
            Duration::from_secs(30),
            "attempt=100 must sleep 30s (cap) — a pathological \
             `DEP_RETRIES` budget cannot stretch a single sleep past \
             the ceiling.",
        );
    }

    /// The retry loop's `attempt` counter is a `u32` bounded only by
    /// the top-of-module `DEP_RETRIES + 1`, so a pathological future
    /// edit with `DEP_RETRIES: u32 = u32::MAX - 1` could in principle
    /// drive `helm_dep_update_retry_delay(u32::MAX)`. Pre-lift the
    /// `5 * u64::from(attempt)` arithmetic never panicked (it silently
    /// overflowed into a huge sleep at high `attempt`); post-lift the
    /// `saturating_add(1)` bridge inside `helm_dep_update_retry_delay`
    /// bounds the argument to `RetryPolicy::compute_delay`, whose
    /// `checked_pow`-then-cap body itself saturates without panic.
    /// This test pins that composition: an `attempt == u32::MAX`
    /// argument returns a bounded delay rather than panicking.
    #[test]
    fn test_helm_dep_update_retry_delay_saturates_without_panic_at_arbitrarily_large_attempt() {
        assert_eq!(
            helm_dep_update_retry_delay(u32::MAX),
            Duration::from_secs(30),
            "attempt=u32::MAX must saturate to max_backoff without \
             panic — the `saturating_add(1)` bridge + \
             `RetryPolicy::compute_delay`'s `checked_pow` cap close \
             the u32 overflow class by construction.",
        );
        assert_eq!(
            helm_dep_update_retry_delay(u32::MAX - 1),
            Duration::from_secs(30),
            "attempt=u32::MAX - 1 must also saturate to max_backoff \
             — the bridge `saturating_add(1)` returns u32::MAX, still \
             far past the cap.",
        );
    }

    /// Whole-module boundary shield: the `helm_dependency_update`
    /// retry loop MUST consume the typed primitive at
    /// `helm_dep_update_retry_delay` rather than re-fusing the
    /// pre-lift bespoke-arithmetic
    /// `sleep(Duration::from_secs(5 * u64::from(attempt)))` shape
    /// (or any sibling `5 * u64::from(attempt)`-in-a-`sleep`-call
    /// linear-growth schedule). A future refactor that reintroduces
    /// the bespoke arithmetic at the sleep site — or grows a second
    /// backoff surface and copies the pre-lift shape — fails here,
    /// not silently in production. Whole-module boundary discipline
    /// sibling of
    /// `test_run_test_suite_consumes_typed_retry_delay_not_bare_fixed_sleep`
    /// at `commands/test.rs::tests` (9fd38d3) and
    /// `test_flux_polling_loops_consume_typed_poll_delay_not_bespoke_backoff_struct`
    /// at `commands/flux.rs::tests` (65de62f).
    ///
    /// Code-line filter (via [`crate::test_support::code_line_hits`])
    /// skips docstring / prose-comment lines, so the shield does not
    /// false-positive on `HELM_DEP_UPDATE_RETRY_BACKOFF`'s own
    /// docstring (which cites the pre-lift shape as context for the
    /// three defects it forecloses).
    #[test]
    fn test_helm_dependency_update_consumes_typed_retry_delay_not_bespoke_linear_sleep() {
        const SOURCE: &str = include_str!("helm.rs");

        // The forbidden bespoke-arithmetic shape is reconstructed at
        // test time via `format!` so this shield's own source text does
        // not false-match itself when the whole-module scan runs. The
        // diagnostic prose below refers to the shape only via the
        // reconstructed `bespoke_needle` (never the fused literal), so
        // the assert message body stays unmatchable too.
        let bespoke_needle = format!("sleep(Duration::from_secs({} * u64::from(attempt)))", 5);
        let bespoke_hits = crate::test_support::code_line_hits(SOURCE, &bespoke_needle);
        assert!(
            bespoke_hits.is_empty(),
            "commands/helm.rs must NOT drive the retry loop through \
             a bespoke `{}` linear schedule — the sleep site must \
             consume `helm_dep_update_retry_delay(attempt)`, grounding \
             through `RetryPolicy::compute_delay`. Found code-line \
             hits: {:#?}",
            bespoke_needle,
            bespoke_hits,
        );
        let delegation_hits =
            crate::test_support::code_line_hits(SOURCE, "helm_dep_update_retry_delay(attempt)");
        assert!(
            !delegation_hits.is_empty(),
            "commands/helm.rs must consume the typed retry-delay \
             helper at the `helm_dependency_update` between-retry \
             sleep site — the canonical delegation call was not \
             found at any code line.",
        );
    }
}
