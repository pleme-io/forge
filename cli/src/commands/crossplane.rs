//! Crossplane package lifecycle commands.
//!
//! Today: building + pushing a Crossplane **composition Function** package
//! (xpkg) from a Nix-built runtime image + a `package/crossplane.yaml`. This is
//! the typed core of the reusable function-package-release pattern; substrate's
//! `mkCrossplaneFunctionReleaseApp` + the `crossplane-function-auto-release.yml`
//! reusable workflow wrap it, and a function repo (e.g. pitr-tools) consumes it
//! with a 3-line shim — the same shape as `forge image-release` + `mkImageReleaseApp`.
//!
//! Per Pillar 8 (Nix-only image building, no Dockerfiles): the runtime image is
//! built by Nix (`dockerTools`) and handed in as a `docker save` tarball; this
//! command only embeds + pushes it via the `crossplane` CLI.

use anyhow::{bail, Result};
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::info;

use crate::repo::get_tool_path;
use crate::retry::run_inherited_status_sync;

/// Assert a `crossplane.yaml` package-meta manifest exists directly under
/// the given package-root directory, bailing with the exact
/// `"no crossplane.yaml under package-root {package_root}"` envelope on
/// the miss arm.
///
/// # Pre-lift sites fused into ONE body
///
/// Two sibling command-module sites at
/// [`function_release`] and [`configuration_release`] each spelled the
/// 3-line
///
/// ```text
/// if !Path::new(package_root).join("crossplane.yaml").exists() {
///     bail!("no crossplane.yaml under package-root {}", package_root);
/// }
/// ```
///
/// stanza verbatim before their `xpkg build → push` handoff. The gate is
/// domain-specific: it names the `crossplane.yaml` manifest by its
/// verbatim basename and reports the missing-under-a-directory shape,
/// which does NOT compose onto the generic `"{label} not found[ at]: …"`
/// wording that [`crate::repo::require_existing_labeled`] /
/// [`crate::repo::require_existing_path`] /
/// [`crate::repo::require_existing_path_at`] carry — those three project
/// the fully-resolved child path through the message, whereas this gate
/// keeps the operator-typed `package_root` in the wording (the string an
/// operator actually typed on the CLI, so an `ls {package_root}`
/// next-step is exactly what they can paste), and reads as a domain
/// assertion about the package-root's contents rather than a generic
/// path-not-found.
///
/// # Envelope
///
/// The bail wording is
/// `"no crossplane.yaml under package-root {package_root}"`, interpolating
/// the raw operator-typed `&str` verbatim (NOT via
/// `Path::display`) because the pre-lift consumers both fed `package_root:
/// &str` directly. A drift that swapped to
/// `{Path::new(package_root).display()}` would change the wording bytes for
/// operator-typed inputs carrying non-UTF8 fragments (which
/// [`std::path::Path::display`] lossy-projects) and for operator-typed
/// inputs that render differently through the display projection.
///
/// # Errors
///
/// Returns `Err` if `<package_root>/crossplane.yaml` does not exist on
/// disk. On the miss arm the caller-facing wording is
/// `"no crossplane.yaml under package-root {package_root}"`; the primitive
/// does NOT probe why the file is missing (permission denied, ENOENT on
/// an intermediate component, dangling symlink), does NOT probe whether
/// `package_root` itself exists, and does NOT parse the YAML — the
/// discipline is a next-step `ls {package_root}` for the operator, not a
/// diagnostic tree at the primitive body. Composing this gate with
/// downstream `crossplane xpkg build` failure surfaces is the caller's
/// job.
fn require_crossplane_yaml_under_package_root(package_root: &str) -> Result<()> {
    if !Path::new(package_root).join("crossplane.yaml").exists() {
        bail!("no crossplane.yaml under package-root {}", package_root);
    }
    Ok(())
}

/// Resolve the `crossplane` CLI path via `CROSSPLANE_BIN`, falling back to
/// PATH. Every `crossplane` spawn in this module reads through this sigil
/// so the resolve happens in exactly one place — mirrors the `helm_bin()`
/// / `docker_bin()` / `flux_bin()` / `open_bin()` sigil discipline on
/// sibling command modules. Solve-once at the sigil (THEORY §I.5 —
/// duplication budget zero; every recurring shape becomes a generator or
/// helper before it becomes duplicated code) means a future added
/// `crossplane` spawn cannot silently repeat the two-argument resolve
/// string and drift away from `CROSSPLANE_BIN` at exactly the tier the
/// hermetic-runner contract binds. The whole-module shield below asserts
/// both the sigil's existence and its unique resolve — the pre-lift form
/// scattered the resolve across four sites (`function_release`'s xpkg
/// build + push, `configuration_release`'s xpkg build + push, `render`,
/// `validate`), each carrying its own copy of the fallback string.
fn crossplane_bin() -> String {
    get_tool_path("CROSSPLANE_BIN", "crossplane")
}

/// Reserve a hermetic on-disk destination for an `xpkg` build. Returns
/// a `(TempDir, PathBuf)` pair whose `TempDir` half is a RAII guard —
/// its `Drop` unlinks the created directory AND every file underneath,
/// panic-safe by construction. The path half is the destination
/// `crossplane xpkg build --package-file <out>` will write to; it does
/// NOT yet exist (crossplane creates it on build), so a build the CLI
/// refuses to overwrite still succeeds. The returned `TempDir` MUST be
/// bound to a local `_dir` (or longer-lived) variable for the duration
/// of the caller: an unbound `let (_, out) = xpkg_output_file()?;`
/// drops the guard immediately, unlinks the scratch dir, and any later
/// `--package-file <out>` write reproducibly fails with a parent-dir
/// `ENOENT` — a fast, loud signal instead of a flake. Sibling shape
/// discipline to `test_support::make_executable_shim`, which returns
/// `(TempDir, String)` for the same "the returned owner is what keeps
/// the on-disk state alive" reason.
///
/// # Why the RAII-scratch shape is load-bearing
///
/// Two defects lived at the pre-lift `std::env::temp_dir().join(
/// ".xpkg-<slot>.xpkg")` shape that both `function_release` and
/// `configuration_release` carried verbatim:
///
/// 1. **Concurrent-invocation race on a fixed name.** Two `forge
///    crossplane function-release` invocations (say, the parallel
///    matrix jobs a `crossplane-function-auto-release.yml` reusable
///    workflow spawns for a monorepo of Functions) both computed
///    `/tmp/.xpkg-out.xpkg` and raced the build → push handoff: the
///    second builder's `xpkg build` overwrote the first builder's
///    output between the first builder's `build` completing and its
///    `push` reading the file, so the second builder's bytes got
///    pushed to the first builder's OCI ref. `tempfile::Builder::new()
///    .prefix("xpkg-").tempdir()` calls `mkdtemp(3)` under the hood,
///    which appends an OS-unique suffix to the prefix — two concurrent
///    calls return strictly-distinct directories, closing the race at
///    the syscall.
/// 2. **The tempfile leaks on any panic OR success.** The pre-lift
///    shape carried no `remove_file` — success left the xpkg on disk,
///    and a `bail!` between build and push left a stale package the
///    next operator would see as "why is there a `.xpkg-out.xpkg` on
///    my `/tmp`?". `TempDir::Drop` runs unconditionally — through
///    panics, through early returns, through the operator hitting
///    Ctrl-C between build and push — so the on-disk state is bound
///    to the caller's stack frame and released with it.
fn xpkg_output_file() -> Result<(tempfile::TempDir, PathBuf)> {
    // Delegates to the shared `(TempDir, PathBuf)` primitive at
    // [`crate::hermetic_scratch::hermetic_scratch_file`] — the same
    // three-line body lives once, with the sibling sigils
    // `commands/e2e.rs::e2e_image_output_symlink` (ab88937),
    // `commands/federation_tests.rs::federation_test_job_manifest_file`
    // (76b256e), and `commands/migrations.rs::migration_job_manifest_file`
    // (950a0e7) all routed onto it (THEORY §I.3 belief 5 / §V.6 —
    // recurring shape becomes a library before it becomes duplicated
    // code).
    crate::hermetic_scratch::hermetic_scratch_file("xpkg-", "package.xpkg")
}

/// The op label the pre-lift two sibling
/// `run_inherited_status_sync(build, "crossplane xpkg build")` calls
/// spelled inline — `"crossplane xpkg build"` (verb + subcommand,
/// no trailing space). Named as a `const` so a future re-tuning of
/// the operator-facing op label (which the retry primitive stamps
/// into the canonical `"{op} failed (exit {code})"` envelope on
/// non-zero exit) flows through ONE edit rather than through two
/// inline literal edits.
const XPKG_BUILD_OP_LABEL: &str = "crossplane xpkg build";

/// Which shape the leading `crossplane xpkg build` invocation carries
/// — the two sibling [`function_release`] / [`configuration_release`]
/// stanzas differ only on whether an `--embed-runtime-image-tarball
/// <runtime>` argv pair rides between `--package-root <root>` and
/// `--package-file <out>`.
///
/// Sibling of the data-less
/// [`crate::commands::crossplane_xpkg_push::CrossplanePackageKind`]
/// enum that owns the correlated `Function|Configuration` adjective
/// on the DOWNSTREAM push + report grammar. The build phase's
/// runtime axis carries the runtime tarball as data on the `Function`
/// arm — the two enums stay distinct rather than one enum with two
/// dimensions because the push grammar's adjective is invariant
/// across a Function that happens to have zero embedded runtimes.
enum CrossplaneXpkgBuildRuntime<'a> {
    /// Function package — embeds a Nix-built `docker save` runtime
    /// image tarball under the `--embed-runtime-image-tarball
    /// <runtime_image_tarball>` argv pair spliced between
    /// `--package-root <root>` and `--package-file <out>`.
    Function { runtime_image_tarball: &'a str },
    /// Configuration package — pure declarative YAML (XRDs +
    /// Compositions), no runtime image. The
    /// `--embed-runtime-image-tarball` argv pair is omitted; the
    /// trailing `--package-file <out>` rides immediately after
    /// `--package-root <root>`.
    Configuration,
}

/// Spawn `crossplane xpkg build --package-root <root>
/// [--embed-runtime-image-tarball <runtime>] --package-file <out>
/// --examples-root <examples>` and route the exit through
/// [`crate::retry::run_inherited_status_sync`], stamping the
/// canonical `"crossplane xpkg build failed (exit {code})"` envelope
/// on non-zero exit.
///
/// # Pre-lift census — two sibling stanzas, one build shape
///
/// Two consumer sites in this module each spelled the same
/// `Command::new(&crossplane) + .args([...]) +
/// .arg(&out).arg("--examples-root").arg(&examples) +
/// run_inherited_status_sync(build, "crossplane xpkg build")`
/// composition, diverging only on the two-token
/// `["--embed-runtime-image-tarball", <runtime_image>]` pair riding
/// between `--package-root <root>` and `--package-file <out>` on the
/// `Function` arm:
///
/// 1. [`function_release`] — Function xpkg build with
///    `--embed-runtime-image-tarball <runtime_image>` at indices 4-5,
///    `<out>` at index 7, `--examples-root <examples>` at 8-9.
/// 2. [`configuration_release`] — Configuration xpkg build with the
///    `--embed-runtime-image-tarball` argv pair elided; `<out>` rides
///    at index 5, `--examples-root <examples>` at 6-7.
///
/// Post-lift both sites reach [`run_crossplane_xpkg_build`] and the
/// runtime axis is encoded as [`CrossplaneXpkgBuildRuntime`]. A
/// future re-tuning of the argv shape (a rename of `--package-root`,
/// a swap of `--package-file` for the plural `--package-files` that
/// the sibling
/// [`crate::commands::crossplane_xpkg_push::XPKG_PUSH_ARGV`] carries
/// on the push half, a swap of the positional `--package-root <root>`
/// for a bare `<root>`, an argv-order discipline pass across the
/// crate, a re-branding of the `"crossplane xpkg build"` op label)
/// lands at ONE typed body and every consumer inherits the change.
///
/// # Sibling shape discipline
///
/// Mirrors the fusion primitive in
/// [`crate::commands::crossplane_xpkg_push::xpkg_push_and_report`] on
/// the downstream push half — that primitive owns the announce +
/// push + report grammar around ONE `crossplane xpkg push` spawn;
/// this one owns the argv + spawn + classify grammar around ONE
/// `crossplane xpkg build` spawn. Together the pair reduces the
/// pre-lift 4-spawn cluster (function build+push + config build+push)
/// to two typed bodies keyed by the [`CrossplaneXpkgBuildRuntime`] /
/// [`crate::commands::crossplane_xpkg_push::CrossplanePackageKind`]
/// enum pair.
/// Build the `Command` [`run_crossplane_xpkg_build`] passes to
/// [`crate::retry::run_inherited_status_sync`]. Split from the runner
/// so the two byte-oracle shields
/// [`test_run_crossplane_xpkg_build_function_argv_matches_pre_lift_bytes`]
/// and
/// [`test_run_crossplane_xpkg_build_configuration_argv_matches_pre_lift_bytes`]
/// can project [`std::process::Command::get_args`] over the same argv
/// composition the runner drives without actually spawning a
/// `crossplane` process.
///
/// A drift that reordered the argv on either arm would surface at the
/// oracles first — as a mismatched `Vec<OsString>` — rather than as a
/// downstream `crossplane` CLI parse error on an operator's machine.
fn build_crossplane_xpkg_build_command(
    crossplane: &str,
    package_root: &str,
    runtime: CrossplaneXpkgBuildRuntime<'_>,
    output: &Path,
    examples_root: &Path,
) -> Command {
    let mut build = Command::new(crossplane);
    build.args(["xpkg", "build", "--package-root", package_root]);
    if let CrossplaneXpkgBuildRuntime::Function {
        runtime_image_tarball,
    } = runtime
    {
        build.args(["--embed-runtime-image-tarball", runtime_image_tarball]);
    }
    build
        .arg("--package-file")
        .arg(output)
        .arg("--examples-root")
        .arg(examples_root);
    build
}

fn run_crossplane_xpkg_build(
    crossplane: &str,
    package_root: &str,
    runtime: CrossplaneXpkgBuildRuntime<'_>,
    output: &Path,
    examples_root: &Path,
) -> Result<()> {
    let build = build_crossplane_xpkg_build_command(
        crossplane,
        package_root,
        runtime,
        output,
        examples_root,
    );
    run_inherited_status_sync(build, XPKG_BUILD_OP_LABEL)
}

/// Build a Crossplane Function package (xpkg) from a Nix-built runtime image and
/// a `package/` root, then push it to `package_ref:tag`.
///
/// - `package_root` — directory containing `crossplane.yaml` (the Function meta).
/// - `runtime_image` — a `docker save` tarball of the function's runtime image
///   (built by Nix; e.g. `nix build .#functionImage`), NOT a Dockerfile build.
/// - `package_ref` — OCI repo to push to (e.g. `ghcr.io/pleme-io/function-pitr-drill`).
/// - `tag` — the package tag.
pub fn function_release(
    package_root: &str,
    runtime_image: &str,
    package_ref: &str,
    tag: &str,
) -> Result<()> {
    require_crossplane_yaml_under_package_root(package_root)?;
    crate::repo::require_existing_labeled(runtime_image, "runtime image tarball")?;

    // Typed RAII scratch surface — `_out_dir` is the guard whose `Drop`
    // unlinks the whole tempdir + the xpkg inside it, panic-safe across
    // the build → push handoff and closing the concurrent-invocation
    // race the pre-lift fixed-name `.xpkg-out.xpkg` shape carried.
    let (_out_dir, out) = xpkg_output_file()?;
    // Scope --examples-root to the package dir. crossplane defaults it to
    // ./examples (cwd-relative), which scans the REPO's examples/ — those are
    // often non-Crossplane YAML (e.g. a drill spec) and fail to parse as package
    // examples. A package's own examples (if any) live under <package-root>/examples.
    let examples = Path::new(package_root).join("examples");

    info!(
        "crossplane xpkg build: {} + {} → {}",
        package_root,
        runtime_image,
        out.display()
    );
    let crossplane = crossplane_bin();
    run_crossplane_xpkg_build(
        &crossplane,
        package_root,
        CrossplaneXpkgBuildRuntime::Function {
            runtime_image_tarball: runtime_image,
        },
        &out,
        &examples,
    )?;

    // Fused announce-push-report stanza — see
    // [`crate::commands::crossplane_xpkg_push`] for the correlated-
    // adjective enum + byte-oracle grammar shared with
    // `configuration_release`.
    crate::commands::crossplane_xpkg_push::xpkg_push_and_report(
        &crossplane,
        &out,
        package_ref,
        tag,
        crate::commands::crossplane_xpkg_push::CrossplanePackageKind::Function,
    )
}

/// Build + push a Crossplane **Configuration** package (an XRD + Composition
/// bundle) from a `package/` root to `package_ref:tag`. Unlike a Function
/// package, a Configuration carries no runtime image — it is pure declarative
/// YAML (the XRDs/Compositions live alongside `crossplane.yaml`).
pub fn configuration_release(package_root: &str, package_ref: &str, tag: &str) -> Result<()> {
    require_crossplane_yaml_under_package_root(package_root)?;
    let (_out_dir, out) = xpkg_output_file()?;
    let examples = Path::new(package_root).join("examples");
    info!(
        "crossplane xpkg build (configuration): {} → {}",
        package_root,
        out.display()
    );
    let crossplane = crossplane_bin();
    run_crossplane_xpkg_build(
        &crossplane,
        package_root,
        CrossplaneXpkgBuildRuntime::Configuration,
        &out,
        &examples,
    )?;
    // Fused announce-push-report stanza — see
    // [`crate::commands::crossplane_xpkg_push`] for the correlated-
    // adjective enum + byte-oracle grammar shared with
    // `function_release`.
    crate::commands::crossplane_xpkg_push::xpkg_push_and_report(
        &crossplane,
        &out,
        package_ref,
        tag,
        crate::commands::crossplane_xpkg_push::CrossplanePackageKind::Configuration,
    )
}

/// Render a composite against its Composition + functions (`crossplane render`) —
/// the SDLC's test surface. The rendered output goes to stdout so a caller can
/// snapshot/golden-test it. `observed` is an optional observed-resources file.
pub fn render(
    composite: &str,
    composition: &str,
    functions: &str,
    observed: Option<&str>,
) -> Result<()> {
    // Fail with a typed forge error (not an opaque CLI error) when an input is
    // missing — parity with function_release's pre-checks.
    for (label, path) in [
        ("composite", composite),
        ("composition", composition),
        ("functions", functions),
    ] {
        crate::repo::require_existing_labeled(path, &format!("crossplane render: {} file", label))?;
    }
    if let Some(o) = observed {
        if !Path::new(o).exists() {
            bail!(
                "crossplane render: observed-resources file not found: {}",
                o
            );
        }
    }
    let mut args = vec!["render", composite, composition, functions];
    if let Some(o) = observed {
        args.push("--observed-resources");
        args.push(o);
    }
    crate::retry::run_bin_args_inherited_status_sync(&crossplane_bin(), &args, "crossplane render")
}

/// Validate resources against an extensions directory (`crossplane beta
/// validate`) — the SDLC's schema-validation surface.
pub fn validate(extensions: &str, resources: &str) -> Result<()> {
    for (label, path) in [("extensions", extensions), ("resources", resources)] {
        crate::repo::require_existing_labeled(
            path,
            &format!("crossplane validate: {} path", label),
        )?;
    }
    crate::retry::run_bin_args_inherited_status_sync(
        &crossplane_bin(),
        &["beta", "validate", extensions, resources],
        "crossplane beta validate",
    )
}

#[cfg(test)]
mod tests {
    /// Whole-module shield: no raw `Command::new("crossplane")` may live
    /// in the top-level body of `commands/crossplane.rs`. Every spawn
    /// site must resolve `CROSSPLANE_BIN` first via
    /// `crate::repo::get_tool_path("CROSSPLANE_BIN", "crossplane")` so
    /// the hermetic-runner contract substrate's `mkRuntimeToolsEnv`
    /// exports actually binds on the crossplane surface (parity with
    /// the sibling `NIX_BIN` / `KUBECTL_BIN` / `HELM_BIN` /
    /// `DOCKER_BIN` / `GIT_BIN` / `CARGO` / `DOCA_BIN` / `ATTIC_BIN` /
    /// `FLUX` / `BUN_BIN` frontiers).
    ///
    /// Pre-lift six sites (`function_release`'s xpkg build +
    /// xpkg push; `configuration_release`'s xpkg build + xpkg push;
    /// `render`'s crossplane render; `validate`'s crossplane beta
    /// validate) each spelled `Command::new("crossplane")` verbatim,
    /// bypassing `CROSSPLANE_BIN` at exactly the moment the
    /// hermetic-runner contract matters — every one of these six
    /// spawns is the tier that materializes or seals the Crossplane
    /// Function / Configuration package that FluxCD-managed
    /// XRDs+Compositions bind against.
    ///
    /// The scan bounds on the whole-module boundary (from the file
    /// start to the FIRST `\n#[cfg(test)]\n` marker in source order,
    /// which lands at this test module's opener) so this shield's own
    /// docstring mentions of `Command::new("crossplane")` — living in
    /// a `#[cfg(test)]` block below that first marker — stay out of
    /// scope AND every current or future crossplane-spawning helper
    /// landing anywhere in the top-level module body cannot silently
    /// ride along without going through `CROSSPLANE_BIN`. Mirrors the
    /// whole-module-boundary scan discipline pioneered on
    /// `commands/supergraph_verification.rs` (65283fb) and reused on
    /// `commands/build.rs` (d8ef0d5), `commands/developer_tools.rs`
    /// (4dfb2b3), `commands/rust_service.rs` (7c34e57),
    /// `commands/nix_builder.rs` (d930a5d), `commands/e2e.rs`
    /// (5cd137f), and `commands/github_runner_ci.rs` (59a213c).
    #[test]
    fn test_crossplane_routes_through_crossplane_bin_not_raw_command() {
        const SOURCE: &str = include_str!("crossplane.rs");
        let body = crate::test_support::module_body_before_first_cfg_test(
            SOURCE,
            "commands/crossplane.rs",
        );
        assert!(
            !body.contains("Command::new(\"crossplane\")"),
            "commands/crossplane.rs must not spawn `crossplane` via the \
             bare literal — every `crossplane` spawn must resolve \
             `CROSSPLANE_BIN` via the `crossplane_bin()` sigil first. A \
             raw `Command::new(\"crossplane\")` bypasses the \
             hermetic-runner contract substrate's mkRuntimeToolsEnv exports."
        );
        assert!(
            body.contains("fn crossplane_bin()"),
            "commands/crossplane.rs must define `crossplane_bin()` — the \
             sigil function that resolves the tools-registry \
             `CROSSPLANE_BIN` override for every crossplane spawn. \
             Mirrors the `helm_bin()` / `docker_bin()` / `flux_bin()` / \
             `open_bin()` sigil discipline on sibling command modules."
        );
        assert!(
            body.contains("get_tool_path(\"CROSSPLANE_BIN\", \"crossplane\")"),
            "commands/crossplane.rs must resolve the crossplane binary via \
             `get_tool_path(\"CROSSPLANE_BIN\", \"crossplane\")` — the \
             canonical lookup was not found in the module body."
        );
        // Solve-once: the two-argument resolve string appears in exactly
        // ONE place — the `crossplane_bin()` sigil definition — so a
        // future added spawn cannot silently re-copy the resolve inline
        // and drift away from the sigil's single point of truth. Every
        // consumer must read through `crossplane_bin()`. THEORY §I.5:
        // duplication budget zero.
        let resolve_count = body
            .matches("get_tool_path(\"CROSSPLANE_BIN\", \"crossplane\")")
            .count();
        assert_eq!(
            resolve_count, 1,
            "the two-argument resolve `get_tool_path(\"CROSSPLANE_BIN\", \
             \"crossplane\")` must appear exactly ONCE in the module body \
             (only in the `crossplane_bin()` sigil), not {resolve_count} \
             times — every consumer must route through `crossplane_bin()`, \
             not re-copy the resolve inline"
        );
    }

    /// Whole-module shield: every status-only `crossplane` spawn routes
    /// through `crate::retry::run_inherited_status_sync`, never a
    /// hand-rolled `.status()` + `if !…success() { bail! }` stanza that
    /// drops the exit code from the operator log line. Pre-lift all six
    /// spawns (`function_release` build+push, `configuration_release`
    /// build+push, `render`, `validate`) each spelled the inline stanza
    /// with an ad-hoc `bail!("crossplane … failed")` that carried no
    /// exit code; post-lift each is a one-line delegation and the
    /// canonical `"{op} failed (exit {code})"` envelope is emitted by
    /// construction at the primitive's ONE body.
    ///
    /// Post-`crossplane_xpkg_push`-lift: the two xpkg push spawns
    /// migrated into
    /// [`crate::commands::crossplane_xpkg_push::xpkg_push_and_report`],
    /// where the fusion primitive still routes through
    /// `run_inherited_status_sync`.
    ///
    /// Post-`run_crossplane_xpkg_build`-lift: the two xpkg build
    /// spawns (`function_release` + `configuration_release`)
    /// migrated into the module-local
    /// [`super::run_crossplane_xpkg_build`] primitive, which still
    /// routes the fused spawn through `run_inherited_status_sync`.
    /// Three in-module status-only spawn sites remain here (the
    /// [`super::run_crossplane_xpkg_build`] fusion primitive's own
    /// `crossplane xpkg build` spawn, `render`'s `crossplane render`,
    /// `validate`'s `crossplane beta validate`); the push shield
    /// lives in the [`crate::commands::crossplane_xpkg_push`]
    /// module's own tests.
    ///
    /// Negative side: the inline `.status()` builder-terminator must not
    /// reappear at any code line in the module body (a re-inlined spawn
    /// would bypass the primitive and re-drop the exit code). Positive
    /// side: the delegation call must appear at ≥3 code lines (one per
    /// remaining in-module spawn), so a regression that deleted every
    /// primitive call cannot leave the negative scan trivially satisfied
    /// by absence. Both hits route through `code_line_hits` for anti-
    /// docstring-self-match discipline. Same scan boundary (first
    /// `#[cfg(test)]` marker) the sigil shield above uses.
    #[test]
    fn test_crossplane_status_spawns_route_through_run_inherited_status_sync() {
        crate::test_support::assert_source_routes_status_only_spawns_through_run_inherited_status_sync(
            include_str!("crossplane.rs"),
            "commands/crossplane.rs",
            3,
            "the three remaining in-module crossplane spawns \
             (`run_crossplane_xpkg_build` fusion primitive, `render`, \
             `validate`)",
        );
    }

    /// Whole-module shield: every xpkg output-path site routes through
    /// the `xpkg_output_file()` sigil, never a hand-rolled
    /// `std::env::temp_dir().join("<fixed-name>")` stanza that leaks
    /// the produced xpkg AND races two concurrent invocations against
    /// the same on-disk slot. Pre-lift both `function_release` and
    /// `configuration_release` spelled the fixed-name shape verbatim
    /// (`.xpkg-out.xpkg` and `.xpkg-config.xpkg`), so:
    ///
    /// - Two `forge crossplane function-release` invocations on the
    ///   same runner (the parallel matrix a
    ///   `crossplane-function-auto-release.yml` reusable workflow
    ///   spawns for a monorepo of Functions) both wrote to
    ///   `/tmp/.xpkg-out.xpkg` and raced the build → push handoff —
    ///   the second builder's `xpkg build` overwrote the first's
    ///   output between the first's `build` completing and its `push`
    ///   reading the file, and the second's bytes rode into the
    ///   first's OCI ref.
    /// - Any panic (or a `bail!` inside `run_inherited_status_sync`
    ///   between build and push) left the xpkg on `/tmp` forever;
    ///   success left it too. `TempDir::Drop` closes both leaks by
    ///   construction.
    ///
    /// Positive side: the delegation call `xpkg_output_file()?` must
    /// appear at exactly TWO code lines in the module body (one per
    /// release fn), so a regression that deleted every call cannot
    /// leave the negative scan trivially satisfied by absence. The
    /// sigil definition itself (line reading `fn xpkg_output_file()`)
    /// carries no `?` and is excluded from the count — this pins the
    /// solve-once discipline (THEORY §I.5): every consumer routes
    /// through the sigil, never re-copies the tempdir setup inline.
    ///
    /// Negative side: the pre-lift `std::env::temp_dir()` shape must
    /// not appear at any code line in the module body. The forbidden
    /// needle is reconstructed at test time via
    /// `format!("std::env::{}()", "temp_dir")` so this shield's own
    /// panic-message and docstring prose does not false-match itself
    /// (same discipline `canonical_two_arg_sigil_needle` holds for
    /// the routing-needle family). Both halves route through
    /// `code_line_hits` for anti-docstring-self-match discipline.
    /// Same scan boundary (first `#[cfg(test)]` marker) the sigil
    /// shield above uses.
    #[test]
    fn test_crossplane_xpkg_output_paths_route_through_xpkg_output_file() {
        const SOURCE: &str = include_str!("crossplane.rs");
        let body = crate::test_support::module_body_before_first_cfg_test(
            SOURCE,
            "commands/crossplane.rs",
        );
        // Positive: both release fns delegate to the sigil.
        let delegation_hits = crate::test_support::code_line_hits(body, "xpkg_output_file()?");
        assert_eq!(
            delegation_hits.len(),
            2,
            "commands/crossplane.rs must delegate to `xpkg_output_file()?` at \
             exactly two code lines (function_release + configuration_release); \
             got {} — hits: {delegation_hits:#?}",
            delegation_hits.len(),
        );
        // Negative: no code-line hit of the pre-lift fixed-name shape.
        let forbidden = format!("std::env::{}()", "temp_dir");
        let stale = crate::test_support::code_line_hits(body, &forbidden);
        assert!(
            stale.is_empty(),
            "commands/crossplane.rs must not spell the pre-lift fixed-name \
             tempfile shape at any code line — every xpkg output path must \
             route through `xpkg_output_file()` so `TempDir::Drop` closes \
             the leak AND the `mkdtemp(3)`-appended unique suffix closes \
             the concurrent-invocation race. Offending: {stale:#?}",
        );
    }

    /// Primitive pin: the returned path carries the `.xpkg` extension
    /// crossplane's `xpkg push --package-files <out>` reads by content
    /// type. A drift onto a bare `package` basename would still push
    /// (crossplane sniffs the manifest) but the on-disk artifact would
    /// no longer be self-describing to an operator sifting through
    /// `/tmp` after a failed run.
    #[test]
    fn test_xpkg_output_file_returns_xpkg_extension_path() {
        let (_dir, path) = super::xpkg_output_file().expect("xpkg_output_file");
        assert!(
            crate::repo::path_has_extension(&path, "xpkg"),
            "xpkg_output_file must return a path with `.xpkg` extension, got \
             {path:?}",
        );
    }

    /// Primitive pin — the concurrent-race half: two calls in the same
    /// process return strictly-distinct paths, so a matrix workflow's
    /// parallel invocations cannot alias on the same on-disk slot.
    /// `mkdtemp(3)`-backed unique-suffix discipline; a drift onto a
    /// fixed name would fail HERE, not as a mysterious "wrong bytes
    /// pushed to the wrong OCI ref" downstream.
    #[test]
    fn test_xpkg_output_file_returns_distinct_paths_on_each_call() {
        let (_a_dir, a) = super::xpkg_output_file().expect("a");
        let (_b_dir, b) = super::xpkg_output_file().expect("b");
        assert_ne!(
            a, b,
            "two calls to xpkg_output_file() must return strictly-distinct \
             paths — a fixed-name shape would race two concurrent forge \
             crossplane releases against the same `/tmp` entry",
        );
    }

    /// Primitive pin — the leak half: the returned path starts fresh
    /// (crossplane creates it on `xpkg build`), the guard keeps the
    /// scratch dir alive across a mid-body `write`, and `Drop` unlinks
    /// both dir AND file. A drift onto a `NamedTempFile`-only shape
    /// that pre-created the file would fail on `crossplane xpkg
    /// build`'s refuse-to-overwrite check; a drift onto a bare
    /// `tempdir()` without the RAII guard held would flake because
    /// `Drop` ran between build and push. Both surface here.
    #[test]
    fn test_xpkg_output_file_returned_path_is_fresh_and_dir_drop_unlinks_written_bytes() {
        let path = {
            let (dir, out) = super::xpkg_output_file().expect("xpkg_output_file");
            assert!(
                !out.exists(),
                "returned path must be fresh — crossplane creates it on \
                 `xpkg build --package-file <out>`; a pre-created file would \
                 trip the CLI's refuse-to-overwrite check"
            );
            std::fs::write(&out, b"stub xpkg bytes").expect("write stub");
            assert!(
                out.exists() && dir.path().is_dir(),
                "file exists AND dir is alive while the RAII guard is held"
            );
            out
        };
        assert!(
            !path.exists(),
            "`TempDir::Drop` must unlink the scratch dir + its contents — a \
             mid-body panic between build and push would otherwise leak \
             `/tmp/xpkg-*/package.xpkg` forever"
        );
    }

    /// Byte-oracle: the miss-arm envelope
    /// [`super::require_crossplane_yaml_under_package_root`] surfaces is
    /// pinned to the exact string the pre-lift inline `bail!("no
    /// crossplane.yaml under package-root {}", package_root)` stanza
    /// produced. A drift that reworded to `"crossplane.yaml not found
    /// under package-root …"`, that swapped the interpolation to
    /// `Path::display()`, or that projected through
    /// [`crate::repo::require_existing_labeled`]'s
    /// `"{label} not found: {path}"` envelope (which would produce
    /// `"crossplane.yaml not found: <package_root>/crossplane.yaml"`,
    /// losing the "under package-root" domain framing AND surfacing the
    /// resolved child path rather than the operator-typed root) all fail
    /// here first, not in a downstream operator's paste of a stale
    /// runbook.
    #[test]
    fn test_require_crossplane_yaml_under_package_root_bail_envelope_bytes() {
        let missing = tempfile::tempdir().expect("tempdir");
        let package_root: &str = missing.path().to_str().expect("utf8 tempdir path");
        let err = super::require_crossplane_yaml_under_package_root(package_root)
            .expect_err("missing crossplane.yaml must bail");
        let observed = format!("{err:#}");
        let expected = format!("no crossplane.yaml under package-root {}", package_root);
        assert_eq!(
            observed, expected,
            "require_crossplane_yaml_under_package_root miss-arm wording \
             must be byte-for-byte `no crossplane.yaml under package-root \
             {{package_root}}`, interpolating the operator-typed &str \
             verbatim (NOT via Path::display) — a drift would silently \
             change every operator-facing bail across `function_release` \
             + `configuration_release`"
        );
    }

    /// Primitive pin — the pass-arm half: with `crossplane.yaml`
    /// present directly under the package-root the primitive returns
    /// `Ok(())` and does NOT parse the file (an unparseable YAML body
    /// still passes). Pinning the "no parse" half prevents a future
    /// edit from silently widening the gate into a schema-validate
    /// primitive — a widening that would move a syntactic bail from
    /// `crossplane xpkg build`'s own error surface (where the CLI's
    /// diagnostics live) into forge's pre-check and mask them.
    #[test]
    fn test_require_crossplane_yaml_under_package_root_ok_when_manifest_present() {
        let root = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            root.path().join("crossplane.yaml"),
            b"key: [unterminated but ignored by the gate\n",
        )
        .expect("seed crossplane.yaml");
        super::require_crossplane_yaml_under_package_root(
            root.path().to_str().expect("utf8 tempdir path"),
        )
        .expect("present crossplane.yaml must pass the gate even if unparseable");
    }

    /// Positive-delegation + solve-once shield: every package-root
    /// `crossplane.yaml` existence-gate site in
    /// `commands/crossplane.rs` routes through
    /// [`super::require_crossplane_yaml_under_package_root`], and the
    /// underlying
    /// `Path::new(package_root).join("crossplane.yaml").exists()`
    /// probe lives at exactly ONE code line — the primitive body.
    /// Two pre-lift call sites (`function_release`,
    /// `configuration_release`) each spelled the gate verbatim;
    /// post-lift each is a one-line delegation and the probe is fused
    /// at the primitive.
    ///
    /// Positive side: the delegation call
    /// `require_crossplane_yaml_under_package_root(package_root)?`
    /// must appear at exactly TWO code lines in the module body (one
    /// per release fn), so a regression that deleted every call cannot
    /// leave the solve-once scan trivially satisfied by absence.
    ///
    /// Solve-once side: the `.join("crossplane.yaml").exists()` probe
    /// must appear at exactly ONE code line in the module body — the
    /// primitive's own `if !Path::new(package_root).join(
    /// "crossplane.yaml").exists()` line. THEORY §I.5 (duplication
    /// budget zero): every consumer routes through the primitive, and
    /// a re-inlined gate at a third release fn cannot silently ride
    /// around the shared envelope.
    ///
    /// Both halves route through `code_line_hits` for
    /// anti-docstring-self-match discipline. Same scan boundary
    /// (first `#[cfg(test)]` marker) the sigil shields above use, so
    /// this shield's OWN needles (living in the `#[cfg(test)]` block)
    /// stay out of scope.
    #[test]
    fn test_crossplane_yaml_gates_route_through_require_primitive() {
        const SOURCE: &str = include_str!("crossplane.rs");
        let body = crate::test_support::module_body_before_first_cfg_test(
            SOURCE,
            "commands/crossplane.rs",
        );
        let delegation_hits = crate::test_support::code_line_hits(
            body,
            "require_crossplane_yaml_under_package_root(package_root)?",
        );
        assert_eq!(
            delegation_hits.len(),
            2,
            "commands/crossplane.rs must delegate to \
             `require_crossplane_yaml_under_package_root(package_root)?` \
             at exactly two code lines (function_release + \
             configuration_release); got {} — hits: {delegation_hits:#?}",
            delegation_hits.len(),
        );
        let probe_needle = ".join(\"crossplane.yaml\").exists()";
        let probe_hits = crate::test_support::code_line_hits(body, probe_needle);
        assert_eq!(
            probe_hits.len(),
            1,
            "commands/crossplane.rs must spell the \
             `.join(\"crossplane.yaml\").exists()` probe at exactly ONE \
             code line — the primitive's own body inside \
             `require_crossplane_yaml_under_package_root` — so every \
             package-root manifest gate routes through the primitive \
             and the miss-arm envelope stays fused at ONE body. Got \
             {} hits: {probe_hits:#?}",
            probe_hits.len(),
        );
    }

    /// Byte-oracle — `Function` arm:
    /// [`super::build_crossplane_xpkg_build_command`] composes the
    /// `xpkg build` argv as
    /// `["xpkg", "build", "--package-root", <root>,
    /// "--embed-runtime-image-tarball", <runtime>,
    /// "--package-file", <out>, "--examples-root", <examples>]`
    /// byte-for-byte, matching the pre-lift `function_release`
    /// `.args([...])` + `.arg(&out) + .arg("--examples-root") +
    /// .arg(&examples)` composition.
    ///
    /// The test projects [`std::process::Command::get_args`] over the
    /// primitive's returned `Command` and compares to a hand-spelled
    /// argv oracle, so a drift that reorders the argv or drops the
    /// `--embed-runtime-image-tarball` pair from the `Function` arm
    /// fails HERE, not as a downstream `crossplane` CLI parse error
    /// on an operator's machine. Sibling shape discipline to the argv
    /// byte-oracles at [`crate::kubectl_annotate_overwrite_argv`] and
    /// [`crate::docker_tag_argv`] — both hand-projected slices that
    /// pin argv byte layouts against pre-lift restatement.
    #[test]
    fn test_run_crossplane_xpkg_build_function_argv_matches_pre_lift_bytes() {
        let cmd = super::build_crossplane_xpkg_build_command(
            "/bin/true",
            "pkg",
            super::CrossplaneXpkgBuildRuntime::Function {
                runtime_image_tarball: "runtime.tar",
            },
            std::path::Path::new("/tmp/out.xpkg"),
            std::path::Path::new("pkg/examples"),
        );
        let observed: Vec<std::ffi::OsString> = cmd.get_args().map(|a| a.to_os_string()).collect();

        // Independent oracle: hand-spell the expected argv as the
        // pre-lift `.args([...])` + trailing `.arg`s produced.
        let expected: Vec<std::ffi::OsString> = [
            "xpkg",
            "build",
            "--package-root",
            "pkg",
            "--embed-runtime-image-tarball",
            "runtime.tar",
            "--package-file",
            "/tmp/out.xpkg",
            "--examples-root",
            "pkg/examples",
        ]
        .iter()
        .map(std::ffi::OsString::from)
        .collect();

        assert_eq!(
            observed, expected,
            "build_crossplane_xpkg_build_command's Function-arm argv \
             composition must match the pre-lift `function_release` \
             byte layout — `[xpkg, build, --package-root, <root>, \
             --embed-runtime-image-tarball, <runtime>, --package-file, \
             <out>, --examples-root, <examples>]`. A drift that \
             reordered the argv or dropped the runtime-tarball pair \
             would fail here first"
        );
    }

    /// Byte-oracle — `Configuration` arm:
    /// `build_crossplane_xpkg_build_command` composes the argv without
    /// the `--embed-runtime-image-tarball <runtime>` pair — the
    /// trailing `--package-file <out> --examples-root <examples>`
    /// rides immediately after `--package-root <root>`. Sibling of
    /// the Function-arm oracle above.
    #[test]
    fn test_run_crossplane_xpkg_build_configuration_argv_matches_pre_lift_bytes() {
        let cmd = super::build_crossplane_xpkg_build_command(
            "/bin/true",
            "pkg",
            super::CrossplaneXpkgBuildRuntime::Configuration,
            std::path::Path::new("/tmp/out.xpkg"),
            std::path::Path::new("pkg/examples"),
        );
        let observed: Vec<std::ffi::OsString> = cmd.get_args().map(|a| a.to_os_string()).collect();

        let expected: Vec<std::ffi::OsString> = [
            "xpkg",
            "build",
            "--package-root",
            "pkg",
            "--package-file",
            "/tmp/out.xpkg",
            "--examples-root",
            "pkg/examples",
        ]
        .iter()
        .map(std::ffi::OsString::from)
        .collect();

        assert_eq!(
            observed, expected,
            "build_crossplane_xpkg_build_command's Configuration-arm \
             argv composition must match the pre-lift \
             `configuration_release` byte layout — no \
             `--embed-runtime-image-tarball` argv pair; \
             `[xpkg, build, --package-root, <root>, --package-file, \
             <out>, --examples-root, <examples>]`. A drift that spliced \
             the runtime-tarball pair onto the Configuration arm would \
             fail here first"
        );
    }

    /// Positive-delegation + solve-once shield: both release fns route
    /// their `crossplane xpkg build` spawn through the module-local
    /// [`super::run_crossplane_xpkg_build`] primitive, and the invariant
    /// argv tokens the primitive owns
    /// (`--embed-runtime-image-tarball`, the exact
    /// `"crossplane xpkg build"` op label, and the fused
    /// `["xpkg", "build", "--package-root", package_root]` head slice)
    /// each live at exactly ONE code line in the module body — the
    /// primitive body itself.
    ///
    /// Positive side: the delegation call `run_crossplane_xpkg_build(`
    /// must appear at exactly THREE code lines (one per release fn call
    /// site + the primitive's own defining line), so a regression that
    /// deleted every caller cannot leave the solve-once scan trivially
    /// satisfied by absence.
    ///
    /// Solve-once side: the pre-lift `--embed-runtime-image-tarball`
    /// argv token must appear at exactly ONE code line — the primitive
    /// body's `Function`-arm splice. A re-inlined build stanza at a
    /// third release fn would bump the count and fail here.
    ///
    /// Both halves route through `code_line_hits` for
    /// anti-docstring-self-match discipline. Same scan boundary
    /// (first `#[cfg(test)]` marker) the sibling shields above use, so
    /// this shield's OWN needles (living in the `#[cfg(test)]` block)
    /// stay out of scope.
    #[test]
    fn test_crossplane_xpkg_build_routes_through_run_crossplane_xpkg_build() {
        const SOURCE: &str = include_str!("crossplane.rs");
        let body = crate::test_support::module_body_before_first_cfg_test(
            SOURCE,
            "commands/crossplane.rs",
        );

        // Positive: three delegation call-sites (two callers +
        // primitive's own `fn` line).
        let delegation_hits =
            crate::test_support::code_line_hits(body, "run_crossplane_xpkg_build(");
        assert_eq!(
            delegation_hits.len(),
            3,
            "commands/crossplane.rs must spell `run_crossplane_xpkg_build(` \
             at exactly three code lines (function_release call + \
             configuration_release call + the primitive's own `fn` line); \
             got {} — hits: {delegation_hits:#?}",
            delegation_hits.len(),
        );

        // Solve-once: the `--embed-runtime-image-tarball` argv token
        // lives at exactly ONE code line — the primitive body's
        // `Function`-arm splice.
        let runtime_hits =
            crate::test_support::code_line_hits(body, "--embed-runtime-image-tarball");
        assert_eq!(
            runtime_hits.len(),
            1,
            "commands/crossplane.rs must spell the \
             `--embed-runtime-image-tarball` argv token at exactly ONE \
             code line — the `run_crossplane_xpkg_build` primitive's \
             `Function`-arm splice. A re-inlined build stanza at a \
             third release fn would bump this count. Got {} hits: \
             {runtime_hits:#?}",
            runtime_hits.len(),
        );

        // Solve-once: the `"--package-file"` argv literal lives at
        // exactly ONE code line — the primitive body's trailing splice.
        // A pre-lift restatement at a caller would show up here.
        let package_file_hits = crate::test_support::code_line_hits(body, "\"--package-file\"");
        assert_eq!(
            package_file_hits.len(),
            1,
            "commands/crossplane.rs must spell the `\"--package-file\"` \
             argv literal at exactly ONE code line — the \
             `run_crossplane_xpkg_build` primitive body. A re-inlined \
             build argv at a third release fn would bump this count. \
             Got {} hits: {package_file_hits:#?}",
            package_file_hits.len(),
        );
    }
}
