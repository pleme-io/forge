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
use std::path::Path;
use std::process::Command;
use tracing::info;

use crate::repo::get_tool_path;
use crate::retry::run_inherited_status_sync;

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
    if !Path::new(package_root).join("crossplane.yaml").exists() {
        bail!("no crossplane.yaml under package-root {}", package_root);
    }
    if !Path::new(runtime_image).exists() {
        bail!("runtime image tarball not found: {}", runtime_image);
    }

    // Typed path surface (★★ TYPED EMISSION — PathBuf::join, not format!() +
    // trim_end_matches, which mishandles separators).
    let out = std::env::temp_dir().join(".xpkg-out.xpkg");
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
    let mut build = Command::new(&crossplane);
    build
        .args([
            "xpkg",
            "build",
            "--package-root",
            package_root,
            "--embed-runtime-image-tarball",
            runtime_image,
            "--package-file",
        ])
        .arg(&out)
        .arg("--examples-root")
        .arg(&examples);
    run_inherited_status_sync(build, "crossplane xpkg build")?;

    let dest = crate::oci_manifest::image_reference(package_ref.trim_end_matches('/'), tag);
    info!("crossplane xpkg push → {}", dest);
    // `xpkg push <package> -f <files>`: the tag is the positional <package>; the
    // file flag's long form is `--package-files` (plural — verified against the
    // crossplane CLI, NOT the singular `--package-file` that `build` uses).
    let mut push = Command::new(&crossplane);
    push.args(["xpkg", "push", "--package-files"])
        .arg(&out)
        .arg(&dest);
    run_inherited_status_sync(push, &format!("crossplane xpkg push {}", dest))?;

    info!("Function package published: {}", dest);
    Ok(())
}

/// Build + push a Crossplane **Configuration** package (an XRD + Composition
/// bundle) from a `package/` root to `package_ref:tag`. Unlike a Function
/// package, a Configuration carries no runtime image — it is pure declarative
/// YAML (the XRDs/Compositions live alongside `crossplane.yaml`).
pub fn configuration_release(package_root: &str, package_ref: &str, tag: &str) -> Result<()> {
    if !Path::new(package_root).join("crossplane.yaml").exists() {
        bail!("no crossplane.yaml under package-root {}", package_root);
    }
    let out = std::env::temp_dir().join(".xpkg-config.xpkg");
    let examples = Path::new(package_root).join("examples");
    info!(
        "crossplane xpkg build (configuration): {} → {}",
        package_root,
        out.display()
    );
    let crossplane = crossplane_bin();
    let mut build = Command::new(&crossplane);
    build
        .args([
            "xpkg",
            "build",
            "--package-root",
            package_root,
            "--package-file",
        ])
        .arg(&out)
        .arg("--examples-root")
        .arg(&examples);
    run_inherited_status_sync(build, "crossplane xpkg build")?;
    let dest = crate::oci_manifest::image_reference(package_ref.trim_end_matches('/'), tag);
    info!("crossplane xpkg push → {}", dest);
    let mut push = Command::new(&crossplane);
    push.args(["xpkg", "push", "--package-files"])
        .arg(&out)
        .arg(&dest);
    run_inherited_status_sync(push, &format!("crossplane xpkg push {}", dest))?;
    info!("Configuration package published: {}", dest);
    Ok(())
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
        if !Path::new(path).exists() {
            bail!("crossplane render: {} file not found: {}", label, path);
        }
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
    let crossplane = crossplane_bin();
    let mut cmd = Command::new(&crossplane);
    cmd.args(&args);
    run_inherited_status_sync(cmd, "crossplane render")
}

/// Validate resources against an extensions directory (`crossplane beta
/// validate`) — the SDLC's schema-validation surface.
pub fn validate(extensions: &str, resources: &str) -> Result<()> {
    for (label, path) in [("extensions", extensions), ("resources", resources)] {
        if !Path::new(path).exists() {
            bail!("crossplane validate: {} path not found: {}", label, path);
        }
    }
    let crossplane = crossplane_bin();
    let mut cmd = Command::new(&crossplane);
    cmd.args(["beta", "validate", extensions, resources]);
    run_inherited_status_sync(cmd, "crossplane beta validate")
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
        let cutoff = SOURCE.find("\n#[cfg(test)]\n").expect(
            "crossplane.rs must have a `#[cfg(test)]` marker \
             — the shield's scan boundary depends on it",
        );
        let body = &SOURCE[..cutoff];
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
    /// Negative side: the inline `.status()` builder-terminator must not
    /// reappear at any code line in the module body (a re-inlined spawn
    /// would bypass the primitive and re-drop the exit code). Positive
    /// side: the delegation call must appear at ≥6 code lines (one per
    /// pre-lift spawn), so a regression that deleted every primitive call
    /// cannot leave the negative scan trivially satisfied by absence.
    /// Both hits route through `code_line_hits` for anti-docstring-self-
    /// match discipline. Same scan boundary (first `#[cfg(test)]` marker)
    /// the sigil shield above uses.
    #[test]
    fn test_crossplane_status_spawns_route_through_run_inherited_status_sync() {
        crate::test_support::assert_source_routes_status_only_spawns_through_run_inherited_status_sync(
            include_str!("crossplane.rs"),
            "commands/crossplane.rs",
            6,
            "all six crossplane spawns (`function_release` build+push, \
             `configuration_release` build+push, `render`, `validate`)",
        );
    }
}
