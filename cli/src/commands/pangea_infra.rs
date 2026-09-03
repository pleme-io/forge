//! Pangea infrastructure SDLC commands
//!
//! Provides test, plan, apply, verify, cycle, destroy, drift, and status
//! operations for Pangea-managed infrastructure. Each command follows the
//! gated workspace pattern: tests must pass before any infrastructure changes.

use anyhow::{bail, Result};
use std::process::Command;
use tracing::info;

use crate::retry::run_inherited_status_sync;

/// Resolve the `terraform` binary path via `TERRAFORM`, falling back to
/// `terraform` on `PATH`. Wired through [`crate::repo::get_tool_path`] —
/// the two-arg form, because the substrate-exported override for
/// terraform is the unadorned `TERRAFORM` var (the same var the HashiCorp
/// tooling ecosystem itself honors), not a derived `TERRAFORM_BIN`. The
/// one bridge between the pangea-infra SDLC surface and the substrate-
/// `mkRuntimeToolsEnv`-exported binary path. Mirrors the sibling
/// `cargo_bin` idiom in `commands/prerelease.rs` (cfdba0d) and the same
/// idiom every tool-invocation site in forge honors
/// (`commands/test_ci.rs` per e1677d3, `commands/developer_tools.rs`
/// per 8687093, `commands/comprehensive_release.rs` per f95d541; the
/// doc-comment idiom lives at `repo.rs:92`).
///
/// Pre-lift the four consumer sites — `plan` (`terraform plan`), `apply`
/// (`terraform apply`), `destroy` (`terraform destroy`), and `status`
/// (`terraform show`) — each spelled the bare-literal tool-name form
/// (a `Command::new` call with the tool name inline as a string)
/// verbatim, ignoring `TERRAFORM` at every one. A Nix-hermetic runner
/// with a substrate-derived terraform
/// binary silently fell through to whichever `terraform` was first on
/// PATH at these four SDLC-phase-verdict-producing sites: the plan phase
/// that decides whether the infrastructure-change diff is acceptable,
/// the apply phase that mutates the workspace, the destroy phase that
/// tears it down, and the status phase whose read-only view feeds the
/// drift-detection verdict. Same silent-PATH-fallback bug class the
/// sibling `CARGO` / `DOCKER_BIN` / `KUBECTL_BIN` / `GIT_BIN`
/// migrations closed on their respective spawn surfaces.
fn terraform_bin() -> String {
    crate::repo::get_tool_path("TERRAFORM", "terraform")
}

/// Resolve the `bundle` binary path via `BUNDLE_BIN`, falling back to
/// `bundle` on `PATH`. Wired through [`crate::repo::get_tool_path`] with
/// the derived-`_BIN`-suffix override: Bundler already claims the bare
/// `BUNDLE` env-var surface for its own runtime config (`BUNDLE_PATH`,
/// `BUNDLE_GEMFILE`, …), so the sigil honors the `_BIN` derivation
/// convention every substrate-exported tool with a name-collision-prone
/// unadorned env honors (`ATTIC_BIN`, `GH_BIN`, `DOCA_BIN`, `KUBECTL_BIN`,
/// `DOCKER_BIN`) rather than the HashiCorp-tool `TERRAFORM`-style
/// bare-name form that the sibling `terraform_bin()` sigil above honors.
/// The one bridge between the pangea-infra RSpec-synthesis-test surface
/// and the substrate-`mkRuntimeToolsEnv`-exported binary path.
///
/// Pre-lift the single consumer site — `test`
/// (`bundle exec rspec <arch_spec> [<security_spec>] --format
/// documentation`) — spelled the bare-literal tool-name form (a
/// `Command::new` call with the tool name inline as a string) verbatim,
/// ignoring `BUNDLE_BIN` at the one gate every SDLC-phase downstream of
/// it depends on for correctness: `cycle` funnels every apply through the
/// `test` gate first (Phase 1/5), and `drift` reruns it (Phase 1/2), so a
/// stale ambient-PATH `bundle` would silently produce a wrong-Ruby-version
/// spec verdict at exactly the two SDLC-phase entrypoints whose test-gate
/// verdict every mutation and every drift verdict trusts. Same
/// silent-PATH-fallback bug class the sibling `TERRAFORM` / `CARGO` /
/// `DOCKER_BIN` / `KUBECTL_BIN` migrations closed on their respective
/// spawn surfaces.
fn bundle_bin() -> String {
    crate::repo::get_tool_path("BUNDLE_BIN", "bundle")
}

/// Resolve the `inspec` binary path via `INSPEC_BIN`, falling back to
/// `inspec` on `PATH`. Wired through [`crate::repo::get_tool_path`] with
/// the derived-`_BIN`-suffix override: Chef InSpec reserves several
/// `INSPEC_*` env-var prefixes for its own reporter/config surface, so
/// the sigil honors the `_BIN` derivation convention every
/// substrate-exported tool with a name-collision-prone unadorned env
/// honors, matching the sibling `bundle_bin` above. The one bridge
/// between the pangea-infra InSpec-verify surface and the substrate-
/// `mkRuntimeToolsEnv`-exported binary path.
///
/// Pre-lift the single consumer site — `verify`
/// (`inspec exec <profile> -t <target> --reporter cli`) — spelled the
/// bare-literal tool-name form (a `Command::new` call with the tool name
/// inline as a string) verbatim, ignoring `INSPEC_BIN` at the one gate
/// `cycle`'s Phase 5/5 (the live-infrastructure-compliance verdict)
/// depends on: a substrate-derived InSpec binary paired with an
/// ambient-PATH `inspec` at the verify phase would attribute the
/// live-infrastructure-compliance verdict to whichever `inspec` the
/// wrapper's PATH found first — the Chef-InSpec-family binaries have
/// broken compliance-profile syntax across major versions (Ruby-tooling
/// upgrade paths, Cinc-Auditor forks, and vendored profile inputs are
/// the load-bearing failure modes), and the wrong verdict here does not
/// fail loudly but attributes a compliance-passing (or -failing) verdict
/// to the wrong binary. Same silent-PATH-fallback bug class the sibling
/// `TERRAFORM` / `CARGO` / `DOCKER_BIN` / `KUBECTL_BIN` migrations
/// closed on their respective spawn surfaces.
fn inspec_bin() -> String {
    crate::repo::get_tool_path("INSPEC_BIN", "inspec")
}

/// Run RSpec synthesis tests for a pangea architecture.
///
/// Executes `bundle exec rspec` targeting the architecture spec and
/// its corresponding security spec (if it exists).
pub fn test(working_dir: &str, architecture: &str) -> Result<()> {
    info!(
        "Running RSpec synthesis tests for architecture: {}",
        architecture
    );

    let spec_file = format!("spec/architectures/{}_spec.rb", architecture);
    let security_spec = format!("spec/security/{}_security_spec.rb", architecture);

    let mut args = vec![
        "exec".to_string(),
        "rspec".to_string(),
        spec_file,
        "--format".to_string(),
        "documentation".to_string(),
    ];

    // Add security spec if it exists
    let security_path = std::path::Path::new(working_dir).join(&security_spec);
    if security_path.exists() {
        args.insert(2, security_spec);
    }

    let bundle = bundle_bin();
    let mut cmd = Command::new(&bundle);
    cmd.args(&args).current_dir(working_dir);
    run_inherited_status_sync(
        cmd,
        &format!("bundle exec rspec for architecture {}", architecture),
    )?;

    info!("All synthesis tests passed for: {}", architecture);
    Ok(())
}

/// Spawn `terraform <argv>` in `working_dir` scoped to `workspace` via
/// `TF_WORKSPACE`, routing status classification through
/// [`run_inherited_status_sync`]. The `op` label the primitive emits is
/// `format!("terraform {} for workspace {}", argv[0], workspace)`, matching
/// the pre-lift dialect of `plan`/`apply`/`destroy`/`status` verbatim so
/// operator log-scrapers keyed on the pre-lift message shape survive the
/// lift by construction (`terraform apply for workspace prod failed
/// (exit 1)`, etc.).
///
/// Pre-lift four sibling stanzas (`plan`, `apply`, `destroy`, `status`)
/// each hand-rolled the same six lines: `terraform_bin()` sigil
/// resolution, `Command::new(&terraform)`, `.args(...).current_dir(...
/// ).env("TF_WORKSPACE", workspace)`, `run_inherited_status_sync(cmd,
/// &format!("terraform <sub> for workspace {}", workspace))`. Four
/// occurrences past the ≥2 duplication threshold the forge command-
/// module surface enforces (THEORY §VI.1 generation-over-composition;
/// the Compounding Directive PRIME rule). Post-lift, adding a fifth
/// terraform subcommand (`terraform state list`, `terraform import`, …)
/// is one call, and the `TF_WORKSPACE` env-var contract lives at ONE
/// body — a future rename (say to a `-workspace` CLI flag) hits one
/// site, not four.
///
/// # Non-goals
///
/// - Any non-`TF_WORKSPACE`-scoped terraform invocation. This helper
///   bakes both the workspace env-var contract AND the op-label grammar
///   into its body; callers that need a different env-var contract or
///   op-label grammar keep the direct [`run_inherited_status_sync`]
///   surface.
/// - Any capture of stdout/stderr — the primitive inherits both to the
///   parent process (via `run_inherited_status_sync`'s canonical
///   `Stdio::inherit()` override), mirroring the pre-lift stanzas
///   verbatim.
fn run_terraform_workspace(argv: &[&str], working_dir: &str, workspace: &str) -> Result<()> {
    let sub = argv.first().copied().unwrap_or("");
    let terraform = terraform_bin();
    let mut cmd = Command::new(&terraform);
    cmd.args(argv)
        .current_dir(working_dir)
        .env("TF_WORKSPACE", workspace);
    run_inherited_status_sync(
        cmd,
        &format!("terraform {} for workspace {}", sub, workspace),
    )
}

/// Run terraform plan for a pangea workspace.
pub fn plan(workspace: &str, working_dir: &str) -> Result<()> {
    info!("Running terraform plan for workspace: {}", workspace);

    run_terraform_workspace(&["plan", "-input=false"], working_dir, workspace)?;

    info!("Plan complete for workspace: {}", workspace);
    Ok(())
}

/// Apply terraform changes for a pangea workspace.
pub fn apply(workspace: &str, working_dir: &str, auto_approve: bool) -> Result<()> {
    if !auto_approve {
        confirm(&format!(
            "Apply infrastructure changes to workspace '{}'?",
            workspace
        ))?;
    }

    info!("Applying terraform changes for workspace: {}", workspace);

    let mut args = vec!["apply", "-input=false"];
    if auto_approve {
        args.push("-auto-approve");
    }

    run_terraform_workspace(&args, working_dir, workspace)?;

    info!("Apply complete for workspace: {}", workspace);
    Ok(())
}

/// Run InSpec verification against live infrastructure.
pub fn verify(workspace: &str, inspec_profile: &str, target: &str) -> Result<()> {
    info!("Running InSpec verification for workspace: {}", workspace);

    crate::retry::run_bin_args_inherited_status_sync(
        &inspec_bin(),
        &["exec", inspec_profile, "-t", target, "--reporter", "cli"],
        &format!("inspec exec for workspace {}", workspace),
    )?;

    info!("InSpec verification passed for workspace: {}", workspace);
    Ok(())
}

/// Full lifecycle: test → plan → confirm → apply → verify.
pub fn cycle(
    workspace: &str,
    working_dir: &str,
    architecture: &str,
    inspec_profile: Option<&str>,
    inspec_target: &str,
) -> Result<()> {
    info!(
        "Starting full infrastructure cycle for workspace: {}",
        workspace
    );

    // Phase 1: Test
    info!("Phase 1/5: Running synthesis tests...");
    test(working_dir, architecture)?;

    // Phase 2: Plan
    info!("Phase 2/5: Running terraform plan...");
    plan(workspace, working_dir)?;

    // Phase 3: Confirm
    info!("Phase 3/5: Awaiting confirmation...");
    confirm(&format!("Apply changes to workspace '{}'?", workspace))?;

    // Phase 4: Apply
    info!("Phase 4/5: Applying changes...");
    apply(workspace, working_dir, true)?;

    // Phase 5: Verify (optional)
    if let Some(profile) = inspec_profile {
        info!("Phase 5/5: Running InSpec verification...");
        verify(workspace, profile, inspec_target)?;
    } else {
        info!("Phase 5/5: Skipped (no InSpec profile provided)");
    }

    info!("Infrastructure cycle complete for workspace: {}", workspace);
    Ok(())
}

/// Destroy infrastructure for a pangea workspace.
pub fn destroy(workspace: &str, working_dir: &str, auto_approve: bool) -> Result<()> {
    if !auto_approve {
        confirm(&format!(
            "DESTROY all infrastructure in workspace '{}'? This cannot be undone.",
            workspace
        ))?;
    }

    info!("Destroying infrastructure for workspace: {}", workspace);

    let mut args = vec!["destroy", "-input=false"];
    if auto_approve {
        args.push("-auto-approve");
    }

    run_terraform_workspace(&args, working_dir, workspace)?;

    info!("Destroy complete for workspace: {}", workspace);
    Ok(())
}

/// Detect drift: test → plan (no apply).
pub fn drift(workspace: &str, working_dir: &str, architecture: &str) -> Result<()> {
    info!("Detecting drift for workspace: {}", workspace);

    // Phase 1: Test (ensure architecture is still valid)
    info!("Phase 1/2: Running synthesis tests...");
    test(working_dir, architecture)?;

    // Phase 2: Plan (detect drift)
    info!("Phase 2/2: Running terraform plan to detect drift...");
    plan(workspace, working_dir)?;

    info!("Drift detection complete for workspace: {}", workspace);
    Ok(())
}

/// Show workspace status.
pub fn status(workspace: &str, working_dir: &str) -> Result<()> {
    info!("Checking status for workspace: {}", workspace);

    run_terraform_workspace(&["show", "-no-color"], working_dir, workspace)?;

    Ok(())
}

// --- Helpers ---

/// Prompt user for confirmation.
fn confirm(message: &str) -> Result<()> {
    use std::io::{BufRead, Write};

    print!("{} [y/N] ", message);
    std::io::stdout().flush()?;

    let stdin = std::io::stdin();
    let mut line = String::new();
    stdin.lock().read_line(&mut line)?;

    let answer = line.trim().to_lowercase();
    if answer != "y" && answer != "yes" {
        bail!("Operation cancelled by user");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    /// Whole-module shield: no raw `terraform`-literal spawn may live in
    /// `commands/pangea_infra.rs`. Every terraform spawn must resolve
    /// `TERRAFORM` via [`super::terraform_bin`] first — the canonical
    /// env-var override every sibling tool-invocation site in forge
    /// honors (`commands/prerelease.rs` per cfdba0d,
    /// `commands/test_ci.rs` per e1677d3,
    /// `commands/developer_tools.rs` per 8687093,
    /// `commands/comprehensive_release.rs` per f95d541; the doc-comment
    /// idiom lives at `repo.rs:92`).
    ///
    /// Pre-lift the four consumer sites — `plan` (`terraform plan`),
    /// `apply` (`terraform apply`), `destroy` (`terraform destroy`),
    /// and `status` (`terraform show`) — each spelled the bare-literal
    /// tool-name form (a `Command::new` call with the tool name inline
    /// as a string) verbatim, ignoring `TERRAFORM` at every one.
    /// Pangea SDLC commands are invoked from a
    /// hermetic-runner sandbox that exports
    /// `TERRAFORM=/nix/store/...-terraform/bin/terraform`; pre-lift each
    /// SDLC-phase verdict (plan / apply / destroy / status) was
    /// attributed to whichever `terraform` the wrapper's PATH found
    /// first, not to the substrate-pinned terraform derivation the flake
    /// declared. Same silent-PATH-fallback bug class the sibling `CARGO`
    /// / `DOCKER_BIN` / `KUBECTL_BIN` / `GIT_BIN` migrations closed on
    /// their respective spawn surfaces.
    ///
    /// This shield scans the module's own source via [`include_str!`] and
    /// forbids the fused literal shape at every spawn form
    /// (`std::process::Command::new(...)`, the bare `Command::new(...)`,
    /// and the `tokio::process::Command::new(...)` long form). The
    /// forbidden shapes are reconstructed via [`format!`] so this
    /// shield's own source text does not false-match itself — the
    /// whole-module scan therefore covers both the top-of-file
    /// production body AND every sibling `#[cfg(test)]` block (any of
    /// which could otherwise silently re-introduce a raw literal — the
    /// most likely growth site as new SDLC-phase stanzas land in the
    /// pangea-infra surface). Also asserts the canonical
    /// `crate::repo::get_tool_path("TERRAFORM", "terraform")` delegation
    /// form is present so the sigil-body itself cannot silently drift
    /// away from the substrate-exported env-var contract.
    ///
    /// The end-to-end `TERRAFORM`-routing invariant of the underlying
    /// primitive is pinned separately by
    /// [`crate::tools::tests::test_get_tool_path_from_env`] and
    /// [`crate::tools::tests::test_get_tool_path_fallback`]; this
    /// shield only certifies that every terraform-spawning site in
    /// this module reads through `terraform_bin()`.
    #[test]
    fn test_terraform_spawn_routes_through_terraform_bin_not_raw_literal() {
        const SOURCE: &str = include_str!("pangea_infra.rs");

        // Composed three-primitive stanza (`test_support.rs::
        // assert_source_routes_bare_spawn_through_two_arg_sigil`) —
        // no bare `terraform` spawn at any shape, `terraform_bin()`
        // defined at a code line, and the sigil delegates via the
        // canonical two-arg `crate::repo::get_tool_path("TERRAFORM",
        // "terraform")` at a code line. Note the bare-name env-var
        // form (`TERRAFORM`, no `_BIN` suffix) — pangea-infra's
        // Terraform binary follows the Bundler/Chef-InSpec
        // convention on this surface. Sibling shields for `bundle`
        // and `inspec` below ride the same composed stanza.
        crate::test_support::assert_source_routes_bare_spawn_through_two_arg_sigil(
            SOURCE,
            "commands/pangea_infra.rs",
            "terraform",
            "TERRAFORM",
        );
    }

    /// Whole-module shield: no raw `bundle`-literal spawn may live in
    /// `commands/pangea_infra.rs`. Every bundle spawn must resolve
    /// `BUNDLE_BIN` via [`super::bundle_bin`] first — the derived-`_BIN`
    /// override the sibling `_BIN`-suffix tools (`ATTIC_BIN`, `GH_BIN`,
    /// `DOCA_BIN`, `KUBECTL_BIN`, `DOCKER_BIN`) honor, chosen over the
    /// bare-name form because Bundler itself claims the unadorned
    /// `BUNDLE` env-var surface for its own runtime config
    /// (`BUNDLE_PATH`, `BUNDLE_GEMFILE`, …). Mirrors the
    /// sibling terraform shield above.
    ///
    /// Pre-lift the one consumer site — `test` (`bundle exec rspec
    /// <arch_spec> [<security_spec>] --format documentation`) —
    /// spelled the bare-literal tool-name form (a `Command::new` call
    /// with the tool name inline as a string) verbatim, ignoring
    /// `BUNDLE_BIN`. The RSpec-synthesis-test gate this spawn produces
    /// is the load-bearing verdict every SDLC-phase downstream of it
    /// depends on: `cycle`'s Phase 1/5 funnels every apply through it,
    /// and `drift`'s Phase 1/2 reruns it, so a pre-lift ambient-PATH
    /// `bundle` silently attributed both gate verdicts to whichever
    /// `bundle` the wrapper's PATH found first, not to the
    /// substrate-pinned bundler derivation the flake declared. Same
    /// silent-PATH-fallback bug class the sibling `TERRAFORM` / `CARGO`
    /// / `DOCKER_BIN` / `KUBECTL_BIN` / `GIT_BIN` migrations closed on
    /// their respective spawn surfaces.
    ///
    /// This shield scans the module's own source via [`include_str!`]
    /// and forbids the fused literal shape at every spawn form
    /// (`std::process::Command::new(...)`, the bare `Command::new(...)`,
    /// and the `tokio::process::Command::new(...)` long form). The
    /// forbidden shapes are reconstructed via [`format!`] so this
    /// shield's own source text does not false-match itself — the
    /// whole-module scan therefore covers both the top-of-file
    /// production body AND every sibling `#[cfg(test)]` block. Also
    /// asserts the canonical
    /// `crate::repo::get_tool_path("BUNDLE_BIN", "bundle")` delegation
    /// form is present so the sigil-body itself cannot silently drift
    /// away from the substrate-exported env-var contract.
    #[test]
    fn test_bundle_spawn_routes_through_bundle_bin_not_raw_literal() {
        const SOURCE: &str = include_str!("pangea_infra.rs");

        // Composed three-primitive stanza — sibling of the
        // `TERRAFORM` shield above and the `INSPEC_BIN` shield
        // below.
        crate::test_support::assert_source_routes_bare_spawn_through_two_arg_sigil(
            SOURCE,
            "commands/pangea_infra.rs",
            "bundle",
            "BUNDLE_BIN",
        );
    }

    /// Whole-module shield: no raw `inspec`-literal spawn may live in
    /// `commands/pangea_infra.rs`. Every inspec spawn must resolve
    /// `INSPEC_BIN` via [`super::inspec_bin`] first — the derived-`_BIN`
    /// override the sibling `_BIN`-suffix tools honor. Chef InSpec
    /// reserves several `INSPEC_*` env-var prefixes for its own
    /// reporter/config surface, so the sigil honors the derivation
    /// `_BIN`-suffix convention rather than the bare-name form.
    ///
    /// Pre-lift the one consumer site — `verify`
    /// (`inspec exec <profile> -t <target> --reporter cli`) — spelled
    /// the bare-literal tool-name form (a `Command::new` call with the
    /// tool name inline as a string) verbatim, ignoring `INSPEC_BIN`
    /// at exactly the load-bearing gate `cycle`'s Phase 5/5
    /// (live-infrastructure-compliance verdict) depends on. Chef-InSpec
    /// binaries have broken compliance-profile syntax across major
    /// versions (Ruby-tooling upgrade paths, Cinc-Auditor forks, and
    /// vendored profile inputs are the load-bearing failure modes);
    /// a wrong-binary verdict at this phase does not fail loudly, it
    /// attributes a compliance-passing (or -failing) verdict to the
    /// wrong `inspec`. Same silent-PATH-fallback bug class the sibling
    /// `TERRAFORM` / `CARGO` / `DOCKER_BIN` / `KUBECTL_BIN` / `GIT_BIN`
    /// migrations closed on their respective spawn surfaces.
    ///
    /// This shield scans the module's own source via [`include_str!`]
    /// and forbids the fused literal shape at every spawn form
    /// (`std::process::Command::new(...)`, the bare `Command::new(...)`,
    /// and the `tokio::process::Command::new(...)` long form),
    /// reconstructed via [`format!`] so this shield's own source text
    /// does not false-match itself. Also asserts the canonical
    /// `crate::repo::get_tool_path("INSPEC_BIN", "inspec")` delegation
    /// form is present so the sigil-body itself cannot silently drift
    /// away from the substrate-exported env-var contract.
    #[test]
    fn test_inspec_spawn_routes_through_inspec_bin_not_raw_literal() {
        const SOURCE: &str = include_str!("pangea_infra.rs");

        // Composed three-primitive stanza — sibling of the
        // `TERRAFORM` and `BUNDLE_BIN` shields above.
        crate::test_support::assert_source_routes_bare_spawn_through_two_arg_sigil(
            SOURCE,
            "commands/pangea_infra.rs",
            "inspec",
            "INSPEC_BIN",
        );
    }

    /// Whole-module shield: every status-only spawn in
    /// `commands/pangea_infra.rs` routes through
    /// [`crate::retry::run_inherited_status_sync`], never a hand-rolled
    /// `.status()` + `ensure!(status.success(), …)` (or `if
    /// !status.success() { bail!(…) }`) stanza that drops the exit code
    /// from the operator log line. Pre-lift all six spawns — `test`
    /// (`bundle exec rspec`), `plan` (`terraform plan`), `apply`
    /// (`terraform apply`), `verify` (`inspec exec`), `destroy`
    /// (`terraform destroy`), and `status` (`terraform show`) — each
    /// spelled the inline stanza with an ad-hoc `Terraform apply failed
    /// for workspace: <ws>`-style message that carried the workspace or
    /// architecture but no exit code; post-lift each is a one-line
    /// delegation and the canonical `"{op} failed (exit {code})"`
    /// envelope is emitted by construction at the primitive's ONE body,
    /// with the workspace / architecture folded into the `op` label so
    /// the operator log line reads e.g. `terraform apply for workspace
    /// prod failed (exit 1)` — pre-lift context PLUS the exit code.
    ///
    /// Sibling of the `commands/crossplane.rs` shield
    /// `test_crossplane_status_spawns_route_through_run_inherited_status_sync`
    /// (6cb9442). Same three-primitive discipline: negative side forbids
    /// the inline `.status()` builder-terminator at any code line in the
    /// module body; positive side pins that `run_inherited_status_sync(`
    /// appears at ≥3 code lines, so a regression that dropped every
    /// delegation cannot leave the negative scan trivially satisfied by
    /// absence. Both hits route through
    /// [`crate::test_support::code_line_hits`] for
    /// anti-docstring-self-match discipline. Scan bounds from file start
    /// to the FIRST `\n#[cfg(test)]\n` marker (this test module's own
    /// opener), so this shield's own body — the string literal
    /// `".status()"` passed to `code_line_hits`, and the assertion
    /// message that names the forbidden terminator — stays out of scope.
    /// Same boundary discipline as the sibling shield
    /// `test_crossplane_status_spawns_route_through_run_inherited_status_sync`
    /// (6cb9442).
    ///
    /// # Floor lowered from ≥6 to ≥3 by the `run_terraform_workspace` lift
    ///
    /// Pre-lift each of the four terraform stanzas (`plan`, `apply`,
    /// `destroy`, `status`) carried its own inline
    /// `run_inherited_status_sync(cmd, ...)` call, so the module body
    /// held six direct delegations (four terraform + `test` + `verify`,
    /// with `verify` counted via the wrapped-form
    /// `run_bin_args_inherited_status_sync`). Post-lift the four
    /// terraform stanzas share one delegation inside
    /// [`super::run_terraform_workspace`], collapsing the four inline
    /// `run_inherited_status_sync(` code-line hits to ONE inside the
    /// helper body. The remaining three delegation call sites — `test`
    /// (direct), `verify` (wrapped), and the shared helper (direct) —
    /// still make the negative `.status()` scan load-bearing: a
    /// regression that dropped any one of the three would leave a spawn
    /// site with no delegation guard, and the negative scan alone would
    /// not catch it. Sibling shield
    /// [`test_terraform_workspace_env_scope_lives_in_helper_only_body`]
    /// pins the concentration itself — that no
    /// `.env("TF_WORKSPACE", ...)` call may live outside the helper
    /// body — so the four pre-lift call sites cannot silently re-inline
    /// their delegation without also re-inlining a `TF_WORKSPACE` env
    /// set that shield catches.
    #[test]
    fn test_pangea_infra_status_spawns_route_through_run_inherited_status_sync() {
        crate::test_support::assert_source_routes_status_only_spawns_through_run_inherited_status_sync(
            include_str!("pangea_infra.rs"),
            "commands/pangea_infra.rs",
            3,
            "all three status-only delegation call sites \
             (`test` direct, `verify` wrapped, and the \
             `run_terraform_workspace` helper shared by \
             `plan`/`apply`/`destroy`/`status`)",
        );
    }

    /// Concentration shield: every `TF_WORKSPACE` env-var scope in
    /// `commands/pangea_infra.rs` lives inside the
    /// [`super::run_terraform_workspace`] helper body — the four
    /// pre-lift terraform call sites (`plan`, `apply`, `destroy`,
    /// `status`) each hand-rolled `.env("TF_WORKSPACE", workspace)`
    /// alongside the [`std::process::Command`] construction, and the
    /// lift folded all four into ONE `.env("TF_WORKSPACE", workspace)`
    /// call inside the helper. Post-lift a new terraform subcommand
    /// stanza that re-inlined `.env("TF_WORKSPACE", ...)` would (a) miss
    /// the helper's op-label grammar (the pre-lift dialect
    /// `terraform <sub> for workspace <ws>`), (b) miss the helper's
    /// `Stdio::inherit()` override (routed through
    /// `run_inherited_status_sync`), and (c) re-open the four-way
    /// duplication the lift closed. This shield catches the re-inlining
    /// at the env-var construction site, so the sibling
    /// [`test_pangea_infra_status_spawns_route_through_run_inherited_status_sync`]
    /// count-floor cannot be silently satisfied by a re-inlined stanza
    /// (which would add both a `.env("TF_WORKSPACE", ...)` call and its
    /// own `run_inherited_status_sync(` call, satisfying the ≥3 floor
    /// while re-introducing the four-way duplication).
    ///
    /// Scan bounds from the top of the `run_terraform_workspace` helper
    /// body's OPENING brace to the FIRST `\n#[cfg(test)]\n` marker (this
    /// test module's own opener), skipping the helper body itself so
    /// the one canonical `.env("TF_WORKSPACE", workspace)` call inside
    /// the helper does not false-match the shield. The forbidden needle
    /// `.env("TF_WORKSPACE"` is reconstructed via [`format!`] so this
    /// shield's own prose above the assertion cannot false-match
    /// itself.
    #[test]
    fn test_terraform_workspace_env_scope_lives_in_helper_only_body() {
        const SOURCE: &str = include_str!("pangea_infra.rs");

        let helper_marker = "fn run_terraform_workspace(";
        let helper_start = SOURCE
            .find(helper_marker)
            .expect("run_terraform_workspace helper must be defined");
        // Find the helper body's closing brace at column 0 (matching
        // the top-level fn indentation): the first `\n}\n` after the
        // helper start.
        let helper_body_end_rel = SOURCE[helper_start..]
            .find("\n}\n")
            .expect("run_terraform_workspace helper body must terminate with a top-level `}`");
        let after_helper = helper_start + helper_body_end_rel + "\n}\n".len();

        let tests_start = SOURCE
            .find("\n#[cfg(test)]\n")
            .expect("test module marker must follow the module body");

        // Before-helper window (top of module → helper start) and
        // after-helper window (helper end → test module opener) must
        // BOTH be free of any `.env("TF_WORKSPACE"` call.
        let before_helper = &SOURCE[..helper_start];
        let after_helper_before_tests = &SOURCE[after_helper..tests_start];

        let needle = format!(".env(\"{}\"", "TF_WORKSPACE");

        let before_hits = crate::test_support::code_line_hits(before_helper, &needle);
        let after_hits = crate::test_support::code_line_hits(after_helper_before_tests, &needle);

        assert!(
            before_hits.is_empty() && after_hits.is_empty(),
            "commands/pangea_infra.rs: every `.env(\"TF_WORKSPACE\", ...)` \
             call must live inside the `run_terraform_workspace` helper \
             body — no pre-helper or post-helper call site may re-inline \
             the env-var scope. This shield catches a regression that \
             re-inlined the four pre-lift terraform stanzas (plan / apply \
             / destroy / status) and thereby re-opened the four-way \
             duplication the helper closed. Found: before-helper {before_hits:?}, \
             after-helper {after_hits:?}"
        );

        // Positive side: the helper body itself must set `TF_WORKSPACE`
        // exactly once, so a regression that deleted the env-var scope
        // from the helper (and thereby silently stopped scoping every
        // terraform spawn to a workspace) cannot leave the negative
        // scan trivially satisfied by absence.
        let helper_body = &SOURCE[helper_start..after_helper];
        let helper_hits = crate::test_support::code_line_hits(helper_body, &needle);
        assert_eq!(
            helper_hits.len(),
            1,
            "commands/pangea_infra.rs: `run_terraform_workspace` helper body \
             must set `TF_WORKSPACE` exactly once — a missing set would \
             silently drop the workspace scope from every terraform spawn; \
             a duplicated set would spread the env-var contract across the \
             helper body rather than concentrate it. Found: {helper_hits:?}"
        );
    }
}
