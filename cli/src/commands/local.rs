//! Local development service commands (build + run locally)
//!
//! Replaces web-build.nix::mkWebLocalApps.
//! Builds a Docker image via Nix, loads it, and runs it locally.

use anyhow::Result;
use tracing::info;

use crate::nix::build_flake_attr;
use crate::retry::run_query_capture_sync;

/// Resolve the `docker` binary path via `DOCKER_BIN`, falling back to
/// `docker` on `PATH`. Wired through [`crate::repo::get_tool_path`] —
/// the two-arg env-var-or-fallback form every recent sibling sigil
/// (`e2e::docker_bin` at 23241a6, `test_ci::cargo_bin` at 916f1a4,
/// `crossplane::crossplane_bin` at 6b3ac16, `ps_bin` at 758dd6f,
/// `open_bin` at 8f4c717, `sh_bin` at b382b78) already rides. The
/// two-arg form lifts the substrate-exported env-var literal
/// (`DOCKER_BIN`) directly into the sigil site so a fleet-wide
/// `grep DOCKER_BIN` reaches this module — the deriving one-arg form
/// this module previously carried
/// (`crate::tools::get_tool_path(crate::tools::tools::DOCKER)`) hid
/// the env-var literal behind a `tools::DOCKER = "docker"` constant
/// plus an uppercase-suffix derivation, so the load-bearing name
/// never appeared in the source and a `DOCKER_BIN` audit missed the
/// site. The pre-lift shape spelled `"docker"` bare at every call
/// site (5 `Command::new` spawns + 2 `run_query_capture_sync`
/// spawns); each bypassed the env override, so a Nix-hermetic
/// runner's `DOCKER_BIN` lost to whatever `docker` was first on
/// PATH.
fn docker_bin() -> String {
    crate::repo::get_tool_path("DOCKER_BIN", "docker")
}

/// Build a Nix Docker image and run it locally.
pub async fn up(name: &str, flake_attr: &str, port: u16, compose_file: Option<&str>) -> Result<()> {
    // If a compose file is provided, use docker compose instead
    if let Some(cf) = compose_file {
        info!("Starting {} via docker compose...", name);
        crate::retry::run_bin_args_inherited_status_sync(
            &docker_bin(),
            &["compose", "-f", cf, "up", "-d", name],
            "docker compose up",
        )?;

        info!("{} started via compose on port {}", name, port);
        return Ok(());
    }

    // Build the image via Nix through the canonical `build_flake_attr`
    // primitive — typed `(BuildFailed | EmptyStorePath | ExecFailed)`
    // discrimination, structured `(exit_code, stderr)` extraction,
    // canonical UTF-8-lossy-trim of the success-stdout. The typed
    // [`crate::error::NixBuildError`] is recoverable across the anyhow
    // boundary via `err.downcast_ref::<NixBuildError>()`.
    info!("Building .#{}...", flake_attr);
    let image_path = build_flake_attr(&format!(".#{}", flake_attr))
        .await?
        .store_path;

    // Load the image into Docker
    info!("Loading image into Docker...");
    crate::retry::run_bin_args_inherited_status_sync(
        &docker_bin(),
        &["load", "-i", image_path.as_str()],
        "docker load",
    )?;

    // Stop and remove any existing container with the same name.
    // Best-effort cleanup — either invocation may fail (no container
    // by that name yet, or a stale daemon) without gating the
    // downstream `docker run -d --name <name>` on its outcome. Routes
    // through the canonical `crate::retry::run_discard_sync` primitive
    // (the `(bin, args) -> ()` consolidation for the sync
    // discard-both-streams surface) so a future edit to the "silently
    // suppress child streams on best-effort cleanup" contract lands in
    // ONE body rather than at every replicated
    // `let _ = Command::new(bin).args([...]).output();` site.
    crate::retry::run_discard_sync(&docker_bin(), &["stop", name]);
    crate::retry::run_discard_sync(&docker_bin(), &["rm", name]);

    // Run the container
    info!("Starting container {} on port {}...", name, port);
    let port_map = format!("{}:80", port);
    crate::retry::run_bin_args_inherited_status_sync(
        &docker_bin(),
        &["run", "-d", "-p", &port_map, "--name", name, name],
        "docker run",
    )?;

    info!("{} running at http://localhost:{}", name, port);
    Ok(())
}

/// Stop and remove a locally running container.
pub fn down(name: &str, compose_file: Option<&str>) -> Result<()> {
    if let Some(cf) = compose_file {
        info!("Stopping {} via docker compose...", name);
        crate::retry::run_bin_args_inherited_status_sync(
            &docker_bin(),
            &["compose", "-f", cf, "down"],
            "docker compose down",
        )?;

        info!("{} stopped", name);
        return Ok(());
    }

    info!("Stopping container {}...", name);

    // Stop + remove the container — captured output routes through the
    // canonical [`crate::retry::run_query_capture_sync`] primitive (the
    // `(cmd, args) -> Result<String>` consolidation for the sync no-cwd
    // "spawn an external CLI, capture trimmed stdout, surface the
    // structural-record tuple on failure" shape). Pre-this-commit the
    // two sites delegated through a private `run_command_output` wrapper
    // in this module; that wrapper was one of three identically-shaped
    // shape-adapters (`seed.rs::run_command_output`,
    // `sessions.rs::kubectl`) past THEORY §VI.1's three-is-a-law
    // threshold, all collapsed onto `run_query_capture_sync` in one
    // commit. Both sites bail on non-zero exit with the structural
    // `(cmd, args, exit_code, stderr)` tuple THEORY §V.4 attestation
    // records pattern-match on. Binary resolution routes through
    // [`docker_bin`] so `DOCKER_BIN` overrides land here too.
    run_query_capture_sync(&docker_bin(), &["stop", name])?;
    run_query_capture_sync(&docker_bin(), &["rm", name])?;

    info!("{} stopped and removed", name);
    Ok(())
}

#[cfg(test)]
mod docker_bin_routing_tests {
    /// Whole-module shield: no raw `"docker"`-literal spawn may live in
    /// `commands/local.rs`. Every docker spawn must resolve `DOCKER_BIN`
    /// via [`super::docker_bin`] first.
    ///
    /// Pre-lift the five `Command::new` sites (docker compose up / load /
    /// stop / rm / run) and the two `run_query_capture_sync` sites
    /// (stop / rm inside `down`) each spelled the bare `"docker"`
    /// literal verbatim, ignoring `DOCKER_BIN` at every site — a
    /// Nix-hermetic runner's substrate-derived docker path lost to
    /// whatever `docker` sat first on PATH.
    ///
    /// This shield scans the module's own source via
    /// [`include_str!`] and forbids both fused literal shapes. The
    /// forbidden shapes are reconstructed via [`format!`] so this
    /// shield's own source text does not false-match itself — the
    /// whole-module scan therefore covers both the top-of-file
    /// production body AND every sibling `#[cfg(test)]` block (any
    /// of which could otherwise silently re-introduce a raw literal).
    /// The end-to-end `DOCKER_BIN`-routing invariant of the underlying
    /// primitive is pinned separately by
    /// [`crate::tools::tests::test_get_tool_path_from_env`] and
    /// [`crate::tools::tests::test_uppercase_conversion`]; this
    /// shield only certifies that every docker-spawning site in this
    /// module reads through `docker_bin()`.
    #[test]
    fn test_docker_spawns_route_through_docker_bin_not_raw_literal() {
        const SOURCE: &str = include_str!("local.rs");

        crate::test_support::assert_source_forbids_bare_spawn_shapes(
            SOURCE,
            "commands/local.rs",
            "docker",
            "resolve the substrate-exported `DOCKER_BIN` env override via `docker_bin()`",
        );
        // Also refuse the bare `"docker"` literal at
        // `run_query_capture_sync`'s first argument — the primitive
        // spawns the caller-supplied `&str` verbatim via
        // `std::process::Command::new(cmd)`, so every captured-output
        // docker spawn must route through
        // `run_query_capture_sync(&docker_bin(), …)`. Shared helper
        // (`test_support::assert_source_forbids_bare_literal_as_run_query_capture_sync_first_arg`)
        // since three shield sites (this + `commands/seed.rs` +
        // `commands/sessions.rs`) carried the format-plus-assert
        // stanza — the helper defends BOTH the inline and multi-line
        // rustfmt shapes at every site, tightening past this pre-lift
        // shield's inline-only guard.
        crate::test_support::assert_source_forbids_bare_literal_as_run_query_capture_sync_first_arg(
            SOURCE,
            "commands/local.rs",
            "docker",
            "resolve the substrate-exported `DOCKER_BIN` env override via `docker_bin()`",
        );
        crate::test_support::assert_source_defines_sigil_bin_fn_code_line(
            SOURCE,
            "commands/local.rs",
            "docker_bin",
            "DOCKER_BIN",
            "docker",
        );
        // Assert the canonical two-arg sigil-delegation form appears at
        // a code line — filtered through `code_line_hits` so a
        // docstring-only match cannot silently satisfy the shield if
        // the production sigil body regresses. Shared helper since the
        // needle-construction + code-line filter pair was replicated
        // across five shields (`local.rs`, `infra.rs`, `dashboards.rs`,
        // and two shields in `prerelease.rs`). Sibling
        // `e2e::docker_bin_routing_tests` shield rides the same
        // reconstruction discipline.
        crate::test_support::assert_source_has_canonical_two_arg_sigil_code_line(
            SOURCE,
            "commands/local.rs",
            "DOCKER_BIN",
            "docker",
        );
        // Also assert the pre-lift deriving one-arg form does NOT
        // reappear at any *code* line. Shared helper since the
        // reconstruction + code-line filter + panic-message stanza
        // was replicated verbatim across three shields (`local.rs`,
        // `infra.rs`, `prerelease.rs`); the helper's needle
        // constructor is `format!`-based so it does not literally
        // contain the deriving shape either.
        crate::test_support::assert_source_forbids_deriving_one_arg_sigil_constant_form(
            SOURCE,
            "commands/local.rs",
            "DOCKER_BIN",
            "docker",
            "DOCKER",
        );
    }
}

#[cfg(test)]
mod status_spawn_routing_tests {
    /// Whole-module shield: every status-only spawn in
    /// `commands/local.rs` routes through
    /// [`crate::retry::run_inherited_status_sync`], never a hand-rolled
    /// `.status()` + `if !status.success() { bail!(…) }` stanza that
    /// drops the exit code from the operator log line. Pre-lift all
    /// four spawns — `up`'s compose branch (`docker compose -f
    /// <file> up -d <name>`), the Nix-image path's `docker load -i
    /// <image>` and `docker run -d -p <port>:80 --name <name>
    /// <name>`, and `down`'s compose branch (`docker compose -f
    /// <file> down`) — spelled the inline stanza with an ad-hoc
    /// `docker … failed for <name>` message that carried the target
    /// name but no exit code; post-lift each is a one-line delegation
    /// and the canonical `"{op} failed (exit {code})"` envelope is
    /// emitted by construction at the primitive's ONE body, so the
    /// operator log line reads e.g. `docker load failed (exit 1)`.
    ///
    /// Sibling of the `commands/test_ci.rs` shield
    /// `test_test_ci_status_spawns_route_through_run_inherited_status_sync`
    /// (a21bd67), `commands/e2e.rs`'s
    /// `test_e2e_status_spawns_route_through_run_inherited_status_sync`
    /// (5faeecb), `commands/tool.rs`'s
    /// `test_tool_status_spawns_route_through_run_inherited_status_sync`
    /// (a3d51eb), `commands/infra.rs`'s
    /// `test_infra_status_spawns_route_through_run_inherited_status_sync`
    /// (27896e4), `commands/gem.rs`'s
    /// `test_gem_status_spawns_route_through_run_inherited_status_sync`
    /// (9072905), `commands/pangea_infra.rs`'s
    /// `test_pangea_infra_status_spawns_route_through_run_inherited_status_sync`
    /// (a6e9b96), and `commands/crossplane.rs`'s
    /// `test_crossplane_status_spawns_route_through_run_inherited_status_sync`
    /// (6cb9442). Same three-primitive discipline: negative side
    /// forbids the inline `.status()` builder-terminator at any code
    /// line in the module body; positive side pins that
    /// `run_inherited_status_sync(` appears at ≥4 code lines (one per
    /// pre-lift spawn), so a regression that dropped every delegation
    /// cannot leave the negative scan trivially satisfied by absence.
    /// Both hits route through [`crate::test_support::code_line_hits`]
    /// for anti-docstring-self-match discipline. Scan bounds from file
    /// start to the FIRST `\n#[cfg(test)]\n` marker (the sibling
    /// `docker_bin_routing_tests` opener), so this shield's own body
    /// — the string literal `".status()"` passed to `code_line_hits`,
    /// and the assertion message that names the forbidden terminator
    /// — stays out of scope.
    #[test]
    fn test_local_status_spawns_route_through_run_inherited_status_sync() {
        crate::test_support::assert_source_routes_status_only_spawns_through_run_inherited_status_sync(
            include_str!("local.rs"),
            "commands/local.rs",
            4,
            "all four status-only spawns (`docker compose up` / \
             `docker load` / `docker run` in `up`, `docker compose \
             down` in `down`)",
        );
    }
}

#[cfg(test)]
mod discard_spawn_routing_tests {
    /// Whole-module shield: the two best-effort silent
    /// spawn-and-discard `docker` cleanup sites inside [`super::up`]
    /// (`docker stop <name>` and `docker rm <name>`, both between
    /// the async `build_flake_attr` + `docker load` sequence above
    /// and the sync `docker run -d --name <name>` below) MUST
    /// delegate through [`crate::retry::run_discard_sync`], never
    /// through a hand-rolled
    /// `let _ = Command::new(docker_bin()).args([...]).output();`
    /// discard-both-streams stanza that silently reintroduces the
    /// five-copy pre-lift duplication this commit closes.
    ///
    /// Pre-lift the two sites carried the verbatim one-line stanza
    /// above, and the sibling `commands/e2e.rs::cleanup_testcontainers`
    /// / `cleanup_e2e_images` block carried three MORE copies past
    /// its own docker-literal shield — five identically-shaped bodies
    /// past THEORY §VI.1's three-is-a-law threshold (PRIME DIRECTIVE:
    /// duplication budget is zero). The lift onto
    /// [`crate::retry::run_discard_sync`] preserves the exact
    /// pre-lift semantics — spawn `Err` is swallowed, spawn `Ok`
    /// discards the entire [`std::process::Output`] regardless of
    /// `output.status` — so the migration is behavior-identical at
    /// the cleanup surface, and the primitive's docstring pins the
    /// "deliberately infallible at the caller" contract that future
    /// callers must honor.
    ///
    /// # Why a delegation-count floor
    ///
    /// A negative-only shield that forbids the pre-lift stanza is
    /// trivially satisfied by absence — a regression that dropped
    /// one of the two cleanup calls (say, removed the `docker stop`
    /// on the theory that `docker rm` covers it) would still pass
    /// the negative scan while silently breaking the pre-lift
    /// ordering the downstream `docker run -d --name <name>` relies
    /// on. Pinning the delegation count to `>= 2` means every one
    /// of the two cleanup calls MUST still route through the
    /// primitive; a deletion drops the count and fails the shield.
    /// Same discipline the sibling
    /// `test_e2e_cleanup_sweeps_route_through_run_discard_sync`
    /// shield honors on the E2E cleanup surface, and the
    /// fleet-wide status-only-spawn shields
    /// (a21bd67 / 5faeecb / c2922fd / 08fdb86 / a31ef65) honor via
    /// the two-arm
    /// `assert_source_routes_status_only_spawns_through_run_inherited_status_sync`
    /// composition.
    ///
    /// # Reconstruction discipline
    ///
    /// The delegation needle `run_discard_sync(` is reconstructed
    /// via [`format!`] at test time so this shield's own source
    /// text does not self-match the substring count — the per-line
    /// filter would otherwise inflate the count by one for the
    /// needle-literal line. The two delegation sites each spell
    /// `crate::retry::run_discard_sync(` verbatim; the shorter
    /// `run_discard_sync(` needle matches both (a suffix of the
    /// fully-qualified form) without also matching the shield's
    /// own body (which only spells the two halves as separate
    /// literals joined at `format!` time). Scan bounds on the
    /// whole-module boundary from the file start to the FIRST
    /// `\n#[cfg(test)]\n` marker so this shield's own docstring
    /// mentions stay out of scope.
    #[test]
    fn test_local_cleanup_pair_routes_through_run_discard_sync() {
        const SOURCE: &str = include_str!("local.rs");
        let body =
            crate::test_support::module_body_before_first_cfg_test(SOURCE, "commands/local.rs");
        let needle = format!("run_discard_{}(", "sync");
        let hits = crate::test_support::code_line_hits(body, &needle);
        assert!(
            hits.len() >= 2,
            "commands/local.rs must delegate its two best-effort \
             `docker` cleanup calls (`docker stop <name>` and \
             `docker rm <name>` inside `up`, both between the async \
             image-build/load sequence above and the sync `docker \
             run -d --name <name>` below) through the shared \
             `crate::retry::run_discard_sync` primitive — found {} \
             delegation(s) in the top-of-file body, expected at \
             least 2. A regression that reintroduces the pre-lift \
             `let _ = Command::new(docker_bin()).args([...]).output();` \
             stanza re-establishes the five-copy duplication this \
             commit closes. Offending hits: {hits:?}",
            hits.len(),
        );
    }
}
