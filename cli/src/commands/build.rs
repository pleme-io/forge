use anyhow::{Context, Result};
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use tokio::process::Command;
use tracing::{info, warn};

use crate::repo::get_tool_path;

pub async fn execute(
    flake_attr: String,
    working_dir: String,
    arch: String,
    cache_url: String,
    cache_name: String,
    push_cache: bool,
    output: String,
) -> Result<()> {
    println!();
    println!(
        "{}",
        "╔════════════════════════════════════════════════════════════╗".bright_blue()
    );
    println!(
        "{}",
        "║  Nix Build + Attic Cache                                   ║".bright_blue()
    );
    println!(
        "{}",
        "╚════════════════════════════════════════════════════════════╝".bright_blue()
    );
    println!();

    // Get full git SHA for version embedding
    let git_sha = crate::git::get_full_sha().context("Failed to get git SHA")?;
    info!("📦 Git SHA: {}", git_sha);

    // Configure Attic cache
    info!("🔧 Configuring Attic cache...");
    info!("   URL: {}", cache_url);
    info!("   Cache: {}", cache_name);

    let attic_token = std::env::var("ATTIC_TOKEN")
        .ok()
        .or_else(|| {
            crate::infrastructure::kubectl::fetch_secret_value(
                "attic-secrets",
                "infrastructure",
                "server-token",
            )
        })
        .ok_or_else(|| anyhow::anyhow!("ATTIC_TOKEN not found"))?;

    // Attic server alias — configurable via ATTIC_SERVER_NAME (default: "default")
    let attic_server = std::env::var("ATTIC_SERVER_NAME").unwrap_or_else(|_| "default".to_string());

    // Login to Attic. Routes through
    // [`crate::infrastructure::attic::AtticClient::login_optional`] so
    // two load-bearing properties this site previously bypassed land at
    // ONE call:
    //   1. `ATTIC_BIN` env override — the pre-migration raw-spawn body
    //      here ignored the env var every other attic-invocation site in
    //      the workspace honors via `get_tool_path("ATTIC_BIN", "attic")`
    //      (`infrastructure/attic.rs::resolve_attic_bin`).
    //   2. Typed-error dispatch — a spawn failure vs. a non-zero exit
    //      landed as an untyped `Result<ExitStatus>` (with `Stdio::null()`
    //      hiding stderr and the exit status silently discarded); the
    //      primitive routes through `classify_capture` to the
    //      `AtticError::ExecFailed` / `AtticError::LoginFailed` /
    //      `AtticError::TokenRequired` split so the failure mode is
    //      named at the type level and the captured stderr flows into
    //      the `warn!` telemetry that `login_optional` emits.
    // The non-fatal contract this site had (login failure did not abort
    // the build — the subsequent `nix build` surfaces cache-unreachable
    // errors loudly on its own) is preserved by `login_optional`
    // swallowing the typed error into a boolean. Sibling of the
    // `commands/push.rs::execute` migration onto `push_optional`.
    let _login_ok = crate::infrastructure::attic::AtticClient::new(attic_server.clone())
        .with_token(attic_token.clone())
        .login_optional(&cache_url)
        .await;

    // Select the server-scoped cache as active. Routes through
    // [`crate::infrastructure::attic::AtticClient::use_cache`] so two
    // load-bearing properties this site previously bypassed land at ONE
    // call:
    //   1. `ATTIC_BIN` env override — the pre-migration raw-spawn body
    //      here ignored the env var every other attic-invocation site in
    //      the workspace honors via `get_tool_path("ATTIC_BIN", "attic")`
    //      (`infrastructure/attic.rs::resolve_attic_bin`), so a shipped
    //      `attic` binary at a Nix store path could not be routed to at
    //      THIS `use` site — `forge build` on a Nix-hermetic runner
    //      silently fell through to whatever `attic` was on the PATH.
    //   2. Typed-error dispatch — a spawn failure vs. a non-zero exit
    //      landed as an untyped `Result<ExitStatus>` (with
    //      `Stdio::null()` hiding stderr and only a bare "Failed to
    //      configure Attic cache" context on the anyhow boundary); the
    //      primitive routes through `classify_capture` to the
    //      `AtticError::ExecFailed` / `AtticError::UseFailed` split so
    //      a "wrong server alias" surfaces at the type level with the
    //      captured stderr attached, instead of as a mysterious
    //      substituter-fetch failure from the subsequent `nix build`
    //      with no structural link back to the mis-`use`d cache.
    // The hard-fail contract this site had (a `use` failure aborts the
    // build because subsequent nix substituter fetches would target the
    // wrong cache) is preserved by the `?` propagation onto the
    // `AtticError` variant. Sibling of the login-step migration one
    // block above and of the `commands/push.rs::execute` migration onto
    // `push_optional`. The regression-shield
    // `tests::test_execute_routes_attic_use_through_attic_client_not_raw_command`
    // pins the delegation structurally against a future re-fusion.
    crate::infrastructure::attic::AtticClient::new(cache_name.clone())
        .use_cache(&attic_server)
        .await?;

    info!("✅ Attic configured");
    println!();

    // Discover nix-hooks for per-derivation caching
    let nix_hooks = crate::nix_hooks::NixHooks::discover().await.ok();
    let hook_path = nix_hooks.as_ref().and_then(|h| h.attic_push_hook_path());

    // Build with Nix
    info!("🔨 Building {} image for {}...", flake_attr, arch);
    info!("📂 Working directory: {}", working_dir);
    info!("⏱️  First build: ~15-30 minutes. Subsequent builds: instant (cache)");
    if hook_path.is_some() {
        info!("🚀 Per-derivation caching enabled (attic post-build-hook)");
    }
    println!();

    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .unwrap(),
    );
    spinner.set_message("Building with Nix...");
    spinner.enable_steady_tick(std::time::Duration::from_millis(100));

    // Use relative .# to avoid git+file:// protocol issues
    let flake_ref = format!(".#{}", flake_attr);
    // Route the `nix build` spawn through `NIX_BIN` so a Nix-hermetic
    // runner's store-path `nix` wins over whichever `nix` was first on
    // PATH at this spawn site. Mirrors every other nix-invocation site
    // in forge (`commands/tool.rs::build_lock_target`,
    // `nix.rs::build_flake_attr_in`, `nix.rs::build_docker_image_from_dir`,
    // `nix.rs::path_info_recursive`, `nix_hooks.rs::build_and_get_path`,
    // `commands/developer_tools.rs::rust_{update_cargo_nix,regenerate,
    // cargo_update}`); the `test_execute_routes_nix_through_nix_bin_not_raw_command`
    // shield below pins the invariant on the whole module body.
    let nix_bin = get_tool_path("NIX_BIN", "nix");
    let mut cmd = Command::new(&nix_bin);
    cmd.current_dir(&working_dir)
        .env("GIT_SHA", &git_sha) // Pass GIT_SHA for version embedding
        .args(&[
            "build",
            &flake_ref,
            "--print-build-logs",
            "--impure",              // Required for builtins.getEnv in Nix
            "--no-update-lock-file", // Prevent lock file updates (fixes path-type input errors)
            "--system",
            &arch,
        ]);

    // Configure post-build-hook for per-derivation caching if available
    if let Some(ref hook) = hook_path {
        cmd.args(&["--option", "post-build-hook", hook]);
        cmd.env("ATTIC_CACHE", &cache_name);
        cmd.env("ATTIC_SERVER", &cache_url);
        cmd.env("ATTIC_TOKEN", &attic_token);
    }

    // Route the status-only spawn through the canonical primitive so
    // the pre-lift `.status().await.context(...)?` + `if !success()
    // { bail! }` stanza (which dropped the exit code from the operator
    // log line — `"Nix build failed"` carried no `code` even though
    // `status.code()` was in scope) collapses onto
    // `crate::retry::run_inherited_status`, and the canonical
    // `"nix build failed (exit {code})"` envelope emerges by
    // construction. Binding the result before the `?` propagation
    // keeps the spinner-clear on the failure path — pre-lift the
    // `?` on `.context("Failed to run nix build")` ran *before*
    // `spinner.finish_and_clear()`, so a spawn error bubbled with the
    // live spinner still animating beneath the printed error; post-
    // lift the spinner clears on every path (success, non-zero exit,
    // AND spawn error). Sibling of every recent status-only-spawn lift
    // onto `run_inherited_status_sync` (a3d51eb through 6cb9442).
    let outcome = crate::retry::run_inherited_status(cmd, "nix build").await;

    spinner.finish_and_clear();

    outcome?;

    // Create custom symlink if requested
    if output != "result" {
        let result_path = format!("{}/result", working_dir);
        let output_path = format!("{}/{}", working_dir, output);

        tokio::fs::remove_file(&output_path).await.ok(); // Ignore if doesn't exist
        tokio::fs::symlink(&result_path, &output_path)
            .await
            .context("Failed to create symlink")?;

        info!("✅ Build complete: {}", output);
    } else {
        info!("✅ Build complete: result");
    }
    println!();

    // Push to Attic cache - RECURSIVE CLOSURE PUSH (per-derivation caching)
    if push_cache {
        println!();
        info!("📤 Pushing entire build closure to Attic cache...");
        info!("   This includes ALL derivations (granular caching)");

        let result_path = format!("{}/{}", working_dir, output);
        let cache_ref = format!("{}:{}", attic_server, cache_name);

        // Enumerate the recursive closure via the canonical typed
        // primitive `crate::nix::path_info_recursive`. Lifts the
        // pre-migration raw `nix path-info --recursive <result>` spawn
        // stanza (the bare `Command::new` at literal `"nix"` shape) onto
        // three load-bearing properties this call previously bypassed:
        //   1. `NIX_BIN` env override via `get_tool_path` — the
        //      pre-migration raw-spawn ignored the env var every other
        //      nix-invocation site in the workspace honors, so a
        //      Nix-hermetic runner with a store-path `nix` binary fell
        //      through to whatever `nix` was first on PATH here.
        //   2. Typed-error dispatch — pre-migration the exit-code +
        //      stderr fused into a bare `warn!("⚠️ Failed to get
        //      closure info (non-fatal)")` line that dropped BOTH the
        //      exit code and the captured stderr entirely. Post-
        //      migration the failure surfaces as typed
        //      `NixBuildError::ExecFailed` / `NixBuildError::
        //      PathInfoFailed` carrying the structural-record tuple
        //      Phase 1 attestation records (THEORY §V.4) pattern-
        //      match on.
        //   3. `closure_size` derivation — pre-migration each of the
        //      three sites re-derived `.lines().count()`; post-
        //      migration the derivation lives at ONE construction
        //      surface (`crate::nix::path_info_recursive`).
        // The non-fatal contract this site had (closure-enumeration
        // failure did not abort the build — the built image is still
        // shippable without the per-derivation Attic cache warm-up) is
        // preserved by matching on the returned `Result` at this call
        // site with the site-specific `⚠️ Failed to get closure info`
        // warning text.
        match crate::nix::path_info_recursive(&result_path).await {
            Err(e) => warn!("⚠️  Failed to get closure info (non-fatal): {}", e),
            Ok(info) => {
                info!("   Found {} derivations in closure", info.closure_size);

                // Push all derivations via stdin onto the canonical typed
                // primitive (third sibling of the lifted stanza family —
                // `commands/rust_service.rs::push_rust_service` AMD64+ARM64
                // are the other two; THEORY §VI.1 three-is-a-law).
                // Typed-error op-failure path carries (cache, exit_code,
                // stderr) per THEORY §V.4 Phase 1 attestation record shape.
                let attic_client =
                    crate::infrastructure::attic::AtticClient::new(cache_ref.clone())
                        .with_token(attic_token.clone());
                match attic_client
                    .push_closure_via_stdin(info.stdout.as_slice())
                    .await
                {
                    Ok(()) => info!(
                        "✅ All {} derivations cached in Attic (60-80% faster future builds)",
                        info.closure_size
                    ),
                    Err(e) => warn!("⚠️  Failed to push closure to Attic (non-fatal): {}", e),
                }
            }
        }
    }

    // Show image size
    let result_path = format!("{}/{}", working_dir, output);
    if let Ok(metadata) = tokio::fs::metadata(&result_path).await {
        let size_mb = metadata.len() as f64 / 1024.0 / 1024.0;
        println!();
        info!("📦 Image size: {:.1} MB", size_mb);
    }

    println!();
    println!("{}", "✅ Build complete!".bright_green().bold());
    println!();

    Ok(())
}

#[cfg(test)]
mod tests {
    /// Regression-shield: `commands/build.rs::execute` must route its
    /// Attic-login step through
    /// [`crate::infrastructure::attic::AtticClient::login_optional`]
    /// rather than spawning `attic` directly. Pre-migration a raw
    /// `Command::new("attic").args(&["login", server, url, token])
    /// .stdout(Stdio::null()).stderr(Stdio::null()).status()` body lived
    /// at this call site and bypassed two load-bearing properties the
    /// typed primitive carries: the `ATTIC_BIN` env override every other
    /// attic-invocation site honors via
    /// `get_tool_path("ATTIC_BIN", "attic")`, and the typed
    /// [`crate::error::AtticError`] dispatch
    /// (`ExecFailed` vs `LoginFailed` vs `TokenRequired`) the untyped
    /// `Result<ExitStatus>` collapsed away — a distinction Phase 1
    /// attestation records (THEORY §V.4) rely on so a "cache
    /// misconfigured" telemetry entry is separable from an "attic
    /// binary missing" one at the type level.
    ///
    /// This test reads this module's own source via [`include_str!`] and
    /// asserts the raw `Command::new("attic").args(&["login"` string
    /// does not reappear inside `execute()` while the delegation to
    /// `AtticClient::new(...).with_token(...).login_optional(...)` does.
    /// A future regression that re-fuses the raw-spawn body fails here,
    /// not silently in production where a bypassed `ATTIC_BIN` override
    /// or dropped typed-error dispatch would surface only as a
    /// mysterious "attic not found" or a silently-ignored bad-token
    /// login (which the subsequent `nix build` would report as a
    /// substituter-fetch failure with no structural link back to the
    /// login-time cause).
    ///
    /// The check is deliberately structural (substring on the source
    /// text) rather than behavioral — a behavioral test would require
    /// wiring up the full `execute` flow with mocked nix / attic /
    /// filesystem surfaces, which is disproportionate to the invariant
    /// being pinned. Same regression-shield discipline as
    /// `commands/push.rs::tests::test_execute_routes_attic_push_through_attic_client_not_raw_command`.
    #[test]
    fn test_execute_routes_attic_login_through_attic_client_not_raw_command() {
        const SOURCE: &str = include_str!("build.rs");

        // Locate the `execute` function body. The regression-shield only
        // cares about code inside `execute`, not the docstring/test
        // module which legitimately references the pre-migration string
        // for context.
        let execute_marker = "pub async fn execute(";
        let start = SOURCE
            .find(execute_marker)
            .expect("build.rs must contain `pub async fn execute(` — module invariant");
        let after_execute = &SOURCE[start..];
        // Bound the search at the tests module marker so the docstring
        // in THIS test — which legitimately spells the pre-migration
        // `Command::new("attic").args(&["login"` string for context — is
        // excluded from the scan. Every real code site sits strictly
        // between the `execute(` marker and the `#[cfg(test)]` marker.
        let end_relative = after_execute
            .find("\n#[cfg(test)]")
            .expect("build.rs must contain `#[cfg(test)]` tests module — this module's own marker");
        let execute_body = &after_execute[..end_relative];

        assert!(
            !execute_body.contains("Command::new(\"attic\").args(&[\"login\""),
            "execute() must NOT spawn `attic login` directly — route through \
             `crate::infrastructure::attic::AtticClient::new(...).with_token(...)\
             .login_optional(...)` so `ATTIC_BIN` overrides and the typed \
             `AtticError` dispatch both land at the shared primitive. Found \
             the pre-migration raw-spawn body in execute()."
        );
        assert!(
            execute_body.contains("AtticClient::new"),
            "execute() must construct an `AtticClient` for the login step \
             — the `AtticClient::new` string was not found in execute()."
        );
        assert!(
            execute_body.contains("login_optional"),
            "execute() must call `login_optional(...)` to preserve the \
             non-fatal-on-failure contract while inheriting the env \
             resolution and typed error dispatch — the call string was \
             not found in execute()."
        );
    }

    /// Regression-shield: `commands/build.rs::execute` must route its
    /// Attic-`use` (cache-selection) step through
    /// [`crate::infrastructure::attic::AtticClient::use_cache`] rather
    /// than spawning `attic` directly. Pre-migration a raw
    /// `Command::new("attic").args(&["use", &format!("{server}:{cache}")])
    /// .stdout(Stdio::null()).stderr(Stdio::null()).status()` body lived
    /// at this call site and bypassed two load-bearing properties the
    /// typed primitive carries: the `ATTIC_BIN` env override every
    /// other attic-invocation site honors via
    /// `get_tool_path("ATTIC_BIN", "attic")`
    /// (`infrastructure/attic.rs::resolve_attic_bin`), and the typed
    /// [`crate::error::AtticError`] dispatch (`ExecFailed` vs
    /// `UseFailed`) the untyped `Result<ExitStatus>` collapsed away —
    /// a distinction Phase 1 attestation records (THEORY §V.4) rely
    /// on so a "wrong server alias" telemetry entry is separable from
    /// an "attic binary missing" one at the type level, and the
    /// `Stdio::null()` stderr suppression that previously erased the
    /// underlying attic error message is inverted by the primitive
    /// (which pipes stderr through `classify_capture` into the typed
    /// variant's `stderr` field).
    ///
    /// This test reads this module's own source via [`include_str!`]
    /// and asserts the raw `Command::new("attic").args(&["use"` string
    /// does not reappear inside `execute()` while the delegation to
    /// `AtticClient::new(...).use_cache(...)` does. A future regression
    /// that re-fuses the raw-spawn body fails here, not silently in
    /// production where a bypassed `ATTIC_BIN` override or dropped
    /// typed-error dispatch would surface only as a mysterious
    /// substituter-fetch failure from the subsequent `nix build` with
    /// no structural link back to the mis-`use`d cache.
    ///
    /// Sibling of the login-step regression shield above; the two
    /// together pin the "no raw attic spawn survives in execute()"
    /// floor across both post-config attic subcommands (`login` seeds
    /// the token, `use` selects the active cache). Same structural-
    /// substring discipline as
    /// `commands/push.rs::tests::test_execute_routes_attic_push_through_attic_client_not_raw_command`.
    #[test]
    fn test_execute_routes_attic_use_through_attic_client_not_raw_command() {
        const SOURCE: &str = include_str!("build.rs");

        let execute_marker = "pub async fn execute(";
        let start = SOURCE
            .find(execute_marker)
            .expect("build.rs must contain `pub async fn execute(` — module invariant");
        let after_execute = &SOURCE[start..];
        // Bound the search at the tests module marker so the docstring
        // in THIS test — which legitimately spells the pre-migration
        // `Command::new("attic").args(&["use"` string for context — is
        // excluded from the scan. Every real code site sits strictly
        // between the `execute(` marker and the `#[cfg(test)]` marker.
        let end_relative = after_execute
            .find("\n#[cfg(test)]")
            .expect("build.rs must contain `#[cfg(test)]` tests module — this module's own marker");
        let execute_body = &after_execute[..end_relative];

        assert!(
            !execute_body.contains("Command::new(\"attic\").args(&[\"use\""),
            "execute() must NOT spawn `attic use` directly — route through \
             `crate::infrastructure::attic::AtticClient::new(...).use_cache(...)` \
             so `ATTIC_BIN` overrides and the typed `AtticError` dispatch \
             both land at the shared primitive. Found the pre-migration \
             raw-spawn body in execute()."
        );
        assert!(
            execute_body.contains("use_cache"),
            "execute() must call `use_cache(...)` to route the cache-selection \
             step through the typed primitive — the call string was not found \
             in execute()."
        );
    }

    /// Whole-module shield: no raw `Command::new("nix")` may live in
    /// this module's non-test body. Every `nix` spawn in
    /// `commands/build.rs` must first resolve `NIX_BIN` via
    /// [`crate::repo::get_tool_path`] — the canonical env-var override
    /// every other nix-invocation site in forge honors
    /// (`commands/tool.rs::build_lock_target`,
    /// `nix.rs::build_flake_attr_in`,
    /// `nix.rs::build_docker_image_from_dir`,
    /// `nix.rs::path_info_recursive`,
    /// `nix_hooks.rs::NixHooks::build_and_get_path`,
    /// `commands/developer_tools.rs::rust_update_cargo_nix` and
    /// siblings).
    ///
    /// Pre-lift `execute()`'s primary `nix build .#<flake_attr>` site
    /// spelled `Command::new("nix")` verbatim, ignoring `NIX_BIN` at
    /// exactly the moment hermetic-runner consistency matters most —
    /// `forge build` is THE build-platform entrypoint. A Nix-hermetic
    /// runner with a store-path `nix` binary silently fell through to
    /// whatever `nix` was first on PATH at this specific site,
    /// diverging from every other nix-invocation surface in forge and
    /// from the sibling KUBECTL_BIN / GIT_BIN frontier's uniform
    /// discipline (5bb7cff / 818ed9a).
    ///
    /// The scan bounds on the whole-module boundary (from the file
    /// start to the `\n#[cfg(test)]\nmod tests {` marker below) so
    /// this shield's own docstring mentions of `Command::new("nix")`
    /// (which live inside this `#[cfg(test)] mod tests` block) stay
    /// out of scope AND every current or future nix-spawning helper
    /// landing anywhere in the top-level module body cannot silently
    /// ride along without going through `NIX_BIN`. Mirrors the
    /// sibling whole-module shield on
    /// `commands/developer_tools.rs::test_developer_tools_routes_nix_through_nix_bin_not_raw_command`
    /// (4dfb2b3) and matches the whole-module-boundary scan discipline
    /// pioneered on `commands/supergraph_verification.rs` (65283fb).
    #[test]
    fn test_execute_routes_nix_through_nix_bin_not_raw_command() {
        const SOURCE: &str = include_str!("build.rs");
        let cutoff = SOURCE.find("\n#[cfg(test)]\nmod tests {").expect(
            "build.rs must have a `#[cfg(test)] mod tests {` marker \
             — the shield's scan boundary depends on it",
        );
        let body = &SOURCE[..cutoff];
        assert!(
            !body.contains("Command::new(\"nix\")"),
            "commands/build.rs must not spawn `nix` via the bare literal — \
             every `nix` spawn must resolve `NIX_BIN` via \
             `crate::repo::get_tool_path(\"NIX_BIN\", \"nix\")` first. \
             A raw `Command::new(\"nix\")` bypasses the hermetic-runner \
             contract substrate's mkRuntimeToolsEnv exports."
        );
        assert!(
            body.contains("get_tool_path(\"NIX_BIN\", \"nix\")"),
            "commands/build.rs must resolve the nix binary via \
             `get_tool_path(\"NIX_BIN\", \"nix\")` — the canonical \
             lookup was not found in the module body."
        );
    }

    /// Whole-module shield: every status-only spawn in
    /// `commands/build.rs` routes through
    /// [`crate::retry::run_inherited_status`], never a hand-rolled
    /// `.status().await` + `if !…success() { bail! }` stanza that
    /// drops the exit code from the operator log line. Pre-lift the
    /// `nix build` spawn spelled the inline stanza with an ad-hoc
    /// `bail!("Nix build failed")` that carried no exit code — the
    /// same exit-code-drop regression the sync sibling shields
    /// (`commands/{crossplane, pangea_infra, gem, infra, tool}.rs`,
    /// a3d51eb through 6cb9442) close on the sync frontier. Post-
    /// lift the delegation call routes through the primitive and the
    /// canonical `"nix build failed (exit {code})"` envelope emerges
    /// at the primitive's ONE body (THEORY.md §VI.1: the three-times
    /// rule redeemed by lifting to an archetype rather than
    /// re-spelling the stanza).
    ///
    /// Negative side: the inline `.status().await` builder-terminator
    /// must not reappear at any code line in the module body (a
    /// re-inlined spawn would bypass the primitive and re-drop the
    /// exit code). Positive side: the delegation call must appear at
    /// ≥1 code line — a regression that deleted the primitive call
    /// cannot leave the negative scan trivially satisfied by absence.
    /// Both hits route through [`crate::test_support::code_line_hits`]
    /// for anti-docstring-self-match discipline (`.status().await`
    /// legitimately appears in this shield's own docstring above; the
    /// code-line filter excludes it). Same scan boundary (first
    /// `\n#[cfg(test)]\nmod tests {` marker) the whole-module
    /// `NIX_BIN` shield above uses, so the two shields see identical
    /// module-body byte spans.
    #[test]
    fn test_build_status_spawns_route_through_run_inherited_status() {
        crate::test_support::assert_source_routes_status_only_spawns_through_run_inherited_status(
            include_str!("build.rs"),
            "commands/build.rs",
            1,
            "its `nix build` spawn",
        );
    }
}
