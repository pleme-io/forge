use anyhow::{Context, Result};
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use std::process::Stdio;
use tokio::process::Command;
use tracing::{info, warn};

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

    // Use cache
    Command::new("attic")
        .args(&["use", &format!("{}:{}", attic_server, cache_name)])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .context("Failed to configure Attic cache")?;

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
    let mut cmd = Command::new("nix");
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

    let build_result = cmd.status().await.context("Failed to run nix build")?;

    spinner.finish_and_clear();

    if !build_result.success() {
        anyhow::bail!("Nix build failed");
    }

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

        // Get all derivations in the closure
        let path_info_output = Command::new("nix")
            .args(&["path-info", "--recursive", &result_path])
            .output()
            .await
            .context("Failed to run nix path-info")?;

        if !path_info_output.status.success() {
            warn!("⚠️  Failed to get closure info (non-fatal)");
        } else {
            let paths = String::from_utf8_lossy(&path_info_output.stdout);
            let closure_size = paths.lines().count();
            info!("   Found {} derivations in closure", closure_size);

            // Push all derivations via stdin onto the canonical typed
            // primitive (third sibling of the lifted stanza family —
            // `commands/rust_service.rs::push_rust_service` AMD64+ARM64
            // are the other two; THEORY §VI.1 three-is-a-law).
            // Typed-error op-failure path carries (cache, exit_code,
            // stderr) per THEORY §V.4 Phase 1 attestation record shape.
            let attic_client = crate::infrastructure::attic::AtticClient::new(cache_ref.clone())
                .with_token(attic_token.clone());
            match attic_client
                .push_closure_via_stdin(path_info_output.stdout.as_slice())
                .await
            {
                Ok(()) => info!(
                    "✅ All {} derivations cached in Attic (60-80% faster future builds)",
                    closure_size
                ),
                Err(e) => warn!("⚠️  Failed to push closure to Attic (non-fatal): {}", e),
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
}
