//! # Rust Service Release Management
//!
//! This module handles the complete release workflow for Rust microservices:
//! 1. Build with crate2nix (per-crate caching via Attic)
//! 2. Push to GHCR and Attic registries
//! 3. Deploy via GitOps (commit + push to manifest repo)
//! 4. Flux reconciliation
//! 5. Database migrations (PostgreSQL, ClickHouse, or Elasticsearch)
//! 6. GraphQL schema extraction
//! 7. Apollo Federation supergraph composition
//!
//! ## Migration System Requirements
//!
//! Services MUST implement `main.rs` logic to handle the `RUN_MODE` environment variable:
//!
//! - `RUN_MODE=migrate` - Run PostgreSQL migrations using sqlx
//! - `RUN_MODE=migrate_clickhouse` - Run ClickHouse migrations using clickhouse-rs
//! - `RUN_MODE=migrate_elasticsearch` - Run Elasticsearch migrations using elasticsearch-rs
//!
//! Example implementation:
//! ```rust,ignore
//! #[tokio::main]
//! async fn main() -> Result<()> {
//!     match std::env::var("RUN_MODE").as_deref() {
//!         Ok("migrate") => run_postgres_migrations().await,
//!         Ok("MIGRATE") => run_migrations().await, // For Databend (uses sqlx like PostgreSQL)
//!         Ok("migrate_elasticsearch") => run_elasticsearch_migrations().await,
//!         _ => start_server().await,
//!     }
//! }
//! ```

use crate::commands::service_config::{DatabaseType, ServiceConfig};
use crate::config::{resolve_deploy_yaml_path, DeployConfig};
use crate::infrastructure::kubectl::kubectl_command_async;
use crate::infrastructure::registry::{ArchImage, RegistryClient, RegistryCredentials};
use crate::path_builder::PathBuilder;
use crate::repo::get_tool_path;
use crate::ui::print_success_banner;
use anyhow::{anyhow, bail, Context, Result};
use colored::Colorize;
use std::env;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::process::Command;
use tokio::select;

/// Resolve the `ps` binary path via `PS_BIN`, falling back to `ps` on
/// `PATH`. Wired through [`crate::repo::get_tool_path`] — the canonical
/// env-var-or-PATH lookup the sibling `docker_bin` and `open_bin` sigils
/// on `commands/e2e.rs` (23241a6 / 8f4c717) ride on, and the same two-arg
/// `get_tool_path("<TOOL>_BIN", "<tool>")` convention every other
/// substrate-declared tool-spawn site in forge honors (`SH_BIN` b382b78;
/// `{SSH,NC,DIG}_BIN` 5e6672d; `SQLX_BIN` ecace0a; `SEA_ORM_CLI_BIN`
/// b037895; `NOVASEARCHCTL_BIN` 19463db; `OPEN_BIN` 8f4c717).
///
/// The single spawn site lives in [`release_rust_service`], where the
/// concurrent-release-lock check reads `/tmp/forge-<service>.lock`,
/// parses the PID it contains, and shells out `ps -p <pid>` to test
/// whether the prior release process is still alive. Pre-lift that site
/// spawned `ps` via a bare tool-name literal on
/// `std::process::Command`, bypassing `PS_BIN` at exactly the moment
/// the concurrent-release interlock guarantees serialisation across
/// `forge push-rust-service` invocations. A Nix-hermetic runner whose
/// derivation exports `PS_BIN=/nix/store/…-procps/bin/ps` but omits
/// `ps` from `PATH` silently fell through to whatever `ps` was first on
/// `PATH`; on a runner with no `ps` on `PATH` at all, the spawn's
/// `.output()` call resolved to `Err(_)` and the interlock treated the
/// lock as stale — permitting a concurrent release the guard exists to
/// prevent. Post-lift the site observes the same substrate-declared
/// path every other spawn site in this module observes.
fn ps_bin() -> String {
    get_tool_path("PS_BIN", "ps")
}

/// Resolve the `nix` binary path via `NIX_BIN`, falling back to `nix` on
/// `PATH`. Wired through [`crate::repo::get_tool_path`] — the canonical
/// env-var-or-PATH lookup every other nix-invocation site in forge honors
/// (`commands/build.rs::execute` d8ef0d5,
/// `commands/tool.rs::build_lock_target`,
/// `nix.rs::build_flake_attr_in`,
/// `nix.rs::build_docker_image_from_dir`,
/// `nix.rs::path_info_recursive`,
/// `nix_hooks.rs::NixHooks::build_and_get_path`,
/// `commands/developer_tools.rs::rust_update_cargo_nix` and siblings
/// 4dfb2b3).
///
/// Sixth landing of the `<tool>_bin()` sigil pattern after
/// `commands/test_ci.rs:28` (916f1a4),
/// `commands/prerelease.rs:109` (79e03a5),
/// `commands/developer_tools.rs:36` (534ef48),
/// `commands/e2e.rs:87` (170ecac),
/// `commands/tool.rs:37` (9f6046b) — CARGO surface — and
/// `commands/frontend_validation.rs` (9986f11) — BUN_BIN surface. First
/// landing on the NIX_BIN surface. `rust_service.rs` was the biggest
/// remaining nix-spawning outlier still respelling the two-argument
/// resolve at every consumer — three live sites (the
/// `check_cross_compilation_available` `show-config` probe, the
/// `build_rust_service` primary `nix build .#<pkg>` AMD64 site, and the
/// `release_rust_service` federation-tests `nix run .#release` site)
/// plus one dead sibling inside a TODO block comment, all pre-lift
/// respelling the two-argument `NIX_BIN` resolve verbatim at each
/// consumer. The pre-existing whole-module bare-literal-spawn
/// shield closed the raw-literal-spawn class; this sigil closes the
/// re-copied-resolve class by pinning the two-argument resolve at
/// exactly one place — the sigil body — and adding a count-eq-1
/// assertion the sibling `cargo_bin` / `bun_bin` sigil family already
/// carries.
///
/// A Nix-hermetic runner whose derivation exports
/// `NIX_BIN=/nix/store/…/bin/nix` but omits `nix` from `PATH` silently
/// fell through to whatever `nix` was first on `PATH` at each pre-lift
/// site — every cross-compilation-probe / crate-build / federation-tests
/// release verdict was attributed to whichever `nix` PATH resolved
/// first, not to the substrate-pinned nix derivation the flake
/// declared. Post-lift every site observes the same substrate-declared
/// path every other nix-invocation site in forge observes.
fn nix_bin() -> String {
    get_tool_path("NIX_BIN", "nix")
}

/// Compute the tag to use for deployment.
///
/// In normal mode: `tag_suffix` is a raw git SHA, deploy tag is `{arch}-{sha}`
/// In deploy-only mode: `tag_suffix` IS the deploy tag (e.g., "amd64-bb90b44"), used as-is
/// In multi-arch mode: deploy tag is `{sha}` (manifest list)
fn compute_deploy_tag(tag_suffix: &str, arch: &str, deploy_only: bool, has_arm64: bool) -> String {
    if deploy_only {
        tag_suffix.to_string()
    } else if has_arm64 {
        tag_suffix.to_string()
    } else {
        format!("{}-{}", arch, tag_suffix)
    }
}

/// Resolve deploy.yaml path from SERVICE_DIR, checking deploy/{service_name}.yaml first.
///
/// Routes the `SERVICE_DIR` env-var read through the shared
/// [`crate::repo::path_from_env`] primitive (introduced at `repo.rs:127`
/// by d8e6626 and explicitly named in that commit's body as the
/// three-times-is-a-law third caller pending migration), so the
/// `env::var → Context::context → PathBuf::from` composition lives at
/// EXACTLY one point across the crate. The module's domain-specific
/// miss wording `"SERVICE_DIR not set - required for deploy.yaml
/// lookup"` — the third distinct wording alongside
/// `commands/developer_tools.rs`'s `"SERVICE_DIR not set - this should
/// be called via substrate wrapper"` and `commands/schema_validation.rs`'s
/// `"SERVICE_DIR environment variable not set"` — stays grep-visible
/// verbatim at the delegating call so the operator-facing diagnostic
/// prose the caller has been coached to grep for is preserved.
fn resolve_deploy_yaml_from_service_dir() -> Result<PathBuf> {
    let service_dir_path = crate::repo::path_from_env(
        "SERVICE_DIR",
        "SERVICE_DIR not set - required for deploy.yaml lookup",
    )?;
    let service_name = service_dir_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown");

    // Walk up to find product directory — the standalone-or-monorepo
    // arm because a Rust service may live inside a `pkgs/products/{product}`
    // monorepo subtree OR as a standalone product repository whose root
    // carries both `deploy.yaml` and `.git`.
    let product_dir = crate::repo::find_product_dir(
        &service_dir_path,
        crate::repo::ProductDirLayout::MonorepoOrStandalone,
    );
    let deploy_path = if let Some(pd) = product_dir {
        resolve_deploy_yaml_path(&pd, service_name, &service_dir_path)
    } else {
        service_dir_path.join("deploy.yaml")
    };

    Ok(deploy_path)
}

/// Check if Cargo.nix exists (should be generated by Nix flake before calling this)
fn check_cargo_nix_exists() -> Result<()> {
    if !Path::new("Cargo.nix").exists() {
        bail!(
            "❌ Cargo.nix not found!\n\
             \n\
             This should have been generated automatically by the Nix flake.\n\
             If you see this error, the flake wrapper needs to be updated.\n\
             \n\
             Manual workaround:\n\
                nix run .#generateCargoNix\n\
                git add Cargo.nix\n\
                git commit -m 'chore: add Cargo.nix'"
        );
    }
    Ok(())
}

/// Check if an environment variable is set and non-empty
fn check_token(var_name: &str) -> bool {
    env::var(var_name)
        .map(|val| !val.is_empty())
        .unwrap_or(false)
}

/// Get git hash for tagging - Single source of truth
///
/// CRITICAL: To avoid the "one-cycle lag" bug where deploy commits shift HEAD,
/// this function checks for RELEASE_GIT_SHA environment variable FIRST.
/// The Nix release wrapper captures this at the START of the release, before
/// any git commits are made.
///
/// Priority:
/// 1. RELEASE_GIT_SHA env var (set by Nix wrapper at release start)
/// 2. git rev-parse --short HEAD (fallback for direct CLI usage)
pub async fn get_tag_suffix() -> Result<String> {
    // Check for RELEASE_GIT_SHA environment variable first — routed
    // through the crate-scoped `crate::git::release_git_sha_from_env`
    // sigil. The Nix release wrapper captures this at the START of
    // the release, before any deploy commits shift HEAD, so this
    // path always tags against the code commit SHA even when deploy
    // steps have made later commits. Sibling consumers:
    // `commands/push.rs::get_git_sha` and
    // `commands/product_release.rs::execute` (both route through the
    // same sigil).
    if let Some(sha) = crate::git::release_git_sha_from_env() {
        return Ok(sha);
    }

    // Fallback to git rev-parse for direct CLI usage — routed through
    // the canonical async sibling of `git::get_short_sha`. See
    // `cli/src/commands/push.rs::get_git_sha` for the corresponding
    // priority shape; both consumers share the "RELEASE_GIT_SHA env
    // first, then bare git rev-parse" order but each defines its own
    // env-var priority chain locally.
    let hash = crate::git::get_short_sha_async().await.context(
        "Failed to get git SHA for image tagging. \
         Ensure you're in a git repository with committed changes.",
    )?;
    if hash.is_empty() {
        bail!("Git returned empty SHA - repository may be corrupted");
    }
    Ok(hash)
}

/// Write .version file to the service directory
/// This is a backup mechanism - the primary method is GIT_SHA environment variable
/// Returns the path where the file was written, or an error if it failed
async fn write_version_file(
    git_sha: &str,
    deploy_config: &DeployConfig,
) -> Result<std::path::PathBuf> {
    // Get the actual writable service directory in the git repository
    // Structure: {repo_root}/pkgs/products/{product}/services/rust/{service}
    let repo_root = crate::git::get_repo_root()?;
    let service_dir = repo_root
        .join(&deploy_config.global.paths.products_root)
        .join(&deploy_config.product.name)
        .join(&deploy_config.global.paths.services_path)
        .join(&deploy_config.service.name);

    let version_file = service_dir.join(".version");

    // Write the file
    tokio::fs::write(&version_file, git_sha)
        .await
        .with_context(|| {
            format!(
                "Failed to write .version file to {}",
                version_file.display()
            )
        })?;

    Ok(version_file)
}

/// Detect if cross-compilation to ARM64 is available
fn check_cross_compilation_available() -> bool {
    // Check for qemu-aarch64-static
    if which::which("qemu-aarch64-static").is_ok() {
        return true;
    }

    // Check for aarch64-linux in Nix remote builders
    let nix_bin = nix_bin();
    if let Ok(output) = std::process::Command::new(&nix_bin)
        .args(&["show-config"])
        .output()
    {
        let config = crate::repo::utf8_lossy_borrow(&output.stdout);
        if config.contains("aarch64-linux") {
            return true;
        }
    }

    false
}

/// Build Rust service Docker images (AMD64 + ARM64 with cross-compilation detection)
pub async fn build_rust_service(
    service: String,
    cache_url: String,
    cache_name: String,
    _attic_token: String,
    deploy_config: &DeployConfig,
) -> Result<()> {
    println!(
        "🔨 {} {} {}",
        "Building".bold(),
        service.cyan(),
        "with crate2nix (per-crate caching enabled)".dimmed()
    );
    crate::ui::print_ascii_title_underline(50);

    // Pre-flight checks
    println!("🔍 {}", "Pre-flight checks...".bold());
    check_cargo_nix_exists()?;

    // Check ATTIC_TOKEN from environment (set by Nix wrapper)
    let has_attic_token = check_token("ATTIC_TOKEN");
    if has_attic_token {
        println!("✅ ATTIC_TOKEN configured");
    } else {
        println!(
            "{}",
            "⚠️  Warning: ATTIC_TOKEN not set, builds will not use Attic cache".yellow()
        );
    }

    // Remove existing symlinks to avoid conflicts
    for symlink in &["result-amd64", "result-arm64"] {
        if Path::new(symlink).exists() {
            std::fs::remove_file(symlink)
                .with_context(|| format!("Failed to remove existing symlink: {}", symlink))?;
        }
    }

    // Detect cross-compilation availability
    let build_arm64 = crate::repo::env_var_or_default("BUILD_ARM64", "auto");
    let should_build_arm64 = match build_arm64.as_str() {
        "no" => false,
        "force" => true,
        "auto" | _ => {
            let host_arch = env::consts::ARCH;
            if host_arch == "x86_64" {
                let available = check_cross_compilation_available();
                if available {
                    println!("✅ Cross-compilation to ARM64 available");
                } else {
                    crate::ui::print_step_info(
                        "Skipping ARM64 build (cross-compilation not configured)",
                    );
                    println!("   To enable: install qemu-user-static or configure remote builders");
                    println!("   Or set: export BUILD_ARM64=force");
                }
                available
            } else {
                true // On ARM hosts, can build ARM64 natively
            }
        }
    };
    println!();

    // Compute git SHA for build tagging and version embedding
    let git_sha = get_tag_suffix().await?;
    println!("🏷️  Git SHA: {}", git_sha);
    println!();

    // Write .version file for Nix to read (backup mechanism)
    // The primary method is GIT_SHA environment variable with --impure flag
    // This file is optional - if write fails, we continue with env var only
    println!("📝 Writing .version file...");
    match write_version_file(&git_sha, deploy_config).await {
        Ok(path) => {
            println!("   ✓ .version file written to: {}", path.display());
        }
        Err(e) => {
            eprintln!(
                "   {}",
                format!("⚠️  Warning: Could not write .version file: {}", e).yellow()
            );
            eprintln!(
                "   {}",
                "   Continuing with GIT_SHA environment variable (--impure flag)".dimmed()
            );
        }
    }
    println!();

    // Build AMD64 (always)
    println!("📦 {}", "Building AMD64 image...".bold());

    // Construct full cache URL with cache name (Attic serves caches at {url}/{cache-name})
    let full_cache_url = format!("{}/{}", cache_url.trim_end_matches('/'), cache_name);

    // Compute package attribute path from root flake
    // Root flake pattern: packages are named {product}-{service}
    // Example: myapp-auth, myapp-payment
    let package_attr = format!(".#{}-{}", deploy_config.product.name, service);

    // Nix Performance Optimization Strategy:
    // - max-jobs=auto: Parallelize builds across all CPU cores
    // - cores=0: Each job uses all available cores (optimal for large builds)
    // - keep-going: Don't fail entire build on first error (better for parallel builds)
    // - eval-cache: Reuse evaluation results (massive speedup on repeated builds)
    // - connect-timeout=5: Quick fallback if substituter is slow
    // - impure: Allow builtins.getEnv to read GIT_SHA environment variable
    //
    // These settings work with both regular Nix and Determinate Nix for maximum performance.
    // Your nix.conf already has good defaults, these flags ensure they're always applied.

    // Root flake pattern: Simple nix build from repo root
    // No --override-input needed, no service flake complexity
    let nix_bin = nix_bin();
    let mut cmd = Command::new(&nix_bin);
    cmd.args(&[
        "build",
        &package_attr, // e.g., .#myapp-auth
        "--out-link",
        "result-amd64",
        "--system",
        "x86_64-linux",          // Force AMD64 build (use remote builder on Mac)
        "--impure",              // Allow reading GIT_SHA environment variable
        "--no-update-lock-file", // Use committed lock file
        // Performance: Use all available cores
        "--max-jobs",
        "auto",
        "--cores",
        "0",
        "--keep-going",
        "--eval-cache",
        // Cache configuration: Prioritize Attic cache
        "--option",
        "extra-substituters",
        &full_cache_url,
        "--option",
        "extra-trusted-public-keys",
        "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=",
        "--option",
        "connect-timeout",
        &deploy_config
            .global
            .deployment
            .nix_connect_timeout_secs
            .to_string(),
    ]);

    // Set GIT_SHA environment variable for Nix to read with builtins.getEnv
    // Also wrote .version file earlier as backup (belt and suspenders approach)
    cmd.env("GIT_SHA", &git_sha);

    // Configure Attic authentication via access-tokens if token is available
    if has_attic_token {
        let token = env::var("ATTIC_TOKEN").unwrap();
        // Extract hostname from full cache URL for access-tokens config
        let cache_host = full_cache_url
            .replace("https://", "")
            .replace("http://", "")
            .split('/')
            .next()
            .unwrap_or("")
            .to_string();
        let access_token_config = format!("{}={}", cache_host, token);
        cmd.args(&["--option", "access-tokens", &access_token_config]);

        // Enable attic post-build-hook for per-derivation caching
        // This automatically pushes EVERY built derivation (per-crate in crate2nix)
        // to Attic during the build, maximizing cache utilization
        //
        // Auto-discovers nix-hooks package by building .#nix-hooks.
        // Delegates the four-line argv+env splice through the canonical
        // wire primitive `crate::nix_hooks::wire_post_build_hook_env` so
        // a future refinement of the hook's env contract lands at ONE
        // body and reaches every consumer by construction (THEORY §V,
        // §VI.1).
        match crate::nix_hooks::NixHooks::discover().await {
            Ok(hooks) => {
                if let Some(hook_path) = hooks.attic_push_hook_path() {
                    println!("   ✅ Using attic post-build-hook: {}", hook_path.dimmed());
                    println!("   (Uploads EVERY built derivation automatically)");
                    crate::nix_hooks::wire_post_build_hook_env(
                        &mut cmd,
                        &hook_path,
                        &cache_name,
                        &full_cache_url,
                        &token,
                    );
                } else {
                    println!(
                        "   {}",
                        "⚠️  nix-hooks available but attic-push-hook not found".yellow()
                    );
                }
            }
            Err(e) => {
                println!(
                    "   {}",
                    format!("⚠️  Could not discover nix-hooks: {}", e).yellow()
                );
                println!("   (Per-derivation caching disabled, falling back to closure push)");
            }
        }
    }

    let amd64_build = cmd
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .context("Failed to spawn AMD64 build")?;

    // Build ARM64 (conditional)
    // Note: ARM64 packages not yet exposed in root flake, skip for now
    let arm64_build: Option<tokio::process::Child> = if should_build_arm64 {
        println!();
        println!("📦 {}", "Building ARM64 image...".bold());
        println!("   ⚠️  Warning: ARM64 packages not yet exposed in root flake, skipping");
        println!("   To add ARM64 support:");
        println!(
            "   1. Add {}-{}-arm64 package to root flake.nix",
            deploy_config.product.name, service
        );
        println!("   2. Expose it in packages section");
        None

        // TODO: Uncomment when ARM64 packages are exposed in root flake
        /*
        let package_attr_arm64 = format!(".#{}-{}-arm64", deploy_config.product.name, service);

        let nix_bin = nix_bin();
        let mut arm64_cmd = Command::new(&nix_bin);
        arm64_cmd.args(&[
            "build",
            &package_attr_arm64,
            "--out-link",
            "result-arm64",
            "--system",
            "aarch64-linux",
            "--impure",
            "--no-update-lock-file",
            "--max-jobs",
            "auto",
            "--cores",
            "0",
            "--keep-going",
            "--eval-cache",
            "--option",
            "extra-substituters",
            &full_cache_url,
            "--option",
            "extra-trusted-public-keys",
            "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=",
            "--option",
            "connect-timeout",
            &deploy_config.global.deployment.nix_connect_timeout_secs.to_string(),
        ]);

        arm64_cmd.env("GIT_SHA", &git_sha);

        if has_attic_token {
            let token = env::var("ATTIC_TOKEN").unwrap();
            let cache_host = full_cache_url
                .replace("https://", "")
                .replace("http://", "")
                .split('/')
                .next()
                .unwrap_or("")
                .to_string();
            let access_token_config = format!("{}={}", cache_host, token);
            arm64_cmd.args(&["--option", "access-tokens", &access_token_config]);

            if let Ok(nix_hooks_path) = env::var("NIX_HOOKS_PATH") {
                let hook_path = format!("{}/bin/attic-push-hook", nix_hooks_path);
                if std::path::Path::new(&hook_path).exists() {
                    arm64_cmd.args(&["--option", "post-build-hook", &hook_path]);
                    arm64_cmd.env("ATTIC_CACHE", &cache_name);
                    arm64_cmd.env("ATTIC_SERVER", &full_cache_url);
                    arm64_cmd.env("ATTIC_TOKEN", &token);
                }
            }
        }

        Some(
            arm64_cmd
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .spawn()
                .context("Failed to spawn ARM64 build")?,
        )
        */
    } else {
        println!();
        println!("⏭️  {}", "Skipping ARM64 build".dimmed());
        None
    };

    // Wait for builds to complete
    let mut amd64_handle = amd64_build;
    let mut arm64_handle = arm64_build;

    let amd64_result = amd64_handle.wait().await?;
    let arm64_result = if let Some(mut handle) = arm64_handle {
        Some(handle.wait().await?)
    } else {
        None
    };

    // Check results
    if !amd64_result.success() {
        bail!("❌ AMD64 build failed!");
    }

    if let Some(arm64_status) = arm64_result {
        if !arm64_status.success() {
            bail!("❌ ARM64 build failed!");
        }
    }

    // Push to Attic cache - RECURSIVE CLOSURE PUSH (per-derivation caching)
    // This caches ALL Rust crate derivations, not just the final Docker image
    if has_attic_token {
        println!();
        println!(
            "📦 {}",
            "Pushing entire build closure to Attic cache...".bold()
        );
        println!("   This includes ALL Rust crate derivations (granular caching)");
        println!();

        let cache_target = format!("{}:{}", deploy_config.cache_server(), cache_name);

        // Push AMD64 closure recursively. Enumerates via the canonical
        // typed primitive `crate::nix::path_info_recursive` — sibling
        // of `commands/build.rs::execute` (THEORY §VI.1 three-is-a-law:
        // the ARM64 arm below is the third occurrence). The primitive
        // owns `NIX_BIN` env resolution, typed-error dispatch
        // (`NixBuildError::ExecFailed` / `NixBuildError::PathInfoFailed`
        // carrying the structural-record tuple per THEORY §V.4 Phase 1
        // attestation records), and `closure_size` derivation — the
        // three load-bearing properties the pre-lift raw-spawn stanza
        // bypassed at all three sites.
        println!("   Analyzing AMD64 closure...");
        match crate::nix::path_info_recursive("result-amd64").await {
            Err(e) => eprintln!("   ⚠️  Failed to get AMD64 closure info (non-fatal): {}", e),
            Ok(info) => {
                println!(
                    "   AMD64: Found {} derivations in closure",
                    info.closure_size
                );

                let attic_client =
                    crate::infrastructure::attic::AtticClient::new(cache_target.clone());
                match attic_client
                    .push_closure_via_stdin(info.stdout.as_slice())
                    .await
                {
                    Ok(()) => println!("   {}", "✅ AMD64 closure cached".green()),
                    Err(e) => eprintln!("   ⚠️  AMD64 closure push failed (non-fatal): {}", e),
                }
            }
        }

        // Push ARM64 closure recursively (if built). Third sibling of
        // the lifted stanza family — `commands/build.rs::execute` and
        // the AMD64 arm above are the other two; THEORY §VI.1
        // three-is-a-law. Typed-error op-failure path carries (cache,
        // exit_code, stderr) per THEORY §V.4 Phase 1 attestation
        // record shape.
        if should_build_arm64 {
            println!("   Analyzing ARM64 closure...");
            match crate::nix::path_info_recursive("result-arm64").await {
                Err(e) => {
                    eprintln!("   ⚠️  Failed to get ARM64 closure info (non-fatal): {}", e)
                }
                Ok(info) => {
                    println!(
                        "   ARM64: Found {} derivations in closure",
                        info.closure_size
                    );

                    let attic_client =
                        crate::infrastructure::attic::AtticClient::new(cache_target.clone());
                    match attic_client
                        .push_closure_via_stdin(info.stdout.as_slice())
                        .await
                    {
                        Ok(()) => println!("   {}", "✅ ARM64 closure cached".green()),
                        Err(e) => {
                            eprintln!("   ⚠️  ARM64 closure push failed (non-fatal): {}", e)
                        }
                    }
                }
            }
        }

        println!();
        println!(
            "   {}",
            "✅ All derivations cached in Attic (60-80% faster future builds)".green()
        );
    }

    println!();
    println!("✅ {}", "Build complete!".green().bold());
    println!("   AMD64: result-amd64");
    if should_build_arm64 {
        println!("   ARM64: result-arm64");
    }
    println!("   Per-crate derivations cached in Attic for 60-80% faster future builds");

    Ok(())
}

/// Verify image exists in registry and return its digest
/// This provides a cryptographic guarantee that we're deploying exactly what we pushed
async fn verify_image_in_registry(registry: &str, full_tag_suffix: &str) -> Result<String> {
    // Compose `<repository>:<tag>` via
    // `crate::oci_manifest::image_reference` — the typed
    // compositional inverse of `image_repository_and_tag`.
    let full_tag = crate::oci_manifest::image_reference(registry, full_tag_suffix);

    // Get token for authenticated registry access
    let github_token = RegistryCredentials::discover_token(None)
        .context("Registry token required for image verification")?;

    // Extract organization from registry URL for credentials
    let parsed_registry = crate::infrastructure::registry::RegistryRef::parse(registry).ok();
    let organization = parsed_registry
        .as_ref()
        .map_or("user", |r| r.organization());

    println!("   🔍 Verifying image in registry: {}", full_tag.dimmed());

    let doca = get_tool_path("DOCA_BIN", "oci-push");
    // CREDENTIALS BY ENV, NEVER ARGV: `--creds <org>:<token>` put the token in
    // /proc/<pid>/cmdline, readable by any co-tenant process on a shared runner
    // for as long as the command ran. doca reads INPUT_USER / INPUT_PASS.
    //
    // `--digest-only` replaces `--format {{.Digest}}` — both emit the OCI
    // manifest digest (`sha256:…`) and nothing else, so parsing is unchanged.
    let output = Command::new(&doca)
        .args(["inspect", "--ref", &full_tag, "--digest-only"])
        .env("INPUT_USER", organization)
        .env("INPUT_PASS", &github_token)
        .output()
        .await
        .context("Failed to run doca inspect")?;

    if !output.status.success() {
        let stderr = crate::repo::utf8_lossy_borrow(&output.stderr);
        bail!(
            "❌ Image not found in registry: {}\n   \
             This could mean:\n   \
             - Push failed silently\n   \
             - Registry is temporarily unavailable\n   \
             - Authentication issue\n   \
             Error: {}",
            full_tag,
            stderr.trim()
        );
    }

    let digest = crate::repo::utf8_lossy_trim_owned(&output.stdout);
    if digest.is_empty() {
        bail!("❌ Registry returned empty digest for {}", full_tag);
    }

    println!("   ✅ Image verified: {} ({})", full_tag, &digest[..19]);
    Ok(digest)
}

/// Verify that the image in registry matches the expected digest
/// Use this before deploying to ensure we're deploying exactly what we pushed
async fn verify_image_digest_matches(
    registry: &str,
    tag: &str,
    expected_digest: &str,
) -> Result<()> {
    let current_digest = verify_image_in_registry(registry, tag).await?;

    if current_digest != expected_digest {
        bail!(
            "❌ Image digest mismatch!\n   \
             Expected: {}\n   \
             Found:    {}\n   \
             This could indicate a race condition or registry issue.\n   \
             Aborting deployment for safety.",
            expected_digest,
            current_digest
        );
    }

    println!("   ✅ Digest verified: matches pushed image");
    Ok(())
}

/// Push docker images to the registry using the unified multi-arch strategy.
///
/// Accepts one or more (arch, path) pairs. For a single image, pushes with
/// arch-prefixed tags. For multiple images, also creates an OCI manifest index.
async fn push_docker_images(images: &[ArchImage], registry: &str, tag_suffix: &str) -> Result<()> {
    let organization = crate::infrastructure::registry::extract_organization(registry)
        .unwrap_or_else(|_| "user".to_string());

    let client = RegistryClient::discover(None, &organization)
        .context("Cannot authenticate with GHCR")?
        .with_retries(3);

    let arches: Vec<&str> = images.iter().map(|i| i.arch.as_str()).collect();
    println!(
        "📤 Pushing {} image{} to {}...",
        arches.join(" + "),
        if images.len() > 1 { "s" } else { "" },
        registry
    );

    let result = client
        .push_multiarch(registry, images, tag_suffix)
        .await
        .context("Multi-arch push failed")?;

    println!();
    for tag in &result.arch_tags {
        println!("   ✅ {}", tag);
    }
    for tag in &result.manifest_tags {
        println!("   ✅ {} (manifest index)", tag);
    }

    Ok(())
}

/// Backward-compatible wrapper: push a single amd64 image
async fn push_docker_image(image_path: &str, registry: &str, tag_suffix: &str) -> Result<()> {
    push_docker_images(
        &[ArchImage {
            arch: "amd64".to_string(),
            path: image_path.to_string(),
        }],
        registry,
        tag_suffix,
    )
    .await
}

/// Push Rust service Docker image to GHCR (orchestration only, no nix build)
/// Token comes from GITHUB_TOKEN environment variable (set by substrate wrapper)
pub async fn push_rust_service(
    image_path: String,
    _service: String,
    registry: String,
    _cache_name: String,
    _attic_token: String,
    _github_token: String,
) -> Result<()> {
    let tag_suffix = get_tag_suffix().await?;
    push_docker_image(&image_path, &registry, &tag_suffix).await
}

/// Push Rust service images with explicit tag (internal implementation)
///
/// Discovers available arch images from result-{arch} symlinks, then delegates
/// to the unified push_docker_images strategy.
pub async fn push_rust_service_with_tag(
    service: String,
    registry: String,
    _cache_name: String,
    _attic_token: String,
    _github_token: String,
    tag_suffix: String,
) -> Result<()> {
    // Pre-flight checks
    if !Path::new("result-amd64").exists() {
        bail!("❌ Error: Build results not found\n   Run: nix run .#build");
    }

    println!(
        "📤 {} {} {}",
        "Pushing".bold(),
        service.cyan(),
        "images to registries".dimmed()
    );
    crate::ui::print_ascii_title_underline(50);
    println!("Registry: {}", registry);
    println!("Tag suffix: {}", tag_suffix);
    println!();

    // Collect available architecture images
    let mut images = vec![ArchImage {
        arch: "amd64".to_string(),
        path: "result-amd64".to_string(),
    }];

    if Path::new("result-arm64").exists() {
        images.push(ArchImage {
            arch: "arm64".to_string(),
            path: "result-arm64".to_string(),
        });
    }

    push_docker_images(&images, &registry, &tag_suffix).await
}

/// Resolve namespace for an environment from deploy.yaml
///
/// If namespace_override is provided, uses that.
/// Otherwise, looks up the namespace from environments.<env>.namespace in deploy.yaml.
fn resolve_namespace_for_env(env: &str, namespace_override: Option<&str>) -> Result<String> {
    if let Some(ns) = namespace_override {
        return Ok(ns.to_string());
    }

    // Read namespace from deploy.yaml based on environment
    let deploy_yaml_path = resolve_deploy_yaml_from_service_dir()?;

    if !deploy_yaml_path.exists() {
        bail!(
            "deploy.yaml not found at {}\n  \
             Required for environment-based namespace resolution",
            deploy_yaml_path.display()
        );
    }

    let yaml: serde_yaml::Value = crate::repo::read_yaml_sync(&deploy_yaml_path)?;

    // First check if there's an alias for this environment
    let resolved_env = yaml
        .get("environment_aliases")
        .and_then(|a| a.get(env))
        .and_then(|e| e.as_str())
        .unwrap_or(env);

    // Navigate to environments.<resolved_env>.namespace
    let ns = yaml
        .get("environments")
        .and_then(|e| e.get(resolved_env))
        .and_then(|e| e.get("namespace"))
        .and_then(|n| n.as_str())
        .ok_or_else(|| {
            anyhow!(
                "Namespace not found for environment '{}' in deploy.yaml\n  \
             Expected: environments.{}.namespace\n  \
             Available environments: {}",
                env,
                resolved_env,
                yaml.get("environments")
                    .and_then(|e| e.as_mapping())
                    .map(|m| m
                        .keys()
                        .filter_map(|k| k.as_str())
                        .collect::<Vec<_>>()
                        .join(", "))
                    .unwrap_or_else(|| "none".to_string())
            )
        })?;

    Ok(ns.to_string())
}

/// Get manifest path for an environment from deploy.yaml
fn get_manifest_path_for_env(env: &str) -> Result<String> {
    let deploy_yaml_path = resolve_deploy_yaml_from_service_dir()?;

    if !deploy_yaml_path.exists() {
        bail!(
            "deploy.yaml not found at {}\n  \
             Required for manifest path lookup",
            deploy_yaml_path.display()
        );
    }

    let yaml: serde_yaml::Value = crate::repo::read_yaml_sync(&deploy_yaml_path)?;

    // First check if there's an alias for this environment
    let resolved_env = yaml
        .get("environment_aliases")
        .and_then(|a| a.get(env))
        .and_then(|e| e.as_str())
        .unwrap_or(env);

    // Navigate to manifests.<resolved_env>.kustomization
    let manifest = yaml
        .get("manifests")
        .and_then(|m| m.get(resolved_env))
        .and_then(|m| m.get("kustomization"))
        .and_then(|k| k.as_str())
        .ok_or_else(|| {
            anyhow!(
                "Manifest path not found for environment '{}' in deploy.yaml\n  \
             Expected: manifests.{}.kustomization\n  \
             Available manifests: {}",
                env,
                resolved_env,
                yaml.get("manifests")
                    .and_then(|m| m.as_mapping())
                    .map(|m| m
                        .keys()
                        .filter_map(|k| k.as_str())
                        .collect::<Vec<_>>()
                        .join(", "))
                    .unwrap_or_else(|| "none".to_string())
            )
        })?;

    Ok(manifest.to_string())
}

/// Deploy to a single environment (used by orchestrate_release for each env)
///
/// This handles:
/// - Updating the kustomization manifest
/// - Committing the changes
/// - Triggering flux reconcile
///
/// `deploy_tag` is the full image tag (e.g., "amd64-bb90b44") used for the manifest.
/// When `k8s_repo_root` is Some, manifest paths are resolved and git operations
/// happen relative to that directory (separate k8s repo).
async fn deploy_to_environment(
    service: &str,
    env: &str,
    namespace: &str,
    registry: &str,
    deploy_tag: &str,
    watch: bool,
    k8s_repo_root: Option<&std::path::Path>,
    k8s_branch: Option<&str>,
) -> Result<String> {
    let manifest = get_manifest_path_for_env(env)?;

    // If k8s repo is configured, resolve manifest relative to it
    let full_manifest_path = if let Some(k8s_root) = k8s_repo_root {
        k8s_root.join(&manifest)
    } else {
        let repo_root = crate::git::get_repo_root()?;
        repo_root.join(&manifest)
    };

    println!("   📁 Manifest: {}", manifest.dimmed());

    // Deploy via GitOps (updates manifest, commits)
    let git_sha = deploy_rust_service_with_tag(
        service.to_string(),
        crate::repo::path_to_string_lossy(&full_manifest_path),
        registry.to_string(),
        namespace.to_string(),
        watch,
        deploy_tag.to_string(),
        k8s_repo_root.map(|p| p.to_path_buf()),
        k8s_branch.map(|s| s.to_string()),
    )
    .await?;

    Ok(git_sha)
}

/// Full orchestration release workflow (orchestration only, no nix build)
/// This is the main entry point for release workflows from substrate wrappers
///
/// Environment selection:
/// - Uses `environment` parameter (from --environment flag or FORGE_ENV env var)
/// - If `single_environment` is false (default), deploys to ALL environments from deploy.yaml
/// - Reads namespace from service deploy.yaml `environments.<env>.namespace`
/// - If `namespace` is provided explicitly, it overrides the deploy.yaml lookup
pub async fn orchestrate_release(
    service: String,
    registry: String,
    environment: String,
    single_environment: bool,
    namespace_override: Option<String>,
    image_path: Option<String>,
    image_path_arm64: Option<String>,
    watch: bool,
    push_only: bool,
    deploy_only: bool,
    image_tag: Option<String>,
) -> Result<()> {
    // Validate flag combinations
    if push_only && deploy_only {
        bail!("Cannot use both --push-only and --deploy-only");
    }

    // Auto-detect standalone mode: no deploy.yaml in service dir or repo root.
    // Standalone services use the simpler push-only flow without DeployConfig.
    // This lets services like shinryu-mcp, hanabi (when standalone), etc. use the
    // same `nix run .#release` handle as full monorepo product services.
    let deploy_config_result = DeployConfig::load_for_service(&service);
    if deploy_config_result.is_err() {
        // No deploy.yaml found — fall back to standalone push-only mode
        return orchestrate_standalone_release(
            service,
            registry,
            image_path,
            image_path_arm64,
            deploy_only,
            image_tag,
        )
        .await;
    }
    let deploy_config = deploy_config_result?;

    // Determine which environments to deploy to
    // Respects active_environments filter from deploy.yaml
    let environments: Vec<String> = if single_environment {
        // Single environment mode: deploy only to the specified environment
        // Still checks if it's in active_environments
        deploy_config.service.release.get_environments(&environment)
    } else {
        // Multi-environment mode (default): deploy to all ACTIVE environments in order
        deploy_config.service.release.get_environments("all")
    };

    // Fail fast if no environments to deploy to (unless push-only)
    if environments.is_empty() && !push_only {
        bail!(
            "❌ No active environments to deploy to.\n   \
             Check deploy.yaml active_environments configuration.\n   \
             Available environments: {:?}\n   \
             Active environments: {:?}",
            deploy_config.service.release.environment_order,
            deploy_config.service.release.active_environments
        );
    }

    let mode_label = if push_only {
        "Push-Only"
    } else if deploy_only {
        "Deploy-Only"
    } else {
        "Build-Once-Promote Release"
    };

    println!(
        "🚀 {} {} {}",
        service.cyan().bold(),
        mode_label.bold(),
        format!(
            "({} environment{})",
            environments.len(),
            if environments.len() == 1 { "" } else { "s" }
        )
        .dimmed()
    );
    crate::ui::print_ascii_title_underline(60);

    // Show active vs available environments (skip for push-only)
    if !push_only {
        let all_envs = &deploy_config.service.release.environment_order;
        let active_envs = deploy_config.service.release.effective_environments();
        if all_envs.len() != active_envs.len() {
            println!("📍 Environment Status:");
            for env in all_envs {
                if active_envs.contains(env) {
                    println!("   {} {} (active)", "●".green(), env.cyan());
                } else {
                    println!("   {} {} (inactive)", "○".dimmed(), env.dimmed());
                }
            }
            println!();
        }

        // Show deployment plan
        println!("📋 Deployment Plan:");
        for (i, env) in environments.iter().enumerate() {
            let namespace = resolve_namespace_for_env(env, namespace_override.as_deref())?;
            println!("   {}. {} → {}", i + 1, env.cyan(), namespace.dimmed());
        }
        println!();
    }

    // Use the first environment for initial setup (if available)
    let namespace = if !environments.is_empty() {
        let first_env = &environments[0];
        resolve_namespace_for_env(first_env, namespace_override.as_deref())?
    } else {
        String::new()
    };

    // CRITICAL: Prevent concurrent releases of the same service
    // Check if a release lock file exists for this service
    let lock_file = format!("/tmp/forge-{}.lock", service);
    if std::path::Path::new(&lock_file).exists() {
        // Try to read the PID from the lock file
        if let Ok(contents) = std::fs::read_to_string(&lock_file) {
            if let Ok(pid) = contents.trim().parse::<i32>() {
                // Check if the process is still running
                use std::process::Command as StdCommand;
                let check_result = StdCommand::new(ps_bin())
                    .args(&["-p", &pid.to_string()])
                    .output();

                if let Ok(output) = check_result {
                    if output.status.success()
                        && !String::from_utf8_lossy(&output.stdout).is_empty()
                    {
                        bail!(
                            "❌ Another release for '{}' is already running (PID: {})\n\
                             Wait for it to complete or kill it with: kill {}",
                            service,
                            pid,
                            pid
                        );
                    }
                }
            }
        }
    }

    // Create lock file with current PID
    let current_pid = std::process::id();
    std::fs::write(&lock_file, current_pid.to_string())
        .context("Failed to create release lock file")?;

    // Ensure lock file is cleaned up on exit
    let lock_file_cleanup = lock_file.clone();
    let _guard = scopeguard::guard((), move |_| {
        let _ = std::fs::remove_file(&lock_file_cleanup);
    });

    // Step 0: Pre-release FluxCD health check (can be skipped via config)
    let skip_flux_health_check = deploy_config
        .service
        .deployment
        .as_ref()
        .map(|d| d.skip_flux_health_check)
        .unwrap_or(deploy_config.global.deployment.skip_flux_health_check);

    if !deploy_only {
        if skip_flux_health_check {
            println!(
                "Step 0: {}",
                "Skipping FluxCD health check (skip_flux_health_check: true)"
                    .bold()
                    .dimmed()
            );
        } else {
            println!("Step 0: {}", "Pre-release FluxCD health check...".bold());
            crate::commands::flux::health_check("pre-release").await?;
        }
        println!();
    }

    // Create service configuration from deploy.yaml
    let config = ServiceConfig::from_config(service.clone(), &deploy_config);

    // Resolve k8s repo root if configured (for multi-repo deployments)
    let repo_root = crate::git::get_repo_root()?;
    let product_dir = crate::config::resolve_product_dir(&repo_root, &deploy_config.product.name);
    let k8s_repo_root = if deploy_config.product.k8s.is_some() {
        Some(crate::config::resolve_k8s_repo_root(
            &deploy_config.product,
            &product_dir,
        ))
    } else {
        None
    };
    let k8s_branch = deploy_config.product.k8s.as_ref().map(|k| k.branch.clone());

    // Determine the service directory for pre-deployment tests
    let pre_deploy_service_dir = if service == "web" {
        repo_root
            .join(&deploy_config.global.paths.products_root)
            .join(&deploy_config.product.name)
            .join("web")
    } else {
        repo_root
            .join(&deploy_config.global.paths.products_root)
            .join(&deploy_config.product.name)
            .join(&deploy_config.global.paths.services_path)
            .join(&service)
    };

    // Step 0.5: Run pre-deployment tests (BEFORE push/deploy)
    // Skip if deploy-only (tests already ran during push phase)
    if !deploy_only {
        let pre_deploy_config = deploy_config
            .service
            .deployment
            .as_ref()
            .map(|d| &d.pre_deployment_tests)
            .unwrap_or(&deploy_config.global.deployment.pre_deployment_tests);

        if pre_deploy_config.enabled {
            println!("Step 0.5: {}", "Running pre-deployment tests...".bold());
            crate::commands::integration_tests::execute_pre_deployment_tests(
                pre_deploy_config,
                pre_deploy_service_dir.clone(),
                &service,
            )
            .await?;
            println!();
        }
    }

    // Tag resolution:
    // - deploy_only with image_tag: user provides the full deploy tag (e.g., "amd64-bb90b44")
    // - otherwise: get_tag_suffix() returns raw git SHA, deploy_tag adds arch prefix
    let has_arm64 = image_path_arm64.is_some();
    let (tag_suffix, deploy_tag) = if deploy_only {
        let full_tag = image_tag
            .clone()
            .context("--image-tag required with --deploy-only")?;
        (full_tag.clone(), full_tag)
    } else {
        let sha = get_tag_suffix().await?;
        let dtag = compute_deploy_tag(&sha, "amd64", false, has_arm64);
        (sha, dtag)
    };
    if has_arm64 {
        println!(
            "🏷️  Image tags: amd64-{}, arm64-{}, {} (manifest)",
            tag_suffix, tag_suffix, tag_suffix
        );
    } else {
        println!("🏷️  Image tag: {}", deploy_tag);
    }
    println!();

    // Step 1: Push (skip if deploy-only)
    if !deploy_only {
        let img_path = image_path
            .as_ref()
            .context("--image-path required for push")?;

        // Collect all architecture images
        let mut images = vec![ArchImage {
            arch: "amd64".to_string(),
            path: img_path.clone(),
        }];

        if let Some(arm64_path) = &image_path_arm64 {
            images.push(ArchImage {
                arch: "arm64".to_string(),
                path: arm64_path.clone(),
            });
        }

        println!("Step 1: {}", "Pushing to GHCR...".bold());
        push_docker_images(&images, &registry, &tag_suffix).await?;

        // Step 1.5: Verify image exists in registry and capture digest
        println!();
        println!("Step 1.5: {}", "Verifying image in registry...".bold());
        let verify_tag = deploy_tag.clone();
        let pushed_digest = verify_image_in_registry(&registry, &verify_tag).await?;
        println!("   📋 Captured digest: {}", pushed_digest);
        println!();

        // If push-only, we're done
        if push_only {
            println!("{}", "━".repeat(60).bright_green());
            if has_arm64 {
                println!(
                    "{}  Tags: amd64-{}, arm64-{}, {} (manifest)",
                    "PUSH COMPLETE".green().bold(),
                    tag_suffix,
                    tag_suffix,
                    tag_suffix
                );
            } else {
                println!("{}  Tag: {}", "PUSH COMPLETE".green().bold(), deploy_tag);
            }
            println!("{}", "━".repeat(60).bright_green());
            return Ok(());
        }

        // Step 2.5: Verify image digest hasn't changed (race condition protection)
        // before deploying
        verify_image_digest_matches(&registry, &verify_tag, &pushed_digest).await?;
    }

    // Step 2: Run migrations BEFORE deployment (using pushed image)
    // CRITICAL: Migrations must complete successfully BEFORE updating K8s manifests
    // This ensures the database schema is ready when new pods start
    println!("Step 2: {}", "Running database migrations...".bold());

    if config.database_type() == &crate::commands::service_config::DatabaseType::None {
        println!(
            "   {} {}",
            "↷".dimmed(),
            "Skipping migrations (database_type: none)".dimmed()
        );
    } else {
        // For multi-environment deployments, run migrations for each environment in order
        // Each environment may have its own database
        for (i, env) in environments.iter().enumerate() {
            let namespace = resolve_namespace_for_env(env, namespace_override.as_deref())?;

            println!();
            println!(
                "   [{}/{}] {} migrations → {}",
                i + 1,
                environments.len(),
                env.cyan().bold(),
                namespace.dimmed()
            );

            // Check and reset stuck Shinka migrations first
            if let Ok(was_reset) = crate::commands::migrations::check_and_reset_shinka_migration(
                &deploy_config.product.name,
                &service,
                &namespace,
            )
            .await
            {
                if was_reset {
                    crate::ui::print_step_pass("Shinka migration reset, will retry with new image");
                }
            }

            // Run migrations for this environment
            let migration_image_tag = deploy_tag.clone();
            crate::commands::migrations::run_migrations(
                &config,
                namespace.clone(),
                migration_image_tag.clone(),
                &deploy_config,
            )
            .await?;
            crate::ui::print_step_pass(&format!("Migrations completed for {}", env.cyan()));
        }
    }
    println!();

    // Step 3: Deploy to each environment in order (AFTER migrations pass)
    // Now that the database schema is ready, it's safe to deploy new pods
    println!("Step 3: {}", "Deploying to environments...".bold());
    let mut last_git_sha = String::new();
    let mut last_namespace = String::new();

    for (i, env) in environments.iter().enumerate() {
        let namespace = resolve_namespace_for_env(env, namespace_override.as_deref())?;

        println!();
        println!(
            "   [{}/{}] {} → {}",
            i + 1,
            environments.len(),
            env.cyan().bold(),
            namespace.dimmed()
        );

        // Deploy to this environment (updates manifest, commits)
        last_git_sha = deploy_to_environment(
            &service,
            env,
            &namespace,
            &registry,
            &deploy_tag,
            watch,
            k8s_repo_root.as_deref(),
            k8s_branch.as_deref(),
        )
        .await?;
        last_namespace = namespace.clone();

        // Trigger flux reconcile for this namespace (non-blocking unless it's the last env)
        let is_last_env = i == environments.len() - 1;
        if !is_last_env || !deploy_config.service.release.wait_between_environments {
            // Just trigger reconcile, don't wait
            println!("   ⚡ Triggering flux reconcile for {}", namespace.cyan());
            crate::commands::flux::reconcile(namespace.clone()).await?;
        }

        // Shinka migration coordination:
        // - shinka_gating=true: Block release until migration completes (legacy)
        // - shinka_gating=false: Set expected-tag annotation and continue (recommended)
        //   The K8s layer handles coordination via Shinka + wait-for-migrations init container
        if deploy_config.service.migration.shinka_gating {
            let expected_image_tag = deploy_tag.clone();
            crate::commands::migrations::wait_for_shinka_migration(
                &deploy_config.product.name,
                &service,
                &namespace,
                &expected_image_tag,
                deploy_config
                    .service
                    .migration
                    .shinka_migration_name
                    .as_deref(),
                deploy_config.service.migration.shinka_timeout_secs,
            )
            .await?;
        } else {
            // Set expected-tag annotation so Shinka picks up the new release faster
            // (invalidates cache, fast-requeues, auto-retries from Failed state)
            let migration_name = deploy_config
                .service
                .migration
                .shinka_migration_name
                .clone()
                .unwrap_or_else(|| format!("{}-{}", deploy_config.product.name, service));
            let expected_image_tag = deploy_tag.clone();
            crate::commands::migrations::set_expected_tag_if_exists(
                &migration_name,
                &namespace,
                &expected_image_tag,
            )
            .await;
        }
    }
    println!();

    // For subsequent steps, use the last environment's namespace
    let namespace = last_namespace;
    let git_sha = last_git_sha;

    // Step 4: Wait for deployment to be ready
    let wait_for_rollout = deploy_config
        .service
        .deployment
        .as_ref()
        .map(|d| d.wait_for_rollout)
        .unwrap_or(deploy_config.global.deployment.wait_for_rollout);

    if wait_for_rollout {
        println!("Step 4: {}", "Waiting for deployment rollout...".bold());
        crate::commands::flux::wait_for_deployment(
            service.clone(),
            namespace.clone(),
            deploy_config.global.deployment.deployment_wait_timeout_secs,
            tag_suffix.clone(),
            &deploy_config,
        )
        .await?;
        println!();
    } else {
        println!(
            "Step 4: {}",
            "Skipping deployment rollout wait (wait_for_rollout: false)".dimmed()
        );
        println!();
    }

    // Step 4.5 (conditional): Search service GitOps sync
    // Only runs for services with novasearch.enabled = true in deploy.yaml
    if crate::commands::search_sync::should_run_novasearch_sync(&deploy_config) {
        println!("Step 4.5: {}", "Running search service sync...".bold());
        let service_dir = std::path::Path::new(".");
        crate::commands::search_sync::run_novasearch_sync(service_dir, &namespace, &deploy_config)
            .await?;
        println!();
    }

    // Step 5: Extract GraphQL schema
    println!("Step 5: {}", "Extracting GraphQL schema...".bold());
    crate::commands::federation::extract_schema(service.clone(), &deploy_config).await?;
    println!();

    // Step 6: Update GraphQL Federation (Hive Router)
    println!("Step 6: {}", "Updating Hive Router federation...".bold());
    crate::commands::federation::update_federation(
        service.clone(),
        namespace.clone(),
        &deploy_config,
    )
    .await?;
    println!();

    // Step 7: Post-release FluxCD health check with retry (can be skipped via config)
    // CRITICAL: Verify GitOps system is still healthy after deployment
    // Wait for Flux to finish reconciling changes before declaring success
    // This ensures the release didn't break the cluster reconciliation
    if skip_flux_health_check {
        println!(
            "Step 7: {}",
            "Skipping post-release FluxCD health check (skip_flux_health_check: true)".dimmed()
        );
    } else {
        println!("Step 7: {}", "Post-release FluxCD health check...".bold());
        // Wait up to 10 minutes for all kustomizations to reconcile (was 5 minutes)
        // Longer timeout handles complex deployments with multiple services
        crate::commands::flux::health_check_with_retry("post-release", 600, 10).await?;
    }
    println!();

    // Step 8: Run integration tests (if configured in deploy.yaml)
    // CRITICAL: Tests run AFTER Hive Router is updated and FluxCD has reconciled
    // This ensures we're testing against the latest federated schema
    let repo_root = crate::git::get_repo_root()?;
    let service_dir = if service == "web" {
        // Web service: pkgs/products/{product}/web
        repo_root
            .join(&deploy_config.global.paths.products_root)
            .join(&deploy_config.product.name)
            .join("web")
    } else {
        // Rust service: pkgs/products/{product}/services/rust/{service}
        repo_root
            .join(&deploy_config.global.paths.products_root)
            .join(&deploy_config.product.name)
            .join(&deploy_config.global.paths.services_path)
            .join(&service)
    };

    let product_dir = repo_root
        .join(&deploy_config.global.paths.products_root)
        .join(&deploy_config.product.name);
    let deploy_yaml_path = resolve_deploy_yaml_path(&product_dir, &service, &service_dir);
    if deploy_yaml_path.exists() {
        // Try to load integration test config from deploy.yaml
        if let Ok(yaml_content) = tokio::fs::read_to_string(&deploy_yaml_path).await {
            if let Ok(yaml_value) = serde_yaml::from_str::<serde_yaml::Value>(&yaml_content) {
                // Check if deployment.integration_tests exists and is enabled
                if let Some(deployment) = yaml_value.get("deployment") {
                    if let Some(integration_tests) = deployment.get("integration_tests") {
                        if let Some(enabled) = integration_tests.get("enabled") {
                            if enabled.as_bool().unwrap_or(false) {
                                // Parse the integration_tests config
                                if let Ok(config) =
                                    serde_yaml::from_value::<
                                        crate::commands::integration_tests::IntegrationTestConfig,
                                    >(integration_tests.clone())
                                {
                                    println!(
                                        "Step 8: {}",
                                        "Running post-deployment integration tests...".bold()
                                    );
                                    crate::ui::print_step_info("Testing against stable Hive Router with updated federation schema");
                                    println!();
                                    match crate::commands::integration_tests::execute(
                                        config,
                                        service_dir.clone(),
                                    )
                                    .await
                                    {
                                        Ok(_) => {
                                            println!("✅ Integration tests passed!");
                                            println!();
                                        }
                                        Err(e) => {
                                            println!();
                                            println!(
                                                "{}",
                                                "✗ Integration tests failed".red().bold()
                                            );
                                            println!();
                                            return Err(e);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Cleanup: remove temp k8s clone if we created one
    if let Some(ref k8s_root) = k8s_repo_root {
        if k8s_root.starts_with(std::env::temp_dir()) {
            if let Err(e) = std::fs::remove_dir_all(k8s_root) {
                eprintln!("⚠️  Failed to clean up temp k8s repo: {}", e);
            }
        }
    }

    print_success_banner(80, "✅ RELEASE COMPLETE - ALL SYSTEMS HEALTHY");

    Ok(())
}

/// Standalone release: push images for services without a deploy.yaml.
///
/// Used by `nix run .#release` for services that don't follow the monorepo
/// product layout (e.g., shinryu-mcp, standalone microservices). Pushes per-arch
/// images with auto-generated tags and creates a multi-arch manifest if both
/// architectures are present. Skips all DeployConfig-dependent steps (FluxCD
/// health checks, environment promotion, kustomization updates, post-deploy
/// verification).
///
/// The intent is that the cluster's GitOps stack reconciles the new image tag
/// independently — this function only handles "build artifact → registry".
pub async fn orchestrate_standalone_release(
    service: String,
    registry: String,
    image_path: Option<String>,
    image_path_arm64: Option<String>,
    deploy_only: bool,
    _image_tag: Option<String>,
) -> Result<()> {
    if deploy_only {
        bail!("--deploy-only is not supported in standalone mode (no deploy.yaml). Use --image-path/--image-path-arm64 to push directly.");
    }

    println!(
        "🚀 {} {} {}",
        service.cyan().bold(),
        "Standalone Release".bold(),
        "(no deploy.yaml — push only)".dimmed()
    );
    crate::ui::print_ascii_title_underline(60);

    if image_path.is_none() && image_path_arm64.is_none() {
        bail!("Standalone release requires --image-path and/or --image-path-arm64");
    }

    let tag_suffix = get_tag_suffix().await?;

    let mut images = vec![];
    if let Some(path) = image_path.as_ref() {
        images.push(ArchImage {
            arch: "amd64".to_string(),
            path: path.clone(),
        });
    }
    if let Some(path) = image_path_arm64.as_ref() {
        images.push(ArchImage {
            arch: "arm64".to_string(),
            path: path.clone(),
        });
    }

    println!("🏷️  Registry: {}", registry.cyan());
    println!("🏷️  SHA: {}", tag_suffix.dimmed());
    println!();

    push_docker_images(&images, &registry, &tag_suffix).await?;

    println!();
    print_success_banner(60, "✅ STANDALONE RELEASE COMPLETE");
    println!();
    crate::ui::print_step_info(&format!("Image pushed to {}:{}", registry, tag_suffix));
    crate::ui::print_step_info("GitOps reconciliation should pick up the new tag automatically.");
    crate::ui::print_step_info(
        "Run `flux reconcile helmrelease <name>` to force immediate reconciliation.",
    );

    Ok(())
}

/// Deploy Rust service to Kubernetes via GitOps
///
/// Returns the deploy tag used in the deployment
/// Deploy Rust service - wrapper that gets tag internally
pub async fn deploy_rust_service(
    service: String,
    manifest: String,
    registry: String,
    namespace: String,
    watch: bool,
) -> Result<String> {
    let sha = get_tag_suffix().await?;
    let deploy_tag = compute_deploy_tag(&sha, "amd64", false, false);
    deploy_rust_service_with_tag(
        service, manifest, registry, namespace, watch, deploy_tag, None, None,
    )
    .await
}

/// Update an image tag in a manifest using targeted text replacement.
///
/// Supports two formats:
///
/// 1. Kustomize `images:` section:
/// ```yaml
/// images:
/// - name: ghcr.io/your-org/your-project/my-backend
///   newTag: amd64-abc123
/// ```
///
/// 2. HelmRelease `values.image.tag`:
/// ```yaml
///     image:
///       repository: ghcr.io/your-org/my-service
///       tag: amd64-abc123
/// ```
fn update_kustomization_image_tag(
    content: &str,
    service_name: &str,
    new_tag: &str,
) -> Result<String> {
    let lines: Vec<&str> = content.lines().collect();
    let mut result = Vec::with_capacity(lines.len());
    let mut found = false;
    let mut matched_name = false;
    let mut matched_helm_repo = false;

    for (i, line) in lines.iter().enumerate() {
        if matched_name {
            // The previous line was a matching `- name:` entry.
            // The next non-empty line should be `  newTag: ...`
            let trimmed = line.trim();
            if trimmed.starts_with("newTag:") {
                // Replace the newTag value, preserving indentation
                let indent = &line[..line.len() - line.trim_start().len()];
                result.push(format!("{}newTag: {}", indent, new_tag));
                found = true;
                matched_name = false;
                continue;
            }
            // If it's not newTag, keep looking (might be a comment or blank line)
            if !trimmed.is_empty() && !trimmed.starts_with('#') {
                matched_name = false;
            }
        }

        if matched_helm_repo {
            // Previous line was `repository:` containing service_name
            // Next line should be `tag: ...`
            let trimmed = line.trim();
            if trimmed.starts_with("tag:") {
                let indent = &line[..line.len() - line.trim_start().len()];
                result.push(format!("{}tag: {}", indent, new_tag));
                found = true;
                matched_helm_repo = false;
                continue;
            }
            if !trimmed.is_empty() && !trimmed.starts_with('#') {
                matched_helm_repo = false;
            }
        }

        // Check if this line is `- name: <something containing service_name>`
        let trimmed = line.trim();
        if trimmed.starts_with("- name:") {
            let name_value = trimmed.trim_start_matches("- name:").trim();
            if name_value.contains(service_name) {
                matched_name = true;
            }
        }

        // Check if this line is `repository: <something containing service_name>` (HelmRelease)
        if trimmed.starts_with("repository:") {
            let repo_value = trimmed.trim_start_matches("repository:").trim();
            if repo_value.contains(service_name) {
                matched_helm_repo = true;
            }
        }

        result.push(line.to_string());
    }

    if !found {
        bail!(
            "No image entry matching '{}' found in manifest",
            service_name
        );
    }

    // Preserve trailing newline if original had one
    let mut output = result.join("\n");
    if content.ends_with('\n') {
        output.push('\n');
    }

    Ok(output)
}

/// Deploy Rust service with explicit tag (internal implementation)
///
/// `tag_suffix` is the full deploy tag (e.g., "amd64-bb90b44" or "bb90b44" for multi-arch).
/// When `k8s_workdir` is Some, git operations (add/commit/push) happen in that
/// directory instead of the product repo root (for separate k8s repos).
pub async fn deploy_rust_service_with_tag(
    service: String,
    manifest: String,
    registry: String,
    namespace: String,
    watch: bool,
    tag_suffix: String,
    k8s_workdir: Option<std::path::PathBuf>,
    k8s_branch: Option<String>,
) -> Result<String> {
    // Compose `<repository>:<tag>` via
    // `crate::oci_manifest::image_reference` — the typed
    // compositional inverse of `image_repository_and_tag`.
    let image_tag = crate::oci_manifest::image_reference(&registry, &tag_suffix);

    println!(
        "🎯 {} {} {}",
        "Deploying".bold(),
        service.cyan(),
        "to Kubernetes".dimmed()
    );
    crate::ui::print_ascii_title_underline(50);
    println!("Namespace: {}", namespace);
    println!("Image: {}", image_tag);
    println!("Manifest: {}", manifest);
    println!();

    // Verify image exists in registry before updating kustomization.
    // This prevents deploying non-existent images (ImagePullBackOff).
    match verify_image_in_registry(&registry, &tag_suffix).await {
        Ok(_digest) => {
            println!("   ✅ Image verified in registry");
        }
        Err(e) => {
            let err_str = format!("{}", e);
            if err_str.contains("GITHUB_TOKEN") || err_str.contains("GHCR_TOKEN") {
                eprintln!(
                    "   {} Skipping image verification (no registry credentials available)",
                    "⚠️".yellow()
                );
            } else {
                bail!(
                    "❌ Image {}:{} does not exist in registry.\n   \
                     Cannot deploy a non-existent image.\n   \
                     Error: {}",
                    registry,
                    tag_suffix,
                    e
                );
            }
        }
    }
    println!();

    // Read manifest and update image tag using targeted text replacement.
    // CRITICAL: Do NOT round-trip through serde_yaml - it destroys comments,
    // reformats multi-line strings (patch: | blocks), and can corrupt the file.
    let manifest_content = crate::repo::read_text_async(Path::new(&manifest)).await?;

    let new_tag = tag_suffix.clone();
    let updated_manifest = update_kustomization_image_tag(&manifest_content, &service, &new_tag)?;

    crate::repo::write_text_async(Path::new(&manifest), &updated_manifest).await?;

    // Git commit and push (in k8s repo if configured, otherwise product repo)
    let git_workdir = k8s_workdir.as_deref();
    let git_branch = k8s_branch.as_deref().unwrap_or("main");

    if let Some(workdir) = git_workdir {
        // Multi-repo: git operations in the k8s repo
        let manifest_path = std::path::Path::new(&manifest);
        crate::git::commit_and_push_in(
            workdir,
            &[manifest_path],
            &format!("Deploy {} {}", service, tag_suffix),
            git_branch,
        )?;
    } else {
        // Single-repo: git operations in current repo. Each site routes
        // through `retry::run_inherited_status` so non-zero exits bail
        // with the structural `(op, exit_code)` record — symmetric with
        // the multi-repo `git::commit_and_push_in` path's bail-on-
        // non-zero semantics (which the prior shape silently dropped).
        //
        // Binary resolution rides `crate::git::git_command_async()` so a
        // Nix-hermetic runner's `GIT_BIN` override wins over ambient
        // `PATH` — same discipline the sibling async `commands/push.rs`
        // (f6be190), `commands/rollback.rs` (8a1958e),
        // `commands/codegen_validation.rs` (81d7486), and
        // `commands/federation.rs` (8653403) git-mutation sites honor.
        crate::git::git_run_inherited_status(["add", &manifest], "git add")
            .await
            .context("Failed to stage manifest")?;

        let commit_msg = format!("Deploy {} {}", service, tag_suffix);
        crate::git::git_run_inherited_status(["commit", "-m", &commit_msg], "git commit")
            .await
            .context("Failed to commit manifest")?;

        crate::git::git_run_inherited_status(["push", "origin", git_branch], "git push")
            .await
            .context("Failed to push manifest")?;
    }

    crate::ui::print_step_success("Manifest updated and pushed");

    if watch {
        println!();
        crate::ui::print_step_info(&format!(
            "Flux will handle deployment - use 'kubectl get pods -n {}' to monitor",
            namespace
        ));
    }

    println!();
    println!("✅ {}", "GitOps deployment triggered!".green().bold());

    Ok(tag_suffix)
}

/// Print comprehensive deployment report
async fn print_deployment_report(
    service: &str,
    namespace: &str,
    deploy_config: &DeployConfig,
    tag_suffix: &str,
) -> Result<()> {
    use colored::Colorize;

    println!();
    println!("{} {}", "Service:".bold(), service.cyan());
    println!("{} {}", "Namespace:".bold(), namespace);
    println!(
        "{} {}",
        "Environment:".bold(),
        deploy_config.product.environment
    );
    println!("{} {}", "Image Tag:".bold(), tag_suffix.yellow());
    println!();

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // COMPLETED ACTIONS
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    println!("{}", "✅ COMPLETED ACTIONS".green().bold());
    println!("{}", "─".repeat(80).dimmed());
    println!();

    println!("  {} Docker Image", "✓".green());
    println!("    • Built with crate2nix (per-crate Attic caching)");
    println!("    • Pushed to GHCR: {}", deploy_config.registry_url());
    println!("    • Tag: {}", tag_suffix);
    println!();

    println!("  {} GitOps Deployment", "✓".green());
    println!("    • Manifest updated with new image tag");
    println!("    • Changes committed to git (main branch)");
    println!("    • Pushed to remote repository");
    println!();

    println!("  {} Database Migrations", "✓".green());
    println!("    • Migration job completed successfully");
    println!("    • Schema is up to date");
    println!();

    println!("  {} GraphQL Federation", "✓".green());
    println!("    • Schema extracted from Rust code");
    println!("    • Supergraph composed with Rover (Federation v2.11.3)");
    println!("    • Hive Router deployment updated with hash");
    println!("    • Federation changes committed and pushed");
    println!();

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // PENDING ROLLOUTS (FluxCD-managed)
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    println!("{}", "⏳ PENDING ROLLOUTS".yellow().bold());
    println!("{}", "─".repeat(80).dimmed());
    println!();

    // Check current pod status
    let pod_status = kubectl_command_async()
        .args(&[
            "get",
            "pods",
            "-n",
            namespace,
            "-l",
            &format!("app={}", service),
            "-o",
            "jsonpath={.items[0].status.phase}",
        ])
        .output()
        .await;

    let current_image = kubectl_command_async()
        .args(&[
            "get",
            "pods",
            "-n",
            namespace,
            "-l",
            &format!("app={}", service),
            "-o",
            "jsonpath={.items[0].spec.containers[0].image}",
        ])
        .output()
        .await;

    if let (Ok(status_output), Ok(image_output)) = (&pod_status, &current_image) {
        if status_output.status.success() && image_output.status.success() {
            let phase = crate::repo::utf8_lossy_borrow(&status_output.stdout);
            let image = crate::repo::utf8_lossy_borrow(&image_output.stdout);

            println!("  {} Service Pod Rollout", "⏳".yellow());
            println!("    • Current pod status: {}", phase);
            println!("    • Current image: {}", image.dimmed());

            // Compose `<repository>:<tag>` via
            // `crate::oci_manifest::image_reference` — the typed
            // compositional inverse of `image_repository_and_tag`.
            let expected_image =
                crate::oci_manifest::image_reference(&deploy_config.registry_url(), tag_suffix);
            if image.contains(tag_suffix) {
                println!("    • {} New image is already deployed!", "✓".green());
            } else {
                println!("    • ⏳ Waiting for Flux to deploy new image...");
            }
        } else {
            println!("  {} Service Pod Rollout", "⏳".yellow());
            println!("    • Flux will create/update pod with new image");
        }
    } else {
        println!("  {} Service Pod Rollout", "⏳".yellow());
        println!("    • Flux will deploy the new pod (typically 30-60 seconds)");
    }
    println!();

    println!("  {} Hive Router Update", "⏳".yellow());
    println!("    • Flux will detect supergraph.graphql changes");
    println!("    • New ConfigMap will be generated (hash suffix)");
    println!("    • Hive Router pod will restart automatically");
    println!("    • New schema will be live after restart (typically 1-2 minutes)");
    println!();

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // VERIFICATION COMMANDS
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    println!("{}", "✓ VERIFICATION COMMANDS".green().bold());
    println!("{}", "─".repeat(80).dimmed());
    println!();

    println!("  Verify Docker image exists in registry:");
    println!(
        "  $ {}",
        format!(
            "docker pull {}:{}",
            deploy_config.registry_url(),
            tag_suffix
        )
        .yellow()
    );
    println!();

    println!("  Verify git commits were pushed:");
    println!("  $ {}", "git log --oneline -5".yellow());
    println!();

    println!("  Verify kustomization manifest has new image tag:");
    println!(
        "  $ {}",
        format!(
            "grep {} nix/k8s/clusters/{{cluster}}/products/{}/services/{}/kustomization.yaml",
            tag_suffix, namespace, service
        )
        .yellow()
    );
    println!();

    println!("  Verify new pod is running with correct image:");
    println!(
        "  $ {}",
        format!(
            "kubectl get pods -n {} -l app={} -o jsonpath='{{.items[0].spec.containers[0].image}}'",
            namespace, service
        )
        .yellow()
    );
    println!(
        "    Expected: {}:{}",
        deploy_config.registry_url(),
        tag_suffix
    );
    println!();

    println!("  Verify database migrations completed:");
    println!(
        "  $ {}",
        format!(
            "kubectl get jobs -n {} | grep {}-migration",
            namespace, service
        )
        .yellow()
    );
    println!("    Should show: Completed (1/1)");
    println!();

    println!("  Verify GraphQL schema file updated:");
    println!("  $ {}", "git log --oneline --all -- pkgs/products/<product>/infrastructure/hive-router/subgraphs/*.graphql | head -1".yellow());
    println!("    Should show recent commit with schema update");
    println!();

    println!("  Verify supergraph.graphql updated:");
    println!("  $ {}", format!("grep 'graph: {}' nix/k8s/clusters/{{cluster}}/products/{}/hive-router/supergraph.graphql | wc -l",
        service.to_uppercase(), namespace).yellow());
    println!("    Should be > 0 (service present in supergraph)");
    println!();

    println!("  Verify Hive Router has new supergraph hash:");
    println!("  $ {}", format!("kubectl get deployment hive-router -n {} -o jsonpath='{{.spec.template.metadata.annotations.supergraph\\.hash}}'",
        namespace).yellow());
    println!("    Check if hash is recent");
    println!();

    println!("  Verify Hive Router ConfigMap updated:");
    println!(
        "  $ {}",
        format!(
            "kubectl get configmap -n {} | grep hive-router-config",
            namespace
        )
        .yellow()
    );
    println!("    Hash suffix should have changed (triggers pod restart)");
    println!();

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // MONITORING COMMANDS
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    println!("{}", "🔍 MONITORING COMMANDS".cyan().bold());
    println!("{}", "─".repeat(80).dimmed());
    println!();

    println!("  Watch service pod rollout:");
    println!(
        "  $ {}",
        format!("kubectl get pods -n {} -w | grep {}", namespace, service).yellow()
    );
    println!();

    println!("  Check service pod logs:");
    println!(
        "  $ {}",
        format!("kubectl logs -n {} -l app={} -f", namespace, service).yellow()
    );
    println!();

    println!("  Check Hive Router status:");
    println!(
        "  $ {}",
        format!("kubectl get pods -n {} | grep hive-router", namespace).yellow()
    );
    println!();

    println!("  Check Hive Router logs:");
    println!(
        "  $ {}",
        format!("kubectl logs -n {} -l app=hive-router -f", namespace).yellow()
    );
    println!();

    println!("  Check Flux reconciliation status:");
    println!("  $ {}", "flux get kustomizations".yellow());
    println!();

    println!("  Test GraphQL endpoint (after router updates):");
    println!(
        "  $ {}",
        format!(
            "kubectl port-forward -n {} svc/hive-router 4000:4000",
            namespace
        )
        .yellow()
    );
    println!(
        "  $ {}",
        "curl http://localhost:4000/graphql -d '{\"query\":\"{__schema{types{name}}}\"}'".yellow()
    );
    println!();

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // WHAT TO WATCH FOR
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    println!("{}", "⚠️  WATCH FOR THESE ISSUES".yellow().bold());
    println!("{}", "─".repeat(80).dimmed());
    println!();

    println!("  {} Pod fails to start", "□".dimmed());
    println!("    → Check logs for startup errors");
    println!("    → Verify database connection (check secrets/configmap)");
    println!("    → Check if migrations broke the schema");
    println!();

    println!("  {} Pod is CrashLoopBackOff", "□".dimmed());
    println!("    → Service is crashing on startup");
    println!("    → Check logs for panic/error messages");
    println!("    → Verify all environment variables are set");
    println!();

    println!("  {} Hive Router fails after update", "□".dimmed());
    println!("    → Check router logs for schema composition errors");
    println!("    → Verify supergraph.graphql is valid");
    println!("    → Ensure all subgraph URLs are correct");
    println!();

    println!("  {} GraphQL queries fail", "□".dimmed());
    println!("    → Hive Router may not have reloaded schema");
    println!("    → Wait 1-2 minutes for ConfigMap update and pod restart");
    println!("    → Try restarting hive-router pod manually if needed");
    println!();

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // SUMMARY
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    println!("{}", "━".repeat(80).bright_blue());
    println!("{}", "📋 SUMMARY".bright_blue().bold());
    println!("{}", "━".repeat(80).bright_blue());
    println!();

    println!(
        "  {} All build and GitOps operations completed successfully",
        "✓".green()
    );
    println!(
        "  {} Flux will deploy the new pod in 30-60 seconds",
        "⏳".yellow()
    );
    println!("  {} Hive Router will update in 1-2 minutes", "⏳".yellow());
    println!(
        "  {} Monitor the rollout using the commands above",
        "→".cyan()
    );
    println!();

    println!("{}", "🎉 Deployment workflow complete!".green().bold());
    println!("{}", "━".repeat(80).bright_blue());
    println!();

    Ok(())
}

/// Full release workflow for Rust service
pub async fn release_rust_service(
    service: String,
    registry: String,
    namespace: String,
    cache_url: String,
    cache_name: String,
    _attic_token: String,
    _github_token: String,
) -> Result<()> {
    println!(
        "🚀 {} {} {}",
        service.cyan().bold(),
        "Service Release Workflow".bold(),
        "(crate2nix)".dimmed()
    );
    crate::ui::print_ascii_title_underline(50);

    // Load deployment configuration first (hierarchical: global → product → service)
    let deploy_config = DeployConfig::load_for_service(&service)?;

    // Step 0: Pre-release FluxCD health check (can be skipped via config)
    let skip_flux_health_check = deploy_config
        .service
        .deployment
        .as_ref()
        .map(|d| d.skip_flux_health_check)
        .unwrap_or(deploy_config.global.deployment.skip_flux_health_check);

    if skip_flux_health_check {
        println!(
            "Step 0/8: {}",
            "Skipping FluxCD health check (skip_flux_health_check: true)"
                .bold()
                .dimmed()
        );
    } else {
        println!("Step 0/8: {}", "Pre-release FluxCD health check...".bold());
        crate::commands::flux::health_check("pre-release").await?;
    }
    println!();

    // Compute manifest path from configuration
    let manifest_path = deploy_config.k8s_manifest_path()?;
    let manifest = crate::repo::path_to_string_lossy(&manifest_path);

    println!("📋 Configuration loaded:");
    println!("   Product: {}", deploy_config.product.name);
    println!("   Environment: {}", deploy_config.product.environment);
    println!("   Registry: {}", deploy_config.registry_url());
    println!("   Namespace: {}", deploy_config.kubernetes_namespace());
    println!();

    // Tokens are set by Nix wrapper via environment variables

    // Create service configuration from deploy.yaml
    let config = ServiceConfig::from_config(service.clone(), &deploy_config);

    // Capture git tag ONCE at the start to ensure consistency across build/push/deploy
    // IMPORTANT: This prevents tag mismatch when HEAD moves between steps
    let tag_suffix = get_tag_suffix().await?;
    let deploy_tag = compute_deploy_tag(&tag_suffix, "amd64", false, false);
    println!("🏷️  Deploy tag: {}", deploy_tag);
    println!();

    // Step 1: Build
    println!("Step 1/8: {}", "Building with per-crate caching...".bold());
    build_rust_service(
        service.clone(),
        cache_url.clone(),
        cache_name.clone(),
        String::new(),
        &deploy_config,
    )
    .await?;

    // Step 2: Push
    println!();
    println!("Step 2/9: {}", "Pushing to registries...".bold());
    push_rust_service_with_tag(
        service.clone(),
        registry.clone(),
        cache_name.clone(),
        String::new(),
        String::new(),
        tag_suffix.clone(),
    )
    .await?;

    // Step 2.5: Verify image exists in registry and capture digest
    println!();
    println!("Step 2.5/9: {}", "Verifying image in registry...".bold());
    let pushed_digest = verify_image_in_registry(&registry, &deploy_tag).await?;
    println!("   📋 Captured digest: {}", pushed_digest);

    // Step 3: Run migrations BEFORE deploying (CRITICAL: database must be ready before new pods start)
    // Check and reset stuck Shinka migrations first
    if let Ok(was_reset) = crate::commands::migrations::check_and_reset_shinka_migration(
        &deploy_config.product.name,
        &service,
        &deploy_config.kubernetes_namespace(),
    )
    .await
    {
        if was_reset {
            println!("   ✅ Shinka migration reset, will retry with new image");
        }
    }

    println!();
    println!("Step 3/9: {}", "Running database migrations...".bold());
    let image_tag = deploy_tag.clone();
    crate::commands::migrations::run_migrations(
        &config,
        namespace.clone(),
        image_tag,
        &deploy_config,
    )
    .await?;

    // Step 3.5: Verify image digest before deploy (race condition protection)
    println!();
    println!(
        "Step 3.5/9: {}",
        "Verifying image integrity before deploy...".bold()
    );
    verify_image_digest_matches(&registry, &deploy_tag, &pushed_digest).await?;

    // Step 4: Deploy (commits manifest changes to git) - AFTER migrations pass
    println!();
    println!("Step 4/9: {}", "Deploying via GitOps...".bold());
    let git_sha = deploy_rust_service_with_tag(
        service.clone(),
        manifest,
        registry.clone(),
        namespace.clone(),
        true,
        deploy_tag.clone(),
        None,
        None,
    )
    .await?;

    // Step 5: Flux reconcile (source + kustomization)
    println!();
    println!("Step 5/9: {}", "Syncing deployment with Flux...".bold());
    crate::commands::flux::reconcile(namespace.clone()).await?;

    // Step 5.5: Verify deployment has correct image tag after flux reconcile
    {
        let dep_name = deploy_config
            .service
            .kubernetes
            .as_ref()
            .and_then(|k| k.deployment_name.clone())
            .unwrap_or_else(|| service.clone());
        crate::commands::flux::verify_deployment_image(&namespace, &dep_name, &tag_suffix, 120)
            .await?;
    }

    // Step 6: Wait for deployment to be ready
    // Check service-level config first, then global
    let wait_for_rollout = deploy_config
        .service
        .deployment
        .as_ref()
        .map(|d| d.wait_for_rollout)
        .unwrap_or(deploy_config.global.deployment.wait_for_rollout);

    if wait_for_rollout {
        println!();
        println!("Step 6/9: {}", "Waiting for deployment rollout...".bold());
        crate::commands::flux::wait_for_deployment(
            service.clone(),
            namespace.clone(),
            deploy_config.global.deployment.deployment_wait_timeout_secs,
            tag_suffix.clone(),
            &deploy_config,
        )
        .await?;
    } else {
        println!();
        println!(
            "Step 6/9: {}",
            "Skipping deployment rollout wait (wait_for_rollout: false)".bold()
        );
    }

    // Step 6.5 (conditional): Search service GitOps sync
    // Only runs for services with novasearch.enabled = true in deploy.yaml
    if crate::commands::search_sync::should_run_novasearch_sync(&deploy_config) {
        println!();
        println!("Step 6.5/9: {}", "Running search service sync...".bold());
        let service_dir = std::path::Path::new(".");
        crate::commands::search_sync::run_novasearch_sync(service_dir, &namespace, &deploy_config)
            .await?;
    }

    // Step 7: Extract GraphQL schema
    println!();
    println!("Step 7/9: {}", "Extracting GraphQL schema...".bold());
    crate::commands::federation::extract_schema(service.clone(), &deploy_config).await?;

    // Step 8: Update GraphQL Federation (Hive Router)
    println!();
    println!("Step 8/9: {}", "Updating Hive Router federation...".bold());
    crate::commands::federation::update_federation(
        service.clone(),
        namespace.clone(),
        &deploy_config,
    )
    .await?;

    // Step 7.4: Auto-release federation-tests if this service has federation tests enabled
    // This ensures the test image is current before running tests
    let federation_tests_tag_override = if deploy_config.service.federation_tests.enabled
        && !deploy_config.service.federation_tests_service.is_global
    {
        println!();
        println!(
            "Step 8.4/9: {}",
            "Releasing federation-tests image...".bold()
        );

        // Capture the current git SHA BEFORE starting the federation-tests release
        // We'll need to detect the architecture after the build completes
        let git_sha_before_release = crate::commands::rust_service::get_tag_suffix().await?;

        // Find the monorepo root
        let repo_root = crate::git::get_repo_root()?;

        // Construct the service directory path from config
        // We know: repo_root, product name, service name
        // Structure: {repo_root}/pkgs/products/{product}/services/rust/{service}
        let service_dir = repo_root
            .join("pkgs")
            .join("products")
            .join(&deploy_config.product.name)
            .join("services")
            .join("rust")
            .join(&service);

        // Construct path to federation-tests: pkgs/products/{product}/tests/federation
        let federation_tests_dir = repo_root
            .join("pkgs")
            .join("products")
            .join(&deploy_config.product.name)
            .join("tests")
            .join("federation");

        if !federation_tests_dir.exists() {
            bail!(
                "Federation tests directory not found: {}\n  \
                 Expected structure: pkgs/products/{}/tests/federation",
                federation_tests_dir.display(),
                deploy_config.product.name
            );
        }

        println!("   📁 Federation tests: {}", federation_tests_dir.display());

        // Run nix run .#release from the federation-tests directory —
        // routes through `crate::retry::run_inherited_status_sync` so
        // the exit code lands in the operator log line by construction
        // at the primitive's ONE body, closing the last frontier site
        // the primitive's docstring nine-module enumeration named
        // (siblings a21bd67 / 5faeecb / a3d51eb / 27896e4 / 9072905 /
        // a6e9b96 / 6cb9442 / c2922fd).
        let mut cmd = std::process::Command::new(nix_bin());
        cmd.args(["run", ".#release"])
            .current_dir(&federation_tests_dir);
        crate::retry::run_inherited_status_sync(cmd, "nix run .#release (federation-tests)")?;

        println!("   ✅ Federation-tests image released");

        // Detect which architecture was built by checking result files
        // The build creates result-amd64 or result-arm64 symlinks
        let full_image_tag = {
            let amd64_result = federation_tests_dir.join("result-amd64");
            let arm64_result = federation_tests_dir.join("result-arm64");
            let has_arm64 = arm64_result.exists();

            if amd64_result.exists() {
                compute_deploy_tag(&git_sha_before_release, "amd64", false, has_arm64)
            } else if has_arm64 {
                compute_deploy_tag(&git_sha_before_release, "arm64", false, false)
            } else {
                // Fallback to just SHA if no result files found
                git_sha_before_release.clone()
            }
        };

        println!("   📋 Detected image tag: {}", full_image_tag);

        // Now update THIS SERVICE's deploy.yaml with the federation-tests image tag

        println!();
        println!(
            "   📝 Updating {}'s deploy.yaml with federation-tests tag...",
            service
        );
        let fed_product_dir = repo_root
            .join("pkgs")
            .join("products")
            .join(&deploy_config.product.name);
        let fed_deploy_yaml = resolve_deploy_yaml_path(&fed_product_dir, &service, &service_dir);

        update_service_federation_tests_tag(
            &service,
            &full_image_tag,
            &deploy_config,
            &fed_deploy_yaml,
        )
        .await?;

        // Commit the updated service deploy.yaml
        let service_deploy_yaml = fed_deploy_yaml;
        crate::git::commit_and_push(
            &service_deploy_yaml,
            "", // old_tag not needed
            &full_image_tag,
        )?;
        println!("   ✅ Service deploy.yaml updated and committed");

        // Return the full tag so it can be passed to Step 8.5
        // This includes the architecture prefix (e.g., "amd64-347a310176")
        Some(full_image_tag)
    } else {
        None
    };

    // Step 8.5: Run federation integration tests (AFTER deployment is complete)
    if deploy_config.service.federation_tests.enabled {
        println!();
        println!(
            "Step 8.5/9: {}",
            "Running federation integration tests...".bold()
        );

        crate::commands::federation_tests::run_federation_tests(
            &service,
            &deploy_config.product.name,
            &deploy_config.product.environment,
            &namespace,
            &deploy_config.service.federation_tests.suite,
            &deploy_config.service.federation_tests.router_url,
            deploy_config.service.federation_tests.timeout_seconds,
            deploy_config.service.federation_tests.fail_fast,
            &git_sha,
            &deploy_config,
            federation_tests_tag_override.as_deref(),
        )
        .await?;
    } else {
        println!();
        println!(
            "Step 8.5/9: {} {}",
            "Skipping federation integration tests".dimmed(),
            "(not enabled in deploy.yaml)".dimmed()
        );
    }

    // Generate comprehensive deployment report
    println!();
    println!("{}", "━".repeat(80).bright_blue());
    println!("📊 {}", "DEPLOYMENT REPORT".bright_blue().bold());
    println!("{}", "━".repeat(80).bright_blue());
    print_deployment_report(&service, &namespace, &deploy_config, &deploy_tag).await?;

    // Step 9: Post-release FluxCD health check with retry (can be skipped via config)
    // CRITICAL: Verify GitOps system is still healthy after deployment
    // Wait for Flux to finish reconciling changes before declaring success
    // This ensures the release didn't break the cluster reconciliation
    println!();
    if skip_flux_health_check {
        println!(
            "Step 9/9: {}",
            "Skipping post-release FluxCD health check (skip_flux_health_check: true)"
                .bold()
                .dimmed()
        );
    } else {
        println!("Step 9/9: {}", "Post-release FluxCD health check...".bold());
        // Wait up to 10 minutes for all kustomizations to reconcile (was 5 minutes)
        // Longer timeout handles complex deployments with multiple services
        crate::commands::flux::health_check_with_retry("post-release", 600, 10).await?;
    }

    println!();
    print_success_banner(80, "✅ RELEASE COMPLETE");

    Ok(())
}

/// Update service's deploy.yaml with new federation-tests image tag
///
/// This function is called after Step 8.4 releases federation-tests.
/// It updates the service's own deploy.yaml to use the freshly built federation-tests image.
async fn update_service_federation_tests_tag(
    _service: &str,
    tag_suffix: &str,
    _deploy_config: &DeployConfig,
    deploy_yaml_path: &std::path::Path,
) -> Result<()> {
    if !deploy_yaml_path.exists() {
        bail!("deploy.yaml not found at: {}", deploy_yaml_path.display());
    }

    println!("   📝 Updating deploy.yaml...");

    // Read current content
    let content =
        std::fs::read_to_string(&deploy_yaml_path).context("Failed to read deploy.yaml")?;

    // Update or add the image_tag line under federation_tests section
    let mut updated_content = String::new();
    let mut updated = false;
    let mut in_federation_tests_section = false;
    let mut found_image_tag = false;

    for line in content.lines() {
        if line.trim_start().starts_with("federation_tests:") {
            in_federation_tests_section = true;
            updated_content.push_str(line);
            updated_content.push('\n');
        } else if in_federation_tests_section {
            // Check if we're still in the federation_tests section (indented)
            if !line.starts_with(' ') && !line.trim().is_empty() {
                // We've exited the section - add image_tag if not found
                if !found_image_tag {
                    updated_content.push_str(&format!("  image_tag: \"{}\"\n", tag_suffix));
                    updated = true;
                }
                in_federation_tests_section = false;
                updated_content.push_str(line);
                updated_content.push('\n');
            } else if line.trim_start().starts_with("image_tag:") {
                // Replace the existing image_tag line
                let indent = line.len() - line.trim_start().len();
                updated_content.push_str(&" ".repeat(indent));
                updated_content.push_str(&format!("image_tag: \"{}\"\n", tag_suffix));
                updated = true;
                found_image_tag = true;
            } else {
                updated_content.push_str(line);
                updated_content.push('\n');
            }
        } else {
            updated_content.push_str(line);
            updated_content.push('\n');
        }
    }

    // If we reached EOF while still in federation_tests section and didn't find image_tag
    if in_federation_tests_section && !found_image_tag {
        updated_content.push_str(&format!("  image_tag: \"{}\"\n", tag_suffix));
        updated = true;
    }

    if !updated {
        bail!("Could not update image_tag in federation_tests section of deploy.yaml");
    }

    // Write back
    std::fs::write(&deploy_yaml_path, updated_content).context("Failed to write deploy.yaml")?;

    println!(
        "   ✅ Updated federation_tests.image_tag to: {}",
        tag_suffix
    );

    Ok(())
}

#[cfg(test)]
mod deploy_rust_service_with_tag_git_bin_routing_tests {
    /// Regression-shield: every `git`-spawning site in
    /// `commands/rust_service.rs::deploy_rust_service_with_tag`'s
    /// single-repo branch MUST resolve the binary through
    /// [`crate::git::git_command_async`] rather than the pre-lift
    /// `Command::new("git")` literal. Pre-migration three sites
    /// (add / commit / push) bypassed the `GIT_BIN` env override the
    /// `tools::get_tool_path(tools::GIT)` idiom (cli/src/tools.rs:102-105)
    /// resolves — the same class of bug the sibling async
    /// `commands/push.rs::update_kustomization` (f6be190),
    /// `commands/rollback.rs` (8a1958e),
    /// `commands/codegen_validation.rs` (81d7486), and
    /// `commands/federation.rs` (8653403) git-mutation sites redeemed
    /// on the async half of the routing surface, and the sync
    /// `commands/helm.rs::deploy` (0d922f6),
    /// `config/mod::resolve_k8s_repo_root` (0a36ba0),
    /// `commands/e2e.rs::resolve_repo_root` (447cad1), and
    /// `commands/helm.rs::bump` (82376e1) migrations redeemed on the
    /// sync half.
    ///
    /// This test reads this module's own source via [`include_str!`]
    /// and asserts the raw `Command::new("git")` string does not
    /// reappear in `deploy_rust_service_with_tag` while the delegation
    /// to `git_command_async` does. A future regression that re-fuses
    /// the raw-spawn body fails here, not silently in production where
    /// a Nix-hermetic runner's `GIT_BIN`-provided `git` would lose to
    /// whatever `git` is first on `PATH` at
    /// `forge rust-service deploy` time.
    ///
    /// The check is deliberately structural (substring on the source
    /// text) rather than behavioral — the end-to-end
    /// `GIT_BIN`-routing invariant is already pinned by
    /// [`crate::git::tests::test_git_command_async_routes_through_git_bin_env_var`]
    /// on the primitive itself; this shield only certifies that every
    /// `deploy_rust_service_with_tag` git spawn reads through that
    /// primitive. Mirrors the sibling shield on
    /// `commands/push.rs::update_kustomization` for the async half of
    /// the surface.
    #[test]
    fn test_deploy_rust_service_with_tag_routes_git_through_git_command_async_not_raw_command() {
        const SOURCE: &str = include_str!("rust_service.rs");

        // Bound the scan to `deploy_rust_service_with_tag` — the three
        // git spawn sites live in its single-repo `else` branch. The
        // shield's own docstring above legitimately mentions
        // `Command::new("git")` and lives outside this bound.
        // Bound the fn body between `deploy_rust_service_with_tag`'s
        // header and the next top-level `fn` in source order
        // (`print_deployment_report`), which follows it.
        let fn_body = crate::test_support::fn_body_slice_between_markers(
            SOURCE,
            "rust_service.rs",
            "pub async fn deploy_rust_service_with_tag(",
            "\nasync fn print_deployment_report(",
        );

        assert!(
            !fn_body.contains("Command::new(\"git\")"),
            "deploy_rust_service_with_tag() must NOT spawn `git` directly \
             — route through `crate::git::git_run_inherited_status(&[...], \
             \"git …\")` (the async fusion primitive) or \
             `crate::git::git_command_async()` so `GIT_BIN` overrides land \
             at the shared primitive. Found the pre-migration spawn body \
             in deploy_rust_service_with_tag()."
        );
        assert!(
            fn_body.contains("crate::git::git_run_inherited_status(")
                || fn_body.contains("crate::git::git_command_async()"),
            "deploy_rust_service_with_tag() must delegate every git \
             spawn to `crate::git::git_run_inherited_status(&[...], \
             \"git …\")` (the async fusion primitive, which internally \
             routes through `git_command_async()` + \
             `run_inherited_status`) OR to `crate::git::git_command_async()` \
             — neither delegation string was found in \
             deploy_rust_service_with_tag()."
        );
    }
}

#[cfg(test)]
mod nix_bin_routing_tests {
    /// Whole-module shield: no raw `Command::new("nix")` may live in
    /// `commands/rust_service.rs`'s non-test body. Every `nix` spawn
    /// in this module must first resolve `NIX_BIN` via
    /// [`crate::repo::get_tool_path`] — the canonical env-var override
    /// every other nix-invocation site in forge honors
    /// (`commands/build.rs::execute` d8ef0d5,
    /// `commands/tool.rs::build_lock_target`,
    /// `nix.rs::build_flake_attr_in`,
    /// `nix.rs::build_docker_image_from_dir`,
    /// `nix.rs::path_info_recursive`,
    /// `nix_hooks.rs::NixHooks::build_and_get_path`,
    /// `commands/developer_tools.rs::rust_update_cargo_nix` and
    /// siblings 4dfb2b3).
    ///
    /// Pre-lift this module carried three real `nix` spawn sites plus
    /// one dead-code sibling in a TODO block comment: the
    /// `check_cross_compilation_available` `show-config` probe at
    /// line 211, `build_rust_service`'s primary `nix build .#<pkg>`
    /// AMD64 site at line 338, `release_rust_service`'s
    /// `nix run .#release` federation-tests site at line 2514, and
    /// the ARM64 build stanza inside the `/* ... */` block at line
    /// 446. Each real spawn spelled `Command::new("nix")` verbatim,
    /// ignoring `NIX_BIN` at exactly the moment hermetic-runner
    /// consistency matters most — `forge rust-service build` and
    /// `forge rust-service release` are the highest-traffic
    /// nix-invocation surfaces on the Rust-service pipeline. A
    /// Nix-hermetic runner with a store-path `nix` binary silently
    /// fell through to whatever `nix` was first on `PATH` at these
    /// three sites, diverging from every other nix-invocation
    /// surface in forge and from the sibling KUBECTL_BIN / GIT_BIN
    /// frontier's uniform discipline (5bb7cff / 818ed9a).
    ///
    /// The scan bounds on the whole-module boundary (from the file
    /// start to the first `\n#[cfg(test)]\n` marker, which delimits
    /// both this shield and the earlier
    /// `deploy_rust_service_with_tag_git_bin_routing_tests` block
    /// above) so shield docstring mentions of `Command::new("nix")`
    /// stay out of scope AND every current or future nix-spawning
    /// helper landing anywhere in the top-level module body cannot
    /// silently ride along without going through `NIX_BIN`. Mirrors
    /// the sibling whole-module shields on
    /// `commands/build.rs::test_execute_routes_nix_through_nix_bin_not_raw_command`
    /// (d8ef0d5) and
    /// `commands/developer_tools.rs::test_developer_tools_routes_nix_through_nix_bin_not_raw_command`
    /// (4dfb2b3) — the whole-module-boundary scan discipline
    /// pioneered on `commands/supergraph_verification.rs` (65283fb).
    #[test]
    fn test_rust_service_routes_nix_through_nix_bin_not_raw_command() {
        crate::test_support::assert_source_routes_bare_spawn_through_sigil_bin_fn_at_exactly_one_resolve(
            include_str!("rust_service.rs"),
            "commands/rust_service.rs",
            "nix",
            "NIX_BIN",
        );
    }
}

#[cfg(test)]
mod kubectl_bin_routing_tests {
    /// Whole-module shield: no raw `Command::new`-with-bare-`kubectl`-
    /// literal may live in `commands/rust_service.rs`. Every `kubectl`
    /// spawn on this module — pre-lift the two
    /// `print_deployment_report` pod-phase / pod-image probes at lines
    /// 1984 and 1998 in the "PENDING ROLLOUTS" report section — must
    /// resolve through
    /// [`crate::infrastructure::kubectl::kubectl_command_async`] —
    /// the async constructor that reads the `KUBECTL_BIN` env
    /// override via [`crate::tools::get_tool_path`] on the canonical
    /// `tools::KUBECTL` name.
    ///
    /// Pre-lift each of the two `kubectl` spawn sites spelled the
    /// bare `"kubectl"` literal via `Command::new` (aliased through
    /// the module's `use tokio::process::Command`), ignoring
    /// `KUBECTL_BIN` at the site. A Nix-hermetic runner's substrate-
    /// derived `kubectl` path was lost to whatever `kubectl` sat
    /// first on PATH — the same silent-PATH-fallback bug class the
    /// sibling consumer sites in forge already avoid
    /// (`commands/search_sync.rs` at 2bf0490,
    /// `commands/rollout.rs::execute` at c5fcf83,
    /// `commands/migrations.rs` at 946e573,
    /// `commands/status.rs` at c2760df,
    /// `commands/flux.rs` at f8da719,
    /// `commands/federation_tests.rs` at 9a409e8,
    /// `commands/supergraph_verification.rs` at 65283fb,
    /// `services/migration_service.rs` at 5986a10,
    /// `commands/github_runner_ci.rs` at 5566415,
    /// `commands/product_release.rs::run_health_check` at 5bb7cff).
    ///
    /// This shield scans the module's own source via [`include_str!`]
    /// and forbids the fused literal shape. The forbidden shape is
    /// reconstructed via [`format!`] from the bare string `"kubectl"`
    /// so this shield's own source text does not false-match itself
    /// — the whole-module scan therefore covers both the top-of-file
    /// production body AND every sibling `#[cfg(test)]` block (the
    /// `deploy_rust_service_with_tag_git_bin_routing_tests` /
    /// `nix_bin_routing_tests` / this block), any of which could
    /// otherwise silently re-introduce a raw literal. The end-to-end
    /// `KUBECTL_BIN`-routing invariant of the underlying primitive
    /// is pinned separately by
    /// [`crate::infrastructure::kubectl::tests::test_kubectl_command_async_routes_through_kubectl_bin_env_var`];
    /// this shield only certifies that every `kubectl`-spawning site
    /// in this module resolves through the constructor first.
    #[test]
    fn test_kubectl_spawn_routes_through_kubectl_command_async_not_raw_literal() {
        const SOURCE: &str = include_str!("rust_service.rs");

        crate::test_support::assert_source_forbids_bare_spawn_shapes(
            SOURCE,
            "commands/rust_service.rs",
            "kubectl",
            "resolve the substrate-exported `KUBECTL_BIN` env override via `kubectl_command_async`",
        );

        crate::test_support::assert_source_delegates_via_constructor_call_code_line(
            SOURCE,
            "commands/rust_service.rs",
            "kubectl",
            "kubectl_command_async",
        );
    }
}

#[cfg(test)]
mod ps_bin_routing_tests {
    /// Whole-module shield: no raw `ps`-tool-name literal fused into a
    /// `Command::new(...)` call may live in `commands/rust_service.rs`'s
    /// non-test body. The single `ps` spawn site — the concurrent-release
    /// interlock's PID liveness probe inside [`super::release_rust_service`]
    /// (`ps -p <pid>` on `/tmp/forge-<service>.lock`'s contents) — must
    /// resolve through [`super::ps_bin`], which delegates to
    /// [`crate::repo::get_tool_path`] on the canonical two-arg
    /// `("PS_BIN", "ps")` env-var override every sibling probe/spawn
    /// surface in forge honors (this module's own `NIX_BIN` shield above;
    /// `commands/e2e.rs`'s `docker_bin` 23241a6 and `open_bin` 8f4c717;
    /// `SH_BIN` two-arg lift b382b78; `{SSH,NC,DIG}_BIN` 5e6672d;
    /// `SQLX_BIN` ecace0a; `SEA_ORM_CLI_BIN` b037895;
    /// `NOVASEARCHCTL_BIN` 19463db).
    ///
    /// Pre-lift the site spawned `ps` via the bare tool-name literal on
    /// `std::process::Command` (imported inline via `use std::process::
    /// Command as StdCommand;`), bypassing `PS_BIN` at the exact
    /// surface `forge push-rust-service` — and every derived
    /// `forge rust-service release` / `forge comprehensive-release` /
    /// `forge product-release` pipeline that reaches
    /// [`super::release_rust_service`] — checks whether a prior release
    /// of the same service is still running. A Nix-hermetic runner
    /// whose derivation exports `PS_BIN=/nix/store/…-procps/bin/ps` but
    /// omits `ps` from `PATH` silently fell through to whatever `ps`
    /// sat first on `PATH`; on a runner with no `ps` on `PATH` at all,
    /// the spawn's `.output()` return resolved to `Err(_)`, the
    /// interlock's `if let Ok(output) = check_result` binding never
    /// fired, and the guard treated the lock as stale — permitting a
    /// concurrent release the interlock exists to prevent.
    ///
    /// Scan bounds on the whole-module boundary — from the file start
    /// to the FIRST `\n#[cfg(test)]\n` marker in source order (which
    /// lands at the sibling
    /// `deploy_rust_service_with_tag_git_bin_routing_tests` block) — so
    /// this shield's own docstring mentions of the forbidden literal,
    /// living in a `#[cfg(test)]` block below that first marker, stay
    /// out of scope AND every current or future `ps`-spawning helper
    /// landing anywhere in the top-level module body cannot silently
    /// ride along without going through `ps_bin()`. The forbidden
    /// shape is reconstructed at test time via [`format!`] from the
    /// bare string `"ps"` so this shield's own source text does not
    /// false-match itself; the sigil docstring paraphrases the anti-
    /// pattern for the same reason. Also asserts the canonical
    /// `StdCommand::new(ps_bin())` delegation and the `fn ps_bin()`
    /// sigil are present, so a regression that removed the sigil would
    /// surface with a diagnostic pointing at the missing constructor
    /// rather than at a compile error at the call site.
    #[test]
    fn test_rust_service_routes_ps_through_ps_bin_not_raw_command() {
        const SOURCE: &str = include_str!("rust_service.rs");
        let body = crate::test_support::module_body_before_first_cfg_test(
            SOURCE,
            "commands/rust_service.rs",
        );
        crate::test_support::assert_source_forbids_bare_spawn_shapes(
            body,
            "commands/rust_service.rs",
            "ps",
            "resolve `PS_BIN` via `ps_bin()`",
        );
        assert!(
            body.contains("StdCommand::new(ps_bin())"),
            "commands/rust_service.rs must resolve the ps binary via \
             `StdCommand::new(ps_bin())` — the canonical delegation was \
             not found in the module body."
        );
        assert!(
            body.contains("fn ps_bin()"),
            "commands/rust_service.rs must define the `ps_bin` sigil — \
             the one bridge between this module's `ps` spawn and the \
             substrate-exported `PS_BIN` env override."
        );
    }
}

#[cfg(test)]
mod status_spawn_routing_tests {
    /// Whole-module shield: every status-only spawn in
    /// `commands/rust_service.rs` routes through
    /// [`crate::retry::run_inherited_status_sync`], never a hand-rolled
    /// `.status()` + `if !status.success() { bail!(…) }` stanza that
    /// drops the exit code from the operator log line.
    ///
    /// Pre-lift the single spawn — `release_rust_service`'s
    /// federation-tests branch (`nix run .#release` from
    /// `pkgs/products/{product}/tests/federation`) — spelled the
    /// inline `.status()` + `.context(…)?` + `if !status.success() {
    /// bail!(…) }` stanza with a `"Federation-tests release failed
    /// with exit code: {:?}"` message that surfaced a `Debug`-
    /// formatted `Option<i32>` (`Some(1)` / `None`) rather than the
    /// canonical `(exit N)` envelope every other status-only spawn
    /// in forge now emits by construction. Post-lift the site is a
    /// one-line delegation and the operator log line reads
    /// `nix run .#release (federation-tests) failed (exit 1)`.
    ///
    /// Closes the last frontier site the
    /// [`crate::retry::run_inherited_status_sync`] docstring's
    /// nine-module enumeration (`commands/{pangea_infra, crossplane,
    /// test_ci, local, infra, gem, tool, rust_service, e2e}.rs`)
    /// named. Sibling of `commands/test_ci.rs`'s
    /// `test_test_ci_status_spawns_route_through_run_inherited_status_sync`
    /// (a21bd67), `commands/e2e.rs` (5faeecb), `commands/tool.rs`
    /// (a3d51eb), `commands/infra.rs` (27896e4), `commands/gem.rs`
    /// (9072905), `commands/pangea_infra.rs` (a6e9b96),
    /// `commands/crossplane.rs` (6cb9442), and `commands/local.rs`
    /// (c2922fd). Same three-primitive discipline: negative side
    /// forbids the inline `.status()` builder-terminator at any code
    /// line in the module body; positive side pins that
    /// `run_inherited_status_sync(` appears at ≥1 code lines, so a
    /// regression that dropped the delegation cannot leave the
    /// negative scan trivially satisfied by absence. Both hits route
    /// through [`crate::test_support::code_line_hits`] for anti-
    /// docstring-self-match discipline. Scan bounds from file start
    /// to the FIRST `\n#[cfg(test)]\n` marker (the sibling
    /// `deploy_rust_service_with_tag_git_bin_routing_tests` opener),
    /// so this shield's own body — the `.status()` string literal
    /// passed to `code_line_hits`, and the assertion message that
    /// names the forbidden terminator — stays out of scope.
    #[test]
    fn test_rust_service_status_spawns_route_through_run_inherited_status_sync() {
        crate::test_support::assert_source_routes_status_only_spawns_through_run_inherited_status_sync(
            include_str!("rust_service.rs"),
            "commands/rust_service.rs",
            1,
            "the federation-tests `nix run .#release` status-only spawn",
        );
    }
}

#[cfg(test)]
mod service_dir_routing_tests {
    /// Whole-module shield: every read of the `SERVICE_DIR` env var in
    /// this module's non-test body must route through the shared
    /// [`crate::repo::path_from_env`] primitive (introduced at
    /// `repo.rs:127` by d8e6626), never through an inline
    /// `std::env::var("SERVICE_DIR").context(...)?` + `Path::new(&_)` /
    /// `PathBuf::from(_)` two-line stanza.
    ///
    /// Pre-lift the single consumer site — `resolve_deploy_yaml_from_service_dir`
    /// (called by `deploy_rust_service_with_tag` and `deploy_rust_service`
    /// at `commands/rust_service.rs:885, 936`) — spelled the same
    /// `env::var("SERVICE_DIR").context("SERVICE_DIR not set - required
    /// for deploy.yaml lookup")?` + `Path::new(&service_dir)` stanza
    /// verbatim. d8e6626 introduced [`crate::repo::path_from_env`]
    /// explicitly naming this site as the three-times-is-a-law third
    /// caller pending migration (alongside the two per-module sigils in
    /// `commands/developer_tools.rs` and `commands/schema_validation.rs`
    /// the same commit lifted). This shield closes the drift class at
    /// three on the same idiom — the sibling
    /// `commands/developer_tools.rs:1121` and
    /// `commands/schema_validation.rs:450` shields cover the sigil-
    /// bearing modules; this shield covers the single-caller module
    /// that inlines the delegation.
    ///
    /// A future refinement of the `SERVICE_DIR` contract — a canonicalize
    /// hook, a substrate-path validation step, a telemetry sigil on the
    /// resolved path, or a swap to a typed
    /// `substrate::ServiceDir(PathBuf)` newtype — lands at ONE body
    /// ([`crate::repo::path_from_env`]) and reaches every consumer by
    /// construction (THEORY §V — solve-once-at-the-primitive; §VI.1 —
    /// recurring-shape-to-helper).
    ///
    /// The scan bounds on the whole-module boundary (from file start
    /// to the FIRST `\n#[cfg(test)]\n` marker in source order via
    /// [`crate::test_support::module_body_before_first_cfg_test`]) so
    /// this shield's own docstring mentions of `env::var("SERVICE_DIR")`
    /// — living inside a `#[cfg(test)]` block below that first marker —
    /// stay out of scope AND every current or future `SERVICE_DIR`-
    /// reading consumer landing anywhere in the top-level module body
    /// cannot silently ride along without routing through the primitive.
    /// Every hit routes through [`crate::test_support::code_line_hits`]
    /// for anti-docstring-self-match discipline.
    #[test]
    fn test_rust_service_service_dir_routes_through_path_from_env() {
        let body = crate::test_support::module_body_before_first_cfg_test(
            include_str!("rust_service.rs"),
            "commands/rust_service.rs",
        );
        // Negative side: the raw `env::var("SERVICE_DIR")` needle must
        // NOT appear anywhere in the module body post-lift — the read
        // now lives at `crate::repo::path_from_env`, which owns the
        // read at ONE body across the crate. A future consumer that
        // re-copies the two-line stanza pushes this count above zero
        // and fails the shield before it can drift the miss wording or
        // the `PathBuf` projection away from the shared primitive's
        // single point of truth. Substring match catches both
        // `std::env::var("SERVICE_DIR")` and the shorter
        // `env::var("SERVICE_DIR")` (this module carries
        // `use std::env;` and consumers spell both forms elsewhere).
        let raw_env_needle = "env::var(\"SERVICE_DIR\")";
        let env_hits = crate::test_support::code_line_hits(body, raw_env_needle);
        assert!(
            env_hits.is_empty(),
            "commands/rust_service.rs must NOT spell \
             `{raw_env_needle}` inline in the module body — every \
             consumer must route through `crate::repo::path_from_env`, \
             the shared primitive that owns the `env::var` read at ONE \
             body across the crate. Found {} code-line hit(s): \
             {env_hits:#?}. A hand-rolled inline copy re-opens the \
             drift class the primitive was landed to close.",
            env_hits.len()
        );
        // Positive side: the delegating call to
        // `crate::repo::path_from_env(` must appear at EXACTLY one code
        // line — the `resolve_deploy_yaml_from_service_dir` body. A
        // regression that dropped the delegation would leave the
        // negative scan trivially satisfied by absence (zero raw
        // `env::var` hits, but also zero delegating calls), and the
        // module would have stopped resolving `SERVICE_DIR` for
        // deploy.yaml lookup at all.
        let delegate_needle = "crate::repo::path_from_env(";
        let delegate_hits = crate::test_support::code_line_hits(body, delegate_needle);
        assert_eq!(
            delegate_hits.len(),
            1,
            "commands/rust_service.rs must delegate `SERVICE_DIR` \
             resolution to `crate::repo::path_from_env(...)` at EXACTLY \
             one code line — the `resolve_deploy_yaml_from_service_dir` \
             body. Found {} code-line hit(s): {delegate_hits:#?}. A \
             missing delegation would leave the negative scan above \
             trivially satisfied by absence.",
            delegate_hits.len()
        );
        // Wording-preservation side: the domain-specific miss wording
        // `"SERVICE_DIR not set - required for deploy.yaml lookup"` —
        // the third distinct wording d8e6626 catalogued alongside the
        // two per-module sigils' wordings — must stay grep-visible
        // verbatim at the delegating call. A future refactor that
        // reshaped the miss wording (a swap to `.with_context(||)` with
        // drifted text, a lift to a typed error variant, a canonicalize
        // prefix landed in front) would silently drift the message the
        // operator has been coached to grep for.
        let wording_needle = "\"SERVICE_DIR not set - required for deploy.yaml lookup\"";
        let wording_hits = crate::test_support::code_line_hits(body, wording_needle);
        assert_eq!(
            wording_hits.len(),
            1,
            "commands/rust_service.rs must spell the canonical miss \
             wording `{wording_needle}` at EXACTLY one code line — the \
             delegating call's second argument. Found {} code-line \
             hit(s): {wording_hits:#?}. Every pre-lift caller site \
             spelled this wording verbatim at its `.context(...)` call; \
             the delegation preserves it at the same grep-visible \
             surface.",
            wording_hits.len()
        );
    }
}

#[cfg(test)]
mod release_git_sha_routing_tests {
    /// Whole-module shield: every read of the `RELEASE_GIT_SHA` env
    /// var in this module's non-test body must route through the
    /// shared [`crate::git::release_git_sha_from_env`] sigil, never
    /// through an inline
    /// `env::var("RELEASE_GIT_SHA")` + `!sha.is_empty()` two-line
    /// stanza.
    ///
    /// Pre-lift the single consumer site — `get_tag_suffix` — spelled
    /// the same `if let Ok(sha) = env::var("RELEASE_GIT_SHA") { if
    /// !sha.is_empty() { return Ok(sha); } }` stanza verbatim, sibling
    /// to the byte-equivalent copies at
    /// `commands/push.rs::get_git_sha` and
    /// `commands/product_release.rs::execute`. Three consumers past
    /// THEORY §VI.1's three-is-a-law threshold: the trio had to agree
    /// on both the env-var spelling AND the empty-string-is-miss
    /// semantic (the Nix release wrapper exports the var
    /// unconditionally with an empty value on non-release
    /// invocations) for the pushed image tag, the deployed image tag,
    /// and the product-release-driven downstream tags to resolve to
    /// the SAME code-commit SHA.
    ///
    /// A drift at this site (a typo `RELEASE_SHA`, or the empty-check
    /// accidentally deleted so `Ok("")` — the shape the Nix release
    /// wrapper exports on non-release invocations — leaks through as
    /// a valid SHA) would silently render deploy-time image tags with
    /// a bare `amd64-` suffix (no SHA) at this one consumer only,
    /// even while the push-side and product-release consumers stayed
    /// on the sigil.
    ///
    /// A future refinement of the `RELEASE_GIT_SHA` contract — a
    /// canonicalize hook that truncates to 7 chars, a "known length
    /// only" filter, a swap to a typed
    /// `substrate::ReleaseGitSha(String)` newtype, a telemetry sigil
    /// on the resolved SHA — lands at ONE body
    /// ([`crate::git::release_git_sha_from_env`]) and reaches every
    /// consumer by construction (THEORY §V —
    /// solve-once-at-the-primitive; §VI.1 —
    /// recurring-shape-to-helper).
    ///
    /// The scan bounds on the whole-module boundary (from file start
    /// to the FIRST `\n#[cfg(test)]\n` marker in source order via
    /// [`crate::test_support::module_body_before_first_cfg_test`]) so
    /// this shield's own docstring mentions of
    /// `env::var("RELEASE_GIT_SHA")` — living inside a `#[cfg(test)]`
    /// block below that first marker — stay out of scope AND every
    /// current or future `RELEASE_GIT_SHA`-reading consumer landing
    /// anywhere in the top-level module body cannot silently ride
    /// along without routing through the primitive. Every hit routes
    /// through [`crate::test_support::code_line_hits`] for
    /// anti-docstring-self-match discipline.
    #[test]
    fn test_rust_service_release_git_sha_routes_through_sigil() {
        let body = crate::test_support::module_body_before_first_cfg_test(
            include_str!("rust_service.rs"),
            "commands/rust_service.rs",
        );
        let raw_env_needle = "env::var(\"RELEASE_GIT_SHA\")";
        let env_hits = crate::test_support::code_line_hits(body, raw_env_needle);
        assert!(
            env_hits.is_empty(),
            "commands/rust_service.rs must NOT spell \
             `{raw_env_needle}` inline in the module body — every \
             consumer must route through \
             `crate::git::release_git_sha_from_env`, the shared \
             sigil that owns the `env::var` read AND the \
             empty-string-is-miss filter at ONE body across the \
             crate. Found {} code-line hit(s): {env_hits:#?}. A \
             hand-rolled inline copy re-opens the drift class the \
             sigil was landed to close.",
            env_hits.len()
        );
        let delegate_needle = "crate::git::release_git_sha_from_env()";
        let delegate_hits = crate::test_support::code_line_hits(body, delegate_needle);
        assert_eq!(
            delegate_hits.len(),
            1,
            "commands/rust_service.rs must delegate `RELEASE_GIT_SHA` \
             resolution to `crate::git::release_git_sha_from_env()` \
             at EXACTLY one code line — the `get_tag_suffix` body. \
             Found {} code-line hit(s): {delegate_hits:#?}. A \
             missing delegation would leave the negative scan above \
             trivially satisfied by absence.",
            delegate_hits.len()
        );
    }
}
