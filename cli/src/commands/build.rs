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

    let attic_token = std::env::var("ATTIC_TOKEN").or_else(|_| {
        // Try to fetch from kubectl
        std::process::Command::new("kubectl")
            .args(&[
                "get",
                "secret",
                "attic-secrets",
                "-n",
                "infrastructure",
                "-o",
                "jsonpath={.data.server-token}",
            ])
            .output()
            .ok()
            .and_then(|o| {
                if o.status.success() {
                    String::from_utf8(o.stdout)
                        .ok()
                        .and_then(|s| base64::decode(s.trim()).ok())
                        .and_then(|b| String::from_utf8(b).ok())
                } else {
                    None
                }
            })
            .ok_or_else(|| anyhow::anyhow!("ATTIC_TOKEN not found"))
    })?;

    // Attic server alias — configurable via ATTIC_SERVER_NAME (default: "default")
    let attic_server =
        std::env::var("ATTIC_SERVER_NAME").unwrap_or_else(|_| "default".to_string());

    // Login to Attic
    Command::new("attic")
        .args(&["login", &attic_server, &cache_url, &attic_token])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .context("Failed to login to Attic")?;

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

            // Push all derivations via stdin
            let mut attic_push = Command::new("attic")
                .args(&["push", &cache_ref, "--stdin"])
                .stdin(std::process::Stdio::piped())
                .spawn()
                .context("Failed to spawn attic push")?;

            if let Some(mut stdin) = attic_push.stdin.take() {
                use tokio::io::AsyncWriteExt;
                stdin.write_all(path_info_output.stdout.as_slice()).await?;
                drop(stdin);
            }

            let push_result = attic_push.wait().await?;

            if !push_result.success() {
                warn!("⚠️  Failed to push closure to Attic (non-fatal)");
            } else {
                info!(
                    "✅ All {} derivations cached in Attic (60-80% faster future builds)",
                    closure_size
                );
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
