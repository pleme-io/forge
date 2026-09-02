//! Developer tooling commands for Rust services.
//!
//! These commands are exposed via `nix run .#` apps for local development.

use std::env;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use anyhow::{anyhow, bail, Context, Result};
use colored::Colorize;
use tokio::process::Command;

use crate::repo::get_tool_path;
use crate::ui::print_success_banner;

/// Resolve the `cargo` binary via the `CARGO` env override, falling
/// back to PATH. Every `cargo` spawn in this module reads through this
/// sigil so the resolve happens in exactly one place — mirrors the
/// `cargo_bin()` sigil at `commands/test_ci.rs:28` (916f1a4) and
/// `commands/prerelease.rs:109` (79e03a5), and the sibling
/// `crossplane_bin()` / `cosign_bin()` / `jsonnet_bin()` sigil
/// discipline on other command modules (6b3ac16 / a070a3c / a826ac0).
/// Solve-once at the sigil (THEORY §I.5 — duplication budget zero;
/// every recurring shape becomes a helper before it becomes duplicated
/// code) means a future added `cargo` spawn cannot silently re-copy
/// the two-argument resolve and drift away from the `CARGO` override
/// at exactly the tier the hermetic-runner contract binds. The
/// whole-module shield below asserts three invariants: no bare
/// cargo-literal spawn in the body (already landed at 8687093),
/// `fn cargo_bin()` is defined, and the two-argument resolve appears
/// in EXACTLY one place — only the sigil body — so a future added
/// spawn cannot silently re-copy the resolve inline. Pre-lift the
/// nine consumer sites (`rust_test`, `rust_lint`, `rust_fmt`,
/// `rust_fmt_check`, `rust_extract_schema`, `rust_update_cargo_nix`,
/// `rust_regenerate`, `rust_cargo_update`, `rust_dev`) each spelled
/// the two-argument resolve verbatim.
fn cargo_bin() -> String {
    get_tool_path("CARGO", "cargo")
}

/// Resolve the `nix` binary via the `NIX_BIN` env override, falling
/// back to PATH. Every `nix` spawn in this module reads through this
/// sigil so the two-argument resolve happens in exactly one place —
/// mirrors the `nix_bin()` sigil on `commands/rust_service.rs:117`
/// (63d4fe7) and the sibling `cargo_bin()` sigil above (534ef48),
/// converging every substrate-declared `<TOOL>_BIN` resolve on this
/// module onto the fleet-wide `<tool>_bin()` idiom. Solve-once at the
/// sigil (THEORY §I.5 — duplication budget zero; every recurring shape
/// becomes a helper before it becomes duplicated code) means a future
/// added `nix` spawn cannot silently re-copy the two-argument resolve
/// and drift away from the `NIX_BIN` override at exactly the tier the
/// hermetic-runner contract binds. The whole-module shield below
/// asserts three invariants: no bare nix-literal spawn in the body
/// (already landed at 4dfb2b3), `fn nix_bin()` is defined, and the
/// two-argument NIX_BIN resolve appears in EXACTLY one place — only
/// the sigil body — so a future added spawn cannot silently re-copy
/// the resolve inline. Pre-lift the three consumer sites
/// (`rust_update_cargo_nix`, `rust_regenerate`, `rust_cargo_update`)
/// each spelled the two-argument resolve verbatim.
fn nix_bin() -> String {
    get_tool_path("NIX_BIN", "nix")
}

/// Resolve the `docker-compose` binary via the `DOCKER_COMPOSE_BIN`
/// env override, falling back to PATH. Every `docker-compose` spawn
/// in this module reads through this sigil so the two-argument
/// resolve happens in exactly one place — mirrors the sibling
/// `cargo_bin()` / `nix_bin()` sigils above on this same module
/// (534ef48 / a12c172) and the broader `<tool>_bin()` sigil family
/// across the CARGO / NIX_BIN / ATTIC_BIN / BUN_BIN / CRATE2NIX /
/// DOCA_BIN / FLUX_BIN / NC_BIN surfaces (559adae / 6b2ea15 /
/// 9986f11 / 7561329 / 868b2ad / ba3e615 / b5e632a). Solve-once at
/// the sigil (THEORY §I.5 — duplication budget zero; every
/// recurring shape becomes a helper before it becomes duplicated
/// code) means a future added `docker-compose` spawn cannot
/// silently re-copy the two-argument resolve and drift away from
/// the `DOCKER_COMPOSE_BIN` override at exactly the tier the
/// hermetic-runner contract binds. The whole-module shield below
/// asserts three invariants: no bare docker-compose-literal spawn
/// in the body (already landed), `fn docker_compose_bin()` is
/// defined, and the two-argument resolve appears in EXACTLY one
/// place — only the sigil body — so a future added spawn cannot
/// silently re-copy the resolve inline. Pre-lift the two consumer
/// sites (`rust_dev`'s docker-compose-up in Step 1, `rust_dev_down`'s
/// docker-compose-down) each spelled the two-argument resolve
/// verbatim.
fn docker_compose_bin() -> String {
    get_tool_path("DOCKER_COMPOSE_BIN", "docker-compose")
}

/// Resolve the service directory from the `SERVICE_DIR` env var,
/// returning a [`PathBuf`] with the canonical
/// `"SERVICE_DIR not set - this should be called via substrate wrapper"`
/// context on the miss. Every command in this module that reads
/// `SERVICE_DIR` routes through this sigil so the env-var name, the
/// operator-facing miss wording, and the [`Path`] projection live at
/// EXACTLY one body — mirrors the sibling `cargo_bin()` / `nix_bin()`
/// / `docker_compose_bin()` sigils above, all four converging every
/// substrate-declared environment contract in this module onto the
/// solve-once-at-the-sigil idiom (THEORY §I.5 — duplication budget
/// zero; every recurring shape becomes a helper before it becomes
/// duplicated code). Pre-lift the four consumer sites
/// (`rust_regenerate`, `rust_cargo_update`, `rust_dev`, `rust_dev_down`)
/// each spelled the same two-line stanza
/// `let service_dir = env::var("SERVICE_DIR").context(...)?; let
/// service_path = Path::new(&service_dir);` verbatim, so the miss
/// wording drifted only by convention — the shield below now enforces
/// that convention structurally.
///
/// Post-lift a future refinement of the SERVICE_DIR contract — a
/// canonicalize hook, a substrate-path validation step, a telemetry
/// sigil on the resolved path, or a swap to a typed
/// `substrate::ServiceDir(PathBuf)` newtype — lands at ONE body
/// ([`crate::repo::path_from_env`]) and reaches every consumer by
/// construction. The per-module sigil now delegates to that shared
/// primitive with the module's domain-specific miss wording preserved
/// verbatim — the twin `commands/schema_validation.rs:41` sigil
/// (e9e0c5b) delegates through the same primitive with its own
/// distinct wording, so the read-and-project shape lives at ONE body
/// across the crate while each module's operator-facing diagnostic
/// prose stays grep-visible at the delegating call.
fn service_path_from_env() -> Result<PathBuf> {
    crate::repo::path_from_env(
        "SERVICE_DIR",
        "SERVICE_DIR not set - this should be called via substrate wrapper",
    )
}

/// Run Rust unit tests
pub async fn rust_test(service: String) -> Result<()> {
    println!("🧪 Running unit tests for {}...", service.cyan());
    crate::retry::run_bin_args_inherited_status(
        &cargo_bin(),
        &["test", "--lib", "--bins"],
        "cargo test",
    )
    .await
}

/// Run Rust clippy linter
pub async fn rust_lint(service: String) -> Result<()> {
    println!("🔍 Running clippy linter for {}...", service.cyan());
    crate::retry::run_bin_args_inherited_status(
        &cargo_bin(),
        &[
            "clippy",
            "--all-targets",
            "--all-features",
            "--",
            "-D",
            "warnings",
        ],
        "cargo clippy",
    )
    .await
}

/// Format Rust code with rustfmt
pub async fn rust_fmt(service: String) -> Result<()> {
    println!("✨ Formatting code for {}...", service.cyan());
    crate::retry::run_bin_args_inherited_status(&cargo_bin(), &["fmt", "--all"], "cargo fmt").await
}

/// Check Rust code formatting
pub async fn rust_fmt_check(service: String) -> Result<()> {
    println!("🔍 Checking code formatting for {}...", service.cyan());
    crate::retry::run_bin_args_inherited_status(
        &cargo_bin(),
        &["fmt", "--all", "--", "--check"],
        "cargo fmt --check",
    )
    .await
}

/// Extract GraphQL schema from Rust service
pub async fn rust_extract_schema(service: String) -> Result<()> {
    println!("📄 Extracting GraphQL schema for {}...", service.cyan());

    // Check for schema extraction binary
    let bin_names = vec!["extract_schema", "extractschema", "extract-schema"];
    let mut found = false;

    for bin_name in &bin_names {
        let bin_path = format!("src/bin/{}.rs", bin_name);
        if Path::new(&bin_path).exists() {
            crate::retry::run_bin_args_inherited_status(
                &cargo_bin(),
                &["run", "--bin", bin_name],
                &format!("cargo run --bin {}", bin_name),
            )
            .await?;
            found = true;
            break;
        }
    }

    if !found {
        println!("{}", "⚠️  No schema extraction binary found".yellow());
        println!("   Expected: src/bin/extract_schema.rs or src/bin/extractschema.rs");
    }

    Ok(())
}

/// Update Cargo.nix after dependency changes
pub async fn rust_update_cargo_nix(service: String) -> Result<()> {
    println!("🔄 Updating Cargo.nix for {}...", service.cyan());
    println!("   This regenerates per-crate derivations for Attic caching");
    println!();

    // Update Cargo.lock
    println!("Updating Cargo.lock...");
    crate::nix::run_cargo_update(&cargo_bin()).await?;

    // Generate Cargo.nix
    println!();
    println!("Generating Cargo.nix...");
    crate::nix::run_nix_wrapped_crate2nix(&nix_bin(), &[]).await?;

    println!();
    println!("✅ {}", "Cargo.nix updated!".green());
    println!("   Commit both Cargo.lock and Cargo.nix changes");

    Ok(())
}

/// Show help for Rust service commands
pub async fn rust_service_help(service: String) -> Result<()> {
    println!(
        "🦀 {} {} {}",
        "Forge".bold(),
        service.cyan().bold(),
        "Service (crate2nix)".dimmed()
    );
    println!("{}", "=".repeat(50));
    println!();
    println!("{}", "🏗️  Architecture:".bold());
    println!("  • Per-crate derivation caching via crate2nix");
    println!("  • Each dependency (tokio, axum, sqlx, etc.) cached separately in Attic");
    println!("  • 60-80% faster builds with cache hits across all services");
    println!("  • Parallel AMD64/ARM64 builds for maximum speed");
    println!();
    println!("{}", "🚀 Deployment Commands:".bold());
    println!("  nix run .#build           - Build Docker images (parallel AMD64+ARM64)");
    println!("  nix run .#push            - Push to GHCR + Attic");
    println!("  nix run .#deploy          - Deploy via GitOps");
    println!("  nix run .#release         - Full workflow (build+push+deploy)");
    println!("  nix run .#rollout         - Monitor deployment status");
    println!();
    println!("{}", "🧪 Development Commands:".bold());
    println!("  nix develop               - Enter dev shell with all tools");
    println!("  nix run .#test            - Run unit tests");
    println!("  nix run .#lint            - Run clippy linter");
    println!("  nix run .#fmt             - Format code with rustfmt");
    println!("  nix run .#fmt-check       - Check code formatting");
    println!("  nix run .#extract-schema  - Extract GraphQL schema");
    println!("  nix run .#update-cargo-nix - Update Cargo.nix after dependency changes");
    println!();
    println!("{}", "📝 Notes:".bold());
    println!("  • Run 'nix run .#update-cargo-nix' after adding/updating dependencies");
    println!("  • All builds automatically push per-crate derivations to Attic");
    println!("  • Use 'nix run .' to show this help message");

    Ok(())
}

/// Regenerate Cargo.lock and Cargo.nix for workspace
///
/// This command is used by the auto-discovered `nix run .#regenerate-{product}-{service}` apps.
/// It regenerates the workspace-level Cargo.lock and Cargo.nix after dependency changes.
pub async fn rust_regenerate(service: String) -> Result<()> {
    println!(
        "🔄 {} {} {}",
        "Regenerating".bold(),
        "Cargo.lock and Cargo.nix".cyan(),
        format!("for {} workspace", service).dimmed()
    );
    println!("{}", "=".repeat(50));
    println!();

    // Get workspace root from environment (set by setup_service_directory)
    let service_path = service_path_from_env()?;

    // Workspace root is the parent directory of the service
    // Structure: {repo_root}/pkgs/products/{product}/services/rust/{service}
    //           └─────────────────────── workspace root ─────────────────────┘
    let workspace_root = service_path
        .parent()
        .ok_or_else(|| anyhow!("Failed to find workspace root (parent of service directory)"))?;

    println!("📂 Service: {}", service_path.display());
    println!("📂 Workspace: {}", workspace_root.display());
    println!();

    // Change to workspace root
    crate::repo::set_current_dir_labeled(workspace_root, "workspace")?;

    // Step 1: Remove old Cargo.lock
    let cargo_lock = workspace_root.join("Cargo.lock");
    if cargo_lock.exists() {
        println!("🗑️  Removing old Cargo.lock...");
        tokio::fs::remove_file(&cargo_lock)
            .await
            .context("Failed to remove Cargo.lock")?;
        println!("   ✓ Removed");
    } else {
        println!("ℹ️  No existing Cargo.lock found");
    }
    println!();

    // Step 2: Generate new Cargo.lock
    println!(
        "📦 {} {}",
        "Generating new Cargo.lock".bold(),
        "(cargo generate-lockfile)".dimmed()
    );
    crate::retry::run_bin_args_inherited_status(
        &cargo_bin(),
        &["generate-lockfile"],
        "cargo generate-lockfile",
    )
    .await
    .context("Failed to run cargo generate-lockfile")?;
    println!("   ✅ Cargo.lock generated");
    println!();

    // Step 3: Generate Cargo.nix
    println!(
        "📦 {} {}",
        "Generating Cargo.nix".bold(),
        "(crate2nix generate)".dimmed()
    );
    crate::nix::run_nix_wrapped_crate2nix(&nix_bin(), &["-f", "Cargo.toml", "-o", "Cargo.nix"])
        .await?;
    println!("   ✅ Cargo.nix generated");
    println!();

    // Success summary
    print_success_banner(80, "✅ REGENERATION COMPLETE");
    println!();
    println!("Generated files:");
    println!("  • {}", cargo_lock.display());
    println!("  • {}", workspace_root.join("Cargo.nix").display());
    println!();
    println!("Next steps:");
    println!("  1. Review the changes: git diff");
    println!("  2. Commit both files: git add Cargo.lock Cargo.nix && git commit");
    println!();

    Ok(())
}

/// Update dependencies and regenerate Cargo.nix for workspace
///
/// This command is used by the auto-discovered `nix run .#cargo-update-{product}-{service}` apps.
/// It updates dependencies to their latest compatible versions and regenerates Cargo.nix.
pub async fn rust_cargo_update(service: String) -> Result<()> {
    println!(
        "🔄 {} {} {}",
        "Updating dependencies".bold(),
        "and regenerating Cargo.nix".cyan(),
        format!("for {} workspace", service).dimmed()
    );
    println!("{}", "=".repeat(50));
    println!();

    // Get workspace root from environment (set by setup_service_directory)
    let service_path = service_path_from_env()?;

    // Workspace root is the parent directory of the service
    // Structure: {repo_root}/pkgs/products/{product}/services/rust/{service}
    //           └─────────────────────── workspace root ─────────────────────┘
    let workspace_root = service_path
        .parent()
        .ok_or_else(|| anyhow!("Failed to find workspace root (parent of service directory)"))?;

    println!("📂 Service: {}", service_path.display());
    println!("📂 Workspace: {}", workspace_root.display());
    println!();

    // Change to workspace root
    crate::repo::set_current_dir_labeled(workspace_root, "workspace")?;

    // Step 1: Update dependencies
    println!(
        "📦 {} {}",
        "Updating dependencies".bold(),
        "(cargo update)".dimmed()
    );
    crate::nix::run_cargo_update(&cargo_bin()).await?;
    println!("   ✅ Dependencies updated");
    println!();

    // Step 2: Generate Cargo.nix
    println!(
        "📦 {} {}",
        "Generating Cargo.nix".bold(),
        "(crate2nix generate)".dimmed()
    );
    crate::nix::run_nix_wrapped_crate2nix(&nix_bin(), &["-f", "Cargo.toml", "-o", "Cargo.nix"])
        .await?;
    println!("   ✅ Cargo.nix generated");
    println!();

    // Success summary
    print_success_banner(80, "✅ UPDATE COMPLETE");
    println!();
    println!("Updated files:");
    println!("  • {}", workspace_root.join("Cargo.lock").display());
    println!("  • {}", workspace_root.join("Cargo.nix").display());
    println!();
    println!("Next steps:");
    println!("  1. Review the changes: git diff");
    println!("  2. Test the build: cargo build");
    println!("  3. Commit both files: git add Cargo.lock Cargo.nix && git commit");
    println!();

    Ok(())
}

/// Start local development environment for a Rust service
///
/// This command reads deploy.yaml for local configuration and:
/// 1. Starts docker-compose services (postgres, redis, minio, etc.)
/// 2. Waits for services to be ready
/// 3. Runs database migrations
/// 4. Starts the service with cargo run
pub async fn rust_dev(
    service: String,
    skip_docker: bool,
    skip_migrations: bool,
    sqlx_cli: Option<String>,
) -> Result<()> {
    use std::time::Duration;
    use tokio::time::sleep;

    println!(
        "🚀 {} {} {}",
        service.cyan().bold(),
        "Local Development".bold(),
        "(powered by forge)".dimmed()
    );
    println!("{}", "=".repeat(50));
    println!();

    // Get paths from environment
    let service_path = service_path_from_env()?;

    println!("📂 Service directory: {}", service_path.display());

    // Load deploy.yaml configuration
    let config = crate::config::DeployConfig::load_for_service(&service)?;
    let local_config = &config.service.local;

    // Change to service directory for all operations
    crate::repo::set_current_dir_labeled(&service_path, "service")?;

    // Step 1: Start docker-compose if not skipped
    if !skip_docker {
        let compose_file = find_compose_file(&service_path)?;

        if let Some(compose_path) = compose_file {
            println!();
            println!(
                "🐳 {} {}",
                "Starting infrastructure services".bold(),
                format!(
                    "({})",
                    compose_path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                )
                .dimmed()
            );

            crate::retry::run_bin_args_inherited_status(
                &docker_compose_bin(),
                &["-f", compose_path.to_str().unwrap(), "up", "-d"],
                "docker-compose up",
            )
            .await
            .context("Failed to start docker-compose")?;

            // Wait for PostgreSQL to be ready (check DATABASE_URL port)
            if let Some(db_url) = local_config.env.get("DATABASE_URL") {
                if let Some(port) = extract_port_from_url(db_url) {
                    println!("   Waiting for PostgreSQL on port {}...", port);
                    wait_for_port(port, Duration::from_secs(30)).await?;
                    println!("   ✅ PostgreSQL is ready");
                }
            }
        } else {
            println!("⚠️  No compose.yml found - skipping infrastructure startup");
        }
    } else {
        println!("⏭️  Skipping docker-compose (--skip-docker)");
    }

    // Step 2: Set up environment variables from deploy.yaml
    println!();
    println!(
        "📋 {} {}",
        "Setting up environment".bold(),
        format!("({} variables)", local_config.env.len()).dimmed()
    );

    for (key, value) in &local_config.env {
        // Only set if not already set in environment
        if env::var(key).is_err() {
            env::set_var(key, value);
            println!("   {} = {}", key.cyan(), value.dimmed());
        }
    }

    // Set defaults if not provided
    if env::var("RUST_LOG").is_err() {
        let default_log = format!("{}=debug,tower_http=debug", service.replace('-', "_"));
        env::set_var("RUST_LOG", &default_log);
        println!(
            "   {} = {} (default)",
            "RUST_LOG".cyan(),
            default_log.dimmed()
        );
    }

    // Step 3: Run migrations if not skipped
    if !skip_migrations {
        let migrations_dir = service_path.join("migrations");
        if migrations_dir.exists() {
            println!();
            println!(
                "🔄 {} {}",
                "Running migrations".bold(),
                "(sqlx migrate run)".dimmed()
            );

            // Use sqlx_cli from CLI arg (nix derivation path); if unset,
            // fall through to `SQLX_BIN` via `crate::repo::get_tool_path`
            // before landing on bare `"sqlx"` in PATH — same substrate-
            // lifted env-var contract the sibling
            // `commands/comprehensive_release.rs::execute`'s sqlx migrate
            // spawn honors. Preserves the CLI-arg-first precedence (a
            // caller passing `--sqlx-cli /nix/store/.../bin/sqlx` still
            // wins) while closing the silent-PATH-fallback gap on
            // Nix-hermetic runners that export `SQLX_BIN` but no
            // `--sqlx-cli` flag.
            let sqlx_cmd = sqlx_cli
                .clone()
                .unwrap_or_else(|| get_tool_path("SQLX_BIN", "sqlx"));

            let status = Command::new(&sqlx_cmd)
                .args(&["migrate", "run", "--source", "./migrations"])
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .status()
                .await;

            match status {
                Ok(s) if s.success() => {
                    println!("   ✅ Migrations applied");
                }
                Ok(_) => {
                    println!(
                        "   ⚠️  Migration failed (database may not be ready or already migrated)"
                    );
                }
                Err(e) => {
                    println!("   ⚠️  sqlx not found: {} (skipping migrations)", e);
                }
            }
        } else {
            println!();
            println!("ℹ️  No migrations directory found");
        }
    } else {
        println!();
        println!("⏭️  Skipping migrations (--skip-migrations)");
    }

    // Step 4: Determine binary name
    let bin_name = if let Some(ref name) = local_config.binary {
        name.clone()
    } else {
        detect_binary_name(&service_path, &service).await?
    };

    // Step 5: Start cargo run
    println!();
    let port = local_config
        .env
        .get("PORT")
        .map(|s| s.as_str())
        .unwrap_or("8080");
    println!(
        "📡 {} {} on http://localhost:{}",
        "Starting".bold(),
        bin_name.cyan(),
        port
    );
    println!();

    let cargo = cargo_bin();
    let mut cmd = Command::new(&cargo);
    cmd.arg("run");

    if !bin_name.is_empty() {
        cmd.args(&["--bin", &bin_name]);
    }

    // Add any additional cargo args from config
    for arg in &local_config.cargo_args {
        cmd.arg(arg);
    }

    crate::retry::run_inherited_status(cmd, "cargo run")
        .await
        .context("Failed to start cargo run")?;

    Ok(())
}

/// Stop local development environment for a Rust service
pub async fn rust_dev_down(service: String) -> Result<()> {
    println!(
        "🛑 {} {} {}",
        "Stopping".bold(),
        service.cyan(),
        "infrastructure".dimmed()
    );

    // Get paths from environment
    let service_path = service_path_from_env()?;

    crate::repo::set_current_dir_labeled(&service_path, "service")?;

    let compose_file = find_compose_file(&service_path)?;

    if let Some(compose_path) = compose_file {
        crate::retry::run_bin_args_inherited_status(
            &docker_compose_bin(),
            &["-f", compose_path.to_str().unwrap(), "down"],
            "docker-compose down",
        )
        .await
        .context("Failed to stop docker-compose")?;

        println!("✅ Infrastructure stopped");
    } else {
        println!("⚠️  No compose.yml found in {}", service_path.display());
    }

    Ok(())
}

/// Find docker-compose file in service directory
fn find_compose_file(service_path: &Path) -> Result<Option<std::path::PathBuf>> {
    let candidates = [
        "compose.yml",
        "compose.yaml",
        "docker-compose.yml",
        "docker-compose.yaml",
    ];

    for candidate in &candidates {
        let path = service_path.join(candidate);
        if path.exists() {
            return Ok(Some(path));
        }
    }

    Ok(None)
}

/// Extract port number from DATABASE_URL
fn extract_port_from_url(url: &str) -> Option<u16> {
    // Parse URLs like: postgres://user:pass@localhost:5434/dbname
    if let Some(at_pos) = url.rfind('@') {
        let after_at = &url[at_pos + 1..];
        if let Some(colon_pos) = after_at.find(':') {
            let after_colon = &after_at[colon_pos + 1..];
            let port_str: String = after_colon
                .chars()
                .take_while(|c| c.is_ascii_digit())
                .collect();
            return port_str.parse().ok();
        }
    }
    None
}

/// Wait for a TCP port to become available
async fn wait_for_port(port: u16, timeout: std::time::Duration) -> Result<()> {
    use std::time::Instant;
    use tokio::net::TcpStream;
    use tokio::time::sleep;

    let start = Instant::now();
    let addr = format!("127.0.0.1:{}", port);

    while start.elapsed() < timeout {
        match TcpStream::connect(&addr).await {
            Ok(_) => return Ok(()),
            Err(_) => {
                sleep(std::time::Duration::from_millis(500)).await;
            }
        }
    }

    bail!("Timeout waiting for port {} to become available", port)
}

/// Detect binary name from Cargo.toml
async fn detect_binary_name(service_path: &Path, service_name: &str) -> Result<String> {
    let cargo_toml_path = service_path.join("Cargo.toml");

    if !cargo_toml_path.exists() {
        return Ok(service_name.to_string());
    }

    let content = crate::repo::read_text_async(&cargo_toml_path).await?;

    // Try to find [[bin]] section with name
    // This is a simple parser - looks for: name = "binary-name"
    let mut in_bin_section = false;

    for line in content.lines() {
        let trimmed = line.trim();

        if trimmed == "[[bin]]" {
            in_bin_section = true;
            continue;
        }

        if in_bin_section && trimmed.starts_with("name") {
            // Parse: name = "binary-name" or name = 'binary-name'
            if let Some(eq_pos) = trimmed.find('=') {
                let value = trimmed[eq_pos + 1..].trim();
                let name = value.trim_matches('"').trim_matches('\'').to_string();
                if !name.is_empty() {
                    return Ok(name);
                }
            }
        }

        // Reset if we hit another section
        if trimmed.starts_with('[') && !trimmed.starts_with("[[bin]]") {
            in_bin_section = false;
        }
    }

    // Fall back to service name (with underscores replaced by hyphens and vice versa)
    Ok(service_name.to_string())
}

#[cfg(test)]
mod tests {
    /// Whole-module shield: no raw `Command::new("nix")` may live in
    /// this module's non-test body. Every `nix` spawn in
    /// `commands/developer_tools.rs` must first resolve `NIX_BIN` via
    /// [`crate::repo::get_tool_path`] — the canonical env-var override
    /// every other nix-invocation site in forge honors
    /// (`commands/tool.rs::build_lock_target`, `nix.rs::build_flake_attr_in`,
    /// `nix_hooks.rs::NixHooks::build_and_get_path`).
    ///
    /// Pre-lift the three `rust_update_cargo_nix` / `rust_regenerate` /
    /// `rust_cargo_update` sites each spelled `Command::new("nix")`
    /// verbatim, ignoring `NIX_BIN` at every one. A Nix-hermetic runner
    /// with a store-path `nix` binary silently fell through to whatever
    /// `nix` was first on PATH at these three sites specifically — the
    /// same silent-PATH-fallback bug class the KUBECTL_BIN / GIT_BIN
    /// migrations at 5bb7cff / 818ed9a closed on their respective
    /// spawn surfaces.
    ///
    /// The scan bounds on the whole-module boundary (from the file
    /// start to the `\n#[cfg(test)]\nmod tests {` marker below) so this
    /// shield's own docstring mention of `Command::new("nix")` (which
    /// lives inside this `#[cfg(test)] mod tests` block) stays out of
    /// scope AND every current or future nix-spawning helper landing
    /// anywhere in the top-level module body cannot silently ride along
    /// without going through `NIX_BIN`. Mirrors the sibling shield on
    /// `commands/supergraph_verification.rs::test_supergraph_verification_routes_kubectl_through_kubectl_command_async_not_raw_command`
    /// (65283fb) which pioneered the whole-module-boundary scan
    /// discipline for a multi-function consumer.
    #[test]
    fn test_developer_tools_routes_nix_through_nix_bin_not_raw_command() {
        crate::test_support::assert_source_routes_bare_spawn_through_sigil_bin_fn_at_exactly_one_resolve(
            include_str!("developer_tools.rs"),
            "commands/developer_tools.rs",
            "nix",
            "NIX_BIN",
        );
    }

    /// Whole-module shield: no raw `Command::new("cargo")` may live in
    /// this module's non-test body. Every `cargo` spawn in
    /// `commands/developer_tools.rs` must first resolve `CARGO` via
    /// [`crate::repo::get_tool_path`] — the canonical env-var override
    /// every other cargo-invocation site in forge honors
    /// (`commands/bootstrap.rs:639`, `commands/pangea.rs:473`,
    /// `graphql_schema.rs:193`; the doc-comment idiom lives at
    /// `repo.rs:92`).
    ///
    /// Pre-lift the nine consumer sites — `rust_test`, `rust_lint`,
    /// `rust_fmt`, `rust_fmt_check`, `rust_extract_schema`,
    /// `rust_update_cargo_nix`, `rust_regenerate`, `rust_cargo_update`,
    /// `rust_dev` — each spelled `Command::new("cargo")` verbatim,
    /// ignoring `CARGO` at every one. A Nix-hermetic runner with a
    /// store-path `cargo` binary silently fell through to whatever
    /// `cargo` was first on PATH at these nine sites specifically —
    /// the same silent-PATH-fallback bug class the NIX_BIN /
    /// KUBECTL_BIN / GIT_BIN migrations at 4dfb2b3 / 5bb7cff / 818ed9a
    /// closed on their respective spawn surfaces.
    ///
    /// The scan bounds on the whole-module boundary (from the file
    /// start to the `\n#[cfg(test)]\nmod tests {` marker above) so this
    /// shield's own docstring mention of `Command::new("cargo")` (which
    /// lives inside this `#[cfg(test)] mod tests` block) stays out of
    /// scope AND every current or future cargo-spawning helper landing
    /// anywhere in the top-level module body cannot silently ride along
    /// without going through `CARGO`. Mirrors the sibling `NIX_BIN`
    /// shield above (4dfb2b3) and the whole-module-boundary scan
    /// discipline pioneered on `commands/supergraph_verification.rs`
    /// (65283fb).
    #[test]
    fn test_developer_tools_routes_cargo_through_cargo_env_not_raw_command() {
        crate::test_support::assert_source_routes_bare_spawn_through_sigil_bin_fn_at_exactly_one_resolve(
            include_str!("developer_tools.rs"),
            "commands/developer_tools.rs",
            "cargo",
            "CARGO",
        );
    }

    /// Whole-module shield: no raw `Command::new("docker-compose")` may live in
    /// this module's non-test body. Every `docker-compose` spawn in
    /// `commands/developer_tools.rs` must first resolve `DOCKER_COMPOSE_BIN`
    /// via [`crate::repo::get_tool_path`] — the canonical env-var override
    /// idiom every sibling tool-spawn site in this module already honors
    /// (`NIX_BIN` for nix; `CARGO` for cargo), and the same idiom every
    /// sibling docker-family surface honors (`commands/local.rs::docker_bin`,
    /// `commands/e2e.rs::docker_bin`, both routing through `DOCKER_BIN`).
    ///
    /// Pre-lift the two consumer sites (`rust_dev`'s docker-compose-up,
    /// `rust_dev_down`'s docker-compose-down) each spelled
    /// `Command::new("docker-compose")` verbatim, ignoring
    /// `DOCKER_COMPOSE_BIN` at both. A Nix-hermetic runner with a store-path
    /// `docker-compose` binary silently fell through to whatever
    /// `docker-compose` was first on PATH at these two sites specifically —
    /// the same silent-PATH-fallback bug class the NIX_BIN / CARGO shields
    /// above (4dfb2b3 / 8687093) closed on their respective spawn surfaces,
    /// and the sibling DOCKER_BIN lifts at 1a984dd / 23241a6 closed on the
    /// `docker` surface across `commands/local.rs` and `commands/e2e.rs`.
    ///
    /// The scan bounds on the whole-module boundary (from the file start
    /// to the FIRST `\n#[cfg(test)]\nmod tests {` marker in source order,
    /// which lands at this shield's `#[cfg(test)] mod tests` opener) so
    /// this shield's own docstring mentions of `Command::new("docker-compose")`
    /// — living in a `#[cfg(test)]` block below that first marker — stay
    /// out of scope AND every current or future docker-compose-spawning
    /// helper landing anywhere in the top-level module body cannot silently
    /// ride along without going through `DOCKER_COMPOSE_BIN`. Mirrors the
    /// sibling `NIX_BIN` / `CARGO` shields above and the whole-module-boundary
    /// scan discipline pioneered on
    /// `commands/supergraph_verification.rs::test_supergraph_verification_routes_kubectl_through_kubectl_command_async_not_raw_command`
    /// (65283fb).
    #[test]
    fn test_developer_tools_routes_docker_compose_through_docker_compose_bin_not_raw_command() {
        let body = crate::test_support::module_body_before_tests(
            include_str!("developer_tools.rs"),
            "commands/developer_tools.rs",
        );
        assert!(
            !body.contains("Command::new(\"docker-compose\")"),
            "commands/developer_tools.rs must not spawn `docker-compose` via the bare literal — \
             every `docker-compose` spawn must resolve `DOCKER_COMPOSE_BIN` via \
             `crate::repo::get_tool_path(\"DOCKER_COMPOSE_BIN\", \"docker-compose\")` first. \
             A raw `Command::new(\"docker-compose\")` bypasses the hermetic-runner \
             contract substrate's mkRuntimeToolsEnv exports."
        );
        // Sigil sibling: after the `docker_compose_bin()` lift, every consumer
        // routes through the sigil, so `fn docker_compose_bin()` must be
        // defined AND the two-argument resolve string must appear in EXACTLY
        // one place — only the sigil body — so a future added spawn cannot
        // silently re-copy the resolve inline and drift away from the sigil's
        // single point of truth. Mirrors the sibling `nix_bin()` /
        // `cargo_bin()` shields above on this same module, and the broader
        // `<tool>_bin()` sigil-shield family across the CARGO / NIX_BIN /
        // ATTIC_BIN / DOCA_BIN / FLUX_BIN / NC_BIN surfaces. Both needles are
        // reconstructed via `format!` through `test_support::{
        // sigil_bin_fn_definition_needle, get_tool_path_two_arg_call_needle}`
        // so this assertion pair cannot false-match its own source text on
        // either needle, and both hits route through
        // `test_support::code_line_hits` for anti-docstring-self-match
        // discipline. THEORY §I.5: duplication budget zero.
        let sigil_needle =
            crate::test_support::sigil_bin_fn_definition_needle("docker_compose_bin");
        let sigil_hits = crate::test_support::code_line_hits(body, &sigil_needle);
        assert!(
            !sigil_hits.is_empty(),
            "commands/developer_tools.rs must define `docker_compose_bin()` \
             at a code line — the sigil function that resolves the \
             tools-registry `DOCKER_COMPOSE_BIN` override for every \
             `docker-compose` spawn. Mirrors the sibling `nix_bin()` / \
             `cargo_bin()` sigils above on this same module and the broader \
             `<tool>_bin()` sigil family."
        );
        let two_arg_needle = crate::test_support::get_tool_path_two_arg_call_needle(
            "DOCKER_COMPOSE_BIN",
            "docker-compose",
        );
        let resolve_hits = crate::test_support::code_line_hits(body, &two_arg_needle);
        assert_eq!(
            resolve_hits.len(),
            1,
            "the two-argument resolve `{two_arg_needle}` must appear at \
             exactly ONE code line in the module body (only in the \
             `docker_compose_bin()` sigil), not {} — every consumer must \
             route through `docker_compose_bin()`, not re-copy the resolve \
             inline. A future edit to the resolve contract (a substrate-path \
             validation step, a per-spawn env-injection hook, a telemetry \
             sigil on the resolved path) must land at the sigil body once, \
             not at each drifted call site. Found {} code-line hit(s): \
             {resolve_hits:#?}",
            resolve_hits.len(),
            resolve_hits.len()
        );
    }

    /// Whole-module shield: every `cargo update` spawn in this module
    /// must route through the canonical [`crate::nix::run_cargo_update`]
    /// primitive, never through an inline
    /// `Command::new(<cargo>); cmd.arg("update");
    /// run_inherited_status(cmd, "cargo update")` triple.
    ///
    /// Pre-lift `rust_update_cargo_nix` and `rust_cargo_update` each
    /// spelled the primitive's five-line body verbatim — the third and
    /// fourth copies of the same shape after `nix::run_cargo_update`
    /// (nix.rs:435) and its `commands/bootstrap.rs::rebuild_bootstrap_cargo_nix`
    /// consumer (bootstrap.rs:645). Four occurrences past THEORY §VI.1's
    /// three-times-is-a-law threshold; the primitive is the archetype
    /// the pillar demands, and post-lift every `cargo update` spawn in
    /// forge routes through it. A future refinement — the info!
    /// telemetry line grows a structured field, the retry policy for
    /// transient `Cargo.lock`-write contention gets tightened, the
    /// bail-context prefix carries the workspace path — lands at ONE
    /// body and reaches every consumer by construction.
    ///
    /// The `run_inherited_status(cmd, "cargo update")` needle catches
    /// the failure mode a bare `!body.contains("cargo update")` scan
    /// would miss: a caller who kept the operator-visible `println!`
    /// prose but hand-rolled the spawn (`let mut cmd = ...; cmd.arg(...);
    /// run_inherited_status(cmd, "cargo update")`) instead of routing
    /// through `nix::run_cargo_update`. Routing the assertion through
    /// [`crate::test_support::code_line_hits`] keeps this docstring's
    /// mention of the forbidden needle from false-matching itself.
    #[test]
    fn test_developer_tools_cargo_update_routes_through_nix_run_cargo_update() {
        let body = crate::test_support::module_body_before_tests(
            include_str!("developer_tools.rs"),
            "commands/developer_tools.rs",
        );
        let forbidden = "run_inherited_status(cmd, \"cargo update\")";
        let inline_hits = crate::test_support::code_line_hits(body, forbidden);
        assert!(
            inline_hits.is_empty(),
            "commands/developer_tools.rs must not spawn `cargo update` \
             via an inline `run_inherited_status(cmd, \"cargo update\")` \
             triple — every `cargo update` spawn in this module must \
             route through `crate::nix::run_cargo_update(&cargo_bin())`. \
             Found {} inline hit(s): {inline_hits:#?}. \
             A hand-rolled inline copy re-opens the drift class the \
             primitive was landed to close (the info! telemetry line, \
             the bail-on-non-zero-exit `run_inherited_status` routing, \
             and the outer `context(\"Failed to update Cargo.lock\")` \
             wrap all live at ONE body).",
            inline_hits.len()
        );
        // Positive-side sibling: at least one consumer in this module
        // routes through the primitive. A regression that dropped every
        // `nix::run_cargo_update` call from this module would leave the
        // forbidden scan trivially satisfied by absence, so pin the
        // positive presence too — the two pre-lift sites
        // (`rust_update_cargo_nix` and `rust_cargo_update`) each land
        // one `crate::nix::run_cargo_update(&cargo_bin())` hit.
        let canonical = "crate::nix::run_cargo_update(&cargo_bin())";
        let canonical_hits = crate::test_support::code_line_hits(body, canonical);
        assert!(
            canonical_hits.len() >= 2,
            "commands/developer_tools.rs must delegate `cargo update` \
             spawns through `{canonical}` at at least two code lines \
             (one per pre-lift consumer: `rust_update_cargo_nix`, \
             `rust_cargo_update`). Found {} code-line hit(s): \
             {canonical_hits:#?}.",
            canonical_hits.len()
        );
    }

    /// Whole-module shield: every `nix run nixpkgs#crate2nix -- generate`
    /// spawn in this module must route through the canonical
    /// [`crate::nix::run_nix_wrapped_crate2nix`] primitive, never
    /// through an inline `Command::new(<nix>); cmd.args(&["run",
    /// "nixpkgs#crate2nix", "--", "generate", ...]); run_inherited_
    /// status(cmd, "crate2nix generate")` triple.
    ///
    /// Pre-lift `rust_update_cargo_nix`, `rust_regenerate`, and
    /// `rust_cargo_update` each spelled the eight-element argv literal
    /// verbatim — three occurrences past THEORY §VI.1's
    /// three-times-is-a-law threshold, extracted onto ONE archetype.
    /// A future refinement — the info! telemetry line grows a
    /// structured `flake_registry` field, the retry policy for
    /// transient nixpkgs-fetch failures gets tightened, the
    /// bail-context prefix carries the `-o Cargo.nix` target path —
    /// lands at ONE body and reaches every consumer by construction.
    /// The pre-lift bail-context prefix drifted (`"Failed to run
    /// crate2nix generate"` at two sites, `"Failed to generate Cargo.
    /// nix"` at the third) exactly because three sibling hand-rolled
    /// stanzas each free-authored the wrap; the primitive collapses
    /// them onto ONE canonical `"Failed to generate Cargo.nix"` wrap.
    ///
    /// The `"nixpkgs#crate2nix"` needle catches the failure mode a
    /// bare `!body.contains("crate2nix generate")` scan would miss:
    /// a caller who kept the operator-visible `println!` prose but
    /// hand-rolled the wrapped-generate argv (`let mut cmd = ...;
    /// cmd.args(&["run", "nixpkgs#crate2nix", "--", "generate"]);
    /// run_inherited_status(cmd, "crate2nix generate")`) instead of
    /// routing through `nix::run_nix_wrapped_crate2nix`. Routing the
    /// assertion through [`crate::test_support::code_line_hits`]
    /// keeps this docstring's mention of the forbidden flake-attr
    /// literal from false-matching itself.
    #[test]
    fn test_developer_tools_wrapped_crate2nix_routes_through_nix_primitive() {
        let body = crate::test_support::module_body_before_tests(
            include_str!("developer_tools.rs"),
            "commands/developer_tools.rs",
        );
        let forbidden = "\"nixpkgs#crate2nix\"";
        let inline_hits = crate::test_support::code_line_hits(body, forbidden);
        assert!(
            inline_hits.is_empty(),
            "commands/developer_tools.rs must not spawn `nix run \
             nixpkgs#crate2nix -- generate` via an inline argv \
             literal — every wrapped-crate2nix spawn in this module \
             must route through `crate::nix::run_nix_wrapped_crate2nix\
             (&nix_bin(), &[...])`. Found {} inline hit(s): \
             {inline_hits:#?}. A hand-rolled inline copy re-opens the \
             drift class the primitive was landed to close (the info! \
             telemetry line, the eight-element argv prefix, the \
             `retry::run_inherited_status` routing, and the outer \
             `context(\"Failed to generate Cargo.nix\")` wrap all \
             live at ONE body).",
            inline_hits.len()
        );
        // Positive-side sibling: at least three consumers in this
        // module route through the primitive (one per pre-lift site).
        // A regression that dropped every
        // `nix::run_nix_wrapped_crate2nix` call from this module would
        // leave the forbidden scan trivially satisfied by absence, so
        // pin the positive presence too — the three pre-lift sites
        // (`rust_update_cargo_nix`, `rust_regenerate`,
        // `rust_cargo_update`) each land one
        // `crate::nix::run_nix_wrapped_crate2nix(` hit.
        let canonical = "crate::nix::run_nix_wrapped_crate2nix(";
        let canonical_hits = crate::test_support::code_line_hits(body, canonical);
        assert!(
            canonical_hits.len() >= 3,
            "commands/developer_tools.rs must delegate wrapped \
             `crate2nix generate` spawns through `{canonical}...)` at \
             at least three code lines (one per pre-lift consumer: \
             `rust_update_cargo_nix`, `rust_regenerate`, \
             `rust_cargo_update`). Found {} code-line hit(s): \
             {canonical_hits:#?}.",
            canonical_hits.len()
        );
    }

    /// Whole-module shield: every read of the `SERVICE_DIR` env var in
    /// this module's non-test body must route through the module-local
    /// [`super::service_path_from_env`] sigil, which itself delegates
    /// to the shared [`crate::repo::path_from_env`] primitive — never
    /// through an inline `env::var("SERVICE_DIR").context(...)?` +
    /// `PathBuf::from(...)` two-line stanza.
    ///
    /// Pre-lift the four consumer sites (`rust_regenerate`,
    /// `rust_cargo_update`, `rust_dev`, `rust_dev_down`) each spelled
    /// the same two-line stanza verbatim — a byte-identical
    /// operator-facing miss wording that had drifted only by
    /// convention. Four occurrences past THEORY §VI.1's
    /// three-times-is-a-law threshold; the sigil is the archetype the
    /// pillar demands, and post-lift every `SERVICE_DIR` read in this
    /// module routes through it. Post-e9e0c5b the twin
    /// `commands/schema_validation.rs:41` per-module sigil made the
    /// per-module read-and-project shape itself a two-copy recurrence;
    /// this shield now pins the shared-primitive delegation, so a
    /// future refinement of the `SERVICE_DIR` contract — a canonicalize
    /// hook, a substrate-path validation step, a telemetry sigil on
    /// the resolved path, or a swap to a typed
    /// `substrate::ServiceDir(PathBuf)` newtype — lands at ONE body
    /// ([`crate::repo::path_from_env`]) and reaches every consumer in
    /// this module (and the sibling `commands/schema_validation.rs`)
    /// by construction.
    ///
    /// The scan bounds on the whole-module boundary (from the file
    /// start to the FIRST `\n#[cfg(test)]\nmod tests {` marker in
    /// source order, which lands at the parent `#[cfg(test)] mod tests`
    /// opener above) so this shield's own docstring mentions of
    /// `env::var("SERVICE_DIR")` — living inside a `#[cfg(test)]`
    /// block below that first marker — stay out of scope AND every
    /// current or future `SERVICE_DIR`-reading consumer landing anywhere
    /// in the top-level module body cannot silently ride along without
    /// routing through the sigil. Every hit routes through
    /// [`crate::test_support::code_line_hits`] for anti-docstring-self-
    /// match discipline. Mirrors the sibling `<tool>_bin()` sigil-shield
    /// family above on this same module.
    #[test]
    fn test_developer_tools_service_dir_routes_through_service_path_from_env() {
        let body = crate::test_support::module_body_before_tests(
            include_str!("developer_tools.rs"),
            "commands/developer_tools.rs",
        );
        // Negative side: the raw `env::var("SERVICE_DIR")` needle must
        // NOT appear anywhere in the module body post-lift — the sigil
        // now delegates to `crate::repo::path_from_env`, which owns the
        // read at ONE body across the crate. A future consumer that
        // re-copies the two-line stanza pushes this count above zero
        // and fails the shield before it can drift the miss wording or
        // the `PathBuf` projection away from the shared primitive's
        // single point of truth.
        let raw_env_needle = "env::var(\"SERVICE_DIR\")";
        let env_hits = crate::test_support::code_line_hits(body, raw_env_needle);
        assert!(
            env_hits.is_empty(),
            "commands/developer_tools.rs must NOT spell \
             `{raw_env_needle}` inline in the module body — every \
             consumer must route through `service_path_from_env()`, \
             which delegates to `crate::repo::path_from_env`, the \
             shared primitive that owns the `env::var` read at ONE \
             body across the crate. Found {} code-line hit(s): \
             {env_hits:#?}. A hand-rolled inline copy re-opens the \
             drift class the primitive was landed to close.",
            env_hits.len()
        );
        // Positive side: `service_path_from_env` must delegate to
        // `crate::repo::path_from_env(` at EXACTLY one code line — the
        // sigil body. A regression that inlined the read back into the
        // sigil (or into any consumer) would break the delegation and
        // be caught here. The needle matches the call opener only
        // (arguments may wrap across lines under rustfmt's line-width
        // limit — the two-arg form's `miss_context` literal exceeds
        // 100 columns and formats onto separate lines); the sibling
        // `env::var("SERVICE_DIR")` count-eq-0 assertion above bounds
        // the negative side, and this one bounds the positive.
        let delegate_needle = "crate::repo::path_from_env(";
        let delegate_hits = crate::test_support::code_line_hits(body, delegate_needle);
        assert_eq!(
            delegate_hits.len(),
            1,
            "commands/developer_tools.rs must delegate `SERVICE_DIR` \
             resolution to `crate::repo::path_from_env(...)` at EXACTLY \
             one code line — the `service_path_from_env()` sigil body. \
             Found {} code-line hit(s): {delegate_hits:#?}. A missing \
             delegation would leave the negative scan above trivially \
             satisfied by absence (zero raw `env::var` hits, but also \
             zero delegating calls), and the module would have stopped \
             resolving `SERVICE_DIR` at all.",
            delegate_hits.len()
        );
        // Sigil-defined side: `fn service_path_from_env()` must be
        // defined in the module body — a regression that removed the
        // sigil would leave the negative scan trivially satisfied by
        // absence (zero hits on the raw needle, not one), so pin the
        // presence of the sigil definition too.
        let sigil_def_needle = "fn service_path_from_env()";
        let sigil_def_hits = crate::test_support::code_line_hits(body, sigil_def_needle);
        assert_eq!(
            sigil_def_hits.len(),
            1,
            "commands/developer_tools.rs must define \
             `{sigil_def_needle}` at EXACTLY one code line — the \
             sigil function that resolves `SERVICE_DIR` into a `PathBuf` \
             for every `SERVICE_DIR`-reading consumer in this module. \
             Found {} code-line hit(s): {sigil_def_hits:#?}. Mirrors \
             the sibling `nix_bin()` / `cargo_bin()` / \
             `docker_compose_bin()` sigils above on this same module.",
            sigil_def_hits.len()
        );
        // Positive-side sibling: at least four consumers in this
        // module route through the sigil. A regression that dropped
        // every `service_path_from_env()` call from this module would
        // leave the negative scan trivially satisfied by an
        // env-var-free body, so pin the positive presence too — the
        // four pre-lift sites (`rust_regenerate`, `rust_cargo_update`,
        // `rust_dev`, `rust_dev_down`) each land one
        // `service_path_from_env()?` hit.
        let call_needle = "service_path_from_env()?";
        let call_hits = crate::test_support::code_line_hits(body, call_needle);
        assert!(
            call_hits.len() >= 4,
            "commands/developer_tools.rs must delegate `SERVICE_DIR` \
             reads through `{call_needle}` at at least four code lines \
             (one per pre-lift consumer: `rust_regenerate`, \
             `rust_cargo_update`, `rust_dev`, `rust_dev_down`). Found \
             {} code-line hit(s): {call_hits:#?}.",
            call_hits.len()
        );
    }

    /// Functional shield: [`super::service_path_from_env`] surfaces the
    /// canonical
    /// `"SERVICE_DIR not set - this should be called via substrate
    /// wrapper"` context on a `SERVICE_DIR`-unset environment, byte-
    /// identical to what each pre-lift consumer site spelled at its
    /// own `.context(...)` call. Pins the operator-facing miss wording
    /// at the sigil body so a future refactor that reshapes the sigil
    /// (a swap from `.context()` to a `bail!` with drifted wording, a
    /// canonicalize prefix landed in front of the context, a lift to a
    /// typed error variant) cannot silently drift the message every
    /// consumer's caller has been coached to grep for.
    ///
    /// Holds [`crate::test_support::ROOT_FLAKE_ENV_LOCK`] for the
    /// duration of the env mutation — `SERVICE_DIR` is process-global
    /// state, and the sibling `RootFlakeEnvSnapshot` discipline
    /// guarantees no concurrent `SERVICE_DIR`-reading test races the
    /// scope. Restores the pre-scope `SERVICE_DIR` value on drop via
    /// [`crate::test_support::EnvVarSnapshot`]'s RAII guard — the
    /// panic-safe primitive that closes the pre-lift `let prior =
    /// std::env::var("SERVICE_DIR"); ...; match &prior { Ok(v) =>
    /// set_var, Err(_) => remove_var }` inline stanza's window where
    /// an `unwrap_err()` panic between snapshot and restore silently
    /// leaked `SERVICE_DIR=<unset>` to every subsequent test.
    #[test]
    fn test_service_path_from_env_surfaces_canonical_miss_wording_when_unset() {
        let _guard = crate::test_support::ROOT_FLAKE_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let _snapshot = crate::test_support::EnvVarSnapshot::capture("SERVICE_DIR");
        std::env::remove_var("SERVICE_DIR");
        let err = super::service_path_from_env().unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("SERVICE_DIR not set - this should be called via substrate wrapper"),
            "service_path_from_env() must surface the canonical miss \
             wording on a `SERVICE_DIR`-unset environment — the same \
             wording every pre-lift consumer site's `.context(...)` \
             call spelled verbatim. Got: {msg}"
        );
    }

    /// Functional shield: [`super::service_path_from_env`] returns a
    /// [`PathBuf`] equal to `PathBuf::from(SERVICE_DIR)` when the env
    /// var is set. Pins the `SERVICE_DIR` → `PathBuf` projection at the
    /// sigil body so a future refinement (a canonicalize hook, a
    /// substrate-path validation step) that drifts the projection is
    /// caught here rather than at each consumer's downstream
    /// `.parent()` / `.join(...)` call. Uses the same
    /// [`crate::test_support::ROOT_FLAKE_ENV_LOCK`] discipline as the
    /// sibling unset-side shield above.
    #[test]
    fn test_service_path_from_env_returns_path_of_set_env_var() {
        let _guard = crate::test_support::ROOT_FLAKE_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let _snapshot = crate::test_support::EnvVarSnapshot::capture("SERVICE_DIR");
        let sentinel = "/tmp/forge-developer-tools-service-path-sigil-shield";
        std::env::set_var("SERVICE_DIR", sentinel);
        let result = super::service_path_from_env();
        let path = result.expect("service_path_from_env must succeed when SERVICE_DIR is set");
        assert_eq!(
            path,
            std::path::PathBuf::from(sentinel),
            "service_path_from_env() must return `PathBuf::from(SERVICE_DIR)` \
             verbatim — the projection every pre-lift consumer site \
             spelled via `Path::new(&service_dir)`."
        );
    }
}
