//! Developer tooling commands for Rust services.
//!
//! These commands are exposed via `nix run .#` apps for local development.

use std::env;
use std::path::Path;
use std::process::Stdio;

use anyhow::{anyhow, bail, Context, Result};
use colored::Colorize;
use tokio::process::Command;

/// Run Rust unit tests
pub async fn rust_test(service: String) -> Result<()> {
    println!("🧪 Running unit tests for {}...", service.cyan());
    let status = Command::new("cargo")
        .args(&["test", "--lib", "--bins"])
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .await
        .context("Failed to run tests")?;

    if !status.success() {
        bail!("Tests failed");
    }

    Ok(())
}

/// Run Rust clippy linter
pub async fn rust_lint(service: String) -> Result<()> {
    println!("🔍 Running clippy linter for {}...", service.cyan());
    let status = Command::new("cargo")
        .args(&[
            "clippy",
            "--all-targets",
            "--all-features",
            "--",
            "-D",
            "warnings",
        ])
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .await
        .context("Failed to run clippy")?;

    if !status.success() {
        bail!("Linting failed");
    }

    Ok(())
}

/// Format Rust code with rustfmt
pub async fn rust_fmt(service: String) -> Result<()> {
    println!("✨ Formatting code for {}...", service.cyan());
    let status = Command::new("cargo")
        .args(&["fmt", "--all"])
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .await
        .context("Failed to format code")?;

    if !status.success() {
        bail!("Formatting failed");
    }

    Ok(())
}

/// Check Rust code formatting
pub async fn rust_fmt_check(service: String) -> Result<()> {
    println!("🔍 Checking code formatting for {}...", service.cyan());
    let status = Command::new("cargo")
        .args(&["fmt", "--all", "--", "--check"])
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .await
        .context("Failed to check formatting")?;

    if !status.success() {
        bail!("Code is not formatted correctly");
    }

    Ok(())
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
            let status = Command::new("cargo")
                .args(&["run", "--bin", bin_name])
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .status()
                .await
                .context("Failed to extract schema")?;

            if !status.success() {
                bail!("Schema extraction failed");
            }

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
    let status = Command::new("cargo")
        .arg("update")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .await
        .context("Failed to update Cargo.lock")?;

    if !status.success() {
        bail!("Cargo update failed");
    }

    // Generate Cargo.nix
    println!();
    println!("Generating Cargo.nix...");
    let status = Command::new("nix")
        .args(&["run", "nixpkgs#crate2nix", "--", "generate"])
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .await
        .context("Failed to generate Cargo.nix")?;

    if !status.success() {
        bail!("Cargo.nix generation failed");
    }

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
    let service_dir = env::var("SERVICE_DIR")
        .context("SERVICE_DIR not set - this should be called via substrate wrapper")?;

    let service_path = Path::new(&service_dir);

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
    env::set_current_dir(workspace_root).context("Failed to change to workspace directory")?;

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
    let status = Command::new("cargo")
        .arg("generate-lockfile")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .await
        .context("Failed to run cargo generate-lockfile")?;

    if !status.success() {
        bail!("❌ cargo generate-lockfile failed");
    }
    println!("   ✅ Cargo.lock generated");
    println!();

    // Step 3: Generate Cargo.nix
    println!(
        "📦 {} {}",
        "Generating Cargo.nix".bold(),
        "(crate2nix generate)".dimmed()
    );
    let status = Command::new("nix")
        .args(&[
            "run",
            "nixpkgs#crate2nix",
            "--",
            "generate",
            "-f",
            "Cargo.toml",
            "-o",
            "Cargo.nix",
        ])
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .await
        .context("Failed to run crate2nix generate")?;

    if !status.success() {
        bail!("❌ crate2nix generate failed");
    }
    println!("   ✅ Cargo.nix generated");
    println!();

    // Success summary
    println!("{}", "━".repeat(80).bright_green());
    println!("{}", "✅ REGENERATION COMPLETE".green().bold());
    println!("{}", "━".repeat(80).bright_green());
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
    let service_dir = env::var("SERVICE_DIR")
        .context("SERVICE_DIR not set - this should be called via substrate wrapper")?;

    let service_path = Path::new(&service_dir);

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
    env::set_current_dir(workspace_root).context("Failed to change to workspace directory")?;

    // Step 1: Update dependencies
    println!(
        "📦 {} {}",
        "Updating dependencies".bold(),
        "(cargo update)".dimmed()
    );
    let status = Command::new("cargo")
        .arg("update")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .await
        .context("Failed to run cargo update")?;

    if !status.success() {
        bail!("❌ cargo update failed");
    }
    println!("   ✅ Dependencies updated");
    println!();

    // Step 2: Generate Cargo.nix
    println!(
        "📦 {} {}",
        "Generating Cargo.nix".bold(),
        "(crate2nix generate)".dimmed()
    );
    let status = Command::new("nix")
        .args(&[
            "run",
            "nixpkgs#crate2nix",
            "--",
            "generate",
            "-f",
            "Cargo.toml",
            "-o",
            "Cargo.nix",
        ])
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .await
        .context("Failed to run crate2nix generate")?;

    if !status.success() {
        bail!("❌ crate2nix generate failed");
    }
    println!("   ✅ Cargo.nix generated");
    println!();

    // Success summary
    println!("{}", "━".repeat(80).bright_green());
    println!("{}", "✅ UPDATE COMPLETE".green().bold());
    println!("{}", "━".repeat(80).bright_green());
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
    let service_dir = env::var("SERVICE_DIR")
        .context("SERVICE_DIR not set - this should be called via substrate wrapper")?;
    let service_path = Path::new(&service_dir);

    println!("📂 Service directory: {}", service_path.display());

    // Load deploy.yaml configuration
    let config = crate::config::DeployConfig::load_for_service(&service)?;
    let local_config = &config.service.local;

    // Change to service directory for all operations
    env::set_current_dir(service_path).context("Failed to change to service directory")?;

    // Step 1: Start docker-compose if not skipped
    if !skip_docker {
        let compose_file = find_compose_file(service_path)?;

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

            let status = Command::new("docker-compose")
                .args(&["-f", compose_path.to_str().unwrap(), "up", "-d"])
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .status()
                .await
                .context("Failed to start docker-compose")?;

            if !status.success() {
                bail!("❌ docker-compose up failed");
            }

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

            // Use sqlx_cli from CLI arg (nix derivation path), otherwise try "sqlx" in PATH
            let sqlx_cmd = sqlx_cli.clone().unwrap_or_else(|| "sqlx".to_string());

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
        detect_binary_name(service_path, &service).await?
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

    let mut cmd = Command::new("cargo");
    cmd.arg("run");

    if !bin_name.is_empty() {
        cmd.args(&["--bin", &bin_name]);
    }

    // Add any additional cargo args from config
    for arg in &local_config.cargo_args {
        cmd.arg(arg);
    }

    let status = cmd
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .await
        .context("Failed to start cargo run")?;

    if !status.success() {
        bail!("❌ cargo run exited with error");
    }

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
    let service_dir = env::var("SERVICE_DIR")
        .context("SERVICE_DIR not set - this should be called via substrate wrapper")?;
    let service_path = Path::new(&service_dir);

    env::set_current_dir(service_path).context("Failed to change to service directory")?;

    let compose_file = find_compose_file(service_path)?;

    if let Some(compose_path) = compose_file {
        let status = Command::new("docker-compose")
            .args(&["-f", compose_path.to_str().unwrap(), "down"])
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .await
            .context("Failed to stop docker-compose")?;

        if !status.success() {
            bail!("❌ docker-compose down failed");
        }

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

    let content = tokio::fs::read_to_string(&cargo_toml_path)
        .await
        .context("Failed to read Cargo.toml")?;

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
