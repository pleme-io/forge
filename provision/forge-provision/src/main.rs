//! Forge infrastructure provisioning tool
//!
//! YAML-driven, idempotent provisioning for production infrastructure:
//! - PostgreSQL databases with CDC support
//! - Attic binary caches
//!
//! All operations are production-ready with comprehensive security, validation,
//! and retry logic. Safe to run multiple times - automatically detects and skips
//! already-provisioned resources.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::env;
use tracing::info;

mod attic;
mod config;
mod nix_builder;
mod postgres;
mod validation;

use config::{AtticProvisionConfig, NixBuilderConfig, PostgresConfig};

#[derive(Parser, Debug)]
#[command(name = "forge-provision")]
#[command(
    about = "Forge infrastructure provisioning tool",
    long_about = "Production-ready, idempotent provisioning for PostgreSQL databases and Attic caches.\n\n\
    All operations are safe to run multiple times and will skip already-provisioned resources."
)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Provision Attic binary caches
    #[command(name = "attic-cache")]
    AtticCache {
        #[command(subcommand)]
        action: AtticAction,
    },
    /// Provision PostgreSQL databases
    #[command(name = "postgres")]
    Postgres {
        #[command(subcommand)]
        action: PostgresAction,
    },
    /// Provision Nix remote builders
    #[command(name = "nix-builder")]
    NixBuilder {
        #[command(subcommand)]
        action: NixBuilderAction,
    },
}

#[derive(Subcommand, Debug)]
enum AtticAction {
    /// Provision a new cache (idempotent)
    Provision {
        /// Path to YAML config file
        #[arg(long, env = "ATTIC_CONFIG_PATH")]
        config: String,
    },
}

#[derive(Subcommand, Debug)]
enum PostgresAction {
    /// Provision PostgreSQL database (idempotent)
    Provision {
        /// Path to YAML config file
        #[arg(long, env = "POSTGRES_CONFIG_PATH")]
        config: String,
    },
}

#[derive(Subcommand, Debug)]
enum NixBuilderAction {
    /// Provision Nix remote builder (idempotent)
    Provision {
        /// Path to YAML config file
        #[arg(long, env = "NIX_BUILDER_CONFIG_PATH")]
        config: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing with sensible defaults
    tracing_subscriber::fmt()
        .with_env_filter(
            env::var("RUST_LOG")
                .unwrap_or_else(|_| "forge_provision=info,sqlx=warn".to_string()),
        )
        .with_target(false)
        .init();

    let cli = Cli::parse();

    let result = match cli.command {
        Commands::AtticCache { action } => handle_attic_action(action).await,
        Commands::Postgres { action } => handle_postgres_action(action).await,
        Commands::NixBuilder { action } => handle_nix_builder_action(action).await,
    };

    if let Err(ref e) = result {
        tracing::error!("Provisioning failed: {:#}", e);
    }

    result
}

async fn handle_attic_action(action: AtticAction) -> Result<()> {
    match action {
        AtticAction::Provision { config } => {
            info!("Loading Attic configuration from: {}", config);

            let config_content = std::fs::read_to_string(&config).with_context(|| {
                format!(
                    "Failed to read Attic configuration file: {}. Ensure the file exists and is readable.",
                    config
                )
            })?;

            let attic_config: AtticProvisionConfig = serde_yaml::from_str(&config_content)
                .with_context(|| {
                    format!(
                        "Failed to parse Attic configuration file: {}. Ensure the YAML is valid.",
                        config
                    )
                })?;

            attic::provision_from_config(attic_config)
                .await
                .context("Attic cache provisioning failed")
        }
    }
}

async fn handle_postgres_action(action: PostgresAction) -> Result<()> {
    match action {
        PostgresAction::Provision { config } => {
            info!("Loading PostgreSQL configuration from: {}", config);

            let config_content = std::fs::read_to_string(&config).with_context(|| {
                format!(
                    "Failed to read PostgreSQL configuration file: {}. Ensure the file exists and is readable.",
                    config
                )
            })?;

            let pg_config: PostgresConfig = serde_yaml::from_str(&config_content)
                .with_context(|| {
                    format!(
                        "Failed to parse PostgreSQL configuration file: {}. Ensure the YAML is valid.",
                        config
                    )
                })?;

            postgres::provision_from_config(pg_config)
                .await
                .context("PostgreSQL database provisioning failed")
        }
    }
}

async fn handle_nix_builder_action(action: NixBuilderAction) -> Result<()> {
    match action {
        NixBuilderAction::Provision { config } => {
            info!("Loading Nix builder configuration from: {}", config);

            let config_content = std::fs::read_to_string(&config).with_context(|| {
                format!(
                    "Failed to read Nix builder configuration file: {}. Ensure the file exists and is readable.",
                    config
                )
            })?;

            let nix_builder_config: NixBuilderConfig = serde_yaml::from_str(&config_content)
                .with_context(|| {
                    format!(
                        "Failed to parse Nix builder configuration file: {}. Ensure the YAML is valid.",
                        config
                    )
                })?;

            nix_builder::provision_from_config(nix_builder_config)
                .await
                .context("Nix builder provisioning failed")
        }
    }
}
