use anyhow::Result;
use clap::Parser;
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgPoolOptions;
use std::path::PathBuf;
use tracing::{info, error};

/// PostgreSQL database provisioning tool
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to config file
    #[arg(short, long, default_value = "postgres-config.yaml")]
    config: PathBuf,

    /// Dry run - show what would be done without executing
    #[arg(short, long)]
    dry_run: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct Config {
    /// PostgreSQL connection URL
    database_url: String,

    /// Databases to create
    databases: Vec<DatabaseConfig>,

    /// Users to create
    users: Vec<UserConfig>,

    /// Extensions to enable
    extensions: Vec<ExtensionConfig>,
}

#[derive(Debug, Serialize, Deserialize)]
struct DatabaseConfig {
    name: String,
    owner: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct UserConfig {
    username: String,
    password: String,
    superuser: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ExtensionConfig {
    name: String,
    database: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    info!("Loading config from {:?}", args.config);
    let config_content = std::fs::read_to_string(&args.config)?;
    let config: Config = serde_yaml::from_str(&config_content)?;

    if args.dry_run {
        info!("DRY RUN MODE - No changes will be made");
        print_plan(&config);
        return Ok(());
    }

    // Connect to PostgreSQL
    info!("Connecting to PostgreSQL");
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&config.database_url)
        .await?;

    // Create users
    for user in &config.users {
        info!("Creating user: {}", user.username);
        create_user(&pool, user).await?;
    }

    // Create databases
    for db in &config.databases {
        info!("Creating database: {}", db.name);
        create_database(&pool, db).await?;
    }

    // Enable extensions
    for ext in &config.extensions {
        info!("Enabling extension {} in database {}", ext.name, ext.database);
        enable_extension(&pool, ext).await?;
    }

    info!("✅ Provisioning complete");
    Ok(())
}

fn print_plan(config: &Config) {
    println!("\nProvisioning Plan:");
    println!("==================\n");

    println!("Users to create:");
    for user in &config.users {
        println!("  - {} (superuser: {})", user.username, user.superuser.unwrap_or(false));
    }

    println!("\nDatabases to create:");
    for db in &config.databases {
        println!("  - {} (owner: {})", db.name, db.owner.as_deref().unwrap_or("default"));
    }

    println!("\nExtensions to enable:");
    for ext in &config.extensions {
        println!("  - {} in {}", ext.name, ext.database);
    }

    println!();
}

async fn create_user(pool: &sqlx::PgPool, user: &UserConfig) -> Result<()> {
    let superuser = if user.superuser.unwrap_or(false) {
        "SUPERUSER"
    } else {
        "NOSUPERUSER"
    };

    let query = format!(
        "CREATE USER IF NOT EXISTS {} WITH PASSWORD '{}' {}",
        user.username, user.password, superuser
    );

    sqlx::query(&query).execute(pool).await?;
    Ok(())
}

async fn create_database(pool: &sqlx::PgPool, db: &DatabaseConfig) -> Result<()> {
    let owner = db.owner.as_deref().unwrap_or("postgres");

    let query = format!(
        "CREATE DATABASE IF NOT EXISTS {} OWNER {}",
        db.name, owner
    );

    sqlx::query(&query).execute(pool).await?;
    Ok(())
}

async fn enable_extension(pool: &sqlx::PgPool, ext: &ExtensionConfig) -> Result<()> {
    // Connect to specific database
    let db_url = pool.connect_options().database(&ext.database).to_url_lossy();
    let db_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&db_url)
        .await?;

    let query = format!("CREATE EXTENSION IF NOT EXISTS {}", ext.name);
    sqlx::query(&query).execute(&db_pool).await?;

    Ok(())
}
