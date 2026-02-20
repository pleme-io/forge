use anyhow::Result;
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tracing::{info, error};

/// Attic binary cache provisioning tool
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to config file
    #[arg(short, long, default_value = "attic-config.yaml")]
    config: PathBuf,

    /// Dry run - show what would be done without executing
    #[arg(short, long)]
    dry_run: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct Config {
    /// Attic server URL
    server_url: String,

    /// Admin token for API access
    admin_token: String,

    /// Caches to create
    caches: Vec<CacheConfig>,

    /// Tokens to generate
    tokens: Vec<TokenConfig>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CacheConfig {
    name: String,
    public: bool,
    retention_period: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct TokenConfig {
    name: String,
    cache: String,
    read: bool,
    write: bool,
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

    let client = reqwest::Client::new();

    // Create caches
    for cache in &config.caches {
        info!("Creating cache: {}", cache.name);
        create_cache(&client, &config.server_url, &config.admin_token, cache).await?;
    }

    // Generate tokens
    for token in &config.tokens {
        info!("Generating token: {} for cache {}", token.name, token.cache);
        generate_token(&client, &config.server_url, &config.admin_token, token).await?;
    }

    info!("✅ Attic provisioning complete");
    Ok(())
}

fn print_plan(config: &Config) {
    println!("\nAttic Provisioning Plan:");
    println!("========================\n");

    println!("Server: {}", config.server_url);

    println!("\nCaches to create:");
    for cache in &config.caches {
        println!("  - {} (public: {}, retention: {})",
            cache.name,
            cache.public,
            cache.retention_period.as_deref().unwrap_or("default")
        );
    }

    println!("\nTokens to generate:");
    for token in &config.tokens {
        let perms = match (token.read, token.write) {
            (true, true) => "read+write",
            (true, false) => "read-only",
            (false, true) => "write-only",
            (false, false) => "no access",
        };
        println!("  - {} for cache {} ({})", token.name, token.cache, perms);
    }

    println!();
}

async fn create_cache(
    client: &reqwest::Client,
    server_url: &str,
    admin_token: &str,
    cache: &CacheConfig,
) -> Result<()> {
    #[derive(Serialize)]
    struct CreateCacheRequest {
        name: String,
        public: bool,
        retention_period: Option<String>,
    }

    let response = client
        .post(format!("{}/api/v1/caches", server_url))
        .bearer_auth(admin_token)
        .json(&CreateCacheRequest {
            name: cache.name.clone(),
            public: cache.public,
            retention_period: cache.retention_period.clone(),
        })
        .send()
        .await?;

    if response.status().is_success() {
        info!("✓ Cache {} created", cache.name);
    } else {
        error!("✗ Failed to create cache {}: {}", cache.name, response.status());
    }

    Ok(())
}

async fn generate_token(
    client: &reqwest::Client,
    server_url: &str,
    admin_token: &str,
    token: &TokenConfig,
) -> Result<()> {
    #[derive(Serialize)]
    struct GenerateTokenRequest {
        name: String,
        cache: String,
        read: bool,
        write: bool,
    }

    #[derive(Deserialize)]
    struct GenerateTokenResponse {
        token: String,
    }

    let response = client
        .post(format!("{}/api/v1/tokens", server_url))
        .bearer_auth(admin_token)
        .json(&GenerateTokenRequest {
            name: token.name.clone(),
            cache: token.cache.clone(),
            read: token.read,
            write: token.write,
        })
        .send()
        .await?;

    if response.status().is_success() {
        let result: GenerateTokenResponse = response.json().await?;
        info!("✓ Token generated for {}: {}", token.name, result.token);
    } else {
        error!("✗ Failed to generate token for {}: {}", token.name, response.status());
    }

    Ok(())
}
