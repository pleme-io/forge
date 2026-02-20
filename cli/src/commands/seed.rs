//! Product profile seed/unseed commands
//!
//! Seeds test profiles into staging/production environments for QA testing.
//! Profiles are defined in `{product_dir}/seed/profiles.toml`.
//!
//! All product-specific values (namespace, postgres cluster, db name, email
//! domain) are read from `deploy.yaml` — no hardcoding in this file.
//!
//! Usage:
//!   nix run .#seed -- --env=staging           # Seed profiles
//!   nix run .#seed -- --env=staging --dry-run  # Preview SQL
//!   nix run .#unseed -- --env=staging          # Remove profiles

use anyhow::{Context, Result};
use serde::Deserialize;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use tracing::info;

const SEED_EMAIL_PREFIX: &str = "test-seed-";
const PHOTOS_PER_PROFILE: u32 = 3;

/// Profile definition from TOML
#[derive(Debug, Deserialize)]
struct ProfilesFile {
    profiles: Vec<ProfileDef>,
}

#[derive(Debug, Deserialize)]
struct ProfileDef {
    username: String,
    name: String,
    age: i16,
    city: String,
    neighborhood: String,
    whatsapp: String,
    price_per_hour_cents: i32,
    interests: Vec<String>,
    visibility: String,
}

impl ProfileDef {
    fn email(&self, email_domain: &str) -> String {
        format!("{}{}{}", SEED_EMAIL_PREFIX, self.username, email_domain)
    }

    fn photo_urls(&self) -> Vec<String> {
        (1..=PHOTOS_PER_PROFILE)
            .map(|n| {
                format!(
                    "https://picsum.photos/seed/{}_{}/400/600",
                    self.username, n
                )
            })
            .collect()
    }
}

/// Environment configuration derived from product config
struct EnvConfig {
    namespace: String,
}

/// Build EnvConfig from a product config and environment name.
fn env_config_from_product(
    product: &crate::config::ProductConfig,
    env: &str,
) -> Result<EnvConfig> {
    Ok(EnvConfig {
        namespace: product.namespace_for_env(env),
    })
}

/// Execute kubectl command and return output
fn kubectl(args: &[&str]) -> Result<String> {
    let output = Command::new("kubectl")
        .args(args)
        .output()
        .context("Failed to execute kubectl")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("kubectl failed: {}", stderr);
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Execute SQL via kubectl exec into CNPG primary pod
fn exec_psql(namespace: &str, pod: &str, db_name: &str, sql: &str) -> Result<String> {
    let mut child = Command::new("kubectl")
        .args([
            "exec",
            "-i",
            "-n",
            namespace,
            pod,
            "--",
            "psql",
            "-U",
            "postgres",
            "-d",
            db_name,
            "--no-psqlrc",
            "-v",
            "ON_ERROR_STOP=1",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("Failed to spawn kubectl exec")?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(sql.as_bytes())
            .context("Failed to write SQL to psql stdin")?;
    }

    let output = child
        .wait_with_output()
        .context("Failed to wait for psql")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        anyhow::bail!("psql failed:\nstdout: {}\nstderr: {}", stdout, stderr);
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Find the primary CNPG postgres pod
fn find_primary_pod(namespace: &str, postgres_cluster: &str) -> Result<String> {
    let label = format!("cnpg.io/cluster={},role=primary", postgres_cluster);
    kubectl(&[
        "get",
        "pod",
        "-n",
        namespace,
        "-l",
        &label,
        "-o",
        "jsonpath={.items[0].metadata.name}",
    ])
    .context("Failed to find primary postgres pod")
}

/// Escape a string for PostgreSQL single-quoted literals
fn pg_escape(s: &str) -> String {
    s.replace('\'', "''")
}

/// Format a Vec<String> as a PostgreSQL ARRAY literal
fn pg_text_array(items: &[String]) -> String {
    let escaped: Vec<String> = items
        .iter()
        .map(|s| format!("'{}'", pg_escape(s)))
        .collect();
    format!("ARRAY[{}]::text[]", escaped.join(", "))
}

/// Generate seed SQL for all profiles
fn generate_seed_sql(profiles: &[ProfileDef], email_domain: &str) -> String {
    let mut sql = String::from("BEGIN;\n\n");

    for (i, profile) in profiles.iter().enumerate() {
        let email = pg_escape(&profile.email(email_domain));
        let username = pg_escape(&profile.username);
        let name = pg_escape(&profile.name);
        let city = pg_escape(&profile.city);
        let neighborhood = pg_escape(&profile.neighborhood);
        let whatsapp = pg_escape(&profile.whatsapp);
        let photos = pg_text_array(&profile.photo_urls());
        let interests = pg_text_array(&profile.interests);
        let visibility = pg_escape(&profile.visibility);

        // Build SQL for this profile using CTE to chain user + profile inserts
        sql.push_str(&format!("-- Profile {}: {}\n", i, profile.username));
        sql.push_str(&format!(
            "WITH seed_user_{i} AS (\n\
             \x20   INSERT INTO users (id, email, email_verified, user_type, status, created_at, updated_at)\n\
             \x20   VALUES (gen_random_uuid(), '{email}', true, 'provider', 'active', NOW(), NOW())\n\
             \x20   ON CONFLICT (email) DO UPDATE SET\n\
             \x20       email_verified = true,\n\
             \x20       user_type = 'provider',\n\
             \x20       status = 'active',\n\
             \x20       deleted_at = NULL,\n\
             \x20       updated_at = NOW()\n\
             \x20   RETURNING id\n\
             )\n\
             INSERT INTO provider_profiles (\n\
             \x20   id, user_id, email, email_verified, username, name, age,\n\
             \x20   city, neighborhood, whatsapp, photos, interests,\n\
             \x20   price_per_hour_cents, visibility, moderation_status,\n\
             \x20   auto_stealth_enabled, admin_stealth_locked, trust_stealth_mode,\n\
             \x20   favorite_count, reonboarding_count, created_at, updated_at\n\
             )\n\
             SELECT\n\
             \x20   gen_random_uuid(), seed_user_{i}.id, '{email}', true, '{username}', '{name}', {age},\n\
             \x20   '{city}', '{neighborhood}', '{whatsapp}', {photos}, {interests},\n\
             \x20   {price_cents}, '{visibility}', 'approved',\n\
             \x20   false, false, false, 0, 0, NOW(), NOW()\n\
             FROM seed_user_{i}\n\
             ON CONFLICT (email) DO UPDATE SET\n\
             \x20   username = EXCLUDED.username,\n\
             \x20   name = EXCLUDED.name,\n\
             \x20   age = EXCLUDED.age,\n\
             \x20   city = EXCLUDED.city,\n\
             \x20   neighborhood = EXCLUDED.neighborhood,\n\
             \x20   whatsapp = EXCLUDED.whatsapp,\n\
             \x20   photos = EXCLUDED.photos,\n\
             \x20   interests = EXCLUDED.interests,\n\
             \x20   price_per_hour_cents = EXCLUDED.price_per_hour_cents,\n\
             \x20   visibility = EXCLUDED.visibility,\n\
             \x20   moderation_status = 'approved',\n\
             \x20   deleted_at = NULL,\n\
             \x20   updated_at = NOW();\n\n",
            i = i,
            email = email,
            username = username,
            name = name,
            age = profile.age,
            city = city,
            neighborhood = neighborhood,
            whatsapp = whatsapp,
            photos = photos,
            interests = interests,
            price_cents = profile.price_per_hour_cents,
            visibility = visibility,
        ));
    }

    sql.push_str("COMMIT;\n");
    sql
}

/// Generate unseed SQL
fn generate_unseed_sql(email_domain: &str) -> String {
    format!(
        "BEGIN;\n\
         DELETE FROM provider_profiles WHERE email LIKE '{prefix}%{domain}';\n\
         DELETE FROM users WHERE email LIKE '{prefix}%{domain}';\n\
         COMMIT;\n",
        prefix = SEED_EMAIL_PREFIX,
        domain = email_domain,
    )
}

/// Load profiles from TOML file
fn load_profiles(working_dir: &Path) -> Result<Vec<ProfileDef>> {
    let toml_path = working_dir.join("seed/profiles.toml");
    let content = std::fs::read_to_string(&toml_path)
        .with_context(|| format!("Failed to read {}", toml_path.display()))?;
    let file: ProfilesFile =
        toml::from_str(&content).with_context(|| format!("Failed to parse {}", toml_path.display()))?;
    Ok(file.profiles)
}

/// Seed test profiles into the environment
pub async fn seed(working_dir: &Path, env: &str, dry_run: bool) -> Result<()> {
    let product = crate::config::load_product_config_from_dir(working_dir)?;
    let env_cfg = env_config_from_product(&product, env)?;
    let email_domain = product.seed_email_domain();
    let postgres_cluster = product.postgres_cluster();
    let db_name = product.db_name().to_string();
    let profiles = load_profiles(working_dir)?;

    println!(
        "Seeding {} test profiles into {}",
        profiles.len(),
        env_cfg.namespace
    );
    println!();

    let sql = generate_seed_sql(&profiles, &email_domain);

    if dry_run {
        println!("--- DRY RUN SQL ---");
        println!("{}", sql);
        println!("--- END DRY RUN ---");
        return Ok(());
    }

    info!("Finding primary postgres pod...");
    let pod = find_primary_pod(&env_cfg.namespace, &postgres_cluster)?;
    info!("Using pod: {}", pod);

    info!("Executing seed SQL...");
    let output = exec_psql(&env_cfg.namespace, &pod, &db_name, &sql)?;
    info!("psql output: {}", output.trim());

    println!();
    println!("Seeded {} profiles successfully!", profiles.len());
    for profile in &profiles {
        println!(
            "  {} ({}, {})",
            profile.username, profile.city, profile.neighborhood
        );
    }
    println!();
    println!("Note: Profiles will appear on the wall after the next wall refresh (~5 min).");

    Ok(())
}

/// Remove seeded test profiles from the environment
pub async fn unseed(working_dir: &Path, env: &str, dry_run: bool) -> Result<()> {
    let product = crate::config::load_product_config_from_dir(working_dir)?;
    let env_cfg = env_config_from_product(&product, env)?;
    let email_domain = product.seed_email_domain();
    let postgres_cluster = product.postgres_cluster();
    let db_name = product.db_name().to_string();

    println!(
        "Removing seeded test profiles from {}",
        env_cfg.namespace
    );
    println!();

    let sql = generate_unseed_sql(&email_domain);

    if dry_run {
        println!("--- DRY RUN SQL ---");
        println!("{}", sql);
        println!("--- END DRY RUN ---");
        return Ok(());
    }

    info!("Finding primary postgres pod...");
    let pod = find_primary_pod(&env_cfg.namespace, &postgres_cluster)?;
    info!("Using pod: {}", pod);

    info!("Executing unseed SQL...");
    let output = exec_psql(&env_cfg.namespace, &pod, &db_name, &sql)?;
    info!("psql output: {}", output.trim());

    println!();
    println!(
        "Removed all seeded test profiles (email LIKE '{}%{}').",
        SEED_EMAIL_PREFIX, email_domain
    );

    Ok(())
}
