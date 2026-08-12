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

use crate::tools::{get_tool_path, tools};

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
            .map(|n| format!("https://picsum.photos/seed/{}_{}/400/600", self.username, n))
            .collect()
    }
}

/// Environment configuration derived from product config
struct EnvConfig {
    namespace: String,
}

/// Build EnvConfig from a product config and environment name.
fn env_config_from_product(product: &crate::config::ProductConfig, env: &str) -> Result<EnvConfig> {
    Ok(EnvConfig {
        namespace: product.namespace_for_env(env),
    })
}

/// Execute SQL via kubectl exec into CNPG primary pod
///
/// The `kubectl` binary is resolved through
/// [`crate::tools::get_tool_path`] on the canonical `tools::KUBECTL`
/// name so a Nix-hermetic runner's `KUBECTL_BIN`-provided store-path
/// `kubectl` reaches this stdin-fed sync spawn. Pre-lift the site
/// spelled the bare `"kubectl"` literal at `Command::new` and
/// silently resolved to whatever `kubectl` was first on `PATH` —
/// the same class of bug the sibling `commands/rollout.rs::execute`
/// migration (c5fcf83) redeemed on the last raw `kubectl` spawn on
/// that module's surface. This site retains its sync
/// `std::process::Command` + `.spawn()` shape because the seed SQL
/// payload writes into `stdin` synchronously; the stdin-piping
/// discipline is orthogonal to the binary-resolution lift.
fn exec_psql(namespace: &str, pod: &str, db_name: &str, sql: &str) -> Result<String> {
    let kubectl = get_tool_path(tools::KUBECTL);
    let mut child = Command::new(&kubectl)
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

/// Find the primary CNPG postgres pod.
///
/// Routes through the canonical
/// [`crate::retry::run_query_capture_sync`] primitive — the
/// `(cmd, args) -> Result<String>` consolidation for the sync no-cwd
/// "spawn an external CLI, capture trimmed stdout, surface the
/// structural-record tuple on failure" shape. Pre-this-commit the
/// site delegated through a private `run_command_output` wrapper in
/// this module; that wrapper was one of three identically-shaped
/// shape-adapters (`sessions.rs::kubectl`, `local.rs::run_command_output`)
/// past THEORY §VI.1's three-is-a-law threshold, all collapsed onto
/// `run_query_capture_sync` in one commit. The structural-record
/// tuple `(cmd, args, exit_code, stderr)` THEORY §V.4 Phase 1
/// attestation telemetry pattern-matches on is preserved by
/// construction.
///
/// The `kubectl` binary name is resolved via
/// [`crate::tools::get_tool_path`] on the canonical `tools::KUBECTL`
/// name BEFORE it reaches `run_query_capture_sync`, because the
/// primitive itself takes the tool as a bare `&str` and spawns it
/// verbatim (retry.rs:13012-13018) — every consumer that wants the
/// `KUBECTL_BIN`-or-PATH lookup discipline must pre-resolve at the
/// call site. Pre-lift this site handed the primitive the bare
/// `"kubectl"` literal and thereby bypassed the env override the
/// sibling `exec_psql` (this module, migrated in the same commit)
/// and the `commands/rollout.rs::execute` (c5fcf83), migrations
/// listed on the `kubectl_command_async` doc block redeemed.
/// Harmonizing the two sibling seed-module spawn surfaces closes
/// the last raw `kubectl` name-resolution bypass on
/// `commands/seed.rs`.
fn find_primary_pod(namespace: &str, postgres_cluster: &str) -> Result<String> {
    let label = format!("cnpg.io/cluster={},role=primary", postgres_cluster);
    let kubectl = get_tool_path(tools::KUBECTL);
    crate::retry::run_query_capture_sync(
        &kubectl,
        &[
            "get",
            "pod",
            "-n",
            namespace,
            "-l",
            &label,
            "-o",
            "jsonpath={.items[0].metadata.name}",
        ],
    )
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
    let file: ProfilesFile = toml::from_str(&content)
        .with_context(|| format!("Failed to parse {}", toml_path.display()))?;
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

    println!("Removing seeded test profiles from {}", env_cfg.namespace);
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

#[cfg(test)]
mod tests {
    /// Whole-module shield: no raw `Command::new`-with-bare-`kubectl`-
    /// literal, and no bare-`kubectl`-literal-as-first-arg to
    /// [`crate::retry::run_query_capture_sync`], may live in
    /// `commands/seed.rs`'s non-test body. Every `kubectl` spawn on
    /// this module's two entry points — [`exec_psql`] (sync
    /// stdin-fed `std::process::Command` spawn) and
    /// [`find_primary_pod`] (sync capture via `run_query_capture_sync`,
    /// whose primitive body spawns the caller-supplied `&str` verbatim
    /// via `std::process::Command::new(cmd)` per retry.rs:13012-13018
    /// and therefore requires the caller to pre-resolve through
    /// [`crate::tools::get_tool_path`] on the canonical
    /// `tools::KUBECTL` name) MUST resolve the binary through
    /// `KUBECTL_BIN` (or PATH) via
    /// [`crate::tools::get_tool_path`] first.
    ///
    /// Pre-lift the two `kubectl` spawns spelled the bare `"kubectl"`
    /// string verbatim: `exec_psql` at `Command::new`, `find_primary_pod`
    /// at `run_query_capture_sync`'s first argument. Both silently
    /// bypassed the substrate-exported `KUBECTL_BIN` env override the
    /// tools-registry idiom (`crate::tools::get_tool_path(tools::KUBECTL)`,
    /// cli/src/tools.rs:102-105) resolves — the same class of bug
    /// the sibling `commands/migrations.rs` (946e573),
    /// `commands/federation_tests.rs` (9a409e8),
    /// `commands/rollout.rs::execute` (c5fcf83),
    /// `commands/status.rs` (c2760df), `commands/flux.rs` (f8da719),
    /// `commands/supergraph_verification.rs` (65283fb),
    /// `commands/product_release.rs::run_health_check` (5bb7cff),
    /// `commands/github_runner_ci.rs::execute` (5566415),
    /// `services/migration_service.rs::MigrationService` (5986a10)
    /// migrations redeemed. A Nix-hermetic runner whose `KUBECTL_BIN`
    /// points at a specific store-path `kubectl` (substrate's
    /// `mkRuntimeToolsEnv`) would lose to whatever `kubectl` is first
    /// on `PATH` at every pre-lift site — the exact failure mode
    /// `forge seed` / `forge unseed` on a staging cluster would hit
    /// on a runner where two `kubectl` versions coexist.
    ///
    /// This test reads this module's own source via [`include_str!`]
    /// and asserts neither forbidden shape appears in the non-test
    /// body while the canonical `get_tool_path(tools::KUBECTL)`
    /// delegation does. Forbidden shapes are reconstructed via
    /// [`format!`] so this shield's own docstring and body do not
    /// false-match themselves. The scan is bounded strictly to the
    /// module's non-test body — from the file start to the
    /// `#[cfg(test)]` marker — so this shield's own text stays out of
    /// scope AND every current or future kubectl-spawning helper
    /// landing anywhere in the top-level module body (across the two
    /// migrated entry points or any as-yet unadded sibling) is
    /// covered by the same shield without a per-function narrowing.
    /// Mirrors the whole-module boundary discipline the sibling
    /// `commands/rollout.rs` shield (c5fcf83),
    /// `commands/federation_tests.rs` shield (9a409e8),
    /// `commands/status.rs` shield (c2760df), and
    /// `commands/supergraph_verification.rs` shield (65283fb) hold.
    ///
    /// The end-to-end `KUBECTL_BIN`-routing invariant of the
    /// underlying primitives is pinned separately by
    /// [`crate::infrastructure::kubectl::tests::test_kubectl_command_async_routes_through_kubectl_bin_env_var`]
    /// on the async surface and by
    /// [`crate::tools::tests::test_get_tool_path_from_env`] on the
    /// sync resolver; this shield only certifies that every
    /// `kubectl`-spawning site in this module resolves through the
    /// canonical resolver first.
    #[test]
    fn test_kubectl_spawns_resolve_through_tools_kubectl_not_bare_literal() {
        const SOURCE: &str = include_str!("seed.rs");
        let tests_marker = "\n#[cfg(test)]\nmod tests {";
        let body_end = SOURCE.find(tests_marker).expect(
            "the `#[cfg(test)]\\nmod tests {` marker must follow \
             the module body — the shield's slice boundary relies \
             on this module ordering",
        );
        let module_body = &SOURCE[..body_end];

        let bare = "kubectl";
        let raw_command = format!("Command::new(\"{}\")", bare);
        let bypass_primitive = format!("run_query_capture_sync(\n        \"{}\"", bare);

        assert!(
            !module_body.contains(&raw_command),
            "commands/seed.rs must NOT spawn `kubectl` via the bare \
             literal at `Command::new` — every `kubectl` spawn must \
             resolve the substrate-exported `KUBECTL_BIN` env \
             override via `get_tool_path(tools::KUBECTL)` first. \
             A raw literal at `Command::new` bypasses the hermetic-\
             runner contract substrate's `mkRuntimeToolsEnv` exports."
        );
        assert!(
            !module_body.contains(&bypass_primitive),
            "commands/seed.rs must NOT hand the bare `\"kubectl\"` \
             literal to `run_query_capture_sync` as its first arg — \
             the primitive spawns the caller-supplied `&str` verbatim \
             via `std::process::Command::new(cmd)`, so every consumer \
             must pre-resolve through `get_tool_path(tools::KUBECTL)` \
             first. A bare literal at the primitive call site bypasses \
             the `KUBECTL_BIN` env override every sibling site honors."
        );
        assert!(
            module_body.contains("get_tool_path(tools::KUBECTL)"),
            "commands/seed.rs must resolve the `kubectl` binary via \
             the canonical `get_tool_path(tools::KUBECTL)` lookup — \
             the required form was not found in the module body."
        );
    }
}
