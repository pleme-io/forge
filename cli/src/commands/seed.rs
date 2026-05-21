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

/// Execute an external CLI and return its trimmed stdout.
///
/// Sync sibling of `commands/attestation.rs::run_command_output`
/// (commit edbc2e6). Both functions carry the same "spawn a CLI,
/// return its trimmed stdout, anyhow-bail on every failure shape"
/// body; the async one drives `tokio::process::Command` against
/// `git` to produce attestation source records, this sync one
/// drives `std::process::Command` against `kubectl` to discover
/// the CNPG primary pod. Pre-this-commit the sync sibling fused
/// the structural-record tuple `(exit_code, stderr)` into a
/// `bail!("kubectl failed: {}", stderr)` string that dropped the
/// exit code entirely; the async sibling already routed through
/// `classify_capture_query` (edbc2e6) with the canonical mapper-
/// pair shape every typed-error producer site in forge encodes.
/// This commit closes the carve-out on the sync surface: both
/// siblings now flow through the same
/// [`crate::retry::classify_capture_query`] primitive, with the
/// `io::Result<std::process::Output>` post-spawn shape acting as
/// the sync/async-agnostic join — `std::process::Command::output()`
/// and `tokio::process::Command::output().await` produce
/// identically-typed results, so the classifier and the mapper
/// closures are shared by construction (THEORY §VI.1 three-times-
/// rule consolidation across the sync/async spawn surfaces).
fn run_command_output(cmd: &str, args: &[&str]) -> Result<String> {
    let captured = Command::new(cmd).args(args).output();

    // Owned copies for the typed mapper closures — `classify_capture_query`
    // takes `FnOnce` on each arm so each closure consumes its captures by
    // move. Two clones (one per arm) keep both mappers structurally
    // independent — same shape every sibling `from_capture`-flavored
    // consumer in `cli/src/retry.rs`, `cli/src/error.rs`, and
    // `commands/attestation.rs::run_command_output` already encodes.
    let spawn_cmd = cmd.to_string();
    let spawn_args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    let op_cmd = spawn_cmd.clone();
    let op_args = spawn_args.clone();

    crate::retry::classify_capture_query(
        captured,
        move |e| anyhow::anyhow!("Failed to spawn {} {:?}: {}", spawn_cmd, spawn_args, e),
        move |cf| {
            anyhow::anyhow!(
                "{} {:?} failed (exit {:?}): {}",
                op_cmd,
                op_args,
                cf.exit_code,
                cf.stderr
            )
        },
    )
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
    run_command_output(
        "kubectl",
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
    use super::*;
    use crate::test_support::make_executable_shim;

    /// `run_command_output` on a successful spawn returns the trimmed
    /// stdout — pins the success-path floor `find_primary_pod` relies
    /// on. The pre-migration body re-derived the
    /// `String::from_utf8_lossy(...).trim().to_string()` incantation
    /// inline; the new `classify_capture_query`-routed shape keeps the
    /// trim discipline at the canonical primitive so a future
    /// regression that dropped the trim would fail this test before
    /// any downstream `find_primary_pod` caller saw a stray-newline-
    /// bearing pod name flow into `exec_psql`'s `kubectl exec -n NS
    /// POD` invocation (where a trailing `\n` on the pod name
    /// surfaces as a confusing "pod not found" diagnostic).
    #[test]
    fn test_run_command_output_success_returns_trimmed_stdout() {
        let (_dir, shim) =
            make_executable_shim("echo-shim", "#!/bin/sh\necho '  primary-pod-0  '\n");
        let out = run_command_output(&shim, &[]).expect("shim must succeed");
        assert_eq!(
            out, "primary-pod-0",
            "trim must strip both leading/trailing ws"
        );
    }

    /// `run_command_output` on a non-zero exit surfaces the structural-
    /// record tuple in the error message: the operation label (`cmd` +
    /// `args` debug rendering), the exit code, and the trimmed stderr.
    /// Pre-migration the bail string was `kubectl failed: {stderr}` —
    /// it dropped the exit code AND the args entirely, so a future
    /// telemetry consumer that wanted to recover the offending
    /// `(cmd, args, exit_code, stderr)` tuple from a failed
    /// `find_primary_pod` step (the shape THEORY §V.4 Phase 1
    /// attestation records pattern-match on) had to scrape it back
    /// out of the host's process accounting. A future regression that
    /// re-dropped the exit code would fail this test rather than
    /// silently degrade the Phase 1 record shape.
    #[test]
    fn test_run_command_output_op_failure_carries_structural_tuple() {
        let (_dir, shim) = make_executable_shim(
            "fail-shim",
            "#!/bin/sh\necho 'no matching pod' 1>&2\nexit 11\n",
        );
        let err = run_command_output(&shim, &["get", "pod"]).expect_err("nonzero exit must fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("(exit Some(11))"),
            "msg must carry exit code, got: {msg}"
        );
        assert!(
            msg.contains("no matching pod"),
            "msg must carry trimmed stderr, got: {msg}"
        );
        assert!(
            msg.contains("\"get\"") && msg.contains("\"pod\""),
            "msg must carry args debug rendering, got: {msg}"
        );
    }

    /// `run_command_output` on a spawn failure (binary not on PATH /
    /// nonexistent absolute path) surfaces the canonical
    /// `Failed to spawn {cmd} {args:?}: {io_error}` envelope. Pins the
    /// spawn-vs-op discriminator the canonical primitive guarantees at
    /// the typed-error producer surface — pre-migration the `with_context`
    /// envelope fused the spawn arm into `"Failed to execute kubectl"`
    /// that dropped the offending args entirely, so a future test that
    /// wanted to recover the requested-but-unfound CLI binary's invocation
    /// shape had to re-derive it from the `io::Error::Display`. A future
    /// regression that re-fused the spawn arm into the op arm would
    /// fail this test rather than silently collapse the
    /// `classify_capture` (b75a273) spawn-vs-op invariant.
    #[test]
    fn test_run_command_output_spawn_failure_carries_op_label() {
        let missing = "/nonexistent/forge-test-shim-must-not-exist";
        let err = run_command_output(missing, &["arg-a"])
            .expect_err("spawn against nonexistent path must fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("Failed to spawn"),
            "msg must carry spawn-arm envelope, got: {msg}"
        );
        assert!(
            msg.contains(missing),
            "msg must carry the offending cmd path, got: {msg}"
        );
    }
}
