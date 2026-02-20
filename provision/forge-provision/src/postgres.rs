//! PostgreSQL database provisioning with CDC support
//!
//! This module provides idempotent, production-ready PostgreSQL database provisioning
//! with comprehensive security, Change Data Capture (CDC) setup, and schema management.

use anyhow::{Context, Result};
use sqlx::postgres::PgPoolOptions;
use sqlx::Row;
use std::env;
use std::time::Duration;
use tracing::{info, warn};

use crate::config::PostgresConfig;
use crate::validation::{
    quote_identifier, validate_password, validate_pg_extension_name, validate_pg_identifier,
};

// Connection configuration now driven by YAML config (see ConnectionConfig)

/// Main provisioning function driven by PostgresConfig
///
/// Entry point for PostgreSQL provisioning. Orchestrates all steps:
/// 1. Connect to PostgreSQL as admin
/// 2. Create database
/// 3. Create application user
/// 4. Grant ownership
/// 5. Enable extensions
/// 6. Configure schema permissions
/// 7. Setup CDC (if enabled)
///
/// All operations are idempotent and safe to run multiple times.
pub async fn provision_from_config(config: PostgresConfig) -> Result<()> {
    info!("=== PostgreSQL Database Provisioning (Idempotent) ===");
    info!("Target database: {}", config.database.name);
    info!("Target user: {}", config.user.name);
    info!("Host: {}:{}", config.connection.host, config.connection.port);

    // Validate configuration
    info!("Validating configuration...");
    validate_config(&config).context("Configuration validation failed")?;

    // Read passwords from environment variables
    let app_password = env::var(&config.user.password_env).with_context(|| {
        format!(
            "Failed to read password from env var: {}",
            config.user.password_env
        )
    })?;

    validate_password(&app_password, "application password")?;

    // 1. Connect to PostgreSQL as admin
    info!("1. Connecting to PostgreSQL...");
    let admin_pool = create_admin_connection_pool(&config.connection).await?;

    // 2. Create database if it doesn't exist
    info!("2. Creating database if it doesn't exist...");
    ensure_database_exists(&admin_pool, &config.database.name).await?;

    // 3. Create application user if it doesn't exist
    info!("3. Creating application user if it doesn't exist...");
    ensure_user_exists(&admin_pool, &config.user.name, &app_password).await?;

    // 4. Grant database ownership
    info!("4. Granting database ownership...");
    grant_database_ownership(&admin_pool, &config.database.name, &config.user.name).await?;

    // Connect to the target database for schema operations
    let db_url = format!(
        "postgresql://{}@{}:{}/{}",
        config.connection.admin_user,
        config.connection.host,
        config.connection.port,
        config.database.name
    );
    let db_pool = PgPoolOptions::new()
        .max_connections(config.connection.max_connections)
        .acquire_timeout(Duration::from_secs(config.connection.connection_timeout_secs))
        .connect(&db_url)
        .await
        .with_context(|| format!("Failed to connect to database: {}", config.database.name))?;

    // 5. Enable extensions
    info!("5. Enabling extensions...");
    enable_database_extensions(&db_pool, &config.extensions).await?;

    // 6. Grant schema permissions
    info!("6. Setting up schema permissions...");
    grant_schema_permissions(&db_pool, &config.user.name, &config.database.schema).await?;

    // 7. CDC setup (if enabled)
    if let Some(cdc_config) = &config.cdc {
        info!("7. Setting up replication user for CDC...");

        let cdc_password = env::var(&cdc_config.password_env).with_context(|| {
            format!(
                "Failed to read CDC password from env var: {}",
                cdc_config.password_env
            )
        })?;

        validate_password(&cdc_password, "CDC password")?;

        ensure_cdc_replication_user(
            &admin_pool,
            &db_pool,
            &cdc_config.user,
            &cdc_password,
            &config.database.schema,
        )
        .await?;

        // 8. Create publication for CDC
        info!("8. Creating publication for CDC...");
        ensure_cdc_publication(&db_pool, &cdc_config.publication).await?;
    } else {
        info!("7. CDC setup skipped (not enabled)");
    }

    info!("");
    info!("=== PostgreSQL Provisioning Complete ===");
    info!(
        "✓ Database '{}' is ready for application use",
        config.database.name
    );
    info!(
        "✓ User '{}' has full permissions on schema '{}'",
        config.user.name, config.database.schema
    );
    if config.cdc.is_some() {
        info!("✓ CDC replication configured and ready");
    }

    Ok(())
}

/// Validate PostgresConfig before provisioning
fn validate_config(config: &PostgresConfig) -> Result<()> {
    // Validate connection config
    config
        .connection
        .validate()
        .context("Connection configuration validation failed")?;

    // Validate identifiers
    validate_pg_identifier(&config.connection.admin_user, "admin_user")
        .context("Invalid admin_user identifier")?;
    validate_pg_identifier(&config.database.name, "database_name")
        .context("Invalid database_name identifier")?;
    validate_pg_identifier(&config.database.schema, "schema")
        .context("Invalid schema identifier")?;
    validate_pg_identifier(&config.user.name, "user_name")
        .context("Invalid user_name identifier")?;

    // Validate extensions
    if config.extensions.is_empty() {
        warn!("No PostgreSQL extensions configured (this is valid but uncommon)");
    }

    for (i, ext) in config.extensions.iter().enumerate() {
        validate_pg_extension_name(ext, &format!("extension[{}]", i))
            .with_context(|| format!("Invalid extension name at index {}: {}", i, ext))?;
    }

    // Validate CDC config if present
    if let Some(cdc) = &config.cdc {
        validate_pg_identifier(&cdc.user, "cdc_user")
            .context("Invalid cdc_user identifier")?;
        validate_pg_identifier(&cdc.publication, "cdc_publication")
            .context("Invalid cdc_publication identifier")?;
    }

    Ok(())
}

/// Wait for PostgreSQL to be ready and create admin connection pool
///
/// Retries connection based on retry_interval_secs and max_retry_attempts.
/// If max_retry_attempts is 0, retries indefinitely until connection succeeds.
async fn create_admin_connection_pool(
    conn_config: &crate::config::ConnectionConfig,
) -> Result<sqlx::PgPool> {
    let admin_url = format!(
        "postgresql://{}@{}:{}/{}",
        conn_config.admin_user, conn_config.host, conn_config.port, conn_config.admin_database
    );
    info!(
        "Connecting to PostgreSQL as admin user '{}' at {}:{}",
        conn_config.admin_user, conn_config.host, conn_config.port
    );

    let mut attempt = 0;

    loop {
        match PgPoolOptions::new()
            .max_connections(conn_config.max_connections)
            .acquire_timeout(Duration::from_secs(conn_config.connection_timeout_secs))
            .connect(&admin_url)
            .await
        {
            Ok(pool) => {
                info!("✓ PostgreSQL is ready");
                return Ok(pool);
            }
            Err(e) => {
                attempt += 1;

                if conn_config.max_retry_attempts > 0 && attempt >= conn_config.max_retry_attempts
                {
                    anyhow::bail!(
                        "PostgreSQL connection failed after {} attempts: {}",
                        attempt,
                        e
                    );
                }

                warn!(
                    "PostgreSQL is unavailable (attempt {}/{}): {} - retrying in {}s",
                    attempt,
                    if conn_config.max_retry_attempts == 0 {
                        "∞".to_string()
                    } else {
                        conn_config.max_retry_attempts.to_string()
                    },
                    e,
                    conn_config.retry_interval_secs
                );
                tokio::time::sleep(Duration::from_secs(conn_config.retry_interval_secs)).await;
            }
        }
    }
}

/// Idempotently create database
async fn ensure_database_exists(pool: &sqlx::PgPool, database_name: &str) -> Result<()> {
    let db_exists: bool = sqlx::query("SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = $1)")
        .bind(database_name)
        .fetch_one(pool)
        .await?
        .get(0);

    if !db_exists {
        let create_db_sql = format!("CREATE DATABASE {}", quote_identifier(database_name));
        sqlx::query(&create_db_sql).execute(pool).await?;
        info!("✓ Database '{}' created", database_name);
    } else {
        info!("✓ Database '{}' already exists", database_name);
    }

    Ok(())
}

/// Idempotently create user with password (secure - passwords never logged)
///
/// Uses PostgreSQL's format() function with %I (identifier) and %L (literal)
/// for secure parameter interpolation, preventing SQL injection.
async fn ensure_user_exists(pool: &sqlx::PgPool, username: &str, password: &str) -> Result<()> {
    let user_exists: bool = sqlx::query("SELECT EXISTS(SELECT 1 FROM pg_user WHERE usename = $1)")
        .bind(username)
        .fetch_one(pool)
        .await?
        .get(0);

    if !user_exists {
        // Use format() SQL function with %I for identifier, %L for literal (secure)
        let create_user_sql = "SELECT format('CREATE USER %I WITH PASSWORD %L', $1, $2)";
        let sql: String = sqlx::query_scalar(create_user_sql)
            .bind(username)
            .bind(password)
            .fetch_one(pool)
            .await?;

        sqlx::query(&sql).execute(pool).await?;
        info!("✓ User '{}' created", username);
    } else {
        // Update password securely
        let alter_user_sql = "SELECT format('ALTER USER %I WITH PASSWORD %L', $1, $2)";
        let sql: String = sqlx::query_scalar(alter_user_sql)
            .bind(username)
            .bind(password)
            .fetch_one(pool)
            .await?;

        sqlx::query(&sql).execute(pool).await?;
        info!("✓ User '{}' already exists, password updated", username);
    }

    Ok(())
}

/// Grant database ownership to user
async fn grant_database_ownership(
    pool: &sqlx::PgPool,
    database_name: &str,
    username: &str,
) -> Result<()> {
    let grant_db_sql = format!(
        "GRANT ALL PRIVILEGES ON DATABASE {} TO {}",
        quote_identifier(database_name),
        quote_identifier(username)
    );
    sqlx::query(&grant_db_sql).execute(pool).await?;

    let alter_owner_sql = format!(
        "ALTER DATABASE {} OWNER TO {}",
        quote_identifier(database_name),
        quote_identifier(username)
    );
    sqlx::query(&alter_owner_sql).execute(pool).await?;
    info!("✓ Ownership granted to '{}'", username);

    Ok(())
}

/// Enable PostgreSQL extensions
async fn enable_database_extensions(
    db_pool: &sqlx::PgPool,
    extensions: &[String],
) -> Result<()> {
    for ext in extensions.iter().filter(|s| !s.is_empty()) {
        let ext_sql = format!(
            "CREATE EXTENSION IF NOT EXISTS {}",
            quote_identifier(ext)
        );
        sqlx::query(&ext_sql).execute(db_pool).await?;
        info!("✓ Extension '{}' enabled", ext);
    }

    Ok(())
}

/// Grant comprehensive schema permissions to user
///
/// Grants all necessary permissions on schema and all objects within it:
/// - Schema-level: USAGE, CREATE, ALL PRIVILEGES
/// - Existing objects: Tables, sequences, functions, routines
/// - Future objects: DEFAULT PRIVILEGES for new objects
async fn grant_schema_permissions(
    db_pool: &sqlx::PgPool,
    username: &str,
    schema: &str,
) -> Result<()> {
    let user_id = quote_identifier(username);
    let schema_id = quote_identifier(schema);

    // Grant schema-level permissions
    sqlx::query(&format!(
        "GRANT ALL PRIVILEGES ON SCHEMA {} TO {}",
        schema_id, user_id
    ))
    .execute(db_pool)
    .await?;

    sqlx::query(&format!("GRANT USAGE ON SCHEMA {} TO {}", schema_id, user_id))
        .execute(db_pool)
        .await?;

    sqlx::query(&format!(
        "GRANT CREATE ON SCHEMA {} TO {}",
        schema_id, user_id
    ))
    .execute(db_pool)
    .await?;

    // Grant permissions on existing objects
    sqlx::query(&format!(
        "GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA {} TO {}",
        schema_id, user_id
    ))
    .execute(db_pool)
    .await?;

    sqlx::query(&format!(
        "GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA {} TO {}",
        schema_id, user_id
    ))
    .execute(db_pool)
    .await?;

    sqlx::query(&format!(
        "GRANT ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA {} TO {}",
        schema_id, user_id
    ))
    .execute(db_pool)
    .await?;

    sqlx::query(&format!(
        "GRANT ALL PRIVILEGES ON ALL ROUTINES IN SCHEMA {} TO {}",
        schema_id, user_id
    ))
    .execute(db_pool)
    .await?;

    // Grant permissions on future objects
    sqlx::query(&format!(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA {} GRANT ALL ON TABLES TO {}",
        schema_id, user_id
    ))
    .execute(db_pool)
    .await?;

    sqlx::query(&format!(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA {} GRANT ALL ON SEQUENCES TO {}",
        schema_id, user_id
    ))
    .execute(db_pool)
    .await?;

    sqlx::query(&format!(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA {} GRANT ALL ON FUNCTIONS TO {}",
        schema_id, user_id
    ))
    .execute(db_pool)
    .await?;

    sqlx::query(&format!(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA {} GRANT ALL ON ROUTINES TO {}",
        schema_id, user_id
    ))
    .execute(db_pool)
    .await?;

    info!(
        "✓ Schema '{}' permissions configured for '{}'",
        schema, username
    );

    Ok(())
}

/// Idempotently setup CDC replication user with permissions
///
/// Creates a PostgreSQL replication user with necessary privileges for
/// Change Data Capture (CDC) via logical replication.
///
/// Grants:
/// - REPLICATION privilege (for logical replication)
/// - USAGE on schema
/// - SELECT on all existing and future tables
/// - SELECT on all existing and future sequences
async fn ensure_cdc_replication_user(
    admin_pool: &sqlx::PgPool,
    db_pool: &sqlx::PgPool,
    cdc_user: &str,
    cdc_password: &str,
    schema: &str,
) -> Result<()> {
    let cdc_user_exists: bool = sqlx::query("SELECT EXISTS(SELECT 1 FROM pg_user WHERE usename = $1)")
        .bind(cdc_user)
        .fetch_one(admin_pool)
        .await?
        .get(0);

    if !cdc_user_exists {
        // Use format() SQL function for secure CREATE USER with REPLICATION
        let create_repl_sql =
            "SELECT format('CREATE USER %I WITH REPLICATION PASSWORD %L', $1, $2)";
        let sql: String = sqlx::query_scalar(create_repl_sql)
            .bind(cdc_user)
            .bind(cdc_password)
            .fetch_one(admin_pool)
            .await?;

        sqlx::query(&sql).execute(admin_pool).await?;
        info!(
            "✓ Replication user '{}' created with REPLICATION privilege",
            cdc_user
        );
    } else {
        // Update password and ensure REPLICATION privilege
        let alter_repl_sql =
            "SELECT format('ALTER USER %I WITH REPLICATION PASSWORD %L', $1, $2)";
        let sql: String = sqlx::query_scalar(alter_repl_sql)
            .bind(cdc_user)
            .bind(cdc_password)
            .fetch_one(admin_pool)
            .await?;

        sqlx::query(&sql).execute(admin_pool).await?;
        info!("✓ Replication user exists, password and privileges updated");
    }

    let user_id = quote_identifier(cdc_user);
    let schema_id = quote_identifier(schema);

    // Grant schema-level permissions for CDC
    sqlx::query(&format!("GRANT USAGE ON SCHEMA {} TO {}", schema_id, user_id))
        .execute(db_pool)
        .await?;

    // Grant SELECT on all existing and future tables (required for logical replication)
    sqlx::query(&format!(
        "GRANT SELECT ON ALL TABLES IN SCHEMA {} TO {}",
        schema_id, user_id
    ))
    .execute(db_pool)
    .await?;

    sqlx::query(&format!(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA {} GRANT SELECT ON TABLES TO {}",
        schema_id, user_id
    ))
    .execute(db_pool)
    .await?;

    // Grant SELECT on sequences (needed for CDC to capture sequence state)
    sqlx::query(&format!(
        "GRANT SELECT ON ALL SEQUENCES IN SCHEMA {} TO {}",
        schema_id, user_id
    ))
    .execute(db_pool)
    .await?;

    sqlx::query(&format!(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA {} GRANT SELECT ON SEQUENCES TO {}",
        schema_id, user_id
    ))
    .execute(db_pool)
    .await?;

    info!("✓ CDC replication user configured with DML capture permissions");

    Ok(())
}

/// Idempotently create publication for CDC (DML replication)
///
/// Creates a logical replication publication for all tables.
/// PostgreSQL logical replication captures DML (INSERT/UPDATE/DELETE) automatically.
///
/// **Note**: DDL changes (CREATE TABLE, ALTER, etc.) require application-level
/// tracking or extensions like pg_ddl_deploy.
async fn ensure_cdc_publication(db_pool: &sqlx::PgPool, publication_name: &str) -> Result<()> {
    let pub_exists: bool =
        sqlx::query("SELECT EXISTS(SELECT 1 FROM pg_publication WHERE pubname = $1)")
            .bind(publication_name)
            .fetch_one(db_pool)
            .await?
            .get(0);

    if !pub_exists {
        let create_pub_sql = format!(
            "CREATE PUBLICATION {} FOR ALL TABLES",
            quote_identifier(publication_name)
        );
        sqlx::query(&create_pub_sql).execute(db_pool).await?;
        info!(
            "✓ Publication '{}' created for DML replication (INSERT/UPDATE/DELETE)",
            publication_name
        );
    } else {
        info!("✓ Publication '{}' already exists", publication_name);
    }

    info!("   NOTE: PostgreSQL logical replication captures DML automatically");
    info!("   DDL changes (CREATE TABLE, ALTER, etc.) require application-level tracking");

    Ok(())
}
