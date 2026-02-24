use anyhow::Result;
use clap::Parser;

// Core modules
mod cli;
mod commands;
mod config;

// Legacy modules (to be migrated)
mod cloudflare;
mod git;
mod k8s;
mod nix;
mod nix_hooks;
mod observability;
mod path_builder;
mod repo;
mod tools;

// New architecture modules
mod domain;
mod error;
mod infrastructure;
mod services;
mod ui;

use cli::{BootstrapCommands, Cli, Commands, GemCommands, HelmCommands, PangeaCommands};
use commands::{
    bootstrap, build, comprehensive_release, deploy, federation, github_runner_ci,
    integration_tests, kenshi, kenshi_agent, migrations, nix_builder, pangea, push, rollout,
    rust_service, service_config, status, test, web_build_verify, workspace_deps,
};

/// Setup environment for root flake pattern
///
/// Root flake pattern (ONLY supported pattern):
/// - repo_root: Repository root directory (contains root flake.nix)
/// - service_dir: Service directory for computing paths and loading deploy.yaml
/// - Working directory: Change to repo_root to run `nix build`
///
/// Both parameters are REQUIRED for proper operation.
fn setup_service_directory(service_dir: Option<String>, repo_root: Option<String>) -> Result<()> {
    match (repo_root, service_dir) {
        // Root flake pattern: Change to repo root, set SERVICE_DIR for path computation
        (Some(root), Some(dir)) => {
            std::env::set_var("REPO_ROOT", &root);
            std::env::set_var("SERVICE_DIR", &dir);
            std::env::set_current_dir(&root)?;
            Ok(())
        }
        // Missing required parameters
        _ => {
            anyhow::bail!(
                "Root flake pattern requires both --repo-root and --service-dir parameters.\n  \
                 This tool only supports the root flake pattern (single flake.nix at repo root).\n  \
                 Service-level flakes are no longer supported."
            )
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging with LOGGING env var support
    // LOGGING=debug,info,warn,error or just LOGGING=debug
    let log_level = std::env::var("LOGGING")
        .or_else(|_| std::env::var("LOG_LEVEL"))
        .unwrap_or_else(|_| {
            if cli.verbose {
                "debug".to_string()
            } else {
                "info".to_string()
            }
        });

    tracing_subscriber::fmt()
        .with_env_filter(log_level)
        .with_target(false)
        .with_thread_ids(false)
        .with_file(false)
        .with_line_number(false)
        .with_ansi(false) // Disable ANSI escape codes for cleaner output
        .init();

    // Execute command
    match cli.command {
        Commands::Build {
            flake_attr,
            working_dir,
            arch,
            cache_url,
            cache_name,
            push_cache,
            output,
        } => {
            build::execute(
                flake_attr,
                working_dir,
                arch,
                cache_url,
                cache_name,
                push_cache,
                output,
            )
            .await?;
        }
        Commands::Push {
            image_path,
            registry,
            tags,
            auto_tags,
            arch,
            retries,
            token,
            push_attic,
            attic_cache,
            update_kustomization,
            commit_kustomization,
        } => {
            push::execute(
                image_path,
                registry,
                tags,
                auto_tags,
                arch,
                retries,
                token,
                push_attic,
                attic_cache,
                update_kustomization,
                commit_kustomization,
            )
            .await?;
        }
        Commands::Deploy {
            manifest,
            registry,
            tag,
            namespace,
            name,
            watch,
            timeout,
            skip_build,
            cache_url,
            cache_name,
        } => {
            deploy::execute(
                manifest, registry, tag, namespace, name, watch, timeout, skip_build, cache_url,
                cache_name,
            )
            .await?;
        }
        Commands::Rollout {
            namespace,
            name,
            interval,
            timeout,
            rollback,
        } => {
            // Check SAFE mode from environment (default: true)
            let safe_mode = std::env::var("SAFE")
                .map(|v| {
                    let val = v.to_lowercase();
                    val != "false" && val != "0"
                })
                .unwrap_or(true);

            rollout::execute(namespace, name, interval, timeout, rollback, safe_mode).await?;
        }
        Commands::ComprehensiveRelease {
            service_name,
            product_name,
            namespace,
            flake_attr,
            working_dir,
            compose_file,
            registry,
            manifest,
            migrations_path,
            cache_url,
            cache_name,
            db_port,
            db_user,
            db_password,
            db_name,
            skip_unit_tests,
            skip_integration_tests,
            skip_build,
            skip_push,
            skip_deploy,
            watch,
        } => {
            // Default db_user and db_name based on service_name if not provided
            let db_user = db_user.unwrap_or_else(|| format!("{}_test", service_name));
            let db_name = db_name.unwrap_or_else(|| format!("{}_test", service_name));

            comprehensive_release::execute(
                service_name,
                product_name,
                namespace,
                flake_attr,
                working_dir,
                compose_file,
                registry,
                manifest,
                migrations_path,
                cache_url,
                cache_name,
                db_port,
                db_user,
                db_password,
                db_name,
                skip_unit_tests,
                skip_integration_tests,
                skip_build,
                skip_push,
                skip_deploy,
                watch,
            )
            .await?;
        }
        Commands::GithubRunnerCi {
            working_dir,
            cache_url,
            cache_name,
            registry,
            manifest,
            namespace,
            name,
            skip_build,
            skip_push,
            watch,
        } => {
            github_runner_ci::execute(
                working_dir,
                cache_url,
                cache_name,
                registry,
                manifest,
                namespace,
                name,
                skip_build,
                skip_push,
                watch,
            )
            .await?;
        }
        Commands::PushRustService {
            image_path,
            service,
            product: _,
            service_dir,
            repo_root,
            registry,
            cache_name,
            attic_token,
            github_token,
        } => {
            setup_service_directory(service_dir, repo_root)?;
            rust_service::push_rust_service(
                image_path,
                service,
                registry,
                cache_name,
                attic_token,
                github_token,
            )
            .await?;
        }
        Commands::DeployRustService {
            service,
            product: _,
            service_dir,
            repo_root,
            manifest,
            registry,
            namespace,
            watch,
        } => {
            setup_service_directory(service_dir, repo_root)?;
            rust_service::deploy_rust_service(service, manifest, registry, namespace, watch)
                .await?;
        }
        Commands::OrchestrateRelease {
            service,
            service_dir,
            repo_root,
            registry,
            environment,
            single_environment,
            namespace,
            image_path,
            image_path_arm64,
            watch,
            push_only,
            deploy_only,
            image_tag,
        } => {
            setup_service_directory(Some(service_dir), Some(repo_root))?;
            rust_service::orchestrate_release(
                service,
                registry,
                environment,
                single_environment,
                namespace,
                image_path,
                image_path_arm64,
                watch,
                push_only,
                deploy_only,
                image_tag,
            )
            .await?;
        }
        Commands::Rollback {
            product,
            repo_root,
            env,
            skip_health_check,
            force,
        } => {
            let product = match product {
                Some(p) => p,
                None => config::auto_discover_product(&repo_root)?,
            };
            commands::rollback::execute(product, repo_root, env, skip_health_check, force).await?;
        }
        Commands::ProductRelease {
            product,
            repo_root,
            env,
            skip_gates,
            skip_dashboards,
            build_only,
        } => {
            let product = match product {
                Some(p) => p,
                None => config::auto_discover_product(&repo_root)?,
            };
            commands::product_release::product_release(
                product,
                repo_root,
                env,
                skip_gates,
                skip_dashboards,
                build_only,
            )
            .await?;
        }
        Commands::RustTest { service } => {
            commands::developer_tools::rust_test(service).await?;
        }
        Commands::RustLint { service } => {
            commands::developer_tools::rust_lint(service).await?;
        }
        Commands::RustFmt { service } => {
            commands::developer_tools::rust_fmt(service).await?;
        }
        Commands::RustFmtCheck { service } => {
            commands::developer_tools::rust_fmt_check(service).await?;
        }
        Commands::RustExtractSchema { service } => {
            commands::developer_tools::rust_extract_schema(service).await?;
        }
        Commands::RustUpdateCargoNix { service } => {
            commands::developer_tools::rust_update_cargo_nix(service).await?;
        }
        Commands::RustServiceHelp { service } => {
            commands::developer_tools::rust_service_help(service).await?;
        }
        Commands::FluxReconcile { namespace } => {
            commands::flux::reconcile(namespace).await?;
        }
        Commands::RunMigrations {
            service,
            namespace,
            git_sha,
        } => {
            let deploy_config = config::DeployConfig::load_for_service(&service)?;
            let config = service_config::ServiceConfig::from_config(service, &deploy_config);
            migrations::run_migrations(&config, namespace, git_sha, &deploy_config).await?;
        }
        Commands::UpdateFederation {
            service,
            namespace,
            product: _product,
        } => {
            let deploy_config = config::DeployConfig::load_for_service(&service)?;
            federation::update_federation(service, namespace, &deploy_config).await?;
        }
        Commands::WebBuildVerify {
            dist_dir,
            template_path,
        } => {
            use std::path::PathBuf;
            web_build_verify::execute(PathBuf::from(dist_dir), PathBuf::from(template_path))
                .await?;
        }
        Commands::NixBuilderVerify {
            hostname,
            port,
            k8s_service,
            namespace,
        } => {
            nix_builder::verify(hostname, port, k8s_service, namespace).await?;
        }
        Commands::NixBuilderTest {
            package,
            hostname,
            port,
            ssh_key,
        } => {
            nix_builder::test(hostname, port, ssh_key, package).await?;
        }
        Commands::NixBuilderRelease {
            image_path,
            registry,
            primary_nix_builder_kustomization,
            primary_kenshi_kustomization,
            primary_builder_pool,
            secondary_kenshi_kustomization,
            secondary_builder_pool,
            retries,
            token,
        } => {
            nix_builder::release(
                image_path,
                registry,
                primary_nix_builder_kustomization,
                primary_kenshi_kustomization,
                primary_builder_pool,
                secondary_kenshi_kustomization,
                secondary_builder_pool,
                retries,
                token,
            )
            .await?;
        }
        Commands::KenshiRelease {
            image_path,
            registry,
            primary_kustomization,
            secondary_kustomization,
            retries,
            token,
        } => {
            kenshi::release(
                image_path,
                registry,
                primary_kustomization,
                secondary_kustomization,
                retries,
                token,
            )
            .await?;
        }
        Commands::KenshiAgentRelease {
            image_path,
            registry,
            primary_kustomization,
            secondary_kustomization,
            primary_builder_pool,
            secondary_builder_pool,
            retries,
            token,
        } => {
            kenshi_agent::release(
                image_path,
                registry,
                primary_kustomization,
                secondary_kustomization,
                primary_builder_pool,
                secondary_builder_pool,
                retries,
                token,
            )
            .await?;
        }
        Commands::RustRegenerate {
            service,
            service_dir,
            repo_root,
        } => {
            setup_service_directory(Some(service_dir), Some(repo_root))?;
            commands::developer_tools::rust_regenerate(service).await?;
        }
        Commands::RustCargoUpdate {
            service,
            service_dir,
            repo_root,
        } => {
            setup_service_directory(Some(service_dir), Some(repo_root))?;
            commands::developer_tools::rust_cargo_update(service).await?;
        }
        Commands::IntegrationTest {
            service,
            service_dir,
            repo_root,
            suite,
        } => {
            integration_tests::execute_manual(&service, &service_dir, &repo_root, suite).await?;
        }
        Commands::Status {
            service,
            service_dir,
            repo_root,
            format,
        } => {
            let output_format = status::OutputFormat::from_str(&format);
            status::execute(&service, &service_dir, &repo_root, output_format).await?;
        }
        Commands::Test {
            service,
            service_dir,
            repo_root,
            service_type,
            test_type,
        } => {
            test::execute(
                &service,
                &service_dir,
                &repo_root,
                &service_type,
                &test_type,
            )
            .await?;
        }
        Commands::RustDev {
            service,
            service_dir,
            repo_root,
            skip_docker,
            skip_migrations,
            sqlx_cli,
        } => {
            setup_service_directory(Some(service_dir), Some(repo_root))?;
            commands::developer_tools::rust_dev(service, skip_docker, skip_migrations, sqlx_cli)
                .await?;
        }
        Commands::RustDevDown {
            service,
            service_dir,
            repo_root,
        } => {
            setup_service_directory(Some(service_dir), Some(repo_root))?;
            commands::developer_tools::rust_dev_down(service).await?;
        }
        Commands::WebRegenerate {
            product,
            service,
            repo_root,
        } => {
            commands::web_service::web_regenerate(product, service, repo_root).await?;
        }
        Commands::WebCargoUpdate {
            product,
            service,
            repo_root,
        } => {
            commands::web_service::web_cargo_update(product, service, repo_root).await?;
        }
        Commands::Bootstrap { command } => match command {
            BootstrapCommands::Push {
                binary,
                token,
                retries,
                skip_build,
                image_path,
            } => {
                bootstrap::push_single(binary, token, retries, skip_build, image_path).await?;
            }
            BootstrapCommands::PushAll {
                token,
                retries,
                parallel,
            } => {
                bootstrap::push_all(token, retries, parallel).await?;
            }
            BootstrapCommands::List => {
                bootstrap::list_binaries();
            }
            BootstrapCommands::Regenerate { bootstrap_dir } => {
                if let Some(dir) = bootstrap_dir {
                    std::env::set_var("SERVICE_DIR", dir);
                }
                bootstrap::regenerate().await?;
            }
            BootstrapCommands::Release {
                product,
                environment,
                cluster,
                token,
                retries,
                skip_git,
            } => {
                bootstrap::release(product, environment, cluster, token, retries, skip_git).await?;
            }
        },
        Commands::Pangea { command } => match command {
            PangeaCommands::Push {
                component,
                token,
                retries,
                skip_build,
                image_path,
            } => {
                pangea::push_single(component, token, retries, skip_build, image_path).await?;
            }
            PangeaCommands::PushAll {
                token,
                retries,
                parallel,
            } => {
                pangea::push_all(token, retries, parallel).await?;
            }
            PangeaCommands::List => {
                pangea::list_components();
            }
            PangeaCommands::Regenerate { pangea_dir } => {
                pangea::regenerate(pangea_dir).await?;
            }
            PangeaCommands::RegenerateCompiler => {
                pangea::regenerate_compiler().await?;
            }
        },
        Commands::EnsureWorkspaceDeps { repo_root } => {
            workspace_deps::execute(repo_root).await?;
        }
        Commands::MigrationReset {
            service,
            namespace,
            cleanup_jobs,
        } => {
            migrations::reset_migration(&service, &namespace, cleanup_jobs).await?;
        }
        Commands::SessionFlush {
            product,
            environment,
            force,
            dry_run,
        } => {
            commands::sessions::flush(product, environment, force, dry_run).await?;
        }
        Commands::Prerelease {
            working_dir,
            skip_backend,
            skip_frontend,
            skip_migrations,
        } => {
            commands::prerelease::execute(
                working_dir,
                skip_backend,
                skip_frontend,
                skip_migrations,
            )
            .await?;
        }
        Commands::MigrationNew {
            working_dir,
            name,
            classification,
            with_data,
            reason,
        } => {
            commands::migration_new::execute(
                working_dir,
                name,
                classification,
                with_data,
                reason,
            )
            .await?;
        }
        Commands::Codegen {
            working_dir,
            schema_only,
        } => {
            use std::path::PathBuf;
            let base_dir = PathBuf::from(&working_dir);
            let backend_dir = base_dir.join("services/rust/backend");
            let web_dir = base_dir.join("web");

            if schema_only {
                let schema_path = web_dir.join("schema.graphql");
                commands::codegen::export_schema_only(&backend_dir, &schema_path).await?;
            } else {
                commands::codegen::execute(&backend_dir, &web_dir).await?;
            }
        }
        Commands::Sync {
            working_dir,
            schema_only,
            check,
            skip_entities,
        } => {
            use std::path::Path;

            let base_dir = Path::new(&working_dir);

            if schema_only {
                commands::sync::execute_schema_only(base_dir).await?;
            } else if check {
                let result = commands::sync::execute_drift_check(base_dir).await?;
                if result.schema_drift || result.codegen_drift {
                    anyhow::bail!("Drift detected");
                }
                if let Some(error) = result.error {
                    anyhow::bail!("Drift check failed: {}", error);
                }
            } else {
                let result = commands::sync::execute(base_dir, skip_entities).await?;
                if !result.errors.is_empty() {
                    anyhow::bail!("Sync completed with {} error(s)", result.errors.len());
                }
            }
        }
        Commands::RebacValidate {
            working_dir,
            quiet,
            check_redis,
        } => {
            use std::path::Path;

            let base_dir = Path::new(&working_dir);
            let result = commands::rebac_validation::execute_with_options(
                base_dir,
                quiet,
                check_redis,
            )
            .await?;

            if !result.all_passed() {
                anyhow::bail!(
                    "ReBAC validation failed: {} error(s), {} warning(s)",
                    result.errors,
                    result.warnings
                );
            }
        }
        Commands::Dashboards {
            working_dir,
            check,
            verbose: _,
        } => {
            use std::path::Path;

            let base_dir = Path::new(&working_dir);
            let result = commands::dashboards::execute(base_dir, check).await?;

            if check && !result.dashboards_pruned.is_empty() {
                anyhow::bail!(
                    "Dashboard drift detected: {} stale dashboards would be pruned",
                    result.dashboards_pruned.len()
                );
            }

            println!(
                "Dashboard sync complete: {} entities scanned, {} dashboards generated",
                result.entities_scanned, result.dashboards_generated
            );
        }
        Commands::E2ePrepare {
            repo_root,
            skip_backend,
            skip_frontend,
            force,
        } => {
            commands::e2e::prepare_e2e_images(
                repo_root,
                skip_backend,
                skip_frontend,
                force,
            )?;
        }
        Commands::E2eRun {
            repo_root,
            headless,
            filter,
        } => {
            commands::e2e::run_e2e_tests(repo_root, headless, filter)?;
        }
        Commands::TestPyramid {
            repo_root,
            skip_unit,
            skip_integration,
            skip_e2e,
            filter,
            fail_fast,
            report,
            report_path,
        } => {
            commands::e2e::run_test_pyramid(
                repo_root,
                skip_unit,
                skip_integration,
                skip_e2e,
                filter,
                fail_fast,
                report,
                report_path,
            )?;
        }
        Commands::TestUnit {
            repo_root,
            filter,
            skip_frontend,
            report,
            report_path,
        } => {
            commands::e2e::run_unit_tests(
                repo_root,
                filter,
                skip_frontend,
                report,
                report_path,
            )?;
        }
        Commands::TestIntegration { repo_root, filter } => {
            commands::e2e::run_integration_tests(repo_root, filter)?;
        }
        Commands::E2eCleanup => {
            commands::e2e::cleanup_all()?;
        }
        Commands::TestE2e {
            repo_root,
            headless,
            filter,
            force_rebuild,
        } => {
            commands::e2e::run_e2e_tests_smart(repo_root, headless, filter, force_rebuild)?;
        }
        Commands::Seed {
            working_dir,
            env,
            dry_run,
        } => {
            use std::path::Path;
            commands::seed::seed(Path::new(&working_dir), &env, dry_run).await?;
        }
        Commands::Unseed {
            working_dir,
            env,
            dry_run,
        } => {
            use std::path::Path;
            commands::seed::unseed(Path::new(&working_dir), &env, dry_run).await?;
        }
        Commands::Gem { command } => match command {
            GemCommands::Bump {
                working_dir,
                level,
                name,
            } => {
                let (old, new) = commands::gem::bump(&working_dir, &level, name)?;
                println!("{} → {}", old, new);
            }
            GemCommands::Build { working_dir, name } => {
                commands::gem::build(&working_dir, name)?;
            }
            GemCommands::Push {
                working_dir,
                name,
                api_key,
                otp,
            } => {
                commands::gem::push(&working_dir, name, api_key, otp)?;
            }
            GemCommands::Test { working_dir, name } => {
                commands::gem::test(&working_dir, name)?;
            }
        },
        Commands::Helm { command } => match command {
            HelmCommands::Lint { chart_dir, lib_chart_dir, lib_chart_name } => {
                commands::helm::lint_with_lib(&chart_dir, lib_chart_dir.as_deref(), &lib_chart_name)?;
            }
            HelmCommands::Package {
                chart_dir,
                output,
                version,
            } => {
                commands::helm::package(&chart_dir, &output, version.as_deref())?;
            }
            HelmCommands::Push { chart, registry } => {
                commands::helm::push(&chart, &registry)?;
            }
            HelmCommands::Deploy {
                service,
                image_tag,
                k8s_repo,
                environment,
                commit,
                watch,
            } => {
                commands::helm::deploy(&service, &image_tag, &k8s_repo, &environment, commit, watch)?;
            }
            HelmCommands::Release {
                chart_dir,
                registry,
                version,
                lib_chart_dir,
                lib_chart_name,
            } => {
                commands::helm::release_with_lib(&chart_dir, &registry, version.as_deref(), lib_chart_dir.as_deref(), &lib_chart_name)?;
            }
            HelmCommands::Template {
                chart_dir,
                values,
                set,
            } => {
                commands::helm::template(&chart_dir, values.as_deref(), &set)?;
            }
            HelmCommands::Bump {
                charts_dir,
                lib_chart_name,
                level,
                no_commit,
            } => {
                let (old, new) = commands::helm::bump(&charts_dir, &lib_chart_name, &level, !no_commit)?;
                println!("{} → {}", old, new);
            }
            HelmCommands::LintAll {
                charts_dir,
                lib_chart_dir,
                lib_chart_name,
            } => {
                commands::helm::lint_all(&charts_dir, lib_chart_dir.as_deref(), &lib_chart_name)?;
            }
            HelmCommands::ReleaseAll {
                charts_dir,
                lib_chart_dir,
                lib_chart_name,
                registry,
            } => {
                commands::helm::release_all(&charts_dir, lib_chart_dir.as_deref(), &lib_chart_name, &registry)?;
            }
        },
        Commands::PostDeployVerify {
            environment,
            service,
            domain,
            health_url,
            graphql_url,
            timeout,
            retries,
        } => {
            use commands::post_deploy_verification::{
                get_product_endpoints, verify_deployment, PostDeployConfig,
            };
            use std::time::Duration;

            // Use provided URLs, or derive from --domain, or fall back to generic pattern
            let (default_health, default_graphql) = if let Some(d) = domain {
                get_product_endpoints(&d, &environment)
            } else {
                (
                    format!("https://{}.{}.app/health", environment, service),
                    format!("https://{}.{}.app/graphql", environment, service),
                )
            };

            let config = PostDeployConfig {
                environment: environment.clone(),
                service_name: service,
                health_endpoint: health_url.unwrap_or(default_health),
                graphql_endpoint: graphql_url.unwrap_or(default_graphql),
                timeout: Duration::from_secs(timeout),
                retries,
                smoke_queries_enabled: true, // Default on; overridden via deploy.yaml when called from product-release
            };

            let result = verify_deployment(&config).await?;
            if !result.is_valid() {
                anyhow::bail!("Post-deploy verification failed");
            }
        }
    }

    Ok(())
}
