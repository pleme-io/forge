//! CLI definitions for forge
//!
//! This module contains all CLI argument parsing structures using clap.

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "forge",
    version,
    about = "Deployment orchestrator for service infrastructure",
    long_about = "Production-grade deployment tool written in Rust.\nReplaces fragile bash scripts with type-safe, testable code."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Enable verbose logging
    #[arg(short, long, global = true)]
    pub verbose: bool,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Build Docker image with Nix
    Build {
        /// Nix flake attribute to build
        #[arg(long, default_value = "dockerImage")]
        flake_attr: String,

        /// Working directory (where flake.nix is)
        #[arg(long, default_value = ".")]
        working_dir: String,

        /// Target architecture
        #[arg(long, default_value = "x86_64-linux")]
        arch: String,

        /// Attic cache URL
        #[arg(long, env = "ATTIC_CACHE_URL", default_value = "http://localhost:8080")]
        cache_url: String,

        /// Attic cache name
        #[arg(long, env = "ATTIC_CACHE_NAME", default_value = "cache")]
        cache_name: String,

        /// Push to Attic cache after build
        #[arg(long)]
        push_cache: bool,

        /// Output symlink name
        #[arg(long, default_value = "result")]
        output: String,
    },

    /// Push image to container registry
    Push {
        /// Path to Nix build result
        #[arg(long, default_value = "result")]
        image_path: String,

        /// Container registry URL (without tag)
        #[arg(long, required = true)]
        registry: String,

        /// Image tags (can be specified multiple times)
        #[arg(long = "tag")]
        tags: Vec<String>,

        /// Automatically generate architecture-prefixed tags (amd64-{sha}, amd64-latest)
        /// Uses RELEASE_GIT_SHA env var or git rev-parse for the SHA
        #[arg(long)]
        auto_tags: bool,

        /// Architecture for auto-tags (default: amd64)
        #[arg(long, default_value = "amd64")]
        arch: String,

        /// Number of retry attempts
        #[arg(long, default_value = "3")]
        retries: u32,

        /// GHCR token (or set GHCR_TOKEN env var)
        #[arg(long, env = "GHCR_TOKEN")]
        token: Option<String>,

        /// Also push Nix closure to Attic
        #[arg(long)]
        push_attic: bool,

        /// Attic cache name
        #[arg(long, env = "ATTIC_CACHE_NAME", default_value = "cache")]
        attic_cache: String,

        /// Update kustomization.yaml with new image tag after push
        /// Provide path to the kustomization.yaml file
        #[arg(long)]
        update_kustomization: Option<String>,

        /// Commit and push kustomization changes to git
        #[arg(long)]
        commit_kustomization: bool,
    },

    /// Full GitOps deployment workflow
    Deploy {
        /// Path to Kubernetes manifest
        #[arg(long, required = true)]
        manifest: String,

        /// Container registry URL (without tag)
        #[arg(long, required = true)]
        registry: String,

        /// Image tag to deploy
        #[arg(long, required = true)]
        tag: String,

        /// Kubernetes namespace
        #[arg(long, required = true)]
        namespace: String,

        /// Deployment/StatefulSet name
        #[arg(long, required = true)]
        name: String,

        /// Watch rollout progress
        #[arg(long)]
        watch: bool,

        /// Rollout timeout
        #[arg(long, default_value = "10m")]
        timeout: String,

        /// Skip build step (use existing image)
        #[arg(long)]
        skip_build: bool,

        /// Attic cache URL (for build step)
        #[arg(long, default_value = "http://localhost:8080")]
        cache_url: String,

        /// Attic cache name (for build step)
        #[arg(long, env = "ATTIC_CACHE_NAME", default_value = "cache")]
        cache_name: String,
    },

    /// Monitor Kubernetes rollout status
    Rollout {
        /// Kubernetes namespace
        #[arg(short, long, required = true)]
        namespace: String,

        /// Deployment/StatefulSet name
        #[arg(short, long, required = true)]
        name: String,

        /// Refresh interval in seconds
        #[arg(long, default_value = "3")]
        interval: u64,

        /// Timeout for rollout
        #[arg(long)]
        timeout: Option<String>,

        /// Perform rollback instead of monitoring
        #[arg(long)]
        rollback: bool,
    },

    /// Comprehensive release workflow with full testing
    ComprehensiveRelease {
        /// Service name (auth, cart, order, etc.)
        #[arg(long, required = true)]
        service_name: String,

        /// Product name
        #[arg(long, required = true)]
        product_name: String,

        /// Kubernetes namespace
        #[arg(long, required = true)]
        namespace: String,

        /// Nix flake attribute to build
        #[arg(long, default_value = "dockerImage-amd64")]
        flake_attr: String,

        /// Working directory (where flake.nix is)
        #[arg(long, required = true)]
        working_dir: String,

        /// Path to docker-compose.yml (relative to working_dir)
        #[arg(long)]
        compose_file: Option<String>,

        /// Container registry URL (without tag)
        #[arg(long, required = true)]
        registry: String,

        /// Path to Kubernetes manifest
        #[arg(long, required = true)]
        manifest: String,

        /// Migrations directory path (relative to working_dir)
        #[arg(long, default_value = "./migrations")]
        migrations_path: String,

        /// Attic cache URL
        #[arg(long, default_value = "http://localhost:8080")]
        cache_url: String,

        /// Attic cache name
        #[arg(long, env = "ATTIC_CACHE_NAME", default_value = "cache")]
        cache_name: String,

        /// Database port for integration tests
        #[arg(long, default_value = "5434")]
        db_port: u16,

        /// Database username for integration tests
        #[arg(long)]
        db_user: Option<String>,

        /// Database password for integration tests
        #[arg(long, default_value = "test_password")]
        db_password: String,

        /// Database name for integration tests
        #[arg(long)]
        db_name: Option<String>,

        /// Skip unit tests
        #[arg(long)]
        skip_unit_tests: bool,

        /// Skip integration tests
        #[arg(long)]
        skip_integration_tests: bool,

        /// Skip build step
        #[arg(long)]
        skip_build: bool,

        /// Skip push step
        #[arg(long)]
        skip_push: bool,

        /// Skip deploy step
        #[arg(long)]
        skip_deploy: bool,

        /// Watch rollout progress
        #[arg(long)]
        watch: bool,
    },

    /// Complete CI workflow for GitHub Actions runner
    GithubRunnerCi {
        /// Working directory (where github-runner flake.nix is)
        #[arg(long, default_value = "pkgs/infrastructure/github-runner")]
        working_dir: String,

        /// Attic cache URL
        #[arg(long, default_value = "http://localhost:8080")]
        cache_url: String,

        /// Attic cache name
        #[arg(long, env = "ATTIC_CACHE_NAME", default_value = "cache")]
        cache_name: String,

        /// Container registry (e.g., ghcr.io/org/project/github-runner)
        #[arg(long, env = "GITHUB_RUNNER_REGISTRY")]
        registry: String,

        /// Kubernetes manifest path (from repo root)
        #[arg(long, required = true)]
        manifest: String,

        /// Kubernetes namespace
        #[arg(long, default_value = "github-actions")]
        namespace: String,

        /// Kubernetes StatefulSet name
        #[arg(long, default_value = "github-actions-runner")]
        name: String,

        /// Skip build (use existing image)
        #[arg(long)]
        skip_build: bool,

        /// Skip push (don't push to registry)
        #[arg(long)]
        skip_push: bool,

        /// Watch rollout progress
        #[arg(long)]
        watch: bool,
    },

    /// Push Rust service Docker image to GHCR (orchestration only, no nix build)
    PushRustService {
        /// Path to Nix build result (e.g., result-amd64)
        #[arg(long, required = true)]
        image_path: String,
        /// Service name
        #[arg(long, required = true)]
        service: String,

        /// Product name (e.g., myapp)
        #[arg(long)]
        product: Option<String>,

        /// Service directory path (for root flake pattern)
        #[arg(long)]
        service_dir: Option<String>,

        /// Git repository root path (for root flake pattern)
        #[arg(long)]
        repo_root: Option<String>,

        /// Container registry URL
        #[arg(long, required = true)]
        registry: String,

        /// Attic cache name
        #[arg(long, env = "ATTIC_CACHE_NAME", default_value = "cache")]
        cache_name: String,

        /// Attic authentication token
        #[arg(long, env = "ATTIC_TOKEN", default_value = "")]
        attic_token: String,

        /// GitHub authentication token
        #[arg(long, env = "GITHUB_TOKEN", default_value = "")]
        github_token: String,
    },

    /// Deploy Rust service to Kubernetes via GitOps
    DeployRustService {
        /// Service name
        #[arg(long, required = true)]
        service: String,

        /// Product name (e.g., myapp)
        #[arg(long)]
        product: Option<String>,

        /// Service directory path (for root flake pattern)
        #[arg(long)]
        service_dir: Option<String>,

        /// Git repository root path (for root flake pattern)
        #[arg(long)]
        repo_root: Option<String>,

        /// Path to Kubernetes manifest
        #[arg(long, required = true)]
        manifest: String,

        /// Container registry URL
        #[arg(long, required = true)]
        registry: String,

        /// Kubernetes namespace
        #[arg(long, required = true)]
        namespace: String,

        /// Watch rollout progress
        #[arg(long)]
        watch: bool,
    },

    /// Full orchestration release workflow (push + deploy + migrations + federation)
    /// Manifest path is read from deploy.yaml (service.manifests.kustomization field)
    /// Namespace is derived from deploy.yaml based on environment if not explicitly provided
    OrchestrateRelease {
        /// Service name
        #[arg(long, required = true)]
        service: String,

        /// Service directory path (for root flake pattern)
        #[arg(long, required = true)]
        service_dir: String,

        /// Git repository root path (for root flake pattern)
        #[arg(long, required = true)]
        repo_root: String,

        /// Container registry URL
        #[arg(long, required = true)]
        registry: String,

        /// Target environment (e.g., staging, production).
        /// Only used when --single-environment is specified.
        /// Defaults to FORGE_ENV or "staging" if neither is set.
        #[arg(long, env = "FORGE_ENV", default_value = "staging")]
        environment: String,

        /// Deploy to a single environment only (instead of all environments).
        /// When specified, uses --environment to determine which environment.
        /// By default, releases deploy to ALL environments in order (build-once-promote).
        #[arg(long)]
        single_environment: bool,

        /// Kubernetes namespace (optional - derived from deploy.yaml if not provided)
        #[arg(long)]
        namespace: Option<String>,

        /// Path to Nix build result (e.g., result-amd64).
        /// Required unless --deploy-only is used.
        #[arg(long)]
        image_path: Option<String>,

        /// Watch rollout progress
        #[arg(long)]
        watch: bool,

        /// Push image only, skip deploy. Exits after successful push.
        #[arg(long)]
        push_only: bool,

        /// Deploy only, skip push. Requires --image-tag to specify the image.
        #[arg(long)]
        deploy_only: bool,

        /// Image tag for deploy-only mode (overrides RELEASE_GIT_SHA).
        #[arg(long)]
        image_tag: Option<String>,
    },

    /// Rollback a product to the previous deployed version.
    /// Reads previous_tag from each service's deploy.yaml and redeploys that image.
    /// After rollback, swaps current↔previous tags so re-rollback = roll forward.
    /// Usage: forge rollback --product myapp --repo-root /path/to/repo --env staging
    ///        forge rollback --repo-root /path/to/standalone-repo --env staging
    Rollback {
        /// Product name (e.g., "myapp"). Auto-discovered from deploy.yaml if omitted.
        #[arg(long)]
        product: Option<String>,

        /// Git repository root path
        #[arg(long, required = true)]
        repo_root: String,

        /// Target environment (default: staging)
        #[arg(long)]
        env: Option<String>,

        /// Skip health checks after deploying
        #[arg(long)]
        skip_health_check: bool,

        /// Skip confirmation prompt
        #[arg(long)]
        force: bool,
    },

    /// Product-level release orchestration.
    /// Builds all artifacts, then deploys services per environment with health checks.
    /// Usage: forge product-release --product myapp --repo-root /path/to/repo
    ///        forge product-release --repo-root /path/to/standalone-repo
    ProductRelease {
        /// Product name (e.g., "myapp"). Auto-discovered from deploy.yaml if omitted.
        #[arg(long)]
        product: Option<String>,

        /// Git repository root path
        #[arg(long, required = true)]
        repo_root: String,

        /// Target environment (if not set, deploys to all active environments)
        #[arg(long)]
        env: Option<String>,

        /// Skip pre-release gates
        #[arg(long, env = "SKIP_GATES")]
        skip_gates: bool,

        /// Skip dashboard sync
        #[arg(long, env = "SKIP_DASHBOARDS")]
        skip_dashboards: bool,

        /// Build-only mode: run gates, push images, and update artifact tags
        /// without deploying to any environment.
        #[arg(long)]
        build_only: bool,
    },

    /// Run Rust unit tests
    RustTest {
        /// Service name
        #[arg(long, required = true)]
        service: String,
    },

    /// Run Rust clippy linter
    RustLint {
        /// Service name
        #[arg(long, required = true)]
        service: String,
    },

    /// Format Rust code with rustfmt
    RustFmt {
        /// Service name
        #[arg(long, required = true)]
        service: String,
    },

    /// Check Rust code formatting
    RustFmtCheck {
        /// Service name
        #[arg(long, required = true)]
        service: String,
    },

    /// Extract GraphQL schema from Rust service
    RustExtractSchema {
        /// Service name
        #[arg(long, required = true)]
        service: String,
    },

    /// Update Cargo.nix after dependency changes
    RustUpdateCargoNix {
        /// Service name
        #[arg(long, required = true)]
        service: String,
    },

    /// Show help for Rust service commands
    RustServiceHelp {
        /// Service name
        #[arg(long, required = true)]
        service: String,
    },

    /// Force Flux reconciliation for a Kustomization
    FluxReconcile {
        /// Kubernetes namespace (also used as Kustomization name)
        #[arg(long, required = true)]
        namespace: String,
    },

    /// Run database migrations for a service
    RunMigrations {
        /// Service name
        #[arg(long, required = true)]
        service: String,

        /// Kubernetes namespace
        #[arg(long, required = true)]
        namespace: String,

        /// Git SHA for the image tag
        #[arg(long, required = true)]
        git_sha: String,
    },

    /// Update Apollo federation supergraph
    UpdateFederation {
        /// Service name
        #[arg(long, required = true)]
        service: String,

        /// Kubernetes namespace
        #[arg(long, required = true)]
        namespace: String,

        /// Product name
        #[arg(long, required = true)]
        product: String,
    },

    /// Verify web build (NO hardcoded URLs) and prepare runtime env.js
    WebBuildVerify {
        /// Path to dist directory
        #[arg(long, default_value = "dist")]
        dist_dir: String,

        /// Path to env.js template
        #[arg(long, default_value = "public/env.template.js")]
        template_path: String,
    },

    /// Verify nix-builder remote build service
    NixBuilderVerify {
        /// Builder hostname
        #[arg(long, default_value = "nix-builder")]
        hostname: String,

        /// Builder port
        #[arg(long, default_value = "22")]
        port: u16,

        /// Kubernetes service (for in-cluster verification)
        #[arg(long)]
        k8s_service: Option<String>,

        /// Kubernetes namespace (for in-cluster nix-builder verification)
        #[arg(long, env = "NIX_BUILDER_NAMESPACE")]
        namespace: Option<String>,
    },

    /// Test remote build with nix-builder
    NixBuilderTest {
        /// Test package to build
        #[arg(long, default_value = "hello")]
        package: String,

        /// Builder hostname (set via NIX_BUILDER_HOST env var or --hostname flag)
        #[arg(long, env = "NIX_BUILDER_HOST", default_value = "localhost")]
        hostname: String,

        /// Builder port
        #[arg(long, default_value = "30222")]
        port: u16,

        /// SSH key path
        #[arg(long, default_value = "/var/root/.ssh/nix_builder_ed25519")]
        ssh_key: String,
    },

    /// Release nix-builder: push image and update K8s manifests for all clusters
    /// Updates kustomization images[], BUILDER_IMAGE env var, and builder-pool builderImage
    NixBuilderRelease {
        /// Path to nix-built image
        #[arg(long, required = true)]
        image_path: String,

        /// Container registry (e.g., ghcr.io/org/nix-builder)
        #[arg(long, env = "NIX_BUILDER_REGISTRY")]
        registry: String,

        /// Path to primary cluster nix-builder kustomization.yaml (with images[] overlay)
        #[arg(long)]
        primary_nix_builder_kustomization: Option<String>,

        /// Path to primary cluster kenshi kustomization.yaml (for BUILDER_IMAGE env var)
        #[arg(long, required = true)]
        primary_kenshi_kustomization: String,

        /// Path to primary cluster builder-pool.yaml
        #[arg(long, required = true)]
        primary_builder_pool: String,

        /// Path to secondary cluster kenshi kustomization.yaml (for BUILDER_IMAGE env var)
        #[arg(long, required = true)]
        secondary_kenshi_kustomization: String,

        /// Path to secondary cluster builder-pool.yaml
        #[arg(long, required = true)]
        secondary_builder_pool: String,

        /// Number of push retries
        #[arg(long, default_value = "3")]
        retries: u32,

        /// GHCR token (defaults to GHCR_TOKEN env var)
        #[arg(long)]
        token: Option<String>,
    },

    /// Regenerate Cargo.lock and Cargo.nix for workspace
    RustRegenerate {
        /// Service name
        #[arg(long, required = true)]
        service: String,

        /// Service directory path (for root flake pattern)
        #[arg(long, required = true)]
        service_dir: String,

        /// Git repository root path (for root flake pattern)
        #[arg(long, required = true)]
        repo_root: String,
    },

    /// Update dependencies and regenerate Cargo.nix for workspace
    RustCargoUpdate {
        /// Service name
        #[arg(long, required = true)]
        service: String,

        /// Service directory path (for root flake pattern)
        #[arg(long, required = true)]
        service_dir: String,

        /// Git repository root path (for root flake pattern)
        #[arg(long, required = true)]
        repo_root: String,
    },

    /// Run integration tests manually for a deployed service
    /// Reads test suites from deploy.yaml (deployment.integration_tests section)
    IntegrationTest {
        /// Service name
        #[arg(long, required = true)]
        service: String,

        /// Service directory path
        #[arg(long, required = true)]
        service_dir: String,

        /// Git repository root path
        #[arg(long, required = true)]
        repo_root: String,

        /// Specific test suite to run (by name). If not specified, runs all suites
        #[arg(long)]
        suite: Option<String>,
    },

    /// Show deployed version/image/tag for a service
    /// Queries Kubernetes for current deployment state
    Status {
        /// Service name
        #[arg(long, required = true)]
        service: String,

        /// Service directory path (for loading deploy.yaml)
        #[arg(long, required = true)]
        service_dir: String,

        /// Git repository root path
        #[arg(long, required = true)]
        repo_root: String,

        /// Output format (text, json)
        #[arg(long, default_value = "text")]
        format: String,
    },

    /// Run tests (unit and/or integration) for a service
    /// Usage: nix run .#test:product:service -- [unit|integration|all]
    Test {
        /// Service name
        #[arg(long, required = true)]
        service: String,

        /// Service directory path
        #[arg(long, required = true)]
        service_dir: String,

        /// Git repository root path
        #[arg(long, required = true)]
        repo_root: String,

        /// Service type (rust or web)
        #[arg(long, required = true)]
        service_type: String,

        /// Test type to run: unit, integration, or all (default: all)
        #[arg(default_value = "all")]
        test_type: String,
    },

    /// Start local development environment for a Rust service
    /// Starts docker-compose, runs migrations, starts cargo run
    RustDev {
        /// Service name
        #[arg(long, required = true)]
        service: String,

        /// Service directory path
        #[arg(long, required = true)]
        service_dir: String,

        /// Git repository root path
        #[arg(long, required = true)]
        repo_root: String,

        /// Skip starting docker-compose services
        #[arg(long)]
        skip_docker: bool,

        /// Skip running migrations
        #[arg(long)]
        skip_migrations: bool,

        /// Path to sqlx-cli binary (from nix derivation)
        #[arg(long)]
        sqlx_cli: Option<String>,
    },

    /// Stop local development environment for a Rust service
    /// Stops docker-compose services
    RustDevDown {
        /// Service name
        #[arg(long, required = true)]
        service: String,

        /// Service directory path
        #[arg(long, required = true)]
        service_dir: String,

        /// Git repository root path
        #[arg(long, required = true)]
        repo_root: String,
    },

    /// Regenerate deps.nix for web frontend + Cargo.nix for Hanabi (shared BFF)
    /// Usage: forge web-regenerate --product myapp --service web
    WebRegenerate {
        /// Product name (e.g., myapp)
        #[arg(long, required = true)]
        product: String,

        /// Service name (typically "web")
        #[arg(long, required = true)]
        service: String,

        /// Git repository root path
        #[arg(long, required = true)]
        repo_root: String,
    },

    /// Update Hanabi (shared BFF) dependencies and regenerate Cargo.nix
    /// Usage: forge web-cargo-update --product myapp --service web
    WebCargoUpdate {
        /// Product name (e.g., myapp)
        #[arg(long, required = true)]
        product: String,

        /// Service name (typically "web")
        #[arg(long, required = true)]
        service: String,

        /// Git repository root path
        #[arg(long, required = true)]
        repo_root: String,
    },

    /// Bootstrap binary commands (build, push, regenerate)
    /// Manages infrastructure bootstrap binaries: postgres-bootstrap, dragonfly-bootstrap, openbao-bootstrap
    Bootstrap {
        #[command(subcommand)]
        command: BootstrapCommands,
    },

    /// Pangea infrastructure platform commands (build, push, regenerate)
    /// Manages pangea components: operator, cli, web (WASM)
    Pangea {
        #[command(subcommand)]
        command: PangeaCommands,
    },

    /// Ensure all @pleme/* workspace packages have up-to-date dist/ builds
    /// Run this before Nix builds to avoid pleme-linker validation failures
    EnsureWorkspaceDeps {
        /// Git repository root path
        #[arg(long, required = true)]
        repo_root: String,
    },

    /// Reset a Shinka DatabaseMigration to retry after failure
    /// Use after fixing migration code to retry a failed migration
    MigrationReset {
        /// Service name (e.g., backend, auth)
        #[arg(long, required = true)]
        service: String,

        /// Kubernetes namespace (e.g., myapp-staging)
        #[arg(long, required = true)]
        namespace: String,

        /// Also delete failed migration jobs
        #[arg(long)]
        cleanup_jobs: bool,
    },

    /// Flush Redis/Valkey sessions for a product
    /// Forces all users to re-authenticate, getting fresh permissions
    /// Use when sessions have stale permissions after backend updates
    SessionFlush {
        /// Product name
        #[arg(long, required = true)]
        product: String,

        /// Environment (e.g., staging, production)
        #[arg(long, default_value = "staging")]
        environment: String,

        /// Skip confirmation prompt
        #[arg(long)]
        force: bool,

        /// Only show count, don't delete
        #[arg(long)]
        dry_run: bool,
    },

    /// Run product pre-release validation gates
    /// Validates backend (cargo check, clippy, fmt, test, extract-schema),
    /// migrations (idempotency, soft-delete), and frontend (codegen, type-check, lint, tests)
    Prerelease {
        /// Product root directory (repo root for standalone products, pkgs/products/{name} in monorepo)
        #[arg(long, required = true)]
        working_dir: String,

        /// Skip backend gates (G1-G5)
        #[arg(long)]
        skip_backend: bool,

        /// Skip frontend gates (G8-G11)
        #[arg(long)]
        skip_frontend: bool,

        /// Skip migration gates (G6-G7)
        #[arg(long)]
        skip_migrations: bool,
    },

    /// Scaffold a new SeaORM migration with manifest entry
    /// Generates migration file(s) and updates migration-manifest.yaml
    MigrationNew {
        /// Product root directory (repo root for standalone products, pkgs/products/{name} in monorepo)
        #[arg(long, required = true)]
        working_dir: String,

        /// Migration name (snake_case, e.g., "add_user_preferences")
        #[arg(long, required = true)]
        name: String,

        /// Classification: schema_only, data_only, schema_and_data, noop
        #[arg(long, default_value = "schema_only")]
        classification: String,

        /// Also create a companion data migration file
        #[arg(long)]
        with_data: bool,

        /// Reason for the classification (required for noop)
        #[arg(long)]
        reason: Option<String>,
    },

    /// Run schema export and GraphQL codegen
    /// Exports schema from backend and generates TypeScript types
    Codegen {
        /// Product root directory (repo root for standalone products, pkgs/products/{name} in monorepo)
        #[arg(long, required = true)]
        working_dir: String,

        /// Only export schema, don't run codegen
        #[arg(long)]
        schema_only: bool,
    },

    /// One-command sync pipeline
    /// Propagates changes from SSoT (Rust backend) through the entire stack:
    /// Migrations → SeaORM Entities → GraphQL Schema → Frontend Types/Hooks
    Sync {
        /// Product root directory (repo root for standalone products, pkgs/products/{name} in monorepo)
        #[arg(long, required = true)]
        working_dir: String,

        /// Only export schema, don't run codegen
        #[arg(long)]
        schema_only: bool,

        /// Check for drift without syncing (CI mode)
        #[arg(long)]
        check: bool,

        /// Skip SeaORM entity generation
        #[arg(long)]
        skip_entities: bool,
    },

    /// Validate ReBAC configuration
    /// Checks that Redis Tuple Store relations match SeaORM entity definitions
    RebacValidate {
        /// Product root directory (repo root for standalone products, pkgs/products/{name} in monorepo)
        #[arg(long, required = true)]
        working_dir: String,

        /// Quiet mode (only show errors)
        #[arg(long, short)]
        quiet: bool,

        /// Also verify Redis connectivity and key patterns
        #[arg(long)]
        check_redis: bool,
    },

    /// Sync Grafana dashboards from code metadata (Observability as Code)
    /// Scans Rust code for observability attributes and generates
    /// GrafanaDashboard CRDs for FluxCD reconciliation
    Dashboards {
        /// Product root directory (repo root for standalone products, pkgs/products/{name} in monorepo)
        #[arg(long, required = true)]
        working_dir: String,

        /// Check for drift without generating (CI mode)
        #[arg(long)]
        check: bool,

        /// Verbose output showing all scanned entities
        #[arg(long, short)]
        verbose: bool,
    },

    /// Prepare E2E test images
    /// Builds Docker images via Nix and loads them into local Docker daemon
    /// for use with testcontainers-based E2E tests.
    ///
    /// This command:
    /// 1. Verifies Docker daemon is running
    /// 2. Builds backend image via Nix
    /// 3. Builds web image via Nix
    /// 4. Loads both images into Docker
    ///
    /// After running this, you can run E2E tests:
    ///   cargo test --test 'e2e*' -- --include-ignored
    E2ePrepare {
        /// Repository root directory
        #[arg(long)]
        repo_root: Option<String>,

        /// Skip backend image build
        #[arg(long)]
        skip_backend: bool,

        /// Skip frontend image build
        #[arg(long)]
        skip_frontend: bool,

        /// Force rebuild even if images exist
        #[arg(long)]
        force: bool,
    },

    /// Run E2E tests with full-stack testcontainers
    /// Spins up the entire stack (Postgres, Redis, NATS, Backend, Frontend)
    /// using testcontainers and runs browser-based E2E tests.
    ///
    /// Prerequisites: Run `e2e-prepare` first to build images.
    E2eRun {
        /// Repository root directory
        #[arg(long)]
        repo_root: Option<String>,

        /// Run in headless mode (no browser window)
        #[arg(long, default_value = "true")]
        headless: bool,

        /// Test filter pattern (passed to cargo test)
        #[arg(long)]
        filter: Option<String>,
    },

    /// Run full testing pyramid
    /// Executes all test levels in order: Unit → Integration → E2E
    ///
    /// The testing pyramid ensures fast feedback by running quick tests first:
    /// 1. Backend unit tests (cargo test --lib)
    /// 2. Frontend unit tests (npm run test)
    /// 3. Backend integration tests (testcontainers)
    /// 4. E2E tests (full browser automation)
    TestPyramid {
        /// Repository root directory
        #[arg(long)]
        repo_root: Option<String>,

        /// Skip unit tests (both backend and frontend)
        #[arg(long)]
        skip_unit: bool,

        /// Skip integration tests
        #[arg(long)]
        skip_integration: bool,

        /// Skip E2E tests
        #[arg(long)]
        skip_e2e: bool,

        /// Filter pattern for test names
        #[arg(long)]
        filter: Option<String>,

        /// Stop on first failure
        #[arg(long)]
        fail_fast: bool,

        /// Generate JSON test report
        #[arg(long)]
        report: bool,

        /// Path for JSON test report (default: test-report.json in web directory)
        #[arg(long)]
        report_path: Option<String>,
    },

    /// Run unit tests only (backend + frontend)
    /// Fast tests with no external dependencies.
    TestUnit {
        /// Repository root directory
        #[arg(long)]
        repo_root: Option<String>,

        /// Filter pattern for test names
        #[arg(long)]
        filter: Option<String>,

        /// Skip frontend unit tests
        #[arg(long)]
        skip_frontend: bool,

        /// Generate JSON test report
        #[arg(long)]
        report: bool,

        /// Path for JSON test report (default: test-report.json in web directory)
        #[arg(long)]
        report_path: Option<String>,
    },

    /// Run integration tests only
    /// Requires Docker for testcontainers. Auto-starts Docker on macOS if not running.
    TestIntegration {
        /// Repository root directory
        #[arg(long)]
        repo_root: Option<String>,

        /// Filter pattern for test names
        #[arg(long)]
        filter: Option<String>,
    },

    /// Clean up orphaned testcontainers and E2E images
    /// Kills all testcontainers-managed containers, Ryuk sidecars,
    /// and removes backend/web Docker images.
    ///
    /// Run this to recover from a force-killed test run that left
    /// containers and images behind.
    E2eCleanup,

    /// Run E2E tests only
    /// Auto-builds and loads Docker images if missing.
    TestE2e {
        /// Repository root directory
        #[arg(long)]
        repo_root: Option<String>,

        /// Run in headless mode (no browser window)
        #[arg(long, default_value = "true")]
        headless: bool,

        /// Filter pattern for test names
        #[arg(long)]
        filter: Option<String>,

        /// Force rebuild images even if they exist
        #[arg(long)]
        force_rebuild: bool,
    },

    /// Release kenshi operator: push image and update K8s manifests for all clusters
    /// Updates kustomization images[] for the kenshi operator deployment
    KenshiRelease {
        /// Path to nix-built image
        #[arg(long, required = true)]
        image_path: String,

        /// Container registry (e.g., ghcr.io/org/kenshi)
        #[arg(long, env = "KENSHI_REGISTRY")]
        registry: String,

        /// Path to primary cluster kenshi kustomization.yaml
        #[arg(long, required = true)]
        primary_kustomization: String,

        /// Path to secondary cluster kenshi kustomization.yaml
        #[arg(long, required = true)]
        secondary_kustomization: String,

        /// Number of push retries
        #[arg(long, default_value = "3")]
        retries: u32,

        /// GHCR token (defaults to GHCR_TOKEN env var)
        #[arg(long)]
        token: Option<String>,
    },

    /// Release kenshi-agent: push image and update K8s manifests for all clusters
    /// Updates kustomization images[], AGENT_IMAGE env var, and builder-pool agentImage
    KenshiAgentRelease {
        /// Path to nix-built image
        #[arg(long, required = true)]
        image_path: String,

        /// Container registry (e.g., ghcr.io/org/kenshi-agent)
        #[arg(long, env = "KENSHI_AGENT_REGISTRY")]
        registry: String,

        /// Path to primary cluster kenshi kustomization.yaml
        #[arg(long, required = true)]
        primary_kustomization: String,

        /// Path to secondary cluster kenshi kustomization.yaml
        #[arg(long, required = true)]
        secondary_kustomization: String,

        /// Path to primary cluster builder-pool.yaml
        #[arg(long, required = true)]
        primary_builder_pool: String,

        /// Path to secondary cluster builder-pool.yaml
        #[arg(long, required = true)]
        secondary_builder_pool: String,

        /// Number of push retries
        #[arg(long, default_value = "3")]
        retries: u32,

        /// GHCR token (defaults to GHCR_TOKEN env var)
        #[arg(long)]
        token: Option<String>,
    },

    /// Seed test profiles into an environment
    Seed {
        /// Product root directory (repo root for standalone products, pkgs/products/{name} in monorepo)
        #[arg(long, required = true)]
        working_dir: String,

        /// Target environment (e.g., staging, production)
        #[arg(long, default_value = "staging")]
        env: String,

        /// Dry run - print SQL without executing
        #[arg(long)]
        dry_run: bool,
    },

    /// Remove seeded test profiles from an environment
    Unseed {
        /// Product root directory (repo root for standalone products, pkgs/products/{name} in monorepo)
        #[arg(long, required = true)]
        working_dir: String,

        /// Target environment (e.g., staging, production)
        #[arg(long, default_value = "staging")]
        env: String,

        /// Dry run - print SQL without executing
        #[arg(long)]
        dry_run: bool,
    },

    /// Ruby gem operations (build, push to RubyGems.org)
    Gem {
        #[command(subcommand)]
        command: GemCommands,
    },

    /// Helm chart operations
    Helm {
        #[command(subcommand)]
        command: HelmCommands,
    },

    /// Verify deployment health after release
    /// Checks health endpoint and GraphQL introspection
    PostDeployVerify {
        /// Environment (staging, production)
        #[arg(long, required = true)]
        environment: String,

        /// Service name
        #[arg(long, required = true)]
        service: String,

        /// Product domain for URL derivation (e.g., "myapp.io")
        /// If provided, derives health/graphql URLs automatically
        #[arg(long)]
        domain: Option<String>,

        /// Health endpoint URL (overrides domain-based derivation)
        #[arg(long)]
        health_url: Option<String>,

        /// GraphQL endpoint URL (overrides domain-based derivation)
        #[arg(long)]
        graphql_url: Option<String>,

        /// Timeout in seconds
        #[arg(long, default_value = "30")]
        timeout: u64,

        /// Number of retries for health check
        #[arg(long, default_value = "3")]
        retries: u32,
    },
}

/// Bootstrap subcommands
#[derive(Subcommand)]
pub enum BootstrapCommands {
    /// Push a single bootstrap binary to GHCR
    Push {
        /// Bootstrap binary name (postgres-bootstrap, dragonfly-bootstrap, openbao-bootstrap)
        #[arg(long, required = true)]
        binary: String,

        /// GHCR token (or set GHCR_TOKEN env var)
        #[arg(long, env = "GHCR_TOKEN")]
        token: Option<String>,

        /// Number of retry attempts
        #[arg(long, default_value = "3")]
        retries: u32,

        /// Skip building, use existing image
        #[arg(long)]
        skip_build: bool,

        /// Path to existing image (required if --skip-build)
        #[arg(long)]
        image_path: Option<String>,
    },

    /// Push all bootstrap binaries to GHCR
    PushAll {
        /// GHCR token (or set GHCR_TOKEN env var)
        #[arg(long, env = "GHCR_TOKEN")]
        token: Option<String>,

        /// Number of retry attempts
        #[arg(long, default_value = "3")]
        retries: u32,

        /// Build and push in parallel
        #[arg(long)]
        parallel: bool,
    },

    /// List available bootstrap binaries
    List,

    /// Regenerate Cargo.nix for bootstrap workspace
    Regenerate {
        /// Bootstrap directory path (or set SERVICE_DIR env var)
        #[arg(long)]
        bootstrap_dir: Option<String>,
    },

    /// Release bootstrap binaries (push + update K8s manifests + git commit)
    Release {
        /// Product name
        #[arg(long, required = true)]
        product: String,

        /// Environment (staging, production)
        #[arg(long, default_value = "production")]
        environment: String,

        /// Cluster name
        #[arg(long)]
        cluster: Option<String>,

        /// GHCR token (or set GHCR_TOKEN env var)
        #[arg(long, env = "GHCR_TOKEN")]
        token: Option<String>,

        /// Number of retry attempts
        #[arg(long, default_value = "3")]
        retries: u32,

        /// Skip git commit/push (for testing)
        #[arg(long)]
        skip_git: bool,
    },
}

/// Pangea subcommands
#[derive(Subcommand)]
pub enum PangeaCommands {
    /// Push a pangea component to GHCR
    Push {
        /// Component name (operator, cli, web)
        #[arg(long, required = true)]
        component: String,

        /// GHCR token (or set GHCR_TOKEN env var)
        #[arg(long, env = "GHCR_TOKEN")]
        token: Option<String>,

        /// Number of retry attempts
        #[arg(long, default_value = "3")]
        retries: u32,

        /// Skip building, use existing image
        #[arg(long)]
        skip_build: bool,

        /// Path to existing image (required if --skip-build for operator/cli)
        #[arg(long)]
        image_path: Option<String>,
    },

    /// Push all pangea components to GHCR
    PushAll {
        /// GHCR token (or set GHCR_TOKEN env var)
        #[arg(long, env = "GHCR_TOKEN")]
        token: Option<String>,

        /// Number of retry attempts
        #[arg(long, default_value = "3")]
        retries: u32,

        /// Build and push in parallel
        #[arg(long)]
        parallel: bool,
    },

    /// List available pangea components
    List,

    /// Regenerate Cargo.nix for pangea workspace (Rust components)
    Regenerate {
        /// Pangea directory path (or set SERVICE_DIR env var)
        #[arg(long)]
        pangea_dir: Option<String>,
    },

    /// Regenerate gemset.nix for pangea compiler (Ruby)
    RegenerateCompiler,
}

/// Ruby gem subcommands
#[derive(Subcommand)]
pub enum GemCommands {
    /// Build a .gem file from a gemspec
    Build {
        /// Working directory (where *.gemspec lives)
        #[arg(long, default_value = ".")]
        working_dir: String,

        /// Gem name (must match <name>.gemspec). Auto-detected if only one gemspec exists.
        #[arg(long)]
        name: Option<String>,
    },

    /// Bump gem version (patch, minor, or major)
    Bump {
        /// Working directory (where *.gemspec lives)
        #[arg(long, default_value = ".")]
        working_dir: String,

        /// Version bump level
        #[arg(long, default_value = "patch")]
        level: String,

        /// Gem name (auto-detected from gemspec if omitted)
        #[arg(long)]
        name: Option<String>,
    },

    /// Build and push a gem to RubyGems.org
    Push {
        /// Working directory (where *.gemspec lives)
        #[arg(long, default_value = ".")]
        working_dir: String,

        /// Gem name (must match <name>.gemspec). Auto-detected if only one gemspec exists.
        #[arg(long)]
        name: Option<String>,

        /// RubyGems API key (or set GEM_HOST_API_KEY env var)
        #[arg(long, env = "GEM_HOST_API_KEY")]
        api_key: Option<String>,

        /// OTP code for multi-factor authentication
        #[arg(long)]
        otp: Option<String>,
    },
}

/// Helm chart subcommands
#[derive(Subcommand)]
pub enum HelmCommands {
    /// Package a Helm chart into a .tgz tarball
    Package {
        /// Chart directory (e.g., charts/pleme-microservice)
        #[arg(long, required = true)]
        chart_dir: String,

        /// Output directory for the packaged chart
        #[arg(long, default_value = "dist")]
        output: String,

        /// Chart version override (default: read from Chart.yaml)
        #[arg(long)]
        version: Option<String>,
    },

    /// Push a packaged chart to OCI registry
    Push {
        /// Path to chart .tgz tarball
        #[arg(long, required = true)]
        chart: String,

        /// OCI registry URL
        #[arg(long, default_value = "oci://ghcr.io/pleme-io/charts")]
        registry: String,
    },

    /// Deploy a service by updating HelmRelease image tag in k8s repo
    Deploy {
        /// Service name
        #[arg(long, required = true)]
        service: String,

        /// Image tag to deploy
        #[arg(long, required = true)]
        image_tag: String,

        /// Path to k8s repo
        #[arg(long, default_value = "../k8s")]
        k8s_repo: String,

        /// Target environment (staging, production)
        #[arg(long, default_value = "staging")]
        environment: String,

        /// Commit and push changes to git
        #[arg(long)]
        commit: bool,

        /// Watch FluxCD reconciliation after deploy
        #[arg(long)]
        watch: bool,
    },

    /// Full chart lifecycle: lint, package, push
    Release {
        /// Chart directory
        #[arg(long, required = true)]
        chart_dir: String,

        /// OCI registry URL
        #[arg(long, default_value = "oci://ghcr.io/pleme-io/charts")]
        registry: String,

        /// Chart version override
        #[arg(long)]
        version: Option<String>,
    },

    /// Lint a chart (helm lint + helm template validation)
    Lint {
        /// Chart directory
        #[arg(long, required = true)]
        chart_dir: String,
    },

    /// Render chart templates for debugging
    Template {
        /// Chart directory
        #[arg(long, required = true)]
        chart_dir: String,

        /// Values file to use
        #[arg(long)]
        values: Option<String>,

        /// Set individual values (key=value)
        #[arg(long)]
        set: Vec<String>,
    },
}
