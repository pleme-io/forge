# Forge

Deployment orchestrator for Nix-based service infrastructure. Replaces fragile bash scripts with a type-safe Rust CLI that handles the full lifecycle: build, push, deploy, rollback, test, and release.

## Overview

Forge is the glue between Nix builds, container registries, Kubernetes, and FluxCD. It provides:

- **Nix build orchestration** with [Attic](https://github.com/zhaofengli/attic) binary cache integration for per-derivation caching
- **Container image push** to OCI registries (GHCR, etc.) via skopeo with retry logic
- **GitOps deployment** — updates kustomization manifests, commits, pushes, and triggers FluxCD reconciliation
- **Rollout monitoring** — watches Kubernetes rollouts with pod failure detection and automatic log capture
- **Release pipelines** — orchestrated multi-step workflows (build, push, deploy, migrate, verify)
- **Infrastructure provisioning** — YAML-driven PostgreSQL and Attic cache setup via `forge-provision`

## Structure

```
forge/
  cli/            Rust CLI — the main forge binary
  provision/
    forge-provision/   Infrastructure provisioning tool + nix-builder entrypoint
    attic/             Attic cache provisioning (dev shell)
    postgres/          PostgreSQL provisioning (dev shell)
  lib/            Nix utility libraries (error handling, platform detection, Attic helpers)
  flake.nix       Root flake — builds CLI, provision image, regen/release apps
```

## Building

Requires [Nix](https://nixos.org/) with flakes enabled.

```bash
# Build the CLI
nix build .#forge-cli

# Run directly
nix run .#forge-cli -- --help

# Regenerate Cargo.nix after dependency changes
nix run .#regen:cli
nix run .#regen:provision
```

The provision image (`forge-provision-image`) and binary (`forge-provision`) are Linux-only:

```bash
# On a Linux builder
nix build .#forge-provision
nix build .#forge-provision-image

# Push provision image to registry
nix run .#release:provision
```

## CLI Commands

### Core Workflow

| Command | Description |
|---------|-------------|
| `build` | Build a Docker image with Nix, optionally push closure to Attic cache |
| `push` | Push image to a container registry with auto-tagging (`{arch}-{sha}`, `{arch}-latest`) |
| `deploy` | Full GitOps deployment: build, push, update manifest, commit, reconcile |
| `rollout` | Monitor a Kubernetes rollout with failure detection |
| `rollback` | Rollback a deployment to a previous image tag |

### Release Pipelines

| Command | Description |
|---------|-------------|
| `orchestrate-release` | Full pipeline: push, deploy, migrate, update federation, verify |
| `product-release` | Multi-service product release across environments |
| `comprehensive-release` | Build + test + push + deploy with integration testing |
| `prerelease` | Pre-release verification and staging deployment |

### Rust Service Commands

| Command | Description |
|---------|-------------|
| `push-rust-service` | Push a Rust service image to GHCR |
| `deploy-rust-service` | Deploy a Rust service via GitOps |
| `rust-test` | Run Rust tests |
| `rust-lint` | Run clippy lints |
| `rust-fmt` / `rust-fmt-check` | Format or check Rust code |
| `rust-extract-schema` | Extract GraphQL schema from a running service |
| `rust-update-cargo-nix` | Regenerate Cargo.nix |
| `rust-dev` / `rust-dev-down` | Start/stop local development infrastructure |

### Testing

| Command | Description |
|---------|-------------|
| `test` | Run the full test pyramid |
| `test-unit` | Unit tests only |
| `test-integration` | Integration tests with database |
| `test-e2e` | End-to-end browser tests |
| `e2e-prepare` / `e2e-run` | Prepare and run E2E test suites |

### Infrastructure

| Command | Description |
|---------|-------------|
| `run-migrations` | Execute database migrations via Shinka |
| `flux-reconcile` | Trigger FluxCD reconciliation |
| `nix-builder-verify` | Verify nix-builder image |
| `nix-builder-test` | Run tests inside a nix-builder container |
| `nix-builder-release` | Release a new nix-builder image |
| `status` | Show deployment status across environments |

### Code Generation

| Command | Description |
|---------|-------------|
| `codegen` | Generate GraphQL types and hooks |
| `sync` | Sync generated code (schema, types, hooks) |
| `web-regenerate` | Regenerate web frontend code |
| `bootstrap` | Bootstrap a new service or regenerate Cargo.nix |

## Configuration

### deploy.yaml

Forge reads service configuration from a `deploy.yaml` file:

```yaml
service:
  name: my-service
  type: rust

registry:
  host: ghcr.io
  organization: your-org
  project: your-project

cache:
  server: your-attic-server
  name: your-cache

manifests:
  kustomization: path/to/kustomization.yaml
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `ATTIC_TOKEN` | Attic binary cache authentication token | Falls back to K8s secret lookup |
| `ATTIC_CACHE_URL` | Attic server URL | `http://localhost:8080` |
| `ATTIC_CACHE_NAME` | Attic cache name | `cache` |
| `ATTIC_SERVER_NAME` | Attic server alias for login/use commands | `default` |
| `GHCR_TOKEN` | GitHub Container Registry token | Falls back to `gh` CLI token |
| `FORGE_REGISTRY` | Container registry base URL | — |
| `FORGE_REGISTRY_USER` | Registry username | — |

## forge-provision

YAML-driven infrastructure provisioning tool packaged in the `forge-utilities` container image.

### PostgreSQL Provisioning

```bash
export APP_USER_PASSWORD="your-secure-password"
forge-provision postgres provision --config /config/db-config.yaml
```

Provisions databases, users, extensions, schema permissions, and optional CDC replication — all idempotent and type-safe.

### Attic Cache Provisioning

```bash
forge-provision attic provision --config /config/attic-config.yaml
```

Sets up Attic binary caches with authentication tokens.

## Nix Library

The `lib/` directory provides reusable Nix functions consumed by other flakes:

- `errors` — Structured error types and formatting
- `errorReporter` — Error aggregation and reporting
- `platform` — Platform detection and system helpers
- `performance` — Build performance tracking
- `flakeInputs` — Flake input validation and management
- `attic` — Attic binary cache configuration helpers

Access via `forge.lib.errors`, `forge.lib.platform`, etc.

## License

[MIT](LICENSE)
