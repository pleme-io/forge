# forge-utilities

**Production-ready Docker image with Nix utilities for Kubernetes Jobs and CI/CD**

Pre-packaged container with infrastructure provisioning tools, binary caches, and system utilities.

## Contents

- **forge-provision** - YAML-driven infrastructure provisioning (PostgreSQL, Attic)
- **nix** - Nix package manager
- **attic** - Attic binary cache client
- **cachix** - Cachix binary cache client
- **git** - Git version control
- **curl** - HTTP client
- **jq** - JSON processor
- **bash** - Bash shell
- **coreutils** - GNU core utilities

## forge-provision CLI

Production-ready, 100% YAML-driven infrastructure provisioning with comprehensive security and validation.

### Features

- ✅ **100% YAML-driven** - All configuration via YAML files
- ✅ **Idempotent** - Safe to run multiple times, won't duplicate resources
- ✅ **Type-safe** - Strongly typed configuration with early validation
- ✅ **Secure** - SQL injection prevention, secure password handling
- ✅ **Production-ready** - Comprehensive logging, retry logic, detailed errors

### PostgreSQL Database Provisioning

**YAML-driven (RECOMMENDED):**

```bash
# Set required environment variables
export APP_USER_PASSWORD="your-secure-password"
export CDC_REPLICATION_PASSWORD="your-replication-password"  # If using CDC

# Run provisioning
forge-provision postgres provision --config /config/db-config.yaml
```

**What gets provisioned:**
- ✅ Database creation (if not exists)
- ✅ Application user with secure password
- ✅ Database ownership grants
- ✅ Extension installation (uuid-ossp, pg_trgm, etc.)
- ✅ Comprehensive schema permissions (current + future objects)
- ✅ CDC replication user (optional)
- ✅ Logical replication publication (optional)
- ✅ Password rotation support

**Basic configuration (no CDC):**

```yaml
# config/db-config.yaml
connection:
  host: "postgres.database.svc.cluster.local"
  port: 5432
  admin_user: "postgres"

database:
  name: "app_db"
  schema: "public"

user:
  name: "app_user"
  password_env: "APP_USER_PASSWORD"

extensions:
  - "uuid-ossp"
  - "pg_trgm"
```

**With CDC configuration:**

```yaml
# config/email-db-config.yaml
connection:
  host: "postgres.database.svc.cluster.local"
  port: 5432
  admin_user: "postgres"

database:
  name: "email_db"
  schema: "email"

user:
  name: "email"
  password_env: "APP_USER_PASSWORD"

extensions:
  - "uuid-ossp"
  - "pg_trgm"

cdc:
  user: "cdc_replication"
  password_env: "CDC_REPLICATION_PASSWORD"
  publication: "cdc_publication"
```

See `examples/` directory for more configuration examples.

### Attic Cache Provisioning

**YAML-driven:**

```bash
# Set required environment variable
export ATTIC_JWT_TOKEN="your-jwt-token"

# Run provisioning
forge-provision attic-cache provision --config /config/cache-config.yaml
```

**Configuration:**

```yaml
# config/attic-cache-config.yaml
cache_name: "my-cache"

server:
  endpoint: "http://attic-cache:80"
  name: "local"

cache:
  is_public: false
  store_dir: "/nix/store"
  priority: 40

token_env: "ATTIC_JWT_TOKEN"
config_dir: "/root/.config/attic"
```

## Kubernetes Integration

### PostgreSQL Init Container (with CDC)

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: email-db-config
data:
  db-config.yaml: |
    connection:
      host: postgres.database.svc.cluster.local
      port: 5432
      admin_user: postgres
    database:
      name: email_db
      schema: email
    user:
      name: email
      password_env: APP_USER_PASSWORD
    extensions:
      - uuid-ossp
      - pg_trgm
    cdc:
      user: cdc_replication
      password_env: CDC_REPLICATION_PASSWORD
      publication: cdc_publication
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: email-service
spec:
  template:
    spec:
      initContainers:
        - name: db-init
          image: ghcr.io/your-org/forge-utilities:latest
          command:
            - forge-provision
            - postgres
            - provision
            - --config
            - /config/db-config.yaml
          env:
            - name: APP_USER_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: email-db-secret
                  key: password
            - name: CDC_REPLICATION_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: cdc-secret
                  key: password
          volumeMounts:
            - name: db-config
              mountPath: /config
      containers:
        - name: email-service
          image: email-service:latest
          # ... rest of container spec
      volumes:
        - name: db-config
          configMap:
            name: email-db-config
```

### Attic Cache Init Job

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: attic-cache-config
data:
  cache-config.yaml: |
    cache_name: "my-cache"
    server:
      endpoint: "http://attic-cache:80"
      name: "local"
    token_env: "ATTIC_JWT_TOKEN"
---
apiVersion: batch/v1
kind: Job
metadata:
  name: attic-cache-setup
spec:
  template:
    spec:
      containers:
        - name: cache-setup
          image: ghcr.io/your-org/forge-utilities:latest
          command:
            - forge-provision
            - attic-cache
            - provision
            - --config
            - /config/cache-config.yaml
          env:
            - name: ATTIC_JWT_TOKEN
              valueFrom:
                secretKeyRef:
                  name: attic-secret
                  key: jwt-token
          volumeMounts:
            - name: cache-config
              mountPath: /config
      restartPolicy: OnFailure
      volumes:
        - name: cache-config
          configMap:
            name: attic-cache-config
```

## Security

### SQL Injection Prevention

Multi-layer defense in depth:
1. **Validation** - PostgreSQL identifiers validated against strict regex
2. **Quoting** - All identifiers properly quoted with double-quote escaping
3. **Parameterization** - Passwords use PostgreSQL's `format('%L')` for secure interpolation

### Password Security

- Passwords **never** logged or printed to console
- Read from environment variables only (not files or arguments)
- Passed securely using PostgreSQL's `format()` function
- Validated non-empty before use
- Support for password rotation (updates on each run)

### Type Safety

- Strongly typed configuration structures with serde
- Early validation with detailed error messages
- Fail-fast on configuration errors
- Comprehensive logging for debugging

## Configuration Reference

See `examples/` directory for complete examples:
- `postgres-basic-config.yaml` - Basic database provisioning
- `postgres-with-cdc-config.yaml` - With CDC support
- `attic-cache-config.yaml` - Attic binary cache

### PostgreSQL Fields

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `connection.host` | string | No | `127.0.0.1` | PostgreSQL host |
| `connection.port` | number | No | `5432` | PostgreSQL port |
| `connection.admin_user` | string | No | `postgres` | Admin user |
| `connection.admin_database` | string | No | `postgres` | Admin database to connect to initially |
| `connection.retry_interval_secs` | number | No | `2` | Retry interval in seconds |
| `connection.max_retry_attempts` | number | No | `30` | Max retry attempts (0 = infinite) |
| `connection.connection_timeout_secs` | number | No | `10` | Connection timeout in seconds |
| `connection.max_connections` | number | No | `2` | Maximum connections in pool |
| `database.name` | string | **Yes** | - | Database name |
| `database.schema` | string | No | `public` | Schema name |
| `user.name` | string | **Yes** | - | Application user |
| `user.password_env` | string | **Yes** | - | Env var with password |
| `extensions` | array | No | `[]` | PostgreSQL extensions |
| `cdc.user` | string | No | `cdc_replication` | CDC user |
| `cdc.password_env` | string | Yes* | - | Env var with CDC password |
| `cdc.publication` | string | No | `cdc_publication` | Publication name |

\* Required if `cdc` block is present

### Attic Cache Fields

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `cache_name` | string | **Yes** | - | Cache name |
| `server.endpoint` | string | No | `http://attic-cache:80` | Server URL |
| `server.name` | string | No | `local` | Server name |
| `cache.is_public` | boolean | No | `false` | Public cache |
| `cache.store_dir` | string | No | `/nix/store` | Store directory |
| `cache.priority` | number | No | `40` | Cache priority (lower = higher priority) |
| `cache.upstream_cache_key_names` | array | No | `[]` | Upstream caches |
| `cache.keypair_strategy` | string | No | `Generate` | Keypair strategy: "Generate" or custom base64 |
| `token_env` | string | **Yes** | - | Env var with JWT |
| `config_dir` | string | No | See below* | Config directory |
| `http_timeout_secs` | number | No | `30` | HTTP request timeout in seconds |
| `http_max_retries` | number | No | `3` | Maximum HTTP retry attempts |
| `http_retry_interval_secs` | number | No | `2` | Retry interval between HTTP attempts |

\* Config directory defaults to:
- `$XDG_CONFIG_HOME/attic` if `XDG_CONFIG_HOME` is set
- `$HOME/.config/attic` if `HOME` is set
- `/tmp/attic` otherwise (works for non-root containers)

## Building & Releasing

### Build Docker Image

```bash
# From repository root
nix build .#forge-utilities

# Or build just the binary
nix build .#forge-provision
```

### Release to GitHub Container Registry

```bash
# From repository root
nix run .#release-forge-utilities
```

This will:
1. Regenerate Cargo.nix (if needed)
2. Build the Docker image
3. Tag with git SHA and `latest`
4. Push to `ghcr.io/your-org/forge-utilities:latest`
5. Push to `ghcr.io/your-org/forge-utilities:<arch>-<git-sha>`

### Regenerate Cargo.nix

After adding or updating Rust dependencies:

```bash
# From repository root
nix run .#regenerate-forge-utilities-cargo
```

## Development

### Project Structure

```
forge-utilities/
├── src/
│   ├── main.rs         # CLI entry point (110 lines)
│   ├── config.rs       # Configuration structures
│   ├── postgres.rs     # PostgreSQL provisioning logic
│   ├── attic.rs        # Attic cache provisioning logic
│   └── validation.rs   # Security validation utilities
├── examples/
│   ├── postgres-basic-config.yaml
│   ├── postgres-with-cdc-config.yaml
│   └── attic-cache-config.yaml
├── Cargo.toml
├── Cargo.nix           # Generated by crate2nix
├── flake.nix
└── README.md
```

### Local Testing

```bash
# Start PostgreSQL for testing
docker run -d -p 5432:5432 -e POSTGRES_PASSWORD=postgres postgres:16

# Build and run
cd nix/tools/forge-utilities
cargo build --release

# Test provisioning
export APP_USER_PASSWORD="test123"
./target/release/forge-provision postgres provision \
  --config examples/postgres-basic-config.yaml
```

## Logging

Control log level with `RUST_LOG` environment variable:

```bash
# Info level (default)
export RUST_LOG=forge_provision=info

# Debug level
export RUST_LOG=forge_provision=debug

# Trace level (very verbose)
export RUST_LOG=forge_provision=trace,sqlx=debug
```

## Troubleshooting

### "Failed to read password from env var"

Ensure environment variables are set:
```bash
export APP_USER_PASSWORD="your-password"
export CDC_REPLICATION_PASSWORD="your-cdc-password"  # If using CDC
```

### "Failed to parse config file"

Validate YAML syntax:
```bash
yamllint your-config.yaml
```

Check that all required fields are present.

### "PostgreSQL is unavailable - retrying"

Normal during startup. The tool automatically waits for PostgreSQL to be ready.
If it persists, check:
- PostgreSQL is running
- Host/port are correct
- Network connectivity

### CDC not working

Ensure PostgreSQL has `wal_level=logical`:
```sql
SHOW wal_level;  -- Should be 'logical'
```

Set in `postgresql.conf`:
```
wal_level = logical
max_wal_senders = 10
max_replication_slots = 10
```

Then restart PostgreSQL.

## Why This Image?

Instead of installing tools on-the-fly in Jobs (slow, unreliable), we pre-package everything:

- ✅ **Faster execution** - No installation step in Jobs
- ✅ **Reproducible** - Pinned package versions via Nix
- ✅ **Cacheable** - Kubernetes pulls image once, reuses
- ✅ **Version controlled** - Git SHA tags for traceability
- ✅ **Type-safe** - Compiled Rust binary with comprehensive validation
- ✅ **Production-ready** - Battle-tested with proper error handling

## Benefits over Shell Scripts

- **Type safety** - Compiled binary catches errors at compile-time
- **Error handling** - Proper retry logic and error messages
- **Logging** - Structured logging with tracing
- **Security** - No shell escaping issues or SQL injection
- **Testable** - Unit tests for validation logic
- **Consistent** - Same behavior across all environments
- **Automatic retries** - Waits for PostgreSQL to be ready
- **Idempotent** - Safe to run multiple times

## License

MIT
