# postgres-provision

PostgreSQL database provisioning tool for Kubernetes init containers.

## What It Does

Declaratively provisions PostgreSQL:
- Creates users
- Creates databases
- Enables extensions

Reads from YAML config, executes SQL safely.

## Usage

### As Kubernetes Init Container

```yaml
initContainers:
  - name: provision-db
    image: ghcr.io/your-org/postgres-provision:latest
    command: ["postgres-provision"]
    args: ["--config", "/config/provision.yaml"]
    volumeMounts:
      - name: provision-config
        mountPath: /config
```

### Standalone

```bash
postgres-provision --config provision.yaml
postgres-provision --config provision.yaml --dry-run  # Preview
```

## Config Format

```yaml
database_url: "postgres://postgres:password@postgres:5432/postgres"

users:
  - username: "auth_user"
    password: "secure_password"
    superuser: false

databases:
  - name: "auth_db"
    owner: "auth_user"

extensions:
  - name: "uuid-ossp"
    database: "auth_db"
```

## Features

- **Idempotent** - Safe to run multiple times
- **Dry run** - Preview changes before applying
- **YAML config** - Declarative and version-controlled
- **Async** - Fast with sqlx and tokio
- **Typed** - Rust ensures correctness

## Build

```bash
cd nix/tools/postgres-provision
nix build
```

## Environment Variables

Can override config via env:

- `DATABASE_URL` - PostgreSQL connection string
- `POSTGRES_PASSWORD` - Password for user creation

## Security

- **Never commit passwords** - Use Kubernetes Secrets
- **Least privilege** - Don't grant superuser unless needed
- **SSL/TLS** - Use `sslmode=require` in production

## Example: Auth Service Init

```yaml
# In auth-deployment.yaml
initContainers:
  - name: provision-db
    image: ghcr.io/your-org/postgres-provision:latest
    command: ["postgres-provision", "--config", "/config/auth-provision.yaml"]
    env:
      - name: DATABASE_URL
        valueFrom:
          secretKeyRef:
            name: postgres-admin-credentials
            key: url
    volumeMounts:
      - name: provision-config
        mountPath: /config
volumes:
  - name: provision-config
    configMap:
      name: auth-db-provision-config
```

## When to Use

- **Service startup** - Init containers
- **CI/CD** - Automated deployments
- **Local dev** - Consistent setup
- **Disaster recovery** - Rebuild from config

## Related Tools

- **nix-builder** - Remote build infrastructure
- **attic-provision** - Attic cache setup
