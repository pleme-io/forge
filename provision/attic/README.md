# attic-provision

Attic binary cache provisioning tool for Nix infrastructure.

## What It Does

Declaratively provisions Attic caches:
- Creates caches
- Generates access tokens
- Sets retention policies

Reads from YAML config, uses Attic REST API.

## Usage

### Standalone

```bash
attic-provision --config attic.yaml
attic-provision --config attic.yaml --dry-run  # Preview
```

### As Kubernetes Job

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: provision-attic
spec:
  template:
    spec:
      containers:
        - name: provision
          image: ghcr.io/your-org/attic-provision:latest
          command: ["attic-provision"]
          args: ["--config", "/config/attic.yaml"]
          volumeMounts:
            - name: config
              mountPath: /config
      volumes:
        - name: config
          configMap:
            name: attic-provision-config
```

## Config Format

```yaml
server_url: "http://attic-server.infrastructure.svc.cluster.local"
admin_token: "admin-token-from-secret"

caches:
  - name: "my-project"
    public: false
    retention_period: "30d"

tokens:
  - name: "project-builder"
    cache: "my-project"
    read: true
    write: true
```

## Features

- **Idempotent** - Safe to run multiple times
- **Dry run** - Preview changes
- **YAML config** - Version-controlled
- **REST API** - Direct Attic server communication
- **Token generation** - Outputs JWTs for netrc

## Attic API

Uses Attic server REST endpoints:

- `POST /api/v1/caches` - Create cache
- `POST /api/v1/tokens` - Generate token
- `GET /api/v1/caches` - List caches

Requires admin token for authentication.

## Build

```bash
cd nix/tools/attic-provision
nix build
```

## Environment Variables

- `ATTIC_SERVER_URL` - Attic server URL (override config)
- `ATTIC_ADMIN_TOKEN` - Admin token (from Kubernetes Secret)

## Security

- **Protect admin token** - Use Kubernetes Secrets, never commit
- **Token scope** - Limit read/write per token
- **Private caches** - Set `public: false` for sensitive builds
- **Retention** - Auto-delete old artifacts

## Example: Initial Setup

```bash
# 1. Create admin token on Attic server
kubectl exec -it attic-server-0 -- attic-server create-admin-token

# 2. Create provision config
cat > attic-provision.yaml <<EOF
server_url: "http://attic-server.infrastructure.svc.cluster.local"
admin_token: "token-from-step-1"

caches:
  - name: "my-project"
    public: false
    retention_period: "30d"

tokens:
  - name: "project-builder"
    cache: "my-project"
    read: true
    write: true
EOF

# 3. Run provisioner
attic-provision --config attic-provision.yaml

# 4. Save generated token to Kubernetes Secret
kubectl create secret generic nix-builder-netrc \
  --from-literal=netrc="machine attic-server.infrastructure.svc.cluster.local
login bearer
password <TOKEN_FROM_OUTPUT>"
```

## Cache Retention

Automatic cleanup based on retention policy:

- `7d` - Keep for 7 days
- `30d` - Keep for 30 days
- `90d` - Keep for 90 days
- `never` - Never delete (use for releases)

## When to Use

- **Cluster bootstrap** - Initial Attic setup
- **New product** - Create dedicated cache
- **Token rotation** - Regenerate access tokens
- **Audit** - Review cache configuration

## Related Tools

- **nix-builder** - Uses Attic for binary caching
- **postgres-provision** - Database setup
