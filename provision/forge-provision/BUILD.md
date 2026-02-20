# forge-utilities Build Guide

Docker image for Nix remote builders in Kubernetes.

## Architecture

- **Target**: x86_64-linux only (Kubernetes pods)
- **Platform**: MUST be built on x86_64-linux (plo node)
- **Why**: Cross-compilation from Mac causes "Bus error" due to dynamic linker issues

## What's Inside

1. **Nix 2.39** - Build system and daemon
2. **SSH Server** - Remote builder access
3. **Build Tools** - bash, coreutils, tar, gzip, etc.
4. **Binary Caches** - Attic (self-hosted) + Cachix
5. **FHS Layout** - `/lib64/ld-linux-x86-64.so.2` for dynamic linker
6. **Entrypoint** - Rust binary (`nix-builder-entrypoint`)

## Build Process

### On Linux builder node (REQUIRED)

```bash
# SSH to your x86_64-linux build machine
ssh your-builder-node

# Navigate to forge-utilities
cd ~/forge/provision/forge-provision

# Build and release
nix run .#release
```

This will:
1. Regenerate `Cargo.nix` from `Cargo.lock`
2. Build Docker image with Nix
3. Tag as `amd64-<git-sha>` and `latest`
4. Push to `ghcr.io/your-org/forge-utilities`

### Environment Variables

**GHCR_TOKEN**: GitHub Container Registry token
- Tries `$GHCR_TOKEN` env var
- Falls back to `~/.config/gh/token`
- Error if neither found

## Deployment

After building:

1. Update image tag in Kubernetes manifest:
   ```yaml
   # k8s/clusters/<cluster>/infrastructure/nix-builder/nix-builder-deployment.yaml
   image: ghcr.io/your-org/forge-utilities:amd64-<NEW_SHA>
   ```

2. Commit and push:
   ```bash
   git add k8s/clusters/<cluster>/infrastructure/nix-builder/
   git commit -m "Update nix-builder image to amd64-<NEW_SHA>"
   git push
   ```

3. FluxCD will automatically deploy to cluster

## Why FHS Layout?

The "Bus error" we encountered was caused by missing `/lib64/ld-linux-x86-64.so.2`.

All Linux x86_64 binaries expect the dynamic linker at this path:
```
/lib64/ld-linux-x86-64.so.2 -> /nix/store/.../glibc-2.40-66/lib/ld-linux-x86-64.so.2
```

Without it, every binary fails immediately with "Bus error".

## Troubleshooting

### "Bus error" when running nix

**Cause**: Missing dynamic linker symlink
**Fix**: Ensure `fakeRootCommands` creates `/lib64/ld-linux-x86-64.so.2`

### Cannot build on Mac

**Cause**: This flake is x86_64-linux only
**Solution**: Build on plo node instead

### GHCR authentication failed

**Cause**: Missing GitHub token
**Solution**:
```bash
# Option 1: Set env var
export GHCR_TOKEN=ghp_...

# Option 2: Use gh CLI
gh auth login
```

## Key Files

- `flake.nix` - Main build definition (x86_64-linux only)
- `Cargo.nix` - Rust dependencies (generated from Cargo.lock)
- `src/bin/nix_builder_entrypoint.rs` - Container entrypoint
- `BUILD.md` - This file

## Reference

- Dynamic linker fix: See `fakeRootCommands` in `flake.nix`
- Nix version: Pinned to same commit as main forge flake
- Registry: Your organization's container registry
