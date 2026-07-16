{
  description = "Forge - Build, push, and deploy platform for Nix-based services";

  inputs = {
    nixpkgs.follows = "substrate/nixpkgs";

    flake-parts = {
      url = "github:hercules-ci/flake-parts";
      inputs.nixpkgs-lib.follows = "nixpkgs";
    };

    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    devenv = {
      url = "github:cachix/devenv";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    substrate = {
      url = "github:pleme-io/substrate";
      inputs.fenix.follows = "fenix";
    };
  };

  outputs = inputs @ { self, nixpkgs, flake-parts, fenix, substrate, devenv, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      imports = [ inputs.devenv.flakeModule ];
      systems = [ "aarch64-darwin" "x86_64-linux" "aarch64-linux" ];

      perSystem = { system, ... }: let
        # Apply substrate's Rust overlay for consistent fenix-based buildRustCrate
        rustOverlay = import "${substrate}/lib/rust-overlay.nix";
        pkgs = import nixpkgs {
          inherit system;
          config.allowUnfree = true;
          overlays = [ (rustOverlay.mkRustOverlay { inherit fenix system; }) ];
        };

        substrateLib = substrate.libFor {
          inherit pkgs system;
          fenix = fenix.packages.${system};
        };

        isLinux = pkgs.lib.hasSuffix "-linux" system;

        # ── forge CLI ────────────────────────────────────────────────
        # gen-cargo DELTA-ONLY: cli/Cargo.gen.lock is the committed sidecar;
        # substrate's lockfile-builder reconstructs Cargo.build-spec.json in
        # pure Nix at eval (useLockfileBuilder defaults to true).
        forgeCli = substrateLib.mkCrate2nixTool {
          toolName = "forge";
          src = ./cli;
          crateOverrides = {
            forge = oldAttrs: {
              nativeBuildInputs = (oldAttrs.nativeBuildInputs or [])
                ++ (with pkgs; [ cmake perl git ]);
            };
          };
        };

        # ── forge-provision (Linux only) ─────────────────────────────
        forgeProvision = if isLinux then
          let
            lockfileBuilder = import "${substrate}/lib/build/rust/lockfile-builder.nix" { inherit pkgs; };
            plemeCrateOverrides = import "${substrate}/lib/build/rust/pleme-crate-overrides.nix";
          in (lockfileBuilder.mkProject {
            src = ./provision/forge-provision;
            defaultCrateOverrides = pkgs.defaultCrateOverrides // plemeCrateOverrides;
          }).rootCrate.build
        else null;

        # ── forge-provision image (Linux only) ───────────────────────
        forgeProvisionImage = if forgeProvision != null then
          pkgs.dockerTools.buildLayeredImage {
            name = "forge-utilities";
            tag = "latest";
            contents = with pkgs; [
              nix git curl jq bash coreutils busybox findutils
              openssh attic-client cachix cacert
              forgeProvision
            ];
            config = {
              Env = [
                "PATH=/root/.nix-profile/bin:/nix/var/nix/profiles/default/bin:/bin:/usr/bin"
                "NIX_PATH=nixpkgs=${pkgs.path}"
                "NIX_SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
              ];
              Cmd = [ "${pkgs.bash}/bin/bash" ];
              WorkingDir = "/workspace";
            };
          }
        else null;

      in {
        # ── devenv shell ─────────────────────────────────────────
        devenv.shells.default = {
          imports = [ "${substrate}/lib/devenv/rust.nix" ];

          packages = with pkgs; [
            cmake perl git
          ];

          env = {
            RUST_SRC_PATH = "${pkgs.fenixRustToolchain or ""}/lib/rustlib/src/rust/library";
          };
        };

        # ── packages ───────────────────────────────────────────────
        packages = {
          forge-cli = forgeCli;
          default = forgeCli;
        } // pkgs.lib.optionalAttrs (forgeProvision != null) {
          forge-provision = forgeProvision;
        } // pkgs.lib.optionalAttrs (forgeProvisionImage != null) {
          forge-provision-image = forgeProvisionImage;
        };

        # ── apps ───────────────────────────────────────────────────
        # Regen apps retired with the crate2nix → gen-cargo migration.
        # Regenerate a build sidecar with `gen build .` in cli/ or
        # provision/forge-provision/ whenever Cargo.lock changes.
        apps = {} // pkgs.lib.optionalAttrs (forgeProvisionImage != null) {
          "release:provision" = {
            type = "app";
            program = toString (pkgs.writeShellScript "release-forge-provision" ''
              set -euo pipefail
              SHORT_SHA=$(${pkgs.git}/bin/git rev-parse --short HEAD)
              ARCH=$(uname -m)
              case "$ARCH" in
                x86_64)  ARCH_TAG="amd64" ;;
                aarch64) ARCH_TAG="arm64" ;;
                *)       ARCH_TAG="$ARCH" ;;
              esac

              REGISTRY="''${FORGE_REGISTRY:?FORGE_REGISTRY must be set}"
              REGISTRY_USER="''${FORGE_REGISTRY_USER:?FORGE_REGISTRY_USER must be set}"
              IMAGE="$REGISTRY/forge-utilities"

              if [ -z "''${GHCR_TOKEN:-}" ]; then
                GHCR_TOKEN=$(cat ~/.config/gh/token 2>/dev/null || true)
              fi

              echo "==> Pushing $IMAGE:$ARCH_TAG-$SHORT_SHA"
              ${pkgs.skopeo}/bin/skopeo copy \
                --dest-creds="$REGISTRY_USER:$GHCR_TOKEN" \
                docker-archive:${forgeProvisionImage} \
                "docker://$IMAGE:$ARCH_TAG-$SHORT_SHA"

              echo "==> Pushing $IMAGE:$ARCH_TAG-latest"
              ${pkgs.skopeo}/bin/skopeo copy \
                --dest-creds="$REGISTRY_USER:$GHCR_TOKEN" \
                docker-archive:${forgeProvisionImage} \
                "docker://$IMAGE:$ARCH_TAG-latest"

              echo "==> Done: $IMAGE"
            '');
          };
        };
      };

      # ── Cross-cutting Nix utilities (system-independent) ───────
      flake = {
        lib = {
          errors = import ./lib/errors.nix;
          errorReporter = import ./lib/error-reporter.nix;
          platform = import ./lib/platform.nix;
          performance = import ./lib/performance.nix;
          flakeInputs = import ./lib/flake-inputs.nix;
          attic = import ./lib/attic.nix;
        };
      };
    };
}
