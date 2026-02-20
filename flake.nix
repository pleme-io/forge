{
  description = "Forge - Build, push, and deploy platform for Nix-based services";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/d6c71932130818840fc8fe9509cf50be8c64634f";

    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    substrate = {
      url = "github:pleme-io/substrate";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.fenix.follows = "fenix";
    };

    # Kept as a flake (not flake=false) for the crate2nix binary used by regen apps.
    # Substrate captures its own crate2nix source internally for builders.
    crate2nix = {
      url = "github:nix-community/crate2nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, fenix, substrate, crate2nix, flake-utils, ... }:
    flake-utils.lib.eachSystem [ "aarch64-darwin" "x86_64-linux" "aarch64-linux" ] (system: let
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
        (import ./provision/forge-provision/Cargo.nix { inherit pkgs; }).rootCrate.build
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

      crate2nixBin = crate2nix.packages.${system}.default;

    in {
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
      apps = {
        "regen:cli" = {
          type = "app";
          program = toString (pkgs.writeShellScript "regen-forge-cli" ''
            set -euo pipefail
            cd "$(${pkgs.git}/bin/git rev-parse --show-toplevel)/cli"
            ${crate2nixBin}/bin/crate2nix generate
          '');
        };

        "regen:provision" = {
          type = "app";
          program = toString (pkgs.writeShellScript "regen-forge-provision" ''
            set -euo pipefail
            cd "$(${pkgs.git}/bin/git rev-parse --show-toplevel)/provision/forge-provision"
            ${crate2nixBin}/bin/crate2nix generate
          '');
        };
      } // pkgs.lib.optionalAttrs (forgeProvisionImage != null) {
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
    }) // {
      # ── Cross-cutting Nix utilities (system-independent) ───────
      lib = {
        errors = import ./lib/errors.nix;
        errorReporter = import ./lib/error-reporter.nix;
        platform = import ./lib/platform.nix;
        performance = import ./lib/performance.nix;
        flakeInputs = import ./lib/flake-inputs.nix;
        attic = import ./lib/attic.nix;
      };
    };
}
