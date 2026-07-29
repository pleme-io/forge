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

    # Follow substrate's PINNED devenv rather than carrying our own URL.
    # substrate's flake is explicit that this is the fleet source of truth,
    # and that recent devenv revs (bc8b216 / c429c11 / c58faa9) EVAL-FAIL on
    # this nixpkgs pin — a3ebee0 is the known-good rev. Carrying an unpinned
    # `github:cachix/devenv` floated us straight onto a broken one, which is
    # why `nix flake check` died with:
    #   error: Failed assertions:
    #   - devenv was not able to determine the current directory.
    # and why forge CI has been red since 2026-07-17.
    devenv.follows = "substrate/devenv";

    # Required BY devenv's own containers module, which is instantiated the
    # moment `inputs.devenv.flakeModule` is imported below. Without them
    # `nix flake check` fails with devenv's own instruction:
    #   error: To use 'containers', Add the following to flake.nix:
    #   inputs.nix2container.url = "github:nlewo/nix2container";
    #   inputs.mk-shell-bin.url  = "github:rrbutani/nix-mk-shell-bin";
    #
    # forge is the only pleme-io repo that imports devenv.flakeModule —
    # substrate declares devenv but merely EXPORTS devenvModules, and
    # iac-forge passes devenv into substrate's builder. Neither instantiates
    # the container module, which is why neither needs these and why this
    # failure was forge-only. The import is legitimate, not a deviation: it
    # is how forge consumes substrate's exported devenvModules.rust.
    #
    # Both follow our nixpkgs so no second nixpkgs enters the closure.
    nix2container = {
      url = "github:nlewo/nix2container";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    mk-shell-bin.url = "github:rrbutani/nix-mk-shell-bin";

    # Required BY devenv's own Rust module, for the same reason as the two
    # above: substrate's `lib/devenv/rust.nix` sets `languages.rust.channel
    # = "stable"`, and devenv resolves any non-`nixpkgs` channel through
    # `config.lib.getInput { name = "rust-overlay"; }`, which reads the ROOT
    # flake's inputs — devenv having its own `rust-overlay` in the lock does
    # not satisfy it. Without this, instantiating the devenv shell throws
    # devenv's own instruction:
    #   error: To use 'languages.rust.channel', Add the following to flake.nix:
    #   inputs.rust-overlay.url = "github:oxalica/rust-overlay";
    #
    # This was invisible because `nix flake check` NEVER FORCES a devShell's
    # drvPath — it prints "✅ devShells.<sys>.default (build skipped)" while
    # the shell is un-instantiable. Measured 2026-07-28 on this tree:
    #   nix flake check --impure                        → ✅ (build skipped)
    #   nix eval --impure .#devShells.…default.drvPath  → the throw above
    # A green flake check is not evidence a devShell can be entered.
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
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
        # ── devShells ────────────────────────────────────────────
        #
        # TWO shells, and the split is the whole point.
        #
        # `default` is a PLAIN substrate `mkRustDevShell` because the thing
        # that enters it is CI: substrate's `nix-devshell-cargo-test.yml`
        # runs `nix develop .#default --command cargo test`, purely and
        # non-interactively. A devenv shell CANNOT satisfy that, and not for
        # a fixable reason — devenv's `top-level.nix` asserts
        # `flakesIntegration -> devenv.root != ""`, and `devenv.root` is
        # read from the environment, so under pure eval it is `""` and the
        # shell aborts before anything else is considered:
        #   error: Failed assertions:
        #   - devenv was not able to determine the current directory.
        # That is devenv working as designed (its own flakes guide says use
        # `--impure`), so no input, pin or option here can make a devenv
        # `default` enterable by the CI leg. Measured on this tree
        # 2026-07-28: pure `nix develop .#` hit the assertion above; the
        # same command with `--impure` got PAST it and then hit the missing
        # `rust-overlay` input — two independent faults, in that order.
        #
        # THE TRADE, stated rather than hidden: `nix develop` with no
        # argument no longer gives the devenv environment (git-hooks
        # clippy/rustfmt, `devenv up`, cargo-edit, RUST_LOG=debug). That
        # environment is NOT removed — it is `nix develop .#devenv --impure`
        # below, and it is now actually instantiable, which it was not
        # before this commit in either eval mode.
        devShells.default = substrateLib.mkRustDevShell {
          extraPackages = with pkgs; [ cmake perl git openssl ];
        };

        # The interactive shell, kept in full (MODULARIZE, DON'T DELETE).
        # Renamed off `default` only so CI stops trying to enter it.
        # Requires `--impure` — see the assertion above.
        #
        # Peeling the pure-eval assertion off this shell exposed a STACK of
        # faults underneath it, each of which had been masked by the one in
        # front. In the order they surfaced, 2026-07-28:
        #   1. pure eval        → the devenv.root assertion (structural)
        #   2. + --impure       → missing `rust-overlay` input (fixed above)
        #   3. + rust-overlay   → on DARWIN ONLY, substrate's own
        #      `lib/devenv/rust.nix` reads `pkgs.darwin.apple_sdk.frameworks`,
        #      which this nixpkgs has removed:
        #        error: darwin.apple_sdk_11_0 has been removed as it was a
        #        legacy compatibility stub
        #      That is a SUBSTRATE defect, not forge's, and is left for
        #      substrate to fix rather than forked here (Op-Principle #1).
        #      The Linux arms are unaffected.
        #   4. on every system  → the line removed below.
        #
        # (4) was ours: this shell used to set `env.RUST_SRC_PATH` itself,
        # which collides with the definition devenv's own Rust module
        # already makes, so the module system refused to merge them:
        #   error: The option `…devenv.shells.<n>.env.RUST_SRC_PATH' has
        #   conflicting definition values
        # devenv's value is also the more correct one — it points at the
        # real `rust-src` component of the toolchain it installed, whereas
        # ours pointed into `pkgs.fenixRustToolchain or ""` and would have
        # silently become the string "/lib/rustlib/…" had the overlay ever
        # been absent. Deleting ours is the fix; there is nothing to keep.
        devenv.shells.devenv = {
          imports = [ "${substrate}/lib/devenv/rust.nix" ];

          packages = with pkgs; [
            cmake perl git
          ];
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
