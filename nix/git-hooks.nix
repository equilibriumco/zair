{ inputs, ... }:
{
  imports = [ inputs.git-hooks-nix.flakeModule ];

  perSystem =
    {
      pkgs,
      rustToolchainNightly,
      ...
    }:
    let
      # Prefetch cargo dependencies for sandbox builds
      cargoDeps = pkgs.rustPlatform.importCargoLock {
        lockFile = ../Cargo.lock;
        # Forked crates.
        outputHashes = {
          "halo2_gadgets-0.3.1" = "sha256-+1tMFB2w70mJPAiYJboO5rtu0C+rUuPi9qvHf7kk04U=";
          "orchard-0.11.0" = "sha256-jVoOLFAQy1BtaOccQbb+dhrlcX0Jyqy65twuo0d0QlM=";
          "sapling-crypto-0.5.0" = "sha256-UwxRBXEhvlcar4g3mKAirke3/oyFBI9+DHPVpLeb2bQ=";
        };
      };

      # Wrapper script for cargo-audit that skips in Nix sandbox (no network access)
      cargoAuditWrapper = pkgs.writeShellScript "cargo-audit-wrapper" ''
        if [ -n "$NIX_BUILD_TOP" ]; then
          echo "Skipping cargo-audit in Nix sandbox (requires network access)"
          exit 0
        fi
        exec ${pkgs.cargo-audit}/bin/cargo-audit audit
      '';
    in
    {
      # To configure git hooks after you change this file, run:
      # $ nix develop -c pre-commit run -a
      pre-commit = {
        check.enable = true;
        settings = {
          settings.rust.check.cargoDeps = cargoDeps;
          hooks = {
            # markdown (config in .markdownlint.json)
            markdownlint.enable = true;

            # shell
            shellcheck.enable = true;

            # nix
            nixfmt.enable = true;
            flake-checker.enable = true;
            statix = {
              enable = true;
              settings = {
                ignore = [ ".direnv" ];
              };
            };

            # Rust
            cargo-check = {
              enable = true;
              package = rustToolchainNightly;
              entry = "${rustToolchainNightly}/bin/cargo check --all-targets --all-features";
              extraPackages = [ rustToolchainNightly ];
            };

            cargo-test = {
              enable = true;
              name = "cargo test";
              entry = "${rustToolchainNightly}/bin/cargo test";
              files = "\\.rs$";
              pass_filenames = false;
              extraPackages = [ rustToolchainNightly ];
            };

            # Check for security vulnerabilities
            # Skipped in Nix sandbox (requires network access to fetch advisory database)
            cargo-audit = {
              enable = true;
              name = "cargo-audit";
              entry = "${cargoAuditWrapper}";
            };

            # Check for unused dependencies
            cargo-machete = {
              enable = true;
              name = "cargo-machete";
              entry = "${pkgs.cargo-machete}/bin/cargo-machete";
            };

            # Rust linter
            clippy = {
              enable = true;
              packageOverrides = {
                cargo = rustToolchainNightly;
                clippy = rustToolchainNightly;
              };
              settings = {
                allFeatures = true;
                denyWarnings = true;
                extraArgs = "--all-targets";
              };
            };

            # secret detection
            ripsecrets.enable = true;
            trufflehog.enable = true;

            # spell checker (config in typos.toml)
            typos.enable = true;

            # toml
            taplo.enable = true;

            # yaml
            yamllint.enable = true;
          };
        };
      };
    };
}
