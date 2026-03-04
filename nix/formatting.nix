{ inputs, ... }:
{
  imports = [ inputs.treefmt-nix.flakeModule ];

  perSystem =
    { pkgs, ... }:
    {
      treefmt = {
        projectRootFile = "flake.nix";
        settings.global.excludes = [
          "**/*.txt"
          "**/*.gitignore"
        ];
        programs = {
          nixfmt.enable = true;
          jsonfmt.enable = true;
          shfmt.enable = true;
          taplo.enable = true;

          # Nightly rustfmt has support for more quality-of-life formatting
          # configuration options that aren't available in stable.
          rustfmt = {
            enable = true;
            package = pkgs.rust-bin.nightly.latest.rustfmt;
          };

          # Configure Prettier to handle Markdown and YAML
          prettier = {
            enable = true;
            includes = [
              "*.md"
              "*.yaml"
              "*.yml"
            ];
          };
        };
      };
    };
}
