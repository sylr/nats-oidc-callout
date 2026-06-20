{
  description = "A Nix-flake-based for nats-jwt-callout";

  inputs = {
    nixpkgs.url = "https://flakehub.com/f/NixOS/nixpkgs/0.2605";
    nixpkgs-unstable.url = "https://flakehub.com/f/NixOS/nixpkgs/0.1";
  };

  outputs = { self, nixpkgs, nixpkgs-unstable }:
    let
      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forEachSupportedSystem = f:
        nixpkgs.lib.genAttrs supportedSystems (system:
          let
            pkgs = import nixpkgs {
              inherit system;
              config.allowUnfree = false;
            };
            pkgs-unstable = import nixpkgs-unstable {
              inherit system;
              config.allowUnfree = false;
            };
          in
          f { pkgs = pkgs; pkgs-unstable = pkgs-unstable; system = system; }
        );

      archMap = {
        "x86_64-linux"   = "linux-amd64";
        "aarch64-linux"  = "linux-arm64";
        "x86_64-darwin"  = "darwin-amd64";
        "aarch64-darwin" = "darwin-arm64";
      };

      githubBinaries = {};
    in
    {
      devShells = forEachSupportedSystem ({ pkgs, pkgs-unstable, system }:
        let
          mkGithubBinary = name: spec:
            let
              specArchMap = if spec ? archMap then spec.archMap else archMap;
            in pkgs.stdenv.mkDerivation {
            pname = name;
            version = spec.version;
            src = pkgs.fetchurl {
              url = spec.url spec.version specArchMap.${system};
              sha256 = spec.sha256.${system};
            };
            dontUnpack = true;
            installPhase = if spec ? archMap then ''
              mkdir -p $out/bin
              tar -xzf $src -C $TMPDIR
              find $TMPDIR/${name}/ -maxdepth 1 -type f -perm -u+x -exec cp {} $out/bin/ \;
            '' else ''
              mkdir -p $out/bin
              cp $src $out/bin/${name}
              chmod +x $out/bin/${name}
            '';
          };

          stablePackages = with pkgs; [
            gh
            go_1_26     # bootstrap; go.mod's `go 1.26.4` directive selects the exact toolchain
            goreleaser  # release-config check (ci goreleaser-check)
            kind        # k8s e2e: spins up the ephemeral cluster (test/k8s/run.sh)
            kubectl     # k8s e2e: applies manifests, waits on the client jobs
            trufflehog
          ];
          unstablePackages = with pkgs-unstable; [
            awscli2
            golangci-lint
          ];
          otherPackages = nixpkgs.lib.mapAttrsToList mkGithubBinary githubBinaries;
          allPackages = stablePackages ++ unstablePackages ++ otherPackages;
        in
        {
          default = pkgs.mkShell {
            packages = allPackages;
            shellHook = ''
              uv sync
              export VIRTUAL_ENV=$(realpath .venv)
              layout python3
              pre-commit install-hooks
            '';
          };

          # Non-interactive shell with the identical toolchain, used by CI via
          # `nix develop .#ci --command ...`. Omits the default shell's direnv-only
          # hook (uv sync / layout / pre-commit) so CI gets just the pinned tools.
          ci = pkgs.mkShell {
            packages = allPackages;
          };
        }
      );
    };
}
