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

          # Per-CI-job shells. Each carries only the tools that job actually
          # runs, so its Cachix pull stays minimal (e.g. ci-k8s-e2e never pulls
          # Go/golangci-lint/goreleaser). Names match the job names in ci.yml.
          # The Go compiler is selected by go.mod's directive (GOTOOLCHAIN); the
          # pinned go here only bootstraps it.
          ci-test = pkgs.mkShell {
            packages = [ pkgs.go_1_26 pkgs-unstable.golangci-lint ];
          };
          ci-github-oidc-e2e = pkgs.mkShell {
            packages = [ pkgs.go_1_26 ];
          };
          ci-goreleaser-check = pkgs.mkShell {
            packages = [ pkgs.goreleaser ];
          };
          ci-k8s-e2e = pkgs.mkShell {
            # Docker comes from the runner; kind/kubectl from Nix.
            packages = [ pkgs.kind pkgs.kubectl ];
          };
        }
      );
    };
}
