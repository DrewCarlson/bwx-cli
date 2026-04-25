{
  description = "bwx-cli — Unofficial Bitwarden CLI with first-class macOS support";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        inherit (pkgs) lib stdenv;

        # Read package metadata from Cargo.toml so a version bump only
        # needs editing in one place.
        cargoToml = builtins.fromTOML (builtins.readFile ./Cargo.toml);

        bwx-cli = pkgs.rustPlatform.buildRustPackage {
          pname = "bwx-cli";
          version = cargoToml.package.version;
          src = ./.;

          cargoLock = {
            lockFile = ./Cargo.lock;
          };

          nativeBuildInputs = with pkgs; [ pkg-config installShellFiles ];
          buildInputs = lib.optionals stdenv.isDarwin (with pkgs.darwin.apple_sdk.frameworks; [
            CoreFoundation Security LocalAuthentication
          ]);

          # The e2e tests need a vaultwarden binary on PATH; skip them
          # in the Nix sandbox. Keep the unit tests.
          checkFlags = [ "--lib" ];

          postInstall = ''
            installShellCompletion --cmd bwx \
              --bash <($out/bin/bwx gen-completions bash) \
              --zsh  <($out/bin/bwx gen-completions zsh)  \
              --fish <($out/bin/bwx gen-completions fish)
          '';

          meta = with lib; {
            description = cargoToml.package.description;
            homepage = cargoToml.package.repository;
            license = licenses.mit;
            mainProgram = "bwx";
            platforms = platforms.unix;
          };
        };
      in {
        packages = {
          default = bwx-cli;
          bwx-cli = bwx-cli;
        };

        apps.default = flake-utils.lib.mkApp {
          drv = bwx-cli;
          exePath = "/bin/bwx";
        };

        devShells.default = pkgs.mkShell {
          inputsFrom = [ bwx-cli ];
          packages = with pkgs; [
            cargo-deny cargo-deb cargo-generate-rpm clippy rustfmt
            pinentry  # so `bwx unlock` has a UI inside the dev shell
          ];
        };
      });
}
