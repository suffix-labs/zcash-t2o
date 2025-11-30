{
  description = "zcash-t2o: Transparent-to-Orchard PCZT Library for Go";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
      in
      {
        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            go
            gopls
            golangci-lint
            golangci-lint-langserver
            delve
            rustc
            cargo
            rust-analyzer
            lldb
            pkg-config
            gcc
            zcash
          ];

          shellHook = ''
            export CGO_ENABLED=1
          '';
        };
      }
    );
}
