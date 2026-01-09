{
  description = "ACME Serverless Client development environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs?ref=nixos-25.11";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        python = pkgs.python310;

        # Helper scripts
        devInstall = pkgs.writeShellScriptBin "dev.install" ''
          uv pip install --no-cache -e '.[dev]'
        '';

        downloadTestcerts = pkgs.writeShellScriptBin "download.testcerts" ''
          curl -z ./fixtures/localhost/cert.pem -o ./fixtures/localhost/cert.pem https://raw.githubusercontent.com/letsencrypt/pebble/master/test/certs/localhost/cert.pem
          curl -z ./fixtures/localhost/key.pem -o ./fixtures/localhost/key.pem https://raw.githubusercontent.com/letsencrypt/pebble/master/test/certs/localhost/key.pem
        '';

        testCoverage = pkgs.writeShellScriptBin "test.coverage" ''
          pytest \
            --cov=acme_serverless_client \
            --cov-branch \
            --cov-context=test \
            -v
        '';

        lint = pkgs.writeShellScriptBin "lint" ''
          ruff check --fix src
          ruff format src
          mypy --strict \
            --allow-untyped-decorators \
            --warn-unreachable \
            --allow-any-generics \
            src/ example/index.py
        '';
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = [
            python
            pkgs.uv
            pkgs.pebble
            pkgs.minio

            # Scripts
            devInstall
            downloadTestcerts
            testCoverage
            lint
          ];

          shellHook = ''
            export VIRTUAL_ENV="$PWD/.venv"
            [[ -d $VIRTUAL_ENV ]] || ${pkgs.lib.getExe pkgs.uv} -q venv --python ${pkgs.lib.getExe python} "$VIRTUAL_ENV"
            export PATH="$VIRTUAL_ENV/bin:$PATH"
            export PEBBLE_VA_NOSLEEP="1"
            export PEBBLE_WFE_NONCEREJECT="0"
            export MINIO_ROOT_USER="minio_test_access_key"
            export MINIO_ROOT_PASSWORD="minio_test_secret_key"
          '';
        };
      }
    );
}
