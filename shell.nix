{ system ? builtins.currentSystem }:
let
  pkgsSrc = fetchTarball {
    url = "https://github.com/NixOS/nixpkgs/archive/e7603eba51f2c7820c0a182c6bbb351181caa8e7.tar.gz";
    sha256 = "0mwck8jyr74wh1b7g6nac1mxy6a0rkppz8n12andsffybsipz5jw";
  };
  devshellSrc = fetchTarball {
    url = "https://github.com/numtide/devshell/archive/5143ea68647c4cf5227e4ad2100db6671fc4c369.tar.gz";
    sha256 = "1g7wh875aywn83cwjr56dwjpqh05g2k346n7zj1yrj1rvm6hj2pn";
  };
  nixpkgs = import pkgsSrc { inherit system; };
  devshell = import devshellSrc { inherit system nixpkgs; };
in
with nixpkgs;
let
  LDFLAGS = lib.optionalString stdenv.isLinux "-L${glibc.out}/lib -Wl,-rpath ${glibc.out}/lib";
in
devshell.mkShell {
  name = "magiloop-saas";

  imports = lib.optionals stdenv.isLinux [
    (import "${devshell.extraModulesDir}/locale.nix")
  ];

  packages = [
    python310Packages.pip
    python310
    pebble
    minio
    go
  ] ++ lib.optionals stdenv.isLinux [
    gcc-unwrapped
    binutils
  ] ++ lib.optionals stdenv.hostPlatform.isDarwin [
    clang
  ];

  env = [
    {
      name = "PEBBLE_VA_NOSLEEP";
      value = "1";
    }
    {
      name = "MINIO_ROOT_USER";
      eval = "minio_test_access_key";
    }
    {
      name = "MINIO_ROOT_PASSWORD";
      eval = "minio_test_secret_key";
    }
    {
      name = "LDFLAGS";
      eval = ''"-L${openssl.out}/lib -Wl,-rpath ${openssl.out}/lib ${LDFLAGS}"'';
    }
    {
      name = "CFLAGS";
      value = "-I${openssl.out.dev}/include";
    }
  ] ++ lib.optionals
    (stdenv.isLinux)
    [
      {
        name = "LIBRARY_PATH";
        eval = ''"${glibc.out}/lib"'';
      }
    ] ++ lib.optionals
    (stdenv.isDarwin)
    [
      {
        name = "TMPDIR";
        value = "/tmp/";
      }
    ];

  commands = [
    {

      help = "dev install";
      name = "dev.install";
      command = "pip install -U pip && pip install -e '.[dev]'";
    }
    {
      name = "download.testcerts";
      command = ''
        curl -z ./fixtures/localhost/cert.pem -o ./fixtures/localhost/cert.pem  https://raw.githubusercontent.com/letsencrypt/pebble/master/test/certs/localhost/cert.pem
        curl -z ./fixtures/localhost/key.pem -o ./fixtures/localhost/key.pem https://raw.githubusercontent.com/letsencrypt/pebble/master/test/certs/localhost/key.pem
      '';
    }
    {
      name = "test.coverage";
      command = ''
        	py.test \
        		--cov=acme_serverless_client \
        		--cov-branch \
        		--cov-context=test
      '';
    }
    {
      name = "lint";
      command = ''
        	flake8 src/
        	isort src/
        	black src/
        	mypy --strict \
        		--allow-untyped-decorators \
        		--follow-imports skip \
        		--warn-unreachable \
        		--allow-any-generics \
        		src/ example/index.py
      '';
    }
  ];
}
