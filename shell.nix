{ system ? builtins.currentSystem }:
let
  pkgsSrc = fetchTarball {
    url = "https://github.com/NixOS/nixpkgs/archive/a1007637cea374bd1bafd754cfd5388894c49129.tar.gz";
    sha256 = "sha256:0qnnrn2ahlvxgamwybjafdafaj8mjs6dl91ml5b8bh1v9aj313vl";
  };
  devshellSrc = fetchTarball {
    url = "https://github.com/numtide/devshell/archive/26f25a12265f030917358a9632cd600b51af1d97.tar.gz";
    sha256 = "sha256:0f6fph5gahm2bmzd399mba6b0h6wp6i1v3gryfmgwp0as7mwqpj7";
  };
  pkgs = import pkgsSrc { };
  devshell = import devshellSrc { inherit system pkgs; };
in
with pkgs;
let
  LDFLAGS = lib.optionalString stdenv.isLinux "-L${glibc.out}/lib -Wl,-rpath ${glibc.out}/lib";
in
devshell.mkShell {
  name = "magiloop-saas";

  imports = lib.optionals stdenv.isLinux [
    (import "${devshell.extraModulesDir}/locale.nix")
  ];

  packages = [
    python39Packages.pip
    python39Full
    pebble
    minio
    go
  ] ++ lib.optionals stdenv.isLinux [ gcc-unwrapped binutils ];

  env = [
    {
      name = "PEBBLE_VA_NOSLEEP";
      value = "1";
    }
    {
      name = "PYTHONPATH";
      eval = "$PWD/src";
    }
    {
      name = "MINIO_ACCESS_KEY";
      eval = "minio_test_access_key";
    }
    {
      name = "MINIO_SECRET_KEY";
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
  ] ++ lib.optionals (stdenv.isLinux) [
    {
      name = "LIBRARY_PATH";
      eval = ''"${glibc.out}/lib"'';
    }
  ] ++ lib.optionals (stdenv.isDarwin) [
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
  ];
}
