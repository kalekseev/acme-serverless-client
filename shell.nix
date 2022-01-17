{ system ? builtins.currentSystem }:
let
  pkgsSrc = fetchTarball {
    url = "https://github.com/NixOS/nixpkgs/archive/bacc31ff571ece62147f3ba70cb6d8d8f483a949.tar.gz";
    sha256 = "1wbgry1as0867bk5mmx3954pya41j34b3g6af4dpah9mh1ai2jc6";
  };
  devshellSrc = fetchTarball {
    url = "https://github.com/numtide/devshell/archive/f87fb932740abe1c1b46f6edd8a36ade17881666.tar.gz";
    sha256 = "10cimkql88h7jfjli89i8my8j5la91zm4c78djqlk22dqrxmm6bs";
  };
  pkgs = import pkgsSrc { inherit system; };
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
    python39
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
  ];
}
