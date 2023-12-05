{ pkgs, ... }:

## .envrc
# source_url "https://raw.githubusercontent.com/cachix/devenv/d1f7b48e35e6dee421cfd0f51481d17f77586997/direnvrc" "sha256-YBzqskFZxmNb3kYVoKD9ZixoPXJh1C9ZvTLGFRkauZ0="
# use devenv
# layout python
{
  env.PEBBLE_VA_NOSLEEP = "1";
  env.MINIO_ROOT_USER = "minio_test_access_key";
  env.MINIO_ROOT_PASSWORD = "minio_test_secret_key";

  packages = [
    pkgs.python310Packages.pip
    pkgs.python310
    pkgs.pebble
    pkgs.minio
  ];

  scripts."dev.install".exec = "pip install -U pip && pip install --no-cache -e '.[dev]'";
  scripts."download.testcerts".exec = ''
    curl -z ./fixtures/localhost/cert.pem -o ./fixtures/localhost/cert.pem  https://raw.githubusercontent.com/letsencrypt/pebble/master/test/certs/localhost/cert.pem
    curl -z ./fixtures/localhost/key.pem -o ./fixtures/localhost/key.pem https://raw.githubusercontent.com/letsencrypt/pebble/master/test/certs/localhost/key.pem
  '';
  scripts."test.coverage".exec = ''
    	py.test \
    		--cov=acme_serverless_client \
    		--cov-branch \
        --cov-context=test \
        -v
  '';
  scripts."lint".exec = ''
      ruff --fix src
      ruff format src
    	mypy --strict \
    		--allow-untyped-decorators \
    		--warn-unreachable \
    		--allow-any-generics \
    		src/ example/index.py
  '';
}
