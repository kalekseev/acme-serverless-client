# ACME Serverless Client

Currently supports only AWS S3 as certificate storage (experimental support for AWS ACM).

Install with `pip install https://github.com/kalekseev/acme-serverless-client/archive/master.tar.gz`,
replace master with commit hash to pin.

## Example lambda

`example/index.py` contains example lambda function that accepts input like: `{"action": "issue", "domain": "example.com"}`.
To build zip archive for deployment run `make lambda.zip` inside `example` dir.

## Development

For testing these binaries must be available in PATH:

- dig
- [pebble](https://github.com/letsencrypt/pebble/releases)
- [challtestsrv](https://github.com/letsencrypt/pebble/releases)
- [minio](https://min.io/download)

Run tests with `PEBBLE_VA_NOSLEEP=1 py.test`
