# ACME Serverless Client

Currently supports only AWS S3 as cloud storage (experimental support for AWS ACM)

## Development

You need these binaries available in your PATH:

 - [pebble](https://github.com/letsencrypt/pebble/releases)
 - [challtestsrv](https://github.com/letsencrypt/pebble/releases)
 - [minio](https://min.io/download)

Run `make services.install` to install them in `./services` direcotry.
On MacOS you will need `golang` to build pebble.

Envorinment setup with [direnv](https://direnv.net/), .evnrc:

```
layout python python3.8
PATH_add ./services
export PEBBLE_VA_NOSLEEP=1
export PYTHONPATH=$(pwd)/src
```
