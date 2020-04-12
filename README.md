# Let's Encrypt Client for AWS Lambda

## Development

Setup using [direnv](https://direnv.net/), .evnrc:

    layout python python3.8
    PATH_add ./services
    export PEBBLE_VA_NOSLEEP=1

You need these binaries available on your path:

 - [pebble](https://github.com/letsencrypt/pebble/releases)
 - [challtestsrv](https://github.com/letsencrypt/pebble/releases)
 - [minio](https://min.io/download)

Run `make services.install` to install them in `./services` direcotry.
On MacOS you will need `golang` to build pebble.
