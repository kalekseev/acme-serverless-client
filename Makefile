PEBBLE_VERSION := 2.3.1
CURL := curl -L -s -S
PWD := $(shell pwd)
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
	ARCH:=linux-amd64
endif
ifeq ($(UNAME_S),Darwin)
	ARCH:=darwin-amd64
endif
export GOPATH=$(PWD)/services/.go

services:
	mkdir services

services/pebble-challtestsrv: | services
ifeq ($(UNAME_S),Linux)
	$(CURL) -z $@ -o $@ https://github.com/letsencrypt/pebble/releases/download/v$(PEBBLE_VERSION)/pebble-challtestsrv_$(ARCH)
	chmod +x $@
endif

services/pebble: services/pebble-challtestsrv | services
ifeq ($(UNAME_S),Linux)
	$(CURL) -z $@ -o $@ https://github.com/letsencrypt/pebble/releases/download/v$(PEBBLE_VERSION)/pebble_$(ARCH)
	chmod +x $@
endif
ifeq ($(UNAME_S),Darwin)
	go get -u github.com/letsencrypt/pebble/...
	cp $(GOPATH)/bin/* ./services/
endif

services/minio: services
	$(CURL) -z $@ -o $@ https://dl.min.io/server/minio/release/$(ARCH)/minio
	chmod +x $@

services.install: services/pebble services/minio

fixtures/localhost_cert.pem:
	$(CURL) -z $@ -o $@  https://raw.githubusercontent.com/letsencrypt/pebble/master/test/certs/localhost/cert.pem

fixtures/localhost_key.pem:
	$(CURL) -z $@ -o $@ https://raw.githubusercontent.com/letsencrypt/pebble/master/test/certs/localhost/key.pem

fixtures.refresh: fixtures/localhost_cert.pem fixtures/localhost_key.pem

lint:
	flake8 src/
	isort src/
	black src/
	mypy --strict \
		--ignore-missing-imports \
		--allow-untyped-decorators \
		--follow-imports skip \
		--warn-unreachable \
		--allow-any-generics \
		src/ example/index.py

test:
	PATH=./services:$(PATH) PYTHONPATH=./src PEBBLE_VA_NOSLEEP=1 py.test \
		--cov=acme_serverless_client \
		--cov-branch \
		--cov-context=test
