#!/bin/bash
set -xe
mkdir -p build
python3.8 -m pip install https://github.com/kalekseev/acme-serverless-client/archive/master.tar.gz -t build
rm -f /code/lambda.zip
cp -r /code/index.py build
cd build
zip -r /code/lambda.zip .
