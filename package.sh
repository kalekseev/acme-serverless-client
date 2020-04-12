#!/bin/bash
mkdir tmpdir
mkdir tmpdir/lambda_acme
python3.8 -m pip install -r code/requirements.txt -t tmpdir
rm -f /code/lambda.zip
cp -r /code/lambda_acme/*.py tmpdir/lambda_acme/
cd tmpdir
zip -r /code/lambda.zip .
