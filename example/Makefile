build.lambda:
	docker run --rm -v `pwd`:/code -t lambci/lambda:build-python3.8 bash /code/package.sh

clean:
	rm -rf lambda.zip lambda_acme/__pycache__
