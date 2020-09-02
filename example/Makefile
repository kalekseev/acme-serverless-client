lambda.zip: package.sh index.py
	docker run --rm -v `pwd`:/code -t lambci/lambda:build-python3.8 bash /code/package.sh

clean:
	rm -rf lambda.zip
