
## test commands:

test: ## run unit tests
	cd tests ; ./run_tests.sh $(TESTOPTS)

# pylint: ## run pylint on application sources and tests
	# pylint -E $(shell find src tests -name *.py)

## style commands:

style: ## run code style check on application sources and tests
	flake8
	isort --check-only
	black . --check

isort:
	isort -y

black:
	black .
