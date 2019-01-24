.PHONY: tests

build:
	$(MAKE) -C c
	$(MAKE) -C c0

## submodules:
vendor:
	git submodule update --init --recursive --force

## tests commands:
tests:
	pytest --ignore=vendor -k "not hypothesis"

tests_all:
	pytest --ignore=vendor

## style commands:
style_check: ## run code style check on application sources and tests
	flake8 python/ tests/
	isort --check-only --recursive python/ tests/
	black python/ tests/ --check

style:
	black python/ tests/
	isort -y --recursive python/ tests/
