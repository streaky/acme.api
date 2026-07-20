.PHONY: build deps-check deps-update dev format-check lint logs max-lines simulate-ci start stop test test-unit test-integration test-e2e test-coverage type-check verify

COVERAGE_MIN ?= 80
PYTHON_SOURCES := acme_api dev tests

ACT_VERSION ?= 0.2.89
ACT_PLATFORM ?= Linux_x86_64
ACT_IMAGE ?= ghcr.io/catthehacker/ubuntu:full-24.04

.venv/bin/python:
	python3 -m venv .venv
	.venv/bin/python3 -m ensurepip --upgrade
	.venv/bin/python3 -m pip install --upgrade pip

dev: .venv/bin/python requirements-dev.txt
	.venv/bin/pip3 install --require-hashes --no-deps -r requirements-dev.txt

# Regenerate the lock and both hashed exports at the newest compatible versions.
deps-update:
	uv lock --upgrade
	uv run python dev/dependencies.py export

deps-check:
	uv run python dev/dependencies.py check


format-check:
	uv run ruff format --check $(PYTHON_SOURCES)

# Ruff runs first for fast feedback; Pylint follows for complementary checks.
lint:
	uv run ruff check $(PYTHON_SOURCES)
	uv run pylint acme_api dev tests

max-lines:
	uv run python dev/check_max_lines.py --max-lines 500 $(PYTHON_SOURCES)

type-check:
	uv run mypy acme_api tests

test: test-coverage test-e2e

test-unit:
	uv run python dev/run_tests.py unit

test-integration:
	uv run python dev/run_tests.py integration

test-e2e:
	rm -rf build/pebble-test-runtime; mkdir -p build/pebble-test-runtime/data build/pebble-test-runtime/certificates build/pebble-test-runtime/acmesh; chmod -R 777 build/pebble-test-runtime; docker compose -f docker-compose.test.yml up --build --abort-on-container-exit --exit-code-from e2e-tests

test-coverage:
	mkdir -p build
	uv run pytest --cov=acme_api --cov-fail-under=$(COVERAGE_MIN) --cov-report=term-missing --cov-report=json:build/coverage.json tests/unit tests/integration
	uv run python dev/check_coverage.py build/coverage.json --minimum $(COVERAGE_MIN)


build:
	docker compose build --pull

start: build
	docker compose up -d

stop:
	docker compose down

logs:
	docker compose logs -f --tail=150

verify: deps-check format-check lint type-check max-lines test

install-act:
	if [ -x ./act ]; then echo "act is already installed"; else \
		wget https://github.com/nektos/act/releases/download/v$(ACT_VERSION)/act_$(ACT_PLATFORM).tar.gz && \
		tar -xzf act_$(ACT_PLATFORM).tar.gz act && \
		rm act_$(ACT_PLATFORM).tar.gz && \
		chmod +x act; \
	fi

simulate-ci: install-act
	./act -P ubuntu-24.04=$(ACT_IMAGE) --container-options "--group-add $$(stat --format=%g /var/run/docker.sock)"
