.PHONY: venv pip-cache-dir deps dev start build stop logs test typecheck lint flake8 format isort isort-fix check-max-lines check-forbidden-imports combined-check install-act simulate-ci deps-update test-harness
.ONESHELL:

export ROOT_PATH=$(abspath $(dir $(lastword $(MAKEFILE_LIST))))
export PYTHONPATH=$(ROOT_PATH)
COV_FILE_MIN ?= 80
PY_PATHS ?= acme_api tests
MYPY_PATHS ?= acme_api tests
MAX_FILE_LINES ?= 500
MAX_FILE_LINES_PATHS ?= acme_api tests

ACT_VERSION ?= 0.2.89
ACT_PLATFORM ?= Linux_x86_64
ACT_IMAGE ?= ghcr.io/catthehacker/ubuntu:full-24.04

ifneq (,$(wildcard $(ROOT_PATH)/.env))
include $(ROOT_PATH)/.env
export
endif

export PYTHONPYCACHEPREFIX=./.pycache

venv:
	if [ ! -d ".venv" ]; then \
		python3 -m venv .venv; \
	fi

pip-cache-dir:
	mkdir -p .venv/pip-cache

dev: venv pip-cache-dir
	echo "Installing dependencies..."
	.venv/bin/python3 -m pip install -q --cache-dir .venv/pip-cache --upgrade pip
	.venv/bin/pip install -q --cache-dir .venv/pip-cache -r requirements-dev.txt
	.venv/bin/pip install -q --cache-dir .venv/pip-cache -e .

deps-update: venv pip-cache-dir
	.venv/bin/python3 -m pip install --cache-dir .venv/pip-cache --upgrade pip setuptools wheel pip-tools
	.venv/bin/pip-compile pyproject.toml --output-file requirements.txt --strip-extras --pip-args "--cache-dir=.venv/pip-cache"
	.venv/bin/pip-compile pyproject.toml --extra dev -c requirements.txt --output-file requirements-dev.txt --no-strip-extras --pip-args "--cache-dir=.venv/pip-cache"

deps: venv
	.venv/bin/pip install -r requirements.txt

start: build
	docker compose up -d

build:
	docker compose build --pull

stop:
	docker compose down

logs:
	docker compose logs -f --tail=150

test: dev
	set -e
	.venv/bin/python3 scripts/check_forbidden_imports.py ${PY_PATHS}
	.venv/bin/pytest -vvv --tb=short --color=yes ${PYTEST_COV} --cov-report=xml:coverage-data/coverage.xml --cov-report=html:coverage-data/htmlcov --cov-report=term --cov-report=json:coverage-data/coverage.json $(if ${TEST},${TEST},--ignore=tests/integration/pebble_harness/test_pebble_e2e.py)
ifeq ($(origin TEST), command line)
	@echo "Skipping per-file coverage gate for scoped TEST=${TEST}"
else
	.venv/bin/python3 dev/check_per_file_coverage.py --minimum "${COV_FILE_MIN}" --coverage-json coverage-data/coverage.json
endif

flake8: dev
	.venv/bin/flake8 ${PY_PATHS} --max-line-length=120 --extend-ignore=E203 --count --show-source --statistics

lint: flake8
	.venv/bin/pylint ${PY_PATHS}

format: dev
	.venv/bin/isort ${PY_PATHS}

isort: dev
	.venv/bin/isort ${PY_PATHS} --check-only --diff

check-max-lines: dev
	.venv/bin/python3 scripts/check_max_lines.py --max-lines "${MAX_FILE_LINES}" ${MAX_FILE_LINES_PATHS}

check-forbidden-imports: dev
	.venv/bin/python3 scripts/check_forbidden_imports.py ${PY_PATHS}

isort-fix: dev
	.venv/bin/isort ${PY_PATHS} --interactive

typecheck: dev
	.venv/bin/mypy ${MYPY_PATHS}

combined-check: typecheck lint flake8 isort check-max-lines test

install-act:
	[ -x ./act ] && echo "act is already installed" && exit 0
	wget https://github.com/nektos/act/releases/download/v$(ACT_VERSION)/act_$(ACT_PLATFORM).tar.gz
	tar -xzf act_$(ACT_PLATFORM).tar.gz act
	rm act_$(ACT_PLATFORM).tar.gz
	chmod +x act

simulate-ci: install-act
	./act -P ubuntu-latest=$(ACT_IMAGE)

test-harness:
	.venv/bin/python3 tests/integration/pebble_harness/run_harness.py
