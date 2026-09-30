.PHONY: test run dry-run

# Prefer the repo venv (has all deps); fall back to system python3.
PY := $(shell [ -x .venv/bin/python ] && echo .venv/bin/python || echo python3)

test:
	PYTHONPATH=src $(PY) -m pytest

run:
	docker compose up --build

dry-run:
	DRY_RUN=true PYTHONPATH=src $(PY) -m pytest
