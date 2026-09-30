.PHONY: test run dry-run

test:
	PYTHONPATH=src python3 -m pytest

run:
	docker compose up --build

dry-run:
	DRY_RUN=true PYTHONPATH=src python3 -m pytest
