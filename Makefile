# scopeward — stdlib-only; no runtime deps.
PYTHON ?= python

.PHONY: help install dev test demos smoke lint build clean

help:
	@echo "targets: install dev test demos smoke build clean"

install:
	$(PYTHON) -m pip install -e .

dev:
	$(PYTHON) -m pip install -e ".[dev]"

test:
	$(PYTHON) -m pytest -q

demos:
	$(PYTHON) demos/run_all.py

# End-to-end CLI smoke test against the example scope.
smoke:
	SCOPEWARD_KEY=make-key $(PYTHON) -m scopeward.cli validate --scope examples/engagement.example.json
	SCOPEWARD_KEY=make-key $(PYTHON) -m scopeward.cli sign   --scope examples/engagement.example.json --out .smoke_signed.json
	SCOPEWARD_KEY=make-key $(PYTHON) -m scopeward.cli verify --scope .smoke_signed.json
	SCOPEWARD_KEY=make-key $(PYTHON) -m scopeward.cli check  --scope .smoke_signed.json --module apkprobe --target android:com.acme.app --log .smoke_ev.jsonl
	SCOPEWARD_KEY=make-key $(PYTHON) -m scopeward.cli audit  --log .smoke_ev.jsonl --summary
	SCOPEWARD_KEY=make-key $(PYTHON) -m scopeward.cli report --log .smoke_ev.jsonl --format sarif --out .smoke.sarif
	rm -f .smoke_signed.json .smoke_ev.jsonl .smoke.sarif

build:
	$(PYTHON) -m build

clean:
	rm -rf build dist *.egg-info .pytest_cache .smoke_signed.json .smoke_ev.jsonl .smoke.sarif
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
