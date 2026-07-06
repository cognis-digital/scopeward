#!/usr/bin/env bash
# scopeward installer (Linux / macOS).
# Installs scopeward (stdlib-only, no runtime deps) into the current Python
# environment as an editable install. Pass --dev for the test extras.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

PY="${PYTHON:-python3}"
if ! command -v "$PY" >/dev/null 2>&1; then
  PY=python
fi

echo "scopeward: using $("$PY" --version 2>&1)"

EXTRA=""
if [[ "${1:-}" == "--dev" ]]; then
  EXTRA="[dev]"
  echo "scopeward: installing with dev (test) extras"
fi

"$PY" -m pip install -e ".${EXTRA}"

echo "scopeward: installed. Try: scopeward --version"
