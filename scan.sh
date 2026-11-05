#!/usr/bin/env bash
# AO Log Scanner - Rocky Linux, drop-folder mode, NO browser needed
# Usage:
#   ./scan.sh                 scan everything in input/
#   ./scan.sh my-incident     scan only input/my-incident/
#   ./scan.sh --watch         keep watching input/ every 30s, auto-scan new tars
set -e
cd "$(dirname "$0")"
mkdir -p input reports analysis

PY=""
for c in python3 /usr/bin/python3 /usr/local/bin/python3 python; do
  if command -v "$c" >/dev/null 2>&1 && "$c" --version >/dev/null 2>&1; then PY="$c"; break; fi
done

if [ -z "$PY" ]; then
  echo "Python 3 not found. Installing via dnf (needs sudo)..."
  command -v dnf >/dev/null 2>&1 && sudo dnf install -y python3 || true
  for c in python3 /usr/bin/python3 python; do
    if command -v "$c" >/dev/null 2>&1; then PY="$c"; break; fi
  done
fi

if [ -z "$PY" ]; then
  echo "ERROR: Python 3 not found. Run: sudo dnf install -y python3"
  exit 1
fi

echo "Using $PY ($("$PY" --version 2>&1))"
echo "Drop AO tars in: $PWD/input/   Reports go to: $PWD/reports/"
exec "$PY" scan_all.py "$@"
