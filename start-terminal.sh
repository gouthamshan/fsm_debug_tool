#!/usr/bin/env bash
# FortiSIEM Log Terminal - Rocky Linux launcher (no pip needed, stdlib only)
set -e
cd "$(dirname "$0")"
mkdir -p uploads analysis

find_python() {
  for c in python3 /usr/bin/python3 /usr/local/bin/python3 python; do
    if command -v "$c" >/dev/null 2>&1; then
      # skip Microsoft Store shim style stubs: must report a real version
      if "$c" --version >/dev/null 2>&1; then
        echo "$c"; return 0
      fi
    fi
  done
  return 1
}

PY="$(find_python || true)"

if [ -z "$PY" ]; then
  echo "Python 3 not found. Installing via dnf (needs sudo)..."
  if command -v dnf >/dev/null 2>&1; then
    sudo dnf install -y python3
    PY="$(find_python || true)"
  fi
fi

if [ -z "$PY" ]; then
  echo "ERROR: Python 3 still not found."
  echo "Install it yourself, then re-run this script:"
  echo "  sudo dnf install -y python3"
  echo "Check: python3 --version   (needs 3.8 or newer, this app uses stdlib only)"
  exit 1
fi

echo "Using Python: $PY ($("$PY" --version 2>&1))"
echo "Starting FortiSIEM Log Terminal at http://127.0.0.1:8765"
echo "Press Ctrl+C to stop. Uploads go to ./uploads (local only, 127.0.0.1)."

# Open browser if a graphical session is present, ignore failure (headless/SSH is fine)
( sleep 2; command -v xdg-open >/dev/null 2>&1 && xdg-open http://127.0.0.1:8765 >/dev/null 2>&1 || true ) &

exec "$PY" app.py --port 8765
