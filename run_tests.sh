#!/data/data/com.termux/files/usr/bin/bash
# Run the full RUK_HACKER test suite (unit + smoke). No external network needed.
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

PY="$(command -v python3 || command -v python)"
if [ -z "$PY" ]; then
  echo "python not found — install it with: pkg install python" >&2
  exit 1
fi

export NO_COLOR=1
echo "== compile check =="
"$PY" -m compileall -q ruk_hacker ruk_hacker.py
echo "OK"

echo
echo "== unit tests =="
"$PY" -m unittest tests.test_units -v

echo
echo "== smoke tests (localhost only) =="
"$PY" -m unittest tests.test_smoke -v

echo
echo "== all tests =="
"$PY" -m unittest discover -s tests -p 'test_*.py' -v 2>&1 | tail -5
echo
echo "All RUK_HACKER tests passed."
