#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Wait for PostgreSQL to accept connections before starting the engine.
# ---------------------------------------------------------------------------
# WHY THIS IS A SCRIPT AND NOT AN INLINE ExecStartPre
#
# The first version of this was written inline as:
#
#   ExecStartPre=/bin/sh -c 'i=0; while [ $i -lt 60 ]; do ...; done'
#
# That FAILED and took the engine down. systemd does not run ExecStartPre
# through a shell: it performs its own whitespace tokenization and has no
# concept of shell quoting. The single-quoted payload was therefore split into
# many separate argv entries, /bin/sh received only the first token after -c,
# and the probe never ran correctly — so the pre-start gate failed on every
# attempt and the service restart-looped (Restart=always) until the start
# limit was reached.
#
# systemd DOES support "prefix words" when an absolute path is the first token,
# which is why a separate executable is the correct construct here. Referencing
# a script keeps the complex quoting inside bash, where it belongs.
#
# The probe itself is a plain TCP connect to the database port. It is
# deliberately the most primitive check available: no credentials, no query, no
# dependency on the application's own driver, so it cannot fail for a reason
# unrelated to "is PostgreSQL listening yet".
# ---------------------------------------------------------------------------
set -uo pipefail

HOST="${1:-127.0.0.1}"
PORT="${2:-54322}"
TIMEOUT="${3:-60}"

PY=/home/ronzoro/safenestt-platform/apps/api/.venv/bin/python3

i=0
while [ "$i" -lt "$TIMEOUT" ]; do
  if "$PY" - "$HOST" "$PORT" <<'PYEOF' 2>/dev/null
import socket, sys
socket.create_connection((sys.argv[1], int(sys.argv[2])), 2).close()
PYEOF
  then
    echo "PostgreSQL reachable at ${HOST}:${PORT} after ${i}s"
    exit 0
  fi
  i=$((i + 1))
  sleep 1
done

echo "FATAL: PostgreSQL not reachable at ${HOST}:${PORT} after ${TIMEOUT}s" >&2
exit 1