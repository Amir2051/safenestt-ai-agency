#!/usr/bin/env bash
# Capture the Hermes request sequence produced by one Base44 UI investigation,
# and classify which lifecycle branch hermesStart took.
#
# Run and then click "Run Full Pipeline" when prompted:
#   bash /home/ronzoro/safenestt-ai/scripts/capture-hermes-seq.sh
#
# Prints request lines and DB state only. Never prints a credential.
set -uo pipefail
L=/var/log/safenestt/engine.log
START=$(wc -l < "$L")
Q() { PGPASSWORD=postgres psql -h 127.0.0.1 -p 54322 -U postgres -d safenestt_ai -t -A "$@" 2>/dev/null; }

echo "=== baseline ==="
echo "  engine.log lines : $START"
echo "  investigations   : $(Q -c 'SELECT count(*) FROM investigations;' | head -1)"
echo "  auth failures    : $(grep -ac hermes_auth_failed "$L")"

echo
echo ">>> Click 'Run Full Pipeline' in the SafeNestT UI now, then press Enter. <<<"
read -r _

NEW=$(tail -n "+$((START+1))" "$L")
echo
echo "=== NEW Hermes requests from this run ==="
printf '%s\n' "$NEW" | sed 's/^/  /'

echo
echo "=== lifecycle classification ==="
VER=$(printf '%s\n' "$NEW" | grep -cE 'GET /v1/investigations/[0-9a-f]{32} HTTP')
CRT=$(printf '%s\n' "$NEW" | grep -cE '"POST /v1/investigations HTTP')
STOK=$(printf '%s\n' "$NEW" | grep -cE 'start\?wait=false.* 200')
ST409=$(printf '%s\n' "$NEW" | grep -cE 'start\?wait=false.* 409')
echo "  verification GETs       : $VER"
echo "  POST /v1/investigations : $CRT   (1 => a fresh investigation was created)"
echo "  POST /start -> 200      : $STOK"
echo "  POST /start -> 409      : $ST409   (want 0)"
if [ "${ST409:-0}" -gt 0 ]; then
  echo "  VERDICT: 409 still occurring — the COMPLETED branch did not fire."
else
  echo "  VERDICT: no 409."
fi

echo
echo "=== Hermes DB after the run ==="
Q -F' | ' -c "BEGIN READ ONLY; SELECT id, left(investigation_id,20)||'…', status, created_at FROM investigations ORDER BY id DESC LIMIT 4; COMMIT;" \
  | grep -v 'BEGIN\|COMMIT' | sed 's/^/  /'

echo
echo "=== auth failures after the run ==="
echo "  total: $(grep -ac hermes_auth_failed "$L")"