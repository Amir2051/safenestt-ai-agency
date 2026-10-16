#!/usr/bin/env bash
# READ-ONLY verification of Base44 -> Hermes authentication.
# Makes no configuration changes and restarts nothing.
# Never prints the API key; only SHA-256 fingerprints.
set -uo pipefail

LOG=/var/log/safenestt/engine.log
INV="${1:-385b1197431b487394dab018804c4d3e}"

sz=$(/usr/bin/stat -c %s "$LOG")
before=$(/usr/bin/grep -ac hermes_auth_failed "$LOG")

export PATH="/home/ronzoro/.deno/bin:/usr/bin:/bin:/usr/local/bin"
cd /home/ronzoro/safenestT

echo "=== invoking hermesStart status (3 upstream calls) ==="
echo "await base44.functions.invoke(\"hermesStart\", { _action: \"status\", id: \"${INV}\" }); console.log(\"INVOKE_DONE\");" \
  | /usr/bin/timeout 300 npx --yes base44@0.1.20 exec 2>&1 \
  | /usr/bin/grep -E 'INVOKE_DONE|error' | /usr/bin/head -3 | /usr/bin/sed 's/^/  /'

/usr/bin/sleep 2

after=$(/usr/bin/grep -ac hermes_auth_failed "$LOG")
az=$(/usr/bin/stat -c %s "$LOG")

echo
echo "=== engine log lines produced by that invoke ==="
/usr/bin/tail -c $((az - sz)) "$LOG" | /usr/bin/sed 's/^/  /'

echo
echo "=== authentication failures during this verification ==="
echo "  before=${before}  after=${after}  delta=$((after - before))"
if [ "$after" -eq "$before" ]; then
  echo "  RESULT: 0 authentication failures — credential ACCEPTED"
else
  echo "  RESULT: $((after - before)) AUTH FAILURE(S) — see log above"
fi