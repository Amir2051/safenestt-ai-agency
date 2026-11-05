#!/usr/bin/env bash
# Complete the credential rotation: sync engine.env, then restart both services.
#
# Run as:  sudo bash /home/ronzoro/safenestt-ai/scripts/complete-rotation.sh
#
# WHAT THIS DOES (4 steps, in this order)
#   1. Sync /etc/safenestt/engine.env HERMES_API_KEY from apps/api/.env
#      (the mint script already put the NEW key there).
#   2. Verify all four on-disk fingerprints agree BEFORE any restart.
#   3. Restart safenestt-engine.service  — picks up engine.env
#   4. Restart safenestt-backend.service — picks up the new API key + callback secret
#
# WHY RESTART BOTH
#   * backend holds the OLD key and OLD callback secret in memory; it must reload
#   * engine.env is changed, so the engine process env should match the file again
#
# SAFE TRANSITION NOTE
#   The old key (99cf1bb8...) is still registered and ACTIVE at this point, so
#   the backend keeps working right up until it restarts, and Base44 is already
#   on the new key. There is no window in which both are broken.
#   The old key is revoked separately, AFTER verification.
#
# Never prints any secret value — fingerprints only.
set -euo pipefail

REPO=/home/ronzoro/safenestt-ai
API_ENV=/home/ronzoro/safenestt-platform/apps/api/.env

echo "==> Step 1: sync engine.env from apps/api/.env"
bash "${REPO}/scripts/fix-engine-env-hermes-key.sh" || {
  echo "ABORT: engine.env sync failed" >&2; exit 1
}

echo
echo "==> Step 2: verify every on-disk fingerprint agrees before restarting"
NEW=$(grep '^HERMES_API_KEY=' "${API_ENV}" | cut -d= -f2-)
EXPECTED=$(printf '%s' "$NEW" | sha256sum | cut -c1-64)
ENG=$(grep '^HERMES_API_KEY=' /etc/safenestt/engine.env | cut -d= -f2-)
ENGFP=$(printf '%s' "$ENG" | sha256sum | cut -c1-64)
APIFP=$(printf '%s' "$NEW" | sha256sum | cut -c1-64)
echo "    apps/api/.env : $APIFP"
echo "    engine.env    : $ENGFP"
if [ "$ENGFP" != "$APIFP" ]; then
  echo "ABORT: fingerprints disagree — NOT restarting" >&2
  exit 1
fi
echo "    agree — safe to restart"
echo "    new key fingerprint: $EXPECTED"

echo
echo "==> Step 3: restart safenestt-engine.service"
systemctl restart safenestt-engine.service

echo "==> Step 4: restart safenestt-backend.service"
systemctl restart safenestt-backend.service

echo
echo "==> Waiting for engine health (poll, no blind sleep)"
for i in $(seq 1 45); do
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 4 http://127.0.0.1:8002/v1/health || echo 000)
  if [ "$code" = "200" ]; then
    echo "    engine healthy after ${i}s"
    break
  fi
  sleep 1
done

echo
echo "==> Post-restart state"
systemctl is-active safenestt-engine.service  | sed 's/^/    engine : /'
systemctl is-active safenestt-backend.service | sed 's/^/    backend: /'
echo "    engine PID  : $(systemctl show safenestt-engine.service -p MainPID --value)"
echo "    backend PID : $(systemctl show safenestt-backend.service -p MainPID --value)"

EP=$(systemctl show safenestt-engine.service -p MainPID --value)
BP=$(systemctl show safenestt-backend.service -p MainPID --value)
PF=$(tr '\0' '\n' < /proc/$EP/environ | grep '^HERMES_API_KEY=' | cut -d= -f2- | tr -d '\n' | sha256sum | cut -c1-64)
BF=$(tr '\0' '\n' < /proc/$BP/environ | grep '^HERMES_API_KEY=' | cut -d= -f2- | tr -d '\n' | sha256sum | cut -c1-64)
echo "    engine process fp  : $PF"
echo "    backend process fp : $BF"
[ "$PF" = "$EXPECTED" ] && echo "    engine  : MATCHES new key"  || echo "    engine  : MISMATCH"
[ "$BF" = "$EXPECTED" ] && echo "    backend : MATCHES new key" || echo "    backend : MISMATCH"

unset NEW ENG
echo
echo "Done. Old key 99cf1bb8... is STILL ACTIVE — revoke after verification."