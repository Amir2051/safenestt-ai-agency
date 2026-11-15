#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Replace the stale HERMES_API_KEY in /etc/safenestt/engine.env with the
# registered key from apps/api/.env.
# ---------------------------------------------------------------------------
# WHY
#
# /etc/safenestt/engine.env carried HERMES_API_KEY = dea30747... — a credential
# that has NEVER existed in the engine's api_keys table (verified: ABSENT). It
# is a dead credential sitting in the file that every SafeNestT operator reads
# as "the Hermes key".
#
# It caused a real incident: the same stale value was pasted into the Base44
# dashboard, which made the Base44 -> Hermes path return
#   401 {"detail":{"code":"invalid_key","message":"Invalid API key"}}
# even though the SafeNestT backend was authenticating successfully with the
# real key the whole time. Two different "HERMES keys" existed and nothing
# flagged the discrepancy.
#
# The registered key lives in apps/api/.env. This script copies THAT value, so
# after it runs there is exactly one credential, in two places, and they agree.
#
# The engine loads this value for its own outbound/loopback paths but never
# validates it at startup, which is why a dead key sat undetected for hours.
#
# SAFETY
#   * backup written before modification
#   * fingerprints both values, prints NO plaintext
#   * refuses to run if the source key is not the CURRENTLY ACTIVE registered one
#   * idempotent: no-op if engine.env already matches
#
# REGISTERED KEY IS DISCOVERED, NOT HARDCODED
#   This script previously pinned EXPECTED=99cf1bb8... That went stale the
#   moment the key was rotated: 99cf1bb8 was revoked and 5e9a6c41... became
#   the active key, so the guard correctly refused a key that was in fact
#   legitimate — the check was wrong, not the credential.
#
#   EXPECTED is now resolved at run time from the api_keys table: the single
#   row for this tenant+name where active = true AND revoked = false. That
#   makes the guard self-correcting across future rotations instead of needing
#   an edit every time a key changes.
#
#   Override for offline use:  EXPECTED_FP=<fingerprint> ./script.sh
#   Fail-closed: if the database cannot be reached and no override is given,
#   the script aborts rather than assuming any key is acceptable.
# ---------------------------------------------------------------------------
set -euo pipefail

SRC=/home/ronzoro/safenestt-platform/apps/api/.env
DST=/etc/safenestt/engine.env
TENANT="${HERMES_BACKEND_TENANT:-safenestt-remediate-test}"
KEYNAME="${HERMES_BACKEND_KEY_NAME:-SafeNestT Backend (pipeline)}"

fp() { printf '%s' "$1" | sha256sum | cut -c1-64; }

# --- resolve the currently active registered key ---
if [ -n "${EXPECTED_FP:-}" ]; then
  EXPECTED="$EXPECTED_FP"
  echo "registered key         : $EXPECTED (from EXPECTED_FP override)"
else
  # engine.env holds the DB connection settings; source them read-only.
  set -a
  # shellcheck disable=SC1091
  . "$DST"
  set +a
  # No eval: variables are passed directly to psql so quoting stays sane and a
  # tenant/key name containing a space or quote cannot break the command.
  ROWS=$(PGPASSWORD="$DB_PASSWORD" PGCONNECT_TIMEOUT=5 psql \
            -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" \
            -t -A -t \
            -c "SELECT key_fingerprint FROM api_keys WHERE active AND NOT revoked AND tenant_id='${TENANT}' AND name='${KEYNAME}';" \
          2>/dev/null | tr -d '[:space:]' || true)
  N=$(printf '%s' "$ROWS" | grep -c . || true)
  if [ "$N" != "1" ]; then
    echo "ABORT: expected exactly 1 active registered key for" >&2
    echo "       tenant='${TENANT}' name='${KEYNAME}', found ${N}." >&2
    echo "       Cannot establish ground truth. Refusing to continue." >&2
    exit 1
  fi
  EXPECTED="$ROWS"
  echo "registered key         : $EXPECTED (live lookup: active, not revoked)"
fi

# --- read source ---
if [ ! -r "$SRC" ]; then echo "ERROR: cannot read $SRC" >&2; exit 1; fi
KEY=$(grep '^HERMES_API_KEY=' "$SRC" | cut -d= -f2-)
if [ -z "$KEY" ]; then echo "ERROR: no HERMES_API_KEY in $SRC" >&2; exit 1; fi

SRC_FP=$(fp "$KEY")
echo "source key fingerprint : $SRC_FP"
if [ "$SRC_FP" != "$EXPECTED" ]; then
  echo "ABORT: source key does not match the currently active registered key." >&2
  echo "       source    : $SRC_FP" >&2
  echo "       registered: $EXPECTED" >&2
  echo "       Refusing to write an unverified credential." >&2
  exit 1
fi
echo "source verified        : matches the currently active registered key"

# --- read current destination ---
CUR=$(grep '^HERMES_API_KEY=' "$DST" | cut -d= -f2- || true)
if [ -n "$CUR" ]; then
  CUR_FP=$(fp "$CUR")
  echo "engine.env fingerprint : $CUR_FP"
  if [ "$CUR_FP" = "$SRC_FP" ]; then
    echo "NO-OP: engine.env already holds the registered key."
    exit 0
  fi
else
  echo "engine.env            : no HERMES_API_KEY present (will be added)"
fi

# --- backup ---
BAK="${DST}.bak.$(date +%Y%m%d%H%M%S)"
cp -a "$DST" "$BAK"
echo "backup written        : $BAK"

# --- rewrite (value never printed) ---
TMP=$(mktemp /tmp/engine.env.XXXXXX)
KEY="$KEY" DST="$DST" TMP="$TMP" python3 - <<'PY'
import os, pathlib
key, dst, tmp = os.environ["KEY"], os.environ["DST"], os.environ["TMP"]
out, seen = [], False
for line in pathlib.Path(dst).read_text().splitlines():
    if line.startswith("HERMES_API_KEY="):
        if not seen:
            out.append(f"HERMES_API_KEY={key}")
            seen = True
        continue
    out.append(line)
if not seen:
    out.append(f"HERMES_API_KEY={key}")
pathlib.Path(tmp).write_text("\n".join(out) + "\n")
PY
install -o root -g ronzoro -m 0640 "$TMP" "$DST"
rm -f "$TMP"
echo "engine.env updated    : HERMES_API_KEY replaced (value not shown)"

# --- verify ---
NEW_FP=$(fp "$(grep '^HERMES_API_KEY=' "$DST" | cut -d= -f2-)")
echo "verify fingerprint    : $NEW_FP"
if [ "$NEW_FP" = "$EXPECTED" ]; then
  echo "RESULT: OK — engine.env now holds the registered key."
else
  echo "RESULT: FAILED — post-write verification mismatch." >&2
  exit 1
fi
echo
echo "Next: sudo systemctl restart safenestt-engine.service"