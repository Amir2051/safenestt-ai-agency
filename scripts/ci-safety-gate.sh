#!/usr/bin/env bash
# ============================================================================
# CI SAFETY GATE — refuse to run tests if pointed at production.
# ============================================================================
#
# WHY
# ---
# On 2026-10-04 the test suite destroyed the production database. Two
# independent barriers failed open:
#
#   1. The suite's DB_NAME guard read only os.environ["DB_NAME"], so a module
#      that built its own DSN bypassed it entirely.
#   2. Nothing stopped CI (or a developer shell) from exporting DB_NAME
#      to the production database in the first place.
#
# This script is barrier #2: a pre-flight check that fails BEFORE pytest starts.
# It is deliberately a separate process from pytest so it cannot be skipped by
# a conftest change, and it exits non-zero so CI marks the job failed.
#
# It is FAIL-CLOSED: if it cannot determine the target database, it refuses.
#
# USAGE
#   scripts/ci-safety-gate.sh            # check only
#   scripts/ci-safety-gate.sh --run ...  # check, then exec the given command
#
# EXIT CODES
#   0  target is a recognised test database (or unset -> suite default)
#   2  target is production, unapproved, or undeterminable -> REFUSED
# ============================================================================
set -uo pipefail

PROD_DB="safenestt_ai"
ALLOWED_EXACT="safenestt_ai_test"
ALLOWED_PREFIXES=("safenestt_audittest_" "safenestt_gate_" "safenestt_bootstrap_" "safenestt_sg_")

fail() {
  echo "" >&2
  echo "============================================================" >&2
  echo "CI SAFETY GATE: REFUSING TO RUN TESTS" >&2
  echo "============================================================" >&2
  echo "$1" >&2
  echo "" >&2
  echo "If you genuinely intend to target a different database, set" >&2
  echo "  SAFENESTT_TEST_DB_NAME=<name>" >&2
  echo "and ensure the name matches one of:" >&2
  echo "  exact   : ${ALLOWED_EXACT}" >&2
  echo "  prefix  : ${ALLOWED_PREFIXES[*]}" >&2
  exit 2
}

# --- 1. DB_NAME ------------------------------------------------------------
db_name="${DB_NAME:-}"
if [ -z "$db_name" ]; then
  # Unset is safe: conftest resolves the suite default (safenestt_ai_test).
  db_name="$ALLOWED_EXACT"
  echo "[gate] DB_NAME unset -> using suite default: $db_name"
fi

if [ "$db_name" = "$PROD_DB" ]; then
  fail "DB_NAME='$db_name' is the PRODUCTION database.
The engine test suite is destructive by design (DROP/TRUNCATE fixtures).
Running it against production destroyed all investigations on 2026-10-04."
fi

# --- 2. Any *_DATABASE_URL that names production ----------------------------
for var in SAFENESTT_DATABASE_URL DATABASE_URL OWNER_DATABASE_URL \
           SAFENESTT_OWNER_DATABASE_URL; do
  url="${!var:-}"
  [ -z "$url" ] && continue
  # Trailing path segment of a postgres URL, ignoring any query string.
  target="${url%%\?*}"
  target="${target##*/}"
  if [ "$target" = "$PROD_DB" ]; then
    fail "$var points at the PRODUCTION database ('$target').
This is the exact condition that let tests/test_persistence.py drop
production tables while the suite believed it was pointed at a test DB."
  fi
done

# --- 3. Allowlist ----------------------------------------------------------
if [ "$db_name" != "$ALLOWED_EXACT" ]; then
  matched=0
  for p in "${ALLOWED_PREFIXES[@]}"; do
    case "$db_name" in
      "$p"*) matched=1; break ;;
    esac
  done
  if [ "$matched" -ne 1 ]; then
    fail "DB_NAME='$db_name' is not an approved test database.
Approved exact name : $ALLOWED_EXACT
Approved prefixes   : ${ALLOWED_PREFIXES[*]}"
  fi
fi

echo "[gate] PASS — target database '$db_name' is an approved test database."

# --- 4. Optional: gate then run ---------------------------------------------
if [ "${1:-}" = "--run" ]; then
  shift
  if [ "$#" -eq 0 ]; then
    echo "[gate] --run given but no command supplied." >&2
    exit 2
  fi
  echo "[gate] executing: $*"
  exec "$@"
fi
exit 0