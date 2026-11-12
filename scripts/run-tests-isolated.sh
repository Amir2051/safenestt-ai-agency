#!/usr/bin/env bash
# ============================================================================
# Run the test suite against the DEDICATED test PostgreSQL instance.
# ============================================================================
#
# Uses port 55432 (container safenestt-test-postgres), which is physically
# separate from production's 54322. This is the recommended way to run the
# suite locally after the 2026-10-04 production data-loss incident.
#
#   scripts/run-tests-isolated.sh                    # run tests/
#   scripts/run-tests-isolated.sh tests/test_x.py    # run specific files
#   scripts/run-tests-isolated.sh remediation_tests/ # run the remediation suite
#
# It refuses to run if anything resolves to the production database.
# ============================================================================
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="${REPO}/docker-compose.test-db.yml"
VENV="${SAFENESTT_TEST_VENV:-/home/ronzoro/safenestt-platform/apps/api/.venv/bin/python3}"

TEST_PORT="${SAFENESTT_TEST_PORT:-55432}"
TEST_DB="${SAFENESTT_TEST_DB_NAME:-safenestt_ai_test}"
TEST_USER="safenestt_test"
OWNER_ROLE="${SAFENESTT_TEST_OWNER_USER:-safenestt_owner_test}"
TEST_PASSWORD="safenestt_test_local_only"

# --- 1. Start the isolated instance if it is not already up ----------------
if ! docker ps --format '{{.Names}}' | grep -qx safenestt-test-postgres; then
  echo "==> Starting isolated test PostgreSQL (127.0.0.1:${TEST_PORT})"
  docker-compose -f "${COMPOSE_FILE}" up -d
fi

echo "==> Waiting for the test instance to accept connections"
for i in $(seq 1 30); do
  if PGPASSWORD="${TEST_PASSWORD}" psql -h 127.0.0.1 -p "${TEST_PORT}" \
       -U "${TEST_USER}" -d "${TEST_DB}" -t -A -c "SELECT 1" >/dev/null 2>&1; then
    echo "    ready after ${i}s"
    break
  fi
  sleep 1
done

# The RLS tests need a non-superuser, non-BYPASSRLS application role to be
# meaningful. Create it inside the TEST instance (idempotent).
echo "==> Ensuring the application role exists in the test instance"
SAFENESTT_TEST_PASSWORD="${TEST_PASSWORD}" \
SAFENESTT_TEST_APP_PASSWORD="${TEST_PASSWORD}" \
  "${REPO}/scripts/provision-test-app-role.sh" >/dev/null

# --- 2. Export the isolated connection environment ------------------------
# Everything is explicit. DB_PORT is the isolation boundary: production is
# 54322, and nothing in this script ever sets it.
export DB_HOST=127.0.0.1
export DB_PORT="${TEST_PORT}"
export DB_NAME="${TEST_DB}"
export DB_SSL_MODE=disable
export SAFENESTT_DB_PASSWORD="${TEST_PASSWORD}"
export SAFENESTT_OWNER_PASSWORD="${TEST_PASSWORD}"
export SAFENESTT_TEST_PASSWORD="${TEST_PASSWORD}"
export SAFENESTT_TEST_APP_PASSWORD="${TEST_PASSWORD}"
# Both conftests bootstrap schema as this role. It must match between
# tests/conftest.py and remediation_tests/conftest.py or the second one loaded
# inherits the first one's engine singletons and fails with
# "must be owner of function establish_tenant_context".
export SAFENESTT_TEST_OWNER_USER="${OWNER_ROLE}"
export SAFENESTT_OWNER_DATABASE_URL="postgresql://${OWNER_ROLE}:${TEST_PASSWORD}@127.0.0.1:${TEST_PORT}/${TEST_DB}"
export SAFENESTT_DATABASE_URL="postgresql://safenestt_app:${TEST_PASSWORD}@127.0.0.1:${TEST_PORT}/${TEST_DB}"
export DATABASE_URL="${SAFENESTT_DATABASE_URL}"
export MODE=development

# --- 3. Default targets, then refuse to proceed if anything is production ---
if [ "$#" -eq 0 ]; then
  set -- tests/
fi

echo "==> Safety gate"
"${REPO}/scripts/ci-safety-gate.sh"

# --- 4. Run, then re-provision ---------------------------------------------
# Grants on tables only apply once the tables exist, and the schema is created
# by the suite's own session fixture. So: run the suite once to create the
# schema (or rely on a previous run), then re-provision so GRANT ON ALL TABLES
# covers the newly created tables. Provisioning is idempotent, so this is safe
# to repeat.
echo "==> Running: $* (against ${DB_HOST}:${DB_PORT}/${DB_NAME})"
cd "${REPO}"
set +e
"${VENV}" -m pytest "$@" -q --no-header --tb=short
rc=$?
set -e

echo "==> Re-provisioning so grants cover any newly created tables"
SAFENESTT_TEST_PASSWORD="${TEST_PASSWORD}" \
SAFENESTT_TEST_APP_PASSWORD="${TEST_PASSWORD}" \
  "${REPO}/scripts/provision-test-app-role.sh" >/dev/null || true

exit "${rc}"