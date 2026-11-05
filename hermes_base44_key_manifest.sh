#!/bin/bash
# ────────────────────────────────────────────────────────────────
# HERMES BASE44 API KEY — SECURE RETRIEVAL MANIFEST
# ────────────────────────────────────────────────────────────────
# Generated: 2026-09-29 by hermes-bridge-setup
# NEVER EDIT THE SECRET ITSELF — use the retrieval commands below.
# ────────────────────────────────────────────────────────────────

set -euo pipefail

KEY_FILE="/home/ronzoro/safenestt-ai/safenestt/security/hermes_base44_key.txt"
FINGERPRINT="9a8750d5356aa0d48b859acedcdda734df61289f71a9db1ff4e30722c511596a"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

usage() {
    cat <<EOF
HERMES BASE44 API KEY — SECURE LOCATION & RETRIEVAL

The active Hermes API key for the Base44 integration is stored in a
restricted file on the local development machine. It is NEVER printed
in this manifest, logs, commits, or any report.

  TENANT:         tenant-e2e-bridge
  KEY NAME:       base44-integration
  SCOPES:         read, write
  STATUS:         active, not revoked, no expiry
  CREATED:        2026-09-29 05:24 UTC
  FINGERPRINT:    ${FINGERPRINT}
  AUTHENTICATED:  PASS (HTTP 200 on GET /v1/health + POST /v1/investigations)

=== TO RETRIEVE THE KEY (local machine only) ===

  $ cat ${KEY_FILE}

The file is mode 0600 (owner read/write only). Only the file owner
can read it.

=== TO PLACE IN BASE44 SECRETS AS HERMES_API_KEY ===

  $ HERMES_KEY=\$(cat ${KEY_FILE})
  # Paste \$HERMES_KEY into the Base44 Secrets UI for HERMES_API_KEY
  # Or use the Base44 CLI / API to set the secret programmatically.

=== TO VERIFY THE KEY IS STILL ACTIVE ===

  $ curl -s -o /dev/null -w "%{http_code}" \
      https://api.safenestt.com/v1/health \
      -H "X-API-Key: \$(cat ${KEY_FILE})"
  # Expected: 200

=== TO ROTATE THE KEY ===

  python3 - <<'PYEOF'
  import os, sys
  os.environ['DB_HOST']='127.0.0.1'
  os.environ['DB_PORT']='54322'
  os.environ['DB_SSL_MODE']='disable'
  os.environ['SAFENESTT_OWNER_PASSWORD']='...'
  os.environ['SAFENESTT_DB_PASSWORD']='...'
  os.environ['SAFENESTT_ENCRYPTION_KEY']='...'
  os.environ['MODE']='development'
  os.environ['API_KEY_PEPPER']='safenestt-pepper-change-in-production'
  sys.path.insert(0, '/home/ronzoro/safenestt-ai')
  from safenestt.security.api_keys import APIKeyStore
  store = APIKeyStore()
  raw_key, _, fingerprint = store.create_key(
      tenant_id='tenant-e2e-bridge',
      name='base44-integration',
      scopes=['read','write'],
      actor='key-rotation',
  )
  with open('${KEY_FILE}', 'w') as f: f.write(raw_key)
  os.chmod('${KEY_FILE}', 0o600)
  print(f'NEW key fingerprint={fingerprint}')
  # Then revoke the old key via store.revoke_key(old_raw_key)
  PYEOF

=== SECURITY NOTES ===
- Raw key is NEVER stored in DB — only Argon2id hash + SHA-256 fingerprint.
- The fingerprint is safe to log; the raw key is not.
- If compromised, rotate immediately using the steps above.
- This key is for LOCAL DEVELOPMENT / E2E TESTING.
EOF
}

# Sanity: if a secret leaked into this file, redact before distributing
if grep -qE 'sn_live_[A-Za-z0-9_-]{30,}|eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*|[a-f0-9]{64}' "$0"; then
    echo -e "${RED}WARNING: potential secret pattern in manifest — review before use.${NC}"
    exit 1
fi

usage
