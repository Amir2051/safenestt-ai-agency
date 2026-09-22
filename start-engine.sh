#!/usr/bin/env bash
# SafeNestT AI Investigation Engine — Production Startup
# Runs on port 8002 (localhost only, not Cloudflare-exposed)
set -euo pipefail

# ============================================================
# Configuration
# ============================================================
HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-8002}"
WORKERS="${WORKERS:-1}"

# ============================================================
# Environment — MUST be set before starting
# In production, these come from the deployment secret manager.
# DO NOT hardcode production secrets here.
# ============================================================
export MODE="${MODE:-development}"
export HOST
export PORT
export WORKERS

# Database — Supabase Docker PostgreSQL
export DB_HOST="${DB_HOST:-127.0.0.1}"
export DB_PORT="${DB_PORT:-54322}"
export DB_NAME="${DB_NAME:-safenestt_ai}"
export DB_USER="${DB_USER:-safenestt_app}"
export DB_PASSWORD="${DB_PASSWORD:-}"
export DB_SSL_MODE="${DB_SSL_MODE:-disable}"

# API Key (for inter-service auth)
export HERMES_API_KEY="${HERMES_API_KEY:-}"
export HERMES_BASE_URL="${HERMES_BASE_URL:-http://127.0.0.1:8002}"

# Encryption
export SAFENESTT_ENCRYPTION_KEY="${SAFENESTT_ENCRYPTION_KEY:-}"
export ENCRYPTION_AT_REST="${ENCRYPTION_AT_REST:-true}"

# API Key pepper (must match what was used to hash registered keys)
export API_KEY_PEPPER="${API_KEY_PEPPER:-safenestt-pepper-change-in-production}"

# Model provider
export MODEL_PROVIDER="${MODEL_PROVIDER:-ollama}"
export OLLAMA_BASE_URL="${OLLAMA_BASE_URL:-http://localhost:11434}"
export MODEL_NAME="${MODEL_NAME:-qwen3:1.7b}"

# Logging
export DB_QUERY_LOG="${DB_QUERY_LOG:-false}"

# Fernet key (from secrets manager in production — NOT here)
# export FERNET_KEY="..." 

echo "=============================================="
echo "SafeNestT AI Investigation Engine"
echo "  Mode:       ${MODE}"
echo "  Port:       ${PORT}"
echo "  DB:         ${DB_HOST}:${DB_PORT}/${DB_NAME}"
echo "  Model:      ${MODEL_PROVIDER} / ${MODEL_NAME}"
echo "  Encrypt:    ${ENCRYPTION_AT_REST}"
echo "=============================================="

exec /home/ronzoro/safenestt-platform/apps/api/.venv/bin/python3 -m uvicorn safenestt.api.app:app \
    --host "$HOST" --port "$PORT" --workers "$WORKERS" --log-level info --proxy-headers 2>&1
