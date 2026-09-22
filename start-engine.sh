#!/usr/bin/env bash
# SafeNestT AI Investigation Engine — Production Startup
# Runs on port 8002 (localhost only, not Cloudflare-exposed)
#
# DO NOT commit real secrets to this file.
# In production, secrets come from the deployment secret manager
# (e.g. SOPS-encrypted .env, HashiCorp Vault, or container secrets).
# This file documents the required variables and their defaults.
#
# Required secrets (set via environment or secret manager):
#   DB_PASSWORD         — PostgreSQL password for DB_USER
#   HERMES_API_KEY      — Server-to-server API key (registered in engine DB)
#   SAFENESTT_ENCRYPTION_KEY — Fernet key for encryption at rest
#   API_KEY_PEPPER       — Pepper used when hashing API keys (must match DB)
#
# Generated artifacts (from .gitignore'd secrets file):
#   See .env.secrets.example for the template.

set -euo pipefail

# ============================================================
# Configuration
# ============================================================
HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-8002}"
WORKERS="${WORKERS:-1}"

# ============================================================
# Environment (defaults for development; override in production)
# ============================================================
export MODE="${MODE:-development}"
export HOST
export PORT
export WORKERS

# Database — Supabase Docker PostgreSQL (separate from SafeNestT's DB)
export DB_HOST="${DB_HOST:-127.0.0.1}"
export DB_PORT="${DB_PORT:-54322}"
export DB_NAME="${DB_NAME:-safenestt_ai}"
export DB_USER="${DB_USER:-safenestt_app}"
export DB_SSL_MODE="${DB_SSL_MODE:-disable}"

# API Key (for inter-service auth — must be registered in engine's api_keys table)
export HERMES_API_KEY="${HERMES_API_KEY:-}"
export HERMES_BASE_URL="${HERMES_BASE_URL:-http://127.0.0.1:8002}"

# Encryption at rest
export SAFENESTT_ENCRYPTION_KEY="${SAFENESTT_ENCRYPTION_KEY:-}"
export ENCRYPTION_AT_REST="${ENCRYPTION_AT_REST:-true}"

# API key pepper — MUST match what was used to hash registered keys
export API_KEY_PEPPER="${API_KEY_PEPPER:-safenestt-pepper-change-in-production}"

# Model provider
export MODEL_PROVIDER="${MODEL_PROVIDER:-ollama}"
export OLLAMA_BASE_URL="${OLLAMA_BASE_URL:-http://localhost:11434}"
export MODEL_NAME="${MODEL_NAME:-qwen3:1.7b}"

# Logging
export DB_QUERY_LOG="${DB_QUERY_LOG:-false}"

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
