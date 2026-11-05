#!/usr/bin/env bash
# SafeNestT AI Investigation Engine — Production Startup
# Runs on port 8002 (localhost only, not Cloudflare-exposed)
#
# PRODUCTION STARTUP CONTRACT
# --------------------------
#   DATABASE MIGRATION  (privileged, one-shot, run separately)
#          ↓
#   SECURITY GATE       (read-only, this script, pre-start)
#          ↓
#   APPLICATION START   (exec uvicorn below)
#          ↓
#   TRAFFIC             (also gated at /v1/ready)
#
# The gate is run BEFORE uvicorn is exec'd, so the process never opens a
# listening socket while the database security state is unverified. This
# script has `set -euo pipefail`, so a non-zero gate exit aborts startup
# entirely — the application does not come up in a degraded state.
#
# The gate is the SAME mechanism used by systemd (ExecStartPre) and by the
# Docker Compose API service. There is exactly one implementation:
# safenestt/persistence/startup_gate.py. Do not duplicate the checks here.
#
# This script runs as the APPLICATION role and therefore performs the
# read-only verification only. It CANNOT run the migration: enabling RLS
# requires table ownership, which the least-privilege role does not have.
# Run the privileged step separately:
#
#   SAFENESTT_OWNER_DATABASE_URL=... python -m safenestt.persistence.migrate
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

# ============================================================
# PRE-START SECURITY GATE (authoritative; single implementation)
# ============================================================
# Read-only verification on the application credentials. Exits non-zero if
# any prerequisite is unmet, and `set -e` then aborts this script BEFORE
# uvicorn is exec'd — so no listening socket is ever opened while the
# database security state is unverified.
PYTHON_BIN="${PYTHON_BIN:-/home/ronzoro/safenestt-platform/apps/api/.venv/bin/python3}"

echo "Running pre-start database security gate..."
# SECURITY: migrate before verify. --migrate runs the privileged, idempotent
# migration and then verifies internally; the --verify below re-asserts the same
# invariants on the application credentials. A failure exits non-zero so the
# service never starts against an unverified database.
if ! "$PYTHON_BIN" -m safenestt.persistence.startup_gate --migrate; then
    echo "FATAL: database migration failed - refusing to start." >&2
    exit 1
fi

if ! "$PYTHON_BIN" -m safenestt.persistence.startup_gate --verify; then
    echo "SECURITY GATE FAILED — refusing to start the engine." >&2
    exit 1
fi
echo "Security gate passed."

# ============================================================
# APPLICATION START
# ============================================================
exec "$PYTHON_BIN" -m uvicorn safenestt.api.app:app \
    --host "$HOST" --port "$PORT" --workers "$WORKERS" --log-level info --proxy-headers 2>&1
