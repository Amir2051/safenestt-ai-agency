#!/usr/bin/env bash
# Run the investigation dispatcher in the foreground.
#
# Used for manual validation. The systemd unit (safenestt-hermes-dispatcher)
# is the production path; this wrapper only exists so the same code and the
# same secret sources can be exercised without systemd.
#
# Secrets are read from /etc/safenestt/engine.env and are never echoed.
set -euo pipefail

REPO=/home/ronzoro/safenestt-ai
VENV=/home/ronzoro/safenestt-platform/apps/api/.venv/bin/python3

set -a
. /etc/safenestt/engine.env
set +a

export DB_SSL_MODE=disable
export MODE=development
export PYTHONUNBUFFERED=1
export MODEL_PROVIDER=openrouter
export OPENROUTER_BASE_URL=https://openrouter.ai/api/v1
export OPENROUTER_MODEL=nvidia/nemotron-3.5-lightning:free

# The OpenRouter key lives in its own file and is exported, never printed.
if [ -z "${OPENROUTER_API_KEY:-}" ] && [ -r /home/ronzoro/openrouter.env ]; then
  OPENROUTER_API_KEY="$(grep -oP 'sk-or-[^\s"'\'']+' /home/ronzoro/openrouter.env | head -1)"
  export OPENROUTER_API_KEY
fi

cd "${REPO}"
exec "${VENV}" -m safenestt.queue.dispatcher "$@"