#!/usr/bin/env bash
# Install/refresh the SafeNestT production units.
#
# Run as:  sudo bash /home/ronzoro/safenestt-ai/scripts/install-production-units.sh
#
# Usage:
#   ... install-production-units.sh              # engine + dispatcher
#   ... install-production-units.sh --engine-only  # engine only, NOT dispatcher
#
# --engine-only exists because the engine unit and the dispatcher unit have
# independent readiness criteria. The dispatcher must not be installed until
# the backend's Hermes credential and the engine's model provider have both
# been verified, otherwise it starts consuming the queue on a misconfigured
# provider.
#
# This script only installs units, enables them, and adds the OpenRouter key to
# the existing secret file. It never prints a secret value.
set -euo pipefail

ENGINE_ONLY=0
for arg in "$@"; do
  case "${arg}" in
    --engine-only) ENGINE_ONLY=1 ;;
    *) echo "unknown argument: ${arg}" >&2; exit 2 ;;
  esac
done

REPO=/home/ronzoro/safenestt-ai
SECRETS=/etc/safenestt/engine.env
LOGDIR=/var/log/safenestt

echo "==> Creating ${LOGDIR}"
install -d -o ronzoro -g ronzoro -m 0750 "${LOGDIR}"

echo "==> Backing up existing units (if any)"
ts="$(date +%Y%m%d%H%M%S)"
for u in safenestt-engine safenestt-hermes-dispatcher; do
  if [ -f "/etc/systemd/system/${u}.service" ]; then
    cp -a "/etc/systemd/system/${u}.service" "/etc/systemd/system/${u}.service.bak-${ts}"
    echo "    backed up ${u}.service"
  fi
done

echo "==> Installing units"
install -m 0644 -o root -g root "${REPO}/safenestt-engine.service" \
  /etc/systemd/system/safenestt-engine.service
if [ "${ENGINE_ONLY}" -eq 0 ]; then
  install -m 0644 -o root -g root "${REPO}/safenestt-hermes-dispatcher.service" \
    /etc/systemd/system/safenestt-hermes-dispatcher.service
else
  echo "    --engine-only: NOT installing safenestt-hermes-dispatcher.service"
fi

echo "==> Adding OPENROUTER_API_KEY to ${SECRETS} (value never echoed)"
if [ ! -f "${SECRETS}" ]; then
  echo "ERROR: ${SECRETS} missing. Refusing to invent credentials." >&2
  exit 1
fi
if grep -q '^OPENROUTER_API_KEY=' "${SECRETS}"; then
  echo "    already present — left untouched"
else
  key="$(grep -oP 'sk-or-[^\s"'\'']+' /home/ronzoro/openrouter.env | head -1 || true)"
  if [ -z "${key}" ]; then
    echo "ERROR: no sk-or- key found in /home/ronzoro/openrouter.env" >&2
    exit 1
  fi
  printf 'OPENROUTER_API_KEY=%s\n' "${key}" >> "${SECRETS}"
  unset key
  echo "    added"
fi
chown root:safenestt "${SECRETS}" 2>/dev/null || chown root:ronzoro "${SECRETS}"
chmod 0640 "${SECRETS}"

echo "==> systemd reload + enable"
systemctl daemon-reload
systemctl enable safenestt-engine.service
if [ "${ENGINE_ONLY}" -eq 0 ]; then
  systemctl enable safenestt-hermes-dispatcher.service
fi

echo "==> Restarting engine (picks up OpenRouter + boot-order fix)"
systemctl restart safenestt-engine.service

# Wait for the health endpoint rather than sleeping blindly.
echo "==> Waiting for /v1/health"
for i in $(seq 1 60); do
  if curl -fsS --max-time 3 http://127.0.0.1:8002/v1/health >/dev/null 2>&1; then
    echo "    engine healthy after ${i}s"
    break
  fi
  sleep 1
done

if [ "${ENGINE_ONLY}" -eq 1 ]; then
  echo "==> --engine-only: dispatcher NOT started (by request)"
else
  echo "==> Starting dispatcher"
  systemctl restart safenestt-hermes-dispatcher.service
fi

echo
echo "==> Status"
systemctl --no-pager --lines=0 status safenestt-engine.service || true
if [ "${ENGINE_ONLY}" -eq 0 ]; then
  systemctl --no-pager --lines=0 status safenestt-hermes-dispatcher.service || true
fi
echo
echo "==> Engine health:"
curl -fsS --max-time 5 http://127.0.0.1:8002/v1/health || echo "(unavailable)"
echo
echo "Done."