#!/usr/bin/env bash
# Полный прогон проверок Medusa: границ монолита, ноды, прав и сессий панели, панельного API,
# фронтенда против живого API и моковых сценариев.
#
#   ./tools/run_all.sh
#
# Тестовые серверы поднимаются сами на временной базе: панель, агент ноды на отдельном
# порту, и живая связка «панель → нода по ключу». Ничего poza рабочей директорией не трогает.
# Playwright нужен node-ный: tools/node_modules (npm i playwright в tools/).
set -euo pipefail
cd "$(dirname "$0")/.."

port_free() { ! ss -ltn 2>/dev/null | grep -q ":${1} "; }
PANEL_PORT="${MEDUSA_UI_PORT:-8123}"
NODE_PORT="${MEDUSA_TEST_NODE_PORT:-9443}"
while ! port_free "$PANEL_PORT"; do PANEL_PORT=$((PANEL_PORT + 1)); done
while ! port_free "$NODE_PORT"; do NODE_PORT=$((NODE_PORT + 1)); done

WORK="$(mktemp -d)"
export MEDUSA_UI_URL="http://127.0.0.1:${PANEL_PORT}"
export MEDUSA_DB="$WORK/medusa.db"
export MEDUSA_DEMO=1
export MEDUSA_ADMIN_PASSWORD="testpass12345"

# агент ноды: свой порт, своё состояние, свой API-ключ (в жизни она печатает его сама)
export MEDUSA_TEST_NODE_KEY="sk-api-runall0123456789abcdef00"
export MEDUSA_TEST_NODE_PORT="$NODE_PORT"
export MEDUSA_NODE_API_KEY="$MEDUSA_TEST_NODE_KEY"
export MEDUSA_NODE_PORT="$NODE_PORT"
export MEDUSA_NODE_STATE="$WORK/node-state.json"

echo "=== границы монолита (панель/нода/ядро)"
.venv/bin/python tools/arch_test.py

echo
echo "=== нода: ключ и отдельный порт"
.venv/bin/python tools/node_test.py

.venv/bin/python -m uvicorn src.node.main:app --host 127.0.0.1 --port "$NODE_PORT" >"$WORK/node.log" 2>&1 &
NODE_SRV=$!
trap 'kill $NODE_SRV ${SRV:-} 2>/dev/null || true; wait 2>/dev/null || true; rm -rf "$WORK"' EXIT

for _ in $(seq 60); do
  curl -sf "http://127.0.0.1:${NODE_PORT}/node/health" >/dev/null && break
  sleep 0.25
done
curl -sf "http://127.0.0.1:${NODE_PORT}/node/health" >/dev/null || {
  echo "тестовая нода не поднялась на порту $NODE_PORT: см. $WORK/node.log" >&2; tail -5 "$WORK/node.log" >&2; exit 1; }

echo
echo "=== права, сессии и вход по аппаратному ключу"
.venv/bin/python tools/auth_test.py

echo
echo "=== панельный API, включая живую связку с нодой"
.venv/bin/python tools/panel_test.py

if [ ! -e tools/node_modules/playwright ]; then
  echo "\nPlaywright не найден (tools/node_modules) — UI-проверки пропущены." >&2
  exit 0
fi

.venv/bin/python -m uvicorn src.panel.main:app --host 127.0.0.1 --port "$PANEL_PORT" >"$WORK/panel.log" 2>&1 &
SRV=$!

for _ in $(seq 60); do
  curl -sf "$MEDUSA_UI_URL/api/meta" >/dev/null && break
  sleep 0.25
done
curl -sf "$MEDUSA_UI_URL/api/meta" >/dev/null || {
  echo "тестовая панель не поднялась на порту $PANEL_PORT: см. $WORK/panel.log" >&2; tail -5 "$WORK/panel.log" >&2; exit 1; }

echo
node tools/ui_test.mjs
for suite in live overview clients i18n keys; do
  echo
  echo "=== моковая проверка: $suite"
  node "tools/mock/$suite.mjs"
done

echo
echo "все проверки пройдены"
