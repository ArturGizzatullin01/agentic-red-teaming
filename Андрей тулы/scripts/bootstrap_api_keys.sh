#!/usr/bin/env bash
# scripts/bootstrap_api_keys.sh — headless-получение sk-genai-... ключей для тестовых
# клиентов через Direct Access Grant Keycloak (UI_CLIENT_ID/SECRET) + прямой POST на
# agent-api /keys с синтетическим X-Forwarded-Access-Token — тот же путь, что
# app/agent/runner.py::_get_user_scoped_token документирует как "fallback для
# скриптового тестирования без браузера". Не идёт через oauth2-proxy/браузер вообще.
set -euo pipefail

KEYCLOAK_URL="https://localhost:8443/realms/genai-stand/protocol/openid-connect/token"
AGENT_API_URL="http://localhost:8600"
UI_CLIENT_ID="streamlit-ui"
UI_CLIENT_SECRET="streamlit-ui-secret"

for cus in "$@"; do
  user="client${cus}"
  token=$(curl -sk -m 10 "$KEYCLOAK_URL" \
    -d "grant_type=password" \
    -d "client_id=${UI_CLIENT_ID}" \
    -d "client_secret=${UI_CLIENT_SECRET}" \
    -d "username=${user}" \
    -d "password=${user}" | python -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

  html=$(curl -s -m 10 -X POST "${AGENT_API_URL}/keys" -H "X-Forwarded-Access-Token: ${token}")
  key=$(echo "$html" | grep -oE 'sk-genai-[A-Za-z0-9_-]+' | head -1)
  if [ -z "$key" ]; then
    echo "FAILED for ${user}: no sk-genai key found in response" >&2
    echo "$html" >&2
    exit 1
  fi
  echo "${user}: ${key}"
done
