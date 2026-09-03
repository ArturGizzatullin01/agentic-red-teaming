"""Headless-подключение к стенду банка: Keycloak -> sk-genai API-ключ.

Цепочка (без браузера):
  1. Direct Access Grant (password) у Keycloak для тестового пользователя
     client100N (пароль = логин), клиент streamlit-ui.
  2. POST {agent_api}/keys с заголовком X-Forwarded-Access-Token —
     agent-api не проверяет iss/aud, только подпись JWKS.
  3. Ключ sk-genai-... показывается один раз в HTML страницы аккаунта —
     вытаскиваем регуляркой и сохраняем в key store (по умолчанию
     stand_key.json; для stack2 — stand_key_stack2.json, чтобы ключи
     разных стендов не перепутались: они невзаимозаменяемы).

Использование:
  python -m memred.stand_login 1001            # ключ для cus=1001
  python -m memred.stand_login 1001 --base http://localhost:9600 \
      --keycloak http://localhost:9180/realms/genai-stand/protocol/openid-connect/token \
      --store stand_key_stack2.json
"""

import argparse
import json
import re
import sys
from pathlib import Path

import requests

DEFAULTS = {
    "keycloak_token_url": "http://localhost:8180/realms/genai-stand/protocol/openid-connect/token",
    "agent_api": "http://localhost:8600",
    "client_id": "streamlit-ui",
    "client_secret": "streamlit-ui-secret",
}
KEY_RE = re.compile(r"sk-genai-[A-Za-z0-9_\-]+")


def _store_path(store: str = None) -> Path:
    name = store or "stand_key.json"
    p = Path(name)
    return p if p.is_absolute() else Path(__file__).resolve().parent.parent / name


def get_api_key(cus: str, cfg: dict = None, save: bool = True,
                store: str = None) -> str:
    cfg = {**DEFAULTS, **(cfg or {})}
    username = f"client{cus}"

    r = requests.post(cfg["keycloak_token_url"], data={
        "grant_type": "password",
        "client_id": cfg["client_id"],
        "client_secret": cfg["client_secret"],
        "username": username,
        "password": username,
    }, timeout=30)
    if r.status_code != 200:
        raise RuntimeError(f"Keycloak direct grant не удался ({r.status_code}): {r.text[:300]}")
    access_token = r.json()["access_token"]

    r = requests.post(f"{cfg['agent_api']}/keys",
                      headers={"X-Forwarded-Access-Token": access_token}, timeout=30)
    if r.status_code != 200:
        raise RuntimeError(f"POST /keys не удался ({r.status_code}): {r.text[:300]}")
    m = KEY_RE.search(r.text)
    if not m:
        raise RuntimeError("Ключ sk-genai-... не найден в ответе /keys")
    api_key = m.group(0)

    if save:
        sp = _store_path(store)
        data = {}
        if sp.exists():
            try:
                data = json.loads(sp.read_text(encoding="utf-8"))
            except Exception:
                data = {}
        data[cus] = api_key
        sp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return api_key


def load_api_key(cus: str, store: str = None, login_cfg: dict = None) -> str:
    sp = _store_path(store)
    if sp.exists():
        data = json.loads(sp.read_text(encoding="utf-8"))
        if cus in data:
            return data[cus]
    return get_api_key(cus, cfg=login_cfg, store=store)  # получит и сохранит


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("cus", help="номер клиента, например 1001")
    ap.add_argument("--base", default=None, help="адрес agent-api")
    ap.add_argument("--keycloak", default=None, help="URL token-endpoint Keycloak")
    ap.add_argument("--store", default=None, help="файл key store (по умолчанию stand_key.json)")
    args = ap.parse_args()
    cfg = {}
    if args.base:
        cfg["agent_api"] = args.base
    if args.keycloak:
        cfg["keycloak_token_url"] = args.keycloak
    key = get_api_key(args.cus, cfg, store=args.store)
    store_name = args.store or "stand_key.json"
    print(f"cus={args.cus}: {key[:18]}... (сохранён в {store_name})")
