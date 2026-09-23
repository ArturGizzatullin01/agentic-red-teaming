"""tests/test_adapter_http_endpoint.py — CARD-T1: generic HTTP target adapter
(tier-1, линия Влада), OpenAI-совместимая chat-ручка.

Все тесты — ТОЛЬКО localhost: фейковый сервер stdlib http.server в потоке,
внешней сети нет, ключи — строки-плейсхолдеры из env.

Замки (карточка §2.3):
 1. ключ — только из env: отсутствие переменной → ValueError при создании;
    в запросе уходит Bearer <env>; конфиг несёт только ИМЯ переменной;
 2. session-история накопительная (эндпоинт stateless — история в адаптере):
    второй send несёт [user, assistant, user];
 3. форма тела OpenAI-совместима: model + messages; session_id = http-<user>-…;
 4. транспорт: 500 → httpx.HTTPStatusError; отказ соединения → TransportError;
    probe на мёртвой ручке → reachable=False с причиной, не трейсбек;
 5. reset недоступен честно: reset_available=False, исключения нет;
 6. ноль выдуманной наблюдаемости: get_trace/snapshot/snapshot_user = None,
    capabilities все False; WRITE-оракул на таких данных → UNKNOWN;
 7. wait_until_persistent → SettleResult.unavailable с именем сигнала
    (НЕ дефолт-ловушка observed из base.py:134 — замок карточки §2.1);
 8. таймаут > 30 с → громкий ValueError; send в неизвестную/закрытую сессию —
    громкий ValueError.
"""

from __future__ import annotations

import asyncio
import json
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx
import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from memnotsafe.adapters.base import Capabilities  # noqa: E402
from memnotsafe.adapters.http_endpoint import HttpEndpointAdapter  # noqa: E402
from memnotsafe.attacks.base import AttackContext  # noqa: E402
from memnotsafe.core.models import AttackCandidate  # noqa: E402
from memnotsafe.oracles.base import EvaluationContext  # noqa: E402
from memnotsafe.oracles.memory import evaluate_memory  # noqa: E402

KEY_ENV = "MEMNOTSAFE_TARGET_API_KEY"
KEY_PLACEHOLDER = "test-key-placeholder-not-a-secret"
MODEL = "partner-agent"


class _FakeOpenAIHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802 — контракт http.server
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b"{}"
        self.server.requests.append({  # type: ignore[attr-defined]
            "path": self.path,
            "auth": self.headers.get("Authorization"),
            "body": json.loads(raw),
        })
        status = int(getattr(self.server, "next_status", 200))  # type: ignore[attr-defined]
        if status >= 400:
            payload = {"error": {"message": "fake server failure"}}
        else:
            users = [m for m in self.server.requests[-1]["body"].get("messages", [])  # type: ignore[attr-defined]
                     if m.get("role") == "user"]
            payload = {"id": "chatcmpl-fake", "choices": [
                {"message": {"role": "assistant", "content": f"echo:{users[-1]['content'] if users else ''}"}}
            ]}
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args) -> None:  # тишина в pytest-выводе
        return


@pytest.fixture()
def fake_server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _FakeOpenAIHandler)
    srv.requests = []  # type: ignore[attr-defined]
    srv.next_status = 200  # type: ignore[attr-defined]
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield srv
    srv.shutdown()
    srv.server_close()


@pytest.fixture()
def key_env(monkeypatch):
    monkeypatch.setenv(KEY_ENV, KEY_PLACEHOLDER)


def _adapter(base_url: str, **kw) -> HttpEndpointAdapter:
    return HttpEndpointAdapter(base_url=base_url, model_name=MODEL, **kw)


def _free_dead_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


# ------------------------------------------------------------ ключ из env


def test_api_key_env_required(key_env, monkeypatch, fake_server) -> None:
    monkeypatch.delenv(KEY_ENV, raising=False)
    with pytest.raises(ValueError, match=KEY_ENV):
        _adapter(f"http://127.0.0.1:{fake_server.server_address[1]}")


def test_api_key_only_from_env_in_request(fake_server, key_env) -> None:
    ada = _adapter(f"http://127.0.0.1:{fake_server.server_address[1]}")
    try:
        sid = asyncio.run(ada.new_session("1001"))
        asyncio.run(ada.send(sid, "ping"))
        assert fake_server.requests[-1]["auth"] == f"Bearer {KEY_PLACEHOLDER}"
        assert ada.api_key_env == KEY_ENV  # конфиг несёт только ИМЯ переменной
    finally:
        asyncio.run(ada.aclose())


# ------------------------------------------------------------ история и форма


def test_history_accumulative_and_body_shape(fake_server, key_env) -> None:
    ada = _adapter(f"http://127.0.0.1:{fake_server.server_address[1]}")
    try:
        sid = asyncio.run(ada.new_session("1001"))
        asyncio.run(ada.send(sid, "первое сообщение"))
        asyncio.run(ada.send(sid, "второе сообщение"))
        body = fake_server.requests[-1]["body"]
        assert body["model"] == MODEL
        roles = [m["role"] for m in body["messages"]]
        assert roles == ["user", "assistant", "user"]
        assert body["messages"][0]["content"] == "первое сообщение"
        assert body["messages"][1]["content"] == "echo:первое сообщение"
        assert body["messages"][2]["content"] == "второе сообщение"
        reply = asyncio.run(ada.send(sid, "третье"))
        assert reply.content == "echo:третье"
    finally:
        asyncio.run(ada.aclose())


def test_session_id_naming(fake_server, key_env) -> None:
    ada = _adapter(f"http://127.0.0.1:{fake_server.server_address[1]}")
    sid = asyncio.run(ada.new_session("1001"))
    assert sid.startswith("http-1001-")


# ------------------------------------------------------------ транспорт


def test_500_raises_status_error(fake_server, key_env) -> None:
    fake_server.next_status = 500
    ada = _adapter(f"http://127.0.0.1:{fake_server.server_address[1]}")
    try:
        sid = asyncio.run(ada.new_session("1001"))
        with pytest.raises(httpx.HTTPStatusError):
            asyncio.run(ada.send(sid, "payload"))
    finally:
        asyncio.run(ada.aclose())


def test_connection_refused_transport_error(key_env) -> None:
    ada = _adapter(f"http://127.0.0.1:{_free_dead_port()}")
    try:
        sid = asyncio.run(ada.new_session("1001"))
        with pytest.raises(httpx.TransportError):
            asyncio.run(ada.send(sid, "payload"))
    finally:
        asyncio.run(ada.aclose())


def test_probe_false_on_dead_handle(key_env) -> None:
    ada = _adapter(f"http://127.0.0.1:{_free_dead_port()}")
    result = asyncio.run(ada.probe())
    assert result.reachable is False
    assert result.error  # причина строкой, не трейсбек


def test_probe_alive(fake_server, key_env) -> None:
    ada = _adapter(f"http://127.0.0.1:{fake_server.server_address[1]}")
    try:
        result = asyncio.run(ada.probe())
        assert result.reachable is True
        assert result.detail.get("status") == 200
    finally:
        asyncio.run(ada.aclose())


# ------------------------------------------------------------ reset/наблюдаемость


def test_reset_unavailable_honestly(fake_server, key_env) -> None:
    ada = _adapter(f"http://127.0.0.1:{fake_server.server_address[1]}")
    assert ada.reset_available is False
    sid = asyncio.run(ada.new_session("1001"))
    asyncio.run(ada.send(sid, "x"))
    assert asyncio.run(ada.reset_state()) is None  # без исключения
    with pytest.raises(ValueError, match="сесс"):  # локальная история очищена
        asyncio.run(ada.send(sid, "y"))


def test_no_fabricated_observability(fake_server, key_env) -> None:
    ada = _adapter(f"http://127.0.0.1:{fake_server.server_address[1]}")
    sid = asyncio.run(ada.new_session("1001"))
    assert asyncio.run(ada.get_trace(sid)) is None
    assert asyncio.run(ada.snapshot()) is None
    assert asyncio.run(ada.snapshot_user("1001")) is None
    assert ada.capabilities.to_dict() == {"trace": False, "memory_snapshot": False,
                                          "tool_calls": False, "retrieval": False}


def test_write_oracle_unknown_on_adapter_data(fake_server, key_env) -> None:
    """Снимков нет → WRITE-оракул обязан ответить UNKNOWN (правок оракулов
    нет: None-каналы адаптера уже покрыты доктриной UNKNOWN≠False)."""
    ada = _adapter(f"http://127.0.0.1:{fake_server.server_address[1]}")
    ctx = AttackContext(attacker_user_id="1001", victim_user_id="1002",
                        run_seed=7, case_id="case-t1")
    cand = AttackCandidate(attack_id="t1", family="cross_user_bac", payload="p", trigger="t",
                           expected_effect={"type": "response_reflects_adoption"})
    ec = EvaluationContext(candidate=cand, ctx=ctx, capabilities=ada.capabilities,
                           before=None, after=None, diff=None,
                           baseline_response="", victim_response="")
    stage = evaluate_memory(ec)
    assert stage.success is None and stage.stage == "write"


def test_settle_unavailable_not_observed(fake_server, key_env) -> None:
    ada = _adapter(f"http://127.0.0.1:{fake_server.server_address[1]}")
    settle = asyncio.run(ada.wait_until_persistent({"case_marker": "CM-abcdef"}))
    assert settle.outcome == "unavailable"
    assert settle.success is None
    assert settle.reason.strip()  # имя сигнала/причина обязательны
    assert settle.outcome != "observed"  # НЕ дефолт-ловушка base.py:134


# ------------------------------------------------------------ границы


def test_timeout_over_30_rejected(key_env) -> None:
    with pytest.raises(ValueError, match="30"):
        _adapter("http://127.0.0.1:1", timeout_s=60.0)


def test_unknown_session_rejected(fake_server, key_env) -> None:
    ada = _adapter(f"http://127.0.0.1:{fake_server.server_address[1]}")
    with pytest.raises(ValueError, match="сесс"):
        asyncio.run(ada.send("http-1001-deadbeef", "x"))


def test_close_session_then_send_rejected(fake_server, key_env) -> None:
    ada = _adapter(f"http://127.0.0.1:{fake_server.server_address[1]}")
    sid = asyncio.run(ada.new_session("1001"))
    asyncio.run(ada.close_session(sid))
    with pytest.raises(ValueError, match="сесс"):
        asyncio.run(ada.send(sid, "x"))
