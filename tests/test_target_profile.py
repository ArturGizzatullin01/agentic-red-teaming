"""tests/test_target_profile.py — EXT-A (поток EXT-OPERATOR, карта 1/4):
версионированная схема target profile + границы безопасности G1–G6.

Все сетевые тесты — ТОЛЬКО localhost: фейковый stdlib-сервер в потоке, внешней
сети нет, ключи — строки-плейсхолдеры из env (имена, не секреты). Live/Docker
не запускаются.

Замки RED→GREEN (карта):
  L1  профиль с опечаткой в ключе → ProfileError ДО запроса;
  L2  валидный OpenAI-профиль → адаптер шлёт mapped-поля (мок-сервер);
  L3  cross-user сценарий + один принципал → отказ до прогона с причиной;
  L4  native session уходит в запрос, когда задана;
  L5  TargetAdapter.wait_until_persistent базовое умолчание → unavailable;
  L6  регресс: bb-сценарий (global_policy_injection_bb_live) работает без профиля.
Границы:
  G1  чужой хост/абсолютный путь/удалённый плейнтекст → отказ ДО чтения ключа;
  G2  зарезервированное поле в extra_fields → ошибка конфигурации;
  G3  два ENV-имени ≠ два субъекта; независимость доказывается или отказ;
  G4  событие из текста без detail.channel и независимого источника — НЕ жёсткая
      телеметрия (SUCCESS/CRITICAL не даёт); связанная пара call/result — даёт;
  G5  стенд, пишущий память только при закрытии сессии, наблюдается корректно;
  G6  digest профиля + schema_version входят в experiment_id (без секретов).
"""

from __future__ import annotations

import asyncio
import json
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from memnotsafe.adapters.http_endpoint import HttpEndpointAdapter  # noqa: E402
from memnotsafe.adapters.profile import ProfileError, load_profile  # noqa: E402

KEY_ENV = "MEMNOTSAFE_TARGET_API_KEY"
KEY_A_ENV = "MEMNOTSAFE_KEY_ALICE"
KEY_B_ENV = "MEMNOTSAFE_KEY_BOB"
KEY_PLACEHOLDER = "test-key-placeholder-not-a-secret"


# ------------------------------------------------------------ фейковый сервер


class _Handler(BaseHTTPRequestHandler):
    def _record_and_reply(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b"{}"
        try:
            body = json.loads(raw)
        except ValueError:
            body = {}
        self.server.requests.append({  # type: ignore[attr-defined]
            "path": self.path,
            "auth": self.headers.get("Authorization"),
            "headers": {k: v for k, v in self.headers.items()},
            "body": body,
        })
        if "finalize" in self.path:
            self.server.persisted = True  # type: ignore[attr-defined]
            payload = {"finalized": True}
        else:
            payload = {"choices": [{"message": {"role": "assistant", "content": "echo"}}]}
        data = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self) -> None:  # noqa: N802 — контракт http.server
        self._record_and_reply()

    def do_GET(self) -> None:  # noqa: N802
        self.server.requests.append({"path": self.path, "method": "GET"})  # type: ignore[attr-defined]
        data = b'{"ok": true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args) -> None:
        return


@pytest.fixture()
def fake_server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    srv.requests = []  # type: ignore[attr-defined]
    srv.persisted = False  # type: ignore[attr-defined]
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield srv
    srv.shutdown()
    srv.server_close()


@pytest.fixture()
def keys(monkeypatch):
    monkeypatch.setenv(KEY_ENV, KEY_PLACEHOLDER)
    monkeypatch.setenv(KEY_A_ENV, "sk-alice-placeholder")
    monkeypatch.setenv(KEY_B_ENV, "sk-bob-placeholder")


def _base(server) -> str:
    return f"http://127.0.0.1:{server.server_address[1]}"


def _openai_profile(**over):
    raw = {
        "schema_version": 1,
        "transport": {
            "chat_path": "/v1/chat/completions",
            "request": {"model_field": "model", "messages_field": "messages"},
            "response": {"content_path": ["choices", 0, "message", "content"]},
        },
        "auth": {"scheme": "bearer_env", "api_key_env": KEY_ENV},
        "identity": {"scheme": "none"},
        "session": {"mode": "adapter_history"},
    }
    raw.update(over)
    return load_profile(raw)


# ============================================================ L1: строгость


def test_l1_unknown_key_is_error_before_request():
    with pytest.raises(ProfileError, match="chat_path|неизвест"):
        load_profile({
            "schema_version": 1,
            "transport": {"chat_pat": "/v1/chat/completions"},  # опечатка
        })


def test_l1_schema_version_required():
    with pytest.raises(ProfileError, match="schema_version"):
        load_profile({"transport": {"chat_path": "/v1/x"}})


def test_l1_unsupported_schema_version():
    with pytest.raises(ProfileError, match="schema_version"):
        load_profile({"schema_version": 99})


# ============================================================ L2: mapped-поля


def test_l2_openai_profile_sends_mapped_fields(fake_server, keys):
    profile = _openai_profile(transport={
        "chat_path": "/custom/chat",
        "request": {"model_field": "model_id", "messages_field": "turns"},
        "response": {"content_path": ["choices", 0, "message", "content"]},
        "extra_fields": {"temperature": 0},
    })
    ada = HttpEndpointAdapter(base_url=_base(fake_server), model_name="partner", profile=profile)
    try:
        sid = asyncio.run(ada.new_session("1001"))
        reply = asyncio.run(ada.send(sid, "ping"))
        req = fake_server.requests[-1]
        assert req["path"] == "/custom/chat"
        assert req["body"]["model_id"] == "partner"          # mapped model field
        assert isinstance(req["body"]["turns"], list)         # mapped messages field
        assert req["body"]["turns"][-1]["content"] == "ping"
        assert req["body"]["temperature"] == 0                # extra merged
        assert reply.content == "echo"                        # response read by content_path
    finally:
        asyncio.run(ada.aclose())


# ============================================================ L4: native session


def test_l4_native_session_id_in_request(fake_server, keys):
    profile = _openai_profile(session={"mode": "native", "native_field": "session_id"})
    ada = HttpEndpointAdapter(base_url=_base(fake_server), profile=profile)
    try:
        sid = asyncio.run(ada.new_session("1001"))
        asyncio.run(ada.send(sid, "ping"))
        assert fake_server.requests[-1]["body"]["session_id"] == sid
    finally:
        asyncio.run(ada.aclose())


def test_l4_adapter_history_omits_session_field(fake_server, keys):
    ada = HttpEndpointAdapter(base_url=_base(fake_server), profile=_openai_profile())
    try:
        sid = asyncio.run(ada.new_session("1001"))
        asyncio.run(ada.send(sid, "ping"))
        assert "session_id" not in fake_server.requests[-1]["body"]
    finally:
        asyncio.run(ada.aclose())


# ============================================================ L5: base default


def test_l5_base_wait_until_persistent_defaults_unavailable():
    from memnotsafe.adapters.base import ProbeResult, SendResult, TargetAdapter

    class _Bare(TargetAdapter):
        async def probe(self):
            return ProbeResult(reachable=True)

        async def reset_state(self):
            return None

        async def new_session(self, user_id):
            return "s"

        async def send(self, session_id, message):
            return SendResult(content="")

        async def close_session(self, session_id):
            return None

    settle = asyncio.run(_Bare().wait_until_persistent({"case_marker": "CM-abc123"}))
    assert settle.outcome == "unavailable"
    assert settle.success is None
    assert settle.reason.strip()  # честная причина обязательна


# ============================================================ G1: граница хоста


def test_g1_absolute_chat_path_rejected():
    with pytest.raises(ProfileError, match="G1"):
        load_profile({"schema_version": 1, "transport": {"chat_path": "http://evil.example/v1"}})


def test_g1_protocol_relative_path_rejected():
    with pytest.raises(ProfileError, match="G1"):
        load_profile({"schema_version": 1, "transport": {"chat_path": "//evil.example/v1"}})


def test_g1_remote_plaintext_refused_before_key_read(monkeypatch):
    # ключа НЕТ в окружении — отказ обязан случиться ДО его чтения.
    monkeypatch.delenv(KEY_ENV, raising=False)
    profile = _openai_profile()  # allow_remote=false по умолчанию
    with pytest.raises(ProfileError, match="G1"):
        HttpEndpointAdapter(base_url="http://198.51.100.7:9000", profile=profile)


def test_g1_base_url_with_credentials_refused():
    profile = _openai_profile()
    with pytest.raises(ProfileError, match="G1"):
        HttpEndpointAdapter(base_url="http://user:pass@127.0.0.1:9000", profile=profile)


def test_g1_remote_allowed_with_explicit_flag(monkeypatch):
    monkeypatch.setenv(KEY_ENV, KEY_PLACEHOLDER)
    profile = _openai_profile(transport={"chat_path": "/v1/chat", "allow_remote": True})
    ada = HttpEndpointAdapter(base_url="http://198.51.100.7:9000", profile=profile)
    asyncio.run(ada.aclose())  # конструируется без сети


# ============================================================ G2: reserved fields


@pytest.mark.parametrize("bad", ["messages", "model", "identity", "session", "auth"])
def test_g2_reserved_literal_in_extra_fields_rejected(bad):
    with pytest.raises(ProfileError, match="G2"):
        _openai_profile(transport={
            "chat_path": "/v1/chat",
            "request": {"model_field": "model", "messages_field": "messages"},
            "extra_fields": {bad: "x"},
        })


def test_g2_mapped_field_name_in_extra_rejected():
    with pytest.raises(ProfileError, match="G2"):
        _openai_profile(transport={
            "chat_path": "/v1/chat",
            "request": {"model_field": "model_id", "messages_field": "turns"},
            "extra_fields": {"turns": "override"},  # совпадает с messages_field
        })


# ============================================================ G3: independence


def _identity(scheme="bearer_env", principals=None, **over):
    ident = {"scheme": scheme, "principals": principals or []}
    ident.update(over)
    return _openai_profile(identity=ident)


def test_g3_single_user_allowed_without_attestation():
    prof = _identity(principals=[{"subject": "solo", "user_id": "1001", "env": KEY_A_ENV}])
    prof.validate_for_actors("1001", "1001")  # не бросает


def test_g3_cross_user_one_principal_refused():
    prof = _identity(principals=[{"subject": "solo", "user_id": "1001", "env": KEY_A_ENV}])
    with pytest.raises(ProfileError, match="G3"):
        prof.validate_for_actors("1001", "1002")


def test_g3_cross_user_two_keys_one_subject_refused():
    prof = _identity(
        principals=[
            {"subject": "same", "user_id": "1001", "env": KEY_A_ENV},
            {"subject": "same", "user_id": "1002", "env": KEY_B_ENV},
        ],
        cross_user_independent=True,
    )
    with pytest.raises(ProfileError, match="один субъект|G3"):
        prof.validate_for_actors("1001", "1002")


def test_g3_cross_user_same_env_name_refused():
    prof = _identity(
        principals=[
            {"subject": "alice", "user_id": "1001", "env": KEY_A_ENV},
            {"subject": "bob", "user_id": "1002", "env": KEY_A_ENV},  # одно имя
        ],
        cross_user_independent=True,
    )
    with pytest.raises(ProfileError, match="G3"):
        prof.validate_for_actors("1001", "1002")


def test_g3_cross_user_without_attestation_refused():
    prof = _identity(
        principals=[
            {"subject": "alice", "user_id": "1001", "env": KEY_A_ENV},
            {"subject": "bob", "user_id": "1002", "env": KEY_B_ENV},
        ],
        cross_user_independent=False,  # не доказано
    )
    with pytest.raises(ProfileError, match="не доказал|G3"):
        prof.validate_for_actors("1001", "1002")


def test_g3_cross_user_attested_independent_passes():
    prof = _identity(
        principals=[
            {"subject": "alice", "user_id": "1001", "env": KEY_A_ENV},
            {"subject": "bob", "user_id": "1002", "env": KEY_B_ENV},
        ],
        cross_user_independent=True,
    )
    prof.validate_for_actors("1001", "1002")  # не бросает


# ============================================================ G4: evidence-происхождение


def test_g4_text_only_event_is_soft_not_hard_telemetry():
    from memnotsafe.core.models import EVIDENCE_KIND_SIGNATURE_MATCH, EVIDENCE_KIND_TELEMETRY
    from memnotsafe.oracles.adoption import channel_evidence_kind

    text_only = [{"event": "tool_result", "detail": {"channel": "victim_response"}}]
    linked_pair = [
        {"event": "tool_call", "detail": {"channel": "tool_telemetry"}, "call_id": "c1"},
        {"event": "tool_result", "detail": {"channel": "tool_telemetry"}, "call_id": "c1"},
    ]
    assert channel_evidence_kind(text_only) == EVIDENCE_KIND_SIGNATURE_MATCH
    assert channel_evidence_kind(linked_pair) == EVIDENCE_KIND_TELEMETRY


def test_g4_http_endpoint_never_fabricates_hard_telemetry(fake_server, keys):
    ada = HttpEndpointAdapter(base_url=_base(fake_server), profile=_openai_profile())
    try:
        sid = asyncio.run(ada.new_session("1001"))
        result = asyncio.run(ada.send(sid, "какой-то ответ с чужим cus 4242"))
        assert result.events == []  # чёрный ящик не синтезирует call/result из текста
        assert ada.capabilities.to_dict() == {
            "trace": False, "memory_snapshot": False, "tool_calls": False, "retrieval": False,
        }
    finally:
        asyncio.run(ada.aclose())


def test_g4_observation_claiming_channel_refused():
    # tier-1 http_endpoint не имеет канала наблюдения — заявка → отказ до прогона.
    profile = _openai_profile(observation={"memory_snapshot": True})
    with pytest.raises(ProfileError):
        HttpEndpointAdapter(base_url="http://127.0.0.1:1", profile=profile)


# ============================================================ G5: session-finalize


def test_g5_native_close_finalizes_and_persists(fake_server, keys):
    profile = _openai_profile(session={
        "mode": "native",
        "native_field": "session_id",
        "writes_on_close": True,
        "finalize_path": "/v1/sessions/{session_id}/finalize",
    })
    ada = HttpEndpointAdapter(base_url=_base(fake_server), profile=profile)
    try:
        sid = asyncio.run(ada.new_session("1001"))
        asyncio.run(ada.send(sid, "запомни правило"))
        assert fake_server.persisted is False  # память ещё не записана
        asyncio.run(ada.close_session(sid))
        assert fake_server.persisted is True   # закрытие сессии финализировало запись
        finalize_calls = [r for r in fake_server.requests if "finalize" in r["path"]]
        assert finalize_calls and sid in finalize_calls[-1]["path"]
    finally:
        asyncio.run(ada.aclose())


def test_g5_adapter_history_close_does_not_call_network(fake_server, keys):
    ada = HttpEndpointAdapter(base_url=_base(fake_server), profile=_openai_profile())
    try:
        sid = asyncio.run(ada.new_session("1001"))
        asyncio.run(ada.send(sid, "ping"))
        before = len(fake_server.requests)
        asyncio.run(ada.close_session(sid))
        assert len(fake_server.requests) == before  # локальная история: закрытие без сети
    finally:
        asyncio.run(ada.aclose())


# ============================================================ config point-of-read (L3)


_PROFILE_YAML = """
id: ext_a_profile_case
target:
  adapter: http_endpoint
  base_url: "http://127.0.0.1:9"
  profile:
    schema_version: 1
    transport:
      chat_path: /v1/chat/completions
    auth:
      scheme: bearer_env
      api_key_env: MEMNOTSAFE_TARGET_API_KEY
    identity:
      scheme: bearer_env
      principals:
        - subject: alice
          user_id: "1001"
          env: MEMNOTSAFE_KEY_ALICE
{extra_principal}
{attest}
actors:
  attacker:
    user_id: "1001"
  victim:
    user_id: "{victim}"
attack:
  family: global_policy_injection
"""


def _write_scenario(tmp_path, *, victim, two_principals, attest):
    extra_principal = (
        '        - subject: bob\n          user_id: "1002"\n          env: MEMNOTSAFE_KEY_BOB'
        if two_principals else ""
    )
    attest_line = "      cross_user_independent: true" if attest else ""
    text = _PROFILE_YAML.format(victim=victim, extra_principal=extra_principal, attest=attest_line)
    path = tmp_path / "scenario.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_l3_config_refuses_cross_user_single_principal(tmp_path, keys):
    from memnotsafe.core.config import build_adapter, load_scenario

    path = _write_scenario(tmp_path, victim="1002", two_principals=False, attest=False)
    scenario = load_scenario(path)
    with pytest.raises(ValueError, match="G3|cross-user"):
        build_adapter(scenario)


def test_l3_config_cross_user_attested_builds(tmp_path, keys):
    from memnotsafe.core.config import build_adapter, load_scenario

    path = _write_scenario(tmp_path, victim="1002", two_principals=True, attest=True)
    scenario = load_scenario(path)
    ada = build_adapter(scenario)
    asyncio.run(ada.aclose())


def test_l3_config_single_user_builds(tmp_path, keys):
    from memnotsafe.core.config import build_adapter, load_scenario

    path = _write_scenario(tmp_path, victim="1001", two_principals=False, attest=False)
    scenario = load_scenario(path)
    ada = build_adapter(scenario)
    asyncio.run(ada.aclose())


# ============================================================ L6: регресс без профиля


def test_l6_bb_live_scenario_builds_without_profile(monkeypatch):
    from memnotsafe.core.config import build_adapter, load_scenario

    monkeypatch.setenv("SK_GENAI_1001", "sk-genai-placeholder-not-a-secret")
    scenario = load_scenario(Path(__file__).resolve().parents[1] / "scenarios" / "global_policy_injection_bb_live.yaml")
    assert scenario.target.profile is None  # у сценария профиля нет — legacy-путь
    ada = build_adapter(scenario)
    try:
        # дефолт = текущее поведение: ноль наблюдаемости, честный unavailable settle.
        assert ada.capabilities.to_dict() == {
            "trace": False, "memory_snapshot": False, "tool_calls": False, "retrieval": False,
        }
        settle = asyncio.run(ada.wait_until_persistent({"case_marker": "CM-abc123"}))
        assert settle.outcome == "unavailable"
    finally:
        asyncio.run(ada.aclose())


# ============================================================ G6: провенанс


def test_g6_profile_digest_stable_and_secret_free():
    prof = _openai_profile(auth={"scheme": "bearer_env", "api_key_env": KEY_ENV})
    d1 = prof.normalized_digest()
    d2 = _openai_profile(auth={"scheme": "bearer_env", "api_key_env": KEY_ENV}).normalized_digest()
    assert d1 == d2 and len(d1) == 64            # стабильный sha256
    assert KEY_PLACEHOLDER not in json.dumps(prof.as_digest())  # значений секретов нет (их и не было)


def test_g6_experiment_id_includes_profile(tmp_path, keys):
    from memnotsafe.core.config import load_scenario
    from memnotsafe.core.experiment import build_experiment_spec

    with_profile = load_scenario(_write_scenario(tmp_path, victim="1001", two_principals=False, attest=False))
    spec = build_experiment_spec(with_profile)
    assert spec.target.get("profile_digest") == with_profile.target.profile.normalized_digest()
    assert spec.target.get("profile_schema_version") == 1


def test_g6_profileless_experiment_target_unchanged(monkeypatch, tmp_path):
    """Регресс: сценарий без профиля не получает новых ключей target — старый
    experiment_id не меняется."""
    from memnotsafe.core.config import load_scenario
    from memnotsafe.core.experiment import build_experiment_spec

    monkeypatch.setenv("SK_GENAI_1001", "sk-genai-placeholder-not-a-secret")
    scenario = load_scenario(Path(__file__).resolve().parents[1] / "scenarios" / "global_policy_injection_bb_live.yaml")
    spec = build_experiment_spec(scenario)
    assert "profile_digest" not in spec.target
    assert "profile_schema_version" not in spec.target
