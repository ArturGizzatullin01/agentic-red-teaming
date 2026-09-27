"""tests/test_ext_b_effective_target.py — EXT-B (поток EXT-OPERATOR, 2/4):
единая эффективная цель + preflight по контракту адаптера + судья из конфигурации.

Всё офлайн (Принцип VI): ни живого стенда, ни сети наружу — HTTP цели
подменяется локальным фейком/слотами, ключи — плейсхолдеры из env, значения
секретов в вывод не попадают.

Замки:
  1. Единая эффективная цель: одна точка резолва (resolve_effective_target)
     для адаптера, эксперимента и метаданных; смена цели меняет experiment_id;
     артефакты называют ЭФФЕКТИВНУЮ цель (кейс pilot: mock-сценарий против
     http_endpoint-адаптера — метаданные обязаны назвать http_endpoint).
  2. Никогда тихий mock: URL поверх mock-сценария → ValueError с причиной и
     подсказкой; --target <имя адаптера> → явное переключение; --target mock →
     явный mock.
  3. Preflight по контракту адаптера: http_endpoint без /healthz НЕ даёт
     W1-БЛОКЕР; probe различает host_responds/auth_passed/contract_ok
     (401/403/404 ≠ reachable); POST-проба помечена target_call и, при наличии
     леджера, ложится в budget-ledger; preflight уважает эффективную цель.
  4. Судья из конфигурации: порядок флаги → блок сценария → ENV-дефолт проекта
     (MEMNOTSAFE_JUDGE_*) → человеческая ошибка ДО обращения к цели; D1-пресет
     и judge-блоки не ломаются.
"""

from __future__ import annotations

import asyncio
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from memnotsafe.core.config import (  # noqa: E402
    EffectiveTarget,
    JudgeSpec,
    apply_project_judge_defaults,
    build_adapter,
    load_scenario,
    resolve_effective_target,
    validate_judge_spec,
)
from memnotsafe.core.experiment import build_experiment_spec  # noqa: E402
from memnotsafe.core.runner import RunnerError  # noqa: E402

KEY_ENV = "MEMNOTSAFE_TARGET_API_KEY"
KEY_PLACEHOLDER = "test-key-placeholder-not-a-secret"


# --------------------------------------------------------------- сценарии-фикстуры
def _write(tmp_path: Path, text: str, name: str = "scenario.yaml") -> Path:
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


_MOCK_YAML = """
id: ext_b_mock
target:
  adapter: mock
actors:
  attacker: {user_id: "1001"}
  victim: {user_id: "1002"}
attack:
  family: cross_user_bac
"""

_OPENAI_YAML = """
id: ext_b_openai
target:
  adapter: openai
  base_url: "http://target-a.example:1/v1"
  model_name: partner-agent
actors:
  attacker: {user_id: "1001"}
  victim: {user_id: "1002"}
attack:
  family: cross_user_bac
"""

_STAND_YAML = """
id: ext_b_stand
target:
  adapter: investment_stand
  base_url: "http://localhost:9600"
  auth_mode: vulnerable
  identities:
    "1001": SK_GENAI_1001
    "1002": SK_GENAI_1002
actors:
  attacker: {user_id: "1001"}
  victim: {user_id: "1002"}
attack:
  family: cross_user_bac
"""

_HTTP_ENDPOINT_YAML = """
id: ext_b_http_endpoint
target:
  adapter: http_endpoint
  base_url: "http://target-a.example:8080"
  model_name: partner-agent
actors:
  attacker: {user_id: "1001"}
  victim: {user_id: "1002"}
attack:
  family: cross_user_bac
"""

_BLOCKLESS_MOCK_JUDGE_YAML = _MOCK_YAML  # без блока judge:


# ============================================================ ЗАМОК 1: эффективная цель
def test_resolve_effective_target_url_override(tmp_path):
    sc = load_scenario(_write(tmp_path, _OPENAI_YAML))
    eff = resolve_effective_target(sc, "http://target-b.example:2/v1")
    assert eff.adapter == "openai"
    assert eff.base_url == "http://target-b.example:2/v1"
    assert eff.profile is None


def test_resolve_effective_target_default_is_yaml(tmp_path):
    sc = load_scenario(_write(tmp_path, _OPENAI_YAML))
    eff = resolve_effective_target(sc, None)
    assert eff.adapter == "openai"
    assert eff.base_url == "http://target-a.example:1/v1"


def test_effective_target_changes_experiment_id(tmp_path):
    sc = load_scenario(_write(tmp_path, _OPENAI_YAML))
    eff_a = resolve_effective_target(sc, None)
    eff_b = resolve_effective_target(sc, "http://target-b.example:2/v1")
    id_a = build_experiment_spec(sc, effective_target=eff_a).experiment_id
    id_b = build_experiment_spec(sc, effective_target=eff_b).experiment_id
    assert id_a != id_b  # смена эффективной цели меняет тождество эксперимента


def test_experiment_id_regression_none_equals_resolved_yaml(tmp_path):
    """Регресс G6: effective_target=None и явный resolve(YAML-цель) дают
    ПОБАЙТОВО тот же experiment_id — сценарии без оверрайда не сдвигаются."""
    sc = load_scenario(_write(tmp_path, _OPENAI_YAML))
    spec_none = build_experiment_spec(sc)
    spec_yaml = build_experiment_spec(sc, effective_target=resolve_effective_target(sc, None))
    assert spec_none.experiment_id == spec_yaml.experiment_id
    assert spec_none.target == spec_yaml.target


def test_campaign_metadata_names_effective_adapter(tmp_path):
    """Кейс pilot: сценарий mock, но реально бьём http_endpoint-цель — метаданные
    прогона обязаны назвать ЭФФЕКТИВНЫЙ адаптер и цель, а не строку из YAML."""
    from memnotsafe.adapters.mock import MockTarget
    from memnotsafe.core.campaign import Campaign

    sc = load_scenario(_write(tmp_path, _MOCK_YAML))
    eff = EffectiveTarget(adapter="http_endpoint", base_url="http://target-b.example:8080", profile=None)
    camp = Campaign(sc, MockTarget(vulnerable=True), tmp_path / "out",
                    effective_target=eff)
    meta = camp._run_metadata("RUN-x", 1)
    assert meta["adapter"] == "http_endpoint"
    assert meta["target"] == "http://target-b.example:8080"


# ============================================================ ЗАМОК 2: никогда тихий mock
def test_url_over_mock_scenario_refused(tmp_path):
    sc = load_scenario(_write(tmp_path, _MOCK_YAML))
    with pytest.raises(ValueError) as exc:
        resolve_effective_target(sc, "http://target.example:9/v1")
    msg = str(exc.value)
    assert "mock" in msg.lower()
    assert "http://target.example:9/v1" in msg  # причина называет игнорируемый URL
    # и build_adapter отказывает так же (не возвращает молча MockTarget)
    with pytest.raises(ValueError):
        build_adapter(sc, "http://target.example:9/v1")


def test_target_mock_forces_mock(tmp_path):
    from memnotsafe.adapters.mock import MockTarget

    sc = load_scenario(_write(tmp_path, _OPENAI_YAML))
    eff = resolve_effective_target(sc, "mock")
    assert eff.adapter == "mock"
    assert isinstance(build_adapter(sc, "mock"), MockTarget)


def test_target_adapter_name_switches_not_silent_mock(tmp_path):
    """--target <имя известного адаптера> поверх mock-сценария — ЯВНОЕ
    переключение адаптера, не молчаливый mock. http_endpoint без base_url →
    честный отказ «нужен base_url», а не MockTarget."""
    sc = load_scenario(_write(tmp_path, _MOCK_YAML))
    eff = resolve_effective_target(sc, "http_endpoint")
    assert eff.adapter == "http_endpoint"
    with pytest.raises(ValueError, match="base_url"):
        build_adapter(sc, "http_endpoint")


# ============================================================ ЗАМОК 3: probe + preflight
def test_classify_probe_status_three_facts():
    from memnotsafe.adapters.http_endpoint import classify_probe_status

    ok = classify_probe_status(200)
    assert ok == {"host_responds": True, "auth_passed": True, "contract_ok": True}
    for code in (401, 403):
        f = classify_probe_status(code)
        assert f["host_responds"] is True
        assert f["auth_passed"] is False   # авторизация отвергнута
        assert f["contract_ok"] is False   # ≠ reachable
    nf = classify_probe_status(404)
    assert nf["host_responds"] is True and nf["auth_passed"] is True and nf["contract_ok"] is False
    dead = classify_probe_status(None)
    assert dead == {"host_responds": False, "auth_passed": False, "contract_ok": False}


class _StatusHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        status = int(getattr(self.server, "next_status", 200))  # type: ignore[attr-defined]
        if 200 <= status < 300:
            payload = {"choices": [{"message": {"role": "assistant", "content": "pong"}}]}
        else:
            payload = {"error": {"message": "denied"}}
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a) -> None:
        return


@pytest.fixture()
def status_server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _StatusHandler)
    srv.next_status = 200  # type: ignore[attr-defined]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv
    srv.shutdown()
    srv.server_close()


def test_probe_401_not_reachable(status_server, monkeypatch):
    from memnotsafe.adapters.http_endpoint import HttpEndpointAdapter

    monkeypatch.setenv(KEY_ENV, KEY_PLACEHOLDER)
    status_server.next_status = 401  # type: ignore[attr-defined]
    ada = HttpEndpointAdapter(base_url=f"http://127.0.0.1:{status_server.server_address[1]}")
    try:
        res = asyncio.run(ada.probe())
        assert res.reachable is False                 # 401 ≠ доступно
        assert res.detail.get("status") == 401
        assert res.detail.get("host_responds") is True
        assert res.detail.get("auth_passed") is False
        assert res.detail.get("contract_ok") is False
        assert res.detail.get("target_call") is True  # POST-проба — вызов цели
    finally:
        asyncio.run(ada.aclose())


def test_probe_200_reachable_marks_target_call(status_server, monkeypatch):
    from memnotsafe.adapters.http_endpoint import HttpEndpointAdapter

    monkeypatch.setenv(KEY_ENV, KEY_PLACEHOLDER)
    ada = HttpEndpointAdapter(base_url=f"http://127.0.0.1:{status_server.server_address[1]}")
    try:
        res = asyncio.run(ada.probe())
        assert res.reachable is True
        assert res.detail.get("status") == 200
        assert res.detail.get("target_call") is True
    finally:
        asyncio.run(ada.aclose())


def _fake_get(table):
    async def http_get(url):
        from memnotsafe.preflight import HttpReply

        for path, code in table.items():
            if url.endswith(path):
                return HttpReply(status_code=code)
        return HttpReply(status_code=404)

    return http_get


def test_preflight_http_endpoint_no_healthz_blocker(tmp_path, monkeypatch):
    from memnotsafe.preflight import BLOCKER, run_preflight

    monkeypatch.setenv(KEY_ENV, KEY_PLACEHOLDER)
    sc_path = _write(tmp_path, _HTTP_ENDPOINT_YAML)
    result = run_preflight(sc_path, environ={})
    # http_endpoint без /healthz: НЕ должно быть БЛОКЕРА «стенд не готов (healthz не 200)»
    blocker_texts = " ".join(c.text for c in result.checks if c.status == BLOCKER)
    assert "healthz" not in blocker_texts.lower()
    assert result.exit_code == 0  # отсутствие /healthz у http_endpoint — не блокер


def test_preflight_post_probe_ledgered(tmp_path, monkeypatch):
    from memnotsafe.core.ledger import BudgetLedger, OP_TARGET_CALL
    from memnotsafe.preflight import run_preflight

    monkeypatch.setenv(KEY_ENV, KEY_PLACEHOLDER)
    sc_path = _write(tmp_path, _HTTP_ENDPOINT_YAML)
    ledger = BudgetLedger(tmp_path / "budget-ledger.jsonl", experiment_id=None, run_id="RUN-preflight")

    async def http_post(url, json=None):  # noqa: A002 — контракт слота
        from memnotsafe.preflight import HttpReply

        return HttpReply(status_code=200)

    result = run_preflight(sc_path, environ={}, http_post=http_post, ledger=ledger)
    entries = ledger.entries()
    assert any(e.operation == OP_TARGET_CALL for e in entries), "POST-проба не легла в budget-ledger"
    assert result.exit_code == 0


def test_preflight_respects_target_override(tmp_path, monkeypatch):
    from memnotsafe.preflight import run_preflight

    monkeypatch.setenv("SK_GENAI_1001", "v1")
    monkeypatch.setenv("SK_GENAI_1002", "v2")
    sc_path = _write(tmp_path, _STAND_YAML)
    seen: list[str] = []

    async def http_get(url):
        from memnotsafe.preflight import HttpReply

        seen.append(url)
        return HttpReply(status_code=200)

    run_preflight(sc_path, target_override="http://other-stand.example:9601",
                  http_get=http_get, mongo_probe=lambda *a: __import__(
                      "memnotsafe.preflight", fromlist=["MongoProbe"]).MongoProbe(state="ok"),
                  environ=None)
    # эффективная цель = оверрайд, проверки бьют по ней, а не по YAML localhost:9600
    assert any("other-stand.example:9601" in u for u in seen)
    assert not any("localhost:9600" in u for u in seen)


# ============================================================ ЗАМОК 4: судья из конфигурации
def test_judge_env_default_blockless(tmp_path, monkeypatch):
    """Сценарий без блока judge: + судья включён + проектный ENV-дефолт →
    модель/URL/имя-ключа берутся из MEMNOTSAFE_JUDGE_*."""
    sc = load_scenario(_write(tmp_path, _BLOCKLESS_MOCK_JUDGE_YAML))
    sc.judge.enabled = True
    monkeypatch.setenv("MEMNOTSAFE_JUDGE_MODEL", "proj/model-x")
    monkeypatch.setenv("MEMNOTSAFE_JUDGE_BASE_URL", "http://judge.proj.example/v1")
    monkeypatch.setenv("MEMNOTSAFE_JUDGE_API_KEY_ENV", "PROVIDER_API_KEY")
    apply_project_judge_defaults(sc, args=None, environ=dict(__import__("os").environ))
    assert sc.judge.model == "proj/model-x"
    assert sc.judge.base_url == "http://judge.proj.example/v1"
    assert sc.judge.api_key_env == "PROVIDER_API_KEY"


def test_judge_blockless_no_config_is_human_error(tmp_path, monkeypatch):
    """Судья включён на блоклесс-сценарии, проектного дефолта НЕТ → человеческая
    ошибка ДО обращения к цели (RunnerError), не молчаливый OpenRouter."""
    monkeypatch.delenv("MEMNOTSAFE_JUDGE_MODEL", raising=False)
    monkeypatch.delenv("MEMNOTSAFE_JUDGE_BASE_URL", raising=False)
    monkeypatch.delenv("MEMNOTSAFE_JUDGE_API_KEY_ENV", raising=False)
    sc = load_scenario(_write(tmp_path, _BLOCKLESS_MOCK_JUDGE_YAML))
    sc.judge.enabled = True
    apply_project_judge_defaults(sc, args=None, environ=dict(__import__("os").environ))
    # без модели из конфигурации — validate обязан отказать до цели
    with pytest.raises(RunnerError):
        validate_judge_spec(sc.judge, sc.id)


def test_judge_block_scenario_untouched_by_env(tmp_path, monkeypatch):
    """Сценарий СО своим блоком judge: не трогаем даже при заданном ENV-дефолте."""
    text = _MOCK_YAML + "judge:\n  enabled: true\n  model: own/model\n  api_key_env: OWN_KEY\n"
    sc = load_scenario(_write(tmp_path, text))
    monkeypatch.setenv("MEMNOTSAFE_JUDGE_MODEL", "proj/model-x")
    monkeypatch.setenv("MEMNOTSAFE_JUDGE_API_KEY_ENV", "PROVIDER_API_KEY")
    apply_project_judge_defaults(sc, args=None, environ=dict(__import__("os").environ))
    assert sc.judge.model == "own/model"        # свой блок победил ENV
    assert sc.judge.api_key_env == "OWN_KEY"


def test_judge_defaults_no_hardcoded_openrouter_when_env_set(tmp_path, monkeypatch):
    """ENV-дефолт проекта перекрывает встроенный OpenRouter для блоклесс-сценария."""
    sc = load_scenario(_write(tmp_path, _BLOCKLESS_MOCK_JUDGE_YAML))
    assert sc.judge.api_key_env == "OPENROUTER_API_KEY"  # встроенный дефолт до резолва
    sc.judge.enabled = True
    monkeypatch.setenv("MEMNOTSAFE_JUDGE_MODEL", "proj/model-x")
    monkeypatch.setenv("MEMNOTSAFE_JUDGE_API_KEY_ENV", "PROVIDER_API_KEY")
    apply_project_judge_defaults(sc, args=None, environ=dict(__import__("os").environ))
    assert sc.judge.api_key_env != "OPENROUTER_API_KEY"
    assert sc.judge.api_key_env == "PROVIDER_API_KEY"
