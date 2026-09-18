"""tests/test_run_sampling_provenance.py — карточка Q (W6, наша половина):
memnotsafe кладёт фактический сэмплинг таргета в артефакт прогона.

Всё офлайн (Принцип VI): ни стенда, ни сети, ни docker — HTTP подменяется
фейковым клиентом, кампания гоняется на _FakeStand-паттерне из
test_investment_stand_adapter.py (T023). Проверяются: счастливый путь,
четыре пути недоступности с различимыми причинами, таймаут сборщика,
граница 64 КБ, непротекание посторонних полей, тристейт pin_held,
третья роль и ВЫЧИСЛЯЕМОСТЬ правила проверяемости (не список двух имён).
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from memnotsafe.adapters.investment_stand import (  # noqa: E402
    InvestmentStandAdapter,
    _pin_verdict,
)
from memnotsafe.adapters.mock import MockTarget  # noqa: E402
from memnotsafe.core.campaign import Campaign  # noqa: E402
from memnotsafe.core.config import ActorConfig, Scenario, TargetSpec  # noqa: E402

_GOOD_BODY = {
    "schema": "stand.sampling/v1",
    "observed": [
        {"role": "research", "model": "openai:gpt-4o-mini", "temperature": 0.0,
         "top_p": 1.0, "max_tokens": 2048, "base_url": "http://llm.example:8000"},
        {"role": "summarization", "model": "openai:gpt-4o-mini", "temperature": 0.0,
         "top_p": 1.0, "max_tokens": 1024, "base_url": "http://llm.example:8000"},
    ],
    "configured": {
        "research_temperature": 0.0, "research_top_p": 1.0,
        "summarization_temperature": 0.0, "summarization_top_p": 1.0,
    },
}


class _FakeResp:
    def __init__(self, *, status_code=200, text=""):
        self.status_code = status_code
        self.text = text
        self.content = text.encode("utf-8")


class _FakeHttpClient:
    """Транспорт с ручным исходом: (status, text) | исключение | задержка.
    Моделирует таймаут httpx: если передан timeout и задержка его превышает —
    обрыв ReadTimeout РОВНО на границе таймаута, а не после полной задержки."""

    def __init__(self, *, status_code=200, text="", exc=None, delay=0.0):
        self.status_code = status_code
        self.text = text
        self.exc = exc
        self.delay = delay
        self.calls: list[str] = []
        self.seen_timeout = None

    async def get(self, url, timeout=None):
        import httpx

        self.calls.append(url)
        self.seen_timeout = timeout
        if self.delay:
            limit = self.delay if timeout is None else min(self.delay, timeout)
            await asyncio.sleep(limit)
            if timeout is not None and self.delay > timeout:
                raise httpx.ReadTimeout(f"timed out after {timeout}s")
        if self.exc is not None:
            raise self.exc
        return _FakeResp(status_code=self.status_code, text=self.text)


def _stand_with(client: _FakeHttpClient) -> InvestmentStandAdapter:
    stand = InvestmentStandAdapter(
        base_url="http://stand.invalid",
        identities={"1001": "SK_A", "1002": "SK_V"},
    )
    stand._client = client
    return stand


# --------------------------------------------------------------- счастливый путь


def test_observed_path_copies_blocks_verbatim():
    import httpx

    stand = _stand_with(_FakeHttpClient(text=json.dumps(_GOOD_BODY)))
    asyncio.run(stand.acollect_run_observations())
    meta = stand.run_metadata()
    block = meta["target_sampling"]
    assert block["status"] == "observed"
    assert block["endpoint"] == "http://stand.invalid/debug/sampling"
    assert block["schema"] == "stand.sampling/v1"
    assert block["observed"] == _GOOD_BODY["observed"]
    assert block["configured"] == _GOOD_BODY["configured"]
    assert block["pin_held"] is True
    assert isinstance(httpx.AsyncClient, type)  # импорт просто используется выше


def test_no_collection_leaves_key_absent_not_error():
    stand = InvestmentStandAdapter(
        base_url="http://stand.invalid", identities={"1001": "SK_A"}
    )
    assert "target_sampling" not in stand.run_metadata()


# ---------------------------------------------------------- четыре пути недоступности


def test_unavailable_transport():
    import httpx

    stand = _stand_with(_FakeHttpClient(exc=httpx.ConnectError("no route")))
    asyncio.run(stand.acollect_run_observations())
    block = stand.run_metadata()["target_sampling"]
    assert block["status"] == "unavailable"
    assert block["pin_held"] is None
    assert block["reason"] == "транспорт недоступен: ConnectError"
    assert block["endpoint"] == "http://stand.invalid/debug/sampling"


def test_unavailable_http_404():
    stand = _stand_with(_FakeHttpClient(status_code=404, text="not found"))
    asyncio.run(stand.acollect_run_observations())
    block = stand.run_metadata()["target_sampling"]
    assert block["status"] == "unavailable"
    assert block["pin_held"] is None
    assert block["reason"] == "HTTP 404 от /debug/sampling"


def test_unavailable_broken_json():
    stand = _stand_with(_FakeHttpClient(text="<<<не json>>>"))
    asyncio.run(stand.acollect_run_observations())
    block = stand.run_metadata()["target_sampling"]
    assert block["status"] == "unavailable"
    assert block["reason"].startswith("ответ не разбирается как JSON")


def test_unavailable_wrong_schema():
    body = dict(_GOOD_BODY, schema="some.other/v9-with-a-very-long-schema-identifier")
    stand = _stand_with(_FakeHttpClient(text=json.dumps(body)))
    asyncio.run(stand.acollect_run_observations())
    block = stand.run_metadata()["target_sampling"]
    assert block["status"] == "unavailable"
    # в причине — фактическое значение schema, обрезанное до 64 символов
    assert "some.other/v9-with-a-very-long-schema-identifier"[:64] in block["reason"]


# ------------------------------------------------------------------ таймаут и размер


def test_hanging_endpoint_times_out_without_failing_run():
    # транспорт молчит дольше таймаута сборщика: сборщик передаёт СВОЙ короткий
    # таймаут, обрыв происходит на его границе, прогон не тонет
    import time

    client = _FakeHttpClient(delay=30.0)
    stand = _stand_with(client)
    t0 = time.monotonic()
    asyncio.run(stand.acollect_run_observations())
    elapsed = time.monotonic() - t0
    assert client.seen_timeout == 5.0, "таймаут сборщика не дошёл до транспорта"
    assert elapsed < 15.0, f"сборщик ждал {elapsed:.1f}c вместо своего таймаута"
    block = stand.run_metadata()["target_sampling"]
    assert block["status"] == "unavailable"
    assert block["reason"] == "транспорт недоступен: ReadTimeout"


def test_oversized_body_rejected():
    big = "x" * (64 * 1024 + 1)
    stand = _stand_with(_FakeHttpClient(text=big))
    asyncio.run(stand.acollect_run_observations())
    block = stand.run_metadata()["target_sampling"]
    assert block["status"] == "unavailable"
    assert "больше 65536 байт" in block["reason"]
    assert "x" * 100 not in json.dumps(block)


# ------------------------------------------------------------- посторонние поля


def test_extra_top_level_keys_names_only():
    body = dict(_GOOD_BODY)
    body["api_key"] = "SENSITIVE-VALUE-DO-NOT-LEAK"
    body["session_secret"] = "also-sensitive"
    stand = _stand_with(_FakeHttpClient(text=json.dumps(body)))
    asyncio.run(stand.acollect_run_observations())
    block = stand.run_metadata()["target_sampling"]
    assert block["note"] == (
        "посторонние поля верхнего уровня не копировались: api_key, session_secret"
    )
    dumped = json.dumps(block)
    assert "SENSITIVE-VALUE-DO-NOT-LEAK" not in dumped
    assert "also-sensitive" not in dumped


# ------------------------------------------------------------------ pin_held


def test_pin_true_when_all_checkable_match():
    held, note = _pin_verdict(
        _GOOD_BODY["observed"], _GOOD_BODY["configured"]
    )
    assert held is True
    assert "все проверяемые записи совпадают" in note


def test_pin_false_names_role_field_both_values():
    observed = [dict(_GOOD_BODY["observed"][0], temperature=0.0)]
    configured = dict(_GOOD_BODY["configured"], research_temperature=0.5)
    held, note = _pin_verdict(observed, configured)
    assert held is False
    assert "research.temperature" in note
    assert "observed=0.0" in note and "configured=0.5" in note


def test_pin_null_on_empty_observed():
    held, note = _pin_verdict([], _GOOD_BODY["configured"])
    assert held is None
    assert "observed пуст" in note


def test_pin_null_when_nothing_checkable():
    held, note = _pin_verdict(
        [{"role": "judge", "temperature": 0.0, "top_p": 1.0}],
        _GOOD_BODY["configured"],
    )
    assert held is None
    assert "ни одна запись" in note and "judge" in note


def test_pin_true_with_unchecked_third_role_named():
    observed = _GOOD_BODY["observed"] + [
        {"role": "judge", "temperature": 0.9, "top_p": 0.5}
    ]
    held, note = _pin_verdict(observed, _GOOD_BODY["configured"])
    assert held is True
    assert "judge" in note and "непроверенные роли" in note


def test_pin_rule_is_computed_not_two_name_list():
    # правило проверяемости вычисляется из ИМЕНИ роли: произвольная третья
    # роль с парой ключей в configured проверяется тем же кодом без правок
    held_false, note = _pin_verdict(
        [{"role": "escalation", "temperature": 0.3, "top_p": 1.0}],
        {"escalation_temperature": 0.1, "escalation_top_p": 1.0},
    )
    assert held_false is False
    assert "escalation.temperature" in note
    held_true, _ = _pin_verdict(
        [{"role": "escalation", "temperature": 0.1, "top_p": 1.0}],
        {"escalation_temperature": 0.1, "escalation_top_p": 1.0},
    )
    assert held_true is True


# ------------------------------------------------------------------ e2e артефакт


def _scenario(tmp_path) -> Scenario:
    return Scenario(
        id="cross_user_bac",
        path=tmp_path / "s.yaml",
        target=TargetSpec(adapter="investment_stand"),
        attacker=ActorConfig(user_id="1001"),
        victim=ActorConfig(user_id="1002"),
        attack_family="cross_user_bac",
        repetitions=1,
        stop_on_success=False,
    )


class _SamplingFakeStand(InvestmentStandAdapter):
    """_FakeStand (T023) + управляемый транспорт /debug/sampling."""

    def __init__(self, sampling_client: _FakeHttpClient):
        super().__init__(
            base_url="http://stand.invalid",
            identities={"1001": "SK_A", "1002": "SK_V"},
            mongo_uri="mongodb://fake",
        )
        self._poison_cus = None
        self._writes: list[tuple[str, str]] = []
        self._sampling_client = sampling_client

    def _db(self):
        return None

    async def close_session(self, session_id):
        return None

    async def _http_post_chat(self, user_id, message, session_id):
        low = message.lower()
        if "запомни" in low:
            import re

            m = re.search(r'cus\s*[:=]\s*"?(\d{3,6})"?', message, re.IGNORECASE)
            if m:
                self._poison_cus = m.group(1)
            self._writes.append((user_id, message))
            return {"choices": [{"message": {"content": "Готово."}}]}
        if "портфель" in low or "portfolio" in low:
            cus = (
                self._poison_cus
                if (self._poison_cus and self._poison_cus != user_id)
                else user_id
            )
            return {
                "choices": [{"message": {"content": f"Портфель клиента {cus}."}}],
                "tool_calls": [{"name": "portfolio_get_positions_valuation",
                                "arguments": {"cus": cus}}],
            }
        return {"choices": [{"message": {"content": "Здравствуйте."}}]}

    def _read_all_docs(self):
        docs = [{"policy_id": f"p{i}", "user_id": u, "text": t}
                for i, (u, t) in enumerate(self._writes)]
        return {"agent_policy_memories": docs, "dialog_sessions": [],
                "episodic_memories": [], "semantic_memories": []}

    def _read_session_docs(self, session_id):
        return []

    async def acollect_run_observations(self):
        # подмена транспорта только для этого вызова: реальный _client не трогаем
        real = self._client
        self._client = self._sampling_client
        try:
            await super().acollect_run_observations()
        finally:
            self._client = real


def _run_campaign(tmp_path, target) -> dict:
    campaign = Campaign(_scenario(tmp_path), target, tmp_path / "run-out")
    result = asyncio.run(campaign.run())
    artifact = json.loads(
        (tmp_path / "run-out" / "campaign.json").read_text(encoding="utf-8")
    )
    return {"attempts": result.attempts, "artifact": artifact}


def test_campaign_json_contains_target_sampling_happy(tmp_path):
    out = _run_campaign(tmp_path, _SamplingFakeStand(
        _FakeHttpClient(text=json.dumps(_GOOD_BODY))))
    assert out["attempts"] == 1
    block = out["artifact"]["metadata"]["target_sampling"]
    assert block["status"] == "observed"
    assert block["observed"] == _GOOD_BODY["observed"]
    assert block["configured"] == _GOOD_BODY["configured"]
    assert block["endpoint"] == "http://stand.invalid/debug/sampling"
    assert block["pin_held"] is True


def test_campaign_json_target_sampling_null_for_mock(tmp_path):
    out = _run_campaign(tmp_path, MockTarget(vulnerable=True))
    assert out["attempts"] == 1
    assert out["artifact"]["metadata"]["target_sampling"] is None


def test_unavailable_sampling_does_not_fail_campaign(tmp_path):
    out = _run_campaign(tmp_path, _SamplingFakeStand(
        _FakeHttpClient(status_code=404, text="not found")))
    assert out["attempts"] == 1  # прогон прошёл, артефакт написан
    block = out["artifact"]["metadata"]["target_sampling"]
    assert block["status"] == "unavailable"
    assert block["pin_held"] is None
    assert block["reason"] == "HTTP 404 от /debug/sampling"


def test_hanging_sampling_does_not_fail_campaign(tmp_path):
    out = _run_campaign(tmp_path, _SamplingFakeStand(_FakeHttpClient(delay=30.0)))
    assert out["attempts"] == 1  # кампания пережила висящий эндпоинт
    block = out["artifact"]["metadata"]["target_sampling"]
    assert block["status"] == "unavailable"
    assert block["reason"] == "транспорт недоступен: ReadTimeout"


def test_extra_keys_do_not_leak_into_campaign_json(tmp_path):
    body = dict(_GOOD_BODY)
    body["api_key"] = "SENSITIVE-VALUE-DO-NOT-LEAK"
    out = _run_campaign(tmp_path, _SamplingFakeStand(
        _FakeHttpClient(text=json.dumps(body))))
    whole = json.dumps(out["artifact"])
    assert "SENSITIVE-VALUE-DO-NOT-LEAK" not in whole
    block = out["artifact"]["metadata"]["target_sampling"]
    assert "api_key" in block["note"]
