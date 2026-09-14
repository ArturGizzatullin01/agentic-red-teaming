"""tests/test_p09_e2e.py — P09-full (фича 010): сквозной поток офлайн.

Кампания → ExperimentSpec → пакет со слотом context_tool_evidence →
report/replay. Плюс 10 обязательных negative controls карточки 010.
Без сети/live; CLI-контракт не меняется."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from memnotsafe import cli
from memnotsafe.adapters.mock import MockTarget
from memnotsafe.core.attempt import read_history
from memnotsafe.core.experiment import read_experiment
from memnotsafe.evidence.bundle import (
    STATUS_ABSENT,
    STATUS_UNAVAILABLE,
    find_bundles,
    read_bundle,
    verify_run_evidence,
)
from memnotsafe.evidence.telemetry import (
    PHASE_M3_TRIGGER_FINALIZE,
    adapter_actual_divergence,
    proven_no_call,
)

_SCENARIOS = Path(__file__).resolve().parents[1] / "scenarios"


def _run(tmp_path: Path, name: str = "run", scenario: str = "cross_user_bac.yaml") -> Path:
    rc = cli.main(["run", "--scenario", str(_SCENARIOS / scenario),
                   "--output", str(tmp_path / name), "--json"])
    assert rc == 0
    return tmp_path / name


# ------------------------------------- кампания пишет слот, replay проходит


def test_campaign_bundle_carries_context_tool_evidence(tmp_path) -> None:
    out = _run(tmp_path)
    bundles = find_bundles(out)
    assert bundles
    bundle = read_bundle(next(iter(bundles.values())))
    assert bundle.present("context_tool_evidence")
    artifact = json.loads(
        (next(iter(bundles.values())) / "artifacts" / "context_tool_evidence.json").read_text(encoding="utf-8")
    )
    # effective_context — ФАКТ выборки, атрибутированный по фазе раннера:
    # m3-trigger-finalize — trigger-сессия жертвы; запросы delivery-сессии
    # легитимно дают m1-delivery секции; baseline в слот не попадает.
    sections = artifact["effective_context"]
    assert sections
    assert all(s["phase"] in ("m1-delivery", "m3-trigger-finalize") for s in sections)
    victim_sections = [s for s in sections if s["phase"] == PHASE_M3_TRIGGER_FINALIZE]
    assert victim_sections and victim_sections[0]["records"]
    # ФАКТ уязвимости виден в контексте жертвы: global-запись атакующего дошла
    assert any(
        r["scope"] == "global" and r["source_user"] == "1001"
        for r in victim_sections[0]["records"]
    )
    # фактические аргументы инструмента дошли в слот отдельной секцией
    assert artifact["actual_tool_calls"], "cross_user_bac обязан вызвать tool"
    # подготовлено то же, что и фактически (в mock расхождений нет)
    div = adapter_actual_divergence(artifact)
    assert div == []
    # replay: полный verify (пакеты + история) зелёный со новым слотом
    assert verify_run_evidence(out) >= 1
    rc = cli.main(["report", "--input", str(out), "--output", str(tmp_path / "rep"), "--json"])
    assert rc == 0


def test_experiment_spec_records_stand_version_in_volatile(tmp_path) -> None:
    out = _run(tmp_path, "run-stand")
    spec = read_experiment(out)
    assert spec.volatile.get("stand_version") == "mock"
    # volatile вне digest: перечитанная спека сохраняет experiment_id
    from memnotsafe.core.experiment import ExperimentSpec

    assert ExperimentSpec.from_serialized(spec.to_dict()).experiment_id == spec.experiment_id


def test_channel_without_method_slot_absent_and_verdicts_intact(tmp_path) -> None:
    class NoChannelMock(MockTarget):
        # адаптер старого поколения: канала телеметрии нет вообще
        context_tool_evidence = None  # type: ignore[assignment]

    from memnotsafe.core.campaign import Campaign
    from memnotsafe.core.config import ActorConfig, Scenario, TargetSpec

    scenario = Scenario(
        id="cross_user_bac", path=_SCENARIOS / "cross_user_bac.yaml",
        target=TargetSpec(adapter="mock", extra={"vulnerable": True}),
        attacker=ActorConfig(user_id="1001"), victim=ActorConfig(user_id="1002"),
        attack_family="cross_user_bac", repetitions=1,
    )
    campaign = Campaign(scenario, NoChannelMock(vulnerable=True), tmp_path / "run-nochan")
    result = asyncio_run(campaign.run())
    assert result.results, "прогон обязан состояться"
    bundles = find_bundles(tmp_path / "run-nochan")
    assert bundles
    bundle = read_bundle(next(iter(bundles.values())))
    assert bundle.slots["context_tool_evidence"].status == STATUS_ABSENT
    # вердикты не зависят от отсутствия канала: vulnerable mock даёт успех
    assert any(r.success for r in result.results)


def test_channel_returning_none_slot_unavailable_with_provenance(tmp_path) -> None:
    class DeadChannelMock(MockTarget):
        def context_tool_evidence(self):  # канал заявлен, но данных не отдаёт
            return None

    from memnotsafe.core.campaign import Campaign
    from memnotsafe.core.config import ActorConfig, Scenario, TargetSpec

    scenario = Scenario(
        id="cross_user_bac", path=_SCENARIOS / "cross_user_bac.yaml",
        target=TargetSpec(adapter="mock", extra={"vulnerable": True}),
        attacker=ActorConfig(user_id="1001"), victim=ActorConfig(user_id="1002"),
        attack_family="cross_user_bac", repetitions=1,
    )
    campaign = Campaign(scenario, DeadChannelMock(vulnerable=True), tmp_path / "run-dead")
    result = asyncio_run(campaign.run())
    assert result.results
    bundles = find_bundles(tmp_path / "run-dead")
    bundle = read_bundle(next(iter(bundles.values())))
    assert bundle.slots["context_tool_evidence"].status == STATUS_UNAVAILABLE
    # причина видима в provenance, не спрятана
    final = result.results[-1]
    assert "context_tool_evidence_error" in (final.evidence.get("provenance") or {})


def asyncio_run(coro):
    import asyncio

    return asyncio.run(coro)


# ============ RETURN_FOR_FIX d09299a: настоящий live-тип адаптера (без сети)


def test_fix4_investment_stand_declares_no_channel_unavailable(tmp_path) -> None:
    from memnotsafe.adapters.investment_stand import InvestmentStandAdapter
    from memnotsafe.core.campaign import Campaign
    from memnotsafe.core.config import ActorConfig, Scenario, TargetSpec

    # настоящий тип адаптера: метод существует, ходит в сеть только конструктором
    # httpx-клиента (запросов не делает), фактов без канала не выдумывает
    adapter = InvestmentStandAdapter("http://127.0.0.1:9", mongo_uri=None)
    assert adapter.context_tool_evidence() is None

    # сквозное поведение кампании на настоящем типе: слот unavailable с причиной
    class OfflineStand(InvestmentStandAdapter):
        """Тот же класс канала телеметрии, но без сети: reset/сессии
        подменяются минимально, факт-канал — РЕАЛЬНЫЙ код адаптера."""

        async def reset_state(self) -> None:
            return None

        async def probe(self):
            from memnotsafe.adapters.base import Capabilities, ProbeResult

            return ProbeResult(reachable=True, capabilities=Capabilities(True, True, False, False),
                               detail={"adapter": "offline-stand"})

        async def new_session(self, user_id: str) -> str:
            self._session_users[f"s-{user_id}"] = user_id
            return f"s-{user_id}"

        async def send(self, session_id: str, message: str):
            from memnotsafe.adapters.base import SendResult

            return SendResult(content="ок", events=[], raw={})

        async def close_session(self, session_id: str) -> None:
            return None

        async def get_trace(self, session_id: str):
            return []

        async def wait_until_persistent(self, evidence):
            from memnotsafe.adapters.base import SettleResult

            return SettleResult("timeout", "офлайн-стаб", observations=0)

        async def snapshot(self):
            return None

    scenario = Scenario(
        id="cross_user_bac", path=_SCENARIOS / "cross_user_bac.yaml",
        target=TargetSpec(adapter="investment_stand", extra={"vulnerable": True}),
        attacker=ActorConfig(user_id="1001"), victim=ActorConfig(user_id="1002"),
        attack_family="cross_user_bac", repetitions=1,
    )
    campaign = Campaign(scenario, OfflineStand("http://127.0.0.1:9", mongo_uri=None), tmp_path / "run-stand")
    result = asyncio_run(campaign.run())
    assert result.results
    bundle = read_bundle(next(iter(find_bundles(tmp_path / "run-stand").values())))
    assert bundle.slots["context_tool_evidence"].status == STATUS_UNAVAILABLE
    final = result.results[-1]
    reason = (final.evidence.get("provenance") or {}).get("context_tool_evidence_error", "")
    assert "фактов не отдал" in reason and "unavailable" in reason
