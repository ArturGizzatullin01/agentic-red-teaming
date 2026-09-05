"""tests/test_campaign_budget.py — офлайн-проверка бюджета N повторов и
early-exit (FR-013) + разделение кодов возврата (FR-006/FR-010, Принцип VII).

Всё на mock-таргете и поддельном адаптере: без сети/LLM/стенда. Проверяется
target-agnostic ядро (core/campaign.py, core/config.py, cli.py), не стенд.
"""

from __future__ import annotations

import asyncio
import json

import memnotsafe.cli as cli
from memnotsafe.adapters.base import ProbeResult, SendResult, TargetAdapter
from memnotsafe.adapters.mock import MockTarget
from memnotsafe.core.campaign import Campaign
from memnotsafe.core.config import ActorConfig, Scenario, TargetSpec
from memnotsafe.core.runner import RunnerError


def _scenario(tmp_path, *, reps: int, stop_on_success: bool, family="cross_user_bac") -> Scenario:
    return Scenario(
        id=family,
        path=tmp_path / f"{family}.yaml",
        target=TargetSpec(adapter="mock"),
        attacker=ActorConfig(user_id="1001"),
        victim=ActorConfig(user_id="1002"),
        attack_family=family,
        repetitions=reps,
        stop_on_success=stop_on_success,
    )


# --------------------------------------------------------------- T005: бюджет N


def test_early_exit_stops_on_first_success(tmp_path):
    """stop_on_success=True + уязвимый таргет → выходим после первого success,
    не тратя оставшийся бюджет N."""
    scenario = _scenario(tmp_path, reps=5, stop_on_success=True)
    campaign = Campaign(scenario, MockTarget(vulnerable=True), tmp_path / "run-out")

    result = asyncio.run(campaign.run())

    assert result.attempts == 1
    assert len(result.results) == 1
    assert result.results[0].success is True


def test_budget_exhausted_without_success_runs_all_n(tmp_path):
    """stop_on_success=True, но таргет не пробивается (protected) → честно
    исчерпываем весь бюджет N и ни один повтор не success."""
    scenario = _scenario(tmp_path, reps=3, stop_on_success=True)
    campaign = Campaign(scenario, MockTarget(vulnerable=False), tmp_path / "run-out")

    result = asyncio.run(campaign.run())

    assert result.attempts == 3
    assert all(r.success is False for r in result.results)


def test_default_off_runs_full_budget_even_on_success(tmp_path):
    """Дефолт stop_on_success=False → mock-путь не меняется: считаем все N,
    несмотря на ранние success (FR-011/SC-007)."""
    scenario = _scenario(tmp_path, reps=3, stop_on_success=False)
    campaign = Campaign(scenario, MockTarget(vulnerable=True), tmp_path / "run-out")

    result = asyncio.run(campaign.run())

    assert result.attempts == 3
    assert all(r.success is True for r in result.results)


# ---------------------------------------------- T020: коды возврата (Принцип VII)

_MOCK_PROTECTED_YAML = """\
id: budget_negative
target:
  adapter: mock
  vulnerable: false
actors:
  attacker:
    user_id: "1001"
  victim:
    user_id: "1002"
attack:
  family: cross_user_bac
metrics:
  repetitions: 2
"""


def test_observable_channel_without_leak_is_not_exploitable_exit_zero(tmp_path):
    """Наблюдаемый канал (mock всё видит), но авторизация блокирует утечку →
    external_effect=False → NOT_EXPLOITABLE + exit 0 (честный негатив, не сбой)."""
    scenario_path = tmp_path / "budget_negative.yaml"
    scenario_path.write_text(_MOCK_PROTECTED_YAML, encoding="utf-8")
    out = tmp_path / "out"

    rc = cli.main(["campaign", "--scenario", str(scenario_path), "--output", str(out), "--iterations", "2"])

    assert rc == 0
    findings = json.loads((out / "report" / "findings.json").read_text(encoding="utf-8"))
    assert findings and all(f["status"] == "NOT_EXPLOITABLE" for f in findings)
    campaign = json.loads((out / "campaign.json").read_text(encoding="utf-8"))
    assert all(r["stages"][-1]["stage"] == "external_effect" for r in campaign["results"])
    assert all(r["success"] is False for r in campaign["results"])


class _RaisingAdapter(TargetAdapter):
    """Поддельный адаптер, падающий на reset_state → RunnerError → exit 1."""

    async def probe(self):
        return ProbeResult(reachable=True)

    async def reset_state(self):
        raise RunnerError("симулированный сбой адаптера/сети")

    async def new_session(self, user_id):
        return "s"

    async def send(self, session_id, message):
        return SendResult(content="")

    async def close_session(self, session_id):
        return None


def test_runner_error_exits_one(tmp_path, monkeypatch):
    """Сбой раннера/адаптера → exit 1 (ОТДЕЛЬНО от честного негатива)."""
    scenario_path = tmp_path / "budget_negative.yaml"
    scenario_path.write_text(_MOCK_PROTECTED_YAML, encoding="utf-8")

    monkeypatch.setattr(cli, "build_adapter", lambda scenario, target_override=None: _RaisingAdapter())

    rc = cli.main(["campaign", "--scenario", str(scenario_path), "--output", str(tmp_path / "out"), "--iterations", "2"])

    assert rc == 1
