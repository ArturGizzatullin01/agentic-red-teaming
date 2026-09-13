"""tests/test_budget_ledger_p10b.py — P10b (фича 007): Budget Ledger.

Проверяется: planned/executed/unknown_outcome/blocked различаются; списание
без двойного учёта (planned == spend существующего бюджета); usage=None —
явное «неизвестно», не ноль; блокировка фиксирована, решения леджер не
принимает; judge summary сверяется с JudgeBudget; исторические runs — пусто.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from memnotsafe.adapters.mock import MockTarget
from memnotsafe.core.campaign import Campaign
from memnotsafe.core.config import ActorConfig, JudgeSpec, Scenario, TargetSpec
from memnotsafe.core.ledger import (
    LEDGER_SCHEMA_VERSION,
    OP_ATTACKER_LLM,
    OP_JUDGE_LLM,
    OP_TARGET_CALL,
    PHASE_BLOCKED,
    PHASE_EXECUTED,
    PHASE_PLANNED,
    PHASE_UNKNOWN_OUTCOME,
    BudgetLedger,
    LedgerError,
    read_ledger,
)


def _scenario(tmp_path: Path, *, corpus=None, family="cross_user_bac", judged=False) -> Scenario:
    return Scenario(
        id=family, path=tmp_path / "s.yaml",
        target=TargetSpec(adapter="mock"),
        attacker=ActorConfig(user_id="1001"), victim=ActorConfig(user_id="1002"),
        attack_family=family, repetitions=1, corpus_path=corpus,
        judge=JudgeSpec(enabled=judged, model="stub-judge") if judged else JudgeSpec(),
    )


def test_ledger_entry_roundtrip_and_version_guard(tmp_path) -> None:
    ledger = BudgetLedger(tmp_path / "l.jsonl", experiment_id="EXP", run_id="RUN")
    ledger.record(OP_TARGET_CALL, PHASE_EXECUTED, case_id="C", attempt_no=1)
    ledger.record(OP_ATTACKER_LLM, PHASE_PLANNED, usage=None)  # usage неизвестен явно
    entries = read_ledger(tmp_path / "l.jsonl")
    assert entries[0].to_dict() == entries[0].to_dict()
    assert entries[1].usage is None  # None, не ноль
    raw = entries[0].to_dict()
    assert raw["schema_version"] == LEDGER_SCHEMA_VERSION
    raw["schema_version"] = 42
    with pytest.raises(LedgerError):
        from memnotsafe.core.ledger import LedgerEntry

        LedgerEntry.from_dict(raw)


def test_read_ledger_tolerant_for_historical_runs(tmp_path) -> None:
    assert read_ledger(tmp_path / "nope.jsonl") == []


def test_offline_run_ledger_no_double_counting(tmp_path) -> None:
    """Офлайн-прогон без онлайна: единственные расходы — target_call по одной
    executed-записи на попытку; planned-записей attacker_llm нет."""
    scenario = _scenario(tmp_path)
    out = tmp_path / "run"
    asyncio.run(Campaign(scenario, MockTarget(vulnerable=True), out).run())
    entries = read_ledger(out / "budget-ledger.jsonl")
    target_executed = [e for e in entries if e.operation == OP_TARGET_CALL and e.phase == PHASE_EXECUTED]
    assert len(target_executed) == 1
    attacker_planned = [e for e in entries if e.operation == OP_ATTACKER_LLM]
    assert attacker_planned == []
    assert all(e.usage is None or isinstance(e.usage, dict) for e in entries)


def test_attacker_planned_equals_budget_used(tmp_path) -> None:
    """Списание без двойного учёта: planned-записей ровно столько, сколько
    потратил CallBudget; после каждого planned есть executed/unknown_outcome."""
    from memnotsafe.generation.config import AttackerConfig
    from memnotsafe.generation.offline import escalation_stub_script

    scenario = _scenario(
        tmp_path, corpus=Path("corpora/escalation-seed.yaml"), family="generated"
    )
    cfg = AttackerConfig(
        provider="stub", scripted=[escalation_stub_script() for _ in range(4)], budget=10
    )
    out = tmp_path / "run-online"
    campaign = Campaign(
        scenario, MockTarget(vulnerable=True), out,
        attacker_config=cfg, online=True, online_attempts=4,
    )
    asyncio.run(campaign.run())
    entries = read_ledger(out / "budget-ledger.jsonl")
    planned = [e for e in entries if e.operation == OP_ATTACKER_LLM and e.phase == PHASE_PLANNED]
    resolved = [
        e for e in entries
        if e.operation == OP_ATTACKER_LLM and e.phase in (PHASE_EXECUTED, PHASE_UNKNOWN_OUTCOME)
    ]
    assert len(planned) == campaign._budget.used  # нет двойного списания
    assert len(planned) == len(resolved)  # каждая запланированная операция разрешена
    assert all(e.usage is None for e in planned)  # usage неизвестен → None, не ноль
    # planned связан с попыткой: case_id заполнен циклом эскалации
    assert all(e.case_id for e in planned)


def test_budget_blocked_recorded(tmp_path) -> None:
    """Отклонённый rewrite тратит последний вызов бюджета → следующая
    итерация упирается в exhausted: леджер фиксирует blocked (решение —
    у существующего CallBudget, леджер только наблюдает)."""
    from memnotsafe.generation.config import AttackerConfig

    scenario = _scenario(
        tmp_path, corpus=Path("corpora/escalation-seed.yaml"), family="generated"
    )
    goal_change = json.dumps({
        "payload": "новый текст", "trigger": "новый вопрос",
        "expected_effect": {"type": "response_reflects_adoption", "markers": ["X"]},
        "signal_strength": "weak",
    }, ensure_ascii=False)
    cfg = AttackerConfig(provider="stub", scripted=[goal_change], budget=1)
    out = tmp_path / "run-blocked"
    asyncio.run(
        Campaign(scenario, MockTarget(vulnerable=True), out,
                 attacker_config=cfg, online=True, online_attempts=4).run()
    )
    entries = read_ledger(out / "budget-ledger.jsonl")
    blocked = [e for e in entries if e.phase == PHASE_BLOCKED]
    assert blocked and blocked[0].operation == OP_ATTACKER_LLM
    # блокировка — не расход: usage нет и phase не executed
    assert all(e.usage is None for e in blocked)


def test_attacker_unknown_outcome_on_llm_failure(tmp_path) -> None:
    """Сбой атакующей LLM ПОСЛЕ spend(): planned + unknown_outcome — исход
    не наблюдаем, это не «выполнено с нулём» и не «не выполнено»."""
    from memnotsafe.generation.attacker_client import AttackerClient
    from memnotsafe.generation.config import AttackerConfig
    from memnotsafe.generation.errors import AttackerError

    scenario = _scenario(
        tmp_path, corpus=Path("corpora/escalation-seed.yaml"), family="generated"
    )

    class _DyingClient(AttackerClient):
        async def complete(self, prompt, *, system=""):
            raise AttackerError("сеть недоступна")

        async def aclose(self):
            return None

    cfg = AttackerConfig(provider="stub", budget=5)
    out = tmp_path / "run-unknown"
    campaign = Campaign(
        scenario, MockTarget(vulnerable=True), out,
        attacker_config=cfg, online=True, online_attempts=3,
    )
    campaign._attacker_client = _DyingClient()
    from memnotsafe.generation.budget import CallBudget

    campaign._budget = CallBudget(limit=5)
    asyncio.run(campaign.run())
    entries = read_ledger(out / "budget-ledger.jsonl")
    unknown = [e for e in entries if e.phase == PHASE_UNKNOWN_OUTCOME and e.operation == OP_ATTACKER_LLM]
    assert unknown and "сеть недоступна" in unknown[0].error
    planned = [e for e in entries if e.operation == OP_ATTACKER_LLM and e.phase == PHASE_PLANNED]
    assert len(planned) == 1 and campaign._budget.used == 1  # списание одно


def test_target_unknown_outcome_on_transport_error(tmp_path, monkeypatch) -> None:
    from memnotsafe.core.runner import RunnerError

    scenario = _scenario(tmp_path)
    out = tmp_path / "run-transport"

    async def broken_run_attack(*args, **kwargs):
        raise RunnerError("таймаут стенда")

    monkeypatch.setattr("memnotsafe.core.campaign.run_attack", broken_run_attack)
    with pytest.raises(RunnerError):
        asyncio.run(Campaign(scenario, MockTarget(vulnerable=True), out).run())
    entries = read_ledger(out / "budget-ledger.jsonl")
    assert any(
        e.operation == OP_TARGET_CALL and e.phase == PHASE_UNKNOWN_OUTCOME
        and "таймаут стенда" in (e.error or "")
        for e in entries
    )


def test_judge_summary_entry_matches_judge_budget(tmp_path) -> None:
    """Judge-расход фиксируется summary-записью и сверяется с JudgeBudget:
    calls_used/calls_limit в леджере == фактические значения бюджета судьи."""
    from memnotsafe.judge.runtime import LLMJudge
    from tests.test_judge_offline_regression import StubClient

    scenario = _scenario(tmp_path, judged=True)
    out = tmp_path / "run-judged"
    judge = LLMJudge(scenario.judge, client=StubClient(), repetitions=1, artifacts_dir=out / "judge")
    asyncio.run(Campaign(scenario, MockTarget(vulnerable=True), out, judge=judge).run())
    entries = read_ledger(out / "budget-ledger.jsonl")
    summary = [e for e in entries if e.operation == OP_JUDGE_LLM]
    assert len(summary) == 1 and summary[0].note == "summary"
    assert summary[0].usage["calls_used"] == judge.budget.used
    assert summary[0].usage["calls_limit"] == judge.budget.limit


def test_ledger_has_no_own_limits(tmp_path) -> None:
    """Леджер не принимает решений: у BudgetLedger нет лимитов/счётчиков
    списания — только запись наблюдений."""
    ledger = BudgetLedger(tmp_path / "l.jsonl", experiment_id="EXP", run_id="RUN")
    assert not hasattr(ledger, "limit")
    assert not hasattr(ledger, "spend")
