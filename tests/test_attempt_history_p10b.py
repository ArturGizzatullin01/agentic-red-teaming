"""tests/test_attempt_history_p10b.py — P10b (фича 007): AttemptRecord.

Проверяется: различение логический кейс / кандидат / попытка / транспортный
повтор; lineage rewrite (parent → child); в истории есть seed, отклонённый
кандидат, исчерпание бюджета, транспортная ошибка, прерванная попытка;
retry не создаёт нового кандидата; связь с ASR задокументирована и не ломает
aggregate_metrics; исторические runs читаются толерантно.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from memnotsafe.adapters.mock import MockTarget
from memnotsafe.core.attempt import (
    ATTEMPT_SCHEMA_VERSION,
    COMPLETED_OUTCOMES,
    OUTCOME_ABORTED,
    OUTCOME_BUDGET_EXHAUSTED,
    OUTCOME_COMPLETED_FAILURE,
    OUTCOME_COMPLETED_SUCCESS,
    OUTCOME_REGISTERED,
    OUTCOME_REWRITE_ACCEPTED,
    OUTCOME_REWRITE_REJECTED,
    OUTCOME_TRANSPORT_ERROR,
    OUTCOME_UNKNOWN,
    AttemptHistory,
    AttemptHistoryError,
    outcome_of_result,
    read_history,
    sessions_from_transcript,
)
from memnotsafe.core.campaign import Campaign
from memnotsafe.core.config import ActorConfig, Scenario, TargetSpec
from memnotsafe.core.models import AttackResult, StageResult


def _scenario(tmp_path: Path, *, corpus=None, family="cross_user_bac") -> Scenario:
    return Scenario(
        id=family, path=tmp_path / "s.yaml",
        target=TargetSpec(adapter="mock"),
        attacker=ActorConfig(user_id="1001"), victim=ActorConfig(user_id="1002"),
        attack_family=family, repetitions=1, corpus_path=corpus,
    )


# ------------------------------------------------------------------ unit

def test_outcome_of_result_tristate() -> None:
    def _result(success, retrieval=None):
        stages = [
            StageResult(stage="write", success=True),
            StageResult(stage="persistence", success=True),
            StageResult(stage="retrieval", success=retrieval),
            StageResult(stage="adoption", success=retrieval),
            StageResult(stage="external_effect", success=success),
        ]
        return AttackResult(
            run_id="R", case_id="C", attack_id="a", scenario_id="s",
            stages=stages, success=success, metrics={}, evidence={},
        )

    assert outcome_of_result(_result(True, True)) == OUTCOME_COMPLETED_SUCCESS
    assert outcome_of_result(_result(False, False)) == OUTCOME_COMPLETED_FAILURE
    assert outcome_of_result(_result(False, None)) == OUTCOME_UNKNOWN  # не сплющивается


def test_sessions_from_transcript_and_missing_telemetry() -> None:
    transcript = {"messages": [
        {"phase": "delivery", "session_id": "sess-a"},
        {"phase": "trigger", "session_id": "sess-b"},
        {"phase": "delivery", "session_id": "sess-a2"},  # первая фаза выигрывает
    ]}
    sessions = sessions_from_transcript(transcript)
    assert sessions == {"delivery": "sess-a", "trigger": "sess-b"}
    assert sessions_from_transcript(None) == {}
    # отсутствие телеметрии → None-значение, не вымышленная сессия
    assert sessions_from_transcript({"messages": [{"phase": "delivery", "session_id": None}]}) == {
        "delivery": None,
    }


def test_transport_retry_is_not_a_new_candidate() -> None:
    path = Path("attempts-unit.jsonl")
    if path.exists():
        path.unlink()
    history = AttemptHistory(path, experiment_id="EXP", run_id="RUN-1")
    history.record(
        case_id="CASE-x-001-aaaaaa", candidate_id="CASE-x-001-aaaaaa",
        outcome=OUTCOME_TRANSPORT_ERROR, attempt_no=1, transport_retry=0,
        error="connection reset",
    )
    history.record(
        case_id="CASE-x-001-aaaaaa", candidate_id="CASE-x-001-aaaaaa",
        outcome=OUTCOME_TRANSPORT_ERROR, attempt_no=1, transport_retry=1,
        error="connection reset again",
    )
    entries = read_history(path)
    assert [e.transport_retry for e in entries] == [0, 1]
    assert {e.candidate_id for e in entries} == {"CASE-x-001-aaaaaa"}  # кандидат один
    assert {e.case_id for e in entries} == {"CASE-x-001-aaaaaa"}
    path.unlink()


def test_record_roundtrip_and_version_guard() -> None:
    from memnotsafe.core.attempt import AttemptRecord

    path = Path("attempts-unit2.jsonl")
    if path.exists():
        path.unlink()
    history = AttemptHistory(path, experiment_id="EXP", run_id="RUN-1")
    history.record(
        case_id="C", candidate_id="C", outcome=OUTCOME_REGISTERED, attempt_no=0,
        case_marker="CM-abc123", seed=7, session_ids={"delivery": "s1"},
    )
    raw = read_history(path)[0].to_dict()
    assert raw["schema_version"] == ATTEMPT_SCHEMA_VERSION
    assert raw["case_marker"] == "CM-abc123" and raw["seed"] == 7
    restored = AttemptRecord.from_dict(raw)
    assert restored == read_history(path)[0]
    raw["schema_version"] = 99
    with pytest.raises(AttemptHistoryError):
        AttemptRecord.from_dict(raw)
    path.unlink()


def test_history_and_ledger_array_line_is_contract_error(tmp_path) -> None:
    """Фикс приёмки P2 (раунд 3): строка-массив [] в JSONL — контрактная
    ошибка, а не AttributeError."""
    from memnotsafe.core.ledger import LedgerError, read_ledger

    (tmp_path / "h.jsonl").write_text("[]", encoding="utf-8")
    with pytest.raises(AttemptHistoryError, match="JSON-объектом"):
        read_history(tmp_path / "h.jsonl")
    with pytest.raises(LedgerError, match="JSON-объектом"):
        read_ledger(tmp_path / "h.jsonl")


def test_read_history_tolerant_for_historical_runs(tmp_path) -> None:
    assert read_history(tmp_path / "nope.jsonl") == []


# --------------------------------------------------- интеграция: офлайн-прогон

def test_offline_run_history_chain(tmp_path) -> None:
    """Обычный прогон: registered + completed на каждый случай, experiment_id
    из experiment.json, маркер и сессии записаны, ASR-знаменатель не тронут."""
    scenario = _scenario(tmp_path)
    out = tmp_path / "run"
    result = asyncio.run(Campaign(scenario, MockTarget(vulnerable=True), out).run())
    entries = read_history(out / "attempts.jsonl")
    case_ids = {e.case_id for e in entries}
    assert case_ids == {r.case_id for r in result.results}
    for case in case_ids:
        chain = [e for e in entries if e.case_id == case]
        assert chain[0].outcome == OUTCOME_REGISTERED
        assert chain[0].seed is not None
        registered, attempted = chain[0], chain[-1]
        assert attempted.attempt_no == 1
        assert attempted.outcome in COMPLETED_OUTCOMES
        assert attempted.goal_digest  # цель валидна → digest в истории
        assert attempted.case_marker  # маркер-канарейка записан
        assert attempted.session_ids  # сессии транскрипта присутствуют
    # связь с метриками: попытки в истории ≥ случаев; ASR-знаменатель прежний
    completed = [e for e in entries if e.outcome in COMPLETED_OUTCOMES]
    assert len(completed) >= len(result.results)
    experiment = json.loads((out / "experiment.json").read_text(encoding="utf-8"))
    assert all(e.experiment_id == experiment["experiment_id"] for e in entries)
    assert result.aggregate_metrics["attempts"] == len(result.results)


def test_escalation_history_lineage(tmp_path) -> None:
    """Онлайн-эскалация: rewrite-потомок = новый кандидат с parent; попытки
    нумеруются по порядку; budget/rewrite события попадают в историю."""
    from memnotsafe.generation.config import AttackerConfig
    from memnotsafe.generation.offline import escalation_stub_script

    scenario = _scenario(
        tmp_path, corpus=Path("corpora/escalation-seed.yaml"), family="generated"
    )
    cfg = AttackerConfig(
        provider="stub",
        scripted=[escalation_stub_script() for _ in range(6)],
        budget=10,
    )
    out = tmp_path / "run-online"
    result = asyncio.run(
        Campaign(scenario, MockTarget(vulnerable=True), out,
                 attacker_config=cfg, online=True, online_attempts=4).run()
    )
    entries = read_history(out / "attempts.jsonl")
    accepted = [e for e in entries if e.outcome == OUTCOME_REWRITE_ACCEPTED]
    assert accepted, "онлайн-прогон обязан иметь принятый rewrite"
    by_child = {e.candidate_id: e for e in accepted}
    for child in accepted:
        assert child.parent_candidate_id  # lineage непустой
        # у потомка есть собственная попытка на target
        attempts_of_child = [
            e for e in entries
            if e.candidate_id == child.candidate_id and e.attempt_no >= 1
        ]
        assert attempts_of_child
    # финальный результат кейса — последняя завершённая попытка цепочки
    logical_case = accepted[0].case_id
    completed_chain = [
        e for e in entries
        if e.case_id == logical_case and e.outcome in COMPLETED_OUTCOMES
    ]
    assert completed_chain
    assert completed_chain[-1].candidate_id == result.results[0].case_id


def test_rejected_rewrite_recorded_without_target_attempt(tmp_path) -> None:
    """Отклонённый кандидат (смена цели) — в историю, target не тронут:
    после reject-записи попыток с большим attempt_no нет."""
    from memnotsafe.generation.config import AttackerConfig

    scenario = _scenario(
        tmp_path, corpus=Path("corpora/escalation-seed.yaml"), family="generated"
    )
    goal_change = json.dumps({
        "payload": "новый текст", "trigger": "новый вопрос",
        "expected_effect": {"type": "response_reflects_adoption", "markers": ["X"]},
        "signal_strength": "weak",
    }, ensure_ascii=False)
    cfg = AttackerConfig(provider="stub", scripted=[goal_change], budget=5)
    out = tmp_path / "run-rejected"
    asyncio.run(
        Campaign(scenario, MockTarget(vulnerable=True), out,
                 attacker_config=cfg, online=True, online_attempts=3).run()
    )
    entries = read_history(out / "attempts.jsonl")
    rejected = [e for e in entries if e.outcome == OUTCOME_REWRITE_REJECTED]
    assert rejected, "смена цели обязана дать rewrite_rejected"
    assert all(r.attempt_no == 0 for r in rejected)  # до target не дошло


def test_budget_exhausted_recorded(tmp_path) -> None:
    from memnotsafe.generation.config import AttackerConfig
    from memnotsafe.generation.offline import escalation_stub_script

    scenario = _scenario(
        tmp_path, corpus=Path("corpora/escalation-seed.yaml"), family="generated"
    )
    cfg = AttackerConfig(provider="stub", scripted=[escalation_stub_script()], budget=1)
    out = tmp_path / "run-budget"
    asyncio.run(
        Campaign(scenario, MockTarget(vulnerable=True), out,
                 attacker_config=cfg, online=True, online_attempts=4).run()
    )
    entries = read_history(out / "attempts.jsonl")
    assert any(e.outcome == OUTCOME_BUDGET_EXHAUSTED for e in entries)


def test_transport_error_recorded_and_reraised(tmp_path, monkeypatch) -> None:
    """Сбой транспорта: запись в историю (candidate тот же) + RunnerError
    НЕ глотается — CLI обязан вернуть exit 1 (exit-контракт)."""
    from memnotsafe.core.runner import RunnerError

    scenario = _scenario(tmp_path)
    out = tmp_path / "run-transport"

    async def broken_run_attack(*args, **kwargs):
        raise RunnerError("транспорт недоступен")

    monkeypatch.setattr("memnotsafe.core.campaign.run_attack", broken_run_attack)
    with pytest.raises(RunnerError):
        asyncio.run(Campaign(scenario, MockTarget(vulnerable=True), out).run())
    entries = read_history(out / "attempts.jsonl")
    errors = [e for e in entries if e.outcome == OUTCOME_TRANSPORT_ERROR]
    assert len(errors) == 1
    assert errors[0].candidate_id == errors[0].case_id  # retry ≠ новый кандидат
    assert "транспорт недоступен" in errors[0].error


def test_aborted_recorded_on_attacker_error(tmp_path) -> None:
    """Сбой атакующей LLM в эскалации: попытка прервана (aborted), уже
    собранные результаты сохраняются (FR-010/FR-011)."""
    from memnotsafe.generation.attacker_client import AttackerClient
    from memnotsafe.generation.config import AttackerConfig
    from memnotsafe.generation.errors import AttackerError

    scenario = _scenario(
        tmp_path, corpus=Path("corpora/escalation-seed.yaml"), family="generated"
    )

    class _DyingClient(AttackerClient):
        async def complete(self, prompt, *, system=""):
            raise AttackerError("ключ отозван")

        async def aclose(self):
            return None

    cfg = AttackerConfig(provider="stub", budget=5)
    out = tmp_path / "run-abort"
    campaign = Campaign(
        scenario, MockTarget(vulnerable=True), out,
        attacker_config=cfg, online=True, online_attempts=3,
    )
    campaign._attacker_client = _DyingClient()
    campaign._budget = __import__(
        "memnotsafe.generation.budget", fromlist=["CallBudget"]
    ).CallBudget(limit=5)
    result = asyncio.run(campaign.run())
    assert campaign.attacker_error == "ключ отозван"
    assert len(result.results) == 1  # результат сохранён
    entries = read_history(out / "attempts.jsonl")
    aborted = [e for e in entries if e.outcome == OUTCOME_ABORTED]
    assert aborted and "ключ отозван" in aborted[0].error


def test_asr_denominator_documented_and_untouched(tmp_path) -> None:
    """История не меняет метрики: знаменатель ASR = len(results), записи
    истории не пересчитывают aggregate_metrics."""
    scenario = _scenario(tmp_path)
    out = tmp_path / "run-asr"
    result = asyncio.run(Campaign(scenario, MockTarget(vulnerable=True), out).run())
    entries = read_history(out / "attempts.jsonl")
    completed = [e for e in entries if e.outcome in COMPLETED_OUTCOMES]
    # без эскалации: одна завершённая попытка на случай
    assert len(completed) == len(result.results)
    assert result.aggregate_metrics["attempts"] == len(result.results)
