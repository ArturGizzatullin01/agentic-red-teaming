"""tests/test_runner_stage_timers.py — карточка P12: стадийные таймеры runner.

Runner метит монотонными часами границы фаз попытки (reset_state / delivery /
settle / trigger / finalize=close_pending / scoring) и кладёт длительности в
evidence["timing"]; campaign записывает их аддитивным полем timing в строку
исхода attempts.jsonl. Замки:

  1. полный прогон: все шесть полей присутствуют, float >= 0; сумма
     длительностей согласована со стеной попытки (сумма непересекающихся
     фаз <= стена + допуск на округление/неизмеримые щели);
  2. attempts.jsonl: строка registered БЕЗ timing (форма старых строк не
     меняется), строка исхода С timing (шесть ключей);
  3. невыполненная фаза — null, не ноль и не выкидывание ключа; чтение
     толерантно к строкам без timing;
  4. измеритель B0 предпочитает поля runner, фолбэк на null сохранён
     (старый run-dir без timing).

P12 только измеряет: поведение фаз (порядок/ошибки/отмена) не меняется —
это держат существующие тесты runner/campaign, здесь не дублируется.
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from memnotsafe.adapters.mock import MockTarget  # noqa: E402
from memnotsafe.attacks import get_attack  # noqa: E402
from memnotsafe.attacks.base import AttackContext  # noqa: E402
from memnotsafe.core.attempt import AttemptHistory, read_history  # noqa: E402
from memnotsafe.core.campaign import Campaign  # noqa: E402
from memnotsafe.core.config import ActorConfig, Scenario, TargetSpec  # noqa: E402
from memnotsafe.core.runner import new_run_id, run_attack  # noqa: E402

STAGES = ("t_reset", "t_delivery", "t_settle", "t_trigger", "t_finalize", "t_scoring")
# Допуск согласования суммы фаз со стеной: фазы непересекающиеся, но каждая
# округляется до 6 знаков, а между фазами есть неизмеримые щели (baseline,
# снимки, сборка результата) — сумма обязана быть <= стены с малым допуском.
SUM_TOLERANCE_S = 0.25


def _run_mock_attack() -> dict:
    attack = get_attack("cross_user_bac")()
    ctx = AttackContext("1001", "1002", 1, "CASE-P12-001")
    result = asyncio.run(run_attack(attack, ctx, MockTarget(vulnerable=True), run_id=new_run_id()))
    return result.evidence["timing"]


def test_full_run_has_all_stage_timers_nonnegative() -> None:
    """Замок 1a: шесть полей, все float >= 0 (полный прогон все фазы выполнил)."""
    timing = _run_mock_attack()
    assert set(timing) == set(STAGES), f"набор фаз: {sorted(timing)}"
    for stage in STAGES:
        value = timing[stage]
        assert isinstance(value, float) and value >= 0, (stage, value)


def test_stage_sum_consistent_with_attempt_wall() -> None:
    """Замок 1b: сумма длительностей непересекающихся фаз <= стена попытки
    (+ допуск на округление и щели между фазами)."""
    attack = get_attack("cross_user_bac")()
    ctx = AttackContext("1001", "1002", 1, "CASE-P12-002")
    started = time.perf_counter()
    result = asyncio.run(
        run_attack(attack, ctx, MockTarget(vulnerable=True), run_id=new_run_id())
    )
    wall = time.perf_counter() - started
    total = sum(v for v in result.evidence["timing"].values() if v is not None)
    assert total <= wall + SUM_TOLERANCE_S, (
        f"сумма фаз {total:.6f}s больше стены попытки {wall:.6f}s (допуск {SUM_TOLERANCE_S}s) "
        "— фазы пересекаются или часы несогласованы"
    )


def test_campaign_writes_timing_into_outcome_row(tmp_path: Path) -> None:
    """Замок 2: attempts.jsonl — registered без timing (старая форма строк не
    меняется), строка исхода несёт timing со всеми шестью фазами."""
    scenario = Scenario(
        id="cross_user_bac", path=tmp_path / "s.yaml",
        target=TargetSpec(adapter="mock"),
        attacker=ActorConfig(user_id="1001"), victim=ActorConfig(user_id="1002"),
        attack_family="cross_user_bac", repetitions=1,
    )
    out = tmp_path / "run"
    campaign = Campaign(scenario, MockTarget(vulnerable=True), out)
    asyncio.run(campaign.run(repetitions=1))

    rows = [
        json.loads(line)
        for line in (out / "attempts.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    by_outcome = {row["outcome"]: row for row in rows}
    assert "timing" not in by_outcome["registered"], (
        "нефазовые события (registered) не несут таймингов — аддитивность не "
        "меняет форму старых строк"
    )
    completed = by_outcome["completed_success"]
    assert set(completed["timing"]) == set(STAGES)
    assert all(isinstance(v, float) and v >= 0 for v in completed["timing"].values())


def test_unperformed_phase_is_null_not_zero(tmp_path: Path) -> None:
    """Замок 3: невыполненная фаза — null в JSON (не 0, не выкидывание ключа);
    from_dict толерантен и к строкам без timing, и к null-фазам."""
    history = AttemptHistory(tmp_path / "attempts.jsonl", experiment_id=None, run_id="R")
    history.record(
        case_id="C", candidate_id="C", outcome="completed_unknown", attempt_no=1,
        timing={"t_reset": 0.001, "t_delivery": 0.002, "t_settle": None,
                "t_trigger": None, "t_finalize": None, "t_scoring": None},
    )
    history.record(case_id="C", candidate_id="C", outcome="budget_exhausted", attempt_no=0)

    raw = [
        json.loads(line)
        for line in (tmp_path / "attempts.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert raw[0]["timing"]["t_settle"] is None, "невыполненная фаза обязана быть null, не ноль"
    assert raw[0]["timing"]["t_reset"] == 0.001
    assert "timing" not in raw[1]

    entries = read_history(tmp_path / "attempts.jsonl")
    assert entries[0].timing is not None and entries[0].timing["t_scoring"] is None
    assert entries[1].timing is None, "чтение старых строк без timing не падает"


def test_measurer_prefers_runner_fields_with_fallback(tmp_path: Path) -> None:
    """Замок 4: измеритель читает timing из attempts.jsonl (последняя строка,
    где поле есть); старый run-dir без timing — пустой словарь и честный null."""
    # импорт внутри теста: на базе карточки этих хелперов ещё нет — RED должен
    # быть чистым падением теста, а не collection-error всего файла
    from memnotsafe.perf.baseline import _attempt_timing, _timing_seconds

    out = tmp_path / "old-run"
    out.mkdir()
    (out / "attempts.jsonl").write_text(
        json.dumps({"schema_version": 1, "outcome": "registered"}) + "\n"
        + json.dumps({"schema_version": 1, "outcome": "completed_success"}) + "\n",
        encoding="utf-8",
    )
    assert _attempt_timing(out) == {}, "старый прогон без timing — фолбэк, не ошибка"
    assert _timing_seconds({}, "t_reset") is None

    (out / "attempts.jsonl").write_text(
        json.dumps({"schema_version": 1, "outcome": "registered"}) + "\n"
        + json.dumps({"schema_version": 1, "outcome": "completed_success",
                      "timing": {"t_reset": 0.0004, "t_finalize": 0.0001, "t_scoring": 0.0}}) + "\n",
        encoding="utf-8",
    )
    timing = _attempt_timing(out)
    assert _timing_seconds(timing, "t_reset") == 0.0004
    assert _timing_seconds(timing, "t_scoring") == 0.0, "выполненная нулевая фаза — 0.0, не null"
    assert _timing_seconds(timing, "t_settle") is None, "отсутствующая фаза — null"
