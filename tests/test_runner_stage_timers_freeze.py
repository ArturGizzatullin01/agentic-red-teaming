"""tests/test_runner_stage_timers_freeze.py — CARD-CLOCK + CARD-CAMPAIGN-CLOCK.

run_attack принимает keyword-only clock (None → time.perf_counter — поведение
по умолчанию неизменно; паттерн тот же, что у TraceExporter P11-1). Все точки
замера P12 — ровно 12 вызовов на полный прогон (старт/финиш шести фаз) — идут
через clock(): тесты получают детерминированные тайминги без правки
продукционного поведения. Источник: VERDICT-P12-2026-09-20, «следствие для
репозитория» — побайтовые замки артефактов обязаны исключать timing либо
замораживать часы; эта карточка даёт второй инструмент.

CARD-CAMPAIGN-CLOCK: Campaign тоже принимает keyword-only clock и проводит
его в свой (единственный) вызов run_attack — инъекция идёт штатным
продукционным параметром, без тестовой подмены модульного имени.

Замки:

  1. scripted clock передаётся Campaign(...) напрямую и доезжает до точек
     замера через РЕАЛЬНЫЙ путь кампании: timing в строке исхода
     attempts.jsonl равен заданным длительностям ТОЧНО (значения представимы
     в double, допусков нет); clock вызван ровно 12 раз — новых точек замера
     не появилось;
  2. дефолт (clock не передан) — тайминги не-null и неотрицательны
     (регрессионный замок живости дефолтного пути; runner напрямую и
     Campaign с явным clock=None);
  3. падение внутри фазы settle: фазы после точки сбоя не выполнялись —
     clock за границей сбоя не вызывается, строка истории попытки НЕ получает
     timing (чтение — честный None): инжектор не фабрикует значения для
     невыполненных фаз;
  4. CARD-TIMERS-FIX (FINDING-5): дефолтные часы «дышат» между прогонами —
     два последовательных прогона без инъекции clock дают различающиеся
     timing-наборы; регресс «дефолтный clock стал константой» проходит
     замки 2 (не-null/неотрицательность), но не этот.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from memnotsafe.adapters.base import SettleResult  # noqa: E402
from memnotsafe.adapters.mock import MockTarget  # noqa: E402
from memnotsafe.attacks import get_attack  # noqa: E402
from memnotsafe.attacks.base import AttackContext  # noqa: E402
from memnotsafe.core.attempt import read_history  # noqa: E402
from memnotsafe.core.campaign import Campaign  # noqa: E402
from memnotsafe.core.config import ActorConfig, Scenario, TargetSpec  # noqa: E402
from memnotsafe.core.runner import RunnerError, new_run_id, run_attack  # noqa: E402

STAGES = ("t_reset", "t_delivery", "t_settle", "t_trigger", "t_finalize", "t_scoring")


class _ScriptedClock:
    """Фиктивные часы: выдают значения по списку, ровно одно на вызов.

    Исчерпание последовательности — AssertionError: лишний вызов clock()
    означал бы точку замера за пределами P12 (или второй вызов в фазе,
    которой быть не должно) — замок 1 опирается на это.
    """

    def __init__(self, values: list[float]) -> None:
        self._values = list(values)
        self.calls = 0

    def __call__(self) -> float:
        assert self.calls < len(self._values), (
            f"clock() вызван {self.calls + 1}-й раз, последовательность из "
            f"{len(self._values)} значений исчерпана — появилась точка замера "
            "за пределами ожидаемых границ фаз P12"
        )
        value = self._values[self.calls]
        self.calls += 1
        return value


# Полный успешный прогон = 12 вызовов: старт/финиш фаз P12 в порядке
# выполнения (reset → delivery → finalize → settle → trigger → scoring).
# Значения точно представимы в double (целые, 0.5=2^-1, 0.25=2^-2): разности
# не накапливают погрешность, round(x, 6) их не меняет — равенство ТОЧНОЕ.
_SCRIPT = [
    0.0, 1.0,        # t_reset    = 1.0
    10.0, 13.0,      # t_delivery = 3.0
    20.0, 20.5,      # t_finalize = 0.5
    30.0, 32.0,      # t_settle   = 2.0
    40.0, 45.0,      # t_trigger  = 5.0
    50.0, 50.25,     # t_scoring  = 0.25
]
_EXPECTED_TIMING = {
    "t_reset": 1.0, "t_delivery": 3.0, "t_finalize": 0.5,
    "t_settle": 2.0, "t_trigger": 5.0, "t_scoring": 0.25,
}


class _SettleFailsTarget(MockTarget):
    """Транспортный сбой ВНУТРИ фазы settle: фазы после точки сбоя
    (завершение settle, trigger, scoring) в попытке не выполняются."""

    async def wait_until_persistent(self, evidence: dict[str, Any]) -> SettleResult:
        raise RuntimeError("settle transport failure (CARD-CLOCK)")


def _mock_scenario(tmp_path: Path) -> Scenario:
    return Scenario(
        id="cross_user_bac", path=tmp_path / "s.yaml",
        target=TargetSpec(adapter="mock"),
        attacker=ActorConfig(user_id="1001"), victim=ActorConfig(user_id="1002"),
        attack_family="cross_user_bac", repetitions=1,
    )


def _read_rows(out: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in (out / "attempts.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def test_scripted_clock_freezes_attempts_jsonl_timing(tmp_path: Path) -> None:
    """Замок 1: scripted clock передан Campaign напрямую — через реальный
    путь кампании timing в строке исхода attempts.jsonl равен заданным
    длительностям ТОЧНО; clock вызван ровно 12 раз (только точки P12,
    новых замеров нет)."""
    clock = _ScriptedClock(_SCRIPT)
    out = tmp_path / "run"
    campaign = Campaign(_mock_scenario(tmp_path), MockTarget(vulnerable=True), out, clock=clock)
    asyncio.run(campaign.run(repetitions=1))

    assert clock.calls == len(_SCRIPT), (
        f"точек вызова clock {clock.calls}, ожидается {len(_SCRIPT)} — появились "
        "замеры за пределами границ фаз P12"
    )
    outcome_rows = [r for r in _read_rows(out) if r["outcome"] != "registered"]
    assert len(outcome_rows) == 1, outcome_rows
    completed = outcome_rows[0]
    assert completed["timing"] == _EXPECTED_TIMING, (
        f"timing не заморожен scripted clock: {completed['timing']!r}"
    )


def test_default_clock_path_alive() -> None:
    """Замок 2: clock не передан — дефолтный perf_counter-путь жив: шесть полей,
    все не-null и неотрицательны (карточка CLOCK §2.3)."""
    attack = get_attack("cross_user_bac")()
    ctx = AttackContext("1001", "1002", 1, "CASE-CLOCK-DEFAULT")
    result = asyncio.run(run_attack(attack, ctx, MockTarget(vulnerable=True), run_id=new_run_id()))
    timing = result.evidence["timing"]
    assert set(timing) == set(STAGES), f"набор фаз: {sorted(timing)}"
    for stage in STAGES:
        value = timing[stage]
        assert isinstance(value, float) and value >= 0, (stage, value)


def test_phases_after_failure_stay_null_with_injected_clock() -> None:
    """Замок 3a: сбой внутри settle — clock за границей сбоя НЕ вызывается
    (инжектор не фабрикует значения для невыполненных фаз)."""
    # 7 значений: reset(2) + delivery(2) + finalize(2) + старт settle(1);
    # финиш settle / trigger / scoring не выполняются.
    clock = _ScriptedClock(_SCRIPT[:7])
    attack = get_attack("cross_user_bac")()
    ctx = AttackContext("1001", "1002", 1, "CASE-CLOCK-FAIL")
    with pytest.raises(RunnerError):
        asyncio.run(
            run_attack(attack, ctx, _SettleFailsTarget(), run_id=new_run_id(), clock=clock)
        )
    assert clock.calls == 7, (
        f"clock вызван {clock.calls} раз, ожидается 7 — замеры выполнялись за "
        "границей сбоя settle, хотя фазы не выполнялись"
    )


def test_failed_attempt_history_row_keeps_timing_none(tmp_path: Path) -> None:
    """Замок 3b: та же попытка через кампанию — строка transport_error БЕЗ
    timing (чтение истории — честный None), нули не фабрикуются."""
    clock = _ScriptedClock(_SCRIPT[:7])
    out = tmp_path / "run"
    campaign = Campaign(_mock_scenario(tmp_path), _SettleFailsTarget(), out, clock=clock)
    with pytest.raises(RunnerError):
        asyncio.run(campaign.run(repetitions=1))

    transport = [r for r in _read_rows(out) if r["outcome"] == "transport_error"]
    assert len(transport) == 1, transport
    assert "timing" not in transport[0], (
        "упавшая попытка не доносит timing до истории — невыполненные фазы "
        "остаются null, а не нулями"
    )
    entries = read_history(out / "attempts.jsonl")
    assert entries[-1].timing is None


def test_campaign_explicit_default_clock_completes(tmp_path: Path) -> None:
    """CARD-CAMPAIGN-CLOCK §2.3: явный clock=None у Campaign — прогон
    завершается, проводка параметра дефолт не сломала: timing строки исхода
    не-null и неотрицательны. (test_default_clock_path_alive бьёт в runner
    напрямую и остаётся как есть — здесь именно слой кампании.)"""
    out = tmp_path / "run"
    campaign = Campaign(_mock_scenario(tmp_path), MockTarget(vulnerable=True), out, clock=None)
    asyncio.run(campaign.run(repetitions=1))

    outcome_rows = [r for r in _read_rows(out) if r["outcome"] != "registered"]
    assert len(outcome_rows) == 1, outcome_rows
    timing = outcome_rows[0]["timing"]
    assert set(timing) == set(STAGES), f"набор фаз: {sorted(timing)}"
    for stage in STAGES:
        value = timing[stage]
        assert value is not None and value >= 0, (stage, value)


def test_default_clock_breathes_between_runs(tmp_path: Path) -> None:
    """Замок 4 (CARD-TIMERS-FIX, FINDING-5): дефолтные часы ЖИВЫ между
    прогонами — не константа. Два последовательных прогона без инъекции
    clock: timing присутствует в обоих, все шесть значений не-null >= 0, и
    наборы РАЗЛИЧАЮТСЯ (хотя бы одно значение). Ретраев нет намеренно:
    побайтовое равенство наборов — регресс «дефолтный clock заморожен», его
    надо вскрывать, а не маскировать повтором."""

    def _run_once(out: Path) -> dict[str, float]:
        campaign = Campaign(_mock_scenario(tmp_path), MockTarget(vulnerable=True), out)
        asyncio.run(campaign.run(repetitions=1))
        outcome_rows = [r for r in _read_rows(out) if r["outcome"] != "registered"]
        assert len(outcome_rows) == 1, outcome_rows
        timing = outcome_rows[0]["timing"]
        assert set(timing) == set(STAGES), f"набор фаз: {sorted(timing)}"
        for stage in STAGES:
            value = timing[stage]
            assert value is not None and value >= 0, (stage, value)
        return timing

    first = _run_once(tmp_path / "run-breath-1")
    second = _run_once(tmp_path / "run-breath-2")
    assert first != second, (
        f"timing двух прогонов дефолтных часов побайтово равны ({first!r}) — "
        "дефолтный clock ведёт себя как константа"
    )
