"""tests/test_scheduler_hardening.py — FIX-PACK-2 (MULTI-1): семантика
планировщика пакетов (core/plan.py + core/worker.orchestrate_plan).

Шесть дефектов, по RED-замку на каждый (детерминированно, без реальных
подпроцессов — runner инжектируется, run_plan монкипатчится, леджеры/кампании
пишутся на диск руками):

  D1 расход = ФАКТ вызовов цели из budget-ledger.jsonl, не число кейсов;
  D2 requires разблокирует зависимое только исходом completed;
  D3 исключение воркера не теряет summary.json/batch-state.json;
  D4 rebuild_summary берёт факт из леджера и добавляет расход контроля;
  D6 стенд/принципалы пробрасываются дочернему env-ом и пишутся в сводку.

D5 (инверсия семантики isolation_group) переписан в test_plan_orchestrator.py —
два прежних `test_stop_*` заменены на легальность + предупреждение сводки.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest
import yaml

from memnotsafe.core.ledger import LedgerEntry
from memnotsafe.core.plan import (
    OUTCOME_BLOCKED,
    OUTCOME_COMPLETED,
    OUTCOME_TRANSPORT,
    OUTCOME_UNKNOWN,
    CleanResult,
    Job,
    JobRun,
    Plan,
    Stand,
    build_summary,
    load_plan,
    rebuild_summary,
    run_plan,
    write_batch,
)

REPO = Path(__file__).resolve().parents[1]
SC = str(REPO / "scenarios" / "cross_user_bac.yaml")


# ------------------------------------------------------------- фабрики/утилиты
def _stand(sid, group, principals, *, target="mock", clean_check=("true",)):
    return Stand(id=sid, target=target, principals=tuple(principals),
                 isolation_group=group, slots=1, clean_check=clean_check)


def _job(jid, *, control=None, iterations=1, requires=()):
    return Job(id=jid, scenario=SC, control=control, iterations=iterations, requires=tuple(requires))


def _plan(stands, jobs, *, cap=100, mps=2):
    return Plan(version=1, max_parallel_stands=mps, max_total_target_calls=cap,
                stands=tuple(stands), jobs=tuple(jobs))


def _clean(_stand):
    return CleanResult(status="clean")


def _write_campaign(run_dir: Path, *, attempts: int, successful: int = 0) -> None:
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "campaign.json").write_text(json.dumps({
        "run_id": run_dir.name,
        "aggregate_metrics": {"successful": successful, "attempts": attempts,
                              "end_to_end_asr": (successful / attempts) if attempts else None},
    }), encoding="utf-8")


def _write_ledger(run_dir: Path, *, executed_target_calls: int, noise: bool = True) -> None:
    """Пишет budget-ledger.jsonl каноническим LedgerEntry: N executed target_call
    + (опц.) шум, который считаться НЕ должен."""
    run_dir.mkdir(parents=True, exist_ok=True)
    rows = [LedgerEntry(experiment_id="e", run_id=run_dir.name, operation="target_call",
                        phase="executed", attempt_no=i).to_dict()
            for i in range(executed_target_calls)]
    if noise:
        rows += [
            LedgerEntry(experiment_id="e", run_id=run_dir.name, operation="target_call",
                        phase="unknown_outcome").to_dict(),          # target_call, но НЕ executed
            LedgerEntry(experiment_id="e", run_id=run_dir.name, operation="target_call",
                        phase="blocked").to_dict(),                  # отказ бюджета — не вызов
            LedgerEntry(experiment_id="e", run_id=run_dir.name, operation="judge_llm",
                        phase="executed").to_dict(),                 # executed, но НЕ target_call
        ]
    (run_dir / "budget-ledger.jsonl").write_text(
        "\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n", encoding="utf-8")


# =================================================================== D1
def test_d1_actual_is_ledger_fact_not_case_count(tmp_path):
    from memnotsafe.core.plan import count_executed_target_calls, resolve_target_calls_actual
    run_dir = tmp_path / "j1"
    _write_campaign(run_dir, attempts=1)                 # знаменатель ASR (кейсы) = 1
    _write_ledger(run_dir, executed_target_calls=5)      # ФАКТ вызовов цели = 5
    # старый код отдавал бы m=1; факт — 5, и он берётся из леджера, не из кейсов
    assert count_executed_target_calls(run_dir) == 5
    assert resolve_target_calls_actual(run_dir, 1) == (5, False)


def test_d1_no_ledger_falls_back_to_flagged_estimate(tmp_path):
    from memnotsafe.core.plan import count_executed_target_calls, resolve_target_calls_actual
    run_dir = tmp_path / "j1"
    _write_campaign(run_dir, attempts=3)                 # леджера нет
    assert count_executed_target_calls(run_dir) is None
    assert resolve_target_calls_actual(run_dir, 3) == (3, True)   # оценка + пометка


def test_d1_corrupt_ledger_degrades_to_estimate_not_crash(tmp_path):
    from memnotsafe.core.plan import resolve_target_calls_actual
    run_dir = tmp_path / "j1"
    run_dir.mkdir()
    (run_dir / "budget-ledger.jsonl").write_text("{not json\n", encoding="utf-8")
    # битый леджер не роняет сводку пакета — честный откат к оценке
    assert resolve_target_calls_actual(run_dir, 4) == (4, True)


# =================================================================== D2
class _OutcomeRunner:
    """Инжектируемый runner: возвращает заданный исход по job_id, считает выдачи."""

    def __init__(self, outcomes: dict[str, str]):
        self.outcomes = outcomes
        self.calls: list[str] = []

    async def __call__(self, job, stand, out):
        self.calls.append(job.id)
        return JobRun(job_id=job.id, stand_id=stand.id,
                      outcome=self.outcomes.get(job.id, OUTCOME_COMPLETED),
                      run_dir=str(Path(out) / job.id))


def test_d2_failed_dependency_blocks_dependent(tmp_path):
    # j1 падает транспортом; j2 требует j1 — ДОЛЖЕН остаться невыданным (BLOCKED),
    # прежний код (`dep in done`) выдал бы его после любого исхода зависимости.
    plan = _plan([_stand("a", "g1", ["p1"])], [_job("j1"), _job("j2", requires=["j1"])], mps=1)
    r = _OutcomeRunner({"j1": OUTCOME_TRANSPORT})
    runs = asyncio.run(run_plan(plan, tmp_path / "b", runner=r, clean_checker=_clean))
    assert r.calls == ["j1"]                       # j2 НЕ запускался
    assert runs["j1"].outcome == OUTCOME_TRANSPORT
    assert runs["j2"].outcome == OUTCOME_BLOCKED
    assert "j1" in (runs["j2"].detail or "") and OUTCOME_TRANSPORT in (runs["j2"].detail or "")


def test_d2_completed_dependency_unblocks_dependent(tmp_path):
    # позитивный контроль: успешная зависимость по-прежнему разблокирует зависимое
    plan = _plan([_stand("a", "g1", ["p1"])], [_job("j1"), _job("j2", requires=["j1"])], mps=1)
    r = _OutcomeRunner({})   # всё completed
    runs = asyncio.run(run_plan(plan, tmp_path / "b", runner=r, clean_checker=_clean))
    assert r.calls == ["j1", "j2"]
    assert runs["j1"].outcome == OUTCOME_COMPLETED and runs["j2"].outcome == OUTCOME_COMPLETED


def test_d2_transitively_blocks_chain(tmp_path):
    # j1 падает → j2 (req j1) BLOCKED → j3 (req j2) тоже BLOCKED, ни один не запущен
    plan = _plan([_stand("a", "g1", ["p1"])],
                 [_job("j1"), _job("j2", requires=["j1"]), _job("j3", requires=["j2"])], mps=1)
    r = _OutcomeRunner({"j1": OUTCOME_TRANSPORT})
    runs = asyncio.run(run_plan(plan, tmp_path / "b", runner=r, clean_checker=_clean))
    assert r.calls == ["j1"]
    assert runs["j2"].outcome == OUTCOME_BLOCKED and runs["j3"].outcome == OUTCOME_BLOCKED


# =================================================================== D3
def test_d3_worker_exception_still_writes_summary_and_reraises(tmp_path, monkeypatch):
    from memnotsafe.core import plan as plan_mod
    from memnotsafe.core.worker import orchestrate_plan

    doc = {
        "version": 1, "max_parallel_stands": 1, "max_total_target_calls": 20,
        "stands": [{"id": "stand-a", "isolation_group": "g", "slots": 1,
                    "target_profile": {"target": "mock", "principals": ["acct-a"], "clean_check": ["true"]}}],
        "jobs": [{"id": "j1", "scenario": SC, "control": "none", "iterations": 1, "requires": []},
                 {"id": "j2", "scenario": SC, "control": "none", "iterations": 1, "requires": []}],
    }
    plan_path = tmp_path / "plan.yaml"
    plan_path.write_text(yaml.safe_dump(doc), encoding="utf-8")
    out = tmp_path / "runs" / "batch"

    async def _boom(the_plan, output, *, runner, clean_checker, results):
        # частичный прогресс до краха: j1 успел, j2 нет
        results["j1"] = JobRun(job_id="j1", stand_id="stand-a", outcome=OUTCOME_COMPLETED,
                               run_dir=str(Path(output) / "j1"))
        raise RuntimeError("worker exploded mid-batch")

    monkeypatch.setattr(plan_mod, "run_plan", _boom)

    with pytest.raises(RuntimeError, match="exploded"):
        asyncio.run(orchestrate_plan(plan_path, output=out))

    # сводка и состояние ВСЁ РАВНО записаны
    assert (out / "summary.json").exists()
    assert (out / "batch-state.json").exists()
    summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
    by_id = {j["job_id"]: j for j in summary["jobs"]}
    assert by_id["j1"]["outcome"] == OUTCOME_COMPLETED          # частичный прогресс сохранён
    assert by_id["j2"]["outcome"] == OUTCOME_UNKNOWN            # недовыполненное → UNKNOWN
    assert "RuntimeError" in (by_id["j2"]["detail"] or "")      # тип исключения в detail


def test_d3_results_dict_captures_progress(tmp_path):
    # run_plan наполняет переданный объект results (тот же и возвращает)
    plan = _plan([_stand("a", "g1", ["p1"])], [_job("j1")], mps=1)
    r = _OutcomeRunner({})
    bag: dict[str, JobRun] = {}
    returned = asyncio.run(run_plan(plan, tmp_path / "b", runner=r, clean_checker=_clean, results=bag))
    assert returned is bag
    assert bag["j1"].outcome == OUTCOME_COMPLETED


# =================================================================== D4
def test_d4_rebuild_uses_ledger_and_adds_control(tmp_path):
    # атака: 7 вызовов (кейсов 2); контроль: 3 вызова (кейсов 1).
    # старый rebuild отдал бы m=2 и терял контроль. Новый: 7 + 3 = 10.
    a = tmp_path / "j1"
    b = tmp_path / "j1-control"
    _write_campaign(a, attempts=2)
    _write_ledger(a, executed_target_calls=7)
    _write_campaign(b, attempts=1)
    _write_ledger(b, executed_target_calls=3)

    plan = _plan([_stand("s", "g", ["p1"])], [_job("j1", control=SC)], cap=100)
    runs = {"j1": JobRun(job_id="j1", stand_id="s", outcome=OUTCOME_COMPLETED,
                         run_dir=str(a), control_scenario=SC, control_run_dir=str(b),
                         control_outcome=OUTCOME_COMPLETED, target_calls_committed=4)}
    write_batch(plan, tmp_path, runs)

    rebuilt = rebuild_summary(plan, tmp_path)
    summary = json.loads(rebuilt.read_text(encoding="utf-8"))
    job = {j["job_id"]: j for j in summary["jobs"]}["j1"]
    assert job["target_calls"]["actual"] == 10           # атака 7 + контроль 3
    assert job["target_calls"]["estimate"] is False
    assert job["asr"]["m"] == 2                          # знаменатель ASR не смешан с расходом


def test_d4_rebuild_flags_estimate_when_control_ledger_missing(tmp_path):
    a = tmp_path / "j1"
    b = tmp_path / "j1-control"
    _write_campaign(a, attempts=2)
    _write_ledger(a, executed_target_calls=7)        # атака — факт
    _write_campaign(b, attempts=1)                   # контроль без леджера → оценка 1
    plan = _plan([_stand("s", "g", ["p1"])], [_job("j1", control=SC)], cap=100)
    runs = {"j1": JobRun(job_id="j1", stand_id="s", outcome=OUTCOME_COMPLETED,
                         run_dir=str(a), control_scenario=SC, control_run_dir=str(b),
                         control_outcome=OUTCOME_COMPLETED, target_calls_committed=4)}
    write_batch(plan, tmp_path, runs)
    summary = json.loads(rebuild_summary(plan, tmp_path).read_text(encoding="utf-8"))
    job = {j["job_id"]: j for j in summary["jobs"]}["j1"]
    assert job["target_calls"]["actual"] == 8            # 7 (факт) + 1 (оценка контроля)
    assert job["target_calls"]["estimate"] is True       # часть — оценка → флаг


# =================================================================== D6
def test_d6_batch_child_env_injects_stand_attribution():
    from memnotsafe.core.worker import (
        BATCH_PRINCIPALS_ENV,
        BATCH_STAND_ID_ENV,
        batch_child_env,
    )
    stand = _stand("stand-a", "g", ["acct-a", "acct-b"])
    env = batch_child_env({"PATH": "/x", "PYTHONPATH": "/src"}, stand)
    assert env["PATH"] == "/x" and env["PYTHONPATH"] == "/src"     # база сохранена
    assert env[BATCH_STAND_ID_ENV] == "stand-a"
    assert env[BATCH_PRINCIPALS_ENV] == "acct-a,acct-b"


def test_d6_base_env_not_mutated():
    from memnotsafe.core.worker import BATCH_STAND_ID_ENV, batch_child_env
    base = {"PATH": "/x"}
    batch_child_env(base, _stand("s", "g", ["p1"]))
    assert BATCH_STAND_ID_ENV not in base       # исходный env не тронут


def test_d6_summary_records_stand_principals(tmp_path):
    plan = _plan([_stand("s", "g", ["acct-a"])], [_job("j1")])
    runs = {"j1": JobRun(job_id="j1", stand_id="s", outcome=OUTCOME_COMPLETED,
                         stand_principals=("acct-a", "acct-b"), run_dir="runs/x/j1")}
    summary = build_summary(plan, tmp_path, runs)
    assert summary["jobs"][0]["stand_principals"] == ["acct-a", "acct-b"]
    # незапущенное задание — принципалов нет (честный null, не пустой список)
    runs2 = {"j1": JobRun(job_id="j1", stand_id=None, outcome=OUTCOME_BLOCKED)}
    assert build_summary(plan, tmp_path, runs2)["jobs"][0]["stand_principals"] is None


def test_d6_rebuild_preserves_stand_principals(tmp_path):
    plan = _plan([_stand("s", "g", ["acct-a"])], [_job("j1")])
    run_dir = tmp_path / "j1"
    _write_campaign(run_dir, attempts=1)
    runs = {"j1": JobRun(job_id="j1", stand_id="s", outcome=OUTCOME_COMPLETED,
                         stand_principals=("acct-a", "acct-b"), run_dir=str(run_dir))}
    write_batch(plan, tmp_path, runs)
    summary = json.loads(rebuild_summary(plan, tmp_path).read_text(encoding="utf-8"))
    assert summary["jobs"][0]["stand_principals"] == ["acct-a", "acct-b"]


# =================================================================== секреты
def test_hardening_summary_has_no_secrets(tmp_path):
    plan = _plan([_stand("s", "g", ["acct-a"])], [_job("j1", control=SC)])
    runs = {"j1": JobRun(job_id="j1", stand_id="s", outcome=OUTCOME_COMPLETED,
                         stand_principals=("acct-a",), target_calls_actual=9,
                         target_calls_estimate=False, run_dir="runs/x/j1")}
    blob = json.dumps(build_summary(plan, tmp_path, runs)).lower()
    for needle in ("password", "api_key", "secret", "token", "cookie"):
        assert needle not in blob
