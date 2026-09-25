"""tests/test_plan_orchestrator.py — CARD-MULTI-1 (Этап 1, офлайн): планировщик
пакетов проверок (core/plan.py + worker.orchestrate_plan + cli --plan).

Всё офлайн: планировщик тестируется инжектированным управляемым runner'ом (без
подпроцессов), плюс ОДИН интеграционный тест на управляемых локальных процессах
(дочерние mock-кампании) — ни одного живого обращения. Замки офлайн-приёмки:
2 сценария на 2 независимых стендах параллельно ровно по разу; очередь на
освободившийся стенд; общая isolation_group блокирует параллелизм; потолок
вызовов не превышается.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import pytest
import yaml

from memnotsafe.cli import build_parser, cmd_orchestrate
from memnotsafe.core.plan import (
    OUTCOME_AUTH_401,
    OUTCOME_BLOCKED,
    OUTCOME_BUDGET_EXHAUSTED,
    OUTCOME_COMPLETED,
    OUTCOME_INCOMPLETE_FINALIZE,
    OUTCOME_RATE_LIMITED_429,
    OUTCOME_STAND_CLEAN_UNKNOWN,
    OUTCOME_STAND_DIRTY,
    OUTCOME_TRANSPORT,
    OUTCOME_UNKNOWN,
    CleanResult,
    Job,
    JobRun,
    Plan,
    PlanError,
    Stand,
    asr_from_campaign,
    build_summary,
    classify_outcome,
    job_cost,
    load_plan,
    rebuild_summary,
    run_plan,
    validate_plan,
    write_batch,
)
from memnotsafe.core.worker import orchestrate_plan

REPO = Path(__file__).resolve().parents[1]
SC = str(REPO / "scenarios" / "cross_user_bac.yaml")
SC2 = str(REPO / "scenarios" / "direct_poisoning.yaml")


# ------------------------------------------------------------- фабрики модели
def _stand(sid, group, principals, *, slots=1, target="mock", clean_check=("true",)):
    return Stand(id=sid, target=target, principals=tuple(principals),
                 isolation_group=group, slots=slots, clean_check=clean_check)


def _job(jid, *, scenario=SC, control=None, iterations=1, requires=()):
    return Job(id=jid, scenario=scenario, control=control, iterations=iterations, requires=tuple(requires))


def _plan(stands, jobs, *, version=1, mps=2, cap=100):
    return Plan(version=version, max_parallel_stands=mps, max_total_target_calls=cap,
                stands=tuple(stands), jobs=tuple(jobs))


class RecordingRunner:
    """Управляемый инжектируемый runner: считает конкурентность и выдачи, не
    запускает подпроцессов. delay удерживает задание активным, чтобы соседняя
    выдача успела стать одновременной (детерминированно в одном event-loop)."""

    def __init__(self, *, outcome=OUTCOME_COMPLETED, delay=0.03):
        self.active = 0
        self.max_active = 0
        self.calls: list[str] = []
        self.outcome = outcome
        self.delay = delay

    async def __call__(self, job, stand, out):
        self.calls.append(job.id)
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        await asyncio.sleep(self.delay)
        self.active -= 1
        return JobRun(job_id=job.id, stand_id=stand.id, outcome=self.outcome,
                      asr_n=0, asr_m=job.iterations, asr_value=0.0,
                      target_calls_actual=job.iterations, run_dir=str(Path(out) / job.id))


def _clean(_stand):
    return CleanResult(status="clean")


# =============================================================== ВАЛИДАЦИЯ
def test_valid_plan_passes():
    plan = _plan([_stand("a", "g1", ["p1"]), _stand("b", "g2", ["p2"])],
                 [_job("j1"), _job("j2")])
    validate_plan(plan, scenario_exists=lambda s: True)  # не бросает


# FIX-PACK-2 D5: изоляция по принципалам — не ошибка. isolation_group маркирует
# ОБЩИЙ РЕСУРС (одна Mongo → одна группа → сериализация), а не независимость.
# Две прежние PlanError-проверки заменены: общая группа при разных принципалах
# теперь легальна, пересечение принципалов у разных групп — предупреждение
# сводки (было: два `test_stop_*`, ждавших PlanError).
def test_shared_isolation_group_with_independent_principals_is_legal():
    # прежде: PlanError «делят isolation_group». Теперь — легальный план
    # (общий ресурс, планировщик его сериализует), без предупреждений.
    plan = _plan([_stand("a", "shared", ["p1"]), _stand("b", "shared", ["p2"])], [_job("j1")])
    validate_plan(plan, scenario_exists=lambda s: True)          # не бросает
    assert build_summary(plan, "runs/d5-shared", {})["warnings"] == []


def test_cross_group_principal_overlap_is_warning_not_error():
    # прежде: PlanError «принципалы пересекаются». Теперь — легально (две
    # независимые копии стенда с одними принципалами), но помечено в сводке.
    plan = _plan([_stand("a", "g1", ["shared"]), _stand("b", "g2", ["shared"])], [_job("j1")])
    validate_plan(plan, scenario_exists=lambda s: True)          # не бросает
    warnings = build_summary(plan, "runs/d5-cross", {})["warnings"]
    assert any("shared" in w and "разных isolation_group" in w for w in warnings), warnings


def test_stop_unknown_scenario():
    plan = _plan([_stand("a", "g1", ["p1"])], [_job("j1", scenario="scenarios/NOPE.yaml")])
    with pytest.raises(PlanError, match="неизвестный сценарий"):
        validate_plan(plan)  # дефолтная проверка существования файла


def test_stop_unknown_control_scenario():
    plan = _plan([_stand("a", "g1", ["p1"])], [_job("j1", control="scenarios/NOPE.yaml")])
    with pytest.raises(PlanError, match="неизвестный контрольный сценарий"):
        validate_plan(plan, scenario_exists=lambda s: s != "scenarios/NOPE.yaml")


def test_stop_unknown_requires():
    plan = _plan([_stand("a", "g1", ["p1"])], [_job("j1", requires=["ghost"])])
    with pytest.raises(PlanError, match="неизвестное задание"):
        validate_plan(plan, scenario_exists=lambda s: True)


def test_stop_requires_cycle():
    plan = _plan([_stand("a", "g1", ["p1"])],
                 [_job("j1", requires=["j2"]), _job("j2", requires=["j1"])])
    with pytest.raises(PlanError, match="цикл зависимостей"):
        validate_plan(plan, scenario_exists=lambda s: True)


@pytest.mark.parametrize("needle", ["version", "stands", "jobs"])
def test_stop_empty_required_fields(needle):
    base_stands = (_stand("a", "g1", ["p1"]),)
    base_jobs = (_job("j1"),)
    if needle == "version":
        plan = _plan(base_stands, base_jobs, version=0)
    elif needle == "stands":
        plan = _plan((), base_jobs)
    else:
        plan = _plan(base_stands, ())
    with pytest.raises(PlanError, match=needle):
        validate_plan(plan, scenario_exists=lambda s: True)


def test_stop_empty_principals_and_bad_iterations_and_slots():
    with pytest.raises(PlanError, match="principals"):
        validate_plan(_plan([_stand("a", "g1", [])], [_job("j1")]), scenario_exists=lambda s: True)
    with pytest.raises(PlanError, match="iterations"):
        validate_plan(_plan([_stand("a", "g1", ["p1"])], [_job("j1", iterations=0)]), scenario_exists=lambda s: True)
    with pytest.raises(PlanError, match="slots"):
        validate_plan(_plan([_stand("a", "g1", ["p1"], slots=0)], [_job("j1")]), scenario_exists=lambda s: True)


def test_stop_duplicate_ids():
    with pytest.raises(PlanError, match="дублирующийся стенд"):
        validate_plan(_plan([_stand("a", "g1", ["p1"]), _stand("a", "g2", ["p2"])], [_job("j1")]),
                      scenario_exists=lambda s: True)
    with pytest.raises(PlanError, match="дублирующийся job"):
        validate_plan(_plan([_stand("a", "g1", ["p1"])], [_job("j1"), _job("j1")]),
                      scenario_exists=lambda s: True)


def test_load_plan_roundtrip(tmp_path):
    doc = {
        "version": 1, "max_parallel_stands": 2, "max_total_target_calls": 10,
        "stands": [{"id": "a", "target_profile": {"target": "mock", "principals": ["p1"],
                                                   "clean_check": ["true"]}, "isolation_group": "g1", "slots": 1}],
        "jobs": [{"id": "j1", "scenario": SC, "control": "none", "iterations": 2, "requires": []}],
    }
    p = tmp_path / "plan.yaml"
    p.write_text(yaml.safe_dump(doc), encoding="utf-8")
    plan = load_plan(p)
    assert plan.version == 1 and plan.max_parallel_stands == 2
    assert plan.stands[0].principals == ("p1",) and plan.stands[0].clean_check == ("true",)
    assert plan.jobs[0].control is None and plan.jobs[0].iterations == 2
    validate_plan(plan)  # SC существует


# =============================================================== ПЛАНИРОВЩИК
def test_two_independent_stands_run_in_parallel_once_each():
    plan = _plan([_stand("a", "g1", ["p1"]), _stand("b", "g2", ["p2"])],
                 [_job("j1"), _job("j2")], mps=2)
    r = RecordingRunner()
    runs = asyncio.run(run_plan(plan, "/tmp/x-batch-parallel", runner=r, clean_checker=_clean))
    assert r.max_active == 2                    # шли параллельно
    assert sorted(r.calls) == ["j1", "j2"]       # каждое ровно по разу
    assert runs["j1"].outcome == OUTCOME_COMPLETED and runs["j2"].outcome == OUTCOME_COMPLETED


def test_shared_isolation_group_blocks_parallelism():
    plan = _plan([_stand("a", "shared", ["p1"]), _stand("b", "shared", ["p1"])],
                 [_job("j1"), _job("j2")], mps=2)
    r = RecordingRunner()
    runs = asyncio.run(run_plan(plan, "/tmp/x-batch-serial", runner=r, clean_checker=_clean))
    assert r.max_active == 1                    # общая группа блокирует параллелизм
    assert sorted(r.calls) == ["j1", "j2"]       # оба всё равно выполнились по разу


def test_queue_onto_freed_stand():
    plan = _plan([_stand("a", "g1", ["p1"])], [_job("j1"), _job("j2"), _job("j3")], mps=2)
    r = RecordingRunner()
    runs = asyncio.run(run_plan(plan, "/tmp/x-batch-queue", runner=r, clean_checker=_clean))
    assert r.max_active == 1                     # один стенд — по одному
    assert r.calls == ["j1", "j2", "j3"]          # очередь на освободившийся стенд, порядок сохранён
    assert all(runs[j].outcome == OUTCOME_COMPLETED for j in ("j1", "j2", "j3"))


def test_budget_cap_not_exceeded():
    plan = _plan([_stand("a", "g1", ["p1"]), _stand("b", "g2", ["p2"])],
                 [_job("j1", iterations=1), _job("j2", iterations=1)], mps=2, cap=1)
    r = RecordingRunner()
    runs = asyncio.run(run_plan(plan, "/tmp/x-batch-cap", runner=r, clean_checker=_clean))
    completed = [j for j, run in runs.items() if run.outcome == OUTCOME_COMPLETED]
    exhausted = [j for j, run in runs.items() if run.outcome == OUTCOME_BUDGET_EXHAUSTED]
    assert len(completed) == 1 and len(exhausted) == 1     # потолок 1 → одно выполнено, одно срезано
    assert len(r.calls) == 1                                # срезанное НЕ запускалось (никаких скрытых повторов)
    summary = build_summary(plan, "/tmp/x-batch-cap", runs)
    assert summary["caps"]["committed_target_calls"] <= plan.max_total_target_calls


def test_requires_gates_dispatch():
    plan = _plan([_stand("a", "g1", ["p1"])], [_job("j2", requires=["j1"]), _job("j1")], mps=2)
    r = RecordingRunner()
    asyncio.run(run_plan(plan, "/tmp/x-batch-req", runner=r, clean_checker=_clean))
    assert r.calls == ["j1", "j2"]     # j1 раньше j2, несмотря на порядок в плане


def test_job_dispatched_exactly_once():
    plan = _plan([_stand("a", "g1", ["p1"]), _stand("b", "g2", ["p2"])],
                 [_job("j1", iterations=3), _job("j2", iterations=2)], mps=2)
    r = RecordingRunner()
    asyncio.run(run_plan(plan, "/tmp/x-batch-once", runner=r, clean_checker=_clean))
    assert r.calls.count("j1") == 1 and r.calls.count("j2") == 1  # повторы — только через iterations


def test_dirty_stand_not_dispatched():
    plan = _plan([_stand("a", "g1", ["p1"])], [_job("j1")], mps=1)
    r = RecordingRunner()
    runs = asyncio.run(run_plan(plan, "/tmp/x-batch-dirty", runner=r,
                                clean_checker=lambda s: CleanResult(status="dirty")))
    assert r.calls == []                                  # грязный стенд — не выдаём
    assert runs["j1"].outcome == OUTCOME_STAND_DIRTY


def test_unknown_cleanliness_not_dispatched():
    plan = _plan([_stand("a", "g1", ["p1"], clean_check=None)], [_job("j1")], mps=1)
    r = RecordingRunner()
    runs = asyncio.run(run_plan(plan, "/tmp/x-batch-unk", runner=r,
                                clean_checker=lambda s: CleanResult(status="unknown")))
    assert r.calls == []
    assert runs["j1"].outcome == OUTCOME_STAND_CLEAN_UNKNOWN


def test_no_hidden_retry_on_bad_outcome():
    plan = _plan([_stand("a", "g1", ["p1"])], [_job("j1")], mps=1)
    r = RecordingRunner(outcome=OUTCOME_RATE_LIMITED_429)
    runs = asyncio.run(run_plan(plan, "/tmp/x-batch-noretry", runner=r, clean_checker=_clean))
    assert r.calls == ["j1"]                    # ровно один запуск, никакого повтора на 429
    assert runs["j1"].outcome == OUTCOME_RATE_LIMITED_429


# =============================================================== ИСХОДЫ (pure)
def test_classify_outcome_taxonomy():
    camp = {"aggregate_metrics": {"successful": 0, "attempts": 1}, "attempts": 1}
    assert classify_outcome(0, camp, "") == OUTCOME_COMPLETED
    assert classify_outcome(1, None, "HTTP 401 Unauthorized") == OUTCOME_AUTH_401
    assert classify_outcome(1, None, "got 429 rate limit") == OUTCOME_RATE_LIMITED_429
    assert classify_outcome(1, None, "connection timeout") == OUTCOME_TRANSPORT
    assert classify_outcome(0, None, "") == OUTCOME_INCOMPLETE_FINALIZE
    assert classify_outcome(1, None, "weird failure") == OUTCOME_UNKNOWN


def test_asr_unknown_is_none_not_zero():
    # пустой прогон: end_to_end_asr = None (UNKNOWN), не 0.0
    n, m, value = asr_from_campaign({"aggregate_metrics": {"successful": 0, "attempts": 0, "end_to_end_asr": None}})
    assert value is None
    assert job_cost(_job("j", iterations=2, control=SC)) == 4  # атака + контроль


# =============================================================== СВОДКА
def test_summary_shape_and_no_secrets():
    plan = _plan([_stand("a", "g1", ["p1"])], [_job("j1")], mps=1)
    runs = {"j1": JobRun(job_id="j1", stand_id="a", outcome=OUTCOME_COMPLETED,
                         experiment_id="exp-abc", asr_n=1, asr_m=2, asr_value=0.5,
                         target_calls_committed=1, target_calls_actual=2, run_dir="runs/b/j1")}
    s = build_summary(plan, "runs/mybatch", runs)
    assert s["batch_id"] == "mybatch"
    assert s["jobs"][0]["experiment_id"] == "exp-abc"
    assert s["jobs"][0]["asr"] == {"n": 1, "m": 2, "value": 0.5}
    assert s["caps"]["committed_target_calls"] == 1
    # UNKNOWN ≠ False: незапущенное задание даёт value=None, не 0
    runs2 = {"j1": JobRun(job_id="j1", stand_id=None, outcome=OUTCOME_BLOCKED)}
    assert build_summary(plan, "runs/b2", runs2)["jobs"][0]["asr"]["value"] is None
    assert "password" not in json.dumps(s).lower() and "api_key" not in json.dumps(s).lower()


# =========================================== ИНТЕГРАЦИЯ (локальные процессы)
def test_orchestrate_plan_integration_two_stands_offline(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    clean_ok = [sys.executable, "-c", "import sys; sys.exit(0)"]
    doc = {
        "version": 1, "max_parallel_stands": 2, "max_total_target_calls": 20,
        "stands": [
            {"id": "stand-a", "isolation_group": "grp-a", "slots": 1,
             "target_profile": {"target": "mock", "principals": ["acct-a"], "clean_check": clean_ok}},
            {"id": "stand-b", "isolation_group": "grp-b", "slots": 1,
             "target_profile": {"target": "mock", "principals": ["acct-b"], "clean_check": clean_ok}},
        ],
        "jobs": [
            {"id": "job-bac", "scenario": SC, "control": "none", "iterations": 1, "requires": []},
            {"id": "job-dp", "scenario": SC2, "control": "none", "iterations": 1, "requires": []},
        ],
    }
    plan_path = tmp_path / "plan.yaml"
    plan_path.write_text(yaml.safe_dump(doc), encoding="utf-8")
    out = tmp_path / "runs" / "batch1"

    summary_path, rc = asyncio.run(orchestrate_plan(plan_path, output=out))
    assert rc == 0
    assert summary_path == out / "summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    assert summary["batch_id"] == "batch1"
    outcomes = {j["job_id"]: j for j in summary["jobs"]}
    assert outcomes["job-bac"]["outcome"] == OUTCOME_COMPLETED
    assert outcomes["job-dp"]["outcome"] == OUTCOME_COMPLETED
    # каждое задание — свой каталог с реальными артефактами и experiment_id
    stand_principals = {"stand-a": ["acct-a"], "stand-b": ["acct-b"]}
    for jid in ("job-bac", "job-dp"):
        assert (out / jid / "campaign.json").exists()
        assert (out / jid / "experiment.json").exists()
        assert outcomes[jid]["experiment_id"]
        assert outcomes[jid]["asr"]["m"] == 1        # N of M
        # FIX-PACK-2 D1: расход — ФАКТ из budget-ledger.jsonl (не знаменатель ASR);
        # mock пишет 1 executed target_call на попытку → actual=1, estimate=False.
        assert (out / jid / "budget-ledger.jsonl").exists()
        assert outcomes[jid]["target_calls"]["actual"] == 1
        assert outcomes[jid]["target_calls"]["estimate"] is False
        # FIX-PACK-2 D6: принципалы стенда прогона записаны в сводку (record-only)
        assert outcomes[jid]["stand_principals"] == stand_principals[outcomes[jid]["stand"]]
    assert summary["caps"]["committed_target_calls"] <= doc["max_total_target_calls"]

    # пересборка сводки НЕ перезапускает задания: удалить summary, зафиксировать
    # mtime дочернего campaign.json, пересобрать, убедиться, что артефакт не тронут
    camp = out / "job-bac" / "campaign.json"
    before = camp.stat().st_mtime_ns
    summary_path.unlink()
    plan = load_plan(plan_path)
    rebuilt = rebuild_summary(plan, out)
    assert rebuilt.exists()
    assert camp.stat().st_mtime_ns == before        # дочерний прогон не перезапущен
    resummary = json.loads(rebuilt.read_text(encoding="utf-8"))
    assert {j["job_id"] for j in resummary["jobs"]} == {"job-bac", "job-dp"}
    assert all(j["experiment_id"] for j in resummary["jobs"])


# =========================================== СТАРЫЙ ПУТЬ orchestrate --scenario
def test_orchestrate_scenario_path_unchanged_and_arg_parsing():
    parser = build_parser()
    # старый вызов по-прежнему валиден и НЕ включает режим плана
    args = parser.parse_args(["orchestrate", "--scenario", SC, "--output", "runs/o"])
    assert args.plan is None and args.scenario == SC
    # режим плана распознаётся
    pargs = parser.parse_args(["orchestrate", "--plan", "plan.yaml", "--output", "runs/b"])
    assert pargs.plan == "plan.yaml"


def test_orchestrate_requires_plan_or_scenario():
    import argparse
    args = argparse.Namespace(plan=None, scenario=None, output="runs/x",
                              workers=2, iterations=None, json=False, quiet=True, no_color=True)
    assert cmd_orchestrate(args) == 1     # ни --plan, ни --scenario → управляемый отказ
