"""tests/test_ledger_recon.py — P13-c: сверка budget-ledger N run-каталогов.

Пять сверок карточки §2.1 (норматив — текст карточки, не G3-SPEC):
(1) фазы по словарю операций; (2) биекция attempts<->target_call для
attempt_no>=1 с легитимными исключениями (attempt_no==0-строки, evidence_error
как вторая строка попытки); (3) повтор операции не создаёт второй записи;
(4) сходимость summary с бюджетами (источники разведены: судья — JudgeBudget,
attacker — campaign.json.attacker.calls_used по planned-записям);
(5) суммарный расход <= суммарных бюджетов воркеров.

Фикстуры — реальные offline mock-прогоны Campaign (чистая пара, эскалация со
стабом, судья со стабом, транспортный сбой) + рукодельные аномалии поверх
копий. Каждая аномалия ловится ИМЕННО своей сверкой (замки по кодам находок),
unknown («attacker неактивен», «сводка не завершена», «campaign.json
отсутствует») расхождением НЕ является.
"""

from __future__ import annotations

import asyncio
import json
import shutil
from pathlib import Path

import pytest

from memnotsafe.adapters.mock import MockTarget
from memnotsafe.core.campaign import Campaign
from memnotsafe.core.config import ActorConfig, JudgeSpec, Scenario, TargetSpec
from memnotsafe.core.ledger import OP_TARGET_CALL, PHASE_EXECUTED, read_ledger
from memnotsafe.reporting.ledger_recon import main, reconcile, render_text


# --------------------------------------------------------------------- фикстуры


def _scenario(tmp_path: Path, *, corpus=None, family="cross_user_bac", judged=False) -> Scenario:
    return Scenario(
        id=family, path=tmp_path / "s.yaml",
        target=TargetSpec(adapter="mock"),
        attacker=ActorConfig(user_id="1001"), victim=ActorConfig(user_id="1002"),
        attack_family=family, repetitions=1, corpus_path=corpus,
        judge=JudgeSpec(enabled=judged, model="stub-judge") if judged else JudgeSpec(),
    )


def _offline_run(tmp_path: Path, name: str) -> Path:
    """Чистый offline mock-прогон: target_call/executed + registered/completed_*."""
    out = tmp_path / name
    asyncio.run(Campaign(_scenario(tmp_path), MockTarget(vulnerable=True), out).run())
    return out


def _online_run(tmp_path: Path, name: str) -> Path:
    """Эскалационный прогон на стабе атакующей LLM: attacker_llm planned +
    executed пары, rewrite_accepted в истории (отрицательная пара карточки —
    наивная биекция здесь обязана дать ноль дефектов)."""
    from memnotsafe.generation.config import AttackerConfig
    from memnotsafe.generation.offline import escalation_stub_script

    scenario = _scenario(tmp_path, corpus=Path("corpora/escalation-seed.yaml"), family="generated")
    cfg = AttackerConfig(
        provider="stub", scripted=[escalation_stub_script() for _ in range(4)], budget=10
    )
    out = tmp_path / name
    asyncio.run(
        Campaign(scenario, MockTarget(vulnerable=True), out,
                 attacker_config=cfg, online=True, online_attempts=4).run()
    )
    return out


def _judged_run(tmp_path: Path, name: str) -> Path:
    """Прогон со судьёй на стабе: judge_llm summary-запись + активный блок
    judge в campaign.json (сверка 4 по JudgeBudget)."""
    from memnotsafe.judge.runtime import LLMJudge
    from tests.test_judge_offline_regression import StubClient

    scenario = _scenario(tmp_path, judged=True)
    out = tmp_path / name
    judge = LLMJudge(scenario.judge, client=StubClient(), repetitions=1, artifacts_dir=out / "judge")
    asyncio.run(Campaign(scenario, MockTarget(vulnerable=True), out, judge=judge).run())
    return out


# ------------------------------------------------------------- рукодельные правки


def _entry(op: str, phase: str, *, case=None, cand=None, attempt: int = 1,
           usage=None, error=None, retry_of=None, note=None, run_id="RUN") -> dict:
    return {
        "schema_version": 1, "experiment_id": None, "run_id": run_id,
        "operation": op, "phase": phase,
        "case_id": case, "candidate_id": cand, "attempt_no": attempt,
        "usage": usage, "error": error, "retry_of": retry_of, "note": note,
    }


def _append_ledger(run_dir: Path, *entries: dict) -> None:
    with (run_dir / "budget-ledger.jsonl").open("a", encoding="utf-8") as f:
        for e in entries:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")


def _ledger_dicts(run_dir: Path) -> list[dict]:
    return [json.loads(l) for l in
            (run_dir / "budget-ledger.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]


def _rewrite_ledger(run_dir: Path, lines: list[dict]) -> None:
    (run_dir / "budget-ledger.jsonl").write_text(
        "".join(json.dumps(l, ensure_ascii=False) + "\n" for l in lines), encoding="utf-8")


def _append_attempts(run_dir: Path, *rows: dict) -> None:
    with (run_dir / "attempts.jsonl").open("a", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


def _attempt_row(run_dir: Path, **override) -> dict:
    """Строка истории той же формы, что пишет раннер (все поля AttemptRecord)."""
    base = next(iter(_attempt_rows(run_dir)))  # реальный case_id прогона
    row = {
        "schema_version": 1, "experiment_id": base.get("experiment_id"),
        "run_id": base.get("run_id"), "case_id": base["case_id"],
        "candidate_id": base["case_id"], "parent_candidate_id": None,
        "attempt_no": 1, "transport_retry": 0, "case_marker": None,
        "goal_digest": None, "seed": None, "session_ids": {},
        "outcome": "evidence_error", "error": None,
    }
    row.update(override)
    return row


def _attempt_rows(run_dir: Path) -> list[dict]:
    return [json.loads(l) for l in
            (run_dir / "attempts.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]


def _patch_campaign(run_dir: Path, mutate) -> None:
    path = run_dir / "campaign.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    mutate(data)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def _codes(report: dict, check: str) -> list[str]:
    return [f["code"] for run in report["runs"]
            for f in run["checks"].get(check, {}).get("findings", [])]


def _mk_judge_dir(tmp_path: Path, name: str, *, used: int, limit: int) -> Path:
    """Рукодельный run-каталог с ВНУТРЕННЕ СОГЛАСОВАННЫМ судейским расходом
    (summary == metadata.judge) — для изолированной проверки сверски 5."""
    run_dir = tmp_path / name
    run_dir.mkdir()
    (run_dir / "budget-ledger.jsonl").write_text(
        json.dumps(_entry("judge_llm", "executed", usage={"calls_used": used, "calls_limit": limit},
                          note="summary"), ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    (run_dir / "attempts.jsonl").write_text("", encoding="utf-8")
    (run_dir / "campaign.json").write_text(json.dumps({
        "run_id": name, "metadata": {"judge": {
            "active": True, "calls_used": used, "calls_limit": limit,
        }},
    }, ensure_ascii=False), encoding="utf-8")
    return run_dir


def _unknown_signals(report: dict) -> list[str]:
    return [u["signal"] for u in report["summary"]["unknowns"]]


# ------------------------------------------------------------------ 1. чистые прогоны


def test_clean_pair_zero_discrepancies(tmp_path) -> None:
    """Чистая пара offline-прогонов: расхождений 0; attacker неактивен —
    честный unknown, НЕ расхождение (карточка §2.1 п.4)."""
    a = _offline_run(tmp_path, "run-a")
    b = _offline_run(tmp_path, "run-b")
    report = reconcile([a, b])
    assert report["summary"]["discrepancies"] == 0
    for run in report["runs"]:
        for name, chk in run["checks"].items():
            assert chk["findings"] == [], (name, chk)
    assert any("attacker неактивен" in s for s in _unknown_signals(report))
    assert main([str(a), str(b)]) == 0


def test_escalation_run_no_false_positives(tmp_path) -> None:
    """Прогон с эскалацией (rewrite_accepted + planned/executed пары + вторые
    target_call той же пары) — наивная биекция НЕ даёт ложных дефектов;
    attacker активен: planned == campaign.json.calls_used (сверка 4 ok)."""
    out = _online_run(tmp_path, "run-online")
    rows = _attempt_rows(out)
    assert any(r["outcome"] == "rewrite_accepted" for r in rows)  # прогон действительно эскалационный
    entries = read_ledger(out / "budget-ledger.jsonl")
    assert any(e.operation == "attacker_llm" and e.phase == "planned" for e in entries)
    report = reconcile([out])
    assert report["summary"]["discrepancies"] == 0
    budgets = report["runs"][0]["checks"]["budgets"]
    assert budgets["attacker"]["status"] == "ok"
    assert budgets["judge"]["status"] == "ok"


def test_judged_run_summary_matches_budget(tmp_path) -> None:
    """Судейский прогон: summary-запись сходится с JudgeBudget-блоком
    campaign.json — сверка 4 ok, суммарный расход в пределах лимита."""
    out = _judged_run(tmp_path, "run-judged")
    report = reconcile([out])
    assert report["summary"]["discrepancies"] == 0
    assert report["runs"][0]["checks"]["budgets"]["judge"]["status"] == "ok"
    assert report["totals"]["judge"]["status"] == "ok"


def test_transport_error_run_bijection_clean(tmp_path, monkeypatch) -> None:
    """Транспортный сбой target: unknown_outcome в леджере + transport_error в
    истории — биекция чиста; campaign.json не дописан — честный unknown, не
    расхождение."""
    from memnotsafe.core.runner import RunnerError

    async def broken_run_attack(*args, **kwargs):
        raise RunnerError("таймаут стенда")

    monkeypatch.setattr("memnotsafe.core.campaign.run_attack", broken_run_attack)
    out = tmp_path / "run-transport"
    with pytest.raises(RunnerError):
        asyncio.run(Campaign(_scenario(tmp_path), MockTarget(vulnerable=True), out).run())
    report = reconcile([out])
    assert report["summary"]["discrepancies"] == 0
    assert report["runs"][0]["checks"]["bijection"]["findings"] == []
    assert any("campaign.json" in s for s in _unknown_signals(report))


# ------------------------------------------------------------------ 2. аномалии: каждой — своя сверка


def test_duplicate_target_call_caught_by_duplicates_check(tmp_path) -> None:
    """Дубль target_call (повтор операции создал вторую запись) — сверка 3;
    биекция и фазы при этом чисты."""
    src = _offline_run(tmp_path, "run-src")
    dst = tmp_path / "run-dup"
    shutil.copytree(src, dst)
    tc = next(e for e in read_ledger(dst / "budget-ledger.jsonl")
              if e.operation == OP_TARGET_CALL)
    _append_ledger(dst, _entry(OP_TARGET_CALL, PHASE_EXECUTED,
                               case=tc.case_id, cand=tc.candidate_id, attempt=tc.attempt_no))
    report = reconcile([dst])
    assert _codes(report, "duplicates") == ["duplicate_target_call"]
    assert _codes(report, "bijection") == []
    assert _codes(report, "phases") == []
    assert report["summary"]["discrepancies"] >= 1
    assert main([str(dst)]) == 1


def test_attempt_without_target_call(tmp_path) -> None:
    """Потеря списания: терминальная строка истории без target_call-записи —
    сверка 2, только она."""
    src = _offline_run(tmp_path, "run-src")
    dst = tmp_path / "run-lost"
    shutil.copytree(src, dst)
    _rewrite_ledger(dst, [l for l in _ledger_dicts(dst) if l["operation"] != OP_TARGET_CALL])
    report = reconcile([dst])
    assert _codes(report, "bijection") == ["attempt_without_target_call"]
    assert _codes(report, "duplicates") == []
    assert _codes(report, "phases") == []


def test_target_call_without_attempt(tmp_path) -> None:
    """Запись без попытки: target_call для ключа, которого нет в истории —
    сверка 2."""
    src = _offline_run(tmp_path, "run-src")
    dst = tmp_path / "run-ghost"
    shutil.copytree(src, dst)
    _append_ledger(dst, _entry(OP_TARGET_CALL, PHASE_EXECUTED,
                               case="case-ghost", cand="case-ghost", attempt=1))
    report = reconcile([dst])
    assert "target_call_without_attempt" in _codes(report, "bijection")
    assert _codes(report, "duplicates") == []


def test_phase_and_operation_out_of_vocabulary(tmp_path) -> None:
    """Фаза/операция вне словаря (target_call/planned, чужая операция) —
    сверка 1; дублей при этом нет."""
    src = _offline_run(tmp_path, "run-src")
    dst = tmp_path / "run-vocab"
    shutil.copytree(src, dst)
    _append_ledger(
        dst,
        _entry(OP_TARGET_CALL, "planned", case="case-x", cand="case-x", attempt=1),
        _entry("vendor_llm", "executed"),
    )
    report = reconcile([dst])
    codes = _codes(report, "phases")
    assert "phase_out_of_vocabulary" in codes
    assert "operation_out_of_vocabulary" in codes
    assert _codes(report, "duplicates") == []


def test_budgets_mismatch_caught_by_budgets_check(tmp_path) -> None:
    """Summary-расхождение судьи (ledger != JudgeBudget-блок) и расхождение
    attacker (calls_used != числу planned) — сверка 4, только она."""
    judged = _judged_run(tmp_path, "run-judged")
    lines = _ledger_dicts(judged)
    for l in lines:
        if l["operation"] == "judge_llm":
            l["usage"]["calls_used"] += 1
    _rewrite_ledger(judged, lines)
    report = reconcile([judged])
    assert _codes(report, "budgets") == ["judge_summary_mismatch"]
    assert _codes(report, "bijection") == []
    assert _codes(report, "duplicates") == []

    online = _online_run(tmp_path, "run-online")

    def bump(data: dict) -> None:
        data["metadata"]["attacker"]["calls_used"] += 1

    _patch_campaign(online, bump)
    report2 = reconcile([online])
    assert _codes(report2, "budgets") == ["attacker_calls_mismatch"]
    assert _codes(report2, "totals") == []


def test_overspend_caught_by_totals_check(tmp_path) -> None:
    """Перерасход — сверка 5: attacker budget_limit опущен ниже факта (per-run
    сверки чисты — check 4 смотрит на calls_used, не на лимит); судейский
    перерасход — два внутренне согласованных рукодельных каталога."""
    online = _online_run(tmp_path, "run-online")
    planned = sum(1 for l in _ledger_dicts(online)
                  if l["operation"] == "attacker_llm" and l["phase"] == "planned")
    assert planned >= 1

    def drop_limit(data: dict) -> None:
        data["metadata"]["attacker"]["budget_limit"] = planned - 1

    _patch_campaign(online, drop_limit)
    report = reconcile([online])
    findings = report["totals"]["attacker"]["findings"]
    assert [f["code"] for f in findings] == ["attacker_overspend"]
    assert all(run["checks"]["budgets"]["findings"] == [] for run in report["runs"])

    d1 = _mk_judge_dir(tmp_path, "run-j1", used=2, limit=1)
    d2 = _mk_judge_dir(tmp_path, "run-j2", used=2, limit=1)
    report2 = reconcile([d1, d2])
    assert [f["code"] for f in report2["totals"]["judge"]["findings"]] == ["judge_overspend"]
    assert all(run["checks"]["budgets"]["findings"] == [] for run in report2["runs"])


def test_killed_before_summary_is_unknown_not_mismatch(tmp_path) -> None:
    """Воркер убит до summary: судья активен, summary-записи нет — честный
    unknown «сводка не завершена», расхождением НЕ является (exit 0)."""
    src = _judged_run(tmp_path, "run-src")
    dst = tmp_path / "run-killed"
    shutil.copytree(src, dst)
    _rewrite_ledger(dst, [l for l in _ledger_dicts(dst) if l["operation"] != "judge_llm"])
    report = reconcile([dst])
    assert report["summary"]["discrepancies"] == 0
    assert any("сводка не завершена" in s for s in _unknown_signals(report))
    assert main([str(dst)]) == 0


# ------------------------------------------------------- 3. легитимные формы строк


def test_attempt_no_zero_rows_stay_out_of_bijection(tmp_path) -> None:
    """Шесть видов строк attempt_no==0 не участвуют в биекции; target_call на
    нулевой попытке — дефект биекции."""
    src = _offline_run(tmp_path, "run-src")
    dst = tmp_path / "run-zero"
    shutil.copytree(src, dst)
    case = _attempt_rows(dst)[0]["case_id"]
    _append_attempts(
        dst,
        _attempt_row(dst, outcome="budget_exhausted", attempt_no=0),
        _attempt_row(dst, outcome="rewrite_rejected", attempt_no=0),
        _attempt_row(dst, outcome="aborted", attempt_no=0, error="сбой атакующей LLM"),
    )
    assert reconcile([dst])["summary"]["discrepancies"] == 0
    _append_ledger(dst, _entry(OP_TARGET_CALL, PHASE_EXECUTED, case=case, cand=case, attempt=0))
    report = reconcile([dst])
    assert "target_call_attempt_no_zero" in _codes(report, "bijection")


def test_evidence_error_is_legit_second_line(tmp_path) -> None:
    """evidence_error — легитимная ВТОРАЯ строка той же попытки: биекция
    чиста (наивный подсчет строк дал бы ложный дефект)."""
    src = _offline_run(tmp_path, "run-src")
    dst = tmp_path / "run-evidence"
    shutil.copytree(src, dst)
    _append_attempts(dst, _attempt_row(dst, error="пакет доказательств не записан: OSError"))
    report = reconcile([dst])
    assert report["summary"]["discrepancies"] == 0
    assert report["runs"][0]["checks"]["bijection"]["findings"] == []


def test_retry_must_not_create_second_record(tmp_path) -> None:
    """Рукодельный retry (retry_of на второй planned того же ключа) — дубль
    списания, сверка 3; сегодня ни один продюсер в src/ retry_of не пишет,
    поэтому только рукодельная фикстура (оговорка карточки §2.1 п.3)."""
    src = _online_run(tmp_path, "run-src")
    dst = tmp_path / "run-retry"
    shutil.copytree(src, dst)
    planned = next(l for l in _ledger_dicts(dst)
                   if l["operation"] == "attacker_llm" and l["phase"] == "planned")
    _append_ledger(dst, _entry("attacker_llm", "planned",
                               case=planned["case_id"], cand=planned["candidate_id"],
                               attempt=planned["attempt_no"], retry_of="attacker-op-1"))
    report = reconcile([dst])
    assert _codes(report, "duplicates") == ["duplicate_attacker_planned"]
    assert _codes(report, "bijection") == []


# ------------------------------------------------------------------------- 4. CLI


def test_cli_output_exit_codes_and_ledger_error(tmp_path, capsys) -> None:
    """python -m ... <dirs>: 0 — расхождений нет, 1 — есть; LedgerError —
    сообщение с именем run-каталога, без трейсбека; --output пишет JSON."""
    clean = _offline_run(tmp_path, "run-clean")
    assert main([str(clean), "--output", str(tmp_path / "recon.json")]) == 0
    saved = json.loads((tmp_path / "recon.json").read_text(encoding="utf-8"))
    assert saved["summary"]["discrepancies"] == 0
    capsys.readouterr()

    corrupt = tmp_path / "run-corrupt"
    shutil.copytree(clean, corrupt)
    with (corrupt / "budget-ledger.jsonl").open("a", encoding="utf-8") as f:
        f.write("не-json{\n")
    assert main([str(corrupt)]) == 1
    out = capsys.readouterr().out
    assert str(corrupt) in out
    assert "Traceback" not in out

    assert main([str(tmp_path / "no-such-dir")]) == 1
    assert "не существует" in capsys.readouterr().out


def test_render_text_human_table(tmp_path, capsys) -> None:
    """Человекочитаемая печать: заголовки сверок + итог расхождений + находки."""
    clean = _offline_run(tmp_path, "run-clean")
    dst = tmp_path / "run-dup"
    shutil.copytree(clean, dst)
    tc = next(e for e in read_ledger(dst / "budget-ledger.jsonl")
              if e.operation == OP_TARGET_CALL)
    _append_ledger(dst, _entry(OP_TARGET_CALL, PHASE_EXECUTED,
                               case=tc.case_id, cand=tc.candidate_id, attempt=tc.attempt_no))
    assert main([str(dst)]) == 1
    text = capsys.readouterr().out
    assert "Биекция" in text and "Повторы" in text and "Расхождений" in text
    assert "duplicate_target_call" in text
    report = reconcile([dst])
    assert "duplicate_target_call" in render_text(report)
