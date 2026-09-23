"""src/memnotsafe/reporting/ledger_recon.py — P13-c: сверка budget-ledger
N run-каталогов (ledger recon, G3.3).

Read-only сверщик (паттерн B4 stage_map): читает `budget-ledger.jsonl` +
`attempts.jsonl` + `campaign.json` каждого run-каталога и выполняет пять
сверок (норматив — CARD-P13-c §2.1; G3-SPEC в main отсутствует, его текст
расходится с кодом в двух местах):

1. **Фазы** — фаза вне словаря операции: `target_call` несёт только
   `executed|unknown_outcome` (продюсеры campaign.py/escalation.py);
   `blocked` допустим только у `attacker_llm`; `judge_llm` пишет только
   summary-`executed`; `planned` для `target_call` не пишется вовсе.
2. **Биекция** — строки истории с `attempt_no >= 1` <-> ровно одна
   `target_call`-запись (case_id/candidate_id/attempt_no). Строки с
   `attempt_no == 0` (registered / budget_exhausted / aborted /
   rewrite_accepted / rewrite_rejected) в биекции НЕ участвуют — у них нет
   и не должно быть target_call. `evidence_error` — ЛЕГИТИМНАЯ вторая строка
   той же попытки (сбой записи пакета, не потеря списания). Наивный подсчёт
   «все строки минус registered» давал бы ложный дефект на любом
   эскалационном прогоне — поэтому словари исходов разведены явно.
3. **Повторы** — повтор операции не создаёт второй записи (контракт
   ledger.py: одно списание = одна planned-запись; retry_of/error — поля
   существующей записи). Механика: по ключу операции нет дублей записей.
   Оговорка: `retry_of=` сегодня не пишет ни один продюсер в src/ — сверка
   проверяется только рукодельными фикстурами; отдельного валидатора ссылки
   нет (формат ссылки продюсерами не зафиксирован).
4. **Сводки <-> бюджеты** — источники разведены: judge-расход сверяется по
   summary-записи (`judge_llm/executed/note=summary`) с блоком JudgeBudget
   в campaign.json; attacker-расход — по числу `attacker_llm/planned`
   (одна на budget.spend()) с `campaign.json.attacker.calls_used`, НЕ по
   общему числу строк attacker_llm (rewrite.py пишет две записи на вызов,
   blocked расходом не является). Offline-прогон (attacker/judge
   `{"active": false}`) — честный unknown, НЕ расхождение.
5. **Суммарный расход <= суммарных бюджетов воркеров** — общий
   экспериментальный лимит отсутствует (открытый вопрос владельца, не
   измеряется).

Честность unknown: недостающий сигнал называется по имени и НЕ является
расхождением — «воркер убит до summary» = «сводка не завершена», а не
выдуманная сумма; отсутствующие файлы (исторический/прерванный run) не
маскируются под чистый прогон.

CLI (паттерн B4 — собственный main, существующий cli.py не трогается):
    python -m memnotsafe.reporting.ledger_recon <run_dir> [<run_dir> ...] \
        [--output PATH]
exit 0 — расхождений нет, 1 — есть (новых exit-кодов нет). Контрактные
нарушения файлов (LedgerError/AttemptHistoryError) и несуществующий каталог
перехватываются здесь: сообщение с именем run-каталога, exit 1, без
трейсбека.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from memnotsafe.core.attempt import (
    OUTCOME_ABORTED,
    OUTCOME_BUDGET_EXHAUSTED,
    OUTCOME_COMPLETED_FAILURE,
    OUTCOME_COMPLETED_SUCCESS,
    OUTCOME_EVIDENCE_ERROR,
    OUTCOME_REGISTERED,
    OUTCOME_REWRITE_ACCEPTED,
    OUTCOME_REWRITE_REJECTED,
    OUTCOME_TRANSPORT_ERROR,
    OUTCOME_UNKNOWN,
    AttemptHistoryError,
    read_history,
)
from memnotsafe.core.ledger import (
    OP_ATTACKER_LLM,
    OP_JUDGE_LLM,
    OP_TARGET_CALL,
    PHASE_BLOCKED,
    PHASE_EXECUTED,
    PHASE_UNKNOWN_OUTCOME,
    LedgerError,
    read_ledger,
)

SCHEMA_VERSION = "ledger-recon/1"

# Словарь фаз по операциям (сверка 1). Продюсеры: campaign.py:243,259,
# escalation.py:224,242 (target_call); rewrite.py:44,55,63 + escalation.py:161
# (attacker_llm); campaign.py:358-362 (judge_llm summary — единственный).
_PHASES_BY_OP: dict[str, set[str]] = {
    OP_TARGET_CALL: {PHASE_EXECUTED, PHASE_UNKNOWN_OUTCOME},
    OP_ATTACKER_LLM: {"planned", PHASE_EXECUTED, PHASE_UNKNOWN_OUTCOME, PHASE_BLOCKED},
    OP_JUDGE_LLM: {PHASE_EXECUTED},
}

# Исходы истории: терминальные (попытка дошла до оценки/транспорта — обязана
# иметь target_call) и легитимные строки attempt_no==0 (в биекции не участвуют).
_TERMINAL_OUTCOMES = {
    OUTCOME_COMPLETED_SUCCESS, OUTCOME_COMPLETED_FAILURE, OUTCOME_UNKNOWN, OUTCOME_TRANSPORT_ERROR,
}
_ZERO_ATTEMPT_OUTCOMES = {
    OUTCOME_REGISTERED, OUTCOME_BUDGET_EXHAUSTED, OUTCOME_ABORTED,
    OUTCOME_REWRITE_ACCEPTED, OUTCOME_REWRITE_REJECTED,
}

_LEDGER_FILE = "budget-ledger.jsonl"
_ATTEMPTS_FILE = "attempts.jsonl"
_CAMPAIGN_FILE = "campaign.json"


def _key(case_id: Any, candidate_id: Any, attempt_no: int) -> tuple[Any, Any, int]:
    return (case_id, candidate_id, attempt_no)


def _finding(code: str, detail: str) -> dict[str, str]:
    return {"code": code, "detail": detail}


def _read_campaign(run_dir: Path) -> tuple[dict[str, Any] | None, str | None]:
    """(metadata-словарь | None, сигнал-причина | None). Отсутствие/битый
    campaign.json — честный unknown с именем причины, не падение."""
    path = run_dir / _CAMPAIGN_FILE
    if not path.exists():
        return None, "campaign.json отсутствует (прогон прерван до сводки)"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError, UnicodeDecodeError):
        return None, "campaign.json не читается (битый файл)"
    if not isinstance(data, dict):
        return None, "campaign.json не является JSON-объектом"
    meta = data.get("metadata")
    return (meta if isinstance(meta, dict) else {}), None


def _load_run(run_dir: Path) -> dict[str, Any]:
    if not run_dir.is_dir():
        raise LedgerError(f"{run_dir}: run-каталог не существует")
    ledger_path = run_dir / _LEDGER_FILE
    attempts_path = run_dir / _ATTEMPTS_FILE
    return {
        "run_dir": run_dir,
        "ledger_present": ledger_path.exists(),
        "entries": read_ledger(ledger_path) if ledger_path.exists() else [],
        "attempts_present": attempts_path.exists(),
        "history": read_history(attempts_path) if attempts_path.exists() else [],
        "metadata": _read_campaign(run_dir),
    }


# ------------------------------------------------------------------ сверка 1: фазы


def _check_phases(run: dict[str, Any]) -> dict[str, Any]:
    if not run["ledger_present"]:
        return {"status": "unknown", "findings": [],
                "signals": [f"{_LEDGER_FILE} отсутствует (исторический run)"]}
    findings: list[dict[str, str]] = []
    for e in run["entries"]:
        allowed = _PHASES_BY_OP.get(e.operation)
        if allowed is None:
            findings.append(_finding(
                "operation_out_of_vocabulary",
                f"операция {e.operation!r} (phase={e.phase!r}) вне словаря "
                f"{OP_TARGET_CALL}/{OP_ATTACKER_LLM}/{OP_JUDGE_LLM}",
            ))
        elif e.phase not in allowed:
            note = " (blocked допустим только у attacker_llm)" if e.phase == PHASE_BLOCKED else ""
            findings.append(_finding(
                "phase_out_of_vocabulary",
                f"{e.operation}/{e.phase} (case={e.case_id}, attempt={e.attempt_no}){note}",
            ))
    return {"status": "mismatch" if findings else "ok", "findings": findings, "signals": []}


# ------------------------------------------------------------- сверка 2: биекция


def _check_bijection(run: dict[str, Any]) -> dict[str, Any]:
    if not run["ledger_present"] or not run["attempts_present"]:
        missing = [name for name, present in (
            (_LEDGER_FILE, run["ledger_present"]), (_ATTEMPTS_FILE, run["attempts_present"]),
        ) if not present]
        return {"status": "unknown", "findings": [],
                "signals": [f"{m} отсутствует (исторический/прерванный run)" for m in missing]}
    findings: list[dict[str, str]] = []
    target_calls = [e for e in run["entries"] if e.operation == OP_TARGET_CALL]

    for e in target_calls:
        if e.attempt_no < 1:
            findings.append(_finding(
                "target_call_attempt_no_zero",
                f"target_call на attempt_no={e.attempt_no} (case={e.case_id}): "
                f"у строк attempt_no==0 (registered/budget_exhausted/aborted/"
                f"rewrite_*) target_call'а быть не должно",
            ))
    tc_keys = {_key(e.case_id, e.candidate_id, e.attempt_no)
               for e in target_calls if e.attempt_no >= 1}

    terminal_by_key: dict[tuple[Any, Any, int], int] = {}
    evidence_by_key: dict[tuple[Any, Any, int], int] = {}
    for r in run["history"]:
        if r.outcome not in _TERMINAL_OUTCOMES and r.outcome not in _ZERO_ATTEMPT_OUTCOMES \
                and r.outcome != OUTCOME_EVIDENCE_ERROR:
            findings.append(_finding(
                "history_outcome_out_of_vocabulary",
                f"исход {r.outcome!r} вне словаря истории (case={r.case_id}, "
                f"attempt={r.attempt_no})",
            ))
            continue
        if r.attempt_no < 1:
            # CARD-P13-c-r2 (Ф-1): молча мимо биекции проходят ТОЛЬКО пять
            # легитимных видов@0; терминальный исход или evidence_error на
            # attempt_no<1 — повреждение/подмена артефакта, не тишина.
            if r.outcome not in _ZERO_ATTEMPT_OUTCOMES:
                findings.append(_finding(
                    "terminal_outcome_at_zero_attempt",
                    f"исход {r.outcome!r} на attempt_no={r.attempt_no} "
                    f"(case={r.case_id}, candidate={r.candidate_id}): у строк "
                    f"attempt_no==0 допустимы только registered/budget_exhausted/"
                    f"aborted/rewrite_*, evidence_error несёт реальный attempt_no",
                ))
            continue
        k = _key(r.case_id, r.candidate_id, r.attempt_no)
        if r.outcome == OUTCOME_EVIDENCE_ERROR:
            evidence_by_key[k] = evidence_by_key.get(k, 0) + 1
        else:
            terminal_by_key[k] = terminal_by_key.get(k, 0) + 1

    for k, n in terminal_by_key.items():
        if n > 1:
            findings.append(_finding(
                "duplicate_attempt_outcome",
                f"{n} терминальных строк одной попытки {k}",
            ))
    for k, n in evidence_by_key.items():
        if k not in terminal_by_key:
            findings.append(_finding(
                "attempt_outcome_missing",
                f"evidence_error без строки исхода попытки {k} (прогон прерван "
                f"между пакетом и исходом)",
            ))
        elif n > 1:
            findings.append(_finding("duplicate_evidence_error", f"{n} строк evidence_error попытки {k}"))
    for k in tc_keys:
        if k not in terminal_by_key:
            findings.append(_finding(
                "target_call_without_attempt",
                f"target_call есть, терминальной строки попытки нет: {k}",
            ))
    for k in terminal_by_key:
        if k not in tc_keys:
            findings.append(_finding(
                "attempt_without_target_call",
                f"терминальная строка есть, target_call-записи нет: {k}",
            ))
    return {"status": "mismatch" if findings else "ok", "findings": findings, "signals": []}


# ------------------------------------------------------------- сверка 3: повторы


def _check_duplicates(run: dict[str, Any]) -> dict[str, Any]:
    if not run["ledger_present"]:
        return {"status": "unknown", "findings": [],
                "signals": [f"{_LEDGER_FILE} отсутствует (исторический run)"]}
    findings: list[dict[str, str]] = []

    def _dups(records: list[Any], code: str, what: str) -> None:
        seen: dict[tuple[Any, Any, int], int] = {}
        for e in records:
            seen[_key(e.case_id, e.candidate_id, e.attempt_no)] = \
                seen.get(_key(e.case_id, e.candidate_id, e.attempt_no), 0) + 1
        for k, n in seen.items():
            if n > 1:
                findings.append(_finding(code, f"{n} записей {what} одной операции {k}"))

    _dups([e for e in run["entries"] if e.operation == OP_TARGET_CALL],
          "duplicate_target_call", "target_call")
    _dups([e for e in run["entries"]
           if e.operation == OP_ATTACKER_LLM and e.phase == "planned"],
          "duplicate_attacker_planned", "attacker_llm/planned")
    _dups([e for e in run["entries"]
           if e.operation == OP_ATTACKER_LLM and e.phase in (PHASE_EXECUTED, PHASE_UNKNOWN_OUTCOME)],
          "duplicate_attacker_outcome", "attacker_llm-исход")
    summaries = [e for e in run["entries"]
                 if e.operation == OP_JUDGE_LLM and e.note == "summary"]
    if len(summaries) > 1:
        findings.append(_finding("duplicate_judge_summary",
                                 f"{len(summaries)} summary-записей в одном run-каталоге"))
    return {"status": "mismatch" if findings else "ok", "findings": findings, "signals": []}


# --------------------------------------------------- сверка 4: сводки <-> бюджеты


def _meta_block(run: dict[str, Any], name: str) -> tuple[dict[str, Any] | None, str | None]:
    """(блок metadata.<name> | None, причина отсутствия)."""
    meta, reason = run["metadata"]
    if meta is None:
        return None, reason
    block = meta.get(name)
    if not isinstance(block, dict):
        return None, f"campaign.json: блок metadata.{name} отсутствует"
    return block, None


def _attacker_budgets_sub(run: dict[str, Any]) -> dict[str, Any]:
    findings: list[dict[str, str]] = []
    if not run["ledger_present"]:
        return {"status": "unknown", "findings": [],
                "signal": f"{_LEDGER_FILE} отсутствует — planned не сосчитать"}
    block, reason = _meta_block(run, "attacker")
    if reason is not None:
        return {"status": "unknown", "findings": [], "signal": reason}
    planned = sum(1 for e in run["entries"]
                  if e.operation == OP_ATTACKER_LLM and e.phase == "planned")
    if block is None or not block.get("active"):
        # CARD-P13-c-r2 (Ф-2): неактивный attacker при planned-списаниях —
        # артефакт противоречив (краш mid-campaign?); честный unknown по
        # прецеденту судьи, НЕ находка и НЕ «offline-прогон».
        if planned > 0:
            return {"status": "unknown", "findings": [],
                    "signal": f"attacker помечен неактивным, но леджер несёт "
                              f"{planned} planned-списаний — сверка невозможна, "
                              f"артефакт противоречив"}
        return {"status": "unknown", "findings": [],
                "signal": "attacker неактивен (offline-прогон) — сверка невозможна"}
    calls_used = block.get("calls_used")
    if not isinstance(calls_used, int) or isinstance(calls_used, bool):
        return {"status": "unknown", "findings": [],
                "signal": f"campaign.json: attacker.calls_used отсутствует ({calls_used!r})"}
    if planned != calls_used:
        findings.append(_finding(
            "attacker_calls_mismatch",
            f"attacker_llm/planned={planned}, campaign.json.attacker.calls_used={calls_used}",
        ))
    return {"status": "mismatch" if findings else "ok", "findings": findings, "signal": None,
            "planned": planned}


def _judge_budgets_sub(run: dict[str, Any]) -> dict[str, Any]:
    findings: list[dict[str, str]] = []
    block, reason = _meta_block(run, "judge")
    summaries = [e for e in run["entries"]
                 if e.operation == OP_JUDGE_LLM and e.note == "summary"]
    if reason is not None:
        return {"status": "unknown", "findings": [], "signal": reason}
    if block is None or not block.get("active"):
        if not summaries:
            return {"status": "ok", "findings": [], "signal": "судья неактивен — расход не велся"}
        return {"status": "unknown", "findings": [],
                "signal": "судья неактивен в campaign.json — baseline сверки отсутствует"}
    if not run["ledger_present"]:
        return {"status": "unknown", "findings": [],
                "signal": f"{_LEDGER_FILE} отсутствует — summary не прочитать"}
    if not summaries:
        return {"status": "unknown", "findings": [],
                "signal": "сводка не завершена (воркер убит до summary)"}
    usage = summaries[0].usage
    if not isinstance(usage, dict) or not isinstance(usage.get("calls_used"), int) \
            or not isinstance(usage.get("calls_limit"), int):
        return {"status": "unknown", "findings": [],
                "signal": "summary-запись без usage (сверять не с чем)"}
    pairs = [
        ("calls_used", usage["calls_used"], block.get("calls_used")),
        ("calls_limit", usage["calls_limit"], block.get("calls_limit")),
    ]
    diffs = [f"{name}: summary={s} != campaign.json={c}"
             for name, s, c in pairs if s != c]
    if diffs:
        findings.append(_finding("judge_summary_mismatch", "; ".join(diffs)))
    return {"status": "mismatch" if findings else "ok", "findings": findings, "signal": None,
            "calls_used": usage["calls_used"], "calls_limit": usage["calls_limit"]}


def _check_budgets(run: dict[str, Any]) -> dict[str, Any]:
    attacker = _attacker_budgets_sub(run)
    judge = _judge_budgets_sub(run)
    findings = attacker["findings"] + judge["findings"]
    if findings:
        status = "mismatch"
    elif attacker["status"] == "unknown" or judge["status"] == "unknown":
        status = "unknown"
    else:
        status = "ok"
    return {"status": status, "findings": findings, "attacker": attacker, "judge": judge}


# ------------------------------------------------- сверка 5: суммарный расход


def _totals_attacker(runs: list[dict[str, Any]]) -> dict[str, Any]:
    planned_sum = 0
    limit_sum = 0
    active = 0
    for run in runs:
        sub = run["checks"]["budgets"]["attacker"]
        planned_sum += sub.get("planned", 0)
        block, _ = _meta_block(run, "attacker")
        if block is not None and block.get("active"):
            active += 1
            limit = block.get("budget_limit")
            if not isinstance(limit, int) or isinstance(limit, bool):
                return {"status": "unknown", "findings": [],
                        "signal": "campaign.json: attacker.budget_limit отсутствует — "
                                  "суммарный лимит не сосчитать"}
            limit_sum += limit
    if active == 0:
        return {"status": "unknown", "findings": [],
                "signal": "attacker неактивен во всех прогонах"}
    if any(not run["ledger_present"] for run in runs):
        return {"status": "unknown", "findings": [],
                "signal": f"какой-то run без {_LEDGER_FILE} — суммарный расход не доказуем"}
    findings: list[dict[str, str]] = []
    if planned_sum > limit_sum:
        findings.append(_finding(
            "attacker_overspend",
            f"planned={planned_sum} > суммарных бюджетов воркеров={limit_sum}",
        ))
    return {"status": "mismatch" if findings else "ok", "findings": findings, "signal": None,
            "planned": planned_sum, "budget_limit_sum": limit_sum}


def _totals_judge(runs: list[dict[str, Any]]) -> dict[str, Any]:
    used_sum = 0
    limit_sum = 0
    active = 0
    for run in runs:
        block, _ = _meta_block(run, "judge")
        if block is None or not block.get("active"):
            continue
        active += 1
        sub = run["checks"]["budgets"]["judge"]
        if sub.get("calls_used") is None or sub.get("calls_limit") is None:
            return {"status": "unknown", "findings": [],
                    "signal": f"активный судья без summary/usage ({run['run_dir'].name}) — "
                              f"суммарный расход не доказуем"}
        used_sum += sub["calls_used"]
        limit = block.get("calls_limit")
        if not isinstance(limit, int) or isinstance(limit, bool):
            return {"status": "unknown", "findings": [],
                    "signal": "campaign.json: judge.calls_limit отсутствует"}
        limit_sum += limit
    if active == 0:
        return {"status": "unknown", "findings": [],
                "signal": "судья неактивен во всех прогонах"}
    findings: list[dict[str, str]] = []
    if used_sum > limit_sum:
        findings.append(_finding(
            "judge_overspend",
            f"summary calls_used={used_sum} > суммарных лимитов судей={limit_sum}",
        ))
    return {"status": "mismatch" if findings else "ok", "findings": findings, "signal": None,
            "calls_used": used_sum, "calls_limit_sum": limit_sum}


# ------------------------------------------------------------------ сборка отчёта


def reconcile(run_dirs: list[str | Path]) -> dict[str, Any]:
    """Сверка N run-каталогов. Чистая функция артефактов — идемпотентна,
    read-only; ничего не пишет и не поднимает стенд."""
    runs = [_load_run(Path(p)) for p in run_dirs]
    for run in runs:
        run["checks"] = {
            "phases": _check_phases(run),
            "bijection": _check_bijection(run),
            "duplicates": _check_duplicates(run),
            "budgets": _check_budgets(run),
        }
    totals = {
        "attacker": _totals_attacker(runs),
        "judge": _totals_judge(runs),
    }

    by_check: dict[str, int] = {}
    unknowns: list[dict[str, str | None]] = []
    for run in runs:
        for name, chk in run["checks"].items():
            by_check[name] = by_check.get(name, 0) + len(chk["findings"])
            if chk["status"] == "unknown":
                for signal in chk.get("signals", []):
                    unknowns.append({"run_dir": str(run["run_dir"]), "check": name, "signal": signal})
        for sub_name, sub in (("attacker", run["checks"]["budgets"]["attacker"]),
                              ("judge", run["checks"]["budgets"]["judge"])):
            if sub["status"] == "unknown":
                unknowns.append({"run_dir": str(run["run_dir"]), "check": "budgets",
                                 "signal": f"{sub_name}: {sub['signal']}"})
    for name, tot in totals.items():
        by_check["totals"] = by_check.get("totals", 0) + len(tot["findings"])
        if tot["status"] == "unknown":
            unknowns.append({"run_dir": None, "check": "totals",
                             "signal": f"{name}: {tot['signal']}"})

    return {
        "schema_version": SCHEMA_VERSION,
        "run_dirs": [str(Path(p)) for p in run_dirs],
        "runs": [_run_report(run) for run in runs],
        "totals": totals,
        "summary": {
            "discrepancies": sum(by_check.values()),
            "by_check": by_check,
            "unknowns": unknowns,
        },
    }


def _run_report(run: dict[str, Any]) -> dict[str, Any]:
    """Сериализация одного прогона: сверки с находками, budgets — с
    подписями attacker/judge (машиночитаемые статусы и счётчики)."""
    checks: dict[str, Any] = {}
    for name, chk in run["checks"].items():
        out = {"status": chk["status"], "findings": chk["findings"]}
        if chk.get("signals"):
            out["signals"] = chk["signals"]
        if name == "budgets":
            out["attacker"] = chk["attacker"]
            out["judge"] = chk["judge"]
        checks[name] = out
    return {"run_dir": str(run["run_dir"]), "checks": checks}


_TITLES = {
    "phases": "1 Фазы",
    "bijection": "2 Биекция попыток",
    "duplicates": "3 Повторы (дубли списаний)",
    "budgets": "4 Сводки и бюджеты",
}


def render_text(report: dict[str, Any]) -> str:
    """Человекочитаемая таблица: по каталогу — четыре сверки с находками,
    затем суммарный расход (сверка 5) и итог."""
    lines: list[str] = []
    lines.append(f"Сверка budget-ledger: {len(report['run_dirs'])} run-каталог(ов)")
    for run in report["runs"]:
        lines.append(str(run["run_dir"]))
        for name in ("phases", "bijection", "duplicates", "budgets"):
            chk = run["checks"][name]
            mark = {"ok": "ok", "unknown": "unknown", "mismatch": "РАСХОЖДЕНИЕ"}[chk["status"]]
            lines.append(f"  {_TITLES[name]:32s} {mark}"
                         + (f" ({len(chk['findings'])})" if chk["findings"] else ""))
            for f in chk["findings"]:
                lines.append(f"      {f['code']} — {f['detail']}")
    totals = report["totals"]
    lines.append("5 Суммарный расход (<= бюджетов воркеров):")
    for name in ("attacker", "judge"):
        tot = totals[name]
        mark = {"ok": "ok", "unknown": "unknown", "mismatch": "РАСХОЖДЕНИЕ"}[tot["status"]]
        lines.append(f"  {name:32s} {mark}")
        for f in tot["findings"]:
            lines.append(f"      {f['code']} — {f['detail']}")
    s = report["summary"]
    lines.append(
        "Расхождений: {n} (фазы {p} / биекция {b} / повторы {d} / сводки {u} / суммарный {t})".format(
            n=s["discrepancies"], p=s["by_check"].get("phases", 0),
            b=s["by_check"].get("bijection", 0), d=s["by_check"].get("duplicates", 0),
            u=s["by_check"].get("budgets", 0), t=s["by_check"].get("totals", 0),
        )
    )
    if s["unknowns"]:
        lines.append("Unknown (честный, НЕ расхождение):")
        for u in s["unknowns"]:
            where = u["run_dir"] or "<сводка по всем каталогам>"
            lines.append(f"  {where} [{u['check']}]: {u['signal']}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="memnotsafe.reporting.ledger_recon",
        description="Сверка budget-ledger N run-каталогов (пять сверок G3.3, read-only).",
    )
    parser.add_argument("run_dir", nargs="+",
                        help="run-каталог(и) с budget-ledger.jsonl / attempts.jsonl / campaign.json")
    parser.add_argument("--output", default=None,
                        help="записать машинный JSON-отчёт по пути (по умолчанию — только печать)")
    args = parser.parse_args(argv)

    try:
        report = reconcile([Path(p) for p in args.run_dir])
    except (LedgerError, AttemptHistoryError) as exc:
        print(f"ОШИБКА: {exc}")
        return 1
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(render_text(report))
    return 0 if report["summary"]["discrepancies"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
