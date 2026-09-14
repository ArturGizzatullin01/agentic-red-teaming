"""src/memnotsafe/core/ledger.py — бюджетный леджер эксперимента
(P10b, фича 007).

Файл `runs/<name>/budget-ledger.jsonl`, по записи на операцию, связанную с
расходом: attacker_llm, judge_llm, target_call. Леджер — НАБЛЮДАТЕЛЬ поверх
СУЩЕСТВУЮЩИХ ограничителей (`CallBudget`, `JudgeBudget`, online_attempts):

- собственных лимитов и решений у леджера НЕТ — блокировка новых операций
  при исчерпании остаётся в существующих бюджетах; леджер фиксирует факт
  блокировки записью phase="blocked";
- списание не дублируется: spend() вызывается существующим кодом один раз;
  леджер пишет planned-запись рядом с ним и executed/unknown_outcome после;
- неизвестный исход (запрос отправлен, ответа нет) — phase="unknown_outcome",
  а не «выполнено с нулём» и не «не выполнено»;
- usage/cost, которые клиентский API не отдаёт, записываются usage=None —
  явно «неизвестно», НЕ ноль; выдуманных тарифов и «оценочной стоимости» нет;
- ошибки и повторы сохраняются (error, retry_of) и НЕ создают двойного
  списания — одно списание = одна planned-запись.

Связь с существующими сводками: judge-расход за кампанию дополнительно
сверяется с JudgeBudget (summary-запись в конце прогона); attacker-расход —
с CallBudget.used; расхождений нет, т.к. леджер не списывает сам.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

LEDGER_SCHEMA_VERSION = 1

OP_ATTACKER_LLM = "attacker_llm"
OP_JUDGE_LLM = "judge_llm"
OP_TARGET_CALL = "target_call"

PHASE_PLANNED = "planned"            # spend() выполнен, вызов отправляется
PHASE_EXECUTED = "executed"          # операция завершилась (ответ получен)
PHASE_UNKNOWN_OUTCOME = "unknown_outcome"  # отправлено, исход не наблюдаем
PHASE_BLOCKED = "blocked"            # существующий бюджет отказал: операция не начата


class LedgerError(ValueError):
    """Контрактное нарушение файла леджера."""


@dataclass
class LedgerEntry:
    experiment_id: str | None
    run_id: str
    operation: str                  # attacker_llm | judge_llm | target_call
    phase: str                      # planned | executed | unknown_outcome | blocked
    case_id: str | None = None
    candidate_id: str | None = None
    attempt_no: int = 0
    usage: dict | None = None       # None = неизвестно (НЕ ноль)
    error: str | None = None
    retry_of: str | None = None     # ссылка на операцию-первоисточник при повторе
    note: str | None = None

    def to_dict(self) -> dict:
        return {
            "schema_version": LEDGER_SCHEMA_VERSION,
            "experiment_id": self.experiment_id,
            "run_id": self.run_id,
            "operation": self.operation,
            "phase": self.phase,
            "case_id": self.case_id,
            "candidate_id": self.candidate_id,
            "attempt_no": self.attempt_no,
            "usage": self.usage,
            "error": self.error,
            "retry_of": self.retry_of,
            "note": self.note,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "LedgerEntry":
        if data.get("schema_version") != LEDGER_SCHEMA_VERSION:
            raise LedgerError(
                f"LedgerEntry: schema_version={data.get('schema_version')!r} не поддерживается "
                f"(ожидается {LEDGER_SCHEMA_VERSION})"
            )
        return cls(
            experiment_id=data.get("experiment_id"),
            run_id=str(data.get("run_id") or ""),
            operation=str(data.get("operation") or ""),
            phase=str(data.get("phase") or ""),
            case_id=data.get("case_id"),
            candidate_id=data.get("candidate_id"),
            attempt_no=int(data.get("attempt_no") or 0),
            usage=data.get("usage"),
            error=data.get("error"),
            retry_of=data.get("retry_of"),
            note=data.get("note"),
        )


class BudgetLedger:
    """Append-only леджер; запись сбрасывается немедленно (прерванный прогон
    оставляет историю расходов). Леджер НЕ имеет списывающих методов."""

    def __init__(self, path: str | Path, *, experiment_id: str | None, run_id: str):
        self.path = Path(path)
        self.experiment_id = experiment_id
        self.run_id = run_id

    def record(
        self,
        operation: str,
        phase: str,
        *,
        case_id: str | None = None,
        candidate_id: str | None = None,
        attempt_no: int = 0,
        usage: dict | None = None,
        error: str | None = None,
        retry_of: str | None = None,
        note: str | None = None,
    ) -> LedgerEntry:
        entry = LedgerEntry(
            experiment_id=self.experiment_id,
            run_id=self.run_id,
            operation=operation,
            phase=phase,
            case_id=case_id,
            candidate_id=candidate_id,
            attempt_no=attempt_no,
            usage=usage,
            error=error,
            retry_of=retry_of,
            note=note,
        )
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry.to_dict(), ensure_ascii=False) + "\n")
        return entry

    def entries(self) -> list[LedgerEntry]:
        return read_ledger(self.path)


def read_ledger(path: str | Path) -> list[LedgerEntry]:
    """Толерантное чтение: файла нет (исторический run) → пустой список.
    Повреждённая строка — LedgerError с номером строки: недописанный/подменённый
    леджер не маскируется под пустой (симметрично read_history)."""
    p = Path(path)
    if not p.exists():
        return []
    entries = []
    for no, line in enumerate(p.read_text(encoding="utf-8").splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError as exc:
            raise LedgerError(f"{path}: строка {no} — не JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise LedgerError(
                f"{path}: строка {no} — запись обязана быть JSON-объектом, получено {type(data).__name__}"
            )
        entries.append(LedgerEntry.from_dict(data))
    return entries
