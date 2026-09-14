"""src/memnotsafe/core/attempt.py — история попыток эксперимента
(P10b, фича 007).

Файл `runs/<name>/attempts.jsonl`, по одной JSON-записи на событие. История
различает четыре уровня, которые раньше сливались в «попытку»:

- **логический кейс** (`case_id`) — замысел атаки; цепочка кандидатов одного
  кейса несёт ОДИН и тот же case_id;
- **кандидат** (`candidate_id`) — конкретный контент (payload/trigger/цель) и
  его родитель (`parent_candidate_id`) в lineage rewrite'ов;
- **попытка на target** (`attempt_no`) — прогон кандидата против стенда;
- **транспортный повтор** (`transport_retry`) — повтор ТОГО ЖЕ кандидата
  после транспортной ошибки; он НЕ создаёт нового кандидата.

Именно поэтому rewrite-потомок получает НОВЫЙ candidate_id при том же
case_id, а transport-повтор — тот же candidate_id с transport_retry+1.

**Связь с метриками кампании (явно, без молчаливых смен знаменателей):**
знаменатель ASR остаётся `attempts = len(results)` из campaign.json —
завершённые СЛУЧАИ. Записи `completed_*`/`unknown` в истории — завершённые
ПОПЫТКИ: при эскалации их больше, чем случаев (промежуточные неудачные
попытки не входят в знаменатель ASR, а финальная попытка кейса — это его
AttackResult). Записи rewrite_rejected / budget_exhausted / transport_error /
aborted до оценки не дошли и в знаменатель НЕ входят; aggregate_metrics по
attempts.jsonl не пересчитывается.

Секреты и полные тексты payload'ов в историю не пишутся: только
идентификаторы, маркер (канарейка кейса), digest цели, seed и сессии.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

ATTEMPT_SCHEMA_VERSION = 1

# Исходы записей истории. completed_* / unknown — попытка дошла до оценки
# (финальная попытка кейса 1:1 с его AttackResult; промежуточные попытки
# эскалации остаются в истории, но не в знаменателе ASR).
OUTCOME_REGISTERED = "registered"                  # кандидат создан
OUTCOME_REWRITE_ACCEPTED = "rewrite_accepted"      # rewrite принят (новый кандидат)
OUTCOME_REWRITE_REJECTED = "rewrite_rejected"      # кандидат отклонён (цель/инварианты)
OUTCOME_COMPLETED_SUCCESS = "completed_success"
OUTCOME_COMPLETED_FAILURE = "completed_failure"
OUTCOME_UNKNOWN = "unknown"                        # оценка неопределённа (нет телеметрии)
OUTCOME_BUDGET_EXHAUSTED = "budget_exhausted"      # штатный стоп по бюджету
OUTCOME_TRANSPORT_ERROR = "transport_error"        # сбой транспорта target
OUTCOME_ABORTED = "aborted"                        # попытка прервана (сбой атакующей LLM и т.п.)
OUTCOME_EVIDENCE_ERROR = "evidence_error"          # пакет доказательств не записан (сбой I/O)

# Завершённые исходы — ровно те, что образуют знаменатель ASR.
COMPLETED_OUTCOMES = (OUTCOME_COMPLETED_SUCCESS, OUTCOME_COMPLETED_FAILURE, OUTCOME_UNKNOWN)

_COMPOSITE_STAGES = ("write", "persistence", "retrieval", "adoption", "external_effect")


class AttemptHistoryError(ValueError):
    """Контрактное нарушение файла истории."""


def outcome_of_result(result) -> str:
    """Итог попытки по AttackResult. UNKNOWN не сплющивается в failure:
    композитная стадия без телеметрии (success=None) → unknown."""
    if result.success:
        return OUTCOME_COMPLETED_SUCCESS
    stages = {s.stage: s.success for s in result.stages}
    if any(stages.get(stage) is None for stage in _COMPOSITE_STAGES):
        return OUTCOME_UNKNOWN
    return OUTCOME_COMPLETED_FAILURE


def sessions_from_transcript(transcript: dict | None) -> dict[str, str | None]:
    """session_id по стадиям из wire-транскрипта (phase → session_id).
    Нет транскрипта/фазы → None: отсутствие телеметрии честно записывается,
    а не подменяется вымышленной сессией."""
    sessions: dict[str, str | None] = {}
    for message in (transcript or {}).get("messages") or []:
        phase = message.get("phase")
        if phase and phase not in sessions:
            sessions[phase] = message.get("session_id")
    return sessions


@dataclass
class AttemptRecord:
    experiment_id: str | None
    run_id: str
    case_id: str                  # логический кейс
    candidate_id: str             # кандидат (контент попытки)
    parent_candidate_id: str | None
    attempt_no: int               # попытка этого кандидата на target (1..n)
    transport_retry: int          # 0 = не повтор; N = N-й транспортный повтор
    case_marker: str | None
    goal_digest: str | None
    seed: int | None
    session_ids: dict[str, str | None]
    outcome: str
    error: str | None = None

    def to_dict(self) -> dict:
        return {
            "schema_version": ATTEMPT_SCHEMA_VERSION,
            "experiment_id": self.experiment_id,
            "run_id": self.run_id,
            "case_id": self.case_id,
            "candidate_id": self.candidate_id,
            "parent_candidate_id": self.parent_candidate_id,
            "attempt_no": self.attempt_no,
            "transport_retry": self.transport_retry,
            "case_marker": self.case_marker,
            "goal_digest": self.goal_digest,
            "seed": self.seed,
            "session_ids": self.session_ids,
            "outcome": self.outcome,
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "AttemptRecord":
        if data.get("schema_version") != ATTEMPT_SCHEMA_VERSION:
            raise AttemptHistoryError(
                f"AttemptRecord: schema_version={data.get('schema_version')!r} не поддерживается "
                f"(ожидается {ATTEMPT_SCHEMA_VERSION})"
            )
        return cls(
            experiment_id=data.get("experiment_id"),
            run_id=str(data.get("run_id") or ""),
            case_id=str(data.get("case_id") or ""),
            candidate_id=str(data.get("candidate_id") or ""),
            parent_candidate_id=data.get("parent_candidate_id"),
            attempt_no=int(data.get("attempt_no") or 0),  # 0 = событие вне target (валидный 0, не «по умолчанию 1»)
            transport_retry=int(data.get("transport_retry") or 0),
            case_marker=data.get("case_marker"),
            goal_digest=data.get("goal_digest"),
            seed=data.get("seed"),
            session_ids=dict(data.get("session_ids") or {}),
            outcome=str(data.get("outcome") or ""),
            error=data.get("error"),
        )


class AttemptHistory:
    """Append-only история попыток. Одна кампания — один файл; запись
    немедленно сбрасывается на диск (flush), чтобы прерванный прогон оставил
    историю уже случившегося."""

    def __init__(self, path: str | Path, *, experiment_id: str | None, run_id: str):
        self.path = Path(path)
        self.experiment_id = experiment_id
        self.run_id = run_id

    def record(
        self,
        *,
        case_id: str,
        candidate_id: str,
        outcome: str,
        attempt_no: int = 1,
        transport_retry: int = 0,
        parent_candidate_id: str | None = None,
        case_marker: str | None = None,
        goal_digest: str | None = None,
        seed: int | None = None,
        session_ids: dict[str, str | None] | None = None,
        error: str | None = None,
    ) -> AttemptRecord:
        rec = AttemptRecord(
            experiment_id=self.experiment_id,
            run_id=self.run_id,
            case_id=case_id,
            candidate_id=candidate_id,
            parent_candidate_id=parent_candidate_id,
            attempt_no=attempt_no,
            transport_retry=transport_retry,
            case_marker=case_marker,
            goal_digest=goal_digest,
            seed=seed,
            session_ids=session_ids or {},
            outcome=outcome,
            error=error,
        )
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec.to_dict(), ensure_ascii=False) + "\n")
        return rec

    def entries(self) -> list[AttemptRecord]:
        return read_history(self.path)


def read_history(path: str | Path) -> list[AttemptRecord]:
    """Толерантное чтение: файла нет (исторический run) → пустой список.
    Повреждённая строка — КОНТРАКТНАЯ ошибка AttemptHistoryError с номером
    строки (не сырой JSONDecodeError): недописанная/подменённая история не
    маскируется под пустую или полноценную."""
    p = Path(path)
    if not p.exists():
        return []
    records = []
    for no, line in enumerate(p.read_text(encoding="utf-8").splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError as exc:
            raise AttemptHistoryError(f"{path}: строка {no} — не JSON: {exc}") from exc
        records.append(AttemptRecord.from_dict(data))
    return records
