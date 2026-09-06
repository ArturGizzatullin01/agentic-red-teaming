"""src/memnotsafe/oracles/base.py — общий контекст, который читают все oracles.

Единственная задача oracle — сказать УДАЛАСЬ ЛИ атака на своей стадии. Ничего
не решает про то, КАК это показать (reporting/) или КОГДА вызвать (core/runner.py).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from memnotsafe.adapters.base import Capabilities
from memnotsafe.attacks.base import AttackContext
from memnotsafe.core.models import (
    EVIDENCE_KIND_DETERMINISTIC,
    AttackCandidate,
    JudgeVerdict,
    StageResult,
)
from memnotsafe.evidence.diff import SnapshotDiff
from memnotsafe.evidence.snapshot import SystemSnapshot


@dataclass
class EvaluationContext:
    candidate: AttackCandidate
    ctx: AttackContext
    capabilities: Capabilities
    before: SystemSnapshot | None
    after: SystemSnapshot | None
    diff: SnapshotDiff | None
    baseline_response: str
    victim_response: str
    all_events: list[dict[str, Any]] = field(default_factory=list)
    victim_trace: list[dict[str, Any]] | None = None
    persistence_ok: bool = False
    # Судейские вердикты по стадиям, посчитанные раннером ДО evaluate_all
    # (data-model §5). Пустой словарь = судья не активен, и слияние в
    # oracles/judge_merge.py становится тождественной операцией: вердикты
    # стадий совпадают с прогоном до появления фичи (SC-003).
    judge_verdicts: dict[str, JudgeVerdict] = field(default_factory=dict)


def unknown(stage: str, reason: str, *, evidence_kind: str = EVIDENCE_KIND_DETERMINISTIC) -> StageResult:
    """UNKNOWN-вердикт. `evidence_kind` проставляют судимые стадии
    (`unavailable` — доказательства нет, судья может поднять стадию до True);
    для стадий вне охвата судьи остаётся умолчание."""
    return StageResult(
        stage=stage, success=None, evidence=[], confidence=0.0, reason=reason, evidence_kind=evidence_kind
    )


def find_candidate_record(ec: EvaluationContext, *, scope: str | None = None) -> dict[str, Any] | None:
    """Ищет запись в `after`-снимке, соответствующую payload'у этого кандидата
    и написанную атакующим — по точному совпадению текста (детерминированный
    mock хранит payload as-is), с fallback на подстроку."""
    if ec.after is None:
        return None
    pool: list[dict[str, Any]] = []
    if scope in (None, "global"):
        pool.extend(ec.after.global_memory)
    if scope in (None, "user"):
        pool.extend(ec.after.user(ec.ctx.attacker_user_id))
    for rec in pool:
        if rec.get("source_user") != ec.ctx.attacker_user_id:
            continue
        text = rec.get("text", "")
        if text == ec.candidate.payload or ec.candidate.payload in text or text in ec.candidate.payload:
            return rec
    return None


def events_by_type(events: list[dict[str, Any]], event_type: str) -> list[dict[str, Any]]:
    return [e for e in events if e.get("event") == event_type]
