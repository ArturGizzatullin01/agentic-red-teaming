"""src/memnotsafe/oracles/base.py — общий контекст, который читают все oracles.

Единственная задача oracle — сказать УДАЛАСЬ ЛИ атака на своей стадии. Ничего
не решает про то, КАК это показать (reporting/) или КОГДА вызвать (core/runner.py).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from memnotsafe.adapters.base import Capabilities
from memnotsafe.attacks.base import AttackContext
from memnotsafe.core.models import AttackCandidate, StageResult
from memnotsafe.evidence.diff import SnapshotDiff
from memnotsafe.evidence.matching import match_candidate_record
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
    # Case-marker записи (token string, например "CM-4f2a91") для маркерного
    # пути matching. None = legacy-путь (payload-подстрока + source_user).
    # ВРЕМЕННАЯ граница (T002-2/T002-4): producer маркера в runner и поле
    # case_marker в AttackContext подключаются отдельной задачей (R4/T002-7);
    # сейчас значение задаётся только явным конструированием EvaluationContext
    # в офлайн-тестах. Не путать с expected_effect.markers (маркеры эффекта).
    case_marker: str | None = None


def unknown(stage: str, reason: str) -> StageResult:
    return StageResult(stage=stage, success=None, evidence=[], confidence=0.0, reason=reason)


def find_candidate_record(ec: EvaluationContext, *, scope: str | None = None) -> dict[str, Any] | None:
    """Делегирует в evidence.matching.match_candidate_record и возвращает
    выбранную запись при однозначном успехе (иначе None). Публичная сигнатура
    и результат record|None сохранены для существующих клиентов
    (retrieval/adoption/adapter-тесты); богатый тристейт-результат (с
    UNKNOWN) берите напрямую из match_candidate_record — как делают
    WRITE/PERSISTENCE. Без case_marker это legacy-семантика (подстрока
    payload + source_user==attacker, после-снимок only)."""
    match = match_candidate_record(
        payload=ec.candidate.payload,
        attacker_user_id=ec.ctx.attacker_user_id,
        before=ec.before,
        after=ec.after,
        marker=ec.case_marker,
        scope=scope,
    )
    return match.record if match.matched is True else None


def events_by_type(events: list[dict[str, Any]], event_type: str) -> list[dict[str, Any]]:
    return [e for e in events if e.get("event") == event_type]
