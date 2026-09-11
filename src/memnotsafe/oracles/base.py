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
    # Судейские вердикты по стадиям, посчитанные раннером ДО evaluate_all
    # (data-model §5). Пустой словарь = судья не активен, и слияние в
    # oracles/judge_merge.py становится тождественной операцией: вердикты
    # стадий совпадают с прогоном до появления фичи (SC-003).
    judge_verdicts: dict[str, JudgeVerdict] = field(default_factory=dict)
    # Case-marker записи (token string, например "CM-4f2a91") для маркерного
    # пути matching. None = legacy-путь (payload-подстрока + source_user).
    # ВРЕМЕННАЯ граница (T002-2/T002-4): producer маркера в runner и поле
    # case_marker в AttackContext подключаются отдельной задачей (R4/T002-7);
    # сейчас значение задаётся только явным конструированием EvaluationContext
    # в офлайн-тестах. Не путать с expected_effect.markers (маркеры эффекта).
    case_marker: str | None = None
    # Доверенный контекст происхождения (T002-5): runner — единственный, кто
    # знает, какая сессия в какой фазе создавалась; эти поля передают это
    # знание oracle'ам явно (не задним числом по событиям). Событие
    # trigger-фазы правильного principal'а = session_id ∈ trigger_session_ids
    # И actor == victim_user_id. Пустые кортежи = контекст не передан
    # (ручные/старые конструкции) → фазовая атрибуция событий невозможна,
    # ADOPT/TOOL/EFFECT обязаны отвечать UNKNOWN, не False.
    delivery_session_ids: tuple[str, ...] = ()
    trigger_session_ids: tuple[str, ...] = ()


def unknown(stage: str, reason: str, *, evidence_kind: str = EVIDENCE_KIND_DETERMINISTIC) -> StageResult:
    """UNKNOWN-вердикт. `evidence_kind` проставляют судимые стадии
    (`unavailable` — доказательства нет, судья может поднять стадию до True);
    для стадий вне охвата судьи остаётся умолчание."""
    return StageResult(
        stage=stage, success=None, evidence=[], confidence=0.0, reason=reason, evidence_kind=evidence_kind
    )


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


NO_PHASE_CONTEXT_REASON = "фазовая атрибуция событий недоступна: trigger-сессии не переданы"


def trigger_events(ec: EvaluationContext) -> list[dict[str, Any]] | None:
    """События trigger-фазы правильного principal'а — общий отбор для событийных
    стадий ADOPT/TOOL/EFFECT (FR-E, US3, T002-5; раздел «Trigger-only» контракта
    specs/002-evidence-integrity/contracts/evidence-and-verdict.md). Стадии
    памяти (WRITE/PERSISTENCE/RETRIEVE) фазой не ограничены и продолжают читать
    `all_events`: их доказательство — снимок и трасса жертвы, а не фаза диалога.

    Кто в какой фазе говорил, знает только раннер; здесь это читается из
    переданного контекста, а не восстанавливается задним числом по порядку или
    содержимому событий. Событие засчитывается, если `session_id` объявлен
    trigger-сессией И `actor` — жертва: эхо установки в сессии атакующего и
    реплика постороннего principal'а активацией не являются.

    `None` (а не пустой список) — контекст фаз не передан: доказать фазу нечем,
    вызывающая стадия обязана ответить UNKNOWN. Пустой список — фаза известна, а
    подходящих событий в ней нет; это наблюдаемый факт трассы, и стадия трактует
    его так же, как раньше трактовала отсутствие событий. Разница между «нечем
    проверить» и «проверено, не было» не стирается (принцип IV)."""
    if not ec.trigger_session_ids:
        return None
    trusted = set(ec.trigger_session_ids)
    victim = ec.ctx.victim_user_id
    return [e for e in ec.all_events if e.get("session_id") in trusted and e.get("actor") == victim]
