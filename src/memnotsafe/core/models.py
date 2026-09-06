"""src/memnotsafe/core/models.py — типизированные модели, которыми обмениваются все компоненты.

Правило: компоненты общаются dataclass'ами, а не произвольными dict.
Единственное место, где dict осознанно допустим — сырые события трейса
(src/memnotsafe/tracing/events.py) и сырые ответы адаптеров, потому что они
по определению непредсказуемой внешней формы.

Тристейт success: везде, где стадия может быть НЕИЗВЕСТНА из-за отсутствия
telemetry (черный ящик), используем `bool | None`, где `None` = UNKNOWN.
Никогда не схлопывать `None` в `True` — это жёсткий запрет.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Role(str, Enum):
    ATTACKER = "attacker"
    VICTIM = "victim"
    CONTROL = "control"


@dataclass
class Session:
    session_id: str
    user_id: str
    role: Role


@dataclass
class AttackCandidate:
    """Конкретный сгенерированный кандидат атаки: payload + триггер + метаданные."""

    attack_id: str
    family: str
    payload: str
    trigger: str
    expected_effect: dict[str, Any]
    metadata: dict[str, Any] = field(default_factory=dict)


# Тристейт: True = подтверждено, False = опровергнуто, None = UNKNOWN (telemetry недоступна).
StageVerdict = bool | None


# --------------------------------------------------------------- провенанс вердикта

# Природа доказательства, на котором построен вердикт стадии. Приоритет при
# слиянии с судейским вердиктом определяется ИМЕННО этим, а не именем стадии
# (FR-006/FR-017): одна и та же стадия бывает подтверждена и телеметрией, и
# дословным совпадением строки.
EVIDENCE_KIND_MEMORY_SNAPSHOT = "memory_snapshot"  # снимок памяти таргета — жёсткое
EVIDENCE_KIND_TELEMETRY = "telemetry"              # трасса таргета — жёсткое
EVIDENCE_KIND_MARKER_MATCH = "marker_match"        # дословный маркер в тексте — мягкое
EVIDENCE_KIND_SIGNATURE_MATCH = "signature_match"  # дословная сигнатура в ответе — мягкое
EVIDENCE_KIND_JUDGE_SEMANTIC = "judge_semantic"    # семантическая оценка судьёй
EVIDENCE_KIND_UNAVAILABLE = "unavailable"          # доказательства нет: стадия UNKNOWN
EVIDENCE_KIND_DETERMINISTIC = "deterministic"      # умолчание для стадий вне охвата судьи

HARD_EVIDENCE_KINDS = frozenset({EVIDENCE_KIND_MEMORY_SNAPSHOT, EVIDENCE_KIND_TELEMETRY})
SOFT_EVIDENCE_KINDS = frozenset({EVIDENCE_KIND_MARKER_MATCH, EVIDENCE_KIND_SIGNATURE_MATCH})

# Стадии, которые судья оценивает. `write` и `persistence` держатся на снимке
# памяти и судье не передаются никогда; `tool` — диагностическая (FR-014).
JUDGED_STAGES = ("retrieval", "adoption", "external_effect")

# Исходы судейского вердикта. Модель выбирает только между confirmed/refuted —
# остальные три присваивает фреймворк (порог, ошибка, пустой артефакт).
JUDGE_OUTCOMES = ("confirmed", "refuted", "unknown", "unavailable", "skipped")

# Словарь причин `JudgeVerdict.error`: код -> что он означает читателю отчёта.
JUDGE_ERROR_REASONS: dict[str, str] = {
    "timeout": "модель-судья не ответила за отведённое время",
    "rate_limit": "провайдер судьи вернул лимит запросов",
    "transport": "транспортная ошибка или 5xx при вызове судьи",
    "invalid_json": "ответ судьи не разобран как вердикт после всех повторов",
    "quote_not_verbatim": "цитаты судьи нет в отправленном ему артефакте",
    "quote_in_baseline": "цитата судьи встречается в чистом ответе до отравления",
    "below_threshold": "уверенность судьи ниже порога min_confidence",
    "budget_exhausted": "бюджет судейских вызовов кампании исчерпан",
    "empty_artifact": "оценивать нечего: артефакт пуст",
}


@dataclass
class JudgeVerdict:
    """Судейский вердикт по ОДНОЙ стадии ОДНОГО случая (data-model §1).

    `confidence` хранится сырой — такой, какой её вернула модель, ДО применения
    порога: иначе по отчёту нельзя отличить «судья был почти уверен» от
    «судья не знал». Порог отражается в `outcome`/`error`, а не в числе."""

    stage: str
    outcome: str
    confidence: float = 0.0
    rationale: str = ""
    quote: str = ""
    model: str = ""
    rubric: str = ""
    created_at: str = ""
    artifact_ref: str = ""
    error: str = ""

    @property
    def is_confirmed(self) -> bool:
        return self.outcome == "confirmed"

    def to_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome,
            "confidence": self.confidence,
            "rationale": self.rationale,
            "quote": self.quote,
            "model": self.model,
            "rubric": self.rubric,
            "created_at": self.created_at,
            "artifact_ref": self.artifact_ref,
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, stage: str, raw: dict[str, Any]) -> JudgeVerdict:
        return cls(
            stage=stage,
            outcome=raw.get("outcome", "unknown"),
            confidence=float(raw.get("confidence") or 0.0),
            rationale=raw.get("rationale", ""),
            quote=raw.get("quote", ""),
            model=raw.get("model", ""),
            rubric=raw.get("rubric", ""),
            created_at=raw.get("created_at", ""),
            artifact_ref=raw.get("artifact_ref", ""),
            error=raw.get("error", "") or "",
        )


@dataclass
class DeterministicVerdict:
    """Что сказала дословная проверка ДО слияния (data-model §2).

    Заполняется только когда судья активен: расхождение вердиктов не
    разрешается молча (FR-008), поэтому исходный вердикт обязан пережить
    перезапись."""

    success: StageVerdict
    reason: str = ""
    evidence_kind: str = EVIDENCE_KIND_DETERMINISTIC

    def to_dict(self) -> dict[str, Any]:
        return {"success": self.success, "reason": self.reason, "evidence_kind": self.evidence_kind}

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> DeterministicVerdict:
        return cls(
            success=raw.get("success"),
            reason=raw.get("reason", ""),
            evidence_kind=raw.get("evidence_kind", EVIDENCE_KIND_DETERMINISTIC),
        )


@dataclass
class StageResult:
    """Вердикт одной стадии. Поля провенанса (data-model §3) добавлены со
    значениями по умолчанию: при выключенном судье StageResult ведёт себя
    ровно как до появления фичи, и код, конструирующий его позиционно или
    частично, не ломается (SC-003)."""

    stage: str
    success: StageVerdict
    evidence: list[dict[str, Any]] = field(default_factory=list)
    confidence: float = 1.0
    reason: str = ""
    # Чем подтверждён ИТОГОВЫЙ вердикт: "deterministic" | "judge".
    verdict_source: str = "deterministic"
    # Природа доказательства итогового вердикта — см. словарь EVIDENCE_KIND_*.
    evidence_kind: str = EVIDENCE_KIND_DETERMINISTIC
    # Исходный детерминированный вердикт, если судья участвовал в слиянии.
    deterministic: DeterministicVerdict | None = None
    # Судейский вердикт, если судья вызывался на этой стадии.
    judge: JudgeVerdict | None = None
    # Вердикты разошлись — фиксируется независимо от того, чей победил (FR-008).
    disagreement: bool = False

    @property
    def is_unknown(self) -> bool:
        return self.success is None

    @property
    def is_judge_sourced(self) -> bool:
        return self.verdict_source == "judge"


@dataclass
class AttackResult:
    run_id: str
    case_id: str
    attack_id: str
    scenario_id: str
    stages: list[StageResult]
    success: bool
    metrics: dict[str, Any]
    evidence: dict[str, Any]
    attacker_user_id: str = ""
    victim_user_id: str = ""

    def stage(self, name: str) -> StageResult | None:
        for s in self.stages:
            if s.stage == name:
                return s
        return None

    def stage_bool(self, name: str) -> StageVerdict:
        s = self.stage(name)
        return s.success if s else None


@dataclass
class CampaignResult:
    run_id: str
    scenario_id: str
    attempts: int
    results: list[AttackResult]
    aggregate_metrics: dict[str, Any]
