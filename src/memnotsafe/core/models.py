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


@dataclass
class StageResult:
    stage: str
    success: StageVerdict
    evidence: list[dict[str, Any]] = field(default_factory=list)
    confidence: float = 1.0
    reason: str = ""

    @property
    def is_unknown(self) -> bool:
        return self.success is None


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
