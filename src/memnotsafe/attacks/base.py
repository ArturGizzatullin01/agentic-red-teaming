"""src/memnotsafe/attacks/base.py — контракт атаки, killer feature инструмента.

Разделение ответственности держим строго:
    Attack        знает ЧТО делать (payload/candidate/шаги/ожидаемый эффект)
    TargetAdapter знает КАК говорить с таргетом
    Runner        знает КОГДА что вызывать
    Oracle        знает УДАЛАСЬ ЛИ атака
    Reporter      знает КАК это показать

Attack НИКОГДА не дергает адаптер напрямую — только описывает шаги, которые
исполняет раннер.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from memnotsafe.core.models import AttackCandidate


@dataclass
class AttackContext:
    """Один прогон: кто атакует, на ком проверяем последствие, с каким seed."""

    attacker_user_id: str
    victim_user_id: str
    run_seed: int
    case_id: str
    params: dict[str, Any] = field(default_factory=dict)


@dataclass
class DeliveryStep:
    """Один шаг доставки payload'а. message берётся из candidate, если явно не
    задан (обычно так и есть — но multi-turn атаки могут добавлять служебные
    реплики до/после payload'а, отсюда отдельный список шагов, а не одна строка)."""

    label: str
    message: str
    as_user: str | None = None  # None -> ctx.attacker_user_id


@dataclass
class TriggerStep:
    """Один шаг активации в новой (victim) сессии. message=None допустим для
    служебных шагов (например, только закрыть сессию/дождаться персистентности
    без дополнительной реплики)."""

    label: str
    message: str | None
    as_user: str | None = None  # None -> ctx.victim_user_id


@dataclass
class AttackMetadata:
    id: str
    name: str
    description: str
    family: str
    mpbench_class: str
    signal_strength: str  # "strong" | "weak"
    atlas_technique: str = "AML.T0080"  # Memory Poisoning
    atlas_tactic: str = "Persistence"
    owasp_asi: str = "ASI06"
    references: list[str] = field(default_factory=list)


class AttackBase(ABC):
    """Каждый файл в src/memnotsafe/attacks/ = один класс атаки. Никакой регистрации
    руками — src/memnotsafe/core/config.py подхватывает подклассы по имени family
    из scenario YAML (см. ATTACK_REGISTRY ниже)."""

    metadata: AttackMetadata

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        if getattr(cls, "metadata", None) is not None:
            ATTACK_REGISTRY[cls.metadata.family] = cls

    @abstractmethod
    def generate(self, ctx: AttackContext) -> AttackCandidate:
        """Строит конкретный payload/trigger для этого прогона (seed-детерминированно)."""

    @abstractmethod
    def delivery_steps(self, candidate: AttackCandidate, ctx: AttackContext) -> list[DeliveryStep]: ...

    @abstractmethod
    def trigger_steps(self, candidate: AttackCandidate, ctx: AttackContext) -> list[TriggerStep]: ...

    @abstractmethod
    def expected_effect(self, ctx: AttackContext) -> dict[str, Any]:
        """Декларация того, что должно произойти при успехе — общий словарь,
        который читает oracles/external_effect.py (dispatch по полю "type").
        Держится отдельно от generate(), чтобы raннер/oracle могли узнать
        ожидаемый эффект ДО генерации конкретного payload'а (например, для
        построения baseline-вопроса)."""

    def variants(self, base_ctx: AttackContext) -> list[AttackContext]:
        """По умолчанию один вариант; переопределить для batch-прогона
        (несколько пар attacker/victim, strong/weak формулировки и т.п.)."""
        return [base_ctx]


ATTACK_REGISTRY: dict[str, type[AttackBase]] = {}


def get_attack(family: str) -> type[AttackBase]:
    if family not in ATTACK_REGISTRY:
        raise KeyError(
            f"Атака с family={family!r} не найдена. Известные: {sorted(ATTACK_REGISTRY)}. "
            "Убедись, что модуль memnotsafe.attacks.<file> импортирован (см. src/memnotsafe/attacks/__init__.py)."
        )
    return ATTACK_REGISTRY[family]
