"""src/memnotsafe/adapters/base.py — единый контракт TargetAdapter.

Правило: адаптер знает КАК говорить с таргетом. Раннер (core/runner.py) не
знает деталей конкретного стенда/протокола — только этот интерфейс. Attack-пак
не имеет прямого доступа к адаптеру вообще (только к тому, что даёт AttackContext).

`get_trace()` и `snapshot()`/`snapshot_user()` МОГУТ вернуть None в black-box
режиме (нет доступа к состоянию памяти или к трассе решений агента) — раннер и
oracles обязаны трактовать это как telemetry unavailable (UNKNOWN), не как False.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from memnotsafe.evidence.snapshot import SystemSnapshot


@dataclass
class Capabilities:
    """Что умеет отдавать конкретный таргет — раннер и oracles на это смотрят
    перед тем, как требовать UNKNOWN вместо жёсткого FAIL."""

    trace: bool = False
    memory_snapshot: bool = False
    tool_calls: bool = False
    retrieval: bool = False

    def to_dict(self) -> dict[str, bool]:
        return {
            "trace": self.trace,
            "memory_snapshot": self.memory_snapshot,
            "tool_calls": self.tool_calls,
            "retrieval": self.retrieval,
        }


@dataclass
class ProbeResult:
    reachable: bool
    capabilities: Capabilities = field(default_factory=Capabilities)
    detail: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


@dataclass
class SendResult:
    """Ответ таргета на одно сообщение + порция трейс-событий, которые этот
    вызов породил (memory_write/memory_retrieval/tool_call/... — тип адаптера
    сам решает, что из этого применимо)."""

    content: str
    events: list[dict[str, Any]] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SettleResult:
    """Исход ожидания записи (P05, единый план 2.2/3.4): ТРИ различимых исхода
    вместо сплющенного bool.

    observed    — критерий (case-marker или legacy-needle) увиден в памяти;
    timeout     — память читалась, критерий не появился за окно наблюдения
                  (определённый негатив адаптера);
    unavailable — память недоступна для чтения: исход не наблюдаем. Это НЕ
                  негатив и НЕ успех — оракул обязан ответить UNKNOWN.

    Пустой критерий (пустой needle без маркера) успехом не является никогда:
    «нечего искать» ≠ «запись есть»."""

    outcome: str  # "observed" | "timeout" | "unavailable"
    reason: str = ""
    observations: int = 0
    elapsed_s: float = 0.0
    hits: int = 0

    @property
    def success(self) -> bool | None:
        """Тристейт для оракула: True только у observed; unavailable — None."""
        return {"observed": True, "timeout": False, "unavailable": None}.get(self.outcome)

    def to_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome,
            "reason": self.reason,
            "observations": self.observations,
            "elapsed_s": round(self.elapsed_s, 3),
            "hits": self.hits,
        }


class TargetAdapter(ABC):
    """Единый интерфейс. Стенд-специфика (Mongo-коллекции, auth_mode, схема
    memory-эндпоинтов и т.п.) целиком живёт внутри конкретного адаптера —
    core/runner.py её никогда не видит: target-specific branching не переносим
    в core runner."""

    capabilities: Capabilities = Capabilities()

    @abstractmethod
    async def probe(self) -> ProbeResult: ...

    @abstractmethod
    async def reset_state(self) -> None:
        """Полный сброс состояния таргета перед независимым прогоном/repetition."""

    async def reset(self) -> None:  # алиас для симметрии с остальным контрактом
        await self.reset_state()

    @abstractmethod
    async def new_session(self, user_id: str) -> str: ...

    @abstractmethod
    async def send(self, session_id: str, message: str) -> SendResult: ...

    @abstractmethod
    async def close_session(self, session_id: str) -> None: ...

    async def get_trace(self, session_id: str) -> list[dict[str, Any]] | None:
        """None, если таргет не даёт доступа к своей внутренней трассе решений —
        это не ошибка, а отсутствие telemetry (см. capabilities.trace)."""
        return None

    async def snapshot(self) -> SystemSnapshot | None:
        """Полный системный снимок (global + все известные users). None в
        black-box режиме без доступа к памяти."""
        return None

    async def snapshot_user(self, user_id: str) -> list[dict[str, Any]] | None:
        return None

    async def wait_until_persistent(self, evidence: dict[str, Any]) -> SettleResult:
        """Базовое умолчание — `unavailable` (EXT-A §7): адаптер, который НЕ
        переопределил этот метод, персистентность не наблюдает, поэтому честный
        исход — «не наблюдаемо» (UNKNOWN), а НЕ `observed`. Прежнее умолчание
        `observed` утверждало запись без единого наблюдения и заставляло раннер
        гейтить persistence на выдумке (пост-аудит Opus §6, инвентаризация
        карты U). `observed`/`timeout` возвращают ТОЛЬКО адаптеры, у которых для
        этого есть контрактное обоснование — реальный канал чтения памяти
        (mock/investment_stand переопределяют; http_endpoint честно отдаёт
        unavailable).

        Контракт evidence (T002-10, marker-aware settle): runner передаёт
        `attacker_user_id`, `case_marker` (токен `CM-<6hex>`, producer — runner)
        и `expect_text_contains` (первые 60 символов payload). Финалайзер стенда
        ПЕРЕФРАЗИРУЕТ текст, поэтому адаптер с каналом памяти обязан
        приоритизировать маркерную атрибуцию через общую утилиту matching
        (evidence/matching.py), а не буквальную подстроку. Возврат —
        типизированный SettleResult (P05): observed / timeout / unavailable;
        адаптеры со старым bool-контрактом нормализуются раннером (True→observed,
        False→timeout). Хранилищная специфика — только в переопределении."""
        return SettleResult(
            outcome="unavailable",
            reason=(
                "базовый TargetAdapter не наблюдает персистентность: метод "
                "wait_until_persistent не переопределён каналом чтения памяти — "
                "честный UNKNOWN, не выдуманный observed (EXT-A §7)"
            ),
        )

    async def aclose(self) -> None:
        """Закрыть сетевые ресурсы адаптера (если есть). No-op по умолчанию."""
        return None

    def set_context(self, run_id: str, case_id: str) -> None:
        """Необязательное расширение контракта: раннер вызывает это перед
        началом каждой независимой попытки, чтобы адаптер мог проставлять
        run_id/case_id в собственные трейс-события (см. adapters/mock.py).
        No-op по умолчанию — обязателен только адаптерам, которые сами
        генерируют TraceEvent (а не проксируют трассу таргета как есть)."""
        return None
