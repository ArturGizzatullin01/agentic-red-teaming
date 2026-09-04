"""src/memred/adapters/base.py — единый контракт TargetAdapter.

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

from memred.evidence.snapshot import SystemSnapshot


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

    async def wait_until_persistent(self, evidence: dict[str, Any]) -> bool:
        """По умолчанию — не ждать (синхронный таргет = запись уже персистентна
        к моменту возврата send()). Асинхронные таргеты (см. HANDOFF про Mongo-
        settle на живом стенде) переопределяют polling'ом."""
        return True

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
