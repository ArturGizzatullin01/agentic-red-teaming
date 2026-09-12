"""src/memnotsafe/evidence/snapshot.py — системный снимок памяти.

Критическая ошибка, которую явно запрещает spec: сравнивать snapshot(victim) с
snapshot(другого_пользователя). Нужен ОДИН системный снимок, который несёт
global-слой и срез каждого известного пользователя одновременно — тогда diff
может честно разложить изменения на attacker/victim/global по отдельности.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class SystemSnapshot:
    global_memory: list[dict[str, Any]] = field(default_factory=list)
    users: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    sessions: dict[str, dict[str, Any]] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def user(self, user_id: str) -> list[dict[str, Any]]:
        return self.users.get(user_id, [])

    def to_dict(self) -> dict[str, Any]:
        return {
            "global_memory": self.global_memory,
            "users": self.users,
            "sessions": self.sessions,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "SystemSnapshot":
        if not data:
            return cls()
        return cls(
            global_memory=data.get("global_memory", []),
            users=data.get("users", {}),
            sessions=data.get("sessions", {}),
            metadata=data.get("metadata", {}),
        )


@dataclass
class PhaseSnapshots:
    """Четыре наблюдения одного кейса (P06, WRITE-план 2.3; audit 3.4):

    m0 — после baseline-finalize, ДО доставки: исходное состояние.
    m1 — после delivery-finalize и settle: свидетельство WRITE (новые И
         изменённые документы относительно m0).
    m2 — после открытия новой сессии, ДО trigger-вопроса: свидетельство
         PERSISTENCE (те же id/слой/текст, что в m1).
    m3 — после trigger-finalize: дополнительные записи trigger (в т.ч.
         отказы). НЕ доказательство delivery и НЕ подмена m1/m2.

    Запись, впервые появившаяся в m3, не могла вызвать trigger этого кейса.
    Отсутствующие снимки честно переносятся как None → соответствующие
    стадии отвечают UNKNOWN, а не переписываются по m3 задним числом.
    Mongo-детали чтения остаются в адаптере; ядро видит только SystemSnapshot.
    """

    m0: SystemSnapshot | None = None
    m1: SystemSnapshot | None = None
    m2: SystemSnapshot | None = None
    m3: SystemSnapshot | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "m0": self.m0.to_dict() if self.m0 else None,
            "m1": self.m1.to_dict() if self.m1 else None,
            "m2": self.m2.to_dict() if self.m2 else None,
            "m3": self.m3.to_dict() if self.m3 else None,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "PhaseSnapshots":
        if not data:
            return cls()
        return cls(
            m0=SystemSnapshot.from_dict(data.get("m0")),
            m1=SystemSnapshot.from_dict(data.get("m1")),
            m2=SystemSnapshot.from_dict(data.get("m2")),
            m3=SystemSnapshot.from_dict(data.get("m3")),
        )
