"""memred/evidence/snapshot.py — системный снимок памяти.

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
