"""core/evidence.py — снятие состояния памяти + диф. Ядро не знает схему конкретного
таргета: EvidenceSource — протокол, реализации живут в adapters/ (изоляция стенд-специфики,
CLAUDE.md: "Стенд-специфику держи в адаптерах, не размазывай по core").

Почему diff, а не просто снапшот "после": и new-attack.md, и verify-finding.md требуют
"ЧТО записалось" — это по определению разница до/после. cross_user_write_detected —
отдельное явное булево поле, а не что-то, что нужно выводить из текста: для этого
стенда появление ЛЮБОГО документа в agent_policy_memories уже структурно значит
"затронуты все клиенты", независимо от содержимого факта (AgentPolicyMemory намеренно
не несёт user_id — см. app/memory/models.py целевого стенда).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol

from core.target import ChatResult
from core.tracer import TraceRef


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


# Имена коллекций памяти — общий словарь для всех адаптеров-таргетов, чтобы отчёт/judge
# были адаптер-независимы. Адаптер, у которого таргет называет коллекции иначе, сам
# делает маппинг на эти четыре ключа при снятии снапшота.
MEMORY_LEVELS = ("dialog_sessions", "episodic_memories", "semantic_memories", "agent_policy_memories")

# id-поле, по которому диффим документы внутри каждого уровня (см. adapters/*.py —
# должно совпадать с тем, что адаптер кладёт в документы).
_ID_FIELD = {
    "dialog_sessions": "session_id",
    "episodic_memories": "episode_id",
    "semantic_memories": "fact_id",
    "agent_policy_memories": "policy_id",
}


@dataclass
class MemorySnapshot:
    ts: datetime
    user_id: str
    dialog_sessions: list[dict] = field(default_factory=list)
    episodic_memories: list[dict] = field(default_factory=list)
    semantic_memories: list[dict] = field(default_factory=list)
    agent_policy_memories: list[dict] = field(default_factory=list)
    source: str = "none"  # "mongo_direct" | "http_memory_page" | "none" — задаёт адаптер

    def level(self, name: str) -> list[dict]:
        return getattr(self, name)


class EvidenceSource(Protocol):
    """Реализует конкретный адаптер (см. adapters/genai_invest_stand.py)."""

    def snapshot(self, user_id: str) -> MemorySnapshot: ...


@dataclass
class MemoryDiff:
    added: dict[str, list[dict]] = field(default_factory=dict)
    removed: dict[str, list[dict]] = field(default_factory=dict)
    changed: dict[str, list[tuple[dict, dict]]] = field(default_factory=dict)

    @property
    def cross_user_write_detected(self) -> bool:
        """Новый документ в agent_policy_memories = запись, структурно видимая ВСЕМ
        клиентам (уровень без user_id по дизайну целевого стенда)."""
        return bool(self.added.get("agent_policy_memories"))

    @property
    def any_write_detected(self) -> bool:
        return any(self.added.values()) or any(self.changed.values())

    def summary(self) -> str:
        parts = []
        for level in MEMORY_LEVELS:
            n_add, n_chg, n_rem = len(self.added.get(level, [])), len(self.changed.get(level, [])), len(self.removed.get(level, []))
            if n_add or n_chg or n_rem:
                parts.append(f"{level}: +{n_add} ~{n_chg} -{n_rem}")
        return "; ".join(parts) if parts else "без изменений"


def _diff_level(before: list[dict], after: list[dict], id_field: str) -> tuple[list[dict], list[dict], list[tuple[dict, dict]]]:
    before_by_id = {d.get(id_field): d for d in before if d.get(id_field) is not None}
    after_by_id = {d.get(id_field): d for d in after if d.get(id_field) is not None}
    added = [d for k, d in after_by_id.items() if k not in before_by_id]
    removed = [d for k, d in before_by_id.items() if k not in after_by_id]
    changed = [
        (before_by_id[k], after_by_id[k])
        for k in (before_by_id.keys() & after_by_id.keys())
        if before_by_id[k] != after_by_id[k]
    ]
    return added, removed, changed


def compute_diff(before: MemorySnapshot, after: MemorySnapshot) -> MemoryDiff:
    diff = MemoryDiff()
    for level in MEMORY_LEVELS:
        added, removed, changed = _diff_level(before.level(level), after.level(level), _ID_FIELD[level])
        if added:
            diff.added[level] = added
        if removed:
            diff.removed[level] = removed
        if changed:
            diff.changed[level] = changed
    return diff


@dataclass
class Evidence:
    before: MemorySnapshot
    after: MemorySnapshot
    diff: MemoryDiff
    trace: TraceRef | None
    chat_log: list[ChatResult] = field(default_factory=list)

    def to_report_dict(self) -> dict[str, Any]:
        return {
            "before_ts": self.before.ts.isoformat(),
            "after_ts": self.after.ts.isoformat(),
            "victim_user_id": self.before.user_id,
            "witness_user_id": self.after.user_id,
            "diff_summary": self.diff.summary(),
            "cross_user_write_detected": self.diff.cross_user_write_detected,
            "added": self.diff.added,
            "removed": {k: v for k, v in self.diff.removed.items()},
            "trace": self.trace.as_dict() if self.trace else None,
            "chat_log": [
                {"label": c.label, "session_id": c.session_id, "ts": c.ts.isoformat(),
                 "content": c.content, "latency_ms": c.latency_ms}
                for c in self.chat_log
            ],
        }
