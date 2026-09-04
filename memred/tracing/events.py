"""memred/tracing/events.py — схема одного события трейса (spec §15)."""

from __future__ import annotations

import itertools
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

EventType = Literal[
    "request",
    "memory_write",
    "memory_read",
    "memory_retrieval",
    "llm_decision",
    "tool_call",
    "tool_result",
    "state_change",
    "session_end",
    "oracle_result",
]

_counter = itertools.count(1)


def new_event_id(run_id: str) -> str:
    return f"evt-{run_id[-8:]}-{next(_counter):04d}"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class TraceEvent:
    run_id: str
    case_id: str
    session_id: str
    actor: str
    event: EventType
    event_id: str = field(default_factory=lambda: f"evt-{uuid.uuid4().hex[:10]}")
    parent_event_id: str | None = None
    timestamp: str = field(default_factory=_utc_now_iso)
    source: str = "agent"
    sink: str = "target"
    trust: str = "model_generated"
    tool: str | None = None
    arguments: dict[str, Any] | None = None
    memory_refs: list[str] = field(default_factory=list)
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "parent_event_id": self.parent_event_id,
            "run_id": self.run_id,
            "case_id": self.case_id,
            "session_id": self.session_id,
            "actor": self.actor,
            "timestamp": self.timestamp,
            "event": self.event,
            "source": self.source,
            "sink": self.sink,
            "trust": self.trust,
            "tool": self.tool,
            "arguments": self.arguments,
            "memory_refs": self.memory_refs,
            "detail": self.detail,
        }
