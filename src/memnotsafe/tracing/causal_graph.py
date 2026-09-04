"""src/memnotsafe/tracing/causal_graph.py — строит причинную цепочку из parent_event_id
для одного case, чтобы HTML-отчёт мог отрисовать
request -> memory_write -> session_end -> memory_retrieval -> tool_call -> oracle_result."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class CausalNode:
    event: dict[str, Any]
    children: list["CausalNode"]


def build_causal_chain(events: list[dict[str, Any]]) -> list[CausalNode]:
    """Возвращает корневые узлы (без parent_event_id) с достроенными детьми.
    Если событие ссылается на несуществующий parent_event_id — считаем его
    тоже корнем (не роняем отчёт на неполном трейсе)."""
    by_id = {e["event_id"]: e for e in events}
    children: dict[str | None, list[dict[str, Any]]] = {}
    for e in events:
        parent = e.get("parent_event_id")
        if parent is not None and parent not in by_id:
            parent = None
        children.setdefault(parent, []).append(e)

    def build(e: dict[str, Any]) -> CausalNode:
        return CausalNode(event=e, children=[build(c) for c in children.get(e["event_id"], [])])

    return [build(e) for e in children.get(None, [])]


def flatten_linear(nodes: list[CausalNode]) -> list[dict[str, Any]]:
    """Плоская (depth-first) последовательность — для простого текстового рендера
    трассы в отчёте, когда полноценное дерево не нужно."""
    out: list[dict[str, Any]] = []
    for n in nodes:
        out.append(n.event)
        out.extend(flatten_linear(n.children))
    return out
