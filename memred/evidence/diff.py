"""memred/evidence/diff.py — диф двух SystemSnapshot по каждому слою отдельно.

Диффим по id-полю записи (`id`, иначе `mem_id`, иначе `fact_id`), не по
содержимому целиком — так уцелевшая, но переписанная запись не даёт ложных
"добавлено+удалено". Урок из core/CLAUDE.md "Андрей тулы": если адаптер не
проставляет стабильный id, диф молча увидит 0 изменений даже при реальной
записи — тесты на mock-таргете это тоже покрывают (см. tests/).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from memred.evidence.snapshot import SystemSnapshot

_ID_KEYS = ("id", "mem_id", "fact_id", "memory_id")


def _rec_id(rec: dict[str, Any], fallback_index: int) -> str:
    for k in _ID_KEYS:
        if k in rec and rec[k] is not None:
            return str(rec[k])
    return f"#{fallback_index}"


def _index(records: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {_rec_id(r, i): r for i, r in enumerate(records)}


@dataclass
class LayerDiff:
    added: list[dict[str, Any]] = field(default_factory=list)
    removed: list[dict[str, Any]] = field(default_factory=list)
    changed: list[dict[str, Any]] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(self.added or self.removed or self.changed)

    def to_dict(self) -> dict[str, Any]:
        return {"added": self.added, "removed": self.removed, "changed": self.changed}


def _diff_layer(before: list[dict[str, Any]], after: list[dict[str, Any]]) -> LayerDiff:
    before_idx, after_idx = _index(before), _index(after)
    added = [after_idx[k] for k in after_idx if k not in before_idx]
    removed = [before_idx[k] for k in before_idx if k not in after_idx]
    changed = [
        after_idx[k]
        for k in after_idx
        if k in before_idx and after_idx[k] != before_idx[k]
    ]
    return LayerDiff(added=added, removed=removed, changed=changed)


@dataclass
class SnapshotDiff:
    global_diff: LayerDiff
    user_diffs: dict[str, LayerDiff]

    def to_dict(self) -> dict[str, Any]:
        return {
            "global": self.global_diff.to_dict(),
            "users": {u: d.to_dict() for u, d in self.user_diffs.items()},
        }

    def any_changes_for(self, user_id: str) -> bool:
        d = self.user_diffs.get(user_id)
        return bool(d and d.has_changes)


def compute_diff(before: SystemSnapshot, after: SystemSnapshot) -> SnapshotDiff:
    """Диф ОДНОГО системного снимка до/после — не смешивает разных пользователей
    (spec §7: attacker_before->attacker_after, victim_before->victim_after,
    global_before->global_after считаются раздельно)."""
    global_diff = _diff_layer(before.global_memory, after.global_memory)
    user_ids = set(before.users) | set(after.users)
    user_diffs = {
        uid: _diff_layer(before.user(uid), after.user(uid)) for uid in sorted(user_ids)
    }
    return SnapshotDiff(global_diff=global_diff, user_diffs=user_diffs)
