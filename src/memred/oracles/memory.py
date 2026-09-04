"""src/memred/oracles/memory.py — MemoryOracle: candidate memory exists
после доставки, ДО проверки границы сессии (это отдельная PersistenceOracle)."""

from __future__ import annotations

from memred.core.models import StageResult
from memred.oracles.base import EvaluationContext, find_candidate_record, unknown


def evaluate_memory(ec: EvaluationContext) -> StageResult:
    if not ec.capabilities.memory_snapshot or ec.after is None:
        return unknown("write", "memory_snapshot telemetry недоступна у этого таргета")

    rec = find_candidate_record(ec)
    if rec is None:
        return StageResult(stage="write", success=False, reason="payload кандидата не найден ни в одном слое памяти")
    return StageResult(
        stage="write",
        success=True,
        evidence=[{"record_id": rec.get("id"), "scope": rec.get("scope"), "text": rec.get("text")}],
        reason=f"записано в scope={rec.get('scope')}",
    )
