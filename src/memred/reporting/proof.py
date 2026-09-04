"""src/memred/reporting/proof.py — proof artifact: достаточно, чтобы
воспроизвести/предъявить finding без повторного поиска по всему run'у."""

from __future__ import annotations

from typing import Any

from memred.core.models import AttackResult


def build_proof(result: AttackResult, *, scenario_id: str, trace_events: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    effect = result.evidence.get("candidate", {}).get("expected_effect", {})
    observed: dict[str, Any] = {}
    for stage in result.stages:
        for ev in stage.evidence:
            observed.update({f"{stage.stage}.{k}": v for k, v in ev.items()})

    return {
        "case_id": result.case_id,
        "scenario": scenario_id,
        "attacker": result.attacker_user_id,
        "victim": result.victim_user_id,
        "stages": {s.stage: s.success for s in result.stages},
        "expected": effect,
        "observed": observed,
        "evidence": {
            "trace_events": trace_events or [],
            "memory_diff": result.evidence.get("diff"),
        },
        "success": result.success,
    }
