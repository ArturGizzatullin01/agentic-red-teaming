"""src/memnotsafe/reporting/proof.py — proof artifact: достаточно, чтобы
воспроизвести/предъявить finding без повторного поиска по всему run'у."""

from __future__ import annotations

from typing import Any

from memnotsafe.core.models import AttackResult


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
        # Явная выжимка внешнего эффекта: чей cus утёк (detail.customer) и какой
        # канал это подтвердил (detail.channel) — чтобы предъявить утечку без
        # раскопок по всему трейсу (FR-007, SC-005).
        "external_effect": _external_effect_proof(trace_events or []),
        # Судейские вердикты рядом с жёстким доказательством: по artifact_ref
        # вердикт перепроверяется постфактум, без повторного прогона (SC-007).
        "judge": _judge_proof(result),
        "evidence": {
            "trace_events": trace_events or [],
            "memory_diff": result.evidence.get("diff"),
        },
        "success": result.success,
    }


def _judge_proof(result: AttackResult) -> dict[str, Any] | None:
    """Блок judge — только для находок, где хотя бы одна композитная стадия
    держится на судейском вердикте. Там, где всё доказано снимком памяти или
    телеметрией, блока нет: он бы только зашумлял proof."""
    judged = [s for s in result.stages if s.judge is not None]
    if not judged:
        return None
    composite_by_judge = [
        s.stage for s in judged
        if s.verdict_source == "judge" and s.stage in ("retrieval", "adoption", "external_effect")
    ]
    if not composite_by_judge:
        return None
    return {
        "stages_by_judge": composite_by_judge,
        "verdicts": [
            {
                "stage": s.stage,
                "outcome": s.judge.outcome,
                "confidence": s.judge.confidence,
                "quote": s.judge.quote,
                "rationale": s.judge.rationale,
                "model": s.judge.model,
                "rubric": s.judge.rubric,
                "artifact_ref": s.judge.artifact_ref,
                "verdict_source": s.verdict_source,
                "disagreement": s.disagreement,
                "deterministic": s.deterministic.to_dict() if s.deterministic else None,
            }
            for s in judged
        ],
    }


def _external_effect_proof(trace_events: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Первый tool_result со status=200 — доказательство внешнего эффекта:
    какой клиент (customer) и через какой канал (channel) подтверждён."""
    for e in trace_events:
        if e.get("event") != "tool_result":
            continue
        detail = e.get("detail") or {}
        if detail.get("status") == 200 and detail.get("customer") is not None:
            return {
                "customer": detail.get("customer"),
                "channel": detail.get("channel"),
                "tool": e.get("tool"),
                "session_id": e.get("session_id"),
            }
    return None
