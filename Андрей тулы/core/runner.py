"""core/runner.py — оркестрирует один прогон атаки: deliver -> (finalize) -> trigger ->
evidence -> judge. Единственное место, где склеены target/evidence/tracer/judge — сами
паки об этом не знают, они только декларируют шаги и success_check (SRP: core/runner.py
не лезет в схему конкретного таргета, adapters/ не лезет в оркестрацию).

Работает через TargetPool, не один TargetClient: cross-user атаки (жертва пишет,
свидетель читает) физически требуют двух разных identity/API-ключей на этом
контракте (identity = Bearer-ключ, не поле тела запроса) — см. core/target.TargetPool.
"""

from __future__ import annotations

from dataclasses import dataclass

from core.attack_base import AttackBase, AttackContext
from core.evidence import Evidence, EvidenceSource, compute_diff
from core.judge import Verdict, evaluate
from core.llm_client import LLMClient
from core.target import TargetPool
from core.tracer import CompositeTracer, new_run_id


@dataclass
class AttackRunResult:
    attack_id: str
    ctx: AttackContext
    evidence: Evidence
    verdict: Verdict


def _witness_session_id(ctx: AttackContext) -> str:
    return ctx.witness_session_id or f"{ctx.session_id}-witness"


def _session_for(ctx: AttackContext, user_id: str) -> str:
    if user_id == ctx.victim_user_id:
        return ctx.session_id
    return _witness_session_id(ctx)


async def run_attack(
    attack: AttackBase,
    ctx: AttackContext,
    *,
    targets: TargetPool,
    evidence_source: EvidenceSource,
    judge_llm: LLMClient,
    tracer: CompositeTracer | None = None,
) -> AttackRunResult:
    tracer = tracer or CompositeTracer()
    run_id = new_run_id()
    handle = tracer.start_run(
        run_id,
        {"attack_id": attack.metadata.id, "victim": ctx.victim_user_id,
         "witness": ctx.witness_user_id, "seed": ctx.run_seed},
    )

    chat_log = []
    witness_id = ctx.witness_user_id or ctx.victim_user_id
    before = evidence_source.snapshot(ctx.victim_user_id)
    handle.log_event("snapshot_before", {"user_id": ctx.victim_user_id, "summary": "captured"})

    payload_plan = await attack.payload_strategy(ctx).generate(ctx)
    handle.log_event("payload_plan", {"strategy": payload_plan.strategy_name,
                                       "similarity_score": payload_plan.similarity_score,
                                       "text": payload_plan.text})

    for step in attack.delivery_steps(ctx):
        as_user = step.as_user or ctx.victim_user_id
        client = targets.get(as_user)
        text = await step.build(ctx, payload_plan)
        result = await client.deliver_user_message(
            _session_for(ctx, as_user), text, label=f"deliver:{step.label}"
        )
        chat_log.append(result)
        handle.log_chat(result, note=f"delivery as {as_user}")

    finalized = False
    for step in attack.trigger_steps(ctx):
        if step.requires_finalize_before and not finalized:
            fin = await targets.get(ctx.victim_user_id).finalize(ctx.session_id)
            handle.log_event("finalize", {"session_id": ctx.session_id, "response": fin.raw_response})
            finalized = True
        text = await step.build(ctx)
        if text is None:
            continue
        as_user = step.as_user or witness_id
        client = targets.get(as_user)
        session_id = step.session_id_override or _session_for(ctx, as_user)
        result = await client.deliver_user_message(
            session_id, text, label=f"trigger:{step.label}"
        )
        chat_log.append(result)
        handle.log_chat(result, note=f"trigger as {as_user}")

    if not finalized:
        fin = await targets.get(ctx.victim_user_id).finalize(ctx.session_id)
        handle.log_event("finalize", {"session_id": ctx.session_id, "response": fin.raw_response})

    after = evidence_source.snapshot(witness_id)
    handle.log_event("snapshot_after", {"user_id": witness_id, "summary": "captured"})

    diff = compute_diff(before, after)
    trace_ref = handle.finish()

    evidence = Evidence(before=before, after=after, diff=diff, trace=trace_ref, chat_log=chat_log)
    verdict = await evaluate(evidence, attack.success_check(), judge_llm)

    return AttackRunResult(attack_id=attack.metadata.id, ctx=ctx, evidence=evidence, verdict=verdict)
