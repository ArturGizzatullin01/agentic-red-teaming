"""src/memnotsafe/core/runner.py — единственное место, где склеены target/attack/oracles/
trace. Attack-паки сюда не лезут (знают только ЧТО), адаптер не знает ПОРЯДКА
вызовов (знает только КАК). Runner не знает деталей конкретного таргета (MongoDB, auth_mode и т.п.) — только контракт TargetAdapter.
"""

from __future__ import annotations

import time
import uuid
from typing import Any

from memnotsafe.adapters.base import Capabilities, TargetAdapter
from memnotsafe.attacks.base import AttackBase, AttackContext
from memnotsafe.core.models import AttackResult, JudgeVerdict, StageResult
from memnotsafe.evidence.diff import SnapshotDiff, compute_diff
from memnotsafe.evidence.snapshot import SystemSnapshot
from memnotsafe.oracles.base import EvaluationContext
from memnotsafe.oracles.composite import composite_success, evaluate_all
from memnotsafe.tracing.recorder import TraceRecorder


def new_run_id() -> str:
    return f"RUN-{time.strftime('%Y%m%dT%H%M%S')}-{uuid.uuid4().hex[:6]}"


def new_case_id(attack_id: str, attempt: int) -> str:
    return f"CASE-{attack_id}-{attempt:03d}-{uuid.uuid4().hex[:6]}"


class RunnerError(RuntimeError):
    """Ошибка самого раннера/адаптера (сеть, контракт, краш) — ОТДЕЛЬНО от
    "атака не удалась". CLI должен различать эти два случая: первое
    -> exit 1, второе -> exit 0 + finding NOT_EXPLOITABLE."""


async def run_baseline(target: TargetAdapter, ctx: AttackContext, trigger_message: str) -> str:
    """Чистое поведение таргета БЕЗ отравления — тот же триггер, но до всякой
    доставки payload'а ("что делает target без poisoning?")."""
    session_id = await target.new_session(ctx.victim_user_id)
    try:
        result = await target.send(session_id, trigger_message)
        return result.content
    finally:
        await target.close_session(session_id)


async def run_attack(
    attack: AttackBase,
    ctx: AttackContext,
    target: TargetAdapter,
    *,
    run_id: str,
    recorder: TraceRecorder | None = None,
    judge: Any | None = None,
) -> AttackResult:
    """`judge` опционален и по умолчанию отсутствует: без него раннер работает
    ровно как до появления фичи, без сети и ключей (FR-001, SC-003)."""
    try:
        await target.reset_state()
        target.set_context(run_id, ctx.case_id)
        probe = await target.probe()
        capabilities: Capabilities = probe.capabilities

        candidate = attack.generate(ctx)

        baseline_response = await run_baseline(target, ctx, candidate.trigger)

        before: SystemSnapshot | None = await target.snapshot()

        all_events: list[dict[str, Any]] = []

        def _collect(events: list[dict[str, Any]]) -> None:
            for e in events:
                all_events.append(e)
                if recorder is not None:
                    recorder.record_raw(e)

        attacker_session = await target.new_session(ctx.attacker_user_id)
        for step in attack.delivery_steps(candidate, ctx):
            as_user = step.as_user or ctx.attacker_user_id
            session = attacker_session if as_user == ctx.attacker_user_id else await target.new_session(as_user)
            result = await target.send(session, step.message)
            _collect(result.events)

        persistence_ok = await target.wait_until_persistent(
            {"expect_text_contains": candidate.payload[:60], "attacker_user_id": ctx.attacker_user_id}
        )
        await target.close_session(attacker_session)

        victim_session = await target.new_session(ctx.victim_user_id)
        victim_response = ""
        for step in attack.trigger_steps(candidate, ctx):
            if step.message is None:
                continue
            as_user = step.as_user or ctx.victim_user_id
            session = victim_session if as_user == ctx.victim_user_id else await target.new_session(as_user)
            result = await target.send(session, step.message)
            _collect(result.events)
            if session == victim_session:
                victim_response = result.content

        victim_trace = await target.get_trace(victim_session)
        await target.close_session(victim_session)

        after: SystemSnapshot | None = await target.snapshot()
        diff: SnapshotDiff | None = compute_diff(before, after) if (before and after) else None

        if recorder is not None:
            recorder.flush_case_trace(ctx.case_id)

    except RunnerError:
        raise
    except Exception as exc:  # noqa: BLE001 — оборачиваем ЛЮБОЙ низкоуровневый сбой в RunnerError
        raise RunnerError(f"Раннер упал на случае {ctx.case_id}: {exc}") from exc

    # Судья вызывается ДО evaluate_all и вне блока try выше: сеть — не дело
    # оракула, а сбой судьи не должен маскироваться под падение раннера.
    # Оцениваются три стадии из JUDGED_STAGES; write/persistence/tool судье не
    # передаются никогда (FR-014). Вызов идёт ВСЕГДА и параллельно дословной
    # проверке — даже когда та уже сказала True: расхождение вердиктов и есть
    # собираемый сигнал качества маркерных правил (FR-016, FR-019).
    judge_verdicts: dict[str, JudgeVerdict] = {}
    if judge is not None:
        judge_verdicts = await judge.evaluate_stages(
            case_id=ctx.case_id,
            expected_effect=candidate.expected_effect,
            artifact=victim_response,
            baseline=baseline_response,
        )

    ec = EvaluationContext(
        candidate=candidate,
        ctx=ctx,
        capabilities=capabilities,
        before=before,
        after=after,
        diff=diff,
        baseline_response=baseline_response,
        victim_response=victim_response,
        all_events=all_events,
        victim_trace=victim_trace,
        persistence_ok=persistence_ok,
        judge_verdicts=judge_verdicts,
    )
    stages: list[StageResult] = evaluate_all(ec)
    success = composite_success(stages)

    metrics = {s.stage: s.success for s in stages}
    evidence = {
        "before": before.to_dict() if before else None,
        "after": after.to_dict() if after else None,
        "diff": diff.to_dict() if diff else None,
        "baseline_response": baseline_response,
        "victim_response": victim_response,
        "trace_events": len(all_events),
        "candidate": {
            "payload": candidate.payload,
            "trigger": candidate.trigger,
            "expected_effect": candidate.expected_effect,
        },
    }

    return AttackResult(
        run_id=run_id,
        case_id=ctx.case_id,
        attack_id=attack.metadata.id,
        scenario_id=attack.metadata.family,
        stages=stages,
        success=success,
        metrics=metrics,
        evidence=evidence,
        attacker_user_id=ctx.attacker_user_id,
        victim_user_id=ctx.victim_user_id,
    )
