"""src/memnotsafe/core/escalation.py — онлайн-цикл эскалации (US2).

Принцип I: «Runner знает КОГДА». Эскалация — это и есть решение «когда повторить
атаку», поэтому её место в слое раннера/кампании, а НЕ в пакете генерации и не
внутри атаки. Цикл вызывает НЕМОДИФИЦИРОВАННЫЙ `run_attack` вокруг одного вызова,
подставляя переписанную запись через `AttackContext.params` (SC-008, research §6).

Тристейт воронки прошлой попытки переносится в обратную связь КАК ЕСТЬ — `None`
не схлопывается в `True` (Принцип IV). Стоимость и число попыток пишутся в
`AttackResult.evidence["provenance"]` (research §12): раннер и модели не трогаются.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any

from memnotsafe.attacks.base import AttackBase, AttackContext
from memnotsafe.core.models import AttackResult, StageVerdict
from memnotsafe.core.runner import new_case_id, run_attack
from memnotsafe.generation.attacker_client import AttackerClient
from memnotsafe.generation.budget import CallBudget
from memnotsafe.generation.corpus import ORIGIN_CORPUS, ORIGIN_ONLINE, CorpusRecord
from memnotsafe.generation.rewrite import rewrite
from memnotsafe.tracing.recorder import TraceRecorder


@dataclass
class EscalationFeedback:
    """Вход чистой `rewrite()` (research §7). Воронка — тристейт как есть."""

    victim_response: str
    baseline_response: str
    funnel: dict[str, StageVerdict]
    previous: CorpusRecord
    attempt: int


@dataclass
class EscalationOutcome:
    result: AttackResult
    attempts: int
    succeeded: bool
    budget_exhausted: bool


def _initial_record(base_ctx: AttackContext, result: AttackResult) -> CorpusRecord:
    """Запись, с которой стартует эскалация: из корпуса (params) либо синтез из
    candidate рукописной атаки — так онлайн-уровень работает и над рукописным
    паком (US2 независимость)."""
    raw = (base_ctx.params or {}).get("record")
    if isinstance(raw, dict):
        return CorpusRecord.from_dict(raw)
    cand = result.evidence.get("candidate", {}) or {}
    prov = result.evidence.get("provenance", {}) or {}
    return CorpusRecord(
        attack_class=prov.get("attack_class") or result.scenario_id,
        payload=str(cand.get("payload", "")),
        trigger=str(cand.get("trigger", "")),
        expected_effect=dict(cand.get("expected_effect") or {}),
        origin=ORIGIN_CORPUS,
    )


def _annotate(result: AttackResult, *, attempts: int, budget_exhausted: bool, adapted: bool, corpus_id: Any) -> AttackResult:
    """Провенанс онлайн-уровня в evidence (FR-013/FR-014). origin становится
    'online' только если реально была адаптация (хотя бы одна переписанная
    попытка); иначе остаётся тем, что проставил слой кампании (corpus/handwritten)."""
    prov = dict(result.evidence.get("provenance") or {})
    prov["attempts"] = attempts
    prov["budget_exhausted"] = budget_exhausted
    if corpus_id is not None and "corpus_id" not in prov:
        prov["corpus_id"] = corpus_id
    if adapted:
        prov["origin"] = ORIGIN_ONLINE
    result.evidence["provenance"] = prov
    return result


async def escalate(
    attack: AttackBase,
    base_ctx: AttackContext,
    target: Any,
    initial_result: AttackResult,
    *,
    limit: int,
    client: AttackerClient,
    budget: CallBudget,
    run_id: str,
    recorder: TraceRecorder | None = None,
) -> EscalationOutcome:
    """Цикл: пока не успех, не исчерпан лимит попыток и не исчерпан бюджет —
    переписываем атаку по обратной связи и пробуем снова. Стоп на первом успехе
    (SC-004). Начальный (корпусный) прогон считается попыткой №1."""
    from memnotsafe.attacks.generated import GeneratedAttack

    corpus_id = (base_ctx.params or {}).get("corpus_id")
    attempts = 1
    last = initial_result
    if last.success:
        return EscalationOutcome(last, attempts=attempts, succeeded=True, budget_exhausted=budget.exhausted)

    previous = _initial_record(base_ctx, initial_result)
    adapted = False

    while attempts < limit:
        if budget.exhausted:
            break  # штатный стоп по бюджету — уже полученный результат сохраняется

        feedback = EscalationFeedback(
            victim_response=str(last.evidence.get("victim_response", "")),
            baseline_response=str(last.evidence.get("baseline_response", "")),
            funnel={s.stage: s.success for s in last.stages},
            previous=previous,
            attempt=attempts + 1,
        )
        # Сбой атакующей LLM (AttackerError) пробрасывается: уже полученные
        # результаты сохранит вызывающий слой кампании (FR-010/FR-011).
        new_record = await rewrite(feedback, client, budget)
        attempts += 1
        adapted = True
        if new_record is None:
            continue  # невалидный ответ модели → отбраковка тратит попытку (FR-012)

        previous = new_record
        gen = GeneratedAttack()  # свежий исполнитель переписанной записи
        new_ctx = replace(
            base_ctx,
            case_id=new_case_id(new_record.attack_class, attempts),
            params={"record": new_record.to_dict(), "corpus_id": corpus_id},
        )
        last = await run_attack(gen, new_ctx, target, run_id=run_id, recorder=recorder)
        if last.success:
            annotated = _annotate(last, attempts=attempts, budget_exhausted=budget.exhausted, adapted=True, corpus_id=corpus_id)
            return EscalationOutcome(annotated, attempts=attempts, succeeded=True, budget_exhausted=budget.exhausted)

    annotated = _annotate(last, attempts=attempts, budget_exhausted=budget.exhausted, adapted=adapted, corpus_id=corpus_id)
    return EscalationOutcome(annotated, attempts=attempts, succeeded=False, budget_exhausted=budget.exhausted)
