"""src/memnotsafe/core/escalation.py — онлайн-цикл эскалации (US2).

Принцип I: «Runner знает КОГДА». Эскалация — это и есть решение «когда повторить
атаку», поэтому её место в слое раннера/кампании, а НЕ в пакете генерации и не
внутри атаки. Цикл вызывает НЕМОДИФИЦИРОВАННЫЙ `run_attack` вокруг одного вызова,
подставляя переписанную запись через `AttackContext.params` (SC-008, research §6).

Тристейт воронки прошлой попытки переносится в обратную связь КАК ЕСТЬ — `None`
не схлопывается в `True` (Принцип IV). Стоимость и число попыток пишутся в
`AttackResult.evidence["provenance"]` (research §12): раннер и модели не трогаются.

Два свойства принадлежат ПРОГОНУ и ПОПЫТКЕ, а не копии базового контекста:

* **Судья** — свойство прогона. Если начальную попытку судили, повторы обязаны
  судиться ТЕМ ЖЕ судьёй: иначе успех/провал внутри одного случая меряются
  разными линейками, а `verdict_source` попыток несопоставим. Поэтому `judge`
  передаётся в `escalate` и дальше в каждый `run_attack` как есть (набор
  судимых стадий не меняется, FR-014).
* **Case-маркер** — свойство ПОПЫТКИ: он производный от `case_id`, а у повтора
  `case_id` новый. `run_attack` проставляет маркер в контекст НА МЕСТЕ, поэтому
  `replace(base_ctx, ...)` унёс бы в повтор маркер прошлой попытки — чужую
  канарейку, по которой WRITE-матчер атрибутировал бы записи не того случая
  (T002-10, FR-B). Маркер повтора гасится в None: производителем остаётся
  раннер, он выведет его из нового `case_id`.

Слои (ARC-1): ядро не импортирует generation/attacks.generated. Всё, что цикл
берёт у периферии (rewrite, запись корпуса, исполнитель переписанной записи),
приходит через `EscalationBackend` из core/escalation_feedback.py — его
связывает generation при импорте пакета. `EscalationFeedback` живёт там же и
реэкспортируется отсюда: публичное имя `core.escalation.EscalationFeedback`
прежнее.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any

from memnotsafe.attacks.base import AttackBase, AttackContext
from memnotsafe.core.attempt import (
    OUTCOME_REWRITE_ACCEPTED,
    OUTCOME_REWRITE_REJECTED,
    OUTCOME_TRANSPORT_ERROR,
    outcome_of_result,
    sessions_from_transcript,
)
from memnotsafe.core.escalation_feedback import (
    ORIGIN_CORPUS,
    ORIGIN_ONLINE,
    AttackRecord,
    EscalationBackend,
    EscalationFeedback,
    escalation_backend,
)
from memnotsafe.core.goal_contract import goal_digest_or_none
from memnotsafe.core.ledger import (
    OP_TARGET_CALL,
    PHASE_BLOCKED,
    PHASE_EXECUTED,
    PHASE_UNKNOWN_OUTCOME,
)
from memnotsafe.core.models import AttackResult
from memnotsafe.core.runner import CaseMarkerError, RunnerError, new_case_id, run_attack
from memnotsafe.tracing.recorder import TraceRecorder


@dataclass
class EscalationOutcome:
    result: AttackResult
    attempts: int
    succeeded: bool
    budget_exhausted: bool


def _initial_record(base_ctx: AttackContext, result: AttackResult, backend: EscalationBackend) -> AttackRecord:
    """Запись, с которой стартует эскалация: из корпуса (params) либо синтез из
    candidate рукописной атаки — так онлайн-уровень работает и над рукописным
    паком (US2 независимость)."""
    raw = (base_ctx.params or {}).get("record")
    if isinstance(raw, dict):
        return backend.record_from_dict(raw)
    cand = result.evidence.get("candidate", {}) or {}
    prov = result.evidence.get("provenance", {}) or {}
    return backend.new_record(
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
    client: Any,
    budget: Any,
    run_id: str,
    recorder: TraceRecorder | None = None,
    judge: Any | None = None,
    require_case_marker: bool = False,
    history: Any | None = None,
    ledger: Any | None = None,
    bundle_writer: Any | None = None,
) -> EscalationOutcome:
    """Цикл: пока не успех, не исчерпан лимит попыток и не исчерпан бюджет —
    переписываем атаку по обратной связи и пробуем снова. Стоп на первом успехе
    (SC-004). Начальный (корпусный) прогон считается попыткой №1.

    `judge` — тот же судья, которым вызывающий слой судил начальную попытку;
    по умолчанию его нет, и тогда повторы судятся ровно как раньше (офлайн,
    без сети и ключей).

    `require_case_marker` — то же требование наличия маркера в доставке, что у
    начальной попытки: у повтора маркер НОВЫЙ (производный от нового case_id),
    но объявленное требование не гасится — переписанная запись без плейсхолдера
    {case_marker} отклоняется раннером до доставки, а не тихо уходит в legacy.

    `client` (AttackerClient) и `budget` (CallBudget) — объекты слоя generation;
    ядро их не типизирует (правило слоёв ARC-1): здесь читается только
    `budget.exhausted`, остальное уходит в `backend.rewrite` как есть."""
    backend = escalation_backend()

    corpus_id = (base_ctx.params or {}).get("corpus_id")
    attempts = 1
    last = initial_result
    if last.success:
        return EscalationOutcome(last, attempts=attempts, succeeded=True, budget_exhausted=budget.exhausted)

    previous = _initial_record(base_ctx, initial_result, backend)
    adapted = False
    # P10b: candidate lineage — первый кандидат = начальный case_id; каждый
    # принятый rewrite = новый кандидат с parent_candidate_id (case_id общий).
    previous_candidate_id = base_ctx.case_id

    while attempts < limit:
        if budget.exhausted:
            # Существующий бюджет отказал: леджер фиксирует блокировку (без
            # собственного списания), штатный стоп — уже полученный результат
            # сохраняется.
            if ledger is not None:
                ledger.record(
                    "attacker_llm", PHASE_BLOCKED, case_id=base_ctx.case_id,
                    candidate_id=previous_candidate_id,
                )
            break  # штатный стоп по бюджету — уже полученный результат сохраняется

        feedback = EscalationFeedback(
            victim_response=str(last.evidence.get("victim_response", "")),
            baseline_response=str(last.evidence.get("baseline_response", "")),
            funnel={s.stage: s.success for s in last.stages},
            previous=previous,
            attempt=attempts + 1,
            case_id=base_ctx.case_id,
            candidate_id=previous_candidate_id,
        )
        # Сбой атакующей LLM (AttackerError) пробрасывается: уже полученные
        # результаты сохранит вызывающий слой кампании (FR-010/FR-011).
        new_record = await backend.rewrite(feedback, client, budget, ledger=ledger)
        attempts += 1
        adapted = True
        if new_record is None:
            # невалидный ответ модели → отбраковка тратит попытку (FR-012);
            # отклонённый кандидат НЕ доходит до target и попадает в историю
            if history is not None:
                history.record(
                    case_id=base_ctx.case_id,
                    candidate_id=previous_candidate_id,
                    outcome=OUTCOME_REWRITE_REJECTED,
                    attempt_no=0,
                    goal_digest=goal_digest_or_none(previous.expected_effect),
                )
            continue

        previous = new_record
        gen = backend.new_attack()  # свежий исполнитель переписанной записи
        new_ctx = replace(
            base_ctx,
            case_id=new_case_id(new_record.attack_class, attempts),
            params={"record": new_record.to_dict(), "corpus_id": corpus_id},
            # маркер прошлой попытки в новый case_id не переезжает (см. докстринг)
            case_marker=None,
        )
        parent_candidate_id = previous_candidate_id
        if history is not None:
            history.record(
                case_id=base_ctx.case_id,
                candidate_id=new_ctx.case_id,
                parent_candidate_id=parent_candidate_id,
                outcome=OUTCOME_REWRITE_ACCEPTED,
                attempt_no=0,
                goal_digest=goal_digest_or_none(new_record.expected_effect),
            )
        previous_candidate_id = new_ctx.case_id
        try:
            last = await run_attack(
                gen, new_ctx, target, run_id=run_id, recorder=recorder, judge=judge,
                require_case_marker=require_case_marker,
            )
        except CaseMarkerError:
            # LIVE-COVERAGE: rewrite живого атакующего потерял {case_marker}. По
            # контракту (докстринг выше) это ОТБРАКОВКА попытки, а НЕ FATAL всей
            # кампании: фиксируем rewrite_rejected, попытка потрачена (бюджет уже
            # списан в backend.rewrite) и продолжаем в пределах лимита/бюджета.
            # Настоящий транспортный RunnerError по-прежнему пробрасывается ниже.
            if history is not None:
                history.record(
                    case_id=base_ctx.case_id,
                    candidate_id=new_ctx.case_id,
                    parent_candidate_id=parent_candidate_id,
                    outcome=OUTCOME_REWRITE_REJECTED,
                    attempt_no=attempts,
                    goal_digest=goal_digest_or_none(new_record.expected_effect),
                )
            continue
        except RunnerError as exc:
            # Транспортный сбой повтора: в историю (candidate тот же — retry не
            # новый кандидат), затем НЕ глотаем — exit-контракт CLI.
            if ledger is not None:
                ledger.record(
                    OP_TARGET_CALL, PHASE_UNKNOWN_OUTCOME,
                    case_id=base_ctx.case_id, candidate_id=new_ctx.case_id,
                    attempt_no=attempts, error=str(exc),
                )
            if history is not None:
                history.record(
                    case_id=base_ctx.case_id,
                    candidate_id=new_ctx.case_id,
                    parent_candidate_id=parent_candidate_id,
                    outcome=OUTCOME_TRANSPORT_ERROR,
                    attempt_no=attempts,
                    case_marker=new_ctx.case_marker,
                    seed=new_ctx.run_seed,
                    error=str(exc),
                )
            raise
        if ledger is not None:
            ledger.record(
                OP_TARGET_CALL, PHASE_EXECUTED,
                case_id=base_ctx.case_id, candidate_id=new_ctx.case_id,
                attempt_no=attempts,
            )
        if bundle_writer is not None:
            # Пакет доказательств для КАЖДОЙ попытки эскалации (не только
            # финальной): attempt_no/parent согласованы с attempts.jsonl.
            bundle_writer(last, new_ctx.case_id, parent_candidate_id, attempts)
        if history is not None:
            history.record(
                case_id=base_ctx.case_id,
                candidate_id=new_ctx.case_id,
                parent_candidate_id=parent_candidate_id,
                outcome=outcome_of_result(last),
                attempt_no=attempts,
                case_marker=last.evidence.get("case_marker") or new_ctx.case_marker,
                goal_digest=goal_digest_or_none((last.evidence.get("candidate") or {}).get("expected_effect")),
                session_ids=sessions_from_transcript(last.evidence.get("transcript")),
            )
        if last.success:
            annotated = _annotate(last, attempts=attempts, budget_exhausted=budget.exhausted, adapted=True, corpus_id=corpus_id)
            return EscalationOutcome(annotated, attempts=attempts, succeeded=True, budget_exhausted=budget.exhausted)

    annotated = _annotate(last, attempts=attempts, budget_exhausted=budget.exhausted, adapted=adapted, corpus_id=corpus_id)
    return EscalationOutcome(annotated, attempts=attempts, succeeded=False, budget_exhausted=budget.exhausted)
