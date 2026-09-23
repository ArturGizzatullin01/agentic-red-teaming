"""src/memnotsafe/generation/rewrite.py — ЧИСТОЕ переписывание атаки по обратной связи.

Функция `rewrite` получает готовый `EscalationFeedback` (его собирает слой
эскалации, у которого есть `AttackResult`) и возвращает следующую запись атаки.
Она НИЧЕГО не знает о таргете и раннере — только просит атакующую LLM составить
улучшенную попытку и разбирает ответ (Принцип I, research §7). Именно эта чистота
делает онлайн-цикл проверяемым офлайн на `StubAttackerClient`.

Невалидный/отказной ответ модели → `None` (отбраковка, FR-012): на онлайн-уровне
это тратит попытку и фиксируется, но не рушит прогон. Сбой самого клиента
(сеть/ключ) — это `AttackerError`, он пробрасывается выше (research §11).

Слои (ARC-1): `EscalationFeedback` берётся из core/escalation_feedback.py, а не
из core/escalation.py; в конце модуля periphery связывает `EscalationBackend`
ядра (rewrite + фабрики записи и исполнителя) — ядро generation не импортирует.
"""

from __future__ import annotations

from memnotsafe.core.escalation_feedback import (
    EscalationBackend,
    EscalationFeedback,
    bind_escalation_backend,
)
from memnotsafe.generation.attacker_client import AttackerClient
from memnotsafe.generation.budget import CallBudget
from memnotsafe.generation.corpus import ORIGIN_ONLINE, CorpusRecord, record_issues
from memnotsafe.generation.corpus_gen import parse_generation_output
from memnotsafe.generation.errors import AttackerError
from memnotsafe.generation.prompts import build_rewrite_prompt


async def rewrite(
    feedback: EscalationFeedback,
    client: AttackerClient,
    budget: CallBudget,
    *,
    ledger=None,
) -> CorpusRecord | None:
    """Следующая запись атаки по обратной связи или None (отбраковка).
    Бюджет тратится ПЕРЕД вызовом — попытка оплачена, даже если ответ негоден.
    Леджер (P10b) наблюдает расход: planned до вызова, executed/unknown_outcome
    после; usage неизвестен клиентскому API → None (не ноль)."""
    system, user = build_rewrite_prompt(feedback)
    budget.spend()
    if ledger is not None:
        ledger.record(
            "attacker_llm", "planned",
            case_id=getattr(feedback, "case_id", None),
            candidate_id=getattr(feedback, "candidate_id", None),
            attempt_no=feedback.attempt,
        )
    try:
        raw = await client.complete(user, system=system)  # AttackerError → выше (exit 1)
    except AttackerError as exc:
        if ledger is not None:
            ledger.record(
                "attacker_llm", "unknown_outcome",
                case_id=getattr(feedback, "case_id", None),
                candidate_id=getattr(feedback, "candidate_id", None),
                attempt_no=feedback.attempt,
                error=str(exc),
            )
        raise
    if ledger is not None:
        ledger.record(
            "attacker_llm", "executed",
            case_id=getattr(feedback, "case_id", None),
            candidate_id=getattr(feedback, "candidate_id", None),
            attempt_no=feedback.attempt,
        )

    record = parse_generation_output(raw, attack_class=feedback.previous.attack_class, origin=ORIGIN_ONLINE)
    if record is None:
        return None  # неразбираемый ответ → отбраковка, попытка потрачена
    # Контракт эффекта наследуется от прошлой записи, если модель его не задала:
    # переписывается формулировка атаки, а тип/поля ожидаемого эффекта — тот же класс.
    if not record.expected_effect:
        record.expected_effect = dict(feedback.previous.expected_effect)
    else:
        # P10a (фича 007): сверка цели через GoalContract — digest из типа
        # эффекта, значений-инвариантов и обязательных доказательств. Смена
        # типа или любого значения («совершить эффект» → «упомянуть эффект»)
        # отбраковывает попытку ДО target (FR-012), а не тихо подменяет цель.
        # Привязки попытки (маркер) в digest не входят: их смена легальна.
        from memnotsafe.core.goal_contract import GoalContract

        previous_contract = GoalContract.from_effect(feedback.previous.expected_effect)
        new_contract = GoalContract.from_effect(record.expected_effect)
        if not previous_contract.same_goal(new_contract):
            return None
    if record_issues(record):
        return None  # нарушены внутренние инварианты записи (FR-012)
    return record


def _generated_attack():
    """Свежий исполнитель переписанной записи. Импорт ленивый: attacks/generated
    сам импортирует generation.corpus, а пакет attacks при импорте ещё не готов."""
    from memnotsafe.attacks.generated import GeneratedAttack

    return GeneratedAttack()


# Связывание онлайн-уровня ядра: импорт этого модуля (его тянет
# generation/__init__.py) = регистрация, по образцу ATTACK_REGISTRY.
bind_escalation_backend(
    EscalationBackend(
        rewrite=rewrite,
        record_from_dict=CorpusRecord.from_dict,
        new_record=CorpusRecord,
        new_attack=_generated_attack,
    )
)
