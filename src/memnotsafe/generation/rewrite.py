"""src/memnotsafe/generation/rewrite.py — ЧИСТОЕ переписывание атаки по обратной связи.

Функция `rewrite` получает готовый `EscalationFeedback` (его собирает слой
эскалации, у которого есть `AttackResult`) и возвращает следующую запись атаки.
Она НИЧЕГО не знает о таргете и раннере — только просит атакующую LLM составить
улучшенную попытку и разбирает ответ (Принцип I, research §7). Именно эта чистота
делает онлайн-цикл проверяемым офлайн на `StubAttackerClient`.

Невалидный/отказной ответ модели → `None` (отбраковка, FR-012): на онлайн-уровне
это тратит попытку и фиксируется, но не рушит прогон. Сбой самого клиента
(сеть/ключ) — это `AttackerError`, он пробрасывается выше (research §11).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from memnotsafe.generation.attacker_client import AttackerClient
from memnotsafe.generation.budget import CallBudget
from memnotsafe.generation.corpus import ORIGIN_ONLINE, CorpusRecord, record_issues
from memnotsafe.generation.corpus_gen import parse_generation_output
from memnotsafe.generation.prompts import build_rewrite_prompt

if TYPE_CHECKING:
    from memnotsafe.core.escalation import EscalationFeedback


async def rewrite(feedback: EscalationFeedback, client: AttackerClient, budget: CallBudget) -> CorpusRecord | None:
    """Следующая запись атаки по обратной связи или None (отбраковка).
    Бюджет тратится ПЕРЕД вызовом — попытка оплачена, даже если ответ негоден."""
    system, user = build_rewrite_prompt(feedback)
    budget.spend()
    raw = await client.complete(user, system=system)  # AttackerError → выше (exit 1)

    record = parse_generation_output(raw, attack_class=feedback.previous.attack_class, origin=ORIGIN_ONLINE)
    if record is None:
        return None  # неразбираемый ответ → отбраковка, попытка потрачена
    # Контракт эффекта наследуется от прошлой записи, если модель его не задала:
    # переписывается формулировка атаки, а тип/поля ожидаемого эффекта — тот же класс.
    if not record.expected_effect:
        record.expected_effect = dict(feedback.previous.expected_effect)
    if record_issues(record):
        return None  # нарушены внутренние инварианты записи (FR-012)
    return record
