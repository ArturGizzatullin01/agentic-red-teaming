"""src/memnotsafe/core/escalation_feedback.py — контракт онлайн-уровня со
стороны ядра (ARC-1: разрыв цикла core ↔ generation).

Ядро знает КОГДА повторить атаку (core/escalation.py, Принцип I); периферия
знает КАК получить следующую запись (generation/rewrite.py). Правило слоёв:
`core.*` не импортирует `generation.*` и `attacks.generated` ни на каком
уровне, обратное разрешено. Поэтому всё, что обе стороны разделяют, лежит в
этом листовом модуле (импортирует только core/models.py):

* `EscalationFeedback` — вход чистой `rewrite()`: собирает цикл эскалации,
  читает generation. Периферия импортирует тип ОТСЮДА, а не из
  core/escalation.py — иначе замыкается цикл prompts → escalation → rewrite.
* `AttackRecord` — минимальный протокол записи атаки, который нужен циклу
  (в generation его реализует `CorpusRecord`).
* `EscalationBackend` + `bind_escalation_backend()` / `escalation_backend()` —
  шов инъекции: периферия связывает реализацию (rewrite, фабрики записи и
  исполнителя) при импорте пакета `memnotsafe.generation` (см.
  generation/__init__.py и generation/rewrite.py) — по образцу ATTACK_REGISTRY:
  импорт пакета = регистрация. Ядро реализацию только вызывает и само
  generation не импортирует.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Protocol

from memnotsafe.core.models import StageVerdict

# Происхождение записи в провенансе результата (значения — контракт артефактов,
# те же строки пишет слой кампании).
ORIGIN_CORPUS = "corpus"
ORIGIN_ONLINE = "online"


class AttackRecord(Protocol):
    """Запись атаки глазами цикла эскалации: класс, тексты, ожидаемый эффект и
    сериализация в `AttackContext.params`. Остальные поля записи ядру не нужны."""

    attack_class: str
    payload: str
    trigger: str
    expected_effect: dict[str, Any]

    def to_dict(self) -> dict[str, Any]: ...


@dataclass
class EscalationFeedback:
    """Вход чистой `rewrite()` (research §7). Воронка — тристейт как есть."""

    victim_response: str
    baseline_response: str
    funnel: dict[str, StageVerdict]
    previous: AttackRecord
    attempt: int
    # P10b: привязка расхода атакующей LLM к попытке; заполняет цикл
    # эскалации, для чистой rewrite() это только данные.
    case_id: str | None = None
    candidate_id: str | None = None


@dataclass(frozen=True)
class EscalationBackend:
    """Реализация онлайн-уровня, которую ядро получает извне.

    rewrite(feedback, client, budget, *, ledger=None) -> AttackRecord | None —
        следующая запись по обратной связи или None (отбраковка);
    record_from_dict(raw) -> AttackRecord — запись из `params["record"]`;
    new_record(*, attack_class, payload, trigger, expected_effect, origin) ->
        AttackRecord — синтез записи из candidate рукописной атаки;
    new_attack() -> AttackBase — свежий исполнитель переписанной записи.
    """

    rewrite: Callable[..., Awaitable[AttackRecord | None]]
    record_from_dict: Callable[[dict[str, Any]], AttackRecord]
    new_record: Callable[..., AttackRecord]
    new_attack: Callable[[], Any]


_backend: EscalationBackend | None = None


def bind_escalation_backend(backend: EscalationBackend) -> None:
    """Связать реализацию онлайн-уровня. Вызывается периферией при импорте;
    повторное связывание заменяет предыдущее."""
    global _backend
    _backend = backend


def escalation_backend() -> EscalationBackend:
    """Связанная реализация онлайн-уровня. Без импорта `memnotsafe.generation`
    её нет — это ошибка сборки вызывающего слоя, а не ядра."""
    if _backend is None:
        raise RuntimeError(
            "онлайн-уровень эскалации не связан: импортируйте memnotsafe.generation "
            "(generation/rewrite.py связывает backend при импорте) до вызова escalate()"
        )
    return _backend
