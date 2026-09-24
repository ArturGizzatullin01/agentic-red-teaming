"""src/memnotsafe/core/campaign_backend.py — ARC-2: шов уровня generation для
кампании (расщепление core/campaign.py). Ядро (core/campaign*.py) конструирует
атакующего клиента, бюджет и корпусные случаи и ловит ошибку атакующей LLM
ЧЕРЕЗ этот контракт — не импортируя `memnotsafe.generation` и
`attacks.generated` ни на каком уровне.

Реализацию связывает периферия при импорте пакета `memnotsafe.generation`
(generation/__init__.py вызывает `bind_campaign_backend`) — по образцу ARC-1
`bind_escalation_backend` и attacks/__init__.py (импорт = регистрация). В любом
пути, где кампания вообще пригодна, пакет generation уже импортирован
транзитивно (core/campaign.py → attacks.base → attacks/__init__ →
attacks.generated → generation.*), так что backend связан до первого обращения.

Функции-конструкторы делают ленивый импорт периферии в момент ВЫЗОВА (а не при
связывании): семантика прежняя — как ленивые `from memnotsafe.generation...`
внутри методов кампании до ARC-2, поэтому monkeypatch модулей generation в
тестах по-прежнему подхватывается.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class CampaignBackend:
    """Конструкторы уровня generation, нужные кампании, + тип ошибки атакующей
    LLM для границы эскалации. Ядро дергает их по имени, типы объектов —
    duck-typed (как AttackRecord в ARC-1)."""

    # онлайн-уровень: атакующий клиент и бюджет
    default_attacker_config: Callable[[], Any]
    build_attacker_client: Callable[[Any], Any]
    new_call_budget: Callable[[int], Any]
    # family='generated': корпус и его атака
    read_corpus: Callable[[str], Any]
    valid_records: Callable[[Any], Any]
    new_generated_attack: Callable[[], Any]
    new_generated_case_params: Callable[[dict[str, Any], str], dict[str, Any]]
    # граница ошибки атакующей LLM (для `except` в _maybe_escalate)
    attacker_error: type[BaseException]


_backend: CampaignBackend | None = None


def bind_campaign_backend(backend: CampaignBackend) -> None:
    """Связать реализацию уровня generation. Вызывается один раз при импорте
    пакета `memnotsafe.generation` (generation/__init__.py)."""
    global _backend
    _backend = backend


def campaign_backend() -> CampaignBackend:
    if _backend is None:
        raise RuntimeError(
            "уровень generation кампании не связан: импортируйте memnotsafe.generation "
            "(generation/__init__.py связывает backend при импорте) до конструирования "
            "атакующего клиента / корпусных случаев"
        )
    return _backend
