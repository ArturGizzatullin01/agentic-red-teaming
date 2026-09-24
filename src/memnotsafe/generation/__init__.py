"""src/memnotsafe/generation/ — слой атакующей LLM: генерация корпуса атак под
файл-профиль агента и переписывание атаки по обратной связи.

Роль слоя — чистое ЧТО (Принцип I конституции): здесь живёт знание «как из
профиля и универсального описания класса атаки получить конкретный payload и
триггер», но НЕ знание о таргете (это адаптеры) и НЕ знание о том, КОГДА
повторить атаку (это core/escalation.py). Слой ничего не импортирует из
core/runner.py и не дёргает адаптер: он лишь порождает текст атаки.

Атакующая LLM — отдельный клиент (attacker_client.py), сконфигурированный
независимо от модели цели и судьи (FR-015). Офлайн-путь обеспечивает
StubAttackerClient: детерминированные ответы без сети/ключей, ровно как
MockTarget обеспечивает офлайн-таргет (Принцип VI, SC-006).

ARC-1: импорт пакета связывает backend онлайн-эскалации ядра
(core/escalation_feedback.py) — по образцу attacks/__init__.py: импорт =
регистрация. Ядро само generation не импортирует.
"""

from memnotsafe.generation import rewrite as _rewrite  # noqa: F401

# ARC-2: связывание уровня generation для кампании (шов core/campaign_backend),
# по образцу ARC-1 (rewrite → bind_escalation_backend) и attacks/__init__: импорт
# пакета = регистрация. Конструкторы делают ленивый импорт периферии в МОМЕНТ
# вызова — семантика прежних ленивых `from memnotsafe.generation...` внутри
# методов campaign.py, поэтому monkeypatch модулей generation в тестах
# по-прежнему подхватывается. Тип ошибки атакующей LLM нужен классом для `except`
# в _maybe_escalate — берётся при связывании (generation.errors — лист).
from memnotsafe.core.campaign_backend import (  # noqa: E402
    CampaignBackend,
    bind_campaign_backend,
)
from memnotsafe.generation.errors import AttackerError as _AttackerError  # noqa: E402


def _default_attacker_config():
    from memnotsafe.generation.config import AttackerConfig

    return AttackerConfig()


def _build_attacker_client(config):
    from memnotsafe.generation.attacker_client import build_attacker_client

    return build_attacker_client(config)


def _new_call_budget(limit):
    from memnotsafe.generation.budget import CallBudget

    return CallBudget(limit=limit)


def _read_corpus(path):
    from memnotsafe.generation.corpus import read_corpus

    return read_corpus(path)


def _valid_records(corpus):
    from memnotsafe.generation.corpus import valid_records

    return valid_records(corpus)


def _new_generated_attack():
    from memnotsafe.attacks.generated import GeneratedAttack

    return GeneratedAttack()


def _new_generated_case_params(record_dict, corpus_id):
    from memnotsafe.attacks.generated import PARAM_CORPUS_ID, PARAM_RECORD

    return {PARAM_RECORD: record_dict, PARAM_CORPUS_ID: corpus_id}


bind_campaign_backend(
    CampaignBackend(
        default_attacker_config=_default_attacker_config,
        build_attacker_client=_build_attacker_client,
        new_call_budget=_new_call_budget,
        read_corpus=_read_corpus,
        valid_records=_valid_records,
        new_generated_attack=_new_generated_attack,
        new_generated_case_params=_new_generated_case_params,
        attacker_error=_AttackerError,
    )
)
