"""src/memnotsafe/attacks/ — pluggable attack packs. Импорт модуля здесь регистрирует
его класс(ы) в ATTACK_REGISTRY через AttackBase.__init_subclass__ (см. base.py).
Новая атака = новый файл + одна строка импорта здесь (или прямой импорт модуля
вызывающим кодом — тоже сработает благодаря __init_subclass__)."""

from memnotsafe.attacks import (  # noqa: F401
    consent_laundering,
    contact_supersede,
    cross_lingual_insertion,
    cross_topic_smuggle,
    cross_user_bac,
    direct_poisoning,
    document_regulation_graft,
    fake_shared_past,
    false_precedent,
    generated,
    procedural_graft,
    recommendation_hijack,
    scope_escalation,
    system_log_impersonation,
    tool_argument_hijack,
    tool_error_echo_poisoning,
)
from memnotsafe.attacks.base import ATTACK_REGISTRY, AttackBase, get_attack  # noqa: F401
