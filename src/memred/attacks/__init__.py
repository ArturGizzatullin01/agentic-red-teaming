"""src/memred/attacks/ — pluggable attack packs. Импорт модуля здесь регистрирует
его класс(ы) в ATTACK_REGISTRY через AttackBase.__init_subclass__ (см. base.py).
Новая атака = новый файл + одна строка импорта здесь (или прямой импорт модуля
вызывающим кодом — тоже сработает благодаря __init_subclass__)."""

from memred.attacks import (  # noqa: F401
    cross_user_bac,
    direct_poisoning,
    false_precedent,
    scope_escalation,
    tool_argument_hijack,
)
from memred.attacks.base import ATTACK_REGISTRY, AttackBase, get_attack  # noqa: F401
