"""src/memnotsafe/generation/config.py — конфигурация атакующей LLM.

Атакующая модель конфигурируется ОТДЕЛЬНО от модели цели и модели судьи
(FR-015): у неё свой провайдер, base_url, имя переменной с ключом и бюджет
вызовов. Секрет в конфиг не попадает — только имя переменной окружения
`api_key_env` (FR-016), как у `adapters/openai.py` и судьи.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Провайдеры атакующей LLM. `stub` — офлайн/CI/демо без ключей (детерминированные
# скриптованные ответы), `openai` — живая генерация по OpenAI-совместимому REST.
PROVIDER_STUB = "stub"
PROVIDER_OPENAI = "openai"


@dataclass
class AttackerConfig:
    """Параметры атакующей LLM. По умолчанию — офлайн-`stub`: генерация и
    эскалация проходят без сети и ключей, поведение прогона без `--online`
    совпадает с текущим инструментом (SC-003)."""

    provider: str = PROVIDER_STUB
    model: str | None = None
    base_url: str | None = None
    api_key_env: str = "ATTACKER_API_KEY"
    budget: int = 50
    timeout_s: float = 60.0
    max_retries: int = 2
    # Ответы StubAttackerClient (офлайн). Заполняется тестами и CLI-путём
    # `--attacker-provider stub` (детерминированные записи атак).
    scripted: list[str] | None = field(default=None)


def warn_on_model_collision(config: AttackerConfig, target_model: str | None) -> str | None:
    """FR-015 / research §13: при совпадении модели атакующей LLM с моделью цели
    результат нельзя читать как независимую проверку — модель наследует свои же
    слепые пятна. Спек требует КАК МИНИМУМ предупреждать, а не запрещать: возврат
    строки-предупреждения (или None). Печать — забота CLI, не этого модуля."""
    if config.model and target_model and config.model == target_model:
        return (
            f"[WARN] модель атакующей LLM ({config.model}) совпадает с моделью цели — "
            f"результат наследует её слепые пятна и не является независимой проверкой (FR-015)"
        )
    return None
