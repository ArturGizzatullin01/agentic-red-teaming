# Описания классов атак (`attack_classes/`)

> Версионируемый **вход** генерации корпуса (US1 фичи
> [004-llm-attack-generation](../specs/004-llm-attack-generation/spec.md)). Один YAML на класс —
> универсальная, агент-независимая формулировка того, что атака должна сделать. Связь с рукописной
> family — поле `family` (обязано существовать в `ATTACK_REGISTRY`).

Схема и правила валидации:
[contracts/attack-class.schema.md](../specs/004-llm-attack-generation/contracts/attack-class.schema.md).

Реестр читается `generation/attack_classes.py`. Новый класс = новый файл, без правок Python
(FR-017). Имя файла — ASCII (`attack_classes/<family>.yaml`), содержимое — русское.
