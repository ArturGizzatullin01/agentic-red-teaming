# Корпуса атак (`corpora/`)

> **Выход** команды `generate` и **вход** прогона `run`/`campaign` (US1 фичи
> [004-llm-attack-generation](../specs/004-llm-attack-generation/spec.md)). Сохранённый
> переиспользуемый набор конкретных атак под формат профиля, с зафиксированным происхождением.

Схема и правила валидации:
[contracts/corpus.schema.md](../specs/004-llm-attack-generation/contracts/corpus.schema.md).

**Коммитится** (в отличие от `runs/`/`reports/`): корпус воспроизводим только ценой повторной
оплаты LLM, а переиспользование между агентами требует его как версионируемый вход (SC-002).
Читается/пишется `generation/corpus.py`. Имя файла — ASCII (`corpora/<name>.yaml`).
