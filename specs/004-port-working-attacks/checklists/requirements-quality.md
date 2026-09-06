# Requirements-quality Checklist: 004-port-working-attacks

**Purpose**: проверка качества требований фичи до реализации.
**Created**: 2026-09-06
**Feature**: [spec.md](../spec.md)

## Полнота

- [ ] Все 9 семейств таблицы контрактов распределены по задачам (5 P1 + 4 P2)
- [ ] Каждая атака имеет positive/negative/insufficient-observation тесты
- [ ] Protected-negative для каждой техники на mock

## Однозначность

- [ ] original_channel vs effective_channel различены с примерами
- [ ] Соответствие ролей донор→команда зафиксировано (victim→attacker, witness→victim)
- [ ] Порядок «основной → варианты» (global, natural) зафиксирован в задачах

## Проверяемость

- [ ] Реестр: unknown family → понятная ошибка, exit 1 (тест)
- [ ] Mock не привязан к attack_id (параметризация по семействам)
- [ ] Core-дифф пуст — проверяемое условие gate

## Согласованность

- [ ] Оракулы P2-атак определены во фиче 002 (policy_evicted — отложен туда явно)
- [ ] Источники payload'ов указаны (донорские pack.py, передаются отдельно)
- [ ] Ссылки резолвятся в дереве
