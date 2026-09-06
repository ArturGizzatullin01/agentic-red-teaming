# Requirements-quality Checklist: 003-runtime-profiles

**Purpose**: проверка качества требований фичи до реализации.
**Created**: 2026-09-06
**Feature**: [spec.md](../spec.md)

## Полнота

- [ ] A09–A11 покрыты: readback/rollback (US2), async-сервис вне generate (FR-C),
  dataclass-контракты (FR-A)
- [ ] reasoning_content/пустой output/429/timeout — в требованиях и тестах
- [ ] Пресеты определены источником (публичные примеры, не live-конфиг)

## Однозначность

- [ ] «Выбор подтверждён запросом» определён механически (fake transport)
- [ ] inactive vs фиктивная модель различены (provenance)
- [ ] requested vs resolved модель различены (readback-правило)

## Проверяемость

- [ ] Все acceptance scenarios тестируются fake-транспортом/fake process runner
- [ ] Восстановление исходного состояния проверяемо в тесте
- [ ] Прогон без сети обязателен (offline gate)

## Согласованность

- [ ] Имена соответствуют data-model.md и contracts/
- [ ] Нет дублей фактов контрактов интеграции (ссылки)
- [ ] Core-изменения фичи перечислены исчерпывающе в plan.md Project Structure
