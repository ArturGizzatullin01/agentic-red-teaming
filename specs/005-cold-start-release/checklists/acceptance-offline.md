# Acceptance Checklist: offline gate (005)

**Purpose**: приёмка офлайн-готовности выпуска.
**Created**: 2026-09-06
**Feature**: [spec.md](../spec.md); источник —
[acceptance.md](../../../docs/integration-handoff/acceptance.md)

Отмечать `[x]` только по факту проверки, не по ожиданию.

- [ ] Чистые Windows/Linux окружения; wheel установлен вне src checkout
- [ ] Исполнение mock без сети, LLM, Docker, Mongo и ключей
- [ ] Все старые тесты и regression-тесты фичей 002–004 проходят
- [ ] Пять основных атак зарегистрированы; CLI неизвестного family даёт понятную ошибку
- [ ] Vulnerable mock даёт подтверждённый positive, protected — negative
- [ ] Ни одна заглушка не возвращает success независимо от поведения
- [ ] Missing telemetry отображается UNKNOWN; composite truth table не изменена
- [ ] Ошибка runner/adapter/config — exit 1; честный negative — exit 0
- [ ] Report и replay сохраняют provenance, Unicode и исходные evidence
- [ ] Поставка не зависит от абсолютных путей автора и не содержит секретов
