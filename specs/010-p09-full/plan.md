# Plan: 010 — P09-full offline

## Архитектура (аддитивно, без изменения ядра)

```
adapters/mock.py            tool_call_prepared (additive event, тот же call_id)
                            + context_tool_evidence() — сырые ФАКТЫ адаптера
evidence/telemetry.py (new) TELEMETRY_PHASES (m1-delivery/m2-pretrigger/m3-trigger-finalize)
                            parse_context_tool_evidence() — строгая схема v1
                            build_context_tool_evidence() — фазы из транскрипта
                            proven_no_call() / adapter_actual_divergence()
evidence/bundle.py          слот context_tool_evidence: OPTIONAL при чтении
                            (исторические пакеты валидны), present=sha256+bytes,
                            структурная валидация артефакта при verify
core/campaign.py            сборка слота из фактов адаптера + фаз транскрипта;
                            сбой телеметрии → unavailable + причина в provenance
core/experiment.py          stand_version → volatile (digest стабилен)
cli.py                      БЕЗ ИЗМЕНЕНИЙ (контракт вывода заморожен)
```

## Ключевые решения

1. **Опциональность слота при чтении.** `read_bundle` требует полный набор
   обязательных слотов; новый слот — в `BUNDLE_SLOTS_OPTIONAL`: у старого
   пакета читается как `absent` («не предусмотрен»), у нового — всегда
   перечислен в манифесте. Валидация present-записи общая (path/sha256/bytes).
2. **Фазы — только из транскрипта.** Адаптер не знает фаз; campaign маппит
   session_id → фазу по wire-транскрипту (delivery→m1-delivery,
   trigger→m3-trigger-finalize); сессии без атрибуции не попадают в слот
   (ничего не выдумывается). m2-pretrigger — состояние между M1/M2, событий
   в слоте не имеет; константа резервируется в схеме.
3. **Валидация в двух точках.** write_bundle отклоняет структурно неверный
   payload (fail-fast); read_bundle(verify=True) перепроверяет артефакт
   структурно после checksum — ловит неверный контент даже с пересчитанным
   манифестом в границах структурного контракта (не криптографии).
4. **«Не вызывался» — только через полный лог + живой канал.**
   `proven_no_call()` = actual_tool_calls пуст И tool_log_complete=True И
   heartbeat_alive=True; любое другое — False (вывод запрещён).
5. **Digest не трогается.** stand_version — volatile-секция; v1/v2-чтение
   сохранено; при одинаковом config experiment_id идентичен прежнему.

## Коммиты

1. `spec/contracts` — карточка 010, gate-док C10=PASS, telemetry-контракт.
2. `bundle schema` — опциональный слот + структурная валидация.
3. `correlation/model` — фазы, builder, proven_no_call, divergence.
4. `adapter instrumentation` — mock: prepared-события + context_tool_evidence().
5. `campaign/replay` — сборка слота, ExperimentSpec volatile, replay-проверки.
6. `negative controls` — 10 обязательных offline-контролей.
7. `docs/checkpoint/handoff` + один полный suite на финальном SHA.

## Тест-стратегия

RED → минимальный GREEN → регресс; узкие тесты контракта → профильный
P09-suite (`test_p09_full_offline.py` + смежные) → ОДИН полный suite в конце.
Старые assertions не ослабляются; composite/UNKNOWN не меняются.
