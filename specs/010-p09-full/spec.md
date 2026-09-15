# Spec: 010 — P09-full offline: четыре сущности доказательства (контекст/аргументы)

Карточка реализации offline-части P09-full (live-часть — отдельно, только после
независимой приёмки и утверждения бюджетов). База — карточка
`specs/008-p09-full/card.md`; ветка `feature/p09-full` от локального `main=f3b4e02`
(R1 завершён пользователем; origin не используется).

## Цель

Разделить и доказательно сохранить ЧЕТЫРЕ разные сущности — без подмены одной
другой:

0. **expected_effect** — декларация цели (GoalContract; уже в candidate-слоте);
1. **effective_context** — ФАКТИЧЕСКИЙ контекст, переданный финалайзеру жертвы;
2. **adapter arguments** — аргументы, подготовленные адаптером для tool-вызова;
3. **actual tool arguments** — аргументы, реально полученные инструментом.

## Требования

- **FR-1 Слот `context_tool_evidence`** (EvidenceBundle, аддитивно):
  present/absent/unavailable без изменения семантики; present обязан иметь
  path+sha256+bytes; исторические пакеты (без слота) читаются без ошибки —
  слот опционален при чтении; unavailable остаётся UNKNOWN; absent = «слот
  не предусмотрен» и ничего больше.
- **FR-2 Корреляция.** Каждое наблюдаемое событие несёт `session_id`,
  `actor_user_id`, `phase`, `call_id`, `case_marker` (когда применим).
  Первичный ключ — `call_id`; маркер НЕ заменяет call_id; call_id непустая
  строка, уникальная внутри секции.
- **FR-3 Фазы** различаются явно: `m1-delivery`, `m2-pretrigger`,
  `m3-trigger-finalize`; данные разных фаз не объединяются неявно. Фазовая
  принадлежность сессий — из транскрипта раннера (единственный авторитет),
  не из событий адаптера.
- **FR-4 Adapter instrumentation** (аддитивно): адаптер фиксирует
  ПОДГОТОВЛЕННЫЕ аргументы отдельным событием `tool_call_prepared` до
  отправки; поведение самого вызова не меняется; Runner/Oracle/composite
  не трогаются; подготовленные аргументы никогда не выдаются за фактические.
- **FR-5 Контракт внешней телеметрии** (`evidence/telemetry.py`):
  строгая схема v1 для effective_context, actual tool args, признака полноты
  tool-лога, heartbeat канала, версии стенда, chat-prompt revision (None =
  неизвестно, не реконструируется). Неизвестные ключи/типы/фазы — контректная
  ошибка. Стенд молча не меняется; handoff владельцу стенда — отдельно.
  До появления канала live-статус = unavailable/UNKNOWN. Строгость
  симметрична на обеих сторонах: и wire-запись, и сырые факты адаптера
  обязаны нести ключи явно — отсутствие ключа ≠ пусто (пустой {} легитимен).
- **FR-6 Экспериментальные метаданные**: версия стенда — в `volatile`
  секции ExperimentSpec (digest не меняется для той же конфигурации);
  чтение исторических v1/v2 сохраняется; usage tokens остаются null без
  источника; связь новых доказательств с candidate_id/case_id/attempt_no
  обеспечивается манифестом пакета (уже проверяется verify_run_evidence).
- **FR-7 Replay/report**: обнаруживает повреждённый/структурно неверный новый
  слот (даже при пересчитанном checksum — структурная валидация при чтении),
  неизвестный статус, пустой/дублирующийся call_id, рассинхрон
  candidate/case/attempt (уже есть), попытку без пакета (уже есть),
  повреждённый JSON/JSONL (уже есть), подмену размера/checksum (уже есть).
  CLI stdout/stderr/exit НЕ меняются.
- **FR-8 Honest-границы**: «инструмент не вызывался» утверждается ТОЛЬКО при
  полном tool-логе И живом heartbeat; иначе — UNKNOWN. Расхождение
  adapter/actual аргументов фиксируется явно (по call_id), не сглаживается.

## Не входит

Live-прогоны, PROMO2024, изменения стенда/адаптера investment_stand,
новые attack families, изменение composite/UNKNOWN-семантики, правки
CLI-контракта.

## Remediation RETURN_FOR_FIX 1a6f633 (D1/D2, offline)

Повторная приёмка воспроизвела на этом же SHA два P1-дефекта сборщика
`build_context_tool_evidence` (полный suite 815 их НЕ ловил — негативные
контроли были слепы к дублю из-за dict/set-индексации по `session_id`):

- **D1 — proven_no_call из отсутствующего ключа фактов.** `adapter_facts.get(
  field) or {}` молча превращал потерянный ключ `*_by_session` в пустой словарь;
  при `tool_log_complete=True` + живом heartbeat это давало «доказано: вызовов
  не было» из отсутствующих данных. Закрыто: сборщик требует явные ключи
  `effective_context_by_session` / `actual_tool_calls_by_session` /
  `prepared_tool_calls_by_session` (паритет с wire-парсером); явный пустой {}
  остаётся легитимным. Тесты: `test_d1_missing_facts_key_is_contract_error_
  not_proven_no_call`, truth-table `test_d1_proven_no_call_truth_table_from_
  builder`, позитивный контроль `test_d1_explicit_empty_dict_is_legitimate_
  proven_no_call`, кампанийный путь `test_d1_campaign_broken_facts_slot_
  unavailable_not_proven_no_call` (TelemetryError → слот unavailable +
  причина в provenance, прогон выживает).
- **D2 — дубль секций effective_context.** Задвоенный `eff_sections.append`
  давал две идентичные секции на одну сессию. Закрыто: удалён второй append;
  одна сессия → ровно одна секция. Тесты: `test_d2_one_session_exactly_one_
  effective_context_section` + явные счётчики секций в тестах, где dict/set-
  индексация съедала повтор (`test_build_maps_phases_and_rejects_unattributed_
  call`, `test_fix1_baseline_sessions_excluded_explicitly_by_runner_authority`).

- **D3 — закрыт отдельной live-gated карточкой** (ветка `fix/p09-l2-driver`
  поверх принятого `475c642`): L2-драйвер `scripts/live_clean_control.py`
  больше не хардкодит исход — AttemptHistory-исход и `verdict_измерения`
  выводятся штатной оценкой (`evaluate_all` → `composite_success` →
  `outcome_of_result`) над реальными снимками/трассой L2; EvaluationContext
  зеркален `core/runner.py` (delivery-фаз нет → документированный ручной
  режим `phases=None`, trigger-сессия одна — жертва). Канарейка контроля
  `CONTROL_SENTINEL` — payload кандидата, критерий settle, маркер эффекта.
  «Грязный» стенд (чужая global-запись + эффект в ответе) даёт все стадии
  True → `completed_success` + FAIL-тревога — контроль больше не слеп.
  Тесты (офлайн, инжекция мок-адаптера): `test_l2_clean_mock_measures_no_
  effect`, `test_l2_dirty_mock_no_longer_blind`
  (`tests/test_live_clean_control_offline.py`).
