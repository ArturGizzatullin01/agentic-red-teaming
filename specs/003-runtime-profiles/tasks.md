---

description: "Tasks for 003-runtime-profiles"
---

# Tasks: Runtime-профили ролей и provenance

**Input**: [plan.md](plan.md), [spec.md](spec.md). Все задачи после gate фичи 002
(базовая линия + suites зелёные).

## Phase 1: типизированные профили

- [ ] T003-1 `core/models.py`: dataclass `RoleProfile` (preset_id, provider, model,
  base_url, api_key_env, timeout, output/retry limits, allowed provider options),
  `RunProvenance` (schema_version, source_revision, seed, variant, scenario hash,
  candidate hash, requested/resolved модели трёх ролей, stand revision,
  effective_channel, auth режим, evidence capabilities, времена, статус),
  `ResolvedConfig`; legacy converter словарей на границе. Contract-тесты.
- [ ] T003-2 `core/config.py` + `cli.py`: загрузка profiles, precedence
  CLI → scenario → default, валидация (unknown preset, missing ENV, конфликт ролей —
  ошибка до reset/delivery, exit 1). Тесты `tests/test_role_profiles.py`.

## Phase 2: runtime-генерация вне ядра

- [ ] T003-3 новый пакет `generation/`: provider transport (HTTP, таймауты, 429),
  attacker service (async) → валидированный candidate; static путь без сети;
  `content` основной, `reasoning_content` — opt-in совместимость с пометкой fallback;
  пустой output → ограниченный retry → ошибка.
- [ ] T003-4 `core/runner.py`: точка подключения — вызов сервиса до доставки,
  candidate передаётся в шаги; без `asyncio.run` внутри loop; тест: выбор attacker
  подтверждён запросом в fake transport; judge/target не изменились.

## Phase 3: judge bridge (R6: async до sync-оракулов)

- [ ] T003-5 judge-мост с явной async-границей: runner выполняет ОДНУ async-фазу
  «judge annotations» ДО `evaluate_all` (сетевые вызовы судьи — только там, где
  детерминированного правила нет); результат — словарь аннотаций по стадиям,
  передаваемый в sync `evaluate_all` через готовый sync `JudgeFn`-адаптер
  (существующий хук `adoption.py::evaluate_adoption(..., llm_judge=None)`).
  Никаких `asyncio.run` внутри активного loop и никаких сетевых вызовов из sync
  оракулов. Судья возвращает структурированную оценку стадии с основанием в
  trigger evidence; попадает в `StageResult` как аннотация (confidence/reason),
  composite остаётся единственным местом success. Тесты: детерминированный путь
  не вызывает judge (все 5 встроенных effect types); fallback; timeout судьи →
  стадия UNKNOWN (не True); отсутствие judge — поведение как сегодня;
  `asyncio.run`-в-loop отсутствует (проверка транспорта).

## Phase 4: смена target — операторский wrapper (R2)

- [ ] T003-6 `scripts/set_stand_target.py`: интерфейс
  `<profile> --stand-path P -- <campaign command...>`; протокол: прекондишены
  (порты, ENV) → именованный бэкап профиля → apply → recreate agent-api → readback
  (без секретов) → health → непустой sanity → ЗАПУСК дочерней команды кампании
  (subprocess, exit code передаётся) → restore в finally. Readback
  mismatch/unavailable или пустой sanity → кампания не запускается, restore
  выполняется, exit 1. Restore-fail → exit 1 с ОБОИМИ ошибками в stderr и
  фактическим состоянием (таблица в
  [контракте](contracts/target-switch.md)). Без автоматического live-запуска
  вне переданной команды.
- [ ] T003-7 `tests/test_target_switch.py`: fake process runner + fake HTTP:
  fake campaign наблюдает НОВУЮ модель; после него (включая падение кампании)
  восстановлена СТАРАЯ; readback mismatch/unavailable блокирует кампанию; пустой
  sanity → кампания не стартует; restore-fail виден и не подменяет exit кампании
  кроме случая restore-fail; каждая операция ровно один раз; `.env.bak` не
  перетирается безымянно (именованные бэкапы профиля).

## Phase 5: provenance в отчётах

- [ ] T003-8 `reporting/json_report.py`, `html_report.py`, `metrics.py`, `cli.py`:
  provenance во всех форматах; report/replay сохраняют provenance; schema version.
  Тест `tests/test_provenance.py`: идемпотентность replay, inactive-роли,
  unknown с причиной.

Gate фичи: выбор attacker подтверждён реальным запросом в fake transport, а не
только YAML.

## Дополнение: запуск сохранённой комбинации ролей

Источник: [контракт пресетов](contracts/launch-presets.md). Пока только план.

- [ ] T003-9 clarify/analyze: согласовать ModelEndpoint/RoleBinding/LaunchPreset
  с T003-1; единый precedence и инструкции по ролям. Обновить контрактные тесты
  T003-2: одинаковая модель attacker/target разрешена; runtime judge фиксирован
  на DeepSeek. Другой judge в CLI/scenario/preset — config error, без fallback.
- [ ] T003-10 после T003-2/6/7: сервис запуска пресета, неизменяемый resolved config,
  эксклюзивный доступ к стенду, идемпотентный запуск, отмена и restore.
  Provider/stand-специфику оставить вне core; fake lifecycle tests обязательны.
- [ ] T003-11 после T003-3/5/8/10: локальная панель с двумя селекторами,
  фиксированным полем «Судья: DeepSeek», сценариями,
  попытками, карточками пресетов, сохранением комбинации, статусом и отменой.
  Один запуск с карточки использует общий backend CLI, без дублирования логики.
- [ ] T003-12 offline-приёмка обеих пользовательских комбинаций, независимости
  ролей, UI/CLI parity, несовместимого target, двойного клика, занятого стенда,
  отмены и restore-fail. Проверить provenance; live — отдельная разрешённая проверка.
