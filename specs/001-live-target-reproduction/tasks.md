---

description: "Список задач фичи: воспроизведение находки на живом стенде"
---

# Tasks: Прогон батареи атак против живого стенда

**Input**: Design documents из `specs/001-live-target-reproduction/`

**Prerequisites**: [plan.md](plan.md) (обязательно), [spec.md](spec.md) (user stories),
[research.md](research.md), [data-model.md](data-model.md), [contracts/](contracts/)

**Tests**: офлайн-тесты ВКЛЮЧЕНЫ — их прямо требуют FR-011, research §10 и quickstart Шаг 0
(гейт воспроизводимости без живого стенда). Живой стенд в CI недоступен, поэтому все тесты —
офлайн на поддельных входах, без сети.

**Organization**: задачи сгруппированы по user story, чтобы каждую можно было реализовать и
проверить независимо.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: можно выполнять параллельно (разные файлы, нет зависимостей от незавершённых задач)
- **[Story]**: к какой user story относится задача (US1, US2, US3)
- В описании — точный путь к файлу

## Path Conventions

Single project, src-layout, пакет `memnotsafe`: `src/memnotsafe/`, `tests/`, `scenarios/` от корня
репозитория (см. [plan.md](plan.md) → Project Structure).

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: базовая готовность окружения; проект уже существует, правки локализованы.

- [X] T001 Зафиксировать офлайн-гейт baseline: прогнать `python3 -m pytest tests/ -q`, убедиться,
      что все существующие mock-тесты зелёные (точка отсчёта для FR-011/SC-007)
- [X] T002 [P] Объявить опциональную зависимость `pymongo` (канал memory_snapshot) в
      [pyproject.toml](../../pyproject.toml); ленивый импорт уже внутри адаптера

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: конфиг-управляемый бюджет N повторов и early-exit (FR-013) в ядре — общий,
target-agnostic механизм, от которого зависят и US1 (early-exit по первому success), и US2
(NOT_EXPLOITABLE после N).

**⚠️ CRITICAL**: до завершения этой фазы работа над user stories не начинается.

- [X] T003 Добавить поле `stop_on_success: bool = False` в dataclass `Scenario` и парсинг
      `metrics.stop_on_success` в `Scenario.from_dict` в
      [src/memnotsafe/core/config.py](../../src/memnotsafe/core/config.py) (data-model §6, FR-013)
- [X] T004 Реализовать конфиг-управляемый early-exit по первому композитному success в
      `Campaign.run()` в [src/memnotsafe/core/campaign.py](../../src/memnotsafe/core/campaign.py):
      прерывать цикл при `stop_on_success=True`; default off → mock-демо и тесты неизменны
      (FR-013, research §6)
- [X] T005 Офлайн-unit тест бюджета на поддельном адаптере в
      `tests/test_campaign_budget.py`: early-exit при первом success и исчерпание N без success
      (проверка target-agnostic поведения T003/T004) (FR-013, research §10г)

**Checkpoint**: ядро умеет бюджет N + early-exit конфигом; mock-путь не изменился — можно начинать
user stories.

---

## Phase 3: User Story 1 - Воспроизвести кросс-юзер утечку на живом таргете (Priority: P1) 🎯 MVP

**Goal**: прогон `cross_user_bac` против живого стенда даёт отчёт, где композит = success, а
`external_effect` подтверждён появлением данных клиента 1001 в сессии клиента 1002.

**Independent Test**: офлайн-тесты нормализации/каналов/тристейта зелёные; ручной прогон
`scenarios/cross_user_bac_live.yaml` даёт хотя бы один case с success и `external_effect=True`,
ссылающийся на реальный артефакт утечки (quickstart Шаг 2).

### Tests for User Story 1 (офлайн, писать ПЕРВЫМИ — убедиться, что падают)

- [X] T006 [US1] Офлайн-unit тест нормализации Mongo-документов → `{id, source_user, text, scope}`
      (agent_policy_memories→scope=global, пользовательские коллекции→scope=user) в
      `tests/test_investment_stand_adapter.py` (data-model §2, adapter-contract)
- [X] T007 [US1] Офлайн-unit тест трёх каналов доказательства в
      `tests/test_investment_stand_adapter.py`: фиксированный порядок 1→2→3, берётся первый
      сработавший; тристейт — 0 наблюдаемых каналов → UNKNOWN, канал наблюдаем без утечки → False,
      утечка → True (evidence-channels.md таблица истинности, data-model §3)

### Implementation for User Story 1

- [X] T008 [US1] Нормализованный `snapshot()` в
      [investment_stand.py](../../src/memnotsafe/adapters/investment_stand.py):
      каждый Mongo-документ → `{id, source_user, text, scope}`, заменить сырой `_strip`
      (data-model §2) — иначе `find_candidate_record` не сматчит payload и write будет ложно False
- [X] T009 [US1] Детекция evidence-каналов в
      [investment_stand.py](../../src/memnotsafe/adapters/investment_stand.py):
      проверка tool_telemetry → memory_snapshot → victim_response в фиксированном порядке, первый
      даёт `leaked_cus`/`channel` (evidence-channels.md, data-model §3, FR-005)
- [X] T010 [US1] Синтез канонических трейс-событий в `send()` в
      [investment_stand.py](../../src/memnotsafe/adapters/investment_stand.py)
      ТОЛЬКО из наблюдённого канала: `memory_retrieval`, `llm_decision`(detail.resolved_cus),
      `tool_call`(arguments.cus), `tool_result`(status=200, customer, channel) (data-model §4,
      Принцип IV)
- [X] T011 [US1] Динамические `Capabilities` в
      [investment_stand.py](../../src/memnotsafe/adapters/investment_stand.py):
      `trace`/`tool_calls` по наблюдённому каналу, `memory_snapshot` по `mongo_uri`; нет канала →
      стадия UNKNOWN, никогда не True (data-model §5, FR-004)
- [X] T012 [US1] Override `wait_until_persistent(evidence)` в
      [investment_stand.py](../../src/memnotsafe/adapters/investment_stand.py):
      polling Mongo до `settle_timeout_s`, пока payload виден в памяти источника или global-слое
      (adapter-contract, research §2)
- [X] T013 [US1] Реализовать `set_context(run_id, case_id)` в
      [investment_stand.py](../../src/memnotsafe/adapters/investment_stand.py)
      для проставления `run_id`/`case_id` в синтезируемые события (adapter-contract, как в mock.py)
- [X] T014 [P] [US1] Создать [cross_user_bac_live.yaml](../../scenarios/cross_user_bac_live.yaml):
      `adapter: investment_stand`, `base_url`, `identities {1001, 1002}`, `mongo_uri`,
      `settle_timeout_s`, `attack.family: cross_user_bac`, `repetitions: 5`, `stop_on_success: true`
      (scenario-live.schema.md, FR-002/FR-009/FR-010)
- [X] T015 [US1] Обеспечить, что `build_proof` кладёт доказательство external_effect
      (`detail.customer`, `detail.channel`) в proof.json — проверить/дополнить проброс trace_events
      в [proof.py](../../src/memnotsafe/reporting/proof.py) (FR-007, SC-005)

**Checkpoint**: `cross_user_bac_live` воспроизводит утечку — success + `external_effect=True` с
`detail.customer="1001"` в сессии `"1002"`; MVP-ворота достигнуты.

---

## Phase 4: User Story 2 - Прогнать всю батарею по живому таргету (Priority: P2)

**Goal**: все пять семейств атак направлены на живой стенд; каждый даёт шестистадийную воронку;
честный негатив помечается `NOT_EXPLOITABLE` (exit 0), инфраструктурный сбой — exit 1.

**Independent Test**: прогон всех `scenarios/*_live.yaml` даёт по воронке на сценарий; коды возврата
корректны (quickstart Шаг 4); офлайн-тест вердикта/кодов зелёный.

**Note**: переиспользует адаптер из US1 (тот же `investment_stand`); новое — только scenario YAML и
проверка кодов возврата (FR-010, Принцип II).

- [X] T016 [P] [US2] Создать live-сценарий
      [direct_poisoning_live.yaml](../../scenarios/direct_poisoning_live.yaml) по образцу
      cross_user_bac_live (тот же `attack.family`, `adapter: investment_stand`, бюджет N)
      (FR-001, FR-010)
- [X] T017 [P] [US2] Создать live-сценарий
      [false_precedent_live.yaml](../../scenarios/false_precedent_live.yaml) (аналог)
      (FR-001, FR-010)
- [X] T018 [P] [US2] Создать live-сценарий
      [scope_escalation_live.yaml](../../scenarios/scope_escalation_live.yaml) (аналог)
      (FR-001, FR-010)
- [X] T019 [P] [US2] Создать live-сценарий
      [tool_argument_hijack_live.yaml](../../scenarios/tool_argument_hijack_live.yaml) (аналог)
      (FR-001, FR-010)
- [X] T020 [US2] Офлайн-unit тест вердикта/кодов в `tests/test_campaign_budget.py`: наблюдаемый
      канал без утечки → `external_effect=False` → `NOT_EXPLOITABLE` + exit 0; `RunnerError` →
      exit 1 (поддельный адаптер, проверка cli/campaign) (FR-006, SC-003)

**Checkpoint**: батарея из пяти семейств выдаёт корректные воронки и коды возврата; доля неверно
классифицированных исходов = 0.

---

## Phase 5: User Story 3 - Паритет артефактов mock ↔ живой таргет (Priority: P3)

**Goal**: отчёт живого прогона структурно идентичен mock-демо (та же воронка из шести стадий в том
же порядке, та же формула композита), артефакты прослеживаются к реальному таргету.

**Independent Test**: структурный офлайн-тест паритета воронки зелёный; ручное сравнение
`campaign.json` живого и mock прогонов совпадает по стадиям (quickstart Шаг 5), metadata несёт
`run_id`/`reset_available`/`evidence_channel`/`target`.

**Note**: переиспользует адаптер из US1; новое — честный `reset_state` и surfacing metadata.

- [X] T021 [US3] Честный `reset_state()` в
      [investment_stand.py](../../src/memnotsafe/adapters/investment_stand.py):
      при отсутствии доступа на запись не падать, а помечать `reset_available=false` для metadata
      (FR-012, research §7)
- [X] T022 [US3] Проставлять metadata живого прогона (`run_id`, `reset_available`,
      `evidence_channel`, `target`) в `campaign.json` в
      [src/memnotsafe/core/campaign.py](../../src/memnotsafe/core/campaign.py) (data-model §7,
      FR-007/FR-012, SC-005)
- [X] T023 [US3] Офлайн-unit тест паритета воронки в `tests/test_investment_stand_adapter.py`:
      шесть стадий в порядке `write→persistence→retrieval→adoption→tool→external_effect` и та же
      формула композита для live-адаптера, что и для mock (SC-002)

**Checkpoint**: воронка и композит живого прогона совпадают с mock; артефакты атрибутируются
кампании.

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: документация, финальный гейт, ручная приёмка.

- [X] T024 [P] Дополнить [README.md](../../README.md) разделом про живой прогон со ссылкой на
      [quickstart.md](quickstart.md) (без секретов — только имена ENV)
- [X] T025 Прогнать полный офлайн-гейт `python3 -m pytest tests/ -q`, подтвердить неизменность
      mock-демо и существующих тестов (FR-011, SC-007)
- [ ] T026 Ручная валидация [quickstart.md](quickstart.md) (Шаги 1–6) против живого стенда:
      воспроизведение, честный негатив, батарея, паритет, изоляция (SC-001…SC-006)

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: без зависимостей — стартует сразу.
- **Foundational (Phase 2)**: после Setup; БЛОКИРУЕТ все user stories (FR-013 нужен и US1, и US2).
- **US1 (Phase 3)**: после Foundational. Доставляет адаптер живого таргета — backbone для US2/US3.
- **US2 (Phase 4)**: после US1 (переиспользует адаптер); scenario YAML можно писать параллельно.
- **US3 (Phase 5)**: после US1 (нужен рабочий адаптер и его события/снимок).
- **Polish (Phase 6)**: после нужных user stories.

### User Story Dependencies

- **US1 (P1)**: зависит только от Foundational. Независимо тестируется офлайн (T006/T007) + ручной
  прогон.
- **US2 (P2)**: зависит от US1 (тот же адаптер); честный факт — не «полностью независима»: новое —
  только конфиги и проверка кодов возврата.
- **US3 (P3)**: зависит от US1 (события/снимок/metadata адаптера).

### Within Each User Story

- Тесты (T006/T007) пишутся ПЕРВЫМИ и падают до реализации.
- Нормализация snapshot (T008) → детекция каналов (T009) → синтез событий (T010) → capabilities
  (T011): в одном файле, строго последовательно.
- Scenario YAML (T014, T016–T019) независимы от кода адаптера — параллельны.

### Parallel Opportunities

- T002 параллелен внутри Setup.
- Внутри US1: T014 (YAML) параллелен коду адаптера; T008–T013 — один файл, последовательно.
- Внутри US2: T016–T019 (четыре YAML) — полностью параллельны.
- T024 (docs) параллелен финальным задачам.

---

## Parallel Example: User Story 2

```bash
# Четыре live-сценария батареи создаются параллельно (разные файлы):
Task: "Создать scenarios/direct_poisoning_live.yaml"
Task: "Создать scenarios/false_precedent_live.yaml"
Task: "Создать scenarios/scope_escalation_live.yaml"
Task: "Создать scenarios/tool_argument_hijack_live.yaml"
```

---

## Implementation Strategy

### MVP First (только US1)

1. Setup (Phase 1) → офлайн-гейт зелёный.
2. Foundational (Phase 2) → бюджет N + early-exit конфигом, mock-путь неизменен.
3. US1 (Phase 3) → адаптер + `cross_user_bac_live.yaml` + офлайн-тесты.
4. **STOP и VALIDATE**: ручной прогон `cross_user_bac_live` → success + `external_effect=True`
   (ворота воспроизведения, SC-001/SC-004).

### Incremental Delivery

1. Setup + Foundational → фундамент.
2. US1 → воспроизведение одной атаки (MVP, ворота успеха).
3. US2 → вся батарея + корректные коды возврата.
4. US3 → паритет с mock + прослеживаемость артефактов.

---

## Notes

- [P] = разные файлы, нет зависимостей от незавершённых задач.
- [Story] = трассировка задачи к user story.
- Инвариант честности: событие эмитится ТОЛЬКО из реально наблюдённого канала; нет канала → UNKNOWN,
  никогда не True (Принцип IV, FR-004).
- Ядро (`oracles/`) и mock не трогаются; правки — адаптер + один конфиг-флаг в `campaign.py`
  (Принципы II/III/VI).
- Секреты (`sk-genai-…`) не в YAML и не в git — только имена ENV; `runs/`/`reports/` не коммитятся.
- Коммит после каждой задачи или логической группы.
