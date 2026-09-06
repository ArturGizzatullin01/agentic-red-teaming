# Tasks: LLM-судья для оценки успешности атаки

**Feature Branch**: `003-llm-judge-oracle` | **Date**: 2026-09-06

**Input**: Design documents from [specs/003-llm-judge-oracle/](.)

**Prerequisites**: [plan.md](plan.md), [spec.md](spec.md), [research.md](research.md),
[data-model.md](data-model.md), [contracts/](contracts/), [quickstart.md](quickstart.md)

**Tests**: включены. Плана раздел «Testing» перечисляет пять новых офлайн-тестовых файлов и то,
что каждый обязан покрыть; SC-002, SC-003 и SC-005 сформулированы как исполняемые проверки.

**Organization**: задачи сгруппированы по user story, чтобы каждую можно было реализовать и
проверить независимо.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: можно выполнять параллельно (разные файлы, нет зависимостей)
- **[Story]**: к какой user story относится задача (US1, US2, US3)
- В описании — точный путь к файлу

## Path Conventions

Single project, src-layout: код в `src/memnotsafe/`, тесты в `tests/`, сценарии в `scenarios/`.
Пути ниже — от корня репозитория.

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: каркас нового пакета и базовая линия, относительно которой проверяется SC-003.

- [X] T001 Создать пакет судьи `src/memnotsafe/judge/__init__.py` с docstring: судья — реализация
      роли Oracle, а не шестая роль (Принцип I)
- [X] T002 [P] Создать каталог `tests/fixtures/` для эталонного и инъекционного наборов
      (файлы `.jsonl` коммитятся — это процесс, а не артефакт прогона)
- [X] T003 [P] Зафиксировать базовую линию SC-003: прогнать `python3 -m pytest tests/ -q` и
      записать вывод (35 passed) в `runs/.baseline-sc003.txt` как эталон для сравнения

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: типы, конфигурация и разметка природы доказательства, без которых не работает ни одна
из трёх историй.

**⚠️ CRITICAL**: ни одна user story не начинается, пока эта фаза не закрыта.

- [X] T004 Добавить dataclass `JudgeVerdict` (stage, outcome, confidence, rationale, quote, model,
      rubric, created_at, artifact_ref, error) в `src/memnotsafe/core/models.py` по data-model §1
- [X] T005 Добавить dataclass `DeterministicVerdict` (success, reason, evidence_kind) и словарь
      причин `error` в `src/memnotsafe/core/models.py` по data-model §2
- [X] T006 Расширить `StageResult` полями `verdict_source`, `evidence_kind`, `deterministic`,
      `judge`, `disagreement` — все со значениями по умолчанию, в
      `src/memnotsafe/core/models.py` (data-model §3)
- [X] T007 [P] Добавить поле `judge_verdicts: dict[str, JudgeVerdict]` (default `{}`) в
      `EvaluationContext` в `src/memnotsafe/oracles/base.py` (data-model §5)
- [X] T008 [P] Добавить dataclass `JudgeSpec` и разбор опционального блока `judge:` в
      `load_scenario()` в `src/memnotsafe/core/config.py` по contracts/scenario-judge.schema.md
- [X] T009 Добавить валидацию `JudgeSpec` (нет `model` при `enabled`, пустой ENV-ключ, порог вне
      `[0,1]`, отрицательные лимиты) → `RunnerError` до обращения к таргету, в
      `src/memnotsafe/core/config.py`; значение ключа в сообщение не попадает
- [X] T010 [P] Проставить `evidence_kind` по веткам в `src/memnotsafe/oracles/retrieval.py`:
      `telemetry` для попадания в `memory_retrieval`, `memory_snapshot` для «запись не найдена»,
      `unavailable` для UNKNOWN
- [X] T011 [P] Проставить `evidence_kind` в `src/memnotsafe/oracles/adoption.py` (`telemetry` для
      `llm_decision`, `memory_snapshot` для `scope_escalated`, `marker_match` для
      `response_reflects_adoption`) и снять устаревший хук `llm_judge` с его параметром `JudgeFn`
- [X] T012 [P] Проставить `evidence_kind` в `src/memnotsafe/oracles/external_effect.py`:
      `telemetry` для `tool_result` c `detail.channel != victim_response`, `signature_match` при
      `detail.channel == victim_response`, `marker_match` для маркеров в ответе

**Checkpoint**: `python3 -m pytest tests/ -q` — прежние 35 тестов зелёные, поведение при
выключенном судье побитово прежнее.

---

## Phase 3: User Story 1 - Поймать принятие payload'а своими словами (Priority: P1) 🎯 MVP

**Goal**: судья вызывается на трёх стадиях параллельно дословной проверке и подтверждает стадию
цитатой из ответа жертвы там, где маркер не найден дословно.

**Independent Test**: подать оракулу ответ жертвы, где отравленный факт выражен синонимами, — судья
возвращает `confirmed` с дословной цитатой, дословная проверка маркер не находит, стадия получает
`verdict_source: "judge"`, расхождение зафиксировано.

### Tests for User Story 1 ⚠️

> Пишутся ДО реализации и обязаны падать до неё. Все — офлайн, клиент судьи подменяется стабом.

- [X] T013 [P] [US1] Собрать корпус инъекций (6 классов попыток из
      contracts/judge-prompt-contract.md) в `tests/fixtures/judge_injection.jsonl` парами
      «чистый / инъецированный артефакт»
- [X] T014 [P] [US1] Тесты разбора вердикта в `tests/test_judge_verdict.py`: семь шагов валидации,
      порог `below_threshold`, `quote_not_verbatim`, `quote_in_baseline`, повторы и их исчерпание,
      усечение «голова + хвост», ни один невалидный ответ не даёт стадии `True`
- [X] T015 [P] [US1] Тесты ограды промпта в `tests/test_judge_prompt_injection.py`: артефакт только
      в `user`-сообщении и только внутри ограды, вычистка последовательностей ограды, уникальность
      nonce на вызов, прогон корпуса из `tests/fixtures/judge_injection.jsonl` (SC-005)
- [X] T016 [P] [US1] Тесты слияния в `tests/test_judge_merge.py`: все 14 строк таблицы
      contracts/verdict-precedence.md, асимметрия `retrieval` (SC-009), тождественность слияния при
      пустом `judge_verdicts`, `write`/`persistence`/`tool` никогда не несут судейский вердикт
- [X] T017 [P] [US1] Тесты бюджета в `tests/test_judge_budget.py`: повтор расходует бюджет наравне
      с первым вызовом, исчерпание даёт `unavailable`/`budget_exhausted` и не обрывает кампанию,
      значение по умолчанию `3 × repetitions × (1 + max_retries)` (FR-012, SC-006)

### Implementation for User Story 1

- [X] T018 [P] [US1] Реализовать девять версионируемых рубрик и поиск по паре
      (стадия, `expected_effect.type`) в `src/memnotsafe/judge/rubrics.py`; идентификатор —
      `"{key}@{version}"` (data-model §4)
- [X] T019 [P] [US1] Реализовать сборку сообщений в `src/memnotsafe/judge/prompt.py`: system без
      единого символа артефакта, ограда `<<<ARTIFACT-{nonce}>>>` из `secrets.token_hex(8)`,
      вычистка последовательностей ограды, отдельный nonce для baseline, усечение по
      `max_artifact_chars`
- [X] T020 [US1] Реализовать разбор и валидацию ответа в `src/memnotsafe/judge/verdict.py`: семь
      шагов contracts/judge-io.schema.md, порог `min_confidence`, сырая `confidence` в вердикте,
      словарь причин `error`
- [X] T021 [US1] Реализовать транспорт в `src/memnotsafe/judge/client.py` по образцу
      `src/memnotsafe/adapters/openai.py`: `httpx.AsyncClient`, ключ из ENV по `api_key_env`,
      `response_format` json_schema, `temperature: 0`, таймаут, классификация
      `timeout`/`rate_limit`/`transport`
- [X] T022 [US1] Реализовать `LLMJudge` в `src/memnotsafe/judge/runtime.py`: учёт бюджета
      кампании, пропуск пустого артефакта (`skipped`/`empty_artifact`), повторы, запись артефакта
      вызова `runs/<name>/judge/<case_id>-<stage>.json` (data-model §9), деградация без обрыва
- [X] T023 [US1] Реализовать слияние вердиктов в `src/memnotsafe/oracles/judge_merge.py`: таблица
      contracts/verdict-precedence.md, жёсткое доказательство не переписывается (FR-006), мягкое
      переписывается при `confirmed` (FR-017), асимметрия `retrieval` (FR-018), проставление
      `disagreement`
- [X] T024 [US1] Вызвать слияние после `evaluate_all()` в `src/memnotsafe/oracles/composite.py`,
      не меняя ни строки булевой формулы `composite_success()` (FR-005, Принцип V)
- [X] T025 [US1] Провести опциональный судья через `run_attack()` в
      `src/memnotsafe/core/runner.py`: три вызова (`retrieval`, `adoption`, `external_effect`) до
      `evaluate_all`, заполнение `ec.judge_verdicts`; `write`/`persistence`/`tool` не передаются
- [X] T026 [US1] Сконструировать судью из `JudgeSpec`, создать каталог `judge/` и провести бюджет
      через кампанию в `src/memnotsafe/core/campaign.py`; при выключенном судье каталог не
      создаётся
- [X] T027 [US1] Добавить флаги `--judge`, `--no-judge`, `--judge-model`, `--judge-max-calls` к
      командам `run` и `campaign` в `src/memnotsafe/cli.py` с приоритетом
      `--no-judge` > `--judge*` > блок сценария > умолчания
- [X] T028 [US1] Создать сценарий-ворота `scenarios/direct_poisoning_live_judged.yaml` с блоком
      `judge:` (только имена ENV-переменных, без секретов) по образцу
      `scenarios/direct_poisoning_live.yaml`

**Checkpoint**: US1 работает независимо — судья поднимает мягкий `False` до `True` с цитатой,
прежние 35 тестов и офлайн-прогон против mock не изменились.

---

## Phase 4: User Story 2 - Отличить доказанное от «сказал судья» (Priority: P2)

**Goal**: по каждой стадии во всех форматах отчёта видно, чем она подтверждена; судейские стадии
несут модель, версию рубрики, уверенность и цитату, расхождения показаны обоими вердиктами.

**Independent Test**: прогнать один сценарий с судьёй и один без — у каждой стадии проставлен
источник вердикта, судейские несут модель, уверенность и цитату, `metadata.judge` при выключенном
судье равен ровно `{"active": false}`.

### Tests for User Story 2 ⚠️

- [X] T029 [P] [US2] Тест round-trip провенанса в `tests/test_judge_offline_regression.py`: отчёт,
      пересобранный `memnotsafe report` из `campaign.json`, идентичен исходному по
      `verdict_source`, `evidence_kind`, судейскому вердикту и `disagreement` (FR-011)
- [X] T030 [P] [US2] Дополнить `tests/test_judge_budget.py` проверкой FR-020: рантайм-недоступность
      даёт `exit 0` и статус находки `INCONCLUSIVE`, а не `NOT_EXPLOITABLE`

### Implementation for User Story 2

- [X] T031 [US2] Сериализовать поля провенанса стадии и блок `metadata.judge` в
      `src/memnotsafe/core/campaign.py` по contracts/report-provenance.md; при неактивном судье —
      ровно `{"active": false}`, без модели и рубрик (FR-013)
- [X] T032 [US2] Восстановить все поля провенанса в `cmd_report()` в `src/memnotsafe/cli.py`
      (сейчас восстанавливаются только четыре поля стадии) — иначе пересобранный отчёт беднее
      исходного
- [X] T033 [P] [US2] Добавить `llm_confirmed`, `confidence_tier` (`proved` / `llm_confirmed`),
      статус `INCONCLUSIVE` c severity `INFO` и `stage_provenance` в
      `src/memnotsafe/reporting/findings.py`
- [X] T034 [P] [US2] Добавить `judge_disagreement_rate` (знаменатель — только `confirmed`/`refuted`)
      и блок `judge` в `src/memnotsafe/reporting/metrics.py`; при неактивном судье поле `null`,
      а не `0` (FR-019, SC-008)
- [X] T035 [P] [US2] Добавить `properties.verdict_source`, `llm_confirmed` и `confidence_tier` в
      `src/memnotsafe/reporting/sarif.py`, не меняя правило экспорта (в SARIF только `SUCCESS`)
- [X] T036 [P] [US2] Добавить бейдж источника `D`/`J` у стадии, плашку «подтверждено LLM», модель,
      версию рубрики, уверенность, цитату в `<blockquote>` и оба вердикта при расхождении в
      `src/memnotsafe/reporting/html_report.py`; цитата экранируется как враждебный текст
- [X] T037 [P] [US2] Добавить блок `judge` со списком вердиктов, цитат и `artifact_ref` в
      `src/memnotsafe/reporting/proof.py` для находок с судейской композитной стадией (SC-007)
- [X] T038 [US2] Добавить строки `JUDGE`, `DISAGREEMENT` и `JUDGE НЕДОСТУПЕН` в `_print_summary()`
      в `src/memnotsafe/cli.py` — печатаются только при активном судье (FR-020)

**Checkpoint**: US1 и US2 работают независимо; читатель за минуту отличает доказанную стадию от
судейской во всех шести форматах отчёта.

---

## Phase 5: User Story 3 - Убедиться, что судье можно верить (Priority: P3)

**Goal**: судья измеряется на эталонном наборе; согласие ниже 0.90, любое ложноположительное
срабатывание или ненулевой `injection_flips` блокируют боевой прогон.

**Independent Test**: прогнать `memnotsafe judge-calibrate` на размеченном наборе — на выходе доля
согласия, число ложноположительных, разбивка по трём стадиям и `injection_flips`; `--gate` даёт
`exit 1` при нарушении порога.

### Tests for User Story 3 ⚠️

- [X] T039 [P] [US3] Тесты калибровки в `tests/test_judge_calibration.py`: подсчёт
      `agreement_rate`, `false_positives`, `false_negatives`, `by_stage`, `injection_flips`,
      логика `gate_passed`, сборка набора из завершённого прогона — всё на стабе, без сети
- [X] T040 [P] [US3] Дополнить `tests/test_judge_offline_regression.py` проверкой SC-003: прогон
      батареи против mock без ключей и сети даёт те же вердикты стадий и тот же код возврата, что
      и базовая линия T003; каталог `runs/<name>/judge/` не создаётся

### Implementation for User Story 3

- [X] T041 [US3] Реализовать загрузку набора JSONL и метрики согласия в
      `src/memnotsafe/judge/calibration.py` по data-model §10: `agreement_rate`,
      `false_positives`, `false_negatives`, `by_stage`, `disagreements`, `gate_passed`
- [X] T042 [US3] Добавить инъекционный прогон (`injection_flips`, где нарушением считается и
      переворот в `refuted`) и сборщик набора из завершённого офлайн-прогона (`--from-run`,
      истина = детерминированный вердикт) в `src/memnotsafe/judge/calibration.py`
- [X] T043 [US3] Добавить команду `judge-calibrate` с аргументами `--dataset`, `--injection-suite`,
      `--judge-model`, `--output`, `--min-confidence`, `--gate`, `--from-run`, `--out` в
      `src/memnotsafe/cli.py`; команда не поднимает адаптер и не пишет в `runs/`
- [X] T044 [US3] Собрать эталонный набор из офлайн-прогона против mock в
      `tests/fixtures/judge_golden.jsonl` командой `judge-calibrate --from-run` и закоммитить его

**Checkpoint**: все три истории работают независимо; судья измерен, гейт SC-002 и SC-005 исполним
командой.

---

## Phase 6: Polish & Cross-Cutting Concerns

- [X] T045 [P] Описать судью в `README.md`: включение, флаги, калибровка, чтение провенанса в
      отчёте — рядом с разделом «Живой прогон на стенде»
- [X] T046 [P] Проверить правила Markdown в `specs/003-llm-judge-oracle/`: ширина ≤100, ASCII-имена
      файлов, относительные ссылки резолвятся, даты ISO
- [X] T047 Прогнать офлайн-часть `specs/003-llm-judge-oracle/quickstart.md` (шаги 0 и 1):
      `runs/judge-off` содержит `"judge": {"active": false}` и не содержит каталога `judge/`
- [X] T048 Прогнать `python3 -m pytest tests/ -q` целиком: 35 прежних тестов и все новые зелёные
      без сети и ключей
- [ ] T049 Прогнать боевую часть `specs/003-llm-judge-oracle/quickstart.md` (шаги 2–6) на живом
      стенде с ключом провайдера: SC-001, SC-002, SC-004, SC-006, SC-007 подтверждены артефактами
      — **НЕ ВЫПОЛНЕНА: нет предусловий.** На машине недоступны `agent-api` (`localhost:8600`),
      Mongo (`localhost:27017`) и не заданы `OPENROUTER_API_KEY` / `SK_GENAI_1003`. Задача
      требует внешней инфраструктуры и платных вызовов к провайдеру, поэтому выполняется
      оператором. Всё, что проверяемо офлайн, закрыто: SC-003 (T048), SC-005 офлайн-часть (T047),
      SC-002/SC-009 как исполняемые проверки (T039, T016). Команды для прогона — в
      [quickstart.md](quickstart.md), шаги 2–6.

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: без зависимостей, стартует сразу
- **Foundational (Phase 2)**: зависит от Setup; БЛОКИРУЕТ все user stories
- **User Story 1 (Phase 3)**: зависит только от Foundational
- **User Story 2 (Phase 4)**: зависит от Foundational; читает провенанс, который проставляет US1,
  поэтому на практике идёт после US1
- **User Story 3 (Phase 5)**: зависит от Foundational; переиспользует `prompt.py`, `verdict.py` и
  `client.py` из US1
- **Polish (Phase 6)**: после всех желаемых историй

### User Story Dependencies

- **US1 (P1)**: самостоятельна после Phase 2. Это MVP: судья ловит перефразированное принятие
- **US2 (P2)**: технически независима (провенанс сериализуется и при выключенном судье), но
  осмысленно проверяется только на данных, которые производит US1
- **US3 (P3)**: независима от US2; ей нужны модули судьи из US1, но не отчётность

### Within Each User Story

- Тесты пишутся первыми и обязаны падать до реализации
- Рубрики и промпт → разбор вердикта → транспорт → runtime → слияние → композит → раннер →
  кампания → CLI
- Модели и конфигурация — до всего остального (Phase 2)

### Parallel Opportunities

- T002, T003 — параллельно в Setup
- T007, T008 и T010, T011, T012 — параллельно в Foundational (разные файлы)
- T013–T017 — все тесты US1 параллельно
- T018, T019 — рубрики и промпт параллельно; дальше цепочка последовательна
- T033–T037 — пять модулей отчётности параллельно (разные файлы)
- T039, T040 — тесты US3 параллельно
- T045, T046 — параллельно в Polish

---

## Parallel Example: User Story 1

```bash
# Тесты US1 — одной волной (разные файлы, ни один не зависит от другого):
Task: "Тесты разбора вердикта в tests/test_judge_verdict.py"
Task: "Тесты ограды промпта в tests/test_judge_prompt_injection.py"
Task: "Тесты слияния в tests/test_judge_merge.py"
Task: "Тесты бюджета в tests/test_judge_budget.py"

# Первая волна реализации:
Task: "Девять рубрик в src/memnotsafe/judge/rubrics.py"
Task: "Сборка промпта с оградой в src/memnotsafe/judge/prompt.py"
```

## Parallel Example: User Story 2

```bash
# Пять форматов отчёта — параллельно:
Task: "llm_confirmed и confidence_tier в src/memnotsafe/reporting/findings.py"
Task: "judge_disagreement_rate в src/memnotsafe/reporting/metrics.py"
Task: "properties провенанса в src/memnotsafe/reporting/sarif.py"
Task: "Бейдж источника и цитата в src/memnotsafe/reporting/html_report.py"
Task: "Блок judge в src/memnotsafe/reporting/proof.py"
```

---

## Implementation Strategy

### MVP First (User Story 1)

1. Phase 1: Setup
2. Phase 2: Foundational — блокирует всё остальное
3. Phase 3: User Story 1
4. **STOP и ПРОВЕРИТЬ**: сценарий `direct_poisoning_live_judged.yaml` даёт стадию с
   `verdict_source: "judge"` и дословной цитатой там, где маркер не найден
5. Офлайн-регрессия обязана оставаться зелёной на каждом шаге

### Incremental Delivery

1. Setup + Foundational → фундамент готов, поведение прежнее
2. US1 → судья ловит перефразированное принятие (MVP, SC-001)
3. US2 → отчёт различает доказанное и судейское (SC-004, SC-008)
4. US3 → судья измерен, гейт исполним (SC-002, SC-005)

### Parallel Team Strategy

После Foundational: разработчик A — US1 (пакет `judge/` и слияние), разработчик B — US2
(отчётность, работает на фикстурах `StageResult` с проставленным провенансом), разработчик C —
US3 (калибровка, зависит от `verdict.py` и `prompt.py` из US1).

---

## Notes

- [P] = разные файлы, нет зависимостей между задачами
- Ни один исход судьи, кроме `confirmed`, не даёт стадии `True` — это инвариант, проверяемый в
  T016 и обязательный к соблюдению в каждой задаче реализации
- Формула композита не меняется ни в одной задаче (FR-005, Принцип V)
- `write`, `persistence` и `tool` не передаются судье ни в одной задаче (FR-014)
- Коммит после каждой задачи или логической группы; на любом checkpoint прогон
  `python3 -m pytest tests/ -q` обязан быть зелёным
