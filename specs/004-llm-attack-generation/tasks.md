# Tasks: LLM-генерация атак и многоуровневая эскалация

**Input**: Design documents from `specs/004-llm-attack-generation/`

**Prerequisites**: [plan.md](plan.md), [spec.md](spec.md), [research.md](research.md),
[data-model.md](data-model.md), [contracts/](contracts/), [quickstart.md](quickstart.md)

**Tests**: тестовые задачи ВКЛЮЧЕНЫ — офлайн-проверяемость требуется спекой явно (SC-006, FR-018,
Принцип VI конституции), состав тест-файлов зафиксирован в [quickstart.md](quickstart.md).

**Organization**: задачи сгруппированы по user story, чтобы каждую можно было реализовать и
проверить независимо.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: можно выполнять параллельно (разные файлы, нет незакрытых зависимостей)
- **[Story]**: к какой user story относится задача (US1–US4)
- В описании — точный путь к файлу

## Path Conventions

Single project, src-layout: код в `src/memnotsafe/`, тесты в `tests/`, версионируемые данные
(`profiles/`, `attack_classes/`, `corpora/`, `scenarios/`) — в корне репозитория.

## Baseline и запреты

- **Baseline на момент планирования**: `python3 -m pytest tests/ -q` → **174 passed**. Формулировка
  «12 тестов» в SC-008 написана до влития фичи 003; актуальный смысл SC-008 — *ни один существующий
  тест не падает*.
- **Ветка отведена от `main`**, в дереве присутствует код фичи 003 (`judge/`). Вопреки research §14
  это не меняет план: 004 не импортирует `judge/`, атакующая LLM — свой клиент (research §8).
- **Правки ЗАПРЕЩЕНЫ** (SC-008, Принципы I–III): `src/memnotsafe/core/runner.py`,
  `src/memnotsafe/core/models.py`, `src/memnotsafe/oracles/*` (включая `composite.py`),
  `src/memnotsafe/attacks/base.py`.

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: каркас нового пакета и версионируемых каталогов данных

- [X] T001 Создать пакет генерации: `src/memnotsafe/generation/__init__.py` с docstring о роли слоя (чистое ЧТО: генерация и переписывание атак, без знания о таргете)
- [X] T002 [P] Создать версионируемые каталоги данных `profiles/`, `attack_classes/`, `corpora/` с файлами `profiles/README.md`, `attack_classes/README.md`, `corpora/README.md`, описывающими назначение и ссылку на соответствующую схему в `specs/004-llm-attack-generation/contracts/`
- [X] T003 [P] Зафиксировать baseline в `specs/004-llm-attack-generation/tasks.md` (раздел «Baseline»): выполнить `python3 -m pytest tests/ -q` и убедиться, что все существующие тесты зелёные до начала правок (SC-008)

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: инфраструктура атакующей LLM, модель корпуса и исполнитель сгенерированных атак — всё,
без чего невозможна ни одна user story

**⚠️ CRITICAL**: ни одна user story не может начаться до завершения этой фазы

- [X] T004 [P] Реализовать `AttackerError` (сбой атакующей LLM/конфигурации, отличный от `RunnerError`) в `src/memnotsafe/generation/errors.py`
- [X] T005 [P] Реализовать dataclass `CallBudget` (`limit`, `used`, `spend()`, свойство `exhausted`; исчерпание — штатный стоп, НЕ исключение) в `src/memnotsafe/generation/budget.py` по data-model.md
- [X] T006 Реализовать dataclass `AttackerConfig` (`provider`/`model`/`base_url`/`api_key_env`/`budget`/`timeout_s`/`scripted`, значения по умолчанию из data-model.md; ключ только по имени переменной окружения — FR-016) в `src/memnotsafe/generation/config.py` (зависит от T004)
- [X] T007 Реализовать `AttackerClient(Protocol)` с `complete(prompt, *, system) -> str`, `StubAttackerClient` (офлайн, отдаёт `scripted` по очереди) и `HTTPAttackerClient` (OpenAI-совместимый `/v1/chat/completions` на `httpx`, ключ из `os.environ[api_key_env]`, ретраи, таймаут; любой сбой → `AttackerError`) в `src/memnotsafe/generation/attacker_client.py` по паттерну `src/memnotsafe/adapters/openai.py` (зависит от T004, T006)
- [X] T008 [P] Реализовать загрузку и валидацию `AgentProfile` (+ `InterfaceSpec`/`ToolSpec`/`MemorySpec`/`CompromiseSpec`, вычисляемый `sha256` нормализованного содержимого; отсутствие обязательной секции или пустой `compromise.external_effect` → `AttackerError`-config ДО сетевых вызовов) в `src/memnotsafe/generation/profile.py` по `contracts/agent-profile.schema.md`
- [X] T009 [P] Реализовать загрузку реестра `AttackClassSpec` из каталога/списка файлов (валидация обязательных полей; `family` обязан существовать в `ATTACK_REGISTRY`) в `src/memnotsafe/generation/attack_classes.py` по `contracts/attack-class.schema.md`
- [X] T010 Реализовать dataclass'ы `Corpus`/`CorpusRecord`/`CorpusProvenance`, чтение/запись YAML и отбраковку невалидной записи (пустой `payload`/`trigger`, неизвестный `attack_class`, `expected_effect` без обязательных полей класса — FR-012) в `src/memnotsafe/generation/corpus.py` по `contracts/corpus.schema.md` (зависит от T009)
- [X] T011 Реализовать `GeneratedAttack(AttackBase)` с `family="generated"`, читающий `CorpusRecord` из `AttackContext.params`: `generate`/`delivery_steps`/`trigger_steps`/`expected_effect` + подмена `metadata` на экземпляре копией `AttackMetadata` класса из `attack_class` с сохранением `signal_strength`/`mpbench_class`/`atlas_*`/`owasp_asi` (research §2) в `src/memnotsafe/attacks/generated.py` (зависит от T010)
- [X] T012 Добавить поле `Scenario.corpus_path` и его разбор из блока `attack.corpus` в `src/memnotsafe/core/config.py` (аддитивно, значение по умолчанию `None` — существующие сценарии не затрагиваются)
- [X] T013 Подключить прогон корпуса в `src/memnotsafe/core/campaign.py`: при `attack_family == "generated"` загрузить корпус по `scenario.corpus_path` и прогнать каждую валидную запись, передавая её в `AttackContext.params` (вызов `run_attack` не изменяется) (зависит от T010, T011, T012)

**Checkpoint**: фундамент готов — корпус исполняется существующим раннером; можно начинать истории

---

## Phase 3: User Story 1 - Заранее сгенерировать переиспользуемый корпус атак под нового агента (Priority: P1) 🎯 MVP

**Goal**: по файлу-профилю агента и универсальным описаниям классов атак команда `generate` собирает
сохранённый переиспользуемый корпус, пригодный к прогону существующими `run`/`campaign`.

**Independent Test**: дать профиль тестового агента и `StubAttackerClient` → `memnotsafe generate`
создаёт `corpora/support-agent.yaml` с провенансом; `memnotsafe run --scenario
scenarios/generated_support.yaml` даёт честный вердикт на `MockTarget`; профиль без
`compromise.external_effect` → `exit 1` до вызовов LLM.

### Tests for User Story 1 ⚠️

> Пишутся ПЕРВЫМИ и должны падать до реализации

- [X] T014 [P] [US1] Тесты валидации профиля/классов/корпуса и отбраковки невалидной записи (FR-012), включая негативный профиль без `compromise.external_effect` → config-ошибка до сетевых вызовов, в `tests/test_profile_and_corpus.py`
- [X] T015 [P] [US1] Офлайн e2e US1: генерация корпуса на `StubAttackerClient` + прогон корпуса на `MockTarget` с честным вердиктом (`success` и `NOT_EXPLOITABLE`), и переиспользование того же корпуса вторым профилем без вызовов LLM (SC-002), в `tests/test_generation_offline.py`

### Implementation for User Story 1

- [X] T016 [US1] Реализовать промпт генерации атаки (system + user, с оградой: модель отдаёт только структурированную запись атаки, без исполняемого кода) в `src/memnotsafe/generation/prompts.py`
- [X] T017 [US1] Реализовать precompute `corpus_gen(profile, classes, client, budget) -> Corpus`: по каждому классу вызвать атакующую LLM, распарсить ответ в `CorpusRecord`, отбраковать невалидные, собрать `CorpusProvenance` (включая `profile_sha256`, `attacker_calls`) в `src/memnotsafe/generation/corpus_gen.py` (зависит от T016)
- [X] T018 [P] [US1] Создать фикстуры профилей `profiles/support-agent.yaml` (валидный, по примеру из `contracts/agent-profile.schema.md`) и `profiles/broken-no-effect.yaml` (без `compromise.external_effect`, для негативного сценария)
- [X] T019 [P] [US1] Создать описания классов атак `attack_classes/cross_user_bac.yaml`, `attack_classes/direct_poisoning.yaml`, `attack_classes/scope_escalation.yaml`, `attack_classes/false_precedent.yaml`, `attack_classes/tool_argument_hijack.yaml` по `contracts/attack-class.schema.md`
- [X] T020 [US1] Добавить команду `generate` (`--profile`, `--classes`, `--out` + общий блок флагов атакующей LLM) с кодами возврата 0/1 по `contracts/cli-commands.md` в `src/memnotsafe/cli.py` (зависит от T017)
- [X] T021 [US1] Добавить предупреждение о наследовании слепых пятен при совпадении `AttackerConfig.model` с моделью цели (`scenario.target.extra["model_name"]`) — предупреждение, не ошибка (FR-015, research §13) в `src/memnotsafe/generation/config.py`
- [X] T022 [US1] Создать сценарии прогона корпуса `scenarios/generated_support.yaml` и `scenarios/generated_support_agent2.yaml` (`attack.family: generated` + `attack.corpus:`) по примеру из `contracts/cli-commands.md`
- [X] T023 [US1] Записывать провенанс корпусной атаки (`origin="corpus"`, `attack_class`, `corpus_id`) в `AttackResult.evidence["provenance"]` слоем кампании в `src/memnotsafe/core/campaign.py` (раннер не трогается — research §12)
- [X] T024 [US1] Сгенерировать и закоммитить эталонный корпус `corpora/support-agent.yaml` командой `generate --attacker-provider stub` (версионируемый вход прогона, research §5)

**Checkpoint**: US1 полностью работоспособна и проверяема независимо — MVP готов

---

## Phase 4: User Story 2 - Онлайн-адаптация: добить атаку, которую не взял корпус (Priority: P2)

**Goal**: при неуспехе атаки из корпуса атакующая LLM переписывает её по ответу защищающегося и
пробует снова — до предела попыток и бюджета, со стопом на первом успехе.

**Independent Test**: на `MockTarget` со `StubAttackerClient`, скриптованным «1-я попытка не
пробивает, 2-я пробивает»: с выключенным онлайн-уровнем атака честно `NOT_EXPLOITABLE`; с
включённым — успех со 2-й попытки, число попыток ≤ лимита.

### Tests for User Story 2 ⚠️

- [X] T025 [P] [US2] Тесты цикла эскалации: лимит попыток не превышается, стоп на первом успехе, исчерпание бюджета → `exit 0` + `budget_exhausted` в провенансе, сбой атакующей LLM → `AttackerError` и `exit 1` с сохранением уже полученных результатов (SC-004, SC-005, FR-010, FR-011), в `tests/test_escalation.py`
- [X] T026 [P] [US2] Офлайн e2e US2 «fail→success» на `MockTarget` + `StubAttackerClient`, доказывающий и успех, и честный `NOT_EXPLOITABLE` (SC-006), в `tests/test_generation_offline.py`

### Implementation for User Story 2

- [X] T027 [US2] Добавить промпт переписывания атаки по обратной связи (ответ защищающегося + воронка стадий + прошлая запись) в `src/memnotsafe/generation/prompts.py`
- [X] T028 [US2] Реализовать ЧИСТУЮ функцию `rewrite(feedback, client, budget) -> CorpusRecord` (без знания о таргете и раннере; невалидный ответ модели отбраковывается) в `src/memnotsafe/generation/rewrite.py` (зависит от T027)
- [X] T029 [US2] Реализовать dataclass'ы `EscalationFeedback`/`EscalationOutcome` и цикл эскалации вокруг **немодифицированного** `run_attack` (тристейт воронки переносится как есть, `None` не схлопывается в `True` — Принцип IV) в `src/memnotsafe/core/escalation.py` (зависит от T028)
- [X] T030 [US2] Дополнять `AttackResult.evidence["provenance"]` полями `origin="online"`, `attempts`, `budget_exhausted` слоем эскалации в `src/memnotsafe/core/escalation.py` (зависит от T029)
- [X] T031 [US2] Вызывать цикл эскалации из `src/memnotsafe/core/campaign.py` при включённом онлайн-уровне и `success=False`, сохраняя уже полученные результаты при досрочном выходе (FR-010) (зависит от T029)
- [X] T032 [US2] Создать сценарий `scenarios/generated_escalation.yaml` и скриптованные ответы заглушки «первая попытка не пробивает, вторая пробивает» (research §9)
- [X] T033 [US2] Обеспечить разделение исходов в `src/memnotsafe/cli.py`: `AttackerError` → `exit 1` с сообщением в `stderr`; исчерпание лимита попыток/бюджета → `exit 0` + finding `NOT_EXPLOITABLE`; в обоих случаях уже собранные результаты записаны в `runs/<name>/` (FR-011, SC-005)

**Checkpoint**: US1 и US2 работают независимо; онлайн-уровень вызываем программно

---

## Phase 5: User Story 3 - Включить онлайн-эскалацию флагом CLI (Priority: P2)

**Goal**: одна опция CLI управляет тем, работает ли прогон только на корпусе или поднимается на
онлайн-уровень с заданным пределом попыток и бюджетом.

**Independent Test**: один и тот же сценарий прогоняется дважды — без флага поведение и стоимость
совпадают с текущим инструментом (ноль вызовов атакующей LLM), с флагом включается онлайн-уровень и
предел попыток берётся из опции (`--online-attempts 1` → ровно одна попытка).

### Tests for User Story 3 ⚠️

- [X] T034 [P] [US3] Тесты CLI-флагов: без `--online` — ноль вызовов атакующей LLM и результат идентичен прогону без фичи (SC-003); с `--online --online-attempts 1` — ровно одна попытка и `NOT_EXPLOITABLE` (SC-004), в `tests/test_escalation.py`

### Implementation for User Story 3

- [X] T035 [US3] Добавить флаги `--online` (по умолчанию ВЫКЛ) и `--online-attempts` (по умолчанию 5) командам `run` и `campaign` в `src/memnotsafe/cli.py` по `contracts/cli-commands.md` (FR-008, FR-009)
- [X] T036 [US3] Вынести общий блок флагов атакующей LLM (`--attacker-provider`/`--attacker-model`/`--attacker-base-url`/`--attacker-api-key-env`/`--attacker-budget`) в переиспользуемый хелпер и подключить его к `generate`, `run` и `campaign` в `src/memnotsafe/cli.py` (зависит от T035)
- [X] T037 [US3] Прокинуть `AttackerConfig` и предел попыток из CLI в слой кампании/эскалации, обеспечив, что при выключенном `--online` атакующая LLM не инстанцируется вовсе, в `src/memnotsafe/cli.py` и `src/memnotsafe/core/campaign.py` (зависит от T036)

**Checkpoint**: онлайн-уровень управляется из CLI; поведение по умолчанию не изменилось

---

## Phase 6: User Story 4 - Отчёт объясняет происхождение атаки и число попыток (Priority: P3)

**Goal**: в отчёте у каждой находки видно происхождение (рукописный пак / корпус / онлайн) и — для
онлайновых — число попыток и факт исчерпания бюджета.

**Independent Test**: после смешанного прогона `runs/<name>/report/findings.json` содержит у каждой
находки `evidence.provenance.origin`, у онлайновых — `attempts`; агрегат прогона показывает
суммарное число вызовов атакующей LLM и `budget_exhausted`.

### Tests for User Story 4 ⚠️

- [ ] T038 [P] [US4] Тесты провенанса в отчёте: `origin` у каждой находки, `attempts` у онлайновых, агрегат стоимости в `campaign.json`, корректный severity/ATLAS для `family=generated` (SC-007, FR-013, FR-014), в `tests/test_escalation.py`

### Implementation for User Story 4

- [ ] T039 [US4] Резолвить severity и ATLAS-маппинг по `evidence.provenance.attack_class` (а не по `family="generated"`) в `src/memnotsafe/reporting/findings.py` (FR-003, FR-013, research §2)
- [ ] T040 [US4] Писать агрегат стоимости прогона (суммарные вызовы атакующей LLM, `budget_exhausted`) рядом с существующим `metadata` в `campaign.json` в `src/memnotsafe/core/campaign.py` (FR-014, research §12)
- [ ] T041 [P] [US4] Показывать происхождение атаки и число попыток в отчётах: `src/memnotsafe/reporting/html_report.py`, `src/memnotsafe/reporting/json_report.py`, `src/memnotsafe/reporting/sarif.py` (зависит от T039)

**Checkpoint**: все user stories независимо работоспособны

---

## Phase 7: Polish & Cross-Cutting Concerns

- [ ] T042 [P] Дополнить `README.md` разделом о генерации корпуса и многоуровневой эскалации: команда `generate`, флаги `--online*`, каталоги `profiles/`/`attack_classes/`/`corpora/`, работа офлайн через `--attacker-provider stub`
- [ ] T043 Прогнать все сценарии из `specs/004-llm-attack-generation/quickstart.md` (сценарии 1–6) и убедиться, что фактические коды возврата и артефакты совпадают с ожидаемыми
- [ ] T044 Проверить соблюдение SC-008: `git diff main -- src/memnotsafe/core/runner.py src/memnotsafe/core/models.py src/memnotsafe/oracles/ src/memnotsafe/attacks/base.py` пуст
- [ ] T045 Прогнать полный набор тестов `python3 -m pytest tests/ -q`: все ранее существовавшие тесты зелёные (baseline 174) плюс новые офлайн-тесты фичи

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: без зависимостей
- **Foundational (Phase 2)**: зависит от Phase 1 — БЛОКИРУЕТ все user stories
- **US1 (Phase 3)**: зависит от Phase 2. Самостоятельная ценность — MVP
- **US2 (Phase 4)**: зависит от Phase 2; практический смысл — поверх корпуса US1
- **US3 (Phase 5)**: зависит от Phase 4 (нечего включать без цикла эскалации)
- **US4 (Phase 6)**: зависит от US1 (провенанс корпуса) и US2 (attempts/бюджет)
- **Polish (Phase 7)**: после всех желаемых историй

### User Story Dependencies

- **US1 (P1)**: стартует сразу после Foundational, ни от одной истории не зависит
- **US2 (P2)**: технически независима от US1 (эскалация работает и над рукописной атакой), но
  осмысленна поверх корпуса
- **US3 (P2)**: управляющая обвязка US2 — требует T029/T031
- **US4 (P3)**: надстройка над провенансом, который пишут US1 (T023) и US2 (T030)

### Parallel Opportunities

- Phase 1: T002, T003 параллельно
- Phase 2: T004, T005 параллельно; затем T008, T009 параллельно с T006/T007
- Phase 3: T014, T015 параллельно (тесты); T018, T019 параллельно (фикстуры данных)
- Phase 4: T025, T026 параллельно (тесты)
- Phase 6: T041 параллельно с T040
- Phase 7: T042 параллельно с T043/T044

---

## Parallel Example: User Story 1

```bash
# Тесты US1 — вместе (разные файлы):
Task: "Тесты валидации профиля/классов/корпуса в tests/test_profile_and_corpus.py"
Task: "Офлайн e2e US1 в tests/test_generation_offline.py"

# Фикстуры данных US1 — вместе (разные каталоги):
Task: "Профили в profiles/support-agent.yaml и profiles/broken-no-effect.yaml"
Task: "Описания классов в attack_classes/*.yaml"
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Phase 1: Setup
2. Phase 2: Foundational (КРИТИЧНО — блокирует все истории)
3. Phase 3: US1 — генерация корпуса и его прогон
4. **STOP и ПРОВЕРИТЬ**: сценарии 1–2 из quickstart.md, `tests/test_profile_and_corpus.py` и
   `tests/test_generation_offline.py` зелёные
5. Это уже снимает исходный блокер «для не-инвестиционного агента нет данных» (SC-001)

### Incremental Delivery

1. Setup + Foundational → фундамент готов
2. US1 → корпус генерируется и прогоняется → **MVP**
3. US2 → онлайн-эскалация работает программно
4. US3 → эскалация включается флагом CLI
5. US4 → отчёт объясняет происхождение и стоимость

### Parallel Team Strategy

После Foundational: разработчик A — US1 (Phase 3); разработчик B — US2 (Phase 4) на рукописной
атаке; US3 подхватывается тем, кто закончил US2; US4 — последним, поверх обоих провенансов.

---

## Notes

- Правки ядра запрещены — см. раздел «Baseline и запреты» выше (SC-008)
- Секреты только через `api_key_env`; ни `profiles/`, ни `corpora/`, ни `scenarios/` не содержат
  ключей (FR-016)
- Весь e2e обязан проходить офлайн на `MockTarget` + `StubAttackerClient` (Принцип VI, SC-006)
- Коммит после каждой задачи или логической группы; сообщения на русском по правилам конституции
- На любом checkpoint можно остановиться и валидировать историю независимо
