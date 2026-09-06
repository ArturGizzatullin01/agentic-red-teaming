# Tasks: последовательность заданий GLM

Все задания пока открыты. Идентификатор этапа и критерий выхода обязательны в handoff.
Пути коду ниже относительны к целевому `agentic-red-teaming-main`.

## Phase 1: исходная база и SDD

- [ ] T001 GLM 5.3: создать отдельную рабочую копию архива команды, прочитать локальные
  правила, сверить SHA256 с manifest, не перезаписывать донор и его незакоммиченные правки.
- [ ] T002 Flash: установить зависимости в отдельное окружение; выполнить baseline
  `python -m pytest tests/ -q`; сохранить команду, exit и сводку, не обещать число тестов.
- [ ] T003 GLM 5.3: создать SDD-документы 002–005 из этого пакета, пройти clarify/analyze;
  записать решения по запрету core и dataclass; подготовить поправку атрибуции коммитов.

Gate: воспроизводимый baseline и отсутствие нерешённых конституционных конфликтов.

## Phase 2: evidence integrity — GLM 5.3

- [ ] T004 [US4] `tests/test_runner_lifecycle.py`, `core/runner.py`: regression на запись
  только при finalize, порядок finalize/settle, закрытие сессий при исключениях.
- [ ] T005 [US4] `evidence/matching.py`, `oracles/base.py`, `adapters/investment_stand.py`:
  case-marker, diff, ownerless records, Unicode, пустые записи и таймауты settle.
- [ ] T006 [US4] `oracles/adoption.py`, `external_effect.py`, `tool.py`:
  trigger-only evidence и корреляция вызовов; отказ с маркером не проходит.
- [ ] T007 [US4] `tests/test_evidence_integrity.py`: old marker, install-only echo,
  неизвестный author, чужой principal, несвязанные call/result, missing telemetry.
- [ ] T008 [US4] проверить неизменность `oracles/composite.py` и отчётных шести стадий;
  прогнать baseline suite, оформить review этапа.

Зависимости: T004–T008 после T003. Отдельный инфраструктурный diff, не перенос атаки.

## Phase 3: runtime profiles — GLM 5.3, затем Flash на тесты

- [ ] T009 [US3] `core/models.py`, `core/config.py`, `cli.py`: типизированные профили,
  precedence CLI → scenario → default, validation и legacy compatibility.
- [ ] T010 [US3] новый сервис генерации вне core, подключение в `core/runner.py`:
  async attacker → валидированный candidate; static путь без сети.
- [ ] T011 [US3] `oracles/adoption.py`: отдельный judge bridge, structured output,
  ограниченные retries, evidence-based оценка; детерминированный путь первым.
- [ ] T012 [US3] `scripts/set_stand_target.py` в целевом проекте: явный stand path,
  recreate/readback/sanity/restore; fake process tests, без автоматического live запуска.
- [ ] T013 [US3] `reporting/json_report.py`, `html_report.py`, `metrics.py`, `cli.py`:
  provenance во всех форматах и сохранность при report/replay, schema version.
- [ ] T014 [US3] `tests/test_role_profiles.py`, `test_target_switch.py`:
  конфликт моделей, missing ENV, invalid preset, пустой output, 429, rollback failure.

Зависимости: T009 после T008; T010–T014 после определения контрактов T009.
Gate: выбор attacker подтверждён реальным запросом в fake transport, не только YAML.

## Phase 4: attack port — Flash, одна атака на задание

- [ ] T015 [US2] `attacks/procedural_graft.py`, `scenarios/procedural-graft.yaml`.
- [ ] T016 [US2] `attacks/consent_laundering.py`, `scenarios/consent-laundering.yaml`.
- [ ] T017 [US2] `attacks/document_regulation_graft.py`, соответствующие plain/global YAML.
- [ ] T018 [US2] `attacks/cross_topic_smuggle.py`, user/global YAML.
- [ ] T019 [US2] `attacks/tool_error_echo_poisoning.py`, direct YAML.
- [ ] T020 [US2] для каждого T015–T019: импорт в `attacks/__init__.py`, регистрация,
  `tests/test_all_attacks.py`, поведенческий mock, protected-negative и описание канала.
- [ ] T021 [US5] GLM 5.3: cross-user oracles и тесты по contracts; Flash затем портирует
  `attacks/cross_user_scope_global.py`, без изменений core.
- [ ] T022 [US5] GLM 5.3: `policy_evicted` adoption/effect и контрольный baseline;
  Flash затем портирует `attacks/policy_flood_eviction.py` как experimental.
- [ ] T023 [US5] Flash: zwsp и conditional risk, после T021–T022 и проверки источников.

T015–T020 после T014. Каждое задание включает собственные тесты и GLM review.
Запрещён `core/` diff в этой фазе; нужда в новом контракте возвращается в SDD-инфраструктуру.

## Phase 5: cold start и выпуск

- [ ] T024 [US1] `pyproject.toml`, `README.md`, `.env.example`, live example scenarios:
  wheel/install, опциональная Mongo, Windows/Linux команды и проверка отсутствующих ENV.
- [ ] T025 [US4] исторический manifest/агрегат в docs; fixtures очистить, raw не коммитить;
  findings конвертировать через `reporting/findings.py`, сохранив historical status.
- [ ] T026 [US1] чистая установка и пять основных сценариев; protected mode и UNKNOWN;
  report/replay без исходного донора. Проверить Markdown и секреты в поставке.
- [ ] T027 [US4] отдельный локальный live-стенд, фиксированный профиль, n>=5 на каждую
  основную атаку; cross-user/flood n>=10 при включении в демонстрацию.
- [ ] T028 GLM 5.3: итоговый аудит по [acceptance.md](acceptance.md), отчёт о readiness,
  остаточных дефектах и фактически выполненных командах. PR только после quality gate.

T024–T028 после основных T015–T020. Экспериментальные T021–T023 не блокируют основной релиз,
но их нельзя объявлять реализованными или доказанными, если они отложены.
