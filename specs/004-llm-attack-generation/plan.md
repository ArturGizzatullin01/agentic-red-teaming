# Implementation Plan: LLM-генерация атак и многоуровневая эскалация

**Branch**: `004-llm-attack-generation` | **Date**: 2026-09-06 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `specs/004-llm-attack-generation/spec.md`

## Summary

Фича добавляет два связанных слоя поверх существующего target-agnostic ядра, **не трогая его**:

1. **Precompute-генерация корпуса атак** (US1) под произвольного агента: по декларативному
   файлу-профилю и универсальным описаниям классов атак атакующая LLM порождает конкретные payload'ы
   и триггеры, сохраняемые в версионируемый корпус (`corpora/*.yaml`) для переиспользования.
2. **Онлайн-эскалация** (US2/US3): при неуспехе атаки из корпуса атакующая LLM переписывает её по
   ответу защищающегося и пробует снова, до предела попыток и бюджета; включается флагом CLI.

Технический стержень (из [research.md](research.md)): корпус — это **данные**, исполняемые одним
универсальным `GeneratedAttack(AttackBase)` через готовый шов `AttackContext.params`; эскалация живёт
в новом `core/escalation.py`, который в цикле вызывает **немодифицированный** `run_attack`; атакующая
LLM — отдельный клиент `generation/` с офлайн-заглушкой для CI. Провенанс и стоимость собирает слой
эскалации/кампании и кладёт в `evidence`, чтобы раннер и модели ядра остались нетронутыми (SC-008).

**Файл-аналог (обязателен по конституции)**: новая атака повторяет форму
[attacks/cross_user_bac.py](../../src/memnotsafe/attacks/cross_user_bac.py) +
[scenarios/cross_user_bac.yaml](../../scenarios/cross_user_bac.yaml) +
[tests/test_all_attacks.py](../../tests/test_all_attacks.py); новый сетевой клиент повторяет паттерн
[adapters/openai.py](../../src/memnotsafe/adapters/openai.py). Правки ядра
(`core/runner.py`, `oracles/*`, `oracles/composite.py`) **запрещены**.

## Technical Context

**Language/Version**: Python 3.11+ (`requires-python = ">=3.11"`, `pyproject.toml`).

**Primary Dependencies**: stdlib + `pyyaml>=6.0` (профили/классы/корпуса), `httpx>=0.27` (HTTP-клиент
атакующей LLM — та же зависимость, что у `adapters/openai.py`). Новых зависимостей не вводится.

**Storage**: файлы. Версионируемые входы: `profiles/`, `attack_classes/`, `corpora/` (YAML,
коммитятся). Выходы прогона: `runs/<name>/` (как сейчас, не коммитятся).

**Testing**: `pytest` (`pythonpath=["src"]`, `testpaths=["tests"]`), полностью офлайн на `MockTarget`
и `StubAttackerClient`. Существующие 12 тестов остаются зелёными (SC-008).

**Target Platform**: CLI-инструмент, локальный запуск и CI (Linux/macOS).

**Project Type**: single project (src-layout, CLI-пакет `memnotsafe`).

**Performance Goals**: не latency-критично; ограничитель — **бюджет вызовов** атакующей LLM
(`CallBudget`), а не пропускная способность. Precompute оплачивается один раз и переиспользуется.

**Constraints**: секреты только через `api_key_env` (FR-016); ядро (Runner/Oracle/composite) не
изменяется (SC-008); весь e2e проходит офлайн без сети/ключей/Docker (Принцип VI, SC-006); коды
возврата различают сбой генерации и честный `NOT_EXPLOITABLE` (Принцип VII, FR-011).

**Scale/Scope**: 5 существующих family как источник описаний классов; корпус десятков атак на профиль;
онлайн-лимит по умолчанию 5 попыток на атаку.

## Constitution Check

*GATE: пройден до Phase 0 и повторно после Phase 1 design. Нарушений нет — Complexity Tracking пуст.*

| Принцип | Как соблюдается | Ссылка |
|---------|-----------------|--------|
| I. Разделение ролей | Генерация/rewrite — чистые (ЧТО); эскалация в `core/` решает КОГДА повторить; provenance пишет слой эскалации, Reporter только показывает; атака не дёргает LLM/адаптер | research §1, §6, §8, §12 |
| II. Новая атака — новый файл | Один `attacks/generated.py`, data-driven; корпус — данные, не код; ядро не трогается | research §1 |
| III. Ядро не знает о таргетах | Генерация target-agnostic (по профилю); `escalation.py` без стенд-ветвлений; знание о таргете — только в адаптерах | research §6, §7 |
| IV. Тристейт UNKNOWN | Композит не меняется; воронка стадий как есть уходит в feedback; UNKNOWN не читается как True | research §7 |
| V. Композит + external_effect | Формула не меняется; `compromise.external_effect` обязателен в профиле — иначе `success` невозможен | research §3 |
| VI. Офлайн mock + настоящая уязвимость | `StubAttackerClient` + `MockTarget`: e2e доказывает и success, и честный `NOT_EXPLOITABLE` офлайн | research §9 |
| VII. Коды возврата | `AttackerError` (сбой LLM) → exit 1; бюджет исчерпан / атака не пробила → exit 0 + `NOT_EXPLOITABLE` | research §11 |
| VIII. Типизированные dataclass | `AttackerConfig`, `CorpusRecord`, `Corpus`, `EscalationFeedback`, `EscalationOutcome`, `CallBudget`; dict только для сырого провенанса в `evidence` | data-model |

**Документация**: артефакты плана — ASCII-имена, русский текст, кодовые блоки с языком, относительные
ссылки резолвятся, ширина ≤100 (правила 1,5,6,7,10,13 конституции для `specs/**`).

**Quality gate фичи**: существующие тесты зелёные; новая функциональность покрыта офлайн-тестом на
mock (Принцип VI); ядро не изменено.

## Project Structure

### Documentation (this feature)

```text
specs/004-llm-attack-generation/
├── plan.md              # этот файл (/speckit-plan)
├── research.md          # Phase 0 (§1–§14 + значения по умолчанию)
├── data-model.md        # Phase 1 — сущности и их связи
├── quickstart.md        # Phase 1 — сценарии валидации US1–US4
├── contracts/           # Phase 1 — схемы профиля/классов/корпуса + CLI
│   ├── agent-profile.schema.md
│   ├── attack-class.schema.md
│   ├── corpus.schema.md
│   └── cli-commands.md
├── checklists/
│   └── requirements.md  # уже есть (quality checklist)
└── tasks.md             # Phase 2 (/speckit-tasks — НЕ создаётся этой командой)
```

### Source Code (repository root)

```text
src/memnotsafe/
├── attacks/
│   └── generated.py          # НОВОЕ: GeneratedAttack(AttackBase), family="generated", data-driven
├── generation/               # НОВЫЙ пакет: атакующая LLM + генерация + rewrite (чистое ЧТО)
│   ├── __init__.py
│   ├── config.py             # AttackerConfig + выбор провайдера (stub|openai)
│   ├── attacker_client.py    # AttackerClient(Protocol), HTTPAttackerClient, StubAttackerClient
│   ├── errors.py             # AttackerError (сбой/бюджет генерации ≠ RunnerError)
│   ├── budget.py             # CallBudget — счётчик вызовов атакующей LLM
│   ├── prompts.py            # промпты генерации/переписывания с оградой (guardrail)
│   ├── profile.py            # загрузка/валидация файла-профиля агента
│   ├── attack_classes.py     # загрузка реестра описаний классов атак
│   ├── corpus.py             # dataclass Corpus/CorpusRecord + read/write YAML + provenance
│   ├── corpus_gen.py         # precompute: (профиль + классы + LLM) → Corpus
│   └── rewrite.py            # ЧИСТАЯ: EscalationFeedback → следующая CorpusRecord (через LLM-текст)
├── core/
│   ├── escalation.py         # НОВОЕ: онлайн-цикл вокруг немодифицированного run_attack (КОГДА)
│   ├── campaign.py           # ПРАВКА: прогон корпуса записями + вызов escalation при --online
│   ├── config.py             # ПРАВКА: Scenario.corpus_path; резолв family=generated
│   └── runner.py             # НЕ ТРОГАЕТСЯ (SC-008)
├── oracles/                  # НЕ ТРОГАЕТСЯ (SC-008)
├── reporting/
│   └── findings.py           # ПРАВКА: severity/ATLAS по provenance.attack_class (FR-013)
└── cli.py                    # ПРАВКА: команда `generate`; флаги --online/--online-attempts/--attacker-*

profiles/                     # НОВОЕ (версионируется): файлы-профили агентов
attack_classes/               # НОВОЕ (версионируется): описания классов атак (1 YAML на класс)
corpora/                      # НОВОЕ (версионируется): сгенерированные корпуса — вход прогона
scenarios/
└── generated_support.yaml    # НОВОЕ: пример сценария family=generated + corpus: corpora/...

tests/
├── test_generation_offline.py    # НОВОЕ: US1+US2 e2e офлайн на MockTarget + StubAttackerClient
├── test_profile_and_corpus.py    # НОВОЕ: валидация профиля/корпуса, отбраковка невалидной атаки
├── test_escalation.py            # НОВОЕ: лимит попыток, стоп на успехе, бюджет, коды возврата
└── (существующие 12 тестов остаются зелёными)
```

**Structure Decision**: single project, src-layout — как во всём репозитории. Вся новая логика
добавляется **файлами** (пакет `generation/`, `attacks/generated.py`, `core/escalation.py`) и
аддитивными правками не-ядровых модулей (`campaign.py`, `config.py`, `findings.py`, `cli.py`).
Ядро (`runner.py`, `oracles/*`, `composite.py`, `models.py`) не изменяется — соответствие Принципам
I–III и SC-008. Директории данных (`profiles/`, `attack_classes/`, `corpora/`) версионируются как
входы, зеркаля роль `scenarios/`.

## Complexity Tracking

> Нарушений Constitution Check нет — таблица пуста.

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| —         | —          | —                                   |
