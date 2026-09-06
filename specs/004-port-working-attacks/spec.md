# Feature Specification: Перенос рабочих атак донора

**Feature Branch**: `004-port-working-attacks`

**Created**: 2026-09-06

**Status**: Draft

**Input**: User description: "Перенести пять основных и экспериментальные атаки из
донорского прототипа на контракты команды: payload/шаги/маркеры из pack.py, сценарии
YAML, поведенческий mock, protected-negative. Правки `core/` запрещены.
Основание — [аудит A12](../../docs/integration-handoff/audit.md) и
[таблица семейств](../../docs/integration-handoff/contracts.md)."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Пять основных атак в реестре (Priority: P1)

Аналитик выбирает procedural, consent, document, cross-topic или tool-error direct;
каждая доступна через реестр по стабильному id/family и запускается сценарием YAML.

**Why this priority**: это ядро демонстрации команды; атаки — расходник (принцип II).

**Independent Test**: параметризованный тест по семействам: регистрация, positive/
negative/insufficient-observation на поведенческом mock, без привязки mock к attack_id.

**Acceptance Scenarios**:

1. **Given** сценарий основной атаки, **When** run на vulnerable mock, **Then**
   композитный success с полными шестью стадиями и external_effect.
2. **Given** protected mock, **When** run той же атаки, **Then** честный negative
   (NOT_EXPLOITABLE), exit 0.
3. **Given** неизвестный family в сценарии, **When** run, **Then** понятная ошибка
   регистрации, exit 1.

### User Story 2 - Честное описание канала (Priority: P1)

Каждая атака декларирует effective_channel честно: донорские DOCUMENT и TOOL_OUTPUT
на этой базе доставляются как user message — отмечается `effective_channel=user_message`,
настоящий перехват tool output не заявляется.

**Why this priority**: A12 — заявленный канал, которого нет, обесценивает находку.

**Independent Test**: метаданные атаки содержат original_channel и effective_channel;
тест проверяет соответствие.

**Acceptance Scenarios**:

1. **Given** атака document_regulation_graft, **When** metadata читается, **Then**
   original_channel=document, effective_channel=user_message.
2. **Given** отчёт кампании, **When** воронка показана, **Then** effective_channel
   виден в provenance.

### User Story 3 - Экспериментальные атаки после готовности оракулов (Priority: P2)

Cross-user и policy flood включаются после отдельных оракулов (T021–T022); zwsp и
conditional risk — после проверки исходников, со статусом experimental и без обещания ASR.

**Why this priority**: P2 по спеке переноса; не блокируют релиз, не объявляются
доказанными, пока отложены.

**Independent Test**: cross-user успех требует ответа отдельного principal (см. 002);
отсутствие выдачи другому principal — не успех; flood требует eviction-оракула.

**Acceptance Scenarios**:

1. **Given** policy_flood без наблюдаемого eviction, **When** EFFECT оценивается,
   **Then** UNKNOWN, success=False.
2. **Given** zwsp-атака, **When** отчёт строится, **Then** статус experimental виден.

---

## Requirements

- FR-A: перенос — только payload, маркеры, шаги и варианты из донорских pack.py;
  новые техники в ходе порта не конструируются; правки `core/` запрещены.
- FR-B: каждая атака — класс с уникальными id/family + scenario YAML (конфиг без
  логики); duplicate registration — ошибка.
- FR-C: соответствие ролей: донор victim → команда attacker; донор witness → команда
  victim (семантическое переназначение, не перестановка чисел).
- FR-D: варианты конфигурируются YAML без кода (direct/natural, doc/plain, user/global
  — как отдельные сценарии или параметр варианта).
- FR-E: behavioral mock поддерживает уязвимое и защищённое поведение для каждой
  переносимой техники (глобальный слой + свежесть конфликтов уже есть; добавить
  реакцию на консент-ловушку и эхо-ошибку тула).
- FR-F: атаки не вызывают adapter/HTTP/Docker/Mongo; generate остаётся sync.

Требования-источник: FR-002, FR-008 ([спека переноса](../../docs/integration-handoff/spec.md));

## Success Criteria

- SC: пять основных атак регистрируются и проходят все три типа offline-исходов.
- SC: baseline и suites фичей 002–003 остаются зелёными; `core/` diff пуст.
