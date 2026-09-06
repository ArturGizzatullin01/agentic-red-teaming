# Feature Specification: Cold start и выпуск

**Feature Branch**: `005-cold-start-release`

**Created**: 2026-09-06

**Status**: Draft

**Input**: User description: "Установка из wheel в чистом окружении, офлайн-демо на
mock без ключей/сети/Docker, документация Windows/Linux, исторический manifest/агрегат
в docs, live-протокол на отдельном стенде, финальный аудит по приёмке.
Основание — [acceptance.md](../../docs/integration-handoff/acceptance.md)."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Чистый офлайн-запуск (Priority: P1)

Разработчик устанавливает собранный wheel вне исходного дерева и получает отчёт по
атаке: без ключей, сети, Docker, Mongo и донорской папки.

**Why this priority**: «из коробки» — главный результат выпуска; SC-001.

**Independent Test**: чистое venv, `pip install dist/*.whl`, run demo-сценария,
отчёт; повторить на Windows и Linux.

**Acceptance Scenarios**:

1. **Given** пустое окружение, **When** wheel установлен и mock-сценарий запущен,
   **Then** отчёт содержит vulnerable-positive и protected-negative, шесть стадий,
   exit 0.
2. **Given** переменные окружения ключей отсутствуют, **When** запрошен live-таргет,
   **Then** понятная ошибка до кампании (offline-путь не требует ключей).

### User Story 2 - Проверяемый live-результат (Priority: P1)

Оператор на отдельном локальном стенде получает доказательства с раздельными
execution error / completed failure / UNKNOWN / composite success.

**Why this priority**: SC-006 — live readiness по протоколу, не по историческому ASR.

**Independent Test**: не менее пяти свежих повторов каждой основной атаки в одном
профиле; cross-user/flood n>=10 при включении в демонстрацию.

**Acceptance Scenarios**:

1. **Given** live-профиль зафиксирован (модели, seed, версия), **When** кампания
   завершена, **Then** каждая попытка содержит provenance или явный unknown с причиной.
2. **Given** попытка завершилась ошибкой исполнения, **When** агрегат строится,
   **Then** она не смешана с completed failure и не участвует в ASR-числителе.

### User Story 3 - История перенесена честно (Priority: P2)

Исторические результаты донора публикуются как manifest/агрегат в docs с явной
атрибуцией и статусом «заявление источника»; сырые runs не коммитятся.

**Why this priority**: FR-007 — без атрибуции история смешивается с новыми данными.

**Independent Test**: агрегат содержит n/W/A/доли и пометку о смешанных целях; в
репозитории нет сырых runs/reports.

**Acceptance Scenarios**:

1. **Given** historical-summary.json, **When** конвертация findings, **Then**
   исторический статус сохранён, новые данные не присвоены.

---

## Requirements

- FR-A: `pyproject.toml` собирает wheel; установка и запуск вне src-checkout.
- FR-B: README: установка, опциональный Mongo extra, команды Windows/Linux, поведение
  при отсутствующих ENV.
- FR-C: live example scenarios с отдельным профилем стенда (порты, identities), без
  секретов; глобальный reset общей БД запрещён.
- FR-D: findings конвертируются через `reporting/findings.py` с сохранением
  historical status; fixtures — очищенные, маленькие; raw не коммитится.
- FR-E: Markdown-гигиена и секрет-скан поставки (конституция, раздел документации).
- FR-F: итоговый аудит по приёмке: offline gate + live gate, readiness-статус
  (`offline-ready` / `live-ready` / blockers).

Требования-источник: FR-001, FR-008, FR-010, FR-011
([спека переноса](../../docs/integration-handoff/spec.md)).

## Success Criteria

- SC-001 выполнена буквально: два чистых запуска (Windows/Linux) без сети.
- SC-006: live readiness подтверждён протоколом приёмки.
