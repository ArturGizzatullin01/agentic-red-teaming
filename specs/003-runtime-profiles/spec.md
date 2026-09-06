# Feature Specification: Runtime-профили ролей и provenance

**Feature Branch**: `003-runtime-profiles`

**Created**: 2026-09-06

**Status**: Draft

## Дополнение пользователя: пресеты трёх ролей

Требования интерфейса и две заданные комбинации определены в
[контракте запуска пресетов](contracts/launch-presets.md).
FR-PRESET-1: независимый выбор attacker/target, фиксированный DeepSeek judge
и сохранённые комбинации. Уточнение пользователя 2026-09-06 заменяет выбор judge.
FR-PRESET-2: запуск карточкой без ручной правки YAML, единый resolver с CLI.
FR-PRESET-3: одна модель допустима в нескольких ролях с изолированными инструкциями.
FR-PRESET-4: смена LLM внутри стенда, проверка совместимости и фактической модели.
FR-PRESET-5: защита общего стенда от параллельных переключений, отмена и restore.
FR-PRESET-6: provenance конфигурации и фактического использования ролей.
FR-PRESET-7: runtime judge только DeepSeek; иной judge в UI/CLI/scenario/preset
не допускается, автоматической подмены модели нет. Offline остаётся без LLM-судьи.
Дополнение находится на стадии проектирования и требует analyze до реализации.

**Input**: User description: "Типизированные профили ролей (attacker/judge),
подключение runtime-генерации вне ядра, независимый judge bridge, операторская
утилита смены target с readback/rollback, provenance во всех отчётах.
Основание — [аудит A09–A11](../../docs/integration-handoff/audit.md)."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Выбор аттакера реально меняет генерацию (Priority: P1)

Оператор выбирает attacker preset (static — дефолт, либо runtime: qwen/glm).
Выбор подтверждается фактическим запросом в транспорт (не только YAML), judge
и target не меняются.

**Why this priority**: без реального выбора аттакера переносимые атаки не
воспроизводят донорские варианты и матрица атака×аттакер×target невозможна.

**Independent Test**: fake HTTP transport фиксирует запрос и его модель; смена
preset меняет запрос, не меняет judge/target в provenance.

**Acceptance Scenarios**:

1. **Given** preset qwen выбран, **When** кампания стартует, **Then** генерация
   candidate выполнена сервисом вне ядра через выбранный провайдер, запрос
   зафиксирован fake-транспортом.
2. **Given** preset неизвестен или ключ ENV отсутствует, **When** кампания стартует,
   **Then** понятная ошибка ДО reset/delivery, exit 1, кампания не запускается.
3. **Given** static preset (дефолт), **When** кампания идёт, **Then** сетевых вызовов
   нет, аттакер помечен inactive в provenance.

### User Story 2 - Смена target доказывается readback и доживает до кампании (Priority: P1)

Операторский wrapper переключает модель тестового стенда и запускает переданную
команду кампании под новой моделью: сохранить профиль → apply → recreate → readback →
health → непустой sanity → **запуск кампании** → restore в finally (исправление R2:
restore после apply без кампании не имеет смысла — кампания ушла бы на старой модели).

**Why this priority**: A09 — sanity без readback не доказывает идентичность модели;
мгновенный restore ломает смысл переключения; сломанный restore оставляет стенд в
чужом состоянии.

**Independent Test**: fake process runner и fake HTTP: fake campaign наблюдает новую
модель; после него (включая падение кампании) восстановлена старая; readback
mismatch/unavailable блокирует запуск кампании; сбой restore — отдельная ошибка с
фактически оставшимся состоянием.

**Acceptance Scenarios**:

1. **Given** профиль применён и сервис пересоздан, **When** readback выполняется,
   **Then** фактическая модель взята из конфигурации стенда (без секретов) и записана
   в provenance; при отсутствии readback кампания не запускается, а запрошенная
   модель не пишется как фактическая.
2. **Given** sanity вернул пустой ответ, **When** wrapper завершается, **Then**
   кампания не запущена, exit ненулевой, состояние стенда восстановлено или ошибка
   restore видима.
3. **Given** кампания упала и restore упал, **When** wrapper завершается, **Then**
   exit 1, stderr содержит обе ошибки и фактическое состояние стенда.
4. **Given** wrapper завершился (успех или сбой), **When** finally выполняется,
   **Then** исходный профиль стенда восстановлен; общий `.env.bak` не перетирается
   безымянными переключениями.

### User Story 3 - Provenance в отчётах (Priority: P1)

Каждый отчёт (JSON, HTML, metrics, report/replay) содержит RunProvenance: schema
version, seed, variant, scenario hash, candidate hash, requested/resolved модели трёх
ролей, effective_channel, статус исполнения.

**Why this priority**: SC-004/FR-007 — без атрибуции исторические и новые результаты
несмешиваемы; матрица атака×аттакер×target не строится.

**Independent Test**: report и replay одного прогона дают идентичный provenance-блок;
отсутствующие данные помечены unknown с причиной.

**Acceptance Scenarios**:

1. **Given** кампания завершена, **When** отчёт сгенерирован, **Then** provenance
   присутствует во всех форматах и переживает replay без изменений.
2. **Given** judge не использовался (static attacker), **When** provenance собирается,
   **Then** judge помечен inactive, а не фиктивной моделью.

---

## Requirements

- FR-A: `RoleProfile` и `RunProvenance` — типизированные dataclass; legacy-словари
  конвертируются на границе, массовая миграция не входит.
- FR-B: precedence CLI → scenario → default; валидация до reset/delivery.
- FR-C: runtime-генерация — отдельный сервис вне `AttackBase`; runner вызывает его
  до доставки; static путь использует текущий sync generate; без `asyncio.run` внутри loop.
- FR-D: judge bridge отдельный, structured output, ограниченные retries; judge не
  меняется при смене attacker; LLM-судья не выставляет composite success.
- FR-E: `content` — основной output; `reasoning_content` — явно включённая
  совместимость с валидацией и пометкой fallback; пустой/невалидный output —
  ограниченный retry, затем ошибка.
- FR-F: модели активных ролей сравниваются по resolved provider/model, не по alias.
- FR-G: утилита смены target принимает путь к отдельному compose-проекту; разрешённые
  identities 1001/1002; порты проверяются до запуска; общий reset БД запрещён.

Требования-источник: FR-006, FR-007, FR-009 ([спека переноса](../../docs/integration-handoff/spec.md)),
контракты ролей ([contracts](../../docs/integration-handoff/contracts.md)).

## Success Criteria

- SC: fake-транспорт подтверждает, что выбор attacker реален (запрос, модель).
- SC: все форматы отчётов содержат provenance; replay идемпотентен.
- SC: недоступный провайдер/ключ/пресет — ошибка до кампании, exit 1.
