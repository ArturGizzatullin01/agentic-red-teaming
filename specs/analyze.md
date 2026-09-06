# Analyze: сверка spec ↔ plan ↔ tasks ↔ tests (фичи 002–005)

**Created**: 2026-09-06. Артефакт этапа analyze (требование аудита R5: одна
каноническая нумерация + таблица requirement/task/test/open issue). Создание
файлов само по себе цикл не закрывает — таблица ниже и есть рабочая сверка;
пересматривается после каждого изменения документов.

## Каноническая нумерация и маппинг старых ID handoff

Канон: `T00N-M` (фича N, задача M). Старые ID `tasks.md` handoff сохранены в
таблице для трассировки; в документах фичей используются только канонические.

| Старый ID | Канон | Статус |
|---|---|---|
| T001 | T001 (выполнен, принят аудитором) | done |
| T002 | T002 (baseline: 35 passed, exit 0 — выполнен и повторён аудитором) | done |
| T003 | T003 (проектирование; настоящая ревизия — исправления R1–R6) | in-review |
| T004 | T002-3 | open |
| T005 | T002-1 + T002-2 + T002-6 | open |
| T006 | T002-4 + T002-5 | open |
| T007 | T002-8 | open |
| T008 | T002-9 | open |
| T009 | T003-1 + T003-2 | open |
| T010 | T003-3 + T003-4 | open |
| T011 | T003-5 | open |
| T012 | T003-6 + T003-7 | open |
| T013 | T003-8 | open |
| T014 | распределено: T003-2, T003-7, T003-8 (тесты внутри задач) | open |
| T015–T019 | T004-1 … T004-5 | open |
| T020 | T004-6 | open |
| T021 | T004-7 | open |
| T022 | T004-8 | open |
| T023 | T004-9 | open |
| T024–T026 | T005-1 … T005-5 | open |
| T027 | T005-6 | open |
| T028 | T005-7 | open |

Зависимости: T002-3 (lifecycle) НЕ зависит от T002-1/T002-2 — зависимость фазы
2→1 из ранней ревизии снята (R5); Phase 3 (002) — после T002-2; фича 003 — после
T002-9; фича 004 — после фичи 003; 005 — после T004-1…T004-6.

## 002-evidence-integrity: requirement → task → test

| Requirement | Task | Test |
|---|---|---|
| FR-A lifecycle (R3 владение) | T002-3 | test_runner_lifecycle.py: порядок, исключение, два case на одном target |
| FR-B case-marker (R4) | T002-1, T002-2, T002-7 | test_evidence_integrity: маркер/legacy/дубли/пустой (matcher-часть готова; producer — T002-7) |
| FR-C ownerless | T002-2 | test_evidence_integrity: ownerless-запись автору не приписывается; чужой source_user → UNKNOWN |
| FR-D нормализация | T002-1 | U+2011, U+FF0D, ZWSP, ANSI, `-`, ISIN/URL нетронуты |
| FR-E trigger-only | T002-5 | install-only echo, несвязанные call/result, чужой principal |
| FR-F композит неизменен | T002-9 | truth-table fixture; round-trip True/False/None (R1) |
| FR-G matching вне ядра | T002-1, T002-6 | grep mongo в core/oracles пуст; adapter-тесты |
| A01 | T002-3 | finalize → settle → новая trigger-сессия (порядок вызовов) |
| A02/A03 | T002-2, T002-1 | старая запись → UNKNOWN; пустой marker → ValueError; баг пустой подстроки исправлен (test_evidence_integrity) |
| A04/A05 | T002-5 | snapshot ≠ cross-user EFFECT |
| A07 | T002-1, T002-5 | отказ-с-цитатой ≠ adoption |

## 003-runtime-profiles: requirement → task → test

| Requirement | Task | Test |
|---|---|---|
| FR-A/FR-B профили+precedence | T003-1, T003-2 | test_role_profiles: unknown preset, missing ENV, конфликт ролей |
| FR-C генерация вне ядра (A10) | T003-3, T003-4 | fake transport: запрос реально ушёл; static без сети |
| FR-D judge bridge (R6) | T003-5 | детерминированный путь без judge; timeout → UNKNOWN; нет asyncio.run в loop |
| FR-E output-политика | T003-3 | пустой output → retry → ошибка; fallback помечен |
| FR-F readback (A09, R2) | T003-6, T003-7 | fake campaign видит новую модель; restore при падении кампании; две ошибки → exit 1 |
| FR-G provenance | T003-8 | test_provenance: replay идемпотентен; inactive-роли |

## 004-port-working-attacks: requirement → task → test

| Requirement | Task | Test |
|---|---|---|
| FR-A/FR-B порт без core | T004-1…T004-5 | core-дифф пуст (gate фичи) |
| FR-C соответствие ролей | T004-1…T004-5 | сценарные тесты attacker/victim |
| FR-D варианты YAML | T004-3, T004-4 | doc/plain, user/global сценарии |
| FR-E mock поведение | T004-6 | positive/negative/insufficient на mock; protected-negative |
| FR-F честный канал (A12) | T004-6 | original vs effective channel в metadata |
| P2 oracles | T004-7, T004-8 | cross-user principal-ответ; policy_evicted ветки |

## 005-cold-start-release: requirement → task → test

| Requirement | Task | Test |
|---|---|---|
| FR-A wheel | T005-1 | установка в чистое venv вне src (Windows; Linux) |
| FR-B README/ENV | T005-2 | missing ENV → понятная ошибка |
| FR-C live-профили | T005-3 | секрет-скан, порты/identities в примерах |
| FR-D история | T005-4 | findings с historical status; raw не в git |
| FR-F аудит | T005-7 | acceptance-offline / acceptance-live чек-листы |

## Открытые вопросы (open issues)

Дополнение 2026-09-06: FR-PRESET-1–7 фичи 003 → T003-9–12 и уточнения
T003-1/2/6/8 → fake routing, UI/CLI parity, cancellation/restore tests.
Контракт: [запуск пресетов](003-runtime-profiles/contracts/launch-presets.md).
Статус: пользовательское требование добавлено; полный analyze реализации впереди.
Уточнение: во всех runtime-пресетах судья DeepSeek; выбираются attacker и target.
Проверки включают отказ для другого judge и отсутствие автоматического fallback.

1. Атрибуция коммитов: поправка
   [agent-attribution-trailer.md](../docs/amendments/agent-attribution-trailer.md)
   не ратифицирована — GLM-коммиты заблокированы до PR команды. Gate для Phase 2+.
2. Донорские pack.py передаются кодеру отдельно (не в репозитории команды) —
   задача T004-1 блокирована на передачу источников. Gate для фичи 004.
3. Live-профиль: фактическая модель стенда и доступность провайдеров проверяются
   probe при реализации T003-6; handoff-описание не гарантирует доступность
   (не блокирует 002–003, gate для 005 live gate).
4. `reasoning_content`-совместимость: включается флагом профиля; значение по
   умолчанию (off) подтвердить при T003-3 на fake transport.
