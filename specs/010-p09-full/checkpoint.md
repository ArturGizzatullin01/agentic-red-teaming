# Checkpoint: 010 — P09-full offline

## 2026-09-14 — старт

- R1 завершён пользователем: локальный `main = f3b4e02` (fast-forward от
  `cbd7e6b` через принятую цепочку; origin/GitHub выведены из контура
  решением пользователя — аккаунт suspended).
- C10 = **PASS** (сетевая сессия разрешена пользователем): wheelhouse 12 колёс,
  wheel `memnotsafe-0.1.0` (sha256 270c73a2…), чистый venv вне репо,
  `pip install --no-index --find-links`, `pip check` зелёный, импорт из
  site-packages, installed-CLI smoke по всем 7 командам и режимам вывода —
  зелёный. Полная доказательная запись: gate-док
  `specs/007-evidence-foundation/offline-install-gate.md` (раздел «Вердикт (финал)»).
- Создан worktree `worktrees/p09-full`, ветка `feature/p09-full` от `main=f3b4e02`.
- Карточка 010 оформлена (spec/plan/tasks/checkpoint); карточка 008 перенесена
  в рабочий контекст (требования §3/§6/§7 учтены: намерение ≠ факт, absent ≠
  proven absence, слот context_tool_evidence — теперь реально вносится).

## Журнал

### 2026-09-15 — D3 закрыт: L2-драйвер мерит исход штатной оценкой (fix/p09-l2-driver)

Отдельная live-gated карточка (последний открытый пункт RETURN_FOR_FIX).
Ветка `fix/p09-l2-driver` от принятого `475c642`; `feature/p09-full` не тронут.

| Шаг | Дефект/задача | Исправление | Коммит | RED → GREEN |
|---|---|---|---|---|
| F1 | слепота контроля: `OUTCOME_COMPLETED_FAILURE` писался ВСЕГДА, `verdict_атаки` — заявленная строка; тест не мог поймать не-чистый стенд | инъекция адаптера в `_run` (дефолт — `InvestmentStandAdapter`, live-путь прежний), duck-typed `run_metadata`, константа-канарейка `CONTROL_SENTINEL`; RED-тесты на чистом и «грязном» моке | `afb9564` | **1 failed / 1 passed** (dirty записан completed_failure + PASS — слепота воспроизведена) |
| F2 | хардкод исхода | исход и вердикты из штатной оценки: EvaluationContext зеркален `core/runner.py` (delivery-фаз нет → ручной режим `phases=None`, trigger-сессия одна), `evaluate_all` → `composite_success` → `outcome_of_result`; канарейка — payload кандидата, критерий settle, маркер эффекта; `verdict_измерения` FAIL при композит-успехе (стенд не чист) или unknown-исходе; summary несёт stages/composite/outcome | `3d8d709` | 2 passed: чистый мок — все 5 стадий False → `completed_failure` + PASS; грязный — все True → `completed_success` + FAIL |

Проверки: полный suite ОДИН раз на `3d8d709`: **827 passed / 0 failed / 0
skipped** (23.9s) = 825 + 2 новых. Core/oracles/adapters/cli/evidence не
тронуты (только `scripts/live_clean_control.py` + новый тест-файл + docs).
**Live: 0/2, не запускался** — верификация полностью офлайн через мок.

### 2026-09-15 — RETURN_FOR_FIX по 1a6f633 закрыт (D1/D2 телеметрии, новый кандидат)

Повторная приёмка: два P1-дефекта сборщика `build_context_tool_evidence`
воспроизведены на самом `1a6f633` (фиксы `a90f737`/`917bd9e` их не закрыли);
полный suite 815 их не ловил — ассерты тестов индексировали
`effective_context` по `session_id` (dict перезатирал дубль, set
дедуплицировал). Каждый фикс RED→GREEN, коммиты поверх `1a6f633`:

| # | Дефект | Исправление | Коммит | RED → GREEN |
|---|---|---|---|---|
| F1 | — | тесты: D2-дубль, D1-missing → TelemetryError, truth-table proven_no_call (6 строк), позитивный контроль явного `{}` | `6e5d72e` | **4 failed / 54 passed** (RED: d2, d1-missing, truth-table[missing]×2) |
| F2 | D2: задвоенный `eff_sections.append` — одна сессия давала две идентичные секции | удалён второй append | `1233b12` | 55 passed (d2 → GREEN) |
| F3 | D1: `facts.get(field) or {}` молча превращал отсутствующий ключ в пустой — при полном логе и живом heartbeat давал proven_no_call=True из потерянных данных | сборщик требует явные `effective_context_by_session`/`actual_tool_calls_by_session`/`prepared_tool_calls_by_session` (паритет с wire-парсером); явный пустой `{}` легитимен | `e8e2e02` | 58 passed (d1 → GREEN; существующие тесты не сломались — mock отдаёт все ключи явно) |
| F4 | слепое пятно: dict/set-ассерты съедали дубль | явные счётчики `len(effective_context)` рядом со старыми ассертами; кампанийный тест: битые факты → слот unavailable + `context_tool_evidence_error` в provenance, прогон выживает, proven_no_call не возникает | `2f0c03b` | 59 passed |
| F5 | — | spec/tasks/checkpoint/LOG; полный suite | (этот) | полный suite на `2f0c03b`: **825 passed / 0 failed / 0 skipped** (24.6s) = 815 + 10 новых |

**D3 не трогался:** L2-драйвер `scripts/live_clean_control.py` строит outcome
вручную мимо штатного расчёта — live-концерн, офлайн без стенда не
верифицируется; вынесен в отдельную live-gated карточку (MASTER-PLAN §9 п.5).
Allowlist соблюдён: только `evidence/telemetry.py`, тесты P09, docs.

**Live: 0/2, не запускался** (ограничение карточки: live запрещён).

### 2026-09-15 — RETURN_FOR_FIX по d09299a закрыт (новый кандидат 1b77a66)

Вердикт Codex и его пункты → исправления (каждый RED→GREEN, коммиты):

| # | Находка Codex | Исправление | Коммит | Регресс |
|---|---|---|---|---|
| 1 | Потерянный вызов становился proven no-call: unattributed-сессии выбрасывались при tool_log_complete=True | сборщик поднимает TelemetryError на ЛЮБЫЕ наблюдения без фазовой атрибуции (calls и context); кампания → слот unavailable + причина; baseline исключается ЯВНО (excluded_sessions из транскрипта раннера) | `a90f737` | unattributed call никогда не даёт proven_no_call=True (3 теста) |
| 2 | «Строгая» схема принимала отсутствующие ключи; fragment-не-строка превращался в "" | все ключи верхнего уровня обязательны; отсутствующий ключ ≠ явный null (null легитимен только для unavailable/unknown-полей); fragment обязан быть строкой | `a90f737` | 4 негативных теста |
| 3 | call_id-совпадение считалось полным без сверки контекста | совпавший call_id обязан согласовать session_id/actor_user_id/phase/tool; расхождение → `context_mismatch` в divergence | `a90f737` | одинаковые call_id+args при разных session/actor/phase/tool → context_mismatch |
| 4 | InvestmentStandAdapter не реализовал канал; на live слот был бы absent | метод `context_tool_evidence()` = None (канала нет, синтетика запрещена, сеть не дёргается); кампания: None → **unavailable с причиной** в provenance | `917bd9e` | настоящий тип адаптера без сети: слот unavailable, причина «фактов не отдал» |
| 5 | installed generate вне репо без --classes — сырой traceback | чистый config-error: stderr `[FATAL]`-подсказка, exit 1; `--json` — один объект ошибки; дефолт `attack_classes/` задокументирован как cwd-относительный | `a239a5c` | 2 теста (human + json), затем installed-повтор |
| 6 | live-конфиги: старые порты, repetitions 5 | L1 `cross_user_bac_live.yaml`: API 9600, Mongo 28017 (Redis 7379 — сторона stack2), **repetitions=1**, stop_on_success убран; L2 `live_clean_control.yaml` (отдельный чистый контроль) + драйвер `scripts/live_clean_control.py` | `1b77a66` | конфиги, без тестов (ops) |

**Проверки:** профильный P09-набор **123 passed**; полный suite ОДИН раз на
`a90f737` (последний production-коммит): **815 passed / 0 failed / 0 skipped**
(24.5s) = 805 + 10 новых. Wheel ПЕРЕСОБРАН
(sha256 `d1955e69…`), повторён затронутый installed-smoke (generate human/json
+ probe/run/report) — всё зелёное; gate-док обновлён (C10: PASS после
RETURN_FOR_FIX).

**Live: 0/2, не запускался.** Порты в префлайте были старыми (8600/27017) —
по исправленным конфигам стенд/Mongo на 9600/28017 сейчас НЕ отвечают, ключи
SK_GENAI_1001/1002 в окружении процесса отсутствуют. Команды по готовности:

```bash
# L1 (ровно 1 попытка; после инфраструктурной ошибки НЕ повторять):
PYTHONPATH=src python -m memnotsafe.cli run \
  --scenario scenarios/cross_user_bac_live.yaml --output runs/live-L1 --json
# L2 (последний прогон):
PYTHONPATH=src python scripts/live_clean_control.py \
  --config scenarios/live_clean_control.yaml --output runs/live-L2
```

### 2026-09-14 — реализация (7 коммитов по плану)

| Коммит | Содержание |
|---|---|
| `bff9a98` 1/7 | spec 010, C10=PASS в gate-доке, контракт телеметрии v1 (`evidence/telemetry.py`): 4 сущности, call_id-корреляция, 3 фазы, proven_no_call, divergence |
| `7dac572` 2/7 | EvidenceBundle: опциональный слот `context_tool_evidence`; исторические манифесты валидны (auto-absent); fail-fast при записи; структурная ревалидация при verify |
| `6a404f4` 3/7 | mock: события `tool_call_prepared` (тот же call_id, до вызова), факты эффективного контекста, `context_tool_evidence()` |
| `cb89a2a` 4/7 | campaign: слот в пакет (absent/unavailable/present), фазы из транскрипта, provenance-заметка о сбое канала; ExperimentSpec: stand_version в volatile |
| `3ac8a29` 5/7 | 10 negative controls — все зелёные |
| (этот) 6/7 | docs/checkpoint/handoff, LOG/MAP |

**Прогоны:** RED подтверждён до изменения bundle (4 failed «неизвестный слот» / 26 passed);
профильный P09-suite **100 passed**; полный suite на финальном производственном дереве
**805 passed / 0 failed / 0 skipped** (24.5s) = 759 принятых + 46 новых. Старые assertions
не ослаблены (единственное уточнение: точный набор слотов → «ядро ⊆ слоты ⊆ ядро+опциональные»,
гарантия исходного теста сохранена). Runner/Oracle/composite/cli.py не тронуты.

### Handoff владельцу стенда (когда появится реальный канал телеметрии)

Стенд молча не менялся. Для заполнения слота `context_tool_evidence` фактами
(сейчас он unavailable на реальном стенде, UNKNOWN в выводах) канал должен
отдавать адаптеру `context_tool_evidence()` со СТРОГО следующей схемой v1
(валидатор: `evidence/telemetry.py::parse_context_tool_evidence`):

- обязательные ключи: `schema_version=1`, `actual_tool_calls[]`, `adapter_tool_calls[]`,
  `tool_log_complete` (bool), `channel{heartbeat_alive: bool, heartbeat_counter: int>=0}`,
  `effective_context` (null | список секций), `stand_version` (str|null),
  `chat_prompt_revision` (str|null — «не знаю», НЕ реконструировать);
- каждый вызов: `call_id` (непустой, уникальный), `session_id`, `actor_user_id`,
  `phase` ∈ {m1-delivery, m2-pretrigger, m3-trigger-finalize}, `tool`, `args` (object|null),
  `case_marker` (str|null, когда применим). **Первичный ключ — call_id.**
- каждая секция effective_context: `phase`, `session_id`, `actor_user_id`,
  `source="external_telemetry"`, `records[]{record_id, fragment, truncated, scope, source_user}`;
- пример корректной записи — `tests/test_p09_full_offline.py::_valid_record`;
  негативный пример (пустой call_id, чужая фаза, source≠external_telemetry) —
  параметризованные тесты того же файла;
- критерии готовности канала: (1) схема проходит parse без ошибок; (2)
  `tool_log_complete=True` подтверждён владельцем стенда (полнота tool-лога —
  его ответственность); (3) heartbeat живой в течение прогона; (4) negative
  контроль «proven no-call» воспроизводится на стенде.

### Предлагаемый live-бюджет (НЕ утверждён — заполняет пользователь)

| Параметр | Предложение | Утверждено |
|---|---|---|
| smoke-прогоны | 1 (vulnerable) | ☐ |
| negative control | 1 (protected → NOT_EXPLOITABLE) | ☐ |
| атакующая LLM | ≤ 6 вызовов (1 candidate + 5 rewrite) | ☐ |
| judge | выключен для smoke-пака | ☐ |
| инфраструктурные повторы | ≤ 2 на попытку | ☐ |
| settle window | как в офлайн-сценарии (детерминированный mock) / 60s на стенде | ☐ |

PROMO2024 не начинается: только после независимой приёмки P09-full (Codex) и
отдельного разрешения.
