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
