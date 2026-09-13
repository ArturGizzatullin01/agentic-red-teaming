# План: 007-evidence-foundation

## Границы модулей

| Модуль | Роль | Не делает |
|---|---|---|
| `core/goal_contract.py` (new) | GoalContract: тип эффекта (P03-валидатор), инварианты, обязательные доказательства, привязки попытки, digest | не решает «успешна ли атака»; не дублирует реестр типов |
| `generation/rewrite.py` (правка) | сверка цели через GoalContract до target | не меняет бюджет/парсинг |
| `evidence/bundle.py` (new) | EvidenceBundle: слоты, checksums, атомарный манифест, чтение с верификацией | не интерпретирует вердикты; не пишет в campaign.json |
| `core/experiment.py` (new) | ExperimentSpec: конфигурация + digest значимых файлов | не содержит секретов; не фиксирует летучие поля |
| `core/attempt.py` (new) | AttemptHistory: JSONL история попыток/кандидатов/ретраев | не меняет знаменатели ASR и aggregate_metrics |
| `core/ledger.py` (new) | BudgetLedger: наблюдение расходов поверх существующих бюджетов | не имеет собственных лимитов, не дублирует решения |
| `core/campaign.py` (аддитивно) | точки записи: experiment.json, bundles/, attempts.jsonl, ledger | не меняет composite/oracle/стадии/воронку |
| `cli.py` (аддитивно) | report: верификация bundles при наличии | не меняет флаги/exit-схему/формат вывода |

## Форматы (версионированные, аддитивные к runs/)

- `experiment.json` — schema_version 1, experiment_id (digest), секции target/
  attacker/judge/corpus/delivery/budgets/file_digests.
- `bundles/<case_id>/manifest.json` + артефакты в том же каталоге; слоты со
  статусами present/absent/unavailable; sealed-манифест пишется последним
  (tmp+os.replace).
- `attempts.jsonl`, `budget-ledger.jsonl` — по строке JSON с schema_version на
  запись; append-only.
- Совместимость: старые runs (без новых файлов) читаются прежним кодом;
  load_campaign/cmd_report не требуют новых полей.

## Миграция/совместимость

- Никаких миграций исторических файлов: недостающее = «нет» (None/absent),
  не «ноль» и не «неудача».
- Каноническая сериализация: `json.dumps(..., sort_keys=True, ensure_ascii=False,
  separators=(",", ":"))` — единый хелпер, используется digest'ами контракта и
  эксперимента.

## Тесты

- K1: существующие roundtrip-тесты (перечень в spec §2) + 1 новый тест ноги
  CLI-replay (реальный writer → cmd_report → family в findings.json).
- GoalContract: digest-стабильность; маркер вне digest; смена типа/инварианта
  отклоняется в rewrite; доп. поля roundtrip; неизвестный тип → ValueError.
- EvidenceBundle: запись/чтение; атомарность (без манифеста = незавершён);
  порча артефакта; traversal; unavailable≠absent; старые runs; секреты.
- ExperimentSpec: digest стабилен; секреты/летучие вне digest; corpus/profile
  digests; связь с манифестами попыток.
- AttemptHistory: lineage rewrite (parent/child); отклонённый rewrite;
  budget_exhausted; transport_error (RunnerError → запись + re-raise);
  retry не новый кандидат; связь с ASR задокументирована.
- Ledger: planned/executed/unknown; ошибки без двойного списания; блокировка
  фиксируется; usage null при неизвестном; judge summary из существующего
  JudgeBudget.
- E2E (mock, офлайн): 9 сценариев из spec §8.

## Подэтапы (порядок реализации)

0. спека+план+tasks (этот комплект) → коммит
1. K1: прогон существующих тестов + новый CLI-replay тест → коммит
2. P10a GoalContract + rewrite-интеграция → коммит
3. P10a EvidenceBundle + запись в кампании → коммит
4. P10b ExperimentSpec → коммит
5. P10b AttemptRecord → коммит
6. P10b BudgetLedger → коммит
7. интеграция report/replay + e2e-матрица + LOG/MAP + полный suite → коммит
