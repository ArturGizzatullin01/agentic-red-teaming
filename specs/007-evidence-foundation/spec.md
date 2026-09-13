# Спецификация: Evidence Foundation (K1 + P10a + P10b)

- Feature: 007-evidence-foundation
- Основание: MASTER-PLAN §4 (K1/P01 → P10a → P10b), §6 матрица проверок, §7 Часть II
- База: `052467c` (принятый CLI v1, стек `b1926e0` → `c7fd325` → `052467c`)
- Дата: 2026-09-14

## 1. Проблема и цель

Воспроизводимый эксперимент = неизменная цель + проверяемый пакет доказательств +
полная история попыток + учёт бюджета. Сегодня:

- family через writer→file→reader доказана частично (см. §2, K1);
- цель атаки (expected_effect) контролируется точечно в `rewrite` (K3), но не
  имеет версионированного контракта с воспроизводимым digest;
- доказательства попытки разбросаны по `runs/<name>/` без манифеста, контрольных
  сумм и явных состояний отсутствия телеметрии;
- конфигурация эксперимента не фиксируется (target/модель/корпус/бюджеты/ревизии);
- история попыток не различает кейс / кандидата / попытку / транспортный повтор;
- расходы (attacker LLM, judge, target) не связаны с попытками единым леджером.

## 2. K1 — основание (проверка, без нового production-кода)

Контракт: обычная family сохраняется через реальный writer кампании → файл →
штатный reader (`cli.load_campaign`)/replay (`cmd_report`); generated остаётся
`family="generated"` независимо от attack_class/attack_id; legacy-файл без
`family` читается по документированному правилу (точное вхождение attack_id в
ATTACK_REGISTRY — иначе диагностическая ошибка, без выдуманных fallback'ов).

Существующее покрытие (не дублируется): `test_reporting_replay.py`:
`test_writer_records_family_in_campaign_json`,
`test_generated_run_keeps_family_generated_not_source_class`,
`test_family_and_provenance_attack_class_stay_independent`,
`test_round_trip_keeps_tristate_stages_judge_provenance_and_composite`,
`test_legacy_wire_without_family_still_reads_by_the_old_rule`;
`tests/test_reporting_html.py` (legacy wire); CLI-legacy (`test_cli_report_legacy_*`).
Выявленный нога-пробел: нет теста «реальный writer → `cmd_report` (CLI replay) →
family в findings.json» одной цепочкой — добавляется один тест.

## 3. P10a — GoalContract

Версионированный контракт цели попытки (новый модуль `core/goal_contract.py`):

- `schema_version = 1`;
- тип ожидаемого эффекта — ТОЛЬКО из принятого валидатора P03
  (`generation.corpus.supported_effect_types()`); конкурирующих реестров типов нет;
- смысловые инварианты — канонические пары ключ/значение из `expected_effect`
  (tool/field/injected/user scope и др.);
- обязательные доказательства — слоты пакета EvidenceBundle, требуемые для
  вынесения вердикта по данному типу эффекта;
- допустимые привязки значений конкретной попытки (например case_marker) —
  ВНЕ digest: смена маркера не является сменой цели;
- `digest()` — sha256 над канонической JSON-сериализацией (sort_keys,
  компактные разделители); стабильность доказывается тестом (одинаковый
  контракт → одинаковый digest при любом порядке ключей; изменение любого
  смыслового поля → другой digest).

Интеграция в rewrite (замена точечной проверки K3, поведение совместимо):
допустимый rewrite (смена текста, тот же эффект) проходит; смена типа/значений
инвариантов → `None` ДО обращения к target; дополнительные поля эффекта не
теряются (roundtrip). Отклонённый rewrite не тратит target-вызов (бюджет
атакующей LLM уже потрачен на генерацию — как и было; документируется).

## 4. P10a — EvidenceBundle

Файловый пакет доказательств попытки (новый модуль `evidence/bundle.py`),
пишется кампанией в `runs/<name>/bundles/<case_id>/`:

- `manifest.json` с `schema_version`, идентификаторами (run_id, case_id,
  experiment_id, candidate_id, attempt_no, goal_digest);
- слоты доказательств: `m0`,`m1`,`m2`,`m3` (фазовые снимки), `transcript`,
  `settle`, `candidate`, `memory_diff`, `tool_events`, `trace`;
  состояние каждого слота: `present` | `absent` | `unavailable`;
  **unavailable (телеметрия не наблюдала) ≠ absent (слот не предусмотрен) ≠
  доказанное отсутствие события**;
- sha256 каждого артефакта; пути артефактов — только относительные внутри
  каталога пакета (traversal отклоняется);
- атомарное завершение: манифест пишется последним через tmp+rename;
  незавершённый пакет (нет манифеста / `sealed=false`) не выдаётся за
  завершённый (`read_bundle` отклоняет);
- повреждённый/подменённый артефакт обнаруживается при чтении (несовпадение
  sha256 → ошибка с именем слота);
- старые runs (без каталога bundles) читаются как «пакетов нет», без
  выдумывания полей; replay работает без target и вызовов моделей;
- секреты в манифест и снимки конфигурации не попадают (только имена
  переменных окружения, никогда значения).

P09-full ещё не даёт живого effective_context/tool-args: слоты обрабатывают
доступность честно (unavailable), телеметрия не выдумывается.

## 5. P10b — ExperimentSpec

Воспроизводимая конфигурация эксперимента (новый модуль `core/experiment.py`),
пишется кампанией в `runs/<name>/experiment.json`:

- target (adapter, base_url, модель или явное `unknown`), доступные ревизии
  writer/chat prompt (sha256 `generation/prompts.py`; неизвестное — `unknown`);
- конфигурация и начальное состояние (judge on/off, онлайн on/off, auth_mode
  из run_metadata адаптера или `unknown`);
- версии корпуса и оценщиков (sha256 файла корпуса, модель судьи);
- канал доставки и область пользователей (attacker/victim user_id);
- бюджеты (attacker budget, judge max_calls, online_attempts, repetitions);
- digest значимых файлов рабочего дерева (сценарий YAML, корпус, профиль,
  attack_classes/*.yaml);
- `experiment_id` = digest канонической сериализации БЕЗ секретов и летучих
  полей (создан в модуле список «что создаёт новый эксперимент»); связь с
  попытками и пакетами — через `experiment_id` в manifest/attempt/ledger.

## 6. P10b — AttemptRecord

История попыток (новый модуль `core/attempt.py`, файл `runs/<name>/attempts.jsonl`),
различающая: логический кейс (`case_id`) / кандидата (`candidate_id`) и его
родителя (`parent_candidate_id`) / попытку на target (`attempt_no`) /
транспортный повтор (`transport_retry`).

- поля: experiment_id, run_id, case_id, candidate_id, parent_candidate_id,
  attempt_no, transport_retry, case_marker, goal_digest, seed, session_ids
  (по стадиям, где доступны; иначе null), outcome, error, op;
- исходы: `completed_success`, `completed_failure`, `unknown`,
  `rewrite_rejected`, `budget_exhausted`, `transport_error`, `aborted`;
- в историю попадают: исходный seed; успешные и неуспешные rewrite;
  отклонённый кандидат; исчерпание бюджета; транспортная ошибка;
  прерванная попытка;
- транспортный повтор НЕ создаёт нового кандидата (тот же candidate_id,
  transport_retry+1);
- связь с метриками: знаменатель ASR остаётся `attempts = len(results)`
  (завершённые случаи); `attempts.jsonl` — полная история операций
  (включая не достигшие target), метрики кампании не меняются и не
  пересчитываются по истории; связь задокументирована в модуле и спеке.

## 7. P10b — Budget Ledger

Учёт бюджета (новый модуль `core/ledger.py`, файл `runs/<name>/budget-ledger.jsonl`)
поверх СУЩЕСТВУЮЩИХ ограничителей (`CallBudget`, `JudgeBudget`, online_attempts):

- записи связывают расход с experiment/case/candidate/attempt и операцией
  (`attacker_llm` | `judge_llm` | `target_call`);
- различаются: запланировано (spend до вызова), выполнено (ответ получен),
  неизвестный исход (ошибка/повтор: executed + outcome_known=false);
- ошибки и повторы сохраняются без двойного списания (списание остаётся в
  существующем бюджете; леджер только наблюдает);
- блокировка новых операций при исчерпании — СУЩЕСТВУЮЩИЙ механизм
  (`budget.exhausted`); леджер фиксирует факт блокировки;
- неизвестные usage/cost помечаются явно (`usage: null`), нулём НЕ записываются;
  выдуманных тарифов и «оценочной стоимости» нет;
- решения о лимитах не дублируются: леджер не имеет собственных лимитов.

## 8. Интеграция и replay

Реальный последовательный поток: подготовка эксперимента (ExperimentSpec) →
кандидат → валидация цели (GoalContract) → попытка (run_attack) → пакет
доказательств (EvidenceBundle) → завершение (AttemptRecord) → отчёт/replay
(проверка пакетов при наличии, без target и моделей).

Доказывается офлайн (mock/stub, без live): успешный сценарий; честный
отрицательный; UNKNOWN из-за отсутствующей телеметрии; отклонённый rewrite;
исчерпанный бюджет; транспортная ошибка; незавершённый пакет; повреждение
артефакта; чтение исторического run (без новых полей).

## 9. Неизменяемые правила (границы)

- Непробитие атаки: exit 0 + NOT_EXPLOITABLE. UNKNOWN остаётся UNKNOWN/null.
- Формула composite и критерии успеха не меняются. Запись, принятие, вызов
  инструмента и внешний эффект различаются как раньше.
- Контракт `console-output.md` соблюдён (CLI-правки только: проверка пакетов
  в report; ошибки пакета — runtime-ошибка → exit 1 по существующей строке
  таблицы; формат вывода не меняется).
- Никаких новых attack families, UI, Langfuse, DPO/RLHF; P13 worker/lease — нет.
- Никаких live-запусков и платных вызовов; без push/merge/force-push.
- Публичный CLI-контракт (флаги, exit-коды, JSON-схема) не меняется; новые
  файлы в runs/ аддитивны и версионированы.
