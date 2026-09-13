# Задачи: 007-evidence-foundation

## Этап 0 — база и спецификация
- [x] Проверка git-состояния и принятых SHA (052467c — база; origin/main 6f0c4a7 не трогаем)
- [x] Worktree `evidence-foundation`, ветка `evidence/foundation`
- [x] Зависимости: P10a ← K1 (этап 1); P10b ← P10a; внешних незакрытых gate для
      офлайн-части нет; R1/main не требуется и не выполняется
- [x] spec.md / plan.md / tasks.md (Spec Kit: clarify — вопросы фиксируются в spec;
      analyze — сверка с MASTER-PLAN §6 и console-output.md в plan/tests)

## Этап 1 — K1
- [ ] Прогнать существующие roundtrip-тесты family (имена в spec §2)
- [ ] Новый тест: реальный writer → cmd_report → family в findings.json
- [ ] Коммит `K1: family roundtrip — existing coverage + CLI replay leg`

## Этап 2 — P10a GoalContract
- [ ] core/goal_contract.py (тип через supported_effect_types, каноническая
      сериализация, digest, привязки вне digest, REQUIRED_EVIDENCE_BY_TYPE)
- [ ] rewrite.py: сверка цели через GoalContract (замена K3-инлайн-проверки)
- [ ] Тесты digest-стабильности/отклонений/roundtrip; коммит

## Этап 3 — P10a EvidenceBundle
- [ ] evidence/bundle.py (write/read, слоты, sha256, атомарный sealed-манифест,
      traversal-защита, absence/unavailable)
- [ ] campaign._persist_case: запись bundles/<case_id> (аддитивно)
- [ ] Тесты записи/порчи/незавершённости/старых runs/секретов; коммит

## Этап 4 — P10b ExperimentSpec
- [ ] core/experiment.py (build из scenario+конфига, digest значимых файлов,
      unknown-ревизии явно, без секретов/летучих)
- [ ] campaign: experiment.json в начале run(); experiment_id в manifest/attempts
- [ ] Тесты; коммит

## Этап 5 — P10b AttemptRecord
- [ ] core/attempt.py (AttemptHistory JSONL, lineage, outcome-набор)
- [ ] campaign/escalation: записи кандидатов, rewrite (принят/отклонён),
      budget_exhausted, transport_error (запись + re-raise), aborted
- [ ] Тесты (включая «retry ≠ новый кандидат»); коммит

## Этап 6 — P10b Budget Ledger
- [ ] core/ledger.py (entries planned/executed/unknown, без двойного списания,
      блокировка, usage=null при неизвестном)
- [ ] Интеграция: rewrite-хук (attacker_llm), target_call в кампании,
      judge summary из JudgeBudget.metadata
- [ ] Тесты; коммит

## Этап 7 — интеграция и replay
- [ ] cmd_report: верификация bundles при наличии (runtime-ошибка → exit 1,
      формат вывода прежний; старые runs — без пакетов, пропуск)
- [ ] E2E-матрица (9 сценариев spec §8) на mock/stub
- [ ] Полный офлайн-suite; diff-аудит на секреты; LOG.md/MAP.md; коммит; HANDOFF
