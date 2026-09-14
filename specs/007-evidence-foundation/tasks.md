# Задачи: 007-evidence-foundation

## Этап 0 — база и спецификация
- [x] Проверка git-состояния и принятых SHA (052467c — база; origin/main 6f0c4a7 не трогаем)
- [x] Worktree `evidence-foundation`, ветка `evidence/foundation`
- [x] Зависимости: P10a ← K1 (этап 1); P10b ← P10a; внешних незакрытых gate для
      офлайн-части нет; R1/main не требуется и не выполняется
- [x] spec.md / plan.md / tasks.md (Spec Kit: clarify — вопросы фиксируются в spec;
      analyze — сверка с MASTER-PLAN §6 и console-output.md в plan/tests)

## Этап 1 — K1
- [x] Прогнать существующие roundtrip-тесты family (имена в spec §2)
- [x] Новый тест: реальный writer → cmd_report → family в findings.json
- [x] Коммит `K1: family roundtrip — existing coverage + CLI replay leg`

## Этап 2 — P10a GoalContract
- [x] core/goal_contract.py (тип через supported_effect_types, каноническая
      сериализация, digest, привязки вне digest, REQUIRED_EVIDENCE_BY_TYPE)
- [x] rewrite.py: сверка цели через GoalContract (замена K3-инлайн-проверки)
- [x] Тесты digest-стабильности/отклонений/roundtrip; коммит

## Этап 3 — P10a EvidenceBundle
- [x] evidence/bundle.py (write/read, слоты, sha256, атомарный sealed-манифест,
      traversal-защита, absence/unavailable)
- [x] campaign._persist_case: запись bundles/<case_id> (аддитивно)
- [x] Тесты записи/порчи/незавершённости/старых runs/секретов; коммит

## Этап 4 — P10b ExperimentSpec
- [x] core/experiment.py (build из scenario+конфига, digest значимых файлов,
      unknown-ревизии явно, без секретов/летучих)
- [x] campaign: experiment.json в начале run(); experiment_id в manifest/attempts
- [x] Тесты; коммит

## Этап 5 — P10b AttemptRecord
- [x] core/attempt.py (AttemptHistory JSONL, lineage, outcome-набор)
- [x] campaign/escalation: записи кандидатов, rewrite (принят/отклонён),
      budget_exhausted, transport_error (запись + re-raise), aborted
- [x] Тесты (включая «retry ≠ новый кандидат»); коммит

## Этап 6 — P10b Budget Ledger
- [x] core/ledger.py (entries planned/executed/unknown, без двойного списания,
      блокировка, usage=null при неизвестном)
- [x] Интеграция: rewrite-хук (attacker_llm), target_call в кампании,
      judge summary из JudgeBudget.metadata
- [x] Тесты; коммит

## Этап 7 — интеграция и replay
- [x] cmd_report: верификация bundles при наличии (runtime-ошибка → exit 1,
      формат вывода прежний; старые runs — без пакетов, пропуск)
- [x] E2E-матрица (9 сценариев spec §8) на mock/stub
- [x] Полный офлайн-suite; diff-аудит на секреты; LOG.md/MAP.md; коммит; HANDOFF

## Блок «подготовка к интеграции» (2026-09-14)
- [x] Этап 1: воспроизводимость (tmp_path, TERM-герметичность) — 746×2
- [x] Этап 2: аудит A–E — 5 дефектов закрыты (752)
- [x] Этап 3: согласованность манифест↔история (753)
- [x] Этап 4: BLOCKED документирован (offline-install-gate.md)
- [x] Этап 5: карточка P09-full (specs/008-p09-full/card.md)
- [x] Этап 6: финал 753×2, checkpoint.md, LOG/MAP
