# Tasks: 009 — интеграционный RC1

## Phase 0. Состояние

- [x] T0.1 Ancestry `origin/main(6f0c4a7) → b1926e0 → c7fd325 → 052467c → 03832ee` — подтверждён `git merge-base --is-ancestor` (6/6 OK)
- [x] T0.2 Ветки-слой стоят на принятых SHA; worktree-статусы чистые (untracked — только временные каталоги pytest и чужие docs)
- [x] T0.3 Diff `origin/main..03832ee`: 65 файлов, +8256/−240; только src/tests/specs/доки; секретов нет (совпадения — имена env-переменных и dummy-фикстуры)
- [x] T0.4 Worktree `worktrees/full-stack-rc1` + ветка `integration/full-stack-rc1` от `03832ee` созданы
- [x] T0.5 Карточка 009 (spec/plan/tasks/checkpoint) оформлена

## Phase 1. Границы слоёв

- [ ] T1.1 Дельты `--name-status` по каждой границе; пересечения файлов между слоями отмечены
- [ ] T1.2 Профильный прогон слоя A (measurement): `test_write_marker_p04 test_phase_snapshots_p06 test_settle_outcomes_p05 test_reporting_diagnostics_p08 test_judge_goal_p07 test_write_zone_owner test_investment_stand_settle`
- [ ] T1.3 Профильный прогон слоя B (P02/P03): `test_attack_registry test_profile_and_corpus`
- [ ] T1.4 Профильный прогон слоя C (CLI v1): `test_cli_output test_cli_exit_invariants test_cli_wiring test_cli_edges`
- [ ] T1.5 Профильный прогон слоя D (Evidence Foundation): `test_goal_contract_p10a test_evidence_bundle_p10a test_experiment_spec_p10b test_attempt_history_p10b test_budget_ledger_p10b test_evidence_foundation_e2e`
- [ ] T1.6 Вывод по каждому слою: контракт жив на финальном дереве, отменяющих коммитов нет

PASS_IF: все профильные прогоны зелёные на candidate; ни один принятый контракт не откачен.

## Phase 2. Интеграционные инварианты

- [ ] T2.1 Матрица 11 сценариев → существующие тесты (без дубликатов)
- [ ] T2.2 Профильный E2E-прогон матрицы по именам
- [ ] T2.3 (только при дефекте) red → минимальный фикс → green → отдельный коммит

PASS_IF: каждый сценарий матрицы закрыт именованным существующим тестом либо
честно помечен как не покрытый (с обоснованием, почему это не дефект).

## Phase 3. C10 wheel/чистая установка

- [ ] T3.1 Известные интерпретаторы + pip-кэш: setuptools/wheel/wheelhouse
- [ ] T3.2 Доступно → сборка wheel, чистый venv вне репо, `--no-index --find-links`, `pip check`, installed-CLI smoke
- [ ] T3.2н Недоступно → NEEDS_AUTHORITY: одна точная PowerShell-команда, остальные этапы продолжаются

PASS_IF: установленное приложение доказано (`memnotsafe.__file__` в site-packages
чистого venv, smoke пройден) ЛИБО блокер зафиксирован командой, требующей только
сетевых прав и не меняющей код.

## Phase 4. Release manifest

- [ ] T4.1 `release-manifest.md`: base/candidate SHA, слои, diff-stat, проверки, suite, C10, C5-стратегия, секреты, команда PR/ff, rollback, обновляемые статусы MASTER-PLAN

## Phase 5. Следующая работа + финал

- [ ] T5.1 Handoff P09-full offline-подготовки (после R1) в checkpoint
- [ ] T5.2 Один полный suite на финальном candidate SHA
- [ ] T5.3 LOG/MAP дополнены; handoff выдан
