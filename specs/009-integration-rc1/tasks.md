# Tasks: 009 — интеграционный RC1

## Phase 0. Состояние

- [x] T0.1 Ancestry `origin/main(6f0c4a7) → b1926e0 → c7fd325 → 052467c → 03832ee` — подтверждён `git merge-base --is-ancestor` (6/6 OK)
- [x] T0.2 Ветки-слой стоят на принятых SHA; worktree-статусы чистые (untracked — только временные каталоги pytest и чужие docs)
- [x] T0.3 Diff `origin/main..03832ee`: 65 файлов, +8256/−240; только src/tests/specs/доки; секретов нет (совпадения — имена env-переменных и dummy-фикстуры)
- [x] T0.4 Worktree `worktrees/full-stack-rc1` + ветка `integration/full-stack-rc1` от `03832ee` созданы
- [x] T0.5 Карточка 009 (spec/plan/tasks/checkpoint) оформлена

## Phase 1. Границы слоёв

- [x] T1.1 Дельты `--name-status` по каждой границе; пересечения файлов между слоями отмечены
- [x] T1.2 Профильный прогон слоя A (measurement): 183 passed
- [x] T1.3 Профильный прогон слоя B (P02/P03): 59 passed
- [x] T1.4 Профильный прогон слоя C (CLI v1): 63 passed
- [x] T1.5 Профильный прогон слоя D (Evidence Foundation): 106 passed
- [x] T1.6 Вывод по каждому слою: контракт жив на финальном дереве, отменяющих коммитов нет (oracles/adapters/snapshot/judge/runner не трогались после b1926e0; общие файлы — аддитивные правки, покрытые прогонами B–D)

PASS_IF: все профильные прогоны зелёные на candidate; ни один принятый контракт не откачен.

## Phase 2. Интеграционные инварианты

- [x] T2.1 Матрица 11 сценариев → существующие тесты (маппинг в release-manifest §5, без дубликатов)
- [x] T2.2 Профильный E2E-прогон матрицы: 98 passed
- [x] T2.3 Дефектов не обнаружено — red/fix/green не потребовался; production-код карточкой не менялся

PASS_IF: каждый сценарий матрицы закрыт именованным существующим тестом либо
честно помечен как не покрытый (с обоснованием, почему это не дефект).

## Phase 3. C10 wheel/чистая установка

- [x] T3.1 Известные интерпретаторы + pip-кэш: setuptools/wheel отсутствуют, собранных колёс 0, wheelhouse нет
- [ ] T3.2 Доступно → сборка wheel, чистый venv вне репо, `--no-index --find-links`, `pip check`, installed-CLI smoke — **НЕ ВЫПОЛНЯЛОСЬ: заблокировано (см. T3.2н)**
- [x] T3.2н NEEDS_AUTHORITY: точная PowerShell-команда в release-manifest §7; остальные этапы продолжены

PASS_IF: установленное приложение доказано (`memnotsafe.__file__` в site-packages
чистого venv, smoke пройден) ЛИБО блокер зафиксирован командой, требующей только
сетевых прав и не меняющей код.

## Phase 4. Release manifest

- [x] T4.1 `release-manifest.md`: base/candidate SHA, слои, diff-stat, проверки, suite, C10, C5-стратегия, секреты, команда PR/ff, rollback, обновляемые статусы MASTER-PLAN

## Phase 5. Следующая работа + финал

- [x] T5.1 Handoff P09-full offline-подготовки (после R1) в checkpoint
- [x] T5.2 Один полный suite на производственном дереве candidate: 759 passed / 0 failed / 0 skipped (c60aba7; последующий коммит — только документация)
- [x] T5.3 LOG дополнен; handoff выдан
