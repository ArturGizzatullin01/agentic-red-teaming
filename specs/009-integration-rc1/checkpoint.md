# Checkpoint: 009 — интеграционный RC1

## 2026-09-14 — Этап 0 (состояние и карточка)

- Ancestry подтверждён повторно: `origin/main(6f0c4a7)` — предок `03832ee`;
  цепочка `b1926e0 → c7fd325 → 052467c → 03832ee` линейна (6/6 `--is-ancestor` OK,
  включая `main(cbd7e6b) → 03832ee`).
- Принятые ветки стоят ровно на своих SHA, пост-accept коммитов нет:
  `k2k3/correctness=c7fd325`, `r0/measurement-merge=b1926e0`,
  `cli/operator-v1=052467c`, `evidence/foundation=03832ee`.
- Worktree-статусы: tracked-изменений нет нигде; untracked — только pytest-временные
  каталоги и чужие docs в `team-publish` (не трогаются).
- Diff `origin/main..03832ee`: 65 файлов, +8256/−240, только src/tests/specs/docs/метаданные;
  runs/reports/cache отсутствуют; скан добавленных строк на секреты — только имена
  env-переменных и dummy-значения тестов, проверяющих отсутствие утечки.
- Создан worktree `worktrees/full-stack-rc1`, ветка `integration/full-stack-rc1` от `03832ee`.
- Карточка 009 оформлена (spec/plan/tasks). Реконструкция стека не требуется —
  стартуем ровно с `03832ee`.

## Журнал

(заполняется по ходу этапов)
