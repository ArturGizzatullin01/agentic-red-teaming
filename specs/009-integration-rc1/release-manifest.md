# Release Manifest — integration RC1 (подготовка к R1/C10)

Дата: 2026-09-14 · Ветка: `integration/full-stack-rc1` · Worktree:
`C:\Users\dota2\memnotsafe-integration\worktrees\full-stack-rc1`

## 1. Идентификация

- **base_sha:** `6f0c4a7` — `origin/main` (истинная база, PR #39)
- **candidate_sha:** HEAD ветки `integration/full-stack-rc1` на момент handoff.
  Коммит данного манифеста — финальный коммит ветки; производственный код
  ветки идентичен принятому `03832ee`, после него только документация
  (`specs/009-*`, LOG). Точный SHA candidate фиксируется в handoff-сообщении
  и проверяется приёмщиком (`git rev-parse integration/full-stack-rc1`).
- **git status ветки:** чистый (tracked), untracked — только каталоги
  `.pytest-tmp-rc1*` (временные, не коммитятся).
- **Локальный main `cbd7e6b`** отстаёт от `origin/main` на 2 коммита —
  не трогался; перед будущим merge владельцу сделать `git fetch` (MAP/план §1).

## 2. Порядок принятых слоёв (все — с независимым ACCEPT, линейно)

| # | Слой | SHA | Независимая приёмка |
|---|---|---|---|
| 0 | origin/main (база) | `6f0c4a7` | — |
| 1 | R0 measurement-дельта (P04–P08, P07-neg, K4-fin, P09-lite) | `b1926e0` | A0 ACCEPT, 593 passed |
| 2 | K2/P02 + K3/P03 | `c7fd325` | ACCEPT, 608 passed |
| 3 | CLI v1 (C1–C9) | `052467c` | ACCEPT, 671 passed |
| 4 | Evidence Foundation (P10a/P10b) | `03832ee` | ACCEPTED_UNMERGED, 759 passed |

Ancestry перепроверен при сборке RC1 (6/6 `git merge-base --is-ancestor` OK):
`origin/main → b1926e0 → c7fd325 → 052467c → 03832ee → candidate`.

## 3. Коммиты и diff-stat

- Коммитов `6f0c4a7..candidate`: **43** (14 measurement + 2 P02/P03 + 9 CLI +
  16 Evidence Foundation + 2 карточки 009: спека и manifest/доки).
- Diff-stat `origin/main..candidate`: **70 файлов**; дельта RC1 к принятому
  `03832ee` — ТОЛЬКО документация (`LOG.md` + `specs/009-integration-rc1/*`),
  производственный код идентичен `03832ee` (`git diff 03832ee..HEAD --name-only`).
  Точный подсчёт строк: `git diff --shortstat 6f0c4a7..integration/full-stack-rc1`.
- Полный список: `git log --oneline 6f0c4a7..integration/full-stack-rc1`.

## 4. Профильные проверки границ (на финальном дереве, по одному прогону на слой)

| Слой | Файлы | Результат |
|---|---|---|
| A measurement | write_marker_p04, phase_snapshots_p06, settle_outcomes_p05, reporting_diagnostics_p08, judge_goal_p07, write_zone_owner, investment_stand_settle, evidence_integrity, e2e_cross_user, all_attacks | **183 passed** |
| B P02/P03 | attack_registry, profile_and_corpus, generation_offline, escalation | **59 passed** |
| C CLI v1 | cli_output, cli_exit_invariants, cli_wiring, cli_edges | **63 passed** |
| D Evidence Foundation | goal_contract_p10a, evidence_bundle_p10a, experiment_spec_p10b, attempt_history_p10b, budget_ledger_p10b, evidence_foundation_e2e, reporting_replay | **106 passed** |

Отменяющих коммитов нет: после `b1926e0` не трогались oracles/, adapters/,
evidence/snapshot|matching, judge/, core/runner.py; поздние правки общих файлов
(`generation/rewrite.py`, `cli.py`, `core/campaign.py`, `core/escalation.py`,
`attacks/base.py`) аддитивны и покрыты прогонами слоёв B–D на финальном дереве.

## 5. Интеграционные инварианты (матрица 11 сценариев → существующие тесты)

Прогон матрицы: **98 passed** (`evidence_foundation_e2e + cli_edges + cli_output +
cli_exit_invariants + reporting_replay + write_zone_owner + all_attacks +
e2e_cross_user`).

| Сценарий | Существующие тесты |
|---|---|
| обычная mock-атака | `test_success_scenario_full_artifact_chain`; `test_all_attacks` |
| защищённый честный негатив (exit 0 + NOT_EXPLOITABLE) | `test_honest_negative_full_chain`; `test_honest_negative_exits_zero_with_not_exploitable` |
| UNKNOWN при отсутствии телеметрии | `test_unknown_outcome_from_missing_telemetry`; `test_json_unknown_stage_is_null_never_coerced` |
| cross-user victim-zone | `test_runner_e2e_victim_zone_write_persist_retrieval`, `test_cross_positive_chain_write_persist_retrieval`, `test_cross_write_in_attacker_layer_is_not_success`; `test_e2e_cross_user` |
| generated family | `test_generated_run_keeps_family_generated_not_source_class`, `test_cli_replay_preserves_family_from_real_writer`; `test_generation_offline` |
| несколько попыток escalation | `test_multistep_escalation_bundles_match_history`, `test_accepted_rewrite_e2e_lineage`, `test_rejected_rewrite_e2e`; `test_escalation` |
| повреждённый пакет | `test_corrupted_artifact_detected_by_replay`, `test_incomplete_bundle_is_not_mistaken_for_complete`, `test_bundle_failure_before_mkdir_replay_exit_1`, `test_manifest_history_mismatch_detected` |
| исторический run без новых артефактов | `test_historical_run_without_new_artifacts`, `test_historical_v1_spec_reads_with_own_digest` |
| JSON / non-TTY / quiet / no-color | `test_cli_edges` (13), `test_cli_output` |
| runner error → exit 1; argparse → exit 2 | `test_runtime_error_exits_one`, `test_transport_error_e2e_cli_exit_1`, `test_argparse_error_exits_two`, `test_no_inconclusive_exit_code` |
| composite и ASR не изменены | `test_asr_counts_composite_success_not_external_effect`, `test_asr_run_replay_consistency`, `test_asr_unknown_mandatory_stage_is_not_success`; `test_evidence_integrity` |

Интеграционных дефектов не обнаружено; новых тестов не добавлялось.

## 6. Полный suite (один прогон)

- **759 passed / 0 failed / 0 skipped**, 21.1s — на производственном дереве
  `c60aba7` (код ветки = принятый `03832ee`; последующий коммит манифеста —
  только документация, повтор по политике карточки не требуется).
- Совпадает с независимо подтверждённым числом на `03832ee` — дрейфа нет.

## 7. C10 wheel / чистая установка — **NEEDS_AUTHORITY** (внешний блокер среды)

Проверено (известные интерпретаторы + локальные кэши, без скана машины):
- `.venv-integration` (Py 3.14.7): `import setuptools` → ModuleNotFoundError;
  `import wheel` → ModuleNotFoundError (совпадает с независимым подтверждением приёмщика).
- `pip cache`: locally built wheels = **0**; HTTP-кэш (2210 файлов) wheelhouse не образует.
- Локальных каталогов wheelhouse нет; backend сборки — `setuptools.build_meta>=68`.
- uv 0.12.12 установлен, но offline-bootstrap setuptools не снимает.

Следствие: сборка wheel, чистый venv с `--no-index` и installed-CLI smoke
офлайн невозможны. Подэтап помечен **NEEDS_AUTHORITY** — нужна ОДНА сетевая
сессия (скачивание зависимостей в wheelhouse + build-isolation bootstrap).
Точная команда (PowerShell, код не меняет; `$repo` = этот worktree):

```powershell
$work = "$env:TEMP\c10-preview"
New-Item -ItemType Directory -Force -Path "$work\wheelhouse" | Out-Null
$PY = "C:\Users\dota2\memnotsafe-integration\agentic-red-teaming-main\.venv-integration\Scripts\python.exe"
$repo = "C:\Users\dota2\memnotsafe-integration\worktrees\full-stack-rc1"
& $PY -m pip download -d "$work\wheelhouse" pyyaml httpx "rich>=13.9,<15"
& $PY -m pip wheel "$repo" --no-deps -w "$work\wheelhouse"
```

После снятия блокера: чистый venv вне репо → `--no-index --find-links` →
`pip check` → installed-CLI smoke по чеклисту
`specs/007-evidence-foundation/offline-install-gate.md`. Запуск через
PYTHONPATH проверкой установки не считается.

## 8. Стратегия истории

- Стек линейный, сохраняется как есть: **42 коммита с документированным
  непроходным промежуточным CLI-коммитом C5 `39458fa`** (11 переходных failed:
  `cmd_report` ссылался на удалённый `_print_summary` до проводки C6; закрыт в C6,
  финальный HEAD зелёный — подтверждено приёмкой CLI).
- Альтернатива (squash в 1–4 коммита при будущем PR) — решение владельца/приёмщика
  R1; сейчас не выполняется (переписывание принятой истории запрещено карточкой).

## 9. Секреты и случайные артефакты

- Diff не содержит runs/, reports/, cache, временных файлов; скан добавленных
  строк: только имена env-переменных и dummy-значения тестов, проверяющих
  отсутствие утечки (`test_json_contract_carries_no_secrets`,
  `test_manifest_carries_no_secrets`).
- Untracked в worktree: только `.pytest-tmp-rc1*` — не коммитятся.

## 10. Точная команда будущего слияния (выполняет ВЛАДЕЛЕЦ, не исполнитель)

```bash
git fetch origin
git checkout main && git merge --ff-only origin/main   # подтянуть cbd7e6b → 6f0c4a7+
git merge --ff-only integration/full-stack-rc1          # или PR из этой ветки в main
```

Прямой push/merge исполнителем запрещён; кандидат не запушен.

## 11. Rollback

- main не тронут → откат = удалить ветку: `git branch -D integration/full-stack-rc1`
  и `git worktree remove worktrees/full-stack-rc1`. Ни один принятый слой не
  изменён, внешних эффектов нет.

## 12. Статусы MASTER-PLAN, обновляемые ПОСЛЕ фактического слияния

НЕ обновляются этим RC (acceptance.md остаётся без записей о merge; main нигде ✅):
- после влития R1 (этот candidate или его squash): леджер §2 — `CLI v1` Реал.=✅,
  Пров.=✅ (независимый прогон приёмщика), main=✅; `P02/P03/K4-fin` main=✅;
  `P10 контракты+ledger` Реал.=✅, Пров.=✅; C10 остаётся ⬜ до wheel-gate;
- R1 в §4/§9 помечается выполненным только владельцем после фактического merge.

## 13. Известные ограничения кандидата (наследованные, не дефекты RC)

- C10 не пройден (NEEDS_AUTHORITY, §7) — R1/C10 релиз-гейт остаётся открытым.
- Живой TTY-цвет и `python -m memnotsafe` (нет `__main__.py`) — из записи
  приёмки CLI, вне объёма этой карточки.
- Установка из wheel не доказана → «поставлено из PyPI/wheel» нигде не заявляется.
