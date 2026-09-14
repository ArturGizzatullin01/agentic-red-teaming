# Checkpoint — блок «Evidence Foundation к интеграции» (фича 007)

Обновлён: 2026-09-14, исполнитель GLM 5.3 Flash.

## База и позиция
- Исходная база блока: `4ee868a` (последний кандидат, оба RETURN_FOR_FIX закрыты), ветка
  `evidence/foundation` продолжена на месте (worktree чист, чужого WIP нет).
- База Evidence Foundation: `052467c`; ancestry проверен (`merge-base --is-ancestor` ok).
- HEAD на момент checkpoint: см. git log — последний коммит секции «Команды» ниже.

## Этапы блока
| Этап | Статус | Результат |
|---|---|---|
| 0. база/план | ✅ | allowlist: core/{goal_contract,experiment,attempt,ledger}, evidence/bundle, generation/rewrite, campaign/escalation/cli (аддитивно), specs/007, specs/008-p09-full, tests/test_*; main и соседние worktree не тронуты |
| 1. воспроизводимость | ✅ | /tmp/esc-unit → tmp_path (6 call sites, фиксированный путь удалён из тестов, каталог пользователя не тронут); TTY-тесты герметичны от TERM (TERM=dumb воспроизведён → фикс в тесте, production-контракт цел); полный suite 746×2 на свежих basetemp |
| 2. аудит полноты A–E | ✅ | подтверждены и исправлены: attempt_no="x"/слоты-не-объекты → BundleError (были краши); мусорный attempts.jsonl → AttemptHistoryError с номером строки → обёрнут в BundleError для replay; ExperimentSpec получил runner-секцию (stop_on_success/trigger_override/oracle_overrides/require_case_marker) — изменение создаёт новый experiment_id; 752 passed |
| 3. E2E-интеграция | ✅ | согласованность манифест↔история enforcement в verify_run_evidence (attempt_no/case_id/candidate_id) + негативный тест подмены attempt_no → 753 passed |
| 4. офлайн-установка | ⛔ BLOCKED | setuptools>=68 отсутствует во всех интерпретаторах машины; колёса зависимостей локально нет; сеть без разрешения запрещена → specs/007/offline-install-gate.md: точный список wheelhouse + команды + smoke-чеклист; C10 не закрывается |
| 5. карточка P09-full | ✅ | specs/008-p09-full/card.md: gates, UNKNOWN-таблица с причинами, три источника, различение effective context/adapter args/tool args, корреляция call_id, negative controls, UNKNOWN vs доказанное отсутствие, поля бюджета для владельца; live не начинался |
| 6. финал | ✅ | 753×2 passed на свежих basetemp; секрет-скан и скан ослабления assertions чистые; LOG/MAP обновлены |

## Команды и результаты (реально выполненные)
- `pytest tests/ -q -p no:cacheprovider --basetemp=…` → 746, 746, 752, 753, 753 (хронология этапов), финал ×2: 753 passed, exit 0.
- `TERM=dumb pytest tests/test_cli_output.py` → до фикса 1 failed (воспроизведение), после — 26 passed.
- Интерпретатор: Python 3.14.7; pytest 9.1.1, rich 14.3.4, PyYAML 6.0.3, httpx 0.28.1, pymongo 4.18.0 (не используется офлайн-путём).

## Дефекты блока (все закрыты)
1. тесты зависели от фиксированного /tmp/esc-unit (PermissionError у приёмщика);
2. TTY-тест зависел от TERM окружения (TERM=dumb → нет ANSI);
3. read_bundle падал сырым ValueError/AttributeError на некорректных типах полей манифеста;
4. read_history/read_ledger падали сырым JSONDecodeError на повреждённой строке;
5. ExperimentSpec не включал runner-оверрайды (противоречие собственному докстрингу);
6. verify_run_evidence проверял существование пакета, но не согласованность с историей.

## Следующий шаг
- Приёмщик: независимый прогон полного suite + ревью диффа блока.
- Внешние блокеры: offline-install gate (сетевые права — см. offline-install-gate.md), R1, P09-full live (поля бюджета §9 карточки — на утверждение владельца).
- Не начаты: R1/P09/C10-релиз (по указанию).
