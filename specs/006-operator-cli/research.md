# 006-operator-cli — research

## Baseline (C1)

- База: `c7fd325` (принятый K2/K3), ветка `cli/operator-v1`, worktree
  `../worktrees/cli-operator-v1` (вне team-publish).
- Полный офлайн-набор на базе: **608 passed in 11.70s**
  (`PYTHONPATH=src <venv-integration>/python.exe -m pytest tests/ -q -p no:cacheprovider --basetemp=.pytest-tmp-cli`).
- Текущее состояние вывода CLI: человекочитаемые строки — прямые `print()` внутри `cmd_*`
  (`cli.py`), ошибки — `[FATAL] …` в stderr, argparse печатает usage сам. Отдельного
  output-слоя нет; формат `[FATAL]` на stderr заффиксен тестом
  `test_config_error_is_exit_1_before_touching_the_target` — он сохраняется.

## Exit-инварианты (фиксируются тестами в C1, менять запрещено)

| Код | Ситуация |
|---|---|
| 0 | успех ИЛИ честный негатив (находка NOT_EXPLOITABLE — регресс `cross_user_bac_protected`) |
| 1 | ошибка runner/adapter/config (до таргета или после сохранения результата при сбое атакующей LLM) |
| 2 | ошибка разбора аргументов argparse — до `cmd_*`, вне JSON-контракта |

UNKNOWN/INCONCLUSIVE — это **состояние** находки/стадии (`None` в JSON, статус INCONCLUSIVE),
а НЕ код возврата: отдельного exit-кода для него нет и не вводится
(`test_no_inconclusive_exit_code`). Не путать с `--gate`: непройденный гейт калибровки —
outcome `gate_failed`, exit 1, но это НЕ runtime-ошибка (stdout «как success»).

## Маппинг CampaignResult → outcome (решение для C5/C7)

- `outcome` команды ∈ {`success`, `gate_failed`, `error`}. Статусы находок (SUCCESS /
  NOT_EXPLOITABLE / INCONCLUSIVE) — данные (`data.findings_counts`, `data.results`), не outcome.
- Завершённый прогон (run/campaign/report) → `outcome=success`; exit 0, либо 1 при сбое
  атакующей LLM в эскалации — тогда сначала `emit_result` (результат сохранён, артефакты
  записаны), затем `emit_error`, затем exit 1 (не глотать, не чинить «на успех»).
- probe недостижимого таргета → честный негатив probes? Нет: существующая семантика
  `probe` — exit 1 при `reachable=False` (таргет недоступен = отказ операции), выводится
  через `emit_error`.

## План коммитов

| C | Содержание |
|---|---|
| C1 | baseline 608 + exit-инварианты (тесты) + RED output-тесты |
| C2 | `reporting/console.py`: `OutputOptions` + `ConsoleReporter`, инъекция потоков, plain |
| C3 | Rich-рендер только на TTY; non-TTY/`--no-color`/`NO_COLOR` → ASCII; lazy import; pyproject `rich>=13.9,<15` |
| C4 | `--json/--quiet/--no-color` на каждый subparser |
| C5 | `run` + `campaign` через reporter (статусы из build_findings/CampaignResult) |
| C6 | `probe`, `report`, `judge-calibrate`, `replay`, `generate` через reporter |
| C7 | JSON-контракт: один объект на stdout, UNKNOWN → null, без секретов |
| C8 | quiet/error/security-грани + `contracts/console-output.md` (таблица дословно) |
| C9 | help-тексты + README/MAP/LOG/quickstart (по фактическому CLI) |

C10 (release: offline wheel, E2E-gate) — вне карточки, ждёт R1.
