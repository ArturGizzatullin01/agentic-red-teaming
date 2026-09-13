# 006-operator-cli — контракт вывода консоли (console-output)

Источники: карточка CLI v1 (C8), `specs/006-operator-cli/research.md`.
Каждая строка таблицы покрыта тестом в `tests/test_cli_edges.py` (имя теста в колонке «Тест»).

## Таблица поведения

| Ситуация | stdout | stderr | exit |
|---|---|---|---|
| success human | таблица | — | 0 |
| success --json | один JSON | — | 0 |
| success --quiet | пусто | — | 0 |
| success --json --quiet | один JSON (json>quiet) | — | 0 |
| runtime/config error human | — | сообщение | 1 |
| runtime/config error --json | пусто | JSON error | 1 |
| judge gate fail | как success | — | outcome=gate_failed, exit 1 (не runtime) |
| --help | справка | — | 0 |
| missing/unknown arg | пусто | usage + ошибка | 2 (до renderer; вне JSON-контракта) |

## Правила

- **--help и ошибка argparse — РАЗНЫЕ строки.** `--help` → stdout / exit 0;
  неизвестный или недостающий аргумент → stderr (usage + ошибка) / exit 2. Обе ситуации
  отрабатывают ДО `cmd_*` (печатает сам argparse), и JSON-контракт «один объект» на них
  НЕ распространяется.
- **--json сильнее --quiet.** `--json --quiet` даёт один JSON-объект, а не пустоту.
- **JSON-контракт (success).** Ровно один объект на stdout, `json.loads` разбирает целиком:
  `{schema_version, command, outcome, exit_code, data, artifacts}`. `outcome ∈ {success,
  gate_failed, error}`; UNKNOWN/INCONCLUSIVE внутри `data` — это `null` (стадия со
  `success: None`) и никогда не приводится к pass/fail; отдельного exit-кода для
  INCONCLUSIVE не существует. Секреты (значения ключей) в объект не попадают.
- **JSON-ошибка (--json).** При runtime/config-ошибке stdout пуст, в stderr — один объект
  той же схемы с `outcome: "error"`, `exit_code: 1`, `data.message`.
- **judge gate fail — не runtime.** Непройденный `--gate` калибровки: stdout «как success»
  (human-таблица или JSON), stderr пуст, `outcome: "gate_failed"`, exit 1.
- **attacker-failure в run/campaign.** Результат проговора НЕ глотается: сначала
  результат-объект (`outcome: "success"`, `exit_code: 1`, артефакты записаны), затем
  error-объект в stderr, затем exit 1. Чинить «на успех» запрещено.
- **Цвет.** ANSI только на настоящем TTY; `--no-color`, `NO_COLOR`, non-TTY, `--json`,
  `--quiet` — чистый ASCII. rich импортируется лениво и только в TTY-ветке с цветом.
- **Предупреждения конфигурации** (`[WARN]`) всегда идут в stderr и не являются частью
  JSON-контракта (диагностика, не результат).

## Покрытие тестами

| Строка таблицы | Тест |
|---|---|
| success human | `test_success_human_stdout_table_stderr_empty` |
| success --json | `test_success_json_stdout_one_object_stderr_empty` |
| success --quiet | `test_quiet_success_has_empty_stdout` (исключает --json) |
| success --json --quiet | `test_json_quiet_success_stdout_one_object` |
| runtime/config error human | `test_runtime_error_human_stdout_empty_stderr_message`, `test_config_error_human_exit_1_before_target` |
| runtime/config error --json | `test_runtime_error_json_stdout_empty_stderr_json_object` |
| judge gate fail | `test_judge_gate_fail_human_stdout_like_success_stderr_empty`, `test_judge_gate_fail_json_stdout_object_outcome_gate_failed` |
| --help | `test_help_goes_to_stdout_exit_0` |
| missing/unknown arg | `test_unknown_arg_stderr_exit_2_before_any_renderer`, `test_missing_required_arg_stderr_exit_2` |
