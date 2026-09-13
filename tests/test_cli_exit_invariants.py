"""tests/test_cli_exit_invariants.py — C1 (фича 006): фиксация exit-инвариантов CLI.

Различение кодов возврата — жёсткое требование (cli.py docstring):
    0 — успех ИЛИ честный негатив (находка NOT_EXPLOITABLE);
    1 — ошибка runner/adapter/config;
    2 — ошибка разбора аргументов argparse.
Отдельного кода возврата для INCONCLUSIVE/UNKNOWN нет и не вводится: это состояние
находки/стадии (None в JSON), а не код выхода (Принцип VII, FR-020).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from memnotsafe import cli

_SCENARIOS = Path(__file__).resolve().parents[1] / "scenarios"


def test_honest_negative_exits_zero_with_not_exploitable(tmp_path) -> None:
    """Protected-сценарий: авторизация реально сработала, утечки нет — это
    честный НЕГАТИВ, а не ошибка: exit 0 + находки NOT_EXPLOITABLE."""
    out = tmp_path / "out"
    rc = cli.main(
        [
            "run",
            "--scenario", str(_SCENARIOS / "cross_user_bac_protected.yaml"),
            "--output", str(out),
        ]
    )
    assert rc == 0
    findings = json.loads((out / "report" / "findings.json").read_text(encoding="utf-8"))
    assert findings, "protected-прогон обязан дать находки"
    assert all(f["status"] == "NOT_EXPLOITABLE" for f in findings)


def test_runtime_error_exits_one(tmp_path) -> None:
    """report по несуществующему прогону — runtime-ошибка операции: exit 1."""
    rc = cli.main(
        [
            "report",
            "--input", str(tmp_path / "missing-run"),
            "--output", str(tmp_path / "rep"),
        ]
    )
    assert rc == 1


def test_argparse_error_exits_two(capsys) -> None:
    """Неизвестный аргумент — ошибка разбора: SystemExit(2), usage в stderr,
    до cmd_* (вне JSON-контракта)."""
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["run", "--no-such-flag"])
    assert excinfo.value.code == 2
    captured = capsys.readouterr()
    assert "usage" in captured.err
    assert captured.out == ""


def test_no_inconclusive_exit_code() -> None:
    """INCONCLUSIVE/UNKNOWN не получает собственного кода возврата — ни константы,
    ни `return 3`, ни `sys.exit(3)` в cli.py."""
    src = Path(cli.__file__).read_text(encoding="utf-8")
    assert "EXIT_INCONCLUSIVE" not in src
    assert not re.search(r"\breturn 3\b", src)
    assert not re.search(r"sys\.exit\(3\)", src)
