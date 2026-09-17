"""tests/test_cli_repetitions_warning.py — W9, безопасная половина: молчаливое
переопределение metrics.repetitions должно «молчать громко».

CLI всегда задаёт число повторов явно (run — жёстко 1, campaign — --iterations
или 5), значение из YAML не влияет ни на что. С этой карточки расхождение
объявленного и фактического печатается предупреждением в stderr с ОБОИМИ
числами и причиной. Семантика НЕ меняется (PASS_IF-1): фактическое число
повторов у команд то же, что до карточки; --json-контракт «один объект»
на stdout чист (предупреждение — только stderr).
"""

from __future__ import annotations

import json
from pathlib import Path

from memnotsafe import cli

_SCENARIOS = Path(__file__).resolve().parents[1] / "scenarios"
# false_precedent.yaml объявляет metrics.repetitions: 3; cross-topic-smuggle — 1
_DECLARED_3 = str(_SCENARIOS / "false_precedent.yaml")
_DECLARED_1 = str(_SCENARIOS / "cross-topic-smuggle.yaml")


def _attempts(out: Path) -> int:
    return json.loads((out / "campaign.json").read_text(encoding="utf-8"))["attempts"]


def test_run_warns_with_both_numbers_and_keeps_attempts_1(tmp_path, capsys) -> None:
    rc = cli.main(["run", "--scenario", _DECLARED_3, "--output", str(tmp_path / "r1")])
    assert rc == 0
    err = capsys.readouterr().err
    assert "metrics.repetitions=3" in err
    assert "исполнено будет 1" in err
    assert "умолчанием команды run" in err
    # PASS_IF-1: фактическое число повторов не изменилось — run по-прежнему 1
    assert _attempts(tmp_path / "r1") == 1


def test_no_warning_when_declared_matches_actual(tmp_path, capsys) -> None:
    rc = cli.main(["run", "--scenario", _DECLARED_1, "--output", str(tmp_path / "r2")])
    assert rc == 0
    assert "metrics.repetitions" not in capsys.readouterr().err
    assert _attempts(tmp_path / "r2") == 1


def test_campaign_flag_override_warns_with_both_numbers(tmp_path, capsys) -> None:
    rc = cli.main(["campaign", "--scenario", _DECLARED_3, "--output",
                   str(tmp_path / "c1"), "--iterations", "2"])
    assert rc == 0
    err = capsys.readouterr().err
    assert "metrics.repetitions=3" in err
    assert "исполнено будет 2" in err
    assert "флагом --iterations" in err
    # PASS_IF-1: campaign исполняет ровно --iterations
    assert _attempts(tmp_path / "c1") == 2


def test_campaign_default_override_warns_with_command_default(tmp_path, capsys) -> None:
    rc = cli.main(["campaign", "--scenario", _DECLARED_3, "--output", str(tmp_path / "c2")])
    assert rc == 0
    err = capsys.readouterr().err
    assert "metrics.repetitions=3" in err
    assert "исполнено будет 5" in err
    assert "умолчанием команды campaign (5)" in err
    # PASS_IF-1: campaign без флага по-прежнему 5
    assert _attempts(tmp_path / "c2") == 5


def test_json_contract_stays_one_object_with_warning(tmp_path, capsys) -> None:
    # PASS_IF-3: предупреждение не ломает машинный контракт — при --json оба
    # потока чисты (предупреждение — только human-режим, контракты «один
    # объект»/«пусто» не меняются), stdout парсится одним объектом, exit 0
    rc = cli.main(["run", "--scenario", _DECLARED_3, "--output",
                   str(tmp_path / "r3"), "--json"])
    assert rc == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["command"] == "run" and payload["outcome"] == "success"
    assert captured.err == ""
