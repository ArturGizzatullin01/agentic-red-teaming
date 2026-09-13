"""tests/test_cli_edges.py — C8 (фича 006): граничные случаи вывода CLI.

Каждая строка таблицы contracts/console-output.md покрыта тестом. --help и
ошибка argparse отрабатывают ДО cmd_* и ВНЕ JSON-контракта (argparse печатает
сам); exit-семантика: 0 — успех/честный негатив, 1 — runtime/config и
gate_failed, 2 — argparse. Отдельного кода для INCONCLUSIVE нет.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from memnotsafe import cli

_SCENARIOS = Path(__file__).resolve().parents[1] / "scenarios"
_VULNERABLE = str(_SCENARIOS / "cross_user_bac.yaml")


def _make_run(tmp_path: Path) -> Path:
    run = tmp_path / "run"
    assert cli.main(["run", "--scenario", _VULNERABLE, "--output", str(run)]) == 0
    return run


# | success human | таблица | — | 0 |
def test_success_human_stdout_table_stderr_empty(tmp_path, capsys) -> None:
    _make_run(tmp_path)
    capsys.readouterr()
    rc = cli.main(["report", "--input", str(tmp_path / "run"), "--output", str(tmp_path / "rep")])
    captured = capsys.readouterr()
    assert rc == 0
    assert "AGENTIC MEMORY RED TEAMING" in captured.out  # таблица
    assert captured.err == ""


# | success --json | один JSON | — | 0 |
def test_success_json_stdout_one_object_stderr_empty(tmp_path, capsys) -> None:
    _make_run(tmp_path)
    capsys.readouterr()
    rc = cli.main(["report", "--input", str(tmp_path / "run"), "--output", str(tmp_path / "rep"), "--json"])
    captured = capsys.readouterr()
    assert rc == 0
    payload = json.loads(captured.out)  # ровно один объект
    assert payload["outcome"] == "success"
    assert captured.err == ""


# | success --quiet | пусто | — | 0 |
# Исключает случай --json: json сильнее quiet (следующая строка таблицы).
def test_quiet_success_has_empty_stdout(tmp_path, capsys) -> None:
    _make_run(tmp_path)
    capsys.readouterr()
    rc = cli.main(["report", "--input", str(tmp_path / "run"), "--output", str(tmp_path / "rep"), "--quiet"])
    captured = capsys.readouterr()
    assert rc == 0
    assert captured.out == ""
    assert captured.err == ""


# | success --json --quiet | один JSON (json>quiet) | — | 0 |
def test_json_quiet_success_stdout_one_object(tmp_path, capsys) -> None:
    _make_run(tmp_path)
    capsys.readouterr()
    rc = cli.main(["report", "--input", str(tmp_path / "run"), "--output", str(tmp_path / "rep"),
                   "--json", "--quiet"])
    captured = capsys.readouterr()
    assert rc == 0
    payload = json.loads(captured.out)
    assert payload["command"] == "report"
    assert captured.err == ""


# | runtime/config error human | — | сообщение | 1 |
def test_runtime_error_human_stdout_empty_stderr_message(tmp_path, capsys) -> None:
    rc = cli.main(["report", "--input", str(tmp_path / "missing"), "--output", str(tmp_path / "rep")])
    captured = capsys.readouterr()
    assert rc == 1
    assert captured.out == ""
    assert "[FATAL]" in captured.err


# | runtime/config error human | — | сообщение | 1 | (config-вариант: судья без ключа)
def test_config_error_human_exit_1_before_target(tmp_path, capsys, monkeypatch) -> None:
    monkeypatch.setenv("OPENROUTER_API_KEY", "")
    scenario = tmp_path / "judged.yaml"
    scenario.write_text(
        "id: t\n"
        "target:\n  adapter: mock\n"
        "actors:\n  attacker:\n    user_id: '1001'\n  victim:\n    user_id: '1002'\n"
        "attack:\n  family: cross_user_bac\n"
        "judge:\n  enabled: true\n  model: some-model\n  api_key_env: OPENROUTER_API_KEY\n",
        encoding="utf-8",
    )
    rc = cli.main(["run", "--scenario", str(scenario), "--output", str(tmp_path / "run")])
    captured = capsys.readouterr()
    assert rc == 1
    assert captured.out == ""
    assert "OPENROUTER_API_KEY" in captured.err


# | runtime/config error --json | пусто | JSON error | 1 |
def test_runtime_error_json_stdout_empty_stderr_json_object(tmp_path, capsys) -> None:
    rc = cli.main(["report", "--input", str(tmp_path / "missing"), "--output", str(tmp_path / "rep"), "--json"])
    captured = capsys.readouterr()
    assert rc == 1
    assert captured.out == ""
    payload = json.loads(captured.err)  # один JSON-объект ошибки в stderr
    assert payload["outcome"] == "error"
    assert payload["exit_code"] == 1
    assert "не найден" in payload["data"]["message"]


# | judge gate fail | как success | — | outcome=gate_failed, exit 1 (не runtime) |
def _gate_dataset(tmp_path: Path, capsys) -> Path:
    run = _make_run(tmp_path)
    capsys.readouterr()
    dataset = tmp_path / "dataset.jsonl"
    assert cli.main(["judge-calibrate", "--from-run", str(run), "--out", str(dataset)]) == 0
    capsys.readouterr()
    return dataset


@pytest.fixture()
def _failing_calibrate(monkeypatch):
    async def _fake(cases, *, spec, client, dataset):
        return {
            "model": spec.model, "dataset": dataset, "total": len(cases), "min_confidence": 0.7,
            "agreement_rate": 0.5, "false_positives": 1, "false_negatives": 0, "undecided": 0,
            "injection_flips": 1, "by_stage": {}, "disagreements": [], "injection_details": [],
            "gate_passed": False,
        }

    monkeypatch.setattr("memnotsafe.judge.calibration.calibrate", _fake)
    monkeypatch.setenv("OPENROUTER_API_KEY", "не-пустой")  # config-гейт не мешает


def test_judge_gate_fail_human_stdout_like_success_stderr_empty(
    tmp_path, capsys, _failing_calibrate
) -> None:
    dataset = _gate_dataset(tmp_path, capsys)
    rc = cli.main(["judge-calibrate", "--dataset", str(dataset), "--judge-model", "test-model",
                   "--gate", "--output", str(tmp_path / "cal.json")])
    captured = capsys.readouterr()
    assert rc == 1
    assert "JUDGE CALIBRATION" in captured.out  # stdout «как success»
    assert "[GATE]" in captured.out  # вердикт о судье — в общий вывод, не в stderr
    assert captured.err == ""  # НЕ runtime-ошибка: stderr пуст


def test_judge_gate_fail_json_stdout_object_outcome_gate_failed(
    tmp_path, capsys, _failing_calibrate
) -> None:
    dataset = _gate_dataset(tmp_path, capsys)
    rc = cli.main(["judge-calibrate", "--dataset", str(dataset), "--judge-model", "test-model",
                   "--gate", "--output", str(tmp_path / "cal.json"), "--json"])
    captured = capsys.readouterr()
    assert rc == 1
    payload = json.loads(captured.out)  # один JSON в stdout, как у success
    assert payload["outcome"] == "gate_failed"
    assert payload["exit_code"] == 1
    assert captured.err == ""


def test_judge_without_gate_flag_is_success_despite_gate_passed_false(
    tmp_path, capsys, _failing_calibrate
) -> None:
    # Без --gate калибровка — измерение, а не вердикт о допуске: exit 0.
    dataset = _gate_dataset(tmp_path, capsys)
    rc = cli.main(["judge-calibrate", "--dataset", str(dataset), "--judge-model", "test-model",
                   "--output", str(tmp_path / "cal.json"), "--json"])
    captured = capsys.readouterr()
    assert rc == 0
    assert json.loads(captured.out)["outcome"] == "success"


# | --help | справка | — | 0 |
def test_help_goes_to_stdout_exit_0(capsys) -> None:
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["--help"])
    captured = capsys.readouterr()
    assert excinfo.value.code == 0
    assert "usage:" in captured.out
    assert captured.err == ""


# | missing/unknown arg | пусто | usage + ошибка | 2 (до renderer; вне JSON-контракта) |
def test_unknown_arg_stderr_exit_2_before_any_renderer(capsys) -> None:
    # probe без required-аргументов: чистый «unrecognized arguments» с текстом флага
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["probe", "--no-such-flag"])
    captured = capsys.readouterr()
    assert excinfo.value.code == 2
    assert captured.out == ""  # stdout пуст: JSON-контракт на argparse не распространяется
    assert "usage" in captured.err
    assert "--no-such-flag" in captured.err


def test_missing_required_arg_stderr_exit_2(capsys) -> None:
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["run", "--no-such-flag"])  # и required отсутствуют, и флаг неизвестен
    captured = capsys.readouterr()
    assert excinfo.value.code == 2
    assert captured.out == ""
    assert "required" in captured.err or "unrecognized" in captured.err
