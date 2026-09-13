"""tests/test_cli_wiring.py — маршрутизация команд CLI через ConsoleReporter
(фича 006). Проверки идут через cli.main + capsys: репортер по умолчанию пишет
в sys.stdout/sys.stderr, разрешая потоки при использовании (не при создании)."""

from __future__ import annotations

import json
from pathlib import Path

from memnotsafe import cli

_SCENARIOS = Path(__file__).resolve().parents[1] / "scenarios"
_VULNERABLE = str(_SCENARIOS / "cross_user_bac.yaml")


# --------------------------------------------------------------------- C5

def test_run_human_summary_through_reporter(tmp_path, capsys) -> None:
    rc = cli.main(["run", "--scenario", _VULNERABLE, "--output", str(tmp_path / "run")])
    assert rc == 0
    out = capsys.readouterr().out
    assert "AGENTIC MEMORY RED TEAMING" in out
    assert "WRITE" in out and "END-TO-END ASR:" in out
    assert "Report:" in out


def test_run_json_is_one_object_with_data_and_artifacts(tmp_path, capsys) -> None:
    rc = cli.main(["run", "--scenario", _VULNERABLE, "--output", str(tmp_path / "run"), "--json"])
    assert rc == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)  # ровно один объект — парсится целиком
    assert payload["command"] == "run"
    assert payload["outcome"] == "success"
    assert payload["exit_code"] == 0
    assert payload["data"]["findings_counts"] == {"SUCCESS": 1}
    assert payload["data"]["results"][0]["status"] == "SUCCESS"
    assert any(a.endswith("report.html") for a in payload["artifacts"])
    assert captured.err == ""


def test_run_quiet_prints_nothing(tmp_path, capsys) -> None:
    rc = cli.main(["run", "--scenario", _VULNERABLE, "--output", str(tmp_path / "run"), "--quiet"])
    assert rc == 0
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_campaign_json_reports_command_name(tmp_path, capsys) -> None:
    rc = cli.main(
        ["campaign", "--scenario", _VULNERABLE, "--output", str(tmp_path / "run"),
         "--iterations", "2", "--json"]
    )
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["command"] == "campaign"
    assert payload["data"]["attempts"] == 2


class _FailAfterRunCampaign:
    """Подмена Campaign: прогон завершается, результат сохраняется, но
    attacker_error выставлен — имитация сбоя атакующей LLM в эскалации."""

    def __init__(self, scenario, target, run_output, **kwargs) -> None:
        self.judge = None
        self.attacker_error = None
        self._scenario = scenario

    async def run(self, repetitions: int = 1):
        from memnotsafe.core.models import CampaignResult
        from memnotsafe.reporting.metrics import aggregate_metrics

        self.attacker_error = "stub-скрипт исчерпан"
        return CampaignResult(
            run_id="RUN-FAIL",
            scenario_id=self._scenario.id,
            attempts=0,
            results=[],
            aggregate_metrics=aggregate_metrics([]),
        )

    async def aclose_attacker(self) -> None:
        return None


def test_attacker_failure_saves_result_then_error_exit_1(tmp_path, capsys, monkeypatch) -> None:
    monkeypatch.setattr(cli, "Campaign", _FailAfterRunCampaign)
    rc = cli.main(["run", "--scenario", _VULNERABLE, "--output", str(tmp_path / "run")])
    captured = capsys.readouterr()
    assert rc == 1
    assert "AGENTIC MEMORY RED TEAMING" in captured.out  # результат проговорён, не проглочен
    assert "[FATAL]" in captured.err
    assert "сбой атакующей LLM" in captured.err
    assert (tmp_path / "run" / "report" / "report.html").exists()  # артефакты сохранены


def test_attacker_failure_json_stdout_result_stderr_error(tmp_path, capsys, monkeypatch) -> None:
    monkeypatch.setattr(cli, "Campaign", _FailAfterRunCampaign)
    rc = cli.main(["run", "--scenario", _VULNERABLE, "--output", str(tmp_path / "run"), "--json"])
    captured = capsys.readouterr()
    assert rc == 1
    result_payload = json.loads(captured.out)  # один объект результата в stdout
    assert result_payload["outcome"] == "success"
    assert result_payload["exit_code"] == 1  # честный итоговый код команды
    error_payload = json.loads(captured.err)  # один объект ошибки в stderr
    assert error_payload["outcome"] == "error"
    assert "сбой атакующей LLM" in error_payload["data"]["message"]
