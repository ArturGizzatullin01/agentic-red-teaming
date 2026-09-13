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


# --------------------------------------------------------------------- C6

def test_probe_mock_human_reachable_line(tmp_path, capsys) -> None:
    rc = cli.main(["probe", "--target", "mock"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "reachable: True" in out
    assert "capabilities:" in out


def test_probe_mock_json_one_object(tmp_path, capsys) -> None:
    rc = cli.main(["probe", "--target", "mock", "--json"])
    assert rc == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["command"] == "probe"
    assert payload["outcome"] == "success"
    assert payload["data"]["reachable"] is True
    assert captured.err == ""


def test_probe_quiet_prints_nothing(capsys) -> None:
    rc = cli.main(["probe", "--target", "mock", "--quiet"])
    assert rc == 0
    captured = capsys.readouterr()
    assert captured.out == ""


def test_report_human_summary_with_replay_note(tmp_path, capsys) -> None:
    run = tmp_path / "run"
    assert cli.main(["run", "--scenario", _VULNERABLE, "--output", str(run)]) == 0
    capsys.readouterr()
    rc = cli.main(["report", "--input", str(run), "--output", str(tmp_path / "rep")])
    assert rc == 0
    out = capsys.readouterr().out
    assert "AGENTIC MEMORY RED TEAMING" in out
    assert "Replay: агрегаты пересчитаны" in out  # регресс test_reporting_replay:269


def test_report_json_artifacts_listed(tmp_path, capsys) -> None:
    run = tmp_path / "run"
    assert cli.main(["run", "--scenario", _VULNERABLE, "--output", str(run)]) == 0
    capsys.readouterr()
    rc = cli.main(["report", "--input", str(run), "--output", str(tmp_path / "rep"), "--json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["command"] == "report"
    assert any(a.endswith("report.html") for a in payload["artifacts"])
    assert any(a.endswith("findings.sarif") is False for a in payload["artifacts"])


def test_replay_prints_trace_lines_and_missing_trace_errors(tmp_path, capsys) -> None:
    run = tmp_path / "run"
    assert cli.main(["run", "--scenario", _VULNERABLE, "--output", str(run)]) == 0
    case_id = json.loads((run / "campaign.json").read_text(encoding="utf-8"))["results"][0]["case_id"]
    capsys.readouterr()
    rc = cli.main(["replay", "--input", str(run), "--case", case_id])
    assert rc == 0
    out = capsys.readouterr().out
    assert "actor=" in out and "tool=" in out

    rc = cli.main(["replay", "--input", str(run), "--case", "no-such-case"])
    captured = capsys.readouterr()
    assert rc == 1
    assert "[FATAL]" in captured.err
    assert captured.out == ""


def test_generate_offline_stub_success(tmp_path, capsys) -> None:
    rc = cli.main([
        "generate",
        "--profile", "profiles/support-agent.yaml",
        "--classes", "attack_classes/",
        "--out", str(tmp_path / "corpus.yaml"),
    ])
    assert rc == 0
    captured = capsys.readouterr()
    assert "Корпус сохранён" in captured.out
    assert (tmp_path / "corpus.yaml").exists()


def test_generate_json_data_has_profile_and_counts(tmp_path, capsys) -> None:
    rc = cli.main([
        "generate",
        "--profile", "profiles/support-agent.yaml",
        "--classes", "attack_classes/",
        "--out", str(tmp_path / "corpus.yaml"),
        "--json",
    ])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["command"] == "generate"
    assert payload["data"]["profile_id"]
    assert payload["data"]["records"] >= 1
    assert payload["artifacts"] == [payload["data"]["corpus"]]


def test_judge_calibrate_from_run_offline(tmp_path, capsys) -> None:
    run = tmp_path / "run"
    assert cli.main(["run", "--scenario", _VULNERABLE, "--output", str(run)]) == 0
    capsys.readouterr()
    dataset = tmp_path / "dataset.jsonl"
    rc = cli.main([
        "judge-calibrate", "--from-run", str(run), "--out", str(dataset),
    ])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Собрано случаев:" in out
    assert dataset.exists()


def test_judge_calibrate_from_run_json_contract(tmp_path, capsys) -> None:
    run = tmp_path / "run"
    assert cli.main(["run", "--scenario", _VULNERABLE, "--output", str(run)]) == 0
    capsys.readouterr()
    dataset = tmp_path / "dataset.jsonl"
    rc = cli.main(["judge-calibrate", "--from-run", str(run), "--out", str(dataset), "--json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["command"] == "judge-calibrate"
    assert payload["data"]["cases"] >= 1
    assert payload["artifacts"] == [payload["data"]["dataset"]]


# --------------------------------------------------------------------- C7

_JSON_KEYS = {"schema_version", "command", "outcome", "exit_code", "data", "artifacts"}


def _write_campaign_with_unknown_stage(tmp_path: Path) -> Path:
    """Прогон с UNKNOWN-стадией (retrieval/tool success=None): JSON-контракт
    обязан отдать её как null, а НЕ привести к pass/fail."""
    from memnotsafe.core.models import AttackResult, StageResult
    from memnotsafe.reporting.metrics import aggregate_metrics

    result = {
        "case_id": "CASE-direct_poisoning-001-df4699",
        "attack_id": "direct_poisoning",
        "family": "direct_poisoning",
        "success": False,
        "stages": [
            {"stage": "write", "success": False, "reason": "нет", "evidence": []},
            {"stage": "persistence", "success": False, "reason": "нет", "evidence": []},
            {"stage": "retrieval", "success": None, "reason": "нет trace", "evidence": []},
            {"stage": "adoption", "success": False, "reason": "нет", "evidence": []},
            {"stage": "tool", "success": None, "reason": "не задействует", "evidence": []},
            {"stage": "external_effect", "success": False, "reason": "нет", "evidence": []},
        ],
        "attacker_user_id": "1003",
        "victim_user_id": "1003",
        "evidence": {"victim_response": "…"},
    }
    attack_result = AttackResult(
        run_id="RUN-TEST", case_id=result["case_id"], attack_id="direct_poisoning",
        scenario_id="direct_poisoning_smoke", family="direct_poisoning",
        stages=[StageResult(stage=s["stage"], success=s["success"], reason=s["reason"])
                for s in result["stages"]],
        success=False, metrics={}, evidence={}, attacker_user_id="1003", victim_user_id="1003",
    )
    campaign = {
        "run_id": "RUN-TEST", "scenario_id": "direct_poisoning_smoke", "attempts": 1,
        "metadata": {}, "aggregate_metrics": aggregate_metrics([attack_result]),
        "results": [result],
    }
    d = tmp_path / "run"
    d.mkdir(parents=True, exist_ok=True)
    (d / "campaign.json").write_text(json.dumps(campaign, ensure_ascii=False), encoding="utf-8")
    return d


def test_json_contract_keys_and_types(tmp_path, capsys) -> None:
    run = tmp_path / "run"
    assert cli.main(["run", "--scenario", _VULNERABLE, "--output", str(run), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert set(payload) == _JSON_KEYS
    assert isinstance(payload["schema_version"], int)
    assert isinstance(payload["command"], str)
    assert payload["outcome"] in {"success", "gate_failed", "error"}
    assert isinstance(payload["exit_code"], int)
    assert isinstance(payload["data"], dict)
    assert isinstance(payload["artifacts"], list) and all(isinstance(a, str) for a in payload["artifacts"])


def test_json_unknown_stage_is_null_never_coerced(tmp_path, capsys) -> None:
    d = _write_campaign_with_unknown_stage(tmp_path)
    rc = cli.main(["report", "--input", str(d), "--output", str(tmp_path / "rep"), "--json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    stages = payload["data"]["results"][0]["stages"]
    assert stages["retrieval"] is None  # UNKNOWN → null
    assert stages["tool"] is None
    assert payload["data"]["results"][0]["status"] == "NOT_EXPLOITABLE"


def test_json_beats_quiet_at_cli_level(tmp_path, capsys) -> None:
    rc = cli.main(["run", "--scenario", _VULNERABLE, "--output", str(tmp_path / "run"),
                   "--json", "--quiet"])
    assert rc == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)  # один объект, не пусто
    assert payload["command"] == "run"
    assert captured.err == ""


def test_json_contract_carries_no_secrets(tmp_path, capsys, monkeypatch) -> None:
    monkeypatch.setenv("ATTACKER_API_KEY", "sk-super-secret-value")
    rc = cli.main(["run", "--scenario", _VULNERABLE, "--output", str(tmp_path / "run"), "--json"])
    assert rc == 0
    captured = capsys.readouterr()
    assert "sk-super-secret-value" not in captured.out
    assert "sk-super-secret-value" not in captured.err
    payload = json.loads(captured.out)  # контракт при этом не сломан
    assert payload["command"] == "run"
