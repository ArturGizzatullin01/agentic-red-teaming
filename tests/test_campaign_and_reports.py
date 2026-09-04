"""tests/test_campaign_and_reports.py — Campaign + reporting layer (spec §18/§32):
проверяет, что после кампании реально появляются events.jsonl/report.json/
report.html/findings.json, а метрики/severity согласованы с результатами."""

from __future__ import annotations

import asyncio
import json

from memred.adapters.mock import MockTarget
from memred.core.campaign import Campaign
from memred.core.config import ActorConfig, Scenario, TargetSpec
from memred.reporting.findings import build_findings
from memred.reporting.html_report import write_html_report
from memred.reporting.json_report import write_json_reports
from memred.reporting.metrics import aggregate_metrics


def _scenario(tmp_path, family="cross_user_bac", attacker="1001", victim="1002", reps=3) -> Scenario:
    return Scenario(
        id=family,
        path=tmp_path / f"{family}.yaml",
        target=TargetSpec(adapter="mock"),
        attacker=ActorConfig(user_id=attacker),
        victim=ActorConfig(user_id=victim),
        attack_family=family,
        repetitions=reps,
    )


def test_campaign_writes_expected_artifacts(tmp_path):
    scenario = _scenario(tmp_path)
    target = MockTarget(vulnerable=True)
    campaign = Campaign(scenario, target, tmp_path / "run-out")

    result = asyncio.run(campaign.run())

    assert result.attempts == 3
    assert len(result.results) == 3
    assert all(r.success for r in result.results)

    out = tmp_path / "run-out"
    assert (out / "events.jsonl").exists()
    assert (out / "cases.jsonl").exists()
    assert (out / "campaign.json").exists()
    assert (out / "baseline.json").exists()
    assert len(list((out / "evidence").glob("*-diff.json"))) == 3
    assert len(list((out / "traces").glob("*.json"))) == 3


def test_metrics_and_findings_consistent(tmp_path):
    scenario = _scenario(tmp_path)
    target = MockTarget(vulnerable=True)
    campaign = Campaign(scenario, target, tmp_path / "run-out")
    result = asyncio.run(campaign.run())

    m = aggregate_metrics(result.results)
    assert m["attempts"] == 3
    assert m["write_rate"] == 1.0
    assert m["end_to_end_asr"] == 1.0

    findings = build_findings(result.results)
    assert len(findings) == 3
    assert all(f.status == "SUCCESS" for f in findings)
    assert all(f.severity == "CRITICAL" for f in findings)  # cross_user_bac -> CRITICAL

    report_dir = tmp_path / "reports"
    written = write_json_reports(result, report_dir)
    assert written["report"].exists()
    assert json.loads(written["findings"].read_text())[0]["status"] == "SUCCESS"

    html_path = write_html_report(result, report_dir / "report.html")
    html = html_path.read_text(encoding="utf-8")
    assert "CRITICAL" in html
    assert "SUCCESS" in html


def test_protected_scenario_gives_not_exploitable_findings(tmp_path):
    scenario = _scenario(tmp_path, reps=2)
    target = MockTarget(vulnerable=False)
    campaign = Campaign(scenario, target, tmp_path / "run-out")
    result = asyncio.run(campaign.run())

    assert all(r.success is False for r in result.results)
    findings = build_findings(result.results)
    assert all(f.status == "NOT_EXPLOITABLE" for f in findings)
    assert all(f.severity == "INFO" for f in findings)
