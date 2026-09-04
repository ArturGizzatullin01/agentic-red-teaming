"""memred/reporting/json_report.py — report.json + findings.json +
metrics.json: машиночитаемая часть отчёта."""

from __future__ import annotations

import json
from pathlib import Path

from memred.core.models import CampaignResult
from memred.reporting.findings import build_findings


def write_json_reports(campaign: CampaignResult, output_dir: Path) -> dict[str, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    findings = build_findings(campaign.results)

    findings_path = output_dir / "findings.json"
    findings_path.write_text(
        json.dumps([f.to_dict() for f in findings], ensure_ascii=False, indent=2), encoding="utf-8"
    )

    metrics_path = output_dir / "metrics.json"
    metrics_path.write_text(json.dumps(campaign.aggregate_metrics, ensure_ascii=False, indent=2), encoding="utf-8")

    report = {
        "run_id": campaign.run_id,
        "scenario_id": campaign.scenario_id,
        "attempts": campaign.attempts,
        "metrics": campaign.aggregate_metrics,
        "findings": [f.to_dict() for f in findings],
    }
    report_path = output_dir / "report.json"
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    return {"report": report_path, "findings": findings_path, "metrics": metrics_path}
