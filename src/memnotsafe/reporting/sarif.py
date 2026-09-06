"""src/memnotsafe/reporting/sarif.py — минимальный экспорт находок в SARIF 2.1.0
(для импорта в ASOC/CI-платформы)."""

from __future__ import annotations

import json
from pathlib import Path

from memnotsafe.reporting.findings import Finding

_SEVERITY_TO_SARIF_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
}


def build_sarif(findings: list[Finding], *, tool_name: str = "memnotsafe") -> dict:
    rules = {}
    results = []
    for f in findings:
        if f.status != "SUCCESS":
            # Правило экспорта не меняется: в SARIF идут только подтверждённые
            # находки. INCONCLUSIVE, как и NOT_EXPLOITABLE, остаётся в findings.json.
            continue
        rules[f.family] = {
            "id": f.family,
            "name": f.title,
            "shortDescription": {"text": f.title},
            "properties": {"atlas_technique": f.atlas_technique, "owasp_asi": f.owasp_asi},
        }
        results.append(
            {
                "ruleId": f.family,
                "level": _SEVERITY_TO_SARIF_LEVEL.get(f.severity, "warning"),
                "message": {"text": f"{f.title} — {f.case_id} (attacker={f.attacker}, victim={f.victim})"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f"cases/{f.case_id}"},
                        }
                    }
                ],
                # Провенанс идёт и в машинный формат: потребитель SARIF обязан
                # видеть, чем держится находка, не открывая findings.json.
                "properties": {
                    "severity": f.severity,
                    "stages": f.stages,
                    "verdict_source": {k: v["verdict_source"] for k, v in f.stage_provenance.items()},
                    "llm_confirmed": f.llm_confirmed,
                    "confidence_tier": f.confidence_tier,
                    # Происхождение атаки и стоимость онлайн-адаптации (FR-013/FR-014):
                    # рукописный пак / корпус / онлайн, число попыток, исчерпание бюджета.
                    "attack_provenance": (f.evidence or {}).get("provenance", {}),
                },
            }
        )
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": tool_name, "informationUri": "https://github.com", "rules": list(rules.values())}},
                "results": results,
            }
        ],
    }


def write_sarif(findings: list[Finding], output_path: Path) -> Path:
    output_path.write_text(json.dumps(build_sarif(findings), ensure_ascii=False, indent=2), encoding="utf-8")
    return output_path
