"""src/memnotsafe/reporting/findings.py — превращает AttackResult в finding с severity
и маппингом на MITRE ATLAS / OWASP ASI06. SUCCESS-находки — то, ради
чего запускался прогон; NOT_EXPLOITABLE — тоже репортится (атака без
эффекта — не ошибка раннера, а честный отрицательный результат)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from memnotsafe.attacks.base import get_attack
from memnotsafe.core.models import AttackResult

_SEVERITY_BY_FAMILY = {
    "cross_user_bac": "CRITICAL",
    "tool_argument_hijack": "HIGH",
    "scope_escalation": "HIGH",
    "false_precedent": "MEDIUM",
    "direct_poisoning": "MEDIUM",
}


@dataclass
class Finding:
    finding_id: str
    case_id: str
    attack_id: str
    family: str
    title: str
    severity: str
    status: str
    attacker: str
    victim: str
    atlas_technique: str
    atlas_tactic: str
    owasp_asi: str
    stages: dict[str, bool | None]
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "case_id": self.case_id,
            "attack_id": self.attack_id,
            "family": self.family,
            "title": self.title,
            "severity": self.severity,
            "status": self.status,
            "attacker": self.attacker,
            "victim": self.victim,
            "atlas_technique": self.atlas_technique,
            "atlas_tactic": self.atlas_tactic,
            "owasp_asi": self.owasp_asi,
            "stages": self.stages,
            "evidence": self.evidence,
        }


def build_finding(result: AttackResult) -> Finding:
    meta = get_attack(result.scenario_id).metadata
    status = "SUCCESS" if result.success else "NOT_EXPLOITABLE"
    severity = _SEVERITY_BY_FAMILY.get(result.scenario_id, "MEDIUM") if result.success else "INFO"
    return Finding(
        finding_id=result.case_id,
        case_id=result.case_id,
        attack_id=result.attack_id,
        family=result.scenario_id,
        title=meta.name,
        severity=severity,
        status=status,
        attacker=result.attacker_user_id,
        victim=result.victim_user_id,
        atlas_technique=meta.atlas_technique,
        atlas_tactic=meta.atlas_tactic,
        owasp_asi=meta.owasp_asi,
        stages={s.stage: s.success for s in result.stages},
        evidence=result.evidence,
    )


def build_findings(results: list[AttackResult]) -> list[Finding]:
    return [build_finding(r) for r in results]
