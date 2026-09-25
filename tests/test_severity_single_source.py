"""tests/test_severity_single_source.py — FIX-B: единый источник severity.

Дефект (перепроверен): `reporting.findings` держал собственную таблицу
`_SEVERITY_BY_FAMILY` на 4 семьи, а остальные 18 молча падали в MEDIUM (`.get(f,
"MEDIUM")`) и так уходили в SARIF/JSON — в расхождении с каноном эталона
(`threat_report.IMPACT_SEVERITY` по `FAMILY_PLAYBOOK[family].impact`). Одна и та
же находка выходила CRITICAL/HIGH в threat-report, но MEDIUM в SARIF (напр.
global_policy_injection, tool_route_hijack).

Замки:
  * СВЕРКА: severity КАЖДОЙ находки == канон эталона для её семьи — доказывает,
    что findings не держит отдельной таблицы. На базе расходятся ровно
    tool_route_hijack и global_policy_injection (MEDIUM в findings vs HIGH/CRITICAL
    в каноне) → RED;
  * tool_route_hijack SUCCESS → SARIF level=error, severity=HIGH (был warning/MEDIUM);
  * cross-user SUCCESS → CRITICAL и в findings, и в SARIF (регресс-замок обоих выходов);
  * семья, зарегистрированная в движке, но без канонической записи в
    FAMILY_PLAYBOOK → severity UNRATED (SARIF level=note), НЕ молчаливый MEDIUM.

Канон в тесте берётся из `threat_report.IMPACT_SEVERITY/FAMILY_PLAYBOOK`: они
есть и на базе (определены в модуле), и после (реэкспорт из severity_map),
поэтому сверка версионно-устойчива и краснеет ПО СУТИ (расхождение таблиц), а не
из-за отсутствия нового модуля. Офлайн: без сети/Mongo/ключей.
"""

from __future__ import annotations

import pytest

from memnotsafe.attacks.base import ATTACK_REGISTRY
from memnotsafe.core.models import (
    EVIDENCE_KIND_MEMORY_SNAPSHOT,
    EVIDENCE_KIND_TELEMETRY,
    AttackResult,
    StageResult,
)
from memnotsafe.reporting import threat_report as tr
from memnotsafe.reporting.findings import build_finding
from memnotsafe.reporting.sarif import build_sarif


def _canonical_family_severity(family: str) -> str | None:
    """Канон эталона версионно-устойчиво — только таблицы (есть на базе и после)."""
    entry = tr.FAMILY_PLAYBOOK.get(family)
    if entry is None:
        return None
    rated = tr.IMPACT_SEVERITY.get(entry.get("impact"))
    return rated[0] if rated else None


def _stage(stage: str, success, kind: str) -> StageResult:
    return StageResult(stage=stage, success=success, evidence_kind=kind,
                       verdict_source="deterministic", reason="x")


def _hard_success_result(family: str) -> AttackResult:
    """Композитный успех на ЖЁСТКОМ доказательстве (снимок/телеметрия → FIX-A не
    понижает), без судьи. severity зависит только от семьи, не от evidence."""
    stages = [
        _stage("write", True, EVIDENCE_KIND_MEMORY_SNAPSHOT),
        _stage("persistence", True, EVIDENCE_KIND_MEMORY_SNAPSHOT),
        _stage("retrieval", None, EVIDENCE_KIND_MEMORY_SNAPSHOT),
        _stage("adoption", True, EVIDENCE_KIND_TELEMETRY),
        _stage("tool", True, EVIDENCE_KIND_TELEMETRY),
        _stage("external_effect", True, EVIDENCE_KIND_MEMORY_SNAPSHOT),
    ]
    return AttackResult(
        run_id="R", case_id=f"CASE-{family}", attack_id=family, scenario_id="s",
        family=family, stages=stages, success=True, metrics={}, evidence={},
        attacker_user_id="1001", victim_user_id="1002",
    )


def _sarif_result_for(findings, rule_id):
    sarif = build_sarif(findings)
    hits = [r for r in sarif["runs"][0]["results"] if r["ruleId"] == rule_id]
    assert hits, f"нет находки {rule_id} в SARIF"
    return hits[0]


@pytest.mark.parametrize("family", sorted(ATTACK_REGISTRY))
def test_finding_severity_equals_canonical_for_every_family(family: str) -> None:
    """findings НЕ держит своей таблицы: severity находки == канон эталона для её
    семьи. RED на базе для tool_route_hijack (HIGH) и global_policy_injection
    (CRITICAL), которые findings молча ставил MEDIUM."""
    f = build_finding(_hard_success_result(family))
    assert f.status == "SUCCESS", (family, f.status)  # жёсткая фикстура → SUCCESS
    assert f.severity == _canonical_family_severity(family), (
        f"{family}: findings severity={f.severity!r} != канон эталона "
        f"{_canonical_family_severity(family)!r} — таблицы расходятся"
    )


def test_tool_route_hijack_is_high_in_sarif() -> None:
    """Карта: tool_route_hijack SUCCESS → SARIF level=error, severity=HIGH
    (на базе был warning/MEDIUM)."""
    f = build_finding(_hard_success_result("tool_route_hijack"))
    assert f.severity == "HIGH"
    res = _sarif_result_for([f], "tool_route_hijack")
    assert res["level"] == "error"
    assert res["properties"]["severity"] == "HIGH"


def test_cross_user_is_critical_in_both_outputs() -> None:
    """Карта (регресс обоих выходов): cross-user SUCCESS → CRITICAL и в findings,
    и в SARIF."""
    f = build_finding(_hard_success_result("cross_user_bac"))
    assert f.severity == "CRITICAL"
    res = _sarif_result_for([f], "cross_user_bac")
    assert res["level"] == "error"
    assert res["properties"]["severity"] == "CRITICAL"


def test_unknown_family_is_unrated_not_medium(monkeypatch) -> None:
    """Семья в реестре движка, но без канонической записи в FAMILY_PLAYBOOK →
    severity UNRATED (SARIF level=note) с названной причиной, НЕ молчаливый
    MEDIUM. Моделируем удалением записи из канона (severity_map)."""
    from memnotsafe.reporting import severity_map

    victim = "direct_poisoning"  # есть и в реестре, и в playbook
    assert victim in ATTACK_REGISTRY
    monkeypatch.delitem(severity_map.FAMILY_PLAYBOOK, victim)

    f = build_finding(_hard_success_result(victim))
    assert f.status == "SUCCESS"
    assert f.severity == severity_map.UNRATED, f.severity
    assert getattr(f, "status_reason", None), "причина «severity не оценена» не названа"
    res = _sarif_result_for([f], victim)
    assert res["level"] == "note"
    assert res["properties"]["severity"] == severity_map.UNRATED
