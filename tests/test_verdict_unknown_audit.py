"""tests/test_verdict_unknown_audit.py — хвост W8: как отчёт показывает
НЕизмеренную попытку (characterization, код не меняется).

Попытка может завершиться с нерешёнными телеметрией стадиями (outcome unknown,
у стадий success=None — как L2 на стенде без trace-канала). Вопрос карточки B:
как такая попытка выглядит в отчёте. `build_finding` (reporting/findings.py)
знает три статуса: SUCCESS / INCONCLUSIVE (только «композитная стадия
нерешена ИМЕННО из-за недоступного судьи») / NOT_EXPLOITABLE (всё остальное).
Этот тест ФИКСИРУЕТ фактическое поведение как есть (characterization):
какой status/severity у unknown-попытки, что рисует HTML, попадает ли она в
SARIF, и различает ли отчёт «атака не пробилась» и «не измерили».
Ответ для владельца — в хендофе карточки; `reporting/` здесь не правится.
"""

from __future__ import annotations

import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from memnotsafe.core.models import AttackResult, CampaignResult, StageResult  # noqa: E402
from memnotsafe.reporting.findings import build_finding, build_findings  # noqa: E402
from memnotsafe.reporting.html_report import render_html  # noqa: E402
from memnotsafe.reporting.sarif import build_sarif  # noqa: E402

STAGES = ("write", "persistence", "retrieval", "adoption", "tool", "external_effect")

# unknown-профиль: запись решена телеметрией снимков, а retrieval/adoption/
# tool/external_effect нерешены (стенд без trace-канала — как боевой L2)
UNKNOWN_PROFILE = {
    "write": True, "persistence": True, "retrieval": None,
    "adoption": None, "tool": None, "external_effect": None,
}
# «честный негатив»: все решаемые стадии решены, эффекта нет (protected-профиль
# generic-семей из аудита карточки A)
RESOLVED_NEGATIVE_PROFILE = {
    "write": True, "persistence": True, "retrieval": True,
    "adoption": False, "tool": None, "external_effect": False,
}
SUCCESS_PROFILE = {s: True for s in STAGES}


def _result(profile: dict, case_id: str) -> AttackResult:
    stages = [StageResult(stage=s, success=v) for s, v in profile.items()]
    return AttackResult(
        run_id="RUN-B-AUDIT", case_id=case_id, attack_id=f"att-{case_id}",
        scenario_id="verdict-unknown-audit",
        stages=stages,
        # UNKNOWN не читается композитом как успех — как считает composite_success
        success=all(profile[s] is True for s in
                    ("write", "persistence", "retrieval", "adoption", "external_effect")),
        metrics={s: v for s, v in profile.items()},
        evidence={},
        attacker_user_id="1001", victim_user_id="1002",
        family="cross_user_bac",
    )


def _campaign(results: list[AttackResult]) -> CampaignResult:
    funnel = {}
    for stage in STAGES:
        vals = [r.metrics.get(stage) for r in results]
        funnel[stage] = {
            "pass": sum(v is True for v in vals),
            "fail": sum(v is False for v in vals),
            "unknown": sum(v is None for v in vals),
            "total": len(vals),
        }
    return CampaignResult(
        run_id="RUN-B-AUDIT", scenario_id="verdict-unknown-audit",
        attempts=len(results), results=results,
        aggregate_metrics={
            "attempts": len(results),
            "successful": sum(r.success for r in results),
            "end_to_end_asr": (sum(r.success for r in results) / len(results)) if results else 0.0,
            "funnel": funnel,
        },
    )


def test_unknown_attempt_finding_status_characterization() -> None:
    # characterization «как есть» на cc3c65a: попытка с нерешёнными стадиями
    # (судьи нет — ветка INCONCLUSIVE не задета) получает NOT_EXPLOITABLE/INFO
    finding = build_finding(_result(UNKNOWN_PROFILE, "CASE-B-UNKNOWN"))
    assert finding.status == "NOT_EXPLOITABLE"
    assert finding.severity == "INFO"
    assert finding.confidence_tier is None
    assert finding.llm_confirmed is False
    # и главный замок (PASS_IF-2): ложной тревоги нет — никогда не SUCCESS
    assert finding.status != "SUCCESS"


def test_report_does_not_distinguish_unmeasured_from_failed() -> None:
    # characterization: «не измерили» (стадии None) и «честно не пробилось»
    # (стадии решены, эффекта нет) в отчёте НЕРАЗЛИЧИМЫ — оба NOT_EXPLOITABLE/INFO.
    unknown = build_finding(_result(UNKNOWN_PROFILE, "CASE-B-UNKNOWN"))
    resolved = build_finding(_result(RESOLVED_NEGATIVE_PROFILE, "CASE-B-NEG"))
    assert unknown.status == resolved.status == "NOT_EXPLOITABLE"
    assert unknown.severity == resolved.severity == "INFO"
    # различимо только внутри пакета/стадий (stages-словарь finding'а), не статусом
    assert unknown.stages != resolved.stages


def test_unknown_attempt_in_html_and_json_pipeline() -> None:
    findings = build_findings([_result(UNKNOWN_PROFILE, "CASE-B-UNKNOWN")])
    html_text = render_html(_campaign([_result(UNKNOWN_PROFILE, "CASE-B-UNKNOWN")]))
    # HTML: машинный статус — data-status="NOT_EXPLOITABLE", человекочитаемая
    # строка — «NOT CONFIRMED» (та же, что у честного негатива)
    assert 'data-status="NOT_EXPLOITABLE"' in html_text
    assert "NOT CONFIRMED" in html_text
    assert "COMPROMISE CONFIRMED" not in html_text
    assert [f.status for f in findings] == ["NOT_EXPLOITABLE"]


def test_unknown_attempt_not_exported_to_sarif() -> None:
    # SARIF фильтрует по status != "SUCCESS": unknown-попытка НЕ экспортируется
    # (как и любой негатив); позитив-контроль ниже доказывает, что фильтр
    # работает выборочно, а не «всегда пусто»
    unknown = build_finding(_result(UNKNOWN_PROFILE, "CASE-B-UNKNOWN"))
    success = build_finding(_result(SUCCESS_PROFILE, "CASE-B-SUCCESS"))
    sarif_unknown = build_sarif([unknown])
    assert sarif_unknown["runs"][0]["results"] == []
    sarif_success = build_sarif([success])
    assert len(sarif_success["runs"][0]["results"]) == 1
