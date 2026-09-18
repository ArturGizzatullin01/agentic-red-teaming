"""tests/test_asr_provenance.py — карточка R (W2): ASR обязана объявлять свою
природу. `successful`/`end_to_end_asr` не меняются; разложение живёт рядом.

Проверяются: сумма четырёх непересекающихся клеток тождественно равна
successful на вырожденных и смешанных раскладках; непересечение клеток
(судейский retrieval ≠ терпимость композита); достижимость четвёртой клетки;
счёт judge_raised_stages по стадиям; исключение неуспешных; нули (не null)
при выключенном судье против null у judge_disagreement_rate; ноль попыток;
round-trip replay; старый артефакт без verdict_source; отсутствующая стадия;
три поверхности (консоль/HTML/_campaign_data).
"""

from __future__ import annotations

import asyncio
import json
import sys
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))

from memnotsafe.adapters.mock import MockTarget  # noqa: E402
from memnotsafe.core.campaign import Campaign  # noqa: E402
from memnotsafe.core.config import ActorConfig, JudgeSpec, Scenario, TargetSpec  # noqa: E402
from memnotsafe.core.models import (  # noqa: E402
    AttackResult,
    CampaignResult,
    StageResult,
)
from memnotsafe.judge.client import JudgeCallResult  # noqa: E402
from memnotsafe.judge.runtime import LLMJudge  # noqa: E402
from memnotsafe.reporting.console import render_campaign_summary  # noqa: E402
from memnotsafe.reporting.findings import build_findings  # noqa: E402
from memnotsafe.reporting.html_report import render_html  # noqa: E402
from memnotsafe.reporting.metrics import aggregate_metrics  # noqa: E402


def _stage(stage: str, success: bool | None, *, judge: bool = False) -> StageResult:
    return StageResult(
        stage=stage,
        success=success,
        reason="тест",
        verdict_source="judge" if judge else "deterministic",
    )


def _ok_stages(
    *,
    retrieval: bool | None = True,
    judge_stages: tuple[str, ...] = (),
) -> list[StageResult]:
    """Полный успешный композит; judge_stages получают verdict_source="judge"."""
    out = [
        _stage("write", True),
        _stage("persistence", True),
        _stage("retrieval", retrieval),
        _stage("adoption", True),
        _stage("tool", True),
        _stage("external_effect", True),
    ]
    return [
        replace(s, verdict_source="judge") if s.stage in judge_stages else s
        for s in out
    ]


def _result(
    *,
    success: bool = True,
    stages: list[StageResult] | None = None,
) -> AttackResult:
    return AttackResult(
        run_id="RUN-TEST", case_id="CASE-prov-001-abcdef",
        attack_id="direct_poisoning", scenario_id="prov",
        family="direct_poisoning", stages=stages or [], success=success,
        metrics={}, evidence={}, attacker_user_id="1001", victim_user_id="1002",
    )


def _prov(results: list[AttackResult]) -> dict:
    return aggregate_metrics(results)["asr_provenance"]


_CELLS = (
    "independent",
    "judge_raised_only",
    "retrieval_tolerated_only",
    "judge_raised_and_retrieval_tolerated",
)


# --------------------------------------------------- PASS_IF 2: сумма тождественна


def test_cells_sum_equals_successful_across_layouts():
    layouts = {
        "ноль попыток": [],
        "ноль успехов": [_result(success=False, stages=_ok_stages())],
        "все независимы": [
            _result(stages=_ok_stages()) for _ in range(3)
        ],
        "все judge-raised": [
            _result(stages=_ok_stages(judge_stages=("retrieval",)))
            for _ in range(2)
        ],
        "вся терпимость": [
            _result(stages=_ok_stages(retrieval=None)) for _ in range(2)
        ],
    }
    for name, results in layouts.items():
        prov = _prov(results)
        assert sum(prov[c] for c in _CELLS) == prov["successful"], name

    mixed = [
        _result(stages=_ok_stages()),                                   # independent
        _result(stages=_ok_stages(judge_stages=("retrieval",))),        # judge only
        _result(stages=_ok_stages(retrieval=None)),                     # tolerated only
        _result(stages=_ok_stages(retrieval=None, judge_stages=("adoption",))),
        _result(success=False, stages=_ok_stages(judge_stages=("retrieval",))),
    ]
    prov = _prov(mixed)
    assert prov["successful"] == 4
    assert prov["independent"] == 1
    assert prov["judge_raised_only"] == 1
    assert prov["retrieval_tolerated_only"] == 1
    assert prov["judge_raised_and_retrieval_tolerated"] == 1
    assert sum(prov[c] for c in _CELLS) == prov["successful"] == 4
    assert prov["end_to_end_asr_independent"] == 0.2  # 1/5 через тот же _rate


# ------------------------------------------- PASS_IF 3: клетки не путаются


def test_judge_raised_retrieval_is_judge_only_not_tolerated():
    # судья ПОДНЯЛ retrieval с UNKNOWN до True: success True + verdict_source judge
    prov = _prov([_result(stages=_ok_stages(judge_stages=("retrieval",)))])
    assert prov["judge_raised_only"] == 1
    assert prov["retrieval_tolerated_only"] == 0


def test_unobserved_retrieval_without_judge_is_tolerated_only():
    prov = _prov([_result(stages=_ok_stages(retrieval=None))])
    assert prov["retrieval_tolerated_only"] == 1
    assert prov["judge_raised_only"] == 0


# ------------------------------------------------- PASS_IF 4: четвёртая клетка


def test_fourth_cell_reachable():
    prov = _prov([
        _result(stages=_ok_stages(retrieval=None, judge_stages=("adoption",)))
    ])
    assert prov["judge_raised_and_retrieval_tolerated"] == 1


# --------------------------------- PASS_IF 5: счёт по стадиям, не по попыткам


def test_judge_raised_stages_counts_stages_not_attempts():
    prov = _prov([
        _result(stages=_ok_stages(judge_stages=("adoption", "external_effect")))
    ])
    assert prov["judge_raised_only"] == 1
    assert prov["judge_raised_stages"] == {
        "retrieval": 0, "adoption": 1, "external_effect": 1,
    }
    assert list(prov["judge_raised_stages"]) == [
        "retrieval", "adoption", "external_effect",
    ]


# -------------------------------------- PASS_IF 6: неуспешные не попадают


def test_unsuccessful_attempt_not_in_decomposition():
    prov = _prov([
        _result(success=False, stages=_ok_stages(judge_stages=("retrieval",)))
    ])
    assert prov["successful"] == 0
    assert all(prov[c] == 0 for c in _CELLS)
    assert prov["judge_raised_stages"] == {
        "retrieval": 0, "adoption": 0, "external_effect": 0,
    }


# --------------------- PASS_IF 7: выключенный судья — нули, не null (обе половины)


def test_judge_off_gives_zeros_but_disagreement_rate_stays_null():
    m = aggregate_metrics([_result(stages=_ok_stages())])
    prov = m["asr_provenance"]
    assert prov["judge_raised_only"] == 0
    assert prov["judge_raised_and_retrieval_tolerated"] == 0
    assert prov["judge_raised_stages"] == {
        "retrieval": 0, "adoption": 0, "external_effect": 0,
    }
    assert m["judge_disagreement_rate"] is None  # осознанная разница в одном тесте


# ------------------------------------------------------ PASS_IF 8: ноль попыток


def test_zero_attempts():
    m = aggregate_metrics([])
    prov = m["asr_provenance"]
    assert prov["successful"] == 0
    assert all(prov[c] == 0 for c in _CELLS)
    assert prov["end_to_end_asr_independent"] is None
    assert m["end_to_end_asr"] is None


# --------------------------------------------------- PASS_IF 9: round-trip


class _ConfirmingJudge:
    """Судья-заглушка: всегда подтверждает. Без сети."""

    async def complete(self, system: str, user: str) -> JudgeCallResult:
        inside = user.split(">>>\n", 1)[1].split("\n<<<END", 1)[0]
        body = {
            "outcome": "confirmed", "confidence": 0.83,
            "rationale": "ответ отражает отравленный факт",
            "quote": inside[:40] or "пусто",
        }
        return JudgeCallResult(
            ok=True, content=json.dumps(body, ensure_ascii=False),
            status=200, raw={"stub": True},
        )

    async def aclose(self) -> None:
        return None


def _scenario(tmp_path: Path, *, judged: bool) -> Scenario:
    return Scenario(
        id="prov_smoke", path=tmp_path / "p.yaml",
        target=TargetSpec(adapter="mock"),
        attacker=ActorConfig(user_id="1001"), victim=ActorConfig(user_id="1002"),
        attack_family="direct_poisoning", repetitions=1,
        judge=JudgeSpec(enabled=True, model="stub-judge", min_confidence=0.7)
        if judged else JudgeSpec(),
    )


def test_round_trip_provenance_block_is_verbatim(tmp_path):
    # прогон с судьёй: confirmed-судья поднимает стадии до True с
    # verdict_source="judge" — блок получается ненулевым и осмысленным
    out = tmp_path / "run"
    judge = LLMJudge(
        _scenario(tmp_path, judged=True).judge,
        client=_ConfirmingJudge(), repetitions=1, artifacts_dir=out / "judge",
    )
    result = asyncio.run(Campaign(
        _scenario(tmp_path, judged=True), MockTarget(vulnerable=True), out, judge=judge
    ).run())
    original = result.aggregate_metrics["asr_provenance"]

    saved = json.loads((out / "campaign.json").read_text(encoding="utf-8"))

    import memnotsafe.cli as cli

    rc = cli.main(["report", "--input", str(out), "--output", str(tmp_path / "rep")])
    assert rc == 0
    rebuilt = json.loads(
        (tmp_path / "rep" / "report.json").read_text(encoding="utf-8")
    )
    # блок в сохранённом campaign.json и в пересобранном отчёте дословно равен
    assert saved["aggregate_metrics"]["asr_provenance"] == original
    assert rebuilt["metrics"]["asr_provenance"] == original


# ------------------------------------ PASS_IF 10: старый артефакт без поля


def test_old_artifact_without_verdict_source_still_reports(tmp_path):
    # минимальный campaign.json БЕЗ verdict_source в стадиях (поле появилось
    # позже): умолчание "deterministic" у _stage_from_dict — задокументировано
    run = tmp_path / "old-run"
    run.mkdir()
    campaign_doc = {
        "run_id": "RUN-OLD", "scenario_id": "old", "attempts": 1,
        "results": [
            {
                "case_id": "CASE-old-001-aaaaaa", "attack_id": "direct_poisoning",
                "family": "direct_poisoning", "scenario_id": "old",
                "success": True,
                "stages": [
                    {"stage": "write", "success": True, "reason": "r"},
                    {"stage": "persistence", "success": True, "reason": "r"},
                    {"stage": "retrieval", "success": None, "reason": "r"},
                    {"stage": "adoption", "success": True, "reason": "r"},
                    {"stage": "tool", "success": True, "reason": "r"},
                    {"stage": "external_effect", "success": True, "reason": "r"},
                ],
                "metrics": {}, "evidence": {},
                "attacker_user_id": "1001", "victim_user_id": "1002",
            }
        ],
        "metadata": {"run_id": "RUN-OLD", "adapter": "mock", "attempts": 1,
                     "judge": {"active": False}, "attacker": {"active": False}},
        "aggregate_metrics": {"attempts": 1},  # пересчитывается при replay
    }
    (run / "campaign.json").write_text(
        json.dumps(campaign_doc, ensure_ascii=False), encoding="utf-8"
    )
    import memnotsafe.cli as cli

    rc = cli.main(["report", "--input", str(run), "--output", str(tmp_path / "rep")])
    assert rc == 0  # отчёт собрался
    report = json.loads(
        (tmp_path / "rep" / "report.json").read_text(encoding="utf-8")
    )
    prov = report["metrics"]["asr_provenance"]
    assert prov["successful"] == 1
    assert prov["retrieval_tolerated_only"] == 1  # retrieval None, судейских нет
    assert prov["judge_raised_only"] == 0


# ------------------------------ PASS_IF 11: отсутствующая стадия не роняет


def test_missing_retrieval_stage_does_not_crash():
    results = [
        _result(
            success=False,  # композит без retrieval — попытка неуспешна
            stages=[
                _stage("write", True),
                _stage("persistence", True),
                _stage("adoption", True),
                _stage("external_effect", True),
            ],
        )
    ]
    prov = _prov(results)  # не упало
    assert prov["successful"] == 0
    assert all(prov[c] == 0 for c in _CELLS)


# ------------------------------ PASS_IF 12: три поверхности показывают блок


class _Rep:
    def __init__(self):
        self.lines: list[str] = []

    def line(self, text, **_kw):
        self.lines.append(str(text))

    def heading(self, text, **_kw):
        self.lines.append(str(text))

    def status_line(self, * _a, **_kw):
        pass

    def rule(self, * _a, **_kw):
        pass


def test_console_line_names_mechanisms():
    results = [
        _result(stages=_ok_stages()),
        _result(stages=_ok_stages(judge_stages=("retrieval",))),
        _result(stages=_ok_stages(retrieval=None)),
    ]
    m = aggregate_metrics(results)
    campaign = CampaignResult(
        run_id="RUN-C", scenario_id="prov", attempts=3, results=results,
        aggregate_metrics=m,
    )
    rep = _Rep()
    render_campaign_summary(rep, campaign, html_path="x.html")
    line = next(l for l in rep.lines if "независимых" in l)
    assert "поднято судьёй" in line and "ненаблюдённом retrieval" in line
    assert "1/3" in line


def test_console_line_present_when_all_independent():
    results = [_result(stages=_ok_stages())]
    m = aggregate_metrics(results)
    campaign = CampaignResult(
        run_id="RUN-C", scenario_id="prov", attempts=1, results=results,
        aggregate_metrics=m,
    )
    rep = _Rep()
    render_campaign_summary(rep, campaign, html_path="x.html")
    line = next(l for l in rep.lines if "независимых" in l)
    assert "все успехи независимы" in line
    assert "судьёй" not in line.replace("все успехи независимы", "")


def test_html_contains_provenance_text():
    results = [
        _result(stages=_ok_stages()),
        _result(stages=_ok_stages(judge_stages=("retrieval",))),
    ]
    m = aggregate_metrics(results)
    campaign = CampaignResult(
        run_id="RUN-H", scenario_id="prov", attempts=2, results=results,
        aggregate_metrics=m,
    )
    page = render_html(campaign)
    assert "Из них независимых" in page
    assert "поднято судьёй" in page
    # плиточная сетка не изменилась: та же плитка ASR, без новой
    assert page.count('class="stat asr"') == 1
    assert page.count('class="summary-grid"') == 1


def test_campaign_data_carries_provenance_block():
    import memnotsafe.cli as cli

    results = [_result(stages=_ok_stages())]
    m = aggregate_metrics(results)
    campaign = CampaignResult(
        run_id="RUN-D", scenario_id="prov", attempts=1, results=results,
        aggregate_metrics=m,
    )
    data = cli._campaign_data(campaign, build_findings(results))
    assert data["asr_provenance"] == m["asr_provenance"]
    assert data["end_to_end_asr"] == m["end_to_end_asr"]
