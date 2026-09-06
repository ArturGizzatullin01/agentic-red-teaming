"""tests/test_judge_offline_regression.py — офлайн-регрессия и round-trip
провенанса (FR-011, SC-003, T029/T040).

Два независимых требования в одном файле, потому что оба про одно свойство:
отчёт обязан пережить сохранение и пересборку без потерь, а выключенный судья
обязан быть неотличим от прогона до появления фичи.
"""

from __future__ import annotations

import asyncio
import json

import memnotsafe.cli as cli
from memnotsafe.adapters.mock import MockTarget
from memnotsafe.core.campaign import Campaign
from memnotsafe.core.config import ActorConfig, JudgeSpec, Scenario, TargetSpec
from memnotsafe.core.models import JudgeVerdict
from memnotsafe.judge.client import JudgeCallResult
from memnotsafe.judge.runtime import LLMJudge


def _scenario(tmp_path, family="cross_user_bac", attacker="1001", victim="1002", reps=2, judge=None) -> Scenario:
    return Scenario(
        id=family,
        path=tmp_path / f"{family}.yaml",
        target=TargetSpec(adapter="mock"),
        attacker=ActorConfig(user_id=attacker),
        victim=ActorConfig(user_id=victim),
        attack_family=family,
        repetitions=reps,
        judge=judge or JudgeSpec(),
    )


class StubClient:
    """Судья, который всегда подтверждает и всегда цитирует дословно."""

    async def complete(self, system: str, user: str) -> JudgeCallResult:
        inside = user.split(">>>\n", 1)[1].split("\n<<<END", 1)[0]
        body = {
            "outcome": "confirmed",
            "confidence": 0.83,
            "rationale": "ответ отражает отравленный факт",
            "quote": inside[:40] or "пусто",
        }
        return JudgeCallResult(ok=True, content=json.dumps(body, ensure_ascii=False), status=200, raw={"stub": True})

    async def aclose(self) -> None:
        return None


class UnavailableClient:
    async def complete(self, system: str, user: str) -> JudgeCallResult:
        return JudgeCallResult(ok=False, error="timeout")

    async def aclose(self) -> None:
        return None


# ------------------------------------------------- SC-003: судья выключен


def test_judge_off_run_needs_no_network_and_no_keys(tmp_path, monkeypatch):
    """Ни одной переменной окружения провайдера — прогон обязан пройти."""
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    scenario = _scenario(tmp_path)
    campaign = Campaign(scenario, MockTarget(vulnerable=True), tmp_path / "run")
    assert campaign.judge is None

    result = asyncio.run(campaign.run())
    assert all(r.success for r in result.results)


def test_judge_off_leaves_stages_provenance_free(tmp_path):
    scenario = _scenario(tmp_path)
    result = asyncio.run(Campaign(scenario, MockTarget(vulnerable=True), tmp_path / "run").run())

    for r in result.results:
        for s in r.stages:
            assert s.verdict_source == "deterministic"
            assert s.judge is None
            assert s.deterministic is None
            assert s.disagreement is False


def test_judge_off_writes_exactly_active_false_and_no_judge_dir(tmp_path):
    scenario = _scenario(tmp_path)
    out = tmp_path / "run"
    asyncio.run(Campaign(scenario, MockTarget(vulnerable=True), out).run())

    meta = json.loads((out / "campaign.json").read_text(encoding="utf-8"))["metadata"]
    assert meta["judge"] == {"active": False}  # РОВНО это, без модели и рубрик (FR-013)
    assert not (out / "judge").exists()

    stages = json.loads((out / "campaign.json").read_text(encoding="utf-8"))["results"][0]["stages"]
    assert all(s.get("judge") is None for s in stages)
    assert all(s.get("deterministic") is None for s in stages)


def test_judge_off_verdicts_match_the_baseline_battery(tmp_path):
    """SC-003 по существу: те же вердикты стадий и тот же композит, что даёт
    прогон без всякого судьи, на всех пяти семействах атак."""
    families = [
        ("direct_poisoning", "1001", "1001"),
        ("false_precedent", "1001", "1001"),
        ("scope_escalation", "1001", "1002"),
        ("cross_user_bac", "1001", "1002"),
        ("tool_argument_hijack", "1001", "1001"),
    ]
    for family, attacker, victim in families:
        scenario = _scenario(tmp_path, family=family, attacker=attacker, victim=victim, reps=1)
        res = asyncio.run(Campaign(scenario, MockTarget(vulnerable=True), tmp_path / f"run-{family}").run())
        r = res.results[0]
        assert r.success is True, family
        assert all(s.verdict_source == "deterministic" for s in r.stages), family


# ----------------------------------------- FR-011: round-trip провенанса


def _run_with_judge(tmp_path, client=None, family="cross_user_bac", attacker="1001", victim="1002"):
    scenario = _scenario(
        tmp_path, family=family, attacker=attacker, victim=victim,
        judge=JudgeSpec(enabled=True, model="stub-judge", min_confidence=0.7),
    )
    out = tmp_path / "run"
    judge = LLMJudge(scenario.judge, client=client or StubClient(), repetitions=2, artifacts_dir=out / "judge")
    result = asyncio.run(Campaign(scenario, MockTarget(vulnerable=True), out, judge=judge).run())
    return result, out


def test_judged_run_serializes_full_stage_provenance(tmp_path):
    _result, out = _run_with_judge(tmp_path)
    raw = json.loads((out / "campaign.json").read_text(encoding="utf-8"))

    judged = [s for s in raw["results"][0]["stages"] if s["stage"] in ("retrieval", "adoption", "external_effect")]
    assert judged
    for s in judged:
        assert s["verdict_source"] in ("deterministic", "judge")
        assert s["evidence_kind"]
        assert s["judge"]["outcome"] == "confirmed"
        assert s["judge"]["model"] == "stub-judge"
        assert s["judge"]["rubric"].endswith("@1")
        assert s["judge"]["artifact_ref"].startswith("judge/")
        assert s["deterministic"] is not None

    for s in raw["results"][0]["stages"]:
        if s["stage"] in ("write", "persistence", "tool"):
            assert s.get("judge") is None  # FR-014


def test_report_rebuild_is_identical_in_provenance(tmp_path, capsys):
    """Пересобранный `memnotsafe report` отчёт обязан совпасть с исходным по
    verdict_source, evidence_kind, судейскому вердикту и disagreement."""
    from memnotsafe.reporting.findings import build_findings

    result, out = _run_with_judge(tmp_path)
    original = json.loads((out / "campaign.json").read_text(encoding="utf-8"))
    original_findings = [f.to_dict() for f in build_findings(result.results)]

    rebuilt_dir = tmp_path / "rebuilt"
    code = cli.main(["report", "--input", str(out), "--output", str(rebuilt_dir)])
    capsys.readouterr()
    assert code == 0

    rebuilt_findings = json.loads((rebuilt_dir / "findings.json").read_text(encoding="utf-8"))

    def provenance(findings):
        return [(f["case_id"], f["status"], f["llm_confirmed"], f["confidence_tier"], f["stage_provenance"])
                for f in findings]

    assert provenance(rebuilt_findings) == provenance(original_findings)

    for case in original["results"]:
        for s in case["stages"]:
            assert s["verdict_source"] in ("deterministic", "judge")


def test_rebuilt_stage_objects_keep_judge_verdicts(tmp_path, capsys):
    _result, out = _run_with_judge(tmp_path)
    rebuilt = cli.load_campaign(out)
    capsys.readouterr()

    stage = next(s for s in rebuilt.results[0].stages if s.stage == "adoption")
    assert isinstance(stage.judge, JudgeVerdict)
    assert stage.judge.outcome == "confirmed"
    assert stage.judge.quote
    assert stage.deterministic is not None
    assert stage.evidence_kind
    assert stage.verdict_source in ("deterministic", "judge")


def test_judged_run_writes_call_artifacts(tmp_path):
    """SC-007: вердикт перепроверяется по сохранённому артефакту без повторного
    прогона атаки — вход, сырой ответ и попытки на месте."""
    _result, out = _run_with_judge(tmp_path)
    artifacts = sorted((out / "judge").glob("*.json"))
    assert artifacts

    payload = json.loads(artifacts[0].read_text(encoding="utf-8"))
    assert payload["request"]["system"]
    assert "<<<ARTIFACT-" in payload["request"]["user"]
    assert payload["attempts"]
    assert payload["raw_response"] is not None
    assert payload["verdict"]["outcome"]
    assert "Authorization" not in json.dumps(payload)  # секретов в артефакте нет
