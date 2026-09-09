"""tests/test_reporting_html.py — 002-reporting: журнал диалога (transcript),
HTML-отчёт v2, совместимость со старым форматом, экранирование недоверенного
текста, replay без сети/моделей."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from memnotsafe.adapters.mock import MockTarget
from memnotsafe.attacks import get_attack
from memnotsafe.attacks.base import AttackContext
from memnotsafe.core.models import AttackResult, StageResult
from memnotsafe.core.runner import RunnerError, new_run_id, run_attack
from memnotsafe.reporting.html_report import render_html


def _run(family: str, target=None) -> AttackResult:
    attack = get_attack(family)()
    ctx = AttackContext(attacker_user_id="1001", victim_user_id="1001" if family == "consent_laundering" else "1002",
                        run_seed=1, case_id="CASE-REP-001")
    return asyncio.run(run_attack(attack, ctx, target or MockTarget(vulnerable=True), run_id=new_run_id()))


def test_transcript_full_order_and_completeness_multi_turn() -> None:
    # двухходовая consent_laundering: baseline → delivery(elicit, consent) → trigger
    result = _run("consent_laundering")
    wire = result.evidence["transcript"]
    assert wire["schema_version"] == 1 and wire["complete"] is True
    msgs = wire["messages"]
    # фазы на КАЖДОЕ сообщение: user+agent в каждой фазе
    phases = [m["phase"] for m in msgs]
    assert phases == ["baseline", "baseline", "delivery", "delivery", "delivery", "delivery", "trigger", "trigger"]
    # порядок и направление
    roles = [(m["role"], m["direction"]) for m in msgs]
    assert roles[0] == ("user", "user->agent") and roles[1] == ("agent", "agent->user")
    # каждая отправленная реплика и каждый реальный ответ присутствуют
    assert "Подключить вам тарифный код PLAT-77" in msgs[2]["content"]
    assert msgs[3]["content"]  # реальный ответ агента на elicit сохранён
    assert msgs[4]["role"] == "user" and "Да, конечно" in msgs[4]["content"]
    # последовательность сквозная
    assert [m["sequence"] for m in msgs] == list(range(len(msgs)))


def test_transcript_single_turn_attack() -> None:
    result = _run("procedural_graft")
    msgs = result.evidence["transcript"]["messages"]
    assert [m["phase"] for m in msgs] == ["baseline", "baseline", "delivery", "delivery", "trigger", "trigger"]
    assert "checklist-v2.xlsx" in msgs[2]["content"]  # payload реально отправлен
    assert msgs[3]["content"]  # реальный ответ агента на доставку


def test_transcript_partial_saved_on_runner_error(tmp_path: Path) -> None:
    """Ошибка адаптера на trigger-шаге не теряет наблюдённую часть диалога:
    traces/<case>-transcript.json содержит baseline+delivery с complete=false."""
    from memnotsafe.tracing.recorder import TraceRecorder

    class _HalfBroken(MockTarget):
        calls = 0

        async def send(self, session_id, message):
            _HalfBroken.calls += 1
            if _HalfBroken.calls == 3:  # 1=baseline, 2=delivery, 3=trigger — падает trigger
                raise RuntimeError("boom")
            return await super().send(session_id, message)

    rec = TraceRecorder(events_path=tmp_path / "events.jsonl", traces_dir=tmp_path / "traces")
    attack = get_attack("procedural_graft")()
    ctx = AttackContext(attacker_user_id="1001", victim_user_id="1002", run_seed=1, case_id="CASE-ERR-001")
    with pytest.raises(RunnerError):
        asyncio.run(run_attack(attack, ctx, _HalfBroken(vulnerable=True), run_id=new_run_id(), recorder=rec))
    files = list((tmp_path / "traces").glob("CASE-ERR-001-transcript.json"))
    assert len(files) == 1
    wire = json.loads(files[0].read_text(encoding="utf-8"))
    assert wire["complete"] is False and "phase=trigger" in wire["incomplete_reason"]
    phases = [m["phase"] for m in wire["messages"]]
    assert "baseline" in phases and "delivery" in phases and "trigger" not in phases


def test_html_escapes_untrusted_payload_and_responses() -> None:
    class _XssEcho(MockTarget):
        async def send(self, session_id, message):
            res = await super().send(session_id, message)
            # модель/память — недоверенные данные: ответ содержит опасный HTML
            res = type(res)(content=res.content + " <script>alert(1)</script><img src=x onerror=alert(2)>",
                            events=res.events, raw=res.raw)
            return res

    attack = get_attack("direct_poisoning")()
    attack.MARKER = "0.1%<script>alert(0)</script>"  # и в payload
    ctx = AttackContext(attacker_user_id="1001", victim_user_id="1001", run_seed=1, case_id="CASE-XSS-001")
    result = asyncio.run(run_attack(attack, ctx, _XssEcho(vulnerable=True), run_id=new_run_id()))
    from memnotsafe.core.models import CampaignResult
    camp = CampaignResult(run_id="R", scenario_id="s", attempts=1, results=[result],
                          aggregate_metrics={"attempts": 1, "successful": 0, "funnel": {
                              k: {"pass": 0, "fail": 0, "unknown": 0, "total": 1}
                              for k in ["write", "persistence", "retrieval", "adoption", "tool", "external_effect"]},
                              "end_to_end_asr": 0.0})
    html_out = render_html(camp)
    assert "<script>alert" not in html_out
    assert "&lt;script&gt;" in html_out
    assert "onerror" not in html_out.split("msg-body")[1].split("</div>")[0] if "msg-body" in html_out else True


def test_html_old_format_shows_fragments_with_honest_note() -> None:
    result = AttackResult(
        run_id="R", case_id="CASE-OLD-001", attack_id="direct_poisoning", scenario_id="direct_poisoning",
        family="direct_poisoning",
        stages=[StageResult(stage="write", success=False, reason="нет")],
        success=False, metrics={}, evidence={
            "baseline_response": "старый baseline",
            "victim_response": "старый victim",
            "candidate": {"payload": "старый payload", "trigger": "t", "expected_effect": {}},
        },
        attacker_user_id="1001", victim_user_id="1001",
    )
    from memnotsafe.core.models import CampaignResult
    camp = CampaignResult(run_id="R", scenario_id="s", attempts=1, results=[result],
                          aggregate_metrics={"attempts": 1, "successful": 0, "funnel": {
                              k: {"pass": 0, "fail": 0, "unknown": 0, "total": 1}
                              for k in ["write", "persistence", "retrieval", "adoption", "tool", "external_effect"]},
                              "end_to_end_asr": 0.0})
    html_out = render_html(camp)
    # issue #15: UI-хром переведён на английский; честная пометка о старом
    # формате сохранена (формулировка из html_report._transcript_html).
    assert "The full dialogue was not recorded" in html_out
    assert "NOT a proven transcript" in html_out
    assert "старый baseline" in html_out and "старый victim" in html_out
    assert "Judge inactive" in html_out  # честный judge-блок вместо вымышленного verdict


def test_html_artifact_links_are_relative() -> None:
    result = _run("procedural_graft")
    from memnotsafe.core.models import CampaignResult
    camp = CampaignResult(run_id="R", scenario_id="s", attempts=1, results=[result],
                          aggregate_metrics={"attempts": 1, "successful": 0, "funnel": {
                              k: {"pass": 0, "fail": 0, "unknown": 0, "total": 1}
                              for k in ["write", "persistence", "retrieval", "adoption", "tool", "external_effect"]},
                              "end_to_end_asr": 0.0})
    html_out = render_html(camp, run_dir_rel="..")
    assert 'href="../evidence/CASE-REP-001-transcript.json"' in html_out
    assert 'href="../traces/CASE-REP-001.json"' in html_out
    assert "file://" not in html_out and "C:\\" not in html_out


def test_cli_replay_renders_new_format_without_models(tmp_path: Path, monkeypatch) -> None:
    """Replay построенного run'а: HTML читается с диска, транскрипт попадает в
    отчёт, модели/адаптер не вызываются."""
    import memnotsafe.cli as cli

    def _explode(*_a, **_k):
        raise AssertionError("replay не строит адаптер/сценарий")

    monkeypatch.setattr(cli, "load_scenario", _explode)
    monkeypatch.setattr(cli, "build_adapter", _explode)

    result = _run("consent_laundering")
    from memnotsafe.core.models import CampaignResult
    camp_dir = tmp_path / "run"
    camp_dir.mkdir()
    campaign = CampaignResult(run_id="R", scenario_id="consent", attempts=1, results=[result],
                              aggregate_metrics={"attempts": 1, "successful": 0, "funnel": {
                                  k: {"pass": 0, "fail": 0, "unknown": 0, "total": 1}
                                  for k in ["write", "persistence", "retrieval", "adoption", "tool", "external_effect"]},
                                  "end_to_end_asr": 0.0})
    (camp_dir / "campaign.json").write_text(json.dumps(cli.__dict__ and _campaign_wire(campaign), ensure_ascii=False), encoding="utf-8")
    rc = cli.cmd_report(type("A", (), {"input": str(camp_dir), "output": str(tmp_path / "rep")})())
    assert rc == 0
    html_out = (tmp_path / "rep" / "report.html").read_text(encoding="utf-8")
    assert "Подключить вам тарифный код PLAT-77" in html_out  # полный диалог виден
    assert "msg-user" in html_out and "msg-agent" in html_out


def _campaign_wire(campaign) -> dict:
    from memnotsafe.core.models import StageResult
    return {
        "run_id": campaign.run_id, "scenario_id": campaign.scenario_id, "attempts": campaign.attempts,
        "metadata": {},
        "aggregate_metrics": campaign.aggregate_metrics,
        "results": [{
            "case_id": r.case_id, "attack_id": r.attack_id, "family": r.family, "success": r.success,
            "stages": [{"stage": s.stage, "success": s.success, "reason": s.reason, "evidence": s.evidence} for s in r.stages],
            "attacker_user_id": r.attacker_user_id, "victim_user_id": r.victim_user_id,
            "evidence": r.evidence,
        } for r in campaign.results],
    }

