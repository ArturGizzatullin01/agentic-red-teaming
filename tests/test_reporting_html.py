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


# ------------------------------- FIX-10 (E1/H3): фактический Judge provenance
#
# HTML писал «Judge inactive» безусловно — даже когда судья реально выносил
# вердикты. Ниже проверяется то, что требует contracts/report-provenance.md,
# раздел `report.html`: источник стадии, модель, рубрика, уверенность, цитата,
# оба вердикта при расхождении, и честное различие «судьи не было» / «судья был
# недоступен». Все вердикты собираются в памяти: сети и моделей здесь нет.

_FUNNEL_STAGES = ["write", "persistence", "retrieval", "adoption", "tool", "external_effect"]


def _metrics(judge: dict | None = None, disagreement_rate: float | None = None,
             attempts: int = 1, successful: int = 0) -> dict:
    return {
        "attempts": attempts,
        "successful": successful,
        "funnel": {k: {"pass": 0, "fail": 0, "unknown": 0, "total": attempts} for k in _FUNNEL_STAGES},
        "end_to_end_asr": 0.0,
        "judge": {"active": False} if judge is None else judge,
        "judge_disagreement_rate": disagreement_rate,
    }


def _case(stages: list[StageResult], *, case_id: str = "CASE-JUDGE-001", success: bool = False,
          family: str = "direct_poisoning") -> AttackResult:
    return AttackResult(
        run_id="R", case_id=case_id, attack_id=family, scenario_id=family, family=family,
        stages=stages, success=success, metrics={},
        evidence={"candidate": {"payload": "p", "trigger": "t", "expected_effect": {}}},
        attacker_user_id="1001", victim_user_id="1001",
    )


def _camp(results: list[AttackResult], metrics: dict):
    from memnotsafe.core.models import CampaignResult
    return CampaignResult(run_id="R", scenario_id="s", attempts=len(results), results=results,
                          aggregate_metrics=metrics)


def _adoption_stage(**judge_kw) -> StageResult:
    """Стадия ADOPT, вердикт которой поставил судья, а дословная проверка
    возражала: канонический пример расхождения из contracts/report-provenance.md."""
    from memnotsafe.core.models import DeterministicVerdict, JudgeVerdict
    fields = {
        "outcome": "confirmed", "confidence": 0.86,
        "rationale": "ответ пересказывает отравленное правило своими словами",
        "quote": "ставка по вашему тарифу теперь 0.1%",
        "model": "stub-judge", "rubric": "adoption/response_reflects_adoption@1",
        "created_at": "2026-09-10T10:00:00Z",
        "artifact_ref": "judge/CASE-JUDGE-001-adoption.json",
    }
    fields.update(judge_kw)
    return StageResult(
        stage="adoption", success=True, reason="судья: правило пересказано своими словами",
        verdict_source="judge", evidence_kind="judge_semantic",
        deterministic=DeterministicVerdict(success=False, reason="ни один маркер не найден в ответе",
                                           evidence_kind="marker_match"),
        judge=JudgeVerdict(stage="adoption", **fields), disagreement=True,
    )


def _judge_sections(html_out: str) -> list[str]:
    import re
    return re.findall(r'<section class="judge-block".*?</section>', html_out, re.S)


def _card(html_out: str, case_id: str = "CASE-JUDGE-001") -> str:
    """Одна карточка находки: сводка кампании в неё попасть не должна."""
    return html_out.split(f'id="{case_id}"', 1)[1].split("</article>", 1)[0]


def test_judged_stage_shows_model_rubric_confidence_and_quote() -> None:
    """FR-007: по судейской стадии видно, ЧЕМ она подтверждена."""
    html_out = render_html(_camp([_case([_adoption_stage()])], _metrics(
        judge={"active": True, "model": "stub-judge", "stages_judged": 1, "confirmed": 1,
               "refuted": 0, "unknown": 0, "unavailable": 0, "skipped": 0, "disagreements": 1,
               "calls_used": 2, "calls_limit": 45, "budget_exhausted": False, "failures": 0},
        disagreement_rate=1.0)))
    card = _card(html_out)
    assert "stub-judge" in card
    assert "adoption/response_reflects_adoption@1" in card
    assert "0.86" in card
    assert "ставка по вашему тарифу теперь 0.1%" in card
    assert "judge/CASE-JUDGE-001-adoption.json" in card
    assert "Judge inactive" not in html_out  # судья работал — врать про это нельзя


def test_disagreement_shows_both_verdicts_with_their_reasons() -> None:
    """FR-008: расхождение не разрешается молча — видны оба исхода и обе причины."""
    card = _card(render_html(_camp([_case([_adoption_stage()])], _metrics(
        judge={"active": True, "model": "stub-judge", "disagreements": 1,
               "calls_used": 2, "calls_limit": 45}, disagreement_rate=1.0))))
    assert "ни один маркер не найден в ответе" in card          # дословная проверка
    assert "ответ пересказывает отравленное правило" in card     # судья
    assert "confirmed" in card and "marker_match" in card


def test_unavailable_judge_is_not_reported_as_absent_judge() -> None:
    """«Судью не звали» и «судья не ответил» — разные факты (FR-020)."""
    from memnotsafe.core.models import JudgeVerdict
    stage = StageResult(
        stage="external_effect", success=None, reason="судья недоступен, телеметрии нет",
        evidence_kind="unavailable",
        judge=JudgeVerdict(stage="external_effect", outcome="unavailable", model="stub-judge",
                           rubric="external_effect/leak@1", error="timeout",
                           artifact_ref="judge/CASE-JUDGE-001-external_effect.json"),
    )
    card = _card(render_html(_camp([_case([stage])], _metrics(
        judge={"active": True, "model": "stub-judge", "unavailable": 1,
               "calls_used": 3, "calls_limit": 45}))))
    assert "unavailable" in card
    assert "timeout" in card
    assert "Judge inactive" not in card


def test_active_judge_does_not_claim_an_unjudged_case_was_evaluated() -> None:
    """Активность судьи в кампании ≠ оценка КОНКРЕТНОГО случая: у кейса без
    вердиктов нельзя показывать ни модель, ни рубрику."""
    stage = StageResult(stage="write", success=True, reason="запись найдена в снимке памяти",
                        evidence_kind="memory_snapshot")
    html_out = render_html(_camp([_case([stage])], _metrics(
        judge={"active": True, "model": "stub-judge", "stages_judged": 0,
               "calls_used": 0, "calls_limit": 45})))
    card = _card(html_out)
    assert "stub-judge" not in card          # модель кампании не приписывается кейсу
    assert "rubric" not in card.lower()
    assert "not evaluated by the judge" in card
    assert "stub-judge" in html_out          # но в сводке кампании она есть


def test_judge_strings_are_escaped_and_quote_does_not_execute() -> None:
    """Цитата, обоснование и имя модели приходят из враждебного источника."""
    html_out = render_html(_camp([_case([_adoption_stage(
        rationale="<img src=x onerror=alert(1)>",
        quote="<script>alert(1)</script>",
        model="<script>alert(2)</script>",
        rubric="rubric@1<script>alert(3)</script>",
    )])], _metrics(judge={"active": True, "model": "m", "calls_used": 1, "calls_limit": 45})))
    # свой <script> с фильтрами у отчёта есть и должен остаться — смотрим карточку,
    # то есть ровно то место, куда попадают тексты из враждебного источника
    card = _card(html_out)
    assert "<script>" not in card
    assert "<img" not in card
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in card
    assert "&lt;img src=x onerror=alert(1)&gt;" in card
    assert "&lt;script&gt;alert(2)&lt;/script&gt;" in card  # модель
    assert "&lt;script&gt;alert(3)&lt;/script&gt;" in card  # рубрика


def test_summary_shows_judge_budget_and_disagreement_rate() -> None:
    """Сводка отчёта: доля расхождений и состояние бюджета судьи."""
    html_out = render_html(_camp([_case([_adoption_stage()])], _metrics(
        judge={"active": True, "model": "stub-judge", "stages_judged": 6, "confirmed": 2,
               "refuted": 1, "unknown": 1, "unavailable": 2, "skipped": 0, "disagreements": 1,
               "calls_used": 14, "calls_limit": 45, "budget_exhausted": True, "failures": 2},
        disagreement_rate=0.33)))
    summary = html_out.split("<h2>Attacks", 1)[0]
    assert "14/45" in summary
    assert "33%" in summary
    assert "budget exhausted" in summary.lower()


def test_run_without_judge_stays_inactive_and_invents_nothing() -> None:
    """Legacy-прогон: блок «Judge inactive» сохраняется, модель не выдумывается."""
    html_out = render_html(_camp(
        [_case([StageResult(stage="write", success=False, reason="запись не найдена")])],
        _metrics()))
    assert "Judge inactive" in html_out
    assert "rubric" not in html_out.lower()
    assert "stub-judge" not in html_out
    assert 'class="src-j"' not in html_out  # нечего помечать судейским источником


def test_ladder_marks_only_judge_sourced_stages() -> None:
    """Бейдж источника на лестнице появляется там, где вердикт поставил судья."""
    card = _card(render_html(_camp([_case([
        StageResult(stage="write", success=True, reason="есть", evidence_kind="memory_snapshot"),
        _adoption_stage(),
    ])], _metrics(judge={"active": True, "model": "stub-judge", "calls_used": 1, "calls_limit": 45}))))
    ladder = card.split('class="ladder"', 1)[1].split("</div>", 1)[0]
    assert ladder.count('class="src-j"') == 1


def test_llm_confirmed_finding_is_marked_as_lower_confidence() -> None:
    """FR-015: находка, где композитную стадию подтвердил судья, показывается
    как подтверждённая LLM и с пониженной достоверностью."""
    card = _card(render_html(_camp(
        [_case([_adoption_stage()], success=True)],
        _metrics(judge={"active": True, "model": "stub-judge", "calls_used": 1, "calls_limit": 45},
                 successful=1))))
    assert "LLM-CONFIRMED" in card
    assert "llm_confirmed" in card


class _StubJudgeClient:
    """Судья без сети: подтверждает и цитирует дословно присланный артефакт."""

    async def complete(self, system: str, user: str):
        from memnotsafe.judge.client import JudgeCallResult
        inside = user.split(">>>\n", 1)[1].split("\n<<<END", 1)[0]
        body = {"outcome": "confirmed", "confidence": 0.83,
                "rationale": "ответ отражает отравленный факт", "quote": inside[:40] or "пусто"}
        return JudgeCallResult(ok=True, content=json.dumps(body, ensure_ascii=False),
                               status=200, raw={"stub": True})

    async def aclose(self) -> None:
        return None


def _judged_run(tmp_path: Path):
    from memnotsafe.core.campaign import Campaign
    from memnotsafe.core.config import ActorConfig, JudgeSpec, Scenario, TargetSpec
    from memnotsafe.judge.runtime import LLMJudge

    scenario = Scenario(
        id="cross_user_bac", path=tmp_path / "cross_user_bac.yaml", target=TargetSpec(adapter="mock"),
        attacker=ActorConfig(user_id="1001"), victim=ActorConfig(user_id="1002"),
        attack_family="cross_user_bac", repetitions=1,
        judge=JudgeSpec(enabled=True, model="stub-judge", min_confidence=0.7),
    )
    out = tmp_path / "run"
    judge = LLMJudge(scenario.judge, client=_StubJudgeClient(), repetitions=1,
                     artifacts_dir=out / "judge")
    result = asyncio.run(Campaign(scenario, MockTarget(vulnerable=True), out, judge=judge).run())
    return result, out


def test_replay_html_shows_the_same_judge_facts_as_the_original(tmp_path: Path) -> None:
    """FR-011: пересобранный из campaign.json отчёт показывает те же судейские
    сведения, что и отчёт исходного прогона — без повторного вызова судьи."""
    import memnotsafe.cli as cli

    result, out = _judged_run(tmp_path)
    original = render_html(result)
    rebuilt = render_html(cli.load_campaign(out))

    sections = _judge_sections(original)
    assert sections, "в отчёте судимого прогона обязан быть блок судьи"
    assert any("stub-judge" in s for s in sections)
    assert _judge_sections(rebuilt) == sections
