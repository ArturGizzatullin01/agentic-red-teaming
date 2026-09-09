"""tests/test_escalation.py — онлайн-эскалация (US2/US3): лимит попыток, стоп на
первом успехе, исчерпание бюджета (штатный стоп, exit 0), сбой атакующей LLM
(exit 1 с сохранением результатов), провенанс/стоимость (SC-004/005/007).

Всё офлайн на MockTarget + StubAttackerClient (Принцип VI)."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from memnotsafe.adapters.mock import MockTarget
from memnotsafe.cli import main
from memnotsafe.core.campaign import Campaign
from memnotsafe.core.config import ActorConfig, Scenario, TargetSpec
from memnotsafe.generation.config import AttackerConfig
from memnotsafe.generation.offline import escalation_stub_script

SEED_CORPUS = Path("corpora/escalation-seed.yaml")
ESC_SCENARIO = "scenarios/generated_escalation.yaml"


def _scenario():
    return Scenario(
        id="esc", path=Path("esc.yaml"),
        target=TargetSpec(adapter="mock", extra={"vulnerable": True}),
        attacker=ActorConfig("1001"), victim=ActorConfig("1002"),
        attack_family="generated", repetitions=1, corpus_path=SEED_CORPUS,
    )


def _run(*, online, attempts=5, budget=50, scripted=None):
    cfg = AttackerConfig(provider="stub", scripted=scripted, budget=budget) if online else None
    campaign = Campaign(_scenario(), MockTarget(vulnerable=True), Path("/tmp/esc-unit"),
                        attacker_config=cfg, online=online, online_attempts=attempts)
    result = asyncio.run(campaign.run())
    return campaign, result.results[0]


# --------------------------------------------------------------- US2 цикл

def test_online_off_is_not_exploitable_and_zero_calls():
    # SC-003: без онлайна атака честно не пробивает, атакующая LLM не создаётся.
    campaign, r = _run(online=False)
    assert r.success is False
    assert campaign._attacker_client is None
    assert campaign.attacker_calls == 0


def test_online_breaks_on_second_attempt_and_stops():
    # SC-004: атака пробивается адаптацией в пределах лимита; стоп на первом успехе.
    campaign, r = _run(online=True, attempts=5, scripted=[escalation_stub_script(), escalation_stub_script()])
    prov = r.evidence["provenance"]
    assert r.success is True
    assert prov["attempts"] == 2  # корпус (1) + одно переписывание (2)
    assert prov["origin"] == "online"
    assert campaign.attacker_calls == 1  # ровно один вызов (стоп на успехе)


def test_attempts_never_exceed_limit():
    # SC-004: число попыток никогда не больше лимита. attempts=1 → ровно одна.
    _campaign, r = _run(online=True, attempts=1, scripted=[escalation_stub_script()])
    assert r.success is False
    assert r.evidence["provenance"]["attempts"] == 1


def test_budget_exhaustion_is_graceful_stop():
    # FR-010: исчерпание бюджета — штатный стоп (не ошибка). budget=0 → нет
    # переписываний, budget_exhausted=true, результат сохранён, ошибки нет.
    campaign, r = _run(online=True, attempts=5, budget=0, scripted=[escalation_stub_script()])
    assert r.success is False
    assert r.evidence["provenance"]["budget_exhausted"] is True
    assert campaign.attacker_error is None  # НЕ сбой


def test_attacker_failure_sets_error_and_preserves_results():
    # FR-011/SC-005: сбой атакующей LLM (скрипт пуст → AttackerError) — это НЕ
    # «атака не пробила». Ошибка зафиксирована, результат сохранён.
    campaign, r = _run(online=True, attempts=5, scripted=[])  # пустой скрипт → AttackerError
    assert campaign.attacker_error is not None
    assert r is not None  # результат до сбоя сохранён
    assert "attacker_error" in r.evidence["provenance"]


# --------------------------------------------------------------- US3 коды возврата CLI

def test_cli_online_off_exit_zero(tmp_path):
    code = main(["run", "--scenario", ESC_SCENARIO, "--output", str(tmp_path / "off")])
    assert code == 0  # честный NOT_EXPLOITABLE — не сбой


def test_cli_online_success_exit_zero(tmp_path):
    code = main(["run", "--scenario", ESC_SCENARIO, "--output", str(tmp_path / "on"),
                 "--online", "--online-attempts", "5", "--attacker-provider", "stub"])
    assert code == 0


def test_cli_online_attempts_one_exit_zero(tmp_path):
    code = main(["run", "--scenario", ESC_SCENARIO, "--output", str(tmp_path / "one"),
                 "--online", "--online-attempts", "1", "--attacker-provider", "stub"])
    assert code == 0  # NOT_EXPLOITABLE в пределах лимита — тоже exit 0


def test_cli_attacker_failure_exit_one_but_saves_run(tmp_path, monkeypatch):
    # SC-005: сбой атакующей LLM → exit 1; уже собранные результаты в runs/.
    monkeypatch.setenv("ATTACKER_API_KEY", "")
    out = tmp_path / "fail"
    code = main(["run", "--scenario", ESC_SCENARIO, "--output", str(out),
                 "--online", "--attacker-provider", "openai", "--attacker-base-url", "http://127.0.0.1:1"])
    assert code == 1
    assert (out / "campaign.json").exists()  # результаты сохранены до выхода


# --------------------------------------------------------------- US4 провенанс в отчёте

def _corpus_scenario():
    return Scenario(
        id="gen", path=Path("gen.yaml"),
        target=TargetSpec(adapter="mock", extra={"vulnerable": True}),
        attacker=ActorConfig("1001"), victim=ActorConfig("1002"),
        attack_family="generated", repetitions=1, corpus_path=Path("corpora/support-agent.yaml"),
    )


def test_findings_carry_origin_and_severity_by_attack_class(tmp_path):
    # FR-013/FR-003: у каждой находки видно origin; severity/ATLAS резолвятся по
    # attack_class из провенанса, а не по family="generated".
    from memnotsafe.reporting.findings import build_findings

    campaign = Campaign(_corpus_scenario(), MockTarget(vulnerable=True), tmp_path / "run")
    result = asyncio.run(campaign.run())
    findings = build_findings(result.results)

    by_class = {f.evidence["provenance"]["attack_class"]: f for f in findings}
    assert all(f.evidence["provenance"]["origin"] == "corpus" for f in findings)
    # cross_user_bac резолвится в CRITICAL (а не generic MEDIUM для generated).
    assert by_class["cross_user_bac"].severity == "CRITICAL"
    assert by_class["cross_user_bac"].status == "SUCCESS"
    assert by_class["scope_escalation"].severity == "HIGH"
    # title — имя класса-источника, а не «Сгенерированная атака».
    assert "generated" not in by_class["cross_user_bac"].title.lower()


def test_online_finding_reports_attempts(tmp_path):
    # SC-007: у онлайновой находки видно число потраченных попыток.
    campaign, r = _run(online=True, attempts=5, scripted=[escalation_stub_script()])
    assert r.evidence["provenance"]["attempts"] == 2
    assert r.evidence["provenance"]["origin"] == "online"


def test_campaign_json_records_attacker_cost(tmp_path):
    # FR-014: агрегат стоимости (вызовы, исчерпание бюджета) — в campaign.json.
    import json

    out = tmp_path / "run"
    code = main(["run", "--scenario", ESC_SCENARIO, "--output", str(out),
                 "--online", "--online-attempts", "5", "--attacker-provider", "stub"])
    assert code == 0
    meta = json.load((out / "campaign.json").open())["metadata"]["attacker"]
    assert meta["active"] is True
    assert meta["calls_used"] == 1  # одно переписывание до успеха
    assert meta["budget_exhausted"] is False


def test_online_off_campaign_json_attacker_inactive(tmp_path):
    # SC-003: без --online блок стоимости — ровно {"active": false}.
    import json

    out = tmp_path / "run"
    main(["run", "--scenario", ESC_SCENARIO, "--output", str(out)])
    assert json.load((out / "campaign.json").open())["metadata"]["attacker"] == {"active": False}


# ------------------------------------- судья и case-маркер повторной попытки

class _RecordingJudge:
    """Судья-двойник: сети нет, вердиктов не выдаёт (пустой dict = для оракулов
    ровно то же, что отсутствие судьи), но помнит, по каким case_id его звали.
    Контракт тот же, что у LLMJudge.evaluate_stages — раннер зовёт его
    именованными аргументами."""

    def __init__(self) -> None:
        self.case_ids: list[str] = []

    async def evaluate_stages(self, *, case_id, expected_effect, artifact, baseline):
        self.case_ids.append(case_id)
        return {}

    def metadata(self) -> dict:
        # блок metadata.judge активного судьи — его читает слой кампании
        return {"active": True, "model": "recording-stub", "calls_used": len(self.case_ids),
                "calls_limit": 0, "budget_exhausted": False, "failures": 0}

    async def aclose(self) -> None:
        return None


def _seed_case():
    """Корпусный случай seed-корпуса — ровно так его собирает слой кампании."""
    from memnotsafe.attacks.base import AttackContext
    from memnotsafe.attacks.generated import GeneratedAttack
    from memnotsafe.core.runner import new_case_id
    from memnotsafe.generation.corpus import read_corpus, valid_records

    record = valid_records(read_corpus(SEED_CORPUS))[0]
    ctx = AttackContext(
        attacker_user_id="1001", victim_user_id="1002", run_seed=1,
        case_id=new_case_id(record.attack_class, 1),
        params={"record": record.to_dict(), "corpus_id": "escalation-seed"},
    )
    return GeneratedAttack(), ctx


def _escalate_with_spy(monkeypatch, judge):
    """Начальная попытка + эскалация на mock. Шпион запоминает контекст и судью
    КАЖДОГО повтора; объект контекста тот же, что видел раннер, поэтому после
    вызова в нём лежит маркер, под которым попытка реально прогонялась."""
    import memnotsafe.core.escalation as esc
    from memnotsafe.core.runner import new_run_id, run_attack
    from memnotsafe.generation.attacker_client import StubAttackerClient
    from memnotsafe.generation.budget import CallBudget

    retries: list[tuple] = []
    real_run_attack = esc.run_attack

    async def spy(attack, ctx, target, **kw):
        retries.append((ctx, kw.get("judge")))
        return await real_run_attack(attack, ctx, target, **kw)

    monkeypatch.setattr(esc, "run_attack", spy)

    attack, base_ctx = _seed_case()
    target = MockTarget(vulnerable=True)
    run_id = new_run_id()

    async def go():
        first = await run_attack(attack, base_ctx, target, run_id=run_id, judge=judge)
        assert first.success is False  # seed намеренно не пробивает (NOT_EXPLOITABLE)
        return await esc.escalate(
            attack, base_ctx, target, first,
            limit=2, client=StubAttackerClient([escalation_stub_script()]),
            budget=CallBudget(limit=5), run_id=run_id, judge=judge,
        )

    return asyncio.run(go()), base_ctx, retries


def test_retry_is_judged_by_the_same_judge(monkeypatch):
    # Судья — свойство прогона: повтор судится тем же судьёй, что и начальная
    # попытка, иначе вердикты внутри одного случая несопоставимы.
    judge = _RecordingJudge()
    outcome, base_ctx, retries = _escalate_with_spy(monkeypatch, judge)

    assert outcome.attempts == 2
    assert len(retries) == 1
    retry_ctx, retry_judge = retries[0]
    assert retry_judge is judge
    assert judge.case_ids == [base_ctx.case_id, retry_ctx.case_id]


def test_retry_gets_own_case_marker_not_the_previous_one(monkeypatch):
    # T002-10/FR-B: маркер производен от case_id. У повтора case_id новый, значит
    # и маркер обязан быть свой — иначе записи атрибутируются чужой канарейкой.
    from memnotsafe.evidence.matching import derive_case_marker

    _outcome, base_ctx, retries = _escalate_with_spy(monkeypatch, None)
    retry_ctx, _judge = retries[0]

    assert base_ctx.case_marker == derive_case_marker(base_ctx.case_id)
    assert retry_ctx.case_id != base_ctx.case_id
    assert retry_ctx.case_marker == derive_case_marker(retry_ctx.case_id)
    assert retry_ctx.case_marker != base_ctx.case_marker


def test_escalation_without_judge_stays_offline(monkeypatch):
    # SC-003: судья опционален. Без него повтор идёт как раньше — judge=None
    # доезжает до раннера, сеть и ключи не нужны.
    outcome, _base_ctx, retries = _escalate_with_spy(monkeypatch, None)

    assert retries[0][1] is None
    assert outcome.succeeded is True  # переписанная запись пробивает уязвимый mock


def test_campaign_hands_the_same_judge_to_escalation(monkeypatch, tmp_path):
    # Проводка слоя кампании: судья, которым судили первую попытку, доезжает до
    # escalate() ТЕМ ЖЕ объектом (он живёт на кампанию — общий бюджет вызовов).
    import memnotsafe.core.escalation as esc

    judge = _RecordingJudge()
    seen: dict = {}
    real_escalate = esc.escalate

    async def spy(*args, **kw):
        seen["judge"] = kw.get("judge")
        return await real_escalate(*args, **kw)

    monkeypatch.setattr(esc, "escalate", spy)

    cfg = AttackerConfig(provider="stub", scripted=[escalation_stub_script()], budget=50)
    campaign = Campaign(_scenario(), MockTarget(vulnerable=True), tmp_path / "wired",
                        judge=judge, attacker_config=cfg, online=True, online_attempts=2)
    result = asyncio.run(campaign.run())

    assert seen["judge"] is judge
    # обе попытки одного случая прошли через одного судью, и итоговый результат —
    # это судимый повтор, а не начальная попытка
    assert len(judge.case_ids) == 2
    assert len(set(judge.case_ids)) == 2
    assert judge.case_ids[1] == result.results[0].case_id
