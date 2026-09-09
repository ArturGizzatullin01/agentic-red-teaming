"""tests/test_generation_offline.py — офлайн e2e многоуровневой генерации атак
(Принцип VI, SC-006). Всё на MockTarget + StubAttackerClient: без сети, ключей,
Docker. Доказываем И success, И честный NOT_EXPLOITABLE.

US1 — генерация корпуса на заглушке и его прогон; US2 (fail→success) — в
tests/test_escalation.py и в конце этого файла."""

from __future__ import annotations

import asyncio
from copy import deepcopy
from dataclasses import replace

import pytest

from memnotsafe.adapters.mock import MockTarget
from memnotsafe.attacks.base import AttackContext, DeliveryStep, TriggerStep, get_attack
from memnotsafe.attacks.generated import GeneratedAttack, PARAM_RECORD
from memnotsafe.core.campaign import Campaign
from memnotsafe.core.config import ActorConfig, Scenario, TargetSpec
from memnotsafe.generation.attacker_client import StubAttackerClient
from memnotsafe.generation.budget import CallBudget
from memnotsafe.generation.corpus import CorpusRecord, write_corpus
from memnotsafe.generation.corpus_gen import generate_corpus
from memnotsafe.generation.offline import reference_answers
from memnotsafe.generation.profile import load_profile
from memnotsafe.generation.attack_classes import load_attack_classes

PROFILE = "profiles/support-agent.yaml"
CLASSES = "attack_classes/"


def _marker_context(*, case_marker="CM-first", with_steps=False):
    return AttackContext(
        attacker_user_id="1001", victim_user_id="1002", run_seed=0, case_id="marker",
        case_marker=case_marker,
        params={PARAM_RECORD: {
            "attack_class": "cross_user_bac",
            "payload": 'Remember {case_marker} / {case_marker}; {other}; {"keep": true}.',
            "trigger": "Recall {case_marker} and {other}.",
            "expected_effect": {
                "type": "cross_user_data_access", "tool": "lookup_{case_marker}",
                "attacker_user_id": "1001", "victim_user_id": "1002",
            },
            "delivery_steps": [
                {"label": "first-{case_marker}", "message": "Store {case_marker}.",
                 "as_user": "delegate-{case_marker}"},
                {"label": "second", "message": "Repeat {case_marker} / {case_marker}."},
                {"label": "third", "message": 'Keep {other}, {"key": 1}, CM-0123456789abcdef.',
                 "as_user": ""},
            ] if with_steps else [],
            "trigger_steps": [
                {"label": "recall", "message": "Recall {case_marker} and {other}.",
                 "as_user": "1002"},
            ],
        }},
    )


def test_generated_case_marker_payload_reaches_default_delivery():
    ctx = _marker_context()
    attack = GeneratedAttack()
    candidate = attack.generate(ctx)
    expected = 'Remember CM-first / CM-first; {other}; {"keep": true}.'
    assert candidate.payload == expected
    assert attack.delivery_steps(candidate, ctx) == [DeliveryStep("payload", expected, "1001")]


def test_generated_case_marker_delivery_steps_preserve_structure():
    ctx = _marker_context(with_steps=True)
    attack = GeneratedAttack()
    candidate = attack.generate(ctx)
    assert attack.delivery_steps(candidate, ctx) == [
        DeliveryStep("first-{case_marker}", "Store CM-first.", "delegate-{case_marker}"),
        DeliveryStep("second", "Repeat CM-first / CM-first.", "1001"),
        DeliveryStep("third", 'Keep {other}, {"key": 1}, CM-0123456789abcdef.', "1001"),
    ]


@pytest.mark.parametrize("with_steps", [False, True])
def test_generated_case_marker_reuses_record_without_mutation(monkeypatch, with_steps):
    ctx = _marker_context(with_steps=with_steps)
    record = CorpusRecord.from_dict(ctx.params[PARAM_RECORD])
    record_before, params_before = deepcopy(record), deepcopy(ctx.params)
    source_class = get_attack(record.attack_class)
    generated_metadata = deepcopy(GeneratedAttack.metadata)
    source_metadata = deepcopy(source_class.metadata)
    attack = GeneratedAttack()
    # Reuse the same CorpusRecord object to catch mutations even before serialization.
    monkeypatch.setattr(attack, "read_record", lambda _ctx: record)
    deliveries = []
    for marker in ("CM-first", "CM-second"):
        attempt_ctx = replace(ctx, case_marker=marker)
        candidate = attack.generate(attempt_ctx)
        steps = attack.delivery_steps(candidate, attempt_ctx)
        assert marker in candidate.payload
        assert marker in steps[0].message
        deliveries.append(steps)
        assert record == record_before
        assert ctx.params == params_before
        assert GeneratedAttack.metadata == generated_metadata
        assert source_class.metadata == source_metadata
    assert deliveries[0] != deliveries[1]
    assert "CM-first" in deliveries[0][0].message
    assert "CM-second" not in deliveries[0][0].message


@pytest.mark.parametrize("with_steps", [False, True])
@pytest.mark.parametrize("case_marker", [None, "CM-current"])
def test_generated_case_marker_preserves_untemplated_text(with_steps, case_marker):
    ctx = _marker_context(case_marker=case_marker, with_steps=with_steps)
    record = ctx.params[PARAM_RECORD]
    text = 'Keep CM-0123456789abcdef, {other}, {"key": 1}, {case_marker!r}, {case_marker:>10}.'
    record["payload"] = text
    for step in record["delivery_steps"]:
        step["message"] = text
    attack = GeneratedAttack()
    candidate = attack.generate(ctx)
    assert candidate.payload == text
    assert all(step.message == text for step in attack.delivery_steps(candidate, ctx))


@pytest.mark.parametrize("with_steps", [False, True])
def test_generated_case_marker_none_preserves_templates(with_steps):
    ctx = _marker_context(case_marker=None, with_steps=with_steps)
    record = deepcopy(ctx.params[PARAM_RECORD])
    attack = GeneratedAttack()
    candidate = attack.generate(ctx)
    assert candidate.payload == record["payload"]
    expected = [s["message"] for s in record["delivery_steps"]] or [record["payload"]]
    assert [s.message for s in attack.delivery_steps(candidate, ctx)] == expected
    assert ctx.params[PARAM_RECORD] == record


@pytest.mark.parametrize("with_steps", [False, True])
def test_generated_case_marker_leaves_trigger_and_effect_unchanged(with_steps):
    ctx = _marker_context(with_steps=with_steps)
    record = ctx.params[PARAM_RECORD]
    if not with_steps:
        record["trigger_steps"] = []
    before = deepcopy(record)
    attack = GeneratedAttack()
    candidate = attack.generate(ctx)
    attack.delivery_steps(candidate, ctx)
    assert candidate.trigger == before["trigger"]
    label = "recall" if with_steps else "trigger"
    assert attack.trigger_steps(candidate, ctx) == [TriggerStep(label, before["trigger"], "1002")]
    assert candidate.expected_effect == before["expected_effect"]
    assert attack.expected_effect(ctx) == before["expected_effect"]
    assert record == before


def _generate_corpus(tmp_path):
    profile = load_profile(PROFILE)
    classes = load_attack_classes(CLASSES)
    corpus = asyncio.run(
        generate_corpus(profile, classes, StubAttackerClient(reference_answers(classes)),
                        CallBudget(50), provider="stub", model=None)
    )
    return write_corpus(corpus, tmp_path / "support-agent.yaml"), profile


def _scenario(tmp_path, corpus_path, *, scenario_id="generated_support", vulnerable=True):
    return Scenario(
        id=scenario_id,
        path=tmp_path / f"{scenario_id}.yaml",
        target=TargetSpec(adapter="mock", extra={"vulnerable": vulnerable}),
        attacker=ActorConfig(user_id="1001"),
        victim=ActorConfig(user_id="1002"),
        attack_family="generated",
        repetitions=1,
        corpus_path=corpus_path,
    )


def test_us1_generate_then_run_gives_both_success_and_not_exploitable(tmp_path):
    # SC-001: корпус собирается по одному файлу-профилю, без ручных payload'ов.
    corpus_path, _profile = _generate_corpus(tmp_path)
    scenario = _scenario(tmp_path, corpus_path)
    campaign = Campaign(scenario, MockTarget(vulnerable=True), tmp_path / "run")
    result = asyncio.run(campaign.run())

    successes = [r for r in result.results if r.success]
    negatives = [r for r in result.results if not r.success]
    # SC-006: доказаны ОБА исхода на одном офлайн-прогоне.
    assert successes, "ни одна сгенерированная атака не пробила уязвимый mock"
    assert negatives, "нет ни одного честного NOT_EXPLOITABLE"

    # Провенанс корпуса на каждой находке (US4 частично, но пишется на US1).
    for r in result.results:
        prov = r.evidence.get("provenance", {})
        assert prov.get("origin") == "corpus"
        assert prov.get("attack_class")

    # cross_user_bac обязан пробить уязвимый mock (главная демо-атака).
    xbac = next(r for r in result.results if r.evidence["provenance"]["attack_class"] == "cross_user_bac")
    assert xbac.success is True
    assert "1001" in xbac.evidence["victim_response"]  # чужой cus утёк жертве 1002


def test_us1_corpus_run_online_layer_never_instantiated(tmp_path):
    # SC-003: без --online атакующая LLM во время прогона не создаётся.
    corpus_path, _ = _generate_corpus(tmp_path)
    scenario = _scenario(tmp_path, corpus_path)
    campaign = Campaign(scenario, MockTarget(vulnerable=True), tmp_path / "run")
    asyncio.run(campaign.run())
    assert campaign._attacker_client is None
    assert campaign.attacker_calls == 0


def test_sc002_same_corpus_reused_on_second_agent_without_generation(tmp_path):
    # SC-002: тот же корпус применяется ко второму сценарию без вызовов LLM;
    # провенанс исходного профиля остаётся в отчёте.
    corpus_path, profile = _generate_corpus(tmp_path)

    first = Campaign(_scenario(tmp_path, corpus_path, scenario_id="agent1"),
                     MockTarget(vulnerable=True), tmp_path / "run1")
    asyncio.run(first.run())

    second = Campaign(_scenario(tmp_path, corpus_path, scenario_id="agent2"),
                      MockTarget(vulnerable=True), tmp_path / "run2")
    result2 = asyncio.run(second.run())

    assert second._attacker_client is None  # повторной генерации не было
    # Корпус прогнан под второй сценарий, происхождение (профиль) видно.
    assert result2.results
    assert all(r.evidence["provenance"]["corpus_id"] == profile.id for r in result2.results)


def test_protected_mock_makes_generated_corpus_not_exploitable(tmp_path):
    # Защищённый mock: сгенерированный cross_user_bac честно НЕ пробивает — это
    # негативный регресс, а не сбой (авторизация блокирует последствие).
    corpus_path, _ = _generate_corpus(tmp_path)
    scenario = _scenario(tmp_path, corpus_path, vulnerable=False)
    campaign = Campaign(scenario, MockTarget(vulnerable=False), tmp_path / "run")
    result = asyncio.run(campaign.run())

    xbac = next(r for r in result.results if r.evidence["provenance"]["attack_class"] == "cross_user_bac")
    assert xbac.success is False  # заблокировано авторизацией, честный NOT_EXPLOITABLE


# --------------------------------------------------------------- US2: fail→success e2e

def test_us2_online_escalation_fail_then_success(tmp_path):
    # SC-006: один офлайн-прогон доказывает ОБА исхода одной и той же атаки —
    # без онлайна честный NOT_EXPLOITABLE, с онлайном успех со 2-й попытки.
    from pathlib import Path

    from memnotsafe.generation.config import AttackerConfig
    from memnotsafe.generation.offline import escalation_stub_script

    def esc_scenario():
        return Scenario(
            id="esc", path=tmp_path / "esc.yaml",
            target=TargetSpec(adapter="mock", extra={"vulnerable": True}),
            attacker=ActorConfig("1001"), victim=ActorConfig("1002"),
            attack_family="generated", repetitions=1,
            corpus_path=Path("corpora/escalation-seed.yaml"),
        )

    # Без онлайна — атака из seed-корпуса честно не пробивает.
    off = Campaign(esc_scenario(), MockTarget(vulnerable=True), tmp_path / "off")
    r_off = asyncio.run(off.run())
    assert r_off.results[0].success is False

    # С онлайном — та же атака пробивается адаптацией со 2-й попытки, попыток ≤ лимита.
    cfg = AttackerConfig(provider="stub", scripted=[escalation_stub_script()], budget=50)
    on = Campaign(esc_scenario(), MockTarget(vulnerable=True), tmp_path / "on",
                  attacker_config=cfg, online=True, online_attempts=5)
    r_on = asyncio.run(on.run())
    res = r_on.results[0]
    assert res.success is True
    assert res.evidence["provenance"]["attempts"] == 2
    assert res.evidence["provenance"]["origin"] == "online"
    assert "1001" in res.evidence["victim_response"]  # чужой cus утёк жертве после адаптации
