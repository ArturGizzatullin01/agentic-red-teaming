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
