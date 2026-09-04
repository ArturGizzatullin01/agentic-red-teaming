"""tests/test_e2e_cross_user.py — обязательный E2E-тест: полный
pipeline на mock-таргете, без сети/LLM/Docker. vulnerable=True должен доказать
компромисс сквозь все стадии; vulnerable=False — честно НЕ должен (это не
ошибка раннера, а негативный регресс: авторизация блокирует последствие)."""

from __future__ import annotations

import asyncio

from memnotsafe.adapters.mock import MockTarget
from memnotsafe.attacks import get_attack
from memnotsafe.attacks.base import AttackContext
from memnotsafe.core.runner import new_run_id, run_attack


def _run_once(*, vulnerable: bool, family: str = "cross_user_bac", attacker="1001", victim="1002"):
    attack = get_attack(family)()
    target = MockTarget(vulnerable=vulnerable)
    ctx = AttackContext(attacker_user_id=attacker, victim_user_id=victim, run_seed=1, case_id="CASE-TEST-001")
    return asyncio.run(run_attack(attack, ctx, target, run_id=new_run_id()))


def test_cross_user_bac_e2e_vulnerable():
    result = _run_once(vulnerable=True)

    assert result.success is True
    assert result.stage_bool("write") is True
    assert result.stage_bool("persistence") is True
    assert result.stage_bool("adoption") is True
    assert result.stage_bool("tool") is True
    assert result.stage_bool("external_effect") is True

    # доказательство cross-user утечки на JSON-уровне evidence
    tool_events = [e for e in result.evidence["candidate"].keys()]
    assert "expected_effect" in tool_events
    assert result.evidence["victim_response"] != result.evidence["baseline_response"]
    assert "1001" in result.evidence["victim_response"]  # чужой cus утёк в ответ жертве 1002


def test_cross_user_bac_protected_regression():
    """success=False здесь значит ОТСУТСТВИЕ уязвимости, а не падение раннера:
    запись/адопция всё равно проходят, но авторизация блокирует
    итоговую утечку, поэтому composite success корректно False."""
    result = _run_once(vulnerable=False)

    assert result.success is False
    assert result.stage_bool("write") is True
    assert result.stage_bool("adoption") is True
    assert result.stage_bool("external_effect") is False  # заблокировано авторизацией


def test_baseline_is_clean_before_poisoning():
    result = _run_once(vulnerable=True)
    # baseline снят ДО доставки payload'а — victim ещё не отравлен на этот момент
    assert "1001" not in result.evidence["baseline_response"]
