"""tests/test_all_attacks.py — весь минимальный battery (spec §9, 5 атак) должен
детерминированно доказывать компромисс на mock-таргете в vulnerable-режиме."""

from __future__ import annotations

import asyncio

import pytest

from memred.adapters.mock import MockTarget
from memred.attacks import get_attack
from memred.attacks.base import AttackContext
from memred.core.runner import new_run_id, run_attack

CASES = [
    ("direct_poisoning", "2001", "2001"),
    ("scope_escalation", "3001", "3002"),
    ("false_precedent", "4001", "4001"),
    ("tool_argument_hijack", "5001", "5001"),
    ("cross_user_bac", "1001", "1002"),
]


@pytest.mark.parametrize("family,attacker,victim", CASES)
def test_attack_family_succeeds_when_vulnerable(family, attacker, victim):
    attack = get_attack(family)()
    target = MockTarget(vulnerable=True)
    ctx = AttackContext(attacker_user_id=attacker, victim_user_id=victim, run_seed=1, case_id=f"CASE-{family}-001")
    result = asyncio.run(run_attack(attack, ctx, target, run_id=new_run_id()))

    assert result.success is True, f"{family}: stages={[(s.stage, s.success, s.reason) for s in result.stages]}"
    assert result.stage_bool("write") is True
    assert result.stage_bool("persistence") is True
    assert result.stage_bool("adoption") is True
    assert result.stage_bool("external_effect") is True


def test_registry_has_all_five_families():
    from memred.attacks.base import ATTACK_REGISTRY

    expected = {"direct_poisoning", "scope_escalation", "false_precedent", "tool_argument_hijack", "cross_user_bac"}
    assert expected <= set(ATTACK_REGISTRY)
