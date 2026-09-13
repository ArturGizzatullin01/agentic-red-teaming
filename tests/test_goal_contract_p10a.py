"""tests/test_goal_contract_p10a.py — P10a (фича 007): GoalContract.

Проверяется: digest воспроизводим и чувствителен к смыслу (не к порядку
ключей); привязки попытки (маркер) вне digest; тип эффекта — только из
авторитетного набора P03; сериализация/чтение roundtrip без потерь
дополнительных полей; rewrite отклоняет смену цели ДО target.
"""

from __future__ import annotations

import asyncio
import json

import pytest

from memnotsafe.core.goal_contract import (
    GOAL_CONTRACT_SCHEMA_VERSION,
    REQUIRED_EVIDENCE_BY_TYPE,
    GoalContract,
    canonical_json,
)


def test_digest_stable_across_key_order_and_sensitive_to_meaning() -> None:
    effect = {"type": "tool_argument_injected", "tool": "book_transaction", "injected": "PROMO2024"}
    reordered = {"injected": "PROMO2024", "tool": "book_transaction", "type": "tool_argument_injected"}
    assert GoalContract.from_effect(effect).digest() == GoalContract.from_effect(reordered).digest()

    other_tool = GoalContract.from_effect({**effect, "tool": "send_message"})
    assert other_tool.digest() != GoalContract.from_effect(effect).digest()
    other_type = GoalContract.from_effect({"type": "response_reflects_adoption", "markers": ["PROMO2024"]})
    assert other_type.digest() != GoalContract.from_effect(effect).digest()


def test_bindings_and_schema_version_are_outside_goal_digest() -> None:
    """Смена маркера/привязок попытки — не смена цели: digest тот же."""
    effect = {"type": "cross_user_data_access", "attacker_user_id": "1001", "victim_user_id": "1002"}
    a = GoalContract.from_effect(effect, bindings={"case_marker": "CM-aaa111"})
    b = GoalContract.from_effect(effect, bindings={"case_marker": "CM-bbb222"})
    assert a.digest() == b.digest()
    assert a.same_goal(b)
    # но сериализации различаются — привязки не потеряны, просто не в digest
    assert a.to_dict()["bindings"] != b.to_dict()["bindings"]


def test_required_evidence_changes_the_goal() -> None:
    effect = {"type": "response_reflects_adoption"}
    base = GoalContract.from_effect(effect)
    assert base.required_evidence == REQUIRED_EVIDENCE_BY_TYPE["response_reflects_adoption"]
    widened = GoalContract(effect=dict(effect), required_evidence=("m1", "m2", "transcript", "settle"))
    assert not base.same_goal(widened)


def test_unknown_or_empty_effect_type_fails_closed() -> None:
    with pytest.raises(ValueError, match="обязателен"):
        GoalContract.from_effect({})
    with pytest.raises(ValueError, match="не поддерживается"):
        GoalContract.from_effect({"type": "made_up_effect"})
    # набор типов берётся у P03, а не заводится заново
    from memnotsafe.generation.corpus import supported_effect_types

    assert set(REQUIRED_EVIDENCE_BY_TYPE) == set(supported_effect_types())


def test_serialization_roundtrip_keeps_extra_effect_fields() -> None:
    effect = {
        "type": "tool_argument_injected",
        "tool": "book_transaction",
        "field": "comment",
        "injected": "PROMO2024",
        # дополнительное допустимое поле эффекта
        "note": "записывается в комментарий транзакции",
    }
    contract = GoalContract.from_effect(effect, bindings={"case_marker": "CM-abc123"})
    restored = GoalContract.from_serialized(contract.to_dict())
    assert restored == contract
    assert restored.digest() == contract.digest()
    assert restored.to_dict()["effect"]["note"] == effect["note"]  # доп. поле не потеряно


def test_serialized_version_mismatch_is_explicit() -> None:
    data = GoalContract.from_effect({"type": "response_reflects_adoption"}).to_dict()
    data["schema_version"] = GOAL_CONTRACT_SCHEMA_VERSION + 1
    with pytest.raises(ValueError, match="schema_version"):
        GoalContract.from_serialized(data)


def test_canonical_json_is_sorting_and_compact() -> None:
    text = canonical_json({"b": 1, "a": {"d": 2, "c": 3}})
    assert text == '{"a":{"c":3,"d":2},"b":1}'


def test_rewritten_effect_with_reordered_keys_keeps_goal() -> None:
    """Интеграция в rewrite: модель вернула те же значения в другом порядке
    ключей — цель та же, rewrite проходит."""
    from memnotsafe.generation.attacker_client import StubAttackerClient
    from memnotsafe.generation.budget import CallBudget
    from memnotsafe.generation.rewrite import rewrite

    from tests.test_escalation import _k3_feedback, _k3_script

    previous = {"injected": "PROMO2024", "tool": "book_transaction", "type": "tool_argument_injected"}
    out = asyncio.run(rewrite(
        _k3_feedback({"type": "tool_argument_injected", "tool": "book_transaction", "injected": "PROMO2024"}),
        StubAttackerClient([_k3_script(previous)]), CallBudget(limit=5),
    ))
    assert out is not None  # порядок ключей не меняет digest → цель та же


def test_rewrite_rejects_commit_to_mention_downgrade() -> None:
    """«Совершить эффект» → «упомянуть эффект»: подмена реально вызванного
    инструмента на отражение в ответе отбраковывается до target."""
    from memnotsafe.generation.attacker_client import StubAttackerClient
    from memnotsafe.generation.budget import CallBudget
    from memnotsafe.generation.rewrite import rewrite

    from tests.test_escalation import _k3_feedback, _k3_script

    previous = {"type": "tool_argument_injected", "tool": "book_transaction", "injected": "PROMO2024"}
    mentioned = {"type": "response_reflects_adoption", "markers": ["PROMO2024"]}
    budget = CallBudget(limit=5)
    out = asyncio.run(rewrite(_k3_feedback(previous), StubAttackerClient([_k3_script(mentioned)]), budget))
    assert out is None
    assert budget.used == 1  # вызов атакующей LLM оплачен, target НЕ тронут


def test_goal_contract_serialization_is_json_dumpable() -> None:
    payload = GoalContract.from_effect(
        {"type": "scope_escalated", "attacker_user_id": "1001", "victim_user_id": "1002"},
        bindings={"case_marker": None},
    ).to_dict()
    json.loads(json.dumps(payload, ensure_ascii=False))  # без сюрпризов типов
