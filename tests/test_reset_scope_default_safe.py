"""tests/test_reset_scope_default_safe.py — FIX-C: reset_scope по умолчанию
безопасен и достижим из YAML (блокер перепрогона G3.1/G3.2).

Дефект (перепроверен): дефолт `scope="global"` в адаптере → `reset_state()`
делал `delete_many({})` по всем 4 коллекциям, включая глобальный слой политик
(agent_policy_memories — предмет G3.2). Ни один сценарий не задавал режим, а
`build_adapter` прокидывал только `target.extra` — namespace-режим из сценария
был НЕДОСТИЖИМ. Эрратум G3.1: живые прогоны шли с глобальным wipe (стирали то,
что измеряли).

Замки:
  * сценарий без поля reset_scope → namespace (безопасный дефолт);
  * namespace ДОСТИЖИМ: build_adapter отдаёт адаптер с scope=namespace;
  * reset_scope=global без непустого target.reset_ack → громкий отказ;
  * reset_scope=global с ack → глобальный адаптер (режим доступен явно);
  * опечатка в reset_scope → отказ (прецедент конструктора адаптера);
  * страж имени БД: scope=global + не-стендовая БД → отказ до обращения к Mongo;
  * все живые investment_stand-сценарии резолвятся в namespace.

Офлайн: конструирование адаптера не подключается к Mongo (ленивый _db()).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from memnotsafe.adapters.investment_stand import InvestmentStandAdapter
from memnotsafe.core.config import build_adapter, load_scenario

_SCENARIOS = Path(__file__).resolve().parent.parent / "scenarios"


def _write_scenario(tmp_path: Path, *, reset_scope: str | None, reset_ack: str | None = None,
                    mongo_db: str = "agent_memory") -> Path:
    lines = [
        "id: tmp_reset_scope_test",
    ]
    if reset_scope is not None:
        lines.append(f"reset_scope: {reset_scope}")
    lines += [
        "target:",
        "  adapter: investment_stand",
        '  base_url: "http://fake"',
        f"  mongo_db: {mongo_db}",
    ]
    if reset_ack is not None:
        lines.append(f'  reset_ack: "{reset_ack}"')
    lines += [
        "actors:",
        "  attacker:",
        '    user_id: "1001"',
        "  victim:",
        '    user_id: "1002"',
        "attack:",
        "  family: cross_user_bac",
    ]
    p = tmp_path / "scenario.yaml"
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return p


def _investment_stand_scenarios() -> list[Path]:
    out = []
    for p in sorted(_SCENARIOS.glob("*.yaml")):
        text = p.read_text(encoding="utf-8")
        if "adapter: investment_stand" in text:
            out.append(p)
    return out


def test_scenario_defaults_to_namespace_without_field(tmp_path) -> None:
    """Сценарий без ключа reset_scope грузится как namespace (безопасный дефолт)."""
    sc = load_scenario(_write_scenario(tmp_path, reset_scope=None))
    assert sc.reset_scope == "namespace"


def test_namespace_is_reachable_from_yaml(tmp_path) -> None:
    """Главный замок дефекта: build_adapter отдаёт адаптер в namespace-режиме
    (на базе он молча строил scope=global — namespace был недостижим)."""
    sc = load_scenario(_write_scenario(tmp_path, reset_scope=None))
    adapter = build_adapter(sc)
    assert adapter._reset_scope == "namespace"


def test_global_without_ack_refused(tmp_path) -> None:
    """reset_scope=global без непустого target.reset_ack → громкий отказ."""
    sc = load_scenario(_write_scenario(tmp_path, reset_scope="global", reset_ack=None))
    with pytest.raises(ValueError, match="reset_ack"):
        build_adapter(sc)


def test_global_with_ack_builds_global_adapter(tmp_path) -> None:
    """reset_scope=global с непустым ack и стендовой БД → глобальный адаптер."""
    sc = load_scenario(_write_scenario(tmp_path, reset_scope="global",
                                       reset_ack="G3.2 rerun approved"))
    adapter = build_adapter(sc)
    assert adapter._reset_scope == "global"


def test_global_with_blank_ack_refused(tmp_path) -> None:
    """Пустой/пробельный reset_ack не считается подтверждением."""
    sc = load_scenario(_write_scenario(tmp_path, reset_scope="global", reset_ack="   "))
    with pytest.raises(ValueError, match="reset_ack"):
        build_adapter(sc)


def test_reset_scope_typo_refused(tmp_path) -> None:
    """Опечатка в reset_scope → отказ (прецедент конструктора адаптера, не
    молчаливый global)."""
    sc = load_scenario(_write_scenario(tmp_path, reset_scope="globl"))
    with pytest.raises(ValueError, match="scope"):
        build_adapter(sc)


def test_global_scope_wrong_db_refused() -> None:
    """Страж имени БД: scope=global против не-стендовой БД → отказ до обращения."""
    with pytest.raises(ValueError, match="mongo_db"):
        InvestmentStandAdapter(base_url="http://fake", scope="global",
                               mongo_db="production", mongo_uri=None)


def test_global_scope_stand_db_ok() -> None:
    """Регресс: scope=global против БД тестового стенда конструируется."""
    InvestmentStandAdapter(base_url="http://fake", scope="global",
                           mongo_db="agent_memory", mongo_uri=None)
    InvestmentStandAdapter(base_url="http://fake", scope="global",
                           mongo_db="agent_memory_stack2", mongo_uri=None)


@pytest.mark.parametrize("scenario_path", _investment_stand_scenarios(),
                         ids=lambda p: p.name)
def test_live_investment_stand_scenarios_resolve_to_namespace(scenario_path) -> None:
    """Все живые investment_stand-сценарии резолвятся в namespace (миграция +
    дефолт) — ни один не идёт с молчаливым глобальным wipe."""
    sc = load_scenario(scenario_path)
    assert sc.reset_scope == "namespace", f"{scenario_path.name}: {sc.reset_scope}"
