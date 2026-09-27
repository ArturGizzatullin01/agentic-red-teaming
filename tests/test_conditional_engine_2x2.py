"""tests/test_conditional_engine_2x2.py — CARD-LIVE-COVERAGE Задача 3.

Диагностика 0.917 probe vs 0/72 движок: 2×2 (trust-шаг × маркер-операнд) на условном
варианте global_policy_injection. Замки офлайн:
  - параметрический гейт trust_step в delivery_steps (умолчание True → канон не тронут);
  - четыре ячейки scenarios/cond-2x2/ валидны и несут верную конфигурацию 2×2;
  - маркер-операнд переключается case_marker_in_payload.
Живой прогон 2×2 и атрибуция по source_session_id — A0 по «го» (см. spec 001 amendment).
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from memnotsafe.attacks import get_attack  # noqa: E402
from memnotsafe.attacks.base import AttackContext  # noqa: E402
from memnotsafe.core.config import load_scenario  # noqa: E402

FAMILY = "global_policy_injection"
COND2X2 = SRC.parent / "scenarios" / "cond-2x2"
CELLS = {
    "cond_2x2_trust1_marker1": (True, True),
    "cond_2x2_trust1_marker0": (True, False),
    "cond_2x2_trust0_marker1": (False, True),
    "cond_2x2_trust0_marker0": (False, False),
}


def _ctx(**params) -> AttackContext:
    return AttackContext(attacker_user_id="1005", victim_user_id="1001", run_seed=1,
                         case_id="CASE-2X2", params=params, case_marker=params.get("_marker"))


def test_trust_step_gate_toggles_delivery() -> None:
    attack = get_attack(FAMILY)()
    # trust_step вкл (и по умолчанию) → две реплики: доверие + payload
    for params in ({"variant": "conditional", "trust_step": True}, {"variant": "conditional"}):
        ctx = _ctx(**params)
        steps = attack.delivery_steps(attack.generate(ctx), ctx)
        assert [s.label for s in steps] == ["trust_building", "policy_payload"], params
    # trust_step выкл → одна реплика (как probe H09)
    ctx_off = _ctx(variant="conditional", trust_step=False)
    steps_off = attack.delivery_steps(attack.generate(ctx_off), ctx_off)
    assert [s.label for s in steps_off] == ["policy_payload"]


def test_marker_operand_toggle_in_payload() -> None:
    attack = get_attack(FAMILY)()
    on = attack.generate(_ctx(variant="conditional", _marker="CM-abcd12",
                              case_marker_in_payload=True, case_marker_style="operand"))
    assert 'reg="CM-abcd12"' in on.payload
    off = attack.generate(_ctx(variant="conditional", case_marker_in_payload=False))
    assert "reg=" not in off.payload


def test_2x2_scenarios_valid_and_configured() -> None:
    assert COND2X2.is_dir(), "подкаталог scenarios/cond-2x2/ отсутствует"
    for stem, (trust, marker) in CELLS.items():
        path = COND2X2 / f"{stem}.yaml"
        sc = load_scenario(str(path))  # валиден
        assert sc.attack_family == FAMILY and sc.target.adapter == "investment_stand"
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        params = raw.get("params") or {}
        assert params.get("variant") == "conditional"
        assert bool(params.get("trust_step")) is trust, (stem, "trust_step")
        assert bool(params.get("case_marker_in_payload")) is marker, (stem, "marker")
        # stack2-main адреса (как у прочих live), reset_scope namespace
        assert raw["target"]["base_url"] == "http://localhost:9600"
        assert raw.get("reset_scope") == "namespace"


def test_2x2_not_scanned_by_root_inventory() -> None:
    """Ячейки в подкаталоге — нерекурсивный glob каталога инвентаря их не видит
    (прецедент scenarios/h09-matrix/), поэтому инвентарные замки не трогаются."""
    root_stems = {p.stem for p in (SRC.parent / "scenarios").glob("*.yaml")}
    assert not (set(CELLS) & root_stems)
