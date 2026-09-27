"""tests/test_mock_live_symmetry.py — CARD-LIVE-COVERAGE Задача 1.

Директива владельца 2026-09-27: «все атаки идут в бой, ВСЕ; mock простаивает —
кончить». Три замка, все механические (по scenarios/*.yaml + ATTACK_REGISTRY,
без рукописных списков имён):

  1. КАЖДАЯ семья из ATTACK_REGISTRY имеет ≥1 live-сценарий (investment_stand
     или http_endpoint) — «все в бой», mock не простаивает.
  2. 1:1 зеркало: каждая семья с live имеет ≥1 mock-сценарий (smoke-зеркало).
  3. Правило навсегда: mock — ТОЛЬКО smoke. adapter==mock ⇒ нет живых адресов
     (base_url/mongo_uri) И repetitions ≤ SMOKE_MAX (утверждено A0 Q4,
     VERDICT-DESIGN-LIVE-COVERAGE-2026-09-27: mock==5×1 не режет).

Гранулярность — семья, а не файл: у существующих семей несколько live-армов
(cross_user_bac ×6, live-контроли), их пофайловый mock-двойник не существует
ПО ЗАМЫСЛУ (это live-контроли, не «атака↔контроль»); «1:1 по числу» карты
трактуем как «у каждой семьи есть и mock-smoke, и live» — зафиксировано в
фактшите и одобрено A0.
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import memnotsafe.attacks  # noqa: E402,F401  # населяет ATTACK_REGISTRY
from memnotsafe.attacks.base import ATTACK_REGISTRY  # noqa: E402

SCENARIOS = Path(__file__).resolve().parents[1] / "scenarios"
LIVE_ADAPTERS = ("investment_stand", "http_endpoint")
SMOKE_MAX_REPETITIONS = 5  # A0 Q4: mock repetitions по факту 45×1/7×3/2×5


def _load_all() -> dict[str, dict]:
    out: dict[str, dict] = {}
    for p in sorted(SCENARIOS.glob("*.yaml")):
        try:
            cfg = yaml.safe_load(p.read_text(encoding="utf-8"))
        except yaml.YAMLError:
            continue
        if isinstance(cfg, dict):
            out[p.stem] = cfg
    return out


def _family(cfg: dict) -> str | None:
    return (cfg.get("attack") or {}).get("family")


def _adapter(cfg: dict) -> str | None:
    return (cfg.get("target") or {}).get("adapter")


def test_every_family_has_live_scenario() -> None:
    """«ВСЕ атаки в бой»: у каждой зарегистрированной семьи ≥1 live-сценарий."""
    scen = _load_all()
    live_families = {_family(c) for c in scen.values() if _adapter(c) in LIVE_ADAPTERS}
    missing = sorted(f for f in ATTACK_REGISTRY if f not in live_families)
    print(f"[LIVE-COVERAGE] семей всего: {len(ATTACK_REGISTRY)}; с live: "
          f"{len(set(ATTACK_REGISTRY) & live_families)}; без live: {missing or 'нет'}")
    assert not missing, (
        f"семьи без live-сценария (mock простаивает): {missing} — карта "
        f"LIVE-COVERAGE: каждой семье по каноническому live на stack2"
    )


def test_every_family_has_mock_smoke_mirror() -> None:
    """1:1: у каждой семьи с live есть mock-smoke зеркало."""
    scen = _load_all()
    mock_families = {_family(c) for c in scen.values() if _adapter(c) == "mock"}
    live_families = {_family(c) for c in scen.values() if _adapter(c) in LIVE_ADAPTERS}
    orphan_live = sorted(f for f in live_families if f not in mock_families)
    assert not orphan_live, (
        f"семьи с live, но без mock-smoke зеркала: {orphan_live} — правило "
        f"навсегда: на каждый live — mock-smoke зеркало"
    )


def test_mock_scenarios_are_smoke_only() -> None:
    """Правило навсегда: mock — только smoke (без живых адресов, repetitions ≤ SMOKE_MAX)."""
    scen = _load_all()
    offenders: list[tuple[str, object, object]] = []
    for stem, cfg in scen.items():
        target = cfg.get("target") or {}
        if target.get("adapter") != "mock":
            continue
        reps = (cfg.get("metrics") or {}).get("repetitions", 1)
        live_addr = target.get("base_url") or target.get("mongo_uri")
        if live_addr is not None or (isinstance(reps, int) and reps > SMOKE_MAX_REPETITIONS):
            offenders.append((stem, live_addr, reps))
    assert not offenders, (
        f"mock-сценарии не smoke: {offenders} — mock только smoke "
        f"(без живых base_url/mongo_uri, repetitions ≤ {SMOKE_MAX_REPETITIONS})"
    )
