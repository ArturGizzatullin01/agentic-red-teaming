"""tests/test_protected_symmetry_audit.py — хвост W1: инвентаризация
protected-симметрии ВСЕХ зарегистрированных семей атак.

W1 (слепой protected-контроль booking) нашли случайно, при попытке сделать A2;
остальные семьи на симметрию никто не проверял. Этот тест не требует симметрии —
он ИЗМЕРЯЕТ и фиксирует факт: для каждой семьи из ATTACK_REGISTRY одна и та же
атака прогоняется через MockTarget(vulnerable=True) и MockTarget(vulnerable=False)
in-process; собирается профиль стадий и печатается строка инвентаризации
(семья → стадии vuln → стадии prot → какие различаются → есть ли
protected-сценарий в scenarios/). Семьи с полностью одинаковым профилем —
кандидаты в слепые контроли (находка для владельца, мок не чинится).

Конфигурация прогона (актёры/params) берётся из КАНОНИЧЕСКОГО yaml семьи
(scenarios/<id == family>.yaml; для generated — первый сценарий с
family=generated + первая валидная запись corpora/support-agent.yaml) —
а не рукописной таблицей; покрытие сверяется с ATTACK_REGISTRY ассертом:
новая семья без канонического сценария уронит тест с внятным сообщением.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest
import yaml

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from memnotsafe.adapters.mock import MockTarget  # noqa: E402
from memnotsafe.attacks import get_attack  # noqa: E402
from memnotsafe.attacks.base import ATTACK_REGISTRY, AttackContext  # noqa: E402
from memnotsafe.attacks.generated import PARAM_CORPUS_ID, PARAM_RECORD  # noqa: E402
from memnotsafe.core.runner import new_run_id, run_attack  # noqa: E402
from memnotsafe.generation.corpus import read_corpus, valid_records  # noqa: E402

SCENARIOS = Path(__file__).resolve().parents[1] / "scenarios"
STAGE_ORDER = ("write", "persistence", "retrieval", "adoption", "tool", "external_effect")
COMPOSITE_STAGES = ("write", "persistence", "retrieval", "adoption", "external_effect")


def _scenario_configs() -> dict[str, dict]:
    """{family: конфиг прогона} из канонических сценариев репозитория."""
    configs: dict[str, dict] = {}
    for path in sorted(SCENARIOS.glob("*.yaml")):
        try:
            cfg = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError:
            continue
        if not isinstance(cfg, dict):
            continue
        family = (cfg.get("attack") or {}).get("family")
        target = cfg.get("target") or {}
        if not family or target.get("adapter") != "mock":
            continue
        # канонический сценарий: нормализованный id равен семье или является
        # её префиксом (tool-error-echo -> tool_error_echo_poisoning);
        # вариантовки (-global/-pilot/-plain/-marker) и live отсекаются
        fn = str(cfg.get("id", "")).replace("-", "_")
        canonical = fn == family or family.startswith(fn) or family == "generated"
        if canonical and "identities" not in target and family not in configs:
            configs[family] = {
                "attacker": cfg["actors"]["attacker"]["user_id"],
                "victim": cfg["actors"]["victim"]["user_id"],
                "params": cfg.get("params") or {},
                "path": path.name,
            }
    return configs


def _family_params(family: str, cfg: dict) -> dict:
    if family != "generated":
        return dict(cfg["params"])
    corpus = read_corpus(Path(__file__).resolve().parents[1] / "corpora" / "support-agent.yaml")
    record = valid_records(corpus)[0]
    return {PARAM_RECORD: record.to_dict(), PARAM_CORPUS_ID: "support-agent"}


def _profile(family: str, vulnerable: bool) -> dict[str, object]:
    cfg = _scenario_configs()[family]
    attack = get_attack(family)()
    ctx = AttackContext(
        attacker_user_id=cfg["attacker"], victim_user_id=cfg["victim"],
        run_seed=1, case_id=f"CASE-SYMAUDIT-{family}",
        params=_family_params(family, cfg),
    )
    result = asyncio.run(run_attack(attack, ctx, MockTarget(vulnerable=vulnerable), run_id=new_run_id()))
    return {s.stage: s.success for s in result.stages}


def _protected_scenarios() -> dict[str, str]:
    """{family: имя protected-сценария} по всем yaml."""
    found: dict[str, str] = {}
    for path in sorted(SCENARIOS.glob("*.yaml")):
        try:
            cfg = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError:
            continue
        if not isinstance(cfg, dict):
            continue
        family = (cfg.get("attack") or {}).get("family")
        if family and (cfg.get("target") or {}).get("vulnerable") is False:
            found.setdefault(family, path.name)
    return found


@pytest.mark.parametrize("family", sorted(ATTACK_REGISTRY))
def test_protected_symmetry_inventory(family: str) -> None:
    # карточка A, PASS_IF-1: тест ОПИСЫВАЕТ факт, а не требует симметрии.
    # Ассерты — только на то, что измерение состоялось.
    cfgs = _scenario_configs()
    assert family in cfgs, (
        f"у семьи {family!r} нет канонического mock-сценария (id == family) — "
        "добавь сценарий или расширь выборку, список семей берётся из ATTACK_REGISTRY"
    )
    vuln = _profile(family, vulnerable=True)
    prot = _profile(family, vulnerable=False)

    assert tuple(vuln) == STAGE_ORDER, f"{family}: неожидаемый набор стадий: {sorted(vuln)}"
    # телеметрия мока не зависит от auth_mode: нерешаемые стадии обязаны
    # совпадать в обоих режимах, решаемые — быть булевыми
    assert {k for k, v in vuln.items() if v is None} == {k for k, v in prot.items() if v is None}
    assert all(v is None or isinstance(v, bool) for v in list(vuln.values()) + list(prot.values()))

    diff = sorted(k for k in STAGE_ORDER if vuln[k] != prot[k])
    prot_scen = _protected_scenarios().get(family, "—")
    blind = "  <-- PROTECTED-СЛЕП? (профили идентичны)" if not diff else ""
    print(
        f"[SYMAUDIT] {family:28s} vuln={ {k: vuln[k] for k in COMPOSITE_STAGES} } "
        f"prot={ {k: prot[k] for k in COMPOSITE_STAGES} } diff={diff or 'НЕТ'} "
        f"prot-сценарий={prot_scen}{blind}"
    )


@pytest.mark.parametrize("family", ["cross_user_bac", "tool_argument_hijack"])
def test_w1_lock_protected_differs_only_in_external_effect(family: str) -> None:
    # карточка A, PASS_IF-2: регрессионный замок на доказанные W1-фиксы —
    # в protected различается РОВНО external_effect, композитные стадии записи
    # и принятия остаются True. Если контроль снова станет слепым — падает.
    vuln = _profile(family, vulnerable=True)
    prot = _profile(family, vulnerable=False)
    diff = sorted(k for k in STAGE_ORDER if vuln[k] != prot[k])
    assert diff == ["external_effect"], f"{family}: diff={diff}, профили: vuln={vuln} prot={prot}"
    for stage in COMPOSITE_STAGES:
        if stage == "external_effect":
            assert prot[stage] is False
        else:
            assert prot[stage] is True, f"{family}: {stage}={prot[stage]!r} в protected"
