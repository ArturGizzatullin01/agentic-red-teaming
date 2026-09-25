"""tests/test_marker_order_and_provenance.py — FIX-D (два в одном).

(a) Порядок маркера H19/H22. campaign.py писал в историю REGISTERED-запись,
вызывая `attack.expected_effect(ctx)` ДО того, как runner выводит case_marker
(инвариант «producer маркера — runner»). У маркерных семей deferred_payload
(H22) и delimiter_summary_injection (H19) `expected_effect` требует маркер и
бросал ValueError наружу трейсбеком — эти семьи были непрогоняемы через run/go.
Фикс: goal_digest REGISTERED-записи откладывается (None), если маркер ещё не
выведен; на пост-ран записи (attempt 1) он и так считается из candidate.

(b) Ловушка W10 (editable-install). `pip install -e` мог указывать на СТАРЫЙ
checkout, и «голый» `memnotsafe` молча исполнял старый код. Фикс: go/pilot при
старте печатают версию/путь пакета и предупреждают, если пакет импортирован не
из текущего дерева.

Офлайн: сценарии H19/H22 идут против mock; провенанс не трогает сеть.
"""

from __future__ import annotations

import asyncio
from io import StringIO
from pathlib import Path

import pytest
from rich.console import Console

from memnotsafe.core.campaign import Campaign
from memnotsafe.core.config import build_adapter, load_scenario

_SCENARIOS = Path(__file__).resolve().parent.parent / "scenarios"


# ============================================================ (a) порядок маркера

@pytest.mark.parametrize("stem", ["deferred-payload", "delimiter-summary-injection"])
def test_marker_family_runs_through_campaign_without_traceback(stem, tmp_path) -> None:
    """Главный замок карты: run/go на сценарии H19/H22-типа даёт КОРРЕКТНЫЙ
    прогон, а не ValueError-трейсбек из REGISTERED-записи истории. На базе
    campaign.py звал expected_effect(ctx) до вывода маркера → ValueError наружу."""
    scenario = load_scenario(_SCENARIOS / f"{stem}.yaml")
    target = build_adapter(scenario)
    result = asyncio.run(Campaign(scenario, target, tmp_path / stem).run(repetitions=1))
    assert result.results, f"{stem}: прогон не дал результатов"


def test_registered_goal_digest_defers_when_marker_absent() -> None:
    """`_registered_goal_digest` откладывает (None) дайджест, когда маркер ещё не
    выведен (маркерная семья), и считает его, когда маркер уже есть."""
    from memnotsafe.attacks import get_attack
    from memnotsafe.attacks.base import AttackContext
    from memnotsafe.core.campaign import _registered_goal_digest

    a = get_attack("deferred_payload")
    dp = a() if isinstance(a, type) else a
    no_marker = AttackContext(attacker_user_id="1001", victim_user_id="1002", run_seed=1,
                              case_id="C1", params={"case_marker_in_payload": True}, case_marker=None)
    assert _registered_goal_digest(dp, no_marker) is None
    with_marker = AttackContext(attacker_user_id="1001", victim_user_id="1002", run_seed=1,
                                case_id="C1", params={"case_marker_in_payload": True}, case_marker="CASE-XYZ")
    assert _registered_goal_digest(dp, with_marker) is not None


def test_registered_goal_digest_computes_for_non_marker_family() -> None:
    """Обычная семья (не требующая маркера) получает дайджест на REGISTERED как и
    прежде — откладывание не меняет их поведение."""
    from memnotsafe.attacks import get_attack
    from memnotsafe.attacks.base import AttackContext
    from memnotsafe.core.campaign import _registered_goal_digest

    a = get_attack("cross_user_bac")
    cu = a() if isinstance(a, type) else a
    ctx = AttackContext(attacker_user_id="1001", victim_user_id="1002", run_seed=1, case_id="C2")
    assert _registered_goal_digest(cu, ctx) is not None


# ============================================================ (b) ловушка W10

def _pkg_tree_root() -> Path:
    """Корень дерева текущего пакета: .../src/memnotsafe → .../ (родитель src)."""
    import memnotsafe
    return Path(memnotsafe.__file__).resolve().parents[2]


def test_package_is_in_tree_true_for_current_tree() -> None:
    from memnotsafe.selfserve import _package_is_in_tree, _package_provenance

    _ver, pkg = _package_provenance()
    assert _package_is_in_tree(pkg, _pkg_tree_root()) is True


def test_package_is_in_tree_false_for_foreign_tree() -> None:
    from memnotsafe.selfserve import _package_is_in_tree, _package_provenance

    _ver, pkg = _package_provenance()
    assert _package_is_in_tree(pkg, Path("/nonexistent/foreign/checkout")) is False


def test_render_provenance_warns_when_out_of_tree() -> None:
    """go/pilot при старте предупреждают, если пакет импортирован не из текущего
    дерева (ловушка W10)."""
    from memnotsafe.selfserve import render_provenance

    buf = StringIO()
    console = Console(file=buf, no_color=True, width=240)
    ok = render_provenance(console, cwd=Path("/some/foreign/checkout"))
    out = buf.getvalue()
    assert ok is False
    assert "W10" in out and ("ВНИМАНИЕ" in out or "editable" in out)
    # путь/версия пакета печатается всегда (провенанс виден оператору)
    assert "memnotsafe" in out


def test_render_provenance_quiet_when_in_tree() -> None:
    from memnotsafe.selfserve import render_provenance

    buf = StringIO()
    console = Console(file=buf, no_color=True, width=240)
    ok = render_provenance(console, cwd=_pkg_tree_root())
    out = buf.getvalue()
    assert ok is True
    assert "W10" not in out  # предупреждения нет, но провенанс напечатан
    assert "memnotsafe" in out
